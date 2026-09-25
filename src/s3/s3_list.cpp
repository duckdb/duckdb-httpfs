#include "s3/s3_list.hpp"

#include "s3/s3_settings.hpp"
#include "s3/s3fs.hpp"

#include "duckdb/common/algorithm.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar/string_common.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/parallel/task_executor.hpp"

#include <exception>

namespace duckdb {

enum class S3GlobMatchMode : uint8_t { PREFIX, COMPLETE };

static bool Match(vector<string>::const_iterator key, vector<string>::const_iterator key_end,
                  vector<string>::const_iterator pattern, vector<string>::const_iterator pattern_end,
                  S3GlobMatchMode mode) {

	if (key == key_end && mode == S3GlobMatchMode::PREFIX) {
		return true;
	}

	while (key != key_end && pattern != pattern_end) {
		if (*pattern == "**") {
			if (std::next(pattern) == pattern_end) {
				return true;
			}
			pattern++;
			while (key != key_end) {
				if (Match(key, key_end, pattern, pattern_end, mode)) {
					return true;
				}
				key++;
			}
			if (mode == S3GlobMatchMode::PREFIX) {
				return true;
			}
			return false;
		}
		if (!Glob(key->data(), key->length(), pattern->data(), pattern->length())) {
			return false;
		}
		key++;
		pattern++;
	}
	if (pattern != pattern_end && mode == S3GlobMatchMode::PREFIX) {
		return true;
	}
	return key == key_end && pattern == pattern_end;
}

enum GlobType { HIERARCHICAL, LISTING, UNKNOWN };

struct S3GlobResult : public LazyMultiFileList {
public:
	S3GlobResult(S3FileSystem &fs_p, const string &path, optional_ptr<FileOpener> opener);

protected:
	bool ExpandNextPath() const override;

private:
	struct PrefixResult {
		S3ListObjectsV2Result response;
		std::exception_ptr error;
	};
	struct Prefix {
		string continuation_token;
		optional<PrefixResult> result;
		//! A throttled prefix is re-issued once, alone, before its failure is reported.
		bool reissued = false;
	};
	struct Entry {
		OpenFileInfo file;
		unique_ptr<Prefix> prefix;
	};
	class ListPrefixTask;

	idx_t GetConcurrency() const;
	void PrefetchPrefixes(idx_t limit) const;
	void AdaptListWindow(const vector<PrefixResult> &results) const;
	static bool IsThrottledError(const std::exception_ptr &error);
	void ScanPrefix() const;
	S3ListObjectsV2Result ListPrefix(const Entry &entry) const;
	S3ListObjectsV2Result Request(const string &path, const string &continuation_token, S3ListMode mode,
	                              optional_ptr<const string> prefix = nullptr) const;
	void AppendPage(const S3ListObjectsV2Result &response) const;
	void ScanTopLevel() const;
	bool ShouldInvestigateRecursiveGlob() const;
	void SelectGlobType(S3ListObjectsV2Result &response, string &continuation_token) const;
	bool ContainsDenseDirectories(const vector<OpenFileInfo> &s3_keys) const;
	void AppendMatchingFiles(vector<OpenFileInfo> &s3_keys) const;

private:
	S3FileSystem &fs;
	string glob_pattern;
	optional_ptr<FileOpener> opener;
	mutable bool finished = false;
	shared_ptr<HTTPRequestSession> request_session;
	string shared_path;
	optional<ParsedS3Url> parsed_s3_url;
	mutable string main_continuation_token;
	mutable vector<Entry> entries;
	mutable idx_t prefetched_count = 0;
	idx_t max_list_concurrency = S3Settings::DEFAULT_LIST_CONCURRENCY;
	//! Additive-increase/multiplicative-decrease bound on concurrent prefix listings, driven by throttling.
	mutable idx_t list_window = 0;
	mutable GlobType glob_type {UNKNOWN};
};

class S3GlobResult::ListPrefixTask : public BaseExecutorTask {
public:
	ListPrefixTask(TaskExecutor &executor, const S3GlobResult &glob_p, const Entry &entry_p, PrefixResult &result_p)
	    : BaseExecutorTask(executor), glob(glob_p), entry(entry_p), result(result_p) {
	}

	void ExecuteTask() override {
		try {
			result.response = glob.ListPrefix(entry);
		} catch (...) {
			// Report prefetched failures when their prefix is consumed.
			result.error = std::current_exception();
		}
	}

private:
	const S3GlobResult &glob;
	const Entry &entry;
	PrefixResult &result;
};

S3GlobResult::S3GlobResult(S3FileSystem &fs_p, const string &glob_pattern_p, optional_ptr<FileOpener> opener)
    : LazyMultiFileList(FileOpener::TryGetClientContext(opener)), fs(fs_p), glob_pattern(glob_pattern_p),
      opener(opener) {
	if (!opener) {
		throw InternalException("Cannot S3 Glob without FileOpener");
	}
	Value list_concurrency;
	if (FileOpener::TryGetCurrentSetting(opener, "s3_list_concurrency", list_concurrency)) {
		max_list_concurrency = MaxValue<idx_t>(list_concurrency.GetValue<idx_t>(), 1);
	}
	FileOpenerInfo info = {glob_pattern};

	// Trim any query parameters from the string
	auto s3_auth_params = S3AuthResolver::Resolve(opener, info);

	// In url compatibility mode, we ignore globs allowing users to query files with the glob chars
	if (s3_auth_params.GetURLParams().compatibility_mode) {
		expanded_files.emplace_back(glob_pattern);
		finished = true;
		return;
	}

	parsed_s3_url = S3Url::Parse(glob_pattern, s3_auth_params);
	auto parsed_glob_url = S3Url::GetDisplayUrl(glob_pattern, s3_auth_params);

	// AWS matches on prefix, not glob pattern, so we take a substring until the first wildcard char for the aws calls
	auto first_wildcard_pos = parsed_glob_url.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		expanded_files.emplace_back(glob_pattern);
		finished = true;
		return;
	}
	if (parsed_s3_url->GetObjectVersion().IsSet()) {
		throw NotImplementedException("The %s parameter cannot be used with glob patterns",
		                              S3Provider::GetVersionParameterName(parsed_s3_url->GetObjectVersion().GetType()));
	}

	shared_path = parsed_glob_url.substr(0, first_wildcard_pos);

	request_session = S3RequestExecutor::CreateSession(opener, glob_pattern, s3_auth_params);
}

bool S3GlobResult::ExpandNextPath() const {
	if (finished) {
		return false;
	}

	if (entries.empty()) {
		ScanTopLevel();
	} else if (entries.back().prefix) {
		ScanPrefix();
	}

	vector<OpenFileInfo> s3_keys;
	while (!entries.empty() && !entries.back().prefix) {
		s3_keys.push_back(std::move(entries.back().file));
		entries.pop_back();
	}
	if (main_continuation_token.empty() && entries.empty()) {
		finished = true;
	}
	AppendMatchingFiles(s3_keys);
	return true;
}

S3ListObjectsV2Result S3GlobResult::Request(const string &path, const string &continuation_token, S3ListMode mode,
                                            optional_ptr<const string> prefix) const {
	if (context && context->IsInterrupted()) {
		throw InterruptException();
	}
	return AWSListObjectV2::Request(fs.GetEncryptionUtil(), *request_session, path, continuation_token, mode, {},
	                                prefix);
}

S3ListObjectsV2Result S3GlobResult::ListPrefix(const Entry &entry) const {
	auto path = parsed_s3_url->GetPrefix() + parsed_s3_url->GetBucket() + '/';
	return Request(path, entry.prefix->continuation_token, S3ListMode::HIERARCHICAL, &entry.file.path);
}

void S3GlobResult::AppendPage(const S3ListObjectsV2Result &response) const {
	const auto start = entries.size();
	vector<OpenFileInfo> files;
	AWSListObjectV2::AppendFileList(response, files);
	for (auto &file : files) {
		entries.push_back({std::move(file), nullptr});
	}
	auto pattern_splits = StringUtil::Split(parsed_s3_url->GetKey(), "/");
	for (const auto &prefix : response.common_prefixes) {
		auto path = S3Url::Decode(prefix);
		auto key_splits = StringUtil::Split(path, "/");
		if (Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end(),
		          S3GlobMatchMode::PREFIX)) {
			entries.push_back({OpenFileInfo(std::move(path)), make_uniq<Prefix>()});
		}
	}
	// Merge files and prefixes by decoded key before descending into subdirectories.
	std::sort(entries.begin() + NumericCast<int64_t>(start), entries.end(),
	          [](const Entry &left, const Entry &right) { return left.file.path > right.file.path; });
}

idx_t S3GlobResult::GetConcurrency() const {
	auto client_context = context;
	const auto threads = client_context ? TaskScheduler::GetScheduler(*client_context).NumberOfAsyncThreads() + 1 : 1;
	return MinValue<idx_t>(threads, max_list_concurrency);
}

bool S3GlobResult::IsThrottledError(const std::exception_ptr &error) {
	try {
		std::rethrow_exception(error);
	} catch (std::exception &ex) {
		return S3RequestUtil::IsThrottledError(ErrorData(ex));
	} catch (...) {
		return false;
	}
}

void S3GlobResult::AdaptListWindow(const vector<PrefixResult> &results) const {
	bool throttled = false;
	for (const auto &result : results) {
		throttled |= result.error ? IsThrottledError(result.error) : result.response.throttled_retries > 0;
	}
	const auto previous_window = list_window;
	if (throttled) {
		list_window = MaxValue<idx_t>(list_window / 2, 1);
	} else {
		list_window = MinValue<idx_t>(list_window + 1, GetConcurrency());
	}
	if (list_window < previous_window && context) {
		DUCKDB_LOG_WARNING(*context,
		                   "S3 throttled listing requests for glob \"%s\" - reducing concurrent list requests from "
		                   "%llu to %llu",
		                   glob_pattern, static_cast<unsigned long long>(previous_window),
		                   static_cast<unsigned long long>(list_window));
	}
}

void S3GlobResult::PrefetchPrefixes(idx_t limit) const {
	if (list_window == 0) {
		list_window = GetConcurrency();
	}
	const auto window = MinValue<idx_t>(list_window, limit);
	const auto available = window > prefetched_count ? window - prefetched_count : 1;
	vector<idx_t> pending;
	for (idx_t i = entries.size(); i > 0 && pending.size() < available; --i) {
		const auto &prefix = entries[i - 1].prefix;
		if (prefix && !prefix->result) {
			pending.push_back(i - 1);
		}
	}
	const auto count = pending.size();
	D_ASSERT(count > 0);
	vector<PrefixResult> results(count);
	if (count == 1) {
		results[0].response = ListPrefix(entries[pending[0]]);
	} else {
		auto client_context = context;
		TaskExecutor executor(*client_context, TaskSchedulerType::ASYNC);
		for (idx_t i = 0; i < count; i++) {
			executor.ScheduleTask(make_uniq<ListPrefixTask>(executor, *this, entries[pending[i]], results[i]));
		}
		executor.WorkOnTasks();
	}
	AdaptListWindow(results);
	for (idx_t i = 0; i < count; i++) {
		entries[pending[i]].prefix->result = std::move(results[i]);
	}
	prefetched_count += count;
}

void S3GlobResult::ScanPrefix() const {
	auto &prefix = *entries.back().prefix;
	if (!prefix.result) {
		PrefetchPrefixes(GetConcurrency());
	}
	if (prefix.result->error && !prefix.reissued && IsThrottledError(prefix.result->error)) {
		// The request exhausted its retry budget while competing with the rest of its wave.
		// Give it one sequential attempt with a fresh budget before failing the glob.
		prefix.reissued = true;
		prefix.result.reset();
		D_ASSERT(prefetched_count > 0);
		--prefetched_count;
		PrefetchPrefixes(1);
	}
	if (prefix.result->error) {
		std::rethrow_exception(prefix.result->error);
	}
	auto entry = std::move(entries.back());
	entries.pop_back();
	D_ASSERT(prefetched_count > 0);
	--prefetched_count;
	auto response = std::move(entry.prefix->result->response);
	if (!response.continuation_token.empty()) {
		entry.prefix->continuation_token = std::move(response.continuation_token);
		entry.prefix->result.reset();
		entries.push_back(std::move(entry));
	}
	AppendPage(response);
}

void S3GlobResult::ScanTopLevel() const {
	if (!entries.empty()) {
		throw InternalException("Cannot perform a top-level S3 list request with pending entries");
	}
	const auto list_mode = glob_type == GlobType::HIERARCHICAL ? S3ListMode::HIERARCHICAL : S3ListMode::FLAT;
	auto response = Request(shared_path, main_continuation_token, list_mode);
	auto continuation_token = response.continuation_token;
	if (ShouldInvestigateRecursiveGlob() && !continuation_token.empty()) {
		SelectGlobType(response, continuation_token);
	}
	main_continuation_token = continuation_token;
	AppendPage(response);
}

bool S3GlobResult::ShouldInvestigateRecursiveGlob() const {
	if (glob_type != GlobType::UNKNOWN) {
		return false;
	}
	Value value;
	if (!FileOpener::TryGetCurrentSetting(opener, "s3_allow_recursive_globbing", value)) {
		return true;
	}
	return value.GetValue<bool>();
}

void S3GlobResult::SelectGlobType(S3ListObjectsV2Result &response, string &continuation_token) const {
	vector<OpenFileInfo> s3_keys;
	AWSListObjectV2::AppendFileList(response, s3_keys);
	if (!ContainsDenseDirectories(s3_keys)) {
		glob_type = GlobType::LISTING;
		return;
	}
	response = Request(shared_path, main_continuation_token, S3ListMode::HIERARCHICAL);
	continuation_token = response.continuation_token;
	glob_type = GlobType::HIERARCHICAL;
}

bool S3GlobResult::ContainsDenseDirectories(const vector<OpenFileInfo> &s3_keys) const {
	unordered_set<string> directories;
	for (const auto &s3_key : s3_keys) {
		auto slash = s3_key.path.find_last_of('/');
		directories.insert(slash == string::npos ? "" : s3_key.path.substr(0, slash + 1));
	}
	if (directories.size() * 100 < s3_keys.size()) {
		return true;
	}
	return !s3_keys.empty() && directories.size() * 1000 <= s3_keys.size() * GetConcurrency();
}

void S3GlobResult::AppendMatchingFiles(vector<OpenFileInfo> &s3_keys) const {
	auto pattern_splits = StringUtil::Split(parsed_s3_url->GetKey(), "/");
	for (auto &s3_key : s3_keys) {
		auto key_splits = StringUtil::Split(s3_key.path, "/");
		if (Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end(),
		          S3GlobMatchMode::COMPLETE)) {
			auto result_full_url = parsed_s3_url->GetPrefix() + parsed_s3_url->GetBucket() + "/" + s3_key.path;
			if (!parsed_s3_url->GetQueryString().empty()) {
				result_full_url += '?' + parsed_s3_url->GetQueryString();
			}
			s3_key.path = std::move(result_full_url);
			auto captured = request_session->Capture();
			auto &snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
			if (snapshot.region_redirected) {
				D_ASSERT(!snapshot.auth_params.GetCredentials().region.empty());
				s3_key.extended_info->options["s3_region"] = snapshot.auth_params.GetCredentials().region;
			}
			expanded_files.push_back(std::move(s3_key));
		}
	}
}

unique_ptr<MultiFileList> S3FileSystem::GlobFilesExtended(const string &path, const FileGlobInput &input,
                                                          optional_ptr<FileOpener> opener) {
	return make_uniq<S3GlobResult>(*this, path, opener);
}

bool S3FileSystem::ListFilesExtended(const string &directory, const std::function<void(OpenFileInfo &info)> &callback,
                                     optional_ptr<FileOpener> opener) {
	string trimmed_dir = directory;
	auto sep = PathSeparator(trimmed_dir);
	StringUtil::RTrim(trimmed_dir, sep);
	auto glob_res = GlobFilesExtended(JoinPath(trimmed_dir, "**"), FileGlobOptions::ALLOW_EMPTY, opener);

	if (!glob_res || glob_res->GetExpandResult() == FileExpandResult::NO_FILES) {
		return false;
	}
	auto base_path = trimmed_dir + sep;

	for (auto file : glob_res->Files()) {
		if (!StringUtil::StartsWith(file.path, base_path)) {
			throw InvalidInputException(
			    "Globbed directory \"%s\", but found file \"%s\" that does not start with base path \"%s\"", directory,
			    file.path, base_path);
		}
		file.path = file.path.substr(base_path.size());
		callback(file);
	}

	return true;
}

struct S3ListRequest {
	static S3ListObjectsV2Result Finish(const S3RequestContext &request_context, unique_ptr<HTTPResponse> response,
	                                    optional<S3ListObjectsV2Result> result) {
		if (response->HasRequestError() || response->status != HTTPStatusCode::OK_200) {
			auto display_url = request_context.display_url;
			StringUtil::RTrim(display_url, "/");
			if (response->HasRequestError()) {
				throw IOException("%s error for HTTP GET to '%s'", response->GetRequestError(), display_url);
			}
			throw S3RequestUtil::GetRequestError(request_context, *response);
		}
		if (!result) {
			throw IOException("Malformed S3 list response for \"%s\"", request_context.display_url);
		}
		result->throttled_retries = request_context.throttled_retries;
		return std::move(*result);
	}

	static S3RequestQuery BuildQuery(const string &prefix, const string &continuation_token, S3ListMode mode,
	                                 optional_idx max_keys) {
		vector<pair<string, string>> request_params;
		if (!continuation_token.empty()) {
			request_params.emplace_back("continuation-token", continuation_token);
		}
		if (mode == S3ListMode::HIERARCHICAL) {
			request_params.emplace_back("delimiter", "/");
		}
		request_params.emplace_back("encoding-type", "url");
		request_params.emplace_back("list-type", "2");
		if (max_keys.IsValid()) {
			request_params.emplace_back("max-keys", to_string(max_keys.GetIndex()));
		}
		request_params.emplace_back("prefix", prefix);
		return S3RequestQuery(std::move(request_params));
	}
};

S3ListObjectsV2Result AWSListObjectV2::Request(EncryptionUtil &encryption_util, HTTPRequestSession &session,
                                               const string &path, const string &continuation_token, S3ListMode mode,
                                               optional_idx max_keys, optional_ptr<const string> prefix) {
	optional<S3ListObjectsV2Result> parsed_result;
	auto request_result = S3RequestExecutor::RunSession(
	    encryption_util, session,
	    S3RequestSpec {path, S3RequestOperation::LIST_OBJECTS,
	                   [&](const ParsedS3Url &parsed_url) {
		                   return S3ListRequest::BuildQuery(prefix ? *prefix : parsed_url.GetKey(), continuation_token,
		                                                    mode, max_keys);
	                   },
	                   "", "", ""},
	    [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    GetRequestInfo get_request(request_data.http_url, request_data.headers, params, nullptr, nullptr);
		    return S3RequestExecutor::SendSessionRequest(session, request_data, get_request);
	    },
	    [&](const S3RequestData &request_data, const string &previous_region, const string &correct_region) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    DUCKDB_LOG_WARNING(
		        params.logger,
		        "Ran S3 glob \"%s\" from incorrect region \"%s\" - retrying with updated region \"%s\".\n"
		        "Consider setting the S3 region to this explicitly to avoid extra round-trips.",
		        request_data.display_url, previous_region, correct_region);
	    },
	    [&](const S3RequestData &, const HTTPResponse &response) {
		    parsed_result.reset();
		    if (response.HasRequestError() || response.status != HTTPStatusCode::OK_200) {
			    return S3ReceivedResponseAction::ACCEPT;
		    }
		    S3ListObjectsV2Result attempt_result;
		    if (!S3XMLResponseParser::TryParseListObjectsV2(response.body, attempt_result)) {
			    return S3ReceivedResponseAction::RETRY_FRESH_CONNECTION;
		    }
		    parsed_result = std::move(attempt_result);
		    return S3ReceivedResponseAction::ACCEPT;
	    });
	return S3ListRequest::Finish(request_result.context, std::move(request_result.response), std::move(parsed_result));
}

void AWSListObjectV2::AppendFileList(const S3ListObjectsV2Result &response, vector<OpenFileInfo> &result) {
	for (const auto &object : response.objects) {
		try {
			auto parsed_path = S3Url::Decode(object.key);
			if (parsed_path.back() == '/') {
				continue;
			}
			OpenFileInfo result_file(parsed_path);
			auto extra_info = make_shared_ptr<ExtendedOpenFileInfo>();
			if (!object.last_modified.empty()) {
				extra_info->options["last_modified"] =
				    Value(object.last_modified).DefaultCastAs(LogicalType::TIMESTAMP);
			}
			if (!object.etag.empty()) {
				extra_info->options["etag"] = Value(object.etag);
			}
			if (!object.size.empty()) {
				extra_info->options["file_size"] = Value(object.size).DefaultCastAs(LogicalType::UBIGINT);
			}
			result_file.extended_info = std::move(extra_info);
			result.push_back(std::move(result_file));
		} catch (const InvalidInputException &exception) {
			throw IOException("Malformed S3 list response for key \"%s\": %s", object.key, exception.what());
		} catch (const ConversionException &exception) {
			throw IOException("Malformed S3 list response for key \"%s\": %s", object.key, exception.what());
		}
	}
}

} // namespace duckdb
