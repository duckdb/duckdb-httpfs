#include "s3/s3_list.hpp"

#include "s3/s3fs.hpp"

#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/common/multi_file/multi_file_list.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar/string_common.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/logging/logger.hpp"

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
	void ScanCurrentCommonPrefix(vector<OpenFileInfo> &s3_keys) const;
	void ScanTopLevel(vector<OpenFileInfo> &s3_keys) const;
	bool ShouldInvestigateRecursiveGlob() const;
	void SelectGlobType(S3ListObjectsV2Result &response, string &continuation_token) const;
	static bool ContainsDenseDirectories(const vector<OpenFileInfo> &s3_keys);
	void SelectNextCommonPrefix() const;
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
	mutable string current_common_prefix;
	mutable string common_prefix_continuation_token;
	mutable vector<string> common_prefixes;
	mutable GlobType glob_type {UNKNOWN};
};

S3GlobResult::S3GlobResult(S3FileSystem &fs_p, const string &glob_pattern_p, optional_ptr<FileOpener> opener)
    : LazyMultiFileList(FileOpener::TryGetClientContext(opener)), fs(fs_p), glob_pattern(glob_pattern_p),
      opener(opener) {
	if (!opener) {
		throw InternalException("Cannot S3 Glob without FileOpener");
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

	shared_path = parsed_glob_url.substr(0, first_wildcard_pos);

	request_session = S3RequestExecutor::CreateSession(opener, glob_pattern, s3_auth_params);
}

bool S3GlobResult::ExpandNextPath() const {
	if (finished) {
		return false;
	}

	vector<OpenFileInfo> s3_keys;
	if (!current_common_prefix.empty()) {
		ScanCurrentCommonPrefix(s3_keys);
	} else {
		ScanTopLevel(s3_keys);
	}

	if (main_continuation_token.empty() && current_common_prefix.empty()) {
		finished = true;
	}
	AppendMatchingFiles(s3_keys);
	return true;
}

void S3GlobResult::ScanCurrentCommonPrefix(vector<OpenFileInfo> &s3_keys) const {
	auto prefix_path = parsed_s3_url->GetPrefix() + parsed_s3_url->GetBucket() + '/' + current_common_prefix;
	current_common_prefix = S3Url::Decode(current_common_prefix);
	auto key_splits = StringUtil::Split(current_common_prefix, "/");
	auto pattern_splits = StringUtil::Split(parsed_s3_url->GetKey(), "/");
	if (Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end(),
	          S3GlobMatchMode::PREFIX)) {
		prefix_path = S3Url::Decode(prefix_path);
		auto response = AWSListObjectV2::Request(fs.GetEncryptionUtil(), *request_session, prefix_path,
		                                         common_prefix_continuation_token, S3ListMode::HIERARCHICAL);
		AWSListObjectV2::AppendFileList(response, s3_keys);
		common_prefixes.insert(common_prefixes.end(), response.common_prefixes.begin(), response.common_prefixes.end());
		common_prefix_continuation_token = response.continuation_token;
	}
	if (common_prefix_continuation_token.empty()) {
		SelectNextCommonPrefix();
	}
}

void S3GlobResult::ScanTopLevel(vector<OpenFileInfo> &s3_keys) const {
	if (!common_prefixes.empty()) {
		throw InternalException("We have common prefixes but we are doing a top-level request");
	}
	const auto list_mode = glob_type == GlobType::HIERARCHICAL ? S3ListMode::HIERARCHICAL : S3ListMode::FLAT;
	auto response = AWSListObjectV2::Request(fs.GetEncryptionUtil(), *request_session, shared_path,
	                                         main_continuation_token, list_mode);
	auto continuation_token = response.continuation_token;
	if (ShouldInvestigateRecursiveGlob() && !continuation_token.empty()) {
		SelectGlobType(response, continuation_token);
	}
	main_continuation_token = continuation_token;
	AWSListObjectV2::AppendFileList(response, s3_keys);
	common_prefixes = response.common_prefixes;
	SelectNextCommonPrefix();
}

bool S3GlobResult::ShouldInvestigateRecursiveGlob() const {
	if (glob_type != GlobType::UNKNOWN || StringUtil::Contains(parsed_s3_url->GetKey(), "**")) {
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
	response = AWSListObjectV2::Request(fs.GetEncryptionUtil(), *request_session, shared_path, main_continuation_token,
	                                    S3ListMode::HIERARCHICAL);
	continuation_token = response.continuation_token;
	glob_type = GlobType::HIERARCHICAL;
}

bool S3GlobResult::ContainsDenseDirectories(const vector<OpenFileInfo> &s3_keys) {
	unordered_set<string> directories;
	for (const auto &s3_key : s3_keys) {
		auto key_splits = StringUtil::Split(s3_key.path, "/");
		key_splits.pop_back();
		string directory;
		for (const auto &split : key_splits) {
			directory += split + "/";
		}
		directories.insert(std::move(directory));
	}
	return directories.size() * 100 < s3_keys.size();
}

void S3GlobResult::SelectNextCommonPrefix() const {
	if (common_prefixes.empty()) {
		current_common_prefix.clear();
		return;
	}
	current_common_prefix = common_prefixes.back();
	common_prefixes.pop_back();
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
		return std::move(*result);
	}

	static S3RequestQuery BuildQuery(const ParsedS3Url &parsed_url, const string &continuation_token, S3ListMode mode,
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
		request_params.emplace_back("prefix", parsed_url.GetKey());
		return S3RequestQuery(std::move(request_params));
	}
};

S3ListObjectsV2Result AWSListObjectV2::Request(EncryptionUtil &encryption_util, HTTPRequestSession &session,
                                               const string &path, const string &continuation_token, S3ListMode mode,
                                               optional_idx max_keys) {
	optional<S3ListObjectsV2Result> parsed_result;
	auto request_result = S3RequestExecutor::RunSession(
	    encryption_util, session,
	    S3RequestSpec {path, S3RequestOperation::LIST_OBJECTS,
	                   [&](const ParsedS3Url &parsed_url) {
		                   return S3ListRequest::BuildQuery(parsed_url, continuation_token, mode, max_keys);
	                   },
	                   "", "", ""},
	    [&](S3RequestData &request_data) {
		    auto &params = request_data.http_params->Cast<HTTPFSParams>();
		    GetRequestInfo get_request(request_data.http_url, request_data.headers, params, nullptr, nullptr);
		    return S3RequestExecutor::SendSessionRequest(session, request_data.captured, params, get_request);
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
