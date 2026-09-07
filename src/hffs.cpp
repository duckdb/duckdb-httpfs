#include "hffs.hpp"

#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/path.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/scalar/string_common.hpp"

#include <sstream>
#include <string>

namespace duckdb {

static string JoinHFPath(const string &base, const string &path) {
	return Path::FromString(base).Join(path).ToString();
}

HuggingFaceFileSystem::~HuggingFaceFileSystem() = default;

static string ParseNextUrlFromLinkHeader(const string &link_header_content) {
	auto split_outer = StringUtil::Split(link_header_content, ',');
	for (auto &split : split_outer) {
		auto split_inner = StringUtil::Split(split, ';');
		if (split_inner.size() != 2) {
			throw IOException("Unexpected link header for huggingface pagination: %s", link_header_content);
		}

		StringUtil::Trim(split_inner[1]);
		if (split_inner[1] == "rel=\"next\"") {
			StringUtil::Trim(split_inner[0]);

			if (!StringUtil::StartsWith(split_inner[0], "<") || !StringUtil::EndsWith(split_inner[0], ">")) {
				throw IOException("Unexpected link header for huggingface pagination: %s", link_header_content);
			}

			return split_inner[0].substr(1, split_inner[0].size() - 2);
		}
	}

	throw IOException("Failed to parse Link header for paginated response, pagination support");
}

HFFileHandle::~HFFileHandle() = default;

string HuggingFaceFileSystem::ListHFRequest(const ParsedHFUrl &url, HTTPFSParams &http_params, string &next_page_url) {
	HTTPHeaders header_map;
	string link_header_result;

	std::stringstream response;
	string fragment_next_page_url = next_page_url;
	if (StringUtil::StartsWith(next_page_url, url.endpoint)) {
		fragment_next_page_url = next_page_url.substr(url.endpoint.size());
	}
	if (!StringUtil::StartsWith(fragment_next_page_url, "/")) {
		fragment_next_page_url = "/" + fragment_next_page_url;
	}
	GetRequestInfo get_request(
	    url.endpoint + fragment_next_page_url, header_map, http_params,
	    [&](const HTTPResponse &response) {
		    if (static_cast<int>(response.status) >= 400) {
			    throw HTTPFSUtil::GetHTTPStatusError(response, RequestType::GET_REQUEST, "listing", next_page_url);
		    }
		    if (response.HasHeader("Link")) {
			    link_header_result = response.GetHeaderValue("Link");
		    }
		    return true;
	    },
	    [&](const_data_ptr_t data, idx_t data_length) {
		    response << string(const_char_ptr_cast(data), data_length);
		    return true;
	    });
	auto res = http_params.http_util.Request(get_request);
	if (res->HasRequestError()) {
		throw IOException(res->GetRequestError() + " error for HTTP GET to '" + next_page_url + "'");
	}
	if (res->status != HTTPStatusCode::OK_200) {
		throw HTTPFSUtil::GetHTTPStatusError(*res, RequestType::GET_REQUEST, "listing", next_page_url);
	}

	if (!link_header_result.empty()) {
		next_page_url = ParseNextUrlFromLinkHeader(link_header_result);
	} else {
		next_page_url = "";
	}

	return response.str();
}

static bool Match(vector<string>::const_iterator key, vector<string>::const_iterator key_end,
                  vector<string>::const_iterator pattern, vector<string>::const_iterator pattern_end) {

	while (key != key_end && pattern != pattern_end) {
		if (*pattern == "**") {
			if (std::next(pattern) == pattern_end) {
				return true;
			}
			while (key != key_end) {
				if (Match(key, key_end, std::next(pattern), pattern_end)) {
					return true;
				}
				key++;
			}
			return false;
		}
		if (!Glob(key->data(), key->length(), pattern->data(), pattern->length())) {
			return false;
		}
		key++;
		pattern++;
	}
	return key == key_end && pattern == pattern_end;
}

struct HFListResultParser {
public:
	enum class EntryType : uint8_t { FILE, DIRECTORY, UNKNOWN };

public:
	HFListResultParser(const string &input_p, vector<string> &files_p, vector<string> &directories_p)
	    : input(input_p), files(files_p), directories(directories_p) {
	}

public:
	static void Parse(const string &input, vector<string> &files, vector<string> &directories) {
		HFListResultParser(input, files, directories).ParseEntries();
	}

private:
	void ParseEntries() {
		while (SeekEntry()) {
			ParseEntry();
		}
	}

	bool SeekEntry() {
		position = input.find('{', position);
		if (position == string::npos) {
			return false;
		}
		position++;
		return true;
	}

	void ParseEntry() {
		idx_t nested = 0;
		EntryType type = EntryType::UNKNOWN;
		optional_idx path_position;
		string path;
		while (position < input.size()) {
			if (input[position] == '}') {
				position++;
				if (nested > 0) {
					nested--;
					continue;
				}
				AppendEntry(type, path_position, path);
				return;
			}
			if (input[position] == '{') {
				nested++;
				position++;
			} else if (Consume("\"type\":\"directory\"")) {
				type = EntryType::DIRECTORY;
			} else if (Consume("\"type\":\"file\"")) {
				type = EntryType::FILE;
			} else if (Consume("\"path\":\"")) {
				path_position = position;
				path = ParseString();
			} else {
				position++;
			}
		}
	}

	bool Consume(const string &token) {
		if (input.compare(position, token.size(), token) != 0) {
			return false;
		}
		position += token.size();
		return true;
	}

	string ParseString() {
		string result;
		while (position < input.size()) {
			if (input[position] == '"') {
				position++;
				return result;
			}
			if (input[position] == '\\' && position + 1 < input.size() &&
			    (input[position + 1] == '"' || input[position + 1] == '\\')) {
				result += input[position + 1];
				position += 2;
				continue;
			}
			result += input[position++];
		}
		return result;
	}

	void AppendEntry(EntryType type, optional_idx path_position, const string &path) {
		if (!path_position.IsValid() || type == EntryType::UNKNOWN) {
			throw IOException("Failed to parse list result");
		}
		if (type == EntryType::FILE) {
			files.push_back("/" + path);
		} else {
			directories.push_back("/" + path);
		}
	}

private:
	const string &input;
	vector<string> &files;
	vector<string> &directories;
	idx_t position = 0;
};

void HuggingFaceFileSystem::ParseListResult(const string &input, vector<string> &files, vector<string> &directories) {
	HFListResultParser::Parse(input, files, directories);
}

// Some valid example Urls:
// - hf://datasets/lhoestq/demo1/default/train/0000.parquet
// - hf://datasets/lhoestq/demo1/default/train/*.parquet
// - hf://datasets/lhoestq/demo1/*/train/file_[abc].parquet
// - hf://datasets/lhoestq/demo1/**/train/*.parquet
vector<OpenFileInfo> HuggingFaceFileSystem::Glob(const string &path, FileOpener *opener) {
	// Ensure the glob pattern is a valid HF url
	auto parsed_glob_url = HFUrlParse(path);
	auto first_wildcard_pos = parsed_glob_url.path.find_first_of("*[\\");

	if (first_wildcard_pos == string::npos) {
		return {path};
	}

	string shared_path = parsed_glob_url.path.substr(0, first_wildcard_pos);
	auto last_path_slash = shared_path.find_last_of('/', first_wildcard_pos);

	// trim the final
	if (last_path_slash == string::npos) {
		// Root path
		shared_path = "";
	} else {
		shared_path = shared_path.substr(0, last_path_slash);
	}

	FileOpenerInfo info;
	info.file_path = path;
	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	auto &http_params = params->Cast<HTTPFSParams>();
	SetParams(http_params, path, opener);
	ParsedHFUrl curr_hf_path = parsed_glob_url;
	curr_hf_path.path = shared_path;

	vector<string> files;
	vector<string> dirs = {shared_path};
	string next_page_url = "";

	// Loop over the paths and paginated responses for each path
	while (true) {
		if (next_page_url.empty() && !dirs.empty()) {
			// Done with previous dir, load the next one
			curr_hf_path.path = dirs.back();
			dirs.pop_back();
			next_page_url = HuggingFaceFileSystem::GetTreeUrl(curr_hf_path, http_params.hf_max_per_page);
		} else if (next_page_url.empty()) {
			// No more pages to read, also no more dirs
			break;
		}

		auto response_str = ListHFRequest(curr_hf_path, http_params, next_page_url);
		ParseListResult(response_str, files, dirs);
	}

	vector<string> pattern_splits = StringUtil::Split(parsed_glob_url.path, "/");
	vector<OpenFileInfo> result;
	for (const auto &file : files) {

		vector<string> file_splits = StringUtil::Split(file, "/");
		bool is_match = Match(file_splits.begin(), file_splits.end(), pattern_splits.begin(), pattern_splits.end());

		if (is_match) {
			curr_hf_path.path = file;
			result.push_back(GetHFUrl(curr_hf_path));
		}
	}

	// Prune files using match
	return result;
}

unique_ptr<HTTPResponse> HuggingFaceFileSystem::HeadRequest(FileHandle &handle, const string &hf_url,
                                                            HTTPHeaders header_map) {
	auto &hf_handle = handle.Cast<HFFileHandle>();
	auto http_url = HuggingFaceFileSystem::GetFileUrl(hf_handle.parsed_url);
	return HTTPFileSystem::HeadRequest(handle, http_url, header_map);
}

unique_ptr<HTTPResponse> HuggingFaceFileSystem::GetRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
                                                           const HTTPReadConfig &read_config,
                                                           CachedFileDownload &download) {
	auto &hf_handle = handle.Cast<HFFileHandle>();
	auto http_url = HuggingFaceFileSystem::GetFileUrl(hf_handle.parsed_url);
	return HTTPFileSystem::GetRequest(handle, http_url, header_map, read_config, download);
}

unique_ptr<HTTPResponse> HuggingFaceFileSystem::GetRangeRequest(FileHandle &handle, string s3_url,
                                                                HTTPHeaders header_map,
                                                                const HTTPReadConfig &read_config, idx_t file_offset,
                                                                data_ptr_t buffer_out, idx_t buffer_out_len) {
	auto &hf_handle = handle.Cast<HFFileHandle>();
	auto http_url = HuggingFaceFileSystem::GetFileUrl(hf_handle.parsed_url);
	return HTTPFileSystem::GetRangeRequest(handle, http_url, header_map, read_config, file_offset, buffer_out,
	                                       buffer_out_len);
}

unique_ptr<HTTPFileHandle> HuggingFaceFileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                               optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	auto parsed_url = HFUrlParse(file.path);

	FileOpenerInfo info;
	info.file_path = file.path;

	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	SetParams(params->Cast<HTTPFSParams>(), file.path, opener);

	return make_uniq<HFFileHandle>(*this, std::move(parsed_url), file, flags, std::move(params));
}

void HuggingFaceFileSystem::SetParams(HTTPFSParams &params, const string &path, optional_ptr<FileOpener> opener) {
	auto secret_manager = FileOpener::TryGetSecretManager(opener);
	auto transaction = FileOpener::TryGetCatalogTransaction(opener);
	if (secret_manager && transaction) {
		auto secret_match = secret_manager->LookupSecret(*transaction, path, "huggingface");

		if (secret_match.HasMatch()) {
			const auto &kv_secret = secret_match.secret_entry->secret->Cast<KeyValueSecret>();
			params.bearer_token = kv_secret.TryGetValue("token", true).ToString();
		}
	}
}

static void ThrowParseError(const string &url) {
	throw IOException(
	    "Failed to parse '%s'. Please format url like: 'hf://datasets/my-username/my-dataset/path/to/file.parquet'",
	    url);
}

ParsedHFUrl HuggingFaceFileSystem::HFUrlParse(const string &url) {
	ParsedHFUrl result;

	if (!StringUtil::StartsWith(url, "hf://")) {
		throw InternalException("Not an hf url");
	}

	idx_t last_delim = 5;
	idx_t curr_delim;

	// Parse Repository type
	curr_delim = url.find('/', last_delim);
	if (curr_delim == string::npos) {
		ThrowParseError(url);
	}
	result.repo_type = url.substr(last_delim, curr_delim - last_delim);
	if (result.repo_type != "datasets" && result.repo_type != "spaces") {
		throw IOException(
		    "Failed to parse: '%s'. Currently DuckDB only supports querying datasets or spaces, so the url should "
		    "start with 'hf://datasets' or 'hf://spaces'",
		    url);
	}

	last_delim = curr_delim;

	// Parse repository and revision
	auto repo_delim = url.find('/', last_delim + 1);
	if (repo_delim == string::npos) {
		ThrowParseError(url);
	}

	auto next_at = url.find('@', repo_delim + 1);
	auto next_slash = url.find('/', repo_delim + 1);

	if (next_slash == string::npos) {
		ThrowParseError(url);
	}

	if (next_at != string::npos && next_at < next_slash) {
		result.repository = url.substr(last_delim + 1, next_at - last_delim - 1);
		result.revision = url.substr(next_at + 1, next_slash - next_at - 1);
	} else {
		result.repository = url.substr(last_delim + 1, next_slash - last_delim - 1);
	}
	last_delim = next_slash;

	// The remainder is the path
	result.path = url.substr(last_delim);

	return result;
}

string HuggingFaceFileSystem::GetHFUrl(const ParsedHFUrl &url) {
	if (url.revision == "main") {
		return "hf://" + url.repo_type + "/" + url.repository + url.path;
	} else {
		return "hf://" + url.repo_type + "/" + url.repository + "@" + url.revision + url.path;
	}
}

string HuggingFaceFileSystem::GetTreeUrl(const ParsedHFUrl &url, idx_t limit) {
	//! Url format {endpoint}/api/{repo_type}/{repository}/tree/{revision}{encoded_path_in_repo}
	string http_url = url.endpoint;

	http_url = JoinHFPath(http_url, "api");
	http_url = JoinHFPath(http_url, url.repo_type);
	http_url = JoinHFPath(http_url, url.repository);
	http_url = JoinHFPath(http_url, "tree");
	http_url = JoinHFPath(http_url, url.revision);
	http_url += url.path;

	if (limit > 0) {
		http_url += "?limit=" + to_string(limit);
	}

	return http_url;
}

string HuggingFaceFileSystem::GetFileUrl(const ParsedHFUrl &url) {
	//! Url format {endpoint}/{repo_type}[/{repository}/{revision}{encoded_path_in_repo}
	string http_url = url.endpoint;
	http_url = JoinHFPath(http_url, url.repo_type);
	http_url = JoinHFPath(http_url, url.repository);
	http_url = JoinHFPath(http_url, "resolve");
	http_url = JoinHFPath(http_url, url.revision);
	http_url += url.path;

	return http_url;
}

} // namespace duckdb
