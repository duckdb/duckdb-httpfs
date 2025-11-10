#include "webdavfs.hpp"

#include "crypto.hpp"
#include "duckdb.hpp"
#ifndef DUCKDB_AMALGAMATION
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "http_state.hpp"
#endif

#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar/string_common.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "httpfs_client.hpp"

#include <fstream>
#include <cstdlib>
#include <unistd.h>

namespace duckdb {

WebDAVFileHandle::~WebDAVFileHandle() = default;

void WebDAVFileHandle::Close() {
}

void WebDAVFileHandle::Initialize(optional_ptr<FileOpener> opener) {
	HTTPFileHandle::Initialize(opener);
}

unique_ptr<HTTPClient> WebDAVFileHandle::CreateClient() {
	return http_params.http_util.InitializeClient(http_params, path);
}

WebDAVAuthParams WebDAVAuthParams::ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info) {
	WebDAVAuthParams params;

	if (!opener) {
		return params;
	}

	KeyValueSecretReader secret_reader(*opener, &info, "webdav");
	secret_reader.TryGetSecretKey("username", params.username);
	secret_reader.TryGetSecretKey("password", params.password);

	return params;
}

string ParsedWebDAVUrl::GetHTTPUrl() const {
	return http_proto + "://" + host + path;
}

ParsedWebDAVUrl WebDAVFileSystem::ParseUrl(const string &url) {
	ParsedWebDAVUrl result;

	// Check for storagebox:// protocol (Hetzner Storage Box shorthand)
	if (StringUtil::StartsWith(url, "storagebox://")) {
		result.http_proto = "https";
		// Extract username and path from storagebox://u123456/path/to/file
		string remainder = url.substr(13); // Skip "storagebox://"

		auto slash_pos = remainder.find('/');
		string username;
		if (slash_pos != string::npos) {
			username = remainder.substr(0, slash_pos);
			result.path = remainder.substr(slash_pos);
		} else {
			username = remainder;
			result.path = "/";
		}

		// Build the Hetzner Storage Box hostname
		result.host = username + ".your-storagebox.de";
		return result;
	}

	// Check for webdav:// or webdavs:// protocol
	if (StringUtil::StartsWith(url, "webdav://")) {
		result.http_proto = "http";
		result.host = url.substr(9);
	} else if (StringUtil::StartsWith(url, "webdavs://")) {
		result.http_proto = "https";
		result.host = url.substr(10);
	} else if (StringUtil::StartsWith(url, "https://")) {
		result.http_proto = "https";
		result.host = url.substr(8);
	} else if (StringUtil::StartsWith(url, "http://")) {
		result.http_proto = "http";
		result.host = url.substr(7);
	} else {
		throw IOException("Invalid WebDAV URL: %s", url);
	}

	// Split host and path
	auto slash_pos = result.host.find('/');
	if (slash_pos != string::npos) {
		result.path = result.host.substr(slash_pos);
		result.host = result.host.substr(0, slash_pos);
	} else {
		result.path = "/";
	}

	return result;
}

string WebDAVFileSystem::Base64Encode(const string &input) {
	const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	string result;
	int val = 0;
	int valb = -6;

	for (unsigned char c : input) {
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			result.push_back(base64_chars[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}

	if (valb > -6) {
		result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
	}

	while (result.size() % 4) {
		result.push_back('=');
	}

	return result;
}

// Custom HTTP request using HTTP client infrastructure
duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::CustomRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                                 const string &method, char *buffer_in,
                                                                 idx_t buffer_in_len) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	auto &http_util = wfh.http_params.http_util;

	// Store the method in extra headers as a hint for custom processing
	auto &http_params = wfh.http_params;
	auto original_extra_headers = http_params.extra_headers;
	http_params.extra_headers["X-DuckDB-HTTP-Method"] = method;

	// Create POST request
	PostRequestInfo post_request(url, header_map, http_params, const_data_ptr_cast(buffer_in), buffer_in_len);
	auto result = http_util.Request(post_request);

	// Copy the response body to the result
	if (result) {
		result->body = std::move(post_request.buffer_out);
	}

	// Restore headers
	http_params.extra_headers = original_extra_headers;

	return result;
}

string WebDAVFileSystem::DirectPropfindRequest(const string &url, const WebDAVAuthParams &auth_params, int depth) {
	// We need a file handle to make HTTP requests through the proper infrastructure
	// Since we're being called from Glob which has an opener, we should create a temporary handle
	// For now, we'll return empty and the caller should handle creating the handle properly
	return "";
}

void WebDAVFileSystem::AddAuthHeaders(HTTPHeaders &headers, const WebDAVAuthParams &auth_params) {
	if (!auth_params.username.empty() || !auth_params.password.empty()) {
		string credentials = auth_params.username + ":" + auth_params.password;
		string encoded = Base64Encode(credentials);
		headers["Authorization"] = "Basic " + encoded;
	}
}

string WebDAVFileSystem::GetName() const {
	return "WebDAVFileSystem";
}

bool WebDAVFileSystem::IsWebDAVUrl(const string &url) {
	// Check for storagebox:// protocol (Hetzner Storage Box shorthand)
	if (StringUtil::StartsWith(url, "storagebox://")) {
		return true;
	}
	// Check for explicit WebDAV protocol
	if (StringUtil::StartsWith(url, "webdav://") || StringUtil::StartsWith(url, "webdavs://")) {
		return true;
	}
	// Check for Hetzner Storage Box URLs (these use WebDAV)
	if (url.find(".your-storagebox.de/") != string::npos) {
		return true;
	}
	return false;
}

bool WebDAVFileSystem::CanHandleFile(const string &fpath) {
	return IsWebDAVUrl(fpath);
}

duckdb::unique_ptr<HTTPFileHandle> WebDAVFileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                                  optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	// First, read auth params using ORIGINAL URL for secret matching
	// This is critical for proper secret scoping - secrets are scoped to storagebox:// URLs,
	// not the converted https:// URLs
	FileOpenerInfo info;
	info.file_path = file.path; // Use ORIGINAL URL (e.g., storagebox://u507042/file.parquet)
	auto auth_params = WebDAVAuthParams::ReadFrom(opener, info);

	// Parse and convert the URL for actual HTTP operations (e.g., storagebox:// -> https://)
	auto parsed_url = ParseUrl(file.path);
	string converted_url = parsed_url.GetHTTPUrl();

	// Create a modified file info with the converted URL for HTTP operations
	OpenFileInfo converted_file = file;
	converted_file.path = converted_url;

	auto params = HTTPFSUtil::GetHTTPUtil(opener)->InitializeParameters(opener, &info);
	auto http_params_p = dynamic_cast<HTTPFSParams *>(params.get());
	if (!http_params_p) {
		throw InternalException("Failed to cast HTTP params");
	}

	return make_uniq<WebDAVFileHandle>(*this, converted_file, flags, std::move(params), auth_params);
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::PropfindRequest(FileHandle &handle, string url,
                                                                   HTTPHeaders header_map, int depth) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);
	header_map["Depth"] = to_string(depth);
	header_map["Content-Type"] = "application/xml; charset=utf-8";

	// Basic PROPFIND request body
	string propfind_body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
	                       "<D:propfind xmlns:D=\"DAV:\">"
	                       "<D:prop>"
	                       "<D:resourcetype/>"
	                       "<D:getcontentlength/>"
	                       "<D:getlastmodified/>"
	                       "</D:prop>"
	                       "</D:propfind>";

	// Use CustomRequest which sets up PROPFIND properly
	return CustomRequest(handle, url, header_map, "PROPFIND", const_cast<char *>(propfind_body.c_str()),
	                     propfind_body.size());
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::MkcolRequest(FileHandle &handle, string url,
                                                                HTTPHeaders header_map) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);

	// Use PUT request with a trailing slash to create directory
	// This is a workaround since we don't have a MKCOL request type
	return PutRequest(handle, url, header_map, nullptr, 0, "");
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::HeadRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);
	return HTTPFileSystem::HeadRequest(handle, url, header_map);
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::GetRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);
	return HTTPFileSystem::GetRequest(handle, url, header_map);
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::GetRangeRequest(FileHandle &handle, string url,
                                                                   HTTPHeaders header_map, idx_t file_offset,
                                                                   char *buffer_out, idx_t buffer_out_len) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);
	return HTTPFileSystem::GetRangeRequest(handle, url, header_map, file_offset, buffer_out, buffer_out_len);
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::PutRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                              char *buffer_in, idx_t buffer_in_len, string params) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);
	return HTTPFileSystem::PutRequest(handle, url, header_map, buffer_in, buffer_in_len, params);
}

duckdb::unique_ptr<HTTPResponse> WebDAVFileSystem::DeleteRequest(FileHandle &handle, string url,
                                                                 HTTPHeaders header_map) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	AddAuthHeaders(header_map, wfh.auth_params);
	return HTTPFileSystem::DeleteRequest(handle, url, header_map);
}

void WebDAVFileSystem::RemoveFile(const string &filename, optional_ptr<FileOpener> opener) {
	auto parsed_url = ParseUrl(filename);
	string http_url = parsed_url.GetHTTPUrl();

	FileOpenerInfo info;
	info.file_path = filename;
	auto auth_params = WebDAVAuthParams::ReadFrom(opener, info);

	// Create a temporary handle for the delete operation
	OpenFileInfo file_info;
	file_info.path = filename;
	auto handle = CreateHandle(file_info, FileOpenFlags::FILE_FLAGS_READ, opener);
	handle->Initialize(opener);

	HTTPHeaders headers;
	auto response = DeleteRequest(*handle, http_url, headers);

	if (response->status != HTTPStatusCode::OK_200 && response->status != HTTPStatusCode::NoContent_204 &&
	    response->status != HTTPStatusCode::Accepted_202) {
		throw IOException("Failed to delete file %s: HTTP %d", filename, static_cast<int>(response->status));
	}
}

void WebDAVFileSystem::MoveFile(const string &source, const string &target, optional_ptr<FileOpener> opener) {
	// WebDAV doesn't support atomic move, so we implement it as copy + delete
	// For large files, this could be inefficient, but it works

	// Parse both URLs
	auto source_parsed = ParseUrl(source);
	auto target_parsed = ParseUrl(target);
	string source_http_url = source_parsed.GetHTTPUrl();
	string target_http_url = target_parsed.GetHTTPUrl();

	// Read the source file
	OpenFileInfo source_file;
	source_file.path = source;
	auto source_handle = CreateHandle(source_file, FileOpenFlags::FILE_FLAGS_READ, opener);
	source_handle->Initialize(opener);

	// Read all data from source
	auto file_size = source_handle->length;
	auto buffer = make_unsafe_uniq_array<char>(file_size);
	source_handle->Read(buffer.get(), file_size, 0);

	// Write to target
	OpenFileInfo target_file;
	target_file.path = target;
	FileOpenFlags write_flags;
	write_flags = FileOpenFlags::FILE_FLAGS_WRITE;
	auto target_handle = CreateHandle(target_file, write_flags, opener);

	HTTPHeaders headers;
	auto response = PutRequest(*target_handle, target_http_url, headers, buffer.get(), file_size, "");

	if (response->status != HTTPStatusCode::OK_200 && response->status != HTTPStatusCode::Created_201 &&
	    response->status != HTTPStatusCode::NoContent_204) {
		throw IOException("Failed to write target file %s during move: HTTP %d", target,
		                  static_cast<int>(response->status));
	}

	// Delete source file
	RemoveFile(source, opener);
}

void WebDAVFileSystem::CreateDirectory(const string &directory, optional_ptr<FileOpener> opener) {
	auto parsed_url = ParseUrl(directory);
	string http_url = parsed_url.GetHTTPUrl();

	// Ensure the URL ends with a slash for directory creation
	if (!StringUtil::EndsWith(http_url, "/")) {
		http_url += "/";
	}

	FileOpenerInfo info;
	info.file_path = directory;
	auto auth_params = WebDAVAuthParams::ReadFrom(opener, info);

	// Create a temporary handle for the MKCOL operation
	OpenFileInfo file_info;
	file_info.path = directory;
	auto handle = CreateHandle(file_info, FileOpenFlags::FILE_FLAGS_READ, opener);
	handle->Initialize(opener);

	HTTPHeaders headers;
	auto response = MkcolRequest(*handle, http_url, headers);

	if (response->status != HTTPStatusCode::Created_201 && response->status != HTTPStatusCode::OK_200 &&
	    response->status != HTTPStatusCode::NoContent_204) {
		// Directory might already exist
		if (response->status != HTTPStatusCode::MethodNotAllowed_405) {
			throw IOException("Failed to create directory %s: HTTP %d", directory, static_cast<int>(response->status));
		}
	}
}

void WebDAVFileSystem::RemoveDirectory(const string &directory, optional_ptr<FileOpener> opener) {
	RemoveFile(directory, opener);
}

bool WebDAVFileSystem::DirectoryExists(const string &directory, optional_ptr<FileOpener> opener) {
	auto parsed_url = ParseUrl(directory);
	string http_url = parsed_url.GetHTTPUrl();

	if (!StringUtil::EndsWith(http_url, "/")) {
		http_url += "/";
	}

	FileOpenerInfo info;
	info.file_path = directory;

	// Create a temporary handle for the HEAD operation
	OpenFileInfo file_info;
	file_info.path = directory;
	auto handle = CreateHandle(file_info, FileOpenFlags::FILE_FLAGS_READ, opener);
	handle->Initialize(opener);

	HTTPHeaders headers;
	auto response = HeadRequest(*handle, http_url, headers);

	return response->status == HTTPStatusCode::OK_200 || response->status == HTTPStatusCode::NoContent_204;
}

void WebDAVFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &wfh = handle.Cast<WebDAVFileHandle>();
	auto parsed_url = ParseUrl(wfh.path);
	string http_url = parsed_url.GetHTTPUrl();

	HTTPHeaders headers;
	auto response = PutRequest(handle, http_url, headers, static_cast<char *>(buffer), nr_bytes, "");

	if (response->status != HTTPStatusCode::OK_200 && response->status != HTTPStatusCode::Created_201 &&
	    response->status != HTTPStatusCode::NoContent_204) {
		throw IOException("Failed to write to file %s: HTTP %d", wfh.path, static_cast<int>(response->status));
	}

	wfh.file_offset += nr_bytes;
}

void WebDAVFileSystem::FileSync(FileHandle &handle) {
	// WebDAV PUT is synchronous, so no additional sync needed
}

// Helper function to parse XML and extract file paths from PROPFIND response
static vector<OpenFileInfo> ParsePropfindResponse(const string &xml_response, const string &base_path) {
	vector<OpenFileInfo> result;

	// Simple XML parsing - look for <D:href> or <href> tags
	// WebDAV PROPFIND responses contain <response> elements with <href> child elements
	size_t pos = 0;
	while ((pos = xml_response.find("<D:href>", pos)) != string::npos ||
	       (pos = xml_response.find("<href>", pos)) != string::npos) {

		string tag_open = xml_response.substr(pos, 8) == "<D:href>" ? "<D:href>" : "<href>";
		string tag_close = tag_open == "<D:href>" ? "</D:href>" : "</href>";

		size_t start = pos + tag_open.length();
		size_t end = xml_response.find(tag_close, start);

		if (end == string::npos) {
			break;
		}

		string href = xml_response.substr(start, end - start);

		// URL decode the href
		string decoded_href;
		for (size_t i = 0; i < href.length(); i++) {
			if (href[i] == '%' && i + 2 < href.length()) {
				string hex = href.substr(i + 1, 2);
				char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
				decoded_href += ch;
				i += 2;
			} else {
				decoded_href += href[i];
			}
		}

		// Skip the directory itself (entries ending with /)
		if (!StringUtil::EndsWith(decoded_href, "/")) {
			// Extract just the path portion (remove any host/port prefix)
			// WebDAV servers often return absolute paths like /path/to/file
			OpenFileInfo info;
			info.path = decoded_href;
			result.push_back(info);
		}

		pos = end + tag_close.length();
	}

	return result;
}

// Pattern matching helper (similar to S3)
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

vector<OpenFileInfo> WebDAVFileSystem::Glob(const string &glob_pattern, FileOpener *opener) {
	if (!opener) {
		// Without an opener, we can't authenticate, so just return the pattern
		return {glob_pattern};
	}

	// Parse the WebDAV URL
	auto parsed_url = ParseUrl(glob_pattern);
	string path = parsed_url.path;

	// Find the first wildcard character
	auto first_wildcard_pos = path.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		// No wildcards, return as-is
		return {glob_pattern};
	}

	// Extract the shared prefix path (up to the last '/' before the wildcard)
	auto last_slash_before_wildcard = path.rfind('/', first_wildcard_pos);
	string prefix_path;
	if (last_slash_before_wildcard != string::npos) {
		prefix_path = path.substr(0, last_slash_before_wildcard + 1);
	} else {
		prefix_path = "/";
	}

	// Construct the base URL for listing
	string list_url_pattern = parsed_url.http_proto + "://" + parsed_url.host + prefix_path;

	// Create a file handle for the PROPFIND request
	// Use a non-wildcard path to avoid recursive file opening
	FileOpenerInfo info;
	string non_wildcard_path;
	if (StringUtil::StartsWith(glob_pattern, "storagebox://")) {
		// Extract the username from the original pattern
		string remainder = glob_pattern.substr(13);
		auto slash_pos = remainder.find('/');
		string username = remainder.substr(0, slash_pos);
		non_wildcard_path = "storagebox://" + username + prefix_path;
	} else if (StringUtil::StartsWith(glob_pattern, "webdav://")) {
		non_wildcard_path = "webdav://" + parsed_url.host + prefix_path;
	} else if (StringUtil::StartsWith(glob_pattern, "webdavs://")) {
		non_wildcard_path = "webdavs://" + parsed_url.host + prefix_path;
	} else {
		non_wildcard_path = parsed_url.http_proto + "://" + parsed_url.host + prefix_path;
	}

	info.file_path = non_wildcard_path;

	OpenFileInfo file_info;
	file_info.path = non_wildcard_path;

	unique_ptr<WebDAVFileHandle> handle;
	try {
		auto base_handle = CreateHandle(file_info, FileOpenFlags::FILE_FLAGS_READ, opener);
		handle = unique_ptr_cast<HTTPFileHandle, WebDAVFileHandle>(std::move(base_handle));
		handle->Initialize(opener);
	} catch (HTTPException &e) {
		// If we can't create a handle, return empty result
		return {};
	}

	// Make PROPFIND request to list files
	// Note: We use depth=1 and recursively explore subdirectories
	HTTPHeaders headers;
	auto response = PropfindRequest(*handle, list_url_pattern, headers, 1);

	// WebDAV PROPFIND should return 207 Multi-Status
	// Some servers might return 200 OK
	if (!response ||
	    (response->status != HTTPStatusCode::MultiStatus_207 && response->status != HTTPStatusCode::OK_200)) {
		// PROPFIND failed, return empty result
		return {};
	}

	// Check if we got any response body
	if (response->body.empty()) {
		return {};
	}

	// Parse the XML response
	auto files = ParsePropfindResponse(response->body, prefix_path);
	string response_body = response->body;

	// For depth=1, we need to recursively explore subdirectories
	// Collect all subdirectories from the response
	vector<string> subdirs;
	size_t pos = 0;
	while ((pos = response_body.find("<D:href>", pos)) != string::npos ||
	       (pos = response_body.find("<href>", pos)) != string::npos) {

		string tag_open = response_body.substr(pos, 8) == "<D:href>" ? "<D:href>" : "<href>";
		string tag_close = tag_open == "<D:href>" ? "</D:href>" : "</href>";

		size_t start = pos + tag_open.length();
		size_t end = response_body.find(tag_close, start);

		if (end == string::npos) {
			break;
		}

		string href = response_body.substr(start, end - start);

		// URL decode
		string decoded_href;
		for (size_t i = 0; i < href.length(); i++) {
			if (href[i] == '%' && i + 2 < href.length()) {
				string hex = href.substr(i + 1, 2);
				char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
				decoded_href += ch;
				i += 2;
			} else {
				decoded_href += href[i];
			}
		}

		// This is a directory if it ends with /
		if (StringUtil::EndsWith(decoded_href, "/") && decoded_href != prefix_path) {
			string subdir_url = parsed_url.http_proto + "://" + parsed_url.host + decoded_href;
			subdirs.push_back(subdir_url);
		}

		pos = end + tag_close.length();
	}

	// Recursively list subdirectories
	for (const auto &subdir_url : subdirs) {
		auto subdir_response = PropfindRequest(*handle, subdir_url, headers, 1);
		if (subdir_response && (subdir_response->status == HTTPStatusCode::MultiStatus_207 ||
		                        subdir_response->status == HTTPStatusCode::OK_200)) {
			auto subdir_files = ParsePropfindResponse(subdir_response->body, prefix_path);
			files.insert(files.end(), subdir_files.begin(), subdir_files.end());
		}
	}

	// Match the pattern against the file paths
	vector<string> pattern_splits = StringUtil::Split(path, "/");
	vector<OpenFileInfo> result;

	for (auto &file_info : files) {
		// Extract the path component from the href
		string file_path = file_info.path;

		// Remove any leading protocol/host if present
		size_t path_start = file_path.find(parsed_url.host);
		if (path_start != string::npos) {
			file_path = file_path.substr(path_start + parsed_url.host.length());
		}

		vector<string> key_splits = StringUtil::Split(file_path, "/");
		bool is_match = Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end());

		if (is_match) {
			// Reconstruct the full URL with the original protocol
			string full_url;
			if (StringUtil::StartsWith(glob_pattern, "storagebox://")) {
				// Extract the username from the original pattern
				string remainder = glob_pattern.substr(13);
				auto slash_pos = remainder.find('/');
				string username = remainder.substr(0, slash_pos);
				full_url = "storagebox://" + username + file_path;
			} else if (StringUtil::StartsWith(glob_pattern, "webdav://")) {
				full_url = "webdav://" + parsed_url.host + file_path;
			} else if (StringUtil::StartsWith(glob_pattern, "webdavs://")) {
				full_url = "webdavs://" + parsed_url.host + file_path;
			} else {
				full_url = parsed_url.http_proto + "://" + parsed_url.host + file_path;
			}

			file_info.path = full_url;
			result.push_back(file_info);
		}
	}

	return result;
}

bool WebDAVFileSystem::ListFiles(const string &directory, const std::function<void(const string &, bool)> &callback,
                                 FileOpener *opener) {
	string trimmed_dir = directory;
	// Remove trailing slash if present
	if (StringUtil::EndsWith(trimmed_dir, "/")) {
		trimmed_dir = trimmed_dir.substr(0, trimmed_dir.length() - 1);
	}

	// Use Glob with ** pattern to list all files recursively
	auto glob_res = Glob(trimmed_dir + "/**", opener);

	if (glob_res.empty()) {
		return false;
	}

	for (const auto &file : glob_res) {
		callback(file.path, false);
	}

	return true;
}

HTTPException WebDAVFileSystem::GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url) {
	auto status_message = HTTPUtil::GetStatusMessage(response.status);
	string error = "WebDAV error on '" + url + "' (HTTP " + to_string(static_cast<int>(response.status)) + " " +
	               status_message + ")";
	return HTTPException(response, error);
}

} // namespace duckdb
