#include "httpfs.hpp"

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "http_state.hpp"

#include <chrono>
#include <map>
#include <string>
#include <thread>

namespace duckdb {

shared_ptr<HTTPUtil> HTTPFSUtil::GetHTTPUtil(optional_ptr<FileOpener> opener) {
	if (opener) {
		return opener->GetHTTPUtil();
	}
	throw InternalException("FileOpener not provided, can't get HTTPUtil");
}

unique_ptr<HTTPParams> HTTPFSUtil::InitializeParameters(optional_ptr<FileOpener> opener,
                                                        optional_ptr<FileOpenerInfo> info) {
	auto result = make_uniq<HTTPFSParams>(*this);
	result->Initialize(opener);

	// No point in continueing without an opener
	if (!opener) {
		return std::move(result);
	}

	Value value;

	// Setting lookups
	FileOpener::TryGetCurrentSetting(opener, "http_timeout", result->timeout, info);
	FileOpener::TryGetCurrentSetting(opener, "force_download", result->force_download, info);
	FileOpener::TryGetCurrentSetting(opener, "http_retries", result->retries, info);
	FileOpener::TryGetCurrentSetting(opener, "http_retry_wait_ms", result->retry_wait_ms, info);
	FileOpener::TryGetCurrentSetting(opener, "http_retry_backoff", result->retry_backoff, info);
	FileOpener::TryGetCurrentSetting(opener, "http_keep_alive", result->keep_alive, info);
	FileOpener::TryGetCurrentSetting(opener, "enable_server_cert_verification", result->enable_server_cert_verification,
	                                 info);
	FileOpener::TryGetCurrentSetting(opener, "ca_cert_file", result->ca_cert_file, info);
	FileOpener::TryGetCurrentSetting(opener, "hf_max_per_page", result->hf_max_per_page, info);

	// HTTP Secret lookups
	KeyValueSecretReader settings_reader(*opener, info, "http");

	string proxy_setting;
	if (settings_reader.TryGetSecretKey<string>("http_proxy", proxy_setting) && !proxy_setting.empty()) {
		idx_t port;
		string host;
		HTTPUtil::ParseHTTPProxyHost(proxy_setting, host, port);
		result->http_proxy = host;
		result->http_proxy_port = port;
	}
	settings_reader.TryGetSecretKey<string>("http_proxy_username", result->http_proxy_username);
	settings_reader.TryGetSecretKey<string>("http_proxy_password", result->http_proxy_password);
	settings_reader.TryGetSecretKey<string>("bearer_token", result->bearer_token);

	Value extra_headers;
	if (settings_reader.TryGetSecretKey("extra_http_headers", extra_headers)) {
		auto children = MapValue::GetChildren(extra_headers);
		for (const auto &child : children) {
			auto kv = StructValue::GetChildren(child);
			D_ASSERT(kv.size() == 2);
			result->extra_headers[kv[0].GetValue<string>()] = kv[1].GetValue<string>();
		}
	}

	return std::move(result);
}

unique_ptr<HTTPClient> HTTPClientCache::GetClient() {
	lock_guard<mutex> lck(lock);
	if (clients.size() == 0) {
		return nullptr;
	}

	auto client = std::move(clients.back());
	clients.pop_back();
	return client;
}

void HTTPClientCache::StoreClient(unique_ptr<HTTPClient> client) {
	lock_guard<mutex> lck(lock);
	clients.push_back(std::move(client));
}

unique_ptr<HTTPResponse> HTTPFileSystem::PostRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                     string &buffer_out, char *buffer_in, idx_t buffer_in_len,
                                                     string params) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto &http_util = hfh.http_params.http_util;
	PostRequestInfo post_request(url, header_map, hfh.http_params, const_data_ptr_cast(buffer_in), buffer_in_len);
	auto result = http_util.Request(post_request);
	buffer_out = std::move(post_request.buffer_out);
	return result;
}

unique_ptr<HTTPResponse> HTTPFileSystem::PutRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                    char *buffer_in, idx_t buffer_in_len, string params) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto &http_util = hfh.http_params.http_util;
	string content_type = "application/octet-stream";
	PutRequestInfo put_request(url, header_map, hfh.http_params, (const_data_ptr_t)buffer_in, buffer_in_len,
	                           content_type);
	return http_util.Request(put_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::HeadRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto &http_util = hfh.http_params.http_util;
	auto http_client = hfh.GetClient();

	HeadRequestInfo head_request(url, header_map, hfh.http_params);
	auto response = http_util.Request(head_request, http_client);

	hfh.StoreClient(std::move(http_client));
	return response;
}

unique_ptr<HTTPResponse> HTTPFileSystem::DeleteRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto &http_util = hfh.http_params.http_util;
	auto http_client = hfh.GetClient();
	DeleteRequestInfo delete_request(url, header_map, hfh.http_params);
	auto response = http_util.Request(delete_request, http_client);

	hfh.StoreClient(std::move(http_client));
	return response;
}

HTTPException HTTPFileSystem::GetHTTPError(FileHandle &, const HTTPResponse &response, const string &url) {
	auto status_message = HTTPFSUtil::GetStatusMessage(response.status);
	string error = "HTTP GET error on '" + url + "' (HTTP " + to_string(static_cast<int>(response.status)) + " " +
	               status_message + ")";
	if (response.status == HTTPStatusCode::RangeNotSatisfiable_416) {
		error += " This could mean the file was changed. Try disabling the duckdb http metadata cache "
		         "if enabled, and confirm the server supports range requests.";
	}
	return HTTPException(response, error);
}

unique_ptr<HTTPResponse> HTTPFileSystem::GetRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto &http_util = hfh.http_params.http_util;

	D_ASSERT(hfh.cached_file_handle);

	auto http_client = hfh.GetClient();
	GetRequestInfo get_request(
	    url, header_map, hfh.http_params,
	    [&](const HTTPResponse &response) {
		    if (static_cast<int>(response.status) >= 400) {
			    string error =
			        "HTTP GET error on '" + url + "' (HTTP " + to_string(static_cast<int>(response.status)) + ")";
			    if (response.status == HTTPStatusCode::RangeNotSatisfiable_416) {
				    error += " This could mean the file was changed. Try disabling the duckdb http metadata cache "
				             "if enabled, and confirm the server supports range requests.";
			    }
			    throw HTTPException(error);
		    }
		    return true;
	    },
	    [&](const_data_ptr_t data, idx_t data_length) {
		    if (!hfh.cached_file_handle->GetCapacity()) {
			    hfh.cached_file_handle->AllocateBuffer(data_length);
			    hfh.length = data_length;
			    hfh.cached_file_handle->Write(const_char_ptr_cast(data), data_length);
		    } else {
			    auto new_capacity = hfh.cached_file_handle->GetCapacity();
			    while (new_capacity < hfh.length + data_length) {
				    new_capacity *= 2;
			    }
			    // Grow buffer when running out of space
			    if (new_capacity != hfh.cached_file_handle->GetCapacity()) {
				    hfh.cached_file_handle->GrowBuffer(new_capacity, hfh.length);
			    }
			    // We can just copy stuff
			    hfh.cached_file_handle->Write(const_char_ptr_cast(data), data_length, hfh.length);
			    hfh.length += data_length;
		    }
		    return true;
	    });

	auto response = http_util.Request(get_request, http_client);

	hfh.StoreClient(std::move(http_client));
	return response;
}

unique_ptr<HTTPResponse> HTTPFileSystem::GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                         idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto &http_util = hfh.http_params.http_util;

	// send the Range header to read only subset of file
	string range_expr = "bytes=" + to_string(file_offset) + "-" + to_string(file_offset + buffer_out_len - 1);
	header_map.Insert("Range", range_expr);

	auto http_client = hfh.GetClient();

	idx_t out_offset = 0;

	GetRequestInfo get_request(
	    url, header_map, hfh.http_params,
	    [&](const HTTPResponse &response) {
		    if (static_cast<int>(response.status) >= 400) {
			    string error =
			        "HTTP GET error on '" + url + "' (HTTP " + to_string(static_cast<int>(response.status)) + ")";
			    if (response.status == HTTPStatusCode::RangeNotSatisfiable_416) {
				    error += " This could mean the file was changed. Try disabling the duckdb http metadata cache "
				             "if enabled, and confirm the server supports range requests.";
			    }
			    throw HTTPException(response, error);
		    }
		    if (static_cast<int>(response.status) < 300) { // done redirecting
			    out_offset = 0;
			    if (response.HasHeader("Content-Length")) {
				    auto content_length = stoll(response.GetHeaderValue("Content-Length"));
				    if ((idx_t)content_length != buffer_out_len) {
					    throw HTTPException("HTTP GET error: Content-Length from server mismatches requested "
					                        "range, server may not support range requests.");
				    }
			    }
		    }
		    return true;
	    },
	    [&](const_data_ptr_t data, idx_t data_length) {
		    if (buffer_out != nullptr) {
			    if (data_length + out_offset > buffer_out_len) {
				    // As of v0.8.2-dev4424 we might end up here when very big files are served from servers
				    // that returns more data than requested via range header. This is an uncommon but legal
				    // behaviour, so we have to improve logic elsewhere to properly handle this case.

				    // To avoid corruption of memory, we bail out.
				    throw HTTPException("Server sent back more data than expected, `SET force_download=true` might "
				                        "help in this case");
			    }
			    memcpy(buffer_out + out_offset, data, data_length);
			    out_offset += data_length;
		    }
		    return true;
	    });

	auto response = http_util.Request(get_request, http_client);

	hfh.StoreClient(std::move(http_client));
	return response;
}

void TimestampToTimeT(timestamp_t timestamp, time_t &result) {
	auto components = Timestamp::GetComponents(timestamp);
	struct tm tm {};
	tm.tm_year = components.year - 1900;
	tm.tm_mon = components.month - 1;
	tm.tm_mday = components.day;
	tm.tm_hour = components.hour;
	tm.tm_min = components.minute;
	tm.tm_sec = components.second;
	tm.tm_isdst = 0;
	result = mktime(&tm);
}

HTTPFileHandle::HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                               unique_ptr<HTTPParams> params_p)
    : FileHandle(fs, file.path, flags), params(std::move(params_p)), http_params(params->Cast<HTTPFSParams>()),
      flags(flags), length(0), force_full_download(false), buffer_available(0), buffer_idx(0), file_offset(0),
      buffer_start(0), buffer_end(0) {
	// check if the handle has extended properties that can be set directly in the handle
	// if we have these properties we don't need to do a head request to obtain them later
	if (file.extended_info) {
		auto &info = file.extended_info->options;
		auto lm_entry = info.find("last_modified");
		if (lm_entry != info.end()) {
			TimestampToTimeT(lm_entry->second.GetValue<timestamp_t>(), last_modified);
		}
		auto etag_entry = info.find("etag");
		if (etag_entry != info.end()) {
			etag = StringValue::Get(etag_entry->second);
		}
		auto fs_entry = info.find("file_size");
		if (fs_entry != info.end()) {
			length = fs_entry->second.GetValue<uint64_t>();
		}
		auto force_full_download_entry = info.find("force_full_download");
		if (force_full_download_entry != info.end()) {
			force_full_download = force_full_download_entry->second.GetValue<bool>();
		}
		if (lm_entry != info.end() && etag_entry != info.end() && fs_entry != info.end()) {
			// we found all relevant entries (last_modified, etag and file size)
			// skip head request
			initialized = true;
		}
	}
}
unique_ptr<HTTPFileHandle> HTTPFileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                        optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	FileOpenerInfo info;
	info.file_path = file.path;

	auto http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util->InitializeParameters(opener, info);

	auto secret_manager = FileOpener::TryGetSecretManager(opener);
	auto transaction = FileOpener::TryGetCatalogTransaction(opener);
	if (secret_manager && transaction) {
		auto secret_match = secret_manager->LookupSecret(*transaction, file.path, "bearer");

		if (secret_match.HasMatch()) {
			const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(*secret_match.secret_entry->secret);
			auto &httpfs_params = params->Cast<HTTPFSParams>();
			httpfs_params.bearer_token = kv_secret.TryGetValue("token", true).ToString();
		}
	}
	return duckdb::make_uniq<HTTPFileHandle>(*this, file, flags, std::move(params));
}

unique_ptr<FileHandle> HTTPFileSystem::OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
                                                        optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	if (flags.ReturnNullIfNotExists()) {
		try {
			auto handle = CreateHandle(file, flags, opener);
			handle->Initialize(opener);
			return std::move(handle);
		} catch (...) {
			return nullptr;
		}
	}

	auto handle = CreateHandle(file, flags, opener);
	handle->Initialize(opener);

	DUCKDB_LOG_FILE_SYSTEM_OPEN((*handle));

	return std::move(handle);
}

// Buffered read from http file.
// Note that buffering is disabled when FileFlags::FILE_FLAGS_DIRECT_IO is set
void HTTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = handle.Cast<HTTPFileHandle>();

	D_ASSERT(hfh.http_params.state);
	if (hfh.cached_file_handle) {
		if (!hfh.cached_file_handle->Initialized()) {
			throw InternalException("Cached file not initialized properly");
		}
		memcpy(buffer, hfh.cached_file_handle->GetData() + location, nr_bytes);
		DUCKDB_LOG_FILE_SYSTEM_READ(handle, nr_bytes, location);
		hfh.file_offset = location + nr_bytes;
		return;
	}

	idx_t to_read = nr_bytes;
	idx_t buffer_offset = 0;

	// Don't buffer when DirectIO is set or when we are doing parallel reads
	bool skip_buffer = hfh.flags.DirectIO() || hfh.flags.RequireParallelAccess();
	if (skip_buffer && to_read > 0) {
		GetRangeRequest(hfh, hfh.path, {}, location, (char *)buffer, to_read);
		DUCKDB_LOG_FILE_SYSTEM_READ(handle, nr_bytes, location);
		// Update handle status within critical section for parallel access.
		if (hfh.flags.RequireParallelAccess()) {
			std::lock_guard<std::mutex> lck(hfh.mu);
			hfh.buffer_available = 0;
			hfh.buffer_idx = 0;
			hfh.file_offset = location + nr_bytes;
			return;
		}

		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
		hfh.file_offset = location + nr_bytes;
		return;
	}

	if (location >= hfh.buffer_start && location < hfh.buffer_end) {
		hfh.buffer_idx = location - hfh.buffer_start;
		hfh.buffer_available = (hfh.buffer_end - hfh.buffer_start) - hfh.buffer_idx;
	} else {
		// reset buffer
		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
	}

	idx_t start_offset = location; // Start file offset to read from.
	while (to_read > 0) {
		auto buffer_read_len = MinValue<idx_t>(hfh.buffer_available, to_read);
		if (buffer_read_len > 0) {
			D_ASSERT(hfh.buffer_start + hfh.buffer_idx + buffer_read_len <= hfh.buffer_end);
			memcpy((char *)buffer + buffer_offset, hfh.read_buffer.get() + hfh.buffer_idx, buffer_read_len);

			buffer_offset += buffer_read_len;
			to_read -= buffer_read_len;

			hfh.buffer_idx += buffer_read_len;
			hfh.buffer_available -= buffer_read_len;
			start_offset += buffer_read_len;
		}

		if (to_read > 0 && hfh.buffer_available == 0) {
			auto new_buffer_available = MinValue<idx_t>(hfh.READ_BUFFER_LEN, hfh.length - start_offset);

			// Bypass buffer if we read more than buffer size
			if (to_read > new_buffer_available) {
				GetRangeRequest(hfh, hfh.path, {}, location + buffer_offset, (char *)buffer + buffer_offset, to_read);
				hfh.buffer_available = 0;
				hfh.buffer_idx = 0;
				start_offset += to_read;
				break;
			} else {
				GetRangeRequest(hfh, hfh.path, {}, start_offset, (char *)hfh.read_buffer.get(), new_buffer_available);
				hfh.buffer_available = new_buffer_available;
				hfh.buffer_idx = 0;
				hfh.buffer_start = start_offset;
				hfh.buffer_end = hfh.buffer_start + new_buffer_available;
			}
		}
	}
	hfh.file_offset = location + nr_bytes;
	DUCKDB_LOG_FILE_SYSTEM_READ(handle, nr_bytes, location);
}

int64_t HTTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	idx_t max_read = hfh.length - hfh.file_offset;
	nr_bytes = MinValue<idx_t>(max_read, nr_bytes);
	Read(handle, buffer, nr_bytes, hfh.file_offset);
	return nr_bytes;
}

void HTTPFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	throw NotImplementedException("Writing to HTTP files not implemented");
}

int64_t HTTPFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	Write(handle, buffer, nr_bytes, hfh.file_offset);
	return nr_bytes;
}

void HTTPFileSystem::FileSync(FileHandle &handle) {
	throw NotImplementedException("FileSync for HTTP files not implemented");
}

int64_t HTTPFileSystem::GetFileSize(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.length;
}

time_t HTTPFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.last_modified;
}

string HTTPFileSystem::GetVersionTag(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.etag;
}

bool HTTPFileSystem::FileExists(const string &filename, optional_ptr<FileOpener> opener) {
	try {
		auto handle = OpenFile(filename, FileFlags::FILE_FLAGS_READ, opener);
		auto &sfh = handle->Cast<HTTPFileHandle>();
		if (sfh.length == 0) {
			return false;
		}
		return true;
	} catch (...) {
		return false;
	};
}

bool HTTPFileSystem::CanHandleFile(const string &fpath) {
	return fpath.rfind("https://", 0) == 0 || fpath.rfind("http://", 0) == 0;
}

void HTTPFileSystem::Seek(FileHandle &handle, idx_t location) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	sfh.file_offset = location;
}

idx_t HTTPFileSystem::SeekPosition(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.file_offset;
}

optional_ptr<HTTPMetadataCache> HTTPFileSystem::GetGlobalCache() {
	lock_guard<mutex> lock(global_cache_lock);
	if (!global_metadata_cache) {
		global_metadata_cache = make_uniq<HTTPMetadataCache>(false, true);
	}
	return global_metadata_cache.get();
}

// Get either the local, global, or no cache depending on settings
static optional_ptr<HTTPMetadataCache> TryGetMetadataCache(optional_ptr<FileOpener> opener, HTTPFileSystem &httpfs) {
	auto db = FileOpener::TryGetDatabase(opener);
	auto client_context = FileOpener::TryGetClientContext(opener);
	if (!db) {
		return nullptr;
	}

	bool use_shared_cache = db->config.options.http_metadata_cache_enable;
	if (use_shared_cache) {
		return httpfs.GetGlobalCache();
	} else if (client_context) {
		return client_context->registered_state->GetOrCreate<HTTPMetadataCache>("http_cache", true, true).get();
	}
	return nullptr;
}

void HTTPFileHandle::FullDownload(HTTPFileSystem &hfs, bool &should_write_cache) {
	// We are going to download the file at full, we don't need to do no head request.
	const auto &cache_entry = http_params.state->GetCachedFile(path);
	cached_file_handle = cache_entry->GetHandle();
	if (!cached_file_handle->Initialized()) {
		// Try to fully download the file first
		const auto full_download_result = hfs.GetRequest(*this, path, {});
		if (full_download_result->status != HTTPStatusCode::OK_200) {
			throw HTTPException(*full_download_result, "Full download failed to to URL \"%s\": %d (%s)",
			                    full_download_result->url, static_cast<int>(full_download_result->status),
			                    full_download_result->GetError());
		}
		// Mark the file as initialized, set its final length, and unlock it to allowing parallel reads
		cached_file_handle->SetInitialized(length);
		// We shouldn't write these to cache
		should_write_cache = false;
	} else {
		length = cached_file_handle->GetSize();
	}
}

bool HTTPFileSystem::TryParseLastModifiedTime(const string &timestamp, time_t &result) {
	StrpTimeFormat::ParseResult parse_result;
	if (!StrpTimeFormat::TryParse("%a, %d %h %Y %T %Z", timestamp, parse_result)) {
		return false;
	}
	struct tm tm {};
	tm.tm_year = parse_result.data[0] - 1900;
	tm.tm_mon = parse_result.data[1] - 1;
	tm.tm_mday = parse_result.data[2];
	tm.tm_hour = parse_result.data[3];
	tm.tm_min = parse_result.data[4];
	tm.tm_sec = parse_result.data[5];
	tm.tm_isdst = 0;
	result = mktime(&tm);
	return true;
}

optional_idx TryParseContentRange(const HTTPHeaders &headers) {
	if (!headers.HasHeader("Content-Range")) {
		return optional_idx();
	}
	string content_range = headers.GetHeaderValue("Content-Range");
	auto range_find = content_range.find("/");
	if (range_find == std::string::npos || content_range.size() < range_find + 1) {
		return optional_idx();
	}
	string range_length = content_range.substr(range_find + 1);
	if (range_length == "*") {
		return optional_idx();
	}
	try {
		return std::stoull(range_length);
	} catch (...) {
		return optional_idx();
	}
}

optional_idx TryParseContentLength(const HTTPHeaders &headers) {
	if (!headers.HasHeader("Content-Length")) {
		return optional_idx();
	}
	string content_length = headers.GetHeaderValue("Content-Length");
	try {
		return std::stoull(content_length);
	} catch (...) {
		return optional_idx();
	}
}

void HTTPFileHandle::LoadFileInfo() {
	if (initialized || force_full_download) {
		// already initialized or we specifically do not want to perform a head request and just run a direct download
		return;
	}
	auto &hfs = file_system.Cast<HTTPFileSystem>();
	auto res = hfs.HeadRequest(*this, path, {});
	if (res->status != HTTPStatusCode::OK_200) {
		if (flags.OpenForWriting() && res->status == HTTPStatusCode::NotFound_404) {
			if (!flags.CreateFileIfNotExists() && !flags.OverwriteExistingFile()) {
				throw IOException("Unable to open URL \"" + path +
				                  "\" for writing: file does not exist and CREATE flag is not set");
			}
			length = 0;
			return;
		} else {
			// HEAD request fail, use Range request for another try (read only one byte)
			if (flags.OpenForReading() && res->status != HTTPStatusCode::NotFound_404) {
				auto range_res = hfs.GetRangeRequest(*this, path, {}, 0, nullptr, 2);
				if (range_res->status != HTTPStatusCode::PartialContent_206 &&
				    range_res->status != HTTPStatusCode::Accepted_202 && range_res->status != HTTPStatusCode::OK_200) {
					// It failed again
					throw HTTPException(*range_res, "Unable to connect to URL \"%s\": %d (%s).", path,
					                    static_cast<int>(res->status), res->GetError());
				}
				res = std::move(range_res);
			} else {
				throw HTTPException(*res, "Unable to connect to URL \"%s\": %d (%s).", res->url,
				                    static_cast<int>(res->status), res->GetError());
			}
		}
	}
	length = 0;
	optional_idx content_size;
	content_size = TryParseContentRange(res->headers);
	if (!content_size.IsValid()) {
		content_size = TryParseContentLength(res->headers);
	}
	if (content_size.IsValid()) {
		length = content_size.GetIndex();
	}
	if (res->headers.HasHeader("Last-Modified")) {
		HTTPFileSystem::TryParseLastModifiedTime(res->headers.GetHeaderValue("Last-Modified"), last_modified);
	}
	if (res->headers.HasHeader("ETag")) {
		etag = res->headers.GetHeaderValue("ETag");
	}
	initialized = true;
}

void HTTPFileHandle::Initialize(optional_ptr<FileOpener> opener) {
	auto &hfs = file_system.Cast<HTTPFileSystem>();
	http_params.state = HTTPState::TryGetState(opener);
	if (!http_params.state) {
		http_params.state = make_shared_ptr<HTTPState>();
	}

	if (opener) {
		TryAddLogger(*opener);
	}

	auto current_cache = TryGetMetadataCache(opener, hfs);

	bool should_write_cache = false;
	if (flags.OpenForReading()) {
		if (http_params.force_download) {
			FullDownload(hfs, should_write_cache);
			return;
		}

		if (current_cache) {
			HTTPMetadataCacheEntry value;
			bool found = current_cache->Find(path, value);

			if (found) {
				last_modified = value.last_modified;
				length = value.length;
				etag = value.etag;

				if (flags.OpenForReading()) {
					read_buffer = duckdb::unique_ptr<data_t[]>(new data_t[READ_BUFFER_LEN]);
				}
				return;
			}

			should_write_cache = true;
		}
	}
	LoadFileInfo();

	if (flags.OpenForReading()) {
		if ((http_params.state && length == 0) || force_full_download) {
			FullDownload(hfs, should_write_cache);
		}
		if (should_write_cache) {
			current_cache->Insert(path, {length, last_modified, etag});
		}

		// Initialize the read buffer now that we know the file exists
		read_buffer = duckdb::unique_ptr<data_t[]>(new data_t[READ_BUFFER_LEN]);
	}

	// If we're writing to a file, we might as well remove it from the cache
	if (current_cache && flags.OpenForWriting()) {
		current_cache->Erase(path);
	}
}

unique_ptr<HTTPClient> HTTPFileHandle::GetClient() {
	// Try to fetch a cached client
	auto cached_client = client_cache.GetClient();
	if (cached_client) {
		return cached_client;
	}

	// Create a new client
	return CreateClient();
}

unique_ptr<HTTPClient> HTTPFileHandle::CreateClient() {
	// Create a new client
	string path_out, proto_host_port;
	HTTPUtil::DecomposeURL(path, path_out, proto_host_port);
	return http_params.http_util.InitializeClient(http_params, proto_host_port);
}

void HTTPFileHandle::StoreClient(unique_ptr<HTTPClient> client) {
	client_cache.StoreClient(std::move(client));
}

HTTPFileHandle::~HTTPFileHandle() {
	DUCKDB_LOG_FILE_SYSTEM_CLOSE((*this));
};

string HTTPFSUtil::GetName() const {
	return "HTTPFS";
}

} // namespace duckdb
