#include "httpfs.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/logging/log_manager.hpp"

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "http_state.hpp"

#include <chrono>
#include <map>
#include <string>

#include "s3fs.hpp"

namespace duckdb {

HTTPUtil &HTTPFSUtil::GetHTTPUtil(optional_ptr<FileOpener> opener) {
	if (opener) {
		return opener->GetHTTPUtil();
	}
	throw InternalException("FileOpener not provided, can't get HTTPUtil");
}

unique_ptr<HTTPParams> HTTPFSUtil::InitializeParameters(optional_ptr<FileOpener> opener,
                                                        optional_ptr<FileOpenerInfo> info) {
	auto result = make_uniq<HTTPFSParams>(*this);
	result->Initialize(opener);
	result->state = HTTPState::TryGetState(opener);

	// No point in continuing without an opener
	if (!opener) {
		return std::move(result);
	}

	Value value;

	// Setting lookups
	FileOpener::TryGetCurrentSetting(opener, "http_timeout", result->timeout, info);
	FileOpener::TryGetCurrentSetting(opener, "force_download", result->force_download, info);
	FileOpener::TryGetCurrentSetting(opener, "force_download_threshold", result->force_download_threshold, info);
	FileOpener::TryGetCurrentSetting(opener, "auto_fallback_to_full_download", result->auto_fallback_to_full_download,
	                                 info);
	FileOpener::TryGetCurrentSetting(opener, "http_retries", result->retries, info);
	FileOpener::TryGetCurrentSetting(opener, "http_retry_wait_ms", result->retry_wait_ms, info);
	FileOpener::TryGetCurrentSetting(opener, "http_retry_backoff", result->retry_backoff, info);
	FileOpener::TryGetCurrentSetting(opener, "http_keep_alive", result->keep_alive, info);
	FileOpener::TryGetCurrentSetting(opener, "enable_server_cert_verification", result->enable_server_cert_verification,
	                                 info);
	FileOpener::TryGetCurrentSetting(opener, "ca_cert_file", result->ca_cert_file, info);
	FileOpener::TryGetCurrentSetting(opener, "hf_max_per_page", result->hf_max_per_page, info);
	FileOpener::TryGetCurrentSetting(opener, "unsafe_disable_etag_checks", result->unsafe_disable_etag_checks, info);
	FileOpener::TryGetCurrentSetting(opener, "s3_version_id_pinning", result->s3_version_id_pinning, info);

	{
		auto db = FileOpener::TryGetDatabase(opener);
		if (db) {
			result->user_agent = StringUtil::Format("%s %s", db->config.UserAgent(), DuckDB::SourceID());
		}
	}

	unique_ptr<KeyValueSecretReader> settings_reader;
	if (info && !S3FileSystem::TryGetPrefix(info->file_path).empty()) {
		// This is an S3-type url, we should
		const char *s3_secret_types[] = {"s3", "r2", "gcs", "aws", "http"};

		idx_t secret_type_count = 5;
		Value merge_http_secret_into_s3_request;
		FileOpener::TryGetCurrentSetting(opener, "merge_http_secret_into_s3_request",
		                                 merge_http_secret_into_s3_request);

		if (!merge_http_secret_into_s3_request.IsNull() && !merge_http_secret_into_s3_request.GetValue<bool>()) {
			// Drop the http secret from the lookup
			secret_type_count = 4;
		}
		settings_reader = make_uniq<KeyValueSecretReader>(*opener, info, s3_secret_types, secret_type_count);
	} else {
		settings_reader = make_uniq<KeyValueSecretReader>(*opener, info, "http");
	}

	// HTTP Secret lookups

	string proxy_setting;
	if (settings_reader->TryGetSecretKey<string>("http_proxy", proxy_setting) && !proxy_setting.empty()) {
		idx_t port;
		string host;
		HTTPUtil::ParseHTTPProxyHost(proxy_setting, host, port);
		result->http_proxy = host;
		result->http_proxy_port = port;
	}
	result->override_verify_ssl = settings_reader->TryGetSecretKey<bool>("verify_ssl", result->verify_ssl);
	settings_reader->TryGetSecretKey<string>("http_proxy_username", result->http_proxy_username);
	settings_reader->TryGetSecretKey<string>("http_proxy_password", result->http_proxy_password);
	settings_reader->TryGetSecretKey<string>("bearer_token", result->bearer_token);

	Value extra_headers;
	if (settings_reader->TryGetSecretKey("extra_http_headers", extra_headers)) {
		auto children = MapValue::GetChildren(extra_headers);
		for (const auto &child : children) {
			auto kv = StructValue::GetChildren(child);
			D_ASSERT(kv.size() == 2);
			result->extra_headers[kv[0].GetValue<string>()] = kv[1].GetValue<string>();
		}
	}

	return std::move(result);
}

unique_ptr<HTTPParams> HTTPFSParams::Clone() const {
	auto result = make_uniq<HTTPFSParams>(http_util);
	result->timeout = timeout;
	result->timeout_usec = timeout_usec;
	result->retries = retries;
	result->retry_wait_ms = retry_wait_ms;
	result->retry_backoff = retry_backoff;
	result->keep_alive = keep_alive;
	result->follow_location = follow_location;
	result->override_verify_ssl = override_verify_ssl;
	result->verify_ssl = verify_ssl;
	result->http_proxy = http_proxy;
	result->http_proxy_port = http_proxy.empty() ? 0 : http_proxy_port;
	result->http_proxy_username = http_proxy_username;
	result->http_proxy_password = http_proxy_password;
	result->extra_headers = extra_headers;
	result->logger = logger;

	result->force_download = force_download;
	result->auto_fallback_to_full_download = auto_fallback_to_full_download;
	result->enable_server_cert_verification = enable_server_cert_verification;
	result->hf_max_per_page = hf_max_per_page;
	result->ca_cert_file = ca_cert_file;
	result->bearer_token = bearer_token;
	result->unsafe_disable_etag_checks = unsafe_disable_etag_checks;
	result->s3_version_id_pinning = s3_version_id_pinning;
	result->state = state;
	result->user_agent = user_agent;
	result->pre_merged_headers = pre_merged_headers;
	result->force_download_threshold = force_download_threshold;
	return std::move(result);
}

unique_ptr<HTTPClient> HTTPClientCache::GetClient() {
	return GetClientWithGeneration().client;
}

HTTPClientCache::Entry HTTPClientCache::GetClientWithGeneration() {
	lock_guard<mutex> lck(lock);
	Entry result;
	result.generation = generation;
	if (clients.size() == 0) {
		return result;
	}

	result.client = std::move(clients.back());
	clients.pop_back();
	return result;
}

void HTTPClientCache::StoreClient(unique_ptr<HTTPClient> client) {
	lock_guard<mutex> lck(lock);
	clients.push_back(std::move(client));
}

bool HTTPClientCache::StoreClient(Entry &entry) {
	lock_guard<mutex> lck(lock);
	if (!entry.client) {
		return true;
	}
	if (entry.generation != generation) {
		return false;
	}
	clients.push_back(std::move(entry.client));
	return true;
}

void HTTPClientCache::Clear() {
	lock_guard<mutex> lck(lock);
	generation++;
	clients.clear();
}

static void AddUserAgentIfAvailable(HTTPFSParams &http_params, HTTPHeaders &header_map) {
	if (!http_params.user_agent.empty()) {
		header_map.Insert("User-Agent", http_params.user_agent);
	}
}

static void AddHandleHeaders(HTTPFSParams &http_params, HTTPHeaders &header_map) {
	// Inject headers from the http param extra_headers into the request
	for (auto &header : http_params.extra_headers) {
		header_map[header.first] = header.second;
	}
	http_params.pre_merged_headers = true;
}

static string StripETagQuotes(const string &etag) {
	if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') {
		return etag.substr(1, etag.size() - 2);
	}
	return etag;
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunHeadRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
                                                        HTTPSendCallback send_request) {
	HeadRequestInfo head_request(url, header_map, http_params);
	return send_request(head_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunDeleteRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
                                                          HTTPSendCallback send_request) {
	DeleteRequestInfo delete_request(url, header_map, http_params);
	return send_request(delete_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunPostRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
                                                        string &buffer_out, char *buffer_in, idx_t buffer_in_len,
                                                        HTTPSendCallback send_request) {
	PostRequestInfo post_request(url, header_map, http_params, const_data_ptr_cast(buffer_in), buffer_in_len);
	auto result = send_request(post_request);
	buffer_out = std::move(post_request.buffer_out);
	return result;
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunPutRequest(string url, HTTPHeaders header_map, HTTPFSParams &http_params,
                                                       char *buffer_in, idx_t buffer_in_len, const string &content_type,
                                                       HTTPSendCallback send_request) {
	PutRequestInfo put_request(url, header_map, http_params, const_data_ptr_cast(buffer_in), buffer_in_len,
	                           content_type);
	return send_request(put_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunGetRequest(HTTPFileHandle &hfh, string url, HTTPHeaders header_map,
                                                       HTTPFSParams &http_params, CachedFileDownload &download,
                                                       HTTPErrorCallback get_error, HTTPSendCallback send_request) {
	GetRequestInfo get_request(
	    url, header_map, http_params,
	    [&](const HTTPResponse &response) {
		    if (static_cast<int>(response.status) >= 400) {
			    throw get_error(response);
		    }
		    download.Reset();
		    optional_idx content_length;
		    if (response.HasHeader("Content-Length")) {
			    try {
				    content_length = std::stoull(response.GetHeaderValue("Content-Length"));
			    } catch (const std::exception &) {
				    // Grow the buffer incrementally when Content-Length is not numeric.
			    }
		    }
		    if (content_length.IsValid() && content_length.GetIndex() > 0) {
			    download.Reserve(content_length.GetIndex());
		    }
		    if (http_params.s3_version_id_pinning && response.HasHeader("x-amz-version-id")) {
			    lock_guard<mutex> lck(hfh.mu);
			    if (hfh.version_id.empty()) {
				    hfh.version_id = response.GetHeaderValue("x-amz-version-id");
			    }
		    }
		    return true;
	    },
	    [&](const_data_ptr_t data, idx_t data_length) {
		    download.Append(data, data_length);
		    return true;
	    });

	return send_request(get_request);
}

static void SetRangeRequestNotSupported(HTTPResponse &response) {
	try {
		RangeRequestNotSupportedException::Throw();
	} catch (HTTPException &ex) {
		response.request_error = ex.what();
		response.success = false;
	}
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunGetRangeRequest(HTTPFileHandle &hfh, string url, HTTPHeaders header_map,
                                                            HTTPFSParams &http_params, const string &etag,
                                                            bool auto_fallback_to_full_file_download, idx_t file_offset,
                                                            char *buffer_out, idx_t buffer_out_len,
                                                            HTTPErrorCallback get_error,
                                                            HTTPSendCallback send_request) {
	// send the Range header to read only subset of file
	string range_expr = "bytes=" + to_string(file_offset) + "-" + to_string(file_offset + buffer_out_len - 1);
	header_map.Insert("Range", range_expr);

	D_ASSERT(hfh.file_state);
	auto range_request = hfh.file_state->BeginRangeRequest(auto_fallback_to_full_file_download);
	if (range_request.Support() == RangeRequestSupport::NOT_SUPPORTED && auto_fallback_to_full_file_download) {
		auto response = make_uniq<HTTPResponse>(HTTPStatusCode::INVALID);
		SetRangeRequestNotSupported(*response);
		return response;
	}

	idx_t out_offset = 0;
	bool range_request_not_supported = false;
	GetRequestInfo get_request(
	    url, header_map, http_params,
	    [&](const HTTPResponse &response) {
		    if (static_cast<int>(response.status) >= 400) {
			    throw get_error(response);
		    }
		    if (static_cast<int>(response.status) < 300) { // done redirecting
			    out_offset = 0;

			    if (!http_params.unsafe_disable_etag_checks && !etag.empty() && response.HasHeader("ETag")) {
				    string responseEtag = response.GetHeaderValue("ETag");

				    if (!responseEtag.empty() && StripETagQuotes(responseEtag) != StripETagQuotes(etag)) {
					    if (global_metadata_cache) {
						    global_metadata_cache->Erase(hfh.path);
					    }
					    throw HTTPException(
					        response,
					        "ETag on reading file \"%s\" was initially %s and now it returned %s, this likely means "
					        "the remote file has changed.\nFor parquet or similar single table sources, consider "
					        "retrying the query, for "
					        "persistent FileHandles such as databases consider `DETACH` and re-`ATTACH` "
					        "\nYou can disable checking etags via `SET "
					        "unsafe_disable_etag_checks = true;`",
					        hfh.path, etag, response.GetHeaderValue("ETag"));
				    }
			    }

			    if (http_params.s3_version_id_pinning && response.HasHeader("x-amz-version-id")) {
				    lock_guard<mutex> lck(hfh.mu);
				    if (hfh.version_id.empty()) {
					    hfh.version_id = response.GetHeaderValue("x-amz-version-id");
				    }
			    }

			    if (response.HasHeader("Content-Length")) {
				    unsigned long long content_length;
				    bool parsed = false;
				    try {
					    content_length = stoull(response.GetHeaderValue("Content-Length"));
					    parsed = true;
				    } catch (const std::exception &) {
					    // Content-Length header contains a non-numeric value, so skip validation.
				    }
				    if (parsed && (idx_t)content_length != buffer_out_len) {
					    range_request_not_supported = true;
					    range_request.MarkNotSupported();
					    return false;
				    }
			    }
			    if (response.status == HTTPStatusCode::PartialContent_206) {
				    range_request.MarkSupported();
			    }
		    }
		    return true;
	    },
	    [&](const_data_ptr_t data, idx_t data_length) {
		    if (buffer_out != nullptr) {
			    if (data_length + out_offset > buffer_out_len) {
				    throw HTTPException("Server sent back more data than expected, `SET force_download=true` might "
				                        "help in this case");
			    }
			    memcpy(buffer_out + out_offset, data, data_length);
			    out_offset += data_length;
		    }
		    return true;
	    });

	get_request.try_request = auto_fallback_to_full_file_download;
	auto response = send_request(get_request);
	if (range_request_not_supported) {
		SetRangeRequestNotSupported(*response);
		return response;
	}
	if (response && !response->HasRequestError() && response->Success() && buffer_out != nullptr &&
	    out_offset != buffer_out_len) {
		throw IOException("Short read for HTTP GET to '%s': requested range %s (%llu bytes), but received %llu bytes",
		                  url, range_expr, static_cast<unsigned long long>(buffer_out_len),
		                  static_cast<unsigned long long>(out_offset));
	}

	// Feed the prefetch cost model a network measurement for this ranged GET
	if (response && (response->Success() || response->status == HTTPStatusCode::PartialContent_206 ||
	                 response->status == HTTPStatusCode::Accepted_202)) {
		range_request.MarkSupported();
		const auto elapsed_nanos =
		    TimePoint::ElapsedNanos(get_request.request_monotonic_start, get_request.request_monotonic_end);
		const double total_seconds = elapsed_nanos > 0 ? static_cast<double>(elapsed_nanos) / 1e9 : 0;
		const idx_t bytes = get_request.bytes_received != 0 ? get_request.bytes_received : buffer_out_len;
		hfh.RecordNetworkSample(total_seconds, bytes, get_request.have_time_to_fst_byte,
		                        get_request.time_to_fst_byte_sec);
	}
	return response;
}

unique_ptr<HTTPResponse> HTTPFileSystem::PostRequest(HTTPInput &input, string url, HTTPHeaders header_map,
                                                     string &buffer_out, char *buffer_in, idx_t buffer_in_len,
                                                     string params) {
	AddUserAgentIfAvailable(input.http_params, header_map);
	AddHandleHeaders(input.http_params, header_map);
	return RunPostRequest(url, header_map, input.http_params, buffer_out, buffer_in, buffer_in_len,
	                      [&](BaseRequest &request) { return input.http_params.http_util.Request(request); });
}

unique_ptr<HTTPResponse> HTTPFileSystem::PutRequest(HTTPInput &input, string url, HTTPHeaders header_map,
                                                    char *buffer_in, idx_t buffer_in_len, string params) {
	AddUserAgentIfAvailable(input.http_params, header_map);
	AddHandleHeaders(input.http_params, header_map);

	string content_type = "application/octet-stream";
	return RunPutRequest(url, header_map, input.http_params, buffer_in, buffer_in_len, content_type,
	                     [&](BaseRequest &request) { return input.http_params.http_util.Request(request); });
}

unique_ptr<HTTPResponse> HTTPFileSystem::HeadRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	AddUserAgentIfAvailable(hfh.http_params, header_map);
	AddHandleHeaders(hfh.http_params, header_map);

	auto http_client = hfh.GetClient();
	auto response = RunHeadRequest(url, header_map, hfh.http_params, [&](BaseRequest &request) {
		return hfh.http_params.http_util.Request(request, http_client);
	});
	hfh.StoreClient(std::move(http_client));
	return response;
}

unique_ptr<HTTPResponse> HTTPFileSystem::DeleteRequest(FileHandle &handle, string url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	AddUserAgentIfAvailable(hfh.http_params, header_map);
	AddHandleHeaders(hfh.http_params, header_map);

	auto http_client = hfh.GetClient();
	auto response = RunDeleteRequest(url, header_map, hfh.http_params, [&](BaseRequest &request) {
		return hfh.http_params.http_util.Request(request, http_client);
	});
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

unique_ptr<HTTPResponse> HTTPFileSystem::GetRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                    CachedFileDownload &download) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	AddUserAgentIfAvailable(hfh.http_params, header_map);
	AddHandleHeaders(hfh.http_params, header_map);

	auto http_client = hfh.GetClient();
	auto response = RunGetRequest(
	    hfh, url, header_map, hfh.http_params, download,
	    [&](const HTTPResponse &response) { return GetHTTPError(handle, response, url); },
	    [&](BaseRequest &request) { return hfh.http_params.http_util.Request(request, http_client); });
	hfh.StoreClient(std::move(http_client));
	return response;
}

unique_ptr<HTTPResponse> HTTPFileSystem::GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                         idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	AddUserAgentIfAvailable(hfh.http_params, header_map);
	AddHandleHeaders(hfh.http_params, header_map);

	auto http_client = hfh.GetClient();
	auto response = RunGetRangeRequest(
	    hfh, url, header_map, hfh.http_params, hfh.etag, hfh.auto_fallback_to_full_file_download, file_offset,
	    buffer_out, buffer_out_len, [&](const HTTPResponse &response) { return GetHTTPError(handle, response, url); },
	    [&](BaseRequest &request) { return hfh.http_params.http_util.Request(request, http_client); });
	hfh.StoreClient(std::move(http_client));
	return response;
}

HTTPInput::HTTPInput(unique_ptr<HTTPParams> params_p)
    : params(std::move(params_p)), http_params(params->Cast<HTTPFSParams>()) {
}

HTTPFileHandle::HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                               shared_ptr<HTTPInput> input_p)
    : FileHandle(fs, file.path, flags), http_input(std::move(input_p)), http_params(http_input->http_params),
      flags(flags), length(0), last_modified(0), force_full_download(false), buffer_available(0), buffer_idx(0),
      file_offset(0), buffer_start(0), buffer_end(0) {
	// check if the handle has extended properties that can be set directly in the handle
	// if we have these properties we don't need to do a head request to obtain them later
	if (file.extended_info) {
		auto &info = file.extended_info->options;
		auto lm_entry = info.find("last_modified");
		if (lm_entry != info.end()) {
			last_modified = lm_entry->second.GetValue<timestamp_t>();
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

HTTPFileHandle::HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                               unique_ptr<HTTPParams> params_p)
    : HTTPFileHandle(fs, file, flags, make_shared_ptr<HTTPInput>(std::move(params_p))) {
}

unique_ptr<HTTPFileHandle> HTTPFileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                        optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	FileOpenerInfo info;
	info.file_path = file.path;

	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);

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

	if (flags.OpenForWriting() && !flags.OpenForAppending() && !flags.OpenForReading()) {
		handle->write_overwrite_mode = true;
	}

	handle->Initialize(opener);

	DUCKDB_LOG_FILE_SYSTEM_OPEN((*handle));

	return std::move(handle);
}

void HTTPFileHandle::AddStatistics(idx_t read_offset, idx_t read_length, idx_t read_duration) {
	lock_guard<mutex> guard(throughput_lock);
	range_request_statistics.push_back({read_offset, read_length, read_duration});
}

void HTTPFileHandle::RecordNetworkSample(double total_seconds, idx_t bytes, bool sample_has_ttfb, double ttfb_seconds) {
	if (!(total_seconds > 0)) {
		return;
	}
	lock_guard<mutex> guard(throughput_lock);
	const idx_t n = tp_sample_count + 1;
	const double alpha = MaxValue<double>(0.2, 1.0 / static_cast<double>(n));

	if (sample_has_ttfb && ttfb_seconds > 0) {
		tp_latency_seconds =
		    tp_latency_seconds <= 0 ? ttfb_seconds : alpha * ttfb_seconds + (1.0 - alpha) * tp_latency_seconds;
	}

	const double transfer_seconds = sample_has_ttfb ? (total_seconds - ttfb_seconds) : total_seconds;
	if (bytes >= MIN_BANDWIDTH_SAMPLE_BYTES && transfer_seconds > 0) {
		const double bandwidth = static_cast<double>(bytes) / transfer_seconds;
		tp_bandwidth_bps = tp_bandwidth_bps <= 0 ? bandwidth : alpha * bandwidth + (1.0 - alpha) * tp_bandwidth_bps;
	}
	tp_sample_count = n;
}

bool HTTPFileHandle::TryGetNetworkThroughput(NetworkThroughputEstimate &result) {
	lock_guard<mutex> guard(throughput_lock);
	if (tp_sample_count == 0 || tp_latency_seconds <= 0 || tp_bandwidth_bps <= 0) {
		return false;
	}
	result.latency_seconds = tp_latency_seconds;
	result.bandwidth_bytes_per_s = tp_bandwidth_bps;
	return true;
}

void HTTPFileHandle::AdaptReadBufferSize(idx_t next_read_offset) {
	D_ASSERT(!SkipBuffer());
	if (range_request_statistics.empty()) {
		return; // No requests yet - nothing to do
	}

	const auto &last_read = range_request_statistics.back();
	if (last_read.offset + last_read.length != next_read_offset) {
		return; // Not reading sequentially
	}

	if (read_buffer.GetSize() >= MAXIMUM_READ_BUFFER_LEN) {
		return; // Already at maximum size
	}

	// Grow the buffer
	// TODO: can use statistics to estimate per-byte and round-trip cost using least squares, and do something smarter
	read_buffer = read_buffer.GetAllocator()->Allocate(read_buffer.GetSize() * 2);
}

static bool RespondedWithRangeRequestNotSupported(const HTTPResponse &res) {
	if (!res.HasRequestError()) {
		return false;
	}
	ErrorData error(res.GetRequestError());
	return error.Type() == RangeRequestNotSupportedException::TYPE &&
	       error.RawMessage() == RangeRequestNotSupportedException::MESSAGE;
}

bool HTTPFileSystem::TryRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map, idx_t file_offset,
                                     char *buffer_out, idx_t buffer_out_len) {
	auto &hfh = handle.Cast<HTTPFileHandle>();

	const auto timestamp_before = std::chrono::steady_clock::now();
	auto res = GetRangeRequest(handle, url, header_map, file_offset, buffer_out, buffer_out_len);

	if (res) {
		// Request failed and we have a request error
		if (res->HasRequestError()) {
			// Special case: we can do a retry with a full file download
			if (RespondedWithRangeRequestNotSupported(*res)) {
				if (hfh.http_params.auto_fallback_to_full_download) {
					return false;
				}
			}
			ErrorData error(res->GetRequestError());
			error.Throw();
		}

		// Request succeeded TODO: fix upstream that 206 is not considered success
		if (res->Success() || res->status == HTTPStatusCode::PartialContent_206 ||
		    res->status == HTTPStatusCode::Accepted_202) {
			if (!hfh.flags.RequireParallelAccess()) {
				// Update range request statistics
				const auto timestamp_after = std::chrono::steady_clock::now();
				const auto duration = NumericCast<idx_t>(
				    std::chrono::duration_cast<std::chrono::microseconds>(timestamp_after - timestamp_before).count());
				hfh.AddStatistics(file_offset, buffer_out_len, duration);
			}

			return true;
		}

		throw HTTPException(*res, "Request returned HTTP %d for HTTP %s to '%s'", static_cast<int>(res->status),
		                    EnumUtil::ToString(RequestType::GET_REQUEST), url);
	}
	throw IOException("Unknown error for HTTP %s to '%s'", EnumUtil::ToString(RequestType::GET_REQUEST), url);
}

bool HTTPFileSystem::ReadInternal(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = handle.Cast<HTTPFileHandle>();

	D_ASSERT(hfh.file_state);
	auto cached_file = hfh.file_state->TryGetCachedFileHandle();
	if (cached_file) {
		if (cached_file->GetSize() < location + nr_bytes) {
			throw IOException("Cached file length can't satisfy the requested Read. You can try to resolve this by "
			                  "enabling `SET force_download=true`");
		}
		memcpy(buffer, cached_file->GetData() + location, nr_bytes);
		DUCKDB_LOG_FILE_SYSTEM_READ(handle, nr_bytes, location);
		if (hfh.flags.RequireParallelAccess()) {
			std::lock_guard<mutex> lck(hfh.mu);
			hfh.file_offset = location + nr_bytes;
			return true;
		}
		hfh.file_offset = location + nr_bytes;
		return true;
	}

	idx_t to_read = nr_bytes;
	idx_t buffer_offset = 0;

	// Don't buffer when DirectIO is set or when we are doing parallel reads
	if (hfh.SkipBuffer() && to_read > 0) {
		if (!TryRangeRequest(hfh, hfh.path, {}, location, (char *)buffer, to_read)) {
			return false;
		}
		DUCKDB_LOG_FILE_SYSTEM_READ(handle, nr_bytes, location);
		// Update handle status within critical section for parallel access.
		if (hfh.flags.RequireParallelAccess()) {
			std::lock_guard<mutex> lck(hfh.mu);
			hfh.buffer_available = 0;
			hfh.buffer_idx = 0;
			hfh.file_offset = location + nr_bytes;
			return true;
		}

		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
		hfh.file_offset = location + nr_bytes;
		return true;
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
			auto new_buffer_available = MinValue<idx_t>(hfh.read_buffer.GetSize(), hfh.length - start_offset);

			// Bypass buffer if we read more than buffer size
			if (to_read > new_buffer_available) {
				if (!TryRangeRequest(hfh, hfh.path, {}, location + buffer_offset, (char *)buffer + buffer_offset,
				                     to_read)) {
					return false;
				}
				hfh.buffer_available = 0;
				hfh.buffer_idx = 0;
				start_offset += to_read;
				break;
			} else {
				hfh.AdaptReadBufferSize(start_offset);
				new_buffer_available = MinValue<idx_t>(hfh.read_buffer.GetSize(), hfh.length - start_offset);
				if (!TryRangeRequest(hfh, hfh.path, {}, start_offset, (char *)hfh.read_buffer.get(),
				                     new_buffer_available)) {
					return false;
				}
				hfh.buffer_available = new_buffer_available;
				hfh.buffer_idx = 0;
				hfh.buffer_start = start_offset;
				hfh.buffer_end = hfh.buffer_start + new_buffer_available;
			}
		}
	}
	hfh.file_offset = location + nr_bytes;
	DUCKDB_LOG_FILE_SYSTEM_READ(handle, nr_bytes, location);
	return true;
}

// Buffered read from http file.
// Note that buffering is disabled when FileFlags::FILE_FLAGS_DIRECT_IO is set
void HTTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto success = ReadInternal(handle, buffer, nr_bytes, location);
	if (success) {
		return;
	}

	// ReadInternal returned false. This means the regular path of querying the file with range requests failed. We will
	// attempt to download the full file and retry.

	if (handle.logger) {
		DUCKDB_LOG_WARNING(handle.logger,
		                   "Falling back to full file download for file '%s': the server does not support HTTP range "
		                   "requests. Performance and memory usage are potentially degraded.",
		                   handle.path);
	}

	auto &hfh = handle.Cast<HTTPFileHandle>();
	const auto head_reported_length = hfh.length;

	bool should_write_cache = false;
	auto cached_file = FullDownload(hfh, should_write_cache);

	const auto downloaded_length = cached_file->GetSize();
	if (downloaded_length != head_reported_length) {
		hfh.file_state->InvalidateCachedFile();
		hfh.http_params.state->EraseFileState(hfh.path);
		throw HTTPException(Exception::ConstructMessage(
		    "The size reported by HEAD for '%s' was %llu bytes, but the full GET downloaded %llu bytes. You can try "
		    "to resolve this by enabling `SET force_download=true`",
		    hfh.path, static_cast<unsigned long long>(head_reported_length),
		    static_cast<unsigned long long>(downloaded_length)));
	}

	if (!ReadInternal(handle, buffer, nr_bytes, location)) {
		throw HTTPException("Failed to read from HTTP file after automatically retrying a full file download.");
	}
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

timestamp_t HTTPFileSystem::GetLastModifiedTime(FileHandle &handle) {
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
		(void)handle; // suppress warning
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

	Value use_shared_cache_val;
	bool use_shared_cache = false;
	FileOpener::TryGetCurrentSetting(opener, "enable_http_metadata_cache", use_shared_cache_val);
	if (!use_shared_cache_val.IsNull()) {
		use_shared_cache = use_shared_cache_val.GetValue<bool>();
	}

	if (use_shared_cache) {
		return httpfs.GetGlobalCache();
	} else if (client_context) {
		return client_context->registered_state->GetOrCreate<HTTPMetadataCache>("http_cache", true, true).get();
	}
	return nullptr;
}

unique_ptr<CachedFileHandle> HTTPFileSystem::FullDownload(HTTPFileHandle &hfh, bool &should_write_cache) {
	D_ASSERT(hfh.file_state);
	D_ASSERT(hfh.buffer_allocator);
	should_write_cache = false;

	while (true) {
		if (auto cached_file = hfh.file_state->TryGetCachedFileHandle()) {
			return cached_file;
		}

		auto download = hfh.file_state->StartCachedFileDownload(*hfh.buffer_allocator);
		if (!download) {
			continue;
		}
		auto full_download_result = GetRequest(hfh, hfh.path, {}, *download);
		if (full_download_result->status != HTTPStatusCode::OK_200) {
			throw HTTPException(*full_download_result, "Full download failed to to URL \"%s\": %d (%s)",
			                    full_download_result->url, static_cast<int>(full_download_result->status),
			                    full_download_result->GetError());
		}
		return download->Finalize();
	}
}

bool HTTPFileSystem::TryParseLastModifiedTime(const string &timestamp, timestamp_t &result) {
	StrpTimeFormat::ParseResult parse_result;
	if (!StrpTimeFormat::TryParse("%a, %d %h %Y %T %Z", timestamp, parse_result)) {
		return false;
	}
	if (!parse_result.TryToTimestamp(result)) {
		return false;
	}
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

	// Check if file is already fully cached (e.g., from a prior force_download_threshold open)
	D_ASSERT(file_state);
	if (auto cached_file = file_state->TryGetCachedFileHandle()) {
		length = cached_file->GetSize();
		initialized = true;
		return;
	}

	if (initialized || force_full_download) {
		// already initialized or we specifically do not want to perform a head request and just run a direct download
		return;
	}

	// In write_overwrite_mode we dgaf about the size, so no head request is needed
	if (write_overwrite_mode) {
		length = 0;
		initialized = true;
		return;
	}

	auto &hfs = file_system.Cast<HTTPFileSystem>();
	auto res = hfs.HeadRequest(*this, path, {});
	if (res->status != HTTPStatusCode::OK_200) {
		if (flags.OpenForWriting() && res->status == HTTPStatusCode::NotFound_404) {
			if (!flags.CreateFileIfNotExists() && !flags.OverwriteExistingFile()) {
				throw IOException(
				    "Unable to open URL \"%s\" for writing: file does not exist and CREATE flag is not set", path);
			}
			length = 0;
			return;
		} else {
			// HEAD request fail, use Range request for another try (read only one byte)
			if (flags.OpenForReading() && res->status != HTTPStatusCode::NotFound_404 &&
			    res->status != HTTPStatusCode::MovedPermanently_301) {
				auto range_res = hfs.GetRangeRequest(*this, path, {}, 0, nullptr, 2);
				if (range_res->status != HTTPStatusCode::PartialContent_206 &&
				    range_res->status != HTTPStatusCode::Accepted_202 && range_res->status != HTTPStatusCode::OK_200) {
					// It failed again, check whether we can fall back to full download
					if (RespondedWithRangeRequestNotSupported(*range_res) &&
					    http_params.auto_fallback_to_full_download) {
						force_full_download = true;
					} else {
						throw hfs.GetHTTPError(*this, *range_res, path);
					}
				}
				res = std::move(range_res);
			} else {
				throw hfs.GetHTTPError(*this, *res, path);
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
	if (http_params.s3_version_id_pinning && res->headers.HasHeader("x-amz-version-id")) {
		version_id = res->headers.GetHeaderValue("x-amz-version-id");
	}
	if (res->headers.HasHeader("Accept-Ranges")) {
		auto accept_ranges = res->headers.GetHeaderValue("Accept-Ranges");
		StringUtil::Trim(accept_ranges);
		if (StringUtil::CIEquals(accept_ranges, "bytes")) {
			file_state->MarkRangeRequestsSupported();
		}
	}
	initialized = true;
}

void HTTPFileHandle::TryAddLogger(FileOpener &opener) {
	auto context = opener.TryGetClientContext();
	if (context) {
		logger = context->logger;
		return;
	}
	auto database = opener.TryGetDatabase();
	if (database) {
		logger = database->GetLogManager().GlobalLoggerReference();
	}
}

void HTTPFileHandle::AllocateReadBuffer(optional_ptr<FileOpener> opener) {
	D_ASSERT(!SkipBuffer());
	D_ASSERT(!read_buffer.IsSet());
	auto &allocator = opener && opener->TryGetClientContext() ? BufferAllocator::Get(*opener->TryGetClientContext())
	                                                          : Allocator::DefaultAllocator();
	read_buffer = allocator.Allocate(INITIAL_READ_BUFFER_LEN);
}

void HTTPFileHandle::InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry) {
	last_modified = cache_entry.last_modified;
	length = cache_entry.length;
	etag = cache_entry.etag;
	version_id = cache_entry.version_id;

	// TODO: handle properties
}

HTTPMetadataCacheEntry HTTPFileHandle::GetCacheEntry() const {
	HTTPMetadataCacheEntry result;
	result.length = length;
	result.last_modified = last_modified;
	result.etag = etag;
	result.version_id = version_id;
	// TODO: handle properties
	return result;
}

void HTTPFileHandle::Initialize(optional_ptr<FileOpener> opener) {
	auto &hfs = file_system.Cast<HTTPFileSystem>();
	auto client_context = FileOpener::TryGetClientContext(opener);
	if (client_context) {
		buffer_allocator = BufferAllocator::Get(*client_context);
	} else {
		auto database = FileOpener::TryGetDatabase(opener);
		buffer_allocator = database ? BufferAllocator::Get(*database) : Allocator::DefaultAllocator();
	}
	http_params.state = HTTPState::TryGetState(opener);
	if (!http_params.state) {
		http_params.state = make_shared_ptr<HTTPState>();
	}
	file_state = http_params.state->GetFileState(path);

	if (opener) {
		TryAddLogger(*opener);
	}

	auto current_cache = TryGetMetadataCache(opener, hfs);

	bool should_write_cache = false;
	if (flags.OpenForReading()) {
		if (http_params.force_download) {
			length = hfs.FullDownload(*this, should_write_cache)->GetSize();
			return;
		}

		if (current_cache) {
			HTTPMetadataCacheEntry value;
			bool found = current_cache->Find(path, value);

			if (found) {
				InitializeFromCacheEntry(value);

				if (flags.OpenForReading() && !SkipBuffer()) {
					AllocateReadBuffer(opener);
				}
				return;
			}

			should_write_cache = true;
		}
	}
	LoadFileInfo();

	if (flags.OpenForReading()) {

		const auto has_cache_state = (http_params.state != nullptr) && (length == 0);
		const auto always_download = force_full_download;
		const auto meets_threshold = (length < http_params.force_download_threshold) && (length != 0);

		const auto should_full_download = has_cache_state || meets_threshold || always_download;

		if (should_full_download) {
			length = hfs.FullDownload(*this, should_write_cache)->GetSize();
		}
		if (should_write_cache) {
			current_cache->Insert(path, GetCacheEntry());
		}

		if (!should_full_download && !SkipBuffer()) {
			// Initialize the read buffer now that we know the file exists
			AllocateReadBuffer(opener);
		}
	}

	// If we're writing to a file, we might as well remove it from the cache
	if (current_cache && flags.OpenForWriting()) {
		current_cache->Erase(path);
	}
}

//! Whether clients are checked out from the shared connection pool instead of the per-handle cache.
//! Only the curl util pools clients (one pool per database instance); every other configuration
//! keeps per-handle reuse so it does not pay a fresh connection per request.
static bool UseSharedConnectionPool(const HTTPParams &http_params) {
#ifndef EMSCRIPTEN
	auto &util = http_params.http_util;
	if (util.GetName() == "HTTPFS-Curl") {
		return static_cast<const HTTPFSCurlUtil &>(util).connection_caching_enabled;
	}
#endif
	return false;
}

unique_ptr<HTTPClient> HTTPFileHandle::GetClient() {
	if (!UseSharedConnectionPool(http_params)) {
		// no shared pool for this configuration - reuse this handle's cached client
		auto cached_client = client_cache.GetClient();
		if (cached_client) {
			return cached_client;
		}
	}
	// with the shared pool enabled InitializeClient consults the pool, so that concurrent handles
	// share connections instead of each hoarding a private pool
	return CreateClient();
}

unique_ptr<HTTPClient> HTTPFileHandle::CreateClient() {
	string path_out, proto_host_port;
	HTTPUtil::DecomposeURL(path, path_out, proto_host_port);
	return http_params.http_util.InitializeClient(http_params, proto_host_port);
}

void HTTPFileHandle::StoreClient(unique_ptr<HTTPClient> client) {
	if (!UseSharedConnectionPool(http_params)) {
		client_cache.StoreClient(std::move(client));
		return;
	}
	// return the client to the shared connection pool so other handles can reuse it
	http_params.http_util.CloseClient(std::move(client));
}

HTTPFileHandle::~HTTPFileHandle() {
	DUCKDB_LOG_FILE_SYSTEM_CLOSE((*this));
	auto client = client_cache.GetClient();
	while (client) {
		http_params.http_util.CloseClient(std::move(client));
		client = client_cache.GetClient();
	}
}

void HTTPFSUtil::ClearCachedConnections() {
	// no-op by default
}

string HTTPFSUtil::GetName() const {
	return "HTTPFS";
}

} // namespace duckdb
