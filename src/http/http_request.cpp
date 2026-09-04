#include "http/httpfs.hpp"

#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/types/time.hpp"

namespace duckdb {

static string StripETagQuotes(const string &etag) {
	if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') {
		return etag.substr(1, etag.size() - 2);
	}
	return etag;
}

static void ApplyReadCondition(HTTPHeaders &headers, const HTTPReadConfig &read_config) {
	if (read_config.condition.type == HTTPReadConditionType::ETAG) {
		headers["If-Match"] = read_config.condition.value;
	}
}

static HTTPHeaders RemoveRangeHeader(const HTTPHeaders &headers) {
	HTTPHeaders result;
	for (const auto &header : headers) {
		if (!StringUtil::CIEquals(header.first, "Range")) {
			result[header.first] = header.second;
		}
	}
	return result;
}

static HTTPHeaders PrepareFullGetHeaders(const HTTPHeaders &headers, const HTTPReadConfig &read_config) {
	auto result = RemoveRangeHeader(headers);
	ApplyReadCondition(result, read_config);
	return result;
}

static unique_ptr<HTTPResponse> SendSessionRequest(HTTPRequestSession &session,
                                                   const CapturedHTTPRequestSnapshot &captured,
                                                   HTTPFSParams &request_params, BaseRequest &request) {
	auto lease = session.AcquireClient(captured, request_params, request.proto_host_port);
	try {
		auto response = request_params.http_util.Request(request, lease.Client());
		// A completed HTTP response leaves the transport reusable, regardless of its status.
		if (response && response->HasRequestError()) {
			lease.Invalidate();
		}
		return response;
	} catch (...) {
		lease.Invalidate();
		throw;
	}
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunHeadRequest(const string &url, const HTTPHeaders &header_map,
                                                        HTTPFSParams &http_params,
                                                        const HTTPSendCallback &send_request) {
	auto request_headers = RemoveRangeHeader(header_map);
	http_params.extra_headers.erase("Range");
	HeadRequestInfo head_request(url, request_headers, http_params);
	return send_request(head_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunDeleteRequest(const string &url, const HTTPHeaders &header_map,
                                                          HTTPFSParams &http_params,
                                                          const HTTPSendCallback &send_request) {
	DeleteRequestInfo delete_request(url, header_map, http_params);
	return send_request(delete_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunPostRequest(const string &url, const HTTPHeaders &header_map,
                                                        HTTPFSParams &http_params, string &buffer_out,
                                                        const_data_ptr_t buffer_in, idx_t buffer_in_len,
                                                        const HTTPSendCallback &send_request) {
	PostRequestInfo post_request(url, header_map, http_params, buffer_in, buffer_in_len);
	auto result = send_request(post_request);
	buffer_out = std::move(post_request.buffer_out);
	return result;
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunPutRequest(const string &url, const HTTPHeaders &header_map,
                                                       HTTPFSParams &http_params, const_data_ptr_t buffer_in,
                                                       idx_t buffer_in_len, const string &content_type,
                                                       const HTTPSendCallback &send_request) {
	PutRequestInfo put_request(url, header_map, http_params, buffer_in, buffer_in_len, content_type);
	return send_request(put_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::RunGetRequest(HTTPFileHandle &hfh, const string &url,
                                                       const HTTPHeaders &header_map, HTTPFSParams &http_params,
                                                       const HTTPReadConfig &read_config, CachedFileDownload &download,
                                                       const HTTPErrorCallback &get_error,
                                                       const HTTPSendCallback &send_request) {
	auto request_headers = PrepareFullGetHeaders(header_map, read_config);
	http_params.extra_headers.erase("Range");
	GetRequestInfo get_request(
	    url, request_headers, http_params,
	    [&](const HTTPResponse &response) {
		    if (response.status == HTTPStatusCode::PreconditionFailed_412 &&
		        read_config.condition.type == HTTPReadConditionType::ETAG) {
			    return false;
		    }
		    if (static_cast<int>(response.status) >= 400) {
			    throw get_error(response);
		    }
		    if (static_cast<int>(response.status) < 300) {
			    ValidateResponseETag(hfh, read_config, response);
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

struct HTTPRangeRequestContext {
public:
	HTTPRangeRequestContext(HTTPFileHandle &handle_p, const HTTPReadConfig &read_config_p, string url_p,
	                        string range_expression_p, data_ptr_t buffer_out_p, idx_t buffer_out_len_p,
	                        RangeRequestState::Guard range_request_p,
	                        std::function<HTTPException(const HTTPResponse &)> get_error_p,
	                        std::function<void(const HTTPResponse &)> validate_response_p)
	    : handle(handle_p), read_config(read_config_p), url(std::move(url_p)),
	      range_expression(std::move(range_expression_p)), buffer_out(buffer_out_p), buffer_out_len(buffer_out_len_p),
	      range_request(std::move(range_request_p)), get_error(std::move(get_error_p)),
	      validate_response(std::move(validate_response_p)) {
	}

public:
	bool HandleResponse(const HTTPResponse &response) {
		if (response.status == HTTPStatusCode::PreconditionFailed_412 &&
		    read_config.condition.type == HTTPReadConditionType::ETAG) {
			return false;
		}
		if (static_cast<int>(response.status) >= 400) {
			throw get_error(response);
		}
		if (static_cast<int>(response.status) >= 300) {
			return true;
		}

		out_offset = 0;
		validate_response(response);
		if (!ValidateContentLength(response)) {
			return false;
		}
		if (response.status == HTTPStatusCode::PartialContent_206) {
			range_request.MarkSupported();
		}
		return true;
	}

	bool HandleContent(const_data_ptr_t data, idx_t data_length) {
		if (!buffer_out) {
			return true;
		}
		if (out_offset > buffer_out_len || data_length > buffer_out_len - out_offset) {
			throw HTTPException("Server sent back more data than expected, `SET force_download=true` might "
			                    "help in this case");
		}
		memcpy(buffer_out + out_offset, data, data_length);
		out_offset += data_length;
		return true;
	}

	unique_ptr<HTTPResponse> Finalize(unique_ptr<HTTPResponse> response, const GetRequestInfo &request) {
		if (range_request_not_supported) {
			D_ASSERT(response);
			SetRangeRequestNotSupported(*response);
			return response;
		}
		ValidateReadLength(response);
		if (IsSuccessfulResponse(response)) {
			range_request.MarkSupported();
			RecordNetworkSample(request);
		}
		return response;
	}

private:
	bool ValidateContentLength(const HTTPResponse &response) {
		if (!response.HasHeader("Content-Length")) {
			return true;
		}
		try {
			auto content_length = NumericCast<idx_t>(stoull(response.GetHeaderValue("Content-Length")));
			if (content_length == buffer_out_len) {
				return true;
			}
			range_request_not_supported = true;
			range_request.MarkNotSupported();
			return false;
		} catch (const std::exception &) {
			// A malformed Content-Length cannot be used to validate range support.
			return true;
		}
	}

	void ValidateReadLength(const unique_ptr<HTTPResponse> &response) const {
		if (!response || response->HasRequestError() || !response->Success() || !buffer_out ||
		    out_offset == buffer_out_len) {
			return;
		}
		throw IOException("Short read for HTTP GET to '%s': requested range %s (%llu bytes), but received %llu bytes",
		                  url, range_expression, static_cast<uint64_t>(buffer_out_len),
		                  static_cast<uint64_t>(out_offset));
	}

	static bool IsSuccessfulResponse(const unique_ptr<HTTPResponse> &response) {
		return response && (response->Success() || response->status == HTTPStatusCode::PartialContent_206 ||
		                    response->status == HTTPStatusCode::Accepted_202);
	}

	void RecordNetworkSample(const GetRequestInfo &request) {
		const auto elapsed_nanos =
		    TimePoint::ElapsedNanos(request.request_monotonic_start, request.request_monotonic_end);
		const double total_seconds = elapsed_nanos > 0 ? static_cast<double>(elapsed_nanos) / 1e9 : 0;
		const idx_t bytes = request.bytes_received != 0 ? request.bytes_received : buffer_out_len;
		handle.RecordNetworkSample(total_seconds, bytes, request.have_time_to_fst_byte, request.time_to_fst_byte_sec);
	}

private:
	HTTPFileHandle &handle;
	const HTTPReadConfig &read_config;
	const string url;
	const string range_expression;
	data_ptr_t buffer_out;
	const idx_t buffer_out_len;
	RangeRequestState::Guard range_request;
	std::function<HTTPException(const HTTPResponse &)> get_error;
	std::function<void(const HTTPResponse &)> validate_response;
	idx_t out_offset = 0;
	bool range_request_not_supported = false;
};

unique_ptr<HTTPResponse> HTTPFileSystem::RunGetRangeRequest(HTTPFileHandle &hfh, const string &url,
                                                            const HTTPHeaders &header_map, HTTPFSParams &http_params,
                                                            const HTTPReadConfig &read_config, idx_t file_offset,
                                                            data_ptr_t buffer_out, idx_t buffer_out_len,
                                                            const HTTPErrorCallback &get_error,
                                                            const HTTPSendCallback &send_request) {
	auto range_expr = "bytes=" + to_string(file_offset) + "-" + to_string(file_offset + buffer_out_len - 1);
	auto request_headers = header_map;
	request_headers["Range"] = range_expr;
	ApplyReadCondition(request_headers, read_config);

	D_ASSERT(hfh.file_state);
	auto range_request = hfh.file_state->BeginRangeRequest(read_config.auto_fallback_to_full_download);
	if (range_request.Support() == RangeRequestSupport::NOT_SUPPORTED && read_config.auto_fallback_to_full_download) {
		auto response = make_uniq<HTTPResponse>(HTTPStatusCode::INVALID);
		SetRangeRequestNotSupported(*response);
		return response;
	}

	HTTPRangeRequestContext context(
	    hfh, read_config, url, range_expr, buffer_out, buffer_out_len, std::move(range_request), get_error,
	    [&](const HTTPResponse &response) { ValidateResponseETag(hfh, read_config, response); });
	GetRequestInfo get_request(
	    url, request_headers, http_params,
	    [&](const HTTPResponse &response) { return context.HandleResponse(response); },
	    [&](const_data_ptr_t data, idx_t data_length) { return context.HandleContent(data, data_length); });

	get_request.try_request = read_config.auto_fallback_to_full_download;
	return context.Finalize(send_request(get_request), get_request);
}

unique_ptr<HTTPResponse> HTTPFileSystem::HeadRequest(FileHandle &handle, const string &url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto captured = hfh.request_session->Capture();
	auto session_request = captured.snapshot->CreateRequest(std::move(header_map));
	return RunHeadRequest(url, session_request.headers, *session_request.params, [&](BaseRequest &request) {
		return SendSessionRequest(*hfh.request_session, captured, *session_request.params, request);
	});
}

unique_ptr<HTTPResponse> HTTPFileSystem::DeleteRequest(FileHandle &handle, const string &url, HTTPHeaders header_map) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto captured = hfh.request_session->Capture();
	auto session_request = captured.snapshot->CreateRequest(std::move(header_map));
	return RunDeleteRequest(url, session_request.headers, *session_request.params, [&](BaseRequest &request) {
		return SendSessionRequest(*hfh.request_session, captured, *session_request.params, request);
	});
}

const char *HTTPFSUtil::GetRequestMethod(RequestType request_type) {
	switch (request_type) {
	case RequestType::GET_REQUEST:
		return "GET";
	case RequestType::PUT_REQUEST:
		return "PUT";
	case RequestType::HEAD_REQUEST:
		return "HEAD";
	case RequestType::DELETE_REQUEST:
		return "DELETE";
	case RequestType::POST_REQUEST:
		return "POST";
	case RequestType::OPTIONS_REQUEST:
		return "OPTIONS";
	}
	throw InternalException("Unsupported HTTP request type");
}

HTTPException HTTPFSUtil::GetHTTPStatusError(const HTTPResponse &response, RequestType request_type,
                                             const string &operation, const string &display_url,
                                             const string &details) {
	return HTTPException(response, "HTTP %s error %s '%s' (HTTP %d %s)%s", GetRequestMethod(request_type), operation,
	                     display_url, response.status, GetStatusMessage(response.status), details);
}

HTTPException HTTPFileSystem::GetHTTPError(FileHandle &, const HTTPResponse &response, RequestType request_type,
                                           const string &url) {
	string details;
	if (response.status == HTTPStatusCode::RangeNotSatisfiable_416) {
		details = " This could mean the file was changed. Try disabling the duckdb http metadata cache "
		          "if enabled, and confirm the server supports range requests.";
	}
	return HTTPFSUtil::GetHTTPStatusError(response, request_type, "on", url, details);
}

void HTTPFileSystem::ValidateResponseETag(HTTPFileHandle &hfh, const HTTPReadConfig &read_config,
                                          const HTTPResponse &response) {
	if (!read_config.validate_etag || read_config.etag.empty() || !response.HasHeader("ETag")) {
		return;
	}
	auto response_etag = response.GetHeaderValue("ETag");
	if (response_etag.empty() || StripETagQuotes(response_etag) == StripETagQuotes(read_config.etag)) {
		return;
	}
	EraseGlobalCacheEntry(hfh.path);
	throw HTTPException(
	    response,
	    "ETag on reading file \"%s\" was initially %s and now it returned %s, this likely means "
	    "the remote file has changed.\nFor parquet or similar single table sources, consider "
	    "retrying the query, for persistent FileHandles such as databases consider `DETACH` and re-`ATTACH` "
	    "\nYou can disable checking etags via `SET unsafe_disable_etag_checks = true;`",
	    hfh.path, read_config.etag, response_etag);
}

void HTTPFileSystem::ThrowIfReadConditionFailed(HTTPFileHandle &hfh, const HTTPReadConfig &read_config,
                                                const HTTPResponse &response) {
	if (response.status != HTTPStatusCode::PreconditionFailed_412 ||
	    read_config.condition.type != HTTPReadConditionType::ETAG) {
		return;
	}
	EraseGlobalCacheEntry(hfh.path);
	throw HTTPException(response, "ETag on reading file \"%s\" changed after it was opened: the server rejected %s",
	                    hfh.path, read_config.condition.value);
}

unique_ptr<HTTPResponse> HTTPFileSystem::GetRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                    const HTTPReadConfig &read_config, CachedFileDownload &download) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto captured = hfh.request_session->Capture();
	auto session_request = captured.snapshot->CreateRequest(std::move(header_map));
	return RunGetRequest(
	    hfh, url, session_request.headers, *session_request.params, read_config, download,
	    [&](const HTTPResponse &response) { return GetHTTPError(handle, response, RequestType::GET_REQUEST, url); },
	    [&](BaseRequest &request) {
		    return SendSessionRequest(*hfh.request_session, captured, *session_request.params, request);
	    });
}

unique_ptr<HTTPResponse> HTTPFileSystem::GetRangeRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                         const HTTPReadConfig &read_config, idx_t file_offset,
                                                         data_ptr_t buffer_out, idx_t buffer_out_len) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto captured = hfh.request_session->Capture();
	auto session_request = captured.snapshot->CreateRequest(std::move(header_map));
	return RunGetRangeRequest(
	    hfh, url, session_request.headers, *session_request.params, read_config, file_offset, buffer_out,
	    buffer_out_len,
	    [&](const HTTPResponse &response) { return GetHTTPError(handle, response, RequestType::GET_REQUEST, url); },
	    [&](BaseRequest &request) {
		    return SendSessionRequest(*hfh.request_session, captured, *session_request.params, request);
	    });
}

} // namespace duckdb
