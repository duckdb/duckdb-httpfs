#include "s3/s3_remote_signer.hpp"

#include "http/http_state.hpp"
#include "http/httpfs_client.hpp"

#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/json_document.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/interval.hpp"
#include "duckdb/common/types/timestamp.hpp"

#include <algorithm>

namespace duckdb {

//! Matches how long the Iceberg reference signer client reuses a signature the signer allows to be cached
static constexpr int64_t SIGNED_REQUEST_CACHE_MICROS = 30 * Interval::MICROS_PER_SEC;

static vector<pair<string, string>> SortHeaders(const HTTPHeaders &headers) {
	vector<pair<string, string>> result;
	for (auto &header : headers) {
		result.emplace_back(header.first, header.second);
	}
	std::sort(result.begin(), result.end(), [](const pair<string, string> &left, const pair<string, string> &right) {
		return StringUtil::Lower(left.first) < StringUtil::Lower(right.first);
	});
	return result;
}

static string CreateSignRequest(const S3AuthRemoteSigner &signer, const string &region, const string &method,
                                const string &url, const HTTPHeaders &headers, const string &body) {
	JSONWriter writer;
	auto root = writer.CreateObject();
	root.AddString("region", region);
	root.AddString("uri", url);
	root.AddString("method", method);
	auto request_headers = writer.CreateObject();
	for (auto &header : SortHeaders(headers)) {
		auto values = writer.CreateArray();
		values.AppendString(header.second);
		request_headers.Add(header.first, values);
	}
	root.Add("headers", request_headers);
	auto properties = writer.CreateObject();
	for (auto &property : signer.properties) {
		properties.AddString(property.first, property.second);
	}
	root.Add("properties", properties);
	if (!body.empty()) {
		root.AddString("body", body);
	}
	writer.SetRoot(root);
	return writer.ToString();
}

static string CreateCacheKey(const S3AuthRemoteSigner &signer, const string &sign_request) {
	auto result = signer.url + "\n";
	for (auto &header : signer.headers) {
		result += header.first + ": " + header.second + "\n";
	}
	return result + sign_request;
}

static bool AllowsCaching(const HTTPResponse &response) {
	if (!response.HasHeader("Cache-Control")) {
		return false;
	}
	auto cache_control = StringUtil::Lower(response.GetHeaderValue("Cache-Control"));
	return cache_control.find("private") != string::npos && cache_control.find("no-cache") == string::npos &&
	       cache_control.find("no-store") == string::npos;
}

static HTTPSignedRequest ParseSignResponse(const string &response_body, const string &request_url,
                                           const string &signer_url) {
	JSONParseError error;
	auto document = JSONDocument::TryParse(response_body.c_str(), response_body.size(), error);
	if (!document || !document->GetRoot().IsObject()) {
		throw IOException("Remote signer \"%s\" returned a response that is not a JSON object: %s", signer_url,
		                  response_body);
	}
	auto root = document->GetRoot();
	HTTPSignedRequest result;
	auto uri = root.GetMember("uri");
	result.url = uri.IsString() && !uri.GetString().empty() ? uri.GetString() : request_url;
	auto headers = root.GetMember("headers");
	if (!headers.IsObject()) {
		throw IOException("Remote signer \"%s\" returned a response without headers: %s", signer_url, response_body);
	}
	headers.IterateObject([&](const string &name, JSONValue value) {
		// The signer's caching policy, which is not part of the request
		if (StringUtil::CIEquals(name, "Cache-Control")) {
			return;
		}
		vector<string> values;
		if (value.IsString()) {
			values.push_back(value.GetString());
		} else if (value.IsArray()) {
			value.IterateArray([&](JSONValue element) {
				if (!element.IsString()) {
					throw IOException("Remote signer \"%s\" returned a non-string value for header \"%s\"", signer_url,
					                  name);
				}
				values.push_back(element.GetString());
			});
		} else {
			throw IOException("Remote signer \"%s\" returned a non-string value for header \"%s\"", signer_url, name);
		}
		result.headers[name] = StringUtil::Join(values, ", ");
	});
	return result;
}

static HTTPSignedRequest RequestSignature(const HTTPFSParams &request_params, const S3AuthRemoteSigner &signer,
                                          const string &sign_request, const string &request_url,
                                          const string &display_url, bool &allows_caching) {
	auto signer_params_p = request_params.Clone();
	auto &signer_params = signer_params_p->Cast<HTTPFSParams>();
	// Credentials configured for the object store are not meant for the signer
	signer_params.bearer_token.clear();
	signer_params.extra_headers.clear();
	signer_params.RefreshTransportReuseDomain();

	HTTPHeaders headers;
	for (auto &header : signer.headers) {
		headers[header.first] = header.second;
	}
	headers["Content-Type"] = "application/json";
	PostRequestInfo post_request(signer.url, headers, signer_params, const_data_ptr_cast(sign_request.data()),
	                             sign_request.size());
	post_request.try_request = true;
	auto response = signer_params.http_util.Request(post_request);
	if (!response) {
		throw IOException("Remote signer \"%s\" did not respond while signing the request for \"%s\"", signer.url,
		                  display_url);
	}
	if (response->HasRequestError()) {
		throw IOException("Could not reach remote signer \"%s\" while signing the request for \"%s\": %s", signer.url,
		                  display_url, response->GetRequestError());
	}
	if (response->status != HTTPStatusCode::OK_200) {
		throw HTTPFSUtil::GetHTTPStatusError(*response, RequestType::POST_REQUEST, "signing the request for",
		                                     display_url, StringUtil::Format(" at remote signer \"%s\"", signer.url));
	}
	allows_caching = AllowsCaching(*response);
	return ParseSignResponse(post_request.buffer_out, request_url, signer.url);
}

static void ApplySignedRequest(S3RequestData &request_data, const HTTPSignedRequest &signed_request) {
	request_data.http_url = signed_request.url;
	for (auto &header : signed_request.headers) {
		request_data.headers[header.first] = header.second;
	}
}

void S3RemoteSigner::Sign(S3RequestData &request_data, const string &body) {
	auto &signer = request_data.auth_params.GetRemoteSigner();
	auto &region = request_data.auth_params.GetCredentials().region;
	if (region.empty()) {
		throw InvalidInputException("Cannot sign the request for \"%s\" remotely without a region: set REGION in the "
		                            "S3 secret",
		                            request_data.display_url);
	}
	auto request_type = S3RequestUtil::GetOperationInfo(request_data.operation).request_type;
	auto sign_request = CreateSignRequest(signer, region, HTTPFSUtil::GetRequestMethod(request_type),
	                                      request_data.http_url, request_data.headers, body);

	auto &params = request_data.http_params->Cast<HTTPFSParams>();
	// Reads are repeated for the same object, for instance as ranged reads, while every write signs its own payload
	auto cacheable = request_type == RequestType::GET_REQUEST || request_type == RequestType::HEAD_REQUEST;
	auto state = cacheable ? params.state : nullptr;
	string cache_key;
	if (state) {
		cache_key = CreateCacheKey(signer, sign_request);
		HTTPSignedRequest cached;
		if (state->TryGetSignedRequest(cache_key, cached)) {
			ApplySignedRequest(request_data, cached);
			return;
		}
	}

	bool allows_caching = false;
	auto signed_request =
	    RequestSignature(params, signer, sign_request, request_data.http_url, request_data.display_url, allows_caching);
	if (state && allows_caching) {
		auto expires_at = timestamp_t(Timestamp::GetCurrentTimestamp().value + SIGNED_REQUEST_CACHE_MICROS);
		state->PutSignedRequest(cache_key, signed_request, expires_at);
	}
	ApplySignedRequest(request_data, signed_request);
}

} // namespace duckdb
