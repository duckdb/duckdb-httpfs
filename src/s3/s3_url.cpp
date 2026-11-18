#include "s3/s3_url.hpp"
#include "s3/s3_provider.hpp"

#include "duckdb/common/string_util.hpp"

namespace duckdb {

string S3Url::Decode(const string &input) {
	return StringUtil::URLDecode(input, true);
}

string S3Url::Encode(const string &input, S3URLEncodeMode mode) {
	return StringUtil::URLEncode(input, mode == S3URLEncodeMode::QUERY_COMPONENT);
}

static bool GetQueryParam(const string &key, string &param, unordered_map<string, string> &query_params) {
	auto found_param = query_params.find(key);
	if (found_param == query_params.end()) {
		return false;
	}
	param = found_param->second;
	query_params.erase(found_param);
	return true;
}

unordered_map<string, string> S3Url::ParseQueryParameters(const string &url_query_param) {
	unordered_map<string, string> result;
	idx_t offset = 0;
	while (offset <= url_query_param.size()) {
		auto separator = url_query_param.find('&', offset);
		auto parameter_end = separator == string::npos ? url_query_param.size() : separator;
		auto equals = url_query_param.find('=', offset);
		if (equals == string::npos || equals > parameter_end) {
			equals = parameter_end;
		}
		if (equals > offset) {
			auto key = Decode(url_query_param.substr(offset, equals - offset));
			auto value_offset = equals == parameter_end ? parameter_end : equals + 1;
			auto value = Decode(url_query_param.substr(value_offset, parameter_end - value_offset));
			if (!result.emplace(key, std::move(value)).second) {
				throw IOException("Duplicate S3 URL query parameter '%s'", key);
			}
		}
		if (separator == string::npos) {
			break;
		}
		offset = separator + 1;
	}
	return result;
}

string S3Url::GetCopySourcePath(string source, const S3AuthParams &params) {
	StringUtil::Trim(source);
	if (source.find('#') != string::npos) {
		throw PermissionException("Cannot check S3 copy source, '#' in an object key must be URL-encoded");
	}
	if (source.find('?') != string::npos) {
		throw PermissionException("Cannot check S3 copy source with query parameters, versionId is not supported");
	}
	// Copy sources use path encoding, so '+' must not become a space.
	source = StringUtil::URLDecode(source, false);
	if (!source.empty() && source[0] == '/') {
		source.erase(0, 1);
	}
	auto slash = source.find('/');
	// Only bucket/key sources map to filesystem paths, access point ARNs need a different mapping.
	if (slash == string::npos || slash == 0 || slash + 1 == source.size() || source.find(':') < slash) {
		throw PermissionException("Cannot check S3 copy source, expected a bucket and object key");
	}
	// A literal '?' key must not be checked as a URL with parameters.
	if (params.GetURLParams().ParseURLParameters() && source.find('?') != string::npos) {
		throw PermissionException("Cannot check S3 copy source with the current S3 URL parameter settings");
	}
	return params.GetProvider().GetRoute().prefix + source;
}

void S3Url::ReadQueryParams(const string &url_query_param, S3AuthConfig &config) {
	if (url_query_param.empty()) {
		return;
	}

	auto query_params = ParseQueryParameters(url_query_param);
	auto &credentials = config.credentials;
	auto &request_options = config.request_options;

	GetQueryParam("s3_region", credentials.region, query_params);
	GetQueryParam("s3_access_key_id", credentials.access_key_id, query_params);
	GetQueryParam("s3_secret_access_key", credentials.secret_access_key, query_params);
	GetQueryParam("s3_session_token", credentials.session_token, query_params);
	auto found_param = query_params.find("s3_use_ssl");
	if (found_param != query_params.end()) {
		if (found_param->second == "true") {
			config.use_ssl = true;
		} else if (found_param->second == "false") {
			config.use_ssl = false;
		} else {
			throw IOException("Incorrect setting found for s3_use_ssl, allowed values are: 'true' or 'false'");
		}
		query_params.erase(found_param);
	}
	string endpoint;
	if (GetQueryParam("s3_endpoint", endpoint, query_params)) {
		config.endpoint = std::move(endpoint);
		config.endpoint_from_url = true;
		auto trimmed_endpoint = config.endpoint;
		StringUtil::Trim(trimmed_endpoint);
		config.endpoint_mode = trimmed_endpoint.empty() ? S3EndpointMode::AUTOMATIC : S3EndpointMode::EXPLICIT;
	}
	GetQueryParam("s3_url_style", config.url_style, query_params);
	auto found_requester_pays_param = query_params.find("s3_requester_pays");
	if (found_requester_pays_param != query_params.end()) {
		if (found_requester_pays_param->second == "true") {
			request_options.requester_pays = true;
		} else if (found_requester_pays_param->second == "false") {
			request_options.requester_pays = false;
		} else {
			throw IOException("Incorrect setting found for s3_requester_pays, allowed values are: 'true' or 'false'");
		}
		query_params.erase(found_requester_pays_param);
	}
	string sse_c_key;
	if (GetQueryParam("s3_sse_c_key", sse_c_key, query_params)) {
		if (sse_c_key.empty()) {
			// An empty override clears any key configured through a secret.
			request_options.sse_customer_key.reset();
		} else {
			// Base64 keys contain '+', which URL decoding turns into a space unless it was percent-encoded.
			// A valid key never contains a space, so restore the '+' before validating.
			sse_c_key = StringUtil::Replace(sse_c_key, " ", "+");
			try {
				request_options.sse_customer_key = S3SSECustomerKey::Create(sse_c_key);
			} catch (InvalidInputException &) {
				throw IOException("Incorrect setting found for s3_sse_c_key, expected a base64-encoded 256-bit key "
				                  "(percent-encode '+' as %2B, '/' as %2F and '=' as %3D)");
			}
		}
	}
	if (config.route.type == S3ProviderType::GCS) {
		GetQueryParam("gcs_user_project", request_options.user_project, query_params);
	}
	// Validate object selection without storing it in authentication parameters.
	S3Provider::ParseObjectVersion(config.route.type, query_params);
	if (!query_params.empty()) {
		auto supported_parameters =
		    string("'s3_region', 's3_access_key_id', 's3_secret_access_key', 's3_session_token',\n's3_endpoint', "
		           "'s3_url_style', 's3_use_ssl', 's3_requester_pays', 's3_sse_c_key'");
		supported_parameters +=
		    ", '" + string(S3Provider::GetVersionParameterName(HTTPObjectVersionType::S3_VERSION_ID)) + "'";
		if (config.route.type == S3ProviderType::GCS) {
			supported_parameters += ", 'gcs_user_project', '" +
			                        string(S3Provider::GetVersionParameterName(HTTPObjectVersionType::GCS_GENERATION)) +
			                        "'";
		}
		throw IOException("Invalid query parameters found. Supported parameters are:\n%s", supported_parameters);
	}
}

void S3Url::ApplyAuthQueryParameters(const string &url, S3AuthConfig &config) {
	if (!config.enable_deprecated_url_parameters || config.compatibility_mode) {
		return;
	}
	auto question_pos = url.find_first_of('?');
	if (question_pos != string::npos) {
		ReadQueryParams(url.substr(question_pos + 1), config);
	}
}

string S3Url::GetDisplayUrl(const string &url, const S3AuthParams &params) {
	if (!params.GetURLParams().ParseURLParameters()) {
		return url;
	}
	auto query_position = url.find('?');
	return query_position == string::npos ? url : url.substr(0, query_position);
}

//! A plain http(s) url that a secret signs (SIGN_HTTP_URLS) names the request target directly: the host is used as
//! written, and bucket and key are read off it against the secret's endpoint. Path style when the host is the endpoint
//! (http://endpoint/bucket/key), virtual-hosted style when the host is a bucket below it (http://bucket.endpoint/key);
//! for AWS, whose endpoint may be unresolved or regional, the 's3.' label marks where the bucket ends
ParsedS3Url S3Url::ParseHttpUrl(const string &url, const S3AuthParams &params, const string &prefix) {
	auto &route = params.GetProvider().GetRoute();
	auto host_start = prefix.size();
	auto path_start = url.find('/', host_start);
	if (path_start == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	auto request_host = url.substr(host_start, path_start - host_start);
	auto rest = url.substr(path_start);
	string query_string;
	auto question_pos = rest.find('?');
	if (question_pos != string::npos) {
		query_string = rest.substr(question_pos + 1);
		rest = rest.substr(0, question_pos);
	}
	// the path arrives encoded; it is decoded here and encoded again below, the way every S3 request is
	auto path = Decode(rest);

	auto host = StringUtil::Lower(request_host);
	auto endpoint = StringUtil::Lower(params.GetURLParams().endpoint.GetAuthority());
	string bucket;
	string key;
	bool use_path;
	auto take_bucket_from_path = [&]() {
		auto bucket_end = path.find('/', 1);
		bucket = path.substr(1, bucket_end == string::npos ? string::npos : bucket_end - 1);
		key = bucket_end == string::npos ? string() : path.substr(bucket_end);
		use_path = true;
	};
	if (host == endpoint) {
		take_bucket_from_path();
	} else if (StringUtil::EndsWith(host, "." + endpoint)) {
		bucket = request_host.substr(0, host.size() - endpoint.size() - 1);
		key = path;
		use_path = false;
	} else if (StringUtil::EndsWith(host, ".amazonaws.com") && StringUtil::StartsWith(host, "s3.")) {
		take_bucket_from_path();
	} else if (StringUtil::EndsWith(host, ".amazonaws.com") && host.find(".s3.") != string::npos) {
		bucket = request_host.substr(0, host.find(".s3."));
		key = path;
		use_path = false;
	} else {
		throw IOException("Cannot sign '%s' as an S3 request: its host '%s' is neither the endpoint of the secret that "
		                  "covers it ('%s') nor a bucket below it",
		                  url, request_host, endpoint);
	}
	if (bucket.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}
	if (key.empty()) {
		// a bucket without a slash after it; a bare "/" is a bucket url, which a listing asks for
		throw IOException("URL needs to contain key");
	}

	string encoded_path;
	if (use_path) {
		encoded_path = "/" + Encode(bucket, S3URLEncodeMode::PATH);
	}
	auto encoded_bucket_path = encoded_path.empty() ? "/" : encoded_path + "/";
	encoded_path += Encode(key, S3URLEncodeMode::PATH);

	ParsedS3Url result;
	if (!query_string.empty()) {
		auto query_params = ParseQueryParameters(query_string);
		result.object_version = S3Provider::ParseObjectVersion(route.type, query_params);
	}
	result.prefix = prefix;
	result.bucket = std::move(bucket);
	result.key = key.substr(1);
	result.query_string = std::move(query_string);
	result.host = std::move(request_host);
	result.encoded_path = std::move(encoded_path);
	result.encoded_bucket_path = std::move(encoded_bucket_path);
	result.use_ssl = StringUtil::CIStartsWith(prefix, "https://");
	return result;
}

ParsedS3Url S3Url::Parse(const string &url, const S3AuthParams &params) {
	string prefix, host, bucket, key, encoded_path, encoded_bucket_path, query_string;

	auto &route = params.GetProvider().GetRoute();
	prefix = route.prefix;
	if (S3UrlScheme::IsHttpUrl(prefix)) {
		return ParseHttpUrl(url, params, prefix);
	}
	D_ASSERT(StringUtil::CIStartsWith(url, prefix));
	auto prefix_end_pos = url.find("//") + 2;
	auto slash_pos = url.find('/', prefix_end_pos);
	if (slash_pos == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	bucket = url.substr(prefix_end_pos, slash_pos - prefix_end_pos);
	if (bucket.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}

	if (!params.GetURLParams().ParseURLParameters()) {
		// With URL parameters disabled, the entire suffix is part of the object key.
		key += url.substr(slash_pos);
	} else {
		// Parse query parameters
		auto question_pos = url.find_first_of('?');
		if (question_pos != string::npos) {
			query_string = url.substr(question_pos + 1);
		}

		if (!query_string.empty()) {
			key += url.substr(slash_pos, question_pos - slash_pos);
		} else {
			key += url.substr(slash_pos);
		}
	}

	if (key.empty()) {
		throw IOException("URL needs to contain key");
	}

	// Derived host and path based on the normalized endpoint
	auto &url_params = params.GetURLParams();
	host = url_params.endpoint.GetAuthority();
	auto &base_path = url_params.endpoint.GetBasePath();
	for (idx_t i = 0; i < base_path.size(); i++) {
		if (base_path[i] == '%' && i + 2 < base_path.size()) {
			encoded_path += base_path.substr(i, 3);
			i += 2;
		} else {
			encoded_path += Encode(base_path.substr(i, 1), S3URLEncodeMode::PATH);
		}
	}

	// Update host and path according to the url style
	// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
	auto url_style = url_params.style;
	bool use_vhost = url_style == S3URLStyle::VIRTUAL_HOSTED;
	if (use_vhost && url_params.endpoint.IsIPv6()) {
		throw InvalidInputException("IPv6 S3 endpoints require path-style URLs");
	}
	// A bucket name containing periods (.) is not addressable vhost-style over TLS. Fallback to path style url
	bool use_path = url_style == S3URLStyle::PATH ||
	                (use_vhost && url_params.endpoint.UsesSSL() && bucket.find('.') != string::npos);
	if (use_path) {
		encoded_path += "/" + Encode(bucket, S3URLEncodeMode::PATH);
	} else if (use_vhost) {
		host = NormalizedS3Endpoint::Parse(bucket + "." + host, url_params.endpoint.UsesSSL()).GetAuthority();
	}
	encoded_bucket_path = encoded_path.empty() ? "/" : encoded_path + "/";

	// Append key (including leading slash) to the path
	encoded_path += Encode(key, S3URLEncodeMode::PATH);

	// Remove leading slash from key
	key = key.substr(1);

	ParsedS3Url result;
	if (!query_string.empty()) {
		auto query_params = ParseQueryParameters(query_string);
		result.object_version = S3Provider::ParseObjectVersion(route.type, query_params);
	}
	result.prefix = std::move(prefix);
	result.bucket = std::move(bucket);
	result.key = std::move(key);
	result.query_string = std::move(query_string);
	result.host = std::move(host);
	result.encoded_path = std::move(encoded_path);
	result.encoded_bucket_path = std::move(encoded_bucket_path);
	result.use_ssl = url_params.endpoint.UsesSSL();
	return result;
}

const string &ParsedS3Url::GetPrefix() const {
	return prefix;
}

const string &ParsedS3Url::GetBucket() const {
	return bucket;
}

const string &ParsedS3Url::GetKey() const {
	return key;
}

const string &ParsedS3Url::GetQueryString() const {
	return query_string;
}

const HTTPObjectVersion &ParsedS3Url::GetObjectVersion() const {
	return object_version;
}

string ParsedS3Url::GetHTTPUrl(const string &http_query_string) const {
	return BuildHTTPUrl(encoded_path, http_query_string);
}

string ParsedS3Url::GetBucketHTTPUrl(const string &http_query_string) const {
	return BuildHTTPUrl(encoded_bucket_path, http_query_string);
}

const string &ParsedS3Url::GetHost() const {
	return host;
}

const string &ParsedS3Url::GetEncodedPath() const {
	return encoded_path;
}

const string &ParsedS3Url::GetEncodedBucketPath() const {
	return encoded_bucket_path;
}

string ParsedS3Url::BuildHTTPUrl(const string &request_path, const string &http_query_string) const {
	string full_url = use_ssl ? "https://" : "http://";
	full_url += host + request_path;

	if (!http_query_string.empty()) {
		full_url += "?" + http_query_string;
	}
	return full_url;
}

} // namespace duckdb
