#include "s3/s3_url.hpp"

#include "duckdb/common/string_util.hpp"

namespace duckdb {

string S3Url::Decode(const string &input) {
	return StringUtil::URLDecode(input, true);
}

string S3Url::Encode(const string &input, S3URLEncodeMode mode) {
	return StringUtil::URLEncode(input, mode == S3URLEncodeMode::QUERY_COMPONENT);
}

static optional<string> GetQueryParam(const string &key, unordered_map<string, string> &query_params) {
	auto found_param = query_params.find(key);
	if (found_param == query_params.end()) {
		return {};
	}
	auto value = std::move(found_param->second);
	query_params.erase(found_param);
	return value;
}

static optional<bool> GetBooleanQueryParam(const string &key, unordered_map<string, string> &query_params) {
	auto value = GetQueryParam(key, query_params);
	if (!value) {
		return {};
	}
	if (*value == "true") {
		return true;
	}
	if (*value == "false") {
		return false;
	}
	throw IOException("Incorrect setting found for %s, allowed values are: 'true' or 'false'", key);
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

S3AuthQueryParameters S3Url::ParseAuthQueryParameters(const string &query, S3ProviderType provider) {
	auto query_params = ParseQueryParameters(query);
	S3AuthQueryParameters result;
	result.region = GetQueryParam("s3_region", query_params);
	result.access_key_id = GetQueryParam("s3_access_key_id", query_params);
	result.secret_access_key = GetQueryParam("s3_secret_access_key", query_params);
	result.session_token = GetQueryParam("s3_session_token", query_params);
	result.use_ssl = GetBooleanQueryParam("s3_use_ssl", query_params);
	result.endpoint = GetQueryParam("s3_endpoint", query_params);
	result.url_style = GetQueryParam("s3_url_style", query_params);
	result.requester_pays = GetBooleanQueryParam("s3_requester_pays", query_params);
	result.sse_c_key = GetQueryParam("s3_sse_c_key", query_params);
	if (provider == S3ProviderType::GCS) {
		result.user_project = GetQueryParam("gcs_user_project", query_params);
	}
	// Validate object selection without storing it in authentication parameters.
	S3Provider::ParseObjectVersion(provider, query_params);
	if (!query_params.empty()) {
		auto supported_parameters =
		    string("'s3_region', 's3_access_key_id', 's3_secret_access_key', 's3_session_token',\n's3_endpoint', "
		           "'s3_url_style', 's3_use_ssl', 's3_requester_pays', 's3_sse_c_key'");
		supported_parameters +=
		    ", '" + string(S3Provider::GetVersionParameterName(HTTPObjectVersionType::S3_VERSION_ID)) + "'";
		if (provider == S3ProviderType::GCS) {
			supported_parameters += ", 'gcs_user_project', '" +
			                        string(S3Provider::GetVersionParameterName(HTTPObjectVersionType::GCS_GENERATION)) +
			                        "'";
		}
		throw IOException("Invalid query parameters found. Supported parameters are:\n%s", supported_parameters);
	}
	return result;
}

S3Url::PathComponents S3Url::Split(const string &url, S3URLQueryMode mode) {
	auto separator = mode == S3URLQueryMode::LITERAL_KEY ? string::npos : url.rfind('?');
	if (separator == string::npos) {
		return {url, ""};
	}
	return {url.substr(0, separator), url.substr(separator + 1)};
}

string S3Url::GetDisplayUrl(const string &url, const S3AuthParams &params) {
	return Split(url, params.GetURLParams().query_mode).path;
}

ParsedS3Url S3Url::Parse(const string &url, const S3AuthParams &params) {
	return Parse(url, params.GetProvider().GetRoute(), params.GetURLParams());
}

ParsedS3Url S3Url::Parse(const string &url, const S3ProviderMatch &route, const S3AuthURLParams &url_params) {
	string prefix, host, bucket, key, encoded_path, encoded_bucket_path, query_string;

	prefix = route.prefix;
	D_ASSERT(StringUtil::CIStartsWith(url, prefix));
	auto components = Split(url, url_params.query_mode);
	auto prefix_end_pos = components.path.find("//") + 2;
	auto slash_pos = components.path.find('/', prefix_end_pos);
	if (slash_pos == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	bucket = components.path.substr(prefix_end_pos, slash_pos - prefix_end_pos);
	if (bucket.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}

	key = components.path.substr(slash_pos);
	query_string = std::move(components.query);

	if (key.empty()) {
		throw IOException("URL needs to contain key");
	}

	// Derived host and path based on the normalized endpoint
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
		auto bucket_endpoint = NormalizedS3Endpoint::Parse(bucket + "." + host, url_params.endpoint.UsesSSL());
		host = bucket_endpoint.GetAuthority();
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
	result.query_mode = url_params.query_mode;
	result.host = std::move(host);
	result.encoded_path = std::move(encoded_path);
	result.encoded_bucket_path = std::move(encoded_bucket_path);
	result.use_ssl = url_params.endpoint.UsesSSL();
	return result;
}

string ParsedS3Url::GetObjectQuery(const string &object_key) const {
	if (query_mode == S3URLQueryMode::PARSE_OPTIONS &&
	    (!query_string.empty() || object_key.find('?') != string::npos)) {
		return '?' + query_string;
	}
	return "";
}

string ParsedS3Url::GetObjectUrl(const string &object_key) const {
	return prefix + bucket + "/" + object_key + GetObjectQuery(object_key);
}

string ParsedS3Url::GetRelativeObjectUrl(const string &object_key, const string &base_key) const {
	if (!StringUtil::StartsWith(object_key, base_key)) {
		throw IOException("Listed S3 object does not start with the requested directory");
	}
	return object_key.substr(base_key.size()) + GetObjectQuery(object_key);
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
