#include "s3/s3_url.hpp"

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
	if (config.route.type == S3ProviderType::GCS) {
		GetQueryParam("gcs_user_project", request_options.user_project, query_params);
	}
	if (!query_params.empty()) {
		auto supported_parameters =
		    string("'s3_region', 's3_access_key_id', 's3_secret_access_key', 's3_session_token',\n's3_endpoint', "
		           "'s3_url_style', 's3_use_ssl', 's3_requester_pays'");
		if (config.route.type == S3ProviderType::GCS) {
			supported_parameters += ", 'gcs_user_project'";
		}
		throw IOException("Invalid query parameters found. Supported parameters are:\n%s", supported_parameters);
	}
}

void S3Url::ApplyAuthQueryParameters(const string &url, S3AuthConfig &config) {
	if (config.compatibility_mode) {
		return;
	}
	auto question_pos = url.find_first_of('?');
	if (question_pos != string::npos) {
		ReadQueryParams(url.substr(question_pos + 1), config);
	}
}

string S3Url::GetDisplayUrl(const string &url, const S3AuthParams &params) {
	if (params.GetURLParams().compatibility_mode) {
		return url;
	}
	auto query_position = url.find('?');
	return query_position == string::npos ? url : url.substr(0, query_position);
}

ParsedS3Url S3Url::Parse(const string &url, const S3AuthParams &params) {
	string prefix, host, bucket, key, encoded_path, encoded_bucket_path, query_string;

	auto &route = params.GetProvider().GetRoute();
	prefix = route.prefix;
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

	if (params.GetURLParams().compatibility_mode) {
		// In url compatibility mode, we will ignore any special chars, so query param strings are disabled
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
		host = bucket + "." + host;
	}
	encoded_bucket_path = encoded_path.empty() ? "/" : encoded_path + "/";

	// Append key (including leading slash) to the path
	encoded_path += Encode(key, S3URLEncodeMode::PATH);

	// Remove leading slash from key
	key = key.substr(1);

	ParsedS3Url result;
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
