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

void S3Url::ReadQueryParams(const string &url_query_param, S3AuthParams &params) {
	if (url_query_param.empty()) {
		return;
	}

	auto query_params = ParseQueryParameters(url_query_param);

	GetQueryParam("s3_region", params.region, query_params);
	GetQueryParam("s3_access_key_id", params.access_key_id, query_params);
	GetQueryParam("s3_secret_access_key", params.secret_access_key, query_params);
	GetQueryParam("s3_session_token", params.session_token, query_params);
	string endpoint;
	if (GetQueryParam("s3_endpoint", endpoint, query_params)) {
		params.SetEndpoint(std::move(endpoint));
	}
	if (GetQueryParam("s3_url_style", params.url_style, query_params)) {
		S3Provider::ParseURLStyle(params.url_style);
	}
	auto found_param = query_params.find("s3_use_ssl");
	if (found_param != query_params.end()) {
		if (found_param->second == "true") {
			params.use_ssl = true;
		} else if (found_param->second == "false") {
			params.use_ssl = false;
		} else {
			throw IOException("Incorrect setting found for s3_use_ssl, allowed values are: 'true' or 'false'");
		}
		query_params.erase(found_param);
	}
	auto found_requester_pays_param = query_params.find("s3_requester_pays");
	if (found_requester_pays_param != query_params.end()) {
		if (found_requester_pays_param->second == "true") {
			params.requester_pays = true;
		} else if (found_requester_pays_param->second == "false") {
			params.requester_pays = false;
		} else {
			throw IOException("Incorrect setting found for s3_requester_pays, allowed values are: 'true' or 'false'");
		}
		query_params.erase(found_requester_pays_param);
	}
	if (params.provider_type == S3ProviderType::GCS) {
		GetQueryParam("gcs_user_project", params.user_project, query_params);
	}
	if (!query_params.empty()) {
		auto supported_parameters =
		    string("'s3_region', 's3_access_key_id', 's3_secret_access_key', 's3_session_token',\n's3_endpoint', "
		           "'s3_url_style', 's3_use_ssl', 's3_requester_pays'");
		if (params.provider_type == S3ProviderType::GCS) {
			supported_parameters += ", 'gcs_user_project'";
		}
		throw IOException("Invalid query parameters found. Supported parameters are:\n%s", supported_parameters);
	}
}

ParsedS3Url S3Url::Resolve(const string &url, S3AuthParams &params) {
	auto parsed_url = Parse(url, params);
	// The last source of an endpoint, so validation happens after it
	ReadQueryParams(parsed_url.query_param, params);
	S3Provider::FinalizeAuthParams(params);
	return Parse(url, params);
}

string S3Url::GetDisplayUrl(const string &url, const S3AuthParams &params) {
	if (params.s3_url_compatibility_mode) {
		return url;
	}
	auto query_position = url.find('?');
	return query_position == string::npos ? url : url.substr(0, query_position);
}

ParsedS3Url S3Url::Parse(const string &url, const S3AuthParams &params) {
	string http_proto, prefix, host, bucket, key, path, query_param, trimmed_s3_url;

	auto provider_match = S3Provider::TryMatchUrl(url);
	if (provider_match) {
		D_ASSERT(provider_match->type == params.provider_type);
		prefix = std::move(provider_match->prefix);
	} else {
		// Alias-routed url: the caller already matched it against 's3_url_scheme_aliases'
		D_ASSERT(params.provider_type == S3ProviderType::S3);
		auto scheme_end = url.find("://");
		if (scheme_end == string::npos) {
			S3Provider::MatchUrl(url); // throws with the expected-prefixes message
		}
		prefix = StringUtil::Lower(url.substr(0, scheme_end + 3));
	}
	auto prefix_end_pos = url.find("//") + 2;
	auto slash_pos = url.find('/', prefix_end_pos);
	if (slash_pos == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	bucket = url.substr(prefix_end_pos, slash_pos - prefix_end_pos);
	if (bucket.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}

	if (params.s3_url_compatibility_mode) {
		// In url compatibility mode, we will ignore any special chars, so query param strings are disabled
		trimmed_s3_url = url;
		key += url.substr(slash_pos);
	} else {
		// Parse query parameters
		auto question_pos = url.find_first_of('?');
		if (question_pos != string::npos) {
			query_param = url.substr(question_pos + 1);
			trimmed_s3_url = url.substr(0, question_pos);
		} else {
			trimmed_s3_url = url;
		}

		if (!query_param.empty()) {
			key += url.substr(slash_pos, question_pos - slash_pos);
		} else {
			key += url.substr(slash_pos);
		}
	}

	if (key.empty()) {
		throw IOException("URL needs to contain key");
	}

	// Derived host and path based on the endpoint
	auto sub_path_pos = params.endpoint.find_first_of('/');
	if (sub_path_pos != string::npos) {
		// Host header should conform to <host>:<port> so not include the path
		host = params.endpoint.substr(0, sub_path_pos);
		path = params.endpoint.substr(sub_path_pos);
	} else {
		host = params.endpoint;
		path = "";
	}

	// Update host and path according to the url style
	// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
	auto url_style = S3Provider::ParseURLStyle(params.url_style);
	bool use_vhost = url_style == S3URLStyle::VIRTUAL_HOSTED;
	// A bucket name containing periods (.) is not addressable vhost-style over TLS. Fallback to path style url
	bool use_path = url_style == S3URLStyle::PATH || (use_vhost && params.use_ssl && bucket.find('.') != string::npos);
	if (use_path) {
		path += "/" + bucket;
	} else if (use_vhost) {
		host = bucket + "." + host;
	}

	// Append key (including leading slash) to the path
	path += key;

	// Remove leading slash from key
	key = key.substr(1);

	http_proto = params.use_ssl ? "https://" : "http://";

	return {http_proto, prefix, host, bucket, key, path, query_param, trimmed_s3_url};
}

string ParsedS3Url::GetHTTPUrl(const string &http_query_string) const {
	string full_url = http_proto + host + S3Url::Encode(path, S3URLEncodeMode::PATH);

	if (!http_query_string.empty()) {
		full_url += "?" + http_query_string;
	}
	return full_url;
}

string ParsedS3Url::GetBucketPath() const {
	auto bucket_path = path.substr(0, path.length() - key.length());
	return bucket_path.empty() ? "/" : bucket_path;
}

} // namespace duckdb
