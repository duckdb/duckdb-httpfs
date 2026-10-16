#pragma once

#include "s3/s3_auth.hpp"
#include "http/http_object_version.hpp"

namespace duckdb {

class ParsedS3Url {
	friend struct S3Url;

private:
	ParsedS3Url() = default;

public:
	//! Logical S3 URL
	const string &GetPrefix() const;
	const string &GetBucket() const;
	const string &GetKey() const;
	const string &GetQueryString() const;
	string GetObjectUrl(const string &object_key) const;
	string GetRelativeObjectUrl(const string &object_key, const string &base_key) const;
	const HTTPObjectVersion &GetObjectVersion() const;

	//! HTTP request target
	string GetHTTPUrl(const string &http_query_string = "") const;
	string GetBucketHTTPUrl(const string &http_query_string = "") const;
	const string &GetHost() const;
	const string &GetEncodedPath() const;
	const string &GetEncodedBucketPath() const;

private:
	string GetObjectQuery(const string &object_key) const;
	string BuildHTTPUrl(const string &request_path, const string &http_query_string) const;

private:
	//! Logical S3 URL
	string prefix;
	string bucket;
	string key;
	string query_string;
	S3URLQueryMode query_mode = S3URLQueryMode::PARSE_OPTIONS;

	//! Explicit object version, independent of credentials and endpoint routing
	HTTPObjectVersion object_version;

	//! HTTP request target
	string host;
	string encoded_path;
	string encoded_bucket_path;
	bool use_ssl = true;
};

enum class S3URLEncodeMode : uint8_t { PATH, QUERY_COMPONENT };

struct S3Url {
	struct PathComponents {
		string path;
		string query;
	};

	static PathComponents Split(const string &url, S3URLQueryMode mode);
	static string Decode(const string &input);
	static string Encode(const string &input, S3URLEncodeMode mode);
	static S3AuthQueryParameters ParseAuthQueryParameters(const string &query, S3ProviderType provider);
	static ParsedS3Url Parse(const string &url, const S3AuthParams &params);
	static ParsedS3Url Parse(const string &url, const S3ProviderMatch &route, const S3AuthURLParams &params);
	static string GetDisplayUrl(const string &url, const S3AuthParams &params);

private:
	static unordered_map<string, string> ParseQueryParameters(const string &url_query_param);
};

} // namespace duckdb
