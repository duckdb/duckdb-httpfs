#pragma once

#include "s3/s3_auth.hpp"

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

	//! HTTP request target
	string GetHTTPUrl(const string &http_query_string = "") const;
	string GetBucketHTTPUrl(const string &http_query_string = "") const;
	const string &GetHost() const;
	const string &GetEncodedPath() const;
	const string &GetEncodedBucketPath() const;

private:
	string BuildHTTPUrl(const string &request_path, const string &http_query_string) const;

private:
	//! Logical S3 URL
	string prefix;
	string bucket;
	string key;
	string query_string;

	//! HTTP request target
	string host;
	string encoded_path;
	string encoded_bucket_path;
	bool use_ssl = true;
};

enum class S3URLEncodeMode : uint8_t { PATH, QUERY_COMPONENT };

struct S3Url {
	static string Decode(const string &input);
	static string Encode(const string &input, S3URLEncodeMode mode);
	static ParsedS3Url Parse(const string &url, const S3AuthParams &params);
	static ParsedS3Url Resolve(const string &url, S3AuthParams &params);
	static string GetDisplayUrl(const string &url, const S3AuthParams &params);

private:
	static unordered_map<string, string> ParseQueryParameters(const string &url_query_param);
	static void ReadQueryParams(const string &url_query_param, S3AuthParams &params);
};

} // namespace duckdb
