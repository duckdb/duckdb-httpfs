#pragma once

#include "duckdb/common/common.hpp"

namespace duckdb {

enum class S3XMLResponseType : uint8_t { UNKNOWN, MULTIPART_INITIALIZATION, MULTIPART_COMPLETION, ERROR };

struct S3XMLResponse {
	S3XMLResponseType type = S3XMLResponseType::UNKNOWN;
	string upload_id;
	string etag;
	string error_code;
	string error_message;
	string error_access_key_id;
};

struct S3XMLError {
	string code;
	string message;
	string access_key_id;
};

struct S3ListObjectsV2Object {
	string key;
	string last_modified;
	string etag;
	string size;
};

struct S3ListObjectsV2Result {
	vector<S3ListObjectsV2Object> objects;
	vector<string> common_prefixes;
	string continuation_token;
};

struct S3DeleteObjectsError {
	string key;
	string code;
	string message;
};

struct S3DeleteObjectsResult {
	vector<S3DeleteObjectsError> errors;
};

struct S3XMLResponseParser {
	static bool TryParse(const string &input, S3XMLResponse &response);
	static bool TryParseError(const string &input, S3XMLError &error);
	static bool TryParseListObjectsV2(const string &input, S3ListObjectsV2Result &result);
	static bool TryParseDeleteObjects(const string &input, S3DeleteObjectsResult &result);
};

struct S3XMLWriter {
	static string EscapeText(const string &text);
	static string WriteDeleteObjectsRequest(const vector<string> &keys, idx_t begin, idx_t end);
	static string WriteCompleteMultipartUploadRequest(const vector<string> &etags);
};

} // namespace duckdb
