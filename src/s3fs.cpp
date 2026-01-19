#include "s3fs.hpp"

#include "crypto.hpp"
#include "duckdb.hpp"
#ifndef DUCKDB_AMALGAMATION
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "http_state.hpp"
#endif

#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar/string_common.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/storage/buffer_manager.hpp"

#include "create_secret_functions.hpp"
#include "re2/re2.h"

#include <iostream>
#include <thread>
#ifdef EMSCRIPTEN
#define SAME_THREAD_UPLOAD
#endif

namespace duckdb {

HTTPHeaders CreateS3Header(string url, string query, string host, string service, string method,
                           const S3AuthParams &auth_params, string date_now, string datetime_now, string payload_hash,
                           string content_type) {

	HTTPHeaders res;
	res["Host"] = host;
	// If access key is not set, we don't set the headers at all to allow accessing public files through s3 urls
	if (auth_params.secret_access_key.empty() && auth_params.access_key_id.empty()) {
		return res;
	}

	if (payload_hash == "") {
		payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty payload hash
	}

	// we can pass date/time but this is mostly useful in testing. normally we just get the current datetime here.
	if (datetime_now.empty()) {
		auto timestamp = Timestamp::GetCurrentTimestamp();
		date_now = StrfTimeFormat::Format(timestamp, "%Y%m%d");
		datetime_now = StrfTimeFormat::Format(timestamp, "%Y%m%dT%H%M%SZ");
	}

	// Only some S3 operations supports SSE-KMS, which this "heuristic" attempts to detect.
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/specifying-kms-encryption.html#sse-request-headers-kms
	bool use_sse_kms = auth_params.kms_key_id.length() > 0 && (method == "POST" || method == "PUT") &&
	                   query.find("uploadId") == std::string::npos;

	res["x-amz-date"] = datetime_now;
	res["x-amz-content-sha256"] = payload_hash;
	if (auth_params.session_token.length() > 0) {
		res["x-amz-security-token"] = auth_params.session_token;
	}
	if (use_sse_kms) {
		res["x-amz-server-side-encryption"] = "aws:kms";
		res["x-amz-server-side-encryption-aws-kms-key-id"] = auth_params.kms_key_id;
	}

	bool use_requester_pays = auth_params.requester_pays;
	if (use_requester_pays) {
		res["x-amz-request-payer"] = "requester";
	}

	string signed_headers = "";
	hash_bytes canonical_request_hash;
	hash_str canonical_request_hash_str;
	if (content_type.length() > 0) {
		signed_headers += "content-type;";
#ifdef EMSCRIPTEN
		res["content-type"] = content_type;
#endif
	}
	signed_headers += "host;x-amz-content-sha256;x-amz-date";
	if (use_requester_pays) {
		signed_headers += ";x-amz-request-payer";
	}
	if (auth_params.session_token.length() > 0) {
		signed_headers += ";x-amz-security-token";
	}
	if (use_sse_kms) {
		signed_headers += ";x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id";
	}
	auto canonical_request = method + "\n" + S3FileSystem::UrlEncode(url) + "\n" + query;
	if (content_type.length() > 0) {
		canonical_request += "\ncontent-type:" + content_type;
	}
	canonical_request += "\nhost:" + host + "\nx-amz-content-sha256:" + payload_hash + "\nx-amz-date:" + datetime_now;
	if (use_requester_pays) {
		canonical_request += "\nx-amz-request-payer:requester";
	}
	if (auth_params.session_token.length() > 0) {
		canonical_request += "\nx-amz-security-token:" + auth_params.session_token;
	}
	if (use_sse_kms) {
		canonical_request += "\nx-amz-server-side-encryption:aws:kms";
		canonical_request += "\nx-amz-server-side-encryption-aws-kms-key-id:" + auth_params.kms_key_id;
	}

	canonical_request += "\n\n" + signed_headers + "\n" + payload_hash;
	sha256(canonical_request.c_str(), canonical_request.length(), canonical_request_hash);

	hex256(canonical_request_hash, canonical_request_hash_str);
	auto string_to_sign = "AWS4-HMAC-SHA256\n" + datetime_now + "\n" + date_now + "/" + auth_params.region + "/" +
	                      service + "/aws4_request\n" + string((char *)canonical_request_hash_str, sizeof(hash_str));
	// compute signature
	hash_bytes k_date, k_region, k_service, signing_key, signature;
	hash_str signature_str;
	auto sign_key = "AWS4" + auth_params.secret_access_key;
	hmac256(date_now, sign_key.c_str(), sign_key.length(), k_date);
	hmac256(auth_params.region, k_date, k_region);
	hmac256(service, k_region, k_service);
	hmac256("aws4_request", k_service, signing_key);
	hmac256(string_to_sign, signing_key, signature);
	hex256(signature, signature_str);

	res["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + auth_params.access_key_id + "/" + date_now + "/" +
	                       auth_params.region + "/" + service + "/aws4_request, SignedHeaders=" + signed_headers +
	                       ", Signature=" + string((char *)signature_str, sizeof(hash_str));

	return res;
}

string S3FileSystem::UrlDecode(string input) {
	return StringUtil::URLDecode(input, true);
}

string S3FileSystem::UrlEncode(const string &input, bool encode_slash) {
	return StringUtil::URLEncode(input, encode_slash);
}

static bool IsGCSRequest(const string &url) {
	return StringUtil::StartsWith(url, "gcs://") || StringUtil::StartsWith(url, "gs://");
}

void AWSEnvironmentCredentialsProvider::SetExtensionOptionValue(string key, const char *env_var_name,
                                                                vector<AWSEnvVarToConfigHelper> &ret) {
	char *evar;

	Value val;
	if ((evar = std::getenv(env_var_name)) != NULL) {
		if (StringUtil::Lower(evar) == "false") {
			// db_config.SetOption(key, Value(false));
			val = Value(false);
		} else if (StringUtil::Lower(evar) == "true") {
			// db_config.SetOption(key, Value(true));
			val = Value(true);
		} else {
			val = Value(evar);
		}
		config.options.set_variables[key] = val;
		ret.emplace_back(env_var_name, key, val.ToString());
	}
}

vector<AWSEnvVarToConfigHelper> AWSEnvironmentCredentialsProvider::SetAll() {
	vector<AWSEnvVarToConfigHelper> ret;
	SetExtensionOptionValue("s3_region", DEFAULT_REGION_ENV_VAR, ret);
	SetExtensionOptionValue("s3_region", REGION_ENV_VAR, ret);
	SetExtensionOptionValue("s3_access_key_id", ACCESS_KEY_ENV_VAR, ret);
	SetExtensionOptionValue("s3_secret_access_key", SECRET_KEY_ENV_VAR, ret);
	SetExtensionOptionValue("s3_session_token", SESSION_TOKEN_ENV_VAR, ret);
	auto duckdb_settings = SetDuckDBSettings();
	for (auto &val : duckdb_settings) {
		ret.emplace_back(val);
	}
	return ret;
}

vector<AWSEnvVarToConfigHelper> AWSEnvironmentCredentialsProvider::SetDuckDBSettings() {
	vector<AWSEnvVarToConfigHelper> ret;
	SetExtensionOptionValue("s3_endpoint", DUCKDB_ENDPOINT_ENV_VAR, ret);
	SetExtensionOptionValue("s3_use_ssl", DUCKDB_USE_SSL_ENV_VAR, ret);
	SetExtensionOptionValue("s3_kms_key_id", DUCKDB_KMS_KEY_ID_ENV_VAR, ret);
	SetExtensionOptionValue("s3_requester_pays", DUCKDB_REQUESTER_PAYS_ENV_VAR, ret);
	return ret;
}

S3AuthParams AWSEnvironmentCredentialsProvider::CreateParams() {
	S3AuthParams params;

	params.region = DEFAULT_REGION_ENV_VAR;
	params.region = REGION_ENV_VAR;
	params.access_key_id = ACCESS_KEY_ENV_VAR;
	params.secret_access_key = SECRET_KEY_ENV_VAR;
	params.session_token = SESSION_TOKEN_ENV_VAR;
	params.endpoint = DUCKDB_ENDPOINT_ENV_VAR;
	params.kms_key_id = DUCKDB_KMS_KEY_ID_ENV_VAR;
	params.use_ssl = DUCKDB_USE_SSL_ENV_VAR;
	params.requester_pays = DUCKDB_REQUESTER_PAYS_ENV_VAR;

	return params;
}

S3AuthParams S3AuthParams::ReadFrom(optional_ptr<FileOpener> opener, FileOpenerInfo &info) {

	// Without a FileOpener we can not access settings nor secrets: return empty auth params
	if (!opener) {
		return {};
	}

	const char *secret_types[] = {"s3", "r2", "gcs", "aws"};
	S3KeyValueReader secret_reader(*opener, info, secret_types, 3);

	return ReadFrom(secret_reader, info.file_path);
}

S3AuthParams S3AuthParams::ReadFrom(S3KeyValueReader &secret_reader, const std::string &file_path) {
	auto result = S3AuthParams();

	// These settings we just set or leave to their S3AuthParams default value
	secret_reader.TryGetSecretKeyOrSetting("region", "s3_region", result.region);
	secret_reader.TryGetSecretKeyOrSetting("key_id", "s3_access_key_id", result.access_key_id);
	secret_reader.TryGetSecretKeyOrSetting("secret", "s3_secret_access_key", result.secret_access_key);
	secret_reader.TryGetSecretKeyOrSetting("session_token", "s3_session_token", result.session_token);
	secret_reader.TryGetSecretKeyOrSetting("region", "s3_region", result.region);
	secret_reader.TryGetSecretKeyOrSetting("use_ssl", "s3_use_ssl", result.use_ssl);
	secret_reader.TryGetSecretKeyOrSetting("kms_key_id", "s3_kms_key_id", result.kms_key_id);
	secret_reader.TryGetSecretKeyOrSetting("s3_url_compatibility_mode", "s3_url_compatibility_mode",
	                                       result.s3_url_compatibility_mode);
	secret_reader.TryGetSecretKeyOrSetting("requester_pays", "s3_requester_pays", result.requester_pays);
	// Endpoint and url style are slightly more complex and require special handling for gcs and r2
	auto endpoint_result = secret_reader.TryGetSecretKeyOrSetting("endpoint", "s3_endpoint", result.endpoint);
	auto url_style_result = secret_reader.TryGetSecretKeyOrSetting("url_style", "s3_url_style", result.url_style);

	if (StringUtil::StartsWith(file_path, "gcs://") || StringUtil::StartsWith(file_path, "gs://")) {
		// For GCS urls we force the endpoint and vhost path style, allowing only to be overridden by secrets
		if (result.endpoint.empty() || endpoint_result.GetScope() != SettingScope::SECRET) {
			result.endpoint = "storage.googleapis.com";
		}
		if (result.url_style.empty() || url_style_result.GetScope() != SettingScope::SECRET) {
			result.url_style = "path";
		}
		// Read bearer token for GCS
		secret_reader.TryGetSecretKey("bearer_token", result.oauth2_bearer_token);
	}

	if (!result.region.empty() && (result.endpoint.empty() || result.endpoint == "s3.amazonaws.com")) {
		result.endpoint = StringUtil::Format("s3.%s.amazonaws.com", result.region);
	} else if (result.endpoint.empty()) {
		result.endpoint = "s3.amazonaws.com";
	}

	return result;
}

unique_ptr<KeyValueSecret> CreateSecret(vector<string> &prefix_paths_p, string &type, string &provider, string &name,
                                        S3AuthParams &params) {
	auto return_value = make_uniq<KeyValueSecret>(prefix_paths_p, type, provider, name);

	//! Set key value map
	return_value->secret_map["region"] = params.region;
	return_value->secret_map["key_id"] = params.access_key_id;
	return_value->secret_map["secret"] = params.secret_access_key;
	return_value->secret_map["session_token"] = params.session_token;
	return_value->secret_map["endpoint"] = params.endpoint;
	return_value->secret_map["url_style"] = params.url_style;
	return_value->secret_map["use_ssl"] = params.use_ssl;
	return_value->secret_map["kms_key_id"] = params.kms_key_id;
	return_value->secret_map["s3_url_compatibility_mode"] = params.s3_url_compatibility_mode;
	return_value->secret_map["requester_pays"] = params.requester_pays;
	return_value->secret_map["bearer_token"] = params.oauth2_bearer_token;

	//! Set redact keys
	return_value->redact_keys = {"secret", "session_token"};
	if (!params.oauth2_bearer_token.empty()) {
		return_value->redact_keys.insert("bearer_token");
	}

	return return_value;
}

S3FileHandle::~S3FileHandle() {
	if (Exception::UncaughtException()) {
		// We are in an exception, don't do anything
		return;
	}

	try {
		Close();
	} catch (...) { // NOLINT
	}
}

S3ConfigParams S3ConfigParams::ReadFrom(optional_ptr<FileOpener> opener) {
	uint64_t uploader_max_filesize;
	uint64_t max_parts_per_file;
	uint64_t max_upload_threads;
	Value value;

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_max_filesize", value)) {
		uploader_max_filesize = DBConfig::ParseMemoryLimit(value.GetValue<string>());
	} else {
		uploader_max_filesize = S3ConfigParams::DEFAULT_MAX_FILESIZE;
	}

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_max_parts_per_file", value)) {
		max_parts_per_file = value.GetValue<uint64_t>();
	} else {
		max_parts_per_file = S3ConfigParams::DEFAULT_MAX_PARTS_PER_FILE; // AWS Default
	}

	if (FileOpener::TryGetCurrentSetting(opener, "s3_uploader_thread_limit", value)) {
		max_upload_threads = value.GetValue<uint64_t>();
	} else {
		max_upload_threads = S3ConfigParams::DEFAULT_MAX_UPLOAD_THREADS;
	}

	return {uploader_max_filesize, max_parts_per_file, max_upload_threads};
}

void S3FileHandle::Close() {
	auto &s3fs = (S3FileSystem &)file_system;
	if (flags.OpenForWriting() && !upload_finalized) {
		s3fs.FlushAllBuffers(*this);
		if (parts_uploaded) {
			s3fs.FinalizeMultipartUpload(*this);
		}
	}
}

unique_ptr<HTTPClient> S3FileHandle::CreateClient() {
	auto parsed_url = S3FileSystem::S3UrlParse(path, this->auth_params);

	string proto_host_port = parsed_url.http_proto + parsed_url.host;
	return http_params.http_util.InitializeClient(http_params, proto_host_port);
}

// Opens the multipart upload and returns the ID
string S3FileSystem::InitializeMultipartUpload(S3FileHandle &file_handle) {
	auto &s3fs = (S3FileSystem &)file_handle.file_system;

	// AWS response is around 300~ chars in docs so this should be enough to not need a resize
	string result;
	string query_param = "uploads=";
	auto res = s3fs.PostRequest(file_handle, file_handle.path, {}, result, nullptr, 0, query_param);

	if (res->status != HTTPStatusCode::OK_200) {
		throw HTTPException(*res, "Unable to connect to URL %s: %s (HTTP code %d)", res->url, res->GetError(),
		                    static_cast<int>(res->status));
	}

	auto open_tag_pos = result.find("<UploadId>", 0);
	auto close_tag_pos = result.find("</UploadId>", open_tag_pos);

	if (open_tag_pos == string::npos || close_tag_pos == string::npos) {
		throw HTTPException("Unexpected response while initializing S3 multipart upload");
	}

	open_tag_pos += 10; // Skip open tag

	file_handle.initialized_multipart_upload = true;

	return result.substr(open_tag_pos, close_tag_pos - open_tag_pos);
}

void S3FileSystem::NotifyUploadsInProgress(S3FileHandle &file_handle) {
	{
		unique_lock<mutex> lck(file_handle.uploads_in_progress_lock);
		file_handle.uploads_in_progress--;
	}
	// Note that there are 2 cv's because otherwise we might deadlock when the final flushing thread is notified while
	// another thread is still waiting for an upload thread
#ifndef SAME_THREAD_UPLOAD
	file_handle.uploads_in_progress_cv.notify_one();
	file_handle.final_flush_cv.notify_one();
#endif
}

void S3FileSystem::UploadBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer) {
	string query_param = "partNumber=" + to_string(write_buffer->part_no + 1) + "&" +
	                     "uploadId=" + S3FileSystem::UrlEncode(file_handle.multipart_upload_id, true);

	UploadBufferImplementation(file_handle, write_buffer, query_param, false);

	NotifyUploadsInProgress(file_handle);
}

void S3FileSystem::UploadSingleBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer) {
	UploadBufferImplementation(file_handle, write_buffer, "", true);
}

void S3FileSystem::UploadBufferImplementation(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer,
                                              string query_param, bool single_upload) {
	auto &s3fs = (S3FileSystem &)file_handle.file_system;

	unique_ptr<HTTPResponse> res;
	string etag;

	try {
		res = s3fs.PutRequest(file_handle, file_handle.path, {}, (char *)write_buffer->Ptr(), write_buffer->idx,
		                      query_param);

		if (res->status != HTTPStatusCode::OK_200) {
			throw HTTPException(*res, "Unable to connect to URL %s: %s (HTTP code %d)", res->url, res->GetError(),
			                    static_cast<int>(res->status));
		}

		if (!res->headers.HasHeader("ETag")) {
			throw IOException("Unexpected response when uploading part to S3");
		}
		etag = res->headers.GetHeaderValue("ETag");
	} catch (std::exception &ex) {
		if (single_upload) {
			throw;
		}
		ErrorData error(ex);
		if (error.Type() != ExceptionType::IO && error.Type() != ExceptionType::HTTP) {
			throw;
		}
		// Ensure only one thread sets the exception
		bool f = false;
		auto exchanged = file_handle.uploader_has_error.compare_exchange_strong(f, true);
		if (exchanged) {
			file_handle.upload_exception = std::current_exception();
		}

		D_ASSERT(!single_upload); // If we are here we are in the multi-buffer situation
		NotifyUploadsInProgress(file_handle);
		return;
	}

	// Insert etag
	{
		unique_lock<mutex> lck(file_handle.part_etags_lock);
		file_handle.part_etags.insert(std::pair<uint16_t, string>(write_buffer->part_no, etag));
	}

	file_handle.parts_uploaded++;

	// Free up space for another thread to acquire an S3WriteBuffer
	write_buffer.reset();
}

void S3FileSystem::FlushBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer) {
	if (write_buffer->idx == 0) {
		return;
	}

	auto uploading = write_buffer->uploading.load();
	if (uploading) {
		return;
	}
	bool can_upload = write_buffer->uploading.compare_exchange_strong(uploading, true);
	if (!can_upload) {
		return;
	}

	file_handle.RethrowIOError();

	{
		unique_lock<mutex> lck(file_handle.write_buffers_lock);
		file_handle.write_buffers.erase(write_buffer->part_no);
	}

	{
		unique_lock<mutex> lck(file_handle.uploads_in_progress_lock);
		// check if there are upload threads available
#ifndef SAME_THREAD_UPLOAD
		if (file_handle.uploads_in_progress >= file_handle.config_params.max_upload_threads) {
			// there are not - wait for one to become available
			file_handle.uploads_in_progress_cv.wait(lck, [&file_handle] {
				return file_handle.uploads_in_progress < file_handle.config_params.max_upload_threads;
			});
		}
#endif
		file_handle.uploads_in_progress++;
	}
	if (file_handle.initialized_multipart_upload == false) {
		file_handle.multipart_upload_id = InitializeMultipartUpload(file_handle);
	}

#ifdef SAME_THREAD_UPLOAD
	UploadBuffer(file_handle, write_buffer);
	return;
#endif

	thread upload_thread(UploadBuffer, std::ref(file_handle), write_buffer);
	upload_thread.detach();
}

// Note that FlushAll currently does not allow to continue writing afterwards. Therefore, FinalizeMultipartUpload should
// be called right after it!
// TODO: we can fix this by keeping the last partially written buffer in memory and allow reuploading it with new data.
void S3FileSystem::FlushAllBuffers(S3FileHandle &file_handle) {
	//  Collect references to all buffers to check
	vector<shared_ptr<S3WriteBuffer>> to_flush;
	file_handle.write_buffers_lock.lock();
	for (auto &item : file_handle.write_buffers) {
		to_flush.push_back(item.second);
	}
	file_handle.write_buffers_lock.unlock();

	if (file_handle.initialized_multipart_upload == false) {
		// TODO (carlo): unclear how to handle kms_key_id, but given currently they are custom, leave the multiupload
		// codepath in that case
		if (to_flush.size() == 1 && file_handle.auth_params.kms_key_id.empty()) {
			UploadSingleBuffer(file_handle, to_flush[0]);
			file_handle.upload_finalized = true;
			return;
		} else {
			file_handle.multipart_upload_id = InitializeMultipartUpload(file_handle);
		}
	}
	// Flush all buffers that aren't already uploading
	for (auto &write_buffer : to_flush) {
		if (!write_buffer->uploading) {
			FlushBuffer(file_handle, write_buffer);
		}
	}
	unique_lock<mutex> lck(file_handle.uploads_in_progress_lock);
#ifndef SAME_THREAD_UPLOAD
	file_handle.final_flush_cv.wait(lck, [&file_handle] { return file_handle.uploads_in_progress == 0; });
#endif

	file_handle.RethrowIOError();
}

void S3FileSystem::FinalizeMultipartUpload(S3FileHandle &file_handle) {
	auto &s3fs = (S3FileSystem &)file_handle.file_system;
	if (file_handle.upload_finalized) {
		return;
	}

	file_handle.upload_finalized = true;

	std::stringstream ss;
	ss << "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";

	auto parts = file_handle.parts_uploaded.load();
	for (auto i = 0; i < parts; i++) {
		auto etag_lookup = file_handle.part_etags.find(i);
		if (etag_lookup == file_handle.part_etags.end()) {
			throw IOException("Unknown part number");
		}
		ss << "<Part><ETag>" << etag_lookup->second << "</ETag><PartNumber>" << i + 1 << "</PartNumber></Part>";
	}
	ss << "</CompleteMultipartUpload>";
	string body = ss.str();

	// Response is around ~400 in AWS docs so this should be enough to not need a resize
	string result;

	string query_param = "uploadId=" + S3FileSystem::UrlEncode(file_handle.multipart_upload_id, true);
	auto res =
	    s3fs.PostRequest(file_handle, file_handle.path, {}, result, (char *)body.c_str(), body.length(), query_param);
	auto open_tag_pos = result.find("<CompleteMultipartUploadResult", 0);
	if (open_tag_pos == string::npos) {
		throw HTTPException(*res, "Unexpected response during S3 multipart upload finalization: %d\n\n%s",
		                    static_cast<int>(res->status), result);
	}
}

// Wrapper around the BufferManager::Allocate to that allows limiting the number of buffers that will be handed out
BufferHandle S3FileSystem::Allocate(idx_t part_size, uint16_t max_threads) {
	return buffer_manager.Allocate(MemoryTag::EXTENSION, part_size);
}

shared_ptr<S3WriteBuffer> S3FileHandle::GetBuffer(uint16_t write_buffer_idx) {
	auto &s3fs = (S3FileSystem &)file_system;

	// Check if write buffer already exists
	{
		unique_lock<mutex> lck(write_buffers_lock);
		auto lookup_result = write_buffers.find(write_buffer_idx);
		if (lookup_result != write_buffers.end()) {
			shared_ptr<S3WriteBuffer> buffer = lookup_result->second;
			return buffer;
		}
	}

	auto buffer_handle = s3fs.Allocate(part_size, config_params.max_upload_threads);
	auto new_write_buffer =
	    make_shared_ptr<S3WriteBuffer>(write_buffer_idx * part_size, part_size, std::move(buffer_handle));
	{
		unique_lock<mutex> lck(write_buffers_lock);
		auto lookup_result = write_buffers.find(write_buffer_idx);

		// Check if other thread has created the same buffer, if so we return theirs and drop ours.
		if (lookup_result != write_buffers.end()) {
			// write_buffer_idx << std::endl;
			shared_ptr<S3WriteBuffer> write_buffer = lookup_result->second;
			return write_buffer;
		}
		write_buffers.insert(pair<uint16_t, shared_ptr<S3WriteBuffer>>(write_buffer_idx, new_write_buffer));
	}

	return new_write_buffer;
}

void GetQueryParam(const string &key, string &param, unordered_map<string, string> &query_params) {
	auto found_param = query_params.find(key);
	if (found_param != query_params.end()) {
		param = found_param->second;
		query_params.erase(found_param);
	}
}

void S3FileSystem::ReadQueryParams(const string &url_query_param, S3AuthParams &params) {
	if (url_query_param.empty()) {
		return;
	}

	auto query_params = HTTPFSUtil::ParseGetParameters(url_query_param);

	GetQueryParam("s3_region", params.region, query_params);
	GetQueryParam("s3_access_key_id", params.access_key_id, query_params);
	GetQueryParam("s3_secret_access_key", params.secret_access_key, query_params);
	GetQueryParam("s3_session_token", params.session_token, query_params);
	GetQueryParam("s3_endpoint", params.endpoint, query_params);
	GetQueryParam("s3_url_style", params.url_style, query_params);
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
	if (!query_params.empty()) {
		throw IOException("Invalid query parameters found. Supported parameters are:\n's3_region', 's3_access_key_id', "
		                  "'s3_secret_access_key', 's3_session_token',\n's3_endpoint', 's3_url_style', 's3_use_ssl', "
		                  "'s3_requester_pays'");
	}
}

string S3FileSystem::TryGetPrefix(const string &url) {
	const string prefixes[] = {"s3://", "s3a://", "s3n://", "gcs://", "gs://", "r2://"};
	for (auto &prefix : prefixes) {
		if (StringUtil::StartsWith(StringUtil::Lower(url), prefix)) {
			return prefix;
		}
	}
	return {};
}

string S3FileSystem::GetPrefix(const string &url) {
	auto prefix = TryGetPrefix(url);
	if (prefix.empty()) {
		throw IOException("URL needs to start with s3://, gcs:// or r2://");
	}
	return prefix;
}

ParsedS3Url S3FileSystem::S3UrlParse(string url, S3AuthParams &params) {
	string http_proto, prefix, host, bucket, key, path, query_param, trimmed_s3_url;

	prefix = GetPrefix(url);
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
	if (params.url_style == "vhost" || params.url_style == "") {
		host = bucket + "." + host;
	} else if (params.url_style == "path") {
		path += "/" + bucket;
	}

	// Append key (including leading slash) to the path
	path += key;

	// Remove leading slash from key
	key = key.substr(1);

	http_proto = params.use_ssl ? "https://" : "http://";

	return {http_proto, prefix, host, bucket, key, path, query_param, trimmed_s3_url};
}

string S3FileSystem::GetPayloadHash(char *buffer, idx_t buffer_len) {
	if (buffer_len > 0) {
		hash_bytes payload_hash_bytes;
		hash_str payload_hash_str;
		sha256(buffer, buffer_len, payload_hash_bytes);
		hex256(payload_hash_bytes, payload_hash_str);
		return string((char *)payload_hash_str, sizeof(payload_hash_str));
	} else {
		return "";
	}
}

string ParsedS3Url::GetHTTPUrl(S3AuthParams &auth_params, const string &http_query_string) {
	string full_url = http_proto + host + S3FileSystem::UrlEncode(path);

	if (!http_query_string.empty()) {
		full_url += "?" + http_query_string;
	}
	return full_url;
}

unique_ptr<HTTPResponse> S3FileSystem::PostRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                   string &result, char *buffer_in, idx_t buffer_in_len,
                                                   string http_params) {
	auto auth_params = handle.Cast<S3FileHandle>().auth_params;
	auto parsed_s3_url = S3UrlParse(url, auth_params);
	string http_url = parsed_s3_url.GetHTTPUrl(auth_params, http_params);

	HTTPHeaders headers;
	if (IsGCSRequest(url) && !auth_params.oauth2_bearer_token.empty()) {
		// Use bearer token for GCS
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = parsed_s3_url.host;
		headers["Content-Type"] = "application/octet-stream";
	} else {
		// Use existing S3 authentication
		auto payload_hash = GetPayloadHash(buffer_in, buffer_in_len);
		headers = CreateS3Header(parsed_s3_url.path, http_params, parsed_s3_url.host, "s3", "POST", auth_params, "", "",
		                         payload_hash, "application/octet-stream");
	}

	return HTTPFileSystem::PostRequest(handle, http_url, headers, result, buffer_in, buffer_in_len);
}

unique_ptr<HTTPResponse> S3FileSystem::PutRequest(FileHandle &handle, string url, HTTPHeaders header_map,
                                                  char *buffer_in, idx_t buffer_in_len, string http_params) {
	auto auth_params = handle.Cast<S3FileHandle>().auth_params;
	auto parsed_s3_url = S3UrlParse(url, auth_params);
	string http_url = parsed_s3_url.GetHTTPUrl(auth_params, http_params);
	auto content_type = "application/octet-stream";

	HTTPHeaders headers;
	if (IsGCSRequest(url) && !auth_params.oauth2_bearer_token.empty()) {
		// Use bearer token for GCS
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = parsed_s3_url.host;
		headers["Content-Type"] = content_type;
	} else {
		// Use existing S3 authentication
		auto payload_hash = GetPayloadHash(buffer_in, buffer_in_len);
		headers = CreateS3Header(parsed_s3_url.path, http_params, parsed_s3_url.host, "s3", "PUT", auth_params, "", "",
		                         payload_hash, content_type);
	}

	return HTTPFileSystem::PutRequest(handle, http_url, headers, buffer_in, buffer_in_len);
}

unique_ptr<HTTPResponse> S3FileSystem::HeadRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) {
	auto auth_params = handle.Cast<S3FileHandle>().auth_params;
	auto parsed_s3_url = S3UrlParse(s3_url, auth_params);
	string http_url = parsed_s3_url.GetHTTPUrl(auth_params);

	HTTPHeaders headers;
	if (IsGCSRequest(s3_url) && !auth_params.oauth2_bearer_token.empty()) {
		// Use bearer token for GCS
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = parsed_s3_url.host;
	} else {
		// Use existing S3 authentication
		headers = CreateS3Header(parsed_s3_url.path, "", parsed_s3_url.host, "s3", "HEAD", auth_params, "", "", "", "");
	}

	return HTTPFileSystem::HeadRequest(handle, http_url, headers);
}

unique_ptr<HTTPResponse> S3FileSystem::GetRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) {
	auto auth_params = handle.Cast<S3FileHandle>().auth_params;
	auto parsed_s3_url = S3UrlParse(s3_url, auth_params);
	string http_url = parsed_s3_url.GetHTTPUrl(auth_params);

	HTTPHeaders headers;
	if (IsGCSRequest(s3_url) && !auth_params.oauth2_bearer_token.empty()) {
		// Use bearer token for GCS
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = parsed_s3_url.host;
	} else {
		// Use existing S3 authentication
		headers = CreateS3Header(parsed_s3_url.path, "", parsed_s3_url.host, "s3", "GET", auth_params, "", "", "", "");
	}

	return HTTPFileSystem::GetRequest(handle, http_url, headers);
}

unique_ptr<HTTPResponse> S3FileSystem::GetRangeRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map,
                                                       idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto auth_params = handle.Cast<S3FileHandle>().auth_params;
	auto parsed_s3_url = S3UrlParse(s3_url, auth_params);
	string http_url = parsed_s3_url.GetHTTPUrl(auth_params);

	HTTPHeaders headers;
	if (IsGCSRequest(s3_url) && !auth_params.oauth2_bearer_token.empty()) {
		// Use bearer token for GCS
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = parsed_s3_url.host;
	} else {
		// Use existing S3 authentication
		headers = CreateS3Header(parsed_s3_url.path, "", parsed_s3_url.host, "s3", "GET", auth_params, "", "", "", "");
	}

	return HTTPFileSystem::GetRangeRequest(handle, http_url, headers, file_offset, buffer_out, buffer_out_len);
}

unique_ptr<HTTPResponse> S3FileSystem::DeleteRequest(FileHandle &handle, string s3_url, HTTPHeaders header_map) {
	auto auth_params = handle.Cast<S3FileHandle>().auth_params;
	auto parsed_s3_url = S3UrlParse(s3_url, auth_params);
	string http_url = parsed_s3_url.GetHTTPUrl(auth_params);

	HTTPHeaders headers;
	if (IsGCSRequest(s3_url) && !auth_params.oauth2_bearer_token.empty()) {
		// Use bearer token for GCS
		headers["Authorization"] = "Bearer " + auth_params.oauth2_bearer_token;
		headers["Host"] = parsed_s3_url.host;
	} else {
		// Use existing S3 authentication
		headers =
		    CreateS3Header(parsed_s3_url.path, "", parsed_s3_url.host, "s3", "DELETE", auth_params, "", "", "", "");
	}

	return HTTPFileSystem::DeleteRequest(handle, http_url, headers);
}

unique_ptr<HTTPFileHandle> S3FileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                      optional_ptr<FileOpener> opener) {
	FileOpenerInfo info = {file.path};
	S3AuthParams auth_params = S3AuthParams::ReadFrom(opener, info);

	// Scan the query string for any s3 authentication parameters
	auto parsed_s3_url = S3UrlParse(file.path, auth_params);
	ReadQueryParams(parsed_s3_url.query_param, auth_params);

	auto http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util->InitializeParameters(opener, info);

	return duckdb::make_uniq<S3FileHandle>(*this, file, flags, std::move(params), auth_params,
	                                       S3ConfigParams::ReadFrom(opener));
}

void S3FileHandle::Initialize(optional_ptr<FileOpener> opener) {
	try {
		HTTPFileHandle::Initialize(opener);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		bool refreshed_secret = false;
		if (error.Type() == ExceptionType::IO || error.Type() == ExceptionType::HTTP) {
			// legacy endpoint (no region) returns 400
			auto context = opener->TryGetClientContext();
			if (context) {
				auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*context);
				for (const string type : {"s3", "r2", "gcs", "aws"}) {
					auto res = context->db->GetSecretManager().LookupSecret(transaction, path, type);
					if (res.HasMatch()) {
						refreshed_secret |= CreateS3SecretFunctions::TryRefreshS3Secret(*context, *res.secret_entry);
					}
				}
			}
		}
		if (!refreshed_secret) {
			auto &extra_info = error.ExtraInfo();
			auto entry = extra_info.find("status_code");
			if (entry != extra_info.end()) {
				if (entry->second == "301" || entry->second == "400") {
					auto new_region = extra_info.find("header_x-amz-bucket-region");
					string correct_region = "";
					if (new_region != extra_info.end()) {
						correct_region = new_region->second;
					}
					auto extra_text = S3FileSystem::GetS3BadRequestError(auth_params, correct_region);
					throw Exception(extra_info, error.Type(), error.RawMessage() + extra_text);
				}
				if (entry->second == "403") {
					// 403: FORBIDDEN
					string extra_text;
					if (IsGCSRequest(path)) {
						extra_text = S3FileSystem::GetGCSAuthError(auth_params);
					} else {
						extra_text = S3FileSystem::GetS3AuthError(auth_params);
					}
					throw Exception(extra_info, error.Type(), error.RawMessage() + extra_text);
				}
			}
			throw;
		}
		// We have succesfully refreshed a secret: retry initializing with new credentials
		FileOpenerInfo info = {path};
		auth_params = S3AuthParams::ReadFrom(opener, info);
		HTTPFileHandle::Initialize(opener);
	}

	if (flags.OpenForWriting()) {
		auto aws_minimum_part_size = 5242880; // 5 MiB https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
		auto max_part_count = config_params.max_parts_per_file;
		auto required_part_size = config_params.max_file_size / max_part_count;
		auto minimum_part_size = MaxValue<idx_t>(aws_minimum_part_size, required_part_size);

		// Round part size up to multiple of Storage::DEFAULT_BLOCK_SIZE
		part_size = ((minimum_part_size + Storage::DEFAULT_BLOCK_SIZE - 1) / Storage::DEFAULT_BLOCK_SIZE) *
		            Storage::DEFAULT_BLOCK_SIZE;
		D_ASSERT(part_size * max_part_count >= config_params.max_file_size);
	}
}

bool S3FileSystem::CanHandleFile(const string &fpath) {

	return fpath.rfind("s3://", 0) * fpath.rfind("s3a://", 0) * fpath.rfind("s3n://", 0) * fpath.rfind("gcs://", 0) *
	           fpath.rfind("gs://", 0) * fpath.rfind("r2://", 0) ==
	       0;
}

void S3FileSystem::RemoveFile(const string &path, optional_ptr<FileOpener> opener) {
	auto handle = OpenFile(path, FileFlags::FILE_FLAGS_NULL_IF_NOT_EXISTS, opener);
	if (!handle) {
		throw IOException({{"errno", "404"}}, "Could not remove file \"%s\": %s", path, "No such file or directory");
	}

	auto &s3fh = handle->Cast<S3FileHandle>();
	auto res = DeleteRequest(*handle, s3fh.path, {});
	if (res->status != HTTPStatusCode::OK_200 && res->status != HTTPStatusCode::NoContent_204) {
		throw IOException({{"errno", to_string(static_cast<int>(res->status))}}, "Could not remove file \"%s\": %s",
		                  path, res->GetError());
	}
}

void S3FileSystem::RemoveDirectory(const string &path, optional_ptr<FileOpener> opener) {
	ListFiles(
	    path,
	    [&](const string &file, bool is_dir) {
		    try {
			    this->RemoveFile(file, opener);
		    } catch (IOException &e) {
			    string errmsg(e.what());
			    if (errmsg.find("No such file or directory") != std::string::npos) {
				    return;
			    }
			    throw;
		    }
	    },
	    opener.get());
}

void S3FileSystem::FileSync(FileHandle &handle) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	if (!s3fh.upload_finalized) {
		FlushAllBuffers(s3fh);
		FinalizeMultipartUpload(s3fh);
	}
}

void S3FileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	if (!s3fh.flags.OpenForWriting()) {
		throw InternalException("Write called on file not opened in write mode");
	}
	int64_t bytes_written = 0;

	while (bytes_written < nr_bytes) {
		auto curr_location = location + bytes_written;

		if (curr_location != s3fh.file_offset) {
			throw InternalException("Non-sequential write not supported!");
		}

		// Find buffer for writing
		auto write_buffer_idx = curr_location / s3fh.part_size;

		// Get write buffer, may block until buffer is available
		auto write_buffer = s3fh.GetBuffer(write_buffer_idx);

		// Writing to buffer
		auto idx_to_write = curr_location - write_buffer->buffer_start;
		auto bytes_to_write = MinValue<idx_t>(nr_bytes - bytes_written, s3fh.part_size - idx_to_write);
		memcpy((char *)write_buffer->Ptr() + idx_to_write, (char *)buffer + bytes_written, bytes_to_write);
		write_buffer->idx += bytes_to_write;

		// Flush to HTTP if full
		if (write_buffer->idx >= s3fh.part_size) {
			FlushBuffer(s3fh, write_buffer);
		}
		s3fh.file_offset += bytes_to_write;
		s3fh.length += bytes_to_write;
		bytes_written += bytes_to_write;
	}

	DUCKDB_LOG_FILE_SYSTEM_WRITE(handle, bytes_written, s3fh.file_offset - bytes_written);
}

static bool Match(vector<string>::const_iterator key, vector<string>::const_iterator key_end,
                  vector<string>::const_iterator pattern, vector<string>::const_iterator pattern_end) {

	while (key != key_end && pattern != pattern_end) {
		if (*pattern == "**") {
			if (std::next(pattern) == pattern_end) {
				return true;
			}
			while (key != key_end) {
				if (Match(key, key_end, std::next(pattern), pattern_end)) {
					return true;
				}
				key++;
			}
			return false;
		}
		if (!Glob(key->data(), key->length(), pattern->data(), pattern->length())) {
			return false;
		}
		key++;
		pattern++;
	}
	return key == key_end && pattern == pattern_end;
}

vector<OpenFileInfo> S3FileSystem::Glob(const string &glob_pattern, FileOpener *opener) {
	if (opener == nullptr) {
		throw InternalException("Cannot S3 Glob without FileOpener");
	}

	FileOpenerInfo info = {glob_pattern};

	// Trim any query parameters from the string
	S3AuthParams s3_auth_params = S3AuthParams::ReadFrom(opener, info);

	// In url compatibility mode, we ignore globs allowing users to query files with the glob chars
	if (s3_auth_params.s3_url_compatibility_mode) {
		return {glob_pattern};
	}

	auto parsed_s3_url = S3UrlParse(glob_pattern, s3_auth_params);
	auto parsed_glob_url = parsed_s3_url.trimmed_s3_url;

	// AWS matches on prefix, not glob pattern, so we take a substring until the first wildcard char for the aws calls
	auto first_wildcard_pos = parsed_glob_url.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		return {glob_pattern};
	}

	string shared_path = parsed_glob_url.substr(0, first_wildcard_pos);
	auto http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto http_params = http_util->InitializeParameters(opener, info);

	ReadQueryParams(parsed_s3_url.query_param, s3_auth_params);

	// Do main listobjectsv2 request
	vector<OpenFileInfo> s3_keys;
	string main_continuation_token;

	// Main paging loop
	do {
		// main listobject call, may
		string response_str = AWSListObjectV2::Request(shared_path, *http_params, s3_auth_params,
		                                               main_continuation_token, HTTPState::TryGetState(opener).get());
		main_continuation_token = AWSListObjectV2::ParseContinuationToken(response_str);
		AWSListObjectV2::ParseFileList(response_str, s3_keys);

		// Repeat requests until the keys of all common prefixes are parsed.
		auto common_prefixes = AWSListObjectV2::ParseCommonPrefix(response_str);
		while (!common_prefixes.empty()) {
			auto prefix_path = parsed_s3_url.prefix + parsed_s3_url.bucket + '/' + common_prefixes.back();
			common_prefixes.pop_back();

			// TODO we could optimize here by doing a match on the prefix, if it doesn't match we can skip this prefix
			// Paging loop for common prefix requests
			string common_prefix_continuation_token;
			do {
				auto prefix_res =
				    AWSListObjectV2::Request(prefix_path, *http_params, s3_auth_params,
				                             common_prefix_continuation_token, HTTPState::TryGetState(opener).get());
				AWSListObjectV2::ParseFileList(prefix_res, s3_keys);
				auto more_prefixes = AWSListObjectV2::ParseCommonPrefix(prefix_res);
				common_prefixes.insert(common_prefixes.end(), more_prefixes.begin(), more_prefixes.end());
				common_prefix_continuation_token = AWSListObjectV2::ParseContinuationToken(prefix_res);
			} while (!common_prefix_continuation_token.empty());
		}
	} while (!main_continuation_token.empty());

	vector<string> pattern_splits = StringUtil::Split(parsed_s3_url.key, "/");
	vector<OpenFileInfo> result;
	for (auto &s3_key : s3_keys) {

		vector<string> key_splits = StringUtil::Split(s3_key.path, "/");
		bool is_match = Match(key_splits.begin(), key_splits.end(), pattern_splits.begin(), pattern_splits.end());

		if (is_match) {
			auto result_full_url = parsed_s3_url.prefix + parsed_s3_url.bucket + "/" + s3_key.path;
			// if a ? char was present, we re-add it here as the url parsing will have trimmed it.
			if (!parsed_s3_url.query_param.empty()) {
				result_full_url += '?' + parsed_s3_url.query_param;
			}
			s3_key.path = std::move(result_full_url);
			result.push_back(std::move(s3_key));
		}
	}
	return result;
}

string S3FileSystem::GetName() const {
	return "S3FileSystem";
}

bool S3FileSystem::ListFiles(const string &directory, const std::function<void(const string &, bool)> &callback,
                             FileOpener *opener) {
	string trimmed_dir = directory;
	StringUtil::RTrim(trimmed_dir, PathSeparator(trimmed_dir));
	auto glob_res = Glob(JoinPath(trimmed_dir, "**"), opener);

	if (glob_res.empty()) {
		return false;
	}

	for (const auto &file : glob_res) {
		callback(file.path, false);
	}

	return true;
}

string S3FileSystem::GetS3BadRequestError(S3AuthParams &s3_auth_params, string correct_region) {
	string extra_text = "\n\nBad Request - this can be caused by the S3 region being set incorrectly.";
	if (s3_auth_params.region.empty()) {
		extra_text += "\n* No region is provided.";
	} else {
		extra_text += "\n* Provided region is: \"" + s3_auth_params.region + "\"";
	}
	if (!correct_region.empty()) {
		extra_text += "\n* Correct region is: \"" + correct_region + "\"";
	}
	return extra_text;
}

string S3FileSystem::GetS3AuthError(S3AuthParams &s3_auth_params) {
	string extra_text = "\n\nAuthentication Failure - this is usually caused by invalid or missing credentials.";
	if (s3_auth_params.secret_access_key.empty() && s3_auth_params.access_key_id.empty()) {
		extra_text += "\n* No credentials are provided.";
	} else {
		extra_text += "\n* Credentials are provided, but they did not work.";
	}
	extra_text += "\n* See https://duckdb.org/docs/stable/extensions/httpfs/s3api.html";
	return extra_text;
}

string S3FileSystem::GetGCSAuthError(S3AuthParams &s3_auth_params) {
	string extra_text = "\n\nAuthentication Failure - GCS authentication failed.";
	if (s3_auth_params.oauth2_bearer_token.empty() && s3_auth_params.secret_access_key.empty() &&
	    s3_auth_params.access_key_id.empty()) {
		extra_text += "\n* No credentials provided.";
		extra_text += "\n* For OAuth2: CREATE SECRET (TYPE GCS, bearer_token 'your-token')";
		extra_text += "\n* For HMAC: CREATE SECRET (TYPE GCS, key_id 'key', secret 'secret')";
	} else if (!s3_auth_params.oauth2_bearer_token.empty()) {
		extra_text += "\n* Bearer token was provided but authentication failed.";
		extra_text += "\n* Ensure your OAuth2 token is valid and not expired.";
	} else {
		extra_text += "\n* HMAC credentials were provided but authentication failed.";
		extra_text += "\n* Ensure your HMAC key_id and secret are correct.";
	}
	return extra_text;
}

HTTPException S3FileSystem::GetS3Error(S3AuthParams &s3_auth_params, const HTTPResponse &response, const string &url) {
	string extra_text;
	if (response.status == HTTPStatusCode::BadRequest_400) {
		extra_text = GetS3BadRequestError(s3_auth_params);
	}
	if (response.status == HTTPStatusCode::Forbidden_403) {
		extra_text = GetS3AuthError(s3_auth_params);
	}
	auto status_message = HTTPFSUtil::GetStatusMessage(response.status);
	throw HTTPException(response, "HTTP GET error reading '%s' in region '%s' (HTTP %d %s)%s", url,
	                    s3_auth_params.region, response.status, status_message, extra_text);
}

HTTPException S3FileSystem::GetHTTPError(FileHandle &handle, const HTTPResponse &response, const string &url) {
	auto &s3_handle = handle.Cast<S3FileHandle>();

	// Use GCS-specific error for GCS URLs
	if (IsGCSRequest(url) && response.status == HTTPStatusCode::Forbidden_403) {
		string extra_text = GetGCSAuthError(s3_handle.auth_params);
		auto status_message = HTTPFSUtil::GetStatusMessage(response.status);
		throw HTTPException(response, "HTTP error on '%s' (HTTP %d %s)%s", url, response.status, status_message,
		                    extra_text);
	}

	return GetS3Error(s3_handle.auth_params, response, url);
}
string AWSListObjectV2::Request(string &path, HTTPParams &http_params, S3AuthParams &s3_auth_params,
                                string &continuation_token, optional_ptr<HTTPState> state, bool use_delimiter) {
	auto parsed_url = S3FileSystem::S3UrlParse(path, s3_auth_params);

	// Construct the ListObjectsV2 call
	string req_path = parsed_url.path.substr(0, parsed_url.path.length() - parsed_url.key.length());

	string req_params;
	if (!continuation_token.empty()) {
		req_params += "continuation-token=" + S3FileSystem::UrlEncode(continuation_token, true);
		req_params += "&";
	}
	req_params += "encoding-type=url&list-type=2";
	req_params += "&prefix=" + S3FileSystem::UrlEncode(parsed_url.key, true);

	if (use_delimiter) {
		req_params += "&delimiter=%2F";
	}

	auto header_map =
	    CreateS3Header(req_path, req_params, parsed_url.host, "s3", "GET", s3_auth_params, "", "", "", "");

	// Get requests use fresh connection
	string full_host = parsed_url.http_proto + parsed_url.host;
	string listobjectv2_url = full_host + req_path + "?" + req_params;
	std::stringstream response;
	GetRequestInfo get_request(
	    full_host, listobjectv2_url, header_map, http_params,
	    [&](const HTTPResponse &response) {
		    if (static_cast<int>(response.status) >= 400) {
			    string trimmed_path = path;
			    StringUtil::RTrim(trimmed_path, "/");
			    trimmed_path += listobjectv2_url;
			    throw S3FileSystem::GetS3Error(s3_auth_params, response, trimmed_path);
		    }
		    return true;
	    },
	    [&](const_data_ptr_t data, idx_t data_length) {
		    response << string(const_char_ptr_cast(data), data_length);
		    return true;
	    });
	auto result = http_params.http_util.Request(get_request);
	if (result->HasRequestError()) {
		throw IOException("%s error for HTTP GET to '%s'", result->GetRequestError(), listobjectv2_url);
	}

	return response.str();
}

optional_idx FindTagContents(const string &response, const string &tag, idx_t cur_pos, string &result) {
	string open_tag = "<" + tag + ">";
	string close_tag = "</" + tag + ">";
	auto open_tag_pos = response.find(open_tag, cur_pos);
	if (open_tag_pos == string::npos) {
		// tag not found
		return optional_idx();
	}
	auto close_tag_pos = response.find(close_tag, open_tag_pos + open_tag.size());
	if (close_tag_pos == string::npos) {
		throw InternalException("Failed to parse S3 result: found open tag for %s but did not find matching close tag",
		                        tag);
	}
	result = response.substr(open_tag_pos + open_tag.size(), close_tag_pos - open_tag_pos - open_tag.size());
	return close_tag_pos + close_tag.size();
}

void AWSListObjectV2::ParseFileList(string &aws_response, vector<OpenFileInfo> &result) {
	// Example S3 response:
	//	<Contents>
	//		<Key>lineitem_sf10_partitioned_shipdate/l_shipdate%3D1997-03-28/data_0.parquet</Key>
	//		<LastModified>2024-11-09T11:38:08.000Z</LastModified>
	//		<ETag>&quot;bdf10f525f8355fb80d1ff2d8c62cc8b&quot;</ETag>
	//		<Size>1127863</Size>
	//		<StorageClass>STANDARD</StorageClass>
	//	</Contents>
	idx_t cur_pos = 0;
	while (true) {
		string contents;
		auto next_pos = FindTagContents(aws_response, "Contents", cur_pos, contents);
		if (!next_pos.IsValid()) {
			// exhausted all contents
			break;
		}
		// move to the next position
		cur_pos = next_pos.GetIndex();

		// parse the contents
		string key;
		auto key_pos = FindTagContents(contents, "Key", 0, key);
		if (!key_pos.IsValid()) {
			throw InternalException("Key not found in S3 response: %s", contents);
		}
		auto parsed_path = S3FileSystem::UrlDecode(key);
		if (parsed_path.back() == '/') {
			// not a file but a directory
			continue;
		}
		// construct the file
		OpenFileInfo result_file(parsed_path);

		auto extra_info = make_shared_ptr<ExtendedOpenFileInfo>();
		// get file attributes
		string last_modified, etag, size;
		auto last_modified_pos = FindTagContents(contents, "LastModified", 0, last_modified);
		if (last_modified_pos.IsValid()) {
			extra_info->options["last_modified"] = Value(last_modified).DefaultCastAs(LogicalType::TIMESTAMP);
		}
		auto etag_pos = FindTagContents(contents, "ETag", 0, etag);
		if (etag_pos.IsValid()) {
			etag = StringUtil::Replace(etag, "&quot;", "\"");
			etag = StringUtil::Replace(etag, "&#34;", "\"");
			extra_info->options["etag"] = Value(std::move(etag));
		}
		auto size_pos = FindTagContents(contents, "Size", 0, size);
		if (size_pos.IsValid()) {
			extra_info->options["file_size"] = Value(size).DefaultCastAs(LogicalType::UBIGINT);
		}
		result_file.extended_info = std::move(extra_info);
		result.push_back(std::move(result_file));
	}
}

string AWSListObjectV2::ParseContinuationToken(string &aws_response) {

	auto open_tag_pos = aws_response.find("<NextContinuationToken>");
	if (open_tag_pos == string::npos) {
		return "";
	} else {
		auto close_tag_pos = aws_response.find("</NextContinuationToken>", open_tag_pos + 23);
		if (close_tag_pos == string::npos) {
			throw InternalException("Failed to parse S3 result");
		}
		return aws_response.substr(open_tag_pos + 23, close_tag_pos - open_tag_pos - 23);
	}
}

vector<string> AWSListObjectV2::ParseCommonPrefix(string &aws_response) {
	vector<string> s3_prefixes;
	idx_t cur_pos = 0;
	while (true) {
		cur_pos = aws_response.find("<CommonPrefixes>", cur_pos);
		if (cur_pos == string::npos) {
			break;
		}
		auto next_open_tag_pos = aws_response.find("<Prefix>", cur_pos);
		if (next_open_tag_pos == string::npos) {
			throw InternalException("Parsing error while parsing s3 listobject result");
		} else {
			auto next_close_tag_pos = aws_response.find("</Prefix>", next_open_tag_pos + 8);
			if (next_close_tag_pos == string::npos) {
				throw InternalException("Failed to parse S3 result");
			}
			auto parsed_path = aws_response.substr(next_open_tag_pos + 8, next_close_tag_pos - next_open_tag_pos - 8);
			s3_prefixes.push_back(parsed_path);
			cur_pos = next_close_tag_pos + 6;
		}
	}
	return s3_prefixes;
}

S3KeyValueReader::S3KeyValueReader(FileOpener &opener_p, optional_ptr<FileOpenerInfo> info, const char **secret_types,
                                   idx_t secret_types_len)
    : reader(opener_p, info, secret_types, secret_types_len) {
}

} // namespace duckdb
