#include "http/httpfs.hpp"
#include "s3/s3_provider.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/logging/log_manager.hpp"

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/operator/add.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/operator/multiply.hpp"
#include "duckdb/common/operator/subtract.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/common/types/interval.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "http/http_state.hpp"

#include <map>
#include <string>

namespace duckdb {

void RangeRequestNotSupportedException::Throw() {
	throw HTTPException(MESSAGE);
}

HTTPUtil &HTTPFSUtil::GetHTTPUtil(optional_ptr<FileOpener> opener) {
	if (opener) {
		return opener->GetHTTPUtil();
	}
	throw InternalException("FileOpener not provided, can't get HTTPUtil");
}

void HTTPFSUtil::LogRequest(BaseRequest &request, optional_ptr<HTTPResponse> response) {
	if (!request.params.logger || !request.params.logger->ShouldLog(HTTPLogType::NAME, HTTPLogType::LEVEL)) {
		return;
	}
	if (!request.headers.HasHeader("x-amz-server-side-encryption-customer-key")) {
		HTTPUtil::LogRequest(request, response);
		return;
	}
	auto sanitized_request = request;
	sanitized_request.headers["x-amz-server-side-encryption-customer-key"] = "redacted";
	HTTPUtil::LogRequest(sanitized_request, response);
}

struct HTTPParametersInitializer {
private:
	HTTPParametersInitializer(HTTPFSUtil &httpfs_util_p, optional_ptr<FileOpener> opener_p,
	                          optional_ptr<FileOpenerInfo> info_p)
	    : httpfs_util(httpfs_util_p), opener(opener_p), info(info_p), result(make_uniq<HTTPFSParams>(httpfs_util)) {
	}

public:
	static unique_ptr<HTTPParams> Create(HTTPFSUtil &httpfs_util, optional_ptr<FileOpener> opener,
	                                     optional_ptr<FileOpenerInfo> info) {
		HTTPParametersInitializer initializer(httpfs_util, opener, info);
		return initializer.Initialize();
	}

private:
	unique_ptr<HTTPParams> Initialize() {
		result->Initialize(opener);
		result->state = HTTPState::TryGetState(opener);
		result->client_reuse_mode = httpfs_util.GetClientReuseMode();
		result->httpfs_util = httpfs_util;
		if (!opener) {
			return std::move(result);
		}
		ReadSettings();
		SetUserAgent();
		auto settings_reader = CreateSettingsReader();
		ReadSecrets(*settings_reader);
		return std::move(result);
	}

	void ReadSettings() {
		FileOpener::TryGetCurrentSetting(opener, "http_timeout", result->timeout, info);
		FileOpener::TryGetCurrentSetting(opener, "force_download", result->force_download, info);
		FileOpener::TryGetCurrentSetting(opener, "force_download_threshold", result->force_download_threshold, info);
		FileOpener::TryGetCurrentSetting(opener, "auto_fallback_to_full_download",
		                                 result->auto_fallback_to_full_download, info);
		FileOpener::TryGetCurrentSetting(opener, "http_retries", result->retries, info);
		FileOpener::TryGetCurrentSetting(opener, "http_retry_wait_ms", result->retry_wait_ms, info);
		FileOpener::TryGetCurrentSetting(opener, "http_retry_backoff", result->retry_backoff, info);
		FileOpener::TryGetCurrentSetting(opener, "http_keep_alive", result->keep_alive, info);
		FileOpener::TryGetCurrentSetting(opener, "enable_curl_server_cert_verification",
		                                 result->enable_curl_server_cert_verification, info);
		FileOpener::TryGetCurrentSetting(opener, "enable_server_cert_verification",
		                                 result->enable_server_cert_verification, info);
		FileOpener::TryGetCurrentSetting(opener, "ca_cert_file", result->ca_cert_file, info);
		FileOpener::TryGetCurrentSetting(opener, "hf_max_per_page", result->hf_max_per_page, info);
		FileOpener::TryGetCurrentSetting(opener, "unsafe_disable_etag_checks", result->unsafe_disable_etag_checks,
		                                 info);
		FileOpener::TryGetCurrentSetting(opener, "s3_version_id_pinning", result->s3_version_id_pinning, info);
		auto context = FileOpener::TryGetClientContext(opener);
		Value external_cache_enabled;
		if (context &&
		    context->TryGetCurrentUserSetting(EnableExternalFileCacheSetting::SettingIndex, external_cache_enabled) &&
		    external_cache_enabled.GetValue<bool>()) {
			result->override_response_cache_policy = true;
		} else if (context &&
		           Settings::Get<ValidateExternalFileCacheSetting>(*context) == CacheValidationMode::NO_VALIDATION) {
			result->override_response_cache_policy = true;
		}

		// The base set of headers for every request - a matching secret merges over these per key
		Value extra_http_headers;
		if (TryGetSetting("extra_http_headers", extra_http_headers)) {
			MergeExtraHeaders(extra_http_headers);
		}
	}

	SettingLookupResult TryGetSetting(const Identifier &key, Value &value) {
		if (info) {
			return FileOpener::TryGetCurrentSetting(opener, key, value, *info);
		}
		return FileOpener::TryGetCurrentSetting(opener, key, value);
	}

	void MergeExtraHeaders(const Value &headers) {
		if (headers.IsNull()) {
			return;
		}
		if (headers.type().id() != LogicalTypeId::MAP) {
			throw InvalidInputException("extra_http_headers must be a MAP(VARCHAR, VARCHAR), got \"%s\"",
			                            headers.type().ToString());
		}
		for (const auto &child : MapValue::GetChildren(headers)) {
			auto key_value = StructValue::GetChildren(child);
			if (key_value[1].IsNull()) {
				throw InvalidInputException("extra_http_headers value for \"%s\" must not be NULL",
				                            key_value[0].GetValue<string>());
			}
			result->extra_headers[key_value[0].GetValue<string>()] = key_value[1].GetValue<string>();
		}
	}

	void SetUserAgent() {
		auto db = FileOpener::TryGetDatabase(opener);
		if (db) {
			result->user_agent = StringUtil::Format("%s %s", db->config.UserAgent(), DuckDB::SourceID());
		}
	}

	bool IsS3Path() {
		if (!info) {
			return false;
		}
		auto db = FileOpener::TryGetDatabase(opener);
		auto aliases = db ? S3UrlScheme::GetAliasPrefixes(db->config) : vector<string>();
		return S3UrlScheme::TryMatch(info->file_path, aliases).has_value();
	}

	unique_ptr<KeyValueSecretReader> CreateSettingsReader() {
		if (IsS3Path()) {
			auto provider_secret_types = S3SecretConfig::SecretTypes();
			vector<const char *> s3_secret_types(provider_secret_types.begin(), provider_secret_types.end());
			s3_secret_types.push_back("http");
			idx_t secret_type_count = s3_secret_types.size();
			Value merge_http_secret_into_s3_request;
			FileOpener::TryGetCurrentSetting(opener, "merge_http_secret_into_s3_request",
			                                 merge_http_secret_into_s3_request);
			if (!merge_http_secret_into_s3_request.IsNull() && !merge_http_secret_into_s3_request.GetValue<bool>()) {
				secret_type_count = provider_secret_types.size();
			}
			return make_uniq<KeyValueSecretReader>(*opener, info, s3_secret_types.data(), secret_type_count);
		}
		return make_uniq<KeyValueSecretReader>(*opener, info, "http");
	}

	void ReadSecrets(KeyValueSecretReader &settings_reader) {
		string proxy_setting;
		if (settings_reader.TryGetSecretKey<string>("http_proxy", proxy_setting) && !proxy_setting.empty()) {
			idx_t port;
			string host;
			HTTPUtil::ParseHTTPProxyHost(proxy_setting, host, port);
			result->http_proxy = host;
			result->http_proxy_port = port;
		}
		result->override_verify_ssl = settings_reader.TryGetSecretKey<bool>("verify_ssl", result->verify_ssl);
		settings_reader.TryGetSecretKey<string>("http_proxy_username", result->http_proxy_username);
		settings_reader.TryGetSecretKey<string>("http_proxy_password", result->http_proxy_password);
		settings_reader.TryGetSecretKey<string>("bearer_token", result->bearer_token);

		Value extra_headers;
		if (settings_reader.TryGetSecretKey("extra_http_headers", extra_headers)) {
			MergeExtraHeaders(extra_headers);
		}
	}

private:
	HTTPFSUtil &httpfs_util;
	optional_ptr<FileOpener> opener;
	optional_ptr<FileOpenerInfo> info;
	unique_ptr<HTTPFSParams> result;
};

unique_ptr<HTTPParams> HTTPFSUtil::InitializeParameters(optional_ptr<FileOpener> opener,
                                                        optional_ptr<FileOpenerInfo> info) {
	return HTTPParametersInitializer::Create(*this, opener, info);
}

unique_ptr<HTTPParams> HTTPFSParams::Clone() const {
	return make_uniq<HTTPFSParams>(*this);
}

static bool IsStrongETag(string etag) {
	StringUtil::Trim(etag);
	if (etag.size() < 2 || etag.front() != '"' || etag.back() != '"' || StringUtil::StartsWith(etag, "W/")) {
		return false;
	}
	for (idx_t i = 1; i + 1 < etag.size(); i++) {
		const auto character = static_cast<uint8_t>(etag[i]);
		if (character <= 0x20 || character == 0x22 || character == 0x7F) {
			return false;
		}
	}
	return true;
}

HTTPFileHandle::HTTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                               unique_ptr<HTTPParams> params_p, HTTPObjectVersion object_version_p)
    : FileHandle(fs, file.path, flags), request_session(make_shared_ptr<HTTPRequestSession>(
                                            make_shared_ptr<HTTPRequestSnapshot>(params_p->Cast<HTTPFSParams>()))),
      flags(flags), length(0), last_modified(0), force_full_download(false), file_offset(0),
      object_version(std::move(object_version_p)) {
	// check if the handle has extended properties that can be set directly in the handle
	// if we have these properties we don't need to do a head request to obtain them later
	if (file.extended_info) {
		auto &info = file.extended_info->options;
		auto lm_entry = info.find("last_modified");
		if (lm_entry != info.end()) {
			last_modified = lm_entry->second.GetValue<timestamp_t>();
		}
		auto etag_entry = info.find("etag");
		if (etag_entry != info.end()) {
			etag = StringValue::Get(etag_entry->second);
		}
		auto fs_entry = info.find("file_size");
		if (fs_entry != info.end()) {
			length = fs_entry->second.GetValue<uint64_t>();
		}
		auto force_full_download_entry = info.find("force_full_download");
		if (force_full_download_entry != info.end()) {
			force_full_download = force_full_download_entry->second.GetValue<bool>();
		}
		auto validate_cache_entry = info.find("validate_external_file_cache");
		if (validate_cache_entry != info.end() && !validate_cache_entry->second.GetValue<bool>()) {
			auto captured = request_session->Capture();
			auto snapshot_params = captured.snapshot->Params();
			snapshot_params.override_response_cache_policy = true;
			request_session->TryPublish(captured.snapshot, CreateRequestSnapshot(snapshot_params));
		}
		if (lm_entry != info.end() && etag_entry != info.end() && fs_entry != info.end()) {
			// we found all relevant entries (last_modified, etag and file size)
			// skip head request
			initialized = true;
		}
	}
}

HTTPReadConfig HTTPFileHandle::BuildReadConfig() const {
	auto captured = request_session->Capture();
	auto &params = captured.snapshot->Params();

	HTTPReadConfig result;
	result.etag = etag;
	result.validate_etag = !params.unsafe_disable_etag_checks;
	result.auto_fallback_to_full_download =
	    auto_fallback_to_full_file_download && params.auto_fallback_to_full_download;
	if (result.validate_etag && IsStrongETag(result.etag)) {
		result.condition.type = HTTPReadConditionType::ETAG;
		result.condition.value = result.etag;
		StringUtil::Trim(result.condition.value);
	}
	return result;
}

void HTTPFileHandle::FinalizeReadConfig() {
	D_ASSERT(!read_config_initialized);
	read_config = BuildReadConfig();
	read_config_initialized = true;
}

const HTTPReadConfig &HTTPFileHandle::GetReadConfig() const {
	D_ASSERT(read_config_initialized);
	return read_config;
}

const HTTPObjectVersion &HTTPFileHandle::GetObjectVersion() const {
	return object_version;
}

HTTPObjectVersion HTTPFileHandle::ReadObjectVersion(const HTTPHeaders &headers) const {
	return {};
}

unique_ptr<HTTPFileHandle> HTTPFileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                        optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	FileOpenerInfo info;
	info.file_path = file.path;

	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);

	auto secret_manager = FileOpener::TryGetSecretManager(opener);
	auto transaction = FileOpener::TryGetCatalogTransaction(opener);
	if (secret_manager && transaction) {
		auto secret_match = secret_manager->LookupSecret(*transaction, file.path, "bearer");

		if (secret_match.HasMatch()) {
			const auto &kv_secret = secret_match.secret_entry->secret->Cast<KeyValueSecret>();
			auto &httpfs_params = params->Cast<HTTPFSParams>();
			httpfs_params.bearer_token = kv_secret.TryGetValue("token", true).ToString();
		}
	}
	return make_uniq<HTTPFileHandle>(*this, file, flags, std::move(params));
}

unique_ptr<FileHandle> HTTPFileSystem::OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
                                                        optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	if (flags.ReturnNullIfNotExists()) {
		try {
			auto handle = CreateHandle(file, flags, opener);
			handle->Initialize(opener);
			return std::move(handle);
		} catch (...) {
			return nullptr;
		}
	}

	auto handle = CreateHandle(file, flags, opener);

	if (flags.OpenForWriting() && !flags.OpenForAppending() && !flags.OpenForReading()) {
		handle->write_overwrite_mode = true;
	}

	handle->Initialize(opener);

	DUCKDB_LOG_FILE_SYSTEM_OPEN((*handle));

	return std::move(handle);
}

bool HTTPFileSystem::SupportsOpenFileExtended() const {
	return true;
}

void HTTPFileHandle::RecordNetworkSample(double total_seconds, idx_t bytes, bool sample_has_ttfb, double ttfb_seconds) {
	if (!(total_seconds > 0)) {
		return;
	}
	annotated_lock_guard<annotated_mutex> guard(network_estimator_lock);
	const idx_t n = tp_sample_count + 1;
	const double alpha = MaxValue<double>(0.2, 1.0 / static_cast<double>(n));

	if (sample_has_ttfb && ttfb_seconds > 0) {
		tp_latency_seconds =
		    tp_latency_seconds <= 0 ? ttfb_seconds : alpha * ttfb_seconds + (1.0 - alpha) * tp_latency_seconds;
	}

	const double transfer_seconds = sample_has_ttfb ? (total_seconds - ttfb_seconds) : total_seconds;
	if (bytes >= MIN_BANDWIDTH_SAMPLE_BYTES && transfer_seconds > 0) {
		const double bandwidth = static_cast<double>(bytes) / transfer_seconds;
		tp_bandwidth_bps = tp_bandwidth_bps <= 0 ? bandwidth : alpha * bandwidth + (1.0 - alpha) * tp_bandwidth_bps;
	}
	tp_sample_count = n;
}

bool HTTPFileHandle::GetNetworkThroughputEstimate(NetworkThroughputEstimate &result) {
	annotated_lock_guard<annotated_mutex> guard(network_estimator_lock);
	if (tp_sample_count == 0 || tp_latency_seconds <= 0 || tp_bandwidth_bps <= 0) {
		return false;
	}
	result.latency_seconds = tp_latency_seconds;
	result.bandwidth_bytes_per_s = tp_bandwidth_bps;
	return true;
}

static bool RespondedWithRangeRequestNotSupported(const HTTPResponse &res) {
	if (!res.HasRequestError()) {
		return false;
	}
	ErrorData error(res.GetRequestError());
	return error.Type() == RangeRequestNotSupportedException::TYPE &&
	       error.RawMessage() == RangeRequestNotSupportedException::MESSAGE;
}

bool HTTPFileSystem::TryRangeRequest(FileHandle &handle, const string &url, const HTTPHeaders &header_map,
                                     const HTTPReadConfig &read_config, idx_t file_offset, data_ptr_t buffer_out,
                                     idx_t buffer_out_len) {
	auto &hfh = handle.Cast<HTTPFileHandle>();

	auto res = GetRangeRequest(handle, url, header_map, read_config, file_offset, buffer_out, buffer_out_len);

	if (res) {
		ThrowIfReadConditionFailed(hfh, read_config, *res);
		// Request failed and we have a request error
		if (res->HasRequestError()) {
			// Special case: we can do a retry with a full file download
			if (RespondedWithRangeRequestNotSupported(*res) && read_config.auto_fallback_to_full_download) {
				return false;
			}
			ErrorData error(res->GetRequestError());
			error.Throw();
		}

		// Request succeeded TODO: fix upstream that 206 is not considered success
		if (res->Success() || res->status == HTTPStatusCode::PartialContent_206 ||
		    res->status == HTTPStatusCode::Accepted_202) {
			return true;
		}

		throw GetHTTPError(handle, *res, RequestType::GET_REQUEST, url);
	}
	throw IOException("Unknown error for HTTP %s to '%s'", EnumUtil::ToString(RequestType::GET_REQUEST), url);
}

bool HTTPFileSystem::ReadAt(FileHandle &handle, data_ptr_t buffer, idx_t read_size, idx_t location,
                            const HTTPReadConfig &read_config) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	if (read_size > NumericLimits<idx_t>::Maximum() - location) {
		throw IOException("HTTP read range overflow for file \"%s\"", hfh.path);
	}
	auto read_end = location + read_size;

	D_ASSERT(hfh.file_state);
	auto cached_file = hfh.file_state->TryGetCachedFileHandle();
	if (cached_file) {
		ValidateCachedFile(hfh, read_config, *cached_file);
		if (cached_file->GetSize() < read_end) {
			throw IOException("Cached file length can't satisfy the requested Read. You can try to resolve this by "
			                  "enabling `SET force_download=true`");
		}
		if (read_size > 0) {
			memcpy(buffer, cached_file->GetData() + location, read_size);
		}
	} else if (read_size > 0) {
		if (!TryRangeRequest(hfh, hfh.path, {}, read_config, location, buffer, read_size)) {
			return false;
		}
	}

	DUCKDB_LOG_FILE_SYSTEM_READ(handle, NumericCast<int64_t>(read_size), location);
	return true;
}

void HTTPFileSystem::ReadAtWithFallback(FileHandle &handle, data_ptr_t buffer, idx_t read_size, idx_t location,
                                        const HTTPReadConfig &read_config) {
	auto success = ReadAt(handle, buffer, read_size, location, read_config);
	if (success) {
		return;
	}

	// ReadAt returned false. This means the regular path of querying the file with range requests failed. We will
	// attempt to download the full file and retry.

	if (handle.logger) {
		DUCKDB_LOG_WARNING(handle.logger,
		                   "Falling back to full file download for file '%s': the server does not support HTTP range "
		                   "requests. Performance and memory usage are potentially degraded.",
		                   handle.path);
	}

	auto &hfh = handle.Cast<HTTPFileHandle>();
	const auto head_reported_length = hfh.length;

	bool should_write_cache = false;
	auto cached_file = FullDownload(hfh, read_config, should_write_cache);

	const auto downloaded_length = cached_file->GetSize();
	if (downloaded_length != head_reported_length) {
		hfh.file_state->InvalidateCachedFile();
		hfh.request_session->Capture().snapshot->Params().state->EraseFileState(hfh.path);
		throw HTTPException(Exception::ConstructMessage(
		    "The size reported by HEAD for '%s' was %llu bytes, but the full GET downloaded %llu bytes. You can try "
		    "to resolve this by enabling `SET force_download=true`",
		    hfh.path, static_cast<uint64_t>(head_reported_length), static_cast<uint64_t>(downloaded_length)));
	}

	if (!ReadAt(handle, buffer, read_size, location, read_config)) {
		throw HTTPException("Failed to read from HTTP file after automatically retrying a full file download.");
	}
}

void HTTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto read_size = NumericCast<idx_t>(nr_bytes);
	if (read_size == 0) {
		return;
	}
	auto read_config = hfh.GetReadConfig();
	ReadAtWithFallback(handle, data_ptr_cast(buffer), read_size, location, read_config);
}

int64_t HTTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	auto read_size = NumericCast<idx_t>(nr_bytes);
	annotated_lock_guard<annotated_mutex> guard(hfh.cursor_mutex);
	if (read_size == 0 || hfh.file_offset >= hfh.length) {
		return 0;
	}
	read_size = MinValue<idx_t>(hfh.length - hfh.file_offset, read_size);
	const auto location = hfh.file_offset;
	auto read_config = hfh.GetReadConfig();
	ReadAtWithFallback(handle, data_ptr_cast(buffer), read_size, location, read_config);
	hfh.file_offset += read_size;
	return NumericCast<int64_t>(read_size);
}

void HTTPFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	throw NotImplementedException("Writing to HTTP files not implemented");
}

int64_t HTTPFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = handle.Cast<HTTPFileHandle>();
	idx_t location;
	{
		annotated_lock_guard<annotated_mutex> guard(hfh.cursor_mutex);
		location = hfh.file_offset;
	}
	Write(handle, buffer, nr_bytes, location);
	return nr_bytes;
}

void HTTPFileSystem::FileSync(FileHandle &handle) {
	throw NotImplementedException("FileSync for HTTP files not implemented");
}

int64_t HTTPFileSystem::GetFileSize(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return NumericCast<int64_t>(sfh.length);
}

timestamp_t HTTPFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.last_modified;
}

string HTTPFileSystem::GetVersionTag(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.etag;
}

optional<timestamp_t> HTTPFileSystem::GetCacheValidUntil(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	return sfh.GetCacheValidUntil();
}

FileMetadata HTTPFileSystem::Stats(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	FileMetadata metadata;
	metadata.file_size = NumericCast<int64_t>(sfh.length);
	metadata.last_modification_time = sfh.last_modified;
	metadata.file_type = FileType::FILE_TYPE_REGULAR;
	metadata.cache_valid_until = sfh.GetCacheValidUntil();
	metadata.version_tag = GetVersionTag(handle);
	return metadata;
}

bool HTTPFileSystem::FileExists(const string &filename, optional_ptr<FileOpener> opener) {
	try {
		auto handle = OpenFile(filename, FileFlags::FILE_FLAGS_READ, opener);
		(void)handle; // suppress warning
		return true;
	} catch (...) {
		return false;
	};
}

bool HTTPFileSystem::CanHandleFile(const string &fpath) {
	return fpath.rfind("https://", 0) == 0 || fpath.rfind("http://", 0) == 0;
}

vector<OpenFileInfo> HTTPFileSystem::Glob(const string &path, FileOpener *opener) {
	if (path.find('*') != string::npos && opener) {
		Value setting_val;
		if (FileOpener::TryGetCurrentSetting(opener, "allow_asterisks_in_http_paths", setting_val) &&
		    !setting_val.GetValue<bool>()) {
			throw InvalidInputException("Globs (`*`) for generic HTTP file is are not supported.\nConsider `SET "
			                            "allow_asterisks_in_http_paths = true;` to allow this behaviour");
		}
	}
	return {path}; // FIXME
}

bool HTTPFileSystem::CanSeek() {
	return true;
}

bool HTTPFileSystem::OnDiskFile(FileHandle &) {
	return false;
}

bool HTTPFileSystem::TryGetNetworkThroughput(FileHandle &handle, NetworkThroughputEstimate &result) {
	return handle.Cast<HTTPFileHandle>().GetNetworkThroughputEstimate(result);
}

bool HTTPFileSystem::IsPipe(const string &, optional_ptr<FileOpener>) {
	return false;
}

string HTTPFileSystem::GetName() const {
	return "HTTPFileSystem";
}

string HTTPFileSystem::PathSeparator(const string &) {
	return "/";
}

void HTTPFileSystem::Seek(FileHandle &handle, idx_t location) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	annotated_lock_guard<annotated_mutex> guard(sfh.cursor_mutex);
	sfh.file_offset = location;
}

idx_t HTTPFileSystem::SeekPosition(FileHandle &handle) {
	auto &sfh = handle.Cast<HTTPFileHandle>();
	annotated_lock_guard<annotated_mutex> guard(sfh.cursor_mutex);
	return sfh.file_offset;
}

optional_ptr<HTTPMetadataCache> HTTPFileSystem::GetGlobalCache() {
	annotated_lock_guard<annotated_mutex> lock(global_cache_lock);
	if (!global_metadata_cache) {
		global_metadata_cache = make_uniq<HTTPMetadataCache>(HTTPMetadataCacheMode::GLOBAL);
	}
	return global_metadata_cache;
}

void HTTPFileSystem::EraseGlobalCacheEntry(const string &path) {
	annotated_lock_guard<annotated_mutex> lock(global_cache_lock);
	if (global_metadata_cache) {
		global_metadata_cache->Erase(path);
	}
}

// Get either the local, global, or no cache depending on settings
static optional_ptr<HTTPMetadataCache> TryGetMetadataCache(optional_ptr<FileOpener> opener, HTTPFileSystem &httpfs) {
	auto db = FileOpener::TryGetDatabase(opener);
	auto client_context = FileOpener::TryGetClientContext(opener);
	if (!db) {
		return nullptr;
	}

	Value use_shared_cache_val;
	bool use_shared_cache = false;
	FileOpener::TryGetCurrentSetting(opener, "enable_http_metadata_cache", use_shared_cache_val);
	if (!use_shared_cache_val.IsNull()) {
		use_shared_cache = use_shared_cache_val.GetValue<bool>();
	}

	if (use_shared_cache) {
		return httpfs.GetGlobalCache();
	} else if (client_context) {
		return client_context->registered_state->GetOrCreate<HTTPMetadataCache>("http_cache",
		                                                                        HTTPMetadataCacheMode::QUERY_LOCAL);
	}
	return nullptr;
}

unique_ptr<CachedFileHandle> HTTPFileSystem::FullDownload(HTTPFileHandle &hfh, const HTTPReadConfig &read_config,
                                                          bool &should_write_cache) {
	D_ASSERT(hfh.file_state);
	D_ASSERT(hfh.buffer_allocator);
	should_write_cache = false;

	while (true) {
		if (auto cached_file = hfh.file_state->TryGetCachedFileHandle()) {
			ValidateCachedFile(hfh, read_config, *cached_file);
			if (!hfh.initialized) {
				hfh.InitializeFromCacheEntry(cached_file->GetMetadata());
			}
			return cached_file;
		}

		auto download = hfh.file_state->StartCachedFileDownload(*hfh.buffer_allocator);
		if (!download) {
			continue;
		}
		const auto request_time = Timestamp::GetCurrentTimestamp();
		auto full_download_result = GetRequest(hfh, hfh.path, {}, read_config, *download);
		ThrowIfReadConditionFailed(hfh, read_config, *full_download_result);
		if (full_download_result->HasRequestError()) {
			ErrorData(full_download_result->GetRequestError()).Throw();
		}
		if (full_download_result->status != HTTPStatusCode::OK_200) {
			throw GetHTTPError(hfh, *full_download_result, RequestType::GET_REQUEST, hfh.path);
		}
		auto metadata = hfh.ReadFileInfo(*full_download_result, request_time, Timestamp::GetCurrentTimestamp());
		// A successful conditional or version-selected GET also identifies bytes when a response header is absent.
		if (!metadata.object_version.IsSet()) {
			if (read_config.object_version.IsSet()) {
				metadata.object_version = read_config.object_version;
			} else if (read_config.condition.type == HTTPReadConditionType::GCS_GENERATION_MATCH) {
				metadata.object_version =
				    HTTPObjectVersion(HTTPObjectVersionType::GCS_GENERATION, read_config.condition.value);
			}
		}
		if (metadata.etag.empty() && read_config.condition.type == HTTPReadConditionType::ETAG) {
			metadata.etag = read_config.condition.value;
		}
		if (!hfh.initialized) {
			hfh.InitializeFromCacheEntry(metadata);
		}
		// Publish unconditionally: this buffer is query-scoped and shared only among identical requests,
		// so HTTP cache policy (no-store/Vary/freshness) does not restrict it.
		return download->Finalize(std::move(metadata));
	}
}

bool HTTPFileSystem::TryParseLastModifiedTime(const string &timestamp, timestamp_t &result) {
	StrpTimeFormat::ParseResult parse_result;
	if (!StrpTimeFormat::TryParse("%a, %d %h %Y %T %Z", timestamp, parse_result)) {
		return false;
	}
	if (!parse_result.TryToTimestamp(result)) {
		return false;
	}
	return true;
}

static bool TryParseNonNegativeSeconds(const string &input, int64_t &result) {
	return TryCast::Operation<string_t, int64_t>(string_t(input), result) && result >= 0;
}

static vector<string> GetCacheControlDirectives(const HTTPHeaders &headers) {
	vector<string> result;
	if (!headers.HasHeader("Cache-Control")) {
		return result;
	}
	for (const auto &header_value : headers.GetHeaderValues("Cache-Control")) {
		// Commas inside RFC quoted-strings (e.g., no-cache="a,b") are also split; the resulting
		// fragments are either unparseable (ignored) or match a directive name (conservative).
		for (auto &directive : StringUtil::Split(header_value, ',')) {
			result.push_back(std::move(directive));
		}
	}
	return result;
}

static bool HasCacheControlDirective(const HTTPHeaders &headers, const string &name) {
	for (auto directive : GetCacheControlDirectives(headers)) {
		StringUtil::Trim(directive);
		const auto separator = directive.find('=');
		auto directive_name = separator == string::npos ? directive : directive.substr(0, separator);
		StringUtil::Trim(directive_name);
		if (StringUtil::CIEquals(directive_name, name)) {
			return true;
		}
	}
	return false;
}

static bool VaryProhibitsReuse(const HTTPHeaders &headers, const unordered_map<string, string> &request_headers) {
	if (!headers.HasHeader("Vary")) {
		return false;
	}
	for (const auto &header_value : headers.GetHeaderValues("Vary")) {
		for (auto field : StringUtil::Split(header_value, ',')) {
			StringUtil::Trim(field);
			if (field == "*") {
				return true;
			}
			for (const auto &request_header : request_headers) {
				if (StringUtil::CIEquals(field, request_header.first)) {
					return true;
				}
			}
		}
	}
	return false;
}

static bool TryGetCacheControlSeconds(const HTTPHeaders &headers, const string &name, bool &found, int64_t &result) {
	found = false;
	for (auto directive : GetCacheControlDirectives(headers)) {
		StringUtil::Trim(directive);
		const auto separator = directive.find('=');
		if (separator == string::npos) {
			continue;
		}
		auto directive_name = directive.substr(0, separator);
		StringUtil::Trim(directive_name);
		if (!StringUtil::CIEquals(directive_name, name)) {
			continue;
		}
		if (found) {
			return false;
		}
		found = true;
		auto value = directive.substr(separator + 1);
		StringUtil::Trim(value);
		if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
			value = value.substr(1, value.size() - 2);
		}
		if (!TryParseNonNegativeSeconds(value, result)) {
			return false;
		}
	}
	return true;
}

optional<timestamp_t> HTTPFileSystem::ComputeCacheValidUntil(const HTTPHeaders &headers, timestamp_t request_time,
                                                             timestamp_t response_time) {
	// Freshness lifetime in seconds (RFC 9111): s-maxage takes precedence over max-age, then Expires.
	if (HasCacheControlDirective(headers, "no-cache")) {
		return timestamp_t::ninfinity();
	}
	int64_t freshness_lifetime = 0;
	bool has_freshness_lifetime;
	if (!TryGetCacheControlSeconds(headers, "s-maxage", has_freshness_lifetime, freshness_lifetime)) {
		return timestamp_t::ninfinity();
	}
	if (!has_freshness_lifetime &&
	    !TryGetCacheControlSeconds(headers, "max-age", has_freshness_lifetime, freshness_lifetime)) {
		return timestamp_t::ninfinity();
	}
	if (!has_freshness_lifetime && headers.HasHeader("Expires")) {
		timestamp_t expires;
		if (TryParseLastModifiedTime(headers.GetHeaderValue("Expires"), expires)) {
			timestamp_t reference_time;
			bool has_reference_time = true;
			if (headers.HasHeader("Date")) {
				has_reference_time = TryParseLastModifiedTime(headers.GetHeaderValue("Date"), reference_time);
			} else {
				reference_time = response_time;
			}
			int64_t freshness_micros;
			if (has_reference_time && TrySubtractOperator::Operation(expires, reference_time, freshness_micros)) {
				freshness_lifetime = freshness_micros / Interval::MICROS_PER_SEC;
				has_freshness_lifetime = true;
			}
		}
	}
	if (!has_freshness_lifetime) {
		if (headers.HasHeader("Expires")) {
			return timestamp_t::ninfinity();
		}
		return nullopt;
	}

	// Account for Age, response delay, and the apparent age derived from Date (RFC 9111).
	int64_t age = 0;
	if (headers.HasHeader("Age")) {
		if (!TryParseNonNegativeSeconds(headers.GetHeaderValue("Age"), age)) {
			age = 0;
		}
	}
	int64_t age_micros = 0;
	int64_t response_delay_micros = 0;
	if (!TryMultiplyOperator::Operation(age, Interval::MICROS_PER_SEC, age_micros) ||
	    !TrySubtractOperator::Operation(response_time, request_time, response_delay_micros)) {
		return timestamp_t::ninfinity();
	}
	response_delay_micros = MaxValue<int64_t>(0, response_delay_micros);
	int64_t current_age_micros = 0;
	if (!TryAddOperator::Operation(age_micros, response_delay_micros, current_age_micros)) {
		return timestamp_t::ninfinity();
	}
	if (headers.HasHeader("Date")) {
		timestamp_t date;
		if (TryParseLastModifiedTime(headers.GetHeaderValue("Date"), date)) {
			int64_t apparent_age_micros;
			if (!TrySubtractOperator::Operation(response_time, date, apparent_age_micros)) {
				return timestamp_t::ninfinity();
			}
			current_age_micros = MaxValue<int64_t>(current_age_micros, MaxValue<int64_t>(0, apparent_age_micros));
		}
	}

	int64_t freshness_micros = 0;
	if (freshness_lifetime <= 0 ||
	    !TryMultiplyOperator::Operation(freshness_lifetime, Interval::MICROS_PER_SEC, freshness_micros) ||
	    current_age_micros >= freshness_micros) {
		return timestamp_t::ninfinity();
	}
	// Absurd server-provided lifetimes that would overflow the deadline grant no freshness
	int64_t deadline_micros = 0;
	const auto remaining_micros = freshness_micros - current_age_micros;
	if (!TryAddOperator::Operation(response_time.value, remaining_micros, deadline_micros)) {
		return timestamp_t::ninfinity();
	}
	return timestamp_t(deadline_micros);
}

void HTTPFileHandle::ApplyCachePolicy(const HTTPResponse &response, timestamp_t request_time,
                                      timestamp_t response_time) {
	auto request_snapshot = request_session->Capture().snapshot;
	if (request_snapshot->Params().override_response_cache_policy) {
		return;
	}
	auto response_valid_until = HTTPFileSystem::ComputeCacheValidUntil(response.headers, request_time, response_time);
	// TODO(hjiang): Prevent shared reuse of authenticated requests without explicit permission.
	if (HasCacheControlDirective(response.headers, "no-store")) {
		// no-store applies to this response, so only blocks populated by this read are retired.
		response_valid_until = timestamp_t::ninfinity();
	}
	if (HasCacheControlDirective(response.headers, "private")) {
		// Private responses cannot be stored in caches shared across connections.
		response_valid_until = timestamp_t::ninfinity();
	}
	if (VaryProhibitsReuse(response.headers, request_snapshot->Params().extra_headers)) {
		// The cache key does not include request headers, so responses varying on a supplied header cannot be reused.
		response_valid_until = timestamp_t::ninfinity();
	}

	annotated_lock_guard<annotated_mutex> guard(cache_policy_lock);
	if (response_valid_until && (!cache_valid_until || *response_valid_until < *cache_valid_until)) {
		cache_valid_until = response_valid_until;
	}
}

optional<timestamp_t> HTTPFileHandle::GetCacheValidUntil() const {
	annotated_lock_guard<annotated_mutex> guard(cache_policy_lock);
	return cache_valid_until;
}

bool HTTPFileHandle::CanReuseCachedData() const {
	annotated_lock_guard<annotated_mutex> guard(cache_policy_lock);
	return !cache_valid_until || Timestamp::GetCurrentTimestamp() < *cache_valid_until;
}

struct HTTPFileInfoParser {
public:
	static optional_idx TryParseContentRange(const HTTPHeaders &headers) {
		if (!headers.HasHeader("Content-Range")) {
			return {};
		}
		auto content_range = headers.GetHeaderValue("Content-Range");
		auto range_find = content_range.find('/');
		if (range_find == string::npos || content_range.size() < range_find + 1) {
			return {};
		}
		auto range_length = content_range.substr(range_find + 1);
		if (range_length == "*") {
			return {};
		}
		return TryParseLength(range_length);
	}

	static optional_idx TryParseContentLength(const HTTPHeaders &headers) {
		if (!headers.HasHeader("Content-Length")) {
			return {};
		}
		return TryParseLength(headers.GetHeaderValue("Content-Length"));
	}

private:
	static optional_idx TryParseLength(const string &input) {
		try {
			return NumericCast<idx_t>(std::stoull(input));
		} catch (...) {
			return {};
		}
	}
};

bool HTTPFileHandle::TryLoadFileInfoWithoutRequest() {
	D_ASSERT(file_state);
	if (auto cached_file = file_state->TryGetCachedFileHandle()) {
		if (!initialized) {
			InitializeFromCacheEntry(cached_file->GetMetadata());
		}
		return true;
	}
	if (initialized || force_full_download) {
		return true;
	}
	if (write_overwrite_mode) {
		length = 0;
		initialized = true;
		return true;
	}
	return false;
}

unique_ptr<HTTPResponse> HTTPFileHandle::RequestFileInfo(HTTPFileSystem &hfs, timestamp_t &request_time,
                                                         timestamp_t &response_time) {
	request_time = Timestamp::GetCurrentTimestamp();
	auto response = hfs.HeadRequest(*this, path, {});
	response_time = Timestamp::GetCurrentTimestamp();
	if (response->status == HTTPStatusCode::OK_200) {
		return response;
	}
	if (flags.OpenForWriting() && response->status == HTTPStatusCode::NotFound_404) {
		if (!flags.CreateFileIfNotExists() && !flags.OverwriteExistingFile()) {
			throw IOException("Unable to open URL \"%s\" for writing: file does not exist and CREATE flag is not set",
			                  path);
		}
		length = 0;
		return nullptr;
	}
	if (flags.OpenForReading() && response->status != HTTPStatusCode::NotFound_404 &&
	    response->status != HTTPStatusCode::MovedPermanently_301) {
		return RetryFileInfoWithRange(hfs, request_time, response_time);
	}
	throw hfs.GetHTTPError(*this, *response, RequestType::HEAD_REQUEST, path);
}

unique_ptr<HTTPResponse> HTTPFileHandle::RetryFileInfoWithRange(HTTPFileSystem &hfs, timestamp_t &request_time,
                                                                timestamp_t &response_time) {
	auto config = BuildReadConfig();
	request_time = Timestamp::GetCurrentTimestamp();
	auto response = hfs.GetRangeRequest(*this, path, {}, config, 0, nullptr, 2);
	response_time = Timestamp::GetCurrentTimestamp();
	if (response->status == HTTPStatusCode::PartialContent_206 || response->status == HTTPStatusCode::Accepted_202 ||
	    response->status == HTTPStatusCode::OK_200) {
		return response;
	}
	if (RespondedWithRangeRequestNotSupported(*response) && config.auto_fallback_to_full_download) {
		force_full_download = true;
		return response;
	}
	throw hfs.GetHTTPError(*this, *response, RequestType::GET_REQUEST, path);
}

HTTPMetadataCacheEntry HTTPFileHandle::ReadFileInfo(const HTTPResponse &response, timestamp_t request_time,
                                                    timestamp_t response_time) {
	auto result = GetCacheEntry();
	result.length = 0;
	result.last_modified = timestamp_t(0);
	result.etag.clear();
	auto content_size = HTTPFileInfoParser::TryParseContentRange(response.headers);
	if (!content_size.IsValid()) {
		content_size = HTTPFileInfoParser::TryParseContentLength(response.headers);
	}
	if (content_size.IsValid()) {
		result.length = content_size.GetIndex();
	}
	if (response.headers.HasHeader("Last-Modified")) {
		HTTPFileSystem::TryParseLastModifiedTime(response.headers.GetHeaderValue("Last-Modified"),
		                                         result.last_modified);
	}
	if (response.headers.HasHeader("ETag")) {
		result.etag = response.headers.GetHeaderValue("ETag");
	}
	ApplyCachePolicy(response, request_time, response_time);
	result.cache_valid_until = GetCacheValidUntil();
	result.object_version = ReadObjectVersion(response.headers);
	if (response.headers.HasHeader("Accept-Ranges")) {
		auto accept_ranges = response.headers.GetHeaderValue("Accept-Ranges");
		StringUtil::Trim(accept_ranges);
		if (StringUtil::CIEquals(accept_ranges, "bytes")) {
			file_state->MarkRangeRequestsSupported();
		}
	}
	return result;
}

void HTTPFileHandle::LoadFileInfo() {
	if (TryLoadFileInfoWithoutRequest()) {
		return;
	}
	auto &hfs = file_system.Cast<HTTPFileSystem>();
	timestamp_t request_time;
	timestamp_t response_time;
	auto response = RequestFileInfo(hfs, request_time, response_time);
	if (response) {
		InitializeFromCacheEntry(ReadFileInfo(*response, request_time, response_time));
	}
}

void HTTPFileHandle::InitializeLogger(FileOpener &opener) {
	auto context = opener.TryGetClientContext();
	if (context) {
		logger = context->logger;
		return;
	}
	auto database = opener.TryGetDatabase();
	if (database) {
		logger = database->GetLogManager().GlobalLoggerReference();
	}
}

void HTTPFileHandle::InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry) {
	last_modified = cache_entry.last_modified;
	length = cache_entry.length;
	etag = cache_entry.etag;
	{
		annotated_lock_guard<annotated_mutex> guard(cache_policy_lock);
		cache_valid_until = request_session->Capture().snapshot->Params().override_response_cache_policy
		                        ? optional<timestamp_t>()
		                        : cache_entry.cache_valid_until;
	}
	object_version = cache_entry.object_version;
	initialized = true;

	// TODO: handle properties
}

HTTPMetadataCacheEntry HTTPFileHandle::GetCacheEntry() const {
	HTTPMetadataCacheEntry result;
	result.length = length;
	result.last_modified = last_modified;
	result.etag = etag;
	result.cache_valid_until = GetCacheValidUntil();
	result.object_version = GetObjectVersion();
	// TODO: handle properties
	return result;
}

void HTTPFileHandle::InitializeRequestState(optional_ptr<FileOpener> opener) {
	auto client_context = FileOpener::TryGetClientContext(opener);
	if (client_context) {
		buffer_allocator = BufferAllocator::Get(*client_context);
	} else {
		auto database = FileOpener::TryGetDatabase(opener);
		buffer_allocator = database ? BufferAllocator::Get(*database) : Allocator::DefaultAllocator();
	}
	auto captured = request_session->Capture();
	auto snapshot_params = captured.snapshot->Params();
	snapshot_params.state = HTTPState::TryGetState(opener);
	if (!snapshot_params.state) {
		snapshot_params.state = make_shared_ptr<HTTPState>();
	}
	request_session->TryPublish(captured.snapshot, CreateRequestSnapshot(snapshot_params));
	auto request_snapshot = request_session->Capture().snapshot;
	file_state = request_snapshot->Params().state->GetFileState(path);

	if (opener) {
		InitializeLogger(*opener);
	}
}

bool HTTPFileHandle::TryInitializeRead(HTTPFileSystem &hfs, optional_ptr<HTTPMetadataCache> cache,
                                       bool &should_write_cache) {
	if (!flags.OpenForReading()) {
		return false;
	}
	auto request_snapshot = request_session->Capture().snapshot;
	if (request_snapshot->Params().force_download) {
		FinalizeReadConfig();
		length = hfs.FullDownload(*this, GetReadConfig(), should_write_cache)->GetSize();
		return true;
	}

	if (cache) {
		HTTPMetadataCacheEntry value;
		if (cache->Find(path, value)) {
			InitializeFromCacheEntry(value);
			FinalizeReadConfig();
			return true;
		}
		should_write_cache = true;
	}
	return false;
}

void HTTPFileHandle::InitializeFileInfo(HTTPFileSystem &hfs, optional_ptr<HTTPMetadataCache> cache,
                                        bool should_write_cache) {
	LoadFileInfo();
	FinalizeReadConfig();

	if (flags.OpenForReading()) {
		auto request_snapshot = request_session->Capture().snapshot;
		const auto has_cache_state = (request_snapshot->Params().state != nullptr) && (length == 0);
		const auto always_download = force_full_download;
		const auto meets_threshold = (length < request_snapshot->Params().force_download_threshold) && (length != 0);
		const auto should_full_download = has_cache_state || meets_threshold || always_download;

		if (should_full_download) {
			length = hfs.FullDownload(*this, GetReadConfig(), should_write_cache)->GetSize();
		}
		if (should_write_cache && (cache->OverridesResponseCachePolicy() || CanReuseCachedData())) {
			cache->Insert(path, GetCacheEntry());
		}
	}
}

void HTTPFileHandle::Initialize(optional_ptr<FileOpener> opener) {
	auto &hfs = file_system.Cast<HTTPFileSystem>();
	InitializeRequestState(opener);
	auto current_cache = TryGetMetadataCache(opener, hfs);
	bool should_write_cache = false;
	if (TryInitializeRead(hfs, current_cache, should_write_cache)) {
		return;
	}
	InitializeFileInfo(hfs, current_cache, should_write_cache);

	// If we're writing to a file, we might as well remove it from the cache
	if (current_cache && flags.OpenForWriting()) {
		current_cache->Erase(path);
	}
}

shared_ptr<const HTTPRequestSnapshot> HTTPFileHandle::CreateRequestSnapshot(const HTTPFSParams &params) const {
	return make_shared_ptr<HTTPRequestSnapshot>(params);
}

HTTPFileHandle::~HTTPFileHandle() {
	DUCKDB_LOG_FILE_SYSTEM_CLOSE((*this));
}

void HTTPFileHandle::Close() {
}

void HTTPFSUtil::ClearCachedConnections() {
	// no-op by default
}

HTTPClientReuseMode HTTPFSUtil::GetClientReuseMode() const {
#ifdef EMSCRIPTEN
	return HTTPClientReuseMode::NONE;
#else
	return HTTPClientReuseMode::SESSION_LOCAL;
#endif
}

string HTTPFSUtil::GetName() const {
	return "HTTPFS";
}

} // namespace duckdb
