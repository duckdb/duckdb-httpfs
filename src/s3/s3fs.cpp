#include "s3/s3fs.hpp"

#include "s3/s3_upload_session.hpp"
#include "s3/s3_url.hpp"

#include "duckdb/common/helper.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/storage/buffer_manager.hpp"

namespace duckdb {

S3FileSystem::S3FileSystem(BufferManager &buffer_manager_p) : buffer_manager(buffer_manager_p) {
}

S3FileHandle::S3FileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                           unique_ptr<HTTPParams> http_params_p, const S3AuthParams &auth_params_p,
                           const S3UploadConfig &upload_config)
    : HTTPFileHandle(fs, file, flags, std::move(http_params_p)) {
	auto captured = request_session->Capture();
	auto request_params = captured.snapshot->CreateRequestParams();
	request_session->TryPublish(captured.snapshot,
	                            make_shared_ptr<S3RequestSnapshot>(*request_params, auth_params_p, file.path));
	auto_fallback_to_full_file_download = false;
	if (flags.OpenForReading() && flags.OpenForWriting()) {
		throw NotImplementedException("Cannot open an HTTP file for both reading and writing");
	} else if (flags.OpenForAppending()) {
		throw NotImplementedException("Cannot open an HTTP file for appending");
	}
	if (file.extended_info) {
		auto entry = file.extended_info->options.find("s3_region");
		if (entry != file.extended_info->options.end()) {
			SetRegion(entry->second.ToString());
		}
	}
	if (flags.OpenForWriting()) {
		upload_session = make_uniq<S3UploadSession>(fs.Cast<S3FileSystem>(), request_session, file.path, upload_config);
	}
}

HTTPReadConfig S3FileHandle::BuildReadConfig() const {
	auto result = HTTPFileHandle::BuildReadConfig();
	if (!request_session->Capture().snapshot->Params().s3_version_id_pinning) {
		return result;
	}
	auto version_id = GetVersionId();
	if (!version_id.empty()) {
		result.condition.type = HTTPReadConditionType::S3_VERSION_ID;
		result.condition.value = std::move(version_id);
	}
	return result;
}

shared_ptr<const HTTPRequestSnapshot> S3FileHandle::CreateRequestSnapshot(const HTTPFSParams &params) const {
	auto captured = request_session->Capture();
	auto &s3_snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
	return make_shared_ptr<S3RequestSnapshot>(params, s3_snapshot.auth_params, s3_snapshot.refresh_path,
	                                          s3_snapshot.client_context, s3_snapshot.credential_refresh_enabled,
	                                          s3_snapshot.region_redirected, s3_snapshot.credential_generation);
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

void S3FileHandle::SetRegion(const string &region) {
	string previous_region;
	S3RequestExecutor::SetSessionRegion(*request_session, region, previous_region);
}

void S3FileHandle::Close() {
	FinalizeUpload();
}

void S3FileHandle::FinalizeUpload() {
	if (upload_session) {
		upload_session->Finalize();
	}
}

EncryptionUtil &S3FileSystem::GetEncryptionUtil() {
	auto &config = DBConfig::GetConfig(buffer_manager.GetDatabase());
	if (!config.encryption_util) {
		throw InternalException("HTTPFS encryption util has not been initialized");
	}
	return *config.encryption_util;
}

unique_ptr<HTTPFileHandle> S3FileSystem::CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
                                                      optional_ptr<FileOpener> opener) {
	FileOpenerInfo info = {file.path};
	S3AuthParams auth_params = S3AuthParams::ReadFrom(opener, info);

	S3Url::Resolve(file.path, auth_params);
	if (flags.OpenForWriting() && !auth_params.version_id.empty()) {
		throw NotImplementedException("Cannot write to \"%s\": s3_version_id is only supported for reading",
		                              S3Url::GetDisplayUrl(file.path, auth_params));
	}

	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	S3UploadConfig upload_config;
	if (flags.OpenForWriting()) {
		upload_config = S3UploadConfig::ReadFrom(opener);
	}

	return make_uniq<S3FileHandle>(*this, file, flags, std::move(params), auth_params, upload_config);
}

void S3FileHandle::InitializeFromCacheEntry(const HTTPMetadataCacheEntry &cache_entry) {
	HTTPFileHandle::InitializeFromCacheEntry(cache_entry);
	auto entry = cache_entry.properties.find("s3_region");
	if (entry != cache_entry.properties.end()) {
		SetRegion(entry->second);
	}
}

HTTPMetadataCacheEntry S3FileHandle::GetCacheEntry() const {
	auto result = HTTPFileHandle::GetCacheEntry();
	auto captured = request_session->Capture();
	auto &snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
	if (!snapshot.auth_params.region.empty()) {
		result.properties["s3_region"] = snapshot.auth_params.region;
	}
	return result;
}

void S3FileHandle::Initialize(optional_ptr<FileOpener> opener) {
	auto context = FileOpener::TryGetClientContext(opener);
	auto refresh_enabled = S3RequestExecutor::CredentialRefreshEnabled(opener);
	{
		auto captured = request_session->Capture();
		auto &snapshot = captured.snapshot->Cast<S3RequestSnapshot>();
		auto request_params = snapshot.CreateRequestParams();
		weak_ptr<ClientContext> weak_context;
		if (context && refresh_enabled) {
			weak_context = context->shared_from_this();
		}
		request_session->TryPublish(captured.snapshot, make_shared_ptr<S3RequestSnapshot>(
		                                                   *request_params, snapshot.auth_params, snapshot.refresh_path,
		                                                   std::move(weak_context), refresh_enabled,
		                                                   snapshot.region_redirected, snapshot.credential_generation));
	}
	HTTPFileHandle::Initialize(opener);
}

bool S3FileSystem::CanHandleFile(const string &fpath) {
	return !S3Url::TryGetPrefix(fpath).empty();
}

bool S3FileSystem::OnDiskFile(FileHandle &) {
	return false;
}

FileWriteMode S3FileSystem::GetWriteMode(FileHandle &) {
	return FileWriteMode::CONCURRENT_SEQUENTIAL;
}

bool S3FileSystem::DirectoryExists(const string &, optional_ptr<FileOpener>) {
	return true;
}

bool S3FileSystem::SupportsListFilesExtended() const {
	return true;
}

bool S3FileSystem::SupportsGlobExtended() const {
	return true;
}

void S3FileSystem::FileSync(FileHandle &handle) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	s3fh.FinalizeUpload();
}

void S3FileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	if (!s3fh.flags.OpenForWriting()) {
		throw InternalException("Write called on file not opened in write mode");
	}
	if (nr_bytes < 0) {
		throw InternalException("S3 write size cannot be negative");
	}
	auto write_size = NumericCast<idx_t>(nr_bytes);
	auto write_claim = s3fh.upload_session->Write(const_data_ptr_cast(buffer), write_size, location);
	{
		annotated_lock_guard<annotated_mutex> guard(s3fh.cursor_mutex);
		auto write_end = location + write_size;
		s3fh.file_offset = MaxValue(s3fh.file_offset, write_end);
		s3fh.length = MaxValue(s3fh.length, write_end);
	}
	write_claim.Finish();

	DUCKDB_LOG_FILE_SYSTEM_WRITE(handle, write_size, location);
}

string S3FileSystem::GetName() const {
	return "S3FileSystem";
}

} // namespace duckdb
