#include "s3/s3fs.hpp"

#include "s3/s3_provider.hpp"
#include "s3/s3_upload_session.hpp"
#include "s3/s3_url.hpp"

#include "duckdb/common/helper.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/storage/buffer_manager.hpp"

namespace duckdb {

S3FileSystem::S3FileSystem(BufferManager &buffer_manager_p) : buffer_manager(buffer_manager_p) {
}

S3FileHandle::UploadClaim::UploadClaim(S3FileHandle &handle_p, optional_ptr<S3UploadSession> session_p)
    : handle(handle_p), session(session_p) {
}

S3FileHandle::UploadClaim::UploadClaim(UploadClaim &&other) noexcept : handle(other.handle), session(other.session) {
	other.session = nullptr;
}

S3FileHandle::UploadClaim::~UploadClaim() {
	if (session) {
		handle.get().ReleaseUpload();
	}
}

S3FileHandle::S3FileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags,
                           unique_ptr<HTTPParams> http_params_p, const S3AuthParams &auth_params_p,
                           const S3UploadConfig &upload_config,
                           optional<S3MultipartUploadPolicy> multipart_upload_policy)
    : HTTPFileHandle(fs, file, flags, std::move(http_params_p)) {
	auto captured = request_session->Capture();
	auto request_params = captured.snapshot->CreateRequestParams();
	request_session->TryPublish(captured.snapshot,
	                            make_shared_ptr<S3RequestSnapshot>(*request_params, auth_params_p, file.path,
	                                                               weak_ptr<ClientContext>(), true, false, 0,
	                                                               std::move(multipart_upload_policy)));
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
	                                          s3_snapshot.region_redirected, s3_snapshot.credential_generation,
	                                          s3_snapshot.multipart_upload_policy);
}

S3FileHandle::~S3FileHandle() = default;

void S3FileHandle::SetRegion(const string &region) {
	string previous_region;
	S3RequestExecutor::SetSessionRegion(*request_session, region, previous_region);
}

void S3FileHandle::Close() {
	FinalizeUpload();
}

void S3FileHandle::FinalizeUpload() {
	auto upload_claim = ClaimUpload(false);
	if (upload_claim) {
		upload_claim.Get().Finalize();
	}
}

S3FileHandle::UploadClaim S3FileHandle::ClaimUpload(bool write) {
	annotated_lock_guard<annotated_mutex> guard(upload_lock);
	if (upload_state != UploadState::ACTIVE) {
		if (write) {
			throw IOException("Cannot write to an aborted S3 upload");
		}
		throw IOException("Cannot finalize an aborted S3 upload");
	}
	if (!upload_session) {
		if (write) {
			throw InternalException("S3 write handle has no upload session");
		}
		return UploadClaim(*this, nullptr);
	}
	active_upload_calls++;
	return UploadClaim(*this, upload_session);
}

void S3FileHandle::ReleaseUpload() {
	annotated_lock_guard<annotated_mutex> guard(upload_lock);
	D_ASSERT(active_upload_calls > 0);
	active_upload_calls--;
	if (active_upload_calls == 0) {
		upload_state_changed.notify_all();
	}
}

void S3FileHandle::AbortUpload() {
	optional_ptr<S3UploadSession> session;
	{
		annotated_unique_lock<annotated_mutex> guard(upload_lock);
		while (upload_state == UploadState::ABORTING) {
			upload_state_changed.wait(guard);
		}
		if (upload_state == UploadState::ABORTED || !upload_session) {
			return;
		}
		upload_state = UploadState::ABORTING;
		session = upload_session;
	}

	std::exception_ptr abort_error;
	bool terminal_abort = true;
	try {
		terminal_abort = session->Abort();
	} catch (...) {
		abort_error = std::current_exception();
	}

	unique_ptr<S3UploadSession> detached_session;
	{
		annotated_unique_lock<annotated_mutex> guard(upload_lock);
		if (!terminal_abort) {
			upload_state = UploadState::ACTIVE;
			upload_state_changed.notify_all();
			return;
		}
		while (active_upload_calls > 0) {
			upload_state_changed.wait(guard);
		}
		detached_session = std::move(upload_session);
		upload_state = UploadState::ABORTED;
		upload_state_changed.notify_all();
	}
	detached_session.reset();

	if (abort_error) {
		std::rethrow_exception(abort_error);
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

	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	S3UploadConfig upload_config;
	optional<S3MultipartUploadPolicy> multipart_upload_policy;
	if (flags.OpenForWriting()) {
		multipart_upload_policy = S3Provider::GetMultipartUploadPolicy(auth_params);
		upload_config = S3UploadConfig::ReadFrom(opener, *multipart_upload_policy);
	}

	return make_uniq<S3FileHandle>(*this, file, flags, std::move(params), auth_params, upload_config,
	                               std::move(multipart_upload_policy));
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
	if (snapshot.region_redirected) {
		D_ASSERT(!snapshot.auth_params.region.empty());
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
		request_session->TryPublish(
		    captured.snapshot,
		    make_shared_ptr<S3RequestSnapshot>(*request_params, snapshot.auth_params, snapshot.refresh_path,
		                                       std::move(weak_context), refresh_enabled, snapshot.region_redirected,
		                                       snapshot.credential_generation, snapshot.multipart_upload_policy));
	}
	HTTPFileHandle::Initialize(opener);
}

bool S3FileSystem::CanHandleFile(const string &fpath) {
	// This runs for every path the VFS probes, so keep local paths and built-in schemes off the
	// setting lookup, which takes the database-wide settings lock
	if (S3Provider::TryMatchUrl(fpath)) {
		return true;
	}
	if (fpath.find("://") == string::npos) {
		return false;
	}
	auto &config = DBConfig::GetConfig(buffer_manager.GetDatabase());
	return S3Provider::TryMatchUrl(fpath, S3Provider::GetSchemeAliasPrefixes(config)).has_value();
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

void S3FileSystem::AbortFileWrite(FileHandle &handle) {
	auto &s3fh = handle.Cast<S3FileHandle>();
	s3fh.AbortUpload();
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
	auto upload_claim = s3fh.ClaimUpload(true);
	auto write_claim = upload_claim.Get().Write(const_data_ptr_cast(buffer), write_size, location);
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
