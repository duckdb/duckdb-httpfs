#pragma once

#include "s3/s3_settings.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/storage/buffer/buffer_handle.hpp"

#include <condition_variable>

namespace duckdb {

class HTTPRequestSession;
class HTTPException;
class S3FileSystem;
struct HTTPResponse;
struct S3RequestContext;
struct S3RequestQuery;
enum class RequestType : uint8_t;

class S3UploadSession {
private:
	//! Session, initialization, cleanup, and failure states.
	enum class LifecycleState : uint8_t { ACTIVE, FINALIZING, FINALIZED, ABORTING, ABORTED };
	enum class InitializationState : uint8_t { NOT_STARTED, IN_PROGRESS, SUCCEEDED, FAILED };
	enum class CleanupState : uint8_t { NONE, IN_PROGRESS, COMPLETE };
	enum class FailureDisposition : uint8_t { DEFINITIVE, AMBIGUOUS };

	//! Latched upload failures.
	struct FailureSnapshot {
		shared_ptr<const ErrorData> primary_error;
		shared_ptr<const ErrorData> abort_error;
	};

	//! Buffered write preparation.
	struct BufferedPart {
		BufferedPart(BufferHandle buffer_p, idx_t capacity_p) : buffer(std::move(buffer_p)), capacity(capacity_p) {
		}

		data_ptr_t Ptr() {
			return buffer.GetDataMutable();
		}

		BufferHandle buffer;
		const idx_t capacity;
		idx_t size = 0;
	};

	struct PreparedPart {
		PreparedPart(idx_t part_number_p, const_data_ptr_t data_p, idx_t size_p)
		    : part_number(part_number_p), data(data_p), size(size_p) {
		}
		PreparedPart(idx_t part_number_p, unique_ptr<BufferedPart> buffered_part_p)
		    : part_number(part_number_p), buffered_part(std::move(buffered_part_p)), data(buffered_part->Ptr()),
		      size(buffered_part->size) {
		}

		idx_t part_number;
		unique_ptr<BufferedPart> buffered_part;
		const_data_ptr_t data;
		idx_t size;
	};

	struct PreparedWrite {
		vector<PreparedPart> parts;
		unique_ptr<BufferedPart> buffered_part;
	};

	//! Multipart completion state.
	struct MultipartSnapshot {
		shared_ptr<const string> upload_id;
		vector<string> etags;
	};

public:
	//! Owns one admitted write until it finishes or fails.
	class WriteClaim {
		friend class S3UploadSession;

	private:
		explicit WriteClaim(S3UploadSession &session_p);

	public:
		//! Claim lifecycle.
		WriteClaim(WriteClaim &&other) noexcept;
		WriteClaim(const WriteClaim &) = delete;
		WriteClaim &operator=(const WriteClaim &) = delete;
		~WriteClaim();
		void Finish();

	private:
		//! Failure publication.
		[[noreturn]] void Fail(ErrorData error, FailureDisposition disposition);

		//! Claimed session state.
		reference<S3UploadSession> session;
		bool finished = false;
	};

public:
	//! Session lifecycle.
	S3UploadSession(S3FileSystem &s3fs, shared_ptr<HTTPRequestSession> request_session, string path,
	                S3UploadConfig config);
	~S3UploadSession() noexcept;

	//! Upload operations.
	WriteClaim Write(const_data_ptr_t data, idx_t size, idx_t location);
	void Finalize();
	bool Abort();

private:
	//! Operation admission and lifecycle transitions.
	void BeginWriteOperation() DUCKDB_EXCLUDES(state_lock);
	unique_ptr<BufferedPart> BeginFinalize(bool &already_finalized) DUCKDB_EXCLUDES(state_lock);
	void ReleaseOperation() DUCKDB_EXCLUDES(state_lock);
	void ReleaseWrite() DUCKDB_EXCLUDES(state_lock);
	void ReleaseWriteNoThrow() noexcept DUCKDB_EXCLUDES(state_lock);
	void FinishFinalize() DUCKDB_EXCLUDES(state_lock);

	//! Failure publication and cleanup.
	void LatchFailure(ErrorData error, FailureDisposition disposition) DUCKDB_EXCLUDES(state_lock);
	void LatchFailureLocked(shared_ptr<const ErrorData> error, FailureDisposition disposition)
	    DUCKDB_REQUIRES(state_lock);
	[[noreturn]] void FailOperation(ErrorData error, FailureDisposition disposition) DUCKDB_EXCLUDES(state_lock);
	FailureSnapshot CaptureFailure() const DUCKDB_REQUIRES(state_lock);
	[[noreturn]] static void ThrowFailure(const FailureSnapshot &failure);
	void ThrowIfFailed() DUCKDB_EXCLUDES(state_lock);

	//! Buffered write construction.
	PreparedWrite PrepareWrite(const_data_ptr_t data, idx_t size, idx_t location) DUCKDB_EXCLUDES(state_lock);
	unique_ptr<BufferedPart> AllocateBufferedPart(idx_t capacity);
	static idx_t AppendToBufferedPart(BufferedPart &buffered_part, const_data_ptr_t data, idx_t size);
	void ReservePart(PreparedWrite &write, const_data_ptr_t data, idx_t size) DUCKDB_REQUIRES(state_lock);
	void ReservePart(PreparedWrite &write, unique_ptr<BufferedPart> buffered_part) DUCKDB_REQUIRES(state_lock);

	//! Multipart initialization and completion.
	shared_ptr<const string> EnsureMultipartUpload();
	void PublishInitializationFailure(ErrorData error, FailureDisposition disposition) DUCKDB_EXCLUDES(state_lock);
	string InitializeMultipartUpload();
	void StorePartETag(idx_t part_number, string etag) DUCKDB_EXCLUDES(state_lock);
	MultipartSnapshot GetMultipartSnapshot() DUCKDB_EXCLUDES(state_lock);
	void CompleteMultipartUpload();

	//! S3 upload and cleanup requests.
	unique_ptr<HTTPResponse> RunUploadRequest(const_data_ptr_t data, idx_t size, const S3RequestQuery &query,
	                                          S3RequestContext &request_context);
	void UploadObject(const_data_ptr_t data, idx_t size);
	void UploadPart(PreparedPart &part);
	shared_ptr<const ErrorData> AbortMultipartUpload(const string &upload_id);

	//! Request diagnostics.
	string GetDisplayPath() const;
	static HTTPException GetStatusError(const HTTPResponse &response, const S3RequestContext &request_context,
	                                    const string &operation);

private:
	//! Immutable upload context.
	reference<S3FileSystem> s3fs;
	shared_ptr<HTTPRequestSession> request_session;
	const string path;
	const S3UploadConfig config;

	//! Operation and lifecycle synchronization.
	annotated_mutex state_lock;
	std::condition_variable state_changed;
	LifecycleState lifecycle_state DUCKDB_GUARDED_BY(state_lock) = LifecycleState::ACTIVE;
	idx_t active_operations DUCKDB_GUARDED_BY(state_lock) = 0;

	//! Buffered and multipart upload state.
	idx_t next_offset DUCKDB_GUARDED_BY(state_lock) = 0;
	unique_ptr<BufferedPart> buffered_part DUCKDB_GUARDED_BY(state_lock);
	InitializationState initialization_state DUCKDB_GUARDED_BY(state_lock) = InitializationState::NOT_STARTED;
	shared_ptr<const string> multipart_upload_id DUCKDB_GUARDED_BY(state_lock);
	vector<string> part_etags DUCKDB_GUARDED_BY(state_lock);

	//! Latched failure and cleanup state.
	FailureSnapshot primary_failure DUCKDB_GUARDED_BY(state_lock);
	FailureDisposition failure_disposition DUCKDB_GUARDED_BY(state_lock) = FailureDisposition::DEFINITIVE;
	bool abort_suppressed DUCKDB_GUARDED_BY(state_lock) = false;
	CleanupState cleanup_state DUCKDB_GUARDED_BY(state_lock) = CleanupState::NONE;
};

} // namespace duckdb
