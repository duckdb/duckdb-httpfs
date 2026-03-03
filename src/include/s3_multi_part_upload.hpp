#pragma once

#include "s3fs.hpp"
#include "duckdb/execution/task_error_manager.hpp"

namespace duckdb {

// Holds the buffered data for 1 part of an S3 Multipart upload
class S3WriteBuffer {
public:
	explicit S3WriteBuffer(idx_t buffer_start, size_t buffer_size, BufferHandle buffer_p)
	    : idx(0), buffer_start(buffer_start), buffer(std::move(buffer_p)) {
		buffer_end = buffer_start + buffer_size;
		part_no = buffer_start / buffer_size;
		uploading = false;
	}

	void *Ptr() {
		return buffer.Ptr();
	}

	// The S3 multipart part number. Note that internally we start at 0 but AWS S3 starts at 1
	idx_t part_no;

	idx_t idx;
	idx_t buffer_start;
	idx_t buffer_end;
	BufferHandle buffer;
	atomic<bool> uploading;
};

class S3MultiPartUpload : public enable_shared_from_this<S3MultiPartUpload> {
public:
	S3MultiPartUpload(S3FileHandle &s3_file_handle);

public:
	// Uploads the contents of write_buffer to S3.
	// Note: caller is responsible to not call this method twice on the same buffer
	static void UploadBuffer(shared_ptr<S3MultiPartUpload> multi_part_upload, shared_ptr<S3WriteBuffer> write_buffer);
	void UploadSingleBuffer(shared_ptr<S3WriteBuffer> write_buffer);
	void UploadBufferImplementation(shared_ptr<S3WriteBuffer> write_buffer, string query_param, bool direct_throw);
	void NotifyUploadsInProgress();

	string InitializeMultipartUpload();
	void FinalizeMultipartUpload();

	void FlushBuffer(shared_ptr<S3WriteBuffer> write_buffer);
	void FlushAllBuffers();

	//! Rethrow IO Exception originating from an upload thread
	void RethrowIOError();

public:
	shared_ptr<S3WriteBuffer> GetBuffer(uint16_t write_buffer_idx);
	void Finalize();

	S3FileSystem &s3fs;
	shared_ptr<HTTPInput> http_input;
	string path;
	const S3ConfigParams config_params;

	bool initialized_multipart_upload = false;
	string multipart_upload_id;
	size_t part_size;

	//! Write buffers for this file
	mutex write_buffers_lock;
	unordered_map<uint16_t, shared_ptr<S3WriteBuffer>> write_buffers;

	//! Synchronization for upload threads
	mutex uploads_in_progress_lock;
	std::condition_variable uploads_in_progress_cv;
	std::condition_variable final_flush_cv;
	uint16_t uploads_in_progress;

	//! Etags are stored for each part
	mutex part_etags_lock;
	unordered_map<uint16_t, string> part_etags;

	//! Info for upload
	atomic<uint16_t> parts_uploaded;
	bool upload_finalized = true;

	//! Error handling in upload threads
	TaskErrorManager error_manager;
};

} // namespace duckdb
