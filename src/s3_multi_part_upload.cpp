#include "s3_multi_part_upload.hpp"

namespace duckdb {


S3MultiPartUpload::S3MultiPartUpload(S3FileHandle &s3_file_handle) : s3fs(s3_file_handle.file_system.Cast<S3FileSystem>()), s3_file_handle(s3_file_handle), config_params(s3_file_handle.config_params), uploads_in_progress(0), parts_uploaded(0), upload_finalized(false),
	  uploader_has_error(false), upload_exception(nullptr) {
}

void S3MultiPartUpload::Finalize() {
	if (upload_finalized) {
		// already finalized
		return;
	}
	s3fs.FlushAllBuffers(s3_file_handle);
	if (parts_uploaded) {
		s3fs.FinalizeMultipartUpload(s3_file_handle);
	}
}

shared_ptr<S3WriteBuffer> S3MultiPartUpload::GetBuffer(uint16_t write_buffer_idx) {
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

}
