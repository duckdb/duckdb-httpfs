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


void S3MultiPartUpload::UploadBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer) {
	auto &multi_file_upload = *file_handle.multi_part_upload;
	string query_param = "partNumber=" + to_string(write_buffer->part_no + 1) + "&" +
	                     "uploadId=" + S3FileSystem::UrlEncode(multi_file_upload.multipart_upload_id, true);

	UploadBufferImplementation(file_handle, write_buffer, query_param, false);

	multi_file_upload.NotifyUploadsInProgress();
}

void S3MultiPartUpload::UploadSingleBuffer(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer) {
	UploadBufferImplementation(file_handle, write_buffer, "", true);
}

void S3MultiPartUpload::UploadBufferImplementation(S3FileHandle &file_handle, shared_ptr<S3WriteBuffer> write_buffer,
                                              string query_param, bool single_upload) {
	auto &s3fs = (S3FileSystem &)file_handle.file_system;
	auto &multi_file_upload = *file_handle.multi_part_upload;

	unique_ptr<HTTPResponse> res;
	string etag;

	try {
		res = s3fs.PutRequest(file_handle, file_handle.path, {}, (char *)write_buffer->Ptr(), write_buffer->idx,
		                      query_param);

		if (res->status != HTTPStatusCode::OK_200) {
			throw HTTPException(*res, "Unable to connect to URL %s: %s (HTTP code %d)", file_handle.path,
			                    res->GetError(), static_cast<int>(res->status));
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
		auto exchanged = multi_file_upload.uploader_has_error.compare_exchange_strong(f, true);
		if (exchanged) {
			multi_file_upload.upload_exception = std::current_exception();
		}

		D_ASSERT(!single_upload); // If we are here we are in the multi-buffer situation
		multi_file_upload.NotifyUploadsInProgress();
		return;
	}

	// Insert etag
	{
		unique_lock<mutex> lck(multi_file_upload.part_etags_lock);
		multi_file_upload.part_etags.insert(std::pair<uint16_t, string>(write_buffer->part_no, etag));
	}

	multi_file_upload.parts_uploaded++;

	// Free up space for another thread to acquire an S3WriteBuffer
	write_buffer.reset();
}

void S3MultiPartUpload::NotifyUploadsInProgress() {
	{
		unique_lock<mutex> lck(uploads_in_progress_lock);
		uploads_in_progress--;
	}
	// Note that there are 2 cv's because otherwise we might deadlock when the final flushing thread is notified while
	// another thread is still waiting for an upload thread
#ifndef SAME_THREAD_UPLOAD
	uploads_in_progress_cv.notify_one();
	final_flush_cv.notify_one();
#endif
}

}
