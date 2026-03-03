#include "s3_multi_part_upload.hpp"

#include <thread>
#ifdef EMSCRIPTEN
#define SAME_THREAD_UPLOAD
#endif
namespace duckdb {

S3MultiPartUpload::S3MultiPartUpload(S3FileHandle &s3_file_handle)
    : s3fs(s3_file_handle.file_system.Cast<S3FileSystem>()), http_input(s3_file_handle.http_input),
      path(s3_file_handle.path), config_params(s3_file_handle.config_params), uploads_in_progress(0), parts_uploaded(0),
      upload_finalized(false) {
}

void S3MultiPartUpload::Finalize() {
	if (upload_finalized) {
		// already finalized
		return;
	}
	FlushAllBuffers();
	if (parts_uploaded) {
		FinalizeMultipartUpload();
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

// Opens the multipart upload and returns the ID
string S3MultiPartUpload::InitializeMultipartUpload() {
	// AWS response is around 300~ chars in docs so this should be enough to not need a resize
	string result;
	string query_param = "uploads=";
	auto res = s3fs.PostRequest(*http_input, path, {}, result, nullptr, 0, query_param);

	if (res->status != HTTPStatusCode::OK_200) {
		throw HTTPException(*res, "Unable to connect to URL %s: %s (HTTP code %d)", path, res->GetError(),
		                    static_cast<int>(res->status));
	}

	auto open_tag_pos = result.find("<UploadId>", 0);
	auto close_tag_pos = result.find("</UploadId>", open_tag_pos);

	if (open_tag_pos == string::npos || close_tag_pos == string::npos) {
		throw HTTPException("Unexpected response while initializing S3 multipart upload");
	}

	open_tag_pos += 10; // Skip open tag

	initialized_multipart_upload = true;

	return result.substr(open_tag_pos, close_tag_pos - open_tag_pos);
}

void S3MultiPartUpload::FinalizeMultipartUpload() {
	if (upload_finalized) {
		return;
	}

	upload_finalized = true;

	std::stringstream ss;
	ss << "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";

	auto parts = parts_uploaded.load();
	for (auto i = 0; i < parts; i++) {
		auto etag_lookup = part_etags.find(i);
		if (etag_lookup == part_etags.end()) {
			throw IOException("Unknown part number");
		}
		ss << "<Part><ETag>" << etag_lookup->second << "</ETag><PartNumber>" << i + 1 << "</PartNumber></Part>";
	}
	ss << "</CompleteMultipartUpload>";
	string body = ss.str();

	// Response is around ~400 in AWS docs so this should be enough to not need a resize
	string result;

	string query_param = "uploadId=" + S3FileSystem::UrlEncode(multipart_upload_id, true);
	auto res = s3fs.PostRequest(*http_input, path, {}, result, (char *)body.c_str(), body.length(), query_param);
	auto open_tag_pos = result.find("<CompleteMultipartUploadResult", 0);
	if (open_tag_pos == string::npos) {
		throw HTTPException(*res, "Unexpected response during S3 multipart upload finalization: %d\n\n%s",
		                    static_cast<int>(res->status), result);
	}
}

void S3MultiPartUpload::UploadBuffer(shared_ptr<S3MultiPartUpload> multi_part_upload,
                                     shared_ptr<S3WriteBuffer> write_buffer) {
	string query_param = "partNumber=" + to_string(write_buffer->part_no + 1) + "&" +
	                     "uploadId=" + S3FileSystem::UrlEncode(multi_part_upload->multipart_upload_id, true);

	multi_part_upload->UploadBufferImplementation(write_buffer, query_param, false);
	multi_part_upload->NotifyUploadsInProgress();
}

void S3MultiPartUpload::UploadSingleBuffer(shared_ptr<S3WriteBuffer> write_buffer) {
	UploadBufferImplementation(write_buffer, "", true);
}

void S3MultiPartUpload::UploadBufferImplementation(shared_ptr<S3WriteBuffer> write_buffer, string query_param,
                                                   bool single_upload) {
	unique_ptr<HTTPResponse> res;
	string etag;

	try {
		res = s3fs.PutRequest(*http_input, path, {}, (char *)write_buffer->Ptr(), write_buffer->idx, query_param);

		if (res->status != HTTPStatusCode::OK_200) {
			throw HTTPException(*res, "Unable to connect to URL %s: %s (HTTP code %d)", path, res->GetError(),
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
		error_manager.PushError(std::move(error));

		D_ASSERT(!single_upload); // If we are here we are in the multi-buffer situation
		return;
	}

	// Insert etag
	{
		unique_lock<mutex> lck(part_etags_lock);
		part_etags.insert(std::pair<uint16_t, string>(write_buffer->part_no, etag));
	}

	parts_uploaded++;

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

void S3MultiPartUpload::FlushBuffer(shared_ptr<S3WriteBuffer> write_buffer) {
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

	RethrowIOError();

	{
		unique_lock<mutex> lck(write_buffers_lock);
		write_buffers.erase(write_buffer->part_no);
	}

	{
		unique_lock<mutex> lck(uploads_in_progress_lock);
		// check if there are upload threads available
#ifndef SAME_THREAD_UPLOAD
		if (uploads_in_progress >= config_params.max_upload_threads) {
			// there are not - wait for one to become available
			uploads_in_progress_cv.wait(lck, [&] { return uploads_in_progress < config_params.max_upload_threads; });
		}
#endif
		uploads_in_progress++;
	}
	if (initialized_multipart_upload == false) {
		multipart_upload_id = InitializeMultipartUpload();
	}

#ifdef SAME_THREAD_UPLOAD
	UploadBuffer(shared_from_this(), write_buffer);
	return;
#endif

	std::thread upload_thread(S3MultiPartUpload::UploadBuffer, shared_from_this(), write_buffer);
	upload_thread.detach();
}

// Note that FlushAll currently does not allow to continue writing afterwards. Therefore, FinalizeMultipartUpload should
// be called right after it!
// TODO: we can fix this by keeping the last partially written buffer in memory and allow reuploading it with new data.
void S3MultiPartUpload::FlushAllBuffers() {
	//  Collect references to all buffers to check
	vector<shared_ptr<S3WriteBuffer>> to_flush;
	write_buffers_lock.lock();
	for (auto &item : write_buffers) {
		to_flush.push_back(item.second);
	}
	write_buffers_lock.unlock();

	if (!initialized_multipart_upload) {
		// TODO (carlo): unclear how to handle kms_key_id, but given currently they are custom, leave the multiupload
		// codepath in that case
		auto &s3_input = http_input->Cast<S3HTTPInput>();
		if (to_flush.size() == 1 && s3_input.auth_params.kms_key_id.empty()) {
			UploadSingleBuffer(to_flush[0]);
			upload_finalized = true;
			return;
		} else {
			multipart_upload_id = InitializeMultipartUpload();
		}
	}
	// Flush all buffers that aren't already uploading
	for (auto &write_buffer : to_flush) {
		if (!write_buffer->uploading) {
			FlushBuffer(write_buffer);
		}
	}
	unique_lock<mutex> lck(uploads_in_progress_lock);
#ifndef SAME_THREAD_UPLOAD
	final_flush_cv.wait(lck, [&] { return uploads_in_progress == 0; });
#endif

	RethrowIOError();
}

void S3MultiPartUpload::RethrowIOError() {
	if (error_manager.HasError()) {
		error_manager.ThrowException();
	}
}

} // namespace duckdb
