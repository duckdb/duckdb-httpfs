#include "s3_multi_part_upload.hpp"
#include "duckdb/common/thread.hpp"

namespace duckdb {

S3MultiPartUpload::S3MultiPartUpload(S3FileSystem &s3fs_p, S3FileHandle &file_handle_p)
    : s3fs(s3fs_p), http_input(file_handle_p.http_input), path(file_handle_p.path), config_params(file_handle_p.config_params),
      uploads_in_progress(0), parts_uploaded(0), upload_finalized(false) {
}

shared_ptr<S3MultiPartUpload> S3MultiPartUpload::Initialize(S3FileHandle &file_handle) {
	auto &config_params = file_handle.config_params;

	auto aws_minimum_part_size = 5242880; // 5 MiB https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
	auto max_part_count = config_params.max_parts_per_file;
	auto required_part_size = config_params.max_file_size / max_part_count;
	auto minimum_part_size = MaxValue<idx_t>(aws_minimum_part_size, required_part_size);

	auto &s3fs = file_handle.file_system.Cast<S3FileSystem>();

	auto upload_state = make_shared_ptr<S3MultiPartUpload>(s3fs, file_handle);
	// Round part size up to multiple of Storage::DEFAULT_BLOCK_SIZE
	upload_state->part_size = ((minimum_part_size + Storage::DEFAULT_BLOCK_SIZE - 1) / Storage::DEFAULT_BLOCK_SIZE) *
	                          Storage::DEFAULT_BLOCK_SIZE;
	D_ASSERT(upload_state->part_size * max_part_count >= config_params.max_file_size);

	upload_state->multipart_upload_id = upload_state->InitializeMultipartUpload();
	return upload_state;
}

// Opens the multipart upload and returns the ID
string S3MultiPartUpload::InitializeMultipartUpload() {
	string result;
	string query_param = "uploads=";
	auto res = s3fs.PostRequest(*http_input, path, {}, result, nullptr, 0, query_param);

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

	return result.substr(open_tag_pos, close_tag_pos - open_tag_pos);
}

shared_ptr<S3WriteBuffer> S3MultiPartUpload::GetBuffer(idx_t write_buffer_idx) {
	// Check if write buffer already exists
	{
		lock_guard<mutex> lck(write_buffers_lock);
		auto lookup_result = write_buffers.find(write_buffer_idx);
		if (lookup_result != write_buffers.end()) {
			return lookup_result->second;
		}
	}

	auto buffer_handle = s3fs.Allocate(part_size, config_params.max_upload_threads);
	auto new_write_buffer =
	    make_shared_ptr<S3WriteBuffer>(write_buffer_idx * part_size, part_size, std::move(buffer_handle));
	{
		lock_guard<mutex> lck(write_buffers_lock);
		auto lookup_result = write_buffers.find(write_buffer_idx);

		// Check if other thread has created the same buffer, if so we return theirs and drop ours.
		if (lookup_result != write_buffers.end()) {
			// write_buffer_idx << std::endl;
			return lookup_result->second;
		}
		write_buffers.emplace(write_buffer_idx, new_write_buffer);
	}

	return new_write_buffer;
}

void S3MultiPartUpload::NotifyUploadsInProgress() {
	{
		unique_lock<mutex> lck(uploads_in_progress_lock);
		uploads_in_progress--;
	}
	// Note that there are 2 cv's because otherwise we might deadlock when the final flushing thread is notified while
	// another thread is still waiting for an upload thread
	uploads_in_progress_cv.notify_one();
	final_flush_cv.notify_one();
}

void S3MultiPartUpload::UploadBuffer(shared_ptr<S3MultiPartUpload> upload_state,
                                     shared_ptr<S3WriteBuffer> write_buffer) {
	auto &s3fs = upload_state->s3fs;

	string query_param = "partNumber=" + to_string(write_buffer->part_no + 1) + "&" +
	                     "uploadId=" + S3FileSystem::UrlEncode(upload_state->multipart_upload_id, true);
	unique_ptr<HTTPResponse> res;
	string etag;

	try {
		res = s3fs.PutRequest(*upload_state->http_input, upload_state->path, {}, (char *)write_buffer->Ptr(),
		                      write_buffer->idx, query_param);

		if (res->status != HTTPStatusCode::OK_200) {
			throw HTTPException(*res, "Unable to connect to URL %s: %s (HTTP code %d)", res->url, res->GetError(),
			                    static_cast<int>(res->status));
		}

		if (!res->headers.HasHeader("ETag")) {
			throw IOException("Unexpected response when uploading part to S3");
		}
		etag = res->headers.GetHeaderValue("ETag");
	} catch (std::exception &ex) {
		ErrorData error(ex);
		if (error.Type() != ExceptionType::IO && error.Type() != ExceptionType::HTTP) {
			throw;
		}
		upload_state->error_manager.PushError(std::move(error));

		upload_state->NotifyUploadsInProgress();
		return;
	}

	// Insert etag
	{
		unique_lock<mutex> lck(upload_state->part_etags_lock);
		upload_state->part_etags.insert(std::pair<uint16_t, string>(write_buffer->part_no, etag));
	}

	upload_state->parts_uploaded++;

	// Free up space for another thread to acquire an S3WriteBuffer
	write_buffer.reset();

	upload_state->NotifyUploadsInProgress();
}

void S3MultiPartUpload::FlushBuffer(shared_ptr<S3MultiPartUpload> upload_state,
                                    shared_ptr<S3WriteBuffer> write_buffer) {
	auto uploading = write_buffer->uploading.load();
	if (uploading) {
		return;
	}
	bool can_upload = write_buffer->uploading.compare_exchange_strong(uploading, true);
	if (!can_upload) {
		return;
	}

	if (upload_state->error_manager.HasError()) {
		upload_state->error_manager.ThrowException();
	}

	{
		unique_lock<mutex> lck(upload_state->write_buffers_lock);
		upload_state->write_buffers.erase(write_buffer->part_no);
	}

	{
		unique_lock<mutex> lck(upload_state->uploads_in_progress_lock);
		// check if there are upload threads available
		if (upload_state->uploads_in_progress >= upload_state->config_params.max_upload_threads) {
			// there are not - wait for one to become available
			upload_state->uploads_in_progress_cv.wait(lck, [&] {
				return upload_state->uploads_in_progress < upload_state->config_params.max_upload_threads;
			});
		}
		upload_state->uploads_in_progress++;
	}

	thread upload_thread(UploadBuffer, upload_state, write_buffer);
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

	// Flush all buffers that aren't already uploading
	for (auto &write_buffer : to_flush) {
		if (!write_buffer->uploading) {
			FlushBuffer(shared_from_this(), write_buffer);
		}
	}
	unique_lock<mutex> lck(uploads_in_progress_lock);
	final_flush_cv.wait(lck, [&] { return uploads_in_progress == 0; });

	if (error_manager.HasError()) {
		error_manager.ThrowException();
	}
}

void S3MultiPartUpload::FinalizeMultipartUpload() {
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

	string result;

	string query_param = "uploadId=" + S3FileSystem::UrlEncode(multipart_upload_id, true);
	auto res =
	    s3fs.PostRequest(*http_input, path, {}, result, (char *)body.c_str(), body.length(), query_param);
	auto open_tag_pos = result.find("<CompleteMultipartUploadResult", 0);
	if (open_tag_pos == string::npos) {
		throw HTTPException(*res, "Unexpected response during S3 multipart upload finalization: %d\n\n%s",
		                    static_cast<int>(res->status), result);
	}
}

void S3MultiPartUpload::Finalize() {
	FlushAllBuffers();
	if (parts_uploaded) {
		FinalizeMultipartUpload();
	}
}

} // namespace duckdb
