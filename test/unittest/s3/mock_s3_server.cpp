#include "s3/mock_s3_server.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/atomic.hpp"
#include "duckdb/common/string_util.hpp"

#include "httplib.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <sstream>
#include <thread>

namespace httplib = duckdb_httplib;

namespace duckdb {

namespace {

static string ExtractCredentialKey(const string &authorization) {
	auto credential_pos = authorization.find("Credential=");
	if (credential_pos == string::npos) {
		return string();
	}
	credential_pos += strlen("Credential=");
	auto end_pos = authorization.find('/', credential_pos);
	if (end_pos == string::npos) {
		return authorization.substr(credential_pos);
	}
	return authorization.substr(credential_pos, end_pos - credential_pos);
}

static string ExtractCredentialRegion(const string &authorization) {
	auto credential_pos = authorization.find("Credential=");
	if (credential_pos == string::npos) {
		return string();
	}
	credential_pos += strlen("Credential=");
	auto key_end = authorization.find('/', credential_pos);
	if (key_end == string::npos) {
		return string();
	}
	auto date_end = authorization.find('/', key_end + 1);
	if (date_end == string::npos) {
		return string();
	}
	auto region_end = authorization.find('/', date_end + 1);
	if (region_end == string::npos) {
		return string();
	}
	return authorization.substr(date_end + 1, region_end - date_end - 1);
}

static bool ParseRange(const string &range, idx_t object_size, idx_t &start, idx_t &end) {
	static constexpr const char *PREFIX = "bytes=";
	if (range.rfind(PREFIX, 0) != 0) {
		return false;
	}
	auto dash_pos = range.find('-', strlen(PREFIX));
	if (dash_pos == string::npos) {
		return false;
	}
	try {
		start = std::stoull(range.substr(strlen(PREFIX), dash_pos - strlen(PREFIX)));
		end = std::stoull(range.substr(dash_pos + 1));
	} catch (...) {
		return false;
	}
	return start <= end && end < object_size;
}

static bool ConsumeBehavior(atomic<idx_t> &remaining) {
	auto current = remaining.load();
	while (current > 0) {
		if (remaining.compare_exchange_weak(current, current - 1)) {
			return true;
		}
	}
	return false;
}

static string GetHeader(const httplib::Request &request, const string &header) {
	if (!request.has_header(header)) {
		return string();
	}
	return request.get_header_value(header);
}

static idx_t CountHeader(const httplib::Request &request, const string &header) {
	idx_t result = 0;
	for (const auto &entry : request.headers) {
		if (StringUtil::CIEquals(entry.first, header)) {
			result++;
		}
	}
	return result;
}

static idx_t CountDeleteKeys(const string &body) {
	idx_t result = 0;
	idx_t position = 0;
	while ((position = body.find("<Object>", position)) != string::npos) {
		result++;
		position += strlen("<Object>");
	}
	return result;
}

static void SetETagHeader(httplib::Response &response, MockS3ETagBehavior behavior, const string &value) {
	if (behavior == MockS3ETagBehavior::VALUE) {
		response.set_header("ETag", value);
	} else if (behavior == MockS3ETagBehavior::EMPTY) {
		response.set_header("ETag", "");
	}
}

static string GetParameter(const httplib::Request &request, const string &parameter) {
	if (!request.has_param(parameter)) {
		return string();
	}
	return request.get_param_value(parameter);
}

struct MockS3BodyDigest {
	static string Compute(const string &body) {
		uint64_t hash = 14695981039346656037ULL;
		for (const auto byte : body) {
			hash ^= static_cast<uint8_t>(byte);
			hash *= 1099511628211ULL;
		}
		return StringUtil::Format("%016llx", static_cast<unsigned long long>(hash));
	}
};

struct MockS3XMLText {
	static string Escape(const string &text) {
		std::stringstream result;
		for (const auto character : text) {
			switch (character) {
			case '&':
				result << "&amp;";
				break;
			case '<':
				result << "&lt;";
				break;
			case '>':
				result << "&gt;";
				break;
			default:
				result << character;
			}
		}
		return result.str();
	}
};

static optional_idx GetPartNumber(const httplib::Request &request) {
	auto part_number = GetParameter(request, "partNumber");
	if (part_number.empty()) {
		return {};
	}
	try {
		return {NumericCast<idx_t>(std::stoull(part_number))};
	} catch (...) {
		return {};
	}
}

struct MockS3ManifestPart {
	idx_t part_number;
	string etag;
};

struct MockS3CompletionManifest {
	static bool TryParse(const string &body, vector<MockS3ManifestPart> &parts) {
		idx_t position = 0;
		if (!Consume(body, position, "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")) {
			return false;
		}

		while (!Consume(body, position, "</CompleteMultipartUpload>")) {
			MockS3ManifestPart part;
			string part_number;
			if (!Consume(body, position, "<Part><ETag>") || !ReadUntil(body, position, "</ETag>", part.etag) ||
			    !Consume(body, position, "<PartNumber>") || !ReadUntil(body, position, "</PartNumber>", part_number) ||
			    !Consume(body, position, "</Part>") || !TryParsePartNumber(part_number, part.part_number)) {
				return false;
			}
			parts.push_back(std::move(part));
		}
		return !parts.empty() && position == body.size();
	}

private:
	static bool Consume(const string &body, idx_t &position, const string &value) {
		if (body.compare(position, value.size(), value) != 0) {
			return false;
		}
		position += value.size();
		return true;
	}

	static bool ReadUntil(const string &body, idx_t &position, const string &delimiter, string &result) {
		auto delimiter_position = body.find(delimiter, position);
		if (delimiter_position == string::npos) {
			return false;
		}
		result = body.substr(position, delimiter_position - position);
		position = delimiter_position + delimiter.size();
		return true;
	}

	static bool TryParsePartNumber(const string &value, idx_t &result) {
		if (value.empty()) {
			return false;
		}
		try {
			size_t parsed_length;
			result = NumericCast<idx_t>(std::stoull(value, &parsed_length));
			return parsed_length == value.size() && result > 0;
		} catch (...) {
			return false;
		}
	}
};

} // namespace

struct MockS3Server::Impl {
public:
	struct UploadedPart {
		string etag;
		string body;
	};

	struct ActivePartUpload {
		ActivePartUpload(Impl &server_p, idx_t part_number) : server(server_p) {
			server.get().BeginPartUpload(part_number);
		}

		~ActivePartUpload() {
			server.get().FinishPartUpload();
		}

	public:
		reference<Impl> server;
	};

public:
	explicit Impl(MockS3ServerConfig config_p) : config(std::move(config_p)) {
		uploaded_object = config.upload.initial_published_object;
		remaining_put_failures = config.failures.transient_put_failures;
		remaining_get_failures = config.failures.transient_get_failures;
		remaining_range_behavior_requests = config.range.behavior_requests;
		remaining_head_failures = config.failures.transient_head_failures;
		remaining_head_not_found = config.failures.head_not_found_requests;
		remaining_delete_failures = config.failures.transient_delete_failures;
		remaining_post_failures = config.failures.transient_post_failures;
		remaining_completion_faults = config.failures.completion_fault.count;
		if (config.range.behavior == MockS3RangeBehavior::SHORT_SUCCESS && config.range.behavior_requests > 0) {
			server.set_keep_alive_max_count(1);
		}
		RegisterRoutes();
		port = server.bind_to_any_port("127.0.0.1");
		if (port <= 0) {
			throw IOException("Failed to bind mock S3 server");
		}
		server_thread = std::thread([this]() { server.listen_after_bind(); });
		server.wait_until_ready();
	}

	~Impl() {
		ReleasePartUploads();
		ReleaseMultipartInitialization();
		server.stop();
		if (server_thread.joinable()) {
			server_thread.join();
		}
	}

public:
	string Endpoint() const {
		return StringUtil::Format("127.0.0.1:%d", port);
	}

	string S3Path() const {
		return StringUtil::Format("s3://%s/%s", config.object.bucket, config.object.key);
	}

	string HTTPPath() const {
		return StringUtil::Format("http://%s%s/%s/%s", Endpoint(), config.endpoint_base_path, config.object.bucket,
		                          config.object.key);
	}

	vector<MockS3RequestObservation> Observations() const DUCKDB_EXCLUDES(observation_lock) {
		annotated_lock_guard<annotated_mutex> lock(observation_lock);
		return observations;
	}

	string UploadedObject() const DUCKDB_EXCLUDES(upload_lock) {
		annotated_lock_guard<annotated_mutex> lock(upload_lock);
		return uploaded_object;
	}

	string CompletionBody() const DUCKDB_EXCLUDES(upload_lock) {
		annotated_lock_guard<annotated_mutex> lock(upload_lock);
		return completion_body;
	}

	idx_t MaximumConcurrentPartUploads() const DUCKDB_EXCLUDES(upload_lock) {
		annotated_lock_guard<annotated_mutex> lock(upload_lock);
		return maximum_active_part_uploads;
	}

	bool WaitForPartUpload(idx_t part_number) DUCKDB_EXCLUDES(upload_lock) {
		annotated_unique_lock<annotated_mutex> lock(upload_lock);
		return part_upload_started.wait_for(lock, std::chrono::seconds(5),
		                                    [this, part_number]() DUCKDB_REQUIRES(upload_lock) {
			                                    return parts_seen.find(part_number) != parts_seen.end();
		                                    });
	}

	void ReleasePartUpload(idx_t part_number) DUCKDB_EXCLUDES(upload_lock) {
		{
			annotated_lock_guard<annotated_mutex> lock(upload_lock);
			released_part_numbers.insert(part_number);
		}
		part_upload_release.notify_all();
	}

	void ReleasePartUploads() DUCKDB_EXCLUDES(upload_lock) {
		{
			annotated_lock_guard<annotated_mutex> lock(upload_lock);
			part_uploads_released = true;
		}
		part_upload_release.notify_all();
	}

	bool WaitForMultipartInitialization() DUCKDB_EXCLUDES(initialization_lock) {
		annotated_unique_lock<annotated_mutex> lock(initialization_lock);
		return initialization_started.wait_for(
		    lock, std::chrono::seconds(5),
		    [this]() DUCKDB_REQUIRES(initialization_lock) { return initialization_seen; });
	}

	void ReleaseMultipartInitialization() DUCKDB_EXCLUDES(initialization_lock) {
		{
			annotated_lock_guard<annotated_mutex> lock(initialization_lock);
			initialization_released = true;
		}
		initialization_release.notify_all();
	}

	bool WaitForFullGet() DUCKDB_EXCLUDES(full_get_lock) {
		annotated_unique_lock<annotated_mutex> lock(full_get_lock);
		return full_get_started.wait_for(lock, std::chrono::seconds(5),
		                                 [this]() DUCKDB_REQUIRES(full_get_lock) { return full_get_seen; });
	}

	void ReleaseFullGet() DUCKDB_EXCLUDES(full_get_lock) {
		{
			annotated_lock_guard<annotated_mutex> lock(full_get_lock);
			full_get_released = true;
		}
		full_get_release.notify_all();
	}

	bool MatchesRefreshTarget(const httplib::Request &request) const {
		auto range = GetHeader(request, "Range");
		switch (config.auth.refresh_target) {
		case MockS3RefreshTarget::HEAD:
			return request.method == "HEAD";
		case MockS3RefreshTarget::FULL_GET:
			return request.method == "GET" && range.empty();
		case MockS3RefreshTarget::RANGE_GET:
			return request.method == "GET" && !range.empty();
		case MockS3RefreshTarget::PUT:
			return request.method == "PUT";
		case MockS3RefreshTarget::MULTIPART_INITIATE_POST:
			return request.method == "POST" && request.target.find("uploads") != string::npos;
		case MockS3RefreshTarget::MULTIPART_COMPLETE_POST:
			return request.method == "POST" && request.target.find("uploadId") != string::npos;
		case MockS3RefreshTarget::BULK_DELETE_POST:
			return request.method == "POST" && request.target.find("delete") != string::npos;
		case MockS3RefreshTarget::DELETE_OBJECT:
			return request.method == "DELETE";
		case MockS3RefreshTarget::LIST_OBJECTS_GET:
			return request.method == "GET" && request.target.find("list-type=2") != string::npos;
		default:
			throw InternalException("Unknown refresh target");
		}
	}

	bool ShouldRejectStaleCredentials(const httplib::Request &request) const {
		auto authorization = GetHeader(request, "Authorization");
		if (!config.auth.stale_authorization.empty()) {
			return authorization == config.auth.stale_authorization && MatchesRefreshTarget(request);
		}
		return ExtractCredentialKey(authorization) == config.auth.stale_key_id && MatchesRefreshTarget(request);
	}

	bool ShouldRedirectRegion(const httplib::Request &request) const {
		return !config.auth.required_region.empty() &&
		       ExtractCredentialRegion(GetHeader(request, "Authorization")) != config.auth.required_region;
	}

	void Record(const httplib::Request &request, int status) const DUCKDB_EXCLUDES(observation_lock, upload_lock) {
		MockS3RequestObservation observation;
		for (const auto &header : request.headers) {
			observation.headers.emplace_back(header.first, header.second);
		}
		observation.method = request.method;
		observation.path = request.path;
		observation.target = request.target;
		observation.range = GetHeader(request, "Range");
		observation.if_match = GetHeader(request, "If-Match");
		observation.version_id = GetParameter(request, "versionId");
		observation.authorization = GetHeader(request, "Authorization");
		observation.key_id = ExtractCredentialKey(observation.authorization);
		observation.region = ExtractCredentialRegion(observation.authorization);
		observation.user_agent = GetHeader(request, "User-Agent");
		observation.session_header = GetHeader(request, "X-HTTPFS-Session");
		observation.upload_id = GetParameter(request, "uploadId");
		observation.server_side_encryption = GetHeader(request, "x-amz-server-side-encryption");
		observation.kms_key_id = GetHeader(request, "x-amz-server-side-encryption-aws-kms-key-id");
		observation.part_number = GetPartNumber(request);
		observation.body_size = request.body.size();
		observation.body_digest = MockS3BodyDigest::Compute(request.body);
		observation.delete_key_count = CountDeleteKeys(request.body);
		observation.user_agent_count = CountHeader(request, "User-Agent");
		observation.session_header_count = CountHeader(request, "X-HTTPFS-Session");
		observation.status = status;
		observation.remote_port = request.remote_port;
		{
			annotated_lock_guard<annotated_mutex> lock(upload_lock);
			observation.multipart_upload_published = multipart_upload_published;
		}

		annotated_lock_guard<annotated_mutex> lock(observation_lock);
		observations.push_back(std::move(observation));
	}

	void SetObjectHeaders(httplib::Response &response) const {
		if (config.range.advertise) {
			response.set_header("Accept-Ranges", "bytes");
		} else {
			response.set_header("Accept-Ranges", "none");
		}
		auto content_length = config.metadata.head_content_length.IsValid()
		                          ? config.metadata.head_content_length.GetIndex()
		                          : config.object.data.size();
		response.set_header("Content-Length", std::to_string(content_length));
		response.set_header("ETag", config.metadata.etag);
		if (config.metadata.version_on_head && !config.metadata.version_id.empty()) {
			response.set_header("x-amz-version-id", config.metadata.version_id);
		}
	}

	string GetResponseETag() const {
		return config.metadata.get_etag.empty() ? config.metadata.etag : config.metadata.get_etag;
	}

	void SetGetHeaders(httplib::Response &response) const {
		response.set_header("ETag", GetResponseETag());
		if (config.metadata.version_on_get && !config.metadata.version_id.empty()) {
			response.set_header("x-amz-version-id", config.metadata.version_id);
		}
	}

	void SendSlowDown(const httplib::Request &request, httplib::Response &response) const {
		response.status = 503;
		response.set_content("<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>",
		                     "application/xml");
		Record(request, response.status);
	}

	void SendDisconnectedResponse(const httplib::Request &request, httplib::Response &response,
	                              int status = 200) const {
		response.status = status;
		response.set_content_provider(1, "application/xml", [](size_t, size_t, httplib::DataSink &) { return false; });
		Record(request, response.status);
	}

	void SendAuthFailure(const httplib::Request &request, httplib::Response &response) const {
		response.status = config.auth.stale_status;
		response.set_content(StringUtil::Format("<Error><Code>%s</Code><Message>stale credentials</Message></Error>",
		                                        config.auth.stale_error_code),
		                     "application/xml");
		Record(request, response.status);
	}

	void SendRegionRedirect(const httplib::Request &request, httplib::Response &response) const {
		response.status = 301;
		response.set_header("x-amz-bucket-region", config.auth.required_region);
		response.set_content("<Error><Code>PermanentRedirect</Code></Error>", "application/xml");
		Record(request, response.status);
	}

	void SendPutResponse(const httplib::Request &request, httplib::Response &response) {
		auto part_number = GetPartNumber(request);
		auto &response_config = part_number.IsValid() ? config.upload.multipart_part_put : config.upload.object_put;
		response.status = response_config.status;
		if (part_number.IsValid()) {
			auto part = part_number.GetIndex();
			auto etag = StringUtil::Format("\"mock-part-%llu\"", part);
			SetETagHeader(response, response_config.etag, etag);
			annotated_lock_guard<annotated_mutex> lock(upload_lock);
			uploaded_parts[part] = {std::move(etag), request.body};
		} else {
			SetETagHeader(response, response_config.etag, "\"httpfs-refresh-test-upload-etag\"");
			annotated_lock_guard<annotated_mutex> lock(upload_lock);
			uploaded_object = request.body;
		}
		Record(request, response.status);
	}

	void SendS3Error400(const httplib::Request &request, httplib::Response &response, bool request_timeout) const {
		response.status = 400;
		if (config.failures.truncated_failure_body) {
			response.set_content("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>RequestTimeout",
			                     "application/xml");
		} else if (request_timeout) {
			response.set_content("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			                     "<Error><Code>RequestTimeout</Code><Message>Your socket connection to the server "
			                     "was not read from or written to within the timeout period.</Message></Error>",
			                     "application/xml");
		} else {
			response.set_content("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			                     "<Error><Code>InvalidRequest</Code><Message>malformed request</Message></Error>",
			                     "application/xml");
		}
		Record(request, response.status);
	}

	void SendCompletionFault(const httplib::Request &request, httplib::Response &response) const {
		auto &fault = config.failures.completion_fault;
		response.status = fault.status;
		response.set_content(StringUtil::Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		                                        "<Error><Code>%s</Code><Message>%s</Message></Error>",
		                                        MockS3XMLText::Escape(fault.code),
		                                        MockS3XMLText::Escape(fault.message)),
		                     "application/xml");
		Record(request, response.status);
	}

	bool TryCompleteMultipartUpload(const httplib::Request &request) DUCKDB_EXCLUDES(upload_lock) {
		vector<MockS3ManifestPart> manifest;
		auto valid_manifest = MockS3CompletionManifest::TryParse(request.body, manifest);
		auto upload_id = GetParameter(request, "uploadId");

		annotated_lock_guard<annotated_mutex> lock(upload_lock);
		completion_body = request.body;
		if (!valid_manifest || upload_id != config.upload.upload_id || manifest.size() != uploaded_parts.size()) {
			return false;
		}

		idx_t completed_size = 0;
		for (const auto &uploaded_part : uploaded_parts) {
			if (uploaded_part.second.body.size() > NumericLimits<idx_t>::Maximum() - completed_size) {
				return false;
			}
			completed_size += uploaded_part.second.body.size();
		}
		string completed_object;
		completed_object.reserve(completed_size);
		idx_t previous_part_number = 0;
		idx_t fixed_part_size = 0;
		for (idx_t part_index = 0; part_index < manifest.size(); part_index++) {
			const auto &manifest_part = manifest[part_index];
			auto uploaded_part = uploaded_parts.find(manifest_part.part_number);
			if (manifest_part.part_number <= previous_part_number || uploaded_part == uploaded_parts.end() ||
			    manifest_part.etag != uploaded_part->second.etag) {
				return false;
			}
			if (config.upload.geometry == MockS3MultipartGeometry::FIXED_EQUAL) {
				auto part_size = uploaded_part->second.body.size();
				if (part_index == 0) {
					fixed_part_size = part_size;
				} else if ((part_index + 1 < manifest.size() && part_size != fixed_part_size) ||
				           (part_index + 1 == manifest.size() && part_size > fixed_part_size)) {
					return false;
				}
			}
			completed_object += uploaded_part->second.body;
			previous_part_number = manifest_part.part_number;
		}
		uploaded_object = std::move(completed_object);
		multipart_upload_published = true;
		return true;
	}

	void SendMultipartPost(const httplib::Request &request, httplib::Response &response) {
		if (request.target.find("uploads") != string::npos) {
			if (config.upload.block_initialization) {
				annotated_unique_lock<annotated_mutex> lock(initialization_lock);
				initialization_seen = true;
				initialization_started.notify_all();
				initialization_release.wait_for(
				    lock, std::chrono::seconds(30),
				    [this]() DUCKDB_REQUIRES(initialization_lock) { return initialization_released; });
			}
			switch (config.upload.initialization_behavior) {
			case MockS3MultipartInitializationBehavior::SUCCESS:
				response.status = 200;
				response.set_content(StringUtil::Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				                                        "<InitiateMultipartUploadResult><UploadId>%s</UploadId></"
				                                        "InitiateMultipartUploadResult>",
				                                        config.upload.upload_id),
				                     "application/xml");
				Record(request, response.status);
				return;
			case MockS3MultipartInitializationBehavior::NAMESPACED_ESCAPED_SUCCESS:
				response.status = 200;
				response.set_content(
				    StringUtil::Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				                       "<s3:InitiateMultipartUploadResult "
				                       "xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
				                       "<s3:UploadId>%s</s3:UploadId></s3:InitiateMultipartUploadResult>",
				                       MockS3XMLText::Escape(config.upload.upload_id)),
				    "application/xml");
				Record(request, response.status);
				return;
			case MockS3MultipartInitializationBehavior::MALFORMED_SUCCESS:
				response.status = 200;
				response.set_content("<InitiateMultipartUploadResult><UploadId>unknown", "application/xml");
				Record(request, response.status);
				return;
			case MockS3MultipartInitializationBehavior::CREATE_THEN_DISCONNECT:
				SendDisconnectedResponse(request, response);
				return;
			default:
				throw InternalException("Unknown multipart initialization behavior");
			}
		}

		if (config.upload.completion_behavior == MockS3MultipartCompletionBehavior::EMBEDDED_ERROR) {
			{
				annotated_lock_guard<annotated_mutex> lock(upload_lock);
				completion_body = request.body;
			}
			response.status = 200;
			response.set_content(
			    "<Error><Code>InternalError</Code><Message>Multipart completion failed.</Message></Error>",
			    "application/xml");
			Record(request, response.status);
			return;
		}
		if (!TryCompleteMultipartUpload(request)) {
			response.status = 400;
			response.set_content("<Error><Code>InvalidPart</Code><Message>Invalid multipart completion "
			                     "manifest.</Message></Error>",
			                     "application/xml");
			Record(request, response.status);
			return;
		}
		switch (config.upload.completion_behavior) {
		case MockS3MultipartCompletionBehavior::SUCCESS:
			response.status = 200;
			response.set_content("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			                     "<CompleteMultipartUploadResult><ETag>\"httpfs-refresh-test-final-etag\"</ETag></"
			                     "CompleteMultipartUploadResult>",
			                     "application/xml");
			Record(request, response.status);
			return;
		case MockS3MultipartCompletionBehavior::UNKNOWN_SUCCESS:
			response.status = 200;
			response.set_content("<UnexpectedMultipartResponse/>", "application/xml");
			Record(request, response.status);
			return;
		case MockS3MultipartCompletionBehavior::EMPTY_SUCCESS:
			response.status = 200;
			response.set_content("", "application/xml");
			Record(request, response.status);
			return;
		case MockS3MultipartCompletionBehavior::MALFORMED_SUCCESS:
			response.status = 200;
			response.set_content("<CompleteMultipartUploadResult><ETag>incomplete", "application/xml");
			Record(request, response.status);
			return;
		case MockS3MultipartCompletionBehavior::COMMIT_THEN_DISCONNECT:
			SendDisconnectedResponse(request, response, config.upload.completion_disconnect_status);
			return;
		case MockS3MultipartCompletionBehavior::EMBEDDED_ERROR:
			throw InternalException("Embedded multipart errors must be handled before committing the upload");
		default:
			throw InternalException("Unknown multipart completion behavior");
		}
	}

	void BeginPartUpload(idx_t part_number) DUCKDB_EXCLUDES(upload_lock) {
		{
			annotated_lock_guard<annotated_mutex> lock(upload_lock);
			active_part_uploads++;
			maximum_active_part_uploads = MaxValue(maximum_active_part_uploads, active_part_uploads);
			parts_seen.insert(part_number);
		}
		part_upload_started.notify_all();
	}

	void WaitForPartRelease(idx_t part_number) DUCKDB_EXCLUDES(upload_lock) {
		if (std::find(config.upload.blocked_part_numbers.begin(), config.upload.blocked_part_numbers.end(),
		              part_number) == config.upload.blocked_part_numbers.end()) {
			return;
		}
		annotated_unique_lock<annotated_mutex> lock(upload_lock);
		part_upload_release.wait_for(
		    lock, std::chrono::seconds(30), [this, part_number]() DUCKDB_REQUIRES(upload_lock) {
			    return part_uploads_released || released_part_numbers.find(part_number) != released_part_numbers.end();
		    });
	}

	void FinishPartUpload() DUCKDB_EXCLUDES(upload_lock) {
		annotated_lock_guard<annotated_mutex> lock(upload_lock);
		D_ASSERT(active_part_uploads > 0);
		active_part_uploads--;
	}

	void SendBulkDeleteResponse(const httplib::Request &request, httplib::Response &response) const {
		auto key_count = CountDeleteKeys(request.body);
		if (config.bulk_delete.maximum_key_count.IsValid() &&
		    key_count > config.bulk_delete.maximum_key_count.GetIndex()) {
			response.status = 500;
			response.set_content("<Error><Code>InternalError</Code><Message>DeleteObjects batch is too large</Message>"
			                     "</Error>",
			                     "application/xml");
			Record(request, response.status);
			return;
		}
		response.status = 200;
		response.set_content("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		                     "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>",
		                     "application/xml");
		Record(request, response.status);
	}

	void SendListObjectsSuccess(const httplib::Request &request, httplib::Response &response) const {
		response.status = 200;
		auto unquoted_etag = StringUtil::Replace(config.metadata.etag, "\"", "");
		auto first_page = config.list.paginate && GetParameter(request, "continuation-token").empty();
		auto key = first_page ? "first-page.bin" : config.object.key;
		auto continuation = first_page ? "<NextContinuationToken>page two&amp;token</NextContinuationToken>" : "";
		response.set_content(StringUtil::Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		                                        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
		                                        "<Name>%s</Name>"
		                                        "<Prefix></Prefix>"
		                                        "<KeyCount>1</KeyCount>"
		                                        "<MaxKeys>1000</MaxKeys>"
		                                        "<IsTruncated>%s</IsTruncated>"
		                                        "%s"
		                                        "<Contents>"
		                                        "<Key>%s</Key>"
		                                        "<ETag>&quot;%s&quot;</ETag>"
		                                        "<Size>%llu</Size>"
		                                        "</Contents>"
		                                        "</ListBucketResult>",
		                                        config.object.bucket, first_page ? "true" : "false", continuation, key,
		                                        unquoted_etag,
		                                        static_cast<unsigned long long>(config.object.data.size())),
		                     "application/xml");
		Record(request, response.status);
	}

	void SendMalformedListObjectsSuccess(const httplib::Request &request, httplib::Response &response) const {
		response.status = 200;
		if (config.failures.malformed_list_behavior == MockS3MalformedListBehavior::FOREIGN_NAMESPACE_KEY) {
			response.set_content("<native:ListBucketResult xmlns:native=\"urn:native\" xmlns:foreign=\"urn:foreign\">"
			                     "<native:Contents><foreign:Key>partial-fake-object.bin</foreign:Key>"
			                     "</native:Contents></native:ListBucketResult>",
			                     "application/xml");
		} else {
			response.set_content(
			    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			    "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
			    "<Name>refresh-bucket</Name>"
			    "<Contents><Key>partial-fake-object.bin</Key><ETag>&quot;fake&quot;</ETag><Size>1</Size>"
			    "</Contents>",
			    "application/xml");
		}
		Record(request, response.status);
	}

	void HandleObjectPut(const httplib::Request &request, httplib::Response &response) {
		auto part_number = GetPartNumber(request);
		unique_ptr<ActivePartUpload> active_upload;
		if (part_number.IsValid()) {
			active_upload = make_uniq<ActivePartUpload>(*this, part_number.GetIndex());
			WaitForPartRelease(part_number.GetIndex());
		}
		if (ShouldRejectStaleCredentials(request)) {
			SendAuthFailure(request, response);
			return;
		}
		if (part_number.IsValid() &&
		    std::find(config.upload.failed_part_numbers.begin(), config.upload.failed_part_numbers.end(),
		              part_number.GetIndex()) != config.upload.failed_part_numbers.end()) {
			SendS3Error400(request, response, false);
			return;
		}
		if (remaining_put_failures.load() > 0) {
			remaining_put_failures--;
			SendS3Error400(request, response, config.failures.failure_is_request_timeout);
			return;
		}
		SendPutResponse(request, response);
	}

	void HandleObjectPost(const httplib::Request &request, httplib::Response &response) {
		if (ShouldRejectStaleCredentials(request)) {
			SendAuthFailure(request, response);
			return;
		}
		if (request.target.find("uploads") != string::npos && remaining_post_failures.load() > 0) {
			remaining_post_failures--;
			if (config.failures.transient_post_status == 400) {
				SendS3Error400(request, response, config.failures.failure_is_request_timeout);
			} else {
				response.status = config.failures.transient_post_status;
				response.set_content(
				    "<Error><Code>TooManyRequests</Code><Message>Injected initialization throttle</Message></Error>",
				    "application/xml");
				Record(request, response.status);
			}
			return;
		}
		if (request.target.find("uploadId") != string::npos && remaining_completion_faults.load() > 0) {
			remaining_completion_faults--;
			SendCompletionFault(request, response);
			return;
		}
		SendMultipartPost(request, response);
	}

	void HandleObjectDelete(const httplib::Request &request, httplib::Response &response) {
		if (ShouldRejectStaleCredentials(request)) {
			SendAuthFailure(request, response);
			return;
		}
		auto upload_id = GetParameter(request, "uploadId");
		if (!upload_id.empty()) {
			if (config.upload.abort_behavior == MockS3MultipartAbortBehavior::ERROR) {
				SendS3Error400(request, response, false);
				return;
			}
			if (upload_id != config.upload.upload_id) {
				response.status = 404;
				response.set_content("<Error><Code>NoSuchUpload</Code></Error>", "application/xml");
				Record(request, response.status);
				return;
			}
			{
				annotated_lock_guard<annotated_mutex> lock(upload_lock);
				uploaded_parts.clear();
			}
			response.status = 204;
			Record(request, response.status);
			return;
		}
		if (remaining_delete_failures.load() > 0) {
			remaining_delete_failures--;
			SendS3Error400(request, response, config.failures.failure_is_request_timeout);
			return;
		}
		response.status = 204;
		Record(request, response.status);
	}

	void RegisterRoutes() {
		D_ASSERT(config.endpoint_base_path.empty() ||
		         (config.endpoint_base_path[0] == '/' && config.endpoint_base_path.back() != '/'));
		const string path =
		    config.endpoint_base_path + StringUtil::Format("/%s/%s", config.object.bucket, config.object.key);
		const string proxy_path = "https?://[^/]+" + path;
		const string bucket_path = config.endpoint_base_path + StringUtil::Format("/%s", config.object.bucket);
		const string bucket_path_with_slash = bucket_path + "/";
		const string proxy_bucket_path = "https?://[^/]+" + bucket_path;
		const string proxy_bucket_path_with_slash = proxy_bucket_path + "/";
		server.set_post_routing_handler([this](const httplib::Request &, httplib::Response &response) {
			if (!response.has_header("X-Mock-Successful-Short-Response")) {
				return;
			}
			auto omitted_bytes = MinValue<idx_t>(config.range.truncated_bytes, response.body.size());
			response.body.resize(response.body.size() - omitted_bytes);
			auto content_length = response.headers.equal_range("Content-Length");
			response.headers.erase(content_length.first, content_length.second);
			auto marker = response.headers.equal_range("X-Mock-Successful-Short-Response");
			response.headers.erase(marker.first, marker.second);
		});

		server.set_pre_routing_handler([this, path](const httplib::Request &request, httplib::Response &response) {
			if (request.method != "HEAD" || request.path != path) {
				return httplib::Server::HandlerResponse::Unhandled;
			}
			if (ShouldRedirectRegion(request)) {
				SendRegionRedirect(request, response);
				return httplib::Server::HandlerResponse::Handled;
			}
			if (ShouldRejectStaleCredentials(request)) {
				SendAuthFailure(request, response);
				return httplib::Server::HandlerResponse::Handled;
			}
			if (remaining_head_not_found.load() > 0) {
				remaining_head_not_found--;
				response.status = 404;
				Record(request, response.status);
				return httplib::Server::HandlerResponse::Handled;
			}
			if (remaining_head_failures.load() > 0) {
				remaining_head_failures--;
				SendS3Error400(request, response, config.failures.failure_is_request_timeout);
				return httplib::Server::HandlerResponse::Handled;
			}
			response.status = 200;
			SetObjectHeaders(response);
			Record(request, response.status);
			return httplib::Server::HandlerResponse::Handled;
		});

		server.Get(path, [this](const httplib::Request &request, httplib::Response &response) {
			if (ShouldRejectStaleCredentials(request)) {
				SendAuthFailure(request, response);
				return;
			}
			if (remaining_get_failures.load() > 0) {
				remaining_get_failures--;
				SendS3Error400(request, response, config.failures.failure_is_request_timeout);
				return;
			}
			if (config.metadata.enforce_if_match && GetHeader(request, "If-Match") != GetResponseETag()) {
				response.status = 412;
				Record(request, response.status);
				return;
			}

			auto range = GetHeader(request, "Range");
			if (range.empty()) {
				response.status = 200;
				SetGetHeaders(response);
				if (config.full_get.block_until_released) {
					response.set_content_provider(
					    config.object.data.size(), "application/octet-stream",
					    [this](size_t offset, size_t length, httplib::DataSink &sink) {
						    if (offset == 0) {
							    annotated_unique_lock<annotated_mutex> lock(full_get_lock);
							    full_get_seen = true;
							    full_get_started.notify_all();
							    if (!full_get_release.wait_for(
							            lock, std::chrono::seconds(5),
							            [this]() DUCKDB_REQUIRES(full_get_lock) { return full_get_released; })) {
								    return false;
							    }
						    }
						    return sink.write(config.object.data.data() + offset, length);
					    });
					Record(request, response.status);
					return;
				}
				if (config.full_get.chunked) {
					response.set_chunked_content_provider(
					    "application/octet-stream", [this](size_t offset, httplib::DataSink &sink) {
						    if (offset >= config.object.data.size()) {
							    sink.done();
							    return true;
						    }
						    const auto length = MinValue<size_t>(7, config.object.data.size() - offset);
						    if (!sink.write(config.object.data.data() + offset, length)) {
							    return false;
						    }
						    if (offset + length == config.object.data.size()) {
							    sink.done();
						    }
						    return true;
					    });
					Record(request, response.status);
					return;
				}
				response.set_content(config.object.data, "application/octet-stream");
				Record(request, response.status);
				return;
			}
			if (config.range.behavior == MockS3RangeBehavior::IGNORE_RANGE) {
				response.status = 200;
				SetGetHeaders(response);
				response.set_content(config.object.data, "application/octet-stream");
				Record(request, response.status);
				return;
			}

			idx_t range_start;
			idx_t range_end;
			if (!ParseRange(range, config.object.data.size(), range_start, range_end)) {
				response.status = 416;
				Record(request, response.status);
				return;
			}

			idx_t range_request_index;
			{
				annotated_lock_guard<annotated_mutex> lock(range_request_lock);
				range_request_index = ++range_requests_seen;
			}
			range_request_started.notify_all();
			response.status = 206;
			response.set_header("Accept-Ranges", "bytes");
			SetGetHeaders(response);
			if (!config.range.blocked.empty() && range == config.range.blocked) {
				response.set_content_provider(config.object.data.size(), "application/octet-stream",
				                              [this](size_t offset, size_t length, httplib::DataSink &sink) {
					                              annotated_unique_lock<annotated_mutex> lock(range_release_lock);
					                              if (!range_release.wait_for(lock, std::chrono::seconds(5),
					                                                          [this]()
					                                                              DUCKDB_REQUIRES(range_release_lock) {
						                                                              return release_range_completed;
					                                                              })) {
						                              return false;
					                              }
					                              return sink.write(config.object.data.data() + offset, length);
				                              });
				Record(request, response.status);
				return;
			}
			if (!config.range.release.empty() && range == config.range.release) {
				response.set_content_provider(
				    config.object.data.size(), "application/octet-stream",
				    [this](size_t offset, size_t length, httplib::DataSink &sink) {
					    const auto success = sink.write(config.object.data.data() + offset, length);
					    if (success) {
						    {
							    annotated_lock_guard<annotated_mutex> lock(range_release_lock);
							    release_range_completed = true;
						    }
						    range_release.notify_all();
					    }
					    return success;
				    });
				Record(request, response.status);
				return;
			}
			if (config.range.block_first_body_until_second && range_request_index == 1) {
				auto wait_for_second_request = make_shared_ptr<atomic<bool>>(true);
				response.set_content_provider(
				    config.object.data.size(), "application/octet-stream",
				    [this, wait_for_second_request](size_t offset, size_t length, httplib::DataSink &sink) {
					    if (wait_for_second_request->exchange(false)) {
						    annotated_unique_lock<annotated_mutex> lock(range_request_lock);
						    if (!range_request_started.wait_for(lock, std::chrono::seconds(5),
						                                        [this]() DUCKDB_REQUIRES(range_request_lock) {
							                                        return range_requests_seen >= 2;
						                                        })) {
							    return false;
						    }
					    }
					    return sink.write(config.object.data.data() + offset, length);
				    });
				Record(request, response.status);
				return;
			}
			if (config.range.behavior == MockS3RangeBehavior::SHORT_SUCCESS &&
			    ConsumeBehavior(remaining_range_behavior_requests)) {
				response.set_header("X-Mock-Successful-Short-Response", "1");
				response.set_content(config.object.data, "application/octet-stream");
				Record(request, response.status);
				return;
			}
			if (config.range.behavior == MockS3RangeBehavior::TRUNCATE_TRANSFER &&
			    ConsumeBehavior(remaining_range_behavior_requests)) {
				response.set_content_provider(config.object.data.size(), "application/octet-stream",
				                              [this](size_t offset, size_t length, httplib::DataSink &sink) {
					                              auto omitted_bytes =
					                                  MinValue<idx_t>(config.range.truncated_bytes, length);
					                              auto emitted_bytes = length - omitted_bytes;
					                              if (emitted_bytes > 0) {
						                              sink.write(config.object.data.data() + offset, emitted_bytes);
					                              }
					                              return false;
				                              });
				Record(request, response.status);
				return;
			}
			response.set_content(config.object.data, "application/octet-stream");
			Record(request, response.status);
		});

		auto list_objects = [this](const httplib::Request &request, httplib::Response &response) {
			if (request.target.find("list-type=2") == string::npos) {
				response.status = 404;
				Record(request, response.status);
				return;
			}
			if (ShouldRedirectRegion(request)) {
				SendRegionRedirect(request, response);
				return;
			}
			if (ShouldRejectStaleCredentials(request)) {
				SendAuthFailure(request, response);
				return;
			}
			if (config.list.paginate && GetParameter(request, "continuation-token").empty()) {
				SendListObjectsSuccess(request, response);
				return;
			}
			if (config.failures.transient_503_lists > 0 &&
			    transient_503_lists_sent.fetch_add(1) < config.failures.transient_503_lists) {
				SendSlowDown(request, response);
				return;
			}
			if (config.failures.transient_400_lists > 0 &&
			    transient_400_lists_sent.fetch_add(1) < config.failures.transient_400_lists) {
				SendS3Error400(request, response, config.failures.failure_is_request_timeout);
				return;
			}
			if (config.failures.malformed_success_lists > 0 &&
			    malformed_success_lists_sent.fetch_add(1) < config.failures.malformed_success_lists) {
				SendMalformedListObjectsSuccess(request, response);
				return;
			}
			SendListObjectsSuccess(request, response);
		};
		server.Get(bucket_path, list_objects);
		server.Get(bucket_path_with_slash, list_objects);

		server.Put(path, [this](const httplib::Request &request, httplib::Response &response) {
			HandleObjectPut(request, response);
		});
		server.Put(proxy_path, [this](const httplib::Request &request, httplib::Response &response) {
			HandleObjectPut(request, response);
		});

		server.Post(path, [this](const httplib::Request &request, httplib::Response &response) {
			HandleObjectPost(request, response);
		});
		server.Post(proxy_path, [this](const httplib::Request &request, httplib::Response &response) {
			HandleObjectPost(request, response);
		});

		auto bulk_delete = [this](const httplib::Request &request, httplib::Response &response) {
			if (ShouldRejectStaleCredentials(request)) {
				SendAuthFailure(request, response);
				return;
			}
			SendBulkDeleteResponse(request, response);
		};
		server.Post(bucket_path, bulk_delete);
		server.Post(bucket_path_with_slash, bulk_delete);
		server.Post(proxy_bucket_path, bulk_delete);
		server.Post(proxy_bucket_path_with_slash, bulk_delete);

		server.Delete(path, [this](const httplib::Request &request, httplib::Response &response) {
			HandleObjectDelete(request, response);
		});
		server.Delete(proxy_path, [this](const httplib::Request &request, httplib::Response &response) {
			HandleObjectDelete(request, response);
		});
	}

public:
	//! Server configuration and lifetime
	MockS3ServerConfig config;
	httplib::Server server;
	std::thread server_thread;
	int port = 0;

	//! Injected request failures
	mutable atomic<idx_t> transient_503_lists_sent {0};
	mutable atomic<idx_t> transient_400_lists_sent {0};
	mutable atomic<idx_t> malformed_success_lists_sent {0};
	mutable atomic<idx_t> remaining_put_failures {0};
	mutable atomic<idx_t> remaining_get_failures {0};
	mutable atomic<idx_t> remaining_range_behavior_requests {0};
	mutable atomic<idx_t> remaining_head_failures {0};
	mutable atomic<idx_t> remaining_head_not_found {0};
	mutable atomic<idx_t> remaining_delete_failures {0};
	mutable atomic<idx_t> remaining_post_failures {0};
	mutable atomic<idx_t> remaining_completion_faults {0};

	//! Request observations
	mutable annotated_mutex observation_lock;
	mutable vector<MockS3RequestObservation> observations DUCKDB_GUARDED_BY(observation_lock);

	//! Multipart upload state
	mutable annotated_mutex upload_lock;
	map<idx_t, UploadedPart> uploaded_parts DUCKDB_GUARDED_BY(upload_lock);
	set<idx_t> parts_seen DUCKDB_GUARDED_BY(upload_lock);
	set<idx_t> released_part_numbers DUCKDB_GUARDED_BY(upload_lock);
	string uploaded_object DUCKDB_GUARDED_BY(upload_lock);
	string completion_body DUCKDB_GUARDED_BY(upload_lock);
	bool multipart_upload_published DUCKDB_GUARDED_BY(upload_lock) = false;
	idx_t active_part_uploads DUCKDB_GUARDED_BY(upload_lock) = 0;
	idx_t maximum_active_part_uploads DUCKDB_GUARDED_BY(upload_lock) = 0;
	bool part_uploads_released DUCKDB_GUARDED_BY(upload_lock) = false;
	std::condition_variable part_upload_started;
	std::condition_variable part_upload_release;

	//! Multipart initialization coordination
	annotated_mutex initialization_lock;
	std::condition_variable initialization_started;
	std::condition_variable initialization_release;
	bool initialization_seen DUCKDB_GUARDED_BY(initialization_lock) = false;
	bool initialization_released DUCKDB_GUARDED_BY(initialization_lock) = false;

	//! Range request coordination
	annotated_mutex range_request_lock;
	std::condition_variable range_request_started;
	idx_t range_requests_seen DUCKDB_GUARDED_BY(range_request_lock) = 0;
	annotated_mutex range_release_lock;
	std::condition_variable range_release;
	bool release_range_completed DUCKDB_GUARDED_BY(range_release_lock) = false;

	//! Full GET coordination
	annotated_mutex full_get_lock;
	std::condition_variable full_get_started;
	std::condition_variable full_get_release;
	bool full_get_seen DUCKDB_GUARDED_BY(full_get_lock) = false;
	bool full_get_released DUCKDB_GUARDED_BY(full_get_lock) = false;
};

MockS3Server::MockS3Server(MockS3ServerConfig config) : impl(make_uniq<Impl>(std::move(config))) {
}

MockS3Server::~MockS3Server() {
}

string MockS3Server::Endpoint() const {
	return impl->Endpoint();
}

string MockS3Server::S3Path() const {
	return impl->S3Path();
}

string MockS3Server::HTTPPath() const {
	return impl->HTTPPath();
}

const string &MockS3Server::ObjectData() const {
	return impl->config.object.data;
}

string MockS3Server::UploadedObject() const {
	return impl->UploadedObject();
}

string MockS3Server::CompletionBody() const {
	return impl->CompletionBody();
}

vector<MockS3RequestObservation> MockS3Server::Observations() const {
	return impl->Observations();
}

idx_t MockS3Server::MaximumConcurrentPartUploads() const {
	return impl->MaximumConcurrentPartUploads();
}

bool MockS3Server::WaitForPartUpload(idx_t part_number) {
	return impl->WaitForPartUpload(part_number);
}

void MockS3Server::ReleasePartUpload(idx_t part_number) {
	impl->ReleasePartUpload(part_number);
}

void MockS3Server::ReleasePartUploads() {
	impl->ReleasePartUploads();
}

bool MockS3Server::WaitForMultipartInitialization() {
	return impl->WaitForMultipartInitialization();
}

void MockS3Server::ReleaseMultipartInitialization() {
	impl->ReleaseMultipartInitialization();
}

bool MockS3Server::WaitForFullGet() {
	return impl->WaitForFullGet();
}

void MockS3Server::ReleaseFullGet() {
	impl->ReleaseFullGet();
}

string MockS3RefreshTargetName(MockS3RefreshTarget target) {
	switch (target) {
	case MockS3RefreshTarget::HEAD:
		return "HEAD";
	case MockS3RefreshTarget::FULL_GET:
		return "FULL_GET";
	case MockS3RefreshTarget::RANGE_GET:
		return "RANGE_GET";
	case MockS3RefreshTarget::PUT:
		return "PUT";
	case MockS3RefreshTarget::MULTIPART_INITIATE_POST:
		return "MULTIPART_INITIATE_POST";
	case MockS3RefreshTarget::MULTIPART_COMPLETE_POST:
		return "MULTIPART_COMPLETE_POST";
	case MockS3RefreshTarget::BULK_DELETE_POST:
		return "BULK_DELETE_POST";
	case MockS3RefreshTarget::DELETE_OBJECT:
		return "DELETE";
	case MockS3RefreshTarget::LIST_OBJECTS_GET:
		return "LIST_OBJECTS_GET";
	default:
		throw InternalException("Unknown refresh target");
	}
}

bool MockS3HasObservation(const vector<MockS3RequestObservation> &observations, const string &method,
                          const string &key_id, int status, const string &range, const string &target_contains) {
	for (auto &observation : observations) {
		if (observation.method == method && observation.key_id == key_id && observation.status == status &&
		    observation.range == range &&
		    (target_contains.empty() || observation.target.find(target_contains) != string::npos)) {
			return true;
		}
	}
	return false;
}

vector<string> MockS3HeaderValues(const MockS3RequestObservation &observation, const string &name) {
	vector<string> result;
	for (const auto &header : observation.headers) {
		if (StringUtil::CIEquals(header.first, name)) {
			result.push_back(header.second);
		}
	}
	return result;
}

string MockS3DescribeObservations(const vector<MockS3RequestObservation> &observations) {
	string result;
	for (auto &observation : observations) {
		if (!result.empty()) {
			result += "\n";
		}
		result += StringUtil::Format(
		    "%s %s status=%d key=%s region=%s range=%s if_match=%s version_id=%s target=%s upload_id=%s "
		    "part_number=%s body_size=%llu delete_key_count=%llu body_digest=%s published=%s sse=%s "
		    "kms_key_id=%s user_agent=%s "
		    "session_header=%s",
		    observation.method, observation.path, observation.status, observation.key_id, observation.region,
		    observation.range, observation.if_match, observation.version_id, observation.target, observation.upload_id,
		    observation.part_number.IsValid() ? std::to_string(observation.part_number.GetIndex()) : string(),
		    observation.body_size, observation.delete_key_count, observation.body_digest,
		    observation.multipart_upload_published ? "true" : "false", observation.server_side_encryption,
		    observation.kms_key_id, observation.user_agent, observation.session_header);
	}
	return result;
}

} // namespace duckdb
