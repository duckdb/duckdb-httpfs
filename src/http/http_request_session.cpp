#include "http/http_request_session.hpp"

#include "duckdb/common/file_opener.hpp"
#include "duckdb/main/config.hpp"
#include "http/http_state.hpp"

namespace duckdb {

static HTTPFSParams FinalizeSnapshotParams(const HTTPFSParams &params) {
	auto result = params;
	result.RefreshTransportReuseDomain();
	return result;
}

HTTPRequestSnapshot::HTTPRequestSnapshot(const HTTPFSParams &params, HTTPRequestSnapshotType type_p)
    : type(type_p), params(FinalizeSnapshotParams(params)) {
}

HTTPRequestSnapshot::~HTTPRequestSnapshot() = default;

HTTPSessionRequest HTTPRequestSnapshot::CreateRequest(HTTPHeaders headers) const {
	auto request_params = make_uniq<HTTPFSParams>(params);
	HTTPConfiguredHeaders configured_headers {std::move(request_params->user_agent),
	                                          std::move(request_params->extra_headers)};
	request_params->user_agent.clear();
	request_params->extra_headers.clear();
	if (!configured_headers.user_agent.empty()) {
		headers.Insert("User-Agent", configured_headers.user_agent);
	}
	for (const auto &header : configured_headers.extra_headers) {
		headers[header.first] = header.second;
	}
	return {std::move(headers), std::move(request_params), std::move(configured_headers)};
}

HTTPRequestSession::HTTPRequestSession(shared_ptr<const HTTPRequestSnapshot> snapshot_p)
    : current_snapshot(std::move(snapshot_p)) {
	D_ASSERT(current_snapshot);
}

HTTPRequestSession::HTTPRequestSession(HTTPTransportManager::Session transport_session_p,
                                       shared_ptr<const HTTPRequestSnapshot> snapshot_p)
    : current_snapshot(std::move(snapshot_p)),
      transport_session(make_uniq<HTTPTransportManager::Session>(std::move(transport_session_p))) {
	D_ASSERT(current_snapshot);
}

shared_ptr<HTTPRequestSession> HTTPRequestSession::Create(optional_ptr<FileOpener> opener,
                                                          optional_ptr<FileOpenerInfo> info) {
	auto database = FileOpener::TryGetDatabase(opener);
	if (database) {
		auto transport_session = DBConfig::GetConfig(*database).GetHTTPTransportManager().CreateSession(opener, info);
		auto snapshot = make_shared_ptr<HTTPRequestSnapshot>(transport_session.Parameters().Cast<HTTPFSParams>());
		return make_shared_ptr<HTTPRequestSession>(std::move(transport_session), std::move(snapshot));
	}
	auto &http_util = HTTPFSUtil::GetHTTPUtil(opener);
	auto params = http_util.InitializeParameters(opener, info);
	auto snapshot = make_shared_ptr<HTTPRequestSnapshot>(params->Cast<HTTPFSParams>());
	return make_shared_ptr<HTTPRequestSession>(std::move(snapshot));
}

CapturedHTTPRequestSnapshot HTTPRequestSession::Capture() const {
	annotated_lock_guard<annotated_mutex> guard(lock);
	return {current_snapshot};
}

HTTPRequestSnapshotPublication HTTPRequestSession::TryPublish(const shared_ptr<const HTTPRequestSnapshot> &expected,
                                                              shared_ptr<const HTTPRequestSnapshot> replacement) {
	D_ASSERT(replacement);
	annotated_lock_guard<annotated_mutex> guard(lock);
	if (current_snapshot != expected) {
		return {{current_snapshot}, false};
	}
	current_snapshot = std::move(replacement);
	return {{current_snapshot}, true};
}

unique_ptr<HTTPResponse> HTTPRequestSession::Request(BaseRequest &request) {
	if (transport_session) {
		return transport_session->Request(request);
	}
	return request.params.http_util.Request(request);
}

void HTTPRequestSession::InvalidateConnections() noexcept {
	if (transport_session) {
		transport_session->Invalidate();
	}
}

} // namespace duckdb
