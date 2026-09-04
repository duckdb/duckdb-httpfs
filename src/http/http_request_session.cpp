#include "http/http_request_session.hpp"

#include "http/http_state.hpp"

namespace duckdb {

HTTPRequestSnapshot::HTTPRequestSnapshot(const HTTPFSParams &params, HTTPRequestSnapshotType type_p)
    : type(type_p), params(params) {
}

HTTPRequestSnapshot::~HTTPRequestSnapshot() = default;

bool HTTPRequestSnapshot::CanReuseClientsWith(const HTTPRequestSnapshot &other) const {
	return type == other.type && &params.http_util == &other.params.http_util &&
	       params.client_reuse_mode == other.params.client_reuse_mode;
}

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

HTTPClientLease::HTTPClientLease(shared_ptr<HTTPRequestSession> session_p, reference<HTTPUtil> http_util_p,
                                 HTTPClientReuseMode reuse_mode_p, idx_t generation_p, unique_ptr<HTTPClient> client_p)
    : session(std::move(session_p)), http_util(http_util_p), reuse_mode(reuse_mode_p), generation(generation_p),
      client(std::move(client_p)), reusable(true) {
}

HTTPClientLease::HTTPClientLease(HTTPClientLease &&other) noexcept
    : session(std::move(other.session)), http_util(other.http_util), reuse_mode(other.reuse_mode),
      generation(other.generation), client(std::move(other.client)), reusable(other.reusable) {
	other.reusable = false;
}

HTTPClientLease &HTTPClientLease::operator=(HTTPClientLease &&other) noexcept {
	if (this == &other) {
		return *this;
	}
	Release();
	session = std::move(other.session);
	http_util = other.http_util;
	reuse_mode = other.reuse_mode;
	generation = other.generation;
	client = std::move(other.client);
	reusable = other.reusable;
	other.reusable = false;
	return *this;
}

HTTPClientLease::~HTTPClientLease() noexcept {
	Release();
}

void HTTPClientLease::Release() noexcept {
	if (!session) {
		return;
	}
	auto session_ref = std::move(session);
	session_ref->ReturnClient(std::move(client), http_util, reuse_mode, generation, reusable);
}

HTTPRequestSession::HTTPRequestSession(shared_ptr<const HTTPRequestSnapshot> snapshot_p)
    : current_snapshot(std::move(snapshot_p)) {
	D_ASSERT(current_snapshot);
}

HTTPRequestSession::~HTTPRequestSession() {
	vector<IdleClient> clients;
	{
		annotated_lock_guard<annotated_mutex> guard(lock);
		clients = std::move(idle_clients);
	}
	CloseClients(std::move(clients));
}

CapturedHTTPRequestSnapshot HTTPRequestSession::Capture() const {
	annotated_lock_guard<annotated_mutex> guard(lock);
	return {current_snapshot, client_generation};
}

HTTPRequestSnapshotPublication HTTPRequestSession::TryPublish(const shared_ptr<const HTTPRequestSnapshot> &expected,
                                                              shared_ptr<const HTTPRequestSnapshot> replacement) {
	D_ASSERT(replacement);
	vector<IdleClient> clients;
	HTTPRequestSnapshotPublication result;
	{
		annotated_lock_guard<annotated_mutex> guard(lock);
		if (current_snapshot != expected) {
			return {{current_snapshot, client_generation}, false};
		}
		if (!current_snapshot->CanReuseClientsWith(*replacement)) {
			client_generation++;
			clients = std::move(idle_clients);
		}
		current_snapshot = std::move(replacement);
		result = {{current_snapshot, client_generation}, true};
	}
	return result;
}

HTTPClientLease HTTPRequestSession::AcquireClient(const CapturedHTTPRequestSnapshot &captured,
                                                  HTTPFSParams &request_params, const string &proto_host_port) {
	auto &snapshot_params = captured.snapshot->Params();
	auto reuse_mode = snapshot_params.client_reuse_mode;
	unique_ptr<HTTPClient> client;
	bool reused_client = false;
	if (reuse_mode == HTTPClientReuseMode::SESSION_LOCAL) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		if (captured.client_generation == client_generation) {
			for (idx_t i = idle_clients.size(); i > 0; i--) {
				auto &entry = idle_clients[i - 1];
				if (&entry.http_util.get() == &snapshot_params.http_util && entry.client &&
				    entry.client->GetBaseUrl() == proto_host_port) {
					client = std::move(entry.client);
					idle_clients.erase_at(i - 1);
					reused_client = true;
					break;
				}
			}
		}
	}
	if (reused_client) {
		client->Initialize(request_params);
	} else if (!client && reuse_mode != HTTPClientReuseMode::NONE) {
		client = snapshot_params.http_util.InitializeClient(request_params, proto_host_port);
	}
	return HTTPClientLease(shared_from_this(), snapshot_params.http_util, reuse_mode, captured.client_generation,
	                       std::move(client));
}

void HTTPRequestSession::InvalidateClients() {
	vector<IdleClient> clients;
	{
		annotated_lock_guard<annotated_mutex> guard(lock);
		client_generation++;
		clients = std::move(idle_clients);
	}
}

void HTTPRequestSession::ReturnClient(unique_ptr<HTTPClient> client, reference<HTTPUtil> http_util,
                                      HTTPClientReuseMode reuse_mode, idx_t generation, bool reusable) noexcept {
	if (!client) {
		return;
	}
	if (!reusable) {
		return;
	}
	if (reuse_mode == HTTPClientReuseMode::SESSION_LOCAL) {
		bool generation_current = false;
		try {
			annotated_lock_guard<annotated_mutex> guard(lock);
			generation_current = generation == client_generation;
			if (generation_current) {
				idle_clients.emplace_back(std::move(client), http_util);
				return;
			}
		} catch (...) { // NOLINT
			generation_current = true;
		}
		if (!generation_current) {
			return;
		}
	}
	try {
		http_util.get().CloseClient(std::move(client));
	} catch (...) { // NOLINT
	}
}

void HTTPRequestSession::CloseClients(vector<IdleClient> clients) noexcept {
	for (auto &entry : clients) {
		try {
			entry.http_util.get().CloseClient(std::move(entry.client));
		} catch (...) { // NOLINT
		}
	}
}

} // namespace duckdb
