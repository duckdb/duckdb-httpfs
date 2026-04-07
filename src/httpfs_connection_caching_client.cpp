#include "httpfs_client.hpp"
#include "duckdb/common/random_engine.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/logger.hpp"

namespace duckdb {

unique_ptr<HTTPClient> HTTPFSCachedUtil::FindCachedCandidate(const string &proto_host_port) {
	if (proto_host_port.empty()) {
		return nullptr;
	}
	if (auto lock = std::unique_lock<std::mutex>(cached_httpclients_mutex, std::try_to_lock)) {
		for (idx_t i = 0; i < cached_httpclients.size(); i++) {
			if (cached_httpclients[i].proto_host_port == proto_host_port && cached_httpclients[i].cached_client) {
				return std::move(cached_httpclients[i].cached_client);
			}
		}
	}
	return nullptr;
}

void HTTPFSCachedUtil::StoreCachedCandidate(const string &proto_host_port, unique_ptr<HTTPClient> &&client) {
	if (proto_host_port.empty()) {
		return;
	}
	if (auto lock = std::unique_lock<std::mutex>(cached_httpclients_mutex, std::try_to_lock)) {
		if (cached_httpclients.empty()) {
			cached_httpclients.resize(64);
		}
		// First prefer an empty slot
		for (idx_t i = 0; i < cached_httpclients.size(); i++) {
			if (!cached_httpclients[i].cached_client) {
				cached_httpclients[i].cached_client = std::move(client);
				cached_httpclients[i].proto_host_port = proto_host_port;
				return;
			}
		}
		// Else evict one at random
		{
			RandomEngine engine;
			size_t index = engine.NextRandomInteger() % cached_httpclients.size();
			cached_httpclients[index].cached_client = std::move(client);
			cached_httpclients[index].proto_host_port = proto_host_port;
		}
	}
}

unique_ptr<HTTPClient> HTTPFSCachedUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	auto client = FindCachedCandidate(proto_host_port);
	if (client) {
		client->Initialize(http_params);
		return client;
	}
	return HTTPFSCurlUtil::InitializeClient(http_params, proto_host_port);
}

void HTTPFSCachedUtil::CloseClient(const string &proto_host_port, unique_ptr<HTTPClient> &&client) {
	// TODO: would be nice to log connection_cache_store here, but no logger is available at this call site
	StoreCachedCandidate(proto_host_port, std::move(client));
}

bool HTTPFSCachedUtil::EnableCaching(BaseRequest &request) {
	// TODO: return false for proxied connections
	return true;
}

unique_ptr<HTTPResponse> HTTPFSCachedUtil::SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	bool caller_owns_client = client != nullptr;
	bool caching = EnableCaching(request);

	if (!client && caching) {
		auto cached_client = FindCachedCandidate(request.proto_host_port);
		if (cached_client) {
			if (request.params.logger &&
			    request.params.logger->ShouldLog(HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL)) {
				request.params.logger->WriteLog(
				    HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL,
				    HTTPFSInfoLogType::ConstructLogMessage("connection_cache_hit", request.proto_host_port));
			}
			cached_client->Initialize(request.params);
			client = std::move(cached_client);
		} else {
			if (request.params.logger &&
			    request.params.logger->ShouldLog(HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL)) {
				request.params.logger->WriteLog(
				    HTTPFSInfoLogType::NAME, HTTPFSInfoLogType::LEVEL,
				    HTTPFSInfoLogType::ConstructLogMessage("connection_cache_miss", request.proto_host_port));
			}
		}
	}
	if (!client) {
		client = InitializeClient(request.params, request.proto_host_port);
	}

	std::function<unique_ptr<HTTPResponse>(void)> on_request([&]() {
		unique_ptr<HTTPResponse> response;

		if (request.params.logger) {
			request.have_request_timing = request.params.logger->ShouldLog(HTTPLogType::NAME, HTTPLogType::LEVEL);
		}

		try {
			if (request.have_request_timing) {
				request.request_start = Timestamp::GetCurrentTimestamp();
			}
			response = client->Request(request);
		} catch (...) {
			if (request.have_request_timing) {
				request.request_end = Timestamp::GetCurrentTimestamp();
			}
			LogRequest(request, nullptr);
			throw;
		}
		if (request.have_request_timing) {
			request.request_end = Timestamp::GetCurrentTimestamp();
		}
		LogRequest(request, response ? response.get() : nullptr);
		return response;
	});

	std::function<void(void)> on_retry([&]() { client = InitializeClient(request.params, request.proto_host_port); });

	auto r = RunRequestWithRetry(on_request, request, on_retry);
	// Only cache if the caller didn't provide the client — otherwise the caller manages its lifecycle
	if (caching && !caller_owns_client) {
		StoreCachedCandidate(request.proto_host_port, std::move(client));
	}
	return std::move(r);
}

string HTTPFSCachedUtil::GetName() const {
	return "HTTPFS-CachedConnection";
}

} // namespace duckdb
