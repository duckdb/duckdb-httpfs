#include "httpfs_client.hpp"
#include "duckdb/common/random_engine.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/logger.hpp"

namespace duckdb {

unique_ptr<HTTPClient> HTTPFSCurlUtil::FindCachedCandidate(const string &proto_host_port) {
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

void HTTPFSCurlUtil::StoreCachedCandidate(const string &proto_host_port, unique_ptr<HTTPClient> &&client) {
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

bool HTTPFSCurlUtil::EnableCaching(BaseRequest &request) {
	if (!connection_caching_enabled) {
		return false;
	}
	if (!request.params.http_proxy.empty()) {
		return false;
	}
	return true;
}

void HTTPFSCurlUtil::CloseClient(unique_ptr<HTTPClient> &&client) {
	if (connection_caching_enabled) {
		// TODO: would be nice to log connection_cache_store here, but no logger is available at this call site
		StoreCachedCandidate(client->base_url, std::move(client));
	}
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::BaseSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	return HTTPUtil::SendRequest(request, client);
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::CachingSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	bool caller_owns_client = client != nullptr;

	if (!client) {
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

	auto r = BaseSendRequest(request, client);

	// Only cache if the caller didn't provide the client — otherwise the caller manages its lifecycle
	if (!caller_owns_client) {
		StoreCachedCandidate(request.proto_host_port, std::move(client));
	}
	return std::move(r);
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	if (EnableCaching(request)) {
		return CachingSendRequest(request, client);
	}
	return BaseSendRequest(request, client);
}

} // namespace duckdb
