#include "httpfs_client.hpp"
#include "duckdb/common/random_engine.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/logger.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// HTTPClientConnectionCache
//===--------------------------------------------------------------------===//

unique_ptr<HTTPClient> HTTPClientConnectionCache::Find(const string &base_url) {
	if (base_url.empty()) {
		return nullptr;
	}
	if (auto lock = std::unique_lock<std::mutex>(mutex, std::try_to_lock)) {
		for (idx_t i = 0; i < entries.size(); i++) {
			if (entries[i] && entries[i]->GetBaseUrl() == base_url) {
				return std::move(entries[i]);
			}
		}
	}
	return nullptr;
}

void HTTPClientConnectionCache::Store(unique_ptr<HTTPClient> &&client) {
	if (!client || client->GetBaseUrl().empty()) {
		return;
	}
	if (auto lock = std::unique_lock<std::mutex>(mutex, std::try_to_lock)) {
		if (entries.empty()) {
			entries.resize(64);
		}
		// First prefer an empty slot
		for (idx_t i = 0; i < entries.size(); i++) {
			if (!entries[i]) {
				entries[i] = std::move(client);
				return;
			}
		}
		// Else evict one at random
		{
			RandomEngine engine;
			size_t index = engine.NextRandomInteger() % entries.size();
			entries[index] = std::move(client);
		}
	}
}

void HTTPClientConnectionCache::Clear() {
	lock_guard<std::mutex> lck(mutex);
	entries.clear();
}

//===--------------------------------------------------------------------===//
// HTTPFSCurlUtil — connection caching
//===--------------------------------------------------------------------===//

bool HTTPFSCurlUtil::EnableCaching(BaseRequest &request) {
	if (!connection_caching_enabled) {
		return false;
	}
	if (!request.params.http_proxy.empty()) {
		return false;
	}
	return true;
}

void HTTPFSCurlUtil::ClearCachedConnections() {
	connection_cache.Clear();
}

void HTTPFSCurlUtil::CloseClient(unique_ptr<HTTPClient> &&client) {
	if (connection_caching_enabled) {
		// TODO: would be nice to log connection_cache_store here, but no logger is available at this call site
		connection_cache.Store(std::move(client));
	}
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::BaseSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	return HTTPUtil::SendRequest(request, client);
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::CachingSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	bool caller_owns_client = client != nullptr;

	if (!client) {
		auto cached_client = connection_cache.Find(request.proto_host_port);
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
		connection_cache.Store(std::move(client));
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
