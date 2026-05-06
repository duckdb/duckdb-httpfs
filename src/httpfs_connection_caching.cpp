#include "httpfs_client.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/random_engine.hpp"
#include "duckdb/common/thread.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/logger.hpp"

#include <functional>

namespace duckdb {

//===--------------------------------------------------------------------===//
// HTTPClientConnectionCache
//===--------------------------------------------------------------------===//

// Per-thread starting pool index. Initialised from a hash of the thread id so
// threads spread across pools, then updated to the last successfully-touched
// pool so subsequent calls revisit the warm pool first.
static thread_local size_t cache_pool_idx =
    std::hash<thread_id> {}(ThreadUtil::GetThreadId()) & (HTTPClientConnectionCache::POOL_COUNT - 1);

unique_ptr<HTTPClient> HTTPClientConnectionCache::Find(const string &base_url) {
	if (base_url.empty()) {
		return nullptr;
	}
	const size_t start = cache_pool_idx;
	for (size_t i = 0; i < POOL_COUNT; i++) {
		const size_t idx = (start + i) & (POOL_COUNT - 1);
		auto &pool = pools[idx];
		unique_lock<mutex> lock(pool.lock, std::try_to_lock);
		if (!lock) {
			continue;
		}
		for (auto &entry : pool.entries) {
			if (entry && entry->GetBaseUrl() == base_url) {
				cache_pool_idx = idx;
				return std::move(entry);
			}
		}
	}
	return nullptr;
}

void HTTPClientConnectionCache::Store(unique_ptr<HTTPClient> &&client) {
	if (!client || client->GetBaseUrl().empty()) {
		return;
	}
	const size_t start = cache_pool_idx;
	// Pass 1: prefer an empty slot in any reachable pool
	for (size_t i = 0; i < POOL_COUNT; i++) {
		const size_t idx = (start + i) & (POOL_COUNT - 1);
		auto &pool = pools[idx];
		unique_lock<mutex> lock(pool.lock, std::try_to_lock);
		if (!lock) {
			continue;
		}
		for (auto &entry : pool.entries) {
			if (!entry) {
				entry = std::move(client);
				cache_pool_idx = idx;
				return;
			}
		}
	}
	// Pass 2: every reachable pool is full — evict at random in the first lockable pool
	RandomEngine engine;
	for (size_t i = 0; i < POOL_COUNT; i++) {
		const size_t idx = (start + i) & (POOL_COUNT - 1);
		auto &pool = pools[idx];
		unique_lock<mutex> lock(pool.lock, std::try_to_lock);
		if (!lock) {
			continue;
		}
		const size_t slot = engine.NextRandomInteger() % pool.entries.size();
		pool.entries[slot] = std::move(client);
		cache_pool_idx = idx;
		return;
	}
	// Every pool busy — drop the client; will reconnect next time.
}

void HTTPClientConnectionCache::Clear() {
	for (auto &pool : pools) {
		lock_guard<mutex> lock(pool.lock);
		for (auto &entry : pool.entries) {
			entry.reset();
		}
	}
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
	if (!client || !connection_caching_enabled) {
		return;
	}
	client->Cleanup();
	// TODO: would be nice to log connection_cache_store here, but no logger is available at this call site
	connection_cache.Store(std::move(client));
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
