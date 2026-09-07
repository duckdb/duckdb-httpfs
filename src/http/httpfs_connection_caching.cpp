#include "http/httpfs_client.hpp"
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

static idx_t &GetCachePoolIndex() {
	// Threads spread across pools, then revisit the last successfully-touched pool first.
	static thread_local idx_t cache_pool_idx =
	    std::hash<thread_id> {}(ThreadUtil::GetThreadId()) & (HTTPClientConnectionCache::POOL_COUNT - 1);
	return cache_pool_idx;
}

unique_ptr<HTTPClient> HTTPClientConnectionCache::Find(const string &base_url) {
	if (base_url.empty()) {
		return nullptr;
	}
	auto &cache_pool_idx = GetCachePoolIndex();
	const idx_t start = cache_pool_idx;
	for (idx_t i = 0; i < POOL_COUNT; i++) {
		const idx_t idx = (start + i) & (POOL_COUNT - 1);
		auto &pool = pools[idx];
		// block instead of skipping: a spurious miss dials a new connection (DNS + TLS),
		// which is far more expensive than waiting for this short critical section
		annotated_lock_guard<annotated_mutex> lock(pool.lock);
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
	auto &cache_pool_idx = GetCachePoolIndex();
	const idx_t start = cache_pool_idx;
	// Pass 1: prefer an empty slot in any pool
	for (idx_t i = 0; i < POOL_COUNT; i++) {
		const idx_t idx = (start + i) & (POOL_COUNT - 1);
		auto &pool = pools[idx];
		annotated_lock_guard<annotated_mutex> lock(pool.lock);
		for (auto &entry : pool.entries) {
			if (!entry) {
				entry = std::move(client);
				cache_pool_idx = idx;
				return;
			}
		}
	}
	// Pass 2: every pool is full — evict at random in the starting pool
	RandomEngine engine;
	auto &pool = pools[start];
	unique_ptr<HTTPClient> evicted_client;
	{
		annotated_lock_guard<annotated_mutex> lock(pool.lock);
		const idx_t slot = engine.NextRandomInteger() % pool.entries.size();
		evicted_client = std::move(pool.entries[slot]);
		pool.entries[slot] = std::move(client);
	}
}

void HTTPClientConnectionCache::Clear() {
	vector<unique_ptr<HTTPClient>> cleared_clients;
	cleared_clients.reserve(POOL_COUNT * POOL_SIZE);
	for (auto &pool : pools) {
		annotated_lock_guard<annotated_mutex> lock(pool.lock);
		for (auto &entry : pool.entries) {
			if (entry) {
				cleared_clients.push_back(std::move(entry));
			}
		}
	}
}

//===--------------------------------------------------------------------===//
// HTTPFSCurlUtil — connection caching
//===--------------------------------------------------------------------===//

bool HTTPFSCurlUtil::EnableCaching(const BaseRequest &request) const {
	if (!ConnectionCachingEnabled()) {
		return false;
	}
	if (!request.params.http_proxy.empty()) {
		return false;
	}
	return true;
}

bool HTTPFSCurlUtil::ConnectionCachingEnabled() const {
	return connection_caching_enabled.load();
}

unique_ptr<HTTPClient> HTTPFSCurlUtil::FindCachedClient(const string &base_url) {
	if (!ConnectionCachingEnabled()) {
		return nullptr;
	}
	auto client = connection_cache.Find(base_url);
	if (!ConnectionCachingEnabled()) {
		client.reset();
	}
	return client;
}

void HTTPFSCurlUtil::StoreCachedClient(unique_ptr<HTTPClient> &&client) {
	if (!ConnectionCachingEnabled()) {
		client.reset();
		return;
	}
	connection_cache.Store(std::move(client));
	if (!ConnectionCachingEnabled()) {
		connection_cache.Clear();
	}
}

void HTTPFSCurlUtil::ClearCachedConnections() {
	connection_cache.Clear();
}

HTTPClientReuseMode HTTPFSCurlUtil::GetClientReuseMode() const {
	return ConnectionCachingEnabled() ? HTTPClientReuseMode::SHARED : HTTPClientReuseMode::SESSION_LOCAL;
}

void HTTPFSCurlUtil::SetConnectionCachingEnabled(bool enabled) {
	connection_caching_enabled.store(enabled);
	if (!enabled) {
		ClearCachedConnections();
	}
}

void HTTPFSCurlUtil::CloseClient(unique_ptr<HTTPClient> &&client) {
	if (!client) {
		return;
	}
	client->Cleanup();
	// TODO: would be nice to log connection_cache_store here, but no logger is available at this call site
	StoreCachedClient(std::move(client));
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::BaseSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	return HTTPUtil::SendRequest(request, client);
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::CachingSendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	bool caller_owns_client = client != nullptr;

	if (!client) {
		auto cached_client = FindCachedClient(request.proto_host_port);
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
		if (r && !r->HasRequestError()) {
			StoreCachedClient(std::move(client));
		} else {
			client.reset();
		}
	}
	return r;
}

unique_ptr<HTTPResponse> HTTPFSCurlUtil::SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &client) {
	if (EnableCaching(request)) {
		return CachingSendRequest(request, client);
	}
	return BaseSendRequest(request, client);
}

} // namespace duckdb
