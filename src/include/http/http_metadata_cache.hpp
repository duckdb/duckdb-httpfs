#pragma once

#include "duckdb/common/atomic.hpp"
#include "duckdb/common/chrono.hpp"
#include "duckdb/common/list.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"

#include <stddef.h>
#include <string>

namespace duckdb {

struct HTTPMetadataCacheEntry {
	idx_t length;
	timestamp_t last_modified;
	string etag;
	string version_id;
	unordered_map<string, string> properties;
};

enum class HTTPMetadataCacheMode : uint8_t { GLOBAL, QUERY_LOCAL };

//! Simple cache with a max age for an entry to be valid
class HTTPMetadataCache : public ClientContextState {
public:
	explicit HTTPMetadataCache(HTTPMetadataCacheMode mode_p) : mode(mode_p) {
	}

public:
	void Insert(const string &path, HTTPMetadataCacheEntry val) DUCKDB_EXCLUDES(lock) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		map[path] = std::move(val);
	}

	void Erase(const string &path) DUCKDB_EXCLUDES(lock) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		map.erase(path);
	}

	bool Find(const string &path, HTTPMetadataCacheEntry &ret_val) const DUCKDB_EXCLUDES(lock) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		auto lookup = map.find(path);
		if (lookup == map.end()) {
			return false;
		}
		ret_val = lookup->second;
		return true;
	}

	void Clear() DUCKDB_EXCLUDES(lock) {
		annotated_lock_guard<annotated_mutex> guard(lock);
		map.clear();
	}

	//! Called by the ClientContext when the current query ends
	void QueryEnd(ClientContext &context) override {
		if (mode == HTTPMetadataCacheMode::QUERY_LOCAL) {
			Clear();
		}
	}

private:
	//! Cache policy
	const HTTPMetadataCacheMode mode;

	//! Cached metadata
	mutable annotated_mutex lock;
	unordered_map<string, HTTPMetadataCacheEntry> map DUCKDB_GUARDED_BY(lock);
};

} // namespace duckdb
