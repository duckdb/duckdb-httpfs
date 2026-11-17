#pragma once

#include "duckdb.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/storage/object_cache.hpp"

#include <deque>

namespace duckdb {

class BaseSecret;
class KeyValueSecret;

//! The credentials a REFRESH secret has derived so far, shared by every connection to one database.
//!
//! Why: a refresh publishes its credentials by replacing the secret in the caller's transaction. Another transaction
//! that already holds the expired credentials cannot see that replace (uncommitted, or committed after it started),
//! and its own replace is a catalog write-write conflict (duckdb-httpfs#462). The lineage hands it the credentials the
//! first refresh derived, so it neither re-runs the provider nor touches the catalog.
class S3SecretRefreshLineage {
public:
	//! Held for a whole refresh, so a secret runs its provider once per expiry however many connections hit it
	annotated_mutex refresh_lock;

	//! The newest derived credentials, if `credentials` is a set they already replaced
	unique_ptr<const BaseSecret> TryGetSuccessor(hash_t credentials) DUCKDB_REQUIRES(refresh_lock);
	//! Record that `successor` (fingerprint `successor_credentials`) replaces `credentials`
	void RecordSuccessor(hash_t credentials, const BaseSecret &successor, hash_t successor_credentials)
	    DUCKDB_REQUIRES(refresh_lock);

private:
	//! Older lineage entries are forgotten; a transaction holding one just runs the provider again
	static constexpr idx_t MAX_REPLACED = 32;

	unique_ptr<const BaseSecret> latest DUCKDB_GUARDED_BY(refresh_lock);
	hash_t latest_credentials DUCKDB_GUARDED_BY(refresh_lock) = 0;
	std::deque<hash_t> replaced DUCKDB_GUARDED_BY(refresh_lock);
};

//! Per-database registry of refresh lineages, kept in the (non-evictable part of the) object cache
class S3SecretRefreshState : public ObjectCacheEntry {
public:
	static string ObjectType() {
		return "httpfs_s3_secret_refresh_state";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		// not evictable: forgetting a lineage would let concurrent refreshes conflict again
		return optional_idx();
	}

	static shared_ptr<S3SecretRefreshState> Get(ClientContext &context);

	//! The lineage of a secret: same name, type, provider, scope and refresh recipe
	shared_ptr<S3SecretRefreshLineage> GetLineage(const KeyValueSecret &secret, const Value &refresh_info)
	    DUCKDB_EXCLUDES(lineages_lock);

	//! Fingerprint of the credential material of a secret
	static hash_t FingerprintCredentials(const KeyValueSecret &secret);

private:
	annotated_mutex lineages_lock;
	unordered_map<string, shared_ptr<S3SecretRefreshLineage>> lineages DUCKDB_GUARDED_BY(lineages_lock);
};

} // namespace duckdb
