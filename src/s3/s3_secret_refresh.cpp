#include "s3/s3_secret_refresh.hpp"

#include "s3/s3_provider.hpp"

#include "duckdb/common/types/hash.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

unique_ptr<const BaseSecret> S3SecretRefreshLineage::TryGetSuccessor(hash_t credentials) {
	if (!latest || credentials == latest_credentials) {
		return nullptr;
	}
	for (auto replaced_credentials : replaced) {
		if (replaced_credentials == credentials) {
			return latest->Clone();
		}
	}
	return nullptr;
}

void S3SecretRefreshLineage::RecordSuccessor(hash_t credentials, const BaseSecret &successor,
                                             hash_t successor_credentials) {
	if (latest && latest_credentials != credentials) {
		// the previous successor is now replaced too, even though nobody refreshed from it
		replaced.push_back(latest_credentials);
	}
	replaced.push_back(credentials);
	while (replaced.size() > MAX_REPLACED) {
		replaced.pop_front();
	}
	latest = successor.Clone();
	latest_credentials = successor_credentials;
}

shared_ptr<S3SecretRefreshState> S3SecretRefreshState::Get(ClientContext &context) {
	auto &cache = ObjectCache::GetObjectCache(context);
	auto state = cache.GetOrCreate<S3SecretRefreshState>(ObjectType());
	if (!state) {
		throw InternalException("Object cache entry '%s' has an unexpected type", ObjectType());
	}
	return state;
}

shared_ptr<S3SecretRefreshLineage> S3SecretRefreshState::GetLineage(const KeyValueSecret &secret,
                                                                      const Value &refresh_info) {
	string key = secret.GetType() + '\0' + secret.GetName() + '\0' + secret.GetProvider().GetIdentifierName();
	for (auto &prefix : secret.GetScope()) {
		key += '\0' + prefix;
	}
	key += '\0' + refresh_info.ToString();

	annotated_lock_guard<annotated_mutex> guard(lineages_lock);
	auto &lineage = lineages[key];
	if (!lineage) {
		lineage = make_shared_ptr<S3SecretRefreshLineage>();
	}
	return lineage;
}

hash_t S3SecretRefreshState::FingerprintCredentials(const KeyValueSecret &secret) {
	hash_t result = 0;
	for (const auto key : S3SecretConfig::CredentialMaterialKeys()) {
		Value value;
		auto value_hash = secret.TryGetValue(key, value) ? Hash(value.ToString().c_str()) : hash_t(0);
		result = CombineHash(result, CombineHash(Hash(key), value_hash));
	}
	return result;
}

} // namespace duckdb
