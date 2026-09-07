#pragma once

#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/encryption_functions.hpp"
#include "duckdb/common/helper.hpp"

#include <openssl/rand.h>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

namespace duckdb {

class DUCKDB_EXTENSION_API AESStateSSL : public EncryptionState {

public:
	explicit AESStateSSL(unique_ptr<EncryptionStateMetadata> metadata);
	~AESStateSSL() override;

public:
	void InitializeEncryption(EncryptionNonce &nonce, const_data_ptr_t key, const_data_ptr_t aad,
	                          idx_t aad_len) override;
	void InitializeDecryption(EncryptionNonce &nonce, const_data_ptr_t key, const_data_ptr_t aad,
	                          idx_t aad_len) override;
	size_t Process(const_data_ptr_t in, idx_t in_len, data_ptr_t out, idx_t out_len) override;
	size_t Finalize(data_ptr_t out, idx_t out_len, data_ptr_t tag, idx_t tag_len) override;
	void GenerateRandomData(data_ptr_t data, idx_t len) override;

	const EVP_CIPHER *GetCipher();
	size_t FinalizeGCM(data_ptr_t out, idx_t out_len, data_ptr_t tag, idx_t tag_len);
	void InitializeIVEncrypt(EncryptionNonce &nonce, const_data_ptr_t key);
	void InitializeIVDecrypt(EncryptionNonce &nonce, const_data_ptr_t key);

private:
	EVP_CIPHER_CTX *context;
	EncryptionTypes::Mode mode;
};

} // namespace duckdb

extern "C" {

class DUCKDB_EXTENSION_API AESStateSSLFactory : public duckdb::EncryptionUtil {
public:
	explicit AESStateSSLFactory();
	~AESStateSSLFactory() override;

public:
	duckdb::shared_ptr<duckdb::EncryptionState>
	CreateEncryptionState(duckdb::unique_ptr<duckdb::EncryptionStateMetadata> metadata) const override;
	duckdb::unique_ptr<duckdb::CryptoHashState> CreateHashState(duckdb::CryptoHashFunction function) const override;
	void Hash(duckdb::CryptoHashFunction function, duckdb::const_data_ptr_t input, duckdb::idx_t input_len,
	          duckdb::data_ptr_t output) const override;
	void Hmac(duckdb::CryptoHashFunction function, duckdb::const_data_ptr_t key, duckdb::idx_t key_len,
	          duckdb::const_data_ptr_t input, duckdb::idx_t input_len, duckdb::data_ptr_t output) const override;
	bool SupportsHash(duckdb::CryptoHashFunction function) const override;
	bool SupportsHmac(duckdb::CryptoHashFunction function) const override;
};
}
