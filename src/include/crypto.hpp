#pragma once

#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/helper.hpp"

#include <stddef.h>
#include <string>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

namespace duckdb {

typedef unsigned char hash_bytes[32];
typedef unsigned char hash_str[64];

void sha256(const char *in, size_t in_len, hash_bytes &out);

void hmac256(const std::string &message, const char *secret, size_t secret_len, hash_bytes &out);

void hmac256(std::string message, hash_bytes secret, hash_bytes &out);

void hex256(hash_bytes &in, hash_str &out);

class DUCKDB_EXTENSION_API AESStateSSL : public EncryptionState {

public:
	explicit AESStateSSL(EncryptionTypes::CipherType cipher_p, idx_t key_len_p);
	~AESStateSSL() override;

public:
	void InitializeEncryption(const_data_ptr_t iv, idx_t iv_len, const_data_ptr_t key, idx_t key_len, const_data_ptr_t aad, idx_t aad_len) override;
	void InitializeDecryption(const_data_ptr_t iv, idx_t iv_len, const_data_ptr_t key, idx_t key_len, const_data_ptr_t aad, idx_t aad_len) override;
	size_t Process(const_data_ptr_t in, idx_t in_len, data_ptr_t out, idx_t out_len) override;
	size_t Finalize(data_ptr_t out, idx_t out_len, data_ptr_t tag, idx_t tag_len) override;
	void GenerateRandomData(data_ptr_t data, idx_t len) override;

	const EVP_CIPHER *GetCipher(idx_t key_len);
	size_t FinalizeGCM(data_ptr_t out, idx_t out_len, data_ptr_t tag, idx_t tag_len);

private:
	EVP_CIPHER_CTX *context;
	EncryptionTypes::Mode mode;
};

} // namespace duckdb

extern "C" {

class DUCKDB_EXTENSION_API AESStateSSLFactory : public duckdb::EncryptionUtil {
public:
	explicit AESStateSSLFactory() {
	}

	duckdb::shared_ptr<duckdb::EncryptionState> CreateEncryptionState(duckdb::EncryptionTypes::CipherType cipher_p, duckdb::idx_t key_len_p) const override {
		return duckdb::make_shared_ptr<duckdb::AESStateSSL>(cipher_p, key_len_p);
	}

	~AESStateSSLFactory() override {
	}
};
}
