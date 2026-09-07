#include "crypto.hpp"
#include "duckdb/storage/storage_info.hpp"

#include "duckdb/common/common.hpp"
#include "duckdb/common/exception.hpp"

#include <iostream>
#include <mutex>
#include <stdio.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "re2/re2.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#if defined(_WIN32) && defined(OPENSSL_USE_APPLINK)
#include <openssl/applink.c>
#endif

using CipherType = duckdb::EncryptionTypes::CipherType;
using EncryptionVersion = duckdb::EncryptionTypes::EncryptionVersion;
using MainHeader = duckdb::MainHeader;
using Mode = duckdb::EncryptionTypes::Mode;

static const EVP_MD *GetOpenSSLHashFunction(duckdb::CryptoHashFunction function) {
	switch (function) {
	case duckdb::CryptoHashFunction::MD5:
		return EVP_md5();
	case duckdb::CryptoHashFunction::SHA1:
		return EVP_sha1();
	case duckdb::CryptoHashFunction::SHA256:
		return EVP_sha256();
	default:
		throw duckdb::InternalException("Unsupported crypto hash function");
	}
}

static void CheckOpenSSLHashLength(duckdb::CryptoHashFunction function, unsigned int actual_size) {
	if (actual_size != duckdb::CryptoHash::GetDigestSize(function)) {
		throw duckdb::InternalException("OpenSSL returned an unexpected hash length");
	}
}

class OpenSSLCryptoHashState : public duckdb::CryptoHashState {
public:
	explicit OpenSSLCryptoHashState(duckdb::CryptoHashFunction function)
	    : duckdb::CryptoHashState(function), context(EVP_MD_CTX_new()) {
		if (!context) {
			throw duckdb::InternalException("OpenSSL failed with initializing hash context");
		}
		auto message_digest = GetOpenSSLHashFunction(function);
		if (!EVP_DigestInit_ex(context, message_digest, nullptr)) {
			throw duckdb::InternalException("OpenSSL failed to initialize hash");
		}
	}

	~OpenSSLCryptoHashState() override {
		EVP_MD_CTX_free(context);
	}

public:
	void Hash(duckdb::const_data_ptr_t input, duckdb::idx_t input_len, duckdb::data_ptr_t output) override {
		unsigned int output_size = 0;
		if (!EVP_DigestInit_ex(context, nullptr, nullptr)) {
			throw duckdb::InternalException("OpenSSL failed to initialize hash");
		}
		if (!EVP_DigestUpdate(context, input, input_len)) {
			throw duckdb::InternalException("OpenSSL failed to update hash");
		}
		if (!EVP_DigestFinal_ex(context, output, &output_size)) {
			throw duckdb::InternalException("OpenSSL failed to finalize hash");
		}
		CheckOpenSSLHashLength(GetFunction(), output_size);
	}

private:
	EVP_MD_CTX *context;
};

namespace duckdb {

AESStateSSL::AESStateSSL(unique_ptr<EncryptionStateMetadata> metadata)
    : EncryptionState(std::move(metadata)), context(EVP_CIPHER_CTX_new()) {
	if (!(context)) {
		throw InternalException("OpenSSL AES failed with initializing context");
	}
}

AESStateSSL::~AESStateSSL() {
	// Clean up
	EVP_CIPHER_CTX_free(context);
}

const EVP_CIPHER *AESStateSSL::GetCipher() {
	switch (metadata->GetCipher()) {
	case EncryptionTypes::GCM: {
		switch (metadata->GetKeyLen()) {
		case 16:
			return EVP_aes_128_gcm();
		case 24:
			return EVP_aes_192_gcm();
		case 32:
			return EVP_aes_256_gcm();
		default:
			throw InternalException("Invalid AES key length for GCM");
		}
	}
	case EncryptionTypes::CTR: {
		switch (metadata->GetKeyLen()) {
		case 16:
			return EVP_aes_128_ctr();
		case 24:
			return EVP_aes_192_ctr();
		case 32:
			return EVP_aes_256_ctr();
		default:
			throw InternalException("Invalid AES key length for CTR");
		}
	}
	case EncryptionTypes::CBC: {
		switch (metadata->GetKeyLen()) {
		case 16:
			return EVP_aes_128_cbc();
		case 24:
			return EVP_aes_192_cbc();
		case 32:
			return EVP_aes_256_cbc();
		default:
			throw InternalException("Invalid AES key length for CBC");
		}
	}
	default:
		throw InternalException("Invalid Encryption/Decryption Cipher: %d", static_cast<int>(metadata->GetCipher()));
	}
}

void AESStateSSL::GenerateRandomData(data_ptr_t data, idx_t len) {
	auto res = RAND_bytes(data, NumericCast<int>(len));
	if (res != 1) {
		throw duckdb::InternalException("Failed to generate random data from RAND_bytes");
	}
}

void AESStateSSL::InitializeIVEncrypt(EncryptionNonce &nonce, const_data_ptr_t key) {
	if (1 != EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NumericCast<int>(nonce.total_size()), nullptr)) {
		throw InternalException("EVP_CIPHER_CTX_ctrl failed (EVP_CTRL_GCM_SET_IVLEN)");
	}

	if (1 != EVP_EncryptInit_ex(context, nullptr, nullptr, key, nonce.data())) {
		throw InternalException("EncryptInit failed (attempt 2)");
	}
}

void AESStateSSL::InitializeIVDecrypt(EncryptionNonce &nonce, const_data_ptr_t key) {
	if (1 != EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NumericCast<int>(nonce.total_size()), nullptr)) {
		throw InternalException("EVP_CIPHER_CTX_ctrl failed to set GCM iv len");
	}
	if (1 != EVP_DecryptInit_ex(context, nullptr, nullptr, key, nonce.data())) {
		throw InternalException("EVP_DecryptInit_ex failed to set iv/key");
	}
}

void AESStateSSL::InitializeEncryption(EncryptionNonce &nonce, const_data_ptr_t key, const_data_ptr_t aad,
                                       idx_t aad_len) {
	mode = EncryptionTypes::ENCRYPT;

	if (1 != EVP_EncryptInit_ex(context, GetCipher(), nullptr, nullptr, nullptr)) {
		throw InternalException("EncryptInit failed (attempt 1)");
	}

	InitializeIVEncrypt(nonce, key);

	int len;
	if (aad_len > 0) {
		if (!EVP_DecryptUpdate(context, nullptr, &len, aad, NumericCast<int>(aad_len))) {
			throw InternalException("Setting Additional Authenticated Data  failed");
		}
	}
}

void AESStateSSL::InitializeDecryption(EncryptionNonce &nonce, const_data_ptr_t key, const_data_ptr_t aad,
                                       idx_t aad_len) {
	mode = EncryptionTypes::DECRYPT;

	if (1 != EVP_DecryptInit_ex(context, GetCipher(), nullptr, nullptr, nullptr)) {
		throw InternalException("EVP_DecryptInit_ex failed to set cipher");
	}

	InitializeIVDecrypt(nonce, key);

	int len;
	if (aad_len > 0) {
		if (!EVP_DecryptUpdate(context, nullptr, &len, aad, NumericCast<int>(aad_len))) {
			throw InternalException("Setting Additional Authenticated Data  failed");
		}
	}
}

size_t AESStateSSL::Process(const_data_ptr_t in, idx_t in_len, data_ptr_t out, idx_t out_len) {
	int output_length;
	switch (mode) {
	case EncryptionTypes::ENCRYPT:
		if (1 != EVP_EncryptUpdate(context, out, &output_length, in, NumericCast<int>(in_len))) {
			throw InternalException("EncryptUpdate failed");
		}
		break;

	case EncryptionTypes::DECRYPT:
		if (1 != EVP_DecryptUpdate(context, out, &output_length, in, NumericCast<int>(in_len))) {
			throw InternalException("DecryptUpdate failed");
		}
		break;
	}

	const auto result_length = NumericCast<idx_t>(output_length);
	if (result_length > out_len || result_length != in_len) {
		throw InternalException("AES GCM failed, in- and output lengths differ");
	}
	return result_length;
}

size_t AESStateSSL::FinalizeGCM(data_ptr_t out, idx_t out_len, data_ptr_t tag, idx_t tag_len) {
	auto text_len = out_len;

	switch (mode) {
	case EncryptionTypes::ENCRYPT: {
		int output_length;
		if (1 != EVP_EncryptFinal_ex(context, out + out_len, &output_length)) {
			throw InternalException("EncryptFinal failed");
		}
		text_len += NumericCast<idx_t>(output_length);

		// The computed tag is written at the end of a chunk
		if (1 != EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, NumericCast<int>(tag_len), tag)) {
			throw InternalException("Calculating the tag failed");
		}
		return text_len;
	}
	case EncryptionTypes::DECRYPT: {
		// Set expected tag value
		if (!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, NumericCast<int>(tag_len), tag)) {
			throw InternalException("Finalizing tag failed");
		}

		// EVP_DecryptFinal() will return an error code if final block is not correctly formatted.
		int output_length;
		int ret = EVP_DecryptFinal_ex(context, out + out_len, &output_length);
		text_len += NumericCast<idx_t>(output_length);

		if (ret > 0) {
			// success
			return text_len;
		}
		throw InvalidInputException("Computed AES tag differs from read AES tag, are you using the right key?");
	}
	default:
		throw InternalException("Unhandled encryption mode %d", static_cast<int>(mode));
	}
}

size_t AESStateSSL::Finalize(data_ptr_t out, idx_t out_len, data_ptr_t tag, idx_t tag_len) {

	if (metadata->GetCipher() == EncryptionTypes::GCM) {
		return FinalizeGCM(out, out_len, tag, tag_len);
	}

	auto text_len = out_len;
	switch (mode) {

	case EncryptionTypes::ENCRYPT: {
		int output_length;
		if (1 != EVP_EncryptFinal_ex(context, out + out_len, &output_length)) {
			throw InternalException("EncryptFinal failed");
		}
		return text_len + NumericCast<idx_t>(output_length);
	}

	case EncryptionTypes::DECRYPT: {
		// EVP_DecryptFinal() will return an error code if final block is not correctly formatted.
		int output_length;
		int ret = EVP_DecryptFinal_ex(context, out + out_len, &output_length);
		text_len += NumericCast<idx_t>(output_length);
		if (ret > 0) {
			// success
			return text_len;
		}

		throw InvalidInputException("Computed AES tag differs from read AES tag, are you using the right key?");
	}
	default:
		throw InternalException("Unhandled encryption mode %d", static_cast<int>(mode));
	}
}

} // namespace duckdb

AESStateSSLFactory::AESStateSSLFactory() {
	static std::once_flag rand_init;
	std::call_once(rand_init, []() {
		// Force OpenSSL's DRBG to initialize single-threadedly. In OpenSSL 3.0/3.1,
		// the first RAND_bytes call lazily initializes internal provider state via ossl_ht.
		// Concurrent first calls (e.g. parallel ATTACH) race on that hash table.
		unsigned char dummy;
		RAND_bytes(&dummy, 1);
	});
}

duckdb::shared_ptr<duckdb::EncryptionState>
AESStateSSLFactory::CreateEncryptionState(duckdb::unique_ptr<duckdb::EncryptionStateMetadata> metadata) const {
	return duckdb::make_shared_ptr<duckdb::AESStateSSL>(std::move(metadata));
}

duckdb::unique_ptr<duckdb::CryptoHashState>
AESStateSSLFactory::CreateHashState(duckdb::CryptoHashFunction function) const {
	return duckdb::make_uniq<OpenSSLCryptoHashState>(function);
}

void AESStateSSLFactory::Hash(duckdb::CryptoHashFunction function, duckdb::const_data_ptr_t input,
                              duckdb::idx_t input_len, duckdb::data_ptr_t output) const {
	unsigned int output_size = 0;
	if (!EVP_Digest(input, input_len, output, &output_size, GetOpenSSLHashFunction(function), nullptr)) {
		throw duckdb::InternalException("OpenSSL failed to compute hash");
	}
	CheckOpenSSLHashLength(function, output_size);
}

void AESStateSSLFactory::Hmac(duckdb::CryptoHashFunction function, duckdb::const_data_ptr_t key, duckdb::idx_t key_len,
                              duckdb::const_data_ptr_t input, duckdb::idx_t input_len,
                              duckdb::data_ptr_t output) const {
	if (function != duckdb::CryptoHashFunction::SHA256) {
		throw duckdb::NotImplementedException("OpenSSL HMAC currently only supports SHA256");
	}
	if (key_len > duckdb::NumericLimits<int>::Maximum()) {
		throw duckdb::InvalidInputException("HMAC key length exceeds OpenSSL limit");
	}

	unsigned int output_size = 0;
	if (!HMAC(GetOpenSSLHashFunction(function), key, duckdb::NumericCast<int>(key_len), input, input_len, output,
	          &output_size)) {
		throw duckdb::InternalException("OpenSSL failed to compute HMAC");
	}
	CheckOpenSSLHashLength(function, output_size);
}

bool AESStateSSLFactory::SupportsHash(duckdb::CryptoHashFunction function) const {
	switch (function) {
	case duckdb::CryptoHashFunction::MD5:
	case duckdb::CryptoHashFunction::SHA1:
	case duckdb::CryptoHashFunction::SHA256:
		return true;
	default:
		return false;
	}
}

bool AESStateSSLFactory::SupportsHmac(duckdb::CryptoHashFunction function) const {
	return function == duckdb::CryptoHashFunction::SHA256;
}

AESStateSSLFactory::~AESStateSSLFactory() {
}

extern "C" {

// Call the member function through the factory object
DUCKDB_EXTENSION_API AESStateSSLFactory *CreateSSLFactory() {
	return new AESStateSSLFactory();
}
}
