#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/httpfs_curl_client.hpp"
#include "http/curl_certificate_store_cache.hpp"
#include "test_helpers.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <thread>
#include <cstdlib>

namespace duckdb {

struct CurlCertificateStoreTestHelper {
	static void SetCache(HTTPFSCurlUtil &util, shared_ptr<CurlCertificateStoreCache> cache) {
		util.certificate_store_cache = std::move(cache);
	}
};

namespace {

class ScopedProxyEnvironment {
public:
	ScopedProxyEnvironment() {
		for (auto name : {"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ftp_proxy", "FTP_PROXY",
		                  "ftps_proxy", "FTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"}) {
			auto value = std::getenv(name);
			original.push_back({name, value ? value : "", value != nullptr});
		}
		for (auto &entry : original) {
			Set(entry.name, nullptr);
		}
	}
	~ScopedProxyEnvironment() {
		for (auto &entry : original) {
			Set(entry.name, entry.present ? entry.value.c_str() : nullptr);
		}
	}

public:
	static void Set(const string &name, const char *value) {
#ifdef _WIN32
		_putenv_s(name.c_str(), value ? value : "");
#else
		if (value) {
			setenv(name.c_str(), value, 1);
		} else {
			unsetenv(name.c_str());
		}
#endif
	}

private:
	struct Variable {
		string name;
		string value;
		bool present;
	};
	vector<Variable> original;
};

using TestPrivateKey = unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using TestCertificate = unique_ptr<X509, decltype(&X509_free)>;

static TestPrivateKey GenerateTestPrivateKey() {
	unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
	                                                               EVP_PKEY_CTX_free);
	if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0) {
		throw InternalException("Failed to initialize test certificate key generation");
	}
	EVP_PKEY *key = nullptr;
	if (EVP_PKEY_keygen(context.get(), &key) <= 0) {
		throw InternalException("Failed to generate test certificate key");
	}
	return TestPrivateKey(key, EVP_PKEY_free);
}

static void AddTestCertificateExtension(X509 &certificate, X509 &issuer, int nid, const char *value) {
	string extension_value(value);
	X509V3_CTX context;
	X509V3_set_ctx(&context, &issuer, &certificate, nullptr, nullptr, 0);
	unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
	    X509V3_EXT_conf_nid(nullptr, &context, nid, &extension_value[0]), X509_EXTENSION_free);
	if (!extension || !X509_add_ext(&certificate, extension.get(), -1)) {
		throw InternalException("Failed to add test certificate extension");
	}
}

static TestCertificate GenerateTestCertificate(EVP_PKEY &key, optional_ptr<X509> issuer, EVP_PKEY &issuer_key,
                                               idx_t serial, bool is_ca, bool expired = false) {
	TestCertificate certificate(X509_new(), X509_free);
	if (!certificate || !X509_set_version(certificate.get(), 2) ||
	    !ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), NumericCast<long>(serial)) ||
	    !X509_gmtime_adj(X509_get_notBefore(certificate.get()), -120) ||
	    !X509_gmtime_adj(X509_get_notAfter(certificate.get()), expired ? -60 : 60 * 60) ||
	    !X509_set_pubkey(certificate.get(), &key)) {
		throw InternalException("Failed to initialize test certificate");
	}
	auto subject = X509_get_subject_name(certificate.get());
	auto common_name = is_ca ? "HTTPFS Test CA" : "localhost";
	if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, const_uchar_ptr_cast(common_name), -1, -1, 0) ||
	    !X509_set_issuer_name(certificate.get(), issuer ? X509_get_subject_name(issuer.get()) : subject)) {
		throw InternalException("Failed to name test certificate");
	}
	auto issuer_certificate = issuer ? issuer.get() : certificate.get();
	AddTestCertificateExtension(*certificate, *issuer_certificate, NID_basic_constraints,
	                            is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
	AddTestCertificateExtension(*certificate, *issuer_certificate, NID_key_usage,
	                            is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment");
	if (!is_ca) {
		AddTestCertificateExtension(*certificate, *issuer_certificate, NID_subject_alt_name, "DNS:localhost");
	}
	if (!X509_sign(certificate.get(), &issuer_key, EVP_sha256())) {
		throw InternalException("Failed to sign test certificate");
	}
	return certificate;
}

class CurlTLSTestServer {
public:
	explicit CurlTLSTestServer(const string &name = "httpfs-curl-ca-cache", bool expired = false)
	    : ca_key(GenerateTestPrivateKey()), server_key(GenerateTestPrivateKey()),
	      ca_certificate(GenerateTestCertificate(*ca_key, nullptr, *ca_key, 1, true)),
	      server_certificate(GenerateTestCertificate(*server_key, ca_certificate.get(), *ca_key, 2, false, expired)),
	      ca_path(TestCreatePath(name + ".pem")),
	      server(make_uniq<duckdb_httplib_openssl::SSLServer>([this](duckdb_httplib_openssl::tls::ctx_t context) {
		      auto ssl_context = static_cast<SSL_CTX *>(context);
		      return SSL_CTX_use_certificate(ssl_context, server_certificate.get()) == 1 &&
		             SSL_CTX_use_PrivateKey(ssl_context, server_key.get()) == 1;
	      })) {
		WriteCAFile(ca_path);
		server->Get("/object",
		            [](const duckdb_httplib_openssl::Request &request, duckdb_httplib_openssl::Response &response) {
			            if (request.get_header_value("Range") == "bytes=0-1") {
				            response.status = 206;
				            response.set_header("Content-Range", "bytes 0-1/2");
				            response.set_content("ab", "application/octet-stream");
				            return;
			            }
			            response.set_content("ab", "application/octet-stream");
		            });
		port = server->bind_to_any_port("127.0.0.1");
		if (port <= 0) {
			throw InternalException("Failed to bind test HTTPS server");
		}
		server_thread = std::thread([this]() { server->listen_after_bind(); });
		server->wait_until_ready();
	}

	~CurlTLSTestServer() {
		server->stop();
		if (server_thread.joinable()) {
			server_thread.join();
		}
		TestDeleteFile(ca_path);
	}

	string URL(const string &host = "localhost") const {
		return StringUtil::Format("https://%s:%d/object", host, port);
	}

	const string &CAPath() const {
		return ca_path;
	}

	void WriteCAFile(const string &path) const {
		TestCreateDirectory(TestDirectoryPath());
		unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new_file(path.c_str(), "w"), BIO_free);
		if (!output || !PEM_write_bio_X509(output.get(), ca_certificate.get())) {
			throw InternalException("Failed to write test CA certificate");
		}
	}

private:
	TestPrivateKey ca_key;
	TestPrivateKey server_key;
	TestCertificate ca_certificate;
	TestCertificate server_certificate;
	string ca_path;
	unique_ptr<duckdb_httplib_openssl::SSLServer> server;
	int port = 0;
	std::thread server_thread;
};

static size_t DiscardCurlBody(void *, size_t size, size_t count, void *) {
	return size * count;
}

static CURLcode LoadTestCertificateStore(const string &path, X509_STORE *&result) {
	result = X509_STORE_new();
	if (!result) {
		return CURLE_OUT_OF_MEMORY;
	}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (X509_STORE_load_file(result, path.c_str())) {
#else
	if (X509_STORE_load_locations(result, path.c_str(), nullptr)) {
#endif
		return CURLE_OK;
	}
	X509_STORE_free(result);
	result = nullptr;
	return CURLE_SSL_CACERT_BADFILE;
}

} // namespace

TEST_CASE("Curl certificate stores are shared across concurrent handles", "[httpfs][curl][certificate-store]") {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	CurlCertificateStoreCache::FileIdentity identity;
	identity.size = 42;
	atomic<idx_t> load_count {0};
	CurlCertificateStoreCache cache(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    result = identity;
		    return true;
	    },
	    [&](const string &, X509_STORE *&result) {
		    load_count++;
		    result = X509_STORE_new();
		    return result ? CURLE_OK : CURLE_OUT_OF_MEMORY;
	    },
	    []() { return 0; });

	static constexpr idx_t THREAD_COUNT = 16;
	vector<X509_STORE *> stores(THREAD_COUNT, nullptr);
	vector<CURLcode> results(THREAD_COUNT, CURLE_FAILED_INIT);
	vector<std::thread> threads;
	for (idx_t thread_idx = 0; thread_idx < THREAD_COUNT; thread_idx++) {
		threads.emplace_back([&, thread_idx]() { results[thread_idx] = cache.Acquire("ca.pem", stores[thread_idx]); });
	}
	for (auto &thread : threads) {
		thread.join();
	}

	REQUIRE(load_count == 1);
	for (idx_t thread_idx = 0; thread_idx < THREAD_COUNT; thread_idx++) {
		REQUIRE(results[thread_idx] == CURLE_OK);
		REQUIRE(stores[thread_idx] == stores[0]);
		X509_STORE_free(stores[thread_idx]);
	}
#endif
}

TEST_CASE("Curl certificate stores reload after changes and expiry", "[httpfs][curl][certificate-store]") {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	CurlCertificateStoreCache::FileIdentity identity;
	identity.size = 42;
	idx_t now = 0;
	idx_t load_count = 0;
	bool fail_load = false;
	bool metadata_available = true;
	CurlCertificateStoreCache cache(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    if (!metadata_available) {
			    return false;
		    }
		    result = identity;
		    return true;
	    },
	    [&](const string &, X509_STORE *&result) {
		    load_count++;
		    if (fail_load) {
			    return CURLE_SSL_CACERT_BADFILE;
		    }
		    result = X509_STORE_new();
		    return result ? CURLE_OK : CURLE_OUT_OF_MEMORY;
	    },
	    [&]() { return NumericCast<int64_t>(now); }, 10);

	X509_STORE *first = nullptr;
	REQUIRE(cache.Acquire("ca.pem", first) == CURLE_OK);
	X509_STORE *cached = nullptr;
	REQUIRE(cache.Acquire("ca.pem", cached) == CURLE_OK);
	REQUIRE(first == cached);
	REQUIRE(load_count == 1);

	identity.size++;
	X509_STORE *changed = nullptr;
	REQUIRE(cache.Acquire("ca.pem", changed) == CURLE_OK);
	REQUIRE(changed != first);
	REQUIRE(load_count == 2);

	now = 10;
	fail_load = true;
	X509_STORE *failed = nullptr;
	REQUIRE(cache.Acquire("ca.pem", failed) == CURLE_SSL_CACERT_BADFILE);
	REQUIRE(failed == nullptr);
	REQUIRE(load_count == 3);

	fail_load = false;
	X509_STORE *refreshed = nullptr;
	REQUIRE(cache.Acquire("ca.pem", refreshed) == CURLE_OK);
	REQUIRE(refreshed != changed);
	REQUIRE(load_count == 4);
	metadata_available = false;
	X509_STORE *missing = nullptr;
	REQUIRE(cache.Acquire("ca.pem", missing) == CURLE_SSL_CACERT_BADFILE);
	REQUIRE(missing == nullptr);
	REQUIRE(load_count == 4);
	metadata_available = true;

	X509_STORE *other_path = nullptr;
	REQUIRE(cache.Acquire("other-ca.pem", other_path) == CURLE_OK);
	REQUIRE(load_count == 5);

	X509_STORE_free(first);
	X509_STORE_free(cached);
	X509_STORE_free(changed);
	X509_STORE_free(refreshed);
	X509_STORE_free(other_path);
#endif
}

TEST_CASE("Parallel HTTPS range requests share the Curl certificate store", "[httpfs][curl][certificate-store]") {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	REQUIRE(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
	CURLHandle probe("", "", false);
	if (!CurlCertificateStoreCache::IsSupported(probe)) {
		SUCCEED("Curl does not use the compatible OpenSSL backend");
		return;
	}
	CurlTLSTestServer server;
	CurlCertificateStoreCache::FileIdentity identity;
	identity.size = 42;
	atomic<idx_t> load_count {0};
	auto cache = make_shared_ptr<CurlCertificateStoreCache>(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    result = identity;
		    return true;
	    },
	    [&](const string &path, X509_STORE *&result) {
		    load_count++;
		    return LoadTestCertificateStore(path, result);
	    },
	    []() { return 0; });

	static constexpr idx_t THREAD_COUNT = 8;
	vector<CURLcode> results(THREAD_COUNT, CURLE_FAILED_INIT);
	vector<std::thread> threads;
	for (idx_t thread_idx = 0; thread_idx < THREAD_COUNT; thread_idx++) {
		threads.emplace_back([&, thread_idx]() {
			try {
				CURLHandle handle("", server.CAPath(), false, cache);
				handle.SetVerifySSL(true);
				auto url = server.URL();
				handle.SetOption(CURLOPT_URL, url.c_str());
				handle.SetOption(CURLOPT_RANGE, "0-1");
				handle.SetOption(CURLOPT_NOSIGNAL, 1L);
				handle.SetOption(CURLOPT_WRITEFUNCTION, DiscardCurlBody);
				results[thread_idx] = handle.Execute();
			} catch (...) {
				results[thread_idx] = CURLE_FAILED_INIT;
			}
		});
	}
	for (auto &thread : threads) {
		thread.join();
	}
	for (auto result : results) {
		REQUIRE(result == CURLE_OK);
	}
	REQUIRE(load_count == 1);

	atomic<idx_t> disabled_load_count {0};
	auto disabled_cache = make_shared_ptr<CurlCertificateStoreCache>(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    result = identity;
		    return true;
	    },
	    [&](const string &path, X509_STORE *&result) {
		    disabled_load_count++;
		    return LoadTestCertificateStore(path, result);
	    },
	    []() { return 0; });
	CURLHandle disabled_handle("", server.CAPath(), false, disabled_cache);
	disabled_handle.SetVerifySSL(false);
	CURL *disabled_curl = disabled_handle;
	auto url = server.URL();
	REQUIRE(curl_easy_setopt(disabled_curl, CURLOPT_URL, url.c_str()) == CURLE_OK);
	REQUIRE(curl_easy_setopt(disabled_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody) == CURLE_OK);
	REQUIRE(disabled_handle.Execute() == CURLE_OK);
	REQUIRE(disabled_load_count == 0);

	auto empty_cache = make_shared_ptr<CurlCertificateStoreCache>(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    result = identity;
		    return true;
	    },
	    [&](const string &, X509_STORE *&result) {
		    result = X509_STORE_new();
		    return result ? CURLE_OK : CURLE_OUT_OF_MEMORY;
	    },
	    []() { return 0; });
	CURLHandle untrusted_handle("", server.CAPath(), false, empty_cache);
	untrusted_handle.SetVerifySSL(true);
	CURL *untrusted_curl = untrusted_handle;
	REQUIRE(curl_easy_setopt(untrusted_curl, CURLOPT_URL, url.c_str()) == CURLE_OK);
	REQUIRE(curl_easy_setopt(untrusted_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody) == CURLE_OK);
	REQUIRE(untrusted_handle.Execute() == CURLE_PEER_FAILED_VERIFICATION);

	CURLHandle wrong_host_handle("", server.CAPath(), false, cache);
	wrong_host_handle.SetVerifySSL(true);
	CURL *wrong_host_curl = wrong_host_handle;
	auto wrong_host_url = server.URL("127.0.0.1");
	REQUIRE(curl_easy_setopt(wrong_host_curl, CURLOPT_URL, wrong_host_url.c_str()) == CURLE_OK);
	REQUIRE(curl_easy_setopt(wrong_host_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody) == CURLE_OK);
	REQUIRE(wrong_host_handle.Execute() == CURLE_PEER_FAILED_VERIFICATION);

	CURLHandle fallback_handle("", server.CAPath(), false, nullptr);
	fallback_handle.SetVerifySSL(true);
	CURL *fallback_curl = fallback_handle;
	REQUIRE(curl_easy_setopt(fallback_curl, CURLOPT_URL, url.c_str()) == CURLE_OK);
	REQUIRE(curl_easy_setopt(fallback_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody) == CURLE_OK);
	REQUIRE(fallback_handle.Execute() == CURLE_OK);

	auto failing_cache = make_shared_ptr<CurlCertificateStoreCache>(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    result = identity;
		    return true;
	    },
	    [&](const string &, X509_STORE *&) { return CURLE_SSL_CACERT_BADFILE; }, []() { return 0; });
	CURLHandle failing_handle("", server.CAPath(), false, failing_cache);
	failing_handle.SetVerifySSL(true);
	CURL *failing_curl = failing_handle;
	REQUIRE(curl_easy_setopt(failing_curl, CURLOPT_URL, url.c_str()) == CURLE_OK);
	REQUIRE(curl_easy_setopt(failing_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody) == CURLE_OK);
	REQUIRE(failing_handle.Execute() == CURLE_SSL_CACERT_BADFILE);
#endif
}

TEST_CASE("HTTPFS cached TLS clients preserve trust across reconfiguration", "[httpfs][curl][certificate-store]") {
	CurlTLSTestServer server;
	CurlTLSTestServer other("httpfs-other-ca");
	HTTPFSCurlUtil util;
	HTTPFSParams params(util);
	params.ca_cert_file = server.CAPath();
	params.retries = 0;
	params.timeout = 5;
	params.keep_alive = true;
	const auto url = server.URL();
	const auto origin = url.substr(0, url.rfind('/'));
	auto client = util.InitializeClient(params, origin);
	auto request = [&]() {
		client->Initialize(params);
		GetRequestInfo info(url, HTTPHeaders(), params, nullptr, nullptr);
		return util.Request(info, client);
	};
	REQUIRE(request()->body == "ab");

	SECTION("changing the CA file does not reuse the previously trusted connection") {
		params.ca_cert_file = other.CAPath();
		REQUIRE_THROWS_AS(request(), IOException);
		params.ca_cert_file = server.CAPath();
		REQUIRE(request()->body == "ab");
	}
	SECTION("enabling verification after an unverified request rejects an untrusted server") {
		params.ca_cert_file = other.CAPath();
		params.enable_curl_server_cert_verification = false;
		REQUIRE(request()->body == "ab");
		params.enable_curl_server_cert_verification = true;
		REQUIRE_THROWS_AS(request(), IOException);
	}
	SECTION("a new client observes changed contents at the same CA path") {
		other.WriteCAFile(server.CAPath());
		client.reset();
		client = util.InitializeClient(params, origin);
		REQUIRE_THROWS_AS(request(), IOException);
		server.WriteCAFile(server.CAPath());
		client.reset();
		client = util.InitializeClient(params, origin);
		REQUIRE(request()->body == "ab");
	}
}

TEST_CASE("Curl cached and fallback verification reject expired certificates", "[httpfs][curl][certificate-store]") {
	CurlTLSTestServer server("httpfs-expired-ca", true);
	for (bool use_cache : {false, true}) {
		auto cache = use_cache ? make_shared_ptr<CurlCertificateStoreCache>() : nullptr;
		CURLHandle handle("", server.CAPath(), false, cache);
		handle.SetVerifySSL(true);
		auto url = server.URL();
		handle.SetOption(CURLOPT_URL, url.c_str());
		handle.SetOption(CURLOPT_TIMEOUT, 5L);
		handle.SetOption(CURLOPT_WRITEFUNCTION, DiscardCurlBody);
		REQUIRE(handle.Execute() == CURLE_PEER_FAILED_VERIFICATION);
	}
}

TEST_CASE("Curl environment proxies bypass certificate caching across reinitialization",
          "[httpfs][curl][certificate-store]") {
	ScopedProxyEnvironment environment;
	CURLHandle probe("", "", false);
	if (!CurlCertificateStoreCache::IsSupported(probe)) {
		return;
	}
	CurlTLSTestServer server;
	idx_t acquisitions = 0;
	auto cache = make_shared_ptr<CurlCertificateStoreCache>(
	    [&](const string &, CurlCertificateStoreCache::FileIdentity &result) {
		    acquisitions++;
		    result.size = 42;
		    return true;
	    },
	    LoadTestCertificateStore, []() { return 0; });
	HTTPFSCurlUtil util;
	CurlCertificateStoreTestHelper::SetCache(util, cache);
	HTTPFSParams params(util);
	params.ca_cert_file = server.CAPath();
	params.retries = 0;
	params.timeout = 5;
	params.keep_alive = false;
	const auto url = server.URL();
	auto client = util.InitializeClient(params, url.substr(0, url.rfind('/')));
	auto request = [&]() {
		client->Initialize(params);
		GetRequestInfo info(url, HTTPHeaders(), params, nullptr, nullptr);
		REQUIRE(util.Request(info, client)->body == "ab");
	};
	request();
	REQUIRE(acquisitions == 1);
	// Bypass the proxy on the wire; the configured proxy must still disable our TLS callback.
	ScopedProxyEnvironment::Set("no_proxy", "*");
	for (auto name : {"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ftp_proxy", "FTP_PROXY", "ftps_proxy",
	                  "FTPS_PROXY", "all_proxy", "ALL_PROXY"}) {
		INFO(name);
		auto before = acquisitions;
		ScopedProxyEnvironment::Set(name, "https://127.0.0.1:1");
		request();
		REQUIRE(acquisitions == before);
		ScopedProxyEnvironment::Set(name, nullptr);
		request();
		REQUIRE(acquisitions == before + 1);
	}
}

} // namespace duckdb
