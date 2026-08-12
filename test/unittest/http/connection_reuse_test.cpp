#include "catch.hpp"

#include "http/http_test_helper.hpp"
#include "http/httpfs_curl_client.hpp"
#include "test_helpers.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <memory>
#include <thread>

namespace duckdb {

namespace {

using TestPrivateKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using TestCertificate = std::unique_ptr<X509, decltype(&X509_free)>;

static TestPrivateKey GenerateTestPrivateKey() {
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
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
	X509V3_CTX context;
	X509V3_set_ctx(&context, &issuer, &certificate, nullptr, nullptr, 0);
	std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
	    X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char *>(value)), X509_EXTENSION_free);
	if (!extension || !X509_add_ext(&certificate, extension.get(), -1)) {
		throw InternalException("Failed to add test certificate extension");
	}
}

static TestCertificate GenerateTestCertificate(EVP_PKEY &key, optional_ptr<X509> issuer, EVP_PKEY &issuer_key,
                                               idx_t serial, bool is_ca) {
	TestCertificate certificate(X509_new(), X509_free);
	if (!certificate || !X509_set_version(certificate.get(), 2) ||
	    !ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), NumericCast<long>(serial)) ||
	    !X509_gmtime_adj(X509_get_notBefore(certificate.get()), -60) ||
	    !X509_gmtime_adj(X509_get_notAfter(certificate.get()), 60 * 60) || !X509_set_pubkey(certificate.get(), &key)) {
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
		AddTestCertificateExtension(*certificate, *issuer_certificate, NID_subject_alt_name,
		                            "DNS:localhost,IP:127.0.0.1");
	}
	if (!X509_sign(certificate.get(), &issuer_key, EVP_sha256())) {
		throw InternalException("Failed to sign test certificate");
	}
	return certificate;
}

class CurlTLSTestServer {
public:
	CurlTLSTestServer()
	    : ca_key(GenerateTestPrivateKey()), server_key(GenerateTestPrivateKey()),
	      ca_certificate(GenerateTestCertificate(*ca_key, nullptr, *ca_key, 1, true)),
	      server_certificate(GenerateTestCertificate(*server_key, ca_certificate.get(), *ca_key, 2, false)),
	      ca_path(TestCreatePath("httpfs-curl-ca-cache.pem")),
	      server(make_uniq<duckdb_httplib_openssl::SSLServer>(server_certificate.get(), server_key.get(), nullptr)) {
		std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new_file(ca_path.c_str(), "w"), BIO_free);
		if (!output || !PEM_write_bio_X509(output.get(), ca_certificate.get())) {
			throw InternalException("Failed to write test CA certificate");
		}
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

	string URL() const {
		return StringUtil::Format("https://localhost:%d/object", port);
	}

	const string &CAPath() const {
		return ca_path;
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

static void RunCompletedErrorConnectionReuse(const string &client_implementation) {
	MockS3ServerConfig config;
	config.failures.transient_head_failures = 1;
	config.failures.failure_is_request_timeout = false;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	auto handle = fs.OpenFile(server.HTTPPath(), FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	REQUIRE(handle);
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	auto error_ports = HTTPTestHelper::RequestPorts(observations, "HEAD", 400);
	auto success_ports = HTTPTestHelper::RequestPorts(observations, "GET", 206, "bytes=0-1");
	REQUIRE(error_ports.size() == 1);
	REQUIRE(success_ports.size() == 1);
	REQUIRE(error_ports[0] != 0);
	REQUIRE(error_ports[0] == success_ports[0]);
}

static void RunSharedConnectionNotFoundReuse() {
	MockS3ServerConfig config;
	config.failures.head_not_found_requests = 2;
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, "curl", true);

	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	auto &fs = FileSystem::GetFileSystem(*con.context);
	REQUIRE_FALSE(fs.FileExists(server.HTTPPath()));
	REQUIRE_FALSE(fs.FileExists(server.HTTPPath()));
	HTTPTestHelper::RequireQueryOk(con, "COMMIT");

	auto observations = server.Observations();
	INFO(MockS3DescribeObservations(observations));
	auto not_found_ports = HTTPTestHelper::RequestPorts(observations, "HEAD", 404);
	REQUIRE(not_found_ports.size() == 2);
	REQUIRE(not_found_ports[0] != 0);
	REQUIRE(not_found_ports[0] == not_found_ports[1]);
}

} // namespace

TEST_CASE("Curl certificate stores are shared across concurrent handles", "[httpfs][curl][certificate-store]") {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	CurlCertificateStoreCache::FileIdentity identity;
	identity.size = 42;
	std::atomic<idx_t> load_count {0};
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
	if (!CurlCertificateStoreCache::IsSupported()) {
		SUCCEED("Curl does not use the compatible OpenSSL backend");
		return;
	}
	CurlTLSTestServer server;
	CurlCertificateStoreCache::FileIdentity identity;
	identity.size = 42;
	std::atomic<idx_t> load_count {0};
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
			CURLHandle handle("", server.CAPath(), cache);
			handle.SetVerifySSL(true);
			CURL *curl = handle;
			auto url = server.URL();
			CURLRequestHeaders headers;
			headers.Add("Range: bytes=0-1");
			curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.headers);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
			curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody);
			results[thread_idx] = handle.Execute();
		});
	}
	for (auto &thread : threads) {
		thread.join();
	}
	for (auto result : results) {
		REQUIRE(result == CURLE_OK);
	}
	REQUIRE(load_count == 1);

	std::atomic<idx_t> disabled_load_count {0};
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
	CURLHandle disabled_handle("", server.CAPath(), disabled_cache);
	disabled_handle.SetVerifySSL(false);
	CURL *disabled_curl = disabled_handle;
	auto url = server.URL();
	curl_easy_setopt(disabled_curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(disabled_curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(disabled_curl, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(disabled_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody);
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
	CURLHandle untrusted_handle("", server.CAPath(), empty_cache);
	untrusted_handle.SetVerifySSL(true);
	CURL *untrusted_curl = untrusted_handle;
	curl_easy_setopt(untrusted_curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(untrusted_curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(untrusted_curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(untrusted_curl, CURLOPT_WRITEFUNCTION, DiscardCurlBody);
	REQUIRE(untrusted_handle.Execute() == CURLE_PEER_FAILED_VERIFICATION);
#endif
}

TEST_CASE("HTTP request sessions reuse connections after completed errors", "[httpfs][request-session]") {
	SECTION("httplib reuses a session-local connection") {
		RunCompletedErrorConnectionReuse("httplib");
	}
	SECTION("curl reuses a session-local connection") {
		RunCompletedErrorConnectionReuse("curl");
	}
	SECTION("curl reuses a shared connection across missing-file probes") {
		RunSharedConnectionNotFoundReuse();
	}
}

} // namespace duckdb
