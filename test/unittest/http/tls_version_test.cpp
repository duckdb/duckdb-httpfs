#include "catch.hpp"

#include "http/httpfs_curl_client.hpp"

namespace duckdb {

// Fails if the curl backend's TLS floor value is removed or lowered below 1.2.
TEST_CASE("Curl TLS floor pins a 1.2 minimum", "[httpfs][tls]") {
	const long sslversion = GetCurlMinTLSVersion();

	// The low 16 bits of a CURLOPT_SSLVERSION value carry the minimum protocol version.
	REQUIRE((sslversion & 0xFFFFL) == CURL_SSLVERSION_TLSv1_2);

#if LIBCURL_VERSION_NUM >= 0x073600
	// The maximum is left at curl's default so TLS 1.3 still negotiates.
	REQUIRE(sslversion == (CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT));
#else
	REQUIRE(sslversion == CURL_SSLVERSION_TLSv1_2);
#endif
}

// Exercises the real constructor so the TLS setopt calls (including the HTTPS-proxy
// floor) must be accepted by the linked libcurl. libcurl exposes no getinfo for
// SSLVERSION, so the configured handle cannot be read back and asserted directly.
TEST_CASE("Curl handle applies the TLS floor without error", "[httpfs][tls]") {
	REQUIRE_NOTHROW(CURLHandle(false));
	REQUIRE_NOTHROW(CURLHandle(true));
}

} // namespace duckdb
