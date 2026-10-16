#include "catch.hpp"

#include <openssl/ssl.h>

TEST_CASE("OpenSSL can create a TLS client context", "[httpfs][openssl]") {
	auto context = SSL_CTX_new(TLS_client_method());
	REQUIRE(context != nullptr);
	SSL_CTX_free(context);
}
