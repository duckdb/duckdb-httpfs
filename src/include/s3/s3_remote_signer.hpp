#pragma once

#include "s3/s3_request.hpp"

namespace duckdb {

//! Signs S3 requests through a remote signing endpoint, following the Iceberg REST catalog remote signing protocol
struct S3RemoteSigner {
	//! Replace the URL and headers of the request with the ones returned by the signer
	static void Sign(S3RequestData &request_data, const string &body);
};

} // namespace duckdb
