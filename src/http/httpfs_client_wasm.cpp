#include "http/httpfs_client.hpp"
#include "http/http_state.hpp"

namespace duckdb {

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	throw InternalException("HTTPFSUtil::InitializeClient is not expected to be called");
}

} // namespace duckdb
