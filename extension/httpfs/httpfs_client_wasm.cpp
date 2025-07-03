#include "httpfs_client.hpp"
#include "http_state.hpp"

namespace duckdb {

unique_ptr<HTTPClient> HTTPFSUtil::InitializeClient(HTTPParams &http_params, const string &proto_host_port) {
	throw InternalException("HTTPFSUtil::InitializeClient is not expected to be called");
}

unordered_map<string, string> HTTPFSUtil::ParseGetParameters(const string &text) {
	unordered_map<string, string> result;
	// TODO: HTTPFSUtil::ParseGetParameters is currently not implemented
	return result;
}

} // namespace duckdb
