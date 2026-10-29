#include "http/httpfs_transport.hpp"

#include "http/httpfs_client.hpp"

#include "duckdb/common/string_util.hpp"

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__)
#include <cerrno>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace duckdb {

void HTTPFSParams::RefreshTransportReuseDomain() {
	http_util.Cast<HTTPFSUtil>().SetTransportReuseDomain(*this);
}

void HTTPFSParams::PrepareTransportReuseDomain() {
	if (GetTransportReuseDomain() == 0) {
		RefreshTransportReuseDomain();
	}
	if (!transport_reuse_config.reuse_domain.IsValid() ||
	    transport_reuse_config.reuse_domain.GetIndex() != GetTransportReuseDomain() ||
	    !transport_reuse_config.Matches(*this)) {
		throw InvalidInputException("HTTP transport parameters changed after their reuse domain was captured");
	}
}

bool HTTPFSParams::CanReuseTransport() const {
	return transport_reusable && transport_reuse_config.reuse_domain.IsValid() &&
	       transport_reuse_config.reuse_domain.GetIndex() == GetTransportReuseDomain() &&
	       transport_reuse_config.Matches(*this);
}

void HTTPFSParams::SetTransportReuseConfig(const HTTPFSConnectionConfig &config, bool transport_reusable_p) {
	transport_reuse_config = config;
	transport_reusable = transport_reusable_p;
	SetTransportReuseDomain(config.reuse_domain.GetIndex());
}

bool HTTPFSParams::VerifyServerCertificate() const {
	return override_verify_ssl ? verify_ssl : http_util.Cast<HTTPFSUtil>().GetDefaultVerifySSL(*this);
}

HTTPFSConnectionConfig HTTPFSConnectionConfig::Create(const HTTPFSParams &params) {
	HTTPFSConnectionConfig result;
	result.transport_config = HTTPTransportConfig(params);
	result.ca_cert_file = params.ca_cert_file;
	result.verify_ssl = params.VerifyServerCertificate();
	return result;
}

bool HTTPFSConnectionConfig::Matches(const HTTPFSParams &params) const {
	return transport_config.Matches(params) && ca_cert_file == params.ca_cert_file &&
	       verify_ssl == params.VerifyServerCertificate();
}

bool HTTPFSConnectionConfig::operator==(const HTTPFSConnectionConfig &other) const {
	return transport_config == other.transport_config && ca_cert_file == other.ca_cert_file &&
	       verify_ssl == other.verify_ssl;
}

void HTTPFSUtil::SetTransportReuseDomain(HTTPFSParams &params) {
	auto config = HTTPFSConnectionConfig::Create(params);
	annotated_lock_guard<annotated_mutex> guard(transport_reuse_lock);
	for (auto &entry : transport_reuse_domains) {
		if (entry == config) {
			params.SetTransportReuseConfig(entry, true);
			return;
		}
	}
	if (next_transport_reuse_domain == DConstants::INVALID_INDEX) {
		throw InternalException("HTTPFS transport reuse domain identifiers exhausted");
	}
	config.reuse_domain = next_transport_reuse_domain++;
	if (transport_reuse_domains.size() == MAX_TRANSPORT_REUSE_DOMAINS) {
		params.SetTransportReuseConfig(config, false);
		return;
	}
	transport_reuse_domains.push_back(std::move(config));
	params.SetTransportReuseConfig(transport_reuse_domains.back(), true);
}

bool HTTPFSUtil::GetDefaultVerifySSL(const HTTPFSParams &params) const {
	return params.enable_server_cert_verification;
}

HTTPTransportReusePolicy HTTPFSUtil::GetTransportReusePolicy() const {
#ifdef __EMSCRIPTEN__
	return HTTPTransportReusePolicy::CLIENT_FREE;
#else
	return HTTPTransportReusePolicy::SESSION_LOCAL;
#endif
}

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__)
static bool IsDescriptorExhaustion(int error) {
	return error == EMFILE || error == ENFILE;
}

//! Whether the process can open another file descriptor right now.
static bool DescriptorsExhausted(int &error) {
	auto fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return false;
	}
	error = errno;
	return IsDescriptorExhaustion(error);
}
#endif

string HTTPFSUtil::DescribeRequestError(const string &client_error, int os_errno) {
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__)
	int error = os_errno;
	if (!IsDescriptorExhaustion(error) && !DescriptorsExhausted(error)) {
		return client_error;
	}
	string limit;
	struct rlimit rlim;
	if (error == EMFILE && getrlimit(RLIMIT_NOFILE, &rlim) == 0 && rlim.rlim_cur != RLIM_INFINITY) {
		limit = StringUtil::Format(" of %llu", static_cast<unsigned long long>(rlim.rlim_cur));
	}
	string hint = error == EMFILE ? StringUtil::Format("the process reached its file descriptor limit%s; raise it "
	                                                   "(ulimit -n) or lower http_client_pool_capacity",
	                                                   limit)
	                              : string("the system-wide file table is full");
	return StringUtil::Format("Too many open files (%s; the HTTP client reported \"%s\")", hint, client_error);
#else
	return client_error;
#endif
}

} // namespace duckdb
