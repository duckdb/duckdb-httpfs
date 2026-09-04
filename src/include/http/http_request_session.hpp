#pragma once

#include "duckdb/common/helper.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/unordered_map.hpp"
#include "http/httpfs_client.hpp"

namespace duckdb {

class HTTPRequestSession;
class HTTPState;
class Logger;

enum class HTTPRequestSnapshotType : uint8_t { HTTP, S3 };

struct HTTPConfiguredHeaders {
	string user_agent;
	unordered_map<string, string> extra_headers;
};

struct HTTPSessionRequest {
	HTTPHeaders headers;
	unique_ptr<HTTPFSParams> params;
	HTTPConfiguredHeaders configured_headers;
};

struct HTTPRequestSnapshot {
	explicit HTTPRequestSnapshot(const HTTPFSParams &params,
	                             HTTPRequestSnapshotType type_p = HTTPRequestSnapshotType::HTTP);
	virtual ~HTTPRequestSnapshot();

public:
	bool CanReuseClientsWith(const HTTPRequestSnapshot &other) const;
	HTTPSessionRequest CreateRequest(HTTPHeaders headers = {}) const;
	const HTTPFSParams &Params() const {
		return params;
	}

	template <class TARGET>
	TARGET &Cast() {
		if (type != TARGET::TYPE) {
			throw InternalException("Failed to cast HTTP request snapshot - snapshot type mismatch");
		}
		return reinterpret_cast<TARGET &>(*this);
	}

	template <class TARGET>
	const TARGET &Cast() const {
		if (type != TARGET::TYPE) {
			throw InternalException("Failed to cast HTTP request snapshot - snapshot type mismatch");
		}
		return reinterpret_cast<const TARGET &>(*this);
	}

public:
	static constexpr HTTPRequestSnapshotType TYPE = HTTPRequestSnapshotType::HTTP;
	const HTTPRequestSnapshotType type;

private:
	const HTTPFSParams params;
};

struct CapturedHTTPRequestSnapshot {
	shared_ptr<const HTTPRequestSnapshot> snapshot;
	idx_t client_generation;
};

struct HTTPRequestSnapshotPublication {
	CapturedHTTPRequestSnapshot current;
	bool published;
};

class HTTPClientLease {
	friend class HTTPRequestSession;

private:
	HTTPClientLease(shared_ptr<HTTPRequestSession> session_p, reference<HTTPUtil> http_util_p,
	                HTTPClientReuseMode reuse_mode_p, idx_t generation_p, unique_ptr<HTTPClient> client_p);

public:
	HTTPClientLease(HTTPClientLease &&other) noexcept;
	HTTPClientLease &operator=(HTTPClientLease &&other) noexcept;
	HTTPClientLease(const HTTPClientLease &) = delete;
	HTTPClientLease &operator=(const HTTPClientLease &) = delete;
	~HTTPClientLease() noexcept;

public:
	unique_ptr<HTTPClient> &Client() {
		return client;
	}
	void Invalidate() {
		reusable = false;
	}

private:
	void Release() noexcept;

private:
	shared_ptr<HTTPRequestSession> session;
	reference<HTTPUtil> http_util;
	HTTPClientReuseMode reuse_mode;
	idx_t generation;
	unique_ptr<HTTPClient> client;
	bool reusable;
};

class HTTPRequestSession : public enable_shared_from_this<HTTPRequestSession> {
	friend class HTTPClientLease;

public:
	explicit HTTPRequestSession(shared_ptr<const HTTPRequestSnapshot> snapshot_p);
	~HTTPRequestSession();

public:
	CapturedHTTPRequestSnapshot Capture() const DUCKDB_EXCLUDES(lock);
	HTTPRequestSnapshotPublication TryPublish(const shared_ptr<const HTTPRequestSnapshot> &expected,
	                                          shared_ptr<const HTTPRequestSnapshot> replacement) DUCKDB_EXCLUDES(lock);
	HTTPClientLease AcquireClient(const CapturedHTTPRequestSnapshot &captured, HTTPFSParams &request_params,
	                              const string &proto_host_port) DUCKDB_EXCLUDES(lock);
	void InvalidateClients() DUCKDB_EXCLUDES(lock);

private:
	struct IdleClient {
		IdleClient(unique_ptr<HTTPClient> client_p, reference<HTTPUtil> http_util_p)
		    : client(std::move(client_p)), http_util(http_util_p) {
		}

	public:
		unique_ptr<HTTPClient> client;
		reference<HTTPUtil> http_util;
	};

private:
	void ReturnClient(unique_ptr<HTTPClient> client, reference<HTTPUtil> http_util, HTTPClientReuseMode reuse_mode,
	                  idx_t generation, bool reusable) noexcept DUCKDB_EXCLUDES(lock);
	static void CloseClients(vector<IdleClient> clients) noexcept;

private:
	mutable annotated_mutex lock;
	shared_ptr<const HTTPRequestSnapshot> current_snapshot DUCKDB_GUARDED_BY(lock);
	idx_t client_generation DUCKDB_GUARDED_BY(lock) = 0;
	vector<IdleClient> idle_clients DUCKDB_GUARDED_BY(lock);
};

} // namespace duckdb
