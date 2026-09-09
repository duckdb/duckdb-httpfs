#pragma once

#include "duckdb/common/helper.hpp"
#include "duckdb/main/http/http_transport_manager.hpp"
#include "duckdb/main/http/http_util.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/shared_ptr.hpp"
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
};

struct HTTPRequestSnapshotPublication {
	CapturedHTTPRequestSnapshot current;
	bool published;
};

class HTTPRequestSession {
public:
	explicit HTTPRequestSession(shared_ptr<const HTTPRequestSnapshot> snapshot_p);
	HTTPRequestSession(HTTPTransportManager::Session transport_session_p,
	                   shared_ptr<const HTTPRequestSnapshot> snapshot_p);

public:
	static shared_ptr<HTTPRequestSession> Create(optional_ptr<FileOpener> opener, optional_ptr<FileOpenerInfo> info);

public:
	CapturedHTTPRequestSnapshot Capture() const DUCKDB_EXCLUDES(lock);
	HTTPRequestSnapshotPublication TryPublish(const shared_ptr<const HTTPRequestSnapshot> &expected,
	                                          shared_ptr<const HTTPRequestSnapshot> replacement) DUCKDB_EXCLUDES(lock);
	unique_ptr<HTTPResponse> Request(BaseRequest &request);
	void InvalidateConnections() noexcept;

private:
	mutable annotated_mutex lock;
	shared_ptr<const HTTPRequestSnapshot> current_snapshot DUCKDB_GUARDED_BY(lock);
	unique_ptr<HTTPTransportManager::Session> transport_session;
};

} // namespace duckdb
