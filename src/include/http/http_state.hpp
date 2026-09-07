#pragma once

#include "duckdb/common/allocator.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/common/atomic.hpp"
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/main/client_context_state.hpp"

#include <condition_variable>
#include <functional>

namespace duckdb {

class CachedFileHandle;
class CachedFileDownload;
enum class RequestType : uint8_t;

enum class RangeRequestSupport : uint8_t { UNKNOWN, SUPPORTED, NOT_SUPPORTED };

class RangeRequestState {
public:
	class Guard {
	public:
		explicit Guard(RangeRequestState &state_p, bool enabled_p)
		    : state(state_p), support(RangeRequestSupport::SUPPORTED), enabled(enabled_p), owns_probe(false) {
			if (!enabled) {
				return;
			}
			support = state.support.load();
			if (support == RangeRequestSupport::UNKNOWN) {
				annotated_unique_lock<annotated_mutex> lock(state.state_mutex);
				while (state.probing && state.support.load() == RangeRequestSupport::UNKNOWN) {
					state.probe_complete.wait(lock, [&]() DUCKDB_REQUIRES(state.state_mutex) {
						return !state.probing || state.support.load() != RangeRequestSupport::UNKNOWN;
					});
				}
				support = state.support.load();
				if (support == RangeRequestSupport::UNKNOWN) {
					state.probing = true;
					owns_probe = true;
				}
			}
		}
		Guard(const Guard &) = delete;
		Guard &operator=(const Guard &) = delete;
		Guard(Guard &&other) noexcept
		    : state(other.state), support(other.support), enabled(other.enabled), owns_probe(other.owns_probe) {
			other.owns_probe = false;
		}
		~Guard() {
			if (owns_probe) {
				state.AbortProbe();
			}
		}

	public:
		RangeRequestSupport Support() const {
			return support;
		}
		void MarkSupported() {
			if (enabled && support == RangeRequestSupport::UNKNOWN) {
				state.ResolveProbe(RangeRequestSupport::SUPPORTED);
				support = RangeRequestSupport::SUPPORTED;
				owns_probe = false;
			}
		}
		void MarkNotSupported() {
			if (!enabled) {
				return;
			}
			state.ResolveProbe(RangeRequestSupport::NOT_SUPPORTED);
			support = RangeRequestSupport::NOT_SUPPORTED;
			owns_probe = false;
		}

	private:
		RangeRequestState &state;
		RangeRequestSupport support;
		bool enabled;
		bool owns_probe;
	};

public:
	Guard BeginRequest(bool enabled = true) {
		return Guard(*this, enabled);
	}

private:
	void ResolveProbe(RangeRequestSupport new_support) {
		annotated_lock_guard<annotated_mutex> lock(state_mutex);
		support = new_support;
		probing = false;
		probe_complete.notify_all();
	}
	void AbortProbe() {
		annotated_lock_guard<annotated_mutex> lock(state_mutex);
		if (support.load() == RangeRequestSupport::UNKNOWN) {
			probing = false;
			probe_complete.notify_all();
		}
	}

private:
	annotated_mutex state_mutex;
	std::condition_variable probe_complete DUCKDB_GUARDED_BY(state_mutex);
	bool probing DUCKDB_GUARDED_BY(state_mutex) = false;
	atomic<RangeRequestSupport> support = {RangeRequestSupport::UNKNOWN};
};

//! Represents a file that is intended to be fully downloaded, then used in parallel by multiple threads
class CachedFile : public enable_shared_from_this<CachedFile> {
	friend class CachedFileHandle;
	friend class CachedFileDownload;

public:
	unique_ptr<CachedFileHandle> TryGetHandle();
	unique_ptr<CachedFileDownload> StartDownload(Allocator &allocator);
	void Invalidate();

private:
	//! Download state and cached data
	mutable annotated_mutex lock;
	mutable std::condition_variable download_complete DUCKDB_GUARDED_BY(lock);
	shared_ptr<class CachedFileData> cached_data DUCKDB_GUARDED_BY(lock);
	bool downloading DUCKDB_GUARDED_BY(lock) = false;
};

//! Immutable data published after a full download completes
class CachedFileData {
	friend class CachedFileHandle;

public:
	CachedFileData(AllocatedData data_p, idx_t size_p) : data(std::move(data_p)), size(size_p) {
	}

private:
	AllocatedData data;
	idx_t size;
};

//! Handle to a CachedFile
class CachedFileHandle {
public:
	explicit CachedFileHandle(shared_ptr<CachedFileData> file_p);

public:
	const char *GetData() const;
	//! Return the size of the initialized file
	idx_t GetSize() const;

private:
	shared_ptr<CachedFileData> file;
};

//! Exclusive handle for populating an uninitialized CachedFile
class CachedFileDownload {
	friend class CachedFile;

private:
	CachedFileDownload(shared_ptr<CachedFile> file_p, Allocator &allocator_p);

public:
	~CachedFileDownload();

public:
	//! Reserve capacity without changing the number of downloaded bytes
	void Reserve(idx_t capacity);
	//! Append downloaded bytes, growing the allocation as needed
	void Append(const_data_ptr_t data, idx_t length);
	//! Reset bytes written by a prior request attempt
	void Reset();
	//! Indicate the file is fully downloaded and safe for parallel reading
	unique_ptr<CachedFileHandle> Finalize();

private:
	void ReserveInternal(idx_t capacity);
	void Abort();

private:
	shared_ptr<CachedFile> file;
	Allocator &allocator;
	AllocatedData data;
	idx_t capacity = 0;
	idx_t size = 0;
	bool active = true;
};

//! Per-path state shared by all HTTP file handles in a query
class HTTPFileState {
public:
	HTTPFileState() : cached_file(make_shared_ptr<CachedFile>()) {
	}

public:
	unique_ptr<CachedFileHandle> TryGetCachedFileHandle() {
		return cached_file->TryGetHandle();
	}
	unique_ptr<CachedFileDownload> StartCachedFileDownload(Allocator &allocator) {
		return cached_file->StartDownload(allocator);
	}
	void InvalidateCachedFile() {
		cached_file->Invalidate();
	}
	RangeRequestState::Guard BeginRangeRequest(bool coordinate_requests = true) {
		return range_request_state.BeginRequest(coordinate_requests);
	}
	void MarkRangeRequestsSupported() {
		auto guard = range_request_state.BeginRequest();
		guard.MarkSupported();
	}

private:
	shared_ptr<CachedFile> cached_file;
	RangeRequestState range_request_state;
};

struct HTTPStateCounters {
	//! Request counts
	idx_t head_count = 0;
	idx_t get_count = 0;
	idx_t put_count = 0;
	idx_t post_count = 0;
	idx_t delete_count = 0;
	idx_t options_count = 0;

	//! Transferred bytes
	idx_t total_bytes_received = 0;
	idx_t total_bytes_sent = 0;

	bool IsEmpty() const;
};

class HTTPState : public ClientContextState {
public:
	//! Reset all counters and per-path state
	void Reset();
	//! Record request and transfer statistics
	void RecordRequest(RequestType request_type);
	void RecordBytesReceived(idx_t byte_count);
	void RecordBytesSent(idx_t byte_count);
	HTTPStateCounters GetCounters() const;
	bool IsEmpty() const;

	//! Per-path state shared by HTTP file handles
	shared_ptr<HTTPFileState> GetFileState(const string &path);
	void EraseFileState(const string &path);

	//! Helper functions to get the HTTP state
	static shared_ptr<HTTPState> TryGetState(ClientContext &context);
	static shared_ptr<HTTPState> TryGetState(optional_ptr<FileOpener> opener);

	//! Called by the ClientContext when the current query ends
	void QueryEnd(ClientContext &context) override {
		Reset();
	}
	void WriteProfilingInformation(std::ostream &ss) override;
	bool RunCredentialRefresh(const std::function<bool()> &callback) DUCKDB_EXCLUDES(credential_refresh_mutex);

private:
	//! Request and transfer statistics
	atomic<idx_t> head_count {0};
	atomic<idx_t> get_count {0};
	atomic<idx_t> put_count {0};
	atomic<idx_t> post_count {0};
	atomic<idx_t> delete_count {0};
	atomic<idx_t> options_count {0};
	atomic<idx_t> total_bytes_received {0};
	atomic<idx_t> total_bytes_sent {0};

private:
	//! Serializes credential provider refreshes after auth failures.
	annotated_mutex credential_refresh_mutex;

	//! Protects the per-path state map
	annotated_mutex file_states_mutex;
	//! Per-path state shared by all file handles in this query
	unordered_map<string, shared_ptr<HTTPFileState>> file_states DUCKDB_GUARDED_BY(file_states_mutex);
};

} // namespace duckdb
