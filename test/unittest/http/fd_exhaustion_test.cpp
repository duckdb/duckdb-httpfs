#include "catch.hpp"

#include "http/http_test_helper.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace duckdb {

#ifndef _WIN32
namespace {

//! Lowers the soft descriptor limit to the lowest free descriptor, so the process cannot open another one.
class DescriptorLimitGuard {
public:
	DescriptorLimitGuard() {
		REQUIRE(getrlimit(RLIMIT_NOFILE, &original) == 0);
		auto fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		REQUIRE(fd >= 0);
		close(fd);
		lowered = original;
		lowered.rlim_cur = static_cast<rlim_t>(fd);
		REQUIRE(setrlimit(RLIMIT_NOFILE, &lowered) == 0);
	}
	~DescriptorLimitGuard() {
		setrlimit(RLIMIT_NOFILE, &original);
	}

	rlim_t Limit() const {
		return lowered.rlim_cur;
	}

private:
	struct rlimit original;
	struct rlimit lowered;
};

static void RunExhaustedRead(const string &client_implementation) {
	MockS3ServerConfig config;
	config.object.data = string(1024, 'x');
	MockS3Server server(std::move(config));

	DuckDB db(nullptr);
	Connection con(db);
	HTTPTestHelper::Configure(db, con, 0, client_implementation);
	HTTPTestHelper::RequireQueryOk(con, "BEGIN TRANSACTION");
	string error;
	string limit;
	{
		DescriptorLimitGuard guard;
		limit = to_string(guard.Limit());
		try {
			// opening the handle sends the first request
			auto outcome = HTTPTestHelper::TryReadRange(con, server.HTTPPath(), 0, 16);
			error = outcome.failed ? outcome.error : string();
		} catch (std::exception &ex) {
			error = ErrorData(ex).RawMessage();
		}
	}
	HTTPTestHelper::RequireQueryOk(con, "ROLLBACK");
	INFO(error);
	REQUIRE(StringUtil::Contains(error, "Too many open files"));
	REQUIRE(StringUtil::Contains(error, "file descriptor limit of " + limit));
	REQUIRE(StringUtil::Contains(error, "the HTTP client reported"));
}

} // namespace

TEST_CASE("HTTP requests name file descriptor exhaustion", "[httpfs][http]") {
	for (const auto &client : {"curl", "httplib"}) {
		CAPTURE(client);
		RunExhaustedRead(client);
	}
}
#endif

} // namespace duckdb
