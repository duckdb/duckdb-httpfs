#pragma once

#include "duckdb/common/string.hpp"
#include "duckdb/common/typedefs.hpp"

namespace duckdb {

//! An `http_resolve` entry in curl's CURLOPT_RESOLVE form: HOST:PORT:ADDRESS[,ADDRESS]...
struct HTTPResolveEntry {
	//! Throws an InvalidInputException unless the entry has that form with a port of 1-65535 and IP addresses (IPv6
	//! in brackets). curl's +HOST form is rejected because its entries expire with the DNS cache, and so is -HOST.
	static void Validate(const string &entry);
	//! Throws an InvalidInputException when entries are set and 'http_util' is not the curl client, which alone
	//! applies them
	static void CheckClient(const string &http_util_name, idx_t entry_count);
};

} // namespace duckdb
