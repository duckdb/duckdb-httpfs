#include "http/http_resolve.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include <algorithm>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace duckdb {

static bool IsIPAddress(const string &address) {
	unsigned char buffer[16];
	if (address.size() > 2 && address.front() == '[' && address.back() == ']') {
		return inet_pton(AF_INET6, address.substr(1, address.size() - 2).c_str(), buffer) == 1;
	}
	return inet_pton(AF_INET, address.c_str(), buffer) == 1;
}

void HTTPResolveEntry::Validate(const string &entry) {
	auto host_end = entry.find(':');
	auto port_end = host_end == string::npos ? string::npos : entry.find(':', host_end + 1);
	bool valid =
	    host_end > 0 && port_end != string::npos && port_end + 1 < entry.size() && entry[0] != '+' && entry[0] != '-';
	if (valid) {
		auto port = entry.substr(host_end + 1, port_end - host_end - 1);
		valid = !port.empty() && port.size() <= 5 &&
		        std::all_of(port.begin(), port.end(), StringUtil::CharacterIsDigit) && std::stoi(port) >= 1 &&
		        std::stoi(port) <= 65535;
	}
	if (valid) {
		// Split drops a trailing empty part, so empty addresses are checked for separately
		auto addresses = entry.substr(port_end + 1);
		auto parts = StringUtil::Split(addresses, ',');
		valid = addresses.back() != ',' && std::all_of(parts.begin(), parts.end(), IsIPAddress);
	}
	if (!valid) {
		throw InvalidInputException(
		    "Invalid http_resolve entry \"%s\": expected HOST:PORT:ADDRESS[,ADDRESS]... with IP addresses", entry);
	}
}

} // namespace duckdb
