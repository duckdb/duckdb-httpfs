#include "s3/s3_endpoint.hpp"

#include "duckdb/common/string_util.hpp"

namespace duckdb {

static bool IsValidIPv4Address(const string &address) {
	idx_t component_count = 0;
	idx_t position = 0;
	while (position <= address.size()) {
		auto separator = address.find('.', position);
		auto component_end = separator == string::npos ? address.size() : separator;
		if (component_end == position || component_end - position > 3) {
			return false;
		}
		idx_t value = 0;
		for (idx_t i = position; i < component_end; i++) {
			if (!StringUtil::CharacterIsDigit(address[i])) {
				return false;
			}
			value = value * 10 + NumericCast<idx_t>(address[i] - '0');
		}
		if (value > 255) {
			return false;
		}
		component_count++;
		if (separator == string::npos) {
			break;
		}
		position = separator + 1;
	}
	return component_count == 4;
}

static bool IsValidIPv6Section(const string &section, bool allow_ipv4, idx_t &group_count) {
	if (section.empty()) {
		return true;
	}
	idx_t position = 0;
	while (position <= section.size()) {
		auto separator = section.find(':', position);
		auto group_end = separator == string::npos ? section.size() : separator;
		if (group_end == position) {
			return false;
		}
		auto group = section.substr(position, group_end - position);
		if (group.find('.') != string::npos) {
			if (!allow_ipv4 || separator != string::npos || !IsValidIPv4Address(group)) {
				return false;
			}
			group_count += 2;
		} else {
			if (group.size() > 4) {
				return false;
			}
			for (const auto character : group) {
				if (!StringUtil::CharacterIsHex(character)) {
					return false;
				}
			}
			group_count++;
		}
		if (separator == string::npos) {
			break;
		}
		position = separator + 1;
	}
	return true;
}

static bool IsValidIPv6Address(const string &address) {
	if (address.empty() || address.find('%') != string::npos) {
		return false;
	}
	auto compression = address.find("::");
	if (compression != string::npos && address.find("::", compression + 2) != string::npos) {
		return false;
	}
	idx_t group_count = 0;
	if (compression == string::npos) {
		return IsValidIPv6Section(address, true, group_count) && group_count == 8;
	}
	auto left = address.substr(0, compression);
	auto right = address.substr(compression + 2);
	return IsValidIPv6Section(left, false, group_count) && IsValidIPv6Section(right, true, group_count) &&
	       group_count < 8;
}

static void ValidateEndpointHost(const string &host) {
	for (const auto character : host) {
		if (!StringUtil::CharacterIsAlphaNumeric(character) && character != '-' && character != '.' &&
		    character != '_') {
			throw InvalidInputException("Invalid S3 endpoint host");
		}
	}
}

static void ValidateEndpointBasePath(string &base_path) {
	for (idx_t i = 0; i < base_path.size(); i++) {
		if (base_path[i] == '\\') {
			throw InvalidInputException("S3 endpoint paths cannot contain backslashes");
		}
		if (base_path[i] == '%' && (i + 2 >= base_path.size() || !StringUtil::CharacterIsHex(base_path[i + 1]) ||
		                            !StringUtil::CharacterIsHex(base_path[i + 2]))) {
			throw InvalidInputException("S3 endpoint paths contain an invalid percent escape");
		}
	}

	idx_t position = 0;
	while (position <= base_path.size()) {
		auto separator = base_path.find('/', position);
		auto segment_end = separator == string::npos ? base_path.size() : separator;
		auto segment = base_path.substr(position, segment_end - position);
		if (segment == "." || segment == "..") {
			throw InvalidInputException("S3 endpoint paths cannot contain '.' or '..' segments");
		}
		if (separator == string::npos) {
			break;
		}
		position = separator + 1;
	}
	while (!base_path.empty() && base_path.back() == '/') {
		base_path.pop_back();
	}
}

static optional_idx ParseEndpointPort(const string &port) {
	if (port.empty()) {
		throw InvalidInputException("S3 endpoint port cannot be empty");
	}
	idx_t result = 0;
	for (const auto character : port) {
		if (!StringUtil::CharacterIsDigit(character)) {
			throw InvalidInputException("Invalid S3 endpoint port '%s'", port);
		}
		result = result * 10 + NumericCast<idx_t>(character - '0');
		if (result > 65535) {
			throw InvalidInputException("Invalid S3 endpoint port '%s'", port);
		}
	}
	if (result == 0) {
		throw InvalidInputException("Invalid S3 endpoint port '%s'", port);
	}
	return optional_idx(result);
}

NormalizedS3Endpoint NormalizedS3Endpoint::Parse(const string &endpoint, bool fallback_use_ssl) {
	NormalizedS3Endpoint result;
	result.scheme = fallback_use_ssl ? Scheme::HTTPS : Scheme::HTTP;
	auto input = endpoint;
	StringUtil::Trim(input);
	if (input.empty()) {
		return result;
	}
	if (input.find('?') != string::npos || input.find('#') != string::npos) {
		throw InvalidInputException("S3 endpoints cannot contain a query string or fragment");
	}

	idx_t authority_start = 0;
	auto first_slash = input.find('/');
	auto scheme_end = input.find("://");
	if (scheme_end != string::npos && (first_slash == string::npos || scheme_end < first_slash)) {
		auto scheme = StringUtil::Lower(input.substr(0, scheme_end));
		if (scheme == "http") {
			result.scheme = Scheme::HTTP;
		} else if (scheme == "https") {
			result.scheme = Scheme::HTTPS;
		} else {
			throw InvalidInputException("Unsupported S3 endpoint scheme '%s'", scheme);
		}
		authority_start = scheme_end + 3;
	}

	auto path_start = input.find('/', authority_start);
	auto authority_end = path_start == string::npos ? input.size() : path_start;
	auto authority = input.substr(authority_start, authority_end - authority_start);
	if (authority.empty()) {
		throw InvalidInputException("S3 endpoint authority cannot be empty");
	}
	if (authority.find('@') != string::npos) {
		throw InvalidInputException("S3 endpoints cannot contain user information");
	}

	if (authority[0] == '[') {
		auto bracket = authority.find(']');
		if (bracket == string::npos || bracket == 1 || !IsValidIPv6Address(authority.substr(1, bracket - 1))) {
			throw InvalidInputException("Invalid bracketed IPv6 S3 endpoint");
		}
		result.host = StringUtil::Lower(authority.substr(1, bracket - 1));
		result.is_ipv6 = true;
		if (bracket + 1 < authority.size()) {
			if (authority[bracket + 1] != ':') {
				throw InvalidInputException("Invalid bracketed IPv6 S3 endpoint authority");
			}
			result.port = ParseEndpointPort(authority.substr(bracket + 2));
		}
	} else {
		auto colon = authority.find(':');
		if (colon != string::npos) {
			if (authority.find(':', colon + 1) != string::npos) {
				throw InvalidInputException("IPv6 S3 endpoints must use brackets");
			}
			result.host = authority.substr(0, colon);
			result.port = ParseEndpointPort(authority.substr(colon + 1));
		} else {
			result.host = authority;
		}
		if (result.host.empty()) {
			throw InvalidInputException("S3 endpoint host cannot be empty");
		}
		ValidateEndpointHost(result.host);
		result.host = StringUtil::Lower(result.host);
	}

	if (path_start != string::npos) {
		result.base_path = input.substr(path_start);
		ValidateEndpointBasePath(result.base_path);
	}
	return result;
}

bool NormalizedS3Endpoint::operator==(const NormalizedS3Endpoint &other) const {
	return scheme == other.scheme && base_path == other.base_path && GetAuthority() == other.GetAuthority();
}

bool NormalizedS3Endpoint::IsEmpty() const {
	return host.empty();
}

bool NormalizedS3Endpoint::IsIPv6() const {
	return is_ipv6;
}

bool NormalizedS3Endpoint::UsesSSL() const {
	return scheme == Scheme::HTTPS;
}

const string &NormalizedS3Endpoint::GetHost() const {
	return host;
}

const string &NormalizedS3Endpoint::GetBasePath() const {
	return base_path;
}

string NormalizedS3Endpoint::GetAuthority() const {
	auto result = is_ipv6 ? "[" + host + "]" : host;
	if (port.IsValid() && !IsDefaultPort()) {
		result += ":" + std::to_string(port.GetIndex());
	}
	return result;
}

string NormalizedS3Endpoint::GetProtocol() const {
	return UsesSSL() ? "https://" : "http://";
}

string NormalizedS3Endpoint::GetCanonicalValue() const {
	return GetProtocol() + GetAuthority() + base_path;
}

bool NormalizedS3Endpoint::IsDefaultPort() const {
	if (!port.IsValid()) {
		return true;
	}
	return port.GetIndex() == (UsesSSL() ? 443 : 80);
}

void NormalizedS3Endpoint::SetHost(string host_p) {
	host = StringUtil::Lower(std::move(host_p));
	is_ipv6 = false;
}

} // namespace duckdb
