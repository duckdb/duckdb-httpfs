#include "http/httpfs_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/database.hpp"

namespace duckdb {

// we statically compile in the TLS library, which means the cert file location of the build machine is the
// place it would look. But not every distro has this file in the same location, so we search a
// number of common locations and use the first one we find.
static constexpr const char *CERT_FILE_LOCATIONS[] = {
    // Arch, Debian-based, Gentoo
    "/etc/ssl/certs/ca-certificates.crt",
    // RedHat 7 based
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // Redhat 6 based
    "/etc/pki/tls/certs/ca-bundle.crt",
    // OpenSUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine
    "/etc/ssl/cert.pem"};

HTTPFSUtil::HTTPFSUtil(optional_ptr<DatabaseInstance> db_p) : db(db_p) {
}

bool HTTPFSUtil::IsSecureConnection(const string &proto_host_port) {
	return StringUtil::StartsWith(StringUtil::Lower(proto_host_port), "https://");
}

static shared_ptr<const string> ReadCertificateBundle(FileSystem &fs, const string &path) {
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
	auto size = NumericCast<idx_t>(handle->GetFileSize());
	auto bundle = make_shared_ptr<string>();
	bundle->resize(size);
	handle->Read(reinterpret_cast<void *>(const_cast<char *>(bundle->data())), size, 0);
	return bundle;
}

shared_ptr<const string> HTTPFSUtil::GetCertificateBundle(const string &ca_cert_file) {
	if (!db) {
		return nullptr;
	}
	{
		lock_guard<mutex> guard(certificate_lock);
		auto entry = certificate_bundles.find(ca_cert_file);
		if (entry != certificate_bundles.end()) {
			return entry->second;
		}
	}
	auto &fs = FileSystem::GetFileSystem(*db);
	shared_ptr<const string> bundle;
	if (!ca_cert_file.empty()) {
		bundle = ReadCertificateBundle(fs, ca_cert_file);
	} else {
		// a location the configuration does not allow is skipped; it only becomes an error when none is left
		vector<string> refused;
		for (auto location : CERT_FILE_LOCATIONS) {
			bool exists;
			try {
				exists = fs.FileExists(location);
			} catch (PermissionException &) {
				refused.push_back(location);
				continue;
			}
			if (exists) {
				bundle = ReadCertificateBundle(fs, location);
				break;
			}
		}
		if (!bundle && !refused.empty()) {
			throw PermissionException("Cannot read a CA certificate bundle: file system access is restricted by "
			                          "configuration. Add one of %s to allowed_paths, point ca_cert_file at an allowed "
			                          "file, or disable server certificate verification",
			                          StringUtil::Join(refused, ", "));
		}
	}
	lock_guard<mutex> guard(certificate_lock);
	certificate_bundles[ca_cert_file] = bundle;
	return bundle;
}

} // namespace duckdb
