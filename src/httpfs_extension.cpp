#include "httpfs_extension.hpp"
#include "http/httpfs_client.hpp"
#include "http/http_settings.hpp"
#include "create_secret_functions.hpp"
#include "duckdb.hpp"
#include "s3/s3_settings.hpp"
#include "s3/s3fs.hpp"
#include "hffs.hpp"
#include "duckdb/logging/log_manager.hpp"
#ifdef OVERRIDE_ENCRYPTION_UTILS
#include "crypto.hpp"
#elif defined(EMSCRIPTEN)
#include "mbedtls_wrapper.hpp"
#endif // OVERRIDE_ENCRYPTION_UTILS

namespace duckdb {

struct HTTPFSExtensionLoader {
	static void RegisterFileSystems(DatabaseInstance &instance) {
		auto &fs = instance.GetFileSystem();
		fs.RegisterSubSystem(make_uniq<HTTPFileSystem>());
		fs.RegisterSubSystem(make_uniq<HuggingFaceFileSystem>());
		fs.RegisterSubSystem(make_uniq<S3FileSystem>(BufferManager::GetBufferManager(instance)));
	}

	static void RegisterSettings(DBConfig &config) {
		HTTPSettings::Register(config);
		S3Settings::Register(config);
		HTTPSettings::Initialize(config);
		S3Settings::Initialize(config);
	}

	static void RegisterSecrets(ExtensionLoader &loader) {
		CreateS3SecretFunctions::Register(loader);
		CreateBearerTokenFunctions::Register(loader);
	}

	static void ConfigureEncryption(DBConfig &config) {
#ifdef OVERRIDE_ENCRYPTION_UTILS
		config.encryption_util = make_shared_ptr<AESStateSSLFactory>();
#elif defined(EMSCRIPTEN)
		if (!config.encryption_util) {
			config.encryption_util = make_shared_ptr<duckdb_mbedtls::MbedTlsWrapper::AESStateMBEDTLSFactory>();
		}
#endif
	}

	static void Load(ExtensionLoader &loader) {
		auto &instance = loader.GetDatabaseInstance();
		auto &config = DBConfig::GetConfig(instance);
		RegisterSettings(config);
		RegisterSecrets(loader);
		ConfigureEncryption(config);

		instance.GetLogManager().RegisterLogType(make_uniq<HTTPFSInfoLogType>());
		RegisterFileSystems(instance);
	}
};

static void LoadInternal(ExtensionLoader &loader) {
	HTTPFSExtensionLoader::Load(loader);
}

void HttpfsExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
string HttpfsExtension::Name() {
	return "httpfs";
}

string HttpfsExtension::Version() const {
#ifdef EXT_VERSION_HTTPFS
	return EXT_VERSION_HTTPFS;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(httpfs, loader) {
	duckdb::LoadInternal(loader);
}
}
