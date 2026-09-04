#include "create_secret_functions.hpp"
#include "duckdb/logging/logger.hpp"
#include "s3/s3_provider.hpp"
#include "s3/s3fs.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/common/local_file_system.hpp"

namespace duckdb {

void CreateS3SecretFunctions::Register(ExtensionLoader &loader) {
	for (const auto secret_type : S3SecretConfig::SecretTypes()) {
		RegisterCreateSecretFunction(loader, secret_type);
	}
}

static Value MapToStruct(const Value &map) {
	auto children = MapValue::GetChildren(map);

	child_list_t<Value> struct_fields;
	for (const auto &kv_child : children) {
		auto kv_pair = StructValue::GetChildren(kv_child);
		if (kv_pair.size() != 2) {
			throw InvalidInputException("Invalid input passed to refresh_info");
		}

		struct_fields.emplace_back(kv_pair[0].ToString(), kv_pair[1]);
	}
	return Value::STRUCT(struct_fields);
}

struct S3SecretBuilder {
public:
	explicit S3SecretBuilder(CreateSecretInput &input_p) : input(input_p) {
		auto scope = input.scope.empty() ? S3SecretConfig::DefaultSecretScope(static_cast<const string &>(input.type))
		                                 : input.scope;
		secret = make_uniq<KeyValueSecret>(std::move(scope), input.type, input.provider, input.name);
		secret->redact_keys = {"secret", "session_token"};
	}

public:
	unique_ptr<BaseSecret> Create() {
		S3SecretConfig::ApplySecretDefaults(input, *secret);
		for (const auto &option : input.options) {
			ApplyOption(StringUtil::Lower(option.first), option.second);
		}
		return std::move(secret);
	}

private:
	void ApplyOption(const string &name, const Value &value) {
		if (name == "key_id" || name == "secret" || name == "http_proxy" || name == "http_proxy_password" ||
		    name == "http_proxy_username" || name == "extra_http_headers") {
			secret->secret_map[Identifier(name)] = value;
		} else if (name == "region" || name == "session_token" || name == "endpoint" || name == "kms_key_id") {
			secret->secret_map[Identifier(name)] = value.ToString();
		} else if (name == "url_style") {
			auto url_style = StringUtil::Lower(value.ToString());
			S3AuthURLParams::ParseStyle(url_style);
			secret->secret_map[Identifier(name)] = std::move(url_style);
		} else if (name == "use_ssl" || name == "verify_ssl" || name == "url_compatibility_mode" ||
		           name == "requester_pays") {
			SetBooleanOption(name, value);
		} else if (name == "refresh") {
			SetRefresh(value);
		} else if (name == "refresh_info") {
			SetRefreshInfo(value);
		} else if (S3SecretConfig::TryApplySecretOption(input, name, value, *secret)) {
			return;
		} else {
			throw InvalidInputException("Unknown named parameter passed to CreateSecretFunctionInternal: " + name);
		}
	}

	void SetBooleanOption(const string &name, const Value &value) {
		if (value.type() != LogicalType::BOOLEAN) {
			throw InvalidInputException("Invalid type passed to secret option: '%s', found '%s', expected: 'BOOLEAN'",
			                            name, value.type().ToString());
		}
		secret->secret_map[Identifier(name)] = Value::BOOLEAN(value.GetValue<bool>());
	}

	void SetRefresh(const Value &value) {
		if (refresh) {
			throw InvalidInputException("Can not set `refresh` and `refresh_info` at the same time");
		}
		refresh = StringUtil::Lower(value.GetValue<string>()) == "auto";
		secret->secret_map["refresh"] = Value("auto");
		child_list_t<Value> struct_fields;
		for (const auto &option : input.options) {
			struct_fields.emplace_back(StringUtil::Lower(option.first), option.second);
		}
		secret->secret_map["refresh_info"] = Value::STRUCT(struct_fields);
	}

	void SetRefreshInfo(const Value &value) {
		if (refresh) {
			throw InvalidInputException("Can not set `refresh` and `refresh_info` at the same time");
		}
		refresh = true;
		secret->secret_map["refresh_info"] = MapToStruct(value);
	}

private:
	CreateSecretInput &input;
	unique_ptr<KeyValueSecret> secret;
	bool refresh = false;
};

unique_ptr<BaseSecret> CreateS3SecretFunctions::CreateSecretFunctionInternal(ClientContext &context,
                                                                             CreateSecretInput &input) {
	return S3SecretBuilder(input).Create();
}

CreateSecretInput CreateS3SecretFunctions::GenerateRefreshSecretInfo(const SecretEntry &secret_entry,
                                                                     Value &refresh_info) {
	const auto &kv_secret = secret_entry.secret->Cast<KeyValueSecret>();

	CreateSecretInput result;
	result.on_conflict = OnCreateConflict::REPLACE_ON_CONFLICT;
	result.persist_type = secret_entry.persist_type;

	result.type = kv_secret.GetType();
	result.name = kv_secret.GetName();
	result.provider = Identifier(kv_secret.GetProvider());
	if (result.persist_type != SecretPersistType::TRANSACTION) {
		result.storage_type = Identifier(secret_entry.storage_mode);
	}
	result.scope = kv_secret.GetScope();

	auto result_child_count = StructType::GetChildCount(refresh_info.type());
	auto refresh_info_children = StructValue::GetChildren(refresh_info);
	D_ASSERT(refresh_info_children.size() == result_child_count);
	for (idx_t i = 0; i < result_child_count; i++) {
		auto &key = StructType::GetChildName(refresh_info.type(), i);
		auto &value = refresh_info_children[i];
		result.options[Identifier(key.GetIdentifierName()).GetIdentifierName()] = value;
	}

	return result;
}

static bool SecretCredentialMaterialChanged(const KeyValueSecret &old_secret, const KeyValueSecret &new_secret) {
	for (const auto key : S3SecretConfig::CredentialMaterialKeys()) {
		Value old_value;
		Value new_value;
		auto old_has_value = old_secret.TryGetValue(key, old_value);
		auto new_has_value = new_secret.TryGetValue(key, new_value);
		if (old_has_value != new_has_value) {
			return true;
		}
		if (old_has_value && !Value::NotDistinctFrom(old_value, new_value)) {
			return true;
		}
	}
	return false;
}

//! Function that will automatically try to refresh a secret
bool CreateS3SecretFunctions::TryRefreshS3Secret(ClientContext &context, const SecretEntry &secret_to_refresh) {
	const auto &kv_secret = secret_to_refresh.secret->Cast<KeyValueSecret>();

	Value refresh_info;
	if (!kv_secret.TryGetValue("refresh_info", refresh_info)) {
		return false;
	}
	auto &secret_manager = context.db->GetSecretManager();
	auto refresh_input = GenerateRefreshSecretInfo(secret_to_refresh, refresh_info);

	// TODO: change SecretManager API to avoid requiring catching this exception
	try {
		auto res = secret_manager.CreateSecret(context, refresh_input);
		auto &new_secret = res->secret->Cast<KeyValueSecret>();
		if (SecretCredentialMaterialChanged(kv_secret, new_secret)) {
			DUCKDB_LOG_INFO(context, "Successfully refreshed secret: %s, new key_id: %s",
			                secret_to_refresh.secret->GetName(), new_secret.TryGetValue("key_id").ToString());
		}
		return true;
	} catch (std::exception &ex) {
		ErrorData error(ex);
		string new_message = StringUtil::Format("Exception thrown while trying to refresh secret %s. To fix this, "
		                                        "please recreate or remove the secret and try again. Error: '%s'",
		                                        secret_to_refresh.secret->GetName(), error.Message());
		throw Exception(error.Type(), new_message);
	}
}

unique_ptr<BaseSecret> CreateS3SecretFunctions::CreateS3SecretFromConfig(ClientContext &context,
                                                                         CreateSecretInput &input) {
	return CreateSecretFunctionInternal(context, input);
}

void CreateS3SecretFunctions::SetBaseNamedParams(CreateSecretFunction &function, string &type) {
	function.named_parameters["key_id"] = LogicalType::VARCHAR;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	function.named_parameters["region"] = LogicalType::VARCHAR;
	function.named_parameters["session_token"] = LogicalType::VARCHAR;
	function.named_parameters["endpoint"] = LogicalType::VARCHAR;
	function.named_parameters["url_style"] = LogicalType::VARCHAR;
	function.named_parameters["use_ssl"] = LogicalType::BOOLEAN;
	function.named_parameters["verify_ssl"] = LogicalType::BOOLEAN;
	function.named_parameters["kms_key_id"] = LogicalType::VARCHAR;
	function.named_parameters["url_compatibility_mode"] = LogicalType::BOOLEAN;
	function.named_parameters["requester_pays"] = LogicalType::BOOLEAN;

	// Whether a secret refresh attempt should be made when the secret appears to be incorrect
	function.named_parameters["refresh"] = LogicalType::VARCHAR;

	// Params for HTTP configuration
	function.named_parameters["http_proxy"] = LogicalType::VARCHAR;
	function.named_parameters["http_proxy_password"] = LogicalType::VARCHAR;
	function.named_parameters["http_proxy_username"] = LogicalType::VARCHAR;
	function.named_parameters["extra_http_headers"] = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	// Refresh Modes
	// - auto
	// - disabled
	// - on_error
	// - on_timeout

	// - on_use: every time a secret is used, it will refresh.

	// Debugging/testing option: it allows specifying how the secret will be refreshed using a manually specfied MAP
	function.named_parameters["refresh_info"] = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);

	S3SecretConfig::SetSecretNamedParameters(type, function);
}

void CreateS3SecretFunctions::RegisterCreateSecretFunction(ExtensionLoader &loader, string type) {
	// Register the new type
	SecretType secret_type;
	secret_type.name = Identifier(type);
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";
	secret_type.extension = "httpfs";

	loader.RegisterSecretType(secret_type);

	CreateSecretFunction from_empty_config_fun2 = {type, "config", CreateS3SecretFromConfig};
	SetBaseNamedParams(from_empty_config_fun2, type);
	loader.RegisterFunction(from_empty_config_fun2);
}

void CreateBearerTokenFunctions::Register(ExtensionLoader &loader) {
	// HuggingFace secret
	SecretType secret_type_hf;
	secret_type_hf.name = Identifier(HUGGINGFACE_TYPE);
	secret_type_hf.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type_hf.default_provider = "config";
	secret_type_hf.extension = "httpfs";
	loader.RegisterSecretType(secret_type_hf);

	// Huggingface config provider
	CreateSecretFunction hf_config_fun = {HUGGINGFACE_TYPE, "config", CreateBearerSecretFromConfig};
	hf_config_fun.named_parameters["token"] = LogicalType::VARCHAR;
	loader.RegisterFunction(hf_config_fun);

	// Huggingface credential_chain provider
	CreateSecretFunction hf_cred_fun = {HUGGINGFACE_TYPE, "credential_chain",
	                                    CreateHuggingFaceSecretFromCredentialChain};
	loader.RegisterFunction(hf_cred_fun);
}

unique_ptr<BaseSecret> CreateBearerTokenFunctions::CreateSecretFunctionInternal(ClientContext &context,
                                                                                CreateSecretInput &input,
                                                                                const string &token) {
	// Set scope to user provided scope or the default
	auto scope = input.scope;
	if (scope.empty()) {
		if (input.type == HUGGINGFACE_TYPE) {
			scope.push_back("hf://");
		} else {
			throw InternalException("Unknown secret type found in httpfs extension: '%s'", input.type);
		}
	}
	auto return_value = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	//! Set key value map
	return_value->secret_map["token"] = token;

	//! Set redact keys
	return_value->redact_keys = {"token"};

	return std::move(return_value);
}

unique_ptr<BaseSecret> CreateBearerTokenFunctions::CreateBearerSecretFromConfig(ClientContext &context,
                                                                                CreateSecretInput &input) {
	string token;

	for (const auto &named_param : input.options) {
		auto lower_name = StringUtil::Lower(named_param.first);
		if (lower_name == "token") {
			token = named_param.second.ToString();
		}
	}

	return CreateSecretFunctionInternal(context, input, token);
}

static string ReadTokenFileContents(const string &token_path) {
	LocalFileSystem fs;
	auto handle = fs.OpenFile(token_path, {FileOpenFlags::FILE_FLAGS_READ});
	return handle->ReadLine();
}

static string ReadTokenFile(const string &token_path, const string &error_source_message) {
	try {
		return ReadTokenFileContents(token_path);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		throw IOException("Failed to read token path '%s'%s. (error: %s)", token_path, error_source_message,
		                  error.RawMessage());
	}
}

static string TryReadTokenFile(const string &token_path) {
	try {
		return ReadTokenFileContents(token_path);
	} catch (std::exception &) {
		return "";
	}
}

unique_ptr<BaseSecret>
CreateBearerTokenFunctions::CreateHuggingFaceSecretFromCredentialChain(ClientContext &context,
                                                                       CreateSecretInput &input) {
	// Step 1: Try the ENV variable HF_TOKEN
	const char *hf_token_env = std::getenv("HF_TOKEN");
	if (hf_token_env) {
		return CreateSecretFunctionInternal(context, input, hf_token_env);
	}
	// Step 2: Try the ENV variable HF_TOKEN_PATH
	const char *hf_token_path_env = std::getenv("HF_TOKEN_PATH");
	if (hf_token_path_env) {
		auto token = ReadTokenFile(hf_token_path_env, " fetched from HF_TOKEN_PATH env variable");
		return CreateSecretFunctionInternal(context, input, token);
	}

	// Step 3: Try the path $HF_HOME/token
	const char *hf_home_env = std::getenv("HF_HOME");
	if (hf_home_env) {
		auto token_path = LocalFileSystem().JoinPath(hf_home_env, "token");
		auto token = ReadTokenFile(token_path, " constructed using the HF_HOME variable: '$HF_HOME/token'");
		return CreateSecretFunctionInternal(context, input, token);
	}

	// Step 4: Check the default path
	auto token = TryReadTokenFile("~/.cache/huggingface/token");
	return CreateSecretFunctionInternal(context, input, token);
}
} // namespace duckdb
