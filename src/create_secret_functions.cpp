#include "create_secret_functions.hpp"
#include "s3fs.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"

#include <cctype>
#include <cstdio>

namespace duckdb {

void CreateS3SecretFunctions::Register(ExtensionLoader &loader) {
	RegisterCreateSecretFunction(loader, "s3");
	RegisterCreateSecretFunction(loader, "aws");
	RegisterCreateSecretFunction(loader, "r2");
	RegisterCreateSecretFunction(loader, "gcs");
}

static Value MapToStruct(const Value &map) {
	auto children = MapValue::GetChildren(map);

	child_list_t<Value> struct_fields;
	for (const auto &kv_child : children) {
		auto kv_pair = StructValue::GetChildren(kv_child);
		if (kv_pair.size() != 2) {
			throw InvalidInputException("Invalid input passed to refresh_info");
		}

		struct_fields.push_back({kv_pair[0].ToString(), kv_pair[1]});
	}
	return Value::STRUCT(struct_fields);
}
unique_ptr<BaseSecret> CreateS3SecretFunctions::CreateSecretFunctionInternal(ClientContext &context,
                                                                             CreateSecretInput &input) {
	// Set scope to user provided scope or the default
	auto scope = input.scope;
	if (scope.empty()) {
		if (input.type == "s3") {
			scope.push_back("s3://");
			scope.push_back("s3n://");
			scope.push_back("s3a://");
		} else if (input.type == "r2") {
			scope.push_back("r2://");
		} else if (input.type == "gcs") {
			scope.push_back("gcs://");
			scope.push_back("gs://");
		} else if (input.type == "aws") {
			scope.push_back("");
		} else {
			throw InternalException("Unknown secret type found in httpfs extension: '%s'", input.type);
		}
	}

	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	secret->redact_keys = {"secret", "session_token"};

	// for r2 we can set the endpoint using the account id
	if (input.type == "r2" && input.options.find("account_id") != input.options.end()) {
		secret->secret_map["endpoint"] = input.options["account_id"].ToString() + ".r2.cloudflarestorage.com";
		secret->secret_map["url_style"] = "path";
	}

	bool refresh = false;

	// apply any overridden settings
	for (const auto &named_param : input.options) {
		auto lower_name = StringUtil::Lower(named_param.first);

		if (lower_name == "key_id") {
			secret->secret_map["key_id"] = named_param.second;
		} else if (lower_name == "secret") {
			secret->secret_map["secret"] = named_param.second;
		} else if (lower_name == "region") {
			secret->secret_map["region"] = named_param.second.ToString();
		} else if (lower_name == "session_token") {
			secret->secret_map["session_token"] = named_param.second.ToString();
		} else if (lower_name == "endpoint") {
			secret->secret_map["endpoint"] = named_param.second.ToString();
		} else if (lower_name == "url_style") {
			secret->secret_map["url_style"] = named_param.second.ToString();
		} else if (lower_name == "use_ssl") {
			if (named_param.second.type() != LogicalType::BOOLEAN) {
				throw InvalidInputException("Invalid type past to secret option: '%s', found '%s', expected: 'BOOLEAN'",
				                            lower_name, named_param.second.type().ToString());
			}
			secret->secret_map["use_ssl"] = Value::BOOLEAN(named_param.second.GetValue<bool>());
		} else if (lower_name == "verify_ssl") {
			if (named_param.second.type() != LogicalType::BOOLEAN) {
				throw InvalidInputException("Invalid type past to secret option: '%s', found '%s', expected: 'BOOLEAN'",
				                            lower_name, named_param.second.type().ToString());
			}
			secret->secret_map["verify_ssl"] = Value::BOOLEAN(named_param.second.GetValue<bool>());
		} else if (lower_name == "kms_key_id") {
			secret->secret_map["kms_key_id"] = named_param.second.ToString();
		} else if (lower_name == "url_compatibility_mode") {
			if (named_param.second.type() != LogicalType::BOOLEAN) {
				throw InvalidInputException("Invalid type past to secret option: '%s', found '%s', expected: 'BOOLEAN'",
				                            lower_name, named_param.second.type().ToString());
			}
			secret->secret_map["url_compatibility_mode"] = Value::BOOLEAN(named_param.second.GetValue<bool>());
		} else if (lower_name == "account_id") {
			continue; // handled already
		} else if (lower_name == "refresh") {
			if (refresh) {
				throw InvalidInputException("Can not set `refresh` and `refresh_info` at the same time");
			}
			refresh = named_param.second.GetValue<string>() == "auto";
			secret->secret_map["refresh"] = Value("auto");
			child_list_t<Value> struct_fields;
			for (const auto &named_param : input.options) {
				auto lower_name = StringUtil::Lower(named_param.first);
				struct_fields.push_back({lower_name, named_param.second});
			}
			secret->secret_map["refresh_info"] = Value::STRUCT(struct_fields);
		} else if (lower_name == "refresh_info") {
			if (refresh) {
				throw InvalidInputException("Can not set `refresh` and `refresh_info` at the same time");
			}
			refresh = true;
			secret->secret_map["refresh_info"] = MapToStruct(named_param.second);
		} else if (lower_name == "requester_pays") {
			if (named_param.second.type() != LogicalType::BOOLEAN) {
				throw InvalidInputException("Invalid type past to secret option: '%s', found '%s', expected: 'BOOLEAN'",
				                            lower_name, named_param.second.type().ToString());
			}
			secret->secret_map["requester_pays"] = Value::BOOLEAN(named_param.second.GetValue<bool>());
		} else if (lower_name == "bearer_token" && input.type == "gcs") {
			secret->secret_map["bearer_token"] = named_param.second.ToString();
			// Mark it as sensitive
			secret->redact_keys.insert("bearer_token");
		} else if (lower_name == "http_proxy") {
			secret->secret_map["http_proxy"] = named_param.second;
		} else if (lower_name == "http_proxy_password") {
			secret->secret_map["http_proxy_password"] = named_param.second;
		} else if (lower_name == "http_proxy_username") {
			secret->secret_map["http_proxy_username"] = named_param.second;
		} else if (lower_name == "extra_http_headers") {
			secret->secret_map["extra_http_headers"] = named_param.second;
		} else {
			throw InvalidInputException("Unknown named parameter passed to CreateSecretFunctionInternal: " +
			                            lower_name);
		}
	}

	return std::move(secret);
}

CreateSecretInput CreateS3SecretFunctions::GenerateRefreshSecretInfo(const SecretEntry &secret_entry,
                                                                     Value &refresh_info) {
	const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(*secret_entry.secret);

	CreateSecretInput result;
	result.on_conflict = OnCreateConflict::REPLACE_ON_CONFLICT;
	result.persist_type = SecretPersistType::TEMPORARY;

	result.type = kv_secret.GetType();
	result.name = kv_secret.GetName();
	result.provider = kv_secret.GetProvider();
	result.storage_type = secret_entry.storage_mode;
	result.scope = kv_secret.GetScope();

	auto result_child_count = StructType::GetChildCount(refresh_info.type());
	auto refresh_info_children = StructValue::GetChildren(refresh_info);
	D_ASSERT(refresh_info_children.size() == result_child_count);
	for (idx_t i = 0; i < result_child_count; i++) {
		auto &key = StructType::GetChildName(refresh_info.type(), i);
		auto &value = refresh_info_children[i];
		result.options[key] = value;
	}

	return result;
}

//! Function that will automatically try to refresh a secret
bool CreateS3SecretFunctions::TryRefreshS3Secret(ClientContext &context, const SecretEntry &secret_to_refresh) {
	const auto &kv_secret = dynamic_cast<const KeyValueSecret &>(*secret_to_refresh.secret);

	Value refresh_info;
	if (!kv_secret.TryGetValue("refresh_info", refresh_info)) {
		return false;
	}
	auto &secret_manager = context.db->GetSecretManager();
	auto refresh_input = GenerateRefreshSecretInfo(secret_to_refresh, refresh_info);

	// TODO: change SecretManager API to avoid requiring catching this exception
	try {
		auto res = secret_manager.CreateSecret(context, refresh_input);
		auto &new_secret = dynamic_cast<const KeyValueSecret &>(*res->secret);
		DUCKDB_LOG_INFO(context, "Successfully refreshed secret: %s, new key_id: %s",
		                secret_to_refresh.secret->GetName(), new_secret.TryGetValue("key_id").ToString());
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

	if (type == "r2") {
		function.named_parameters["account_id"] = LogicalType::VARCHAR;
	}

	if (type == "gcs") {
		function.named_parameters["bearer_token"] = LogicalType::VARCHAR;
	}
}

void CreateS3SecretFunctions::RegisterCreateSecretFunction(ExtensionLoader &loader, string type) {
	// Register the new type
	SecretType secret_type;
	secret_type.name = type;
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";
	secret_type.extension = "httpfs";

	loader.RegisterSecretType(secret_type);

	CreateSecretFunction from_empty_config_fun2 = {type, "config", CreateS3SecretFromConfig};
	SetBaseNamedParams(from_empty_config_fun2, type);
	loader.RegisterFunction(from_empty_config_fun2);

	if (type == "gcs") {
		CreateSecretFunction credential_chain_fun = {type, "credential_chain", CreateGCSSecretFromCredentialChain};
		loader.RegisterFunction(credential_chain_fun);
	}
}

//
// Google Application Default Credentials (ADC) chain.
//
// Phase 1 supports two sources, in standard ADC order:
//   2. ~/.config/gcloud/application_default_credentials.json (developer laptops)
//   4. GCE metadata server (GCE/GKE/Cloud Run/Cloud Functions/Cloud Build)
//
// Sources 1 (service-account JSON key, requires JWT signing) and 3 (workload
// identity federation) are not yet implemented.
//
// Each source returns AdcSourceResult{token, error}:
//   - token non-empty: success, use this token
//   - token empty + error empty: source not applicable (try next)
//   - token empty + error non-empty: source attempted but failed (record and try next)
//
// JSON parsing here uses crude string extraction. Sufficient for the
// well-formed output of gcloud and the Google token endpoint, but should be
// replaced with yyjson before merging upstream.
//

namespace {
struct AdcSourceResult {
	string token;
	string error;
};
} // namespace

static string ExtractJsonString(const string &json, const string &key) {
	string needle = "\"" + key + "\"";
	auto pos = json.find(needle);
	if (pos == string::npos) {
		throw IOException("Field '%s' not found in JSON", key);
	}
	pos = json.find('"', pos + needle.size());
	if (pos == string::npos) {
		throw IOException("Malformed JSON near '%s'", key);
	}
	auto end = json.find('"', pos + 1);
	if (end == string::npos) {
		throw IOException("Unterminated string for '%s'", key);
	}
	return json.substr(pos + 1, end - pos - 1);
}

static string UrlEncode(const string &s) {
	string out;
	out.reserve(s.size());
	for (unsigned char c : s) {
		if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			out += (char)c;
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%%%02X", c);
			out += buf;
		}
	}
	return out;
}

// Source 2: gcloud user credentials.
// Reads ~/.config/gcloud/application_default_credentials.json, exchanges the
// refresh token at oauth2.googleapis.com/token for a 1h access token.
static AdcSourceResult TryFetchTokenFromGcloudUserCreds(ClientContext &context) {
	AdcSourceResult result;
	const char *home = std::getenv("HOME");
	if (!home) {
		return result; // not applicable
	}
	string adc_path = string(home) + "/.config/gcloud/application_default_credentials.json";

	LocalFileSystem fs;
	if (!fs.FileExists(adc_path)) {
		return result; // not applicable — chain falls through silently
	}

	try {
		auto handle = fs.OpenFile(adc_path, {FileOpenFlags::FILE_FLAGS_READ});
		auto file_size = fs.GetFileSize(*handle);
		string adc(file_size, '\0');
		fs.Read(*handle, (void *)adc.data(), file_size);

		string client_id = ExtractJsonString(adc, "client_id");
		string client_secret = ExtractJsonString(adc, "client_secret");
		string refresh_token = ExtractJsonString(adc, "refresh_token");

		string body = "client_id=" + UrlEncode(client_id) + "&client_secret=" + UrlEncode(client_secret) +
		              "&refresh_token=" + UrlEncode(refresh_token) + "&grant_type=refresh_token";

		string url = "https://oauth2.googleapis.com/token";
		auto &http_util = HTTPUtil::Get(*context.db);
		auto http_params = http_util.InitializeParameters(context, url);
		HTTPHeaders headers;
		headers["Content-Type"] = "application/x-www-form-urlencoded";
		PostRequestInfo post_request(url, headers, *http_params, const_data_ptr_cast(body.data()), body.size());
		auto response = http_util.Request(post_request);

		if (!response->Success()) {
			result.error = StringUtil::Format("token endpoint returned status %d: %s", (int)response->status,
			                                  post_request.buffer_out);
			return result;
		}
		result.token = ExtractJsonString(post_request.buffer_out, "access_token");
	} catch (std::exception &e) {
		result.error = e.what();
	}
	return result;
}

// Source 4: GCE/GKE/Cloud Run/Cloud Functions metadata server.
// HTTP GET against the link-local metadata service with the required
// `Metadata-Flavor: Google` header. Short timeout so non-GCE hosts fail fast
// rather than hanging the user's CREATE SECRET.
static AdcSourceResult TryFetchTokenFromMetadataServer(ClientContext &context) {
	AdcSourceResult result;
	string url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

	try {
		auto &http_util = HTTPUtil::Get(*context.db);
		auto http_params = http_util.InitializeParameters(context, url);
		http_params->timeout = 2; // seconds — don't hang on non-GCE hosts

		HTTPHeaders headers;
		headers["Metadata-Flavor"] = "Google";

		string body;
		GetRequestInfo get_request(
		    url, headers, *http_params, [](const HTTPResponse &) -> bool { return true; },
		    [&](const_data_ptr_t data, idx_t data_length) -> bool {
			    body.append(const_char_ptr_cast(data), data_length);
			    return true;
		    });
		auto response = http_util.Request(get_request);

		if (!response->Success()) {
			// Network error / DNS failure / refused = not on GCE. Silently skip.
			if (response->HasRequestError()) {
				return result;
			}
			// HTTP-level error (e.g. 403, 500): we reached the server but were rejected.
			// Surface as an error so users on GCE see what went wrong.
			result.error = StringUtil::Format("metadata server returned status %d", (int)response->status);
			return result;
		}
		result.token = ExtractJsonString(body, "access_token");
	} catch (std::exception &e) {
		// Network/DNS exceptions = not on GCE. Silently skip.
	}
	return result;
}

unique_ptr<BaseSecret> CreateS3SecretFunctions::CreateGCSSecretFromCredentialChain(ClientContext &context,
                                                                                   CreateSecretInput &input) {
	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("gcs://");
		scope.push_back("gs://");
	}

	string error_summary;
	string token;

	auto try_source = [&](const string &name, const std::function<AdcSourceResult()> &fn) -> bool {
		auto result = fn();
		if (!result.token.empty()) {
			token = std::move(result.token);
			return true;
		}
		if (!result.error.empty()) {
			error_summary += "  - " + name + ": " + result.error + "\n";
		}
		return false;
	};

	if (!try_source("gcloud user credentials", [&] { return TryFetchTokenFromGcloudUserCreds(context); })) {
		try_source("GCE metadata server", [&] { return TryFetchTokenFromMetadataServer(context); });
	}

	if (token.empty()) {
		string detail = error_summary.empty() ? "  (no source was applicable)\n" : error_summary;
		throw IOException(
		    "Could not obtain a Google ADC access token for GCS. Tried the following sources:\n" + detail +
		    "\nTo configure ADC: run `gcloud auth application-default login` for laptop dev, "
		    "or run on a GCE/GKE/Cloud Run instance with an attached service account.");
	}

	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	secret->secret_map["bearer_token"] = token;

	// Enable the existing httpfs refresh hook (s3fs.cpp:737) so a 401 on a
	// subsequent file open re-invokes this function and yields a fresh token.
	// Addresses two practical cases:
	//   1. Persistent secret used in a new session after the access token has
	//      expired (~1h). Loaded token is dead → first open 401s → refresh
	//      fires → new token → retry succeeds.
	//   2. Long-running session that opens a new file after expiry — same path.
	// What this does NOT address: mid-stream 401 during a single file read,
	// and proactive refresh (no 401 ever fired). Those are deferred.
	secret->secret_map["refresh"] = Value("auto");
	child_list_t<Value> refresh_fields;
	for (const auto &named_param : input.options) {
		refresh_fields.push_back({StringUtil::Lower(named_param.first), named_param.second});
	}
	if (refresh_fields.empty()) {
		// Value::STRUCT requires at least one field; carry a marker that our
		// function happily ignores on the recreate call.
		refresh_fields.push_back({"_provider", Value("credential_chain")});
	}
	secret->secret_map["refresh_info"] = Value::STRUCT(refresh_fields);

	secret->redact_keys = {"bearer_token"};
	return std::move(secret);
}

void CreateBearerTokenFunctions::Register(ExtensionLoader &loader) {
	// HuggingFace secret
	SecretType secret_type_hf;
	secret_type_hf.name = HUGGINGFACE_TYPE;
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

static string TryReadTokenFile(const string &token_path, const string error_source_message,
                               bool fail_on_exception = true) {
	try {
		LocalFileSystem fs;
		auto handle = fs.OpenFile(token_path, {FileOpenFlags::FILE_FLAGS_READ});
		return handle->ReadLine();
	} catch (std::exception &ex) {
		if (!fail_on_exception) {
			return "";
		}
		ErrorData error(ex);
		throw IOException("Failed to read token path '%s'%s. (error: %s)", token_path, error_source_message,
		                  error.RawMessage());
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
		auto token = TryReadTokenFile(hf_token_path_env, " fetched from HF_TOKEN_PATH env variable");
		return CreateSecretFunctionInternal(context, input, token);
	}

	// Step 3: Try the path $HF_HOME/token
	const char *hf_home_env = std::getenv("HF_HOME");
	if (hf_home_env) {
		auto token_path = LocalFileSystem().JoinPath(hf_home_env, "token");
		auto token = TryReadTokenFile(token_path, " constructed using the HF_HOME variable: '$HF_HOME/token'");
		return CreateSecretFunctionInternal(context, input, token);
	}

	// Step 4: Check the default path
	auto token = TryReadTokenFile("~/.cache/huggingface/token", "", false);
	return CreateSecretFunctionInternal(context, input, token);
}
} // namespace duckdb
