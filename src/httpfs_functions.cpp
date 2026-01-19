#include "httpfs_functions.hpp"
#include "s3fs.hpp"
#include "include/httpfs_functions.hpp"

#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/function/cast/cast_function_set.hpp"
#include "duckdb/function/cast/default_casts.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/parser/expression/function_expression.hpp"

class ExtensionLoader;

namespace duckdb {

struct InheritFromConfigGlobalFunctionStatsGlobalState : public GlobalTableFunctionState {
	InheritFromConfigGlobalFunctionStatsGlobalState() : GlobalTableFunctionState(), finished(false) {
	}

public:
	static unique_ptr<GlobalTableFunctionState> Init(ClientContext &context, TableFunctionInitInput &input) {
		auto global_state = make_uniq<InheritFromConfigGlobalFunctionStatsGlobalState>();
		return global_state;
	}
	bool finished;
};

static unique_ptr<FunctionData> HttpfsInheritS3ConfigFromEnvBind(ClientContext &context, TableFunctionBindInput &input,
                                                                 vector<LogicalType> &return_types,
                                                                 vector<string> &names) {
	names.emplace_back("environment_variable_name");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("config_key");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("config_value");
	return_types.emplace_back(LogicalType::VARCHAR);

	return nullptr;
}

// inherit from config function
static void HttpfsInheritS3ConfigFromEnv(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &global_state = data.global_state->Cast<InheritFromConfigGlobalFunctionStatsGlobalState>();
	if (global_state.finished) {
		return;
	}
	D_ASSERT(context.db);
	auto provider = make_uniq<AWSEnvironmentCredentialsProvider>(context.db->config);
	auto set_vals = provider->SetAll();
	idx_t i = 0;
	for (auto &name : set_vals) {
		string_t env_var_string = StringVector::AddString(output.data[0], string_t(name.env_var_name));
		FlatVector::GetData<string_t>(output.data[0])[i] = env_var_string;
		string_t key_string = StringVector::AddString(output.data[1], string_t(name.config_name));
		FlatVector::GetData<string_t>(output.data[1])[i] = key_string;
		string_t value_string = StringVector::AddString(output.data[2], string_t(name.value));
		FlatVector::GetData<string_t>(output.data[2])[i] = value_string;
		++i;
	}
	output.SetCardinality(i);
	global_state.finished = true;
}

vector<TableFunctionSet> HttpfsFunctions::GetTableFunctions(ExtensionLoader &loader) {
	vector<TableFunctionSet> functions;
	TableFunctionSet inherit_aws_config("inherit_aws_config_from_environment");
	TableFunction table_function({}, HttpfsInheritS3ConfigFromEnv, HttpfsInheritS3ConfigFromEnvBind,
	                             InheritFromConfigGlobalFunctionStatsGlobalState::Init);

	inherit_aws_config.AddFunction(table_function);
	functions.emplace_back(inherit_aws_config);
	return functions;
}

} // namespace duckdb
