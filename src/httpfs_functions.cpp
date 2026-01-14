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

struct InheritFromConfigGlobalFunctionStats : public GlobalTableFunctionState {
public:
	static unique_ptr<GlobalTableFunctionState> Init(ClientContext &context, TableFunctionInitInput &input) {}
}

static unique_ptr<FunctionData> HttpfsInheritS3ConfigFromEnvBind(ClientContext &context, TableFunctionBindInput &input,
                                                                 vector<LogicalType> &return_types,
                                                                 vector<string> &names) {
	names.emplace_back("key");
	return_types.emplace_back(LogicalType::VARCHAR);

	names.emplace_back("value");
	return_types.emplace_back(LogicalType::VARCHAR);

	return nullptr;
}

// inherit from config function
static void HttpfsInheritS3ConfigFromEnv(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &config = context.db->config;
	auto provider = make_uniq<AWSEnvironmentCredentialsProvider>(config);
	auto set_vals = provider->SetAll();
	idx_t i = 0;
	for (auto &name : set_vals) {
		string_t key_string = StringVector::AddString(output.data[0], string_t(name.first));
		FlatVector::GetData<string_t>(output.data[0])[i] = key_string;
		string_t value_string = StringVector::AddString(output.data[1], string_t(name.second));
		FlatVector::GetData<string_t>(output.data[1])[i] = value_string;
		++i;
	}
	output.SetCardinality(i);
	auto break_here = 0;
}

vector<TableFunctionSet> HttpfsFunctions::GetTableFunctions(ExtensionLoader &loader) {
	vector<TableFunctionSet> functions;
	TableFunctionSet inherit_aws_config("inherit_aws_config_from_environment");
	TableFunction table_function({}, HttpfsInheritS3ConfigFromEnv, HttpfsInheritS3ConfigFromEnvBind);

	inherit_aws_config.AddFunction(table_function);
	functions.emplace_back(inherit_aws_config);
	return functions;
}

} // namespace duckdb
