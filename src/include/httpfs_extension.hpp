#pragma once

#include "duckdb.hpp"

namespace duckdb {

class HttpfsExtension : public Extension {
public:
	void Load(ExtensionLoader &loader) override;
	string Name() override;
	string Version() const override;
};

} // namespace duckdb
