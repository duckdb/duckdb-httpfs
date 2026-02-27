#pragma once

#include "httpfs.hpp"

namespace duckdb {

struct ParsedHFUrl {
	//! Path within the
	string path;
	//! Name of the repo (i presume)
	string repository;

	//! Endpoint, defaults to HF
	string endpoint = "https://huggingface.co";
	//! Which revision/branch/tag to use
	string revision = "main";
	//! For DuckDB this may be a sensible default?
	string repo_type = "datasets";
};

class HuggingFaceFileSystem : public HTTPFileSystem {
public:
	~HuggingFaceFileSystem() override;

	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener = nullptr) override;

	duckdb::unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, string hf_url, HTTPHeaders header_map) override;
	duckdb::unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string hf_url, HTTPHeaders header_map) override;
	duckdb::unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string hf_url, HTTPHeaders header_map,
	                                                 idx_t file_offset, char *buffer_out,
	                                                 idx_t buffer_out_len) override;

	bool CanHandleFile(const string &fpath) override {
		return fpath.rfind("hf://", 0) == 0;
	};

	string GetName() const override {
		return "HuggingFaceFileSystem";
	}
	static ParsedHFUrl HFUrlParse(const string &url);
	string GetHFUrl(const ParsedHFUrl &url);
	string GetTreeUrl(const ParsedHFUrl &url, idx_t limit);
	string GetFileUrl(const ParsedHFUrl &url);

	static void SetParams(HTTPFSParams &params, const string &path, optional_ptr<FileOpener> opener);

protected:
	duckdb::unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                                optional_ptr<FileOpener> opener) override;

	string ListHFRequest(ParsedHFUrl &url, HTTPFSParams &http_params, string &next_page_url,
	                     optional_ptr<HTTPState> state);
};

class HFFileHandle : public HTTPFileHandle {
	friend class HuggingFaceFileSystem;

public:
	HFFileHandle(FileSystem &fs, ParsedHFUrl hf_url, const OpenFileInfo &file, FileOpenFlags flags,
	             unique_ptr<HTTPParams> http_params)
	    : HTTPFileHandle(fs, file, flags, std::move(http_params)), parsed_url(std::move(hf_url)) {
	}
	~HFFileHandle() override;

	string BaseUrl() const override;

protected:
	ParsedHFUrl parsed_url;
};

} // namespace duckdb
