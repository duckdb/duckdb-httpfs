#pragma once

#include "http/httpfs.hpp"

namespace duckdb {

struct ParsedHFUrl {
	//! Repository coordinates
	string repo_type = "datasets";
	string repository;
	string revision = "main";

	//! Request routing
	string endpoint = "https://huggingface.co";
	string path;
};

class HuggingFaceFileSystem : public HTTPFileSystem {
public:
	~HuggingFaceFileSystem() override;

public:
	//! FileSystem overrides
	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener = nullptr) override;
	bool CanHandleFile(const string &fpath) override {
		return fpath.rfind("hf://", 0) == 0;
	}
	string GetName() const override {
		return "HuggingFaceFileSystem";
	}

	//! HTTP request overrides
	unique_ptr<HTTPResponse> HeadRequest(FileHandle &handle, const string &hf_url, HTTPHeaders header_map) override;
	unique_ptr<HTTPResponse> GetRequest(FileHandle &handle, string hf_url, HTTPHeaders header_map,
	                                    const HTTPReadConfig &read_config, CachedFileDownload &download) override;
	unique_ptr<HTTPResponse> GetRangeRequest(FileHandle &handle, string hf_url, HTTPHeaders header_map,
	                                         const HTTPReadConfig &read_config, idx_t file_offset,
	                                         data_ptr_t buffer_out, idx_t buffer_out_len) override;

	//! List response parsing
	static void ParseListResult(const string &input, vector<string> &files, vector<string> &directories);

protected:
	unique_ptr<HTTPFileHandle> CreateHandle(const OpenFileInfo &file, FileOpenFlags flags,
	                                        optional_ptr<FileOpener> opener) override;

	static string ListHFRequest(const ParsedHFUrl &url, HTTPFSParams &http_params, string &next_page_url);

private:
	static ParsedHFUrl HFUrlParse(const string &url);
	static string GetHFUrl(const ParsedHFUrl &url);
	static string GetTreeUrl(const ParsedHFUrl &url, idx_t limit);
	static string GetFileUrl(const ParsedHFUrl &url);
	static void SetParams(HTTPFSParams &params, const string &path, optional_ptr<FileOpener> opener);
};

class HFFileHandle : public HTTPFileHandle {
	friend class HuggingFaceFileSystem;

public:
	HFFileHandle(FileSystem &fs, ParsedHFUrl hf_url, const OpenFileInfo &file, FileOpenFlags flags,
	             unique_ptr<HTTPParams> http_params)
	    : HTTPFileHandle(fs, file, flags, std::move(http_params)), parsed_url(std::move(hf_url)) {
	}
	~HFFileHandle() override;

private:
	ParsedHFUrl parsed_url;
};

} // namespace duckdb
