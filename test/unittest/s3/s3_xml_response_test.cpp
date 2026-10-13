#include "catch.hpp"

#include "s3/s3_list.hpp"
#include "s3/s3_xml_response.hpp"

namespace duckdb {

TEST_CASE("S3 XML responses follow text and namespace semantics", "[httpfs][s3][xml]") {
	SECTION("predefined and numeric entities are decoded") {
		const string input = "<InitiateMultipartUploadResult><UploadId>opaque&amp;&#38;&#x1F642;</UploadId>"
		                     "</InitiateMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_INITIALIZATION);
		CHECK(response.upload_id == string("opaque&&") + "\xF0\x9F\x99\x82");
	}
	SECTION("direct UTF-8 text is preserved") {
		const string input = "<InitiateMultipartUploadResult><UploadId>opaque-\xF0\x9F\x99\x82</UploadId>"
		                     "</InitiateMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_INITIALIZATION);
		CHECK(response.upload_id == string("opaque-") + "\xF0\x9F\x99\x82");
	}
	SECTION("namespace prefixes are resolved") {
		const string input = "<s3:InitiateMultipartUploadResult xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
		                     "<s3:UploadId>opaque-id</s3:UploadId></s3:InitiateMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_INITIALIZATION);
		CHECK(response.upload_id == "opaque-id");
	}
	SECTION("unknown default namespaces are accepted") {
		const string input = "<InitiateMultipartUploadResult xmlns=\"urn:example:storage\">"
		                     "<UploadId>native-id</UploadId></InitiateMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_INITIALIZATION);
		CHECK(response.upload_id == "native-id");
	}
	SECTION("unknown prefixed namespaces are accepted") {
		const string input = "<native:CompleteMultipartUploadResult xmlns:native=\"urn:example:storage\">"
		                     "<native:ETag>native-etag</native:ETag></native:CompleteMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_COMPLETION);
		CHECK(response.etag == "native-etag");
	}
	SECTION("default namespaces are inherited") {
		const string input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		                     "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
		                     "<ETag>&quot;etag&quot;</ETag></CompleteMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_COMPLETION);
		CHECK(response.etag == "\"etag\"");
	}
	SECTION("default namespaces do not apply to unprefixed attributes") {
		const string input =
		    "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\" "
		    "xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\" value=\"plain\" s3:value=\"namespaced\">"
		    "<ETag>etag</ETag></CompleteMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::MULTIPART_COMPLETION);
		CHECK(response.etag == "etag");
	}
	SECTION("comments and CDATA contribute text") {
		const string input = "<Error><!-- ignored --><Code><![CDATA[InternalError]]></Code>"
		                     "<Message>failed<!-- ignored --> safely</Message></Error>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		REQUIRE(response.type == S3XMLResponseType::ERROR);
		CHECK(response.error_code == "InternalError");
		CHECK(response.error_message == "failed safely");
	}
	SECTION("a UTF-8 BOM is accepted") {
		const string input = "\xEF\xBB\xBF<CompleteMultipartUploadResult><ETag>etag</ETag>"
		                     "</CompleteMultipartUploadResult>";
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		CHECK(response.type == S3XMLResponseType::MULTIPART_COMPLETION);
	}
}

TEST_CASE("S3 XML responses reject malformed XML", "[httpfs][s3][xml]") {
	for (const auto &input :
	     {"<CompleteMultipartUploadResult invalid><ETag>etag</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult attr=value><ETag>etag</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag>etag & broken</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag>&custom;</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag>&#0;</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag>&#xD800;</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag>&#x110000;</ETag></CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult duplicate=\"a\" duplicate=\"b\"><ETag>etag</ETag>"
	      "</CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult xmlns:a=\"urn:attribute\" xmlns:b=\"urn:attribute\" a:value=\"one\" "
	      "b:value=\"two\"><ETag>etag</ETag></CompleteMultipartUploadResult>",
	      "<s3:CompleteMultipartUploadResult><s3:ETag>etag</s3:ETag></s3:CompleteMultipartUploadResult>",
	      "<s3:CompleteMultipartUploadResult xmlns:s3=\"\"><s3:ETag>etag</s3:ETag>"
	      "</s3:CompleteMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag>etag</CompleteMultipartUploadResult></ETag>",
	      "<CompleteMultipartUploadResult/><OtherRoot/>",
	      "<!DOCTYPE CompleteMultipartUploadResult><CompleteMultipartUploadResult/>",
	      "<?other value?><CompleteMultipartUploadResult/>",
	      "<?xml version=\"1.0\"encoding=\"UTF-8\"?><CompleteMultipartUploadResult/>",
	      "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><CompleteMultipartUploadResult/>"}) {
		S3XMLResponse response;
		CHECK_FALSE(S3XMLResponseParser::TryParse(input, response));
	}

	SECTION("invalid UTF-8 is rejected") {
		string input = "<CompleteMultipartUploadResult><ETag>";
		input.push_back(static_cast<char>(0xFF));
		input += "</ETag></CompleteMultipartUploadResult>";
		S3XMLResponse response;
		CHECK_FALSE(S3XMLResponseParser::TryParse(input, response));
	}
	SECTION("literal forbidden XML characters are rejected") {
		string input = "<CompleteMultipartUploadResult><ETag>";
		input.push_back(static_cast<char>(0x01));
		input += "</ETag></CompleteMultipartUploadResult>";
		S3XMLResponse response;
		CHECK_FALSE(S3XMLResponseParser::TryParse(input, response));
	}
	SECTION("excessive nesting is rejected before building a recursive tree") {
		string input = "<CompleteMultipartUploadResult>";
		for (idx_t depth = 0; depth < 256; depth++) {
			input += "<Unknown>";
		}
		for (idx_t depth = 0; depth < 256; depth++) {
			input += "</Unknown>";
		}
		input += "</CompleteMultipartUploadResult>";
		S3XMLResponse response;
		CHECK_FALSE(S3XMLResponseParser::TryParse(input, response));
	}
}

TEST_CASE("S3 XML success responses require the expected contract", "[httpfs][s3][xml]") {
	for (const auto &input :
	     {"<InitiateMultipartUploadResult><Wrapper><UploadId>nested</UploadId></Wrapper>"
	      "</InitiateMultipartUploadResult>",
	      "<InitiateMultipartUploadResult><UploadId>first</UploadId><UploadId>second</UploadId>"
	      "</InitiateMultipartUploadResult>",
	      "<InitiateMultipartUploadResult><UploadId>before<Nested/>after</UploadId>"
	      "</InitiateMultipartUploadResult>",
	      "<CompleteMultipartUploadResult><ETag/></CompleteMultipartUploadResult>", "<UnexpectedMultipartResponse/>"}) {
		S3XMLResponse response;
		REQUIRE(S3XMLResponseParser::TryParse(input, response));
		CHECK(response.type == S3XMLResponseType::UNKNOWN);
	}

	SECTION("required fields must use the root namespace") {
		for (const auto &input :
		     {"<native:InitiateMultipartUploadResult xmlns:native=\"urn:native\" xmlns:foreign=\"urn:foreign\">"
		      "<foreign:UploadId>foreign-id</foreign:UploadId></native:InitiateMultipartUploadResult>",
		      "<native:CompleteMultipartUploadResult xmlns:native=\"urn:native\" xmlns:foreign=\"urn:foreign\">"
		      "<foreign:ETag>foreign-etag</foreign:ETag></native:CompleteMultipartUploadResult>",
		      "<native:InitiateMultipartUploadResult xmlns:native=\"urn:native\">"
		      "<native:UploadId xmlns:native=\"urn:foreign\">rebound</native:UploadId>"
		      "</native:InitiateMultipartUploadResult>"}) {
			S3XMLResponse response;
			REQUIRE(S3XMLResponseParser::TryParse(input, response));
			CHECK(response.type == S3XMLResponseType::UNKNOWN);
		}
	}
}

TEST_CASE("S3 XML errors are extracted without guessing malformed bodies", "[httpfs][s3][xml]") {
	SECTION("all supported details are decoded") {
		S3XMLError error;
		REQUIRE(S3XMLResponseParser::TryParseError(
		    "<Error><Code>InvalidAccessKeyId</Code><Message>bad &amp; expired</Message>"
		    "<AWSAccessKeyId>redacted-id</AWSAccessKeyId></Error>",
		    error));
		CHECK(error.code == "InvalidAccessKeyId");
		CHECK(error.message == "bad & expired");
		CHECK(error.access_key_id == "redacted-id");
	}
	SECTION("code-only errors remain classifiable") {
		S3XMLError error;
		REQUIRE(S3XMLResponseParser::TryParseError("<Error><Code>RequestTimeout</Code></Error>", error));
		CHECK(error.code == "RequestTimeout");
		CHECK(error.message.empty());
	}
	SECTION("unknown namespaces retain optional and duplicate field handling") {
		S3XMLError missing_code;
		REQUIRE(S3XMLResponseParser::TryParseError(
		    "<Error xmlns=\"urn:example:storage\"><Message>missing code</Message></Error>", missing_code));
		CHECK(missing_code.code.empty());
		CHECK(missing_code.message == "missing code");

		S3XMLError duplicate_code;
		REQUIRE(S3XMLResponseParser::TryParseError(
		    "<native:Error xmlns:native=\"urn:example:storage\"><native:Code>first</native:Code>"
		    "<native:Code>second</native:Code><native:Message>kept</native:Message></native:Error>",
		    duplicate_code));
		CHECK(duplicate_code.code.empty());
		CHECK(duplicate_code.message == "kept");

		S3XMLError foreign_code;
		REQUIRE(S3XMLResponseParser::TryParseError(
		    "<native:Error xmlns:native=\"urn:example:storage\" xmlns:foreign=\"urn:foreign\">"
		    "<foreign:Code>ignored</foreign:Code><native:Message>native</native:Message></native:Error>",
		    foreign_code));
		CHECK(foreign_code.code.empty());
		CHECK(foreign_code.message == "native");
	}
	SECTION("malformed and unrelated XML are not errors") {
		S3XMLError error;
		CHECK_FALSE(S3XMLResponseParser::TryParseError("<Error><Code>RequestTimeout", error));
		CHECK_FALSE(S3XMLResponseParser::TryParseError("<Unexpected/>", error));
	}
}

TEST_CASE("S3 ListObjectsV2 XML is parsed into one typed result", "[httpfs][s3][xml]") {
	SECTION("supported namespaces and XML text forms are accepted") {
		for (const auto &input : {"<ListBucketResult><Contents><Key>plain</Key></Contents></ListBucketResult>",
		                          "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
		                          "<Contents><Key>aws</Key></Contents></ListBucketResult>",
		                          "<ListBucketResult xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\">"
		                          "<Contents><Key>gcs-s3</Key></Contents></ListBucketResult>",
		                          "<ListBucketResult xmlns=\"http://doc.storage.googleapis.com/2010-03-01\">"
		                          "<Contents><Key>gcs-storage</Key></Contents></ListBucketResult>"}) {
			S3ListObjectsV2Result result;
			REQUIRE(S3XMLResponseParser::TryParseListObjectsV2(input, result));
			REQUIRE(result.objects.size() == 1);
			CHECK_FALSE(result.objects[0].key.empty());
		}

		const string input =
		    "\xEF\xBB\xBF<g:ListBucketResult xmlns:g=\"http://doc.storage.googleapis.com/2010-03-01\">"
		    "<!-- page --><g:Contents><g:Key>first&amp;key</g:Key><g:LastModified><![CDATA[2026-01-02T03:04:05Z]]>"
		    "</g:LastModified><g:ETag>&quot;etag&quot;</g:ETag><g:Size>42</g:Size><g:Unknown>ignored</g:Unknown>"
		    "</g:Contents><g:Contents><g:Key>second</g:Key></g:Contents>"
		    "<g:CommonPrefixes><g:Prefix/></g:CommonPrefixes>"
		    "<g:CommonPrefixes><g:Prefix>directory%2F</g:Prefix></g:CommonPrefixes>"
		    "<g:NextContinuationToken>next&amp;token</g:NextContinuationToken></g:ListBucketResult>";
		S3ListObjectsV2Result result;
		REQUIRE(S3XMLResponseParser::TryParseListObjectsV2(input, result));
		REQUIRE(result.objects.size() == 2);
		CHECK(result.objects[0].key == "first&key");
		CHECK(result.objects[0].last_modified == "2026-01-02T03:04:05Z");
		CHECK(result.objects[0].etag == "\"etag\"");
		CHECK(result.objects[0].size == "42");
		CHECK(result.objects[1].key == "second");
		CHECK(result.objects[1].last_modified.empty());
		REQUIRE(result.common_prefixes.size() == 1);
		CHECK(result.common_prefixes[0] == "directory%2F");
		CHECK(result.continuation_token == "next&token");
	}

	SECTION("only children in the root namespace are interpreted") {
		const string input = "<s3:ListBucketResult xmlns:s3=\"urn:example:storage\" xmlns:x=\"urn:x\">"
		                     "<x:Contents><x:Key>ignored</x:Key></x:Contents>"
		                     "<s3:Contents><x:Key>also-ignored</x:Key><s3:Key>kept</s3:Key></s3:Contents>"
		                     "<s3:Unknown><s3:Key>not-a-record</s3:Key></s3:Unknown></s3:ListBucketResult>";
		S3ListObjectsV2Result result;
		REQUIRE(S3XMLResponseParser::TryParseListObjectsV2(input, result));
		REQUIRE(result.objects.size() == 1);
		CHECK(result.objects[0].key == "kept");
	}

	SECTION("required and singleton fields are enforced") {
		for (const auto &input :
		     {"<ListBucketResult><Contents/></ListBucketResult>",
		      "<ListBucketResult><Contents><Key/></Contents></ListBucketResult>",
		      "<ListBucketResult><Contents><Key>one</Key><Key>two</Key></Contents></ListBucketResult>",
		      "<ListBucketResult><Contents><Key><Nested/></Key></Contents></ListBucketResult>",
		      "<ListBucketResult><Contents><Key>one</Key><Size>1</Size><Size>2</Size></Contents></ListBucketResult>",
		      "<native:ListBucketResult xmlns:native=\"urn:native\" xmlns:foreign=\"urn:foreign\">"
		      "<native:Contents><foreign:Key>foreign</foreign:Key></native:Contents>"
		      "</native:ListBucketResult>",
		      "<ListBucketResult><NextContinuationToken>one</NextContinuationToken>"
		      "<NextContinuationToken>two</NextContinuationToken></ListBucketResult>",
		      "<ListBucketResult><Contents><Key>truncated</Key></Contents>"}) {
			S3ListObjectsV2Result result;
			CHECK_FALSE(S3XMLResponseParser::TryParseListObjectsV2(input, result));
		}
	}

	SECTION("invalid typed metadata becomes a contextual I/O error") {
		S3ListObjectsV2Result response;
		response.objects.push_back({"key", string(), string(), "not-a-size"});
		vector<OpenFileInfo> files;
		try {
			AWSListObjectV2::AppendFileList(response, files);
			FAIL("Expected malformed metadata to fail");
		} catch (const IOException &exception) {
			CHECK(string(exception.what()).find("Malformed S3 list response") != string::npos);
		}
	}
}

TEST_CASE("S3 DeleteObjects XML preserves all object errors", "[httpfs][s3][xml]") {
	SECTION("quiet success and repeated errors are supported") {
		S3DeleteObjectsResult result;
		REQUIRE(S3XMLResponseParser::TryParseDeleteObjects(
		    "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>", result));
		CHECK(result.errors.empty());
		REQUIRE(S3XMLResponseParser::TryParseDeleteObjects("<DeleteResult xmlns=\"urn:example:storage\"/>", result));
		CHECK(result.errors.empty());

		const string input = "<g:DeleteResult xmlns:g=\"http://doc.s3.amazonaws.com/2006-03-01\">"
		                     "<g:Error><g:Key>first&amp;key</g:Key><g:Code>AccessDenied</g:Code>"
		                     "<g:Message><![CDATA[not allowed]]></g:Message></g:Error>"
		                     "<g:Error><g:Key>second</g:Key><g:Code>InternalError</g:Code></g:Error>"
		                     "<g:Unknown>ignored</g:Unknown></g:DeleteResult>";
		REQUIRE(S3XMLResponseParser::TryParseDeleteObjects(input, result));
		REQUIRE(result.errors.size() == 2);
		CHECK(result.errors[0].key == "first&key");
		CHECK(result.errors[0].code == "AccessDenied");
		CHECK(result.errors[0].message == "not allowed");
		CHECK(result.errors[1].key == "second");
		CHECK(result.errors[1].code == "InternalError");
		CHECK(result.errors[1].message.empty());

		const string native_input =
		    "<native:DeleteResult xmlns:native=\"urn:example:storage\">"
		    "<native:Error><native:Key>native-key</native:Key><native:Code>AccessDenied</native:Code>"
		    "</native:Error></native:DeleteResult>";
		REQUIRE(S3XMLResponseParser::TryParseDeleteObjects(native_input, result));
		REQUIRE(result.errors.size() == 1);
		CHECK(result.errors[0].key == "native-key");
	}

	SECTION("required fields and malformed documents are rejected") {
		for (const auto &input : {"<DeleteResult><Error><Code>AccessDenied</Code></Error></DeleteResult>",
		                          "<DeleteResult><Error><Key>key</Key></Error></DeleteResult>",
		                          "<DeleteResult><Error><Key/><Code>AccessDenied</Code></Error></DeleteResult>",
		                          "<DeleteResult><Error><Key>key</Key><Code/></Error></DeleteResult>",
		                          "<DeleteResult><Error><Key>key</Key><Key>other</Key><Code>Denied</Code></Error>"
		                          "</DeleteResult>",
		                          "<native:DeleteResult xmlns:native=\"urn:native\" xmlns:foreign=\"urn:foreign\">"
		                          "<native:Error><foreign:Key>key</foreign:Key><native:Code>Denied</native:Code>"
		                          "</native:Error></native:DeleteResult>",
		                          "<DeleteResult><Error><Key>key</Key><Code>Denied</Code>"}) {
			S3DeleteObjectsResult result;
			CHECK_FALSE(S3XMLResponseParser::TryParseDeleteObjects(input, result));
		}
	}
}

TEST_CASE("S3 XML writers escape server-controlled text", "[httpfs][s3][xml]") {
	const string special = "key&<>\r'\"";
	const auto escaped = S3XMLWriter::EscapeText(special);
	CHECK(escaped == "key&amp;&lt;&gt;&#13;'\"");

	const auto delete_body = S3XMLWriter::WriteDeleteObjectsRequest({special, "plain"}, 0, 2);
	CHECK(delete_body == "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	                     "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
	                     "<Object><Key>key&amp;&lt;&gt;&#13;'\"</Key></Object>"
	                     "<Object><Key>plain</Key></Object><Quiet>true</Quiet></Delete>");

	const auto completion_body = S3XMLWriter::WriteCompleteMultipartUploadRequest({special});
	CHECK(completion_body == "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
	                         "<Part><ETag>key&amp;&lt;&gt;&#13;'\"</ETag><PartNumber>1</PartNumber></Part>"
	                         "</CompleteMultipartUpload>");

	S3ListObjectsV2Result result;
	REQUIRE(S3XMLResponseParser::TryParseListObjectsV2(
	    "<ListBucketResult><Contents><Key>" + escaped + "</Key></Contents></ListBucketResult>", result));
	REQUIRE(result.objects.size() == 1);
	CHECK(result.objects[0].key == special);
}

} // namespace duckdb
