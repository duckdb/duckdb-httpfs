#!/usr/bin/env bash

# Run this script with 'source' or the shorthand: '.':
# i.e: source scripts/set_webdav_test_server_variables.sh

# Enable the WebDAV tests to run
export WEBDAV_TEST_SERVER_AVAILABLE=1

export WEBDAV_TEST_USERNAME=duckdb_webdav_user
export WEBDAV_TEST_PASSWORD=duckdb_webdav_password
export WEBDAV_TEST_BASE_URL=webdav://localhost:9100
