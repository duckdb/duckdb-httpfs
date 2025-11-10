#!/usr/bin/env bash

echo "Stopping WebDAV test server..."
docker compose -f scripts/webdav.yml -p duckdb-webdav down

echo "WebDAV test server stopped."
