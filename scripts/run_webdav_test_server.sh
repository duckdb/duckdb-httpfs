#!/usr/bin/env bash
# Note: DON'T run as root

docker compose -f scripts/webdav.yml -p duckdb-webdav up -d

# Get setup container name to monitor logs
container_name=$(docker ps -a --format '{{.Names}}' | grep -m 1 "duckdb-webdav")
echo $container_name

# Wait for setup completion (up to 360 seconds like Minio)
for i in $(seq 1 360);
do
  docker_finish_logs=$(docker logs $container_name 2>/dev/null | grep -m 1 'FINISHED SETTING UP WEBDAV' || echo '')
  if [ ! -z "${docker_finish_logs}" ]; then
    break
  fi
  sleep 1
done

export WEBDAV_TEST_SERVER_AVAILABLE=1
export WEBDAV_TEST_BASE_URL="webdav://localhost:9100"
