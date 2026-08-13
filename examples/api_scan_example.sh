#!/bin/sh
set -eu

# Set these values only for an endpoint you are authorised to scan.
: "${PII_RADAR_API_URL:?Set PII_RADAR_API_URL to an authorised endpoint}"
: "${PII_RADAR_AUTHORIZATION:?Set PII_RADAR_AUTHORIZATION to a test credential}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

exec pii-radar --no-config api "$PII_RADAR_API_URL" \
  --method POST \
  --header Content-Type:application/json \
  --header-env Authorization=PII_RADAR_AUTHORIZATION \
  --body-file "$script_dir/api-request.json" \
  --timeout 15 \
  --max-response-bytes 1048576 \
  --no-redirects \
  --format json
