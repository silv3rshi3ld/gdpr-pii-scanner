#!/bin/bash
# Examples of using pii-radar for API endpoint scanning

# Basic GET request
echo "=== Example 1: Basic GET request ==="
pii-radar api "https://httpbin.org/get"

# GET with headers
echo -e "\n=== Example 2: GET with custom headers ==="
pii-radar api "https://httpbin.org/headers" \
  --header "Authorization:Bearer token123" \
  --header "X-Custom-Header:test"

# POST with JSON body
echo -e "\n=== Example 3: POST with JSON body ==="
pii-radar api "https://httpbin.org/post" \
  --method POST \
  --header "Content-Type:application/json" \
  --body '{"email":"john@example.com","phone":"+31612345678"}'

# Multiple endpoints
echo -e "\n=== Example 4: Scan multiple endpoints ==="
pii-radar api \
  "https://httpbin.org/anything/users" \
  "https://httpbin.org/anything/customers" \
  --format json \
  --output api-scan-results.json

# With custom timeout and redirects
echo -e "\n=== Example 5: Custom timeout and no redirects ==="
pii-radar api "https://httpbin.org/delay/2" \
  --timeout 5 \
  --no-redirects

# Scan with lower confidence threshold
echo -e "\n=== Example 6: Lower confidence threshold ==="
pii-radar api "https://httpbin.org/anything?data=test@example.com" \
  --min-confidence low

# Output as CSV
echo -e "\n=== Example 7: CSV output ==="
pii-radar api "https://httpbin.org/anything?bsn=123456782" \
  --format csv \
  --output api-scan.csv

# Using custom plugins
echo -e "\n=== Example 8: With custom plugins ==="
pii-radar api "https://httpbin.org/anything?ssn=123-45-6789" \
  --plugins ~/.pii-radar/plugins

echo -e "\n✅ All examples completed!"
