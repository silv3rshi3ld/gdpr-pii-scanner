# API Endpoint Scanning

PII-Radar can scan API endpoints for Personally Identifiable Information (PII) in HTTP responses.

## Basic Usage

```bash
# Scan a single API endpoint
pii-radar api https://api.example.com/users

# Scan multiple endpoints
pii-radar api \
  https://api.example.com/users \
  https://api.example.com/customers \
  https://api.example.com/orders
```

## HTTP Methods

```bash
# GET request (default)
pii-radar api https://api.example.com/users --method GET

# POST request with JSON body
pii-radar api https://api.example.com/users \
  --method POST \
  --header "Content-Type:application/json" \
  --body '{"name":"John Doe","email":"john@example.com"}'

# PUT request
pii-radar api https://api.example.com/users/123 \
  --method PUT \
  --body '{"email":"newemail@example.com"}'

# PATCH request
pii-radar api https://api.example.com/users/123 \
  --method PATCH \
  --body '{"phone":"+31612345678"}'

# DELETE request
pii-radar api https://api.example.com/users/123 --method DELETE
```

## Authentication

```bash
# Bearer token authentication
pii-radar api https://api.example.com/protected \
  --header "Authorization:Bearer YOUR_TOKEN"

# API key authentication
pii-radar api https://api.example.com/data \
  --header "X-API-Key:your-api-key"

# Basic authentication (Base64 encoded)
pii-radar api https://api.example.com/secure \
  --header "Authorization:Basic dXNlcjpwYXNzd29yZA=="

# Multiple headers
pii-radar api https://api.example.com/endpoint \
  --header "Authorization:Bearer TOKEN" \
  --header "Accept:application/json" \
  --header "User-Agent:PII-Radar/0.4.0"
```

## Request Options

```bash
# Custom timeout (default: 30 seconds)
pii-radar api https://slow-api.example.com \
  --timeout 60

# Disable following redirects
pii-radar api https://api.example.com/redirect \
  --no-redirects

# Set minimum confidence level
pii-radar api https://api.example.com/users \
  --min-confidence low  # or medium, high (default)
```

## Output Formats

```bash
# Terminal output (default)
pii-radar api https://api.example.com/users

# JSON output
pii-radar api https://api.example.com/users \
  --format json \
  --output api-results.json

# Compact JSON (single line)
pii-radar api https://api.example.com/users \
  --format json-compact

# CSV output
pii-radar api https://api.example.com/users \
  --format csv \
  --output api-results.csv

# HTML report
pii-radar api https://api.example.com/users \
  --format html \
  --output api-report.html
```

## Using Custom Plugins

```bash
# Load custom detector plugins
pii-radar api https://api.example.com/users \
  --plugins /path/to/plugins

# Use default plugin directory (~/.pii-radar/plugins)
pii-radar api https://api.example.com/users \
  --plugins ~/.pii-radar/plugins
```

## Real-World Examples

### Example 1: Scan REST API with Authentication

```bash
pii-radar api https://api.company.com/v1/customers \
  --method GET \
  --header "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --header "Accept:application/json" \
  --format json \
  --output customer-scan.json
```

### Example 2: Test POST Endpoint with Sample Data

```bash
pii-radar api https://api.example.com/v1/users \
  --method POST \
  --header "Content-Type:application/json" \
  --body '{
    "name": "John Doe",
    "email": "john.doe@example.com",
    "phone": "+31612345678",
    "bsn": "123456782",
    "iban": "NL91ABNA0417164300"
  }' \
  --min-confidence medium
```

### Example 3: Scan Multiple Endpoints in CI/CD

```bash
#!/bin/bash
# CI/CD script to scan API endpoints

API_BASE="https://staging-api.company.com"
TOKEN="Bearer $CI_API_TOKEN"

pii-radar api \
  "$API_BASE/v1/users" \
  "$API_BASE/v1/customers" \
  "$API_BASE/v1/orders" \
  "$API_BASE/v1/transactions" \
  --header "Authorization:$TOKEN" \
  --format json \
  --output "$CI_PROJECT_DIR/pii-scan-results.json" \
  --min-confidence high

# Exit code 1 if PII found (fails the pipeline)
```

### Example 4: Scan GraphQL Endpoint

```bash
pii-radar api https://api.example.com/graphql \
  --method POST \
  --header "Content-Type:application/json" \
  --body '{
    "query": "{ users { id name email phone address { street city postalCode } } }"
  }' \
  --format html \
  --output graphql-scan-report.html
```

### Example 5: Scan with Custom US SSN Plugin

```bash
# Create plugin for US SSN detection
cat > ~/.pii-radar/plugins/us_ssn.toml <<EOF
[detector]
id = "us_ssn"
name = "US Social Security Number"
description = "Detects US SSN in XXX-XX-XXXX format"
country = "US"
pattern = "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
severity = "critical"
confidence = "medium"

[validation]
min_length = 11
max_length = 11
checksum = "none"
EOF

# Scan API with custom plugin
pii-radar api https://api.example.com/users \
  --plugins ~/.pii-radar/plugins \
  --min-confidence medium
```

## Exit Codes

- `0`: No PII found
- `1`: PII detected (useful for CI/CD to fail builds)
- `2`: Invalid arguments or configuration error

## Tips

1. **Use --min-confidence low** for initial discovery to catch potential PII
2. **Set appropriate timeouts** for slow APIs (--timeout 60)
3. **Test with sample data** before scanning production endpoints
4. **Use --no-redirects** when testing redirect chains
5. **Save JSON output** for automated processing and reporting
6. **Integrate with CI/CD** to prevent PII leaks in API responses

## Performance Considerations

- Each endpoint is scanned sequentially
- Response body is loaded into memory
- Large responses may require more time to scan
- Use appropriate timeouts for production APIs

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never log or expose authentication tokens** in scan results
2. **Use environment variables** for sensitive headers
3. **Scan test/staging environments** before production
4. **Be mindful of rate limits** when scanning multiple endpoints
5. **Ensure you have authorization** to scan the target APIs

## Troubleshooting

### Connection Errors

```bash
# Increase timeout for slow endpoints
pii-radar api https://slow-api.example.com --timeout 120
```

### SSL/TLS Errors

API scanning uses the system's CA certificates. Ensure your system trusts the API's SSL certificate.

### Authentication Failures

Verify your authentication header format:

```bash
# Correct format
--header "Authorization:Bearer token123"

# Incorrect (missing colon)
--header "Authorization Bearer token123"
```

### No PII Detected

1. Check the API response manually
2. Try lower confidence: `--min-confidence low`
3. Load custom plugins if standard detectors don't match
4. Verify the response contains text content (not binary)
