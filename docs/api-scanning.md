# API scanning

The `api` command sends HTTP requests to explicitly supplied endpoints and scans each response body. Use it only against systems you are authorised to access.

```console
pii-radar api https://api.example.invalid/v1/records
```

Multiple URLs can be supplied to one invocation. Supported methods are GET, POST, PUT, PATCH, and DELETE.

## Supply credentials from the environment

`--header-env` maps a request header to an environment-variable name without putting the value in command history:

```console
export PII_RADAR_AUTHORIZATION='Bearer replace-with-a-test-token'
pii-radar api https://api.example.invalid/v1/records \
  --header-env Authorization=PII_RADAR_AUTHORIZATION
```

Repeat the option for additional headers. A missing or non-Unicode environment value is an invocation error. Avoid credentials in URLs and literal `--header` arguments: both can be exposed through shell history, process listings, logs, and proxy records.

## Read a body from a file

Pass request bodies by path so quoting and shell history do not expose their contents:

```console
pii-radar api https://api.example.invalid/v1/search \
  --method POST \
  --header Content-Type:application/json \
  --body-file ./request.json
```

Do not combine `--body` and `--body-file`. A body file must be one regular, non-symlinked UTF-8 file no larger than 25 MiB; violating those constraints is an invocation error. Keep request files synthetic where possible and restrict their file permissions.

## Limit responses

Always set a limit appropriate to the endpoint when response size is not tightly controlled:

```console
pii-radar api https://api.example.invalid/v1/export \
  --timeout 15 \
  --max-response-bytes 1048576 \
  --max-matches 1000 \
  --no-redirects \
  --format json
```

Only successful 2xx responses with valid UTF-8 bodies are scanned. The response cap defaults to 25 MiB and is enforced while reading even when `Content-Length` is absent or wrong. `--max-matches` caps findings for each endpoint. A timeout, rejected redirect, non-2xx response, response over the limit, transport failure, invalid UTF-8 body, or finding truncation makes the scan incomplete and returns exit code `3` with per-endpoint evidence when possible.

Same-origin redirects are followed by default, up to ten hops. Cross-origin redirects are always rejected; `--no-redirects` rejects every redirect response. Malformed, non-HTTP(S), and userinfo-bearing endpoint URLs are invocation errors and return exit code `2` before requests begin. PII Radar does not establish that a target is public or safe; an untrusted URL can reach services accessible from the scanner host.

## Handle output

Response content is processed locally by the scanner, but the request itself reaches the selected server and may be recorded by intermediaries. JSON and CSV report payloads go to standard output; diagnostics go to standard error. API target and credential inputs are deliberately command-scoped rather than stored in the common configuration file. See [security and privacy](security-and-privacy.md) before scanning production systems.
