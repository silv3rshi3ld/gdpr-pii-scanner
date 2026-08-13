# Security and privacy

PII Radar handles content that may be sensitive by definition. Operate it as a security-relevant data-processing tool, even when reports contain masked values.

## Authorise the scope

Scan only files, endpoints, and databases you are authorised to inspect. Confirm the resolved directory, redirect policy, database filters, and configuration file before running. An API URL supplied by an untrusted party can reach services visible from the scanner host; a broad database role can expose unrelated data.

## Minimise access

- Run under an operating-system account that can read only the intended files.
- Use read-only, short-lived API and database credentials.
- Restrict database schemas, tables, collections, columns, and network routes.
- Set file-size, recursion, response-size, timeout, row, sample, and pool limits.
- Disable redirects when a redirect could cross a trust boundary.
- Run untrusted plugin regular expressions against synthetic data before production use.

File scans are processed by the local process. API and database modes necessarily connect to the systems you specify, which may record requests and query metadata.

## Keep secrets out of commands

Use `--header-env NAME=ENV_VAR` for API headers, `--body-file PATH` for request bodies, and `--connection-env ENV_VAR` for database connections. Literal credentials in arguments, URLs, files committed to version control, or diagnostic bundles can escape through history and logs.

Environment variables are not a complete secret boundary: privileged users, crash reporters, and process-inspection tools may expose them. Use the platform's secret facility and a trusted execution host.

## Protect reports

Values are masked, and file-scan context snippets are disabled by default. On the `scan` command, `--include-redacted-snippets` emits only redacted snippets, but surrounding words can still identify a person or system. Paths, table and column names, detector types, and positions can also disclose sensitive facts.

- Write reports to a restricted directory with an appropriate `umask`.
- Do not publish reports as unrestricted CI artifacts.
- Avoid pasting production findings into public issues or chat systems.
- Apply an explicit retention period and remove temporary request bodies and reports when no longer needed.
- Review CSV and HTML in a patched, appropriately isolated viewer when source content is untrusted.

## Interpret results conservatively

PII Radar reports candidates. A match does not establish identity, accuracy, legal status, or a compliance violation. An empty or complete report does not prove the absence of personal data. Unsupported formats, encrypted content, extraction errors, ignored paths, network limits, database sampling, and detector gaps all affect coverage.

Exit code `3` means the scan was incomplete and takes precedence over findings. Preserve diagnostics from standard error without exposing secrets.

## Report vulnerabilities privately

Use the process in [SECURITY.md](../SECURITY.md) for suspected vulnerabilities. Use synthetic reproduction data and do not attach live credentials or personal records.
