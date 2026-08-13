# Security policy

## Supported versions

Security fixes are provided for the latest minor release line.

| Version | Supported |
| --- | :---: |
| 0.6.x | Yes |
| 0.5.x and earlier | No |

Users of unsupported versions should upgrade before requesting a fix.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's [private vulnerability reporting](https://github.com/silv3rshi3ld/gdpr-pii-scanner/security/advisories/new) and include:

- the affected version or commit;
- the affected command, library API, or plugin path;
- reproduction steps using synthetic data;
- the expected and observed behaviour;
- the likely impact and any known mitigations.

Remove personal data, credentials, database contents, access tokens, and private endpoints from the report. If a minimal reproducer must contain sensitive material, describe that need first and wait for a protected transfer method.

We aim to acknowledge reports within five business days. For a confirmed high-severity issue, we aim to provide a remediation plan or patch within 30 days. Timing may vary with complexity and coordinated-disclosure needs. Please allow maintainers a reasonable opportunity to investigate and release a fix before public disclosure.

## Scope

In scope:

- the published `pii-radar` binary and Rust library;
- built-in detectors, parsers, extractors, and output renderers;
- API and supported database scanning;
- configuration discovery and the default TOML plugin loader.

Generally out of scope:

- third-party detector plugins and downstream integrations;
- unsupported versions or platforms;
- findings that require an operator to run untrusted code intentionally;
- denial of service based only on limits that an authenticated operator explicitly disabled;
- scanner accuracy reports without a security impact.

Accuracy problems and ordinary bugs can be reported with the public issue templates after all sensitive data has been removed.

## Operational guidance

Scanning can expose sensitive content to the process, terminal, report files, API servers, and database audit logs. Run with least-privilege credentials, set response and file-size limits, prefer redacted output, restrict report permissions, and delete temporary artifacts according to your retention policy. See [security and privacy](docs/security-and-privacy.md) for details.
