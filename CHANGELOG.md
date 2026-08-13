# Changelog

Notable changes are recorded here. Dates use `YYYY-MM-DD`.

## [Unreleased]

## [0.6.1] - 2026-08-13

### Changed

- Adopted an Apache-2.0-only licensing model by removing the MIT license artifact and updating project references.
- Refreshed dependency versions and `Cargo.lock` after the `sqlx` upgrade and related transitive compatibility updates.
- Updated release packaging to include `LICENSE-APACHE` only.

### Fixed

- Resolved package publication friction from stale package metadata and single-license mismatches during release packaging.

## [0.6.0] - 2026-08-13

### Added

- The `scan` command accepts either one file or a directory.
- Global `--config PATH` and `--no-config` options make configuration layering explicit.
- `--include-redacted-snippets` adds opt-in, redacted context to file-scan reports.
- API scanning accepts headers through `--header-env`, request bodies through `--body-file`, a response-size limit through `--max-response-bytes`, and a per-endpoint finding limit through `--max-matches`.
- Database scanning can read a connection string from a named environment variable with `--connection-env`.
- Release artifacts are split into core and full variants; the full variant adds database connectors.
- Detector plugin schema version 1 is identified by `schema_version = 1`.
- Result schema version 1 records tool version, target kind, completeness status, source errors, truncation, and observed omitted matches.
- File-count, total-byte, depth, extraction, response, and finding budgets bound untrusted input work.

### Changed

- Successful scans now return `0` when no findings are reported and `1` when findings are reported. Invocation or configuration errors return `2`; incomplete scans return `3`.
- JSON and CSV sent to standard output no longer include status, progress, or diagnostic text.
- Machine-readable output uses schema version 1, with a legacy output mode for migration.
- Database scanning is limited to PostgreSQL and MongoDB.
- Version 0.5 single-pattern detector schemas, plugin directories, and ordinary `.toml` filenames remain available through a warning-emitting compatibility bridge in 0.6; new files use `.detector.toml`.
- Documentation and examples have been reorganised around the 0.6 interface.
- HTTP redirects are limited to the original origin, and API responses must be successful UTF-8 bodies within the configured byte limit.
- Database connectors now build independently through `postgres` and `mongodb`; `database` remains their combined feature.
- Directory discovery is deterministic under file and byte limits, with memory proportional to the configured file count rather than the whole tree.

### Fixed

- Masking is UTF-8 safe, and one-character email local parts are no longer disclosed.
- The legacy plugin bridge preserves line scope, byte-length checks, allowed characters, and legacy checksum semantics instead of silently translating or dropping them.
- File, request-body, and document reads validate one opened handle, refuse final-component symlinks where the platform supports it, and enforce byte limits while reading.
- Built-in detectors apply confidence thresholds before bounded retention and stop after the first proven overflow.
- Detector byte spans and line and Unicode-column positions are consistent across CRLF and multilingual input.
- PostgreSQL identifier quoting is schema-qualified and selected values are cast to `TEXT`; decode errors are no longer treated as empty cells.
- MongoDB scans nested objects and arrays with a nesting limit and covers supported scalar values.
- CSV neutralises spreadsheet formulas, HTML escapes source metadata, terminal diagnostics escape control characters, and report files are no-clobber by default with mode `0600` on Unix.
- Danish CPR, Swedish personnummer, French NIR, and Italian Codice Fiscale detectors now apply stricter component, date, and check-character validation.

## [0.5.3] - 2026-04-24

### Security

- Resolved `RUSTSEC-2026-0044`, `RUSTSEC-2026-0045`, `RUSTSEC-2026-0046`, `RUSTSEC-2026-0047`, and `RUSTSEC-2026-0048` in `aws-lc-sys`.
- Resolved `RUSTSEC-2026-0049`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, and `RUSTSEC-2026-0104` in `rustls-webpki`.
- Resolved the `quinn-proto` denial-of-service advisory `RUSTSEC-2026-0037`.
- Resolved the `bytes` integer-overflow advisory `RUSTSEC-2026-0007`.
- Refreshed affected transitive dependencies.

### Fixed

- Fixed two `collapsible_match` Clippy errors in the MongoDB integration with Rust 1.95 so CI and release builds pass.

## [0.5.2] - 2026-04-20

### Changed

- Refreshed `Cargo.lock` after dependency consolidation to restore reproducible locked builds.

## [0.5.1] - 2026-04-20

### Added

- Added a security policy, code of conduct, issue templates, pull request template, pinned Rust toolchain, release workflow, and committed lockfile.

### Changed

- Consolidated project documentation, restored the missing 0.4 release tag, removed stale documentation, and merged the outstanding development branch.

## [0.5.0] - 2026-01-28

### Security

- Removed MySQL and MariaDB support because their dependency path included `rsa` advisory `RUSTSEC-2023-0071` with no upstream fix. PostgreSQL and MongoDB remained available.
- Resolved `RUSTSEC-2024-0363` in `sqlx` and `RUSTSEC-2024-0421` in `idna`.

### Added

- Re-enabled XLSX extraction with `zip` 4.2 and `calamine` 0.32, including `.xlsx`, `.xlsm`, `.xlsb`, and `.xls` formats.
- Added a SQLite database enum variant; the scanner implementation remained pending.

### Changed

- Updated `sqlx` to 0.8.6, `mongodb` to 3.5.0, `reqwest` to 0.13.1, `toml` to 0.9.11, `dirs` to 6, and `zip` to 4.2.
- Adapted to the MongoDB 3.x API, grouped long function parameters into structs, adopted `is_multiple_of`, and resolved Clippy findings.

## [0.4.0] - 2026-01-28

### Added

- Added database scanning for PostgreSQL, MySQL, and MongoDB with include and exclude filters, sampling, connection pooling, asynchronous execution, and progress reporting. MySQL was removed in 0.5.0.
- Added TOML detector plugins using `.detector.toml` files with patterns, confidence, validation, context keywords, severity, and examples.
- Added API scanning for GET, POST, PUT, PATCH, and DELETE requests, with headers, request bodies, timeouts, redirects, and multiple endpoints.
- Added API key and secret detection for AWS, GitHub, Stripe, OpenAI, Slack, Google, JWTs, private keys, and high-entropy values.
- Added detectors for Polish PESEL, Danish CPR, Swedish personnummer, Norwegian fødselsnummer, and Finnish HETU.
- Their validators added jurisdiction-specific date, format, and checksum rules, including dual modulus-11 checks for Norwegian numbers and modulus-31 control characters for Finnish HETU.
- Added configuration files, environment-variable expansion, precedence rules, and an example configuration.
- Added benchmarks for plain text, individual detectors, PII density, file sizes, pattern complexity, and thread scaling.
- Added an optional database feature.
- Re-enabled XLSX extraction.

### Changed

- Updated database dependencies to `sqlx` 0.7, `mongodb` 2.8, `tokio` 1.35, and `futures` 0.3.
- Updated plugin dependencies to `toml` 0.8 and `dirs` 5, API dependencies to `reqwest` 0.12 and `url` 2.5, and document dependencies to `calamine` 0.32 and `zip` 4.2.
- Updated benchmarks to use `std::hint::black_box`, refined validation and diagnostics, and separated the database, plugin, and API modules.

### Fixed

- Resolved the XLSX dependency conflict and restored PDF, DOCX, XLSX, XLSM, XLSB, and XLS extraction.
- Confirmed CSV reporting was functional after it had been described as incomplete.
- Corrected redundant closures, needless borrows, manual modulo checks, and overlong function parameter lists.

## [0.3.0] - 2026-01-27

### Added

- Added detectors for French NIR, German Steuer-ID, and Italian Codice Fiscale.
- Added optional PDF, DOCX, and XLSX text extraction.
- Added HTML reports, progress reporting, confidence levels, extraction metrics, and `--no-progress`.

### Changed

- Improved terminal extraction statistics and validation behaviour, and made scan statistics thread-safe.
- Updated `indicatif` to 0.17, `tera` to 1.19, and used `calamine` 0.24 for XLSX extraction.

### Fixed

- Updated JSON and terminal reporter fixtures for extraction statistics.

## [0.2.0] - 2024-01-15

### Added

- Added detectors for UK NHS numbers, Belgian RRN, and Spanish DNI and NIE.
- Added country filtering, confidence levels, and context analysis.

### Changed

- Improved validation, diagnostics, and parallel scanning behaviour.

## [0.1.0] - 2024-01-01

### Added

- Initial detectors for Dutch BSN, IBAN, payment-card numbers, and email addresses.
- Added parallel directory scanning, terminal and JSON output, `.pii-ignore`, context analysis, thread controls, and file-size limits.

[0.5.3]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.5.2...v0.5.3
[Unreleased]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.5.3...v0.6.0
[0.5.2]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/releases/tag/v0.1.0
