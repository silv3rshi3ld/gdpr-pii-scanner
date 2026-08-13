# PII Radar

PII Radar is a Rust command-line tool and library for locating candidate personal identifiers and secrets in files, API responses, and supported databases. It combines built-in detectors with optional TOML detector plugins and can produce terminal, JSON, CSV, or HTML reports.

Detection is evidence for review, not proof that data is personal, complete, or compliant. Expect false positives and false negatives, and treat reports as sensitive data.

## Capabilities

Binary release bundles are labelled **core** and **full**. Both contain a binary named `pii-radar`.

| Capability | Core | Full |
| --- | :---: | :---: |
| Scan one text file or a directory | Yes | Yes |
| Scan HTTP API responses | Yes | Yes |
| Built-in and TOML plugin detectors | Yes | Yes |
| Terminal, JSON, CSV, and HTML output | Yes | Yes |
| Extract text from PDF, DOCX, and Excel files | Yes | Yes |
| Scan PostgreSQL and MongoDB | No | Yes |

MySQL, MariaDB, and SQLite scanning are not supported in 0.6.
The source tree and crates.io package also expose the scanner as a Rust library; database APIs follow the same feature split.

## Quick start

Scan a file or directory:

```console
pii-radar scan ./sample.txt
pii-radar scan ./data --countries nl,de --min-confidence high
```

Write machine-readable output without progress or status text on standard output:

```console
pii-radar scan ./data --format json > findings.json
pii-radar scan ./data --format csv --output findings.csv
```

Read an API credential from the environment and a request body from a file:

```console
export PII_RADAR_AUTHORIZATION='Bearer replace-with-a-test-token'
pii-radar api https://api.example.invalid/v1/records \
  --method POST \
  --header-env Authorization=PII_RADAR_AUTHORIZATION \
  --body-file ./request.json \
  --max-response-bytes 1048576 \
  --format json
```

Database scanning is available in the full build:

```console
pii-radar scan-db --db-type postgres --connection-env DATABASE_URL --format json
pii-radar scan-db --db-type mongodb --connection-env MONGODB_URI --database example
```

PII Radar layers its platform user configuration, the project file `./.pii-radar.toml`, and an optional file supplied through the global `--config PATH` option. Disable all configuration loading with `--no-config`:

```console
pii-radar --config ./review.toml scan ./data
pii-radar --no-config scan ./data
```

## Exit status

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed with no reportable findings. |
| `1` | Scan completed with one or more reportable findings. |
| `2` | Command-line or configuration error. |
| `3` | Scan was incomplete because an error occurred or a hard resource limit omitted work. |

Code `3` takes precedence over findings so an incomplete scan cannot be mistaken for a clean result. See [output formats](docs/output-formats.md) for automation guidance.

## Build from source

The default build corresponds to the core artifact. Enable the `database` feature to build the database connectors included in the full artifact:

```console
cargo build --release
cargo build --release --features database
```

The x86-64 GNU/Linux release archive is built on Ubuntu 22.04 to keep its glibc baseline stable across releases. Build from source when targeting another C library or an older Linux userspace.

## Documentation

- [File scanning](docs/file-scanning.md)
- [API scanning](docs/api-scanning.md)
- [Database scanning](docs/database-scanning.md)
- [Configuration](docs/configuration.md)
- [Detector plugins](docs/plugins.md)
- [Output formats and exit status](docs/output-formats.md)
- [Built-in detectors](docs/detectors.md)
- [Library use](docs/library.md)
- [Security and privacy](docs/security-and-privacy.md)
- [Migration from 0.5 to 0.6](docs/migration-guide.md)
- [Roadmap](docs/roadmap.md)
- [Contributing](CONTRIBUTING.md) and [security reports](SECURITY.md)

## Limitations

- Pattern and checksum validation cannot establish identity, ownership, or legal classification.
- Binary and encrypted content is not inspected unless a supported extractor can read it.
- Document extraction can omit text or alter layout; validate coverage for your file set.
- API and database scans only inspect data returned within configured limits and permissions.
- Custom regular expressions can be too broad, too narrow, or computationally expensive.
- Redaction reduces exposure but does not make a report non-sensitive.

## Licence

PII Radar is available under the [Apache License 2.0](LICENSE-APACHE).
