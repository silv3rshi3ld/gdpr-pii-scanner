# File scanning

The `scan` command accepts one regular file or one directory. Directory scans recurse under deterministic ignore and resource policies.

```console
pii-radar scan ./record.txt
pii-radar scan ./export
```

## Select detectors

All built-in detectors are enabled by default. Restrict jurisdiction-specific detectors with comma-separated country codes; universal detectors remain enabled.

```console
pii-radar scan ./export --countries be,de,nl
pii-radar scan ./export --min-confidence medium
```

Confidence is a detector classification, not a probability. Lower thresholds usually increase both coverage and false positives. See [built-in detectors](detectors.md).

## Scan documents

Plain-text files are read directly. Enable extraction for supported document containers:

```console
pii-radar scan ./documents --extract-documents
```

The extractors cover PDF, DOCX, and Excel formats (`.xlsx`, `.xlsm`, `.xlsb`, and `.xls`). Extraction can omit images, handwriting, protected content, or text encoded in an unsupported structure. A successful command therefore does not establish complete document coverage.

## Bound the scan

Use limits when scanning an unfamiliar or large tree:

```console
pii-radar scan ./export \
  --max-filesize 25 \
  --max-depth 8 \
  --threads 4
```

`--max-filesize` is measured in MiB. A file-size, file-count, total-byte, depth, extraction, or finding limit that omits work makes the scan incomplete and returns exit code `3`. Invalid UTF-8 and other read or extraction errors also return `3`.

## Ignore paths

Directory discovery honours `.gitignore`, `.ignore`, and `.pii-ignore`, skips hidden entries, and never follows symbolic links. Ignore and hidden-file exclusions are intentional scope choices and do not make the result partial or return exit code `3`. A known hidden regular file can be scanned by naming it directly; library callers can opt into hidden directory entries with `Walker::hidden(false)`.

Place additional gitignore-style patterns in `.pii-ignore` at the scan root. The repository example excludes common dependency, build, editor, media, and archive paths. Review every active ignore file for the data set: an overly broad rule can hide content that should be inspected.

## Control context and paths

Context analysis can adjust classification based on nearby words. Disable it with `--no-context` when the surrounding text must not be processed or when evaluating raw detector behaviour. `--full-paths` affects terminal rendering only. Structured and HTML reports retain the scanner's source paths regardless, so choose the scan root and report destination with path disclosure in mind.

Matched values are masked. Context snippets are omitted unless `--include-redacted-snippets` is set; when enabled, snippets are redacted before output. Reports remain sensitive because paths, detector types, positions, and partial values can reveal information.

## Use configuration

PII Radar layers its platform user configuration, `./.pii-radar.toml`, and an optional explicit file. Global options add an explicit layer or disable all configuration:

```console
pii-radar --config ./review.toml scan ./export
pii-radar --no-config scan ./export
```

Command-line values take precedence over loaded configuration. See [configuration](configuration.md) for the full order.

## Automate safely

JSON and CSV report data can be written to standard output without status text:

```console
pii-radar --no-config scan ./export --format json > findings.json
```

Progress and diagnostics go to standard error. A completed scan with findings exits `1`; do not treat every non-zero result as a tool failure. See [output formats](output-formats.md).
