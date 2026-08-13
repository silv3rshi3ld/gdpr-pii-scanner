# Output formats

Select an output format with `--format terminal|json|json-compact|csv|html`. JSON and CSV default to standard output and may instead use `--output PATH`. HTML requires an output path. Terminal output cannot be combined with `--output`. PII Radar refuses to replace an existing report unless `--force` is present.

| Format | Intended use | Default destination |
| --- | --- | --- |
| `terminal` | Interactive review | Standard output |
| `json` | Structured integrations, formatted | Standard output |
| `json-compact` | Structured integrations, one line | Standard output |
| `csv` | Tabular import | Standard output |
| `html` | Human-readable saved report | A path supplied with `--output` or configuration |

## Standard streams

For JSON and CSV, standard output contains only the report payload. Progress, status messages, warnings, and errors are written to standard error. This makes piping deterministic:

```console
pii-radar --no-config scan ./data --format json > findings.json 2> scan.log
```

`--output` writes the payload directly to a file. A confirmation message, if any, is not written into that file.

The default machine-readable schema is `v1`. For JSON and CSV only, `--output-schema legacy` provides a transitional approximation of the 0.5 shape. It omits v1 completeness metadata but does not restore raw 0.5 context fields. Consumers of legacy output must still use the process exit status and standard-error diagnostics. New integrations should use `v1`.

Version 1 CSV is a record stream. It always begins with one `summary` row, then emits a `source` row for every scanned source and a `finding` row for each retained match. Consumers should branch on `Record Type`; source rows preserve errors and truncation even when a scan has no findings. Legacy CSV retains the flat finding-only layout.

When `truncated` is true, `omitted_matches` is a conservative lower bound. Detectors stop as soon as they can prove that a configured match cap was exceeded instead of continuing to enumerate sensitive values that will not be reported.

## Exit status

| Code | Meaning | Automation action |
| ---: | --- | --- |
| `0` | Complete scan, no reportable findings | Continue. |
| `1` | Complete scan, findings reported | Review or enforce policy. |
| `2` | Invalid invocation or configuration | Correct the command or configuration. |
| `3` | Incomplete scan: an error occurred or a hard resource limit omitted work | Treat the result as incomplete and investigate. |

Code `3` takes precedence when findings coexist with errors or limit-driven omissions.

An automation script should distinguish findings from failures:

```sh
set +e
pii-radar --no-config scan ./data --format json --output findings.json
status=$?
set -e

case "$status" in
  0) echo "scan complete: no findings" ;;
  1) echo "scan complete: findings require review" ;;
  2) echo "invalid command or configuration" >&2; exit 2 ;;
  3) echo "scan incomplete" >&2; exit 3 ;;
  *) echo "unexpected exit status: $status" >&2; exit "$status" ;;
esac
```

## Redaction and context

Matched values are masked in reports. File-scan context snippets are excluded by default. Add `--include-redacted-snippets` to `scan` only when nearby text is necessary for review:

```console
pii-radar scan ./data --format json --include-redacted-snippets
```

Redaction is risk reduction, not anonymisation. File paths, field names, positions, detector names, and partial values may still be sensitive or identifying. Store reports with restricted permissions, avoid public CI artifacts, and apply a retention period.

CSV viewers may interpret cells as formulas, and HTML viewers render a richer document. Use a patched viewer, open reports in an isolated context when the input is untrusted, and avoid forwarding report files without review.
