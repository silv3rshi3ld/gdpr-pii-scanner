# Migrate from 0.5 to 0.6

Version 0.6 formalises configuration, output, exit status, API input, release artifacts, and plugin schema behaviour. Review automation before replacing a 0.5 binary.

## Choose an artifact

The core binary includes file, document, and API scanning, detectors, plugins, and reporters. The full binary also includes PostgreSQL and MongoDB connectors. Both install a binary named `pii-radar`. Consume the Rust library directly from the source repository; its database APIs use the same feature split.

Source builds continue to use the `database` feature for the connectors:

```console
cargo build --release --features database
```

## Update file commands

`scan PATH` now accepts a regular file as well as a directory. Existing directory commands remain valid.

Configuration selection is global and appears before the subcommand:

```console
# 0.6
pii-radar --config ./review.toml scan ./data
pii-radar --no-config scan ./data
```

Configuration now merges `defaults < platform user file < ./.pii-radar.toml < explicit file < CLI`. The platform user file is `pii-radar/config.toml` below the operating system's configuration directory. The legacy `~/.pii-radar/config.toml` path is accepted with a warning when the platform path is absent. Use `--no-config` for a defaults-only run.

Remove 0.5 `[api]` and `[database]` sections before loading the file in 0.6; unknown configuration keys now fail closed. API URLs and requests move to the `api` command, while database targets, filters, and credentials move to `scan-db` options. Common scan, output, limit, and plugin settings remain in the configuration file.

## Handle all exit codes

Version 0.5 used non-zero status inconsistently. Version 0.6 defines:

| Code | Meaning |
| ---: | --- |
| `0` | Complete, no reportable findings |
| `1` | Complete, findings reported |
| `2` | Invocation or configuration error |
| `3` | Incomplete scan: an error occurred or a hard resource limit omitted work |

Change CI rules that treat every non-zero code as an execution failure. Code `1` is a completed scan with findings; code `3` must not be accepted as clean.

## Consume standard output directly

JSON and CSV written to standard output contain only the report payload in 0.6. Status, progress, warnings, and errors go to standard error. Remove filters that stripped banners or progress text from 0.5 output.

Machine-readable output defaults to schema `v1`. For JSON and CSV only, `--output-schema legacy` is a transitional approximation: it omits v1 completeness fields and does not restore raw 0.5 `before` and `after` context. A legacy consumer must still inspect the process exit status and standard error. Update new integrations to consume `v1`.

HTML no longer chooses a default filename; supply `--output PATH`. All file-writing report formats refuse to replace an existing path unless `--force` is explicit. The canonical configuration section is `[limits]`; the old `[filters]` spelling remains an accepted alias during 0.6.

Context snippets are now opt-in:

```console
pii-radar scan ./data --format json --include-redacted-snippets
```

The option emits redacted snippets, not raw matched context. Reports still require sensitive-data controls.

## Move API inputs out of arguments

Replace literal credential headers and body strings with environment and file inputs:

```console
export PII_RADAR_AUTHORIZATION='Bearer replace-with-a-test-token'
pii-radar api https://api.example.invalid/v1/records \
  --method POST \
  --header-env Authorization=PII_RADAR_AUTHORIZATION \
  --body-file ./request.json \
  --max-response-bytes 1048576
```

Set `--max-response-bytes` for every endpoint according to expected payload size. Review redirect behaviour and disable redirects across trust boundaries.

## Review database targets

Only PostgreSQL and MongoDB are supported. MySQL and MariaDB were removed in 0.5 because of an unresolved dependency advisory. The SQLite enum added in 0.5 never had a scanner implementation and is not part of the 0.6 interface.

Use the full artifact or the source `database` feature. Prefer `--connection-env ENV_VAR` over `--connection URL`, and revalidate read-only roles, filters, sampling, row limits, and pool sizes after upgrading.

## Migrate plugins

The 0.5 single-pattern form nested metadata under `[detector]`:

```toml
[detector]
id = "example_employee_id"
name = "Example employee identifier"
country = "universal"
pattern = "\\bEMP-\\d{6}\\b"
severity = "medium"
confidence = "high"
description = "Synthetic example."
```

The canonical 0.6 form declares schema version 1 and uses a pattern array:

```toml
schema_version = 1
id = "example_employee_id"
name = "Example employee identifier"
country = "universal"
category = "custom"
description = "Synthetic example."
severity = "medium"
examples = ["EMP-000001"]
match_scope = "line"

[[patterns]]
pattern = "\\bEMP-\\d{6}\\b"
confidence = "high"

[validation]
length_unit = "bytes"
```

Move `[detector]` metadata to the top level, add `schema_version = 1` and `category`, and convert the single `pattern` and `confidence` fields into one `[[patterns]]` table. Keep arrays such as `examples` and `context_keywords` before `[validation]` so they remain top-level TOML fields. Legacy plugins matched each line separately and measured lengths as UTF-8 bytes; retain `match_scope = "line"` and `length_unit = "bytes"` when that behavior matters. New plugins normally use the `document` and `characters` defaults.

The legacy `[detector]` form loads through a compatibility bridge during the 0.6 release line and emits a warning. The bridge also preserves `allowed_chars` and its legacy checksum algorithms rather than translating `mod11` to a country-specific check.

Version 0.5 also supported unversioned top-level plugins with multiple `[[patterns]]` entries. Add `schema_version = 1`, then run `pii-radar plugins validate PATH`. Version 0.6 replaced `fancy-regex` with Rust's linear-time `regex` engine, so look-around and backreferences must be rewritten. In this older top-level form, `checksum = "mod11"` selected the Dutch BSN test; change it to `checksum = "bsn"` to retain that result. Version 1 reserves `mod11` for the generic repeating-weight algorithm. Re-test checksum and near-miss fixtures.

Version 0.6 still probes `~/.pii-radar/plugins` and `./plugins` and accepts ordinary `.toml` filenames in any plugin directory with warnings. Move files to the platform plugin directory, rename them with `.detector.toml`, and convert their contents before 0.7. See [detector plugins](plugins.md).

## Update Rust integrations

The canonical schema-v1 `PluginConfig`, `PluginDetector`, pattern, validation, match-scope, and length-unit types are now exported at the crate root. The 0.5 plugin API remains available only under deprecated `LegacyPlugin*` names through 0.6. `FileResult`, `ScanResults`, `ContextInfo`, and `ApiScanConfig` gained completeness, schema, privacy, redirect, and limit fields; construct them through defaults or constructors where possible instead of exhaustive struct literals. `ContextInfo::before` and `after` are deprecated, never populated by built-ins, and never serialized. Database connectors now compile under the separate `postgres` and `mongodb` features, with `database` retained as their combined feature.

## Validate the upgrade

Run representative synthetic fixtures with both versions, compare detector IDs and locations, then investigate intentional output changes. Test clean, findings, invalid-configuration, and incomplete-scan paths separately. Do not compare or publish live personal values.
