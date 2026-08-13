# Configuration

PII Radar reads TOML configuration for common scan, output, limit, and plugin settings. API targets, request credentials, and database connection strings remain command-scoped.

## Discovery and precedence

Configuration is layered from lowest to highest precedence:

1. Built-in defaults
2. The platform user configuration at `pii-radar/config.toml`
3. The project file `./.pii-radar.toml`
4. A file supplied through global `--config PATH`
5. Command-line options

On Linux, the user path normally resolves below `$XDG_CONFIG_HOME` or `~/.config`. The legacy `~/.pii-radar/config.toml` path is accepted in 0.6 when the platform path is absent and emits a migration warning.

`--config` adds an explicit highest-priority file after discovered files; it does not suppress discovery. Global `--no-config` disables all file loading and automatic plugin-directory discovery. An explicit `--plugins DIR` still loads that directory. The two global configuration options are mutually exclusive.

```console
pii-radar --config ./review.toml scan ./data
pii-radar --no-config scan ./data
```

An unreadable file, invalid TOML, unknown key, or invalid value returns exit code `2`. Rejecting unknown keys prevents a spelling mistake from silently weakening a scan.

## Scan settings

`[scan]` controls confidence, jurisdictions, context analysis, document extraction, worker count, and opt-in snippets.

```toml
[scan]
min_confidence = "high"
countries = ["de", "nl"]
extract_documents = false
no_context = false
include_redacted_snippets = false
max_threads = 4
```

Country values must be supported lowercase codes: `be`, `de`, `dk`, `es`, `fi`, `fr`, `gb`, `it`, `nl`, `no`, `pl`, `pt`, or `se`. Unknown codes are rejected so a typo cannot silently leave only universal detectors enabled. When `max_threads` is unset, scans use the available CPU count capped at eight workers to limit concurrent memory use. Command flags that enable a Boolean setting take precedence; use `--no-config` when a configured setting must be removed rather than enabled.

## Output settings

```toml
[output]
format = "json"
output_path = "findings.json"
full_paths = false
no_progress = true
```

Supported formats are `terminal`, `json`, `json-compact`, `csv`, and `html`. Existing output files are not replaced unless `--force` is supplied to the command.

## Limits

Use the canonical `[limits]` section. The older `[filters]` spelling remains an alias in 0.6.

```toml
[limits]
max_filesize_mb = 25
max_total_size_mb = 1024
max_files = 10000
max_depth = 8
max_matches_per_source = 1000
max_matches = 10000
max_extracted_size_mb = 25
```

All numeric limits must be greater than zero, and `max_matches_per_source` cannot exceed `max_matches`. Reaching a hard resource limit can make a scan incomplete; treat exit code `3` accordingly.

API response size and API match limits are set per invocation with `--max-response-bytes` and `--max-matches`. Database scope and credentials are also command options. This avoids persisting credential-bearing targets in the common configuration file.

## Plugin settings

```toml
[plugins]
enabled = true
directories = ["./plugins"]
```

Setting `directories` replaces the default directory list after configuration merging; it does not append to it. A command-level `--plugins DIR` replaces all configured directories for that invocation. New plugin files use the `.detector.toml` suffix. During 0.6, ordinary `.toml` filenames are accepted in any plugin directory with a migration warning. See [detector plugins](plugins.md).

The [synthetic example configuration](../examples/config.toml) includes every common section. Keep configuration reviews tied to the installed release.
