# Rust library

The `pii-radar` crate exposes detector registries, scan engines, extractors, reporters, API scanning, and, behind the `database` feature, database scanning.

## Scan one file

```rust
use pii_radar::{default_registry, ScanEngine};
use std::path::Path;

let engine = ScanEngine::new(default_registry())
    .enable_context(true)
    .show_progress(false);

let result = engine.scan_file(Path::new("synthetic.txt"));

if let Some(error) = &result.error {
    eprintln!("scan incomplete: {error}");
}

for finding in &result.matches {
    println!("{}: {}", finding.detector_id, finding.value_masked);
}
```

`scan_file` records read or extraction errors in `FileResult::error`; callers must inspect it before treating an empty match list as a clean result.

## Scan a directory

```rust
use pii_radar::{default_registry, ScanEngine};
use std::path::Path;

let engine = ScanEngine::new(default_registry()).show_progress(false);
let results = engine.scan_directory(Path::new("fixtures"));

println!("{} candidate matches", results.total_matches);
```

Directory callers should inspect per-file errors as well as aggregate matches. Apply their own policy for confidence thresholds, incomplete scans, and process exit status.

## Select jurisdictions

Universal detectors remain present when a registry is restricted:

```rust
use pii_radar::{registry_for_countries, ScanEngine};

let registry = registry_for_countries(vec!["de".into(), "nl".into()]);
let engine = ScanEngine::new(registry).show_progress(false);
```

## Load detector plugins

The crate root exports the canonical schema-v1 `PluginConfig`, `PluginDetector`, `PluginPatternConfig`, and `PluginValidationConfig` types, plus `load_plugin_from_file` and `load_plugins_from_directory`. The old Rust types remain available with `LegacyPlugin*` names during the 0.6 release line and are deprecated for removal in 0.7.

Custom Rust detectors remain source-compatible through `Detector::detect`. To participate in hard finding budgets without first allocating every candidate, production implementations should also override `Detector::detect_limited` and return `DetectionOutcome`; built-in and canonical plugin detectors do so.

Plugin `category`, `context_keywords`, descriptions, and examples are metadata only in schema version 1. They do not alter a finding's confidence, severity, or GDPR classification. See [detector plugins](plugins.md) for validation and compatibility semantics.

## Feature selection

Use the default dependency for file, document, API, detector, plugin, and reporter APIs:

```toml
[dependencies]
pii-radar = "0.6"
```

Enable supported database connectors when required:

```toml
[dependencies]
pii-radar = { version = "0.6", features = ["database"] }
```

The library does not apply the CLI's exit-code contract for you. Avoid logging raw input or serialising unredacted data in wrappers. Review [security and privacy](security-and-privacy.md) before embedding scans in a service.
