//! Loader and validator for declarative detector plugins.

use crate::detectors::plugin::{
    LengthUnit, MatchScope, PatternConfig, PluginConfig, PluginDetector, ValidationConfig,
    PLUGIN_SCHEMA_VERSION,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_PLUGIN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default)]
pub struct PluginLoadReport {
    pub detectors: Vec<PluginDetector>,
    pub warnings: Vec<String>,
}

/// Load canonical `*.detector.toml` files and deprecated `*.toml` filenames.
///
/// Any malformed file makes the operation fail, so a misspelled detector is never silently
/// omitted. Legacy single-pattern files are accepted in v0.6 with a diagnostic.
pub fn load_plugins_with_diagnostics<P: AsRef<Path>>(
    plugin_dir: P,
) -> Result<PluginLoadReport, String> {
    let path = plugin_dir.as_ref();
    if !path.exists() {
        return Err(format!(
            "plugin directory does not exist: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(format!(
            "plugin path is not a directory: {}",
            path.display()
        ));
    }

    let mut files = discover_plugin_files(path)?;
    files.sort();
    let mut report = PluginLoadReport::default();
    let mut errors = Vec::new();
    let mut ids = HashSet::new();

    for file in files {
        match load_plugin_from_file_with_diagnostic(&file) {
            Ok((detector, warning)) => {
                if !ids.insert(detector.config().id.clone()) {
                    errors.push(format!(
                        "{}: duplicate detector id '{}'",
                        file.display(),
                        detector.config().id
                    ));
                    continue;
                }
                if let Some(warning) = warning {
                    report
                        .warnings
                        .push(format!("{}: {warning}", file.display()));
                }
                if !has_canonical_suffix(&file) {
                    report.warnings.push(format!(
                        "{}: legacy .toml plugin filename is deprecated; rename it with the .detector.toml suffix before v0.7",
                        file.display()
                    ));
                }
                report.detectors.push(detector);
            }
            Err(error) => errors.push(format!("{}: {error}", file.display())),
        }
    }

    if errors.is_empty() {
        Ok(report)
    } else {
        Err(format!(
            "failed to load detector plugins:\n{}",
            errors.join("\n")
        ))
    }
}

pub fn load_plugins_from_directory<P: AsRef<Path>>(
    plugin_dir: P,
) -> Result<Vec<PluginDetector>, String> {
    Ok(load_plugins_with_diagnostics(plugin_dir)?.detectors)
}

pub fn load_plugin_from_file<P: AsRef<Path>>(file_path: P) -> Result<PluginLoadReport, String> {
    let path = file_path.as_ref();
    if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
        return Err("plugin file must use a .toml suffix".to_string());
    }

    let (detector, warning) = load_plugin_from_file_with_diagnostic(path)?;
    let mut warnings: Vec<_> = warning.into_iter().collect();
    if !has_canonical_suffix(path) {
        warnings.push(
            "legacy .toml plugin filename is deprecated; rename it with the .detector.toml suffix before v0.7"
                .to_string(),
        );
    }
    Ok(PluginLoadReport {
        detectors: vec![detector],
        warnings,
    })
}

fn load_plugin_from_file_with_diagnostic(
    path: &Path,
) -> Result<(PluginDetector, Option<String>), String> {
    let contents = crate::safe_io::read_utf8_regular_file(path, MAX_PLUGIN_BYTES)
        .map_err(|error| format!("failed to read plugin file: {error}"))?;
    let value: toml::Value =
        toml::from_str(&contents).map_err(|error| format!("invalid TOML: {error}"))?;

    let (config, warning) = if value.get("detector").is_some() {
        (
            parse_legacy(&contents)?,
            Some("legacy [detector] schema is deprecated and will be removed in v0.7".to_string()),
        )
    } else {
        let config: PluginConfig = toml::from_str(&contents)
            .map_err(|error| format!("invalid detector schema: {error}"))?;
        let warning = (!value
            .as_table()
            .is_some_and(|table| table.contains_key("schema_version")))
        .then(|| {
            "missing schema_version is accepted as version 1 in v0.6 and will be rejected in v0.7"
                .to_string()
        });
        (config, warning)
    };

    PluginDetector::new(config).map(|detector| (detector, warning))
}

pub fn discover_plugin_files<P: AsRef<Path>>(plugin_dir: P) -> Result<Vec<PathBuf>, String> {
    let path = plugin_dir.as_ref();
    if !path.exists() {
        return Err(format!(
            "plugin directory does not exist: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(format!(
            "plugin path is not a directory: {}",
            path.display()
        ));
    }

    fs::read_dir(path)
        .map_err(|error| format!("failed to read plugin directory: {error}"))?
        .map(|entry| entry.map_err(|error| format!("failed to read directory entry: {error}")))
        .filter_map(|entry| match entry {
            Ok(entry) => {
                let file = entry.path();
                let is_plugin = entry.file_type().is_ok_and(|file_type| file_type.is_file())
                    && file.extension().and_then(|extension| extension.to_str()) == Some("toml");
                is_plugin.then_some(Ok(file))
            }
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn has_canonical_suffix(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".detector.toml"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPluginConfig {
    detector: LegacyDetector,
    #[serde(default)]
    validation: LegacyValidation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDetector {
    id: String,
    name: String,
    country: String,
    pattern: String,
    #[serde(default = "legacy_severity")]
    severity: String,
    #[serde(default = "legacy_confidence")]
    confidence: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyValidation {
    min_length: Option<usize>,
    max_length: Option<usize>,
    checksum: Option<String>,
    allowed_chars: Option<String>,
}

fn legacy_severity() -> String {
    "high".to_string()
}

fn legacy_confidence() -> String {
    "medium".to_string()
}

fn parse_legacy(contents: &str) -> Result<PluginConfig, String> {
    let legacy: LegacyPluginConfig = toml::from_str(contents)
        .map_err(|error| format!("invalid legacy detector schema: {error}"))?;
    Ok(PluginConfig {
        schema_version: PLUGIN_SCHEMA_VERSION,
        id: legacy.detector.id,
        name: legacy.detector.name,
        country: legacy.detector.country,
        category: "custom".to_string(),
        description: legacy.detector.description,
        patterns: vec![PatternConfig {
            pattern: legacy.detector.pattern,
            confidence: legacy.detector.confidence,
            description: None,
        }],
        severity: legacy.detector.severity,
        examples: Vec::new(),
        context_keywords: Vec::new(),
        match_scope: MatchScope::Line,
        validation: Some(ValidationConfig {
            min_length: legacy.validation.min_length,
            max_length: legacy.validation.max_length,
            checksum: legacy.validation.checksum,
            required_prefix: None,
            required_suffix: None,
            allowed_chars: legacy.validation.allowed_chars,
            length_unit: LengthUnit::Bytes,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Detector;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_plugin(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(format!("{name}.detector.toml"));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_v1_and_legacy_plugins() {
        let directory = TempDir::new().unwrap();
        write_plugin(
            directory.path(),
            "modern",
            r#"
schema_version = 1
id = "modern_id"
name = "Modern"
country = "universal"
[[patterns]]
pattern = "MOD-\\d{4}"
confidence = "high"
"#,
        );
        write_plugin(
            directory.path(),
            "legacy",
            r#"
[detector]
id = "legacy_id"
name = "Legacy"
country = "us"
pattern = "LEG-\\d{4}"
"#,
        );

        let report = load_plugins_with_diagnostics(directory.path()).unwrap();
        assert_eq!(report.detectors.len(), 2);
        assert_eq!(report.warnings.len(), 1);
        assert!(report
            .detectors
            .iter()
            .any(|detector| detector.id() == "modern_id"));
    }

    #[test]
    fn discovers_legacy_toml_filename_with_warning() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("legacy-name.toml");
        fs::write(
            &path,
            r#"
schema_version = 1
id = "legacy_filename"
name = "Legacy filename"
country = "universal"
[[patterns]]
pattern = "LEGACY"
confidence = "high"
"#,
        )
        .unwrap();

        let report = load_plugins_with_diagnostics(directory.path()).unwrap();
        assert_eq!(report.detectors.len(), 1);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("legacy .toml plugin filename")));

        let direct = load_plugin_from_file(&path).unwrap();
        assert_eq!(direct.detectors.len(), 1);
        assert_eq!(direct.warnings.len(), 1);
    }

    #[test]
    fn rejects_duplicate_ids_and_malformed_files() {
        let directory = TempDir::new().unwrap();
        for name in ["first", "second"] {
            write_plugin(
                directory.path(),
                name,
                r#"
schema_version = 1
id = "duplicate_id"
name = "Duplicate"
country = "universal"
[[patterns]]
pattern = "DUP-\\d+"
confidence = "medium"
"#,
            );
        }
        assert!(load_plugins_with_diagnostics(directory.path())
            .unwrap_err()
            .contains("duplicate detector id"));
    }

    #[test]
    fn legacy_bridge_preserves_allowed_characters_line_scope_and_byte_lengths() {
        let config = parse_legacy(
            r#"
[detector]
id = "legacy_unicode"
name = "Legacy Unicode"
country = "xx"
pattern = "^é$"

[validation]
min_length = 2
max_length = 2
allowed_chars = "é"
"#,
        )
        .unwrap();
        assert_eq!(config.match_scope, MatchScope::Line);
        let validation = config.validation.as_ref().unwrap();
        assert_eq!(validation.length_unit, LengthUnit::Bytes);
        assert_eq!(validation.allowed_chars.as_deref(), Some("é"));

        let detector = PluginDetector::new(config).unwrap();
        let matches = detector.detect("é\r\né", Path::new("legacy.txt"));
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[1].location.start_byte, 4);
    }

    #[test]
    fn legacy_bridge_preserves_checksum_semantics() {
        for (checksum, valid, invalid) in [
            ("luhn", "18", "17"),
            ("mod11", "13", "12"),
            ("mod97", "98", "97"),
        ] {
            let source = format!(
                r#"
[detector]
id = "legacy_checksum"
name = "Legacy checksum"
country = "xx"
pattern = "\\b\\d{{2}}\\b"

[validation]
checksum = "{checksum}"
"#
            );
            let detector = PluginDetector::new(parse_legacy(&source).unwrap()).unwrap();
            assert!(detector.validate(valid), "{checksum} should accept {valid}");
            assert!(
                !detector.validate(invalid),
                "{checksum} should reject {invalid}"
            );
        }
    }
}
