//! Configuration discovery, validation, and CLI precedence.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const SUPPORTED_COUNTRY_CODES: &[&str] = &[
    "be", "de", "dk", "es", "fi", "fr", "gb", "it", "nl", "no", "pl", "pt", "se",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub scan: ScanConfig,
    pub output: OutputConfig,
    #[serde(rename = "limits", alias = "filters")]
    pub filters: FilterConfig,
    pub plugins: Option<PluginConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub min_confidence: String,
    pub extract_documents: bool,
    pub max_threads: Option<usize>,
    pub countries: Vec<String>,
    pub no_context: bool,
    pub include_redacted_snippets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    pub format: String,
    pub output_path: Option<PathBuf>,
    pub full_paths: bool,
    pub no_progress: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    pub max_filesize_mb: u64,
    pub max_total_size_mb: u64,
    pub max_files: usize,
    pub max_depth: Option<usize>,
    pub max_matches_per_source: usize,
    pub max_matches: usize,
    pub max_extracted_size_mb: u64,
}

pub type LimitsConfig = FilterConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginConfig {
    pub directories: Vec<PathBuf>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub sources: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct CliOverrides {
    pub countries: Option<String>,
    pub min_confidence: Option<String>,
    pub extract_documents: bool,
    pub no_context: bool,
    pub include_redacted_snippets: bool,
    pub threads: Option<usize>,
    pub format: Option<String>,
    pub output: Option<PathBuf>,
    pub no_progress: bool,
    pub full_paths: bool,
    pub max_filesize: Option<u64>,
    pub max_depth: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            output: OutputConfig::default(),
            filters: FilterConfig::default(),
            plugins: Some(PluginConfig::default()),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_confidence: "high".to_string(),
            extract_documents: false,
            max_threads: None,
            countries: Vec::new(),
            no_context: false,
            include_redacted_snippets: false,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "terminal".to_string(),
            output_path: None,
            full_paths: false,
            no_progress: false,
        }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            max_filesize_mb: 100,
            max_total_size_mb: 10 * 1024,
            max_files: 100_000,
            max_depth: None,
            max_matches_per_source: 10_000,
            max_matches: 100_000,
            max_extracted_size_mb: 100,
        }
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            directories: default_plugin_dirs(),
            enabled: true,
        }
    }
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))?;
        let config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file: {}", path.as_ref().display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Load all discovered layers using `defaults < user < project < explicit` precedence.
    pub fn load_resolved(explicit: Option<&Path>, no_config: bool) -> Result<LoadedConfig> {
        if no_config && explicit.is_some() {
            bail!("--config and --no-config cannot be used together");
        }
        if no_config {
            let config = Self {
                plugins: None,
                ..Self::default()
            };
            return Ok(LoadedConfig {
                config,
                sources: Vec::new(),
                warnings: Vec::new(),
            });
        }

        let mut paths = Vec::new();
        let mut warnings = Vec::new();
        if let Some(user) = user_config_path() {
            if user.exists() {
                paths.push(user);
            } else if let Some(legacy) = legacy_user_config_path().filter(|path| path.exists()) {
                warnings.push(format!(
                    "legacy config location {} is deprecated; move it to {}",
                    legacy.display(),
                    user.display()
                ));
                paths.push(legacy);
            }
        }

        let project = PathBuf::from(".pii-radar.toml");
        if project.exists() {
            paths.push(project);
        }
        if let Some(path) = explicit {
            if !path.is_file() {
                bail!("config file does not exist: {}", path.display());
            }
            paths.push(path.to_path_buf());
        }

        let mut merged = toml::Value::try_from(Self::default())
            .context("failed to construct default configuration")?;
        for path in &paths {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read config file: {}", path.display()))?;
            let mut layer: toml::Value = toml::from_str(&contents)
                .with_context(|| format!("failed to parse config file: {}", path.display()))?;
            normalize_legacy_keys(&mut layer)?;
            merge_toml(&mut merged, layer);
        }

        let config: Self = merged
            .try_into()
            .context("configuration contains unknown or invalid fields")?;
        config.validate()?;
        Ok(LoadedConfig {
            config,
            sources: paths,
            warnings,
        })
    }

    /// Compatibility helper. Prefer [`Config::load_resolved`].
    pub fn load_default() -> Result<Option<Self>> {
        let loaded = Self::load_resolved(None, false)?;
        Ok((!loaded.sources.is_empty()).then_some(loaded.config))
    }

    pub fn merge_with_cli(mut self, overrides: CliOverrides) -> Self {
        if let Some(countries) = overrides.countries {
            self.scan.countries = split_list(&countries);
        }
        if let Some(confidence) = overrides.min_confidence {
            self.scan.min_confidence = confidence;
        }
        self.scan.extract_documents |= overrides.extract_documents;
        self.scan.no_context |= overrides.no_context;
        self.scan.include_redacted_snippets |= overrides.include_redacted_snippets;
        if let Some(threads) = overrides.threads {
            self.scan.max_threads = Some(threads);
        }
        if let Some(format) = overrides.format {
            self.output.format = format;
        }
        if let Some(output) = overrides.output {
            self.output.output_path = Some(output);
        }
        self.output.no_progress |= overrides.no_progress;
        self.output.full_paths |= overrides.full_paths;
        if let Some(size) = overrides.max_filesize {
            self.filters.max_filesize_mb = size;
        }
        if let Some(depth) = overrides.max_depth {
            self.filters.max_depth = Some(depth);
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        if !matches!(self.scan.min_confidence.as_str(), "low" | "medium" | "high") {
            bail!("scan.min_confidence must be low, medium, or high");
        }
        if !matches!(
            self.output.format.as_str(),
            "terminal" | "json" | "json-compact" | "html" | "csv"
        ) {
            bail!("output.format must be terminal, json, json-compact, html, or csv");
        }
        if self
            .scan
            .max_threads
            .is_some_and(|threads| !(1..=crate::crawler::walker::MAX_THREADS).contains(&threads))
        {
            bail!(
                "scan.max_threads must be between 1 and {}",
                crate::crawler::walker::MAX_THREADS
            );
        }
        if self.filters.max_depth == Some(0) {
            bail!("limits.max_depth must be at least 1");
        }
        if self.scan.no_context && self.scan.include_redacted_snippets {
            bail!("scan.include_redacted_snippets requires context analysis");
        }
        if self.filters.max_filesize_mb == 0
            || self.filters.max_total_size_mb == 0
            || self.filters.max_files == 0
            || self.filters.max_matches_per_source == 0
            || self.filters.max_matches == 0
            || self.filters.max_extracted_size_mb == 0
        {
            bail!("all configured limits must be greater than zero");
        }
        if self.filters.max_matches_per_source > self.filters.max_matches {
            bail!("limits.max_matches_per_source must not exceed limits.max_matches");
        }
        for country in &self.scan.countries {
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_lowercase()) {
                bail!("invalid country code '{country}'; use lowercase ISO alpha-2 codes");
            }
            if !SUPPORTED_COUNTRY_CODES.contains(&country.as_str()) {
                bail!(
                    "unsupported country code '{country}'; supported codes: {}",
                    SUPPORTED_COUNTRY_CODES.join(", ")
                );
            }
        }
        Ok(())
    }

    /// Kept for source compatibility. v0.6 common configuration does not expand arbitrary
    /// strings because credentials and target definitions are intentionally not stored here.
    #[deprecated(note = "v0.6 configuration does not store credential-bearing target strings")]
    pub fn expand_env_vars(&mut self) {}
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn merge_toml(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(existing) => merge_toml(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn normalize_legacy_keys(value: &mut toml::Value) -> Result<()> {
    let Some(table) = value.as_table_mut() else {
        bail!("configuration root must be a TOML table");
    };
    if table.contains_key("limits") && table.contains_key("filters") {
        bail!("configuration must not contain both [limits] and legacy [filters]");
    }
    if let Some(filters) = table.remove("filters") {
        table.insert("limits".to_string(), filters);
    }
    Ok(())
}

fn user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|path| path.join("pii-radar").join("config.toml"))
}

fn legacy_user_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|path| path.join(".pii-radar").join("config.toml"))
}

fn default_plugins_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pii-radar")
        .join("plugins")
}

fn default_plugin_dirs() -> Vec<PathBuf> {
    let mut directories = vec![default_plugins_dir()];
    if let Some(legacy) = dirs::home_dir().map(|path| path.join(".pii-radar").join("plugins")) {
        if !directories.contains(&legacy) {
            directories.push(legacy);
        }
    }
    directories.push(PathBuf::from("plugins"));
    directories
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_are_safe_and_valid() {
        let config = Config::default();
        assert_eq!(config.scan.min_confidence, "high");
        assert_eq!(config.filters.max_filesize_mb, 100);
        assert!(!config.scan.include_redacted_snippets);
        config.validate().unwrap();
    }

    #[test]
    fn explicit_config_merges_over_defaults() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            r#"
[scan]
min_confidence = "medium"
countries = ["nl", "de"]

[limits]
max_filesize_mb = 5
"#,
        )
        .unwrap();

        let loaded = Config::load_resolved(Some(&path), false).unwrap();
        assert_eq!(loaded.config.scan.min_confidence, "medium");
        assert_eq!(loaded.config.filters.max_filesize_mb, 5);
        assert_eq!(loaded.config.filters.max_files, 100_000);
    }

    #[test]
    fn legacy_filters_alias_merges_over_default_limits() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(&path, "[filters]\nmax_filesize_mb = 7\n").unwrap();

        let loaded = Config::load_resolved(Some(&path), false).unwrap();
        assert_eq!(loaded.config.filters.max_filesize_mb, 7);
        assert_eq!(loaded.config.filters.max_files, 100_000);
    }

    #[test]
    fn rejects_unknown_and_invalid_fields() {
        let directory = TempDir::new().unwrap();
        let unknown = directory.path().join("unknown.toml");
        fs::write(&unknown, "[api]\nendpoints = []\n").unwrap();
        assert!(Config::load_resolved(Some(&unknown), false).is_err());

        let invalid = directory.path().join("invalid.toml");
        fs::write(&invalid, "[scan]\nmax_threads = 0\n").unwrap();
        assert!(Config::load_resolved(Some(&invalid), false).is_err());
    }

    #[test]
    fn rejects_well_formed_but_unsupported_country_codes() {
        let mut config = Config::default();
        config.scan.countries = vec!["nd".to_string()];
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("unsupported country code 'nd'"));

        config.scan.countries = vec!["nl".to_string(), "de".to_string()];
        config.validate().unwrap();
    }

    #[test]
    fn config_and_no_config_conflict() {
        assert!(Config::load_resolved(Some(Path::new("unused")), true).is_err());
        assert!(Config::load_resolved(None, true)
            .unwrap()
            .config
            .plugins
            .is_none());
    }
}
