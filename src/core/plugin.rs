/// Plugin system for loading custom detectors from TOML files
///
/// Plugins allow users to define custom pattern-based detectors without writing Rust code.
/// Plugin files are TOML files located in `~/.pii-radar/plugins/` directory.
///
/// Example plugin file (`~/.pii-radar/plugins/my_detector.toml`):
/// ```toml
/// [detector]
/// id = "custom_ssn"
/// name = "Custom SSN Detector"
/// country = "xx"
/// pattern = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
/// severity = "critical"
/// confidence = "medium"
///
/// [validation]
/// # Optional: Validation rules
/// min_length = 11
/// max_length = 11
/// checksum = "none"
/// ```
use crate::core::{Confidence, Detector, Match, Severity};
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for a custom detector plugin
#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub detector: DetectorConfig,
    #[serde(default)]
    pub validation: ValidationConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectorConfig {
    pub id: String,
    pub name: String,
    pub country: String,
    pub pattern: String,
    #[serde(default = "default_severity")]
    pub severity: SeverityLevel,
    #[serde(default = "default_confidence")]
    pub confidence: ConfidenceLevel,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationConfig {
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub max_length: Option<usize>,
    #[serde(default = "default_checksum")]
    pub checksum: ChecksumType,
    #[serde(default)]
    pub allowed_chars: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChecksumType {
    None,
    Luhn,
    Mod97,
    Mod11,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            min_length: None,
            max_length: None,
            checksum: ChecksumType::None,
            allowed_chars: None,
        }
    }
}

fn default_severity() -> SeverityLevel {
    SeverityLevel::High
}

fn default_confidence() -> ConfidenceLevel {
    ConfidenceLevel::Medium
}

fn default_checksum() -> ChecksumType {
    ChecksumType::None
}

impl From<SeverityLevel> for Severity {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Low => Severity::Low,
            SeverityLevel::Medium => Severity::Medium,
            SeverityLevel::High => Severity::High,
            SeverityLevel::Critical => Severity::Critical,
        }
    }
}

impl From<ConfidenceLevel> for Confidence {
    fn from(level: ConfidenceLevel) -> Self {
        match level {
            ConfidenceLevel::Low => Confidence::Low,
            ConfidenceLevel::Medium => Confidence::Medium,
            ConfidenceLevel::High => Confidence::High,
        }
    }
}

/// A custom detector loaded from a plugin file
pub struct PluginDetector {
    config: PluginConfig,
    pattern: Regex,
}

impl PluginDetector {
    /// Create a new plugin detector from configuration
    pub fn new(config: PluginConfig) -> Result<Self, String> {
        let pattern = Regex::new(&config.detector.pattern)
            .map_err(|e| format!("Invalid regex pattern: {}", e))?;

        Ok(Self { config, pattern })
    }

    /// Load a plugin from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let contents =
            fs::read_to_string(path).map_err(|e| format!("Failed to read plugin file: {}", e))?;

        let config: PluginConfig =
            toml::from_str(&contents).map_err(|e| format!("Failed to parse plugin TOML: {}", e))?;

        Self::new(config)
    }

    /// Validate a value according to the plugin's validation rules
    fn validate_value(&self, value: &str) -> bool {
        let validation = &self.config.validation;

        // Length checks
        if let Some(min) = validation.min_length {
            if value.len() < min {
                return false;
            }
        }
        if let Some(max) = validation.max_length {
            if value.len() > max {
                return false;
            }
        }

        // Character validation
        if let Some(ref allowed) = validation.allowed_chars {
            if !value.chars().all(|c| allowed.contains(c)) {
                return false;
            }
        }

        // Checksum validation
        match validation.checksum {
            ChecksumType::None => true,
            ChecksumType::Luhn => self.validate_luhn(value),
            ChecksumType::Mod97 => self.validate_mod97(value),
            ChecksumType::Mod11 => self.validate_mod11(value),
        }
    }

    fn validate_luhn(&self, value: &str) -> bool {
        let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();

        if digits.len() < 2 {
            return false;
        }

        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(index, &digit)| {
                if index % 2 == 1 {
                    let doubled = digit * 2;
                    if doubled > 9 {
                        doubled - 9
                    } else {
                        doubled
                    }
                } else {
                    digit
                }
            })
            .sum();

        sum.is_multiple_of(10)
    }

    fn validate_mod97(&self, value: &str) -> bool {
        let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

        if let Ok(num) = digits.parse::<u64>() {
            num % 97 == 1
        } else {
            false
        }
    }

    fn validate_mod11(&self, value: &str) -> bool {
        let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();

        if digits.is_empty() {
            return false;
        }

        // Standard mod 11 with weights 2, 3, 4, 5, 6, 7, 2, 3, 4, ...
        let sum: u32 = digits
            .iter()
            .enumerate()
            .map(|(i, &digit)| {
                let weight = (i % 6) + 2;
                digit * weight as u32
            })
            .sum();

        sum.is_multiple_of(11)
    }
}

impl Detector for PluginDetector {
    fn id(&self) -> &str {
        &self.config.detector.id
    }

    fn name(&self) -> &str {
        &self.config.detector.name
    }

    fn country(&self) -> &str {
        &self.config.detector.country
    }

    fn base_severity(&self) -> Severity {
        self.config.detector.severity.into()
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for cap in self.pattern.captures_iter(line) {
                if let Some(mat) = cap.get(0) {
                    let value = mat.as_str();

                    // Apply validation rules
                    if !self.validate_value(value) {
                        continue;
                    }

                    // Mask the value (show first 3 and last 2 chars)
                    let masked = crate::utils::mask_value(value);

                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: masked,
                        location: crate::core::types::Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1,
                            column: mat.start(),
                            start_byte: byte_offset + mat.start(),
                            end_byte: byte_offset + mat.end(),
                        },
                        confidence: self.config.detector.confidence.into(),
                        severity: self.base_severity(),
                        context: None,
                        gdpr_category: crate::core::types::GdprCategory::Regular,
                    });
                }
            }
            byte_offset += line.len() + 1; // +1 for newline
        }

        matches
    }

    fn validate(&self, value: &str) -> bool {
        self.pattern.is_match(value) && self.validate_value(value)
    }

    fn description(&self) -> Option<String> {
        self.config
            .detector
            .description
            .clone()
            .or_else(|| Some("Custom plugin detector".to_string()))
    }
}

/// Load all plugin detectors from the plugins directory
pub fn load_plugins(plugins_dir: &Path) -> Result<Vec<Box<dyn Detector>>, String> {
    if !plugins_dir.exists() {
        return Ok(Vec::new());
    }

    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

    let entries = fs::read_dir(plugins_dir)
        .map_err(|e| format!("Failed to read plugins directory: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            match PluginDetector::from_file(&path) {
                Ok(detector) => {
                    println!("✅ Loaded plugin: {} ({})", detector.name(), detector.id());
                    detectors.push(Box::new(detector));
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to load plugin {:?}: {}", path.file_name(), e);
                }
            }
        }
    }

    Ok(detectors)
}

/// Get the default plugins directory path
pub fn default_plugins_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".pii-radar")
        .join("plugins")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_plugin_config_parsing() {
        let toml_str = r#"
[detector]
id = "test_ssn"
name = "Test SSN"
country = "xx"
pattern = "\\d{3}-\\d{2}-\\d{4}"
severity = "high"
confidence = "medium"

[validation]
min_length = 11
max_length = 11
"#;

        let config: PluginConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.detector.id, "test_ssn");
        assert_eq!(config.detector.country, "xx");
        assert!(config.validation.min_length == Some(11));
    }

    #[test]
    fn test_plugin_detector_creation() {
        let config = PluginConfig {
            detector: DetectorConfig {
                id: "test_id".to_string(),
                name: "Test Detector".to_string(),
                country: "test".to_string(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                severity: SeverityLevel::High,
                confidence: ConfidenceLevel::Medium,
                description: None,
            },
            validation: ValidationConfig::default(),
        };

        let detector = PluginDetector::new(config).unwrap();
        assert_eq!(detector.id(), "test_id");
        assert_eq!(detector.country(), "test");
    }

    #[test]
    fn test_plugin_detector_pattern_matching() {
        let config = PluginConfig {
            detector: DetectorConfig {
                id: "test_ssn".to_string(),
                name: "Test SSN".to_string(),
                country: "xx".to_string(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                severity: SeverityLevel::High,
                confidence: ConfidenceLevel::High,
                description: None,
            },
            validation: ValidationConfig::default(),
        };

        let detector = PluginDetector::new(config).unwrap();
        let text = "SSN: 123-45-6789";
        let matches = detector.detect(text, Path::new("test.txt"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_plugin_luhn_validation() {
        let config = PluginConfig {
            detector: DetectorConfig {
                id: "test_card".to_string(),
                name: "Test Card".to_string(),
                country: "xx".to_string(),
                pattern: r"\b\d{16}\b".to_string(),
                severity: SeverityLevel::Critical,
                confidence: ConfidenceLevel::High,
                description: None,
            },
            validation: ValidationConfig {
                checksum: ChecksumType::Luhn,
                ..Default::default()
            },
        };

        let detector = PluginDetector::new(config).unwrap();

        // Valid Luhn: 4532015112830366 (Visa test card)
        assert!(detector.validate("4532015112830366"));

        // Invalid Luhn
        assert!(!detector.validate("1234567890123456"));
    }

    #[test]
    fn test_load_plugins_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        let plugin_path = temp_dir.path().join("test_plugin.toml");

        let toml_content = r#"
[detector]
id = "custom_id"
name = "Custom ID"
country = "xx"
pattern = "\\bCUST\\d{6}\\b"
severity = "medium"
confidence = "high"
"#;

        let mut file = fs::File::create(&plugin_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let detectors = load_plugins(temp_dir.path()).unwrap();
        assert_eq!(detectors.len(), 1);
        assert_eq!(detectors[0].id(), "custom_id");
    }

    #[test]
    fn test_length_validation() {
        let config = PluginConfig {
            detector: DetectorConfig {
                id: "test_len".to_string(),
                name: "Test Length".to_string(),
                country: "xx".to_string(),
                pattern: r"\b\d+\b".to_string(),
                severity: SeverityLevel::High,
                confidence: ConfidenceLevel::High,
                description: None,
            },
            validation: ValidationConfig {
                min_length: Some(5),
                max_length: Some(10),
                ..Default::default()
            },
        };

        let detector = PluginDetector::new(config).unwrap();

        // Too short
        assert!(!detector.validate("1234"));

        // Just right
        assert!(detector.validate("12345"));
        assert!(detector.validate("1234567890"));

        // Too long
        assert!(!detector.validate("12345678901"));
    }
}
