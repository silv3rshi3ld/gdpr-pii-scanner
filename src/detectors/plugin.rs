//! Declarative custom detectors.
//!
//! Version 1 plugins use a top-level TOML document and one or more patterns.
//! Patterns are compiled with Rust's linear-time `regex` engine.

use crate::core::detector::Detector;
use crate::core::types::{Confidence, GdprCategory, Location, Match, Severity};
use crate::core::DetectionOutcome;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const PLUGIN_SCHEMA_VERSION: u32 = 1;
const MAX_COMPILED_REGEX_BYTES: usize = 1024 * 1024;
const MAX_REGEX_NESTING: u32 = 128;

fn default_schema_version() -> u32 {
    PLUGIN_SCHEMA_VERSION
}

fn default_category() -> String {
    "custom".to_string()
}

fn default_severity() -> String {
    "medium".to_string()
}

/// Canonical v1 plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub country: String,
    /// Informational metadata; it does not alter GDPR classification in schema version 1.
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub description: String,
    pub patterns: Vec<PatternConfig>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub validation: Option<ValidationConfig>,
    #[serde(default)]
    pub examples: Vec<String>,
    /// Informational metadata; these values are not context-classification rules.
    #[serde(default)]
    pub context_keywords: Vec<String>,
    /// Whether regular expressions run against the complete document or each line separately.
    #[serde(default)]
    pub match_scope: MatchScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternConfig {
    pub pattern: String,
    pub confidence: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationConfig {
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub max_length: Option<usize>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub required_prefix: Option<String>,
    #[serde(default)]
    pub required_suffix: Option<String>,
    /// Optional set of characters permitted in the complete matched value.
    #[serde(default)]
    pub allowed_chars: Option<String>,
    /// Unit used by `min_length` and `max_length`.
    #[serde(default)]
    pub length_unit: LengthUnit,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchScope {
    /// Match patterns against the complete extracted document.
    #[default]
    Document,
    /// Match patterns independently against each line.
    Line,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthUnit {
    /// Count Unicode scalar values.
    #[default]
    Characters,
    /// Count UTF-8 bytes. This preserves the legacy plugin schema's behavior.
    Bytes,
}

#[derive(Debug)]
pub struct PluginDetector {
    config: PluginConfig,
    patterns: Vec<CompiledPattern>,
    severity: Severity,
}

#[derive(Debug)]
struct CompiledPattern {
    regex: Regex,
    confidence: Confidence,
}

impl PluginDetector {
    pub fn new(config: PluginConfig) -> Result<Self, String> {
        validate_config(&config)?;

        let mut patterns = Vec::with_capacity(config.patterns.len());
        for pattern in &config.patterns {
            let regex = compile_plugin_regex(&pattern.pattern)
                .map_err(|error| format!("invalid regex for plugin '{}': {error}", config.id))?;
            patterns.push(CompiledPattern {
                regex,
                confidence: parse_confidence(&pattern.confidence)?,
            });
        }

        let severity = parse_severity(&config.severity)?;
        Ok(Self {
            config,
            patterns,
            severity,
        })
    }

    pub fn config(&self) -> &PluginConfig {
        &self.config
    }

    fn validate_match(&self, value: &str) -> bool {
        let Some(validation) = &self.config.validation else {
            return true;
        };

        let length = match validation.length_unit {
            LengthUnit::Characters => value.chars().count(),
            LengthUnit::Bytes => value.len(),
        };
        if validation
            .min_length
            .is_some_and(|minimum| length < minimum)
            || validation
                .max_length
                .is_some_and(|maximum| length > maximum)
        {
            return false;
        }
        if validation
            .required_prefix
            .as_ref()
            .is_some_and(|prefix| !value.starts_with(prefix))
            || validation
                .required_suffix
                .as_ref()
                .is_some_and(|suffix| !value.ends_with(suffix))
        {
            return false;
        }
        if validation
            .allowed_chars
            .as_ref()
            .is_some_and(|allowed| !value.chars().all(|character| allowed.contains(character)))
        {
            return false;
        }

        match validation.checksum.as_deref().map(str::to_ascii_lowercase) {
            None => true,
            Some(checksum) if checksum == "none" => true,
            Some(checksum) if checksum == "luhn" => validate_generic_luhn(value),
            Some(checksum) if checksum == "mod97" => validate_numeric_mod97(value),
            Some(checksum) if checksum == "mod11" => validate_generic_mod11(value),
            Some(checksum) if checksum == "bsn" => {
                crate::utils::checksum::validate_bsn_11_proef(value)
            }
            Some(checksum) if checksum == "iban" => crate::utils::checksum::validate_iban(value),
            Some(_) => false,
        }
    }
}

fn compile_plugin_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(MAX_COMPILED_REGEX_BYTES)
        .dfa_size_limit(MAX_COMPILED_REGEX_BYTES)
        .nest_limit(MAX_REGEX_NESTING)
        .build()
}

impl Detector for PluginDetector {
    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        self.detect_limited(text, file_path, Confidence::Low, usize::MAX)
            .matches
    }

    fn detect_limited(
        &self,
        text: &str,
        file_path: &Path,
        minimum_confidence: Confidence,
        limit: usize,
    ) -> DetectionOutcome {
        // A pattern may overlap another pattern in the same plugin. Keep one finding per span,
        // choosing the strongest configured confidence for deterministic output.
        let mut spans: BTreeMap<(usize, usize), Confidence> = BTreeMap::new();
        let mut truncated = false;
        for compiled in &self.patterns {
            if compiled.confidence < minimum_confidence {
                continue;
            }
            match self.config.match_scope {
                MatchScope::Document => {
                    if !self.add_pattern_matches_limited(compiled, text, 0, limit, &mut spans) {
                        truncated = true;
                        break;
                    }
                }
                MatchScope::Line => {
                    let mut byte_offset = 0;
                    for segment in text.split_inclusive('\n') {
                        let line = if let Some(without_lf) = segment.strip_suffix('\n') {
                            without_lf.strip_suffix('\r').unwrap_or(without_lf)
                        } else {
                            segment
                        };
                        if !self.add_pattern_matches_limited(
                            compiled,
                            line,
                            byte_offset,
                            limit,
                            &mut spans,
                        ) {
                            truncated = true;
                            break;
                        }
                        byte_offset += segment.len();
                    }
                    if truncated {
                        break;
                    }
                }
            }
        }

        let matches = spans
            .into_iter()
            .map(|((start, end), confidence)| {
                let line_start = text[..start].rfind('\n').map_or(0, |offset| offset + 1);
                let line = text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
                let column = text[line_start..start].chars().count();
                Match {
                    detector_id: self.config.id.clone(),
                    detector_name: self.config.name.clone(),
                    country: self.config.country.clone(),
                    value_masked: crate::utils::masking::mask_value(&text[start..end]),
                    location: Location {
                        file_path: file_path.to_path_buf(),
                        line,
                        column,
                        start_byte: start,
                        end_byte: end,
                    },
                    confidence,
                    severity: self.severity,
                    context: None,
                    gdpr_category: GdprCategory::Regular,
                }
            })
            .collect();
        DetectionOutcome {
            matches,
            truncated,
            omitted_matches: usize::from(truncated),
        }
    }

    fn id(&self) -> &str {
        &self.config.id
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn country(&self) -> &str {
        &self.config.country
    }

    fn base_severity(&self) -> Severity {
        self.severity
    }

    fn validate(&self, value: &str) -> bool {
        self.validate_match(value)
            && self
                .patterns
                .iter()
                .any(|pattern| pattern.regex.is_match(value))
    }

    fn description(&self) -> Option<String> {
        (!self.config.description.is_empty()).then(|| self.config.description.clone())
    }
}

impl PluginDetector {
    /// Returns `false` after observing the first unique qualifying overflow.
    fn add_pattern_matches_limited(
        &self,
        compiled: &CompiledPattern,
        text: &str,
        byte_offset: usize,
        limit: usize,
        spans: &mut BTreeMap<(usize, usize), Confidence>,
    ) -> bool {
        for matched in compiled.regex.find_iter(text) {
            if self.validate_match(matched.as_str()) {
                let span = (byte_offset + matched.start(), byte_offset + matched.end());
                if let Some(confidence) = spans.get_mut(&span) {
                    *confidence = (*confidence).max(compiled.confidence);
                } else if spans.len() >= limit {
                    return false;
                } else {
                    spans.insert(span, compiled.confidence);
                }
            }
        }
        true
    }
}

fn validate_generic_luhn(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter_map(|character| character.to_digit(10))
        .collect();
    if digits.len() < 2 {
        return false;
    }

    digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                *digit
            }
        })
        .fold(0_u32, |sum, digit| (sum + digit) % 10)
        .is_multiple_of(10)
}

fn validate_numeric_mod97(value: &str) -> bool {
    let digits: String = value
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();
    digits.parse::<u64>().is_ok_and(|number| number % 97 == 1)
}

fn validate_generic_mod11(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter_map(|character| character.to_digit(10))
        .collect();
    !digits.is_empty()
        && digits
            .iter()
            .enumerate()
            .fold(0_u32, |sum, (index, digit)| {
                (sum + digit * ((index % 6) as u32 + 2)) % 11
            })
            .is_multiple_of(11)
}

fn validate_config(config: &PluginConfig) -> Result<(), String> {
    if config.schema_version != PLUGIN_SCHEMA_VERSION {
        return Err(format!(
            "unsupported plugin schema_version {}; expected {}",
            config.schema_version, PLUGIN_SCHEMA_VERSION
        ));
    }
    if !valid_id(&config.id) {
        return Err(format!(
            "invalid plugin id '{}'; use 3-64 lowercase ASCII letters, digits, or underscores",
            config.id
        ));
    }
    if config.name.trim().is_empty() {
        return Err("plugin name must not be empty".to_string());
    }
    let valid_country = config.country == "universal"
        || (config.country.len() == 2
            && config.country.bytes().all(|byte| byte.is_ascii_lowercase()));
    if !valid_country {
        return Err(format!(
            "invalid country '{}'; use a lowercase two-letter code or 'universal'",
            config.country
        ));
    }
    if config.patterns.is_empty() {
        return Err("plugin must contain at least one [[patterns]] entry".to_string());
    }
    if config.patterns.len() > 64 {
        return Err("plugin may contain at most 64 patterns".to_string());
    }
    if config
        .patterns
        .iter()
        .any(|pattern| pattern.pattern.len() > 8_192)
    {
        return Err("plugin patterns may not exceed 8192 bytes".to_string());
    }
    parse_severity(&config.severity)?;
    for pattern in &config.patterns {
        parse_confidence(&pattern.confidence)?;
    }
    if let Some(validation) = &config.validation {
        if validation
            .min_length
            .zip(validation.max_length)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return Err("validation min_length must not exceed max_length".to_string());
        }
        if let Some(checksum) = &validation.checksum {
            match checksum.to_ascii_lowercase().as_str() {
                "none" | "luhn" | "mod97" | "mod11" | "bsn" | "iban" => {}
                _ => return Err(format!("unsupported plugin checksum '{checksum}'")),
            }
        }
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    (3..=64).contains(&id.len())
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn parse_confidence(value: &str) -> Result<Confidence, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        _ => Err(format!("invalid confidence '{value}'")),
    }
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("invalid severity '{value}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PluginConfig {
        PluginConfig {
            schema_version: 1,
            id: "test_employee".to_string(),
            name: "Employee ID".to_string(),
            country: "universal".to_string(),
            category: "custom".to_string(),
            description: "Test detector".to_string(),
            severity: "medium".to_string(),
            patterns: vec![PatternConfig {
                pattern: r"EMP-\d{6}".to_string(),
                confidence: "high".to_string(),
                description: None,
            }],
            validation: Some(ValidationConfig {
                min_length: Some(10),
                max_length: Some(10),
                required_prefix: Some("EMP-".to_string()),
                ..ValidationConfig::default()
            }),
            examples: vec![],
            context_keywords: vec![],
            match_scope: MatchScope::Document,
        }
    }

    #[test]
    fn detects_with_unicode_column_and_crlf() {
        let detector = PluginDetector::new(test_config()).unwrap();
        let matches = detector.detect("first\r\néé EMP-123456", Path::new("test.txt"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].location.line, 2);
        assert_eq!(matches[0].location.column, 3);
        assert_eq!(
            &"first\r\néé EMP-123456"[matches[0].location.start_byte..matches[0].location.end_byte],
            "EMP-123456"
        );
    }

    #[test]
    fn rejects_unsupported_regex_features() {
        let mut config = test_config();
        config.patterns[0].pattern = r"(?=EMP)EMP-\d+".to_string();
        assert!(PluginDetector::new(config)
            .unwrap_err()
            .contains("invalid regex"));
    }

    #[test]
    fn rejects_regexes_that_exceed_compilation_budgets() {
        assert!(compile_plugin_regex(r"(?:[A-Za-z0-9]{1000}){1000}").is_err());

        let deeply_nested = format!("{}a{}", "(".repeat(256), ")".repeat(256));
        assert!(compile_plugin_regex(&deeply_nested).is_err());
    }

    #[test]
    fn applies_allowed_characters_and_exact_checksum_algorithms() {
        let mut config = test_config();
        config.patterns[0].pattern = r"[A-Z0-9-]+".to_string();
        config.validation = Some(ValidationConfig {
            allowed_chars: Some("EMP-0123456789".to_string()),
            ..ValidationConfig::default()
        });
        let detector = PluginDetector::new(config).unwrap();
        assert!(detector.validate("EMP-13"));
        assert!(!detector.validate("EMP-X3"));

        let mut config = test_config();
        config.patterns[0].pattern = r"\d{2}".to_string();
        config.validation = Some(ValidationConfig {
            checksum: Some("mod11".to_string()),
            ..ValidationConfig::default()
        });
        let detector = PluginDetector::new(config).unwrap();
        assert!(detector.validate("13"));
        assert!(!detector.validate("12"));

        let mut config = test_config();
        config.patterns[0].pattern = r"\d{2}".to_string();
        config.validation = Some(ValidationConfig {
            checksum: Some("mod97".to_string()),
            ..ValidationConfig::default()
        });
        let detector = PluginDetector::new(config).unwrap();
        assert!(detector.validate("98"));
        assert!(!detector.validate("97"));
    }

    #[test]
    fn supports_explicit_line_scope_and_byte_lengths() {
        let mut config = test_config();
        config.patterns[0].pattern = r"^EMP-\d{6}$".to_string();
        config.match_scope = MatchScope::Line;
        config.validation = None;
        let detector = PluginDetector::new(config).unwrap();
        let matches = detector.detect("EMP-123456\r\nEMP-654321", Path::new("test.txt"));
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[1].location.start_byte, 12);

        let mut config = test_config();
        config.patterns[0].pattern = "é".to_string();
        config.validation = Some(ValidationConfig {
            min_length: Some(2),
            max_length: Some(2),
            length_unit: LengthUnit::Bytes,
            ..ValidationConfig::default()
        });
        let detector = PluginDetector::new(config).unwrap();
        assert!(detector.validate("é"));
    }
}
