/// Plugin-based detector for custom PII patterns
///
/// Allows users to define custom PII detectors via TOML configuration files.
use crate::core::detector::Detector;
use crate::core::types::{Confidence, GdprCategory, Location, Match, Severity};
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Plugin detector configuration loaded from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub id: String,
    pub name: String,
    pub country: String,
    pub category: String,
    pub description: String,
    pub patterns: Vec<PatternConfig>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub validation: Option<ValidationConfig>,
    #[serde(default)]
    pub examples: Vec<String>,
    #[serde(default)]
    pub context_keywords: Vec<String>,
}

fn default_severity() -> String {
    "medium".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternConfig {
    pub pattern: String,
    pub confidence: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let mut patterns = Vec::new();
        for pc in &config.patterns {
            let regex = Regex::new(&pc.pattern)
                .map_err(|e| format!("Invalid regex '{}': {}", pc.pattern, e))?;
            let confidence = match pc.confidence.to_lowercase().as_str() {
                "low" => Confidence::Low,
                "medium" => Confidence::Medium,
                "high" => Confidence::High,
                _ => return Err(format!("Invalid confidence: {}", pc.confidence)),
            };
            patterns.push(CompiledPattern { regex, confidence });
        }

        if patterns.is_empty() {
            return Err("Plugin must have at least one pattern".to_string());
        }

        let severity = match config.severity.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return Err(format!("Invalid severity: {}", config.severity)),
        };

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
        let Some(ref validation) = self.config.validation else {
            return true;
        };

        let len = value.len();
        if let Some(min) = validation.min_length {
            if len < min {
                return false;
            }
        }
        if let Some(max) = validation.max_length {
            if len > max {
                return false;
            }
        }
        if let Some(ref prefix) = validation.required_prefix {
            if !value.starts_with(prefix) {
                return false;
            }
        }
        if let Some(ref suffix) = validation.required_suffix {
            if !value.ends_with(suffix) {
                return false;
            }
        }

        if let Some(ref checksum) = validation.checksum {
            match checksum.to_lowercase().as_str() {
                "luhn" => return crate::utils::checksum::validate_luhn(value),
                "mod11" | "bsn" => return crate::utils::checksum::validate_bsn_11_proef(value),
                "iban" => return crate::utils::checksum::validate_iban(value),
                _ => eprintln!("Warning: Unknown checksum '{}'", checksum),
            }
        }

        true
    }
}

impl Detector for PluginDetector {
    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        
        for compiled in &self.patterns {
            for cap in compiled.regex.captures_iter(text).flatten() {
                let matched = cap.get(0).unwrap();
                let value = matched.as_str();
                
                if !self.validate_match(value) {
                    continue;
                }
                
                let start = matched.start();
                let preceding = &text[..start];
                let line = preceding.matches('\n').count() + 1;
                let column = preceding.rfind('\n').map(|p| start - p - 1).unwrap_or(start);
                let value_masked = crate::utils::masking::mask_value(value);
                
                matches.push(Match {
                    detector_id: self.config.id.clone(),
                    detector_name: self.config.name.clone(),
                    country: self.config.country.clone(),
                    value_masked,
                    location: Location {
                        file_path: file_path.to_path_buf(),
                        line,
                        column,
                        start_byte: start,
                        end_byte: start + value.len(),
                    },
                    confidence: compiled.confidence,
                    severity: self.severity,
                    context: None,
                    gdpr_category: GdprCategory::Regular,
                });
            }
        }
        
        matches
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_config() -> PluginConfig {
        PluginConfig {
            id: "test_emp".to_string(),
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
                checksum: None,
                required_prefix: Some("EMP-".to_string()),
                required_suffix: None,
            }),
            examples: vec![],
            context_keywords: vec![],
        }
    }
    
    #[test]
    fn test_creation() {
        assert!(PluginDetector::new(test_config()).is_ok());
    }
    
    #[test]
    fn test_detection() {
        let detector = PluginDetector::new(test_config()).unwrap();
        let matches = detector.detect("Employee EMP-123456 here", Path::new("test.txt"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "test_emp");
    }
    
    #[test]
    fn test_validation() {
        let detector = PluginDetector::new(test_config()).unwrap();
        let matches = detector.detect("EMP-12345", Path::new("test.txt"));
        assert_eq!(matches.len(), 0); // Wrong length
    }
}
