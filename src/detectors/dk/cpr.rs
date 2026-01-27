/// Denmark CPR detector
/// 
/// CPR (Central Person Register) is a 10-digit Danish national identification number.
///
/// Format: DDMMYY-SSSC
/// - DD: Day of birth
/// - MM: Month of birth
/// - YY: Year of birth (2 digits)
/// - SSS: Sequence number
/// - C: Check digit (modulus 11)
///
/// Validation: Weighted sum with weights [4,3,2,7,6,5,4,3,2,1] mod 11 must equal 0
use crate::core::{Confidence, Detector, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static CPR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{6}-?\d{4}\b").expect("Invalid CPR regex pattern")
});

pub struct CprDetector;

impl CprDetector {
    pub fn new() -> Self {
        Self
    }
    
    /// Validate CPR using modulus 11 check
    fn validate_cpr(cpr: &str) -> bool {
        let normalized = cpr.replace('-', "");
        if normalized.len() != 10 {
            return false;
        }
        
        let digits: Vec<u32> = normalized.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 10 {
            return false;
        }
        
        // Weights: 4, 3, 2, 7, 6, 5, 4, 3, 2, 1
        let weights = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1];
        
        let sum: u32 = digits.iter().zip(weights.iter()).map(|(d, w)| d * w).sum();
        
        sum % 11 == 0
    }
    
    /// Validate date components
    fn validate_date(cpr: &str) -> bool {
        let normalized = cpr.replace('-', "");
        let digits: Vec<u32> = normalized.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 10 {
            return false;
        }
        
        let day = digits[0] * 10 + digits[1];
        let month = digits[2] * 10 + digits[3];
        
        // Month must be 1-12
        if !(1..=12).contains(&month) {
            return false;
        }
        
        // Day must be 1-31
        if !(1..=31).contains(&day) {
            return false;
        }
        
        // Basic month-day validation
        if month == 2 && day > 29 {
            return false;
        }
        
        if [4, 6, 9, 11].contains(&month) && day > 30 {
            return false;
        }
        
        true
    }
}

impl Detector for CprDetector {
    fn id(&self) -> &str {
        "danish_cpr"
    }
    
    fn name(&self) -> &str {
        "Danish CPR (Central Person Register)"
    }
    
    fn country(&self) -> &str {
        "dk"
    }
    
    fn base_severity(&self) -> Severity {
        Severity::Critical
    }
    
    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;
        
        for (line_num, line) in text.lines().enumerate() {
            for cap in CPR_PATTERN.captures_iter(line) {
                if let Some(mat) = cap.get(0) {
                    let value = mat.as_str();
                    
                    // First validate date format
                    if !Self::validate_date(value) {
                        continue;
                    }
                    
                    // Then validate checksum
                    if !Self::validate_cpr(value) {
                        continue;
                    }
                    
                    let digits = value.replace('-', "");
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(&digits),
                        location: crate::core::types::Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1,
                            column: mat.start(),
                            start_byte: byte_offset + mat.start(),
                            end_byte: byte_offset + mat.end(),
                        },
                        confidence: Confidence::High,
                        severity: self.base_severity(),
                        context: None,
                        gdpr_category: crate::core::GdprCategory::Regular,
                    });
                }
            }
            byte_offset += line.len() + 1;
        }
        
        matches
    }
}

impl Default for CprDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_valid_cpr() {
        assert!(CprDetector::validate_cpr("070985-1004")); // Valid CPR
        assert!(CprDetector::validate_cpr("0709851004"));  // Without dash
    }
    
    #[test]
    fn test_invalid_cpr_checksum() {
        assert!(!CprDetector::validate_cpr("070985-1456")); // Wrong checksum
    }
    
    #[test]
    fn test_invalid_date() {
        assert!(!CprDetector::validate_date("320185-1455")); // Day 32
        assert!(!CprDetector::validate_date("071385-1455")); // Month 13
    }
    
    #[test]
    fn test_detector_finds_valid_cpr() {
        let detector = CprDetector::new();
        let text = "CPR: 070985-1004";
        let path = PathBuf::from("test.txt");
        
        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "dk");
    }
    
    #[test]
    fn test_detector_rejects_invalid_cpr() {
        let detector = CprDetector::new();
        let text = "Random: 1234567890";
        let path = PathBuf::from("test.txt");
        
        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }
}
