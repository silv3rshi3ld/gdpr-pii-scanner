/// Poland PESEL detector
/// 
/// PESEL (Powszechny Elektroniczny System Ewidencji Ludności) is an 11-digit
/// Polish national identification number.
///
/// Format: YYMMDDZZZZC
/// - YY: Year of birth (last 2 digits)
/// - MM: Month of birth (with century encoding: +20 for 2000-2099, +40 for 2100-2199, +60 for 2200-2299, +80 for 1800-1899)
/// - DD: Day of birth
/// - ZZZZ: Sequence number (even for females, odd for males)
/// - C: Check digit (weighted modulus 10)
///
/// Validation: Weighted sum with weights [1,3,7,9,1,3,7,9,1,3] mod 10
use crate::core::{Confidence, Detector, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static PESEL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{11}\b").expect("Invalid PESEL regex pattern")
});

pub struct PeselDetector;

impl PeselDetector {
    pub fn new() -> Self {
        Self
    }
    
    /// Validate PESEL using weighted checksum
    fn validate_pesel(pesel: &str) -> bool {
        if pesel.len() != 11 {
            return false;
        }
        
        let digits: Vec<u32> = pesel.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 11 {
            return false;
        }
        
        // Weights: 1, 3, 7, 9, 1, 3, 7, 9, 1, 3 (for first 10 digits)
        let weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
        
        let mut sum = 0;
        for (i, &digit) in digits[..10].iter().enumerate() {
            sum += digit * weights[i];
        }
        
        let check_digit = (10 - (sum % 10)) % 10;
        check_digit == digits[10]
    }
    
    /// Validate date components
    fn validate_date(pesel: &str) -> bool {
        let digits: Vec<u32> = pesel.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 11 {
            return false;
        }
        
        let month_encoded = digits[2] * 10 + digits[3];
        let day = digits[4] * 10 + digits[5];
        
        // Decode month (remove century offset)
        let month = month_encoded % 20;
        
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
            return false; // February max 29 days
        }
        
        if [4, 6, 9, 11].contains(&month) && day > 30 {
            return false; // April, June, September, November have 30 days
        }
        
        true
    }
}

impl Detector for PeselDetector {
    fn id(&self) -> &str {
        "polish_pesel"
    }
    
    fn name(&self) -> &str {
        "Polish PESEL (National ID)"
    }
    
    fn country(&self) -> &str {
        "pl"
    }
    
    fn base_severity(&self) -> Severity {
        Severity::Critical
    }
    
    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;
        
        for (line_num, line) in text.lines().enumerate() {
            for cap in PESEL_PATTERN.captures_iter(line) {
                if let Some(mat) = cap.get(0) {
                    let value = mat.as_str();
                    
                    // First validate date format
                    if !Self::validate_date(value) {
                        continue;
                    }
                    
                    // Then validate checksum
                    if !Self::validate_pesel(value) {
                        continue;
                    }
                    
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(value),
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

impl Default for PeselDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_valid_pesel() {
        // Valid PESEL numbers (checksums verified)
        assert!(PeselDetector::validate_pesel("44051401458")); // Male, 1944-05-14
        assert!(PeselDetector::validate_pesel("00272010219")); // Male, 2000-07-20
        assert!(PeselDetector::validate_pesel("02212112346")); // Female, 2002-01-21
    }
    
    #[test]
    fn test_invalid_pesel_checksum() {
        assert!(!PeselDetector::validate_pesel("44051401459")); // Wrong checksum
        assert!(!PeselDetector::validate_pesel("00272010211")); // Wrong checksum (should be 9)
    }
    
    #[test]
    fn test_invalid_pesel_length() {
        assert!(!PeselDetector::validate_pesel("123456789")); // Too short
        assert!(!PeselDetector::validate_pesel("12345678901234")); // Too long
    }
    
    #[test]
    fn test_invalid_date() {
        assert!(!PeselDetector::validate_date("44131401458")); // Month 13
        assert!(!PeselDetector::validate_date("44013201458")); // Day 32
        assert!(!PeselDetector::validate_date("44023001458")); // Feb 30
    }
    
    #[test]
    fn test_detector_finds_valid_pesel() {
        let detector = PeselDetector::new();
        let text = "Employee ID: 44051401458, Name: John Doe";
        let path = PathBuf::from("test.txt");
        
        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].severity, Severity::Critical);
        assert_eq!(matches[0].country, "pl");
    }
    
    #[test]
    fn test_detector_rejects_invalid_pesel() {
        let detector = PeselDetector::new();
        let text = "Random number: 12345678901";
        let path = PathBuf::from("test.txt");
        
        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }
    
    #[test]
    fn test_detector_multiple_pesels() {
        let detector = PeselDetector::new();
        let text = "PESEL 1: 44051401458\nPESEL 2: 00272010219";
        let path = PathBuf::from("test.txt");
        
        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 2);
    }
    
    #[test]
    fn test_masking() {
        let detector = PeselDetector::new();
        let text = "PESEL: 44051401458";
        let path = PathBuf::from("test.txt");
        
        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        // mask_value shows first 3 and last 2 chars
        assert_eq!(matches[0].value_masked, "440******58");
    }
}
