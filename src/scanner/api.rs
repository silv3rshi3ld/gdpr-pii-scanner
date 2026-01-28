use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

use crate::core::types::{FileResult, Match, ScanResults};
use crate::core::Detector;

/// Configuration for API endpoint scanning
#[derive(Debug, Clone)]
pub struct ApiScanConfig {
    /// HTTP method (GET, POST, etc.)
    pub method: HttpMethod,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body (for POST, PUT, etc.)
    pub body: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow
    pub max_redirects: usize,
}

impl Default for ApiScanConfig {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            headers: HashMap::new(),
            body: None,
            timeout_secs: 30,
            follow_redirects: true,
            max_redirects: 10,
        }
    }
}

/// HTTP methods supported for API scanning
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl FromStr for HttpMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "PATCH" => Ok(HttpMethod::Patch),
            "DELETE" => Ok(HttpMethod::Delete),
            _ => Err(anyhow::anyhow!("Unsupported HTTP method: {}", s)),
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
        }
    }
}

/// Scan an API endpoint for PII data
pub fn scan_api_endpoint(
    url: &str,
    config: &ApiScanConfig,
    detectors: &[Box<dyn Detector>],
    min_confidence: &crate::core::types::Confidence,
) -> Result<ScanResults> {
    let start_time = std::time::Instant::now();

    // Validate URL
    let parsed_url = Url::parse(url).context("Invalid URL")?;

    // Build HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(config.max_redirects)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .context("Failed to create HTTP client")?;

    // Build request
    let mut request = match config.method {
        HttpMethod::Get => client.get(parsed_url.as_str()),
        HttpMethod::Post => client.post(parsed_url.as_str()),
        HttpMethod::Put => client.put(parsed_url.as_str()),
        HttpMethod::Patch => client.patch(parsed_url.as_str()),
        HttpMethod::Delete => client.delete(parsed_url.as_str()),
    };

    // Add headers
    let mut headers = HeaderMap::new();
    for (key, value) in &config.headers {
        let header_name =
            HeaderName::from_str(key).with_context(|| format!("Invalid header name: {}", key))?;
        let header_value = HeaderValue::from_str(value)
            .with_context(|| format!("Invalid header value for {}: {}", key, value))?;
        headers.insert(header_name, header_value);
    }
    request = request.headers(headers);

    // Add body if present
    if let Some(body) = &config.body {
        request = request.body(body.clone());
    }

    // Execute request with detailed error handling
    let response = match request.send() {
        Ok(resp) => resp,
        Err(e) => {
            // Provide detailed error messages based on error type
            if e.is_timeout() {
                return Err(anyhow::anyhow!(
                    "Request timed out after {} seconds",
                    config.timeout_secs
                ));
            } else if e.is_connect() {
                return Err(anyhow::anyhow!("Connection failed: {}", e));
            } else if e.is_request() {
                return Err(anyhow::anyhow!("Request error: {}", e));
            } else {
                return Err(anyhow::anyhow!("HTTP request failed: {}", e));
            }
        }
    };

    // Check status code with detailed error handling
    let status = response.status();
    if !status.is_success() {
        if status.is_client_error() {
            return Err(anyhow::anyhow!(
                "Client error: {} - {}",
                status,
                status.canonical_reason().unwrap_or("Unknown")
            ));
        } else if status.is_server_error() {
            return Err(anyhow::anyhow!(
                "Server error: {} - {}",
                status,
                status.canonical_reason().unwrap_or("Unknown")
            ));
        } else {
            return Err(anyhow::anyhow!(
                "HTTP request failed with status: {}",
                status
            ));
        }
    }

    // Get response body as text
    let response_text = response.text().context("Failed to read response body")?;

    let response_size = response_text.len();

    // Create a pseudo-path for the API endpoint
    let api_path = PathBuf::from(url);

    // Scan the response text for PII
    let mut all_matches = Vec::new();
    for detector in detectors {
        let matches = detector.detect(&response_text, &api_path);
        for m in matches {
            if &m.confidence >= min_confidence {
                all_matches.push(m);
            }
        }
    }

    let scan_time = start_time.elapsed();

    // Create FileResult for the API endpoint
    let file_result = FileResult {
        path: api_path,
        matches: all_matches.clone(),
        size_bytes: response_size as u64,
        scan_time_ms: scan_time.as_millis() as u64,
        error: None,
    };

    Ok(ScanResults {
        total_files: 1,
        total_matches: all_matches.len(),
        files: vec![file_result],
        ..Default::default()
    })
}

/// Scan multiple API endpoints
pub fn scan_api_endpoints(
    endpoints: &[(String, ApiScanConfig)],
    detectors: &[Box<dyn Detector>],
    min_confidence: &crate::core::types::Confidence,
) -> Result<ScanResults> {
    let start_time = std::time::Instant::now();

    let mut all_files = Vec::new();
    let mut total_matches = 0;

    for (url, config) in endpoints {
        match scan_api_endpoint(url, config, detectors, min_confidence) {
            Ok(result) => {
                total_matches += result.total_matches;
                all_files.extend(result.files);
            }
            Err(e) => {
                // Log error but continue with other endpoints
                eprintln!("Failed to scan endpoint {}: {}", url, e);
                all_files.push(FileResult {
                    path: PathBuf::from(url),
                    matches: Vec::new(),
                    size_bytes: 0,
                    scan_time_ms: 0,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let _scan_duration = start_time.elapsed();

    Ok(ScanResults {
        total_files: endpoints.len(),
        total_matches,
        files: all_files,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Confidence, GdprCategory, Location, Severity};
    use crate::core::Detector;

    // Mock detector for testing
    struct MockDetector;

    impl Detector for MockDetector {
        fn id(&self) -> &str {
            "mock_detector"
        }

        fn name(&self) -> &str {
            "Mock Detector"
        }

        fn description(&self) -> Option<String> {
            Some("Test detector".to_string())
        }

        fn country(&self) -> &str {
            "TEST"
        }

        fn base_severity(&self) -> Severity {
            Severity::Critical
        }

        fn detect(&self, text: &str, file_path: &std::path::Path) -> Vec<Match> {
            // Detect any 9-digit sequence as mock PII
            let re = regex::Regex::new(r"\b\d{9}\b").unwrap();
            re.find_iter(text)
                .map(|m| Match {
                    detector_id: self.id().to_string(),
                    detector_name: self.name().to_string(),
                    country: self.country().to_string(),
                    value_masked: format!("{}*****{}", &m.as_str()[..2], &m.as_str()[7..]),
                    location: Location {
                        file_path: file_path.to_path_buf(),
                        line: 1,
                        column: m.start(),
                        start_byte: m.start(),
                        end_byte: m.end(),
                    },
                    confidence: Confidence::High,
                    severity: Severity::Critical,
                    context: None,
                    gdpr_category: GdprCategory::Regular,
                })
                .collect()
        }
    }

    #[test]
    fn test_http_method_from_str() {
        assert_eq!(HttpMethod::from_str("GET").unwrap(), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("get").unwrap(), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("POST").unwrap(), HttpMethod::Post);
        assert_eq!(HttpMethod::from_str("PUT").unwrap(), HttpMethod::Put);
        assert_eq!(HttpMethod::from_str("PATCH").unwrap(), HttpMethod::Patch);
        assert_eq!(HttpMethod::from_str("DELETE").unwrap(), HttpMethod::Delete);
        assert!(HttpMethod::from_str("INVALID").is_err());
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Put.to_string(), "PUT");
        assert_eq!(HttpMethod::Patch.to_string(), "PATCH");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
    }

    #[test]
    fn test_api_scan_config_default() {
        let config = ApiScanConfig::default();
        assert_eq!(config.method, HttpMethod::Get);
        assert!(config.headers.is_empty());
        assert!(config.body.is_none());
        assert_eq!(config.timeout_secs, 30);
        assert!(config.follow_redirects);
        assert_eq!(config.max_redirects, 10);
    }

    #[test]
    fn test_url_validation() {
        let config = ApiScanConfig::default();
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(MockDetector)];
        let min_confidence = Confidence::Low;

        // Invalid URL should return error
        let result = scan_api_endpoint("not a url", &config, &detectors, &min_confidence);
        assert!(result.is_err());
    }

    // Note: Integration tests with real HTTP servers would be added in tests/ directory
}
