use anyhow::{Context, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

use crate::core::types::{
    Confidence, FileResult, Match, ScanResults, ScanStatus, TargetKind, TextIndex,
};
use crate::core::Detector;

/// Default maximum response body retained by an API scan (25 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 25 * 1024 * 1024;

/// Default maximum number of matches retained for one API endpoint.
pub const DEFAULT_MAX_MATCHES: usize = 10_000;

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
    /// Maximum response body size in bytes
    pub max_response_bytes: usize,
    /// Maximum number of matches retained for one endpoint
    pub max_matches: usize,
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
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_matches: DEFAULT_MAX_MATCHES,
        }
    }
}

impl ApiScanConfig {
    fn validate(&self) -> Result<()> {
        if self.timeout_secs == 0 {
            anyhow::bail!("Request timeout must be greater than zero");
        }
        if self.max_response_bytes == 0 {
            anyhow::bail!("Maximum response size must be greater than zero");
        }
        if self.max_matches == 0 {
            anyhow::bail!("Maximum match count must be greater than zero");
        }
        Ok(())
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

fn endpoint_label(parsed_url: &Url) -> PathBuf {
    let mut sanitized = parsed_url.clone();

    // HTTP(S) URLs always support userinfo. Ignore the setters' results so this
    // helper remains total if another URL scheme reaches it in future.
    let _ = sanitized.set_username("");
    let _ = sanitized.set_password(None);
    sanitized.set_query(None);
    sanitized.set_fragment(None);

    PathBuf::from(sanitized.as_str())
}

fn endpoint_label_from_input(url: &str) -> PathBuf {
    Url::parse(url)
        .ok()
        .filter(|parsed| matches!(parsed.scheme(), "http" | "https"))
        .map(|parsed| endpoint_label(&parsed))
        .unwrap_or_else(|| PathBuf::from("<invalid-endpoint>"))
}

fn is_same_origin(initial: &Url, target: &Url) -> bool {
    initial.scheme() == target.scheme()
        && initial
            .host_str()
            .zip(target.host_str())
            .is_some_and(|(initial_host, target_host)| {
                initial_host.eq_ignore_ascii_case(target_host)
            })
        && initial.port_or_known_default() == target.port_or_known_default()
}

fn redirect_policy(initial_url: &Url, max_redirects: usize) -> reqwest::redirect::Policy {
    let initial_url = initial_url.clone();

    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > max_redirects {
            return attempt.error("redirect limit exceeded");
        }
        if !is_same_origin(&initial_url, attempt.url()) {
            return attempt.error("cross-origin redirect blocked");
        }
        attempt.follow()
    })
}

fn read_response_body(response: Response, max_bytes: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("Response body exceeds configured byte limit");
    }

    // Content-Length is advisory and may be absent or false. The bounded reader
    // is the authoritative check for fixed-length and chunked responses alike.
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut body = Vec::new();
    let mut bounded = response.take(read_limit);
    bounded
        .read_to_end(&mut body)
        .map_err(|_| anyhow::anyhow!("Failed to read response body"))?;

    if body.len() > max_bytes {
        anyhow::bail!("Response body exceeds configured byte limit");
    }

    Ok(body)
}

fn detect_with_limit(
    text: &str,
    path: &std::path::Path,
    detectors: &[Box<dyn Detector>],
    min_confidence: &Confidence,
    max_matches: usize,
) -> (Vec<Match>, bool, usize) {
    let mut all_matches = Vec::new();
    let mut truncated = false;
    let mut omitted_matches: usize = 0;
    let index = TextIndex::new(text);

    for detector in detectors {
        let remaining = max_matches.saturating_sub(all_matches.len());
        let mut outcome = detector.detect_limited(text, path, *min_confidence, remaining);
        for detected_match in &mut outcome.matches {
            index.normalize_location(&mut detected_match.location);
        }
        all_matches.extend(outcome.matches);
        omitted_matches = omitted_matches.saturating_add(outcome.omitted_matches);
        if outcome.truncated {
            truncated = true;
            break;
        }
    }

    (all_matches, truncated, omitted_matches)
}

/// Scan an API endpoint for PII data
pub fn scan_api_endpoint(
    url: &str,
    config: &ApiScanConfig,
    detectors: &[Box<dyn Detector>],
    min_confidence: &crate::core::types::Confidence,
) -> Result<ScanResults> {
    let start_time = std::time::Instant::now();

    config.validate()?;

    // Validate URL
    let parsed_url = Url::parse(url).map_err(|_| anyhow::anyhow!("Invalid endpoint URL"))?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        anyhow::bail!("Endpoint URL must use HTTP or HTTPS");
    }
    if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
        anyhow::bail!("Endpoint URL must not contain userinfo");
    }
    let api_path = endpoint_label(&parsed_url);

    // Build HTTP client
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .redirect(if config.follow_redirects {
            redirect_policy(&parsed_url, config.max_redirects)
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
        let header_name = HeaderName::from_str(key).context("Invalid header name")?;
        let header_value =
            HeaderValue::from_str(value).with_context(|| format!("Invalid value for {key}"))?;
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
            } else if e.is_redirect() {
                return Err(anyhow::anyhow!("Redirect blocked by endpoint policy"));
            } else if e.is_connect() {
                return Err(anyhow::anyhow!("Connection failed"));
            } else if e.is_request() {
                return Err(anyhow::anyhow!("Request failed"));
            } else {
                return Err(anyhow::anyhow!("HTTP request failed"));
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

    let response_body = read_response_body(response, config.max_response_bytes)?;
    let response_size = response_body.len();
    let response_text = String::from_utf8(response_body)
        .map_err(|_| anyhow::anyhow!("Response body is not valid UTF-8"))?;

    // Scan the response text for PII
    let (all_matches, truncated, omitted_matches) = detect_with_limit(
        &response_text,
        &api_path,
        detectors,
        min_confidence,
        config.max_matches,
    );

    let scan_time = start_time.elapsed();

    // Create FileResult for the API endpoint
    let file_result = FileResult {
        path: api_path,
        matches: all_matches,
        size_bytes: response_size as u64,
        scan_time_ms: scan_time.as_millis() as u64,
        error: None,
        truncated,
        omitted_matches,
    };

    let mut results = ScanResults::aggregate(vec![file_result]);
    results.target_kind = TargetKind::Http;
    Ok(results)
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
        let endpoint_start = std::time::Instant::now();
        match scan_api_endpoint(url, config, detectors, min_confidence) {
            Ok(result) => {
                total_matches += result.total_matches;
                all_files.extend(result.files);
            }
            Err(e) => {
                // Preserve the error in the result and continue. Library
                // callers decide whether and how to log diagnostics.
                let safe_label = endpoint_label_from_input(url);
                all_files.push(FileResult {
                    path: safe_label,
                    matches: Vec::new(),
                    size_bytes: 0,
                    scan_time_ms: endpoint_start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                    truncated: false,
                    omitted_matches: 0,
                });
            }
        }
    }

    let mut results = ScanResults::aggregate(all_files);
    debug_assert_eq!(results.total_matches, total_matches);
    results.total_time_ms = start_time.elapsed().as_millis() as u64;
    results.target_kind = TargetKind::Http;
    if results.error_count == results.total_files && results.total_files > 0 {
        results.status = ScanStatus::Failed;
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Confidence, GdprCategory, Location, Match, Severity};
    use crate::core::Detector;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;

    fn serve_raw_responses(responses: Vec<Vec<u8>>) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request);
                stream.write_all(&response).unwrap();
                stream.flush().unwrap();
            }
        });
        (address, handle)
    }

    fn serve_responses(responses: Vec<String>) -> (SocketAddr, thread::JoinHandle<()>) {
        serve_raw_responses(responses.into_iter().map(String::into_bytes).collect())
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

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
        assert_eq!(config.max_response_bytes, 25 * 1024 * 1024);
        assert_eq!(config.max_matches, 10_000);
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

    #[test]
    fn test_url_userinfo_is_rejected_without_echoing_credentials() {
        let error = scan_api_endpoint(
            "http://private-user:private-password@127.0.0.1/records",
            &ApiScanConfig::default(),
            &[],
            &Confidence::Low,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(error, "Endpoint URL must not contain userinfo");
        assert!(!error.contains("private-user"));
        assert!(!error.contains("private-password"));
    }

    #[test]
    fn test_response_body_cap_is_enforced_while_reading() {
        let response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n123456".to_string();
        let (address, server) = serve_responses(vec![response]);
        let config = ApiScanConfig {
            max_response_bytes: 5,
            ..Default::default()
        };

        let result = scan_api_endpoint(
            &format!("http://{address}/large"),
            &config,
            &[],
            &Confidence::Low,
        );
        server.join().unwrap();

        assert_eq!(
            result.unwrap_err().to_string(),
            "Response body exceeds configured byte limit"
        );
    }

    #[test]
    fn test_invalid_utf8_response_is_rejected_instead_of_modified() {
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".to_vec();
        response.push(0xff);
        let (address, server) = serve_raw_responses(vec![response]);

        let result = scan_api_endpoint(
            &format!("http://{address}/binary"),
            &ApiScanConfig::default(),
            &[],
            &Confidence::Low,
        );
        server.join().unwrap();

        assert_eq!(
            result.unwrap_err().to_string(),
            "Response body is not valid UTF-8"
        );
    }

    #[test]
    fn test_endpoint_label_is_sanitized_and_totals_are_aggregated() {
        let body = "record 111222333";
        let (address, server) = serve_responses(vec![ok_response(body)]);
        let url = format!("http://{address}/records?token=private#fragment");
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(MockDetector)];

        let results = scan_api_endpoint(
            &url,
            &ApiScanConfig::default(),
            &detectors,
            &Confidence::Low,
        )
        .unwrap();
        server.join().unwrap();

        let label = results.files[0].path.to_string_lossy();
        assert_eq!(label, format!("http://{address}/records"));
        assert!(!label.contains("token"));
        assert_eq!(results.total_files, 1);
        assert_eq!(results.total_bytes, body.len() as u64);
        assert_eq!(results.total_matches, 1);
        assert_eq!(results.by_severity.critical, 1);
        assert_eq!(results.by_country.get("TEST"), Some(&1));
    }

    #[test]
    fn test_match_cap_is_explicit_and_aggregated() {
        let body = "111222333 222333444 333444555";
        let (address, server) = serve_responses(vec![ok_response(body)]);
        let config = ApiScanConfig {
            max_matches: 2,
            ..Default::default()
        };
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(MockDetector)];

        let results = scan_api_endpoint(
            &format!("http://{address}/records"),
            &config,
            &detectors,
            &Confidence::Low,
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(results.total_matches, 2);
        assert_eq!(results.files[0].matches.len(), 2);
        assert!(results.files[0].truncated);
        assert_eq!(results.files[0].omitted_matches, 1);
        assert_eq!(results.omitted_matches, 1);
        assert_eq!(results.status, ScanStatus::Partial);
    }

    #[test]
    fn test_multiple_endpoint_totals_include_successes_and_failures() {
        let body = "record 111222333";
        let (address, server) = serve_responses(vec![ok_response(body)]);
        let endpoints = vec![
            (
                format!("http://{address}/records?token=private"),
                ApiScanConfig::default(),
            ),
            (
                "not a valid endpoint with-secret".to_string(),
                ApiScanConfig::default(),
            ),
        ];
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(MockDetector)];

        let results = scan_api_endpoints(&endpoints, &detectors, &Confidence::Low).unwrap();
        server.join().unwrap();

        assert_eq!(results.total_files, 2);
        assert_eq!(results.total_bytes, body.len() as u64);
        assert_eq!(results.total_matches, 1);
        assert_eq!(results.by_severity.critical, 1);
        assert_eq!(results.error_count, 1);
        assert_eq!(results.status, ScanStatus::Partial);
        assert_eq!(results.target_kind, TargetKind::Http);
        assert_eq!(results.files[1].path, PathBuf::from("<invalid-endpoint>"));
    }

    #[test]
    fn test_same_origin_redirect_is_followed() {
        let redirect = "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
        let (address, server) = serve_responses(vec![redirect, ok_response("safe")]);

        let results = scan_api_endpoint(
            &format!("http://{address}/start"),
            &ApiScanConfig::default(),
            &[],
            &Confidence::Low,
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(results.total_bytes, 4);
    }

    #[test]
    fn test_cross_origin_redirect_is_blocked() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination_address = destination.local_addr().unwrap();
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{destination_address}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (source_address, server) = serve_responses(vec![redirect]);

        let result = scan_api_endpoint(
            &format!("http://{source_address}/start"),
            &ApiScanConfig::default(),
            &[],
            &Confidence::Low,
        );
        server.join().unwrap();

        assert_eq!(
            result.unwrap_err().to_string(),
            "Redirect blocked by endpoint policy"
        );
        destination.set_nonblocking(true).unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn test_diagnostics_do_not_echo_url_or_header_secrets() {
        let mut config = ApiScanConfig::default();
        config.headers.insert(
            "Authorization".to_string(),
            "secret-value\ninvalid".to_string(),
        );
        let error = scan_api_endpoint(
            "http://127.0.0.1/private?token=query-secret",
            &config,
            &[],
            &Confidence::Low,
        )
        .unwrap_err()
        .to_string();

        assert!(!error.contains("secret-value"));
        assert!(!error.contains("url-secret"));
        assert!(!error.contains("query-secret"));

        let endpoints = vec![(
            "not a url containing-url-secret".to_string(),
            ApiScanConfig::default(),
        )];
        let results = scan_api_endpoints(&endpoints, &[], &Confidence::Low).unwrap();
        assert_eq!(results.files[0].path, PathBuf::from("<invalid-endpoint>"));
        assert!(!results.files[0]
            .error
            .as_deref()
            .unwrap()
            .contains("containing-url-secret"));
    }
}
