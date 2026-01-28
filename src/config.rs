use anyhow::{Context, Result};
/// Configuration file support for PII-Radar
/// Supports TOML files at ~/.pii-radar/config.toml or ./.pii-radar.toml
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub output: OutputConfig,

    #[serde(default)]
    pub filters: FilterConfig,

    #[serde(default)]
    pub database: Option<DatabaseConfig>,

    #[serde(default)]
    pub api: Option<ApiConfig>,

    #[serde(default)]
    pub plugins: Option<PluginConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Minimum confidence level (low, medium, high)
    #[serde(default = "default_confidence")]
    pub min_confidence: String,

    /// Extract text from documents (PDF, DOCX, XLSX)
    #[serde(default)]
    pub extract_documents: bool,

    /// Maximum number of threads to use
    #[serde(default)]
    pub max_threads: Option<usize>,

    /// Filter by specific countries (e.g., ["nl", "de", "gb"])
    #[serde(default)]
    pub countries: Vec<String>,

    /// Disable context analysis
    #[serde(default)]
    pub no_context: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_confidence: "high".to_string(),
            extract_documents: false,
            max_threads: None,
            countries: Vec::new(),
            no_context: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format (terminal, json, json-compact, html)
    #[serde(default = "default_format")]
    pub format: String,

    /// Output file path
    #[serde(default)]
    pub output_path: Option<PathBuf>,

    /// Show full file paths
    #[serde(default)]
    pub full_paths: bool,

    /// Disable progress bar
    #[serde(default)]
    pub no_progress: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Maximum file size to scan in MB
    #[serde(default = "default_max_filesize")]
    pub max_filesize_mb: u64,

    /// Maximum directory recursion depth
    #[serde(default)]
    pub max_depth: Option<usize>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            max_filesize_mb: 100,
            max_depth: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database connections
    #[serde(default)]
    pub connections: Vec<DatabaseConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConnection {
    /// Connection name
    pub name: String,

    /// Connection string (supports environment variable substitution)
    pub connection_string: String,

    /// Database type (postgres, mysql)
    pub db_type: String,

    /// Tables to scan (empty = all tables)
    #[serde(default)]
    pub tables: Vec<String>,

    /// Columns to scan (empty = all columns)
    #[serde(default)]
    pub columns: Vec<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_db_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// API endpoints to scan
    #[serde(default)]
    pub endpoints: Vec<ApiEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    /// Endpoint name
    pub name: String,

    /// URL
    pub url: String,

    /// HTTP method (GET, POST)
    #[serde(default = "default_http_method")]
    pub method: String,

    /// Request headers
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Request body (for POST)
    #[serde(default)]
    pub body: Option<String>,

    /// Scan response headers
    #[serde(default = "default_true")]
    pub scan_headers: bool,

    /// Scan response body
    #[serde(default = "default_true")]
    pub scan_body: bool,

    /// Rate limit delay in milliseconds
    #[serde(default = "default_rate_limit")]
    pub rate_limit_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin directories
    #[serde(default = "default_plugin_dirs")]
    pub directories: Vec<PathBuf>,

    /// Enable/disable plugins
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// Default value functions
fn default_confidence() -> String {
    "high".to_string()
}

fn default_format() -> String {
    "terminal".to_string()
}

fn default_max_filesize() -> u64 {
    100
}

fn default_db_timeout() -> u64 {
    30
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_rate_limit() -> u64 {
    1000
}

fn default_true() -> bool {
    true
}

fn default_plugin_dirs() -> Vec<PathBuf> {
    vec![
        dirs::home_dir()
            .map(|home| home.join(".pii-radar/plugins"))
            .unwrap_or_else(|| PathBuf::from("./plugins")),
        PathBuf::from("./plugins"),
    ]
}

/// CLI argument overrides for merging with config file
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub countries: Option<String>,
    pub min_confidence: Option<String>,
    pub extract_documents: bool,
    pub no_context: bool,
    pub threads: Option<usize>,
    pub format: Option<String>,
    pub output: Option<PathBuf>,
    pub no_progress: bool,
    pub full_paths: bool,
    pub max_filesize: Option<u64>,
    pub max_depth: Option<usize>,
}

impl Config {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: Config =
            toml::from_str(&contents).with_context(|| "Failed to parse TOML configuration")?;

        Ok(config)
    }

    /// Try to load configuration from standard locations
    /// Priority: ./.pii-radar.toml > ~/.pii-radar/config.toml
    pub fn load_default() -> Result<Option<Self>> {
        // Try local config first
        let local_config = PathBuf::from("./.pii-radar.toml");
        if local_config.exists() {
            return Ok(Some(Self::load_from_file(local_config)?));
        }

        // Try user config
        if let Some(home_dir) = dirs::home_dir() {
            let user_config = home_dir.join(".pii-radar/config.toml");
            if user_config.exists() {
                return Ok(Some(Self::load_from_file(user_config)?));
            }
        }

        // No config file found
        Ok(None)
    }

    /// Expand environment variables in connection strings
    pub fn expand_env_vars(&mut self) {
        if let Some(ref mut db_config) = self.database {
            for conn in &mut db_config.connections {
                conn.connection_string = expand_env_string(&conn.connection_string);
            }
        }

        if let Some(ref mut api_config) = self.api {
            for endpoint in &mut api_config.endpoints {
                endpoint.url = expand_env_string(&endpoint.url);

                // Expand environment variables in headers
                for (_, value) in endpoint.headers.iter_mut() {
                    *value = expand_env_string(value);
                }

                if let Some(ref mut body) = endpoint.body {
                    *body = expand_env_string(body);
                }
            }
        }
    }

    /// Merge CLI arguments with config file (CLI takes precedence)
    pub fn merge_with_cli(mut self, overrides: CliOverrides) -> Self {
        // CLI overrides config file
        if let Some(countries_str) = overrides.countries {
            self.scan.countries = countries_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }

        if let Some(confidence) = overrides.min_confidence {
            self.scan.min_confidence = confidence;
        }

        if overrides.extract_documents {
            self.scan.extract_documents = true;
        }

        if overrides.no_context {
            self.scan.no_context = true;
        }

        if let Some(t) = overrides.threads {
            self.scan.max_threads = Some(t);
        }

        if let Some(fmt) = overrides.format {
            self.output.format = fmt;
        }

        if let Some(out) = overrides.output {
            self.output.output_path = Some(out);
        }

        if overrides.no_progress {
            self.output.no_progress = true;
        }

        if overrides.full_paths {
            self.output.full_paths = true;
        }

        if let Some(size) = overrides.max_filesize {
            self.filters.max_filesize_mb = size;
        }

        if let Some(depth) = overrides.max_depth {
            self.filters.max_depth = Some(depth);
        }

        self
    }
}

/// Expand environment variables in strings
/// Supports ${VAR_NAME} syntax
fn expand_env_string(s: &str) -> String {
    let mut result = s.to_string();

    // Simple regex-based replacement for ${VAR_NAME}
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let replacement = std::env::var(var_name).unwrap_or_else(|_| {
                format!("${{{}}}", var_name) // Keep original if not found
            });
            result.replace_range(start..start + end + 1, &replacement);
        } else {
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.scan.min_confidence, "high");
        assert!(!config.scan.extract_documents);
        assert_eq!(config.output.format, "terminal");
        assert_eq!(config.filters.max_filesize_mb, 100);
    }

    #[test]
    fn test_expand_env_vars() {
        std::env::set_var("TEST_VAR", "test_value");

        let result = expand_env_string("prefix_${TEST_VAR}_suffix");
        assert_eq!(result, "prefix_test_value_suffix");

        let no_var = expand_env_string("no_var_here");
        assert_eq!(no_var, "no_var_here");

        std::env::remove_var("TEST_VAR");
    }

    #[test]
    fn test_parse_basic_config() {
        let toml_str = r#"
[scan]
min_confidence = "medium"
extract_documents = true
countries = ["nl", "de"]

[output]
format = "json"
full_paths = true
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.min_confidence, "medium");
        assert!(config.scan.extract_documents);
        assert_eq!(config.scan.countries, vec!["nl", "de"]);
        assert_eq!(config.output.format, "json");
        assert!(config.output.full_paths);
    }

    #[test]
    fn test_merge_with_cli() {
        let mut config = Config::default();
        config = config.merge_with_cli(CliOverrides {
            countries: Some("gb,fr".to_string()),
            min_confidence: Some("low".to_string()),
            extract_documents: true,
            no_context: true,
            threads: Some(8),
            format: Some("html".to_string()),
            output: Some(PathBuf::from("output.html")),
            no_progress: true,
            full_paths: true,
            max_filesize: Some(200),
            max_depth: Some(5),
        });

        assert_eq!(config.scan.countries, vec!["gb", "fr"]);
        assert_eq!(config.scan.min_confidence, "low");
        assert!(config.scan.extract_documents);
        assert!(config.scan.no_context);
        assert_eq!(config.scan.max_threads, Some(8));
        assert_eq!(config.output.format, "html");
        assert!(config.output.no_progress);
        assert!(config.output.full_paths);
        assert_eq!(config.filters.max_filesize_mb, 200);
        assert_eq!(config.filters.max_depth, Some(5));
    }

    #[test]
    fn test_database_config_parsing() {
        let toml_str = r#"
[database]
connections = [
    { name = "prod_db", connection_string = "${DATABASE_URL}", db_type = "postgres", tables = ["users", "orders"], timeout_seconds = 30 }
]
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.database.is_some());
        let db = config.database.unwrap();
        assert_eq!(db.connections.len(), 1);
        assert_eq!(db.connections[0].name, "prod_db");
        assert_eq!(db.connections[0].db_type, "postgres");
    }

    #[test]
    fn test_api_config_parsing() {
        let toml_str = r#"
[api]
endpoints = [
    { name = "user_api", url = "https://api.example.com/users", method = "GET", scan_headers = true, scan_body = true }
]
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.api.is_some());
        let api = config.api.unwrap();
        assert_eq!(api.endpoints.len(), 1);
        assert_eq!(api.endpoints[0].name, "user_api");
        assert_eq!(api.endpoints[0].method, "GET");
    }
}
