//! Command-line contract for `pii-radar`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pii-radar",
    version,
    about = "Scan files and data sources for PII and secrets"
)]
pub struct Cli {
    /// Additional configuration layer to load after user and project configuration
    #[arg(long, global = true, value_name = "FILE", conflicts_with = "no_config")]
    pub config: Option<PathBuf>,

    /// Ignore all automatically discovered configuration files
    #[arg(long, global = true)]
    pub no_config: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan one regular file or a directory tree
    Scan {
        #[arg(value_name = "PATH")]
        path: PathBuf,

        #[arg(short, long, value_name = "FORMAT")]
        format: Option<OutputFormat>,

        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        #[arg(short, long, value_name = "CODES")]
        countries: Option<String>,

        #[arg(long, value_name = "LEVEL")]
        min_confidence: Option<ConfidenceLevel>,

        /// Disable heuristic context classification
        #[arg(long)]
        no_context: bool,

        /// Include a best-effort redacted context snippet in results
        #[arg(long)]
        include_redacted_snippets: bool,

        #[arg(long)]
        extract_documents: bool,

        #[arg(long)]
        no_progress: bool,

        #[arg(long)]
        full_paths: bool,

        #[arg(long, value_name = "DEPTH")]
        max_depth: Option<usize>,

        #[arg(short = 'j', long, value_name = "N", value_parser = parse_nonzero_usize)]
        threads: Option<usize>,

        /// Maximum regular-file size in MiB
        #[arg(long, value_name = "MIB")]
        max_filesize: Option<u64>,

        #[arg(long, value_name = "DIR")]
        plugins: Option<PathBuf>,

        #[arg(long, value_enum, default_value = "v1")]
        output_schema: OutputSchema,

        /// Allow replacing an existing report file
        #[arg(long)]
        force: bool,
    },

    /// Scan one or more HTTP response bodies
    Api {
        #[arg(value_name = "URL", required = true)]
        urls: Vec<String>,

        #[arg(short, long, value_name = "METHOD", default_value = "GET")]
        method: String,

        /// Literal request header. Prefer --header-env for credentials.
        #[arg(short = 'H', long = "header", value_name = "NAME:VALUE")]
        headers: Vec<String>,

        /// Read a header value from an environment variable (NAME=ENV_VAR)
        #[arg(long = "header-env", value_name = "NAME=ENV_VAR")]
        header_env: Vec<String>,

        #[arg(short, long, value_name = "BODY", conflicts_with = "body_file")]
        body: Option<String>,

        #[arg(long, value_name = "FILE", conflicts_with = "body")]
        body_file: Option<PathBuf>,

        #[arg(long, value_name = "SECONDS", default_value = "30")]
        timeout: u64,

        #[arg(long)]
        no_redirects: bool,

        #[arg(long, value_name = "BYTES")]
        max_response_bytes: Option<usize>,

        #[arg(long, value_name = "N")]
        max_matches: Option<usize>,

        #[arg(short, long, value_name = "FORMAT")]
        format: Option<OutputFormat>,

        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        #[arg(long, value_name = "LEVEL")]
        min_confidence: Option<ConfidenceLevel>,

        #[arg(long, value_name = "DIR")]
        plugins: Option<PathBuf>,

        #[arg(long, value_enum, default_value = "v1")]
        output_schema: OutputSchema,

        #[arg(long)]
        force: bool,
    },

    /// Scan PostgreSQL or MongoDB
    #[cfg(any(feature = "postgres", feature = "mongodb"))]
    ScanDb {
        /// Database type: postgres or mongodb
        #[arg(long, value_name = "TYPE")]
        db_type: String,

        /// Connection string. Prefer --connection-env to keep credentials out of process lists.
        #[arg(short, long, value_name = "URL", conflicts_with = "connection_env")]
        connection: Option<String>,

        /// Environment variable containing the connection string
        #[arg(
            long,
            value_name = "ENV_VAR",
            conflicts_with = "connection",
            required_unless_present = "connection"
        )]
        connection_env: Option<String>,

        #[arg(short = 'd', long, value_name = "NAME")]
        database: Option<String>,

        #[arg(short = 't', long, value_name = "NAMES")]
        tables: Option<String>,

        #[arg(long, value_name = "NAMES")]
        exclude_tables: Option<String>,

        #[arg(long, value_name = "NAMES")]
        columns: Option<String>,

        #[arg(long, value_name = "NAMES")]
        exclude_columns: Option<String>,

        #[arg(long, value_name = "PERCENT", value_parser = parse_percent)]
        sample_percent: Option<u8>,

        #[arg(long, value_name = "N")]
        row_limit: Option<usize>,

        #[arg(long, value_name = "N", default_value = "4", value_parser = parse_nonzero_u32)]
        pool_size: u32,

        #[arg(short = 'f', long, value_name = "FORMAT")]
        format: Option<OutputFormat>,

        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        #[arg(long, value_name = "CODES")]
        countries: Option<String>,

        #[arg(long)]
        no_progress: bool,

        #[arg(long, value_enum, default_value = "v1")]
        output_schema: OutputSchema,

        #[arg(long)]
        force: bool,
    },

    /// List built-in detectors
    Detectors {
        #[arg(short, long)]
        verbose: bool,
    },

    /// Inspect declarative detector plugins
    Plugins {
        #[command(subcommand)]
        command: PluginCommands,
    },
}

#[derive(Subcommand)]
pub enum PluginCommands {
    /// Validate one plugin file or every supported plugin file in a directory
    Validate {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    JsonCompact,
    Html,
    Csv,
}

impl OutputFormat {
    pub fn parse_config(value: &str) -> Result<Self, String> {
        match value {
            "terminal" => Ok(Self::Terminal),
            "json" => Ok(Self::Json),
            "json-compact" => Ok(Self::JsonCompact),
            "html" => Ok(Self::Html),
            "csv" => Ok(Self::Csv),
            _ => Err(format!("unsupported output format '{value}'")),
        }
    }

    pub fn config_name(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Json => "json",
            Self::JsonCompact => "json-compact",
            Self::Html => "html",
            Self::Csv => "csv",
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputSchema {
    V1,
    Legacy,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

fn parse_nonzero_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("'{value}' is not a valid positive integer"))?;
    (parsed > 0)
        .then_some(parsed)
        .ok_or_else(|| "value must be greater than zero".to_string())
}

#[cfg(any(feature = "postgres", feature = "mongodb"))]
fn parse_nonzero_u32(value: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("'{value}' is not a valid positive integer"))?;
    (parsed > 0)
        .then_some(parsed)
        .ok_or_else(|| "value must be greater than zero".to_string())
}

#[cfg(any(feature = "postgres", feature = "mongodb"))]
fn parse_percent(value: &str) -> Result<u8, String> {
    let parsed = value
        .parse::<u8>()
        .map_err(|_| format!("'{value}' is not a valid percentage"))?;
    (1..=100)
        .contains(&parsed)
        .then_some(parsed)
        .ok_or_else(|| "percentage must be between 1 and 100".to_string())
}

impl ConfidenceLevel {
    pub fn config_name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse_config(value: &str) -> Result<Self, String> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(format!("unsupported confidence '{value}'")),
        }
    }
}

impl From<ConfidenceLevel> for crate::Confidence {
    fn from(level: ConfidenceLevel) -> Self {
        match level {
            ConfidenceLevel::Low => crate::Confidence::Low,
            ConfidenceLevel::Medium => crate::Confidence::Medium,
            ConfidenceLevel::High => crate::Confidence::High,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_contract_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scan_accepts_file_shaped_path_and_new_options() {
        let cli = Cli::try_parse_from([
            "pii-radar",
            "--no-config",
            "scan",
            "sample.txt",
            "--include-redacted-snippets",
            "--output-schema",
            "legacy",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn api_secret_sources_conflict_with_literal_sources() {
        assert!(Cli::try_parse_from([
            "pii-radar",
            "api",
            "https://example.test",
            "--body",
            "secret",
            "--body-file",
            "request.json",
        ])
        .is_err());
    }
}
