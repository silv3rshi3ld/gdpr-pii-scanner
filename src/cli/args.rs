/// CLI argument parsing using clap
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pii-radar",
    version,
    about = "High-performance PII scanner for European data protection",
    long_about = "Detects Personally Identifiable Information (PII) in local files\n\
                  Supports: Dutch BSN, IBAN, Credit Cards, Emails, and more\n\
                  Features context-aware GDPR Article 9 special category detection"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a directory for PII
    Scan {
        /// Directory to scan
        #[arg(value_name = "PATH")]
        directory: PathBuf,

        /// Output format
        #[arg(short, long, value_name = "FORMAT", default_value = "terminal")]
        format: OutputFormat,

        /// Output file (for json/csv formats)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Filter by country codes (comma-separated: nl,de,gb)
        #[arg(short, long, value_name = "CODES")]
        countries: Option<String>,

        /// Minimum confidence level to report
        #[arg(long, value_name = "LEVEL", default_value = "high")]
        min_confidence: ConfidenceLevel,

        /// Disable context analysis (GDPR Art. 9)
        #[arg(long)]
        no_context: bool,

        /// Extract text from documents (PDF, DOCX, XLSX)
        #[arg(long)]
        extract_documents: bool,

        /// Disable progress bar
        #[arg(long)]
        no_progress: bool,

        /// Show full file paths instead of just filenames
        #[arg(long)]
        full_paths: bool,

        /// Maximum recursion depth
        #[arg(long, value_name = "DEPTH")]
        max_depth: Option<usize>,

        /// Number of threads (default: auto)
        #[arg(short = 'j', long, value_name = "N")]
        threads: Option<usize>,

        /// Maximum file size to scan in MB
        #[arg(long, value_name = "SIZE", default_value = "100")]
        max_filesize: u64,
    },

    /// List all available detectors
    Detectors {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Colored terminal output (default)
    Terminal,
    /// JSON format
    Json,
    /// Compact JSON (single line)
    JsonCompact,
    /// HTML report
    Html,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
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
    fn test_cli_verify() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_scan_command_basic() {
        let args = vec!["pii-radar", "scan", "/tmp/test"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_scan_command_with_options() {
        let args = vec![
            "pii-radar",
            "scan",
            "/tmp/test",
            "--format",
            "json",
            "--output",
            "results.json",
            "--no-context",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_detectors_command() {
        let args = vec!["pii-radar", "detectors"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_scan_command_with_extract_documents() {
        let args = vec!["pii-radar", "scan", "/tmp/test", "--extract-documents"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        if let Ok(Cli {
            command: Commands::Scan {
                extract_documents, ..
            },
        }) = cli
        {
            assert!(extract_documents);
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_scan_command_with_all_options() {
        let args = vec![
            "pii-radar",
            "scan",
            "/tmp/test",
            "--format",
            "json",
            "--output",
            "results.json",
            "--countries",
            "nl,de",
            "--min-confidence",
            "medium",
            "--extract-documents",
            "--full-paths",
            "--no-context",
            "--max-depth",
            "3",
            "--threads",
            "4",
            "--max-filesize",
            "50",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
    }
}
