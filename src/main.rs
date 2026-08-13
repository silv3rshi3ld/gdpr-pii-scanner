//! `pii-radar` command-line entry point.

use clap::Parser;
use pii_radar::cli::{Cli, Commands, ConfidenceLevel, OutputFormat, OutputSchema, PluginCommands};
use pii_radar::config::{CliOverrides, Config};
use pii_radar::detectors::plugin_loader::{
    load_plugin_from_file, load_plugins_with_diagnostics, PluginLoadReport,
};
use pii_radar::{
    default_registry, registry_for_countries, scan_api_endpoints, ApiScanConfig, Confidence,
    CsvReporter, Detector, DetectorRegistry, DocxExtractor, ExtractionLimits, ExtractorRegistry,
    HtmlReporter, HttpMethod, JsonReporter, PdfExtractor, ScanEngine, ScanResults, ScanStatus,
    TerminalReporter, Walker, XlsxExtractor,
};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use url::Url;

#[cfg(any(feature = "postgres", feature = "mongodb"))]
use pii_radar::database::scanner::extract_database_name;
#[cfg(any(feature = "postgres", feature = "mongodb"))]
use pii_radar::database::{DatabaseConfig, DatabaseScanner, DatabaseType, ScanOptions};

const EXIT_CLEAN: i32 = 0;
const EXIT_FINDINGS: i32 = 1;
const EXIT_INVALID: i32 = 2;
const EXIT_INCOMPLETE: i32 = 3;
const MIB: u64 = 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: u64 = 25 * MIB;

#[derive(Debug)]
struct AppError {
    exit_code: i32,
    message: String,
}

impl AppError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_INVALID,
            message: message.into(),
        }
    }

    fn operational(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_INCOMPLETE,
            message: message.into(),
        }
    }
}

type AppResult<T> = Result<T, AppError>;

#[cfg(any(feature = "postgres", feature = "mongodb"))]
#[tokio::main]
async fn main() {
    finish(execute_with_database(Cli::parse()).await);
}

#[cfg(not(any(feature = "postgres", feature = "mongodb")))]
fn main() {
    finish(execute_core(Cli::parse()));
}

fn finish(result: AppResult<i32>) {
    match result {
        Ok(exit_code) => {
            if exit_code != EXIT_CLEAN {
                process::exit(exit_code);
            }
        }
        Err(error) => {
            eprintln!("error: {}", sanitize_diagnostic(&error.message));
            process::exit(error.exit_code);
        }
    }
}

fn sanitize_diagnostic(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{{{:x}}}", character as u32);
            }
            character => output.push(character),
        }
    }
    output
}

#[cfg(not(any(feature = "postgres", feature = "mongodb")))]
fn execute_core(cli: Cli) -> AppResult<i32> {
    let Cli {
        config,
        no_config,
        command,
    } = cli;
    let config = load_config(config.as_deref(), no_config)?;
    run_local_command(command, config)
}

#[cfg(any(feature = "postgres", feature = "mongodb"))]
async fn execute_with_database(cli: Cli) -> AppResult<i32> {
    let Cli {
        config,
        no_config,
        command,
    } = cli;
    let config = load_config(config.as_deref(), no_config)?;

    match command {
        Commands::ScanDb { .. } => run_database_command(command, config).await,
        command => run_local_command(command, config),
    }
}

fn load_config(explicit: Option<&Path>, no_config: bool) -> AppResult<Config> {
    let loaded = Config::load_resolved(explicit, no_config)
        .map_err(|error| AppError::invalid(error.to_string()))?;
    for warning in loaded.warnings {
        eprintln!("warning: {}", sanitize_diagnostic(&warning));
    }
    Ok(loaded.config)
}

fn run_local_command(command: Commands, config: Config) -> AppResult<i32> {
    match command {
        Commands::Scan {
            path,
            format,
            output,
            countries,
            min_confidence,
            no_context,
            include_redacted_snippets,
            extract_documents,
            no_progress,
            full_paths,
            max_depth,
            threads,
            max_filesize,
            plugins,
            output_schema,
            force,
        } => run_file_scan(
            path,
            config,
            FileScanCli {
                format,
                output,
                countries,
                min_confidence,
                no_context,
                include_redacted_snippets,
                extract_documents,
                no_progress,
                full_paths,
                max_depth,
                threads,
                max_filesize,
                plugins,
                output_schema,
                force,
            },
        ),
        Commands::Api {
            urls,
            method,
            headers,
            header_env,
            body,
            body_file,
            timeout,
            no_redirects,
            max_response_bytes,
            max_matches,
            format,
            output,
            min_confidence,
            plugins,
            output_schema,
            force,
        } => run_api_scan(
            config,
            ApiCli {
                urls,
                method,
                headers,
                header_env,
                body,
                body_file,
                timeout,
                no_redirects,
                max_response_bytes,
                max_matches,
                format,
                output,
                min_confidence,
                plugins,
                output_schema,
                force,
            },
        ),
        Commands::Detectors { verbose } => {
            print_detectors(verbose);
            Ok(EXIT_CLEAN)
        }
        Commands::Plugins { command } => validate_plugins(command),
        #[cfg(any(feature = "postgres", feature = "mongodb"))]
        Commands::ScanDb { .. } => unreachable!("database command is dispatched asynchronously"),
    }
}

struct FileScanCli {
    format: Option<OutputFormat>,
    output: Option<PathBuf>,
    countries: Option<String>,
    min_confidence: Option<ConfidenceLevel>,
    no_context: bool,
    include_redacted_snippets: bool,
    extract_documents: bool,
    no_progress: bool,
    full_paths: bool,
    max_depth: Option<usize>,
    threads: Option<usize>,
    max_filesize: Option<u64>,
    plugins: Option<PathBuf>,
    output_schema: OutputSchema,
    force: bool,
}

fn run_file_scan(path: PathBuf, config: Config, cli: FileScanCli) -> AppResult<i32> {
    let explicit_plugins = cli.plugins.clone();
    let config = config.merge_with_cli(CliOverrides {
        countries: cli.countries,
        min_confidence: cli
            .min_confidence
            .map(|confidence| confidence.config_name().to_string()),
        extract_documents: cli.extract_documents,
        no_context: cli.no_context,
        include_redacted_snippets: cli.include_redacted_snippets,
        threads: cli.threads,
        format: cli.format.map(|format| format.config_name().to_string()),
        output: cli.output,
        no_progress: cli.no_progress,
        full_paths: cli.full_paths,
        max_filesize: cli.max_filesize,
        max_depth: cli.max_depth,
    });
    config
        .validate()
        .map_err(|error| AppError::invalid(error.to_string()))?;

    let format = parse_output_format(&config.output.format)?;
    let minimum = parse_confidence(&config.scan.min_confidence)?;
    let registry = build_registry(&config, explicit_plugins.as_deref())?;

    let max_file_bytes = mib_to_bytes(config.filters.max_filesize_mb, "max_filesize_mb")?;
    let max_total_bytes = mib_to_bytes(config.filters.max_total_size_mb, "max_total_size_mb")?;
    let max_extracted_bytes = mib_to_bytes(
        config.filters.max_extracted_size_mb,
        "max_extracted_size_mb",
    )?;
    let max_extracted_bytes = usize::try_from(max_extracted_bytes)
        .map_err(|_| AppError::invalid("limits.max_extracted_size_mb is too large"))?;

    let mut walker = Walker::new(&path)
        .max_filesize(max_file_bytes)
        .max_files(config.filters.max_files)
        .max_total_size(max_total_bytes);
    if let Some(depth) = config.filters.max_depth {
        walker = walker.max_depth(depth);
    }
    if let Some(threads) = config.scan.max_threads {
        walker = walker.threads(threads);
    }

    let extraction_limits = ExtractionLimits {
        max_input_bytes: max_file_bytes,
        max_output_bytes: max_extracted_bytes,
        ..ExtractionLimits::default()
    };

    let progress = !config.output.no_progress && std::io::stderr().is_terminal();
    let mut engine = ScanEngine::new(registry)
        .with_walker(walker)
        .with_extraction_limits(extraction_limits)
        .minimum_confidence(minimum)
        .max_matches_per_file(config.filters.max_matches_per_source)
        .max_matches_per_scan(config.filters.max_matches)
        .enable_context(!config.scan.no_context)
        .include_redacted_snippets(config.scan.include_redacted_snippets)
        .show_progress(progress);

    if config.scan.extract_documents {
        let mut extractors = ExtractorRegistry::new();
        extractors.register(Arc::new(PdfExtractor));
        extractors.register(Arc::new(DocxExtractor));
        extractors.register(Arc::new(XlsxExtractor));
        engine = engine.with_extractors(extractors);
    }

    let results = engine.scan_directory(&path);
    emit_results(
        &results,
        format,
        config.output.output_path.as_deref(),
        cli.output_schema,
        cli.force,
        config.output.full_paths,
        config.scan.include_redacted_snippets,
    )?;
    Ok(scan_exit_code(&results))
}

struct ApiCli {
    urls: Vec<String>,
    method: String,
    headers: Vec<String>,
    header_env: Vec<String>,
    body: Option<String>,
    body_file: Option<PathBuf>,
    timeout: u64,
    no_redirects: bool,
    max_response_bytes: Option<usize>,
    max_matches: Option<usize>,
    format: Option<OutputFormat>,
    output: Option<PathBuf>,
    min_confidence: Option<ConfidenceLevel>,
    plugins: Option<PathBuf>,
    output_schema: OutputSchema,
    force: bool,
}

fn run_api_scan(config: Config, cli: ApiCli) -> AppResult<i32> {
    if cli.timeout == 0 {
        return Err(AppError::invalid("--timeout must be greater than zero"));
    }
    if cli.max_response_bytes == Some(0) {
        return Err(AppError::invalid(
            "--max-response-bytes must be greater than zero",
        ));
    }
    if cli.max_matches == Some(0) {
        return Err(AppError::invalid("--max-matches must be greater than zero"));
    }
    for endpoint in &cli.urls {
        validate_endpoint_input(endpoint)?;
    }

    let explicit_plugins = cli.plugins.clone();
    let config = config.merge_with_cli(CliOverrides {
        min_confidence: cli
            .min_confidence
            .map(|confidence| confidence.config_name().to_string()),
        format: cli.format.map(|format| format.config_name().to_string()),
        output: cli.output,
        ..CliOverrides::default()
    });
    config
        .validate()
        .map_err(|error| AppError::invalid(error.to_string()))?;

    let method = cli
        .method
        .parse::<HttpMethod>()
        .map_err(|error| AppError::invalid(error.to_string()))?;
    let headers = resolve_headers(cli.headers, cli.header_env)?;
    let body = match (cli.body, cli.body_file) {
        (Some(body), None) => Some(body),
        (None, Some(path)) => Some(read_utf8_regular_file(&path, MAX_REQUEST_BODY_BYTES)?),
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err(AppError::invalid(
                "--body and --body-file cannot be used together",
            ));
        }
    };

    let defaults = ApiScanConfig::default();
    let api_config = ApiScanConfig {
        method,
        headers,
        body,
        timeout_secs: cli.timeout,
        follow_redirects: !cli.no_redirects,
        max_redirects: defaults.max_redirects,
        max_response_bytes: cli
            .max_response_bytes
            .unwrap_or(defaults.max_response_bytes),
        max_matches: cli
            .max_matches
            .unwrap_or(config.filters.max_matches_per_source),
    };

    let registry = build_registry(&config, explicit_plugins.as_deref())?;
    let minimum = parse_confidence(&config.scan.min_confidence)?;
    let endpoints: Vec<_> = cli
        .urls
        .into_iter()
        .map(|url| (url, api_config.clone()))
        .collect();
    let results = scan_api_endpoints(&endpoints, registry.all(), &minimum)
        .map_err(|error| AppError::operational(error.to_string()))?;

    emit_results(
        &results,
        parse_output_format(&config.output.format)?,
        config.output.output_path.as_deref(),
        cli.output_schema,
        cli.force,
        true,
        false,
    )?;
    Ok(scan_exit_code(&results))
}

fn validate_endpoint_input(endpoint: &str) -> AppResult<()> {
    let parsed = Url::parse(endpoint).map_err(|_| AppError::invalid("invalid endpoint URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::invalid("endpoint URL must use HTTP or HTTPS"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::invalid("endpoint URL must not contain userinfo"));
    }
    Ok(())
}

fn resolve_headers(
    literal: Vec<String>,
    from_environment: Vec<String>,
) -> AppResult<HashMap<String, String>> {
    let mut headers = HashMap::new();
    let mut normalized_names = HashSet::new();

    for header in literal {
        let (name, value) = header.split_once(':').ok_or_else(|| {
            AppError::invalid(format!("invalid header '{header}'; expected NAME:VALUE"))
        })?;
        insert_header(&mut headers, &mut normalized_names, name, value)?;
    }
    for specification in from_environment {
        let (name, variable) = specification.split_once('=').ok_or_else(|| {
            AppError::invalid(format!(
                "invalid --header-env '{specification}'; expected NAME=ENV_VAR"
            ))
        })?;
        if variable.trim().is_empty() {
            return Err(AppError::invalid(
                "header environment variable name is empty",
            ));
        }
        let value = std::env::var(variable.trim()).map_err(|_| {
            AppError::invalid(format!(
                "environment variable '{}' is missing or not valid Unicode",
                variable.trim()
            ))
        })?;
        insert_header(&mut headers, &mut normalized_names, name, &value)?;
    }

    Ok(headers)
}

fn insert_header(
    headers: &mut HashMap<String, String>,
    normalized_names: &mut HashSet<String>,
    name: &str,
    value: &str,
) -> AppResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::invalid("HTTP header name is empty"));
    }
    if !normalized_names.insert(name.to_ascii_lowercase()) {
        return Err(AppError::invalid(format!(
            "HTTP header '{name}' was supplied more than once"
        )));
    }
    headers.insert(name.to_string(), value.trim().to_string());
    Ok(())
}

fn read_utf8_regular_file(path: &Path, maximum: u64) -> AppResult<String> {
    pii_radar::safe_io::read_utf8_regular_file(path, maximum).map_err(|error| match error {
        pii_radar::safe_io::SafeFileError::NotRegular => AppError::invalid(format!(
            "refusing to read symlink or non-regular request body: {}",
            path.display()
        )),
        pii_radar::safe_io::SafeFileError::TooLarge { .. } => {
            AppError::invalid(format!("request body exceeds {maximum} bytes"))
        }
        pii_radar::safe_io::SafeFileError::InvalidUtf8(_) => {
            AppError::invalid("request body is not valid UTF-8")
        }
        pii_radar::safe_io::SafeFileError::Io(error) => AppError::invalid(format!(
            "failed to read request body {}: {error}",
            path.display()
        )),
    })
}

fn build_registry(config: &Config, explicit_plugins: Option<&Path>) -> AppResult<DetectorRegistry> {
    let mut registry = if config.scan.countries.is_empty() {
        default_registry()
    } else {
        registry_for_countries(config.scan.countries.clone())
    };
    let mut known_ids: HashSet<String> = registry.list_ids().into_iter().collect();

    let (directories, strict_missing) = if let Some(directory) = explicit_plugins {
        (vec![directory.to_path_buf()], true)
    } else {
        match &config.plugins {
            Some(plugins) if plugins.enabled => (plugins.directories.clone(), false),
            _ => (Vec::new(), false),
        }
    };

    for directory in directories {
        if !directory.exists() && !strict_missing {
            continue;
        }
        if explicit_plugins.is_none() && is_legacy_plugin_directory(&directory) {
            let warning = format!(
                "legacy plugin directory {} is deprecated; configure the platform plugin directory before v0.7",
                directory.display()
            );
            eprintln!("warning: {}", sanitize_diagnostic(&warning));
        }
        let report = load_plugins_with_diagnostics(&directory)
            .map_err(|error| AppError::invalid(error.to_string()))?;
        register_plugin_report(&mut registry, &mut known_ids, report, &directory)?;
    }
    Ok(registry)
}

fn is_legacy_plugin_directory(path: &Path) -> bool {
    path == Path::new("plugins")
        || path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == ".pii-radar")
}

fn register_plugin_report(
    registry: &mut DetectorRegistry,
    known_ids: &mut HashSet<String>,
    report: PluginLoadReport,
    source: &Path,
) -> AppResult<()> {
    for warning in report.warnings {
        eprintln!("warning: {}", sanitize_diagnostic(&warning));
    }
    for detector in report.detectors {
        if !known_ids.insert(detector.id().to_string()) {
            return Err(AppError::invalid(format!(
                "{}: detector id '{}' conflicts with another detector",
                source.display(),
                detector.id()
            )));
        }
        registry.register(Box::new(detector));
    }
    Ok(())
}

fn validate_plugins(command: PluginCommands) -> AppResult<i32> {
    match command {
        PluginCommands::Validate { path } => {
            let report = if path.is_dir() {
                load_plugins_with_diagnostics(&path)
            } else {
                load_plugin_from_file(&path)
            }
            .map_err(AppError::invalid)?;
            for warning in &report.warnings {
                eprintln!("warning: {}", sanitize_diagnostic(warning));
            }
            println!("validated {} detector plugin(s)", report.detectors.len());
            Ok(EXIT_CLEAN)
        }
    }
}

fn print_detectors(verbose: bool) {
    let registry = default_registry();
    println!("Built-in detectors ({})", registry.all().len());
    for detector in registry.all() {
        if verbose {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                detector.id(),
                detector.country(),
                detector.base_severity(),
                detector.name(),
                detector.description().unwrap_or_default()
            );
        } else {
            println!("{}\t{}", detector.id(), detector.name());
        }
    }
}

fn emit_results(
    results: &ScanResults,
    format: OutputFormat,
    output: Option<&Path>,
    schema: OutputSchema,
    force: bool,
    full_paths: bool,
    show_context: bool,
) -> AppResult<()> {
    let legacy = matches!(schema, OutputSchema::Legacy);
    if legacy
        && !matches!(
            format,
            OutputFormat::Json | OutputFormat::JsonCompact | OutputFormat::Csv
        )
    {
        return Err(AppError::invalid(
            "--output-schema legacy is supported only for JSON and CSV",
        ));
    }
    if !matches!(format, OutputFormat::Terminal) {
        if results.error_count > 0 {
            eprintln!(
                "warning: scan incomplete: {} source error(s); details are in the report",
                results.error_count
            );
        }
        if results.truncated_files > 0 {
            eprintln!(
                "warning: scan incomplete: {} source(s) were truncated",
                results.truncated_files
            );
        }
    }
    match format {
        OutputFormat::Terminal => {
            if output.is_some() {
                return Err(AppError::invalid(
                    "terminal output cannot be combined with --output",
                ));
            }
            TerminalReporter::new()
                .full_paths(full_paths)
                .show_context(show_context)
                .report(results);
        }
        OutputFormat::Json | OutputFormat::JsonCompact => {
            let reporter = JsonReporter::new()
                .pretty(matches!(format, OutputFormat::Json))
                .legacy(legacy)
                .overwrite(force);
            if let Some(path) = output {
                reporter
                    .write_to_file(results, path)
                    .map_err(AppError::operational)?;
                eprintln!(
                    "report written to {}",
                    sanitize_diagnostic(&path.display().to_string())
                );
            } else {
                reporter.print(results).map_err(AppError::operational)?;
            }
        }
        OutputFormat::Csv => {
            let reporter = CsvReporter::new()
                .with_context(show_context)
                .legacy(legacy)
                .overwrite(force);
            if let Some(path) = output {
                reporter
                    .write_to_file(results, path)
                    .map_err(AppError::operational)?;
                eprintln!(
                    "report written to {}",
                    sanitize_diagnostic(&path.display().to_string())
                );
            } else {
                reporter.print(results).map_err(AppError::operational)?;
            }
        }
        OutputFormat::Html => {
            let path = output.ok_or_else(|| {
                AppError::invalid("HTML output requires --output PATH or output.output_path")
            })?;
            HtmlReporter::new()
                .overwrite(force)
                .write_to_file(results, path)
                .map_err(|error| {
                    AppError::operational(format!("failed to write {}: {error}", path.display()))
                })?;
            eprintln!(
                "report written to {}",
                sanitize_diagnostic(&path.display().to_string())
            );
        }
    }
    Ok(())
}

fn parse_output_format(value: &str) -> AppResult<OutputFormat> {
    OutputFormat::parse_config(value).map_err(AppError::invalid)
}

fn parse_confidence(value: &str) -> AppResult<Confidence> {
    ConfidenceLevel::parse_config(value)
        .map(Into::into)
        .map_err(AppError::invalid)
}

fn mib_to_bytes(value: u64, field: &str) -> AppResult<u64> {
    value
        .checked_mul(MIB)
        .ok_or_else(|| AppError::invalid(format!("limits.{field} is too large")))
}

fn scan_exit_code(results: &ScanResults) -> i32 {
    if results.status != ScanStatus::Complete
        || results.error_count > 0
        || results.extraction_failures > 0
        || results.truncated_files > 0
    {
        EXIT_INCOMPLETE
    } else if results.total_matches > 0 {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

#[cfg(any(feature = "postgres", feature = "mongodb"))]
async fn run_database_command(command: Commands, config: Config) -> AppResult<i32> {
    let Commands::ScanDb {
        db_type,
        connection,
        connection_env,
        database,
        tables,
        exclude_tables,
        columns,
        exclude_columns,
        sample_percent,
        row_limit,
        pool_size,
        format,
        output,
        countries,
        no_progress,
        output_schema,
        force,
    } = command
    else {
        unreachable!("only scan-db reaches the database dispatcher")
    };

    let config = config.merge_with_cli(CliOverrides {
        countries,
        format: format.map(|format| format.config_name().to_string()),
        output,
        no_progress,
        ..CliOverrides::default()
    });
    config
        .validate()
        .map_err(|error| AppError::invalid(error.to_string()))?;

    let database_type = db_type.parse::<DatabaseType>().map_err(AppError::invalid)?;
    ensure_connector_is_available(database_type)?;
    let connection = match (connection, connection_env) {
        (Some(connection), None) => connection,
        (None, Some(variable)) => std::env::var(&variable).map_err(|_| {
            AppError::invalid(format!(
                "environment variable '{variable}' is missing or not valid Unicode"
            ))
        })?,
        _ => {
            return Err(AppError::invalid(
                "supply exactly one of --connection or --connection-env",
            ));
        }
    };

    let database_name = database
        .or_else(|| extract_database_name(&connection, database_type))
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            AppError::invalid("database name is required; use --database or include it in the URL")
        })?;
    let registry = build_registry(&config, None)?;

    let mut options = ScanOptions::new();
    options.include_tables = tables.map(|value| split_names(&value));
    options.exclude_tables = exclude_tables.map_or_else(Vec::new, |value| split_names(&value));
    options.include_columns = columns.map(|value| split_names(&value));
    options.exclude_columns = exclude_columns.map_or_else(Vec::new, |value| split_names(&value));
    options.sample_percent = sample_percent;
    options.row_limit = row_limit;
    options.show_progress = !config.output.no_progress && std::io::stderr().is_terminal();
    options.minimum_confidence = parse_confidence(&config.scan.min_confidence)?;
    options.max_matches_per_table = config.filters.max_matches_per_source;
    options.max_matches_total = config.filters.max_matches;
    options
        .validate()
        .map_err(|error| AppError::invalid(error.to_string()))?;

    let database_config = DatabaseConfig::new(database_type, connection).with_pool_size(pool_size);
    let scanner = DatabaseScanner::new(database_config, Some(&database_name), registry)
        .await
        .map_err(|error| AppError::operational(error.to_string()))?;
    let results = scanner
        .scan(&database_name, &options)
        .await
        .map_err(|error| AppError::operational(error.to_string()))?
        .into_scan_results()
        .map_err(|error| AppError::operational(error.to_string()))?;

    emit_results(
        &results,
        parse_output_format(&config.output.format)?,
        config.output.output_path.as_deref(),
        output_schema,
        force,
        true,
        false,
    )?;
    Ok(scan_exit_code(&results))
}

#[cfg(any(feature = "postgres", feature = "mongodb"))]
fn split_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(feature = "postgres", feature = "mongodb"))]
fn ensure_connector_is_available(database_type: DatabaseType) -> AppResult<()> {
    match database_type {
        DatabaseType::PostgreSQL if !cfg!(feature = "postgres") => Err(AppError::invalid(
            "PostgreSQL support is not enabled in this build",
        )),
        DatabaseType::MongoDB if !cfg!(feature = "mongodb") => Err(AppError::invalid(
            "MongoDB support is not enabled in this build",
        )),
        #[allow(deprecated)]
        DatabaseType::SQLite => Err(AppError::invalid("SQLite scanning is not supported")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_status_takes_precedence_over_findings() {
        let mut results = ScanResults::new();
        results.total_matches = 1;
        results.status = ScanStatus::Partial;
        assert_eq!(scan_exit_code(&results), EXIT_INCOMPLETE);
    }

    #[test]
    fn diagnostics_escape_terminal_controls_and_line_breaks() {
        assert_eq!(
            sanitize_diagnostic("path\n\x1b[31mprivate\tvalue\r"),
            "path\\n\\u{1b}[31mprivate\\tvalue\\r"
        );
    }

    #[test]
    fn headers_are_case_insensitively_unique() {
        let error = resolve_headers(
            vec![
                "Authorization:first".to_string(),
                "authorization:second".to_string(),
            ],
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.exit_code, EXIT_INVALID);
    }

    #[cfg(unix)]
    #[test]
    fn request_body_file_rejects_a_direct_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("body.txt");
        let alias = directory.path().join("body-link.txt");
        std::fs::write(&target, "private body").unwrap();
        symlink(&target, &alias).unwrap();

        let error = read_utf8_regular_file(&alias, 1024).unwrap_err();
        assert_eq!(error.exit_code, EXIT_INVALID);
        assert!(error.message.contains("refusing to read symlink"));
    }
}
