/// PII-Radar CLI entry point
use clap::Parser;
use pii_radar::cli::{Cli, Commands, OutputFormat};
use pii_radar::{
    default_registry, registry_for_countries, scan_api_endpoints, ApiScanConfig, CsvReporter,
    DocxExtractor, ExtractorRegistry, HtmlReporter, HttpMethod, JsonReporter, PdfExtractor,
    ScanEngine, TerminalReporter, Walker, XlsxExtractor,
};
use std::collections::HashMap;
use std::process;
use std::sync::Arc;

#[cfg(feature = "database")]
use pii_radar::database::{DatabaseConfig, DatabaseScanner, DatabaseType, ScanOptions};

#[cfg(feature = "database")]
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::ScanDb { .. } => {
            if let Commands::ScanDb {
                db_type,
                connection,
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
            } = cli.command
            {
                handle_scan_db(DbScanParams {
                    db_type,
                    connection,
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
                })
                .await;
            }
        }
        _ => {
            handle_file_commands(cli.command);
        }
    }
}

#[cfg(not(feature = "database"))]
fn main() {
    let cli = Cli::parse();
    handle_file_commands(cli.command);
}

fn handle_file_commands(command: Commands) {
    match command {
        Commands::Scan {
            directory,
            format,
            output,
            countries,
            min_confidence,
            no_context,
            extract_documents,
            no_progress,
            full_paths,
            max_depth,
            threads,
            max_filesize,
            plugins,
        } => {
            // Validate directory
            if !directory.exists() {
                eprintln!(
                    "❌ Error: Directory does not exist: {}",
                    directory.display()
                );
                process::exit(1);
            }

            if !directory.is_dir() {
                eprintln!("❌ Error: Path is not a directory: {}", directory.display());
                process::exit(1);
            }

            // Build registry (with optional country filtering)
            let mut registry = if let Some(country_list) = countries {
                let codes: Vec<String> = country_list
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .collect();

                println!("🌍 Filtering detectors for countries: {:?}", codes);
                registry_for_countries(codes)
            } else {
                default_registry()
            };

            // Load plugin detectors
            let plugins_dir = plugins.unwrap_or_else(pii_radar::default_plugins_dir);

            if plugins_dir.exists() {
                match pii_radar::load_plugins(&plugins_dir) {
                    Ok(plugin_detectors) => {
                        if !plugin_detectors.is_empty() {
                            println!("🔌 Loaded {} plugin detector(s)\n", plugin_detectors.len());
                            for detector in plugin_detectors {
                                registry.register(detector);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  Warning: Failed to load plugins: {}", e);
                    }
                }
            }

            println!("🔍 Using {} detectors\n", registry.all().len());

            // Configure walker
            let mut walker = Walker::new(&directory);

            if let Some(depth) = max_depth {
                walker = walker.max_depth(depth);
            }

            if let Some(t) = threads {
                walker = walker.threads(t);
            }

            let _walker = walker.max_filesize(max_filesize * 1024 * 1024);

            // Create engine
            let mut engine = ScanEngine::new(registry)
                .enable_context(!no_context)
                .show_progress(!no_progress);

            // Configure extractors if requested
            if extract_documents {
                let mut extractor_registry = ExtractorRegistry::new();
                extractor_registry.register(Arc::new(PdfExtractor));
                extractor_registry.register(Arc::new(DocxExtractor));
                extractor_registry.register(Arc::new(XlsxExtractor));

                println!("📄 Document extraction enabled (PDF, DOCX, XLSX)\n");
                engine = engine.with_extractors(extractor_registry);
            }

            // Scan
            let results = engine.scan_directory(&directory);

            // Apply confidence filtering
            let min_conf: pii_radar::Confidence = min_confidence.into();
            let filtered_results = results.filter_by_confidence(min_conf);

            // Output
            match format {
                OutputFormat::Terminal => {
                    let reporter = TerminalReporter::new()
                        .full_paths(full_paths)
                        .show_context(!no_context);
                    reporter.report(&filtered_results);
                }
                OutputFormat::Json | OutputFormat::JsonCompact => {
                    let pretty = matches!(format, OutputFormat::Json);
                    let reporter = JsonReporter::new().pretty(pretty);

                    if let Some(path) = output {
                        if let Err(e) = reporter.write_to_file(&filtered_results, &path) {
                            eprintln!("❌ Error: {}", e);
                            process::exit(1);
                        }
                        println!("✅ Results written to: {}", path.display());
                    } else if let Err(e) = reporter.print(&filtered_results) {
                        eprintln!("❌ Error: {}", e);
                        process::exit(1);
                    }
                }
                OutputFormat::Html => {
                    let reporter = HtmlReporter::new();

                    let output_path =
                        output.unwrap_or_else(|| std::path::PathBuf::from("pii-radar-report.html"));

                    if let Err(e) = reporter.write_to_file(&filtered_results, &output_path) {
                        eprintln!("❌ Error: {}", e);
                        process::exit(1);
                    }
                    println!("✅ HTML report written to: {}", output_path.display());
                }
                OutputFormat::Csv => {
                    let reporter = CsvReporter::new().with_context(!no_context);

                    if let Some(path) = output {
                        if let Err(e) = reporter.write_to_file(&filtered_results, &path) {
                            eprintln!("❌ Error: {}", e);
                            process::exit(1);
                        }
                        println!("✅ CSV report written to: {}", path.display());
                    } else if let Err(e) = reporter.print(&filtered_results) {
                        eprintln!("❌ Error: {}", e);
                        process::exit(1);
                    }
                }
            }

            // Exit code 1 if PII found (for CI/CD)
            if filtered_results.total_matches > 0 {
                process::exit(1);
            }
        }

        Commands::Detectors { verbose } => {
            let registry = default_registry();

            println!(
                "\n📋 Available PII Detectors ({} total)\n",
                registry.all().len()
            );

            for detector in registry.all() {
                println!("🔍 {} ({})", detector.name(), detector.id());
                println!(
                    "   Country: {} | Severity: {:?}",
                    detector.country().to_uppercase(),
                    detector.base_severity()
                );

                if verbose {
                    println!();
                }
            }

            println!();
        }

        Commands::Api {
            urls,
            method,
            headers,
            body,
            timeout,
            no_redirects,
            format,
            output,
            min_confidence,
            plugins,
        } => {
            // Parse HTTP method
            let http_method = match method.parse::<HttpMethod>() {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    process::exit(1);
                }
            };

            // Parse headers
            let mut header_map = HashMap::new();
            for header in headers {
                if let Some((key, value)) = header.split_once(':') {
                    header_map.insert(key.trim().to_string(), value.trim().to_string());
                } else {
                    eprintln!(
                        "❌ Error: Invalid header format: {}. Expected KEY:VALUE",
                        header
                    );
                    process::exit(1);
                }
            }

            // Build API scan config
            let api_config = ApiScanConfig {
                method: http_method,
                headers: header_map,
                body,
                timeout_secs: timeout,
                follow_redirects: !no_redirects,
                max_redirects: 10,
            };

            // Build registry
            let mut registry = default_registry();

            // Load plugin detectors
            let plugins_dir = plugins.unwrap_or_else(pii_radar::default_plugins_dir);

            if plugins_dir.exists() {
                match pii_radar::load_plugins(&plugins_dir) {
                    Ok(plugin_detectors) => {
                        if !plugin_detectors.is_empty() {
                            println!("🔌 Loaded {} plugin detector(s)\n", plugin_detectors.len());
                            for detector in plugin_detectors {
                                registry.register(detector);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  Warning: Failed to load plugins: {}", e);
                    }
                }
            }

            println!("🔍 Using {} detectors\n", registry.all().len());
            println!("🌐 Scanning {} API endpoint(s)...\n", urls.len());

            // Prepare endpoints
            let endpoints: Vec<(String, ApiScanConfig)> = urls
                .into_iter()
                .map(|url| (url, api_config.clone()))
                .collect();

            // Scan endpoints
            let min_conf: pii_radar::Confidence = min_confidence.into();
            let detectors = registry.all();

            let results = match scan_api_endpoints(&endpoints, detectors, &min_conf) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    process::exit(1);
                }
            };

            // Output
            match format {
                OutputFormat::Terminal => {
                    let reporter = TerminalReporter::new().full_paths(true).show_context(true);
                    reporter.report(&results);
                }
                OutputFormat::Json | OutputFormat::JsonCompact => {
                    let pretty = matches!(format, OutputFormat::Json);
                    let reporter = JsonReporter::new().pretty(pretty);

                    if let Some(path) = output {
                        if let Err(e) = reporter.write_to_file(&results, &path) {
                            eprintln!("❌ Error: {}", e);
                            process::exit(1);
                        }
                        println!("✅ Results written to: {}", path.display());
                    } else if let Err(e) = reporter.print(&results) {
                        eprintln!("❌ Error: {}", e);
                        process::exit(1);
                    }
                }
                OutputFormat::Html => {
                    let reporter = HtmlReporter::new();

                    let output_path = output
                        .unwrap_or_else(|| std::path::PathBuf::from("pii-radar-api-report.html"));

                    if let Err(e) = reporter.write_to_file(&results, &output_path) {
                        eprintln!("❌ Error: {}", e);
                        process::exit(1);
                    }
                    println!("✅ HTML report written to: {}", output_path.display());
                }
                OutputFormat::Csv => {
                    let reporter = CsvReporter::new().with_context(true);

                    if let Some(path) = output {
                        if let Err(e) = reporter.write_to_file(&results, &path) {
                            eprintln!("❌ Error: {}", e);
                            process::exit(1);
                        }
                        println!("✅ CSV report written to: {}", path.display());
                    } else if let Err(e) = reporter.print(&results) {
                        eprintln!("❌ Error: {}", e);
                        process::exit(1);
                    }
                }
            }

            // Exit code 1 if PII found (for CI/CD)
            if results.total_matches > 0 {
                process::exit(1);
            }
        }

        #[cfg(feature = "database")]
        Commands::ScanDb { .. } => {
            // This should be handled in the async main function
            unreachable!("ScanDb should be handled in async main");
        }
    }
}

#[cfg(feature = "database")]
struct DbScanParams {
    db_type: String,
    connection: String,
    database: Option<String>,
    tables: Option<String>,
    exclude_tables: Option<String>,
    columns: Option<String>,
    exclude_columns: Option<String>,
    sample_percent: Option<u8>,
    row_limit: Option<usize>,
    pool_size: u32,
    format: OutputFormat,
    output: Option<std::path::PathBuf>,
    countries: Option<String>,
    no_progress: bool,
}

#[cfg(feature = "database")]
async fn handle_scan_db(params: DbScanParams) {
    use std::str::FromStr;

    // Parse database type
    let db_type = match DatabaseType::from_str(&params.db_type) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            eprintln!("Supported types: postgres, mysql, mongodb");
            process::exit(1);
        }
    };

    // Extract or validate database name
    let db_name = if let Some(name) = params.database {
        name
    } else {
        match pii_radar::database::scanner::extract_database_name(&params.connection, db_type) {
            Some(name) => name,
            None => {
                eprintln!("❌ Error: Database name required (use --database or include in connection string)");
                process::exit(1);
            }
        }
    };

    println!("🔗 Connecting to {} database: {}", db_type, db_name);

    // Build registry
    let registry = if let Some(country_list) = params.countries {
        let codes: Vec<String> = country_list
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect();
        println!("🌍 Filtering detectors for countries: {:?}", codes);
        registry_for_countries(codes)
    } else {
        default_registry()
    };

    println!("🔍 Using {} detectors\n", registry.all().len());

    // Build scan options
    let mut scan_options = ScanOptions::new();
    scan_options.show_progress = !params.no_progress;

    if let Some(t) = params.tables {
        scan_options.include_tables = Some(t.split(',').map(|s| s.trim().to_string()).collect());
    }

    if let Some(e) = params.exclude_tables {
        scan_options.exclude_tables = e.split(',').map(|s| s.trim().to_string()).collect();
    }

    if let Some(c) = params.columns {
        scan_options.include_columns = Some(c.split(',').map(|s| s.trim().to_string()).collect());
    }

    if let Some(e) = params.exclude_columns {
        scan_options.exclude_columns = e.split(',').map(|s| s.trim().to_string()).collect();
    }

    scan_options.sample_percent = params.sample_percent;
    scan_options.row_limit = params.row_limit;

    // Build database config
    let config = DatabaseConfig::new(db_type, params.connection).with_pool_size(params.pool_size);

    // Create scanner
    let scanner = match DatabaseScanner::new(config, Some(&db_name), registry).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Error connecting to database: {}", e);
            process::exit(1);
        }
    };

    println!("✅ Connected successfully\n");

    // Scan database
    println!("🔍 Scanning database...\n");
    let results = match scanner.scan(&db_name, &scan_options).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ Error scanning database: {}", e);
            process::exit(1);
        }
    };

    // Print summary
    println!("\n📊 Scan Summary:");
    println!(
        "   Database: {} ({})",
        results.database_name, results.database_type
    );
    println!("   Tables/Collections: {}", results.tables_scanned.len());
    println!("   Total Rows: {}", results.total_rows);
    println!("   Total Matches: {}", results.total_matches);
    println!("   Duration: {:.2}s", results.duration.as_secs_f64());

    // Output detailed results based on format
    match params.format {
        OutputFormat::Terminal => {
            println!("\n📋 Detailed Results:");
            for table in &results.tables_scanned {
                if table.matches_found > 0 {
                    println!(
                        "\n🗂️  {} ({} matches in {} rows):",
                        table.name, table.matches_found, table.rows_scanned
                    );
                    for m in &table.matches {
                        println!(
                            "   ⚠️  {} - {} (Line: {}, Column: {})",
                            m.detector_name,
                            m.value_masked,
                            m.location.line,
                            m.location.file_path.display()
                        );
                    }
                }
            }
        }
        OutputFormat::Json | OutputFormat::JsonCompact => {
            let pretty = matches!(params.format, OutputFormat::Json);
            let json_str = if pretty {
                serde_json::to_string_pretty(&results).unwrap()
            } else {
                serde_json::to_string(&results).unwrap()
            };

            if let Some(path) = params.output {
                if let Err(e) = std::fs::write(&path, json_str) {
                    eprintln!("❌ Error writing to file: {}", e);
                    process::exit(1);
                }
                println!("\n✅ Results written to: {}", path.display());
            } else {
                println!("\n{}", json_str);
            }
        }
        OutputFormat::Html => {
            eprintln!("❌ HTML output format not yet implemented for database scans");
            process::exit(1);
        }
        OutputFormat::Csv => {
            eprintln!("❌ CSV output format not yet implemented for database scans");
            process::exit(1);
        }
    }

    // Exit code 1 if PII found (for CI/CD)
    if results.total_matches > 0 {
        process::exit(1);
    }
}
