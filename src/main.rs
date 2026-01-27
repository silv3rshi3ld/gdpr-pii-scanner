/// PII-Radar CLI entry point
use clap::Parser;
use pii_radar::cli::{Cli, Commands, OutputFormat};
use pii_radar::{
    default_registry, registry_for_countries, CsvReporter, DocxExtractor, ExtractorRegistry,
    HtmlReporter, JsonReporter, PdfExtractor, ScanEngine, TerminalReporter, Walker,
    XlsxExtractor, ApiScanConfig, HttpMethod, scan_api_endpoints,
};
use std::collections::HashMap;
use std::process;
use std::sync::Arc;

fn main() {
    let cli = Cli::parse();

    match cli.command {
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
            let plugins_dir = plugins.unwrap_or_else(|| {
                pii_radar::default_plugins_dir()
            });

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
                    eprintln!("❌ Error: Invalid header format: {}. Expected KEY:VALUE", header);
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
            let plugins_dir = plugins.unwrap_or_else(|| {
                pii_radar::default_plugins_dir()
            });

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

            let results = match scan_api_endpoints(&endpoints, &detectors, &min_conf) {
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

                    let output_path =
                        output.unwrap_or_else(|| std::path::PathBuf::from("pii-radar-api-report.html"));

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
    }
}
