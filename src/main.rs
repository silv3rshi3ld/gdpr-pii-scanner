/// PII-Radar CLI entry point
use clap::Parser;
use pii_radar::cli::{Cli, Commands, OutputFormat};
use pii_radar::{
    default_registry, registry_for_countries, DocxExtractor, ExtractorRegistry, HtmlReporter,
    JsonReporter, PdfExtractor, ScanEngine, TerminalReporter, Walker, XlsxExtractor,
};
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
            let registry = if let Some(country_list) = countries {
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
    }
}
