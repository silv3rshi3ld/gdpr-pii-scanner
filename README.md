# PII-Radar 🔍

> High-performance PII scanner for files and databases with extensible plugin system

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.4.0-green.svg)](CHANGELOG.md)

PII-Radar is a blazing-fast command-line tool that scans files and databases for Personally Identifiable Information (PII) across European countries. Built with Rust for maximum performance and safety, with extensible plugin architecture for custom detectors.

## 🎯 Key Features

- 🌍 **10+ European Countries**: NL, DE, GB, ES, FR, IT, BE, PT + Nordic countries
- 🗄️ **Database Scanning**: PostgreSQL, MySQL, MongoDB with connection pooling
- 🔌 **Plugin System**: Custom detectors via TOML configuration
- 🔑 **API Key Detection**: AWS, GitHub, Stripe, OpenAI, JWT, private keys
- 📄 **Document Extraction**: PDFs, DOCX, XLSX file scanning
- ⚡ **High Performance**: Parallel scanning with benchmarks
- 🛡️ **GDPR Article 9**: Context-aware special category data detection
- 🎯 **Strict Validation**: Checksum algorithms minimize false positives
- 🎨 **Multiple Outputs**: Terminal, JSON, CSV, HTML reports
- 🔒 **Privacy-First**: All data stays local - no cloud uploads
- 🚀 **CI/CD Ready**: Exit code 1 when PII found

## 📦 Installation

### From Source

```bash
git clone https://github.com/silv3rshi3ld/gdpr-pii-scanner
cd gdpr-pii-scanner
cargo build --release
sudo cp target/release/pii-radar /usr/local/bin/
```

### With Database Support

```bash
cargo build --release --features database
```

### Using Cargo

```bash
cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner
```

## 🚀 Quick Start

### File Scanning

```bash
# Basic scan
pii-radar scan /path/to/directory

# Scan documents (PDF, DOCX, XLSX)
pii-radar scan /path --extract-documents

# Filter by countries
pii-radar scan /path --countries nl,de,gb

# Generate HTML report
pii-radar scan /path --format html --output report.html

# Use custom detectors
pii-radar scan /path --plugin-dir ./plugins
```

### Database Scanning

```bash
# Scan PostgreSQL database
pii-radar scan-db \
  --db-type postgres \
  --connection "postgresql://user:pass@localhost:5432/mydb" \
  --format json \
  --output db_results.json

# Scan MySQL with filtering
pii-radar scan-db \
  --db-type mysql \
  --connection "mysql://user:pass@localhost:3306/mydb" \
  --tables "users,customers" \
  --exclude-columns "id,created_at"

# Scan MongoDB collection
pii-radar scan-db \
  --db-type mongodb \
  --connection "mongodb://localhost:27017" \
  --database mydb \
  --tables "users" \
  --row-limit 10000
```

### Database Options

```
--db-type <TYPE>              Database type: postgres, mysql, mongodb
--connection <URL>            Connection string
--database <NAME>             Database name (required for MongoDB)
-t, --tables <NAMES>          Filter specific tables/collections (comma-separated)
--exclude-tables <NAMES>      Exclude tables/collections
--columns <NAMES>             Scan only specific columns
--exclude-columns <NAMES>     Exclude columns from scan
--sample-percent <N>          Sample percentage for large tables (Postgres only)
--row-limit <N>               Maximum rows to scan per table
--pool-size <N>               Connection pool size [default: 4]
```

## 🔌 Plugin System

Create custom PII detectors without modifying code!

### Creating a Plugin

Create a file named `my_detector.detector.toml`:

```toml
id = "custom_employee_id"
name = "Employee ID"
country = "universal"
category = "custom"
description = "Detects company employee IDs"
severity = "medium"  # low, medium, high, critical

# Define regex patterns
[[patterns]]
pattern = "EMP-\\d{6}"
confidence = "high"  # low, medium, high

# Optional validation
[validation]
min_length = 10
max_length = 10
required_prefix = "EMP-"
checksum = "luhn"  # Built-in: luhn, mod11, iban

# Examples for testing
examples = ["EMP-123456", "EMP-987654"]

# Context keywords (boost confidence)
context_keywords = ["employee", "staff", "personnel"]
```

### Using Plugins

```bash
# Load plugins from directory
pii-radar scan /data --plugin-dir ./plugins

# Multiple patterns in one plugin
pii-radar scan /data --plugin-dir ./company-plugins
```

See `examples/plugins/` for complete examples:
- `employee_id.detector.toml` - Company employee IDs
- `patient_id.detector.toml` - Medical patient records (GDPR critical)
- `credit_card.detector.toml` - Credit cards with Luhn validation

## 🔍 Supported PII Types

### Belgium 🇧🇪
- **RRN** (Rijksregisternummer) - Modulus 97 validated

### France 🇫🇷
- **NIR** (Numéro de Sécurité Sociale) - Luhn mod 97 validated

### Germany 🇩🇪
- **Steuer-ID** (Tax Identification Number) - Modified modulus 11 validated

### Italy 🇮🇹
- **Codice Fiscale** (Tax Code) - Complex check digit algorithm

### Netherlands 🇳🇱
- **BSN** (Burgerservicenummer) - 11-proef validated

### Portugal 🇵🇹
- **NIF** (Número de Identificação Fiscal) - Modulus 11 validated

### Spain 🇪🇸
- **DNI** (Documento Nacional de Identidad) - Modulus 23 validated
- **NIE** (Número de Identidad de Extranjero) - Modulus 23 validated

### United Kingdom 🇬🇧
- **NHS Number** (National Health Service) - Modulus 11 validated

### Pan-European 🇪🇺
- **IBAN** (International Bank Account Number) - Mod-97 validation

### Universal 🌍
- **Credit Cards** - Visa, Mastercard, Amex with Luhn validation
- **Email Addresses** - RFC 5322-compliant detection
- **API Keys** - AWS, GitHub, Stripe, OpenAI, JWT, private keys (RSA/DSA/EC)

## 🎨 Output Formats

### Terminal (Default)

Colored, human-readable output with severity indicators:

```
🔴 CRITICAL | Dutch BSN (Burgerservicenummer)
   File: employees.csv:42:15
   Value: 123****782
   Context: Patient medical record...
   GDPR: Special Category (Medical)
```

### JSON

Structured output for programmatic processing:

```bash
pii-radar scan /path --format json --output results.json
```

### HTML Report

Interactive, searchable HTML report:

```bash
pii-radar scan /path --format html --output report.html
```

Features:
- 🎨 Responsive design with gradient theme
- 🔍 Live search and filtering
- 📊 Visual severity breakdown
- 📋 Sortable results table
- 🏷️ GDPR Article 9 badges

## 📊 Performance Benchmarks

Run comprehensive performance benchmarks:

```bash
# Run all benchmarks
cargo bench

# Specific benchmark groups
cargo bench scan_text
cargo bench detector_performance
cargo bench thread_scaling
```

Benchmark categories:
- Plain text scanning
- Individual detector performance
- PII density scenarios
- File size distribution
- Pattern complexity
- Thread scaling (1-32 threads)

## 🛠️ CLI Reference

### `scan` - File Scanning

```
pii-radar scan [OPTIONS] <PATH>

OPTIONS:
  -f, --format <FORMAT>         Output format [default: terminal]
                                [possible: terminal, json, html, csv]
  -o, --output <FILE>           Output file (for json/html/csv)
  -c, --countries <CODES>       Filter by country codes (nl,de,gb,...)
      --min-confidence <LEVEL>  Minimum confidence [default: high]
      --extract-documents       Extract text from PDF/DOCX/XLSX
      --no-context              Disable GDPR Article 9 analysis
      --no-progress             Disable progress bar
      --full-paths              Show full file paths
      --max-depth <DEPTH>       Maximum recursion depth
  -j, --threads <N>             Number of threads (default: auto)
      --max-filesize <SIZE>     Max file size in MB [default: 100]
      --plugin-dir <DIR>        Load custom detectors from directory
  -h, --help                    Print help
```

### `scan-db` - Database Scanning (requires `--features database`)

```
pii-radar scan-db [OPTIONS]

OPTIONS:
      --db-type <TYPE>          Database type: postgres, mysql, mongodb
  -c, --connection <URL>        Connection string
      --database <NAME>         Database name (required for MongoDB)
  -t, --tables <NAMES>          Scan specific tables (comma-separated)
      --exclude-tables <NAMES>  Exclude tables
      --columns <NAMES>         Scan specific columns
      --exclude-columns <NAMES> Exclude columns
      --sample-percent <N>      Sample percentage (Postgres only)
      --row-limit <N>           Max rows per table
      --pool-size <N>           Connection pool size [default: 4]
  -f, --format <FORMAT>         Output format [default: terminal]
  -o, --output <FILE>           Output file
  -c, --countries <CODES>       Filter by country codes
      --no-progress             Disable progress bar
```

### `detectors` - List Detectors

```
pii-radar detectors [OPTIONS]

OPTIONS:
  -v, --verbose    Show detailed information
  -h, --help       Print help
```

## 🔐 GDPR Article 9 - Special Category Data

PII-Radar automatically detects and flags special category data requiring extra protection:

- **Medical**: Patient records, diagnoses, treatments
- **Biometric**: Fingerprints, facial recognition data
- **Genetic**: DNA sequences, genetic test results
- **Criminal**: Criminal records, convictions

When detected, severity is upgraded to **Critical** with GDPR Article 9 badge.

## 🏗️ Architecture

```
pii-radar/
├── src/
│   ├── core/           # Core detection engine
│   ├── detectors/      # Country-specific detectors
│   │   ├── plugin.rs         # Plugin detector runtime
│   │   └── plugin_loader.rs  # TOML plugin loader
│   ├── database/       # Database scanning module
│   │   ├── postgres.rs
│   │   ├── mysql.rs
│   │   └── mongodb.rs
│   ├── scanner/        # File scanning engine
│   ├── extractor/      # Document text extraction
│   ├── reporter/       # Output formatters
│   └── cli/            # Command-line interface
├── benches/            # Performance benchmarks
└── examples/
    └── plugins/        # Example plugin detectors
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with database tests (requires running databases)
cargo test --features database

# Run benchmarks
cargo bench

# Run specific test
cargo test test_bsn_detection
```

**Test Coverage**: 237 tests covering all detectors, database scanning, and plugin system.

## 🚀 CI/CD Integration

PII-Radar exits with code 1 when PII is found, making it perfect for CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Scan for PII
  run: |
    pii-radar scan ./src --format json --output pii-report.json
    
- name: Upload results
  if: failure()
  uses: actions/upload-artifact@v3
  with:
    name: pii-report
    path: pii-report.json
```

## 📚 Examples

### Scan with Custom Plugins

```bash
# Create plugin directory
mkdir -p ./plugins

# Create custom detector (see examples/plugins/)
cat > ./plugins/customer_id.detector.toml << 'EOF'
id = "customer_id"
name = "Customer ID"
country = "universal"
category = "custom"
description = "Company customer identifiers"
severity = "medium"

[[patterns]]
pattern = "CUST-\\d{8}"
confidence = "high"

[validation]
min_length = 13
max_length = 13
EOF

# Scan with plugin
pii-radar scan /data --plugin-dir ./plugins
```

### Database Scanning with Sampling

```bash
# Scan large Postgres database with 10% sampling
pii-radar scan-db \
  --db-type postgres \
  --connection "postgresql://user:pass@localhost/bigdb" \
  --sample-percent 10 \
  --row-limit 100000 \
  --format json \
  --output results.json
```

### Multi-Database Scan Script

```bash
#!/bin/bash
# Scan multiple databases and aggregate results

for db in prod_db staging_db dev_db; do
  pii-radar scan-db \
    --db-type postgres \
    --connection "postgresql://user:pass@localhost/$db" \
    --format json \
    --output "${db}_scan.json"
done

# Merge results
jq -s 'add' *_scan.json > combined_results.json
```

## 🔧 Development

### Building

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# With database support
cargo build --release --features database

# Run clippy lints
cargo clippy --all-features

# Format code
cargo fmt
```

### Adding a New Detector

1. Create detector in `src/detectors/<country>/`
2. Implement `Detector` trait
3. Add tests
4. Register in `src/lib.rs`

See existing detectors for examples.

### Creating Plugins

No code changes needed! Just create a `.detector.toml` file:

```toml
id = "my_detector"
name = "My Custom Detector"
country = "universal"
category = "custom"
description = "Detects custom format"
severity = "medium"

[[patterns]]
pattern = "YOUR-REGEX-HERE"
confidence = "high"
```

## 📝 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## 🔗 Links

- [GitHub Repository](https://github.com/silv3rshi3ld/gdpr-pii-scanner)
- [Issue Tracker](https://github.com/silv3rshi3ld/gdpr-pii-scanner/issues)
- [Changelog](CHANGELOG.md)

## ⚠️ Disclaimer

This tool is designed to help identify PII in data, but it should not be the only measure for ensuring GDPR compliance. Always consult with legal experts regarding data protection requirements.

---

**Built with ❤️ and Rust** | Made for European Data Protection
