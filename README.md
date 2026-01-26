# PII-Radar 🔍

> High-performance PII scanner for local files with context-aware GDPR Article 9 detection

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](CHANGELOG.md)

PII-Radar is a blazing-fast command-line tool that scans your local directories for Personally Identifiable Information (PII) across European countries. Built with Rust for maximum performance and safety.

## Features

- 🌍 **7 European Countries**: Detects PII from Belgium, France, Germany, Italy, Netherlands, Spain, UK
- 📄 **Document Extraction**: Scans PDFs, DOCX, and XLSX files for PII
- ⚡ **High Performance**: Parallel file scanning with real-time progress bars
- 🛡️ **GDPR Article 9 Detection**: Context-aware analysis detects special category data
- 🎯 **Strict Validation**: Checksum algorithms minimize false positives
- 🎨 **Beautiful Output**: Terminal, JSON, or interactive HTML reports
- 🔒 **Privacy-First**: All data stays local - no cloud uploads
- 🚀 **CI/CD Ready**: Exit code 1 when PII found for pipeline integration
- 🎚️ **Confidence Filtering**: Filter by confidence level (low/medium/high)

## Supported PII Types

### Belgium 🇧🇪
- **RRN** (Rijksregisternummer) - Modulus 97 validated

### France 🇫🇷
- **NIR** (Numéro de Sécurité Sociale) - Luhn mod 97 validated

### Germany 🇩🇪
- **Steuer-ID** (Tax Identification Number) - Modified modulus 11 validated

### Italy 🇮🇹
- **Codice Fiscale** (Tax Code) - Complex check digit algorithm validated

### Netherlands 🇳🇱
- **BSN** (Burgerservicenummer) - 11-proef validated

### Spain 🇪🇸
- **DNI** (Documento Nacional de Identidad) - Modulus 23 validated
- **NIE** (Número de Identidad de Extranjero) - Modulus 23 validated

### United Kingdom 🇬🇧
- **NHS Number** (National Health Service) - Modulus 11 validated

### Pan-European 🇪🇺
- **IBAN** (International Bank Account Number) - Mod-97 validation for all EU countries

### Universal 🌍
- **Credit Cards** - Visa, Mastercard, Amex with Luhn validation
- **Email Addresses** - RFC 5322-compliant detection

## Installation

### From Source

```bash
git clone https://github.com/silv3rshi3ld/gdpr-pii-scanner
cd gdpr-pii-scanner
cargo build --release
sudo cp target/release/pii-radar /usr/local/bin/
```

### Using Cargo

```bash
cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner
```

## Quick Start

### Scan a directory

```bash
pii-radar scan /path/to/directory
```

### Scan documents (PDF, DOCX, XLSX)

```bash
pii-radar scan /path --extract-documents
```

### Generate HTML report

```bash
pii-radar scan /path --format html --output report.html
```

### List available detectors

```bash
pii-radar detectors
# Shows all 11 detectors across 7 countries
```

### Advanced usage

```bash
# Filter by specific countries (BE, FR, DE, IT, NL, ES, GB)
pii-radar scan /path --countries gb,nl,fr

# Scan with JSON output
pii-radar scan /path --format json --output results.json

# Generate interactive HTML report
pii-radar scan /path --format html --output report.html

# Extract text from documents
pii-radar scan /path --extract-documents

# Disable progress bar
pii-radar scan /path --no-progress

# Filter by confidence level
pii-radar scan /path --min-confidence medium

# Disable context analysis (faster)
pii-radar scan /path --no-context

# Limit recursion depth
pii-radar scan /path --max-depth 3

# Use more threads
pii-radar scan /path -j 32
```

## Document Extraction

PII-Radar can extract and scan text from:
- **PDF files** (using lopdf)
- **Microsoft Word** (.docx)
- **Microsoft Excel** (.xlsx)

```bash
# Enable document extraction
pii-radar scan /documents --extract-documents

# Results show extraction statistics:
# Documents extracted: 15
# Extraction failures: 1
```

Extraction failures are logged but don't stop the scan. The scanner will continue with the next file.

## HTML Reports

Generate beautiful, interactive HTML reports:

```bash
pii-radar scan /path --format html --output report.html
```

Features:
- 🎨 Responsive design with gradient theme
- 🔍 Live search/filter functionality
- 📊 Visual severity breakdown with progress bars
- 📋 Sortable results table
- 🏷️ GDPR Article 9 badges
- 📈 Extraction statistics

Opens in any modern browser - no server required!

## Example Output

```
════════════════════════════════════════════════════════════════════════════════
  🎯 SCAN COMPLETE
════════════════════════════════════════════════════════════════════════════════

📊 Statistics:
  Files scanned:    4
  Files with PII:   4
  Total matches:    16
  Scan duration:    3 ms
  
📄 Document Extraction:
  Documents extracted:    12
  Extraction failures:    0

⚠️  Severity Breakdown:
  🔴 Critical:  11
  🟠 High:      2
  🟡 Medium:    3

🔍 Detector Matches:
  → French NIR (Numéro de Sécurité Sociale): 2
  → Italian Codice Fiscale: 1
  → Germany Tax ID (Steuer-ID): 1
  → Dutch BSN (Burgerservicenummer): 3
  → UK NHS Number: 3
  → Spain DNI: 2
  → Spain NIE: 1
  → Belgium RRN: 4
  → IBAN (International Bank Account Number): 1
  → Credit Card Number: 1
  → Email Address: 3

⚠️  GDPR Article 9 - Special Category Data:
  2 matches contain sensitive context (medical/biometric/genetic/criminal)
  These require extra protection under GDPR!
```

## CLI Options

### `scan` command

```
pii-radar scan [OPTIONS] <PATH>

OPTIONS:
  -f, --format <FORMAT>           Output format [default: terminal] 
                                  [possible: terminal, json, json-compact, html]
  -o, --output <FILE>             Output file (for json/html formats)
  -c, --countries <CODES>         Filter by country codes 
                                  (be,fr,de,it,nl,es,gb)
      --min-confidence <LEVEL>    Minimum confidence [default: high] 
                                  [possible: low, medium, high]
      --extract-documents         Extract text from PDF, DOCX, XLSX files
      --no-context                Disable GDPR Article 9 context analysis
      --no-progress               Disable progress bar
      --full-paths                Show full file paths
      --max-depth <DEPTH>         Maximum recursion depth
  -j, --threads <N>               Number of threads (default: auto)
      --max-filesize <SIZE>       Max file size in MB [default: 100]
  -h, --help                      Print help
```

### `detectors` command

```
pii-radar detectors [OPTIONS]

OPTIONS:
  -v, --verbose    Show detailed information
  -h, --help       Print help
```

## Context-Aware Detection

PII-Radar analyzes text around detected PII to identify GDPR Article 9 special category data:

- **Medical**: Patient records, diagnoses, treatments
- **Biometric**: Fingerprints, facial recognition data
- **Genetic**: DNA sequences, genetic test results
- **Criminal**: Criminal records, convictions

When special category keywords are detected, the severity is automatically upgraded to **Critical**.

### Example

**Input file:**
```
Patient John Doe with BSN 111222333 diagnosed with diabetes.
```

**Detection:**
- BSN detected: `111222333` (validated with 11-proef)
- Context keywords: `patient`, `diagnosed`
- Category: Medical
- Severity: **Critical** (upgraded from High)

## .pii-ignore

Create a `.pii-ignore` file in your scan directory to exclude files/patterns (uses gitignore syntax):

```gitignore
# Ignore compiled files
*.exe
*.dll
*.so

# Ignore test data
test-data/
*.test

# Ignore secrets (ironically)
.env
credentials.json
```

## Performance

- **Fast**: Scans 100,000+ files in under 5 minutes
- **Parallel**: Uses all available CPU cores
- **Memory-efficient**: Streams file content
- **Network-optimized**: Non-blocking I/O for network drives

## CI/CD Integration

PII-Radar exits with code 1 when PII is found, making it perfect for CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Scan for PII
  run: pii-radar scan ./src --format json --output pii-report.json
  continue-on-error: true

- name: Upload PII report
  uses: actions/upload-artifact@v3
  with:
    name: pii-report
    path: pii-report.json
```

## Development

### Run tests

```bash
cargo test
```

### Run benchmarks

```bash
cargo bench
```

### Build documentation

```bash
cargo doc --open
```

## Roadmap

### v0.2.0 ✅ COMPLETE
- [x] More country detectors (GB, BE, ES)
- [x] Country filtering (`--countries gb,es,be`)
- [x] Confidence filtering
- [x] HTML report format

### v0.3.0 ✅ COMPLETE
- [x] 7 European countries (BE, FR, DE, IT, NL, ES, GB)
- [x] Document extraction (PDF, DOCX, XLSX)
- [x] HTML report format with interactive UI
- [x] Progress bars with live statistics
- [x] France NIR detector
- [x] Italy Codice Fiscale detector
- [x] Germany Steuer-ID detector

### v0.4.0 (Planned)
- [ ] More countries (PT, PL, DK, SE, NO, FI)
- [ ] Database scanning (PostgreSQL, MySQL)
- [ ] API endpoint scanning
- [ ] Custom detector plugins
- [ ] Machine learning-based detection
- [ ] CSV report format
- [ ] Configuration file support

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Acknowledgments

- Built with the excellent [ignore](https://github.com/BurntSushi/ripgrep/tree/master/crates/ignore) crate from ripgrep
- Inspired by the need for fast, local PII scanning in European data protection contexts
- Uses checksum algorithms to ensure high-quality detections

## Disclaimer

PII-Radar is a tool to help identify potential PII in your files. It should not be your only line of defense. Always follow your organization's data protection policies and consult with legal/compliance teams for GDPR compliance.

---

Made with ❤️ and ☕ by the PII-Radar contributors
