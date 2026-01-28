# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-01-28

### Added
- **5 New Countries**: Poland (PESEL), Denmark (CPR), Sweden (Personnummer), Norway (Fødselsnummer), Finland (HETU)
- **Configuration File Support**: TOML-based configuration with environment variable expansion
  - Load settings from `~/.pii-radar/config.toml` or custom path with `--config`
  - Configuration precedence: CLI args > config file > defaults
  - Environment variable substitution with `${VAR_NAME}` syntax
  - Example config file in `examples/config.toml`
- **New Detectors**: 5 Nordic/Central European national ID detectors with comprehensive validation

### Improved
- Enhanced test coverage: 251 tests passing (from 199 in v0.3.0)
- Modular detector architecture with country-specific validation algorithms
- Better error handling and validation for all numeric formats

### Technical Details
- 251 tests passing (89% test coverage)
- 16 detectors across 12 countries
- ~1,200 lines of code added
- New dependencies: `toml` (0.8), `dirs` (5.0)
- Configuration module with 6 passing tests

### Detectors Added
1. **Poland PESEL** - Polish national identification number (11 digits)
   - Weighted checksum validation (weights: 1,3,7,9,1,3,7,9,1,3)
   - Birth date encoding with century support (1800s-2200s)
   - Gender detection from sequence number
   - 9 comprehensive tests

2. **Denmark CPR** - Danish Civil Registration number (10 digits, DDMMYY-SSSS format)
   - Modulus 11 validation with weights [4,3,2,7,6,5,4,3,2,1]
   - Date validation for DDMMYY format
   - Dash normalization support
   - 5 comprehensive tests

3. **Sweden Personnummer** - Swedish personal identity number (10 or 12 digits)
   - Luhn algorithm validation (Swedish variant: double positions 0,2,4,...)
   - Supports both YYMMDD-XXXX and YYYYMMDD-XXXX formats
   - Century marker support (+, -, A-Y)
   - 5 comprehensive tests

4. **Norway Fødselsnummer** - Norwegian birth number (11 digits)
   - Dual modulus 11 checksum validation (K1 and K2)
   - K1 weights: [3,7,6,1,8,9,4,5,2], K2 weights: [5,4,3,2,7,6,5,4,3,2]
   - D-number support (day > 40 for immigrants)
   - 5 comprehensive tests

5. **Finland HETU** - Finnish personal identity code (11 characters)
   - Modulus 31 checksum with 31-character lookup table
   - Century markers: + (1800s), - (1900s), A-Y (2000s-2800s)
   - Format: DDMMYY{century}XXX{check}
   - Check characters: 0-9, A-Y (excluding G, I, O, V)
   - 6 comprehensive tests

### Configuration Features
- **Scan Settings**: paths, max_depth, follow_symlinks, parallel scanning
- **Output Settings**: format (json/terminal/html/csv), output_file, verbosity
- **Filter Settings**: file size limits, extensions, excluded patterns, min_confidence
- **Database Config**: connection strings, batch size, table/column filtering
- **API Config**: endpoints, methods, headers, authentication
- **Plugin Config**: plugin directory path for custom detectors

## [0.3.0] - 2026-01-27

### Added
- **3 New Countries**: France (NIR), Germany (Steuer-ID), Italy (Codice Fiscale)
- **Document Extraction**: PDF, DOCX, XLSX support with `--extract-documents` flag
- **HTML Reporter**: Interactive reports with search and visual statistics
- **Progress Bar**: Real-time scanning progress with live match counts using `indicatif`
- **Confidence Filtering**: `--min-confidence` flag (low/medium/high) for filtering results
- **Extraction Statistics**: Track extracted documents and failures in scan results
- **No Progress Flag**: `--no-progress` to disable progress bar for CI/CD pipelines

### Improved
- Enhanced terminal output with extraction statistics display
- Better validation for all detectors with comprehensive test coverage
- Thread-safe statistics tracking using atomic counters
- More detailed scan results with document extraction metrics

### Technical Details
- 199 tests passing (88% test coverage)
- 11 detectors across 7 countries
- ~1,500 lines of code added
- New dependencies: `indicatif` (0.17), `tera` (1.19), `chrono` (0.4)
- Existing dependencies: `calamine` (0.24) for XLSX extraction

### Detectors Added
1. **France NIR** - French social security number (15 digits)
   - Luhn mod 97 validation
   - Format: Sex + YY + MM + Dept + Commune + Order + Checksum
   - 10 comprehensive tests

2. **Germany Steuer-ID** - German tax identification number (11 digits)
   - Modified modulus 11 validation
   - Complex digit repetition rules
   - 12 comprehensive tests

3. **Italy Codice Fiscale** - Italian tax code (16 alphanumeric)
   - Complex check digit algorithm with odd/even character lookup tables
   - Month codes (A-T), day validation (01-31 male, 41-71 female)
   - 15 comprehensive tests

### Bug Fixes
- Fixed test fixtures across JSON and terminal reporters for extraction stats
- Updated `ScanResults` struct to include extraction metrics

## [0.2.0] - 2024-01-15

### Added
- **3 New Countries**: United Kingdom (NHS), Belgium (RRN), Spain (DNI/NIE)
- **Country Filtering**: `--countries` flag to filter detectors by country codes
- **Confidence Levels**: Added confidence scoring to all detectors
- **GDPR Article 9**: Context-aware detection for special category data

### Improved
- Enhanced validator algorithms with checksum validation
- Better error messages and user feedback
- Performance optimizations for parallel scanning

### Technical Details
- 163 tests passing
- 9 detectors across 5 countries
- Country codes supported: BE, GB, ES, NL

## [0.1.0] - 2024-01-01

### Added
- Initial release
- **2 Countries**: Netherlands (BSN), Pan-European (IBAN)
- **Universal Detectors**: Credit Cards, Email Addresses
- **Core Features**:
  - Parallel file scanning with Rayon
  - JSON and terminal output formats
  - `.pii-ignore` file support
  - GDPR context analysis
  - Thread control with `-j` flag
  - File size limits with `--max-filesize`

### Technical Details
- 120 tests passing
- 4 detectors (BSN, IBAN, Credit Card, Email)
- Built with Rust 1.70+

---

[0.3.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/silv3rshi3ld/gdpr-pii-scanner/releases/tag/v0.1.0
