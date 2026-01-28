# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-01-28

### 🐛 Bug Fixes (2026-01-28)
- **XLSX Extraction Re-enabled**: Fixed dependency conflict by updating `zip` crate from 0.6 to 4.2
  - Resolves compatibility issue between `calamine 0.32` and `zip` crate
  - All XLSX formats now working: .xlsx, .xlsm, .xlsb, .xls
- **Code Quality**: Resolved all clippy linter warnings
  - Replaced manual modulo checks with `is_multiple_of()` method
  - Refactored functions with too many arguments using parameter structs
  - Fixed redundant closures and needless borrows
  - Updated benchmarks to use `std::hint::black_box` instead of deprecated `criterion::black_box`
- **CSV Reporter**: Confirmed fully functional (was incorrectly marked as incomplete)

### 🚀 Major Features

#### Database Scanning
- **PostgreSQL, MySQL, MongoDB Support**: Scan databases directly for PII
  - New `scan-db` command with connection string support
  - Table/collection filtering with regex patterns
  - Column filtering and exclusion
  - Row sampling for large datasets (PostgreSQL TABLESAMPLE)
  - Connection pooling (default 4 connections)
  - Async operations with tokio
  - Progress bars for database scans
  - ~1,200 lines of code for database module

#### Plugin System for Custom Detectors
- **TOML-based Plugin Configuration**: Create custom PII detectors without code
  - Load plugins from `.detector.toml` files
  - Regex pattern matching with confidence levels
  - Built-in validation: Luhn, mod11, IBAN checksums
  - Context keywords for confidence boosting
  - Configurable severity levels
  - Example plugins: employee IDs, patient IDs, custom formats
  - ~560 lines of code for plugin system

#### API Endpoint Scanning
- **Scan REST APIs for PII**: Test API responses for PII exposure
  - New `api` command for scanning HTTP endpoints
  - Support for GET, POST, PUT, PATCH, DELETE
  - Custom headers and request bodies
  - Configurable timeouts and redirect handling
  - Batch scanning of multiple endpoints
  - ~300 lines of code for API scanner

#### Enhanced API Key Detection
- **Entropy-based Secret Detection**: Advanced API key and secret scanning
  - AWS keys (AKIA...), GitHub tokens (ghp_, ghs_, gho_)
  - Stripe keys (sk_live_, pk_live_, rk_live_)
  - OpenAI keys (sk-...), Slack tokens (xox...)
  - Google API keys (AIza...), JWT tokens
  - Private keys (RSA/DSA/EC PEM format)
  - Generic high-entropy secrets (Base64/Hex patterns)
  - Shannon entropy calculation
  - Context-aware confidence scoring
  - ~380 lines of enhanced detection code

### Added

#### 5 New Countries
- **Poland (PESEL)**, **Denmark (CPR)**, **Sweden (Personnummer)**, **Norway (Fødselsnummer)**, **Finland (HETU)**
- Total: **12 countries supported** (BE, DE, DK, ES, FI, FR, GB, IT, NL, NO, PL, PT, SE)

#### Configuration File Support
- TOML-based configuration with environment variable expansion
- Load settings from `~/.pii-radar/config.toml` or custom path with `--config`
- Configuration precedence: CLI args > config file > defaults
- Environment variable substitution with `${VAR_NAME}` syntax
- Example config file in `examples/config.toml`
- 6 tests for configuration module

#### Performance Benchmarks
- Comprehensive Criterion.rs benchmark suite
- Plain text scanning benchmarks
- Individual detector performance tests
- PII density scenarios (0%, 1%, 5%, 10%)
- File size distribution tests (1KB to 1MB)
- Pattern complexity benchmarks
- Thread scaling tests (1 to 32 threads)

### Improved
- **Test Coverage**: 287 tests passing (from 199 in v0.3.0) - **+88 tests (+44%)**
- **Total Detectors**: 16+ detectors across 12 countries
- **Code Quality**: Zero warnings in release build
- **Modular Architecture**: Better separation of concerns
- **Error Handling**: Improved validation and error messages
- **Document Extraction**: XLSX extraction re-enabled with zip 4.2 compatibility

### Fixed
- **XLSX Extraction Re-enabled**: Resolved dependency conflict
  - Updated `zip` dependency from 0.6 to 4.2 (compatible with calamine 0.32)
  - Re-enabled `calamine = "0.32"` for Excel file support
  - Full support for .xlsx, .xlsm, .xlsb, .xls formats
  - Resolved `lzma-rust2`/`crc` conflict by using zip 4.2 instead of 7.2
  - All document extractors (PDF, DOCX, XLSX) now fully functional

### Technical Details
- **Tests**: 287 passing (95% test coverage)
- **Detectors**: 16+ across 12 countries
- **Lines Added**: ~3,500+ lines of production code
- **New Dependencies**: 
  - Database: `sqlx` (0.7), `mongodb` (2.8), `tokio` (1.35), `futures` (0.3)
  - Plugin: `toml` (0.8), `dirs` (5.0)
  - API: `reqwest` (0.12), `url` (2.5)
  - Benchmarks: `criterion` (0.8)
  - Documents: `calamine` (0.32), `zip` (4.2)
- **Feature Flags**: `database` feature for optional database support

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
