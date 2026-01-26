# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2024-01-27

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
