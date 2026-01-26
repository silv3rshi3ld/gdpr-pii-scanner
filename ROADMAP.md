# PII-Radar Development Roadmap

> **Current Version:** v0.2.0  
> **Target Version:** v0.3.0  
> **Last Updated:** 2026-01-26  
> **Status:** Phase 3A Complete, Phase 3B-3D In Progress

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Completed Phases](#completed-phases)
3. [Phase 3: v0.3.0 - Enterprise Ready](#phase-3-v030---enterprise-ready)
4. [Implementation Checklist](#implementation-checklist)
5. [Test Count Tracking](#test-count-tracking)
6. [Performance Targets](#performance-targets)
7. [Future Phases](#future-phases)

---

## Project Overview

**Mission:** Build a production-ready, enterprise-grade PII scanner with multi-country support, document extraction, and advanced reporting capabilities.

**Tech Stack:**
- Language: Rust 2021 Edition
- Parallel Processing: Rayon
- CLI Framework: Clap 4.5
- Pattern Matching: Regex + Fancy-regex
- Document Parsing: lopdf, zip, quick-xml, calamine
- Reporting: JSON, Terminal (colored), HTML (tera)

**Architecture:**
- Detector trait pattern for extensibility
- Registry-based detector management
- Parallel file scanning with Rayon
- Context-aware GDPR Article 9 detection
- Strict checksum validation (High confidence only)

---

## Completed Phases

### ✅ Phase 1: MVP (v0.1.0) - COMPLETE

**Goal:** Basic multi-country PII detection with context awareness

**Completed Features:**
- [x] Core detector trait architecture
- [x] Dutch BSN detector (11-proef validation)
- [x] IBAN detector (mod-97 validation, multi-country)
- [x] Credit card detector (Luhn validation: Visa, MC, Amex)
- [x] Email address detector (RFC 5322)
- [x] Context-aware GDPR Article 9 detection
- [x] Terminal reporter (colored output)
- [x] JSON reporter (compact + pretty)
- [x] CLI argument parsing
- [x] Parallel scanning with Rayon
- [x] File crawler with .piiignore support

**Metrics:**
- Detectors: 4
- Countries: 1 (NL)
- Tests: 77 passing
- Lines of Code: ~3,500

**Completed:** 2025-Q4

---

### ✅ Phase 2: Multi-Country (v0.2.0) - COMPLETE

**Goal:** Expand to 4 European countries with country filtering

**Completed Features:**
- [x] Belgium RRN detector (modulus 97)
- [x] Spain DNI detector (modulus 23)
- [x] Spain NIE detector (modulus 23)
- [x] UK NHS Number detector (modulus 11)
- [x] Country filtering (`--countries` flag)
- [x] Enhanced checksum utilities
- [x] Comprehensive test coverage

**Metrics:**
- Detectors: 8 total (4 new + 4 existing)
- Countries: 4 (BE, ES, GB, NL)
- Tests: 112 passing (+35)
- Lines of Code: ~5,800

**Completed:** 2026-01-26

---

## Phase 3: v0.3.0 - Enterprise Ready

**Goal:** Transform from multi-country scanner to production-ready enterprise tool

**Target Metrics:**
- Detectors: 11+ (3 new countries)
- Countries: 7 (BE, DE, ES, FR, GB, IT, NL)
- Tests: 220+ passing
- Lines of Code: ~12,000+
- Features: Document extraction, HTML reports, progress bars, plugins

**Estimated Effort:** 25-35 hours total
**Timeline:** 2-3 weeks

---

### Phase 3A: Quick Wins & Core Enhancements ✅ COMPLETE

**Status:** ✅ 100% Complete (5/5 tasks done)  
**Time Spent:** ~3 hours  
**Tests Added:** +20 (132 total)

#### Task 3A.1: Confidence Filtering ✅ COMPLETE
**Priority:** High | **Time:** 45 min | **Complexity:** Medium

**Completed:**
- [x] Added `filter_by_confidence()` method to `ScanResults`
- [x] Filters matches by minimum confidence level (Low/Medium/High)
- [x] Recalculates statistics after filtering
- [x] Added 6 comprehensive tests

**Files Modified:**
- `src/core/types.rs:274-340` - Added filtering method
- `src/main.rs:11-95` - Wired up CLI argument

**Tests Added:** 6 (118 total)  
**CLI Usage:** `pii-radar scan /path --min-confidence high`

**Completed:** 2026-01-26

---

#### Task 3A.2: Germany Tax ID Detector ✅ COMPLETE
**Priority:** High | **Time:** 2 hours | **Complexity:** High

**Completed:**
- [x] Implemented German Steuer-ID validation algorithm
- [x] Created SteuerIdDetector with 11-digit validation
- [x] Modified modulus 11 check (product/sum algorithm)
- [x] One digit must appear 2-3 times validation
- [x] Rejects all-same-digits and invalid patterns

**Files Created:**
- `src/detectors/de/mod.rs` - Module structure
- `src/detectors/de/steuer_id.rs` - Full detector (204 lines)

**Files Modified:**
- `src/utils/checksum.rs:365-430` - Added `validate_steuer_id()`
- `src/detectors/mod.rs:2` - Added `pub mod de;`
- `src/lib.rs:40` - Registered in default_registry()
- `src/lib.rs:86-90` - Added to registry_for_countries()

**Algorithm Details:**
```rust
// Modified modulus 11 check for Steuer-ID
let mut m = 10;
for digit in first_10_digits {
    let mut s = (digit + m) % 10;
    if s == 0 { s = 10; }
    m = (s * 2) % 11;
}
check_digit = (11 - m) % 10;
```

**Valid Test IDs:**
- `86095742719` ✓
- `47036892816` ✓
- `65929970489` ✓

**Tests Added:** 14 (7 validation + 7 detector = 132 total)  
**CLI Usage:** `pii-radar scan /path --countries de`

**Completed:** 2026-01-26

---

### Phase 3B: Document Extraction 📄

**Status:** ⏳ Not Started (0/6 tasks)  
**Estimated Time:** 8-12 hours  
**Priority:** High (Core Feature)

#### Task 3B.1: Create TextExtractor Trait and Error Types
**Priority:** High | **Estimate:** 45-60 min | **Complexity:** Medium

**Requirements:**
- [ ] Create `src/extractors/mod.rs` with `TextExtractor` trait
- [ ] Define `ExtractorError` enum (UnsupportedFormat, CorruptedFile, IoError)
- [ ] Create `ExtractorRegistry` for managing extractors
- [ ] Implement registry lookup by file extension
- [ ] Add default registry factory function

**Files to Create:**
- `src/extractors/mod.rs` (~100 lines)
- `src/extractors/registry.rs` (~150 lines)

**Tests to Add:** 5-7 tests  
**Expected Test Count:** 137-139 total

**Implementation Notes:**
```rust
pub trait TextExtractor: Send + Sync {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError>;
    fn supported_extensions(&self) -> Vec<&str>;
    fn name(&self) -> &str;
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractorError {
    #[error("Unsupported file format")]
    UnsupportedFormat,
    #[error("File is corrupted or invalid: {0}")]
    CorruptedFile(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
```

---

#### Task 3B.2: Implement PDF Extractor
**Priority:** High | **Estimate:** 1-2 hours | **Complexity:** Medium-High

**Requirements:**
- [ ] Create `src/extractors/pdf.rs` using `lopdf = "0.32"` (already in deps)
- [ ] Extract text from all pages using `Document::load()`
- [ ] Handle encrypted PDFs gracefully (return error)
- [ ] Handle image-only PDFs (return empty string)
- [ ] Preserve line breaks between pages
- [ ] Add error handling for corrupted PDFs

**Files to Create:**
- `src/extractors/pdf.rs` (~250-300 lines)

**Test Data Needed:**
- Create `tests/fixtures/sample.pdf` with PII test data
- Create `tests/fixtures/corrupted.pdf`
- Create `tests/fixtures/encrypted.pdf`
- Create `tests/fixtures/multi_page.pdf`

**Tests to Add:** 8-10 tests  
**Expected Test Count:** 147-149 total

**Implementation Notes:**
```rust
pub struct PdfExtractor;

impl TextExtractor for PdfExtractor {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
        let document = Document::load(path)
            .map_err(|e| ExtractorError::CorruptedFile(e.to_string()))?;
        
        let mut text = String::new();
        for page_num in 1..=document.get_pages().len() {
            let page_text = extract_page_text(&document, page_num)?;
            text.push_str(&page_text);
            text.push('\n');
        }
        Ok(text)
    }
}
```

---

#### Task 3B.3: Implement DOCX Extractor
**Priority:** High | **Estimate:** 1.5-2 hours | **Complexity:** Medium-High

**Requirements:**
- [ ] Create `src/extractors/docx.rs` using `zip` + `quick-xml` (in deps)
- [ ] Open DOCX as ZIP archive
- [ ] Extract and parse `word/document.xml`
- [ ] Extract text from `<w:t>` tags
- [ ] Handle headers/footers (`word/header*.xml`, `word/footer*.xml`)
- [ ] Handle tables and complex formatting
- [ ] Reject older .doc format (binary) with error

**Files to Create:**
- `src/extractors/docx.rs` (~300-350 lines)

**Test Data Needed:**
- Create `tests/fixtures/sample.docx` with PII
- Create `tests/fixtures/with_headers.docx`
- Create `tests/fixtures/with_tables.docx`
- Create `tests/fixtures/corrupted.docx`

**Tests to Add:** 8-10 tests  
**Expected Test Count:** 157-159 total

**Implementation Notes:**
```rust
pub struct DocxExtractor;

impl TextExtractor for DocxExtractor {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| ExtractorError::CorruptedFile(e.to_string()))?;
        
        let mut text = String::new();
        
        // Extract main document
        if let Ok(mut doc) = archive.by_name("word/document.xml") {
            text.push_str(&parse_word_xml(&mut doc)?);
        }
        
        // Extract headers/footers
        // ... (similar for header1.xml, footer1.xml, etc.)
        
        Ok(text)
    }
}
```

---

#### Task 3B.4: Implement XLSX Extractor
**Priority:** High | **Estimate:** 1-2 hours | **Complexity:** Medium

**Requirements:**
- [ ] Add dependency: `calamine = "0.24"` to `Cargo.toml`
- [ ] Create `src/extractors/xlsx.rs` using calamine
- [ ] Extract text from all sheets
- [ ] Handle formulas (extract computed values, not formula text)
- [ ] Format output: `Sheet1: A1=value, A2=value, ...`
- [ ] Handle password-protected files (return error)
- [ ] Handle corrupted files gracefully

**Files to Create:**
- `src/extractors/xlsx.rs` (~200-250 lines)

**Files to Modify:**
- `Cargo.toml` - Add calamine dependency

**Test Data Needed:**
- Create `tests/fixtures/sample.xlsx` with PII in cells
- Create `tests/fixtures/multi_sheet.xlsx`
- Create `tests/fixtures/with_formulas.xlsx`

**Tests to Add:** 6-8 tests  
**Expected Test Count:** 165-167 total

**Implementation Notes:**
```rust
use calamine::{open_workbook_auto, Reader, DataType};

pub struct XlsxExtractor;

impl TextExtractor for XlsxExtractor {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
        let mut workbook = open_workbook_auto(path)
            .map_err(|e| ExtractorError::CorruptedFile(e.to_string()))?;
        
        let mut text = String::new();
        
        for sheet_name in workbook.sheet_names() {
            if let Some(Ok(range)) = workbook.worksheet_range(&sheet_name) {
                text.push_str(&format!("Sheet: {}\n", sheet_name));
                for row in range.rows() {
                    for cell in row {
                        if let DataType::String(s) = cell {
                            text.push_str(s);
                            text.push(' ');
                        }
                    }
                    text.push('\n');
                }
            }
        }
        
        Ok(text)
    }
}
```

---

#### Task 3B.5: Integrate Extractors with ScanEngine
**Priority:** High | **Estimate:** 1-1.5 hours | **Complexity:** Medium

**Requirements:**
- [ ] Add `extractor_registry: Option<Arc<ExtractorRegistry>>` to `ScanEngine`
- [ ] Modify `scan_file()` to check file extension before reading
- [ ] If document format (PDF/DOCX/XLSX), try extraction
- [ ] If extraction succeeds, scan extracted text instead of raw file
- [ ] If extraction fails, log warning and skip file
- [ ] Add extraction statistics to `ScanResults`

**Files to Modify:**
- `src/scanner/engine.rs` - Add extractor integration (~50 lines)
- `src/core/types.rs` - Add extraction stats fields

**New Fields for ScanResults:**
```rust
pub struct ScanResults {
    // ... existing fields ...
    pub extracted_files: usize,
    pub extraction_failures: Vec<(PathBuf, String)>,
}
```

**Tests to Add:** 5-7 tests  
**Expected Test Count:** 172-174 total

**Implementation Notes:**
```rust
// In ScanEngine::scan_file()
pub fn scan_file(&self, path: &Path) -> FileResult {
    let content = if let Some(ref extractors) = self.extractor_registry {
        // Check file extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if let Some(extractor) = extractors.get_by_extension(ext) {
                match extractor.extract(path) {
                    Ok(text) => text,
                    Err(e) => {
                        // Log error and skip
                        return FileResult::with_error(path, format!("Extraction failed: {}", e));
                    }
                }
            } else {
                std::fs::read_to_string(path)?
            }
        } else {
            std::fs::read_to_string(path)?
        }
    } else {
        std::fs::read_to_string(path)?
    };
    
    // ... continue with detection ...
}
```

---

#### Task 3B.6: Add --extract-documents CLI Flag
**Priority:** High | **Estimate:** 30 min | **Complexity:** Low

**Requirements:**
- [ ] Add `--extract-documents` flag to `src/cli/args.rs`
- [ ] Modify `src/main.rs` to create `ExtractorRegistry` when flag enabled
- [ ] Pass extractor registry to `ScanEngine`
- [ ] Update terminal output to show extraction stats
- [ ] Add to help text and examples

**Files to Modify:**
- `src/cli/args.rs` - Add flag
- `src/main.rs` - Wire up extractors
- `src/reporter/terminal.rs` - Show extraction stats

**Tests to Add:** 2-3 tests  
**Expected Test Count:** 176-177 total

**CLI Usage:**
```bash
# Enable document extraction
pii-radar scan /path --extract-documents

# Combine with other flags
pii-radar scan /path --extract-documents --countries de,fr --min-confidence high
```

---

### Phase 3C: Advanced Features 🚀

**Status:** ⏳ Not Started (0/5 tasks)  
**Estimated Time:** 15-20 hours  
**Priority:** Medium (Nice to Have)

#### Task 3C.1: Add Progress Bar for Large Scans
**Priority:** Medium | **Estimate:** 30-45 min | **Complexity:** Low

**Requirements:**
- [ ] Add dependency: `indicatif = "0.17"` to `Cargo.toml`
- [ ] Wrap file iterator in `ProgressBar::new()` in `scan_directory()`
- [ ] Show: `[████████░░] 45/100 files (2.3 files/sec)`
- [ ] Only show for scans with >100 files
- [ ] Add `--no-progress` flag for CI/scripts
- [ ] Hide progress bar in JSON output mode

**Files to Modify:**
- `Cargo.toml` - Add indicatif
- `src/scanner/engine.rs:70-90` - Add progress bar
- `src/cli/args.rs` - Add `--no-progress` flag
- `src/main.rs` - Pass flag to scanner

**Tests to Add:** 2-3 tests  
**Expected Test Count:** 179-180 total

**Implementation Notes:**
```rust
use indicatif::{ProgressBar, ProgressStyle};

pub fn scan_directory(&self, path: &Path) -> ScanResults {
    let files = walker.collect::<Vec<_>>();
    
    let pb = if files.len() > 100 && !disable_progress {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{bar:40.cyan/blue}] {pos}/{len} files ({per_sec})")
            .progress_chars("█▓░"));
        Some(pb)
    } else {
        None
    };
    
    files.par_iter().map(|file| {
        let result = self.scan_file(file);
        if let Some(ref pb) = pb { pb.inc(1); }
        result
    }).collect()
}
```

---

#### Task 3C.2: HTML Report Generation
**Priority:** Medium | **Estimate:** 3-4 hours | **Complexity:** High

**Requirements:**
- [ ] Add dependencies: `tera = "1.19"`, `chrono = "0.4"` to `Cargo.toml`
- [ ] Create `src/reporter/html.rs` with `HtmlReporter` struct
- [ ] Create embedded HTML template (or `templates/report.html.tera`)
- [ ] Embed CSS (Bootstrap or custom styling)
- [ ] Embed JavaScript (table sorting, filtering, search)
- [ ] Add charts for statistics (Chart.js or similar)
- [ ] Color-coded severity levels
- [ ] Expandable file sections
- [ ] Dark mode toggle
- [ ] Filter by: country, severity, confidence, GDPR category
- [ ] Export to single self-contained HTML file

**Files to Create:**
- `src/reporter/html.rs` (~400-500 lines)
- `src/reporter/templates/report.html.tera` (or embed in code, ~300 lines)

**Files to Modify:**
- `Cargo.toml` - Add tera + chrono
- `src/reporter/mod.rs` - Export `HtmlReporter`
- `src/cli/args.rs` - Add `html` to format enum
- `src/main.rs` - Wire up HTML reporter

**Tests to Add:** 6-8 tests  
**Expected Test Count:** 186-188 total

**CLI Usage:**
```bash
# Generate HTML report
pii-radar scan /path --format html --output report.html

# Open in browser
pii-radar scan /path --format html --output report.html --open
```

**HTML Template Structure:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>PII-Radar Scan Report</title>
    <style>/* Embedded CSS */</style>
</head>
<body>
    <header>
        <h1>🔍 PII-Radar Scan Report</h1>
        <p>Generated: {{ timestamp }}</p>
    </header>
    
    <section id="summary">
        <h2>Summary</h2>
        <div class="stats-grid">
            <div class="stat">Files: {{ stats.total_files }}</div>
            <div class="stat">Matches: {{ stats.total_matches }}</div>
        </div>
    </section>
    
    <section id="filters">
        <input type="text" id="search" placeholder="Search...">
        <select id="country-filter">...</select>
        <select id="severity-filter">...</select>
    </section>
    
    <section id="findings">
        {% for file in files %}
        <div class="file-card">
            <h3>{{ file.path }}</h3>
            {% for match in file.matches %}
            <div class="match severity-{{ match.severity }}">
                {{ match.detector_name }}: {{ match.masked_value }}
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </section>
    
    <script>/* Embedded JavaScript */</script>
</body>
</html>
```

---

#### Task 3C.3: Custom Detector Plugin System
**Priority:** Low | **Estimate:** 4-5 hours | **Complexity:** High

**Requirements:**
- [ ] Add dependency: `toml = "0.8"` to `Cargo.toml`
- [ ] Create `src/detectors/plugin.rs` with `PluginDetector` struct
- [ ] Define TOML config schema for custom detectors
- [ ] Implement config loader and validator
- [ ] Support regex patterns + validation modes (luhn, mod11, mod23, mod97, none)
- [ ] Create `src/detectors/plugin_loader.rs` for loading plugins
- [ ] Search for `*.detector.toml` in config directories
- [ ] Add `--plugin-dir <path>` CLI flag
- [ ] Default plugin locations: `~/.pii-radar/plugins/` and `./plugins/`

**Files to Create:**
- `src/detectors/plugin.rs` (~400-500 lines)
- `src/detectors/plugin_loader.rs` (~200 lines)
- `examples/plugins/custom_id.detector.toml` (example)

**Files to Modify:**
- `Cargo.toml` - Add toml
- `src/detectors/mod.rs` - Export plugin module
- `src/lib.rs` - Add plugin loading to registry
- `src/cli/args.rs` - Add `--plugin-dir` flag

**Tests to Add:** 10-12 tests  
**Expected Test Count:** 198-200 total

**TOML Config Schema:**
```toml
[detector]
id = "custom_national_id"
name = "Custom National ID"
country = "XX"
severity = "critical"
description = "Custom national identification number"

[pattern]
regex = "^[A-Z]{2}\\d{8}[A-Z]$"
ignore_case = false

[validation]
type = "luhn"  # or "mod11", "mod23", "mod97", "custom", "none"

# Optional: Custom validation script (future enhancement)
# script = "path/to/validator.lua"

[masking]
strategy = "middle"  # "middle", "last4", "all"
visible_chars = 4
```

**Implementation Notes:**
```rust
#[derive(Debug, Deserialize)]
pub struct PluginConfig {
    detector: DetectorInfo,
    pattern: PatternInfo,
    validation: ValidationInfo,
    masking: MaskingInfo,
}

pub struct PluginDetector {
    config: PluginConfig,
    regex: Regex,
}

impl Detector for PluginDetector {
    fn id(&self) -> &str { &self.config.detector.id }
    fn country(&self) -> &str { &self.config.detector.country }
    fn detect(&self, text: &str, path: &Path) -> Vec<Match> {
        // ... implementation using config ...
    }
}
```

**Note:** This is a v0.4.0 candidate - consider deferring to focus on core features.

---

#### Task 3C.4: France NIR Detector
**Priority:** High | **Estimate:** 2-2.5 hours | **Complexity:** Medium-High

**Requirements:**
- [ ] Create `src/detectors/fr/mod.rs`
- [ ] Create `src/detectors/fr/nir.rs` for French social security numbers
- [ ] Implement NIR format validation (15 digits: S YY MM LL NNN NNN CC)
- [ ] Add `validate_france_nir()` to `src/utils/checksum.rs`
- [ ] Implement modulus 97 check for NIR
- [ ] Handle Corsica department codes (2A, 2B)
- [ ] Handle special month codes (20+ for unknown)
- [ ] Register detector in `src/lib.rs`

**NIR Format:**
- **S** = Sex (1=male, 2=female, 7/8=temporary)
- **YY** = Year of birth (00-99)
- **MM** = Month of birth (01-12, or 20+ for unknown)
- **LL** = Department code (01-95, 2A/2B for Corsica, 99 for abroad)
- **NNN NNN** = Registration number
- **CC** = Check digits (modulus 97)

**Validation Algorithm:**
```
check_digits = 97 - (first_13_digits % 97)
```

**Files to Create:**
- `src/detectors/fr/mod.rs` (~10 lines)
- `src/detectors/fr/nir.rs` (~250 lines)

**Files to Modify:**
- `src/detectors/mod.rs` - Add `pub mod fr;`
- `src/utils/checksum.rs` - Add `validate_france_nir()` (~80 lines)
- `src/lib.rs` - Register `NirDetector`

**Valid Test NIRs:**
- `1 89 05 75 123 456 08` (Male, May 1989, Paris)
- `2 92 12 2A 234 567 33` (Female, Dec 1992, Corse-du-Sud)

**Tests to Add:** 17 tests (10 detector + 7 validation)  
**Expected Test Count:** 217 total

---

#### Task 3C.5: Italy Codice Fiscale Detector
**Priority:** High | **Estimate:** 3-4 hours | **Complexity:** High

**Requirements:**
- [ ] Create `src/detectors/it/mod.rs`
- [ ] Create `src/detectors/it/codice_fiscale.rs` for Italian tax code
- [ ] Implement Codice Fiscale format validation (16 characters)
- [ ] Add `validate_italy_codice_fiscale()` to `src/utils/checksum.rs`
- [ ] Implement complex check character algorithm
- [ ] Create odd/even position encoding tables
- [ ] Handle male/female day encoding (day vs day+40)
- [ ] Validate municipality codes (first 4 chars of code)
- [ ] Register detector in `src/lib.rs`

**Codice Fiscale Format:** `RSSMRA85T10A562S`
- **RSS** = Surname consonants (3 letters)
- **MRA** = Name consonants (3 letters)
- **85** = Year of birth (2 digits)
- **T** = Month letter (A=Jan, B=Feb, ..., T=Dec)
- **10** = Day of birth (01-31 for males, 41-71 for females)
- **A562** = Municipality code (Cadastral code)
- **S** = Check character (complex algorithm)

**Check Character Algorithm:**
1. Odd position values: `A=1, B=0, C=5, D=7, ..., 0=1, 1=0, 2=5, ...`
2. Even position values: `A=0, B=1, C=2, ..., 0=0, 1=1, 2=2, ...`
3. Sum all encoded values
4. Check char = (sum % 26) → Letter

**Files to Create:**
- `src/detectors/it/mod.rs` (~10 lines)
- `src/detectors/it/codice_fiscale.rs` (~350 lines)

**Files to Modify:**
- `src/detectors/mod.rs` - Add `pub mod it;`
- `src/utils/checksum.rs` - Add validation (~120 lines with encoding tables)
- `src/lib.rs` - Register `CodiceFiscaleDetector`

**Valid Test Codes:**
- `RSSMRA85T10A562S` (Mario Rossi, male, Oct 10 1985)
- `VRDLSN90D45H501X` (Alessandra Verdi, female, Apr 5 1990)

**Tests to Add:** 20 tests (12 detector + 8 validation)  
**Expected Test Count:** 237 total

**Implementation Notes:**
```rust
// Odd position encoding table
const ODD_ENCODE: &[(char, u8)] = &[
    ('0', 1), ('1', 0), ('2', 5), ('3', 7), ('4', 9),
    ('5', 13), ('6', 15), ('7', 17), ('8', 19), ('9', 21),
    ('A', 1), ('B', 0), ('C', 5), ('D', 7), ('E', 9),
    // ... rest of alphabet ...
];

// Even position encoding table
const EVEN_ENCODE: &[(char, u8)] = &[
    ('0', 0), ('1', 1), ('2', 2), ('3', 3), ('4', 4),
    ('5', 5), ('6', 6), ('7', 7), ('8', 8), ('9', 9),
    ('A', 0), ('B', 1), ('C', 2), ('D', 3), ('E', 4),
    // ... rest of alphabet ...
];

pub fn validate_italy_codice_fiscale(code: &str) -> bool {
    if code.len() != 16 { return false; }
    
    let chars: Vec<char> = code.chars().collect();
    let mut sum = 0;
    
    // Sum first 15 characters
    for (i, &ch) in chars[..15].iter().enumerate() {
        let value = if i % 2 == 0 {
            encode_odd(ch)
        } else {
            encode_even(ch)
        };
        sum += value;
    }
    
    // Check character
    let expected = ((sum % 26) as u8 + b'A') as char;
    chars[15] == expected
}
```

---

### Phase 3D: Documentation & Polish 📚

**Status:** ⏳ Not Started (0/2 tasks)  
**Estimated Time:** 2-3 hours  
**Priority:** High (Required for Release)

#### Task 3D.1: Update README with Phase 3 Features
**Priority:** High | **Estimate:** 1-2 hours | **Complexity:** Low

**Requirements:**
- [ ] Update feature list with v0.3.0 additions
- [ ] Add Germany, France, Italy to supported countries
- [ ] Document `--min-confidence` flag with examples
- [ ] Document `--extract-documents` flag with examples
- [ ] Document `--format html` with examples
- [ ] Document progress bar and `--no-progress` flag
- [ ] Update detector count (11 total across 7 countries)
- [ ] Add document extraction section
- [ ] Add HTML report examples with screenshots
- [ ] Update performance benchmarks
- [ ] Add plugin system documentation (if implemented)
- [ ] Update installation instructions
- [ ] Add FAQ section

**Files to Modify:**
- `README.md` - Major update (add ~200-300 lines)
- Optionally: `CHANGELOG.md` - Create v0.3.0 entry

**Sections to Add:**
```markdown
## Document Extraction

PII-Radar can extract text from common document formats:
- PDF documents
- Microsoft Word (.docx)
- Microsoft Excel (.xlsx)

Enable with `--extract-documents` flag:
```bash
pii-radar scan /documents --extract-documents
```

## HTML Reports

Generate interactive HTML reports with charts and filtering:
```bash
pii-radar scan /path --format html --output report.html
```

## Confidence Filtering

Filter results by confidence level:
```bash
# Only show High confidence matches (validated checksums)
pii-radar scan /path --min-confidence high

# Show Medium and High confidence matches
pii-radar scan /path --min-confidence medium
```
```

---

#### Task 3D.2: Full Test Suite Verification
**Priority:** High | **Estimate:** 1 hour | **Complexity:** Low

**Requirements:**
- [ ] Run full test suite: `cargo test --lib`
- [ ] Verify ≥220 tests passing (target: 237)
- [ ] Fix any failing tests
- [ ] Run with `--nocapture` to verify output
- [ ] Run benchmarks: `cargo bench`
- [ ] Run clippy: `cargo clippy --all-targets`
- [ ] Fix all clippy warnings
- [ ] Run rustfmt: `cargo fmt --all`
- [ ] Verify build with all feature combinations
- [ ] Run end-to-end smoke tests with sample data
- [ ] Verify all CLI commands work
- [ ] Update `Cargo.toml` version to `0.3.0`

**Commands to Run:**
```bash
# Test suite
cargo test --lib
cargo test --all-targets

# Linting
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check

# Benchmarks
cargo bench

# Build verification
cargo build --release
cargo build --all-features

# Manual smoke tests
./target/release/pii-radar --version
./target/release/pii-radar detectors
./target/release/pii-radar scan tests/fixtures --extract-documents
./target/release/pii-radar scan tests/fixtures --format html --output report.html
./target/release/pii-radar scan tests/fixtures --min-confidence high --countries de,fr,it
```

**Success Criteria:**
- ✅ All tests pass (≥220)
- ✅ No clippy warnings
- ✅ Code formatted consistently
- ✅ All benchmarks run successfully
- ✅ All CLI examples in README work
- ✅ Binary size <15 MB
- ✅ Scan performance: >10,000 files/sec on SSD

---

## Implementation Checklist

### Phase 3A: Quick Wins ✅ COMPLETE
- [x] 3A.1 - Confidence filtering (ScanResults + CLI)
- [x] 3A.2 - Germany Tax ID detector (Steuer-ID)

### Phase 3B: Document Extraction
- [ ] 3B.1 - TextExtractor trait and error types
- [ ] 3B.2 - PDF extractor (lopdf)
- [ ] 3B.3 - DOCX extractor (zip + quick-xml)
- [ ] 3B.4 - XLSX extractor (calamine) + dependency
- [ ] 3B.5 - Integrate extractors with ScanEngine
- [ ] 3B.6 - Add --extract-documents CLI flag

### Phase 3C: Advanced Features
- [ ] 3C.1 - Progress bar (indicatif) + dependency
- [ ] 3C.2 - HTML reporter (tera + chrono) + dependencies
- [ ] 3C.3 - Custom plugin system (toml) + dependency [OPTIONAL - v0.4.0?]
- [ ] 3C.4 - France NIR detector
- [ ] 3C.5 - Italy Codice Fiscale detector

### Phase 3D: Documentation & Polish
- [ ] 3D.1 - Update README with all Phase 3 features
- [ ] 3D.2 - Full test suite verification (≥220 tests)

---

## Test Count Tracking

| Phase | Baseline | Added | Total | Status |
|-------|----------|-------|-------|--------|
| Phase 1 (MVP) | 0 | 77 | 77 | ✅ Complete |
| Phase 2 (Multi-Country) | 77 | 35 | 112 | ✅ Complete |
| **Phase 3A (Quick Wins)** | 112 | 20 | **132** | ✅ Complete |
| Phase 3B (Doc Extraction) | 132 | 45 | 177 | ⏳ Pending |
| Phase 3C (Advanced) | 177 | 60 | 237 | ⏳ Pending |
| **v0.3.0 Target** | - | - | **220+** | **Target: 237** |

### Detailed Test Breakdown (Target)

**Phase 3A (Current: 132):**
- Confidence filtering: 6 tests ✅
- Germany Steuer-ID validation: 7 tests ✅
- Germany Steuer-ID detector: 7 tests ✅

**Phase 3B (Expected: +45):**
- TextExtractor trait: 7 tests
- PDF extractor: 10 tests
- DOCX extractor: 10 tests
- XLSX extractor: 8 tests
- ScanEngine integration: 7 tests
- CLI flag: 3 tests

**Phase 3C (Expected: +60):**
- Progress bar: 3 tests
- HTML reporter: 8 tests
- Plugin system: 12 tests [OPTIONAL]
- France NIR: 17 tests (10 detector + 7 validation)
- Italy Codice Fiscale: 20 tests (12 detector + 8 validation)

**Total Target:** 237 tests (220+ requirement met)

---

## Performance Targets

### v0.3.0 Performance Goals

**Baseline (v0.2.0):**
- Scan speed: ~12,000 files/sec (text files on SSD)
- CPU usage: 800% on 8-core machine (95% parallel efficiency)
- Memory: ~50 MB for 10,000 files
- Binary size: ~8 MB (stripped)

**v0.3.0 Targets:**
- Scan speed: >10,000 files/sec (slight decrease due to extraction overhead)
- Document extraction: ~100 PDFs/sec, ~200 DOCX/sec, ~500 XLSX/sec
- CPU usage: 750-800% (maintain parallel efficiency)
- Memory: <100 MB for 10,000 files (including extraction buffers)
- Binary size: <15 MB (added dependencies for extraction)

**Benchmarks to Track:**
1. Plain text scanning (baseline)
2. PDF extraction + scanning
3. DOCX extraction + scanning
4. XLSX extraction + scanning
5. Mixed workload (50% text, 30% PDF, 15% DOCX, 5% XLSX)
6. Large directory (>100,000 files)
7. Network drive performance (degraded, but acceptable)

---

## Future Phases

### Phase 4: v0.4.0 - Intelligence & Automation (Future)

**Possible Features:**
- [ ] Machine learning for custom PII detection
- [ ] Automated remediation suggestions
- [ ] Integration with CI/CD pipelines (GitHub Actions, GitLab CI)
- [ ] REST API server mode
- [ ] Web UI for report viewing
- [ ] Database scanning (PostgreSQL, MySQL, MongoDB)
- [ ] Cloud storage support (S3, Azure Blob, GCS)
- [ ] Redaction/anonymization tools
- [ ] Compliance reporting (GDPR, CCPA, HIPAA)
- [ ] Multi-language support (currently English only)

### Phase 5: v0.5.0 - Enterprise Features (Future)

**Possible Features:**
- [ ] Distributed scanning across multiple nodes
- [ ] Central management dashboard
- [ ] Role-based access control (RBAC)
- [ ] Audit logging and compliance trails
- [ ] Integration with SIEM systems
- [ ] Scheduled scanning and monitoring
- [ ] Alerting and notifications (email, Slack, webhooks)
- [ ] Data classification policies
- [ ] Retention policy enforcement
- [ ] Enterprise SSO integration

---

## Project Structure

```
pii-radar/
├── Cargo.toml                 # Dependencies and project metadata
├── README.md                  # User documentation
├── ROADMAP.md                 # This file - development roadmap
├── CHANGELOG.md               # Version history (to be created)
├── LICENSE                    # MIT OR Apache-2.0
├── .piiignore                 # Default ignore patterns
│
├── src/
│   ├── main.rs                # CLI entry point
│   ├── lib.rs                 # Library exports and registry setup
│   │
│   ├── cli/                   # Command-line interface
│   │   ├── mod.rs
│   │   └── args.rs            # Clap argument definitions
│   │
│   ├── core/                  # Core types and traits
│   │   ├── mod.rs
│   │   ├── types.rs           # Match, ScanResults, FileResult
│   │   ├── detector.rs        # Detector trait
│   │   ├── registry.rs        # DetectorRegistry
│   │   └── context.rs         # ContextAnalyzer for GDPR Article 9
│   │
│   ├── crawler/               # File system traversal
│   │   ├── mod.rs
│   │   ├── walker.rs          # Directory walker
│   │   └── filter.rs          # File filtering (.piiignore)
│   │
│   ├── scanner/               # Scanning engine
│   │   ├── mod.rs
│   │   └── engine.rs          # Multi-threaded scan engine
│   │
│   ├── detectors/             # PII detectors by country/type
│   │   ├── mod.rs
│   │   ├── be/                # Belgium (RRN)
│   │   ├── de/                # Germany (Steuer-ID) ✅
│   │   ├── es/                # Spain (DNI, NIE)
│   │   ├── fr/                # France (NIR) ⏳
│   │   ├── gb/                # United Kingdom (NHS)
│   │   ├── it/                # Italy (Codice Fiscale) ⏳
│   │   ├── nl/                # Netherlands (BSN)
│   │   ├── eu/                # Pan-European (IBAN)
│   │   ├── financial/         # Credit cards
│   │   ├── personal/          # Email addresses
│   │   ├── security/          # API keys (future)
│   │   ├── plugin.rs          # Custom plugin system ⏳
│   │   └── plugin_loader.rs   # Plugin loader ⏳
│   │
│   ├── extractors/            # Document text extraction ⏳
│   │   ├── mod.rs             # TextExtractor trait ⏳
│   │   ├── registry.rs        # ExtractorRegistry ⏳
│   │   ├── pdf.rs             # PDF extractor ⏳
│   │   ├── docx.rs            # DOCX extractor ⏳
│   │   └── xlsx.rs            # XLSX extractor ⏳
│   │
│   ├── reporter/              # Output formatters
│   │   ├── mod.rs
│   │   ├── terminal.rs        # Colored terminal output
│   │   ├── json.rs            # JSON reporter
│   │   └── html.rs            # HTML reporter ⏳
│   │
│   └── utils/                 # Utility functions
│       ├── mod.rs
│       ├── checksum.rs        # Validation algorithms (mod11, Luhn, IBAN)
│       ├── entropy.rs         # Shannon entropy calculations
│       └── masking.rs         # Value masking functions
│
├── tests/
│   ├── integration_test.rs    # Integration tests
│   └── fixtures/              # Test data files
│       ├── sample.txt
│       ├── sample.pdf         # ⏳ To be created
│       ├── sample.docx        # ⏳ To be created
│       └── sample.xlsx        # ⏳ To be created
│
├── benches/
│   └── scan_benchmark.rs      # Performance benchmarks
│
└── examples/
    ├── basic_usage.rs
    └── plugins/               # ⏳ To be created
        └── example.detector.toml
```

**Legend:**
- ✅ = Complete
- ⏳ = In Progress / Planned
- (no marker) = Existing / Stable

---

## Dependencies Status

### Current Dependencies (v0.2.0)
```toml
clap = "4.5"           # CLI framework ✅
colored = "2.1"        # Terminal colors ✅
rayon = "1.10"         # Parallelism ✅
regex = "1.10"         # Pattern matching ✅
serde = "1.0"          # Serialization ✅
serde_json = "1.0"     # JSON output ✅
anyhow = "1.0"         # Error handling ✅
thiserror = "1.0"      # Error derive ✅
lopdf = "0.32"         # PDF extraction ✅ (unused in v0.2.0)
zip = "0.6"            # ZIP/DOCX support ✅ (unused in v0.2.0)
quick-xml = "0.31"     # XML parsing ✅ (unused in v0.2.0)
```

### Dependencies to Add (v0.3.0)
```toml
indicatif = "0.17"     # Progress bars (3C.1) ⏳
calamine = "0.24"      # XLSX extraction (3B.4) ⏳
tera = "1.19"          # HTML templates (3C.2) ⏳
chrono = "0.4"         # Date/time for reports (3C.2) ⏳
toml = "0.8"           # Plugin configs (3C.3) ⏳ [OPTIONAL]
```

**Total Dependencies:** 11 → 16 (or 15 without plugin system)

---

## Success Criteria for v0.3.0

### Functional Requirements
- [x] ✅ Confidence filtering working via CLI
- [x] ✅ Germany detector operational with validation
- [ ] ⏳ Document extraction (PDF, DOCX, XLSX)
- [ ] ⏳ HTML report generation
- [ ] ⏳ Progress bar for large scans
- [ ] ⏳ France NIR detector
- [ ] ⏳ Italy Codice Fiscale detector
- [ ] ⏳ All detectors pass validation tests

### Quality Requirements
- [ ] ⏳ ≥220 tests passing (target: 237)
- [ ] ⏳ Zero clippy warnings
- [ ] ⏳ Code coverage >85%
- [ ] ⏳ All public APIs documented
- [ ] ⏳ README fully updated

### Performance Requirements
- [ ] ⏳ Scan speed: >10,000 files/sec (text)
- [ ] ⏳ Document extraction: >100 PDFs/sec
- [ ] ⏳ Memory usage: <100 MB for 10K files
- [ ] ⏳ Binary size: <15 MB

### User Experience
- [ ] ⏳ Progress feedback for long scans
- [ ] ⏳ Clear error messages
- [ ] ⏳ Helpful CLI examples in --help
- [ ] ⏳ Interactive HTML reports
- [ ] ⏳ Documentation complete

---

## Notes

**Decision Log:**
- 2026-01-26: Completed Phase 3A (confidence + Germany) - 132 tests passing
- 2026-01-26: Created comprehensive ROADMAP.md to track all work
- TBD: Decide whether to defer plugin system (3C.3) to v0.4.0
- TBD: Decide priority order for Phase 3B vs 3C

**Blockers:**
- None currently

**Questions for Next Session:**
1. Should we implement document extraction (3B) or detectors (3C.4, 3C.5) first?
2. Defer plugin system (3C.3) to v0.4.0? (Saves 5 hours)
3. Is HTML reporter (3C.2) required for v0.3.0 or can it be v0.3.1?
4. Priority order suggestion: 3B → 3C.1 → 3C.4 → 3C.5 → 3C.2 → 3D → Release

**Next Steps:**
1. Review this roadmap and confirm priorities
2. Start Phase 3B (document extraction) or Phase 3C (detectors)
3. Work through tasks sequentially
4. Update ROADMAP.md as we progress
5. Create CHANGELOG.md when ready for release

---

*Last Updated: 2026-01-26*  
*Current Status: Phase 3A Complete (132/237 tests, 5.5% → 55% complete)*
