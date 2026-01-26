# Contributing to PII-Radar

Bedankt voor je interesse om bij te dragen aan PII-Radar! Deze tool is ontworpen om privacy en security te verbeteren door het detecteren van Personally Identifiable Information (PII) in lokale bestanden.

## 🚀 Quick Start

1. **Fork & Clone**
   ```bash
   git clone https://github.com/yourusername/pii-radar.git
   cd pii-radar
   ```

2. **Build & Test**
   ```bash
   cargo build
   cargo test
   cargo run -- scan ./tests/fixtures
   ```

3. **Create a branch**
   ```bash
   git checkout -b feature/nieuwe-detector
   ```

## 📋 Code of Conduct

- Wees respectvol en professioneel
- Focus op constructieve feedback
- Security vulnerabilities? Rapporteer via private disclosure

## 🐛 Bug Reports

Open een issue met:
- Beschrijving van het probleem
- Steps to reproduce
- Verwachte vs. actuele behavior
- OS en Rust versie (`rustc --version`)
- Relevante logs (met gevoelige data verwijderd!)

## 💡 Feature Requests

Voor nieuwe features:
1. Check of er al een issue bestaat
2. Beschrijf de use case en waarom het waardevol is
3. Indien mogelijk: voorstel voor implementatie

## 🔧 Development Guidelines

### Code Style
- Gebruik `rustfmt`: `cargo fmt`
- Gebruik `clippy`: `cargo clippy -- -D warnings`
- Volg Rust naming conventions

### Testing
- **Unit tests** voor alle validators en detectors
- **Integration tests** voor end-to-end flows
- Test coverage moet >80% zijn voor nieuwe code

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsn_valid() {
        assert!(validate_bsn_11_proef("123456782"));
    }

    #[test]
    fn test_bsn_invalid() {
        assert!(!validate_bsn_11_proef("123456789"));
    }
}
```

### Performance
- Nieuwe detectors moeten schalen tot 1000+ bestanden
- Gebruik `cargo bench` voor performance testing
- Geen blocking I/O in hot paths

### Security
- **Geen PII in test fixtures** zonder duidelijk fake data
- Alle regex patterns moeten ReDoS-safe zijn
- Validatie moet false positives minimaliseren

## 🎯 Adding a New Detector

1. **Maak detector module**
   ```bash
   touch src/detectors/financial/nieuwe_detector.rs
   ```

2. **Implementeer de trait**
   ```rust
   use crate::detectors::{Detector, Match, ConfidenceLevel};
   use regex::Regex;

   pub struct NieuweDetector {
       pattern: Regex,
   }

   impl Detector for NieuweDetector {
       fn detect(&self, text: &str) -> Vec<Match> {
           // Implementation
       }

       fn name(&self) -> &str {
           "nieuwe_detector"
       }
   }
   ```

3. **Voeg tests toe**
   ```rust
   #[cfg(test)]
   mod tests {
       #[test]
       fn test_valid_pattern() { }
       
       #[test]
       fn test_invalid_pattern() { }
       
       #[test]
       fn test_edge_cases() { }
   }
   ```

4. **Register in detector registry** (`src/detectors/mod.rs`)

5. **Update documentatie**

## 📝 Pull Request Process

1. **Zorg dat alle tests slagen**
   ```bash
   cargo test --all
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

2. **Update CHANGELOG.md** met je wijzigingen

3. **Beschrijf je PR**
   - Wat lost het op?
   - Breaking changes?
   - Screenshots/voorbeelden indien relevant

4. **Link naar gerelateerde issues**

5. **Wacht op review** - we proberen binnen 48 uur te reageren

## 🏗️ Project Structure

```
src/
├── detectors/        # Alle PII detectors
│   ├── nl_pii/      # Nederlandse PII (BSN, etc.)
│   ├── financial/   # IBAN, creditcards, etc.
│   └── security/    # API keys, tokens, etc.
├── crawler/         # File system traversal
├── scanner/         # Scan orchestration
├── reporter/        # Output formatters
├── extractors/      # PDF/DOCX text extraction
└── utils/           # Shared utilities
```

## 🔍 Review Criteria

PRs worden gereviewed op:
- **Correctheid**: Doet het wat het belooft?
- **Performance**: Geen regressies
- **Security**: Geen nieuwe vulnerabilities
- **Tests**: Adequate coverage
- **Documentation**: Code is begrijpelijk
- **Style**: Volgt Rust best practices

## 💬 Questions?

- Open een Discussion op GitHub
- Check bestaande issues en PRs
- Lees de [Architecture Decision Records](docs/adr/) (indien beschikbaar)

## 📜 License

Door bij te dragen ga je akkoord dat je bijdragen gelicenseerd worden onder dezelfde MIT OR Apache-2.0 license als het project.

---

**Dank je wel voor je bijdrage! 🎉**
