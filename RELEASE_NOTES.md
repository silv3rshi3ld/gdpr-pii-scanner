# v0.5.0 - Security Hardening Release 🔒

**Release Date**: January 28, 2026  
**Type**: Major release with breaking changes

---

## ⚠️ Breaking Changes

### MySQL/MariaDB Support Removed

This release removes MySQL and MariaDB database scanning support to eliminate a critical security vulnerability in the dependency chain.

**Why was this necessary?**

- **Vulnerability**: RUSTSEC-2023-0071 (Marvin Attack on RSA decryption)
- **Affected**: `rsa 0.9.10` crate (transitive dependency via `sqlx-mysql`)
- **Status**: No fix available from upstream maintainers
- **Severity**: Critical timing attack allowing potential RSA decryption
- **Decision**: Zero-vulnerability policy requires complete removal

**What this means:**

- ❌ `--db-type mysql` flag no longer works
- ❌ `mysql://` connection strings are not supported
- ✅ PostgreSQL and MongoDB remain fully supported
- ✅ SQLite support added (implementation in progress)

**Migration Required:**

If you were using MySQL database scanning, please follow our comprehensive [MIGRATION_GUIDE.md](https://github.com/silv3rshi3ld/gdpr-pii-scanner/blob/main/MIGRATION_GUIDE.md) to transition to:

1. **PostgreSQL** (recommended for SQL compatibility)
2. **MongoDB** (NoSQL alternative)

---

## 🛡️ Security Fixes

This release eliminates **all known security vulnerabilities**:

✅ **RUSTSEC-2023-0071** - Fixed (MySQL removal)  
✅ **RUSTSEC-2024-0363** - Fixed (sqlx binary protocol vulnerability)  
✅ **RUSTSEC-2024-0421** - Fixed (idna Punycode labels vulnerability)

**Verification**: `cargo audit` returns zero vulnerabilities

---

## 🐛 Bug Fixes

### XLSX Extraction Re-enabled

- **Fixed**: XLSX file extraction was disabled due to dependency conflicts
- **Solution**: Updated `zip` crate from 0.6 → 4.2 (compatible with `calamine 0.32`)
- **Result**: All Excel formats working again (.xlsx, .xlsm, .xlsb, .xls)

### Code Quality Improvements

- Resolved all 11 clippy linter warnings across 8 files
- Refactored functions with too many parameters using structs:
  - `CliOverrides` for CLI argument passing
  - `DbScanParams` for database scanning parameters
- Replaced manual modulo checks with `.is_multiple_of()` method
- Fixed redundant closures and needless borrows
- Updated benchmark suite to use `std::hint::black_box`

### MongoDB Driver Update

- Updated to MongoDB 3.x fluent API
- Changed `list_collection_names(None)` → `list_collection_names()`
- Changed `find(None, options)` → `find(Document::new()).limit(n)`

---

## ⬆️ Dependency Updates

Major version updates for security and features:

| Crate | Old Version | New Version | Reason |
|-------|-------------|-------------|--------|
| **sqlx** | 0.7.4 | 0.8.6 | Security fixes + new features |
| **mongodb** | 2.8.2 | 3.5.0 | Security + API improvements |
| **reqwest** | 0.12.28 | 0.13.1 | Bug fixes + performance |
| **toml** | 0.8.23 | 0.9.11 | Improved parsing |
| **dirs** | 5.0.1 | 6.0.0 | API improvements |
| **zip** | 0.6 | 4.2 | XLSX compatibility |

**Total dependencies**: 500 → 487 packages (-13)

---

## ✨ New Features

### SQLite Support (Placeholder)

- Added `DatabaseType::SQLite` enum variant
- Full implementation planned for v0.5.1
- Enables lightweight, file-based database scanning

---

## 📦 Installation

### From Source

```bash
git clone https://github.com/silv3rshi3ld/gdpr-pii-scanner
cd gdpr-pii-scanner
git checkout v0.5.0

# Standard build (file scanning only)
cargo build --release

# With database support (PostgreSQL + MongoDB)
cargo build --release --features database

# Install globally
sudo cp target/release/pii-radar /usr/local/bin/
```

### Using Cargo (from Git)

```bash
# Install directly from this release
cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner --tag v0.5.0

# With database features
cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner --tag v0.5.0 --features database
```

### Using Cargo (from crates.io) - Coming Soon

```bash
cargo install pii-radar
```

---

## 🚀 Usage Examples

### File Scanning (Unchanged)

```bash
# Basic scan
pii-radar scan /path/to/directory

# Scan documents (PDF, DOCX, XLSX)
pii-radar scan /path --extract-documents

# Generate HTML report
pii-radar scan /path --format html --output report.html
```

### Database Scanning (Updated)

**PostgreSQL:**
```bash
pii-radar scan-db \
  --db-type postgres \
  --connection "postgresql://user:pass@localhost:5432/mydb" \
  --format json \
  --output db_results.json
```

**MongoDB:**
```bash
pii-radar scan-db \
  --db-type mongodb \
  --connection "mongodb://localhost:27017" \
  --database mydb \
  --tables "users,orders" \
  --format json \
  --output db_results.json
```

---

## 📊 Supported Features

✅ **12 European Countries**: BE, DE, DK, ES, FI, FR, GB, IT, NL, NO, PL, PT, SE  
✅ **Database Scanning**: PostgreSQL, MongoDB  
✅ **Document Extraction**: PDF, DOCX, XLSX  
✅ **API Endpoint Scanning**: REST API response scanning  
✅ **Plugin System**: TOML-based custom detectors  
✅ **Multiple Output Formats**: Terminal, JSON, CSV, HTML  
✅ **API Key Detection**: AWS, GitHub, Stripe, OpenAI, JWT, etc.  
✅ **Performance**: Parallel file scanning with rayon  
✅ **Zero Security Vulnerabilities**: `cargo audit` clean  

---

## 🧪 Testing

This release includes comprehensive test coverage:

- **Unit tests**: 289 passing (with database feature)
- **Integration tests**: 4 tests (require live databases)
- **Benchmarks**: Performance tracking with Criterion.rs
- **Code coverage**: ~95%

```bash
# Run tests
cargo test --lib

# Run with database feature
cargo test --lib --features database

# Run benchmarks
cargo bench
```

---

## 📝 Documentation Updates

- ✅ [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) - Comprehensive MySQL migration guide
- ✅ [CHANGELOG.md](CHANGELOG.md) - Full changelog with all changes
- ✅ [README.md](README.md) - Updated examples (MySQL removed)
- ✅ [API_SCANNING.md](docs/API_SCANNING.md) - API endpoint scanning guide

---

## 🔄 Upgrading from v0.4.0

### If You Were NOT Using MySQL:

Simply update to v0.5.0 - no changes needed:

```bash
cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner --tag v0.5.0 --features database
```

### If You Were Using MySQL:

1. **Immediate**: Use v0.4.0 (contains vulnerabilities)
   ```bash
   cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner --tag v0.4.0 --features database
   ```

2. **Recommended**: Migrate to PostgreSQL or MongoDB
   - Follow [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
   - Update to v0.5.0 after migration

---

## 🐛 Known Issues

None at this time. Report issues at: https://github.com/silv3rshi3ld/gdpr-pii-scanner/issues

---

## 🗓️ What's Next?

### v0.5.1 (Planned)

- SQLite database scanning implementation
- Performance optimizations for large files
- Additional CLI improvements

### v0.6.0 (Planned)

- Machine learning-based PII detection
- Cloud storage scanning (AWS S3, Azure Blob)
- Additional country detectors (Eastern Europe)
- Improved false positive reduction

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

---

## 🙏 Contributors

Thank you to all contributors who made this release possible!

Special thanks to the Rust security community for identifying and documenting vulnerabilities.

---

## 📜 Full Changelog

See [CHANGELOG.md](https://github.com/silv3rshi3ld/gdpr-pii-scanner/blob/main/CHANGELOG.md) for complete details.

---

## 🔗 Links

- **Repository**: https://github.com/silv3rshi3ld/gdpr-pii-scanner
- **Documentation**: https://github.com/silv3rshi3ld/gdpr-pii-scanner/tree/main/docs
- **Issues**: https://github.com/silv3rshi3ld/gdpr-pii-scanner/issues
- **Discussions**: https://github.com/silv3rshi3ld/gdpr-pii-scanner/discussions
- **Migration Guide**: https://github.com/silv3rshi3ld/gdpr-pii-scanner/blob/main/MIGRATION_GUIDE.md

---

**Questions?** Open an issue or start a discussion on GitHub!

**Found a security issue?** Please see [SECURITY.md](SECURITY.md) for responsible disclosure.
