# Example Plugin README

This directory contains example plugin files demonstrating how to create custom PII detectors for pii-radar.

## What are Plugin Detectors?

Plugin detectors allow you to define custom PII patterns using TOML configuration files without modifying the source code. They're perfect for:

- Company-specific identifiers (employee IDs, customer numbers)
- Industry-specific data (patient records, policy numbers)
- Custom formats not covered by built-in detectors

## File Naming Convention

Plugin files must end with `.detector.toml`:
- ✅ `employee_id.detector.toml`
- ✅ `patient_mrn.detector.toml`
- ❌ `config.toml` (will be ignored)

## Plugin File Structure

```toml
# Required fields
id = "unique_identifier"              # Unique ID for this detector
name = "Human Readable Name"          # Display name
country = "universal"                 # Country code or "universal"
category = "custom"                   # Category (custom, financial, medical, etc.)
description = "What this detects"    # Brief description
severity = "medium"                   # low, medium, high, critical

# At least one pattern required
[[patterns]]
pattern = "YOUR-REGEX-HERE"
confidence = "high"                   # low, medium, high
description = "Optional description"

# Optional: validation rules
[validation]
min_length = 10
max_length = 20
checksum = "luhn"                     # Built-in: luhn, mod11, iban
required_prefix = "PREFIX"
required_suffix = "SUFFIX"

# Optional: example values
examples = ["EXAMPLE-123", "EXAMPLE-456"]

# Optional: context keywords (boost confidence when found nearby)
context_keywords = ["keyword1", "keyword2"]
```

## Available Checksum Validators

- `luhn` - Luhn algorithm (credit cards)
- `mod11` or `bsn` - Modulo-11 (Dutch BSN)
- `iban` - IBAN validation

## Usage

### Command Line

```bash
# Load plugins from a directory
pii-radar scan /path/to/scan --plugin-dir ./examples/plugins

# Plugins are loaded automatically and used alongside built-in detectors
pii-radar scan /data --plugin-dir ./my-plugins --format json -o results.json
```

### Example Output

When a plugin detector finds a match:

```
🟡 MEDIUM | Custom Detector: Employee ID
   File: employees.csv:42:15
   Value: EMP-******
   Country: universal
   Category: custom
```

## Tips

1. **Test Your Patterns**: Use regex testers like regex101.com to validate patterns
2. **Start Simple**: Begin with basic patterns, add validation later
3. **Use Context Keywords**: Improve accuracy by defining relevant keywords
4. **Set Appropriate Severity**: 
   - Low: Public/non-sensitive data
   - Medium: Personal data (emails, phone numbers)
   - High: Financial data (credit cards, IBANs)
   - Critical: Sensitive personal data (national IDs, medical records)

## Examples Included

1. **employee_id.detector.toml** - Company employee identifiers
2. **patient_id.detector.toml** - Medical patient IDs (GDPR critical)
3. **credit_card.detector.toml** - Credit cards with Luhn validation

## Creating Your Own

1. Copy an example file
2. Modify the `id`, `name`, and `description`
3. Update the regex `pattern` to match your data format
4. Add validation rules if needed
5. Test with sample data
6. Deploy to your plugin directory

## Need Help?

- Check the [main documentation](../../README.md)
- Review example files in this directory
- Test patterns at https://regex101.com/ (choose "ECMAScript" flavor)
