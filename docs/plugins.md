# Detector plugins

Detector plugins add regular-expression-based candidate detection without recompiling PII Radar. Treat plugin files as code-like configuration: a weak expression can produce misleading results or consume excessive processing time.

## Load plugins

Plugin files use the `.detector.toml` suffix. Place them in a configured directory or select a directory for one command:

```console
pii-radar scan ./data --plugins ./examples/plugins
```

By default, PII Radar checks `pii-radar/plugins` below the platform configuration directory, then the legacy `~/.pii-radar/plugins` and `./plugins` directories. Setting `[plugins].directories` replaces that default list. Supplying `--plugins DIR` replaces every configured directory for that command.

Version 0.6 accepts ordinary `.toml` filenames in any selected plugin directory and emits a migration warning. New files should use `.detector.toml`; the legacy directories and filename compatibility are removed in 0.7.

Validate one file or every plugin in a directory without starting a scan:

```console
pii-radar plugins validate ./examples/plugins
```

## Schema version 1

Canonical plugins declare `schema_version = 1` at the top level. Version 0.6 accepts an omitted version as version 1 with a warning; version 0.7 will reject it.

```toml
schema_version = 1
id = "example_employee_id"
name = "Example employee identifier"
country = "universal"
category = "custom"
description = "Matches a synthetic employee identifier format."
severity = "medium"
examples = ["EMP-000001"]
context_keywords = ["employee", "staff"]
match_scope = "document"

[[patterns]]
pattern = "\\bEMP-\\d{6}\\b"
confidence = "high"
description = "EMP prefix followed by six digits."

[validation]
min_length = 10
max_length = 10
required_prefix = "EMP-"
```

Top-level fields:

| Field | Purpose |
| --- | --- |
| `schema_version` | Canonical schema integer; use `1`. Omission is deprecated compatibility behaviour. |
| `id` | Stable, unique machine identifier. |
| `name` | Human-readable detector name. |
| `country` | Lowercase country code or `universal`. |
| `category` | Descriptive data category. |
| `description` | Short scope statement. |
| `severity` | `low`, `medium`, `high`, or `critical`. |
| `examples` | Synthetic values for review and testing. |
| `context_keywords` | Informational keywords retained as plugin metadata. They do not alter findings in schema version 1. |
| `match_scope` | `document` (default) or `line`; controls whether anchors apply to the whole extracted source or each line. |

Each `[[patterns]]` table requires `pattern` and `confidence`; `description` is optional. Confidence is `low`, `medium`, or `high`.

One plugin file is limited to 1 MiB, 64 patterns, and 8,192 bytes per pattern. Each expression also has a 1 MiB compiled-size limit, a 1 MiB lazy-DFA cache limit, and a nesting limit. The loader rejects symlinked plugin files and malformed or duplicate detector IDs instead of partially loading a directory.

The optional `[validation]` table accepts `min_length`, `max_length`, `required_prefix`, `required_suffix`, `allowed_chars`, `length_unit`, and `checksum`. `allowed_chars` is a string containing every permitted character. Length validation applies to the complete matched text, including separators, and `length_unit` is `characters` (default) or `bytes`.

Checksum values are `luhn`, `mod11`, `mod97`, `bsn`, and `iban`. `mod11` is the generic repeating-weight algorithm used by the legacy schema; `bsn` selects the Dutch BSN 11-test. `mod97` validates a numeric value whose remainder is 1 and retains the legacy implementation's `u64` size limit; `iban` applies full IBAN validation. Prefer the format-specific option when one exists.

`category`, `context_keywords`, pattern descriptions, and examples are informational metadata in schema version 1. They do not change confidence, severity, or GDPR special-category classification.

## Design safely

- Bound repetitions and avoid nested ambiguous quantifiers.
- Use anchors or boundaries appropriate to the identifier.
- Add near-miss cases that must not match.
- Use structural or checksum validation when it is exact for the format.
- Do not describe an approximation as authoritative validation.
- Use reserved or deliberately invalid example values, never live identifiers.
- Start with a narrow scope and measure false positives on representative synthetic data.

Plugin metadata does not change the legal classification of matched content. Review results in their business context.

## Compatibility with 0.5

Version 0.6 includes a bridge for the 0.5 single-pattern form using `[detector]`. Loading one emits a migration warning. The bridge preserves line-scoped matching, UTF-8 byte-based lengths, `allowed_chars`, and the legacy `luhn`, `mod11`, and numeric `mod97` algorithms. The bridge is provided through the 0.6 release line; migrate before upgrading to 0.7.

Migration consists of moving detector metadata to the top level, adding `schema_version = 1`, and replacing `pattern` plus `confidence` with one `[[patterns]]` table. Add `match_scope = "line"` and `length_unit = "bytes"` if the converted plugin must retain those legacy behaviors. See the [0.5 to 0.6 migration guide](migration-guide.md) and the [plugin examples](../examples/plugins/README.md).

Version 0.5 also accepted an unversioned top-level multi-pattern form. Add `schema_version = 1` and validate it explicitly. Version 0.6 uses Rust's linear-time `regex` engine, which rejects look-around and backreferences previously accepted by `fancy-regex`. For this older top-level form, `checksum = "mod11"` previously selected the Dutch BSN test; use `checksum = "bsn"` to retain that behaviour. The v1 `mod11` name now selects the generic repeating-weight check. Re-test synthetic positive and negative fixtures after conversion.
