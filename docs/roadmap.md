# Roadmap

This roadmap communicates direction, not a release commitment. Scope and ordering can change after security and compatibility review.

## Current baseline: 0.6

- File-or-directory, HTTP response, PostgreSQL, and MongoDB scanning share completeness-aware results.
- JSON and CSV are pipeline-safe, and exit codes distinguish findings from incomplete scans.
- File, response, extraction, traversal, and finding budgets fail visibly instead of presenting partial work as clean.
- Core and full release artifacts separate database connector dependencies.
- Plugin schema version 1 is canonical, with a warning-emitting 0.5 bridge through the 0.6 line.

## Next

- Publish standalone machine-readable JSON and CSV schema definitions and compatibility fixtures.
- Extend byte-volume accounting to database cells and rows.
- Expand adversarial tests for extractors, regular expressions, redaction, CSV, and HTML output.
- Improve configuration diagnostics and secret-handling integrations.

## Later

- Evaluate additional input sources only when dependency maintenance and security requirements can be met.
- Add detector validation primitives based on documented identifier rules.
- Explore incremental scans and resumable manifests for large authorised data sets.
- Define a stable extension interface beyond TOML pattern plugins.

Feature proposals should include a threat model, expected data volume, compatibility impact, and a maintenance plan.
