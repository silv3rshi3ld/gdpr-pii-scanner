# Contributing

Contributions to PII Radar are welcome. Keep changes focused, explain the behaviour they introduce, and avoid including real personal data, credentials, or production endpoints in code, tests, fixtures, logs, and screenshots.

## Before you start

- Use an issue for substantial behaviour changes so scope and compatibility can be discussed first.
- Report suspected vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not a public issue.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Install the Rust toolchain selected by `rust-toolchain.toml`, then build both supported feature sets:

```console
cargo build
cargo build --all-features
```

The default build corresponds to the core artifact. The `database` feature adds the PostgreSQL and MongoDB connectors included in the full artifact.

## Making a change

1. Create a topic branch from the current default branch.
2. Add or update tests for changed behaviour.
3. Use synthetic values such as `EMP-000001` in examples and fixtures.
4. Update the focused document in `docs/` when a command, configuration key, output field, detector, or compatibility promise changes.
5. Add a concise entry under `Unreleased` in `CHANGELOG.md` for user-visible changes.

Run the project checks before opening a pull request:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

For output changes, also confirm that JSON and CSV written to standard output contain no progress, status, or diagnostic text. Diagnostics belong on standard error.

## Detector changes

Detector pull requests should explain:

- the identifier format and intended jurisdiction or domain;
- why the regular expression is bounded safely;
- which checksum or structural validation is applied;
- synthetic positive, negative, and near-miss cases;
- expected false-positive and false-negative conditions.

TOML plugins use `schema_version = 1`; see [plugin documentation](docs/plugins.md). Do not use live identifiers as examples.

## Pull requests

Keep unrelated refactors separate. In the pull request description, state the problem, the chosen approach, user-visible changes, checks run, and any security or privacy implications. Maintainers may ask for smaller commits or compatibility notes when a change affects the CLI, library API, output schema, or plugin schema.

By contributing, you agree that your contribution may be licensed under the repository's MIT or Apache-2.0 terms.
