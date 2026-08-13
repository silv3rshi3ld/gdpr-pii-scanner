## Summary

<!-- Explain the problem, the chosen approach, and the user-visible result. -->

## Compatibility

<!-- Note changes to CLI arguments, exit codes, configuration, output schemas, plugin schemas, or Rust APIs. State "None" when applicable. -->

## Security and privacy

<!-- Describe changes to input trust, redaction, secret handling, network access, database permissions, or resource limits. Do not paste personal data or credentials. -->

## Validation

<!-- List the commands and focused manual checks run. Use synthetic fixtures only. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] Core and database-feature behaviour checked when relevant
- [ ] JSON and CSV standard output checked for payload-only output when relevant

## Documentation

- [ ] Tests cover changed behaviour
- [ ] Focused documentation and examples are updated
- [ ] `CHANGELOG.md` is updated under `Unreleased` for user-visible changes
- [ ] No real personal data, credentials, or production endpoints are included

## Related issues

<!-- For example: Closes #123 -->
