# Plugin examples

These files demonstrate detector plugin schema version 1 with synthetic values:

- `employee_id.detector.toml` uses a fixed prefix and length.
- `patient_id.detector.toml` shows a synthetic domain-specific reference.
- `credit_card.detector.toml` demonstrates Luhn validation with an unissued all-zero value.

Load the directory for a scan:

```console
pii-radar --no-config scan ./fixtures --plugins ./examples/plugins
```

The examples illustrate syntax, not production detector quality. Review pattern bounds, validation rules, false positives, and false negatives for your own format. Never replace the synthetic examples with live identifiers.

See [detector plugins](../../docs/plugins.md) for the schema and the 0.5 compatibility policy.
