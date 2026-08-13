---
name: Bug report
about: Report reproducible incorrect behaviour
title: "[bug] "
labels: bug
assignees: ""
---

## Before reporting

Do not report suspected vulnerabilities publicly; use the private process in `SECURITY.md`. Remove personal data, credentials, connection strings, private URLs, and sensitive paths from this issue. Reproduce with synthetic input.

## Description

<!-- What happened, and which result was incorrect? -->

## Reproduction

<!-- Provide the smallest synthetic fixture and exact command. -->

```console
pii-radar --no-config scan ./synthetic.txt
```

## Expected behaviour

<!-- Include the expected output and exit code. -->

## Actual behaviour

<!-- Include redacted output, standard error, and exit code. -->

## Environment

- PII Radar version:
- Artifact: core / full / source
- Operating system and architecture:
- Installation method:
- Rust version, for source builds:
- Configuration source: `--no-config` / explicit path / discovered path

## Scope

- Command: scan / api / scan-db / detectors / library
- Output format:
- Optional features:
- Does the problem reproduce with `--no-config`?

## Additional context

<!-- Link public specifications where useful. Do not attach production reports or configuration containing secrets. -->
