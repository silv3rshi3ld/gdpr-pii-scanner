# Security Policy

## Supported Versions

Only the latest minor release line of `pii-radar` receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | ✅        |
| < 0.5   | ❌        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately through one of the following channels:

1. **Preferred:** Use GitHub's [private vulnerability reporting](https://github.com/silv3rshi3ld/gdpr-pii-scanner/security/advisories/new) for this repository.
2. Alternatively, open a minimal placeholder issue asking maintainers to contact you privately, without disclosing details.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept if available)
- Affected version(s)
- Any suggested mitigation

## Response Expectations

- We aim to acknowledge reports within **5 business days**.
- We aim to provide a remediation plan or patch within **30 days** for high-severity issues.
- Credit will be given to reporters in release notes unless anonymity is requested.

## Scope

In scope:

- The `pii-radar` crate (binary and library)
- Built-in detectors, extractors, scanners, and reporters
- Default plugin loading behavior

Out of scope:

- Third-party plugins or downstream forks
- Issues that require an attacker to already have local code execution
