# Security Policy

## Supported Versions

`ciguard` is in early development (0.x). Only the latest minor release is supported with security fixes. Older versions are end-of-life on release of the next minor version.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you find a vulnerability in `ciguard`, please **do not open a public issue**. Use one of:

1. **GitHub private security advisory** (preferred): <https://github.com/Jo-Jo98/ciguard/security/advisories/new>
2. **Email**: open an issue asking for a contact channel and the maintainer will follow up privately.

Please include:

- The affected version (`ciguard --version` or PyPI / GHCR tag)
- A minimal reproduction (an input pipeline file, a CLI invocation, or a code path)
- The impact you observed and what you would expect to happen

You can expect:

- An acknowledgement within **5 working days**
- A coordinated disclosure window before any public fix lands; we aim to ship a patched release within **30 days** for High/Critical severity, longer for low-severity issues
- Credit in the changelog if you would like it

## Scope

`ciguard` is a static analyser. It parses YAML pipeline files and runs string / structural rules. The realistic threat surface is:

| Threat                                             | In scope         |
|----------------------------------------------------|------------------|
| Malicious YAML causing parser crash / hang         | Yes              |
| Path traversal / arbitrary file read via inputs    | Yes              |
| Code execution via deserialisation of input YAML   | Yes              |
| Vulnerable third-party dependency in shipped wheel | Yes              |
| Vulnerable OS package in published container image | Yes              |
| LLM enrichment leaking content to a third party    | Yes (config bug) |
| Bugs in user-supplied policy YAML                  | No (user input)  |
| False positives / false negatives in rules         | No (use Issues)  |

## What We Do

The `ciguard` repository runs:

- **Bandit** (Python SAST) on every push and PR — fails on Medium+ severity
- **`pip-audit`** on every push and PR — fails on any known CVE in runtime dependencies (test-only deps excluded)
- **Trivy** image scan on every release tag — fails the release on HIGH/CRITICAL OS-package or Python-library CVE that has an upstream fix
- **GitHub native secret scanning** + push protection
- **Dependabot** weekly version updates + automated security fixes for `github-actions`, `pip` (grouped runtime / dev), and the Docker base image
- **All GitHub Actions are SHA-pinned**; the PyPI publish step requires manual approval per release

If you spot something the above does not cover, that itself is reportable.
