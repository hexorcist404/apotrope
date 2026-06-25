# Security Policy

## About This Project

Apotrope is a **read-only** security auditing tool. It does not modify system configurations, write to the registry, or change any settings on the machines it scans. All operations are observational only.

## Supported Versions

| Version  | Supported          |
| -------- | ------------------ |
| 0.1.9    | :white_check_mark: |
| < 0.1.9  | :x:                |

Only the latest release is actively supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in Apotrope, **please do not open a public GitHub issue.**

Instead, please report it using GitHub's private vulnerability reporting feature, OR via email at:

### <hexorcist404@pm.me>

Include the following in your report:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (optional but appreciated)

### What to Expect

- **Acknowledgment** within 72 hours of your report
- **Status update** within 7 days with an initial assessment
- **Resolution target** of 30 days for confirmed vulnerabilities, though critical issues will be prioritized for faster patching

If the vulnerability is accepted, you will be credited in the release notes (unless you prefer to remain anonymous).

If the vulnerability is declined, you will receive an explanation of why it does not qualify.

## Scope

The following are considered in scope:

- Vulnerabilities in Apotrope's code that could lead to unintended system modifications
- Dependency vulnerabilities that affect Apotrope's functionality or the systems it runs on
- Sensitive data exposure in generated reports (e.g., credentials, tokens, or secrets inadvertently captured)
- Code injection through crafted configuration files (`apotrope.toml`)

The following are **out of scope**:

- Security findings that Apotrope *reports* about a scanned system (these are features, not bugs)
- Issues that require physical access to a machine already running Apotrope
- Social engineering attacks against the maintainers

## Dependency Management

This project uses GitHub Dependabot to automatically monitor and propose updates to dependencies. Security patches to dependencies are prioritized for prompt merging.

## Responsible Use

Apotrope is intended for **authorized security auditing only**. Users are responsible for ensuring they have proper authorization before scanning any system. The maintainers assume no liability for unauthorized use of this tool.
