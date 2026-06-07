# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | ✅ Active support  |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in CyberShield Pipeline, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. Email your findings to: **[security contact — see below]**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours of your report.
- **Assessment:** We will investigate and provide a severity rating within 7 days.
- **Resolution:** Critical vulnerabilities will be patched within 14 days.
- **Credit:** We will credit you in the release notes (unless you prefer anonymity).

### Scope

The following are in scope:
- The Jenkins pipeline (`Jenkinsfile`)
- The CLI scanner (`scripts/christ-scan`)
- Python scripts (`scripts/*.py`)
- Authentication and authorization mechanisms

The following are **out of scope**:
- The sample application in `sample-app/` (this is an intentionally vulnerable demo target)
- Third-party tools (TruffleHog, SonarQube, Snyk, etc.) — report vulnerabilities to their respective maintainers

## Security Architecture

CyberShield Pipeline implements multiple security layers:

- **Jenkins Authentication:** All remote scans require valid Jenkins credentials (username + API token)
- **CSRF Protection:** Jenkins crumb tokens prevent cross-site request forgery
- **Admin Approval Gate:** AI analysis requires explicit `submitter: 'admin'` authorization
- **Credential Isolation:** API keys stored in Jenkins Credential Store, never exposed in logs
- **Zero-Trust AI:** The LLM operates in read-only advisor mode — it never modifies code
