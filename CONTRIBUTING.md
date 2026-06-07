# Contributing to CyberShield Pipeline

Thank you for your interest in contributing! This document provides guidelines for contributing to CyberShield Pipeline.

## Getting Started

1. **Fork** this repository
2. **Clone** your fork locally
3. **Create a branch** for your feature or fix: `git checkout -b feature/your-feature-name`
4. **Make your changes** and test them thoroughly
5. **Commit** with clear, descriptive messages
6. **Push** to your fork and open a **Pull Request**

## Development Setup

See the [README](README.md) for detailed installation instructions. You'll need:
- Docker Desktop
- Python 3.9+
- Jenkins (local or remote)
- Git

## Code Guidelines

### Jenkinsfile
- Follow Groovy scripted pipeline best practices
- Add comments for complex logic
- Use environment variables for configuration — never hardcode secrets or IPs
- Test pipeline changes on a development Jenkins instance before submitting

### Python Scripts
- Follow PEP 8 style guidelines
- Add docstrings to functions
- Use `urllib` (standard library) — avoid external dependencies to keep the pipeline lightweight
- Handle errors gracefully with descriptive messages

### CLI Tool (`christ-scan`)
- Maintain backward compatibility with existing flags (`--local`, `--remote`)
- Test both local and remote scan modes
- Ensure color output degrades gracefully on non-ANSI terminals

## Commit Messages

Use clear, descriptive commit messages:
- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `refactor:` — Code restructuring without behavior change
- `sec:` — Security-related changes

**Example:** `feat: add OWASP ZAP DAST scanning stage`

## Reporting Issues

- Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) template for bugs
- Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) template for enhancements
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
