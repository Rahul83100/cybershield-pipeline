# 🎯 Sample Application — Deliberately Vulnerable Demo Target

This directory contains a **sample web application** used as the default scan target for CyberShield Pipeline demonstrations.

> ⚠️ **This application is intentionally insecure.** It exists solely to demonstrate the pipeline's vulnerability detection capabilities.

## Contents

| File | Purpose |
|------|---------|
| `app.js` | Express.js server with sample routes |
| `index.html` | Frontend HTML page |
| `main.tf` | Terraform configuration (for IaC scanning demo) |
| `package.json` | Node.js dependencies |
| `images/` | Static assets |

## Usage

This application is automatically scanned when you run the CyberShield Pipeline without specifying a custom `REPO_URL`. The pipeline will detect sample vulnerabilities across:

- **Secrets:** Potential credential patterns
- **SAST:** Code quality and security issues in `app.js`
- **SCA:** Known CVEs in dependencies
- **IaC:** Terraform misconfigurations in `main.tf`
- **Container:** Docker image vulnerabilities
- **DAST:** Runtime attack simulation (if a `TARGET_URL` is provided)

## ⚠️ Do Not Deploy

This application should **never** be deployed to a production environment. It serves purely as a testing and demonstration target.
