#!/usr/bin/env bash
# =============================================================
# ai_analyze.sh – Legacy wrapper → Routes to ai_security_audit.sh
# =============================================================
# This script is DEPRECATED. It now delegates to ai_security_audit.sh
# which implements the AI Security Auditor (advisory only, no auto-fix).
#
# Usage (backward-compatible):
#   bash ai_analyze.sh <API_KEY> <ERROR_FILE> <REPORT_FILE> <mode>
#
# New recommended usage:
#   bash ai_security_audit.sh <API_KEY> <WORKSPACE> <REPORT_FILE>
# =============================================================

set -euo pipefail

API_KEY="${1:?'Missing CLAUDE_API_KEY'}"
ERROR_FILE="${2:?'Missing ERROR_FILE path'}"
REPORT_FILE="${3:?'Missing REPORT_FILE path'}"
MODE="${4:-with_errors}"

echo "⚠️  ai_analyze.sh is DEPRECATED. Delegating to ai_security_audit.sh..."
echo "   AI role: Cybersecurity Shield (Claude Opus 4.8) – Advisor Only."
echo "   Output: HTML report with flowcharts and code snippets."
echo ""

# Derive workspace from error file directory
WORKSPACE=$(dirname "${ERROR_FILE}")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/ai_security_audit.sh" "${API_KEY}" "${WORKSPACE}" "${REPORT_FILE}"
