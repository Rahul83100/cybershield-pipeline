#!/usr/bin/env bash
# =============================================================
# ai_security_audit.sh – AI Cybersecurity Shield (Standalone)
# =============================================================
# Standalone version of the AI Cybersecurity Shield.
# Sends all tool scan results + source code to Gemini 2.5 Pro
# for deep semantic vulnerability analysis.
# Generates a premium HTML report. NEVER modifies code.
#
# Usage:
#   bash ai_security_audit.sh <API_KEY> <WORKSPACE> <REPORT_FILE>
#
# Expects these files in WORKSPACE (optional – skips if missing):
#   - trufflehog_report.json
#   - sonar_output.txt
#   - snyk_report.json / snyk_report.txt
#   - checkov_report.json / checkov_report.txt
#   - scan_errors.txt
# =============================================================

set -euo pipefail

API_KEY="${1:?'Missing GEMINI_API_KEY'}"
WORKSPACE="${2:?'Missing WORKSPACE path'}"
REPORT_FILE="${3:?'Missing REPORT_FILE path'}"

# Ensure report file has .html extension
if [[ "${REPORT_FILE}" != *.html ]]; then
    REPORT_FILE="${REPORT_FILE%.txt}.html"
fi

GEMINI_URL="https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent?key=${API_KEY}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helper ────────────────────────────────────────────────────────────────────
header() { echo ""; echo "══> $*"; }

read_report() {
    local file="$1" label="$2"
    echo "=== ${label} ==="
    if [ -f "${WORKSPACE}/${file}" ]; then
        head -c 8000 "${WORKSPACE}/${file}" 2>/dev/null
    else
        echo "No report generated (tool may not have run)."
    fi
    echo ""
}

# Detect stage status from reports
detect_stage_status() {
    local file="$1" tool="$2"
    if [ ! -f "${WORKSPACE}/${file}" ]; then
        echo "NOT_RUN"
    elif grep -qi "error\|fail\|vulnerab\|CRITICAL\|HIGH" "${WORKSPACE}/${file}" 2>/dev/null; then
        echo "FAILED"
    else
        echo "PASSED"
    fi
}

header "🛡️  AI Cybersecurity Shield starting..."

# ── 1. Detect stage status ────────────────────────────────────────────────────
header "Detecting stage status..."

STATUS_TRUFFLEHOG=$(detect_stage_status "trufflehog_report.json" "TruffleHog")
STATUS_SONARQUBE=$(detect_stage_status "sonar_output.txt" "SonarQube")
if [ -f "${WORKSPACE}/snyk_report.json" ]; then
    STATUS_SNYK=$(detect_stage_status "snyk_report.json" "Snyk")
elif [ -f "${WORKSPACE}/snyk_report.txt" ]; then
    STATUS_SNYK=$(detect_stage_status "snyk_report.txt" "Snyk")
else
    STATUS_SNYK="NOT_RUN"
fi
if [ -f "${WORKSPACE}/checkov_report.json" ]; then
    STATUS_CHECKOV=$(detect_stage_status "checkov_report.json" "Checkov")
elif [ -f "${WORKSPACE}/checkov_report.txt" ]; then
    STATUS_CHECKOV=$(detect_stage_status "checkov_report.txt" "Checkov")
else
    STATUS_CHECKOV="NOT_RUN"
fi

echo "  TruffleHog: ${STATUS_TRUFFLEHOG}"
echo "  SonarQube:  ${STATUS_SONARQUBE}"
echo "  Snyk:       ${STATUS_SNYK}"
echo "  Checkov:    ${STATUS_CHECKOV}"

# ── 2. Collect all tool reports ───────────────────────────────────────────────
header "Collecting tool scan reports..."

TOOL_REPORTS=""
TOOL_REPORTS+=$(read_report "trufflehog_report.json" "TRUFFLEHOG (Secrets Scanner) — Stage: ${STATUS_TRUFFLEHOG}")
TOOL_REPORTS+=$(read_report "sonar_output.txt" "SONARQUBE (SAST) — Stage: ${STATUS_SONARQUBE}")

# Snyk: prefer .json then .txt
if [ -f "${WORKSPACE}/snyk_report.json" ]; then
    TOOL_REPORTS+=$(read_report "snyk_report.json" "SNYK (SCA) — Stage: ${STATUS_SNYK}")
else
    TOOL_REPORTS+=$(read_report "snyk_report.txt" "SNYK (SCA) — Stage: ${STATUS_SNYK}")
fi

# Checkov: prefer .json then .txt
if [ -f "${WORKSPACE}/checkov_report.json" ]; then
    TOOL_REPORTS+=$(read_report "checkov_report.json" "CHECKOV (IaC) — Stage: ${STATUS_CHECKOV}")
else
    TOOL_REPORTS+=$(read_report "checkov_report.txt" "CHECKOV (IaC) — Stage: ${STATUS_CHECKOV}")
fi

# ── 3. Collect scan error log (FULL — no truncation) ─────────────────────────
SCAN_ERRORS=""
if [ -f "${WORKSPACE}/scan_errors.txt" ]; then
    SCAN_ERRORS=$(cat "${WORKSPACE}/scan_errors.txt" 2>/dev/null)
fi
if [ -z "${SCAN_ERRORS}" ]; then
    SCAN_ERRORS="No errors logged – all tool stages passed."
fi

# ── 4. Collect source code for semantic analysis ──────────────────────────────
header "Collecting source code for semantic analysis..."

SOURCE_CODE=""
while IFS= read -r FILE; do
    RELATIVE=$(echo "${FILE}" | sed "s|${WORKSPACE}/||")
    CONTENT=$(head -c 3000 "${FILE}" 2>/dev/null)
    SOURCE_CODE+="
--- FILE: ${RELATIVE} ---
${CONTENT}
--- END FILE ---
"
done < <(find "${WORKSPACE}" -type f \
    \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" \
       -o -name "*.tf" -o -name "*.yaml" -o -name "*.yml" \
       -o -name "*.html" -o -name "*.sh" -o -name "*.json" \
       -o -name "*.css" -o -name "*.jsx" -o -name "*.tsx" \
       -o -name "Dockerfile" -o -name "docker-compose*.yml" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/.scannerwork/*" \
    ! -path "*/vendor/*" ! -name "package-lock.json" \
    ! -name "*.min.js" ! -name "*.min.css" \
    2>/dev/null | head -25)

if [ -z "${SOURCE_CODE}" ]; then
    SOURCE_CODE="No source files found for analysis."
fi

# ── 5. Build the stage status text ────────────────────────────────────────────
STAGE_STATUS="
PIPELINE STAGE STATUS:
| Stage                        | Status     |
|------------------------------|------------|
| Secrets (TruffleHog)         | ${STATUS_TRUFFLEHOG} |
| SAST (SonarQube)             | ${STATUS_SONARQUBE} |
| SCA – Dependencies (Snyk)    | ${STATUS_SNYK} |
| IaC Scanning (Checkov)       | ${STATUS_CHECKOV} |

IMPORTANT: You MUST analyze and report on EVERY stage listed above, especially any with status FAILED.
"

# ── 6. Build the AI prompt ────────────────────────────────────────────────────
header "Building AI Cybersecurity Shield prompt..."

PROMPT_FILE="${WORKSPACE}/.gemini_prompt.txt"
cat > "${PROMPT_FILE}" << PROMPTEOF
You are an elite AI Cybersecurity Shield — the LAST LINE OF DEFENSE in a Jenkins DevSecOps pipeline for a project at Christ University.

🚫 STRICT RULE: You are an ADVISOR ONLY. You NEVER modify code directly. You provide detailed analysis, code snippet suggestions, and remediation guidance.

═══ YOUR MISSION ═══
You go BEYOND what automated tools can detect. You are the intelligence layer that finds what scanners miss.
Think like a penetration tester + security architect + threat modeler combined.

═══ ${STAGE_STATUS} ═══

═══ TOOL SCAN RESULTS (Raw Output) ═══
${TOOL_REPORTS}

═══ SCAN ERROR LOG ═══
${SCAN_ERRORS}

═══ SOURCE CODE FOR DEEP SEMANTIC ANALYSIS ═══
${SOURCE_CODE}

═══ ANALYSIS CATEGORIES (You MUST cover ALL of these) ═══

1. 🔍 PIPELINE STAGE ANALYSIS — For EVERY stage marked FAILED, explain exactly what failed and why. Do NOT skip any failed stage.
2. 🛠️ TOOL-DETECTED ISSUES SUMMARY — Summarize what each tool found
3. 🧠 AI-DETECTED HIDDEN VULNERABILITIES — Your deep analysis covering: OWASP Top 10, business logic flaws, frontend security (XSS/CSRF/CSP), hardcoded secrets, dependency chain CVEs, IaC misconfigurations, API security, data handling, configuration issues, container security
4. 🔎 TOOL GAP ANALYSIS — What tools missed and why
5. 🗺️ ATTACK FLOW — Mermaid flowchart for Critical/High findings
6. 📋 REMEDIATION ROADMAP — Prioritized table with fixes and effort estimates

═══ OUTPUT FORMAT (Markdown) ═══

# 🔍 Pipeline Stage Analysis
## Stage: [Name] — [✅ PASSED / ❌ FAILED]
**What happened:** ... **Root cause:** ... **Impact:** ...
(Repeat for EVERY stage)

---
# 🛠️ Tool-Detected Issues
## From [Tool Name]
- **[Severity]** [Issue]: [Description]

---
# 🧠 AI-Detected Hidden Vulnerabilities
## 🔴 Issue [N]: [Title]
- **Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
- **Category:** [Category]
- **Location:** file:line
- **Description:** [Details]
- **Why Tools Missed It:** [Explanation]
- **Suggested Fix:**
\`\`\`[language]
// Before (vulnerable)
[code]
// After (secure)
[code]
\`\`\`
- **Tool Upgrade:** [Recommendation or N/A]

---
# 🔎 Tool Gap Analysis
| Tool | What It Misses | Recommended Action |
---
# 🗺️ Attack Flow Visualization
\`\`\`mermaid
graph TD
    A[Entry Point] -->|How| B[Exploitation] --> C[Impact]
\`\`\`
---
# 📋 Remediation Roadmap
| Priority | Issue | Fix | Effort |
---
# 📊 Audit Summary
- Total issues, severity breakdown, security posture, top priorities

REMEMBER: Report ALL failed stages. Include code snippets. Include Mermaid diagrams. Find what tools missed.
PROMPTEOF

# ── 7. Call Gemini 2.5 Pro API ────────────────────────────────────────────────
header "Calling Gemini 2.5 Pro for deep security analysis..."

# Build request JSON safely
REQUEST=$(python3 -c "
import sys, json
prompt = open('${PROMPT_FILE}', 'r', encoding='utf-8', errors='replace').read()
req = {
    'contents': [{'parts': [{'text': prompt}]}],
    'generationConfig': {
        'temperature': 0.2,
        'maxOutputTokens': 65536
    }
}
print(json.dumps(req))
" 2>/dev/null)

if [ -z "${REQUEST}" ]; then
    echo "❌ Failed to build API request"
    exit 1
fi

# Retry loop with backoff
MAX_RETRIES=3
DELAYS=(30 60 120)
AI_TEXT=""

for ATTEMPT in $(seq 0 ${MAX_RETRIES}); do
    HTTP_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
        -X POST "${GEMINI_URL}" \
        -H "Content-Type: application/json" \
        -d "${REQUEST}")

    HTTP_BODY=$(echo "${HTTP_RESPONSE}" | sed -e 's/HTTP_STATUS:.*//')
    HTTP_STATUS=$(echo "${HTTP_RESPONSE}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

    header "Gemini API response status: ${HTTP_STATUS}"

    if [ "${HTTP_STATUS}" = "200" ]; then
        # Parse response, filter out thinking tokens
        AI_TEXT=$(echo "${HTTP_BODY}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    parts = d['candidates'][0]['content']['parts']
    text_parts = [p['text'] for p in parts if not p.get('thought', False)]
    print('\n'.join(text_parts))
except Exception as e:
    print(f'Failed to parse Gemini response: {e}')
" 2>/dev/null)
        break
    fi

    if [ "${HTTP_STATUS}" = "429" ] || [ "${HTTP_STATUS}" = "503" ]; then
        if [ "${ATTEMPT}" -lt "${MAX_RETRIES}" ]; then
            DELAY=${DELAYS[$ATTEMPT]}
            echo "⏳ Rate limited (${HTTP_STATUS}), waiting ${DELAY}s... (retry $((ATTEMPT+1))/${MAX_RETRIES})"
            sleep "${DELAY}"
        fi
    else
        echo "❌ Gemini API failed with status ${HTTP_STATUS}"
        AI_TEXT="⚠️ Gemini API call failed (HTTP ${HTTP_STATUS}). Manual security review recommended.

Raw API response:
${HTTP_BODY}"
        break
    fi
done

rm -f "${PROMPT_FILE}"

if [ -z "${AI_TEXT}" ]; then
    AI_TEXT="⚠️ Gemini API returned no content after ${MAX_RETRIES} retries. Check API key and quota at https://aistudio.google.com/app/apikey"
fi

# ── 8. Generate HTML report ──────────────────────────────────────────────────
header "Generating HTML report..."

CONTENT_FILE="${WORKSPACE}/.ai_report_content.md"
STAGE_FILE="${WORKSPACE}/.stage_status.json"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "${AI_TEXT}" > "${CONTENT_FILE}"

cat > "${STAGE_FILE}" << STAGEEOF
[
    {"name": "Secrets (TruffleHog)", "status": "${STATUS_TRUFFLEHOG}", "detail": ""},
    {"name": "SAST (SonarQube)", "status": "${STATUS_SONARQUBE}", "detail": ""},
    {"name": "SCA – Snyk", "status": "${STATUS_SNYK}", "detail": ""},
    {"name": "IaC (Checkov)", "status": "${STATUS_CHECKOV}", "detail": ""}
]
STAGEEOF

python3 "${SCRIPT_DIR}/generate_report.py" \
    "${CONTENT_FILE}" \
    "${STAGE_FILE}" \
    "${TIMESTAMP}" \
    "${REPORT_FILE}"

rm -f "${CONTENT_FILE}" "${STAGE_FILE}"

header "Report written to ${REPORT_FILE}"
echo "✅ AI Cybersecurity Shield audit complete."
echo "📥 Open the HTML report in a browser for the full interactive report."
