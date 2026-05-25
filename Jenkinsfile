// ============================================================
// AI-Enhanced DevSecOps Pipeline — AI Cybersecurity Shield
// ============================================================
// Claude Sonnet 4.6 performs DEEP vulnerability analysis beyond
// what tools detect. Generates a premium HTML audit report
// with flowcharts, code snippets, and remediation roadmap.
// AI is ADVISOR ONLY — never modifies code.
// ============================================================

pipeline {

    agent any

    parameters {
        string(name: 'REPO_URL', defaultValue: '', description: 'Repository URL to scan (e.g., https://gitlab.christuniversity.in/...)')
        string(name: 'BRANCH_NAME', defaultValue: 'main', description: 'Branch to scan (e.g., main, develop)')
        string(name: 'SCAN_PATH', defaultValue: '', description: 'Optional: specific file or folder path to scan (e.g., src/app.js or ZNF/). Leave empty to scan entire repo.')
        booleanParam(name: 'REQUEST_AI_LAYER', defaultValue: false, description: 'Check to request AI-powered deep analysis — admin must approve in Jenkins before it runs')
    }

    environment {
        GIT_BRANCH      = 'secure-test'
        ADMIN_EMAIL     = 'rahul636071@gmail.com'

        ERROR_FILE      = "${WORKSPACE}/scan_errors.txt"
        REPORT_FILE     = "${WORKSPACE}/ai_security_audit.html"
        
        // This securely loads the API key from Jenkins without showing developers
        ANTHROPIC_API_KEY = credentials('anthropic_api_key')
    }

    options {
        timestamps()
        ansiColor('xterm')
        timeout(time: 60, unit: 'MINUTES')
    }

    stages {

        // ── Init: clear workspace + initialize stage tracking ────────────
        stage('Init') {
            steps {
                script {
                    sh "rm -rf target_repo scan_errors.txt ai_security_audit.html trufflehog_report.json sonar_output.txt snyk_report.txt snyk_report.json checkov_report.json checkov_report.txt"
                    writeFile file: env.ERROR_FILE, text: ''
                    // Stage status tracking
                    env.STAGE_TRUFFLEHOG = 'NOT_RUN'
                    env.STAGE_SONARQUBE  = 'NOT_RUN'
                    env.STAGE_SNYK       = 'NOT_RUN'
                    env.STAGE_CHECKOV    = 'NOT_RUN'
                    env.AI_APPROVED      = 'false'
                    // Detail messages for each stage
                    env.DETAIL_TRUFFLEHOG = ''
                    env.DETAIL_SONARQUBE  = ''
                    env.DETAIL_SNYK       = ''
                    env.DETAIL_CHECKOV    = ''
                    // Derive dynamic SonarQube project key from repo URL
                    // e.g. https://github.com/user/repo.git → user_repo
                    if (params.REPO_URL) {
                        def raw = params.REPO_URL.replaceAll('\\.git$', '').replaceAll('^https?://', '').replaceAll('^git@', '').replaceAll(':', '/').replaceAll('/', '_').replaceAll('[^a-zA-Z0-9_.-]', '_')
                        env.SONAR_PROJECT_KEY = raw
                        env.SONAR_PROJECT_NAME = raw
                    } else {
                        env.SONAR_PROJECT_KEY = 'default_project'
                        env.SONAR_PROJECT_NAME = 'Default Project'
                    }
                    echo "✅ Workspace cleaned and pipeline initialised. SonarQube project: ${env.SONAR_PROJECT_KEY}"
                }
            }
        }

        // ── Checkout ──────────────────────────────────────────────────────
        stage('Checkout Source Code') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        if (!params.REPO_URL) {
                            error("REPO_URL parameter is required!")
                        }
                        echo "⬇️ Cloning ${params.REPO_URL} (Branch: ${params.BRANCH_NAME}) into target_repo..."
                        dir('target_repo') {
                        try {
                            // Uses GitLab credentials if defined
                            git branch: "${params.BRANCH_NAME}", url: "${params.REPO_URL}", credentialsId: 'gitlab-credentials'
                        } catch (err) {
                            // Fallback to public clone if credentials not setup
                            git branch: "${params.BRANCH_NAME}", url: "${params.REPO_URL}"
                        }
                        }
                        if (params.SCAN_PATH) {
                            def pathExists = sh(script: "test -e target_repo/'${params.SCAN_PATH}'", returnStatus: true) == 0
                            if (!pathExists) {
                                error("Specified SCAN_PATH 'target_repo/${params.SCAN_PATH}' does not exist!")
                            }
                            echo "✅ Validated SCAN_PATH: target_repo/${params.SCAN_PATH} exists."
                        }
                    }
                    echo "✅ Source code checked out."
                }
            }
            post {
                failure {
                    script { _logError('Checkout Source Code', 'SCM checkout failed.') }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════
        // Phase 2-3: All 4 tools run in PARALLEL (read-only on target_repo)
        // ══════════════════════════════════════════════════════════════════
        stage('Phase 2-3: Parallel Tools Scan') {
            parallel {
                // ── Secrets Scanning (Trufflehog) ─────────────────────────────────
                stage('Secrets (Trufflehog)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        def trufflehogPath = sh(script: 'which trufflehog || echo /usr/local/bin/trufflehog', returnStdout: true).trim()
                        def scanTarget = "${WORKSPACE}/target_repo"
                        if (params.SCAN_PATH) {
                            scanTarget = "${WORKSPACE}/target_repo/${params.SCAN_PATH}"
                        }
                        def result = sh(
                            script: """
                                set +e
                                echo "🔍 Running Trufflehog secrets scan on: ${scanTarget}"
                                ${truffhogPath} filesystem "${scanTarget}" --exclude-paths=.trufflehog-ignore --json --no-update > trufflehog_report.json 2>trufflehog_stderr.txt
                                if grep -q '"verified":true' trufflehog_report.json 2>/dev/null; then
                                    echo "[SECRETS_FOUND]"
                                    exit 1
                                fi
                                echo "✅ No secrets detected."
                            """,
                            returnStatus: true
                        )
                        if (result != 0) {
                            env.STAGE_TRUFFLEHOG = 'FAILED'
                            env.DETAIL_TRUFFLEHOG = 'Secrets or potential credentials detected in codebase'
                            def output = fileExists('trufflehog_report.json') ? readFile('trufflehog_report.json').take(5000) : 'Trufflehog failed to run.'
                            _logError('Secrets Scanning (Trufflehog)', output)
                            error("Trufflehog scan failed or found secrets")
                        } else {
                            env.STAGE_TRUFFLEHOG = 'PASSED'
                            env.DETAIL_TRUFFLEHOG = 'No verified secrets found'
                        }
                    }
                }
            }
        }

        // ── SAST (SonarQube Scanner — NO waitForQualityGate here) ──────────
        // waitForQualityGate runs AFTER the parallel block (see Phase 3 below)
        stage('SAST (SonarQube)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        def scannerHome = tool name: 'SonarScanner', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
                        def sonarInclusions = ""
                        if (params.SCAN_PATH) {
                            sonarInclusions = "-Dsonar.inclusions=${params.SCAN_PATH}"
                            echo "🎯 SonarQube target path: ${params.SCAN_PATH}"
                        }
                        withSonarQubeEnv('SonarQube') {
                            sh """
                                echo "🔍 Running SonarQube SAST scan..."
                                ${scannerHome}/bin/sonar-scanner \
                                    -Dsonar.projectKey=${env.SONAR_PROJECT_KEY} \
                                    -Dsonar.projectName="${env.SONAR_PROJECT_NAME}" \
                                    -Dsonar.sources=target_repo \
                                    -Dsonar.exclusions=node_modules/**,**/*.test.js,.git/**,*.json \
                                    ${sonarInclusions} \
                                    -Dsonar.host.url=http://localhost:9000 \
                                    2>&1 | tee sonar_output.txt
                            """
                        }
                        // Mark scanner as done — Quality Gate is checked in the
                        // sequential stage after all parallel tools finish.
                        env.SONAR_CE_TASK_ID = sh(script: "grep -oP 'id=\\K[A-Za-z0-9_]+' sonar_output.txt | tail -1", returnStdout: true).trim()
                        echo "📤 SonarQube report uploaded. CE task: ${env.SONAR_CE_TASK_ID}"
                        env.STAGE_SONARQUBE = 'PASSED'
                        env.DETAIL_SONARQUBE = 'Scanner uploaded successfully'
                    }
                }
            }
        }

        // ── SCA (Snyk) ────────────────────────────────────────────────────
        stage('SCA (Snyk)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        // Skip Snyk if the target repo has no package.json — Snyk needs
                        // node_modules to build a dependency tree, and without
                        // package.json there is nothing for it to scan.
                        if (!fileExists('target_repo/package.json') && !fileExists('target_repo/package-lock.json') && !fileExists('target_repo/yarn.lock')) {
                            env.STAGE_SNYK = 'SKIPPED'
                            env.DETAIL_SNYK = 'No package.json or lock file found — not a Node.js project'
                            echo "⏭️  Snyk skipped — no package.json, package-lock.json, or yarn.lock found in target repo."
                        } else {
                            withCredentials([string(credentialsId: 'snyk-auth-token', variable: 'SNYK_TOKEN')]) {
                                def result = sh(
                                    script: '''#!/bin/bash
                                    SNYK_PATH=$(which snyk || echo /usr/local/bin/snyk)
                                    if [ ! -f "$SNYK_PATH" ]; then
                                        echo "❌ snyk command not found at /usr/local/bin/snyk!"
                                        exit 1
                                    fi

                                    # Authenticate Snyk
                                    $SNYK_PATH auth $SNYK_TOKEN

                                    # Install dependencies so Snyk can analyse them
                                    if [ -f target_repo/package.json ]; then
                                        cd target_repo && npm install --quiet 2>/dev/null || true && cd ..
                                    fi

                                    $SNYK_PATH test target_repo --json 2>&1 | tee snyk_report.json
                                    SNYK_EXIT=${PIPESTATUS[0]}
                                    $SNYK_PATH test target_repo 2>&1 | tee snyk_report.txt
                                    exit $SNYK_EXIT
                                    ''',
                                    returnStatus: true
                                )
                                if (result != 0) {
                                    env.STAGE_SNYK = 'FAILED'
                                    env.DETAIL_SNYK = 'Dependency vulnerabilities detected by Snyk'
                                    def snykOut = ''
                                    if (fileExists('snyk_report.txt')) {
                                        snykOut = readFile('snyk_report.txt').take(8000)
                                    } else if (fileExists('snyk_report.json')) {
                                        snykOut = readFile('snyk_report.json').take(8000)
                                    } else {
                                        snykOut = 'Snyk scan failed - no report generated.'
                                    }
                                    _logError('SCA (Snyk)', snykOut)
                                    error("Snyk found vulnerabilities")
                                } else {
                                    env.STAGE_SNYK = 'PASSED'
                                    env.DETAIL_SNYK = 'No dependency vulnerabilities found'
                                }
                            }
                            echo "✅ No Snyk vulnerabilities found."
                        }
                    }
                }
            }
        }

        // ── IaC Scanning (Checkov) ────────────────────────────────────────
        stage('IaC (Checkov)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        def scanTarget = "target_repo"
                        def scanFlag = "-d"
                        if (params.SCAN_PATH) {
                            scanTarget = "target_repo/${params.SCAN_PATH}"
                            def isFile = sh(script: "test -f '${scanTarget}'", returnStatus: true) == 0
                            if (isFile) {
                                scanFlag = "-f"
                            }
                        }
                        def result = sh(
                            script: """#!/bin/bash
                            CHECKOV_PATH=\$(which checkov || echo /usr/local/bin/checkov)
                            if [ ! -f "\$CHECKOV_PATH" ]; then
                                echo "❌ checkov command not found at /usr/local/bin/checkov!"
                                exit 1
                            fi
                            \$CHECKOV_PATH ${scanFlag} "${scanTarget}" --quiet --skip-check CKV_AWS_144,CKV2_AWS_61,CKV2_AWS_62 -o json 2>&1 | tee checkov_report.json
                            CHECKOV_EXIT=\${PIPESTATUS[0]}
                            \$CHECKOV_PATH ${scanFlag} "${scanTarget}" --quiet --skip-check CKV_AWS_144,CKV2_AWS_61,CKV2_AWS_62 2>&1 | tee checkov_report.txt
                            exit \$CHECKOV_EXIT
                            """,
                            returnStatus: true
                        )
                        if (result != 0) {
                            env.STAGE_CHECKOV = 'FAILED'
                            env.DETAIL_CHECKOV = 'Infrastructure-as-Code misconfigurations found'
                            def checkovOut = ''
                            if (fileExists('checkov_report.txt')) {
                                checkovOut = readFile('checkov_report.txt').take(8000)
                            } else if (fileExists('checkov_report.json')) {
                                checkovOut = readFile('checkov_report.json').take(8000)
                            } else {
                                checkovOut = 'Checkov scan failed - no report generated.'
                            }
                            _logError('IaC Scanning (Checkov)', checkovOut)
                            error("Checkov found IaC issues")
                        } else {
                            env.STAGE_CHECKOV = 'PASSED'
                            env.DETAIL_CHECKOV = 'No IaC misconfigurations found'
                        }
                        echo "✅ No IaC issues found."
                    }
                }
            }
        }
            }  // end parallel
        }  // end Phase 2-3: Parallel Tools Scan

        // ── SonarQube Quality Gate (sequential — must NOT be in parallel) ──
        stage('SonarQube Quality Gate') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        if (env.SONAR_CE_TASK_ID) {
                            echo "⏳ Waiting for SonarQube CE task: ${env.SONAR_CE_TASK_ID}"
                            timeout(time: 20, unit: 'MINUTES') {
                                def qg = waitForQualityGate()
                                if (qg.status != 'OK') {
                                    env.STAGE_SONARQUBE = 'FAILED'
                                    env.DETAIL_SONARQUBE = "Quality Gate FAILED: ${qg.status}"
                                    _logError('SAST (SonarQube)', "SonarQube Quality Gate FAILED: ${qg.status}")
                                    error("SonarQube Quality Gate FAILED: ${qg.status}")
                                } else {
                                    env.STAGE_SONARQUBE = 'PASSED'
                                    env.DETAIL_SONARQUBE = 'Quality Gate passed'
                                }
                            }
                        } else {
                            echo "⏭️ SonarQube Quality Gate skipped — no CE task ID found."
                            env.STAGE_SONARQUBE = 'PASSED'
                            env.DETAIL_SONARQUBE = 'Quality Gate skipped (no scanner output)'
                        }
                    }
                }
            }
        }

        // ── AI Layer: Admin Approval Gate ────────────────────────────────
        stage('AI Layer: Request Admin Approval') {
            when {
                expression { params.REQUEST_AI_LAYER == true }
            }
            steps {
                script {
                    echo "🔐 AI Layer requested — sending approval request to admin..."

                    try {
                        mail(
                            to: env.ADMIN_EMAIL,
                            subject: "🔐 AI Scan Approval Request — ${params.REPO_URL}",
                            body: """\
A developer has requested the AI Cybersecurity Shield for:

  Repository : ${params.REPO_URL}
  Branch     : ${params.BRANCH_NAME}
  Build      : ${BUILD_URL}

To approve or deny, visit:
  ${BUILD_URL}input

This request will expire in 24 hours if not actioned.
"""
                        )
                        echo "📧 Approval request emailed to ${env.ADMIN_EMAIL}"
                    } catch (e) {
                        echo "⚠️ Email notification failed (check Jenkins SMTP config): ${e.message}"
                        echo "📋 Admin can still approve manually at: ${BUILD_URL}input"
                    }

                    try {
                        timeout(time: 24, unit: 'HOURS') {
                            input(
                                id: 'aiApproval',
                                message: "Approve AI Cybersecurity Shield scan?\n\nRepo: ${params.REPO_URL}\nBranch: ${params.BRANCH_NAME}",
                                submitter: 'admin',
                                ok: 'Approve AI Scan'
                            )
                        }
                        env.AI_APPROVED = 'true'
                        echo "✅ AI scan approved by admin."
                    } catch (err) {
                        env.AI_APPROVED = 'false'
                        echo "❌ AI scan request denied or timed out — skipping AI layer."
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════
        // Phase 4: AI CYBERSECURITY SHIELD (Claude Sonnet 4.6 — Deep Analysis)
        // ══════════════════════════════════════════════════════════════════
        stage('Phase 4: AI Cybersecurity Shield') {
            when {
                allOf {
                    expression { params.REQUEST_AI_LAYER == true }
                    expression { env.AI_APPROVED == 'true' }
                }
            }
            steps {
                script {

                    echo "============================================"
                    echo "  🛡️  PHASE 4: AI CYBERSECURITY SHIELD"
                    echo "  Engine: Claude Sonnet 4.6"
                    echo "  Role: Deep Analysis + Advisory Only"
                    echo "============================================"

                    // ── 1. Collect all tool reports ──────────────────
                    def toolReports = _collectToolReports()

                    // ── 2. Collect source code for semantic analysis ─
                    def sourceCode = _collectSourceCode()

                    // ── 3. Collect scan error log (NO TRUNCATION) ────
                    def scanErrors = fileExists(env.ERROR_FILE) ? readFile(env.ERROR_FILE).trim() : ''

                    // ── 4. Build stage status summary ────────────────
                    def stageSummary = _getStageStatusSummary()
                    def stageJson = _getStageStatusJson()

                    // ── 5. Run AI Cybersecurity Shield analysis ──────
                    _runSecurityAudit(toolReports, sourceCode, scanErrors, stageSummary, stageJson)

                    // ── 6. Display summary in console ────────────────
                    echo ""
                    echo "╔══════════════════════════════════════════════╗"
                    echo "║  🛡️  AI CYBERSECURITY SHIELD REPORT          ║"
                    echo "║  Format: HTML (open in browser)              ║"
                    echo "╚══════════════════════════════════════════════╝"
                    echo ""
                    echo "Stage Results:"
                    echo "  TruffleHog: ${env.STAGE_TRUFFLEHOG}"
                    echo "  SonarQube:  ${env.STAGE_SONARQUBE}"
                    echo "  Snyk (SCA): ${env.STAGE_SNYK}"
                    echo "  Checkov:    ${env.STAGE_CHECKOV}"
                    echo ""
                    echo "📥 Download the HTML report from Build Artifacts"
                    echo "============================================"

                    // ── 7. Archive the report ────────────────────────
                    archiveArtifacts artifacts: 'ai_security_audit.html', allowEmptyArchive: true
                }
            }
        }

    } // end stages

    post {
        always {
            script {
                echo "🧹 Cleaning up workspace..."
                // Archive all debug reports and the final AI report before cleanup
                try {
                    archiveArtifacts artifacts: 'scan_errors.txt,ai_security_audit.html,trufflehog_report.json,trufflehog_stderr.txt,snyk_report.json,snyk_report.txt,checkov_report.json,checkov_report.txt,sonar_output.txt', allowEmptyArchive: true
                } catch (e) {
                    echo "Artifact archiving skipped: ${e.message}"
                }
            }
        }
        success  { echo "🎉 Pipeline PASSED – All tools clean. AI audit report in artifacts." }
        unstable { echo "⚠️  Pipeline UNSTABLE – Some stages flagged issues. Check AI audit report in artifacts." }
        failure  { echo "❌ Pipeline FAILED – Check AI audit report in artifacts for full analysis." }
    }

} // end pipeline

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS — AI Cybersecurity Shield
// ═══════════════════════════════════════════════════════════════

/**
 * Logs errors from scan stages to the shared error file.
 */
def _logError(String stageName, String message) {
    def timestamp = new Date().format("yyyy-MM-dd HH:mm:ss")
    def entry = "\n====== ERROR IN: ${stageName} [${timestamp}] ======\n${message}\n=================================================\n"
    def existing = fileExists(env.ERROR_FILE) ? readFile(env.ERROR_FILE) : ''
    writeFile file: env.ERROR_FILE, text: existing + entry
    echo "⚠️  Error logged from stage: ${stageName}"
}

/**
 * Returns a formatted stage status summary for the AI prompt.
 */
def _getStageStatusSummary() {
    return """
PIPELINE STAGE STATUS (from Jenkins):
| Stage                        | Status     | Detail                                    |
|------------------------------|------------|-------------------------------------------|
| Secrets (TruffleHog)         | ${env.STAGE_TRUFFLEHOG.padRight(10)} | ${(env.DETAIL_TRUFFLEHOG ?: 'N/A').take(40).padRight(40)} |
| SAST (SonarQube)             | ${env.STAGE_SONARQUBE.padRight(10)} | ${(env.DETAIL_SONARQUBE ?: 'N/A').take(40).padRight(40)} |
| SCA – Dependencies (Snyk)    | ${env.STAGE_SNYK.padRight(10)} | ${(env.DETAIL_SNYK ?: 'N/A').take(40).padRight(40)} |
| IaC Scanning (Checkov)       | ${env.STAGE_CHECKOV.padRight(10)} | ${(env.DETAIL_CHECKOV ?: 'N/A').take(40).padRight(40)} |

IMPORTANT: You MUST analyze and report on EVERY stage listed above, especially any with status FAILED.
If a stage FAILED, you MUST include it in your report with a detailed explanation of what failed and why.
Do NOT skip or omit any failed stages.
""".stripIndent()
}

/**
 * Returns stage status as JSON for the HTML report generator.
 */
def _getStageStatusJson() {
    return """[
    {"name": "Secrets (TruffleHog)", "status": "${env.STAGE_TRUFFLEHOG}", "detail": "${(env.DETAIL_TRUFFLEHOG ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"},
    {"name": "SAST (SonarQube)", "status": "${env.STAGE_SONARQUBE}", "detail": "${(env.DETAIL_SONARQUBE ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"},
    {"name": "SCA – Snyk", "status": "${env.STAGE_SNYK}", "detail": "${(env.DETAIL_SNYK ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"},
    {"name": "IaC (Checkov)", "status": "${env.STAGE_CHECKOV}", "detail": "${(env.DETAIL_CHECKOV ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"}
]"""
}

/**
 * Collects all tool reports into a single context string.
 * Increased limits: 8000 chars per report for thorough analysis.
 */
def _collectToolReports() {
    def reports = new StringBuilder()

    // TruffleHog
    reports.append("\n=== TRUFFLEHOG (Secrets Scanner) — Stage: ${env.STAGE_TRUFFLEHOG} ===\n")
    if (fileExists('trufflehog_report.json')) {
        reports.append(readFile('trufflehog_report.json').take(8000))
    } else {
        reports.append("No report generated (tool may not have run).")
    }

    // SonarQube
    reports.append("\n\n=== SONARQUBE (SAST) — Stage: ${env.STAGE_SONARQUBE} ===\n")
    if (fileExists('sonar_output.txt')) {
        reports.append(readFile('sonar_output.txt').take(8000))
    } else {
        reports.append("No report generated (tool may not have run).")
    }

    // Snyk (check both .json and .txt)
    reports.append("\n\n=== SNYK (SCA – Dependency Scanning) — Stage: ${env.STAGE_SNYK} ===\n")
    if (fileExists('snyk_report.json')) {
        reports.append(readFile('snyk_report.json').take(8000))
    } else if (fileExists('snyk_report.txt')) {
        reports.append(readFile('snyk_report.txt').take(8000))
    } else {
        reports.append("No report generated (tool may not have run).")
    }

    // Checkov (check both .json and .txt)
    reports.append("\n\n=== CHECKOV (IaC Scanning) — Stage: ${env.STAGE_CHECKOV} ===\n")
    if (fileExists('checkov_report.json')) {
        reports.append(readFile('checkov_report.json').take(8000))
    } else if (fileExists('checkov_report.txt')) {
        reports.append(readFile('checkov_report.txt').take(8000))
    } else {
        reports.append("No report generated (tool may not have run).")
    }

    return reports.toString()
}

/**
 * Collects relevant source code files for semantic analysis.
 * Gathers up to 25 code files, capped at 3000 chars each.
 */
def _collectSourceCode() {
    def findTarget = "${WORKSPACE}/target_repo"
    if (params.SCAN_PATH) {
        findTarget = "${WORKSPACE}/target_repo/${params.SCAN_PATH}"
    }
    def result = sh(
        script: """#!/bin/bash
        if [ -f "${findTarget}" ]; then
            RELATIVE=\$(echo "${findTarget}" | sed "s|${WORKSPACE}/||")
            echo "--- FILE: \${RELATIVE} ---"
            head -c 3000 "${findTarget}" 2>/dev/null
            echo ""
            echo "--- END FILE ---"
            echo ""
        else
            find "${findTarget}" -type f \\
                \\( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" \\
                   -o -name "*.tf" -o -name "*.yaml" -o -name "*.yml" \\
                   -o -name "*.html" -o -name "*.json" -o -name "*.sh" \\
                   -o -name "*.css" -o -name "*.jsx" -o -name "*.tsx" \\
                   -o -name "Dockerfile" -o -name "docker-compose*.yml" \\) \\
                ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/.scannerwork/*" \\
                ! -path "*/vendor/*" ! -name "package-lock.json" \\
                ! -name "*.min.js" ! -name "*.min.css" \\
                2>/dev/null | head -25 | while IFS= read -r FILE; do
                    RELATIVE=\$(echo "\${FILE}" | sed "s|${WORKSPACE}/||")
                    echo "--- FILE: \${RELATIVE} ---"
                    head -c 3000 "\${FILE}" 2>/dev/null
                    echo ""
                    echo "--- END FILE ---"
                    echo ""
                done
        fi
        """,
        returnStdout: true
    ).trim()

    return result ?: "No source files found for analysis."
}

/**
 * Runs the AI Cybersecurity Shield analysis using Gemini 2.5 Flash.
 * Generates a comprehensive vulnerability report in HTML format.
 */
def _runSecurityAudit(String toolReports, String sourceCode, String scanErrors, String stageSummary, String stageJson) {

    def prompt = """You are an elite AI Cybersecurity Shield — the LAST LINE OF DEFENSE in a Jenkins DevSecOps pipeline for a project at Christ University.

🚫 STRICT RULE: You are an ADVISOR ONLY. You NEVER modify code directly. You provide detailed analysis, code snippet suggestions, and remediation guidance.

═══ YOUR MISSION ═══
You go BEYOND what automated tools can detect. You are the intelligence layer that finds what scanners miss.
Think like a penetration tester + security architect + threat modeler combined.

═══ ${stageSummary} ═══

═══ TOOL SCAN RESULTS (Raw Output) ═══
${toolReports.take(30000)}

═══ SCAN ERROR LOG ═══
${scanErrors ?: 'No errors logged – all tool stages passed.'}

═══ SOURCE CODE FOR DEEP SEMANTIC ANALYSIS ═══
${sourceCode.take(30000)}

═══ ANALYSIS CATEGORIES (You MUST cover ALL of these) ═══

1. 🔍 PIPELINE STAGE ANALYSIS
   - For EVERY stage marked FAILED above, explain exactly what failed and why
   - Analyze tool report content to provide specifics about each failure
   - Do NOT skip any failed stage — this is CRITICAL

2. 🛠️ TOOL-DETECTED ISSUES SUMMARY
   - Summarize what each tool found (from the raw reports above)
   - Categorize findings by severity

3. 🧠 AI-DETECTED HIDDEN VULNERABILITIES (YOUR DEEP ANALYSIS)
   Go beyond tools and analyze the source code for:
   a) OWASP Top 10: XSS, injection, CSRF, SSRF, broken auth, security misconfiguration, cryptographic failures
   b) Business Logic Flaws: race conditions, privilege escalation, improper validation, data leakage
   c) Frontend Security: DOM-based XSS, open redirects, clickjacking, missing CSP headers, unsafe inline scripts, mixed content
   d) Hardcoded Secrets: API keys, tokens, private keys, passwords in source code (even obfuscated/fake ones)
   e) Dependency Chain: known CVEs in transitive deps, outdated packages, supply chain risks
   f) Infrastructure (IaC): missing encryption, overly permissive IAM, public exposure, logging gaps, missing MFA
   g) API Security: missing rate limiting, improper input validation, verbose error messages, missing authentication
   h) Data Handling: PII exposure, missing sanitization, insecure storage, GDPR/compliance concerns
   i) Configuration: insecure defaults, debug mode in production, missing security headers, weak TLS
   j) Container/Deployment: Dockerfile security, secrets in images, running as root, missing health checks

4. 🔎 TOOL GAP ANALYSIS
   - What vulnerabilities exist that TruffleHog/SonarQube/Snyk/Checkov CANNOT detect?
   - What tool upgrades or config changes would improve coverage?

5. 🗺️ ATTACK FLOW VISUALIZATION
   For any Critical or High severity findings, create a Mermaid flowchart showing the attack path:
   ```mermaid
   graph TD
       A[Entry Point] -->|How| B[Exploitation]
       B --> C[Impact]
6. 📋 PRIORITIZED REMEDIATION ROADMAP
   Keep explanations extremely brief. Focus ONLY on actionable fixes. Avoid conversational filler.

═══ OUTPUT FORMAT (Markdown) ═══
CRITICAL INSTRUCTION TO SAVE TOKENS: BE EXTREMELY CONCISE. 
Do not write long paragraphs or greetings. Use bullet points and minimal descriptions.

🎯 ZERO-HALLUCINATION RULE:
If ALL pipeline stages PASSED, AND you do not find any legitimate Critical, High, or Medium severity hidden vulnerabilities in the source code, DO NOT force yourself to invent or report theoretical low-severity issues.
Instead, you MUST output ONLY this exact string and literally nothing else:
[NO_ERRORS_DETECTED]

If (and only if) there are tool failures OR you found legitimate hidden vulnerabilities, you MUST follow the exact template below and do not deviate:

# 🔍 Pipeline Stage Analysis

## Stage: [Name] — [✅ PASSED / ❌ FAILED]
**Status:** ...
**What happened:** ...
**Root cause:** ...
**Impact:** ...

(Repeat for EVERY stage, especially all FAILED stages)

---

# 🛠️ Tool-Detected Issues

## From [Tool Name]
- **[Severity]** [Issue]: [Description]

---

# 🧠 AI-Detected Hidden Vulnerabilities

## 🔴 Issue [N]: [Title]
- **Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
- **Category:** [OWASP/Business Logic/Frontend/etc.]
- **Location:** `file:line`
- **Description:** [Detailed explanation]
- **Why Tools Missed It:** [Explanation of tool limitations]
- **Suggested Fix:**
```[language]
// Before (vulnerable)
[vulnerable code]

// After (secure)
[fixed code]
```
- **Tool Upgrade:** [Recommendation or "N/A"]

(Repeat for ALL hidden vulnerabilities found)

---

# 🔎 Tool Gap Analysis

| Tool | What It Misses | Recommended Action |
|------|---------------|-------------------|
| ... | ... | ... |

---

# 🗺️ Attack Flow Visualization

```mermaid
graph TD
    ...
```

---

# 📋 Remediation Roadmap

| Priority | Issue | Fix | Effort |
|----------|-------|-----|--------|
| 🔴 P0 | ... | ... | ... |
| 🟠 P1 | ... | ... | ... |
| 🟡 P2 | ... | ... | ... |

---

# 📊 Audit Summary
- **Total issues found:** [N] (Tool-detected: [X] | AI-detected: [Y])
- **Severity breakdown:** 🔴 Critical: [N] | 🟠 High: [N] | 🟡 Medium: [N] | 🔵 Low: [N]
- **Pipeline stages:** ✅ Passed: [N] | ❌ Failed: [N] | ⏸️ Skipped: [N]
- **Security posture:** [Assessment with emoji rating]
- **Tool upgrade recommendations:** [List]
- **Top 3 priorities:** [Actionable summary]

REMEMBER:
- You MUST report on ALL failed stages
- You MUST provide code snippets for fixes
- You MUST include Mermaid attack flow diagrams
- You MUST find vulnerabilities that tools missed
- Be thorough, specific, and actionable
"""

    echo "🧠 Calling Anthropic Claude Sonnet 4.6 for deep security analysis..."
    def aiOutput = _openAiCall(prompt)

    def timestamp = new Date().format("yyyy-MM-dd HH:mm:ss")

    if (aiOutput.trim().contains("[NO_ERRORS_DETECTED]")) {
        echo "============================================"
        echo "✅ AI SHIELD: PASSED WITH NO ERRORS!"
        echo "No tool vulnerabilities or hidden structural vulnerabilities were detected."
        echo "============================================"
        
        def successMsg = """# ✅ Security Audit Passed
All DevSecOps pipeline scanners passed cleanly. Furthermore, the AI Cybersecurity Shield performed a deep semantic analysis and found no critical, high, or medium severity hidden logic vulnerabilities.
The codebase is currently considered secure."""
        
        _buildHtmlReport(successMsg, stageJson, timestamp)
    } else {
        echo "⚠️ AI SHIELD: Vulnerabilities detected (either by tools or AI)."
        echo "📊 Generating full HTML vulnerability report..."
        _buildHtmlReport(aiOutput, stageJson, timestamp)
    }
}

/**
 * Builds the HTML report using the Python generator script.
 */
def _buildHtmlReport(String aiContent, String stageJson, String timestamp) {
    def contentFile = "${WORKSPACE}/.ai_report_content.md"
    def stageFile = "${WORKSPACE}/.stage_status.json"
    writeFile file: contentFile, text: aiContent
    writeFile file: stageFile, text: stageJson

    sh """#!/bin/bash
    python3 "${WORKSPACE}/scripts/generate_report.py" \
        "${contentFile}" \
        "${stageFile}" \
        "${timestamp}" \
        "${env.REPORT_FILE}"
    rm -f "${contentFile}" "${stageFile}"

    # Just output the HTML file normally
    """

    echo "✅ HTML report generated: ${env.REPORT_FILE}"
}

/**
 * Core OpenAI API call — GPT o3-mini (Reasoning Model for Security)
 * Uses the openai_query.py script to execute the call securely.
 */
def _openAiCall(String prompt) {
    def promptFile = "${WORKSPACE}/.openai_prompt.txt"
    writeFile file: promptFile, text: prompt

    def result = sh(script: '''#!/bin/bash
set +e
python3 "${WORKSPACE}/scripts/anthropic_query.py" "''' + promptFile + '''" 2>&1
''',
    returnStdout: true).trim()

    // Clean up
    sh "rm -f ${promptFile}"

    return result ?: "⚠️ Anthropic API returned no content. Check connectivity and quota."
}
