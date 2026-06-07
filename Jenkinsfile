// ============================================================
// AI-Enhanced DevSecOps Pipeline — AI Cybersecurity Shield
// ============================================================
// Claude Opus 4.8 performs DEEP vulnerability analysis beyond
// what tools detect. Generates a premium HTML audit report
// with flowcharts, code snippets, and remediation roadmap.
// AI is ADVISOR ONLY — never modifies code.
// ============================================================

pipeline {

    agent any

    parameters {
        string(name: 'REPO_URL', defaultValue: '', description: 'Repository URL to scan (e.g., https://gitlab.christuniversity.in/...)')
        string(name: 'BRANCH_NAME', defaultValue: 'main', description: 'Branch to scan (e.g., main, develop)')
        string(name: 'SCAN_PATH', defaultValue: '', description: 'Optional: specific file or folder path to scan (e.g., src/app.js or sample-app/). Leave empty to scan entire repo.')
        string(name: 'DEVELOPER_EMAIL', defaultValue: '', description: 'Optional: developer email address to notify when the AI analysis completes.')
        string(name: 'TARGET_URL', defaultValue: '', description: 'Optional: target URL for dynamic application security testing (DAST) with OWASP ZAP.')
        booleanParam(name: 'REQUEST_AI_LAYER', defaultValue: false, description: 'Check to request AI-powered deep analysis — admin must approve in Jenkins before it runs')
    }

    environment {
        GIT_BRANCH      = 'secure-test'
        // ⬇️ CONFIGURE: Replace with your admin email address
        ADMIN_EMAIL     = 'your-admin@example.com'

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
                    deleteDir() // Wipe the entire workspace to prevent hidden files like old .git logs from triggering scanners
                    writeFile file: env.ERROR_FILE, text: '' // Recreate the error log file
                    // Stage status tracking
                    env.STAGE_TRUFFLEHOG = 'NOT_RUN'
                    env.STAGE_SONARQUBE  = 'NOT_RUN'
                    env.STAGE_SNYK       = 'NOT_RUN'
                    env.STAGE_CHECKOV    = 'NOT_RUN'
                    env.STAGE_TRIVY      = 'NOT_RUN'
                    env.STAGE_SBOM       = 'NOT_RUN'
                    env.STAGE_ZAP        = 'NOT_RUN'
                    env.AI_APPROVED      = 'false'
                    // Detail messages for each stage
                    env.DETAIL_TRUFFLEHOG = ''
                    env.DETAIL_SONARQUBE  = ''
                    env.DETAIL_SNYK       = ''
                    env.DETAIL_CHECKOV    = ''
                    env.DETAIL_TRIVY      = ''
                    env.DETAIL_SBOM       = ''
                    env.DETAIL_ZAP        = ''
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
                                ${trufflehogPath} filesystem "${scanTarget}" --exclude-paths=.trufflehog-ignore --json --no-update > trufflehog_report.json 2>trufflehog_stderr.txt
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

        // ── Container Security (Trivy) ─────────────────────────────────────
        stage('Container Security (Trivy)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        def scanTarget = "${WORKSPACE}/target_repo"
                        if (params.SCAN_PATH) {
                            scanTarget = "${WORKSPACE}/target_repo/${params.SCAN_PATH}"
                        }

                        // Check if target repo has a Dockerfile — if yes, build & scan the image
                        // If no Dockerfile, fall back to filesystem vulnerability scan
                        def hasDockerfile = sh(
                            script: "find ${WORKSPACE}/target_repo -maxdepth 3 -name 'Dockerfile*' -type f | head -1",
                            returnStdout: true
                        ).trim()

                        if (hasDockerfile) {
                            echo "🐳 Dockerfile found: ${hasDockerfile} — building and scanning container image..."
                            def dockerDir = sh(script: "dirname ${hasDockerfile}", returnStdout: true).trim()
                            def imgTag = "trivy-scan-target:${BUILD_NUMBER}"

                            // Build the Docker image from the detected Dockerfile
                            def buildResult = sh(
                                script: """
                                    set +e
                                    cd "${dockerDir}"
                                    docker build -t ${imgTag} -f "${hasDockerfile}" . 2>&1 | tail -20
                                    echo "EXIT_CODE=\$?"
                                """,
                                returnStdout: true
                            ).trim()

                            if (buildResult.contains('EXIT_CODE=0')) {
                                // Scan the built image for CVEs
                                def trivyExit = sh(
                                    script: """
                                        set +e
                                        trivy image --severity HIGH,CRITICAL --format json --output trivy_report.json ${imgTag} 2>&1
                                        exit \$?
                                    """,
                                    returnStatus: true
                                )

                                // Clean up the built image
                                sh "docker rmi ${imgTag} 2>/dev/null || true"

                                if (trivyExit != 0 && fileExists('trivy_report.json')) {
                                    def reportContent = readFile('trivy_report.json').trim()
                                    // Count vulnerabilities from JSON
                                    def vulnCount = sh(script: "grep -c '\\\"VulnerabilityID\\\"' trivy_report.json 2>/dev/null || echo '0'", returnStdout: true).trim()
                                    env.STAGE_TRIVY = 'FAILED'
                                    env.DETAIL_TRIVY = "Found ${vulnCount} HIGH/CRITICAL CVEs in container image"
                                    _logError('Container Security (Trivy)', "Trivy found ${vulnCount} HIGH/CRITICAL vulnerabilities in the Docker image built from ${hasDockerfile}")
                                    error("Trivy found container vulnerabilities")
                                } else {
                                    env.STAGE_TRIVY = 'PASSED'
                                    env.DETAIL_TRIVY = 'No HIGH/CRITICAL CVEs in container image'
                                }
                            } else {
                                // Docker build failed — fall back to filesystem scan
                                echo "⚠️ Docker build failed — falling back to filesystem vulnerability scan..."
                                def trivyExit = sh(
                                    script: "trivy fs --severity HIGH,CRITICAL --format json --output trivy_report.json ${scanTarget} 2>&1",
                                    returnStatus: true
                                )
                                if (trivyExit != 0 && fileExists('trivy_report.json')) {
                                    def vulnCount = sh(script: "grep -c '\\\"VulnerabilityID\\\"' trivy_report.json 2>/dev/null || echo '0'", returnStdout: true).trim()
                                    env.STAGE_TRIVY = 'FAILED'
                                    env.DETAIL_TRIVY = "Found ${vulnCount} HIGH/CRITICAL vulnerabilities in filesystem scan (Docker build failed)"
                                    _logError('Container Security (Trivy)', "Trivy filesystem scan found ${vulnCount} vulnerabilities")
                                    error("Trivy found vulnerabilities")
                                } else {
                                    env.STAGE_TRIVY = 'PASSED'
                                    env.DETAIL_TRIVY = 'No HIGH/CRITICAL vulnerabilities found (filesystem scan — Docker build failed)'
                                }
                            }
                        } else {
                            // No Dockerfile — run filesystem vulnerability scan
                            echo "📁 No Dockerfile found — running Trivy filesystem vulnerability scan..."
                            def trivyExit = sh(
                                script: "trivy fs --severity HIGH,CRITICAL --format json --output trivy_report.json ${scanTarget} 2>&1",
                                returnStatus: true
                            )
                            if (trivyExit != 0 && fileExists('trivy_report.json')) {
                                def vulnCount = sh(script: "grep -c '\\\"VulnerabilityID\\\"' trivy_report.json 2>/dev/null || echo '0'", returnStdout: true).trim()
                                env.STAGE_TRIVY = 'FAILED'
                                env.DETAIL_TRIVY = "Found ${vulnCount} HIGH/CRITICAL vulnerabilities in dependencies"
                                _logError('Container Security (Trivy)', "Trivy filesystem scan found ${vulnCount} vulnerabilities")
                                error("Trivy found vulnerabilities")
                            } else {
                                env.STAGE_TRIVY = 'PASSED'
                                env.DETAIL_TRIVY = 'No HIGH/CRITICAL vulnerabilities found in dependencies'
                            }
                        }
                        echo "✅ Trivy scan complete."
                    }
                }
            }
        }

            }  // end parallel
        }  // end Phase 2-3: Parallel Tools Scan

        // ── SBOM Generation (CycloneDX) ──────────────────────────────────
        // Generates a Software Bill of Materials — required by US Executive
        // Order 14028 and demanded by Google, Microsoft, and every Fortune 500.
        stage('SBOM Generation (CycloneDX)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        def scanTarget = "${WORKSPACE}/target_repo"
                        if (params.SCAN_PATH) {
                            scanTarget = "${WORKSPACE}/target_repo/${params.SCAN_PATH}"
                        }

                        echo "📦 Generating Software Bill of Materials (SBOM) with Syft..."

                        def syftTarget = "dir:${scanTarget}"

                        def syftExit = sh(
                            script: """
                                set +e
                                syft ${syftTarget} -o cyclonedx-json=sbom_cyclonedx.json -o spdx-json=sbom_spdx.json 2>&1
                                exit \$?
                            """,
                            returnStatus: true
                        )

                        if (syftExit == 0 && fileExists('sbom_cyclonedx.json')) {
                            // Count components in the SBOM
                            def componentCount = sh(
                                script: "grep -c '\"bom-ref\"' sbom_cyclonedx.json 2>/dev/null || echo '0'",
                                returnStdout: true
                            ).trim()
                            env.STAGE_SBOM = 'PASSED'
                            env.DETAIL_SBOM = "Generated SBOM with ${componentCount} components (CycloneDX + SPDX)"
                            echo "✅ SBOM generated: ${componentCount} components catalogued."
                        } else {
                            env.STAGE_SBOM = 'FAILED'
                            env.DETAIL_SBOM = 'Syft failed to generate SBOM'
                            _logError('SBOM Generation', 'Syft exited with non-zero status or produced no output')
                            error("SBOM generation failed")
                        }

                        // Archive SBOM files as downloadable Jenkins artifacts
                        try {
                            archiveArtifacts artifacts: 'sbom_cyclonedx.json,sbom_spdx.json', allowEmptyArchive: true
                        } catch (e) {
                            echo "SBOM archiving note: ${e.message}"
                        }
                    }
                }
            }
        }

        // ── DAST Stage (OWASP ZAP) ───────────────────────────────────────
        // Dynamic Application Security Testing (DAST) attacks a running app 
        // to detect vulnerabilities like SQL Injection, XSS, and CSRF.
        stage('DAST (OWASP ZAP)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        if (!params.TARGET_URL) {
                            echo "⏭️ DAST (OWASP ZAP) stage skipped because TARGET_URL parameter is empty. Please provide TARGET_URL if you want to run dynamic application scanning."
                            env.STAGE_ZAP = 'SKIPPED'
                            env.DETAIL_ZAP = 'Skipped (no TARGET_URL provided)'
                        } else {
                            def targetUrl = params.TARGET_URL.trim()
                            if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                                targetUrl = "http://" + targetUrl
                                echo "⚠️ TARGET_URL did not start with http:// or https://. Automatically prepended http:// to make it: ${targetUrl}"
                            }
                            echo "🕷️ Running OWASP ZAP DAST scan against target URL: ${targetUrl}..."
                            
                            // Check network accessibility to targetUrl
                            echo "🔍 Testing network connectivity to ${targetUrl} from EC2..."
                            def connectionExit = sh(script: "curl -I -m 10 --connect-timeout 5 '${targetUrl}' > /dev/null 2>&1", returnStatus: true)
                            if (connectionExit != 0) {
                                echo "⚠️ WARNING: Target URL ${targetUrl} appears to be UNREACHABLE from this EC2 instance (curl exit code: ${connectionExit})."
                                echo "Please verify that:"
                                echo "1. The application is running at ${targetUrl}."
                                echo "2. The Jenkins EC2 Security Group allows outbound traffic to this destination."
                                echo "3. The target application's Security Group/firewall allows inbound traffic from this Jenkins EC2 public/private IP."
                            } else {
                                echo "✅ Network connectivity verified: EC2 can successfully reach ${targetUrl}."
                            }
                            
                            // Check if Docker is available
                            def hasDocker = sh(script: "which docker || echo ''", returnStdout: true).trim()
                            if (!hasDocker) {
                                env.STAGE_ZAP = 'FAILED'
                                env.DETAIL_ZAP = 'Docker not installed on Jenkins agent — cannot run ZAP container'
                                _logError('DAST (OWASP ZAP)', 'Docker command not found on agent.')
                                error("Docker not installed")
                            }

                            // Run ZAP baseline scan in Docker
                            // Mounts the workspace to /zap/wrk so the report is written back to host workspace
                            def zapExit = sh(
                                script: """
                                    set +e
                                    docker run --user root --rm -v "${WORKSPACE}":/zap/wrk/:rw zaproxy/zap-stable zap-baseline.py -t "${targetUrl}" -J zap_report.json 2>&1
                                    exit \$?
                                """,
                                returnStatus: true
                            )

                            if (zapExit == 0 || zapExit == 2 || zapExit == 3) {
                                if (fileExists('zap_report.json')) {
                                    def alertCount = sh(script: "grep -c '\"alert\"' zap_report.json || echo '0'", returnStdout: true).trim()
                                    env.STAGE_ZAP = 'PASSED'
                                    env.DETAIL_ZAP = "DAST scan completed. Found ${alertCount} alerts/warnings."
                                    echo "✅ OWASP ZAP scan complete: ${alertCount} alerts/warnings catalogued."
                                } else {
                                    env.STAGE_ZAP = 'FAILED'
                                    env.DETAIL_ZAP = 'ZAP completed but did not write zap_report.json'
                                    _logError('DAST (OWASP ZAP)', 'ZAP completed but zap_report.json is missing.')
                                    error("ZAP report missing")
                                }
                            } else {
                                env.STAGE_ZAP = 'FAILED'
                                env.DETAIL_ZAP = "ZAP scan failed with exit code ${zapExit}"
                                _logError('DAST (OWASP ZAP)', "ZAP scan exited with error status ${zapExit}")
                                error("ZAP scan exited with status ${zapExit}")
                            }

                            // Archive ZAP report
                            try {
                                archiveArtifacts artifacts: 'zap_report.json', allowEmptyArchive: true
                            } catch (e) {
                                echo "ZAP archiving note: ${e.message}"
                            }
                        }
                    }
                }
            }
        }

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

        // ── Generate Preliminary Report ──────────────────────────────────
        stage('Generate Preliminary Report') {
            steps {
                script {
                    echo "📊 Generating preliminary offline scanners report..."
                    def stageJson = _getStageStatusJson()
                    def timestamp = new Date().format("yyyy-MM-dd HH:mm:ss")
                    def scanErrors = fileExists(env.ERROR_FILE) ? readFile(env.ERROR_FILE).trim() : ''
                    
                    def scanTargetName = params.SCAN_PATH ? "path: ${params.SCAN_PATH}" : "Entire Repository"
                    
                    def prelimContent = """\
# 🛡️ Offline Security Scanners Complete

The automated security scanners have finished scanning your target: **${scanTargetName}** (branch: **${params.BRANCH_NAME}**).
Deep AI Security Analysis layer is **Awaiting Admin Approval**. Once the admin approves, the deep logic analysis and code-level remediations will be performed, and the final report will be sent to you.

---

### 📊 Offline Tool Run Summary
- **Secrets (TruffleHog)**: ${env.STAGE_TRUFFLEHOG} (${env.DETAIL_TRUFFLEHOG ?: 'No verified secrets found'})
- **SAST (SonarQube)**: ${env.STAGE_SONARQUBE} (${env.DETAIL_SONARQUBE ?: 'Quality Gate passed'})
- **SCA (Snyk)**: ${env.STAGE_SNYK} (${env.DETAIL_SNYK ?: 'No dependency vulnerabilities found'})
- **IaC (Checkov)**: ${env.STAGE_CHECKOV} (${env.DETAIL_CHECKOV ?: 'No IaC misconfigurations found'})
- **Container Security (Trivy)**: ${env.STAGE_TRIVY} (${env.DETAIL_TRIVY ?: 'No container vulnerabilities found'})
- **SBOM (CycloneDX/SPDX)**: ${env.STAGE_SBOM} (${env.DETAIL_SBOM ?: 'SBOM not generated'})
- **DAST (OWASP ZAP)**: ${env.STAGE_ZAP} (${env.DETAIL_ZAP ?: 'DAST scan not run'})

---

### 🛠️ Scanner Diagnostic Logs & Warnings
${scanErrors ?: 'No issues or error logs generated.'}
"""
                    _buildHtmlReport(prelimContent, stageJson, timestamp)
                    
                    try {
                        archiveArtifacts artifacts: 'ai_security_audit.html', allowEmptyArchive: true
                    } catch (e) {
                        echo "Preliminary report archiving failed: ${e.message}"
                    }
                }
            }
        }

        // ── Security Metrics Dashboard ───────────────────────────────────
        // Collects scan findings from all tools, records historical trends,
        // and updates the dynamic HTML executive dashboard in Jenkins userContent.
        stage('Security Metrics Dashboard') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        echo "📊 Updating executive security metrics dashboard..."
                        
                        // Execute dashboard update script
                        // Pass environment variables to Python script
                        withEnv([
                            "REPO_URL=${params.REPO_URL}",
                            "BRANCH_NAME=${params.BRANCH_NAME}",
                            "STAGE_TRUFFLEHOG=${env.STAGE_TRUFFLEHOG}",
                            "STAGE_SONARQUBE=${env.STAGE_SONARQUBE}",
                            "STAGE_SNYK=${env.STAGE_SNYK}",
                            "STAGE_CHECKOV=${env.STAGE_CHECKOV}",
                            "STAGE_TRIVY=${env.STAGE_TRIVY}",
                            "STAGE_SBOM=${env.STAGE_SBOM}",
                            "STAGE_ZAP=${env.STAGE_ZAP}",
                            "AI_APPROVED=${env.AI_APPROVED}"
                        ]) {
                            sh "python3 target_repo/scripts/update_dashboard.py"
                            
                            // ⬇️ CONFIGURE: Replace with your Jenkins server's public URL
                            def publicHost = "http://localhost:8080"
                            def detectedHost = publicHost
                            try {
                                def match = env.BUILD_URL =~ /(https?:\/\/[^\/]+)/
                                if (match) {
                                    detectedHost = match[0][1]
                                }
                            } catch (e) {
                                // fallback
                            }
                            echo "\n========================================================================\n📊 SECURITY DASHBOARD REFRESHED SUCCESSFULLY!\n👉 PUBLIC ACCESS LINK:  ${publicHost}/userContent/security_dashboard.html\n👉 DETECTED/VPC LINK:   ${detectedHost}/userContent/security_dashboard.html\n💡 Note: If the Detected link fails to open, it is because it uses a private IP (e.g. 172.x.x.x) only accessible inside AWS. Use the Public Access Link instead.\n========================================================================\n"
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
                    // Validate that developer provided their email before requesting AI layer
                    if (!params.DEVELOPER_EMAIL?.trim()) {
                        echo "❌ DEVELOPER_EMAIL is required when requesting the AI Layer."
                        echo "Please re-run the build and enter your email address in the DEVELOPER_EMAIL field."
                        error("BUILD ABORTED: DEVELOPER_EMAIL is mandatory when REQUEST_AI_LAYER is checked. The admin needs to know who is requesting the AI scan.")
                    }

                    def devEmail = params.DEVELOPER_EMAIL.trim()
                    echo "🔐 AI Layer requested by ${devEmail} — sending approval request to admin..."

                    try {
                        mail(
                            to: env.ADMIN_EMAIL,
                            subject: "🔐 AI Scan Approval Request from ${devEmail} — ${params.REPO_URL}",
                            body: """\
📧 Developer ${devEmail} has requested the AI Cybersecurity Shield for:

  Requested by : ${devEmail}
  Repository   : ${params.REPO_URL}
  Branch       : ${params.BRANCH_NAME}
  Build        : ${BUILD_URL}

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
        // Phase 4: AI CYBERSECURITY SHIELD (Claude Opus 4.8 — Deep Analysis)
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
                    echo "  Engine: Claude Opus 4.8"
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

                    // ── 8. Email the report to the developer ────────
                    if (params.DEVELOPER_EMAIL) {
                        try {
                            echo "📧 Sending AI Security Audit Report to ${params.DEVELOPER_EMAIL}..."
                            emailext (
                                to: params.DEVELOPER_EMAIL,
                                subject: "🛡️ AI DevSecOps Security Audit Report — Build #${BUILD_NUMBER}",
                                mimeType: 'text/html',
                                attachmentsPattern: 'ai_security_audit.html',
                                body: """\
<h3>🛡️ AI DevSecOps Security Audit Complete</h3>
<p>The AI Cybersecurity Shield has completed its deep analysis for repository: <b>${params.REPO_URL}</b> (branch: <b>${params.BRANCH_NAME}</b>).</p>
<p>The build finished with status: <b>${currentBuild.currentResult}</b>.</p>
<p>Please find the premium HTML report attached to this email. You can also view the build details here: <a href="${BUILD_URL}">${BUILD_URL}</a></p>
<br>
<p><i>This is an automated notification from Christ University DevSecOps Audit Pipeline.</i></p>
"""
                            )
                            echo "✅ Email sent successfully."
                        } catch (mailErr) {
                            echo "⚠️ Failed to send email (check Jenkins SMTP configuration): ${mailErr.message}"
                        }
                    }
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
                    archiveArtifacts artifacts: 'scan_errors.txt,ai_security_audit.html,trufflehog_report.json,trufflehog_stderr.txt,snyk_report.json,snyk_report.txt,checkov_report.json,checkov_report.txt,sonar_output.txt,trivy_report.json,sbom_cyclonedx.json,sbom_spdx.json,zap_report.json', allowEmptyArchive: true
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
| Container Security (Trivy)   | ${env.STAGE_TRIVY.padRight(10)} | ${(env.DETAIL_TRIVY ?: 'N/A').take(40).padRight(40)} |
| SBOM (CycloneDX)             | ${env.STAGE_SBOM.padRight(10)} | ${(env.DETAIL_SBOM ?: 'N/A').take(40).padRight(40)} |
| DAST (OWASP ZAP)             | ${env.STAGE_ZAP.padRight(10)} | ${(env.DETAIL_ZAP ?: 'N/A').take(40).padRight(40)} |

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
    {"name": "IaC (Checkov)", "status": "${env.STAGE_CHECKOV}", "detail": "${(env.DETAIL_CHECKOV ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"},
    {"name": "Container Security (Trivy)", "status": "${env.STAGE_TRIVY}", "detail": "${(env.DETAIL_TRIVY ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"},
    {"name": "SBOM (CycloneDX)", "status": "${env.STAGE_SBOM}", "detail": "${(env.DETAIL_SBOM ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"},
    {"name": "DAST (OWASP ZAP)", "status": "${env.STAGE_ZAP}", "detail": "${(env.DETAIL_ZAP ?: '').replaceAll('"', '\\\\"').replaceAll('\n', ' ').replaceAll('\r', '').replaceAll('\t', ' ')}"}
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

    // Trivy (Container / Filesystem vulnerability scanning)
    reports.append("\n\n=== TRIVY (Container Security) — Stage: ${env.STAGE_TRIVY} ===\n")
    if (fileExists('trivy_report.json')) {
        reports.append(readFile('trivy_report.json').take(8000))
    } else {
        reports.append("No report generated (tool may not have run).")
    }

    // SBOM (Software Bill of Materials)
    reports.append("\n\n=== SBOM (CycloneDX) — Stage: ${env.STAGE_SBOM} ===\n")
    if (fileExists('sbom_cyclonedx.json')) {
        reports.append("SBOM generated successfully. Component summary (truncated):\n")
        reports.append(readFile('sbom_cyclonedx.json').take(4000))
    } else {
        reports.append("No SBOM generated.")
    }

    // DAST (OWASP ZAP)
    reports.append("\n\n=== DAST (OWASP ZAP) — Stage: ${env.STAGE_ZAP} ===\n")
    if (fileExists('zap_report.json')) {
        reports.append(readFile('zap_report.json').take(8000))
    } else {
        reports.append("No ZAP DAST report generated.")
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
 * Runs the AI Cybersecurity Shield analysis using Claude Opus 4.8.
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

    echo "🧠 Calling Anthropic Claude Opus 4.8 for deep security analysis..."
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
