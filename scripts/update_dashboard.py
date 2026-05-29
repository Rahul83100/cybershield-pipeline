#!/usr/bin/env python3
import os
import json
import datetime

def parse_trufflehog():
    findings = 0
    if os.path.exists("trufflehog_report.json"):
        try:
            with open("trufflehog_report.json", "r") as f:
                lines = f.readlines()
                # TruffleHog JSON format: one JSON object per finding per line
                findings = len([l for l in lines if l.strip()])
        except Exception as e:
            print(f"Error parsing TruffleHog: {e}")
    return findings

def parse_snyk():
    findings = 0
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if os.path.exists("snyk_report.json"):
        try:
            with open("snyk_report.json", "r") as f:
                data = json.load(f)
                vulns = []
                if isinstance(data, list):
                    for item in data:
                        vulns.extend(item.get("vulnerabilities", []))
                elif isinstance(data, dict):
                    vulns = data.get("vulnerabilities", [])
                
                findings = len(vulns)
                for v in vulns:
                    sev = v.get("severity", "medium").capitalize()
                    if sev == "Critical":
                        severities["Critical"] += 1
                    elif sev == "High":
                        severities["High"] += 1
                    elif sev == "Medium":
                        severities["Medium"] += 1
                    elif sev == "Low":
                        severities["Low"] += 1
        except Exception as e:
            print(f"Error parsing Snyk: {e}")
    return findings, severities

def parse_checkov():
    findings = 0
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if os.path.exists("checkov_report.json"):
        try:
            with open("checkov_report.json", "r") as f:
                data = json.load(f)
                checks = []
                if isinstance(data, list):
                    for item in data:
                        checks.extend(item.get("results", {}).get("failed_checks", []))
                elif isinstance(data, dict):
                    if "results" in data:
                        checks = data["results"].get("failed_checks", [])
                    else:
                        checks = data.get("failed_checks", [])
                
                findings = len(checks)
                for c in checks:
                    # Checkov severity defaults to Medium if not specified
                    sev = c.get("check_severity", "MEDIUM")
                    if isinstance(sev, str):
                        sev = sev.capitalize()
                    else:
                        sev = "Medium"
                    
                    if sev == "Critical":
                        severities["Critical"] += 1
                    elif sev == "High":
                        severities["High"] += 1
                    elif sev == "Medium" or sev == "Medium":
                        severities["Medium"] += 1
                    elif sev == "Low":
                        severities["Low"] += 1
        except Exception as e:
            print(f"Error parsing Checkov: {e}")
    return findings, severities

def parse_trivy():
    findings = 0
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if os.path.exists("trivy_report.json"):
        try:
            with open("trivy_report.json", "r") as f:
                data = json.load(f)
                for res in data.get("Results", []):
                    vulns = res.get("Vulnerabilities", [])
                    findings += len(vulns)
                    for v in vulns:
                        sev = v.get("Severity", "Medium").capitalize()
                        if sev == "Critical":
                            severities["Critical"] += 1
                        elif sev == "High":
                            severities["High"] += 1
                        elif sev == "Medium":
                            severities["Medium"] += 1
                        elif sev == "Low":
                            severities["Low"] += 1
        except Exception as e:
            print(f"Error parsing Trivy: {e}")
    return findings, severities

def parse_zap():
    findings = 0
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if os.path.exists("zap_report.json"):
        try:
            with open("zap_report.json", "r") as f:
                data = json.load(f)
                sites = data.get("site", [])
                if isinstance(sites, dict):
                    sites = [sites]
                for site in sites:
                    alerts = site.get("alerts", [])
                    findings += len(alerts)
                    for a in alerts:
                        risk = a.get("riskdesc", "Medium").split("(")[0].strip().capitalize()
                        if risk == "High":
                            severities["High"] += 1
                        elif risk == "Medium":
                            severities["Medium"] += 1
                        elif risk == "Low":
                            severities["Low"] += 1
                        elif risk == "Informational":
                            # We can treat Informational as Low or ignore, let's treat as Low/Info
                            pass
        except Exception as e:
            print(f"Error parsing ZAP: {e}")
    return findings, severities

def parse_sbom():
    components = 0
    if os.path.exists("sbom_cyclonedx.json"):
        try:
            with open("sbom_cyclonedx.json", "r") as f:
                data = json.load(f)
                components = len(data.get("components", []))
        except Exception as e:
            print(f"Error parsing SBOM: {e}")
    return components

def update_metrics():
    # 1. Parse current run reports
    trufflehog_count = parse_trufflehog()
    snyk_count, snyk_sev = parse_snyk()
    checkov_count, checkov_sev = parse_checkov()
    trivy_count, trivy_sev = parse_trivy()
    zap_count, zap_sev = parse_zap()
    sbom_components = parse_sbom()
    
    # Simple estimate of SonarQube findings if it failed
    sq_status = os.environ.get("STAGE_SONARQUBE", "NOT_RUN")
    sonarqube_count = 5 if sq_status == "FAILED" else 0
    
    # Assemble severity totals
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for sev in severities:
        severities[sev] = (
            (trufflehog_count if sev == "Critical" else 0) +
            snyk_sev.get(sev, 0) +
            checkov_sev.get(sev, 0) +
            trivy_sev.get(sev, 0) +
            zap_sev.get(sev, 0)
        )
    
    # 2. Get environment meta
    repo_url = os.environ.get("REPO_URL", "znfrepairandservices")
    repo_name = repo_url.split("/")[-1].replace(".git", "") if "/" in repo_url else repo_url
    branch_name = os.environ.get("BRANCH_NAME", "main")
    build_num = os.environ.get("BUILD_NUMBER", "1")
    build_url = os.environ.get("BUILD_URL", "")
    ai_approved = os.environ.get("AI_APPROVED", "false") == "true"
    
    scan_record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "build_number": build_num,
        "build_url": build_url,
        "repo_name": repo_name,
        "branch_name": branch_name,
        "ai_approved": ai_approved,
        "tools": {
            "trufflehog": {"findings": trufflehog_count, "status": os.environ.get("STAGE_TRUFFLEHOG", "NOT_RUN")},
            "sonarqube": {"findings": sonarqube_count, "status": sq_status},
            "snyk": {"findings": snyk_count, "status": os.environ.get("STAGE_SNYK", "NOT_RUN")},
            "checkov": {"findings": checkov_count, "status": os.environ.get("STAGE_CHECKOV", "NOT_RUN")},
            "trivy": {"findings": trivy_count, "status": os.environ.get("STAGE_TRIVY", "NOT_RUN")},
            "zap": {"findings": zap_count, "status": os.environ.get("STAGE_ZAP", "NOT_RUN")},
            "sbom": {"components": sbom_components, "status": os.environ.get("STAGE_SBOM", "NOT_RUN")}
        },
        "severity_breakdown": severities,
        "total_findings": trufflehog_count + sonarqube_count + snyk_count + checkov_count + trivy_count + zap_count
    }
    
    # 3. Read & update historical JSON store
    metrics_dir = os.environ.get("METRICS_DIR", "/var/lib/jenkins/userContent")
    os.makedirs(metrics_dir, exist_ok=True)
    scans_file = os.path.join(metrics_dir, "security_scans.json")
    
    scans = []
    if os.path.exists(scans_file):
        try:
            with open(scans_file, "r") as f:
                scans = json.load(f)
        except Exception as e:
            print(f"Error reading security_scans.json: {e}")
            
    # Remove duplicate scan for same build to prevent pollution during manual runs
    scans = [s for s in scans if not (s.get("build_number") == build_num and s.get("repo_name") == repo_name)]
    
    scans.append(scan_record)
    
    # Keep last 50 scans to avoid huge payloads
    if len(scans) > 50:
        scans = scans[-50:]
        
    with open(scans_file, "w") as f:
        json.dump(scans, f, indent=2)
        
    print(f"✅ Appended current scan results to {scans_file}!")
    
    # 4. Generate security_dashboard.html
    dashboard_file = os.path.join(metrics_dir, "security_dashboard.html")
    generate_dashboard_html(dashboard_file)
    print(f"✅ Refreshed security metrics dashboard at {dashboard_file}!")

def generate_dashboard_html(filepath):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ DevSecOps Executive Metrics Dashboard</title>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <!-- FontAwesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <style>
        :root {
            --bg-color: #0b0f19;
            --panel-bg: rgba(17, 24, 39, 0.7);
            --panel-border: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.15);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #06b6d4;
            --purple: #a855f7;
            --glass-blur: blur(12px);
        }

        .light-mode {
            --bg-color: #f8fafc;
            --panel-bg: rgba(255, 255, 255, 0.8);
            --panel-border: rgba(0, 0, 0, 0.06);
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --primary: #4f46e5;
            --primary-glow: rgba(79, 70, 229, 0.1);
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
            --info: #0891b2;
            --purple: #7c3aed;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }

        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            padding: 2rem;
            min-height: 100vh;
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.05) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        /* --- Header --- */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2.5rem;
            border-bottom: 1px solid var(--panel-border);
            padding-bottom: 1.5rem;
        }

        .header-title h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2.25rem;
            font-weight: 700;
            background: linear-gradient(135deg, #fff 30%, var(--primary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .light-mode .header-title h1 {
            background: linear-gradient(135deg, #0f172a 30%, var(--primary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-title p {
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .btn {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            color: var(--text-primary);
            padding: 0.6rem 1.2rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            backdrop-filter: var(--glass-blur);
        }

        .btn:hover {
            background: var(--primary-glow);
            border-color: var(--primary);
        }

        .btn-primary {
            background: var(--primary);
            color: white;
            border: none;
        }

        .btn-primary:hover {
            background: #4f46e5;
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
        }

        /* --- KPI Grid --- */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: var(--glass-blur);
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }

        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--primary);
        }

        .kpi-card.kpi-success::before { background: var(--success); }
        .kpi-card.kpi-warning::before { background: var(--warning); }
        .kpi-card.kpi-danger::before { background: var(--danger); }
        .kpi-card.kpi-info::before { background: var(--info); }
        .kpi-card.kpi-purple::before { background: var(--purple); }

        .kpi-header {
            display: flex;
            justify-content: space-between;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.75rem;
        }

        .kpi-value {
            font-size: 2rem;
            font-weight: 700;
            font-family: 'Outfit', sans-serif;
        }

        .kpi-footer {
            margin-top: 0.5rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        /* --- Main Layout Grid --- */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        @media (max-width: 1024px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        .chart-container {
            min-height: 320px;
            position: relative;
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            border-bottom: 1px solid var(--panel-border);
            padding-bottom: 0.75rem;
        }

        /* --- Tool Grid Status --- */
        .tool-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.75rem;
            height: calc(100% - 40px);
        }

        .tool-item {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--panel-border);
            padding: 0.9rem;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .tool-name-container {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            font-size: 0.85rem;
        }

        .tool-findings-badge {
            font-size: 0.8rem;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-weight: 700;
            align-self: flex-start;
            margin-top: 0.5rem;
        }

        .badge-clean {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
        }

        .badge-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
        }

        .badge-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
        }

        .badge-grey {
            background: rgba(156, 163, 175, 0.1);
            color: var(--text-secondary);
        }

        /* --- Table Styling --- */
        .table-section {
            margin-bottom: 2.5rem;
        }

        .table-controls {
            display: flex;
            justify-content: space-between;
            margin-bottom: 1rem;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .search-wrapper {
            position: relative;
            flex-grow: 1;
            max-width: 400px;
        }

        .search-wrapper i {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-secondary);
        }

        .search-input {
            width: 100%;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            padding: 0.6rem 1rem 0.6rem 2.5rem;
            border-radius: 8px;
            color: var(--text-primary);
            font-family: inherit;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary);
        }

        .table-container {
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid var(--panel-border);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
            background: var(--panel-bg);
        }

        th {
            background: rgba(0, 0, 0, 0.2);
            padding: 1rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--panel-border);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }

        .light-mode th {
            background: rgba(0, 0, 0, 0.02);
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid var(--panel-border);
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }

        .light-mode tr:hover td {
            background: rgba(0, 0, 0, 0.01);
        }

        .badge {
            padding: 0.25rem 0.6rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
        }

        /* --- Footer --- */
        footer {
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 4rem;
            border-top: 1px solid var(--panel-border);
            padding-top: 1.5rem;
        }

        /* --- Empty state --- */
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 4rem;
            color: var(--text-secondary);
            gap: 1rem;
        }

        .empty-state i {
            font-size: 3rem;
            color: var(--primary);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="header-title">
                <h1><i class="fa-solid fa-shield-halved"></i> DevSecOps Security Dashboard</h1>
                <p>Continuous Pipeline Security Metrics & Historical Vulnerability Posture</p>
            </div>
            <div class="header-controls">
                <button class="btn" id="theme-toggle" onclick="toggleTheme()"><i class="fa-solid fa-moon"></i> Theme</button>
                <button class="btn btn-primary" onclick="loadData()"><i class="fa-solid fa-arrows-rotate"></i> Refresh</button>
            </div>
        </header>

        <div id="main-content">
            <!-- KPI Grid -->
            <div class="kpi-grid">
                <div class="card kpi-card kpi-info">
                    <div class="kpi-header">
                        <span>Total Scans Executed</span>
                        <i class="fa-solid fa-fingerprint"></i>
                    </div>
                    <div class="kpi-value" id="kpi-scans">-</div>
                    <div class="kpi-footer">Cumulative pipeline runs</div>
                </div>
                <div class="card kpi-card kpi-danger">
                    <div class="kpi-header">
                        <span>Active Vulnerabilities</span>
                        <i class="fa-solid fa-bug"></i>
                    </div>
                    <div class="kpi-value" id="kpi-findings">-</div>
                    <div class="kpi-footer">From latest scan</div>
                </div>
                <div class="card kpi-card kpi-success">
                    <div class="kpi-header">
                        <span>Latest Scan Status</span>
                        <i class="fa-solid fa-circle-check"></i>
                    </div>
                    <div class="kpi-value" id="kpi-status">-</div>
                    <div class="kpi-footer" id="kpi-latest-meta">No runs recorded</div>
                </div>
                <div class="card kpi-card kpi-purple">
                    <div class="kpi-header">
                        <span>SBOM Catalog size</span>
                        <i class="fa-solid fa-cubes"></i>
                    </div>
                    <div class="kpi-value" id="kpi-sbom">-</div>
                    <div class="kpi-footer">Dependencies catalogued</div>
                </div>
            </div>

            <!-- Dashboard Grid -->
            <div class="dashboard-grid">
                <!-- Trend Chart -->
                <div class="card">
                    <div class="card-title">
                        <i class="fa-solid fa-chart-line"></i> Vulnerability Trends over Time
                    </div>
                    <div class="chart-container">
                        <canvas id="trendChart"></canvas>
                    </div>
                </div>

                <!-- Latest Tool Summary Grid -->
                <div class="card">
                    <div class="card-title">
                        <i class="fa-solid fa-screwdriver-wrench"></i> Latest Run Tool Posture
                    </div>
                    <div class="tool-grid" id="tool-grid-container">
                        <!-- Dynamic tool cells go here -->
                    </div>
                </div>
            </div>

            <div class="dashboard-grid" style="grid-template-columns: 1fr 1fr;">
                <!-- Severity breakdown -->
                <div class="card">
                    <div class="card-title">
                        <i class="fa-solid fa-chart-bar"></i> Vulnerability Severity Distribution
                    </div>
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>

                <!-- Tool breakdown -->
                <div class="card">
                    <div class="card-title">
                        <i class="fa-solid fa-chart-pie"></i> Finding Share by Tool
                    </div>
                    <div class="chart-container">
                        <canvas id="toolShareChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Scan History Table -->
            <div class="card table-section">
                <div class="card-title" style="border-bottom:none; margin-bottom: 0;">
                    <i class="fa-solid fa-clock-rotate-left"></i> Security Scan Run History
                </div>
                <div class="table-controls">
                    <div class="search-wrapper">
                        <i class="fa-solid fa-magnifying-glass"></i>
                        <input type="text" id="search-bar" class="search-input" placeholder="Search by repository name or branch..." onkeyup="filterTable()">
                    </div>
                </div>
                <div class="table-container">
                    <table id="history-table">
                        <thead>
                            <tr>
                                <th>Build</th>
                                <th>Scan Date & Time</th>
                                <th>Repository Name</th>
                                <th>Branch</th>
                                <th>Total Findings</th>
                                <th>AI Approved</th>
                                <th>Report</th>
                            </tr>
                        </thead>
                        <tbody id="history-body">
                            <!-- Dynamic rows -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <footer>
            <p>🛡️ Christ University DevSecOps Audit & Cybersecurity Shield • Dynamic Metrics Dashboard</p>
        </footer>
    </div>

    <script>
        let rawScansData = [];
        let trendChartObj = null;
        let severityChartObj = null;
        let toolShareChartObj = null;

        function getPublicBuildUrl(url) {
            if (!url) return '';
            try {
                const u = new URL(url);
                // Replace internal IP (e.g. 172.31.x.x) or other host with the current browser's host (e.g. 13.233.125.248:8080)
                u.host = window.location.host;
                u.protocol = window.location.protocol;
                return u.toString();
            } catch(e) {
                return url;
            }
        }

        function toggleTheme() {
            const body = document.body;
            body.classList.toggle('light-mode');
            const themeBtn = document.getElementById('theme-toggle');
            if (body.classList.contains('light-mode')) {
                themeBtn.innerHTML = '<i class="fa-solid fa-sun"></i> Theme';
            } else {
                themeBtn.innerHTML = '<i class="fa-solid fa-moon"></i> Theme';
            }
            // Redraw charts with new colors
            updateCharts();
        }

        async function loadData() {
            try {
                const response = await fetch('security_scans.json?' + new Date().getTime());
                if (!response.ok) {
                    throw new Error('No scans JSON found yet.');
                }
                rawScansData = await response.json();
                
                // Sort scans chronologically by timestamp
                rawScansData.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

                if (rawScansData.length === 0) {
                    showEmptyState();
                    return;
                }

                populateKPIs();
                populateToolGrid();
                populateTable();
                updateCharts();
            } catch (err) {
                console.error(err);
                showEmptyState();
            }
        }

        function showEmptyState() {
            document.getElementById('main-content').innerHTML = `
                <div class="card empty-state">
                    <i class="fa-solid fa-shield-virus"></i>
                    <h2>No Security Scan Data Available Yet</h2>
                    <p>Trigger your first Jenkins security pipeline build to populate this real-time metrics dashboard!</p>
                </div>
            `;
        }

        function populateKPIs() {
            const totalScans = rawScansData.length;
            const latestScan = rawScansData[totalScans - 1];

            document.getElementById('kpi-scans').innerText = totalScans;
            document.getElementById('kpi-findings').innerText = latestScan.total_findings;
            
            // Derive latest status from tool statuses
            let hasFailures = false;
            for (const toolKey in latestScan.tools) {
                if (latestScan.tools[toolKey].status === 'FAILED') {
                    hasFailures = true;
                    break;
                }
            }

            const statusKPI = document.getElementById('kpi-status');
            const statusCard = statusKPI.closest('.kpi-card');
            statusCard.className = 'card kpi-card';
            
            if (hasFailures) {
                statusKPI.innerText = 'VULNERABLE';
                statusCard.classList.add('kpi-danger');
            } else {
                statusKPI.innerText = 'SECURE';
                statusCard.classList.add('kpi-success');
            }

            // Sbom components
            const sbomComp = latestScan.tools.sbom?.components || 0;
            document.getElementById('kpi-sbom').innerText = sbomComp;

            // Latest scan meta
            const date = new Date(latestScan.timestamp);
            document.getElementById('kpi-latest-meta').innerText = `Build #${latestScan.build_number} • ${date.toLocaleDateString()} ${date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}`;
        }

        function populateToolGrid() {
            const latestScan = rawScansData[rawScansData.length - 1];
            const container = document.getElementById('tool-grid-container');
            container.innerHTML = '';

            const toolMeta = {
                trufflehog: { name: 'Secrets (TruffleHog)', icon: 'fa-key' },
                sonarqube: { name: 'SAST (SonarQube)', icon: 'fa-code' },
                snyk: { name: 'SCA (Snyk)', icon: 'fa-box-open' },
                checkov: { name: 'IaC (Checkov)', icon: 'fa-cloud' },
                trivy: { name: 'Container (Trivy)', icon: 'fa-cubes' },
                zap: { name: 'DAST (OWASP ZAP)', icon: 'fa-network-wired' }
            };

            for (const key in toolMeta) {
                const tool = latestScan.tools[key] || { status: 'NOT_RUN', findings: 0 };
                const meta = toolMeta[key];
                
                let badgeClass = 'badge-grey';
                if (tool.status === 'PASSED') badgeClass = 'badge-clean';
                else if (tool.status === 'FAILED') badgeClass = 'badge-danger';
                else if (tool.status === 'SKIPPED') badgeClass = 'badge-grey';
                else if (tool.status === 'UNSTABLE') badgeClass = 'badge-warning';

                const toolEl = document.createElement('div');
                toolEl.className = 'tool-item';
                toolEl.innerHTML = `
                    <div class="tool-name-container">
                        <i class="fa-solid ${meta.icon}"></i>
                        <span>${meta.name}</span>
                    </div>
                    <span class="tool-findings-badge ${badgeClass}">
                        ${tool.status === 'SKIPPED' ? 'SKIPPED' : (tool.status === 'NOT_RUN' ? 'NOT RUN' : `${tool.findings} Findings`)}
                    </span>
                `;
                container.appendChild(toolEl);
            }
        }

        function populateTable() {
            const tbody = document.getElementById('history-body');
            tbody.innerHTML = '';

            // Render in reverse chronological order for history table
            const reversedScans = [...rawScansData].reverse();

            reversedScans.forEach(scan => {
                const date = new Date(scan.timestamp);
                const isVulnerable = Object.values(scan.tools).some(t => t.status === 'FAILED');
                
                const badgeClass = isVulnerable ? 'badge-danger' : 'badge-clean';
                const badgeIcon = isVulnerable ? 'fa-triangle-exclamation' : 'fa-circle-check';
                const badgeText = isVulnerable ? `${scan.total_findings} Vulns` : 'Clean';

                const row = document.createElement('tr');
                row.innerHTML = `
                    <td style="font-weight: 700;">#${scan.build_number}</td>
                    <td>${date.toLocaleDateString()} ${date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                    <td style="font-weight: 600;">${scan.repo_name}</td>
                    <td><code style="background: rgba(255,255,255,0.06); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.8rem;">${scan.branch_name}</code></td>
                    <td>
                        <span class="badge ${badgeClass}">
                            <i class="fa-solid ${badgeIcon}"></i> ${badgeText}
                        </span>
                    </td>
                    <td>
                        ${scan.ai_approved ? 
                            '<span class="badge" style="background: rgba(168,85,247,0.1); color: var(--purple);"><i class="fa-solid fa-robot"></i> Approved</span>' : 
                            '<span class="badge badge-grey"><i class="fa-solid fa-ban"></i> Skipped</span>'
                        }
                    </td>
                    <td>
                        ${scan.build_url ? 
                            `<a href="${getPublicBuildUrl(scan.build_url)}artifact/ai_security_audit.html" target="_blank" class="btn" style="padding: 0.3rem 0.6rem; font-size: 0.8rem; border-radius: 6px;"><i class="fa-solid fa-file-pdf"></i> Open Report</a>` : 
                            `<span style="color: var(--text-secondary); font-size: 0.8rem;">Offline</span>`
                        }
                    </td>
                `;
                tbody.appendChild(row);
            });
        }

        function filterTable() {
            const query = document.getElementById('search-bar').value.toLowerCase();
            const rows = document.querySelectorAll('#history-body tr');
            
            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }

        function updateCharts() {
            const isLight = document.body.classList.contains('light-mode');
            const gridColor = isLight ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.05)';
            const labelColor = isLight ? '#475569' : '#9ca3af';

            // --- 1. Line Trend Chart ---
            const trendCtx = document.getElementById('trendChart').getContext('2d');
            const scanLabels = rawScansData.map(s => `Build #${s.build_number}`);
            const scanVulnerabilities = rawScansData.map(s => s.total_findings);

            if (trendChartObj) trendChartObj.destroy();
            trendChartObj = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: scanLabels,
                    datasets: [{
                        label: 'Total Findings',
                        data: scanVulnerabilities,
                        borderColor: '#6366f1',
                        backgroundColor: 'rgba(99, 102, 241, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 3,
                        pointRadius: 6,
                        pointHoverRadius: 8,
                        pointBackgroundColor: '#6366f1'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { color: gridColor },
                            ticks: { color: labelColor }
                        },
                        y: {
                            grid: { color: gridColor },
                            ticks: { color: labelColor },
                            beginAtZero: true
                        }
                    }
                }
            });

            // --- 2. Severity Distribution Chart ---
            const latestScan = rawScansData[rawScansData.length - 1];
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            const sevBreakdown = latestScan.severity_breakdown || { Critical: 0, High: 0, Medium: 0, Low: 0 };

            if (severityChartObj) severityChartObj.destroy();
            severityChartObj = new Chart(severityCtx, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [
                            sevBreakdown.Critical || 0,
                            sevBreakdown.High || 0,
                            sevBreakdown.Medium || 0,
                            sevBreakdown.Low || 0
                        ],
                        backgroundColor: ['#ef4444', '#f59e0b', '#6366f1', '#10b981'],
                        borderRadius: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: labelColor }
                        },
                        y: {
                            grid: { color: gridColor },
                            ticks: { color: labelColor, stepSize: 1 },
                            beginAtZero: true
                        }
                    }
                }
            });

            // --- 3. Share by Tool Chart ---
            const toolCtx = document.getElementById('toolShareChart').getContext('2d');
            const toolKeys = ['trufflehog', 'sonarqube', 'snyk', 'checkov', 'trivy', 'zap'];
            const toolLabels = ['TruffleHog', 'SonarQube', 'Snyk', 'Checkov', 'Trivy', 'OWASP ZAP'];
            const toolFindings = toolKeys.map(k => latestScan.tools[k]?.findings || 0);

            if (toolShareChartObj) toolShareChartObj.destroy();
            toolShareChartObj = new Chart(toolCtx, {
                type: 'doughnut',
                data: {
                    labels: toolLabels,
                    datasets: [{
                        data: toolFindings,
                        backgroundColor: ['#ef4444', '#3b82f6', '#f59e0b', '#06b6d4', '#10b981', '#a855f7'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: labelColor,
                                boxWidth: 12,
                                font: { family: 'Plus Jakarta Sans', size: 11 }
                            }
                        }
                    },
                    cutout: '65%'
                }
            });
        }

        // Initialize on load
        window.addEventListener('DOMContentLoaded', loadData);
    </script>
</body>
</html>
"""
    with open(filepath, "w") as f:
        f.write(html_content)

if __name__ == "__main__":
    update_metrics()
