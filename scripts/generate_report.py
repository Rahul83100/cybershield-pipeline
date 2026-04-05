#!/usr/bin/env python3
"""
generate_report.py - Generate a premium HTML security audit report.
Uses marked.js, mermaid.js, highlight.js via CDN for rich rendering.

Usage:
    python3 generate_report.py <content_file> <stage_file> <timestamp> <output_file>
"""

import sys
import json
import os

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 generate_report.py <content_file> <stage_file> <timestamp> <output>")
        sys.exit(1)

    content_file, stage_file, timestamp, output_file = sys.argv[1:5]

    with open(content_file, 'r', encoding='utf-8', errors='replace') as f:
        ai_content = f.read()
    with open(stage_file, 'r') as f:
        stages = json.load(f)

    stage_cards = build_stage_cards(stages)
    import base64
    b64_content = base64.b64encode(ai_content.encode('utf-8')).decode('utf-8')

    passed = sum(1 for s in stages if s['status'] == 'PASSED')
    failed = sum(1 for s in stages if s['status'] == 'FAILED')
    skipped = len(stages) - passed - failed

    if failed == 0 and passed == len(stages):
        posture_class = 'posture-good'
        posture_label = '🟢 SECURE'
    elif failed <= 1:
        posture_class = 'posture-warn'
        posture_label = '🟡 NEEDS ATTENTION'
    else:
        posture_class = 'posture-critical'
        posture_label = '🔴 AT RISK'

    html = HTML_TEMPLATE
    html = html.replace('__B64_CONTENT__', b64_content)
    html = html.replace('__STAGE_CARDS__', stage_cards)
    html = html.replace('__TIMESTAMP__', timestamp)
    html = html.replace('__PASSED__', str(passed))
    html = html.replace('__FAILED__', str(failed))
    html = html.replace('__SKIPPED__', str(skipped))
    html = html.replace('__POSTURE_CLASS__', posture_class)
    html = html.replace('__POSTURE_LABEL__', posture_label)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"✅ HTML report written to {output_file}")


def build_stage_cards(stages):
    cards = []
    for s in stages:
        name = s['name']
        status = s['status']
        detail = s.get('detail', '')
        if status == 'PASSED':
            icon, css = '✅', 'passed'
        elif status == 'FAILED':
            icon, css = '❌', 'failed'
        else:
            icon, css = '⏸️', 'skipped'
        cards.append(f'''<div class="stage-card {css}">
            <div class="stage-icon">{icon}</div>
            <div class="stage-name">{name}</div>
            <div class="stage-status-badge">{status}</div>
            <div class="stage-detail">{detail}</div>
        </div>''')
    return '\n'.join(cards)


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ AI Security Audit Report</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #6e7681;
    --accent-blue: #58a6ff;
    --accent-purple: #bc8cff;
    --accent-green: #3fb950;
    --accent-red: #f85149;
    --accent-orange: #d29922;
    --accent-cyan: #39d2c0;
    --gradient-1: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    --gradient-2: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
    --gradient-header: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1a1e2e 100%);
    --shadow-lg: 0 10px 40px rgba(0,0,0,0.4);
    --shadow-glow: 0 0 20px rgba(88,166,255,0.15);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.7;
    min-height: 100vh;
}

/* ── Header ─────────────────────────────────── */
.report-header {
    background: var(--gradient-header);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 2rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.report-header::before {
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(88,166,255,0.08) 0%, transparent 70%);
    pointer-events: none;
}
.report-header h1 {
    font-size: 2.2rem;
    font-weight: 800;
    background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple), var(--accent-cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
}
.report-meta {
    color: var(--text-secondary);
    font-size: 0.9rem;
    display: flex; gap: 2rem; justify-content: center; flex-wrap: wrap;
}
.report-meta span { display: flex; align-items: center; gap: 0.4rem; }

/* ── Posture Badge ──────────────────────────── */
.posture-badge {
    display: inline-flex; align-items: center; gap: 0.5rem;
    padding: 0.5rem 1.5rem; border-radius: 50px;
    font-weight: 700; font-size: 1.1rem;
    margin-top: 1rem;
}
.posture-good { background: rgba(63,185,80,0.15); color: var(--accent-green); border: 1px solid rgba(63,185,80,0.3); }
.posture-warn { background: rgba(210,153,34,0.15); color: var(--accent-orange); border: 1px solid rgba(210,153,34,0.3); }
.posture-critical { background: rgba(248,81,73,0.15); color: var(--accent-red); border: 1px solid rgba(248,81,73,0.3); animation: pulse-red 2s infinite; }
@keyframes pulse-red { 0%,100%{box-shadow:0 0 0 0 rgba(248,81,73,0.2)} 50%{box-shadow:0 0 20px 5px rgba(248,81,73,0.15)} }

/* ── Stage Dashboard ────────────────────────── */
.dashboard { padding: 2rem; max-width: 1200px; margin: 0 auto; }
.dashboard h2 {
    font-size: 1.3rem; font-weight: 700; margin-bottom: 1rem;
    color: var(--text-secondary);
    display: flex; align-items: center; gap: 0.5rem;
}
.stage-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
}
.stage-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem;
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
}
.stage-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-lg); }
.stage-card.passed { border-left: 4px solid var(--accent-green); }
.stage-card.failed { border-left: 4px solid var(--accent-red); }
.stage-card.skipped { border-left: 4px solid var(--text-muted); }
.stage-icon { font-size: 2rem; margin-bottom: 0.5rem; }
.stage-name { font-weight: 600; font-size: 0.95rem; margin-bottom: 0.3rem; }
.stage-status-badge {
    display: inline-block; padding: 0.15rem 0.8rem;
    border-radius: 50px; font-size: 0.75rem; font-weight: 700;
    letter-spacing: 0.05em;
}
.passed .stage-status-badge { background: rgba(63,185,80,0.15); color: var(--accent-green); }
.failed .stage-status-badge { background: rgba(248,81,73,0.15); color: var(--accent-red); }
.skipped .stage-status-badge { background: rgba(110,118,129,0.15); color: var(--text-muted); }
.stage-detail { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.3rem; }

/* ── Stats Bar ──────────────────────────────── */
.stats-bar {
    display: flex; gap: 1.5rem; justify-content: center;
    padding: 1rem 2rem; flex-wrap: wrap;
}
.stat {
    background: var(--bg-secondary); border: 1px solid var(--border);
    border-radius: 10px; padding: 0.8rem 1.5rem;
    text-align: center; min-width: 120px;
}
.stat-value { font-size: 1.8rem; font-weight: 800; }
.stat-label { font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }
.stat-passed .stat-value { color: var(--accent-green); }
.stat-failed .stat-value { color: var(--accent-red); }
.stat-skipped .stat-value { color: var(--text-muted); }

/* ── Report Content ─────────────────────────── */
.report-content {
    max-width: 960px; margin: 2rem auto; padding: 0 2rem;
}
.report-content h1 {
    font-size: 1.8rem; font-weight: 800; margin: 2.5rem 0 1rem;
    padding-bottom: 0.5rem; border-bottom: 2px solid var(--border);
    color: var(--accent-blue);
}
.report-content h2 {
    font-size: 1.4rem; font-weight: 700; margin: 2rem 0 0.8rem;
    color: var(--accent-purple);
}
.report-content h3 {
    font-size: 1.15rem; font-weight: 600; margin: 1.5rem 0 0.6rem;
    color: var(--accent-cyan);
}
.report-content p { margin: 0.6rem 0; color: var(--text-primary); }
.report-content ul, .report-content ol { padding-left: 1.5rem; margin: 0.5rem 0; }
.report-content li { margin: 0.3rem 0; }
.report-content strong { color: var(--accent-blue); }
.report-content em { color: var(--text-secondary); }
.report-content a { color: var(--accent-blue); text-decoration: underline; }

/* Code blocks */
.report-content pre {
    background: var(--bg-tertiary) !important;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    overflow-x: auto;
    margin: 1rem 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    line-height: 1.6;
}
.report-content code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85em;
}
.report-content p code, .report-content li code {
    background: var(--bg-tertiary);
    padding: 0.15em 0.4em;
    border-radius: 4px;
    color: var(--accent-cyan);
    font-size: 0.85em;
}

/* Tables */
.report-content table {
    width: 100%; border-collapse: collapse; margin: 1rem 0;
    background: var(--bg-secondary); border-radius: 8px; overflow: hidden;
}
.report-content th {
    background: var(--bg-tertiary); padding: 0.7rem 1rem;
    text-align: left; font-weight: 600; color: var(--accent-blue);
    border-bottom: 2px solid var(--border);
}
.report-content td {
    padding: 0.6rem 1rem; border-bottom: 1px solid var(--border);
}
.report-content tr:hover td { background: rgba(88,166,255,0.04); }

/* Blockquotes (used for callouts) */
.report-content blockquote {
    border-left: 4px solid var(--accent-orange);
    background: rgba(210,153,34,0.08);
    padding: 1rem 1.2rem; margin: 1rem 0;
    border-radius: 0 8px 8px 0;
}

/* Horizontal rules */
.report-content hr {
    border: none; height: 1px;
    background: linear-gradient(90deg, transparent, var(--border), transparent);
    margin: 2.5rem 0;
}

/* Mermaid diagrams */
.mermaid {
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin: 1rem 0;
    text-align: center;
}

/* ── Footer ─────────────────────────────────── */
.report-footer {
    text-align: center; padding: 2rem;
    border-top: 1px solid var(--border);
    color: var(--text-muted); font-size: 0.85rem;
    margin-top: 3rem;
}
.report-footer .badges { display: flex; gap: 0.8rem; justify-content: center; margin-top: 0.8rem; flex-wrap: wrap; }
.report-footer .badge {
    display: inline-flex; align-items: center; gap: 0.3rem;
    padding: 0.3rem 0.8rem; border-radius: 50px;
    background: var(--bg-secondary); border: 1px solid var(--border);
    font-size: 0.8rem;
}

/* ── Button ─────────────────────────────────── */
.pdf-btn {
    background: linear-gradient(90deg, #3fb950, #2ea043);
    border: none; border-radius: 8px; padding: 0.6rem 1.2rem;
    color: white; font-weight: 600; font-family: inherit;
    cursor: pointer; transition: transform 0.2s; margin-top: 1rem;
    box-shadow: 0 4px 15px rgba(63,185,80,0.2);
}
.pdf-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(63,185,80,0.3); }

/* ── Print Styles ───────────────────────────── */
@media print {
    body { background: #fff; color: #000; font-size: 11pt; }
    .report-header { background: #f0f0f0; border-bottom: 2px solid #ccc; padding: 1.5rem; }
    .report-header h1 { -webkit-text-fill-color: #000; background: none; }
    .report-content { max-width: 100%; padding: 0; }
    .stage-card, .stat { border: 1px solid #ccc; break-inside: avoid; }
    .pdf-btn { display: none !important; }
    pre { border: 1px solid #ddd; background: #f8f8f8 !important; white-space: pre-wrap; break-inside: avoid; }
    code { color: #000 !important; font-size: 10pt; }
    h1, h2, h3 { break-after: avoid; }
}

/* ── Responsive ─────────────────────────────── */
@media (max-width: 600px) {
    .report-header h1 { font-size: 1.5rem; }
    .report-content { padding: 0 1rem; }
    .stage-grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>

<!-- Header -->
<div class="report-header">
    <h1>🛡️ AI Cybersecurity Shield — Audit Report</h1>
    <div class="report-meta">
        <span>📅 __TIMESTAMP__</span>
        <span>🤖 Gemini 2.5 Pro</span>
        <span>🔒 Advisory Only — No Code Modified</span>
    </div>
    <button onclick="window.print()" class="pdf-btn">📄 Save as PDF</button>
    <div class="posture-badge __POSTURE_CLASS__">__POSTURE_LABEL__</div>
</div>

<!-- Stats -->
<div class="stats-bar">
    <div class="stat stat-passed"><div class="stat-value">__PASSED__</div><div class="stat-label">Passed</div></div>
    <div class="stat stat-failed"><div class="stat-value">__FAILED__</div><div class="stat-label">Failed</div></div>
    <div class="stat stat-skipped"><div class="stat-value">__SKIPPED__</div><div class="stat-label">Skipped</div></div>
</div>

<!-- Stage Dashboard -->
<div class="dashboard">
    <h2>📊 Pipeline Stage Status</h2>
    <div class="stage-grid">
        __STAGE_CARDS__
    </div>
</div>

<!-- AI Report Content (rendered from markdown) -->
<div class="report-content" id="report-content">
    <noscript>
        <p style="color:var(--accent-orange);">⚠️ JavaScript is required to render this report. Please enable JavaScript or open in a modern browser.</p>
    </noscript>
    <p style="color:var(--text-muted);">Loading report...</p>
</div>

<!-- Footer -->
<div class="report-footer">
    <p>🛡️ AI Cybersecurity Shield — Powered by Gemini 2.5 Pro</p>
    <div class="badges">
        <span class="badge">🚫 Advisor Only</span>
        <span class="badge">📋 Developer Review Required</span>
        <span class="badge">🔒 No Code Modified</span>
    </div>
</div>

<script>
// Securely decode base64 markdown
const base64Data = '__B64_CONTENT__';
const raw = window.atob(base64Data);
const bytes = new Uint8Array(raw.length);
for(let i = 0; i < raw.length; i++) { bytes[i] = raw.charCodeAt(i); }
const mdContent = new TextDecoder().decode(bytes);
try {
    // Configure marked
    const renderer = new marked.Renderer();

    // Custom code block renderer for mermaid support
    const origCode = renderer.code;
    renderer.code = function(code, lang) {
        // Handle both old and new marked.js API
        var codeText = typeof code === 'object' ? code.text : code;
        var codeLang = typeof code === 'object' ? code.lang : lang;
        if (codeLang === 'mermaid') {
            return '<div class="mermaid">' + codeText + '</div>';
        }
        return '<pre><code class="language-' + (codeLang||'') + '">' +
               codeText.replace(/</g,'&lt;').replace(/>/g,'&gt;') +
               '</code></pre>';
    };

    marked.setOptions({
        renderer: renderer,
        gfm: true,
        breaks: true
    });

    document.getElementById('report-content').innerHTML = marked.parse(mdContent);

    // Highlight code blocks
    document.querySelectorAll('pre code').forEach(function(block) {
        hljs.highlightElement(block);
    });

    // Initialize mermaid
    mermaid.initialize({
        startOnLoad: true,
        theme: 'dark',
        themeVariables: {
            primaryColor: '#58a6ff',
            primaryTextColor: '#e6edf3',
            primaryBorderColor: '#30363d',
            lineColor: '#8b949e',
            secondaryColor: '#161b22',
            tertiaryColor: '#21262d',
            background: '#161b22'
        }
    });
} catch(e) {
    // Fallback: show raw markdown
    document.getElementById('report-content').innerHTML =
        '<pre style="white-space:pre-wrap;word-wrap:break-word;">' +
        mdContent.replace(/</g,'&lt;').replace(/>/g,'&gt;') +
        '</pre>';
}
</script>

</body>
</html>'''


if __name__ == '__main__':
    main()
