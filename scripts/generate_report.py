#!/usr/bin/env python3
"""
generate_report.py - Generate a premium, FULLY SELF-CONTAINED HTML security audit report.
NO JavaScript required. NO CDN dependencies. ALL styling is inline.
Markdown is converted to HTML server-side using pure Python (no external libs).

Usage:
    python3 generate_report.py <content_file> <stage_file> <timestamp> <output_file>
"""

import sys
import json
import os
import re
import html as html_module


# ═══════════════════════════════════════════════════════════════════════════════
# Pure Python Markdown-to-HTML converter (no external dependencies)
# ═══════════════════════════════════════════════════════════════════════════════

def md_to_html(md_text):
    """Convert markdown to HTML using pure Python regex. Handles:
    - Headers (h1-h4)
    - Bold, italic, inline code
    - Code blocks (with language label)
    - Mermaid diagrams (rendered as styled boxes)
    - Tables
    - Unordered & ordered lists
    - Blockquotes
    - Horizontal rules
    - Links
    - Paragraphs
    """
    lines = md_text.split('\n')
    html_parts = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # ── Code blocks ───────────────────────────────────────────────
        if line.strip().startswith('```'):
            lang = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing ```
            code_text = html_module.escape('\n'.join(code_lines))

            if lang == 'mermaid':
                html_parts.append(
                    f'<div class="mermaid-box">'
                    f'<div class="mermaid-label">📊 Attack Flow Diagram</div>'
                    f'<pre class="mermaid-code">{code_text}</pre>'
                    f'</div>'
                )
            else:
                lang_label = f'<span class="code-lang">{html_module.escape(lang)}</span>' if lang else ''
                html_parts.append(
                    f'<div class="code-block">{lang_label}'
                    f'<pre><code>{code_text}</code></pre></div>'
                )
            continue

        # ── Tables ────────────────────────────────────────────────────
        if '|' in line and line.strip().startswith('|'):
            table_lines = []
            while i < len(lines) and '|' in lines[i] and lines[i].strip().startswith('|'):
                table_lines.append(lines[i])
                i += 1
            html_parts.append(_render_table(table_lines))
            continue

        # ── Horizontal rule ───────────────────────────────────────────
        if re.match(r'^---+\s*$', line.strip()):
            html_parts.append('<hr>')
            i += 1
            continue

        # ── Headers ───────────────────────────────────────────────────
        m = re.match(r'^(#{1,4})\s+(.+)$', line)
        if m:
            level = len(m.group(1))
            text = _inline_format(m.group(2))
            html_parts.append(f'<h{level}>{text}</h{level}>')
            i += 1
            continue

        # ── Blockquotes ───────────────────────────────────────────────
        if line.strip().startswith('>'):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith('>'):
                quote_lines.append(re.sub(r'^>\s*', '', lines[i]))
                i += 1
            quote_html = '<br>'.join(_inline_format(l) for l in quote_lines)
            html_parts.append(f'<blockquote>{quote_html}</blockquote>')
            continue

        # ── Unordered list ────────────────────────────────────────────
        if re.match(r'^[\s]*[-*]\s+', line):
            list_items = []
            while i < len(lines) and re.match(r'^[\s]*[-*]\s+', lines[i]):
                text = re.sub(r'^[\s]*[-*]\s+', '', lines[i])
                list_items.append(f'<li>{_inline_format(text)}</li>')
                i += 1
            html_parts.append(f'<ul>{"".join(list_items)}</ul>')
            continue

        # ── Ordered list ──────────────────────────────────────────────
        if re.match(r'^[\s]*\d+\.\s+', line):
            list_items = []
            while i < len(lines) and re.match(r'^[\s]*\d+\.\s+', lines[i]):
                text = re.sub(r'^[\s]*\d+\.\s+', '', lines[i])
                list_items.append(f'<li>{_inline_format(text)}</li>')
                i += 1
            html_parts.append(f'<ol>{"".join(list_items)}</ol>')
            continue

        # ── Blank line ────────────────────────────────────────────────
        if not line.strip():
            i += 1
            continue

        # ── Paragraph ─────────────────────────────────────────────────
        para_lines = []
        while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith('#') \
                and not lines[i].strip().startswith('```') and not lines[i].strip().startswith('|') \
                and not re.match(r'^---+\s*$', lines[i].strip()) \
                and not re.match(r'^[\s]*[-*]\s+', lines[i]) \
                and not re.match(r'^[\s]*\d+\.\s+', lines[i]) \
                and not lines[i].strip().startswith('>'):
            para_lines.append(lines[i])
            i += 1
        if para_lines:
            text = ' '.join(para_lines)
            html_parts.append(f'<p>{_inline_format(text)}</p>')
            continue

        i += 1

    return '\n'.join(html_parts)


def _inline_format(text):
    """Apply inline markdown formatting: bold, italic, code, links."""
    text = html_module.escape(text)
    # Inline code
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    # Bold + italic
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    # Links [text](url)
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
    # Restore emoji (html escape may break some)
    return text


def _render_table(lines):
    """Render a markdown table to HTML."""
    if len(lines) < 2:
        return ''

    def parse_row(line):
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        return cells

    headers = parse_row(lines[0])
    # Skip separator line (line[1])
    rows = [parse_row(l) for l in lines[2:]] if len(lines) > 2 else []

    thead = ''.join(f'<th>{_inline_format(h)}</th>' for h in headers)
    tbody_rows = []
    for row in rows:
        cells = ''.join(f'<td>{_inline_format(c)}</td>' for c in row)
        tbody_rows.append(f'<tr>{cells}</tr>')

    return (
        f'<div class="table-wrap"><table>'
        f'<thead><tr>{thead}</tr></thead>'
        f'<tbody>{"".join(tbody_rows)}</tbody>'
        f'</table></div>'
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Report Builder
# ═══════════════════════════════════════════════════════════════════════════════

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

    # Convert markdown to HTML server-side (no JS needed!)
    ai_html_content = md_to_html(ai_content) if ai_content.strip() else '<p class="no-data">⚠️ AI analysis was not generated. Check Gemini API key and model configuration.</p>'

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
    html = html.replace('__AI_CONTENT__', ai_html_content)
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
        name = html_module.escape(s['name'])
        status = s['status']
        detail = html_module.escape(s.get('detail', ''))
        if status == 'PASSED':
            icon, css, badge_bg, badge_color = '✅', 'passed', 'rgba(63,185,80,0.2)', '#3fb950'
        elif status == 'FAILED':
            icon, css, badge_bg, badge_color = '❌', 'failed', 'rgba(248,81,73,0.2)', '#f85149'
        else:
            icon, css, badge_bg, badge_color = '⏸️', 'skipped', 'rgba(110,118,129,0.2)', '#6e7681'

        border_color = badge_color
        cards.append(f'''<div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {border_color};border-radius:12px;padding:1.2rem;text-align:center;">
            <div style="font-size:2rem;margin-bottom:0.5rem;">{icon}</div>
            <div style="font-weight:600;font-size:0.95rem;color:#e6edf3;margin-bottom:0.3rem;">{name}</div>
            <div style="display:inline-block;padding:0.15rem 0.8rem;border-radius:50px;font-size:0.75rem;font-weight:700;letter-spacing:0.05em;background:{badge_bg};color:{badge_color};">{status}</div>
            <div style="font-size:0.8rem;color:#6e7681;margin-top:0.3rem;">{detail}</div>
        </div>''')
    return '\n'.join(cards)


# ═══════════════════════════════════════════════════════════════════════════════
# FULLY SELF-CONTAINED HTML TEMPLATE — Zero JS, Zero CDN, All Inline CSS
# ═══════════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Security Audit Report</title>
<style>
/* ── Reset & Base ───────────────────────────────── */
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:#0d1117;color:#e6edf3;line-height:1.7;min-height:100vh}

/* ── Header ─────────────────────────────────────── */
.header{background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#1a1e2e 100%);border-bottom:1px solid #30363d;padding:2.5rem 2rem;text-align:center;position:relative}
.header::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 50% 0%,rgba(88,166,255,0.08) 0%,transparent 70%);pointer-events:none}
.header h1{font-size:2.2rem;font-weight:800;background:linear-gradient(90deg,#58a6ff,#bc8cff,#39d2c0);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:0.5rem}
.meta{color:#8b949e;font-size:0.9rem;display:flex;gap:2rem;justify-content:center;flex-wrap:wrap}

/* ── Posture Badge ──────────────────────────────── */
.posture{display:inline-flex;align-items:center;gap:0.5rem;padding:0.5rem 1.5rem;border-radius:50px;font-weight:700;font-size:1.1rem;margin-top:1rem}
.posture-good{background:rgba(63,185,80,0.15);color:#3fb950;border:1px solid rgba(63,185,80,0.3)}
.posture-warn{background:rgba(210,153,34,0.15);color:#d29922;border:1px solid rgba(210,153,34,0.3)}
.posture-critical{background:rgba(248,81,73,0.15);color:#f85149;border:1px solid rgba(248,81,73,0.3)}

/* ── Stats Bar ──────────────────────────────────── */
.stats{display:flex;gap:1.5rem;justify-content:center;padding:1.5rem 2rem;flex-wrap:wrap}
.stat{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:0.8rem 1.5rem;text-align:center;min-width:120px}
.stat-val{font-size:1.8rem;font-weight:800}
.stat-lbl{font-size:0.8rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.05em}
.stat-p .stat-val{color:#3fb950} .stat-f .stat-val{color:#f85149} .stat-s .stat-val{color:#6e7681}

/* ── Stage Grid ─────────────────────────────────── */
.dashboard{padding:2rem;max-width:1200px;margin:0 auto}
.dashboard h2{font-size:1.3rem;font-weight:700;margin-bottom:1rem;color:#8b949e}
.stage-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}

/* ── Report Content ─────────────────────────────── */
.content{max-width:960px;margin:2rem auto;padding:0 2rem}
.content h1{font-size:1.8rem;font-weight:800;margin:2.5rem 0 1rem;padding-bottom:0.5rem;border-bottom:2px solid #30363d;color:#58a6ff}
.content h2{font-size:1.4rem;font-weight:700;margin:2rem 0 0.8rem;color:#bc8cff}
.content h3{font-size:1.15rem;font-weight:600;margin:1.5rem 0 0.6rem;color:#39d2c0}
.content h4{font-size:1rem;font-weight:600;margin:1.2rem 0 0.5rem;color:#d29922}
.content p{margin:0.6rem 0;color:#e6edf3}
.content ul,.content ol{padding-left:1.5rem;margin:0.5rem 0}
.content li{margin:0.3rem 0}
.content strong{color:#58a6ff}
.content em{color:#8b949e}
.content a{color:#58a6ff;text-decoration:underline}
.content code{font-family:'Courier New',Courier,monospace;font-size:0.85em;background:#21262d;padding:0.15em 0.4em;border-radius:4px;color:#39d2c0}
.content blockquote{border-left:4px solid #d29922;background:rgba(210,153,34,0.08);padding:1rem 1.2rem;margin:1rem 0;border-radius:0 8px 8px 0}
.content hr{border:none;height:1px;background:linear-gradient(90deg,transparent,#30363d,transparent);margin:2.5rem 0}

/* ── Code Blocks ────────────────────────────────── */
.code-block{position:relative;margin:1rem 0}
.code-block pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.2rem;overflow-x:auto;font-family:'Courier New',Courier,monospace;font-size:0.85rem;line-height:1.6;color:#e6edf3}
.code-block code{background:none;padding:0;color:#e6edf3;font-size:inherit}
.code-lang{position:absolute;top:0;right:0;background:#21262d;color:#8b949e;padding:0.2rem 0.6rem;border-radius:0 8px 0 8px;font-size:0.7rem;text-transform:uppercase;font-weight:600}

/* ── Mermaid Boxes ──────────────────────────────── */
.mermaid-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin:1rem 0;text-align:center}
.mermaid-label{color:#bc8cff;font-weight:700;margin-bottom:0.8rem;font-size:1rem}
.mermaid-code{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:1rem;text-align:left;font-family:'Courier New',monospace;font-size:0.8rem;color:#8b949e;white-space:pre-wrap}

/* ── Tables ─────────────────────────────────────── */
.table-wrap{overflow-x:auto;margin:1rem 0}
.content table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}
.content th{background:#21262d;padding:0.7rem 1rem;text-align:left;font-weight:600;color:#58a6ff;border-bottom:2px solid #30363d}
.content td{padding:0.6rem 1rem;border-bottom:1px solid #30363d;color:#e6edf3}
.content tr:hover td{background:rgba(88,166,255,0.04)}

/* ── No Data ────────────────────────────────────── */
.no-data{color:#d29922;font-size:1.1rem;padding:2rem;text-align:center;background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.3);border-radius:12px;margin:2rem 0}

/* ── Footer ─────────────────────────────────────── */
.footer{text-align:center;padding:2rem;border-top:1px solid #30363d;color:#6e7681;font-size:0.85rem;margin-top:3rem}
.badges{display:flex;gap:0.8rem;justify-content:center;margin-top:0.8rem;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:0.3rem;padding:0.3rem 0.8rem;border-radius:50px;background:#161b22;border:1px solid #30363d;font-size:0.8rem}

/* ── PDF Button ─────────────────────────────────── */
.pdf-btn{background:linear-gradient(90deg,#3fb950,#2ea043);border:none;border-radius:8px;padding:0.6rem 1.2rem;color:white;font-weight:600;font-family:inherit;cursor:pointer;margin-top:1rem;box-shadow:0 4px 15px rgba(63,185,80,0.2);font-size:0.9rem}

/* ── Print Styles ───────────────────────────────── */
@media print{
    body{background:#fff;color:#000;font-size:11pt}
    .header{background:#f0f0f0!important;border-bottom:2px solid #ccc;padding:1.5rem}
    .header h1{-webkit-text-fill-color:#000;background:none;color:#000}
    .content h1{color:#1a56db;border-bottom-color:#ccc}
    .content h2{color:#7c3aed}
    .content h3{color:#0891b2}
    .content strong{color:#1a56db}
    .content code{background:#f3f4f6;color:#111}
    .content p,.content li,.content td{color:#111}
    .content th{background:#e5e7eb;color:#111}
    .content table{border:1px solid #ccc}
    .content td{border-bottom:1px solid #e5e7eb}
    .code-block pre{background:#f8f9fa!important;border:1px solid #ddd;color:#111}
    .code-block code{color:#111}
    .stat,.stage-grid>div{border:1px solid #ccc}
    .pdf-btn{display:none!important}
    .mermaid-box{background:#f8f9fa;border-color:#ccc}
    .mermaid-code{background:#fff;color:#333}
    pre{white-space:pre-wrap;break-inside:avoid}
    h1,h2,h3{break-after:avoid}
}

@media(max-width:600px){
    .header h1{font-size:1.5rem}
    .content{padding:0 1rem}
    .stage-grid{grid-template-columns:1fr 1fr}
}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <h1>🛡️ AI Cybersecurity Shield — Audit Report</h1>
    <div class="meta">
        <span>📅 __TIMESTAMP__</span>
        <span>🤖 Gemini 1.5 Pro</span>
        <span>🔒 Advisory Only — No Code Modified</span>
    </div>
    <button onclick="window.print()" class="pdf-btn">📄 Save as PDF</button>
    <div class="posture __POSTURE_CLASS__">__POSTURE_LABEL__</div>
</div>

<!-- Stats -->
<div class="stats">
    <div class="stat stat-p"><div class="stat-val">__PASSED__</div><div class="stat-lbl">Passed</div></div>
    <div class="stat stat-f"><div class="stat-val">__FAILED__</div><div class="stat-lbl">Failed</div></div>
    <div class="stat stat-s"><div class="stat-val">__SKIPPED__</div><div class="stat-lbl">Skipped</div></div>
</div>

<!-- Stage Dashboard -->
<div class="dashboard">
    <h2>📊 Pipeline Stage Status</h2>
    <div class="stage-grid">
        __STAGE_CARDS__
    </div>
</div>

<!-- AI Report Content (pre-rendered HTML, no JS needed) -->
<div class="content">
__AI_CONTENT__
</div>

<!-- Footer -->
<div class="footer">
    <p>🛡️ AI Cybersecurity Shield — Powered by Gemini 1.5 Pro</p>
    <div class="badges">
        <span class="badge">🚫 Advisor Only</span>
        <span class="badge">📋 Developer Review Required</span>
        <span class="badge">🔒 No Code Modified</span>
    </div>
</div>

</body>
</html>'''


if __name__ == '__main__':
    main()
