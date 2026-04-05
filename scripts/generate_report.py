#!/usr/bin/env python3
"""
generate_report.py - Generate a premium, FULLY SELF-CONTAINED HTML security audit report.
ALL styling is INLINE on every element (no <style> blocks, no <script>, no CDN).
This bypasses Jenkins Content Security Policy completely.

Usage:
    python3 generate_report.py <content_file> <stage_file> <timestamp> <output_file>
"""

import sys
import json
import os
import re
import html as html_module


# ═══════════════════════════════════════════════════════════════════════════
# Pure Python Markdown-to-HTML (with inline styles on every element)
# ═══════════════════════════════════════════════════════════════════════════

# Color palette
C_BG = '#0d1117'
C_BG2 = '#161b22'
C_BG3 = '#21262d'
C_BORDER = '#30363d'
C_TEXT = '#e6edf3'
C_TEXT2 = '#8b949e'
C_MUTED = '#6e7681'
C_BLUE = '#58a6ff'
C_PURPLE = '#bc8cff'
C_GREEN = '#3fb950'
C_RED = '#f85149'
C_ORANGE = '#d29922'
C_CYAN = '#39d2c0'


def md_to_html(md_text):
    """Convert markdown to HTML with inline styles."""
    lines = md_text.split('\n')
    html_parts = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # ── Code blocks ───────────────────────────────
        if line.strip().startswith('```'):
            lang = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1
            code_text = html_module.escape('\n'.join(code_lines))

            if lang == 'mermaid':
                html_parts.append(
                    f'<div style="background:{C_BG2};border:1px solid {C_BORDER};border-radius:8px;padding:1.5rem;margin:1rem 0;text-align:center;">'
                    f'<div style="color:{C_PURPLE};font-weight:700;margin-bottom:0.8rem;font-size:1rem;">📊 Attack Flow Diagram</div>'
                    f'<pre style="background:{C_BG};border:1px solid {C_BG3};border-radius:6px;padding:1rem;text-align:left;font-family:monospace;font-size:0.8rem;color:{C_TEXT2};white-space:pre-wrap;overflow-x:auto;">{code_text}</pre>'
                    f'</div>'
                )
            else:
                lang_label = f'<span style="display:block;text-align:right;color:{C_TEXT2};font-size:0.7rem;text-transform:uppercase;font-weight:600;margin-bottom:0.3rem;">{html_module.escape(lang)}</span>' if lang else ''
                html_parts.append(
                    f'<div style="margin:1rem 0;">'
                    f'<pre style="background:{C_BG2};border:1px solid {C_BORDER};border-radius:8px;padding:1rem 1.2rem;overflow-x:auto;font-family:monospace;font-size:0.85rem;line-height:1.6;color:{C_TEXT};white-space:pre-wrap;">'
                    f'{lang_label}<code>{code_text}</code></pre></div>'
                )
            continue

        # ── Tables ────────────────────────────────────
        if '|' in line and line.strip().startswith('|'):
            table_lines = []
            while i < len(lines) and '|' in lines[i] and lines[i].strip().startswith('|'):
                table_lines.append(lines[i])
                i += 1
            html_parts.append(_render_table(table_lines))
            continue

        # ── Horizontal rule ───────────────────────────
        if re.match(r'^---+\s*$', line.strip()):
            html_parts.append(f'<hr style="border:none;height:1px;background:linear-gradient(90deg,transparent,{C_BORDER},transparent);margin:2.5rem 0;">')
            i += 1
            continue

        # ── Headers ───────────────────────────────────
        m = re.match(r'^(#{1,4})\s+(.+)$', line)
        if m:
            level = len(m.group(1))
            text = _inline_format(m.group(2))
            styles = {
                1: f'font-size:1.8rem;font-weight:800;margin:2.5rem 0 1rem;padding-bottom:0.5rem;border-bottom:2px solid {C_BORDER};color:{C_BLUE};',
                2: f'font-size:1.4rem;font-weight:700;margin:2rem 0 0.8rem;color:{C_PURPLE};',
                3: f'font-size:1.15rem;font-weight:600;margin:1.5rem 0 0.6rem;color:{C_CYAN};',
                4: f'font-size:1rem;font-weight:600;margin:1.2rem 0 0.5rem;color:{C_ORANGE};',
            }
            html_parts.append(f'<h{level} style="{styles[level]}">{text}</h{level}>')
            i += 1
            continue

        # ── Blockquotes ───────────────────────────────
        if line.strip().startswith('>'):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith('>'):
                quote_lines.append(re.sub(r'^>\s*', '', lines[i]))
                i += 1
            quote_html = '<br>'.join(_inline_format(l) for l in quote_lines)
            html_parts.append(f'<blockquote style="border-left:4px solid {C_ORANGE};background:rgba(210,153,34,0.08);padding:1rem 1.2rem;margin:1rem 0;border-radius:0 8px 8px 0;color:{C_TEXT};">{quote_html}</blockquote>')
            continue

        # ── Unordered list ────────────────────────────
        if re.match(r'^[\s]*[-*]\s+', line):
            list_items = []
            while i < len(lines) and re.match(r'^[\s]*[-*]\s+', lines[i]):
                text = re.sub(r'^[\s]*[-*]\s+', '', lines[i])
                list_items.append(f'<li style="margin:0.3rem 0;color:{C_TEXT};">{_inline_format(text)}</li>')
                i += 1
            html_parts.append(f'<ul style="padding-left:1.5rem;margin:0.5rem 0;">{"".join(list_items)}</ul>')
            continue

        # ── Ordered list ──────────────────────────────
        if re.match(r'^[\s]*\d+\.\s+', line):
            list_items = []
            while i < len(lines) and re.match(r'^[\s]*\d+\.\s+', lines[i]):
                text = re.sub(r'^[\s]*\d+\.\s+', '', lines[i])
                list_items.append(f'<li style="margin:0.3rem 0;color:{C_TEXT};">{_inline_format(text)}</li>')
                i += 1
            html_parts.append(f'<ol style="padding-left:1.5rem;margin:0.5rem 0;">{"".join(list_items)}</ol>')
            continue

        # ── Blank line ────────────────────────────────
        if not line.strip():
            i += 1
            continue

        # ── Paragraph ─────────────────────────────────
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
            html_parts.append(f'<p style="margin:0.6rem 0;color:{C_TEXT};line-height:1.7;">{_inline_format(text)}</p>')
            continue

        i += 1

    return '\n'.join(html_parts)


def _inline_format(text):
    """Apply inline markdown formatting with inline styles."""
    text = html_module.escape(text)
    # Inline code
    text = re.sub(r'`([^`]+)`', rf'<code style="font-family:monospace;font-size:0.85em;background:{C_BG3};padding:0.15em 0.4em;border-radius:4px;color:{C_CYAN};">\1</code>', text)
    # Bold + italic
    text = re.sub(r'\*\*\*(.+?)\*\*\*', rf'<strong style="color:{C_BLUE};"><em>\1</em></strong>', text)
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', rf'<strong style="color:{C_BLUE};">\1</strong>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', rf'<em style="color:{C_TEXT2};">\1</em>', text)
    # Links
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', rf'<a href="\2" target="_blank" style="color:{C_BLUE};text-decoration:underline;">\1</a>', text)
    return text


def _render_table(lines):
    """Render a markdown table to HTML with inline styles."""
    if len(lines) < 2:
        return ''

    def parse_row(line):
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        return cells

    headers = parse_row(lines[0])
    rows = [parse_row(l) for l in lines[2:]] if len(lines) > 2 else []

    thead = ''.join(f'<th style="background:{C_BG3};padding:0.7rem 1rem;text-align:left;font-weight:600;color:{C_BLUE};border-bottom:2px solid {C_BORDER};">{_inline_format(h)}</th>' for h in headers)
    tbody_rows = []
    for row in rows:
        cells = ''.join(f'<td style="padding:0.6rem 1rem;border-bottom:1px solid {C_BORDER};color:{C_TEXT};">{_inline_format(c)}</td>' for c in row)
        tbody_rows.append(f'<tr>{cells}</tr>')

    return (
        f'<div style="overflow-x:auto;margin:1rem 0;">'
        f'<table style="width:100%;border-collapse:collapse;background:{C_BG2};border-radius:8px;overflow:hidden;">'
        f'<thead><tr>{thead}</tr></thead>'
        f'<tbody>{"".join(tbody_rows)}</tbody>'
        f'</table></div>'
    )


# ═══════════════════════════════════════════════════════════════════════════
# Report Builder
# ═══════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 generate_report.py <content_file> <stage_file> <timestamp> <output>")
        sys.exit(1)

    content_file, stage_file, timestamp, output_file = sys.argv[1:5]

    with open(content_file, 'r', encoding='utf-8', errors='replace') as f:
        ai_content = f.read()
    with open(stage_file, 'r') as f:
        stages = json.load(f)

    # Convert markdown to HTML with inline styles
    if ai_content.strip():
        ai_html = md_to_html(ai_content)
    else:
        ai_html = f'<p style="color:{C_ORANGE};font-size:1.1rem;padding:2rem;text-align:center;background:rgba(210,153,34,0.08);border:1px solid rgba(210,153,34,0.3);border-radius:12px;margin:2rem 0;">⚠️ AI analysis was not generated. Check Gemini API key and model configuration.</p>'

    passed = sum(1 for s in stages if s['status'] == 'PASSED')
    failed = sum(1 for s in stages if s['status'] == 'FAILED')
    skipped = len(stages) - passed - failed

    if failed == 0 and passed == len(stages):
        posture_bg = 'rgba(63,185,80,0.15)'
        posture_color = C_GREEN
        posture_border = 'rgba(63,185,80,0.3)'
        posture_label = '🟢 SECURE'
    elif failed <= 1:
        posture_bg = 'rgba(210,153,34,0.15)'
        posture_color = C_ORANGE
        posture_border = 'rgba(210,153,34,0.3)'
        posture_label = '🟡 NEEDS ATTENTION'
    else:
        posture_bg = 'rgba(248,81,73,0.15)'
        posture_color = C_RED
        posture_border = 'rgba(248,81,73,0.3)'
        posture_label = '🔴 AT RISK'

    # Build stage cards with inline styles
    stage_cards = build_stage_cards(stages)

    # Build the entire HTML document
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Security Audit Report</title>
</head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:{C_BG};color:{C_TEXT};line-height:1.7;min-height:100vh;">

<!-- Header -->
<div style="background:linear-gradient(135deg,{C_BG} 0%,{C_BG2} 50%,#1a1e2e 100%);border-bottom:1px solid {C_BORDER};padding:2.5rem 2rem;text-align:center;">
    <h1 style="font-size:2.2rem;font-weight:800;background:linear-gradient(90deg,{C_BLUE},{C_PURPLE},{C_CYAN});-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin:0 0 0.5rem 0;">🛡️ AI Cybersecurity Shield — Audit Report</h1>
    <div style="color:{C_TEXT2};font-size:0.9rem;display:flex;gap:2rem;justify-content:center;flex-wrap:wrap;">
        <span>📅 {html_module.escape(timestamp)}</span>
        <span>🤖 Gemini 2.5 Flash</span>
        <span>🔒 Advisory Only — No Code Modified</span>
    </div>
    <button onclick="window.print()" style="background:linear-gradient(90deg,{C_GREEN},#2ea043);border:none;border-radius:8px;padding:0.6rem 1.2rem;color:white;font-weight:600;font-family:inherit;cursor:pointer;margin-top:1rem;box-shadow:0 4px 15px rgba(63,185,80,0.2);font-size:0.9rem;">📄 Save as PDF</button>
    <div style="display:inline-flex;align-items:center;gap:0.5rem;padding:0.5rem 1.5rem;border-radius:50px;font-weight:700;font-size:1.1rem;margin-top:1rem;margin-left:1rem;background:{posture_bg};color:{posture_color};border:1px solid {posture_border};">{posture_label}</div>
</div>

<!-- Stats -->
<div style="display:flex;gap:1.5rem;justify-content:center;padding:1.5rem 2rem;flex-wrap:wrap;">
    <div style="background:{C_BG2};border:1px solid {C_BORDER};border-radius:10px;padding:0.8rem 1.5rem;text-align:center;min-width:120px;">
        <div style="font-size:1.8rem;font-weight:800;color:{C_GREEN};">{passed}</div>
        <div style="font-size:0.8rem;color:{C_TEXT2};text-transform:uppercase;letter-spacing:0.05em;">Passed</div>
    </div>
    <div style="background:{C_BG2};border:1px solid {C_BORDER};border-radius:10px;padding:0.8rem 1.5rem;text-align:center;min-width:120px;">
        <div style="font-size:1.8rem;font-weight:800;color:{C_RED};">{failed}</div>
        <div style="font-size:0.8rem;color:{C_TEXT2};text-transform:uppercase;letter-spacing:0.05em;">Failed</div>
    </div>
    <div style="background:{C_BG2};border:1px solid {C_BORDER};border-radius:10px;padding:0.8rem 1.5rem;text-align:center;min-width:120px;">
        <div style="font-size:1.8rem;font-weight:800;color:{C_MUTED};">{skipped}</div>
        <div style="font-size:0.8rem;color:{C_TEXT2};text-transform:uppercase;letter-spacing:0.05em;">Skipped</div>
    </div>
</div>

<!-- Stage Dashboard -->
<div style="padding:2rem;max-width:1200px;margin:0 auto;">
    <h2 style="font-size:1.3rem;font-weight:700;margin-bottom:1rem;color:{C_TEXT2};">📊 Pipeline Stage Status</h2>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;">
        {stage_cards}
    </div>
</div>

<!-- AI Report Content -->
<div style="max-width:960px;margin:2rem auto;padding:0 2rem;">
{ai_html}
</div>

<!-- Footer -->
<div style="text-align:center;padding:2rem;border-top:1px solid {C_BORDER};color:{C_MUTED};font-size:0.85rem;margin-top:3rem;">
    <p>🛡️ AI Cybersecurity Shield — Powered by Gemini 2.5 Flash</p>
    <div style="display:flex;gap:0.8rem;justify-content:center;margin-top:0.8rem;flex-wrap:wrap;">
        <span style="display:inline-flex;align-items:center;gap:0.3rem;padding:0.3rem 0.8rem;border-radius:50px;background:{C_BG2};border:1px solid {C_BORDER};font-size:0.8rem;">🚫 Advisor Only</span>
        <span style="display:inline-flex;align-items:center;gap:0.3rem;padding:0.3rem 0.8rem;border-radius:50px;background:{C_BG2};border:1px solid {C_BORDER};font-size:0.8rem;">📋 Developer Review Required</span>
        <span style="display:inline-flex;align-items:center;gap:0.3rem;padding:0.3rem 0.8rem;border-radius:50px;background:{C_BG2};border:1px solid {C_BORDER};font-size:0.8rem;">🔒 No Code Modified</span>
    </div>
</div>

</body>
</html>'''

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
            icon = '✅'
            badge_bg = 'rgba(63,185,80,0.2)'
            badge_color = C_GREEN
            border_color = C_GREEN
        elif status == 'FAILED':
            icon = '❌'
            badge_bg = 'rgba(248,81,73,0.2)'
            badge_color = C_RED
            border_color = C_RED
        else:
            icon = '⏸️'
            badge_bg = 'rgba(110,118,129,0.2)'
            badge_color = C_MUTED
            border_color = C_MUTED

        cards.append(f'''<div style="background:{C_BG2};border:1px solid {C_BORDER};border-left:4px solid {border_color};border-radius:12px;padding:1.2rem;text-align:center;">
            <div style="font-size:2rem;margin-bottom:0.5rem;">{icon}</div>
            <div style="font-weight:600;font-size:0.95rem;color:{C_TEXT};margin-bottom:0.3rem;">{name}</div>
            <div style="display:inline-block;padding:0.15rem 0.8rem;border-radius:50px;font-size:0.75rem;font-weight:700;letter-spacing:0.05em;background:{badge_bg};color:{badge_color};">{status}</div>
            <div style="font-size:0.8rem;color:{C_MUTED};margin-top:0.3rem;">{detail}</div>
        </div>''')
    return '\n'.join(cards)


if __name__ == '__main__':
    main()
