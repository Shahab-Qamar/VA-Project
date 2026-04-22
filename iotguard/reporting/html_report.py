"""
HTML report — professional vulnerability assessment report with:
  - Executive summary with risk metrics
  - Attack surface overview
  - Per-device findings with CVSS, CVEs, exploit availability
  - Services inventory table
  - Remediation priority matrix
  - OWASP IoT Top 10 heatmap
"""

from __future__ import annotations

import html
from collections import defaultdict
from pathlib import Path

from ..core.models import ScanResult, RiskLevel, Device


def write_html_report(scan: ScanResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_build_html(scan), encoding="utf-8")
    return path


# ──────────────────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────────────────

_CSS = """
:root {
  --bg: #f1f5f9; --panel: #fff; --border: #e2e8f0; --ink: #0f172a; --muted: #64748b;
  --info: #64748b; --low: #16a34a; --med: #d97706; --high: #dc2626; --crit: #7f1d1d;
  --crit-bg: #fee2e2; --high-bg: #fef2f2; --med-bg: #fffbeb; --low-bg: #f0fdf4;
  --accent: #1d4ed8; --accent-light: #dbeafe;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
       background: var(--bg); color: var(--ink); font-size: 13px; line-height: 1.6; }
a { color: var(--accent); }
.wrap { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }

/* Header */
.report-header { background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
  color: white; padding: 36px 40px; border-radius: 16px; margin-bottom: 28px; }
.report-header h1 { font-size: 28px; font-weight: 800; letter-spacing: -.02em; margin-bottom: 4px; }
.report-header .sub { opacity: .7; font-size: 13px; }
.report-header .meta-grid { display: grid; grid-template-columns: repeat(4,1fr);
  gap: 16px; margin-top: 24px; }
.meta-item { background: rgba(255,255,255,.08); border-radius: 10px; padding: 12px 16px; }
.meta-item .label { font-size: 10px; text-transform: uppercase; letter-spacing: .08em;
  opacity: .6; margin-bottom: 4px; }
.meta-item .value { font-size: 18px; font-weight: 700; }

/* Risk summary */
.risk-grid { display: grid; grid-template-columns: repeat(5,1fr); gap: 12px; margin-bottom: 24px; }
.risk-card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 16px; text-align: center; border-top: 4px solid; }
.risk-card.Critical { border-top-color: var(--crit); }
.risk-card.High     { border-top-color: var(--high); }
.risk-card.Medium   { border-top-color: var(--med); }
.risk-card.Low      { border-top-color: var(--low); }
.risk-card.Info     { border-top-color: var(--info); }
.risk-card .num { font-size: 32px; font-weight: 800; }
.risk-card .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }

/* Risk bar */
.risk-bar { height: 12px; border-radius: 999px; background: #e2e8f0;
  overflow: hidden; display: flex; margin: 12px 0; }
.risk-bar span { display: block; height: 100%; transition: width .3s; }

/* Section */
h2 { font-size: 17px; font-weight: 700; margin: 32px 0 14px;
  padding-bottom: 8px; border-bottom: 2px solid var(--border); color: var(--ink); }
h3 { font-size: 14px; font-weight: 600; color: var(--ink); margin: 20px 0 8px; }

/* Panel */
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 20px; margin-bottom: 16px; }

/* Table */
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border-radius: 12px; overflow: hidden; }
th { background: #f8fafc; padding: 10px 12px; text-align: left; font-size: 11px;
  text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
  border-bottom: 1px solid var(--border); font-weight: 600; }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
tr:hover td { background: #f8fafc; }
.mono { font-family: ui-monospace, Menlo, monospace; font-size: 11px; }

/* Badges */
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 10px;
  font-weight: 700; color: #fff; letter-spacing: .04em; white-space: nowrap; }
.badge-Critical { background: var(--crit); }
.badge-High     { background: var(--high); }
.badge-Medium   { background: #d97706; }
.badge-Low      { background: var(--low); }
.badge-Info     { background: var(--info); }

/* Finding cards */
.finding { border-left: 4px solid; border-radius: 0 10px 10px 0;
  padding: 12px 16px; margin: 8px 0; }
.finding.Critical { border-color: var(--crit); background: var(--crit-bg); }
.finding.High     { border-color: var(--high); background: var(--high-bg); }
.finding.Medium   { border-color: var(--med); background: var(--med-bg); }
.finding.Low      { border-color: var(--low); background: var(--low-bg); }
.finding.Info     { border-color: var(--info); background: #f8fafc; }
.finding-title { font-weight: 700; font-size: 13px; margin-bottom: 6px; display: flex;
  align-items: center; gap: 8px; flex-wrap: wrap; }
.finding p { font-size: 12px; color: #374151; margin: 4px 0; }
.finding .remed { background: rgba(255,255,255,.6); border-radius: 6px;
  padding: 6px 10px; margin-top: 6px; font-size: 12px; }
.finding .remed strong { color: var(--ink); }
.chip { display: inline-block; padding: 1px 8px; border: 1px solid var(--border);
  border-radius: 999px; font-size: 10px; color: var(--muted); margin-right: 3px; background: white; }
.exploit-chip { background: #fef2f2; border-color: var(--high); color: var(--high); font-weight: 700; }

/* Device section */
.device-header { display: flex; align-items: center; gap: 12px; margin: 24px 0 8px;
  padding: 14px 16px; background: var(--panel); border: 1px solid var(--border);
  border-radius: 10px; border-left: 5px solid; }
.device-header.Critical { border-left-color: var(--crit); }
.device-header.High     { border-left-color: var(--high); }
.device-header.Medium   { border-left-color: var(--med); }
.device-header.Low      { border-left-color: var(--low); }
.device-header.Info     { border-left-color: var(--info); }
.device-name { font-weight: 700; font-size: 15px; }
.device-meta { font-size: 11px; color: var(--muted); margin-top: 2px; }

/* OWASP heatmap */
.owasp-grid { display: grid; grid-template-columns: repeat(5,1fr); gap: 8px; }
.owasp-cell { padding: 10px; border-radius: 8px; text-align: center; border: 1px solid var(--border); }
.owasp-cell .code { font-size: 16px; font-weight: 800; }
.owasp-cell .cnt { font-size: 11px; color: var(--muted); }
.owasp-cell .title-s { font-size: 9px; color: var(--muted); margin-top: 2px; line-height: 1.3; }
.owasp-hit { background: #fef2f2; border-color: var(--high); }
.owasp-hit .code { color: var(--high); }

/* Remediation matrix */
.remed-table td:first-child { font-weight: 600; width: 120px; }

/* TOC */
.toc { background: var(--accent-light); border: 1px solid #93c5fd; border-radius: 10px;
  padding: 16px 20px; margin-bottom: 24px; }
.toc h3 { color: var(--accent); margin: 0 0 8px; font-size: 13px; }
.toc a { color: var(--accent); text-decoration: none; margin-right: 16px;
  font-size: 12px; font-weight: 500; }
.toc a:hover { text-decoration: underline; }

.footer { text-align: center; color: var(--muted); font-size: 11px;
  margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); }
.demo-banner { background: #eff6ff; border: 1px solid #93c5fd; border-radius: 8px;
  padding: 10px 14px; margin-bottom: 16px; color: #1e40af; font-size: 12px; }
.lab-banner { background: #fff7ed; border: 1px solid #fdba74; border-radius: 8px;
  padding: 10px 14px; margin-bottom: 16px; color: #9a3412; font-size: 12px; }
"""


def _badge(risk: str) -> str:
    return f'<span class="badge badge-{html.escape(risk)}">{html.escape(risk)}</span>'


def _build_html(scan: ScanResult) -> str:
    sm = scan.summary()
    risk_counts = sm["risk_counts"]
    total_findings = sm["total_findings"]
    all_findings = [f for d in scan.devices for f in d.findings] + \
                   [f for w in scan.wifi_networks for f in w.findings]

    # Collect all open ports across all devices
    all_ports = [(d, p) for d in scan.devices for p in d.open_ports]

    # OWASP category counts
    owasp_counts: dict[str, int] = defaultdict(int)
    for f in all_findings:
        if f.owasp_iot:
            code = f.owasp_iot.split(" - ")[0]
            owasp_counts[code] += 1

    # Exploit count
    exploit_count = sum(1 for f in all_findings if f.cve_ids)

    started = scan.started_at[:19].replace("T", " ")
    finished = scan.finished_at[:19].replace("T", " ") if scan.finished_at else "—"

    # Risk bar widths
    total_risk_items = max(sum(risk_counts.values()), 1)

    def _bar_width(key):
        return f"{100 * risk_counts.get(key, 0) / total_risk_items:.1f}%"

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IoTGuard Vulnerability Assessment Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
"""

    # ── Banners ──────────────────────────────────────────────────────────────
    if scan.demo_mode:
        html_out += '<div class="demo-banner">⚠️ <strong>Demo Mode</strong> — This report contains simulated data for demonstration purposes.</div>\n'
    if scan.lab_mode:
        html_out += '<div class="lab-banner">🔬 <strong>Lab Mode</strong> — Active credential testing was performed. Only run against devices you own or have written permission to test.</div>\n'

    # ── Header ───────────────────────────────────────────────────────────────
    html_out += f"""
<div class="report-header">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
    <span style="font-size:28px">🛡️</span>
    <h1>IoTGuard Security Assessment</h1>
  </div>
  <div class="sub">IoT &amp; WiFi Vulnerability Assessment Report</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="label">Interface</div><div class="value">{html.escape(scan.interface or "—")}</div></div>
    <div class="meta-item"><div class="label">Subnet</div><div class="value">{html.escape(scan.subnet or "—")}</div></div>
    <div class="meta-item"><div class="label">Started</div><div class="value" style="font-size:13px">{html.escape(started)}</div></div>
    <div class="meta-item"><div class="label">Completed</div><div class="value" style="font-size:13px">{html.escape(finished)}</div></div>
  </div>
</div>
"""

    # ── TOC ──────────────────────────────────────────────────────────────────
    html_out += """<div class="toc">
  <h3>📋 Contents</h3>
  <a href="#executive">Executive Summary</a>
  <a href="#devices">Devices</a>
  <a href="#wifi">WiFi Networks</a>
  <a href="#services">Services Inventory</a>
  <a href="#findings">Findings Detail</a>
  <a href="#owasp">OWASP IoT Top 10</a>
  <a href="#remediation">Remediation Plan</a>
</div>
"""

    # ── Executive Summary ────────────────────────────────────────────────────
    html_out += f'<h2 id="executive">📊 Executive Summary</h2>\n'
    html_out += '<div class="risk-grid">\n'
    for risk_name, color_class in [("Critical","Critical"),("High","High"),
                                    ("Medium","Medium"),("Low","Low"),("Info","Info")]:
        count = risk_counts.get(risk_name, 0)
        html_out += f'''<div class="risk-card {color_class}">
  <div class="num">{count}</div>
  <div class="lbl">{risk_name}</div>
</div>\n'''
    html_out += '</div>\n'

    # Summary stat row
    html_out += f"""<div class="panel" style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;text-align:center">
  <div><div style="font-size:28px;font-weight:800;color:#1d4ed8">{sm['device_count']}</div><div style="color:#64748b;font-size:11px;text-transform:uppercase">Devices Found</div></div>
  <div><div style="font-size:28px;font-weight:800;color:#1d4ed8">{sm['wifi_count']}</div><div style="color:#64748b;font-size:11px;text-transform:uppercase">WiFi Networks</div></div>
  <div><div style="font-size:28px;font-weight:800;color:{'#dc2626' if total_findings > 0 else '#16a34a'}">{total_findings}</div><div style="color:#64748b;font-size:11px;text-transform:uppercase">Total Findings</div></div>
  <div><div style="font-size:28px;font-weight:800;color:{'#dc2626' if exploit_count > 0 else '#16a34a'}">{exploit_count}</div><div style="color:#64748b;font-size:11px;text-transform:uppercase">With CVEs</div></div>
</div>
"""

    # Risk distribution bar
    html_out += '<div class="panel"><strong>Risk Distribution</strong><div class="risk-bar">'
    for rname, col in [("Critical","#7f1d1d"),("High","#dc2626"),("Medium","#d97706"),("Low","#16a34a"),("Info","#94a3b8")]:
        html_out += f'<span style="width:{_bar_width(rname)};background:{col}" title="{rname}: {risk_counts.get(rname,0)}"></span>'
    html_out += '</div></div>\n'

    # ── Devices Table ─────────────────────────────────────────────────────────
    html_out += f'<h2 id="devices">🖥️ Discovered Devices ({len(scan.devices)})</h2>\n'
    html_out += """<table>
<thead><tr>
  <th>Risk</th><th>Name / Hostname</th><th>IP Address</th><th>MAC / Vendor</th>
  <th>Type</th><th>OS</th><th>Open Ports</th><th>Findings</th><th>Discovery</th>
</tr></thead><tbody>
"""
    for d in sorted(scan.devices, key=lambda x: -x.highest_risk.order):
        ports_str = ", ".join(str(p.port) for p in d.open_ports[:8])
        if len(d.open_ports) > 8:
            ports_str += f" +{len(d.open_ports)-8} more"
        sources = ", ".join(s.value for s in d.discovery_sources)
        html_out += f"""<tr>
  <td>{_badge(d.highest_risk.value)}</td>
  <td><strong>{html.escape(d.display_name)}</strong></td>
  <td class="mono">{html.escape(d.ip or "—")}</td>
  <td class="mono" style="font-size:10px">{html.escape(d.mac or "")}<br><span style="color:#64748b">{html.escape(d.vendor or "")}</span></td>
  <td>{html.escape(d.device_type.value)}</td>
  <td style="font-size:10px">{html.escape(d.os_guess or "—")}</td>
  <td class="mono" style="font-size:10px">{html.escape(ports_str or "—")}</td>
  <td style="text-align:center">{len(d.findings) if d.findings else "—"}</td>
  <td style="font-size:10px;color:#64748b">{html.escape(sources)}</td>
</tr>
"""
    html_out += "</tbody></table>\n"

    # ── WiFi Networks ─────────────────────────────────────────────────────────
    if scan.wifi_networks:
        html_out += f'<h2 id="wifi">📶 WiFi Networks ({len(scan.wifi_networks)})</h2>\n'
        html_out += """<table><thead><tr>
  <th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th>
  <th>Encryption</th><th>Risk</th><th>Flags</th>
</tr></thead><tbody>
"""
        for w in scan.wifi_networks:
            flags = []
            if w.hidden: flags.append("Hidden")
            if w.rogue_suspected: flags.append("⚠ Rogue AP")
            if w.wps_enabled: flags.append("WPS")
            worst_risk = max(w.findings, key=lambda f: f.risk.order).risk.value if w.findings else "Info"
            html_out += f"""<tr>
  <td><strong>{html.escape(w.ssid or '<hidden>')}</strong></td>
  <td class="mono" style="font-size:10px">{html.escape(w.bssid)}</td>
  <td>{w.channel}</td>
  <td>{w.signal_dbm} dBm <span style="color:#64748b">({w.signal_quality})</span></td>
  <td><strong>{html.escape(w.encryption.value)}</strong></td>
  <td>{_badge(worst_risk)}</td>
  <td style="font-size:10px;color:#dc2626">{html.escape(", ".join(flags))}</td>
</tr>
"""
        html_out += "</tbody></table>\n"

    # ── Services Inventory ────────────────────────────────────────────────────
    if all_ports:
        html_out += f'<h2 id="services">🔌 Services Inventory ({len(all_ports)} open ports)</h2>\n'
        html_out += """<table><thead><tr>
  <th>Device</th><th>IP</th><th>Port</th><th>Protocol</th>
  <th>Service</th><th>Product / Version</th><th>Banner</th>
</tr></thead><tbody>
"""
        for d, p in sorted(all_ports, key=lambda x: (x[0].ip, x[1].port)):
            html_out += f"""<tr>
  <td>{html.escape(d.display_name)}</td>
  <td class="mono">{html.escape(d.ip or "")}</td>
  <td class="mono"><strong>{p.port}</strong></td>
  <td class="mono">{html.escape(p.protocol)}</td>
  <td>{html.escape(p.service or "—")}</td>
  <td style="font-size:11px">{html.escape(f"{p.product} {p.version}".strip() or "—")}</td>
  <td class="mono" style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
      title="{html.escape(p.banner or '')}">{html.escape((p.banner or "")[:60])}</td>
</tr>
"""
        html_out += "</tbody></table>\n"

    # ── Detailed Findings ─────────────────────────────────────────────────────
    html_out += f'<h2 id="findings">🔍 Detailed Findings</h2>\n'

    # Group by device
    devices_with_findings = [d for d in scan.devices if d.findings]
    devices_with_findings.sort(key=lambda d: -d.highest_risk.order)

    for d in devices_with_findings:
        risk = d.highest_risk.value
        ports_list = ", ".join(str(p.port) for p in d.open_ports[:10])
        vendor_info = f" · {d.vendor}" if d.vendor else ""
        os_info = f" · {d.os_guess}" if d.os_guess else ""
        html_out += f"""<div class="device-header {html.escape(risk)}">
  <div>
    <div class="device-name">{_badge(risk)} &nbsp;{html.escape(d.display_name)}</div>
    <div class="device-meta">{html.escape(d.ip or d.mac or "")}{html.escape(vendor_info)}{html.escape(os_info)}</div>
    {f'<div class="device-meta">Open ports: <span class="mono">{html.escape(ports_list)}</span></div>' if ports_list else ''}
  </div>
</div>
"""
        for f in sorted(d.findings, key=lambda x: -x.risk.order):
            cve_chips = "".join(
                f'<span class="chip exploit-chip">{html.escape(c)}</span>'
                for c in f.cve_ids
            )
            owasp_chip = f'<span class="chip">{html.escape(f.owasp_iot)}</span>' if f.owasp_iot else ""
            cvss_chip = f'<span class="chip">CVSS {f.cvss_score:.1f}</span>' if f.cvss_score else ""
            has_exploit = bool(f.cve_ids)
            exploit_flag = '<span class="chip exploit-chip">⚡ Exploit Available</span>' if has_exploit else ""

            html_out += f"""<div class="finding {html.escape(f.risk.value)}">
  <div class="finding-title">
    {_badge(f.risk.value)}
    {html.escape(f.title)}
    {exploit_flag}
  </div>
  <div>{cvss_chip}{owasp_chip}{cve_chips}</div>
  <p>{html.escape(f.description)}</p>
  {f'<p style="font-size:11px;color:#64748b;font-family:monospace">Target: {html.escape(f.target)}</p>' if f.target else ''}
  {f'<p style="font-size:11px;color:#64748b;font-family:monospace">Evidence: {html.escape(f.evidence[:200])}</p>' if f.evidence else ''}
  <div class="remed"><strong>Remediation:</strong> {html.escape(f.remediation)}</div>
</div>
"""

    # WiFi findings
    wifi_findings = [f for w in scan.wifi_networks for f in w.findings]
    if wifi_findings:
        html_out += '<div class="device-header Medium"><div><div class="device-name">📶 WiFi Findings</div></div></div>\n'
        for f in sorted(wifi_findings, key=lambda x: -x.risk.order):
            html_out += f"""<div class="finding {html.escape(f.risk.value)}">
  <div class="finding-title">{_badge(f.risk.value)} {html.escape(f.title)}</div>
  <p>{html.escape(f.description)}</p>
  <div class="remed"><strong>Remediation:</strong> {html.escape(f.remediation)}</div>
</div>
"""

    # ── OWASP IoT Top 10 Heatmap ──────────────────────────────────────────────
    html_out += '<h2 id="owasp">🔐 OWASP IoT Top 10 Coverage</h2>\n'
    html_out += '<div class="owasp-grid">\n'
    OWASP_TITLES = {
        "I1": "Weak Passwords", "I2": "Insecure Network Services",
        "I3": "Insecure Ecosystem Interfaces", "I4": "Lack of Secure Update",
        "I5": "Insecure Components", "I6": "Insufficient Privacy",
        "I7": "Insecure Data Transfer", "I8": "Lack of Device Mgmt",
        "I9": "Insecure Default Settings", "I10": "Lack of Physical Hardening",
    }
    for code, title in OWASP_TITLES.items():
        count = owasp_counts.get(code, 0)
        css_class = "owasp-cell owasp-hit" if count > 0 else "owasp-cell"
        html_out += f"""<div class="{css_class}">
  <div class="code">{code}</div>
  <div class="cnt">{"⚠ " + str(count) + " finding" + ("s" if count != 1 else "") if count else "✓ Clear"}</div>
  <div class="title-s">{html.escape(title)}</div>
</div>
"""
    html_out += '</div>\n'

    # ── Remediation Priority Matrix ───────────────────────────────────────────
    html_out += '<h2 id="remediation">🔧 Remediation Priority Matrix</h2>\n'
    html_out += '<table><thead><tr><th>Priority</th><th>Finding</th><th>Device(s)</th><th>CVSS</th><th>CVEs</th><th>Action</th></tr></thead><tbody>\n'
    priority_findings = sorted(all_findings, key=lambda f: (-f.cvss_score, -f.risk.order))[:20]
    for i, f in enumerate(priority_findings, 1):
        cves = ", ".join(f.cve_ids) if f.cve_ids else "—"
        html_out += f"""<tr>
  <td style="text-align:center;font-weight:800;font-size:16px">{i}</td>
  <td>{_badge(f.risk.value)} {html.escape(f.title)}</td>
  <td class="mono" style="font-size:10px">{html.escape(f.target)}</td>
  <td><strong>{f.cvss_score:.1f}</strong></td>
  <td class="mono" style="font-size:10px">{html.escape(cves)}</td>
  <td style="font-size:11px">{html.escape(f.remediation[:100])}</td>
</tr>
"""
    html_out += '</tbody></table>\n'

    # ── Footer ────────────────────────────────────────────────────────────────
    html_out += f"""<div class="footer">
  Generated by <strong>IoTGuard v1.1</strong> — BS Cybersecurity, Riphah International University<br>
  Scan ID: {html.escape(scan.scan_id)} &nbsp;|&nbsp; {html.escape(started)}
</div>
</div></body></html>
"""
    return html_out
