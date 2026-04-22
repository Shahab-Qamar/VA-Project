"""
Module 6 — Report Generator
Produces a professional HTML dashboard and JSON export.
"""

import json
import os
from datetime import datetime
from typing import Dict


SEVERITY_COLOURS = {
    "CRITICAL": ("#c0392b", "#fdecea"),
    "HIGH":     ("#e67e22", "#fef5ec"),
    "MEDIUM":   ("#f39c12", "#fefce8"),
    "LOW":      ("#27ae60", "#eafaf1"),
    "UNKNOWN":  ("#7f8c8d", "#f2f3f4"),
}

RISK_LABEL = {
    (70, 101): ("Critical",  "#c0392b"),
    (40,  70): ("High",      "#e67e22"),
    (20,  40): ("Medium",    "#f39c12"),
    ( 0,  20): ("Low",       "#27ae60"),
}


def risk_label(score: int):
    for (lo, hi), (label, colour) in RISK_LABEL.items():
        if lo <= score < hi:
            return label, colour
    return "Low", "#27ae60"


class ReportGenerator:
    def __init__(self, output_dir: str = "output", log=None):
        self.output_dir = output_dir
        self.log        = log
        os.makedirs(output_dir, exist_ok=True)

    # ── JSON Export ────────────────────────────────────────────

    def json_export(self, devices: Dict, timestamp: str) -> str:
        path = os.path.join(self.output_dir, f"iot_scan_{timestamp}.json")
        export = {
            "scan_meta": {
                "generated":    datetime.now().isoformat(),
                "tool":         "IoT Security Toolkit",
                "total_devices": len(devices),
                "total_cves":   sum(len(d["cves"]) for d in devices.values()),
                "total_default_creds": sum(len(d["credentials"]) for d in devices.values()),
            },
            "devices": list(devices.values()),
        }
        with open(path, "w") as f:
            json.dump(export, f, indent=2, default=str)
        return path

    # ── HTML Report ────────────────────────────────────────────

    def html(self, devices: Dict, timestamp: str) -> str:
        path = os.path.join(self.output_dir, f"iot_scan_{timestamp}.html")
        html = self._build_html(devices)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _build_html(self, devices: Dict) -> str:
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total  = len(devices)
        t_cves = sum(len(d["cves"]) for d in devices.values())
        t_cred = sum(len(d["credentials"]) for d in devices.values())
        crits  = sum(1 for d in devices.values() if d["risk_score"] >= 70)

        # Risk distribution for chart
        risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for d in devices.values():
            label, _ = risk_label(d["risk_score"])
            risk_dist[label] += 1

        device_cards = "\n".join(self._device_card(d) for d in devices.values())

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IoT Security Scan Report — {now}</title>
<style>
  :root {{
    --bg: #f0f2f5; --surface: #ffffff; --text: #2c3e50;
    --muted: #6c757d; --border: #dee2e6; --radius: 10px;
    --critical: #c0392b; --high: #e67e22;
    --medium: #f39c12; --low: #27ae60;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }}
  header {{ background: #1a1a2e; color: #fff; padding: 28px 40px; display: flex;
            justify-content: space-between; align-items: center; }}
  header h1 {{ font-size: 22px; font-weight: 600; }}
  header .meta {{ font-size: 12px; color: #aaa; text-align: right; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 28px 24px; }}

  /* Summary cards */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
              gap: 16px; margin-bottom: 28px; }}
  .stat-card {{ background: var(--surface); border-radius: var(--radius);
                border: 1px solid var(--border); padding: 20px;
                text-align: center; }}
  .stat-card .num {{ font-size: 36px; font-weight: 700; margin-bottom: 4px; }}
  .stat-card .lbl {{ font-size: 12px; color: var(--muted); text-transform: uppercase;
                     letter-spacing: .5px; }}
  .c-red    {{ color: var(--critical); }}
  .c-orange {{ color: var(--high); }}
  .c-blue   {{ color: #2980b9; }}
  .c-green  {{ color: var(--low); }}

  /* Section headings */
  .section-title {{ font-size: 16px; font-weight: 600; margin: 28px 0 14px;
                    padding-bottom: 8px; border-bottom: 2px solid var(--border); }}

  /* Device cards */
  .device-card {{ background: var(--surface); border-radius: var(--radius);
                  border: 1px solid var(--border); margin-bottom: 20px;
                  overflow: hidden; }}
  .device-header {{ display: flex; align-items: center; gap: 16px;
                    padding: 16px 20px; border-bottom: 1px solid var(--border);
                    background: #fafbfc; cursor: pointer; user-select: none; }}
  .device-header:hover {{ background: #f0f0f0; }}
  .risk-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px;
                 font-weight: 600; color: #fff; white-space: nowrap; }}
  .device-ip   {{ font-weight: 600; font-size: 16px; }}
  .device-meta {{ font-size: 12px; color: var(--muted); }}
  .device-body {{ padding: 20px; display: none; }}
  .device-body.open {{ display: block; }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }}
  th {{ background: #f8f9fa; padding: 8px 12px; text-align: left; font-weight: 600;
        border: 1px solid var(--border); color: var(--muted); }}
  td {{ padding: 8px 12px; border: 1px solid var(--border); vertical-align: top; }}
  tr:nth-child(even) td {{ background: #fbfbfb; }}

  /* Severity pill */
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
           font-size: 11px; font-weight: 600; }}
  .sev-CRITICAL {{ background: #fdecea; color: #c0392b; }}
  .sev-HIGH     {{ background: #fef5ec; color: #e67e22; }}
  .sev-MEDIUM   {{ background: #fefce8; color: #d4ac0d; }}
  .sev-LOW      {{ background: #eafaf1; color: #27ae60; }}
  .sev-UNKNOWN  {{ background: #f2f3f4; color: #7f8c8d; }}

  /* Port chip */
  .port-chip {{ display: inline-block; background: #e8f4fd; color: #1a5276;
                border-radius: 4px; padding: 2px 7px; font-size: 11px;
                margin: 2px; font-family: monospace; }}
  .port-chip.risky {{ background: #fdecea; color: #c0392b; }}

  /* Credential finding */
  .cred-row {{ background: #fdecea !important; }}

  /* Chart bar */
  .chart-bar {{ height: 20px; border-radius: 4px; margin: 4px 0;
                display: flex; align-items: center; padding: 0 8px;
                font-size: 11px; color: #fff; font-weight: 600; }}

  /* Collapsible sub-sections */
  .sub-title {{ font-size: 13px; font-weight: 600; color: var(--muted);
                text-transform: uppercase; letter-spacing: .4px;
                margin: 14px 0 6px; }}
  .empty-note {{ font-size: 12px; color: var(--muted); font-style: italic; }}

  footer {{ text-align: center; padding: 28px; font-size: 12px; color: var(--muted); }}
  a {{ color: #2980b9; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🔐 IoT Security Scan Report</h1>
    <div style="font-size:13px;color:#ccc;margin-top:4px">
      For authorized penetration testing only
    </div>
  </div>
  <div class="meta">
    <div>{now}</div>
    <div style="margin-top:4px">IoT Security Toolkit v1.0</div>
  </div>
</header>

<div class="container">

  <!-- Summary Stats -->
  <div class="summary">
    <div class="stat-card">
      <div class="num c-blue">{total}</div>
      <div class="lbl">Devices Found</div>
    </div>
    <div class="stat-card">
      <div class="num c-red">{crits}</div>
      <div class="lbl">Critical Risk</div>
    </div>
    <div class="stat-card">
      <div class="num c-orange">{t_cred}</div>
      <div class="lbl">Weak Credentials</div>
    </div>
    <div class="stat-card">
      <div class="num c-red">{t_cves}</div>
      <div class="lbl">CVEs Matched</div>
    </div>
  </div>

  <!-- Risk Distribution Chart -->
  <div class="section-title">Risk Distribution</div>
  <div style="background:var(--surface);border-radius:var(--radius);border:1px solid var(--border);padding:16px;margin-bottom:28px">
    {self._risk_chart(risk_dist, total)}
  </div>

  <!-- Device Details -->
  <div class="section-title">Device Details</div>
  {device_cards}

</div>

<footer>
  Generated by IoT Security Toolkit &bull;
  <strong>For authorized use only</strong> &bull;
  {now}
</footer>

<script>
  document.querySelectorAll('.device-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.nextElementSibling.classList.toggle('open');
      const arrow = h.querySelector('.arrow');
      if (arrow) arrow.textContent = h.nextElementSibling.classList.contains('open') ? '▲' : '▼';
    }});
  }});
</script>
</body>
</html>"""

    def _risk_chart(self, dist: dict, total: int) -> str:
        colours = {
            "Critical": "#c0392b", "High": "#e67e22",
            "Medium": "#f39c12",   "Low": "#27ae60"
        }
        bars = ""
        for label, count in dist.items():
            if count == 0:
                continue
            pct  = (count / total * 100) if total else 0
            col  = colours.get(label, "#aaa")
            bars += f"""
      <div style="margin-bottom:8px">
        <div style="font-size:12px;color:#555;margin-bottom:3px">
          {label} ({count})
        </div>
        <div style="background:#e9ecef;border-radius:4px;overflow:hidden;height:18px">
          <div style="width:{pct:.0f}%;background:{col};height:100%;
                      border-radius:4px;transition:width .4s"></div>
        </div>
      </div>"""
        return bars or "<p class='empty-note'>No risk data</p>"

    def _device_card(self, dev: dict) -> str:
        ip    = dev.get("ip", "N/A")
        mac   = dev.get("mac", "unknown")
        vendor = dev.get("vendor", "Unknown")
        cls   = dev.get("device_class", "Unknown")
        score = dev.get("risk_score", 0)
        label, colour = risk_label(score)

        # Ports
        ports_html = self._ports_table(dev.get("services", {}))
        # Credentials
        creds_html = self._creds_table(dev.get("credentials", []))
        # CVEs
        cves_html  = self._cves_table(dev.get("cves", []))

        return f"""
<div class="device-card">
  <div class="device-header">
    <span class="risk-badge" style="background:{colour}">{label} {score}</span>
    <div>
      <div class="device-ip">{ip}</div>
      <div class="device-meta">{mac} &bull; {vendor} &bull; {cls}</div>
    </div>
    <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
      <span style="font-size:12px;color:#888">
        {len(dev.get('open_ports', {}))} ports &bull;
        {len(dev.get('cves', []))} CVEs &bull;
        {len(dev.get('credentials', []))} weak creds
      </span>
      <span class="arrow" style="font-size:14px">▼</span>
    </div>
  </div>
  <div class="device-body">
    <div class="sub-title">Open Ports & Services</div>
    {ports_html}
    <div class="sub-title" style="margin-top:18px">Default Credentials Found</div>
    {creds_html}
    <div class="sub-title" style="margin-top:18px">CVE Vulnerabilities</div>
    {cves_html}
  </div>
</div>"""

    def _ports_table(self, services: dict) -> str:
        if not services:
            return "<p class='empty-note'>No open ports detected</p>"
        rows = ""
        for port, info in sorted(services.items()):
            risk    = info.get("risk","unknown")
            banner  = info.get("banner","")[:80]
            version = info.get("version","")
            chip_cls = "port-chip risky" if risk in ("critical","high") else "port-chip"
            rows += f"""
      <tr>
        <td><span class="{chip_cls}">{port}</span></td>
        <td>{info.get('name','')}</td>
        <td><span class="sev sev-{risk.upper()}">{risk.upper()}</span></td>
        <td>{version or '—'}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;
                   white-space:nowrap;font-family:monospace;font-size:11px">
          {banner or info.get('note','')}</td>
      </tr>"""
        return f"""
    <table>
      <tr><th>Port</th><th>Service</th><th>Risk</th><th>Version</th><th>Banner / Note</th></tr>
      {rows}
    </table>"""

    def _creds_table(self, credentials: list) -> str:
        if not credentials:
            return "<p class='empty-note' style='color:#27ae60'>✓ No default credentials found</p>"
        rows = ""
        for c in credentials:
            rows += f"""
      <tr class="cred-row">
        <td>{c.get('protocol','')}</td>
        <td>{c.get('port','')}</td>
        <td><code>{c.get('user','')}</code></td>
        <td><code>{c.get('pass','')}</code></td>
        <td style="color:#c0392b;font-weight:600">⚠ Default credential active</td>
      </tr>"""
        return f"""
    <table>
      <tr><th>Protocol</th><th>Port</th><th>Username</th><th>Password</th><th>Status</th></tr>
      {rows}
    </table>"""

    def _cves_table(self, cves: list) -> str:
        if not cves:
            return "<p class='empty-note' style='color:#27ae60'>✓ No matching CVEs found</p>"
        rows = ""
        for c in cves:
            sev   = c.get("severity","UNKNOWN")
            score = c.get("score")
            score_str = f"{score:.1f}" if score else "N/A"
            exploit = c.get("exploit_url","")
            exploit_link = f'<a href="{exploit}" target="_blank">Exploit-DB</a>' if exploit else "—"
            rows += f"""
      <tr>
        <td><a href="https://nvd.nist.gov/vuln/detail/{c.get('id','')}"
               target="_blank">{c.get('id','')}</a></td>
        <td><span class="sev sev-{sev}">{sev}</span></td>
        <td>{score_str}</td>
        <td style="max-width:400px">{c.get('description','')[:200]}</td>
        <td>{c.get('published','')}</td>
        <td>{exploit_link}</td>
      </tr>"""
        return f"""
    <table>
      <tr><th>CVE ID</th><th>Severity</th><th>Score</th>
          <th>Description</th><th>Published</th><th>Exploit</th></tr>
      {rows}
    </table>"""
