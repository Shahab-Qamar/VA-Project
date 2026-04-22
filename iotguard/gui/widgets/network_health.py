"""
Network Health dashboard tab.

Layout:
  Top row    — four "stat cards" (public IP, ISP, gateway, latency)
  Middle     — DNS server list + internet latency bars
  Bottom     — collapsible sections: Shodan exposure, DNS hijack check
"""

from __future__ import annotations

import html

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout,
    QPushButton, QTextBrowser, QSizePolicy, QScrollArea, QLineEdit,
)

from ...intel.network_health import NetworkHealth, collect_network_health
from ...intel.shodan_client import ShodanClient
from ...intel.dns_hijack import check_dns_hijack


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------

class _HealthWorker(QThread):
    done = pyqtSignal(object)                  # NetworkHealth

    def __init__(self, use_ip_api: bool, parent=None):
        super().__init__(parent)
        self.use_ip_api = use_ip_api

    def run(self):
        try:
            h = collect_network_health(self.use_ip_api)
        except Exception as e:                                # noqa: BLE001
            h = NetworkHealth(error=str(e))
        self.done.emit(h)


class _ShodanWorker(QThread):
    done = pyqtSignal(dict)                    # {} on failure / no key

    def __init__(self, ip: str, api_key: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.api_key = api_key

    def run(self):
        if not self.ip or not self.api_key:
            self.done.emit({})
            return
        client = ShodanClient(self.api_key)
        try:
            data = client.host_info(self.ip) or {}
        finally:
            client.close()
        self.done.emit(data)


class _DNSWorker(QThread):
    done = pyqtSignal(dict)

    def __init__(self, router_dns: str, parent=None):
        super().__init__(parent)
        self.router_dns = router_dns

    def run(self):
        try:
            rep = check_dns_hijack(self.router_dns)
        except Exception as e:                                # noqa: BLE001
            rep = {"error": str(e)}
        self.done.emit(rep)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _stat_card(label: str, value_widget: QWidget,
               sub: str | None = None) -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.Shape.StyledPanel)
    f.setStyleSheet(
        "QFrame { background:#ffffff; border:1px solid #e5e7eb; border-radius:10px; }"
        "QLabel { background:transparent; border:0; }"
    )
    lay = QVBoxLayout(f)
    lay.setContentsMargins(14, 10, 14, 10)
    lay.setSpacing(2)

    lbl = QLabel(label.upper())
    lbl.setStyleSheet(
        "color:#6b7280;font-size:10px;letter-spacing:0.06em;font-weight:600;"
    )
    lay.addWidget(lbl)
    lay.addWidget(value_widget)
    if sub:
        sub_label = QLabel(sub)
        sub_label.setStyleSheet("color:#9ca3af;font-size:11px;")
        lay.addWidget(sub_label)
    return f


def _big_value(text: str, color: str = "#0b1220") -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{color};font-size:17px;font-weight:700;")
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


# ---------------------------------------------------------------------------
# Main tab widget
# ---------------------------------------------------------------------------

class NetworkHealthTab(QWidget):
    """Network-wide status + Shodan exposure + DNS hijack check."""

    def __init__(self, get_shodan_key, get_use_ip_api, parent=None):
        super().__init__(parent)
        self._get_shodan_key = get_shodan_key     # callable → str
        self._get_use_ip_api = get_use_ip_api     # callable → bool
        self._health: NetworkHealth | None = None
        self._build_ui()

    # -- UI ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(10)

        # Toolbar
        toolbar = QHBoxLayout()
        self.btn_refresh = QPushButton("↻  Refresh")
        self.btn_shodan  = QPushButton("Run Shodan exposure check")
        self.btn_dns     = QPushButton("Run DNS hijack check")
        toolbar.addWidget(self.btn_refresh)
        toolbar.addStretch(1)
        toolbar.addWidget(self.btn_dns)
        toolbar.addWidget(self.btn_shodan)
        outer.addLayout(toolbar)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_shodan.clicked.connect(self._run_shodan)
        self.btn_dns.clicked.connect(self._run_dns_check)

        # Scrollable body
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        body = QWidget()
        self._body_layout = QVBoxLayout(body)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(12)

        self._build_stat_row()
        self._build_detail_panel()
        self._build_shodan_panel()
        self._build_dns_panel()

        self._body_layout.addStretch(1)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

    def _build_stat_row(self) -> None:
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        self.v_public_ip = _big_value("—")
        self.v_isp       = _big_value("—")
        self.v_gateway   = _big_value("—")
        self.v_latency   = _big_value("—")

        grid.addWidget(_stat_card("Public IP", self.v_public_ip), 0, 0)
        grid.addWidget(_stat_card("ISP / Org",  self.v_isp),       0, 1)
        grid.addWidget(_stat_card("Gateway",    self.v_gateway),   0, 2)
        grid.addWidget(_stat_card("Internet latency", self.v_latency,
                                  sub="Cloudflare / Google (TCP 53)"),
                       0, 3)
        self._body_layout.addLayout(grid)

    def _build_detail_panel(self) -> None:
        panel = QFrame()
        panel.setStyleSheet(
            "QFrame { background:#ffffff; border:1px solid #e5e7eb; border-radius:10px; }"
            "QLabel { background:transparent; border:0; }"
        )
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(8)

        hdr = QLabel("Connection details")
        hdr.setStyleSheet("font-weight:700;color:#0b1220;font-size:12px;")
        lay.addWidget(hdr)

        self.details = QLabel("Collecting…")
        self.details.setTextFormat(Qt.TextFormat.RichText)
        self.details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details.setWordWrap(True)
        lay.addWidget(self.details)

        self._body_layout.addWidget(panel)

    def _build_shodan_panel(self) -> None:
        panel = QFrame()
        panel.setStyleSheet(
            "QFrame { background:#ffffff; border:1px solid #e5e7eb; border-radius:10px; }"
            "QLabel, QTextBrowser { background:transparent; border:0; }"
        )
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(6)

        hdr = QLabel("Shodan — internet exposure of your public IP")
        hdr.setStyleSheet("font-weight:700;color:#0b1220;font-size:12px;")
        lay.addWidget(hdr)

        self.shodan_body = QTextBrowser()
        self.shodan_body.setMinimumHeight(120)
        self.shodan_body.setHtml(
            "<span style='color:#6b7280;font-size:12px'>"
            "Configure a Shodan API key in Settings, then click "
            "<b>Run Shodan exposure check</b> above. This will report any "
            "externally-visible open ports / services on your public IP — "
            "the #1 risk vector for home networks.</span>"
        )
        lay.addWidget(self.shodan_body)
        self._body_layout.addWidget(panel)

    def _build_dns_panel(self) -> None:
        panel = QFrame()
        panel.setStyleSheet(
            "QFrame { background:#ffffff; border:1px solid #e5e7eb; border-radius:10px; }"
            "QLabel, QTextBrowser { background:transparent; border:0; }"
        )
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(6)

        hdr = QLabel("DNS hijack check")
        hdr.setStyleSheet("font-weight:700;color:#0b1220;font-size:12px;")
        lay.addWidget(hdr)

        self.dns_body = QTextBrowser()
        self.dns_body.setMinimumHeight(120)
        self.dns_body.setHtml(
            "<span style='color:#6b7280;font-size:12px'>"
            "Queries a handful of well-known domains against your router's "
            "DNS and compares them to Cloudflare (1.1.1.1). Any mismatch is "
            "a red flag — compromised routers commonly redirect banking or "
            "update domains to attacker-controlled hosts.</span>"
        )
        lay.addWidget(self.dns_body)
        self._body_layout.addWidget(panel)

    # -- public API ----------------------------------------------------------

    def refresh(self) -> None:
        self.v_public_ip.setText("…")
        self.v_isp.setText("…")
        self.v_gateway.setText("…")
        self.v_latency.setText("…")
        self.details.setText("Collecting…")

        use_ip_api = True
        try:
            use_ip_api = bool(self._get_use_ip_api())
        except Exception:
            pass

        worker = _HealthWorker(use_ip_api, self)
        worker.done.connect(self._on_health)
        worker.start()
        self._health_worker = worker            # keep reference alive

    # -- worker callbacks ----------------------------------------------------

    def _on_health(self, h: NetworkHealth) -> None:
        self._health = h

        self.v_public_ip.setText(h.public_ip or "—")
        self.v_isp.setText((h.isp or h.org or "—")[:32])

        self.v_gateway.setText(h.gateway_ip or "—")

        if h.cloudflare_latency_ms or h.google_latency_ms:
            cf = f"{h.cloudflare_latency_ms:.0f} ms" if h.cloudflare_latency_ms else "—"
            gg = f"{h.google_latency_ms:.0f} ms"   if h.google_latency_ms   else "—"
            self.v_latency.setText(f"{cf}  /  {gg}")
        else:
            self.v_latency.setText("No internet")

        rows = []
        rows.append(f"<b>Local IP:</b> <span style='font-family:monospace'>"
                    f"{html.escape(h.local_ip or '—')}</span>")
        rows.append(f"<b>Gateway:</b> <span style='font-family:monospace'>"
                    f"{html.escape(h.gateway_ip or '—')}</span>")
        rows.append(f"<b>DNS servers:</b> <span style='font-family:monospace'>"
                    f"{html.escape(', '.join(h.dns_servers) or '—')}</span>")
        if h.city or h.country:
            rows.append(f"<b>Location:</b> "
                        f"{html.escape(h.city or '—')}, "
                        f"{html.escape(h.region or '')} "
                        f"{html.escape(h.country or '')}")
        if h.as_name:
            rows.append(f"<b>ASN:</b> {html.escape(h.as_name)}")
        if h.error:
            rows.append(f"<span style='color:#b45309'><b>Note:</b> "
                        f"{html.escape(h.error)}</span>")
        rows.append(f"<span style='color:#9ca3af;font-size:11px'>"
                    f"Fetched at {html.escape(h.fetched_at)}</span>")
        self.details.setText("<br>".join(rows))

    def _run_shodan(self) -> None:
        if not self._health or not self._health.public_ip:
            self.shodan_body.setHtml(
                "<span style='color:#b45309;font-size:12px'>"
                "No public IP available — run <b>Refresh</b> first.</span>"
            )
            return
        key = (self._get_shodan_key() or "").strip()
        if not key:
            self.shodan_body.setHtml(
                "<span style='color:#b45309;font-size:12px'>"
                "No Shodan API key configured. Open Settings → Integrations "
                "and paste your key (free keys at <a href='https://account.shodan.io/'>"
                "account.shodan.io</a>).</span>"
            )
            return

        self.shodan_body.setHtml(
            f"<span style='color:#6b7280;font-size:12px'>"
            f"Querying Shodan for {html.escape(self._health.public_ip)}…</span>"
        )
        worker = _ShodanWorker(self._health.public_ip, key, self)
        worker.done.connect(self._on_shodan)
        worker.start()
        self._shodan_worker = worker

    def _on_shodan(self, data: dict) -> None:
        if not data:
            self.shodan_body.setHtml(
                "<span style='color:#b45309;font-size:12px'>"
                "Shodan returned no data — likely an invalid API key or a "
                "network error. Check Settings → Integrations.</span>"
            )
            return
        if data.get("not_indexed"):
            self.shodan_body.setHtml(
                f"<div style='color:#047857;font-size:13px;padding:4px 0'>"
                f"<b>✓ Good news.</b> Shodan has no indexed record of "
                f"<code>{html.escape(data.get('ip','') or '')}</code>. "
                f"Your public IP is not currently exposing any services "
                f"that Shodan has discovered.</div>"
            )
            return

        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        severity_color = "#991b1b" if vulns else \
                         "#ef4444" if ports else "#10b981"

        parts = [
            f"<div style='font-size:13px;line-height:1.5'>",
            f"<div><b style='color:{severity_color}'>"
            f"{len(ports)} open port(s) visible externally"
            f"</b>"
            + (f", <b style='color:#991b1b'>{len(vulns)} known CVE(s)</b>"
               if vulns else "") + "</div>",
            f"<div style='color:#6b7280'>"
            f"IP: <code>{html.escape(data.get('ip',''))}</code>"
            f"  ·  ISP: {html.escape(data.get('isp',''))}"
            f"  ·  Last updated: {html.escape(data.get('last_update','')[:10])}"
            f"</div>",
        ]

        if ports:
            parts.append(
                "<div style='margin-top:8px'><b>Open ports:</b><br>"
                + " ".join(
                    f"<span style='background:#fef3c7;padding:1px 8px;"
                    f"border-radius:10px;margin:2px;display:inline-block;"
                    f"font-family:monospace;font-size:11px'>{p}</span>"
                    for p in ports)
                + "</div>"
            )
        if vulns:
            parts.append(
                "<div style='margin-top:8px'><b>Known vulnerabilities:</b><br>"
                + " ".join(
                    f"<span style='background:#fee2e2;color:#991b1b;"
                    f"padding:1px 8px;border-radius:10px;margin:2px;"
                    f"display:inline-block;font-family:monospace;"
                    f"font-size:11px'>{html.escape(v)}</span>"
                    for v in vulns[:20])
                + "</div>"
            )
        tags = data.get("tags") or []
        if tags:
            parts.append(
                "<div style='margin-top:8px;color:#6b7280;font-size:11px'>"
                f"Tags: {html.escape(', '.join(tags))}</div>"
            )
        parts.append("</div>")
        self.shodan_body.setHtml("".join(parts))

    def _run_dns_check(self) -> None:
        if not self._health or not self._health.dns_servers:
            self.dns_body.setHtml(
                "<span style='color:#b45309;font-size:12px'>"
                "No DNS server detected yet — run <b>Refresh</b> first.</span>"
            )
            return
        router_dns = self._health.dns_servers[0]
        self.dns_body.setHtml(
            f"<span style='color:#6b7280;font-size:12px'>"
            f"Querying {len(5*[0])} domains against "
            f"<code>{html.escape(router_dns)}</code> "
            f"and <code>1.1.1.1</code>…</span>"
        )
        worker = _DNSWorker(router_dns, self)
        worker.done.connect(self._on_dns_check)
        worker.start()
        self._dns_worker = worker

    def _on_dns_check(self, rep: dict) -> None:
        if rep.get("error"):
            self.dns_body.setHtml(
                f"<span style='color:#b45309;font-size:12px'>"
                f"Error: {html.escape(rep['error'])}</span>"
            )
            return
        if rep.get("unreachable_router"):
            self.dns_body.setHtml(
                "<span style='color:#b45309;font-size:12px'>"
                "Router DNS not reachable on UDP/53.</span>"
            )
            return

        mismatches = rep.get("mismatches", [])
        if not mismatches:
            parts = [
                "<div style='color:#047857;font-size:13px;padding:4px 0'>"
                "<b>✓ All checks passed.</b> Your router's DNS answers agree "
                "with Cloudflare for every tested domain.</div>"
            ]
        else:
            parts = [
                f"<div style='color:#991b1b;font-size:13px;padding:4px 0'>"
                f"<b>⚠ {len(mismatches)} mismatch(es) detected.</b> "
                f"Your router is returning different IPs than "
                f"Cloudflare for these domains. Investigate the router "
                f"configuration.</div>"
            ]
            for m in mismatches:
                parts.append(
                    f"<div style='margin:4px 0;padding:8px;"
                    f"background:#fef2f2;border-radius:6px;"
                    f"font-size:12px;line-height:1.5'>"
                    f"<b>{html.escape(m['domain'])}</b><br>"
                    f"Router returned: <code>"
                    f"{html.escape(', '.join(m['router_ips']) or '—')}"
                    f"</code><br>Cloudflare returned: <code>"
                    f"{html.escape(', '.join(m['reference_ips']) or '—')}"
                    f"</code></div>"
                )

        parts.append(
            "<div style='margin-top:10px'><b>All checks:</b><br>"
            + "<br>".join(
                f"<span style='font-family:monospace;font-size:11px;"
                f"color:{'#047857' if c['match'] else '#991b1b'}'>"
                f"{'✓' if c['match'] else '✗'} {html.escape(c['domain']):40s}"
                f" → router: {html.escape(', '.join(c['router_ips']) or '—')}"
                f"</span>"
                for c in rep.get("checked", []))
            + "</div>"
        )
        self.dns_body.setHtml("".join(parts))
