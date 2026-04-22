"""
Per-device deep-dive dialog.

Tabs:
  Overview      metadata + rename + notes (persisted via DeviceMetadataStore)
  Open ports    port table
  Findings      finding cards
  Actions       Ping, Traceroute, Wake-on-LAN, Open web UI, Copy IP/MAC
"""

from __future__ import annotations

import html
import webbrowser

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QDialogButtonBox,
    QTextBrowser, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QLineEdit, QPlainTextEdit, QFormLayout, QGroupBox, QMessageBox,
)

from ...core.device_store import DeviceMetadataStore
from ...core.models import Device
from ...scanners.device_actions import ping, traceroute, wake_on_lan
from ..widgets.device_icons import device_icon_pixmap


RISK_COLORS = {
    "Info":     "#6b7280", "Low":      "#10b981",
    "Medium":   "#f59e0b", "High":     "#ef4444",
    "Critical": "#991b1b",
}


class _ActionWorker(QThread):
    done = pyqtSignal(str)

    def __init__(self, func, *args, parent=None):
        super().__init__(parent)
        self._func = func
        self._args = args

    def run(self):
        try:
            self.done.emit(self._func(*self._args))
        except Exception as e:                              # noqa: BLE001
            self.done.emit(f"Error: {e}")


class DeviceDetailDialog(QDialog):
    def __init__(self, device: Device, parent=None,
                 store: DeviceMetadataStore | None = None):
        super().__init__(parent)
        self.device = device
        self.store = store or DeviceMetadataStore()
        self._owns_store = store is None
        self._workers: list[QThread] = []

        self.setWindowTitle(f"Device — {device.display_name}")
        self.resize(820, 680)

        lay = QVBoxLayout(self)
        lay.addWidget(self._header())

        tabs = QTabWidget()
        tabs.addTab(self._overview_tab(), "Overview")
        tabs.addTab(self._ports_tab(),    f"Open ports ({len(device.open_ports)})")
        tabs.addTab(self._findings_tab(), f"Findings ({len(device.findings)})")
        tabs.addTab(self._actions_tab(),  "Actions")
        lay.addWidget(tabs, 1)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.clicked.connect(lambda _: self.accept())
        lay.addWidget(btns)

    # -- header --------------------------------------------------------------

    def _header(self) -> QWidget:
        d = self.device
        risk = d.highest_risk.value
        color = RISK_COLORS[risk]
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 6)
        lay.setSpacing(12)

        icon = QLabel()
        icon.setPixmap(device_icon_pixmap(d.device_type, size=56,
                                          risk=d.highest_risk))
        icon.setFixedSize(56, 56)
        lay.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)

        title = QLabel(
            f"<div style='font-size:18px;font-weight:700'>"
            f"{html.escape(d.display_name)}</div>"
            f"<span style='color:#6b7280;font-family:monospace;font-size:12px'>"
            f"{html.escape(d.ip or '-')}   ·   "
            f"{html.escape(d.mac or '-')}</span>"
            + (f"<br><span style='color:#1e40af;font-size:11px;font-weight:700'>"
               f"⌂ Gateway</span>" if d.is_gateway else "")
        )
        title.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(title, 1)

        pill = QLabel(f"  {risk}  ")
        pill.setStyleSheet(
            f"background:{color};color:white;border-radius:10px;"
            f"padding:4px 10px;font-weight:700;font-size:11px;"
        )
        lay.addWidget(pill, 0, Qt.AlignmentFlag.AlignTop)
        return w

    # -- Overview ------------------------------------------------------------

    def _overview_tab(self) -> QWidget:
        d = self.device
        page = QWidget()
        layout = QVBoxLayout(page)

        label_group = QGroupBox("Label and notes (saved across scans)")
        form = QFormLayout(label_group)
        self.edit_name = QLineEdit(d.custom_name)
        self.edit_name.setPlaceholderText(d.display_name)
        self.edit_notes = QPlainTextEdit(d.notes)
        self.edit_notes.setFixedHeight(72)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save_label)
        form.addRow("Custom name:", self.edit_name)
        form.addRow("Notes:",       self.edit_notes)
        form.addRow("",             save_btn)
        layout.addWidget(label_group)

        rows = [
            ("Vendor",           d.vendor or "—"),
            ("Type",             d.device_type.value),
            ("OS guess",         d.os_guess or "—"),
            ("Hostname",         d.hostname or "—"),
            ("IP address",       d.ip or "—"),
            ("MAC address",      d.mac or "—"),
            ("Discovery",        ", ".join(s.value for s in d.discovery_sources) or "—"),
            ("First seen",       d.first_seen or "—"),
            ("Last seen",        d.last_seen or "—"),
            ("Online now",       "Yes" if d.online else "No"),
            ("mDNS services",    ", ".join(d.mdns_services) or "—"),
            ("UPnP model",       d.upnp_model or "—"),
            ("BLE name",         d.ble_name or "—"),
            ("BLE RSSI",         f"{d.ble_rssi} dBm" if d.ble_rssi else "—"),
            ("Highest risk",     d.highest_risk.value),
            ("Highest CVSS",     f"{d.risk_score:.1f}" if d.risk_score else "—"),
            ("Finding count",    str(len(d.findings))),
        ]
        html_rows = "".join(
            f"<tr><td style='color:#6b7280;padding:4px 12px 4px 0;"
            f"font-size:12px;vertical-align:top'>{html.escape(k)}</td>"
            f"<td style='padding:4px 0'>{html.escape(v)}</td></tr>"
            for k, v in rows
        )
        browser = QTextBrowser()
        browser.setHtml(
            "<div style='font-family:-apple-system,Segoe UI,sans-serif;font-size:13px'>"
            f"<table>{html_rows}</table></div>"
        )
        layout.addWidget(browser, 1)
        return page

    def _save_label(self) -> None:
        if not self.device.mac:
            QMessageBox.warning(self, "Save label",
                                "Cannot save label — device has no MAC address.")
            return
        self.store.set_custom_name(self.device.mac, self.edit_name.text().strip())
        self.store.set_notes(self.device.mac, self.edit_notes.toPlainText())
        self.device.custom_name = self.edit_name.text().strip()
        self.device.notes       = self.edit_notes.toPlainText()
        QMessageBox.information(self, "Saved",
                                "Label and notes saved. They'll apply on future scans.")

    # -- Ports & findings ---------------------------------------------------

    def _ports_tab(self) -> QWidget:
        d = self.device
        t = QTableWidget(len(d.open_ports), 6)
        t.setHorizontalHeaderLabels(["Port", "Proto", "Service", "Product",
                                     "Version", "Banner"])
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hdr = t.horizontalHeader()
        for i in range(5):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for row, op in enumerate(d.open_ports):
            t.setItem(row, 0, QTableWidgetItem(str(op.port)))
            t.setItem(row, 1, QTableWidgetItem(op.protocol))
            t.setItem(row, 2, QTableWidgetItem(op.service))
            t.setItem(row, 3, QTableWidgetItem(op.product))
            t.setItem(row, 4, QTableWidgetItem(op.version))
            it = QTableWidgetItem(op.banner[:120])
            it.setToolTip(op.banner)
            t.setItem(row, 5, it)
        return t

    def _findings_tab(self) -> QWidget:
        d = self.device
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        if not d.findings:
            browser.setHtml("<p style='color:#6b7280;padding:16px'>"
                            "No security findings for this device.</p>")
            return browser

        parts = ["<div style='font-family:-apple-system,Segoe UI,sans-serif;"
                 "font-size:13px;line-height:1.5'>"]
        for f in sorted(d.findings, key=lambda f: -f.risk.order):
            color = RISK_COLORS[f.risk.value]
            chips = []
            if f.cvss_score: chips.append(f"CVSS {f.cvss_score:.1f}")
            if f.owasp_iot:  chips.append(html.escape(f.owasp_iot))
            chips.extend(html.escape(c) for c in f.cve_ids)
            chip_html = " · ".join(chips)
            parts.append(
                f"<div style='border-left:4px solid {color};padding:8px 12px;"
                f"margin:10px 0;background:#fafbfc;border-radius:0 6px 6px 0'>"
                f"<div style='font-weight:600;margin-bottom:4px'>"
                f"<span style='background:{color};color:white;padding:1px 8px;"
                f"border-radius:8px;font-size:11px;margin-right:6px'>"
                f"{f.risk.value}</span>{html.escape(f.title)}</div>"
                f"<div>{html.escape(f.description)}</div>"
                f"<div style='margin-top:4px'><b>Remediation:</b> "
                f"{html.escape(f.remediation)}</div>"
            )
            if f.evidence:
                parts.append(
                    f"<div style='margin-top:4px;font-size:12px'>"
                    f"<b>Evidence:</b> <code>{html.escape(f.evidence)}</code></div>"
                )
            if f.cvss_vector:
                parts.append(
                    f"<div style='margin-top:2px;color:#6b7280;"
                    f"font-family:monospace;font-size:11px'>"
                    f"{html.escape(f.cvss_vector)}</div>"
                )
            if chip_html:
                parts.append(
                    f"<div style='margin-top:6px;color:#6b7280;font-size:11px'>"
                    f"{chip_html}</div>"
                )
            parts.append("</div>")
        parts.append("</div>")
        browser.setHtml("".join(parts))
        return browser

    # -- Actions -------------------------------------------------------------

    def _actions_tab(self) -> QWidget:
        d = self.device
        page = QWidget()
        lay = QVBoxLayout(page)

        btn_row = QHBoxLayout()
        self.btn_ping = QPushButton("Ping")
        self.btn_trace = QPushButton("Traceroute")
        self.btn_wol = QPushButton("Wake-on-LAN")
        self.btn_web = QPushButton("Open web UI")
        self.btn_copy_ip = QPushButton("Copy IP")
        self.btn_copy_mac = QPushButton("Copy MAC")
        for b in (self.btn_ping, self.btn_trace, self.btn_wol,
                  self.btn_web, self.btn_copy_ip, self.btn_copy_mac):
            btn_row.addWidget(b)
        btn_row.addStretch(1)
        lay.addLayout(btn_row)

        self.btn_ping.setEnabled(bool(d.ip))
        self.btn_trace.setEnabled(bool(d.ip))
        self.btn_wol.setEnabled(bool(d.mac))
        self.btn_web.setEnabled(bool(d.ip) and any(
            op.port in (80, 81, 443, 8080, 8443, 8008, 8123, 32400)
            for op in d.open_ports
        ))
        self.btn_copy_ip.setEnabled(bool(d.ip))
        self.btn_copy_mac.setEnabled(bool(d.mac))

        self.btn_ping.clicked.connect(self._on_ping)
        self.btn_trace.clicked.connect(self._on_traceroute)
        self.btn_wol.clicked.connect(self._on_wol)
        self.btn_web.clicked.connect(self._on_open_web)
        self.btn_copy_ip.clicked.connect(lambda: self._copy(d.ip))
        self.btn_copy_mac.clicked.connect(lambda: self._copy(d.mac))

        self.action_output = QPlainTextEdit()
        self.action_output.setReadOnly(True)
        self.action_output.setStyleSheet(
            "font-family:ui-monospace,Consolas,Menlo,monospace;"
            "font-size:12px;background:#0b1220;color:#e5e7eb;"
        )
        self.action_output.setPlainText(
            "Click a button above to run the action. Output appears here.\n"
        )
        lay.addWidget(self.action_output, 1)
        return page

    def _on_ping(self) -> None:
        self.action_output.setPlainText(f"$ ping -c 4 {self.device.ip}\n")
        w = _ActionWorker(ping, self.device.ip, 4, 8, parent=self)
        w.done.connect(self._append_action_output)
        self._workers.append(w)
        w.start()

    def _on_traceroute(self) -> None:
        self.action_output.setPlainText(f"$ traceroute {self.device.ip}\n")
        w = _ActionWorker(traceroute, self.device.ip, 15, 25, parent=self)
        w.done.connect(self._append_action_output)
        self._workers.append(w)
        w.start()

    def _on_wol(self) -> None:
        msg = wake_on_lan(self.device.mac)
        self.action_output.setPlainText(msg)

    def _on_open_web(self) -> None:
        d = self.device
        priorities = [(443, "https"), (8443, "https"), (9443, "https"),
                      (80, "http"),   (8080, "http"),  (8008, "http"),
                      (8123, "http"), (32400, "http"), (81, "http")]
        for port, scheme in priorities:
            if any(op.port == port for op in d.open_ports):
                webbrowser.open(f"{scheme}://{d.ip}:{port}")
                return
        webbrowser.open(f"http://{d.ip}")

    def _copy(self, text: str) -> None:
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        self.action_output.setPlainText(f"Copied: {text}\n")

    def _append_action_output(self, text: str) -> None:
        self.action_output.appendPlainText(text)

    def closeEvent(self, ev):
        for w in self._workers:
            if w.isRunning():
                w.quit()
                w.wait(500)
        if self._owns_store:
            try:
                self.store.close()
            except Exception:
                pass
        super().closeEvent(ev)
