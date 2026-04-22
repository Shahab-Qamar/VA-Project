"""
IoTGuard main window.

Layout
------
┌──────────────────────────────────────────────────────────────┐
│ toolbar: [Start scan] [Stop] [Settings] [Export PDF] [HTML] │
├──────────────────────────────────────────────────────────────┤
│ header: scan metadata + progress bar                         │
├─────────┬────────────────────────────────────────────────────┤
│ Dashboard | Devices | WiFi | Findings | History | Log       │
├──────────────────────────────────────────────────────────────┤
│  tab content                                                 │
└──────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import html
import logging
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtGui import QAction, QColor, QIcon, QKeySequence, QGuiApplication
from PyQt6.QtWidgets import (
    QMainWindow, QToolBar, QStatusBar, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextBrowser, QFileDialog, QMessageBox, QSplitter,
    QMenuBar, QSizePolicy, QLineEdit, QPushButton, QStackedWidget, QMenu,
    QInputDialog,
)

from ..core.database import HistoryDB
from ..core.device_store import DeviceMetadataStore
from ..core.models import ScanResult, Device, WifiNetwork, DeviceType
from ..reporting.html_report import write_html_report
from ..reporting.pdf_report import write_pdf_report
from .scan_worker import ScanWorker, ScanOptions
from .widgets.charts import DashboardCharts
from .widgets.history_view import HistoryView
from .widgets.device_cards import DeviceCardGrid
from .widgets.device_icons import device_icon_pixmap
from .widgets.network_health import NetworkHealthTab
from .dialogs.settings import SettingsDialog, load_options, save_options
from .dialogs.consent import LabConsentDialog
from .dialogs.device_detail import DeviceDetailDialog


log = logging.getLogger(__name__)

RISK_COLORS = {
    "Info": "#6b7280", "Low": "#10b981", "Medium": "#f59e0b",
    "High": "#ef4444", "Critical": "#991b1b",
}


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IoTGuard — IoT & WiFi Vulnerability Assessment")
        self.resize(1360, 860)

        self.options, self.ui_prefs = load_options()
        self.db = HistoryDB()
        self.device_store = DeviceMetadataStore()
        self.current_scan: ScanResult | None = None
        self.worker: ScanWorker | None = None
        self._previous_macs: set[str] = set()      # for intruder detection

        # Auto-rescan timer (Tier-2 feature)
        self._auto_rescan = QTimer(self)
        self._auto_rescan.setInterval(60_000)       # 60s
        self._auto_rescan.timeout.connect(self._auto_rescan_tick)

        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_status()
        self._apply_theme(self.ui_prefs.get("theme", "Light"))
        self._refresh_export_buttons()

    # -- UI construction -----------------------------------------------------

    def _build_menu(self) -> None:
        mb = self.menuBar()
        file_m = mb.addMenu("&File")
        file_m.addAction("Export HTML report…",
                         self._export_html).setShortcut("Ctrl+H")
        file_m.addAction("Export PDF report…",
                         self._export_pdf).setShortcut("Ctrl+P")
        file_m.addAction("Export JSON…",
                         self._export_json).setShortcut("Ctrl+J")
        file_m.addSeparator()
        file_m.addAction("Quit", self.close).setShortcut("Ctrl+Q")

        scan_m = mb.addMenu("&Scan")
        scan_m.addAction("Start scan",
                         self._start_scan).setShortcut("Ctrl+R")
        scan_m.addAction("Stop scan",
                         self._stop_scan).setShortcut("Ctrl+.")
        scan_m.addAction("Settings…",
                         self._open_settings).setShortcut("Ctrl+,")

        help_m = mb.addMenu("&Help")
        help_m.addAction("About IoTGuard", self._about)

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(tb.iconSize() * 0.9)
        self.addToolBar(tb)

        self.act_start = QAction("▶  Start scan", self)
        self.act_start.triggered.connect(self._start_scan)
        tb.addAction(self.act_start)

        self.act_stop = QAction("■  Stop", self)
        self.act_stop.triggered.connect(self._stop_scan)
        self.act_stop.setEnabled(False)
        tb.addAction(self.act_stop)

        tb.addSeparator()

        self.act_settings = QAction("⚙  Settings", self)
        self.act_settings.triggered.connect(self._open_settings)
        tb.addAction(self.act_settings)

        tb.addSeparator()

        self.act_html = QAction("Export HTML", self)
        self.act_html.triggered.connect(self._export_html)
        tb.addAction(self.act_html)

        self.act_pdf = QAction("Export PDF", self)
        self.act_pdf.triggered.connect(self._export_pdf)
        tb.addAction(self.act_pdf)

        self.act_json = QAction("Export JSON", self)
        self.act_json.triggered.connect(self._export_json)
        tb.addAction(self.act_json)

        tb.addSeparator()

        # Auto-rescan toggle (Fing-style continuous monitoring)
        self.act_auto = QAction("⟳  Auto-rescan", self)
        self.act_auto.setCheckable(True)
        self.act_auto.setToolTip(
            "When enabled, re-runs discovery every 60s and flags new devices."
        )
        self.act_auto.toggled.connect(self._toggle_auto_rescan)
        tb.addAction(self.act_auto)

    def _build_central(self) -> None:
        central = QWidget()
        lay = QVBoxLayout(central)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(6)

        # -- header strip ----------------------------------------------------
        hdr = QWidget()
        hlay = QHBoxLayout(hdr)
        hlay.setContentsMargins(0, 0, 0, 0)
        hlay.setSpacing(14)

        self.lbl_scan = QLabel("<b>No scan loaded.</b>")
        self.lbl_scan.setTextFormat(Qt.TextFormat.RichText)

        self.lbl_stage = QLabel("Ready.")
        self.lbl_stage.setStyleSheet("color:#6b7280;")
        self.lbl_stage.setSizePolicy(QSizePolicy.Policy.Expanding,
                                     QSizePolicy.Policy.Preferred)

        self.bar_progress = QProgressBar()
        self.bar_progress.setRange(0, 100)
        self.bar_progress.setValue(0)
        self.bar_progress.setMaximumWidth(240)
        self.bar_progress.setTextVisible(True)
        self.bar_progress.setFormat("%p%")

        hlay.addWidget(self.lbl_scan)
        hlay.addWidget(self.lbl_stage, 1)
        hlay.addWidget(self.bar_progress)
        lay.addWidget(hdr)

        # -- intruder banner (hidden unless a new device appears) ------------
        self.intruder_banner = QLabel()
        self.intruder_banner.setTextFormat(Qt.TextFormat.RichText)
        self.intruder_banner.setWordWrap(True)
        self.intruder_banner.setStyleSheet(
            "background:#fef2f2;border:1px solid #ef4444;color:#991b1b;"
            "padding:8px 12px;border-radius:8px;font-size:12px;"
        )
        self.intruder_banner.hide()
        lay.addWidget(self.intruder_banner)

        # -- tabs ------------------------------------------------------------
        self.tabs = QTabWidget()
        self.tab_dashboard = DashboardCharts()
        self.tab_devices   = self._build_device_tab()
        self.tab_wifi      = self._build_wifi_tab()
        self.tab_findings  = self._build_findings_tab()
        self.tab_network   = NetworkHealthTab(
            get_shodan_key=lambda: self.ui_prefs.get("shodan_api_key", ""),
            get_use_ip_api=lambda: self.ui_prefs.get("use_ip_api", True),
        )
        self.tab_history   = HistoryView(self.db)
        self.tab_history.scan_loaded.connect(self._on_scan_loaded_from_history)
        self.tab_log       = QTextBrowser()
        self.tab_log.setStyleSheet(
            "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;"
            "background:#0b1220;color:#e5e7eb;"
        )

        self.tabs.addTab(self.tab_dashboard, "Dashboard")
        self.tabs.addTab(self.tab_devices,   "Devices")
        self.tabs.addTab(self.tab_wifi,      "WiFi")
        self.tabs.addTab(self.tab_findings,  "Findings")
        self.tabs.addTab(self.tab_network,   "Network Health")
        self.tabs.addTab(self.tab_history,   "History")
        self.tabs.addTab(self.tab_log,       "Log")

        lay.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        # Kick off initial network health fetch shortly after startup.
        QTimer.singleShot(800, self.tab_network.refresh)

    def _build_device_tab(self) -> QWidget:
        """Fing-style cards view + classic table view, toggleable."""
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        # Toolbar: search + view toggle
        bar = QHBoxLayout()
        bar.setContentsMargins(10, 6, 10, 0)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText(
            "Filter devices by name, IP, MAC, vendor, type, or risk…"
        )
        self.search_box.textChanged.connect(self._on_device_filter_changed)
        bar.addWidget(self.search_box, 1)

        self.btn_view_cards = QPushButton("Cards")
        self.btn_view_cards.setCheckable(True)
        self.btn_view_cards.setChecked(True)
        self.btn_view_cards.clicked.connect(lambda: self._switch_device_view(0))
        bar.addWidget(self.btn_view_cards)

        self.btn_view_table = QPushButton("Table")
        self.btn_view_table.setCheckable(True)
        self.btn_view_table.clicked.connect(lambda: self._switch_device_view(1))
        bar.addWidget(self.btn_view_table)

        outer.addLayout(bar)

        # Stacked: cards [0], table [1]
        self.device_stack = QStackedWidget()

        # (0) Fing-style card grid
        self.device_cards = DeviceCardGrid()
        self.device_cards.card_clicked.connect(self._open_device_detail_from_card)
        self.device_cards.card_context_menu.connect(self._show_device_context_menu)
        self.device_stack.addWidget(self.device_cards)

        # (1) Classic table
        t = QTableWidget(0, 8)
        t.setHorizontalHeaderLabels(
            ["", "Device", "IP", "MAC", "Vendor", "Type", "Ports", "Risk"]
        )
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setSortingEnabled(True)
        t.setIconSize(QSize(28, 28))
        hdr = t.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in range(2, 8):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        t.doubleClicked.connect(self._open_device_detail)
        t.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        t.customContextMenuRequested.connect(self._on_table_context_menu)
        self.tbl_devices = t
        self.device_stack.addWidget(t)

        outer.addWidget(self.device_stack, 1)
        return page

    def _switch_device_view(self, idx: int) -> None:
        self.device_stack.setCurrentIndex(idx)
        self.btn_view_cards.setChecked(idx == 0)
        self.btn_view_table.setChecked(idx == 1)

    def _on_device_filter_changed(self, text: str) -> None:
        self.device_cards.set_filter(text)
        # also filter table rows
        t = self.tbl_devices
        needle = (text or "").strip().lower()
        for row in range(t.rowCount()):
            if not needle:
                t.setRowHidden(row, False)
                continue
            row_text = " ".join(
                (t.item(row, c).text() if t.item(row, c) else "")
                for c in range(t.columnCount())
            ).lower()
            t.setRowHidden(row, needle not in row_text)

    def _build_wifi_tab(self) -> QWidget:
        t = QTableWidget(0, 6)
        t.setHorizontalHeaderLabels(
            ["SSID", "BSSID", "Channel", "Signal", "Encryption", "Findings"]
        )
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setSortingEnabled(True)
        hdr = t.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 6):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_wifi = t
        return t

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        t = QTableWidget(0, 6)
        t.setHorizontalHeaderLabels(
            ["Risk", "CVSS", "Target", "Title", "OWASP IoT", "CVEs"]
        )
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setSortingEnabled(True)
        hdr = t.horizontalHeader()
        for i in range(5):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tbl_findings = t

        lay.addWidget(t)
        return w

    def _build_status(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status(self._environment_status())

    def _environment_status(self) -> str:
        """Compose an at-a-glance readiness string for the status bar."""
        import shutil
        from ..scanners.bluetooth_scanner import has_bluetooth_adapter
        bits = []
        bits.append("nmcli ✓" if shutil.which("nmcli") else "nmcli ✗")
        bits.append("nmap ✓" if shutil.which("nmap") else "nmap ✗")
        bt_ok, _ = has_bluetooth_adapter()
        bits.append("bluetooth ✓" if bt_ok else "bluetooth ✗")
        return "Ready.   " + " · ".join(bits)

    # -- theming -------------------------------------------------------------

    def _apply_theme(self, theme: str) -> None:
        if theme == "Dark":
            self.setStyleSheet("""
                QMainWindow, QWidget { background:#0f172a; color:#e5e7eb; }
                QToolBar { background:#111827; border:0; padding:4px; }
                QStatusBar { background:#0b1220; color:#9ca3af; }
                QTableWidget { background:#0b1220; color:#e5e7eb; gridline-color:#1f2937;
                    alternate-background-color:#111827; }
                QHeaderView::section { background:#111827; color:#9ca3af; border:0;
                    padding:6px; font-weight:600; }
                QTabWidget::pane { border:1px solid #1f2937; border-radius:6px; }
                QTabBar::tab { background:transparent; color:#9ca3af; padding:8px 14px; }
                QTabBar::tab:selected { background:#1e293b; color:#ffffff;
                    border-top-left-radius:6px; border-top-right-radius:6px; }
                QProgressBar { border:1px solid #1f2937; border-radius:4px;
                    background:#0b1220; text-align:center; color:#e5e7eb; }
                QProgressBar::chunk { background:#1d4ed8; border-radius:3px; }
                QPushButton { background:#1e293b; color:#e5e7eb; border:1px solid #334155;
                    padding:5px 12px; border-radius:4px; }
                QPushButton:hover { background:#334155; }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow, QWidget { background:#f3f5f9; color:#0b1220; }
                QToolBar { background:#ffffff; border-bottom:1px solid #e5e7eb; padding:4px; }
                QStatusBar { background:#ffffff; color:#6b7280; border-top:1px solid #e5e7eb; }
                QTableWidget { background:#ffffff; gridline-color:#e5e7eb;
                    alternate-background-color:#f8fafc; }
                QHeaderView::section { background:#f8fafc; color:#6b7280; border:0;
                    padding:6px; font-weight:600; }
                QTabWidget::pane { border:1px solid #e5e7eb; border-radius:6px;
                    background:#ffffff; }
                QTabBar::tab { background:transparent; color:#6b7280; padding:8px 14px; }
                QTabBar::tab:selected { background:#ffffff; color:#0b1220;
                    border-top-left-radius:6px; border-top-right-radius:6px; }
                QProgressBar { border:1px solid #e5e7eb; border-radius:4px;
                    background:#ffffff; text-align:center; }
                QProgressBar::chunk { background:#1d4ed8; border-radius:3px; }
                QPushButton { background:#ffffff; color:#0b1220; border:1px solid #e5e7eb;
                    padding:5px 12px; border-radius:4px; }
                QPushButton:hover { background:#f3f4f6; }
            """)

    # -- scan actions --------------------------------------------------------

    def _start_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            return

        # Lab-mode gate: require explicit consent each session.
        if self.options.lab_mode and not self.options.demo_mode:
            dlg = LabConsentDialog(self)
            if dlg.exec() != dlg.DialogCode.Accepted:
                self.options.lab_mode = False
                self._log("Lab Mode disabled for this scan (consent declined).")

        self.worker = ScanWorker(self.options, self)
        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self._log)
        self.worker.finished_scan.connect(self._on_scan_finished)
        self.worker.failed.connect(self._on_scan_failed)

        self.act_start.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.bar_progress.setValue(0)
        self._log("="*60)
        self._log("Scan started at " + datetime.now().isoformat(timespec="seconds"))
        self._status("Scanning…")
        self.worker.start()

    def _stop_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self._log("Cancellation requested.")
            self._status("Cancelling…")

    def _on_progress(self, pct: int, stage: str) -> None:
        self.bar_progress.setValue(pct)
        self.lbl_stage.setText(stage)

    def _on_scan_failed(self, msg: str) -> None:
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self._status("Scan failed.")
        self._log(f"[FAIL] {msg}")
        QMessageBox.critical(self, "Scan failed", msg)

    def _on_scan_finished(self, scan: ScanResult) -> None:
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self._log(f"Scan finished: {len(scan.devices)} devices, "
                  f"{sum(len(d.findings) for d in scan.devices)} device findings, "
                  f"{len(scan.wifi_networks)} WiFi networks.")

        # Merge persistent metadata (custom name, notes, first-seen) into
        # every device, and update last-seen records for MACs present now.
        try:
            self.device_store.apply_to_devices(scan.devices)
        except Exception as e:                                       # noqa: BLE001
            self._log(f"[WARN] device metadata merge failed: {e}")

        # Mark presence: every device in this scan is "online".
        current_macs = {d.mac.upper() for d in scan.devices if d.mac}
        for d in scan.devices:
            d.online = True

        # Intruder detection: MACs seen now but not in previous scan.
        new_macs = current_macs - self._previous_macs
        if self._previous_macs and new_macs:
            new_devs = [d for d in scan.devices if d.mac.upper() in new_macs]
            self._show_intruder_banner(new_devs)
        else:
            self.intruder_banner.hide()
        self._previous_macs = current_macs

        # Persist to history DB
        try:
            self.db.save(scan)
        except Exception as e:
            self._log(f"[WARN] could not save to history: {e}")

        self._load_scan(scan)
        self.tab_history.refresh()
        self._status("Scan complete.")

    def _show_intruder_banner(self, new_devices: list) -> None:
        if not new_devices:
            self.intruder_banner.hide()
            return
        names = []
        for d in new_devices[:5]:
            label = d.custom_name or d.hostname or d.vendor or "Unknown"
            names.append(f"<b>{label}</b> "
                         f"<span style='font-family:monospace;font-size:11px'>"
                         f"{d.ip or d.mac}</span>")
        more = ""
        if len(new_devices) > 5:
            more = f" and {len(new_devices) - 5} more"
        self.intruder_banner.setText(
            f"⚠  <b>Intruder alert:</b> {len(new_devices)} new "
            f"device{'s' if len(new_devices) != 1 else ''} joined your "
            f"network since the previous scan — {'; '.join(names)}{more}."
        )
        self.intruder_banner.show()

    # -- rendering -----------------------------------------------------------

    def _load_scan(self, scan: ScanResult) -> None:
        self.current_scan = scan
        self._refresh_header()
        self.device_cards.set_devices(scan.devices)
        self._refresh_device_table()
        self._refresh_wifi_table()
        self._refresh_findings_table()
        self.tab_dashboard.update_from_scan(scan)
        self.tab_history.set_current_scan(scan)
        self._refresh_export_buttons()
        # Apply current filter to both views
        self._on_device_filter_changed(self.search_box.text())

    def _refresh_header(self) -> None:
        s = self.current_scan
        if not s:
            self.lbl_scan.setText("<b>No scan loaded.</b>")
            return
        mode = " · Demo" if s.demo_mode else (" · Lab" if s.lab_mode else "")
        sm = s.summary()
        self.lbl_scan.setText(
            f"<b>{s.subnet or '—'}</b>  <span style='color:#6b7280'>"
            f"{s.interface or ''} · {s.started_at[:19].replace('T',' ')}{mode}"
            f"</span> &nbsp;·&nbsp; "
            f"<b>{sm['device_count']}</b> devices · "
            f"<b>{sm['wifi_count']}</b> WiFi · "
            f"<span style='color:{RISK_COLORS['Critical']}'>"
            f"{sm['risk_counts']['Critical']} crit</span> · "
            f"<span style='color:{RISK_COLORS['High']}'>"
            f"{sm['risk_counts']['High']} high</span>"
        )

    def _refresh_device_table(self) -> None:
        t = self.tbl_devices
        t.setSortingEnabled(False)
        t.setRowCount(0)
        if not self.current_scan:
            return
        for d in self.current_scan.devices:
            row = t.rowCount()
            t.insertRow(row)

            # column 0: icon with risk tint
            icon_item = QTableWidgetItem("")
            icon_item.setIcon(QIcon(device_icon_pixmap(
                d.device_type, size=28, risk=d.highest_risk)))
            icon_item.setData(Qt.ItemDataRole.UserRole, d)
            t.setItem(row, 0, icon_item)

            name = d.display_name + (" ⌂" if d.is_gateway else "")
            vals = [
                name,
                d.ip or "-",
                d.mac or "-",
                d.vendor or "-",
                d.device_type.value,
                str(len(d.open_ports)),
                d.highest_risk.value,
            ]
            for c, v in enumerate(vals, start=1):
                it = QTableWidgetItem(v)
                if c == 7 and v in RISK_COLORS:
                    it.setForeground(QColor(RISK_COLORS[v]))
                    f = it.font(); f.setBold(True); it.setFont(f)
                if c == 1:
                    it.setData(Qt.ItemDataRole.UserRole, d)
                t.setItem(row, c, it)
            t.setRowHeight(row, 36)
        t.setSortingEnabled(True)

    def _refresh_wifi_table(self) -> None:
        t = self.tbl_wifi
        t.setSortingEnabled(False)
        t.setRowCount(0)
        if not self.current_scan:
            return
        for w in self.current_scan.wifi_networks:
            row = t.rowCount()
            t.insertRow(row)
            vals = [
                w.ssid or "<hidden>",
                w.bssid,
                str(w.channel),
                f"{w.signal_dbm} dBm",
                w.encryption.value,
                str(len(w.findings)),
            ]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 4 and w.encryption.is_weak:
                    it.setForeground(QColor(RISK_COLORS["Critical"]))
                    f = it.font(); f.setBold(True); it.setFont(f)
                t.setItem(row, c, it)
        t.setSortingEnabled(True)

    def _refresh_findings_table(self) -> None:
        t = self.tbl_findings
        t.setSortingEnabled(False)
        t.setRowCount(0)
        if not self.current_scan:
            return
        all_findings = []
        for d in self.current_scan.devices:
            all_findings.extend(d.findings)
        for w in self.current_scan.wifi_networks:
            all_findings.extend(w.findings)
        all_findings.sort(key=lambda f: (-f.risk.order, -f.cvss_score))

        for f in all_findings:
            row = t.rowCount()
            t.insertRow(row)
            vals = [
                f.risk.value,
                f"{f.cvss_score:.1f}" if f.cvss_score else "-",
                f.target or "-",
                f.title,
                f.owasp_iot or "-",
                ", ".join(f.cve_ids) or "-",
            ]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0 and v in RISK_COLORS:
                    it.setForeground(QColor(RISK_COLORS[v]))
                    fnt = it.font(); fnt.setBold(True); it.setFont(fnt)
                t.setItem(row, c, it)
        t.setSortingEnabled(True)

    def _refresh_export_buttons(self) -> None:
        en = self.current_scan is not None
        for a in (self.act_html, self.act_pdf, self.act_json):
            a.setEnabled(en)

    # -- dialogs + actions ---------------------------------------------------

    def _open_device_detail(self, index) -> None:
        row = index.row()
        # name is now in column 1 (col 0 is icon)
        it = self.tbl_devices.item(row, 1) or self.tbl_devices.item(row, 0)
        if not it:
            return
        device: Device | None = it.data(Qt.ItemDataRole.UserRole)
        if device is None:
            return
        self._open_device_detail_from_card(device)

    def _open_device_detail_from_card(self, device: Device) -> None:
        dlg = DeviceDetailDialog(device, self, store=self.device_store)
        dlg.exec()
        # Refresh if user renamed the device so display updates immediately.
        if self.current_scan:
            self.device_cards.set_devices(self.current_scan.devices)
            self._refresh_device_table()

    def _show_device_context_menu(self, device: Device, global_pos) -> None:
        menu = QMenu(self)
        menu.addAction("Open details…",
                       lambda: self._open_device_detail_from_card(device))
        menu.addAction("Rename…",
                       lambda: self._quick_rename(device))
        menu.addSeparator()
        if device.ip:
            menu.addAction("Copy IP",
                           lambda: QGuiApplication.clipboard().setText(device.ip))
        if device.mac:
            menu.addAction("Copy MAC",
                           lambda: QGuiApplication.clipboard().setText(device.mac))
        menu.exec(global_pos)

    def _on_table_context_menu(self, pos) -> None:
        index = self.tbl_devices.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        it = self.tbl_devices.item(row, 1) or self.tbl_devices.item(row, 0)
        if not it:
            return
        device = it.data(Qt.ItemDataRole.UserRole)
        if device is None:
            return
        self._show_device_context_menu(device, self.tbl_devices.viewport()
                                       .mapToGlobal(pos))

    def _quick_rename(self, device: Device) -> None:
        if not device.mac:
            QMessageBox.warning(self, "Rename",
                                "Cannot rename — device has no MAC address.")
            return
        new_name, ok = QInputDialog.getText(
            self, "Rename device",
            f"New name for {device.display_name}:",
            text=device.custom_name,
        )
        if not ok:
            return
        self.device_store.set_custom_name(device.mac, new_name.strip())
        device.custom_name = new_name.strip()
        if self.current_scan:
            self.device_cards.set_devices(self.current_scan.devices)
            self._refresh_device_table()

    def _toggle_auto_rescan(self, enabled: bool) -> None:
        if enabled:
            self._auto_rescan.start()
            self._status("Auto-rescan enabled — running every 60 seconds.")
            self._log("Auto-rescan enabled.")
        else:
            self._auto_rescan.stop()
            self._status("Auto-rescan disabled.")
            self._log("Auto-rescan disabled.")

    def _auto_rescan_tick(self) -> None:
        if self.worker and self.worker.isRunning():
            return  # a manual scan is already running; skip this tick
        self._log("[auto] tick — starting scan")
        self._start_scan()

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self.options, self.ui_prefs, self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            self.options = dlg.options()
            self.ui_prefs = dlg.ui_prefs()
            self._apply_theme(self.ui_prefs.get("theme", "Light"))
            self._status("Settings saved.")

    def _export_html(self) -> None:
        if not self.current_scan: return
        default = self._default_export_path("html")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export HTML report", default, "HTML files (*.html)")
        if not path: return
        write_html_report(self.current_scan, path)
        self._status(f"HTML report saved: {path}")
        self._log(f"HTML report → {path}")

    def _export_pdf(self) -> None:
        if not self.current_scan: return
        default = self._default_export_path("pdf")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF report", default, "PDF files (*.pdf)")
        if not path: return
        try:
            write_pdf_report(self.current_scan, path)
        except Exception as e:
            QMessageBox.critical(self, "PDF export failed", str(e))
            return
        self._status(f"PDF report saved: {path}")
        self._log(f"PDF report → {path}")

    def _export_json(self) -> None:
        if not self.current_scan: return
        default = self._default_export_path("json")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", default, "JSON files (*.json)")
        if not path: return
        Path(path).write_text(self.current_scan.to_json())
        self._status(f"JSON saved: {path}")
        self._log(f"JSON → {path}")

    def _default_export_path(self, ext: str) -> str:
        folder = Path(self.ui_prefs.get("export_dir",
                                         str(Path.home() / "IoTGuard-reports")))
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return str(folder / f"iotguard-{stamp}.{ext}")

    def _on_scan_loaded_from_history(self, scan: ScanResult) -> None:
        self._load_scan(scan)
        self.tabs.setCurrentWidget(self.tab_dashboard)

    # -- misc ----------------------------------------------------------------

    def _about(self) -> None:
        QMessageBox.about(
            self, "About IoTGuard",
            "<h3>IoTGuard</h3>"
            "<p>WiFi & IoT vulnerability assessment.</p>"
            "<p>CVSS 3.1 scoring · OWASP IoT Top 10 · CVE enrichment · "
            "scan-history diff.</p>"
            "<p style='color:#6b7280'>Use only on networks and devices you "
            "are authorized to test.</p>"
        )

    def _status(self, text: str) -> None:
        self.statusBar().showMessage(text)

    def _log(self, line: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.tab_log.append(f"<span style='color:#6b7280'>{ts}</span> "
                            f"{html.escape(line)}")

    def closeEvent(self, ev):
        try:
            self.db.close()
        except Exception:
            pass
        try:
            self.device_store.close()
        except Exception:
            pass
        super().closeEvent(ev)
