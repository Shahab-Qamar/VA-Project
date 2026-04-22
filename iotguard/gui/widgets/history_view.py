"""
Scan-history tab. Lists every stored scan, supports delete + load, and
renders a diff against the currently-loaded scan when selected.
"""

from __future__ import annotations

import html

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QTextBrowser, QSplitter, QLabel, QMessageBox,
)

from ...core.database import HistoryDB, diff_scans
from ...core.models import ScanResult


RISK_COLORS = {
    "Info": "#6b7280", "Low": "#10b981", "Medium": "#f59e0b",
    "High": "#ef4444", "Critical": "#991b1b",
}


class HistoryView(QWidget):
    scan_loaded = pyqtSignal(object)              # ScanResult

    def __init__(self, db: HistoryDB, parent=None):
        super().__init__(parent)
        self.db = db
        self._current_scan: ScanResult | None = None
        self._build_ui()
        self.refresh()

    def set_current_scan(self, scan: ScanResult | None) -> None:
        """The scan currently loaded in the main dashboard. The history diff
        compares each stored scan against this."""
        self._current_scan = scan
        self._update_diff()

    def refresh(self) -> None:
        rows = self.db.list_scans(limit=200)
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            items = [
                QTableWidgetItem(row["started_at"][:19].replace("T", " ")),
                QTableWidgetItem(row["subnet"] or "-"),
                QTableWidgetItem(row["interface"] or "-"),
                QTableWidgetItem(str(row["device_count"])),
                QTableWidgetItem(str(row["wifi_count"])),
                QTableWidgetItem(str(row["finding_count"])),
                QTableWidgetItem(row["worst_risk"] or "-"),
            ]
            for c, it in enumerate(items):
                it.setData(Qt.ItemDataRole.UserRole, row["scan_id"])
                if c == 6 and it.text() in RISK_COLORS:
                    from PyQt6.QtGui import QColor
                    it.setForeground(QColor(RISK_COLORS[it.text()]))
                    it.setData(Qt.ItemDataRole.FontRole, None)
                self.table.setItem(r, c, it)
        self._update_diff()

    # -- UI ------------------------------------------------------------------

    def _build_ui(self) -> None:
        lay = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.btn_load   = QPushButton("Load selected")
        self.btn_delete = QPushButton("Delete selected")
        self.btn_refresh = QPushButton("Refresh")
        toolbar.addWidget(self.btn_load)
        toolbar.addWidget(self.btn_delete)
        toolbar.addWidget(self.btn_refresh)
        toolbar.addStretch(1)
        lay.addLayout(toolbar)

        split = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Started", "Subnet", "Interface", "Devices", "WiFi",
             "Findings", "Worst risk"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        hdr = self.table.horizontalHeader()
        for i in range(6):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        split.addWidget(self.table)

        self.diff_browser = QTextBrowser()
        self.diff_browser.setHtml(self._placeholder_html())
        split.addWidget(self.diff_browser)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)

        # signals
        self.btn_load.clicked.connect(self._on_load)
        self.btn_delete.clicked.connect(self._on_delete)
        self.btn_refresh.clicked.connect(self.refresh)
        self.table.itemSelectionChanged.connect(self._update_diff)
        self.table.doubleClicked.connect(lambda _: self._on_load())

    # -- signals -------------------------------------------------------------

    def _selected_id(self) -> str | None:
        items = self.table.selectedItems()
        if not items:
            return None
        return items[0].data(Qt.ItemDataRole.UserRole)

    def _on_load(self) -> None:
        sid = self._selected_id()
        if not sid:
            return
        scan = self.db.load(sid)
        if scan is None:
            QMessageBox.warning(self, "History", "Failed to load scan payload.")
            return
        self.scan_loaded.emit(scan)

    def _on_delete(self) -> None:
        sid = self._selected_id()
        if not sid:
            return
        if QMessageBox.question(
            self, "Delete scan",
            "Permanently delete this stored scan?",
        ) != QMessageBox.StandardButton.Yes:
            return
        self.db.delete(sid)
        self.refresh()

    def _update_diff(self) -> None:
        sid = self._selected_id()
        if not sid or self._current_scan is None:
            self.diff_browser.setHtml(self._placeholder_html())
            return
        other = self.db.load(sid)
        if other is None or other.scan_id == self._current_scan.scan_id:
            self.diff_browser.setHtml(self._placeholder_html())
            return

        d = diff_scans(other, self._current_scan)
        rows = []
        rows.append("<h3 style='margin:0 0 8px 0'>Diff "
                    "(selected history scan → currently loaded scan)</h3>")
        rows.append(self._diff_block(
            "New devices", d["new_devices"], "#10b981"))
        rows.append(self._diff_block(
            "Removed devices", d["removed_devices"], "#ef4444"))

        if d["changed_devices"]:
            rows.append("<h4 style='margin:14px 0 4px 0'>Changed devices</h4>")
            for cd in d["changed_devices"]:
                rows.append(
                    f"<div style='padding:6px 10px;background:#f8fafc;"
                    f"border-radius:6px;margin:4px 0;font-size:13px'>"
                    f"<b>{html.escape(cd['device'])}</b>  "
                    f"<code style='color:#6b7280'>{html.escape(cd['ip'] or cd['mac'])}</code>")
                if cd["new_ports"]:
                    rows.append(f"<br>New ports: <span style='color:#047857'>"
                                f"{html.escape(str(cd['new_ports']))}</span>")
                if cd["closed_ports"]:
                    rows.append(f"<br>Closed ports: <span style='color:#b91c1c'>"
                                f"{html.escape(str(cd['closed_ports']))}</span>")
                if cd["new_findings"]:
                    rows.append(f"<br>New findings: <span style='color:#b45309'>"
                                f"{html.escape(', '.join(cd['new_findings']))}</span>")
                if cd["resolved_findings"]:
                    rows.append(f"<br>Resolved findings: <span style='color:#047857'>"
                                f"{html.escape(', '.join(cd['resolved_findings']))}</span>")
                rows.append("</div>")

        self.diff_browser.setHtml(
            "<div style='font-family:-apple-system,Segoe UI,sans-serif;"
            "font-size:13px;line-height:1.5'>" + "".join(rows) + "</div>"
        )

    @staticmethod
    def _diff_block(title: str, items: list[str], color: str) -> str:
        if not items:
            return (f"<p style='margin:4px 0'><b>{title}:</b> "
                    f"<span style='color:#6b7280'>none</span></p>")
        chips = "".join(
            f"<span style='background:{color};color:white;padding:1px 8px;"
            f"border-radius:8px;font-size:11px;margin-right:4px;"
            f"display:inline-block;margin-bottom:4px'>{html.escape(x)}</span>"
            for x in items
        )
        return f"<p style='margin:6px 0'><b>{title}:</b><br>{chips}</p>"

    @staticmethod
    def _placeholder_html() -> str:
        return ("<div style='padding:20px;color:#6b7280;font-size:13px'>"
                "Select a stored scan to diff it against the currently "
                "loaded scan. Double-click a row to load it.</div>")
