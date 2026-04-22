"""
Dashboard charts powered by matplotlib embedded in PyQt6.

Three charts live in a single widget so the main window can drop it in:
    1. Risk distribution (horizontal bar)
    2. Device types (donut)
    3. Top 5 CVSS scores per device (horizontal bar)

matplotlib is used instead of pyqtgraph for two reasons:
  * works with the widely-installed `matplotlib` package
  * produces publication-quality rendering that also looks good in PDFs
    if we ever want to embed a chart there.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QGridLayout, QLabel, QSizePolicy

import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from ...core.models import ScanResult, RiskLevel


RISK_COLORS = {
    "Info":     "#6b7280",
    "Low":      "#10b981",
    "Medium":   "#f59e0b",
    "High":     "#ef4444",
    "Critical": "#991b1b",
}

DONUT_PALETTE = [
    "#1d4ed8", "#10b981", "#f59e0b", "#8b5cf6",
    "#ef4444", "#06b6d4", "#f97316", "#84cc16", "#ec4899",
]


class _Canvas(FigureCanvas):
    def __init__(self, parent=None, figsize=(4, 2.6)):
        fig = Figure(figsize=figsize, facecolor="white", tight_layout=True)
        super().__init__(fig)
        self.setParent(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)


class DashboardCharts(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        grid = QGridLayout(self)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        self.title_risk   = QLabel("Risk distribution")
        self.title_types  = QLabel("Device types")
        self.title_topcve = QLabel("Highest-risk devices (by CVSS)")
        for lbl in (self.title_risk, self.title_types, self.title_topcve):
            lbl.setStyleSheet("font-weight:600;color:#374151;"
                              "text-transform:uppercase;letter-spacing:0.04em;"
                              "font-size:11px;")

        self.c_risk   = _Canvas()
        self.c_types  = _Canvas()
        self.c_topcve = _Canvas(figsize=(8, 2.6))

        grid.addWidget(self.title_risk,   0, 0)
        grid.addWidget(self.title_types,  0, 1)
        grid.addWidget(self.c_risk,       1, 0)
        grid.addWidget(self.c_types,      1, 1)
        grid.addWidget(self.title_topcve, 2, 0, 1, 2)
        grid.addWidget(self.c_topcve,     3, 0, 1, 2)

        grid.setRowStretch(1, 1)
        grid.setRowStretch(3, 1)

        self.clear()

    # -- public --------------------------------------------------------------

    def clear(self) -> None:
        for c in (self.c_risk, self.c_types, self.c_topcve):
            c.figure.clear()
            ax = c.figure.add_subplot(111)
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                    color="#9ca3af", fontsize=10, transform=ax.transAxes)
            ax.set_axis_off()
            c.draw()

    def update_from_scan(self, scan: ScanResult) -> None:
        self._draw_risk_bar(scan)
        self._draw_type_donut(scan)
        self._draw_top_cvss(scan)

    # -- individual charts ---------------------------------------------------

    def _draw_risk_bar(self, scan: ScanResult) -> None:
        rc = scan.summary()["risk_counts"]
        order = ["Critical", "High", "Medium", "Low", "Info"]
        values = [rc.get(k, 0) for k in order]
        colors_ = [RISK_COLORS[k] for k in order]

        fig = self.c_risk.figure
        fig.clear()
        ax = fig.add_subplot(111)
        y_pos = range(len(order))
        bars = ax.barh(y_pos, values, color=colors_, height=0.6)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(order, fontsize=9)
        ax.invert_yaxis()
        ax.tick_params(axis="x", labelsize=8)
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.spines["left"].set_color("#e5e7eb")
        ax.spines["bottom"].set_color("#e5e7eb")
        ax.grid(axis="x", linestyle="--", alpha=0.3)
        # value labels at end of bars
        for bar, v in zip(bars, values):
            if v > 0:
                ax.text(bar.get_width() + max(values) * 0.02,
                        bar.get_y() + bar.get_height() / 2,
                        str(v), va="center", fontsize=9)
        if max(values) == 0:
            ax.set_xlim(0, 1)
        else:
            ax.set_xlim(0, max(values) * 1.15)
        self.c_risk.draw()

    def _draw_type_donut(self, scan: ScanResult) -> None:
        from collections import Counter
        counts = Counter(d.device_type.value for d in scan.devices)
        fig = self.c_types.figure
        fig.clear()

        if not counts:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, "No devices", ha="center", va="center",
                    color="#9ca3af", fontsize=10, transform=ax.transAxes)
            ax.set_axis_off()
            self.c_types.draw()
            return

        labels, values = zip(*counts.most_common())
        palette = (DONUT_PALETTE * ((len(labels) // len(DONUT_PALETTE)) + 1))[:len(labels)]

        ax = fig.add_subplot(111)
        wedges, _ = ax.pie(
            values, colors=palette,
            wedgeprops=dict(width=0.35, edgecolor="white"),
            startangle=90,
        )
        ax.set_aspect("equal")
        ax.text(0, 0, f"{sum(values)}", ha="center", va="center",
                fontsize=16, fontweight="bold", color="#0b1220")
        ax.text(0, -0.18, "devices", ha="center", va="center",
                fontsize=8, color="#6b7280")
        ax.legend(wedges, [f"{l}  ({v})" for l, v in zip(labels, values)],
                  loc="center left", bbox_to_anchor=(1.02, 0.5),
                  fontsize=7, frameon=False)
        self.c_types.draw()

    def _draw_top_cvss(self, scan: ScanResult) -> None:
        devices = [d for d in scan.devices if d.risk_score > 0]
        devices.sort(key=lambda d: d.risk_score, reverse=True)
        devices = devices[:5]

        fig = self.c_topcve.figure
        fig.clear()
        ax = fig.add_subplot(111)

        if not devices:
            ax.text(0.5, 0.5, "No devices with CVSS findings",
                    ha="center", va="center", color="#9ca3af",
                    fontsize=10, transform=ax.transAxes)
            ax.set_axis_off()
            self.c_topcve.draw()
            return

        names  = [d.display_name[:28] for d in devices]
        scores = [d.risk_score for d in devices]
        colors_ = [RISK_COLORS[d.highest_risk.value] for d in devices]

        y_pos = range(len(devices))
        bars = ax.barh(y_pos, scores, color=colors_, height=0.6)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(names, fontsize=9)
        ax.invert_yaxis()
        ax.set_xlim(0, 10)
        ax.set_xlabel("CVSS 3.1 score", fontsize=8, color="#6b7280")
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.spines["left"].set_color("#e5e7eb")
        ax.spines["bottom"].set_color("#e5e7eb")
        ax.grid(axis="x", linestyle="--", alpha=0.3)
        ax.axvline(7.0, color="#ef4444", linestyle=":", linewidth=0.8, alpha=0.5)
        ax.axvline(9.0, color="#991b1b", linestyle=":", linewidth=0.8, alpha=0.5)
        for bar, v in zip(bars, scores):
            ax.text(bar.get_width() + 0.15,
                    bar.get_y() + bar.get_height() / 2,
                    f"{v:.1f}", va="center", fontsize=9)
        self.c_topcve.draw()
