"""
Improved Fing-style device card grid with richer info display.
Each card shows: icon, name, IP, vendor/OS, open ports, risk badge,
services tags, discovery sources, presence dot, gateway marker.
"""

from __future__ import annotations
import html

from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QMouseEvent, QFont
from PyQt6.QtWidgets import (
    QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QScrollArea,
    QGridLayout, QSizePolicy, QToolTip,
)

from ...core.models import Device, RiskLevel
from .device_icons import device_icon_pixmap

RISK_COLORS = {
    "Info": "#6b7280", "Low": "#10b981", "Medium": "#f59e0b",
    "High": "#ef4444", "Critical": "#991b1b",
}
RISK_BG = {
    "Info": "#f9fafb", "Low": "#f0fdf4", "Medium": "#fffbeb",
    "High": "#fff1f2", "Critical": "#fff1f2",
}
RISK_BORDER_WIDTH = {
    "Info": 1, "Low": 1, "Medium": 2, "High": 2, "Critical": 3,
}

SOURCE_ICONS = {
    "ARP": "🔗", "mDNS": "📡", "SSDP/UPnP": "📺",
    "BLE": "🔵", "Bluetooth": "🔵", "WiFi Beacon": "📶",
    "Nmap": "🔍", "Demo": "🎭",
}


class DeviceCard(QFrame):
    clicked = pyqtSignal(object)
    context_menu = pyqtSignal(object, object)

    CARD_WIDTH = 250
    CARD_HEIGHT = 190

    def __init__(self, device: Device, parent=None):
        super().__init__(parent)
        self.device = device
        self.setFixedSize(self.CARD_WIDTH, self.CARD_HEIGHT)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_style()
        self._build()

    def _apply_style(self) -> None:
        risk = self.device.highest_risk.value
        border_color = RISK_COLORS[risk]
        bg = RISK_BG[risk]
        bw = RISK_BORDER_WIDTH[risk]
        self.setStyleSheet(f"""
            DeviceCard {{
                background: {bg};
                border: {bw}px solid {border_color};
                border-radius: 12px;
            }}
            DeviceCard:hover {{
                border: 2px solid #2563eb;
                background: #eff6ff;
            }}
            QLabel {{ background: transparent; border: 0; }}
        """)

    def _build(self) -> None:
        d = self.device
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 8)
        root.setSpacing(3)

        # ── Row 1: icon + name + presence dot ────────────────────────────────
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        # Device type icon
        pix = device_icon_pixmap(d.device_type, size=36)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(pix)
        icon_lbl.setFixedSize(36, 36)
        row1.addWidget(icon_lbl)

        name_col = QVBoxLayout()
        name_col.setSpacing(1)

        name_lbl = QLabel(html.escape(d.display_name[:22]))
        font = QFont()
        font.setBold(True)
        font.setPointSize(10)
        name_lbl.setFont(font)
        name_lbl.setStyleSheet("color: #0f172a;")
        name_col.addWidget(name_lbl)

        type_lbl = QLabel(html.escape(d.device_type.value))
        type_lbl.setStyleSheet("color: #64748b; font-size: 9px;")
        name_col.addWidget(type_lbl)

        row1.addLayout(name_col)
        row1.addStretch()

        # Presence dot + gateway star
        dot_col = QVBoxLayout()
        dot_col.setSpacing(2)
        dot = QLabel("●" if d.online else "○")
        dot.setStyleSheet(f"color: {'#22c55e' if d.online else '#9ca3af'}; font-size: 14px;")
        dot.setToolTip("Online" if d.online else "Offline")
        dot_col.addWidget(dot)
        if d.is_gateway:
            gw_lbl = QLabel("⭐")
            gw_lbl.setToolTip("Default Gateway / Router")
            gw_lbl.setStyleSheet("font-size: 10px;")
            dot_col.addWidget(gw_lbl)
        dot_col.addStretch()
        row1.addLayout(dot_col)
        root.addLayout(row1)

        # ── Row 2: IP + MAC ──────────────────────────────────────────────────
        ip_text = d.ip or d.mac or "—"
        ip_lbl = QLabel(html.escape(ip_text))
        ip_lbl.setStyleSheet("color: #1d4ed8; font-family: monospace; font-size: 10px; font-weight: bold;")
        root.addWidget(ip_lbl)

        # ── Row 3: Vendor / OS ────────────────────────────────────────────────
        vendor_text = d.vendor or d.upnp_manufacturer or ""
        if d.os_guess:
            vendor_text = d.os_guess[:35]
        elif vendor_text:
            vendor_text = vendor_text[:35]
        if vendor_text:
            vendor_lbl = QLabel(html.escape(vendor_text))
            vendor_lbl.setStyleSheet("color: #475569; font-size: 9px;")
            root.addWidget(vendor_lbl)

        # ── Row 4: Open ports summary ─────────────────────────────────────────
        if d.open_ports:
            ports_str = ", ".join(str(p.port) for p in d.open_ports[:6])
            if len(d.open_ports) > 6:
                ports_str += f" +{len(d.open_ports)-6}"
            ports_lbl = QLabel(f"Ports: {ports_str}")
            ports_lbl.setStyleSheet("color: #64748b; font-size: 8px; font-family: monospace;")
            ports_lbl.setWordWrap(False)
            root.addWidget(ports_lbl)

        root.addStretch()

        # ── Bottom row: risk badge + findings count + discovery sources ───────
        bottom = QHBoxLayout()
        bottom.setSpacing(4)

        risk = d.highest_risk.value
        risk_color = RISK_COLORS[risk]
        badge = QLabel(risk)
        badge.setStyleSheet(
            f"background: {risk_color}; color: white; border-radius: 8px; "
            f"padding: 1px 7px; font-size: 9px; font-weight: bold;"
        )
        bottom.addWidget(badge)

        if d.findings:
            count_lbl = QLabel(f"⚠ {len(d.findings)}")
            count_lbl.setStyleSheet(f"color: {risk_color}; font-size: 9px; font-weight: bold;")
            count_lbl.setToolTip(f"{len(d.findings)} findings")
            bottom.addWidget(count_lbl)

        bottom.addStretch()

        # Discovery sources (small icons)
        for src in d.discovery_sources[:3]:
            icon = SOURCE_ICONS.get(src.value, "•")
            src_lbl = QLabel(icon)
            src_lbl.setToolTip(src.value)
            src_lbl.setStyleSheet("font-size: 10px;")
            bottom.addWidget(src_lbl)

        root.addLayout(bottom)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.device)
        elif event.button() == Qt.MouseButton.RightButton:
            self.context_menu.emit(self.device, event.globalPosition().toPoint())

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        self.clicked.emit(self.device)


class DeviceCardGrid(QWidget):
    device_selected = pyqtSignal(object)
    device_context_menu = pyqtSignal(object, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices: list[Device] = []
        self._cards: list[DeviceCard] = []
        self._filter_text = ""
        self._filter_risk = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setStyleSheet("background: #f1f5f9;")

        self._container = QWidget()
        self._container.setStyleSheet("background: #f1f5f9;")
        self._grid = QGridLayout(self._container)
        self._grid.setContentsMargins(12, 12, 12, 12)
        self._grid.setSpacing(10)

        self._scroll.setWidget(self._container)
        outer.addWidget(self._scroll)

    def set_devices(self, devices: list[Device]) -> None:
        self._devices = devices
        self._rebuild()

    def set_filter(self, text: str, risk: str = "") -> None:
        self._filter_text = text.lower()
        self._filter_risk = risk
        self._rebuild()

    def _matches_filter(self, d: Device) -> bool:
        if self._filter_risk and d.highest_risk.value != self._filter_risk:
            return False
        if not self._filter_text:
            return True
        haystack = " ".join([
            d.display_name, d.ip, d.mac, d.vendor,
            d.hostname, d.device_type.value,
            d.os_guess or "",
            " ".join(str(p.port) for p in d.open_ports),
        ]).lower()
        return self._filter_text in haystack

    def _rebuild(self) -> None:
        # Clear existing cards
        for card in self._cards:
            card.setParent(None)
            card.deleteLater()
        self._cards.clear()

        visible = [d for d in self._devices if self._matches_filter(d)]

        # Sort: critical first, then by IP
        visible.sort(key=lambda d: (-d.highest_risk.order, d.ip or ""))

        cols = max(1, (self._scroll.viewport().width() - 24) // (DeviceCard.CARD_WIDTH + 10))

        for idx, device in enumerate(visible):
            card = DeviceCard(device)
            card.clicked.connect(self.device_selected)
            card.context_menu.connect(self.device_context_menu)
            self._grid.addWidget(card, idx // cols, idx % cols)
            self._cards.append(card)

        # Fill remaining cells with spacers
        total = len(visible)
        remaining = cols - (total % cols) if total % cols else 0
        for i in range(remaining):
            spacer = QWidget()
            spacer.setFixedSize(DeviceCard.CARD_WIDTH, DeviceCard.CARD_HEIGHT)
            self._grid.addWidget(spacer, (total + i) // cols, (total + i) % cols)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._rebuild()
