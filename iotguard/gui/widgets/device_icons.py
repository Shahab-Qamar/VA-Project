"""
Minimal inline-SVG icon pack for device types.

Each icon is a clean 24×24 line-based SVG. They're generated at runtime
with parameterized stroke/fill so we can tint per risk level and avoid
bundling binary assets.

Usage:
    pix = device_icon_pixmap(DeviceType.CAMERA, size=40, risk_color="#991b1b")
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QByteArray, QSize
from PyQt6.QtGui import QPixmap, QPainter
from PyQt6.QtSvg import QSvgRenderer

from ...core.models import DeviceType, RiskLevel


# 24x24 viewBox, 1.75 stroke width, no fill (except where noted).
# Paths kept compact but recognizable.

_ICONS: dict[DeviceType, str] = {
    DeviceType.ROUTER: """
        <rect x="3" y="11" width="18" height="8" rx="1.5"/>
        <line x1="7" y1="15" x2="7.01" y2="15" stroke-width="3" stroke-linecap="round"/>
        <line x1="11" y1="15" x2="11.01" y2="15" stroke-width="3" stroke-linecap="round"/>
        <path d="M6 11 V8 M12 11 V5 M18 11 V8"/>
    """,
    DeviceType.CAMERA: """
        <rect x="3" y="6" width="14" height="12" rx="1.5"/>
        <path d="M17 10 l4 -2 v8 l-4 -2 z"/>
        <circle cx="9" cy="12" r="2.5" fill="currentColor" fill-opacity="0.3"/>
    """,
    DeviceType.SMART_TV: """
        <rect x="2" y="4" width="20" height="14" rx="1.5"/>
        <line x1="8" y1="21" x2="16" y2="21"/>
        <line x1="12" y1="18" x2="12" y2="21"/>
    """,
    DeviceType.SMART_SPEAKER: """
        <rect x="5" y="3" width="14" height="18" rx="3"/>
        <circle cx="12" cy="9" r="2.5"/>
        <circle cx="12" cy="16" r="1"/>
    """,
    DeviceType.SMART_BULB: """
        <path d="M9 18 h6 M10 21 h4"/>
        <path d="M12 2 a6 6 0 0 1 4 10 c-1 1 -1.5 2 -1.5 3 h-5 c0 -1 -0.5 -2 -1.5 -3 A6 6 0 0 1 12 2 z"/>
    """,
    DeviceType.SMART_PLUG: """
        <path d="M9 2 v4 M15 2 v4"/>
        <rect x="6" y="6" width="12" height="8" rx="2"/>
        <path d="M12 14 v4 a2 2 0 0 1-2 2 h-1"/>
    """,
    DeviceType.THERMOSTAT: """
        <circle cx="12" cy="12" r="9"/>
        <path d="M12 7 v5 l3 2"/>
    """,
    DeviceType.PRINTER: """
        <path d="M6 9 V3 h12 v6"/>
        <rect x="3" y="9" width="18" height="8" rx="1.5"/>
        <rect x="6" y="15" width="12" height="6"/>
        <circle cx="18" cy="12" r="0.8" fill="currentColor"/>
    """,
    DeviceType.NAS: """
        <rect x="3" y="5" width="18" height="5" rx="1.5"/>
        <rect x="3" y="13" width="18" height="5" rx="1.5"/>
        <circle cx="7" cy="7.5" r="0.7" fill="currentColor"/>
        <circle cx="7" cy="15.5" r="0.7" fill="currentColor"/>
        <line x1="11" y1="7.5" x2="18" y2="7.5"/>
        <line x1="11" y1="15.5" x2="18" y2="15.5"/>
    """,
    DeviceType.PHONE: """
        <rect x="7" y="2" width="10" height="20" rx="2"/>
        <line x1="11" y1="18" x2="13" y2="18"/>
    """,
    DeviceType.COMPUTER: """
        <rect x="3" y="4" width="18" height="12" rx="1.5"/>
        <line x1="2" y1="20" x2="22" y2="20"/>
        <line x1="9" y1="16" x2="9" y2="20"/>
        <line x1="15" y1="16" x2="15" y2="20"/>
    """,
    DeviceType.WEARABLE: """
        <rect x="6" y="7" width="12" height="10" rx="2"/>
        <path d="M9 7 V3 h6 v4 M9 17 v4 h6 v-4"/>
    """,
    DeviceType.BLE_PERIPHERAL: """
        <path d="M7 7 l10 10 l-5 5 v-20 l5 5 l-10 10"/>
    """,
    DeviceType.IOT_GENERIC: """
        <rect x="4" y="4" width="16" height="16" rx="2.5"/>
        <circle cx="12" cy="12" r="2" fill="currentColor" fill-opacity="0.25"/>
        <line x1="8" y1="12" x2="10" y2="12"/>
        <line x1="14" y1="12" x2="16" y2="12"/>
        <line x1="12" y1="8" x2="12" y2="10"/>
        <line x1="12" y1="14" x2="12" y2="16"/>
    """,
    DeviceType.UNKNOWN: """
        <circle cx="12" cy="12" r="9"/>
        <path d="M9 9 a3 3 0 0 1 6 0 c0 2 -3 2 -3 4 M12 17.5 v0.01" stroke-linecap="round"/>
    """,
}


def _svg_for(device_type: DeviceType, fg: str, bg: str | None = None) -> str:
    path = _ICONS.get(device_type, _ICONS[DeviceType.UNKNOWN]).strip()
    bg_rect = ""
    if bg:
        bg_rect = f'<rect x="0" y="0" width="24" height="24" rx="5" fill="{bg}"/>'
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'width="24" height="24" fill="none" stroke="{fg}" '
        f'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" '
        f'color="{fg}">'
        f'{bg_rect}{path}</svg>'
    )


def device_icon_pixmap(device_type: DeviceType, size: int = 40,
                       risk: RiskLevel | None = None,
                       tinted_background: bool = True) -> QPixmap:
    """Render the device icon for the given type. If a risk level is given,
    the icon is stroked in the risk color; otherwise it uses a neutral slate.
    """
    fg = "#1e293b"
    bg = None
    if risk is not None and risk != RiskLevel.INFO:
        fg = risk.color
        if tinted_background:
            # Very light tint of the risk color as a rounded-rect background.
            bg = _tint_bg(risk)
    elif tinted_background:
        bg = "#f1f5f9"

    svg = _svg_for(device_type, fg, bg)
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    p = QPainter(pm)
    renderer.render(p)
    p.end()
    return pm


def _tint_bg(risk: RiskLevel) -> str:
    return {
        RiskLevel.INFO:     "#f1f5f9",
        RiskLevel.LOW:      "#d1fae5",
        RiskLevel.MEDIUM:   "#fef3c7",
        RiskLevel.HIGH:     "#fee2e2",
        RiskLevel.CRITICAL: "#fecaca",
    }.get(risk, "#f1f5f9")
