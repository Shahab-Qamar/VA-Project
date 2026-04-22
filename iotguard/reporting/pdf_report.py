"""
PDF report writer using ReportLab.

Produces an A4 portrait report matching the visual style of the HTML report:
  * Cover block with scan metadata
  * Risk-summary stat grid + horizontal risk-distribution bar
  * Device and WiFi overview tables
  * Detailed findings grouped by target

ReportLab is pure-Python, no system dependencies, and handles flowables
with automatic page breaks — good fit for variable-length reports.
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table,
    TableStyle, KeepTogether, PageBreak,
)

from ..core.models import ScanResult, RiskLevel


# -- palette -----------------------------------------------------------------

RISK_COLORS = {
    "Info":     colors.HexColor("#6b7280"),
    "Low":      colors.HexColor("#10b981"),
    "Medium":   colors.HexColor("#f59e0b"),
    "High":     colors.HexColor("#ef4444"),
    "Critical": colors.HexColor("#991b1b"),
}
ACCENT   = colors.HexColor("#1d4ed8")
INK      = colors.HexColor("#0b1220")
MUTED    = colors.HexColor("#6b7280")
BORDER   = colors.HexColor("#e5e7eb")
PANEL_BG = colors.HexColor("#f8fafc")


# -- styles ------------------------------------------------------------------

def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="Brand", fontName="Helvetica-Bold",
                          fontSize=14, textColor=ACCENT, spaceAfter=2))
    ss.add(ParagraphStyle(name="H1", fontName="Helvetica-Bold",
                          fontSize=20, textColor=INK, spaceAfter=8))
    ss.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold",
                          fontSize=13, textColor=INK,
                          spaceBefore=14, spaceAfter=6,
                          borderPadding=(0, 0, 3, 0),
                          borderColor=BORDER, borderWidth=0))
    ss.add(ParagraphStyle(name="H3", fontName="Helvetica-Bold",
                          fontSize=10, textColor=MUTED,
                          spaceBefore=10, spaceAfter=4))
    ss.add(ParagraphStyle(name="Meta", fontName="Helvetica",
                          fontSize=9, textColor=MUTED, leading=13))
    ss.add(ParagraphStyle(name="Body", fontName="Helvetica",
                          fontSize=9.5, textColor=INK, leading=13,
                          alignment=TA_LEFT))
    ss.add(ParagraphStyle(name="Mono", fontName="Courier",
                          fontSize=8.5, textColor=MUTED, leading=12))
    ss.add(ParagraphStyle(name="FindTitle", fontName="Helvetica-Bold",
                          fontSize=10.5, textColor=INK, spaceAfter=3))
    return ss


# -- page template -----------------------------------------------------------

def _make_doc(path: Path) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title="IoTGuard Report", author="IoTGuard",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="body",
                  showBoundary=0)

    def _footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, 10 * mm,
                          "IoTGuard vulnerability assessment report")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm,
                               f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=frame, onPage=_footer)])
    return doc


# -- building blocks ---------------------------------------------------------

def _risk_pill(text: str, risk: str):
    color = RISK_COLORS.get(risk, MUTED)
    t = Table([[text]], colWidths=[18 * mm], rowHeights=[5 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR",  (0, 0), (-1, -1), colors.white),
        ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("ROUNDEDCORNERS", [2, 2, 2, 2]),
    ]))
    return t


def _stat_card(value, label, color=INK):
    t = Table([[Paragraph(f'<font size="16"><b>{value}</b></font>', ParagraphStyle(
                    "s", fontName="Helvetica-Bold", fontSize=16, textColor=color,
                    alignment=1))],
               [Paragraph(label, ParagraphStyle(
                    "l", fontName="Helvetica", fontSize=7, textColor=MUTED,
                    alignment=1))]],
              colWidths=[34 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX",        (0, 0), (-1, -1), 0.4, BORDER),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _risk_bar(risk_counts: dict, width: float = 170 * mm, height: float = 5 * mm):
    total = sum(risk_counts.values()) or 1
    order = ["Critical", "High", "Medium", "Low", "Info"]
    # build segment columns proportional to counts
    segs = [(k, risk_counts.get(k, 0)) for k in order if risk_counts.get(k, 0) > 0]
    if not segs:
        segs = [("Info", 1)]
    col_widths = [width * (v / total) for _, v in segs]
    t = Table([[""] * len(segs)], colWidths=col_widths, rowHeights=[height])
    style = [
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]
    for i, (k, _) in enumerate(segs):
        style.append(("BACKGROUND", (i, 0), (i, 0), RISK_COLORS[k]))
    t.setStyle(TableStyle(style))
    return t


def _devices_table(scan: ScanResult):
    header = ["Device", "Vendor", "Type", "IP / MAC", "Ports", "Risk"]
    rows = [header]
    for d in scan.devices:
        rows.append([
            Paragraph(f"<b>{_esc(d.display_name)}</b>", _small()),
            Paragraph(_esc(d.vendor or "-"), _small()),
            Paragraph(_esc(d.device_type.value), _small()),
            Paragraph(f"{_esc(d.ip or '-')}<br/><font face='Courier' size='7'>"
                      f"{_esc(d.mac or '-')}</font>", _small()),
            str(len(d.open_ports)),
            Paragraph(f"<b>{d.highest_risk.value}</b>", ParagraphStyle(
                "r", fontName="Helvetica-Bold", fontSize=8,
                textColor=RISK_COLORS[d.highest_risk.value])),
        ])
    if len(rows) == 1:
        rows.append(["", "", "No devices discovered.", "", "", ""])
    t = Table(rows, colWidths=[36*mm, 30*mm, 26*mm, 42*mm, 12*mm, 16*mm],
              repeatRows=1)
    t.setStyle(_table_style())
    return t


def _wifi_table(scan: ScanResult):
    header = ["Network", "BSSID", "Ch", "Signal", "Encryption", "Findings"]
    rows = [header]
    for w in scan.wifi_networks:
        rows.append([
            Paragraph(f"<b>{_esc(w.ssid) if w.ssid else '&lt;hidden&gt;'}</b>"
                      + (" <font color='#991b1b'>rogue?</font>" if w.rogue_suspected else ""),
                      _small()),
            Paragraph(f"<font face='Courier' size='7'>{_esc(w.bssid)}</font>", _small()),
            str(w.channel),
            f"{w.signal_dbm} dBm",
            Paragraph(_esc(w.encryption.value),
                      _small_bold(RISK_COLORS["Critical"] if w.encryption.is_weak else INK)),
            str(len(w.findings)),
        ])
    if len(rows) == 1:
        rows.append(["", "No WiFi networks scanned.", "", "", "", ""])
    t = Table(rows, colWidths=[36*mm, 34*mm, 10*mm, 22*mm, 26*mm, 20*mm],
              repeatRows=1)
    t.setStyle(_table_style())
    return t


def _finding_block(f, styles):
    chips = []
    if f.cvss_score:
        chips.append(f"CVSS {f.cvss_score:.1f}")
    if f.owasp_iot:
        chips.append(f.owasp_iot)
    if f.cve_ids:
        chips.extend(f.cve_ids)
    chip_str = "  ·  ".join(chips)

    header_row = Table(
        [[_risk_pill(f.risk.value, f.risk.value),
          Paragraph(f"<b>{_esc(f.title)}</b>", styles["FindTitle"])]],
        colWidths=[22 * mm, None],
    )
    header_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))

    parts = [
        header_row,
        Paragraph(_esc(f.description), styles["Body"]),
        Paragraph(f"<b>Remediation:</b> {_esc(f.remediation)}", styles["Body"]),
    ]
    if f.evidence:
        parts.append(Paragraph(f"<b>Evidence:</b> <font face='Courier' size='8'>"
                               f"{_esc(f.evidence)}</font>", styles["Body"]))
    if f.cvss_vector:
        parts.append(Paragraph(_esc(f.cvss_vector), styles["Mono"]))
    if chip_str:
        parts.append(Paragraph(chip_str, styles["Meta"]))
    parts.append(Spacer(1, 4))

    # Wrap in a KeepTogether to avoid splitting mid-finding across pages
    return KeepTogether(parts)


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), PANEL_BG),
        ("TEXTCOLOR",    (0, 0), (-1, 0), MUTED),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("ALIGN",        (4, 1), (5, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TEXTCOLOR",    (0, 1), (-1, -1), INK),
        ("LINEBELOW",    (0, 0), (-1, 0), 0.5, BORDER),
        ("LINEBELOW",    (0, 1), (-1, -2), 0.3, BORDER),
        ("BOX",          (0, 0), (-1, -1), 0.4, BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ])


def _small():
    return ParagraphStyle("s", fontName="Helvetica", fontSize=8,
                          textColor=INK, leading=11)

def _small_bold(color):
    return ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=8,
                          textColor=color, leading=11)


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# -- public entrypoint -------------------------------------------------------

def write_pdf_report(scan: ScanResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = _make_doc(path)
    ss = _styles()

    story = []
    summary = scan.summary()
    rc = summary["risk_counts"]

    # header
    story.append(Paragraph("IoTGuard", ss["Brand"]))
    story.append(Paragraph("Vulnerability Assessment Report", ss["H1"]))
    story.append(Paragraph(
        f"<b>Started:</b> {_esc(scan.started_at)}<br/>"
        f"<b>Finished:</b> {_esc(scan.finished_at or '—')}<br/>"
        f"<b>Interface:</b> {_esc(scan.interface or '—')} &nbsp;&nbsp;"
        f"<b>Subnet:</b> {_esc(scan.subnet or '—')}<br/>"
        f"<b>Scan ID:</b> <font face='Courier'>{_esc(scan.scan_id)}</font>",
        ss["Meta"]))
    story.append(Spacer(1, 8))

    if scan.demo_mode:
        story.append(Paragraph("<b>Demo data.</b> This report was generated from the "
                               "built-in simulated scan.", ParagraphStyle(
                        "demo", parent=ss["Body"], backColor=colors.HexColor("#eff6ff"),
                        borderColor=colors.HexColor("#93c5fd"), borderWidth=0.5,
                        borderPadding=6, textColor=colors.HexColor("#1e40af"))))
        story.append(Spacer(1, 4))
    if scan.lab_mode:
        story.append(Paragraph("<b>Lab Mode.</b> Active credential testing was permitted. "
                               "Only run against systems you are authorized to test.",
                      ParagraphStyle(
                        "lab", parent=ss["Body"], backColor=colors.HexColor("#fff7ed"),
                        borderColor=colors.HexColor("#fdba74"), borderWidth=0.5,
                        borderPadding=6, textColor=colors.HexColor("#9a3412"))))
        story.append(Spacer(1, 8))

    # stat grid
    stats = Table([[
        _stat_card(summary["device_count"], "DEVICES"),
        _stat_card(summary["wifi_count"],    "WIFI NETWORKS"),
        _stat_card(rc.get("Critical", 0),     "CRITICAL", RISK_COLORS["Critical"]),
        _stat_card(rc.get("High", 0),         "HIGH",     RISK_COLORS["High"]),
        _stat_card(summary["total_findings"], "FINDINGS"),
    ]], colWidths=[34*mm]*5)
    stats.setStyle(TableStyle([("LEFTPADDING", (0,0), (-1,-1), 2),
                               ("RIGHTPADDING", (0,0), (-1,-1), 2)]))
    story.append(stats)
    story.append(Spacer(1, 10))

    story.append(Paragraph("RISK DISTRIBUTION", ss["H3"]))
    story.append(_risk_bar(rc))
    story.append(Spacer(1, 4))

    # device + wifi overview
    story.append(Paragraph("Discovered devices", ss["H2"]))
    story.append(_devices_table(scan))
    story.append(Paragraph("Nearby WiFi networks", ss["H2"]))
    story.append(_wifi_table(scan))

    # detailed findings
    has_findings = (any(w.findings for w in scan.wifi_networks) or
                    any(d.findings for d in scan.devices))
    if has_findings:
        story.append(PageBreak())
        story.append(Paragraph("Detailed findings", ss["H2"]))

        for w in scan.wifi_networks:
            if not w.findings:
                continue
            story.append(Paragraph(
                f"WiFi: {_esc(w.ssid) if w.ssid else '&lt;hidden&gt;'} "
                f"<font face='Courier' size='8'>{_esc(w.bssid)}</font>",
                ss["H3"]))
            for f in sorted(w.findings, key=lambda f: -f.risk.order):
                story.append(_finding_block(f, ss))

        for d in scan.devices:
            if not d.findings:
                continue
            story.append(Paragraph(
                f"Device: {_esc(d.display_name)} "
                f"<font face='Courier' size='8'>{_esc(d.ip or d.mac)}</font>",
                ss["H3"]))
            for f in sorted(d.findings, key=lambda f: -f.risk.order):
                story.append(_finding_block(f, ss))
    else:
        story.append(Paragraph("No security findings identified.", ss["Body"]))

    doc.build(story)
    return path
