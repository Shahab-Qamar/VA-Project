#!/usr/bin/env python3
"""
IoTGuard — main entry point.

Usage:
    python3 main.py                    # launch GUI
    python3 main.py --demo             # launch GUI with demo mode toggled on
    python3 main.py --cli-demo         # run a demo scan and print summary
    python3 main.py --version
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="iotguard",
                                description="IoT & WiFi vulnerability assessment")
    p.add_argument("--demo", action="store_true",
                   help="launch GUI pre-toggled into demo mode")
    p.add_argument("--cli-demo", action="store_true",
                   help="run a demo scan in the terminal and exit")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="enable debug logging")
    p.add_argument("--version", action="version", version="IoTGuard 1.0.0")
    return p.parse_args()


def _cli_demo() -> int:
    from iotguard.scanners.demo_scanner import build_demo_scan
    from iotguard.reporting.html_report import write_html_report
    from iotguard.reporting.pdf_report import write_pdf_report

    scan = build_demo_scan()
    sm = scan.summary()
    print("IoTGuard demo scan")
    print("-" * 50)
    print(f"  interface : {scan.interface}")
    print(f"  subnet    : {scan.subnet}")
    print(f"  devices   : {sm['device_count']}")
    print(f"  WiFi nets : {sm['wifi_count']}")
    print(f"  findings  : {sm['total_findings']}")
    print(f"  risks     : {sm['risk_counts']}")
    print()
    for d in scan.devices:
        print(f"  [{d.highest_risk.value:8s}] {d.display_name:28s}  "
              f"{d.ip or '-':15s}  {d.vendor}")

    out_dir = Path.home() / "IoTGuard-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = write_html_report(scan, out_dir / "demo.html")
    pdf_path  = write_pdf_report(scan,  out_dir / "demo.pdf")
    print()
    print(f"  HTML report → {html_path}")
    print(f"  PDF report  → {pdf_path}")
    return 0


def _run_gui(demo_override: bool = False) -> int:
    from PyQt6.QtWidgets import QApplication
    from iotguard.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("IoTGuard")
    app.setOrganizationName("IoTGuard")

    window = MainWindow()
    if demo_override:
        window.options.demo_mode = True
    window.show()
    return app.exec()


def main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.cli_demo:
        return _cli_demo()
    return _run_gui(demo_override=args.demo)


if __name__ == "__main__":
    sys.exit(main())
