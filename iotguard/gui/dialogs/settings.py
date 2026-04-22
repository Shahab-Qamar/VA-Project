"""
Settings dialog for scan configuration.

Exposes everything in ScanOptions plus a few UI preferences (theme, default
export location). Persisted to ~/.iotguard/config.json so the user doesn't
have to re-tick boxes every launch.
"""

from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit,
    QCheckBox, QDoubleSpinBox, QSpinBox, QComboBox, QPushButton, QGroupBox,
    QDialogButtonBox, QTabWidget, QWidget,
)

from ..scan_worker import ScanOptions


CONFIG_PATH = Path.home() / ".iotguard" / "config.json"


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------

def load_options() -> tuple[ScanOptions, dict]:
    """Return (ScanOptions, ui_prefs_dict). Missing/invalid => defaults."""
    try:
        raw = json.loads(CONFIG_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        raw = {}

    so_raw = raw.get("scan_options", {})
    ui_raw = raw.get("ui", {})

    opts = ScanOptions()
    for fld in ("interface", "subnet"):
        if fld in so_raw: setattr(opts, fld, str(so_raw[fld]))
    for fld in ("scan_wifi", "scan_network", "scan_bluetooth", "scan_ports",
                "enrich_cves", "lab_mode", "demo_mode", "include_classic_bt"):
        if fld in so_raw: setattr(opts, fld, bool(so_raw[fld]))
    for fld in ("port_timeout", "mdns_duration", "ssdp_duration", "ble_duration"):
        if fld in so_raw:
            try: setattr(opts, fld, float(so_raw[fld]))
            except (TypeError, ValueError): pass
    if "port_parallelism" in so_raw:
        try: opts.port_parallelism = int(so_raw["port_parallelism"])
        except (TypeError, ValueError): pass

    return opts, ui_raw


def save_options(opts: ScanOptions, ui_prefs: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "scan_options": {
            k: getattr(opts, k) for k in (
                "interface", "subnet", "scan_wifi", "scan_network",
                "scan_bluetooth", "scan_ports", "enrich_cves", "lab_mode",
                "demo_mode", "include_classic_bt", "port_parallelism",
                "port_timeout", "mdns_duration", "ssdp_duration", "ble_duration",
                "use_nmap_sweep", "deep_port_scan", "run_vuln_scripts",
                "passive_sniff", "passive_duration",
            )
        },
        "ui": ui_prefs,
    }
    CONFIG_PATH.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------

class SettingsDialog(QDialog):
    def __init__(self, options: ScanOptions, ui_prefs: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("IoTGuard Settings")
        self.resize(540, 520)
        self._opts = options
        self._ui = dict(ui_prefs)

        tabs = QTabWidget()
        tabs.addTab(self._build_scan_tab(),         "Scan")
        tabs.addTab(self._build_timing_tab(),       "Timing")
        tabs.addTab(self._build_integrations_tab(), "Integrations")
        tabs.addTab(self._build_ui_tab(),           "Appearance")

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(btns)

    # -- tabs ----------------------------------------------------------------

    def _build_scan_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self.e_interface = QLineEdit(self._opts.interface)
        self.e_interface.setPlaceholderText("auto-detect (e.g. wlan0)")
        form.addRow("Interface:", self.e_interface)

        self.e_subnet = QLineEdit(self._opts.subnet)
        self.e_subnet.setPlaceholderText("auto-detect (e.g. 192.168.1.0/24)")
        form.addRow("Subnet:", self.e_subnet)

        form.addRow(QLabel(""))  # spacer

        self.cb_wifi   = QCheckBox("Scan WiFi networks (nmcli)")
        self.cb_net    = QCheckBox("Network discovery (ARP + mDNS + SSDP)")
        self.cb_bt     = QCheckBox("Bluetooth / BLE proximity scan")
        self.cb_ports  = QCheckBox("Port + service scan (nmap / sockets)")
        self.cb_cve    = QCheckBox("CVE enrichment via NVD API")
        self.cb_classicbt = QCheckBox("Include classic Bluetooth (bluetoothctl)")

        self.cb_wifi.setChecked(self._opts.scan_wifi)
        self.cb_net.setChecked(self._opts.scan_network)
        self.cb_bt.setChecked(self._opts.scan_bluetooth)
        self.cb_ports.setChecked(self._opts.scan_ports)
        self.cb_cve.setChecked(self._opts.enrich_cves)
        self.cb_classicbt.setChecked(self._opts.include_classic_bt)

        # Grey out BT checkboxes if there's no adapter, so the user knows
        # why the scan will be skipped.
        try:
            from ..scanners.bluetooth_scanner import has_bluetooth_adapter
            bt_ok, bt_reason = has_bluetooth_adapter()
        except Exception:
            bt_ok, bt_reason = False, "detection failed"

        if not bt_ok:
            self.cb_bt.setChecked(False)
            self.cb_bt.setEnabled(False)
            self.cb_bt.setText(f"Bluetooth / BLE proximity scan — "
                               f"unavailable ({bt_reason})")
            self.cb_bt.setStyleSheet("color:#9ca3af;")
            self.cb_classicbt.setEnabled(False)
            self.cb_classicbt.setStyleSheet("color:#9ca3af;")

        self.cb_nmap_sweep  = QCheckBox("nmap host sweep (best discovery, needs nmap installed)")
        self.cb_deep_scan   = QCheckBox("Deep port scan (-sS -sV -O, needs root/cap_net_raw)")
        self.cb_vuln_scripts= QCheckBox("Run NSE vuln scripts (--script=vuln,auth — thorough but slow)")
        self.cb_passive     = QCheckBox("Passive wire sniff (catches devices blocking all probes)")

        self.cb_nmap_sweep.setChecked(self._opts.use_nmap_sweep)
        self.cb_deep_scan.setChecked(self._opts.deep_port_scan)
        self.cb_vuln_scripts.setChecked(self._opts.run_vuln_scripts)
        self.cb_passive.setChecked(self._opts.passive_sniff)

        for cb in (self.cb_wifi, self.cb_net, self.cb_bt,
                   self.cb_classicbt, self.cb_ports, self.cb_cve,
                   self.cb_nmap_sweep, self.cb_deep_scan,
                   self.cb_vuln_scripts, self.cb_passive):
            form.addRow("", cb)

        # Lab mode + demo get their own styled box
        dangerous = QGroupBox("Advanced")
        dlay = QVBoxLayout(dangerous)
        self.cb_lab = QCheckBox("Lab Mode — active default-credential testing")
        self.cb_lab.setChecked(self._opts.lab_mode)
        self.cb_lab.setStyleSheet("color:#b45309;font-weight:600;")

        self.cb_demo = QCheckBox("Demo mode (simulated devices — no real scan)")
        self.cb_demo.setChecked(self._opts.demo_mode)
        self.cb_demo.setStyleSheet("color:#1e40af;font-weight:600;")

        dlay.addWidget(self.cb_lab)
        dlay.addWidget(QLabel("  Only use against systems you are "
                              "authorized to test."))
        dlay.addWidget(self.cb_demo)

        form.addRow(dangerous)
        return w

    def _build_timing_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self.sp_mdns = self._dspin(self._opts.mdns_duration, 1.0, 30.0, 1.0)
        self.sp_ssdp = self._dspin(self._opts.ssdp_duration, 1.0, 30.0, 1.0)
        self.sp_ble  = self._dspin(self._opts.ble_duration,  2.0, 60.0, 1.0)
        self.sp_pt   = self._dspin(self._opts.port_timeout,  0.2, 10.0, 0.1)

        self.sp_par  = QSpinBox(); self.sp_par.setRange(1, 64)
        self.sp_par.setValue(self._opts.port_parallelism)

        form.addRow("mDNS duration (s):", self.sp_mdns)
        form.addRow("SSDP duration (s):", self.sp_ssdp)
        form.addRow("BLE duration (s):",  self.sp_ble)
        form.addRow("Port-scan timeout (s):", self.sp_pt)
        form.addRow("Port-scan parallelism:", self.sp_par)
        return w

    def _build_integrations_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        # Shodan API key
        self.e_shodan = QLineEdit(self._ui.get("shodan_api_key", ""))
        self.e_shodan.setEchoMode(QLineEdit.EchoMode.Password)
        self.e_shodan.setPlaceholderText("paste your Shodan API key here")
        form.addRow("Shodan API key:", self.e_shodan)

        hint = QLabel(
            "Used for the <b>internet exposure check</b> on the Network "
            "Health tab. Free keys at "
            "<a href='https://account.shodan.io/'>account.shodan.io</a>."
        )
        hint.setWordWrap(True)
        hint.setOpenExternalLinks(True)
        hint.setStyleSheet("color:#6b7280;font-size:11px;")
        form.addRow("", hint)

        form.addRow(QLabel(""))  # spacer

        # ip-api toggle
        self.cb_ip_api = QCheckBox("Allow outbound call to ip-api.com for "
                                    "public IP / ISP lookup")
        self.cb_ip_api.setChecked(self._ui.get("use_ip_api", True))
        form.addRow("", self.cb_ip_api)

        ip_hint = QLabel(
            "ip-api.com is a free, no-key service rate-limited to 45 "
            "requests/minute. Disable if you prefer full offline mode."
        )
        ip_hint.setWordWrap(True)
        ip_hint.setStyleSheet("color:#6b7280;font-size:11px;")
        form.addRow("", ip_hint)

        return w

    def _build_ui_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self.cmb_theme = QComboBox()
        self.cmb_theme.addItems(["Light", "Dark"])
        cur_theme = self._ui.get("theme", "Light")
        self.cmb_theme.setCurrentText(cur_theme if cur_theme in ("Light", "Dark") else "Light")
        form.addRow("Theme:", self.cmb_theme)

        self.e_export = QLineEdit(self._ui.get("export_dir",
                                               str(Path.home() / "IoTGuard-reports")))
        form.addRow("Default export folder:", self.e_export)

        return w

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _dspin(value, lo, hi, step) -> QDoubleSpinBox:
        s = QDoubleSpinBox()
        s.setRange(lo, hi)
        s.setSingleStep(step)
        s.setDecimals(1)
        s.setValue(value)
        return s

    def _on_accept(self) -> None:
        self._opts.interface = self.e_interface.text().strip()
        self._opts.subnet    = self.e_subnet.text().strip()
        self._opts.scan_wifi         = self.cb_wifi.isChecked()
        self._opts.scan_network      = self.cb_net.isChecked()
        self._opts.scan_bluetooth    = self.cb_bt.isChecked()
        self._opts.include_classic_bt= self.cb_classicbt.isChecked()
        self._opts.scan_ports        = self.cb_ports.isChecked()
        self._opts.enrich_cves       = self.cb_cve.isChecked()
        self._opts.lab_mode          = self.cb_lab.isChecked()
        self._opts.demo_mode         = self.cb_demo.isChecked()
        self._opts.mdns_duration     = float(self.sp_mdns.value())
        self._opts.ssdp_duration     = float(self.sp_ssdp.value())
        self._opts.ble_duration      = float(self.sp_ble.value())
        self._opts.port_timeout      = float(self.sp_pt.value())
        self._opts.port_parallelism  = int(self.sp_par.value())
        self._opts.use_nmap_sweep    = self.cb_nmap_sweep.isChecked()
        self._opts.deep_port_scan    = self.cb_deep_scan.isChecked()
        self._opts.run_vuln_scripts  = self.cb_vuln_scripts.isChecked()
        self._opts.passive_sniff     = self.cb_passive.isChecked()

        self._ui["theme"] = self.cmb_theme.currentText()
        self._ui["export_dir"] = self.e_export.text().strip() or \
                                 str(Path.home() / "IoTGuard-reports")
        self._ui["shodan_api_key"] = self.e_shodan.text().strip()
        self._ui["use_ip_api"] = bool(self.cb_ip_api.isChecked())

        save_options(self._opts, self._ui)
        self.accept()

    # -- public accessors ----------------------------------------------------

    def options(self) -> ScanOptions:
        return self._opts

    def ui_prefs(self) -> dict:
        return self._ui
