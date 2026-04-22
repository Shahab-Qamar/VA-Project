"""
Bluetooth proximity discovery using the built-in adapter.

Two independent paths:

  * BLE (Bluetooth Low Energy) via `bleak`. This is the right path for
    wearables, fitness trackers, smart bulbs, fobs, and most consumer
    IoT sensors.

  * Classic Bluetooth via `bluetoothctl`. Optional; used to find nearby
    speakers, phones in discoverable mode, and older gear.

Both are strictly passive (listen for advertisements for BLE, inquiry
for classic). Nothing is paired, written to, or bonded.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from pathlib import Path

from ..core.models import Device, DeviceType, DiscoverySource
from ..intel.oui_lookup import lookup_vendor

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Adapter availability
# ---------------------------------------------------------------------------

def has_bluetooth_adapter() -> tuple[bool, str]:
    """Return (available, reason). Checks rfkill, /sys/class/bluetooth, and
    hciconfig in that order. On the first positive result we return True
    with an informative reason string; otherwise we explain why."""
    # 1. Kernel-exposed adapters in /sys/class/bluetooth (hci0, hci1, …)
    sys_bt = Path("/sys/class/bluetooth")
    if sys_bt.exists():
        adapters = [p.name for p in sys_bt.iterdir() if p.name.startswith("hci")]
        if adapters:
            return True, f"Found adapter(s): {', '.join(adapters)}"

    # 2. Fall back to hciconfig if /sys isn't populated.
    if shutil.which("hciconfig"):
        try:
            out = subprocess.run(["hciconfig"], capture_output=True,
                                 text=True, timeout=3)
            if "hci" in out.stdout.lower():
                return True, "hciconfig reported an adapter"
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 3. rfkill can tell us if a block exists but no hardware.
    if shutil.which("rfkill"):
        try:
            out = subprocess.run(["rfkill", "list", "bluetooth"],
                                 capture_output=True, text=True, timeout=3)
            if out.stdout.strip():
                # rfkill listed something, but no hci device appeared above,
                # so adapter is probably blocked / missing.
                return False, "Bluetooth entry found but no usable hci device"
        except (subprocess.TimeoutExpired, OSError):
            pass

    return False, "No Bluetooth adapter detected"


# ---------------------------------------------------------------------------
# BLE via bleak
# ---------------------------------------------------------------------------

async def _ble_scan_async(duration: float) -> list[Device]:
    try:
        from bleak import BleakScanner                   # type: ignore
    except ImportError:
        log.info("bleak not installed; BLE scan skipped")
        return []

    devices: list[Device] = []
    try:
        discovered = await BleakScanner.discover(
            timeout=duration, return_adv=True,
        )
    except Exception as e:
        log.warning("BLE discovery failed: %s", e)
        return []

    # bleak >= 0.20 returns {address: (BLEDevice, AdvertisementData)}
    for address, entry in discovered.items():
        if isinstance(entry, tuple) and len(entry) == 2:
            ble_dev, adv = entry
            name = getattr(ble_dev, "name", "") or getattr(adv, "local_name", "") or ""
            rssi = getattr(adv, "rssi", None)
            if rssi is None:
                rssi = getattr(ble_dev, "rssi", 0) or 0
        else:
            ble_dev = entry
            name = getattr(ble_dev, "name", "") or ""
            rssi = getattr(ble_dev, "rssi", 0) or 0

        mac = (address or "").upper()
        devices.append(Device(
            mac=mac,
            ble_name=name,
            ble_rssi=int(rssi),
            device_type=DeviceType.BLE_PERIPHERAL,
            vendor=lookup_vendor(mac),
            discovery_sources=[DiscoverySource.BLE],
        ))
    return devices


def ble_scan(duration: float = 6.0) -> list[Device]:
    """Synchronous wrapper around the async BLE discovery."""
    try:
        return asyncio.run(_ble_scan_async(duration))
    except RuntimeError:
        # Already inside an event loop (shouldn't happen from a QThread, but
        # defend anyway): spin up a nested loop with asyncio.new_event_loop.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_ble_scan_async(duration))
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Classic Bluetooth via bluetoothctl
# ---------------------------------------------------------------------------

_BT_DEVICE_LINE = re.compile(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)")


def classic_bt_scan(duration: float = 8.0) -> list[Device]:
    """Run a bluetoothctl inquiry and parse the results."""
    if shutil.which("bluetoothctl") is None:
        log.info("bluetoothctl not installed; classic BT scan skipped")
        return []

    script = (
        "power on\n"
        "agent off\n"
        "scan on\n"
        f"sleep {int(duration)}\n"
        "devices\n"
        "scan off\n"
        "quit\n"
    )
    try:
        out = subprocess.run(
            ["bluetoothctl"],
            input=script, capture_output=True, text=True,
            timeout=duration + 10,
        )
    except subprocess.TimeoutExpired:
        log.warning("bluetoothctl timed out")
        return []
    except FileNotFoundError:
        return []

    devices: list[Device] = []
    for line in out.stdout.splitlines():
        m = _BT_DEVICE_LINE.search(line)
        if not m:
            continue
        mac, name = m.group(1).upper(), m.group(2).strip()
        devices.append(Device(
            mac=mac,
            ble_name=name,
            device_type=DeviceType.BLE_PERIPHERAL,
            vendor=lookup_vendor(mac),
            discovery_sources=[DiscoverySource.BLUETOOTH],
        ))
    return devices


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def bluetooth_proximity_scan(ble_duration: float = 6.0,
                             classic_duration: float = 6.0,
                             include_classic: bool = True) -> list[Device]:
    """Combined BLE + classic scan, deduped by MAC.
    Returns an empty list (and logs a warning) when no adapter is present."""
    available, reason = has_bluetooth_adapter()
    if not available:
        log.warning("Bluetooth scan skipped: %s", reason)
        return []

    results = ble_scan(ble_duration)
    if include_classic:
        classic = classic_bt_scan(classic_duration)
        seen = {d.mac for d in results}
        for d in classic:
            if d.mac not in seen:
                results.append(d)
    return results
