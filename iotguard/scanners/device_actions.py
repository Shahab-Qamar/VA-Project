"""
Utility per-device actions triggered from the device detail dialog.

All of these run on a short-lived thread and return a plain-text result
block that the GUI displays in a simple output pane.
"""

from __future__ import annotations

import shutil
import socket
import subprocess


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

def ping(host: str, count: int = 4, timeout: int = 5) -> str:
    """Run a short ICMP ping using the system tool."""
    if not host:
        return "No host."
    if shutil.which("ping") is None:
        return "`ping` not available on this system."
    try:
        out = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", host],
            capture_output=True, text=True, timeout=timeout + count,
        )
    except subprocess.TimeoutExpired:
        return f"Timed out pinging {host}."
    return (out.stdout + (("\n" + out.stderr) if out.stderr else "")).strip()


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

def traceroute(host: str, max_hops: int = 15, timeout: int = 20) -> str:
    if not host:
        return "No host."
    tool = shutil.which("traceroute") or shutil.which("tracepath")
    if tool is None:
        return "`traceroute` not installed. Install with: sudo apt install traceroute"
    try:
        args = [tool, "-n", "-q", "1", "-m", str(max_hops), host]
        if tool.endswith("tracepath"):
            args = [tool, "-n", "-m", str(max_hops), host]
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "Traceroute timed out."
    return (out.stdout + (("\n" + out.stderr) if out.stderr else "")).strip()


# ---------------------------------------------------------------------------
# Wake-on-LAN
# ---------------------------------------------------------------------------

def wake_on_lan(mac: str, broadcast: str = "255.255.255.255",
                port: int = 9) -> str:
    """Send a magic packet to the given MAC address."""
    if not mac:
        return "No MAC address available for this device."
    clean = mac.replace(":", "").replace("-", "").strip()
    if len(clean) != 12:
        return f"Invalid MAC address: {mac}"
    try:
        mac_bytes = bytes.fromhex(clean)
    except ValueError:
        return f"Invalid MAC address: {mac}"

    magic = b"\xff" * 6 + mac_bytes * 16
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.sendto(magic, (broadcast, port))
    except OSError as e:
        return f"Send failed: {e}"
    finally:
        sock.close()
    return (f"Wake-on-LAN magic packet sent to {mac.upper()} "
            f"via {broadcast}:{port}. The device must have WoL enabled "
            f"in firmware and BIOS for this to wake it.")


# ---------------------------------------------------------------------------
# Port-state check (single-shot)
# ---------------------------------------------------------------------------

def quick_port_check(host: str, port: int, timeout: float = 1.5) -> str:
    if not host:
        return "No host."
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
    except OSError as e:
        return f"error: {e}"
    finally:
        s.close()
    return "open" if rc == 0 else "closed / filtered"
