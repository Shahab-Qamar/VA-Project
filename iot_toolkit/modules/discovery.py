"""
Module 1 — Device Discovery
Supports ARP scan (same-network) and WiFi beacon capture (proximity).
"""

import socket
import struct
import subprocess
import ipaddress
import threading
import time
import re
from typing import List, Dict


class DeviceDiscovery:
    def __init__(self, interface=None, timeout=3, log=None):
        self.interface = interface
        self.timeout   = timeout
        self.log       = log

    # ── Helpers ────────────────────────────────────────────────

    def detect_local_network(self) -> str:
        """Auto-detect the local subnet via routing table."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "src" in line:
                    src = line.split("src")[1].strip().split()[0]
                    # Guess /24
                    parts = src.split(".")
                    return f"{'.'.join(parts[:3])}.0/24"
        except Exception:
            pass
        return "192.168.1.0/24"

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    # ── ARP Scan ──────────────────────────────────────────────

    def arp_scan(self, target: str) -> List[Dict]:
        """
        Perform ARP scan using 'arp-scan' if available, else fallback
        to ping-sweep + arp table parsing.
        """
        devices = []

        # Try arp-scan first (most reliable)
        if self._has_tool("arp-scan"):
            devices = self._arp_scan_tool(target)
        else:
            self.log.warn("arp-scan not found; using ping-sweep fallback")
            devices = self._ping_sweep(target)

        return devices

    def _has_tool(self, name: str) -> bool:
        try:
            subprocess.run(["which", name], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def _arp_scan_tool(self, target: str) -> List[Dict]:
        cmd = ["arp-scan", "--localnet" if target.endswith("/24") else target]
        if self.interface:
            cmd += ["-I", self.interface]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=60, check=False)
            devices = []
            # Parse lines like: 192.168.1.5  aa:bb:cc:dd:ee:ff  Vendor Name
            pattern = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s*(.*)",
                re.IGNORECASE
            )
            for line in result.stdout.splitlines():
                m = pattern.match(line.strip())
                if m:
                    ip, mac, vendor = m.group(1), m.group(2), m.group(3)
                    devices.append({
                        "ip":       ip,
                        "mac":      mac.lower(),
                        "hostname": self._resolve_hostname(ip),
                        "vendor":   vendor.strip(),
                    })
            return devices
        except subprocess.TimeoutExpired:
            self.log.warn("arp-scan timed out")
            return []

    def _ping_sweep(self, target: str) -> List[Dict]:
        """Ping-sweep then read ARP cache."""
        devices = []
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = ipaddress.ip_network(target + "/32", strict=False)

        # Ping all hosts concurrently
        alive = []
        lock  = threading.Lock()

        def ping(ip):
            r = subprocess.run(
                ["ping", "-c", "1", "-W", str(self.timeout), str(ip)],
                capture_output=True
            )
            if r.returncode == 0:
                with lock:
                    alive.append(str(ip))

        threads = []
        for host in network.hosts():
            t = threading.Thread(target=ping, args=(host,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=self.timeout + 1)

        # Read ARP table
        arp_result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
        arp_table  = {}
        for line in arp_result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[2]:
                arp_table[parts[0]] = parts[2]

        for ip in alive:
            devices.append({
                "ip":       ip,
                "mac":      arp_table.get(ip, "unknown"),
                "hostname": self._resolve_hostname(ip),
                "vendor":   "",
            })
        return devices

    # ── Proximity (WiFi Beacon) Scan ──────────────────────────

    def proximity_scan(self, interface: str = None, duration: int = 30) -> List[Dict]:
        """
        Capture WiFi beacon frames to discover nearby IoT devices/networks.
        Requires: monitor-mode capable interface + tcpdump or tshark.
        """
        iface = interface or self.interface or "wlan0"
        devices = []

        self.log.info(f"Capturing beacons on {iface} for {duration}s …")
        self.log.warn("Interface must be in monitor mode (sudo iwconfig wlan0 mode monitor)")

        if self._has_tool("tshark"):
            devices = self._beacon_tshark(iface, duration)
        elif self._has_tool("tcpdump"):
            devices = self._beacon_tcpdump(iface, duration)
        else:
            self.log.warn("Neither tshark nor tcpdump found — proximity scan skipped")

        return devices

    def _beacon_tshark(self, iface: str, duration: int) -> List[Dict]:
        cmd = [
            "tshark", "-i", iface, "-a", f"duration:{duration}",
            "-Y", "wlan.fc.type_subtype == 0x08",
            "-T", "fields",
            "-e", "wlan.sa",
            "-e", "wlan.ssid",
            "-e", "radiotap.dbm_antsignal",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=duration + 10)
            seen   = {}
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    mac  = parts[0].strip().lower()
                    ssid = parts[1].strip()
                    rssi = parts[2].strip() if len(parts) > 2 else "?"
                    if mac and mac not in seen:
                        seen[mac] = True
                        devices_entry = {
                            "ip":       "",
                            "mac":      mac,
                            "hostname": ssid,
                            "vendor":   "",
                            "rssi":     rssi,
                            "source":   "proximity",
                        }
                        # Crude distance estimate: RSSI -30=~1m, -70=~10m
                        try:
                            rssi_val = int(rssi)
                            dist_m   = round(10 ** ((27.55 - (20 * 2.4) + abs(rssi_val)) / 20), 1)
                            devices_entry["est_distance_m"] = dist_m
                        except (ValueError, TypeError):
                            pass
            return list(seen.values()) if isinstance(seen, dict) else []
        except subprocess.TimeoutExpired:
            return []

    def _beacon_tcpdump(self, iface: str, duration: int) -> List[Dict]:
        import tempfile, os
        out = tempfile.mktemp(suffix=".txt")
        cmd = ["tcpdump", "-i", iface, "-e", "-w", "-",
               "type mgt subtype beacon"]
        try:
            with open(out, "w") as f:
                proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)
                time.sleep(duration)
                proc.terminate()
            # Basic MAC extraction from raw output
            result = subprocess.run(["strings", out], capture_output=True, text=True)
            macs = re.findall(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", result.stdout)
            seen = {}
            for mac in macs:
                if mac not in seen:
                    seen[mac] = {"ip": "", "mac": mac, "hostname": "",
                                 "vendor": "", "source": "proximity"}
            return list(seen.values())
        except Exception as e:
            self.log.warn(f"tcpdump capture failed: {e}")
            return []
        finally:
            if os.path.exists(out):
                os.remove(out)
