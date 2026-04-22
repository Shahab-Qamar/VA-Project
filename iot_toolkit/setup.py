"""
IoT Security Toolkit — Setup & Dependency Installer
Run: python setup.py
"""

import subprocess
import sys
import os

REQUIRED_PACKAGES = [
    ("paramiko",  "paramiko"),        # SSH testing
    ("scapy",     "scapy"),           # Advanced packet crafting (optional)
    ("requests",  "requests"),        # HTTP fallback (optional)
]

SYSTEM_TOOLS = [
    ("arp-scan",  "sudo apt install arp-scan    # or: brew install arp-scan"),
    ("nmap",      "sudo apt install nmap"),
    ("tshark",    "sudo apt install tshark      # WiFi proximity scan"),
]


def check_python():
    v = sys.version_info
    if v < (3, 8):
        print(f"[!] Python 3.8+ required. You have {v.major}.{v.minor}")
        sys.exit(1)
    print(f"[✓] Python {v.major}.{v.minor}.{v.micro}")


def install_packages():
    print("\n[*] Installing Python dependencies…")
    for pkg_import, pkg_name in REQUIRED_PACKAGES:
        try:
            __import__(pkg_import)
            print(f"  [✓] {pkg_name} already installed")
        except ImportError:
            print(f"  [+] Installing {pkg_name}…")
            subprocess.run([sys.executable, "-m", "pip", "install", pkg_name],
                           check=False, capture_output=True)


def check_system_tools():
    print("\n[*] Checking system tools…")
    for tool, install_hint in SYSTEM_TOOLS:
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode == 0:
            print(f"  [✓] {tool}")
        else:
            print(f"  [!] {tool} not found")
            print(f"      Install: {install_hint}")


def create_dirs():
    print("\n[*] Creating directories…")
    for d in ["output", "data/cve_cache", "data/logs"]:
        os.makedirs(d, exist_ok=True)
        print(f"  [✓] {d}/")


def download_oui():
    print("\n[*] OUI database setup…")
    oui_path = "data/oui_database.json"
    if os.path.exists(oui_path):
        print(f"  [✓] OUI database already exists ({oui_path})")
        return
    ans = input("  Download full IEEE OUI database? (~4MB, one-time) [y/N]: ").strip().lower()
    if ans == "y":
        sys.path.insert(0, ".")
        from modules.oui import OUILookup

        class SimpleLog:
            def info(self, m): print(f"  {m}")
            def success(self, m): print(f"  [✓] {m}")
            def warn(self, m): print(f"  [!] {m}")

        oui = OUILookup(db_path=oui_path, log=SimpleLog())
        oui.download_oui_db(oui_path)
    else:
        print("  [i] Using built-in compact OUI table (covers common IoT vendors)")


def print_usage():
    print("""
╔══════════════════════════════════════════════════════════════╗
║  Setup complete! Quick usage:                                ║
║                                                              ║
║  # Network scan (ARP)                                        ║
║  sudo python main.py --mode network --target 192.168.1.0/24  ║
║                                                              ║
║  # With verbose output                                       ║
║  sudo python main.py --target 192.168.1.0/24 -v              ║
║                                                              ║
║  # Skip credential testing                                   ║
║  sudo python main.py --target 192.168.1.1 --skip-creds       ║
║                                                              ║
║  # Dry run (no active auth attempts)                         ║
║  sudo python main.py --target 192.168.1.0/24 --dry-run       ║
║                                                              ║
║  # Scope-restricted scan                                     ║
║  sudo python main.py --scope targets.txt --format html       ║
╚══════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    print("=" * 56)
    print("  IoT Security Toolkit — Setup")
    print("=" * 56)
    check_python()
    install_packages()
    check_system_tools()
    create_dirs()
    download_oui()
    print_usage()
