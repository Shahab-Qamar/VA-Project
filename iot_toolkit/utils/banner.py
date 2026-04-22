"""ASCII art banner for the toolkit."""

R  = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C  = "\033[96m"; W = "\033[97m"; X = "\033[0m"

BANNER = f"""{C}
  ██╗ ██████╗ ████████╗    ███████╗███████╗ ██████╗
  ██║██╔═══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔════╝
  ██║██║   ██║   ██║       ███████╗█████╗  ██║
  ██║██║   ██║   ██║       ╚════██║██╔══╝  ██║
  ██║╚██████╔╝   ██║       ███████║███████╗╚██████╗
  ╚═╝ ╚═════╝    ╚═╝       ╚══════╝╚══════╝ ╚═════╝
{X}
  {Y}IoT Security Toolkit v1.0  —  Ethical Pentest Framework{X}
  {R}For authorized penetration testing only.{X}
"""

def print_banner():
    print(BANNER)
    print(f"  {'─'*58}")
    print(f"   Modules: Discovery · OUI · PortScan · Creds · CVE · Report")
    print(f"  {'─'*58}\n")
