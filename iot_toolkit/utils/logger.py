"""Coloured logger utility."""

import sys
from datetime import datetime

R  = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
B  = "\033[94m"; C = "\033[96m"; W = "\033[97m"; X = "\033[0m"


class Logger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def info(self, msg: str):
        if self.verbose:
            print(f"  {B}[{self._ts()}]{X} {msg}")

    def success(self, msg: str):
        print(f"  {G}[✓]{X} {msg}")

    def warn(self, msg: str):
        print(f"  {Y}[!]{X} {msg}")

    def error(self, msg: str):
        print(f"  {R}[✗]{X} {msg}", file=sys.stderr)

    def section(self, title: str):
        print(f"\n{C}{'─'*55}")
        print(f"  {title}")
        print(f"{'─'*55}{X}")
