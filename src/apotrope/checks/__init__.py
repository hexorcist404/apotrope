"""Apotrope check modules package.

Each module in this package must expose:
  CATEGORY: str          — logical grouping name (e.g. "Firewall")
  run() -> list[CheckResult]  — performs the checks and returns results

``MODULES`` is used by the scanner when running inside a PyInstaller bundle,
where ``pkgutil.iter_modules`` cannot traverse the frozen archive.  Update
this list whenever a new check module is added.
"""

# Explicit module registry — required for PyInstaller (--onefile) compatibility.
# pkgutil.iter_modules cannot discover modules inside a frozen .exe archive.
MODULES: list[str] = [
    "accounts",
    "antivirus",
    "encryption",
    "firewall",
    "misc",
    "network",
    "os_info",
    "powershell",
    "rdp",
    "services",
    "smb",
    "startup",
    "uac",
    "updates",
]
