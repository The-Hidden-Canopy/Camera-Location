#!/usr/bin/env python3
"""
Camera Discovery Octopus — Desktop launcher

Launches the Electron desktop wrapper. Falls back to Flask web UI
if Electron is not available.
"""

import os
import sys
import subprocess
from pathlib import Path


def main():
    base_dir = Path(__file__).parent
    electron_main = base_dir / "electron" / "main.js"
    package_json = base_dir / "package.json"

    # Check if Electron is installed
    electron_bin = _find_electron(base_dir)

    if electron_bin and package_json.exists():
        print("  Launching Camera Discovery Octopus (Desktop)...\n")
        try:
            proc = subprocess.run(
                [electron_bin, "."],
                cwd=str(base_dir),
                shell=True,
            )
            sys.exit(proc.returncode)
        except KeyboardInterrupt:
            sys.exit(0)
        except FileNotFoundError:
            print("  Electron not found. Falling back to web UI...\n")
    else:
        print("  Electron not installed. Falling back to web UI...\n")
        print("  To install Electron for desktop mode:")
        print("    npm install\n")

    # Fallback: launch Flask web UI
    from camdiscover.cli import main as cli_main
    sys.argv = ["camera-discover", "web", "--port", "5000"]
    cli_main()


def _find_electron(base_dir: Path) -> str:
    """Find the Electron binary."""
    # Check node_modules/.bin/electron
    local_electron = base_dir / "node_modules" / ".bin" / "electron"
    if local_electron.exists():
        return str(local_electron)

    # Check global electron
    try:
        result = subprocess.run(
            ["electron", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return "electron"
    except Exception:
        pass

    # Check npx
    try:
        result = subprocess.run(
            ["npx", "electron", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return "npx electron"
    except Exception:
        pass

    return ""


if __name__ == "__main__":
    main()
