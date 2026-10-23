"""Run the portable release checks without modifying the checkout."""

import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    with tempfile.TemporaryDirectory() as output:
        checks = [
            ["-m", "ruff", "check", "malware_scanner", "tests", "setup.py", "run_scanner.py"],
            [
                "-m",
                "ruff",
                "format",
                "--check",
                "malware_scanner",
                "tests",
                "setup.py",
                "run_scanner.py",
            ],
            ["-m", "unittest", "discover", "-s", "tests", "-v"],
            ["-m", "malware_scanner.test_suite"],
            [
                "-m",
                "malware_scanner.lab",
                "samples/lab/manifest.json",
                "--strict",
                "--output",
                str(Path(output) / "report.json"),
            ],
            ["tests/smoke_install.py"],
            ["-m", "pip", "check"],
        ]
        for check in checks:
            print("Running: python " + " ".join(check), flush=True)
            subprocess.run([sys.executable, *check], check=True, timeout=180)


if __name__ == "__main__":
    main()
