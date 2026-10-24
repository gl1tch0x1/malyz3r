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
            if check == ["-m", "pip", "check"]:
                res = subprocess.run([sys.executable, *check], capture_output=True, text=True)
                if res.returncode != 0:
                    malyz3r_deps = {
                        "colorama",
                        "python-magic",
                        "requests",
                        "yara-python",
                        "psutil",
                        "ruff",
                        "mcp",
                    }
                    lines = [
                        line
                        for line in res.stdout.splitlines()
                        if any(dep in line.lower() for dep in malyz3r_deps)
                    ]
                    if lines:
                        print(
                            "pip check dependency issue in project dependencies:\n"
                            + "\n".join(lines),
                            file=sys.stderr,
                        )
                        raise subprocess.CalledProcessError(
                            res.returncode, [sys.executable, *check], res.stdout, res.stderr
                        )
                    else:
                        print(
                            "pip check notice: external workstation packages have unrelated warnings (ignoring for malyz3r):"
                        )
                        print(res.stdout.strip())
                else:
                    print("pip check passed.")
            else:
                subprocess.run([sys.executable, *check], check=True, timeout=180)


if __name__ == "__main__":
    main()
