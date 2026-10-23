"""Benchmark installed Python native modules; these are reference labels, not proof."""

import json
import sys
import sysconfig
from pathlib import Path

from malware_scanner.artifacts import write_json
from malware_scanner.corpus import inventory
from malware_scanner.workbench import run_job


def main():
    output = Path(sys.argv[1]).resolve()
    native = Path(sysconfig.get_config_var("DESTSHARED"))
    manifest = inventory(
        native,
        "Native modules from the official Python container image; assumed benign reference",
        label="benign",
        split="development",
    )
    write_json(output / "native-manifest.json", manifest)
    import malware_scanner

    rules = Path(malware_scanner.__file__).parent / "rules"
    result = run_job(output / "native-manifest.json", rules, output / "runs")
    print(json.dumps(result, indent=2))
    if result["status"] != "completed":
        raise SystemExit(1)
    report = json.loads((Path(result["run_directory"]) / "report.json").read_text())
    print(
        json.dumps(
            dict(
                files=len(report["samples"]),
                errors=report["errors"],
                matching_files=sum(bool(row["matches"]) for row in report["samples"]),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
