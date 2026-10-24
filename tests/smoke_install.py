"""Verify a non-editable install outside the checkout, including packaged rules."""

import os
import subprocess
import sys
import tempfile


def main():
    code = """
import json
from pathlib import Path
import malware_scanner
from malware_scanner.lab import compile_rules, main
rules = Path(malware_scanner.__file__).parent / 'rules'
assert len(compile_rules(rules).identifiers) >= 50
Path('sample.txt').write_text('ordinary benign text')
Path('manifest.json').write_text(json.dumps({'samples': [
    {'path': 'sample.txt', 'label': 'benign', 'expected_rules': [], 'split': 'development'}
]}))
assert main(['manifest.json', '--strict', '--output', 'report.json']) == 0
assert json.loads(Path('report.json').read_text())['complete']
from malware_scanner.workbench import run_job
state = run_job(Path('manifest.json').resolve(), rules, Path('runs').resolve())
assert state['status'] == 'completed', state
assert (Path(state['run_directory']) / 'report.html').is_file()
from malware_scanner.assistant import assist
preview = assist(state['run_directory'], 'assistant-preview', 'test-model')
assert preview['status'] == 'prepared'
assert preview['network_requested'] is False
print('Installed package and bundled rules: OK')
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["MALYZ3R_LOG_FILE"] = os.devnull
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, "-E", "-c", code], cwd=tmp, env=env, check=True, timeout=60)
        subprocess.run(
            [sys.executable, "-E", "-m", "malware_scanner.cli", "--help"],
            cwd=tmp,
            env=env,
            check=True,
            timeout=30,
            stdout=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    main()
