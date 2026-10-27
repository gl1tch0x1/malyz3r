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
assert len(compile_rules(rules).identifiers) == 69
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
from malware_scanner.web import Workspace, make_server
workspace = Workspace(Path.cwd())
assert workspace.history()[0]['run_id'] == state['run_id']
assert (Path(malware_scanner.__file__).parent / 'web_assets' / 'app.js').is_file()
assert (Path(malware_scanner.__file__).parent / 'web_assets' / 'workspace.js').is_file()
from malware_scanner.web_workspace import detection_map
assert detection_map(workspace.report(state['run_id']))['nodes']
server, token = make_server(workspace, 0)
server.server_close()
from malware_scanner.assurance import compare
report = json.loads((Path(state['run_directory']) / 'report.json').read_text())
assert compare(report, report)['comparable']
print('Installed package and bundled rules: OK')
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["MALYZ3R_LOG_FILE"] = os.devnull
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, "-I", "-c", code], cwd=tmp, env=env, check=True, timeout=60)
        subprocess.run(
            [sys.executable, "-I", "-m", "malware_scanner.cli", "--help"],
            cwd=tmp,
            env=env,
            check=True,
            timeout=30,
            stdout=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    main()
