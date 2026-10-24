import contextlib
import copy
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

_TESTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTS_DIR.parent
for _p in (str(_REPO_ROOT), str(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_assistant  # type: ignore[import-not-found,import-untyped]
import test_operations  # type: ignore[import-not-found,import-untyped]

from malware_scanner import config
from malware_scanner.assistant import prepare_evidence
from malware_scanner.cli import investigate_file
from malware_scanner.external import capture_tool
from malware_scanner.lab import evaluate, scan_file
from malware_scanner.providers import configuration
from malware_scanner.quality import compare_reports
from malware_scanner.virus_total import virustotal_scan


class BoundaryTests(unittest.TestCase):
    def test_invalid_environment_does_not_break_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "malware_scanner.cli", "--help"],
            env=dict(os.environ, MALYZ3R_PARALLELISM="bad"),
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_config_live_environment_and_no_persisted_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "config.json")
            with patch.dict(
                os.environ,
                {
                    "MALYZ3R_CONFIG": str(path),
                    "MALYZ3R_PARALLELISM": "3",
                    "MALYZ3R_VT_API_KEY": "SECRET",
                },
                clear=True,
            ):
                loaded = config.load_config()
                self.assertEqual(loaded["scan_parallelism"], 3)
                config.save_config(loaded)
                self.assertNotIn("SECRET", path.read_text())
                os.environ["MALYZ3R_PARALLELISM"] = "0"
                with self.assertRaises(ValueError):
                    config.load_config()
                os.environ["MALYZ3R_PARALLELISM"] = "invalid"
                with self.assertRaises(ValueError):
                    config.load_config()

    def test_malformed_config_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "config.json")
            path.write_text("[]")
            with (
                patch.dict(os.environ, {"MALYZ3R_CONFIG": str(path)}, clear=True),
                self.assertRaises(ValueError),
            ):
                config.load_config()

    def test_investigation_does_not_launch_tools_and_bounds_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp, "-sample")
            sample.write_bytes(b"A" * (2 * 1024 * 1024))
            output = io.StringIO()
            with patch("subprocess.Popen") as launch, contextlib.redirect_stdout(output):
                self.assertTrue(investigate_file(sample))
            launch.assert_not_called()
            self.assertLess(len(output.getvalue()), 5000)
            self.assertIn("truncated", output.getvalue())

    def test_external_tool_deadline_and_output_cap(self):
        with self.assertRaisesRegex(ValueError, "time limit"):
            capture_tool([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)
        with self.assertRaisesRegex(ValueError, "output limit"):
            capture_tool([sys.executable, "-c", 'print("x"*10000)'], max_output=100)
        self.assertEqual(capture_tool([sys.executable, "-c", 'print("ok")']).strip(), "ok")

    def test_virustotal_missing_key_and_file_do_not_send(self):
        with (
            patch("malware_scanner.virus_total.requests.get") as get,
            patch("malware_scanner.virus_total.print_result"),
        ):
            self.assertFalse(virustotal_scan("missing", None))
            self.assertFalse(virustotal_scan("missing", "SECRET"))
            get.assert_not_called()

    def test_virustotal_redirect_and_malformed_response_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp, "sample")
            sample.write_bytes(b"harmless")
            for status, content in ((302, b""), (200, b"[]"), (200, b"x" * (1024 * 1024 + 1))):
                http = Mock(status_code=status)
                http.__enter__ = Mock(return_value=http)
                http.__exit__ = Mock(return_value=False)
                http.iter_content.return_value = [content]
                with (
                    patch("malware_scanner.virus_total.requests.get", return_value=http) as get,
                    patch("malware_scanner.virus_total.print_result"),
                ):
                    self.assertFalse(virustotal_scan(sample, "SECRET"))
                    self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_invalid_url_ports_controls_and_backslashes(self):
        for url in (
            "https://example.com:bad/v1",
            "https://example.com:99999/v1",
            "https://example.com/\npath",
            "https://example.com\\other",
        ):
            with self.assertRaises(ValueError):
                configuration("openai-compatible", "test", url)

    def test_scan_limits_reject_bool_float_and_string(self):
        for value in (True, 1.5, "10", 0):
            with self.assertRaises(ValueError):
                scan_file("unused", Mock(), timeout=value)


class EvidenceBoundaryTests(test_assistant.AssistantBase):
    def test_malformed_samples_and_metrics_fail_before_evidence(self):
        original = copy.deepcopy(self.report)
        for changes in (
            {"matches": [None]},
            {"matches": []},
            {"expected_rules": "wrong"},
            {"sha256": None},
            {"label": "benign", "expected_rules": ["example.yar:Example"]},
        ):
            self.report = copy.deepcopy(original)
            self.report["samples"][0].update(changes)
            self.save_report()
            with self.assertRaises(ValueError):
                prepare_evidence(self.run_dir)
        for key, value in (("tp", None), ("fp", 1.5), ("recall", 2), ("precision", float("nan"))):
            self.report = copy.deepcopy(original)
            self.report["per_rule"]["example.yar:Example"][key] = value
            self.save_report()
            with self.assertRaises(ValueError):
                prepare_evidence(self.run_dir)

    def test_selection_is_bounded_but_validates_unselected_rows(self):
        row = self.report["samples"][0]
        self.report["samples"] = [dict(row, sha256=f"{i:064x}") for i in range(200)]
        self.save_report()
        evidence, mapping, _ = prepare_evidence(self.run_dir)
        self.assertEqual(evidence["total_disagreements"], 200)
        self.assertEqual(len(mapping), 30)
        row_last: dict[str, Any] = self.report["samples"][-1]
        row_last["matches"] = None
        self.save_report()
        with self.assertRaises(ValueError):
            prepare_evidence(self.run_dir)


class ComparisonBoundaryTests(test_operations.OperationsBase):
    def test_comparison_rejects_incomplete_inventory(self):
        report = evaluate(self.manifest, self.rules)
        candidate = copy.deepcopy(report)
        candidate["inventory_complete"] = False
        with self.assertRaisesRegex(ValueError, "inventories"):
            compare_reports(report, candidate)


class PersistenceRegressionTests(unittest.TestCase):
    def test_comparison_cannot_overwrite_its_input(self):
        from malware_scanner.workbench import main

        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, "report.json")
            report.write_text("preserve original")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["compare", str(report), str(report), "--output", str(report)]), 2
                )
            self.assertEqual(report.read_text(), "preserve original")

    def test_terminal_controls_are_escaped(self):
        from malware_scanner.utils import print_result

        with patch("malware_scanner.utils._ensure_colorama"), patch("builtins.print") as display:
            print_result("sample\x1b[2J\rspoof", log=False)
        self.assertIn("sample\\x1b[2J\\x0dspoof", display.call_args.args[0])

    def test_certificate_presence_is_not_any_pe_directory(self):
        import struct

        from malware_scanner.core import check_digital_signature

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "fixture.exe")
            blob = bytearray(512)
            blob[:2] = b"MZ"
            struct.pack_into("<I", blob, 60, 64)
            blob[64:68] = b"PE\x00\x00"
            struct.pack_into("<H", blob, 84, 224)
            struct.pack_into("<H", blob, 88, 0x10B)
            struct.pack_into("<I", blob, 88 + 92, 16)
            path.write_bytes(blob)
            self.assertFalse(check_digital_signature(path))
            struct.pack_into("<II", blob, 88 + 96 + 32, 400, 16)
            struct.pack_into("<IHH", blob, 400, 16, 0x0200, 2)
            path.write_bytes(blob)
            self.assertTrue(check_digital_signature(path))
            struct.pack_into("<II", blob, 88 + 96 + 32, 500, 16)
            path.write_bytes(blob)
            self.assertFalse(check_digital_signature(path))
