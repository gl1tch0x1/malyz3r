import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from malware_scanner.lab import (
    RuleCompilationError,
    compile_rules,
    evaluate,
    main,
    scan_file,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]


class HardeningTests(unittest.TestCase):
    def test_help_survives_unavailable_file_logging(self):
        with tempfile.TemporaryDirectory() as tmp:
            for log_path in (Path(tmp) / "absent" / "app.log", Path(tmp)):
                with self.subTest(log_path=log_path):
                    result = subprocess.run(
                        [sys.executable, "-m", "malware_scanner.cli", "--help"],
                        cwd=ROOT,
                        env=dict(os.environ, MALYZ3R_LOG_FILE=str(log_path)),
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("usage:", result.stdout)
                    self.assertIn("File logging unavailable", result.stderr)

    def test_schema_rejects_malformed_rows(self):
        invalid = [
            [],
            None,
            {},
            {"samples": "wrong"},
            {"samples": [None]},
            {"samples": [{"path": 1}]},
            {"samples": [{"path": "a", "label": "benign", "expected_rules": [], "sha256": "bad"}]},
        ]
        for manifest in invalid:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                validate_manifest(manifest)

    def test_nested_include_fingerprints_and_old_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "parts").mkdir()
            (root / "entry.yar").write_text('include "parts/first.inc"')
            (root / "parts/first.inc").write_text('include "second.inc"')
            dependency = root / "parts/second.inc"
            dependency.write_text("rule included { condition: true }")
            first = compile_rules(root)
            dependency.write_text("rule included { condition: false }")
            second = compile_rules(root)
            self.assertNotEqual(first.sources, second.sources)
            self.assertIn("parts/second.inc", first.sources)
            self.assertTrue(first.match(data=b"harmless"))
            self.assertFalse(second.match(data=b"harmless"))

    def test_include_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            (root / "outside.inc").write_text("rule outside { condition: true }")
            (rules / "entry.yar").write_text('include "../outside.inc"')
            with self.assertRaises(RuleCompilationError):
                compile_rules(rules)

    def test_comment_only_rules_are_not_a_detector(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "empty.yar").write_text("// no public rules")
            with self.assertRaises(RuleCompilationError):
                compile_rules(tmp)

    def test_large_file_is_rejected_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp, "sample")
            sample.write_bytes(b"12345")
            rules = Mock()
            result = scan_file(sample, rules, max_bytes=4)
            self.assertEqual(result["status"], "error")
            rules.match.assert_not_called()

    def test_invalid_manifest_cli_has_controlled_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp, "manifest.json")
            manifest.write_text("[]")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main([str(manifest)])
            self.assertEqual(error.exception.code, 2)

    def test_strict_gate_rejects_false_positives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "entry.yar").write_text("rule noisy { condition: true }")
            (root / "sample").write_text("harmless")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"samples": [dict(path="sample", label="benign", expected_rules=[])]})
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(manifest), "--rules", tmp]), 0)
                self.assertEqual(main([str(manifest), "--rules", tmp, "--strict"]), 3)

    def test_missing_file_cli_exit_is_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(
                os.environ,
                MALYZ3R_RULES_DIR=str(ROOT / "malware_scanner/rules"),
                MALYZ3R_CONFIG=str(Path(tmp, "absent-config.json")),
                MALYZ3R_LOG_FILE=os.devnull,
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "malware_scanner.cli",
                    "--file",
                    str(Path(tmp, "missing")),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("Scan incomplete", result.stdout)

    def test_directory_compiles_once_and_validation_uses_config(self):
        from malware_scanner import cli, core

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").write_text("benign a")
            (root / "b").write_text("benign b")
            rules_dir = str(ROOT / "malware_scanner/rules")
            with (
                patch.object(core, "get_rules_dir", return_value=rules_dir),
                patch.object(core, "compile_rules", wraps=compile_rules) as compile_mock,
                patch.object(core, "print_result"),
            ):
                results = core.scan_directory_with_yara(root)
                self.assertEqual(len(results), 2)
                self.assertEqual(compile_mock.call_count, 1)
            with (
                patch.object(cli, "get_rules_dir", return_value=rules_dir),
                patch.object(cli, "compile_rules", wraps=compile_rules) as compile_mock,
                patch.object(cli, "print_result"),
            ):
                self.assertTrue(cli.validate_rules())
                compile_mock.assert_called_once_with(rules_dir)

    def test_manifest_hash_describes_bytes_that_were_parsed(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "entry.yar").write_text("rule never { condition: false }")
            (root / "sample").write_text("benign")
            manifest = root / "manifest.json"
            original = json.dumps(
                {"samples": [dict(path="sample", label="benign", expected_rules=[])]}
            ).encode()
            manifest.write_bytes(original)

            def compile_and_modify(path):
                manifest.write_text("{}")
                return compile_rules(path)

            with patch("malware_scanner.lab.compile_rules", side_effect=compile_and_modify):
                report = evaluate(manifest, root)
            self.assertEqual(report["manifest_sha256"], hashlib.sha256(original).hexdigest())


if __name__ == "__main__":
    unittest.main()
