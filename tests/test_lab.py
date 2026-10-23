import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import yara

from malware_scanner.lab import RuleCompilationError, compile_rules, evaluate, scan_file

ROOT = Path(__file__).resolve().parents[1]


class LabTests(unittest.TestCase):
    def test_bundled_regressions(self):
        report = evaluate(ROOT / "samples/lab/manifest.json", ROOT / "malware_scanner/rules")
        self.assertTrue(report["complete"])
        for sample in report["samples"]:
            self.assertEqual({m["id"] for m in sample["matches"]}, set(sample["expected_rules"]))
        self.assertEqual(report["per_rule"]["ransomware.yar:Ransomware_Generic"]["recall"], 1)
        self.assertTrue(
            all(count["tp"] >= 1 and count["tn"] >= 1 for count in report["per_rule"].values())
        )

    def test_broken_and_empty_rules_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuleCompilationError):
                compile_rules(tmp)
            Path(tmp, "broken.yar").write_text("rule broken { condition: }")
            with self.assertRaises(RuleCompilationError):
                compile_rules(tmp)

    def test_edits_are_not_stale_and_nested_rules_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp, "nested")
            folder.mkdir()
            rule = folder / "test.yara"
            rule.write_text("rule test { condition: true }")
            self.assertTrue(compile_rules(tmp).match(data=b"hello"))
            rule.write_text("rule test { condition: false }")
            self.assertFalse(compile_rules(tmp).match(data=b"hello"))

    def test_errors_are_not_nonmatches(self):
        rules = Mock()
        self.assertEqual(scan_file(ROOT / "missing-sample", rules)["status"], "error")
        rules.match.side_effect = yara.TimeoutError("timed out")
        self.assertEqual(scan_file(ROOT / "samples/benign_sample.txt", rules)["status"], "timeout")

    def test_confusion_matrix_and_missing_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.yar").write_text('rule test { strings: $a="hit" condition: $a }')
            samples = []
            for name, text, label, expected in [
                ("tp", "hit positive", "target", ["test.yar:test"]),
                ("fn", "miss positive", "target", ["test.yar:test"]),
                ("fp", "hit negative", "benign", []),
                ("tn", "miss negative", "benign", []),
            ]:
                (root / name).write_text(text)
                samples.append(dict(path=name, label=label, expected_rules=expected))
            samples.append(dict(path="absent", label="benign", expected_rules=[]))
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(dict(samples=samples)))
            report = evaluate(manifest, root)
            self.assertFalse(report["complete"])
            self.assertEqual(report["errors"], 1)
            count = report["per_rule"]["test.yar:test"]
            self.assertEqual([count[k] for k in ("tp", "fp", "tn", "fn")], [1, 1, 1, 1])
            self.assertEqual(count["recall"], 0.5)
            self.assertEqual(count["false_positive_rate"], 0.5)
            self.assertEqual(count["precision"], 0.5)

    def test_hash_mismatch_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.yar").write_text("rule test { condition: true }")
            (root / "sample").write_text("harmless")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    dict(
                        samples=[
                            dict(path="sample", label="benign", expected_rules=[], sha256="0" * 64)
                        ]
                    )
                )
            )
            report = evaluate(manifest, root)
            self.assertFalse(report["complete"])
            self.assertEqual(report["per_rule"]["test.yar:test"]["fp"], 0)

    def test_duplicate_samples_and_unknown_rules_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.yar").write_text("rule test { condition: true }")
            (root / "one").write_text("same content")
            (root / "two").write_text("same content")
            manifest = root / "manifest.json"
            samples = [dict(path=p, label="benign", expected_rules=[]) for p in ("one", "two")]
            manifest.write_text(json.dumps(dict(samples=samples)))
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                evaluate(manifest, root)
            samples[0].update(label="target", expected_rules=["unknown:rule"])
            manifest.write_text(json.dumps(dict(samples=samples[:1])))
            with self.assertRaisesRegex(ValueError, "Unknown"):
                evaluate(manifest, root)

    def test_pinned_missing_sample_preserves_read_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.yar").write_text("rule test { condition: true }")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "samples": [
                            dict(path="missing", label="benign", expected_rules=[], sha256="0" * 64)
                        ]
                    }
                )
            )
            report = evaluate(manifest, root)
            self.assertFalse(report["complete"])
            self.assertIsNone(report["samples"][0]["sha256"])
            self.assertNotEqual(report["samples"][0]["error"], "Manifest SHA256 mismatch")
            self.assertIn("missing", report["samples"][0]["error"])


if __name__ == "__main__":
    unittest.main()
