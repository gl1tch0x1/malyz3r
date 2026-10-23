import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from malware_scanner.corpus import inventory, merge_manifests
from malware_scanner.lab import evaluate
from malware_scanner.quality import check_policy, compare_reports
from malware_scanner.workbench import run_job


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rules = self.root / "rules"
        self.rules.mkdir()
        self.rule = self.rules / "detect.yar"
        self.rule.write_text('rule detect { strings: $a="TARGET" condition: $a }')
        (self.root / "positive").write_text("TARGET harmless regression text")
        (self.root / "negative").write_text("ordinary benign text")
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                dict(
                    name="test",
                    kind="synthetic",
                    samples=[
                        dict(
                            path="positive",
                            label="target",
                            expected_rules=["detect.yar:detect"],
                            split="development",
                        ),
                        dict(
                            path="negative", label="benign", expected_rules=[], split="development"
                        ),
                    ],
                )
            )
        )

    def test_inventory_preserves_unknown_and_deduplicates(self):
        corpus = self.root / "corpus"
        corpus.mkdir()
        (corpus / "first").write_text("same file")
        (corpus / "second").write_text("same file")
        result = inventory(corpus, "test provenance")
        self.assertEqual(len(result["samples"]), 1)
        self.assertEqual(len(result["inventory"]["duplicates"]), 1)
        self.assertEqual(result["samples"][0]["label"], "unknown")
        self.assertEqual(len(result["samples"][0]["sha256"]), 64)

    def test_unknown_labels_are_excluded_and_cannot_pass_default_policy(self):
        manifest = json.loads(self.manifest.read_text())
        manifest["samples"][0].update(label="unknown", expected_rules=[])
        self.manifest.write_text(json.dumps(manifest))
        report = evaluate(self.manifest, self.rules)
        self.assertEqual(report["unknown_labels"], 1)
        self.assertEqual(report["per_rule"]["detect.yar:detect"]["fp"], 0)
        self.assertIsNone(report["per_rule"]["detect.yar:detect"]["recall"])
        self.assertFalse(check_policy(report, {})["passed"])

    def test_comparison_reports_real_match_changes(self):
        baseline = evaluate(self.manifest, self.rules)
        self.rule.write_text("rule detect { condition: true }")
        candidate = evaluate(self.manifest, self.rules)
        result = compare_reports(baseline, candidate)
        self.assertEqual(result["regression_count"], 1)
        self.assertEqual(result["changes"][0]["change"], "new_false_positive")
        self.assertEqual(result["deltas"]["detect.yar:detect"]["benign_false_positive_rate"], 1)

    def test_comparison_rejects_changed_labels_and_corpus(self):
        report = evaluate(self.manifest, self.rules)
        modified = copy.deepcopy(report)
        modified["samples"][0]["split"] = "held_out"
        with self.assertRaisesRegex(ValueError, "labels or split"):
            compare_reports(report, modified)
        modified = copy.deepcopy(report)
        modified["samples"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hashes differ"):
            compare_reports(report, modified)

    def test_policy_enforces_evidence_and_thresholds(self):
        report = evaluate(self.manifest, self.rules)
        self.assertTrue(check_policy(report, dict(min_recall=1, max_benign_fpr=0))["passed"])
        for policy in (
            dict(reject_synthetic=True),
            dict(require_held_out=True),
            dict(min_target_samples=10),
            dict(max_benign_fpr_upper95=0.001),
            dict(min_recall_lower95=0.9),
            dict(min_benign_samples=10),
        ):
            self.assertFalse(check_policy(report, policy)["passed"])
        for policy in (dict(min_recall=float("nan")), dict(min_recall=True), dict(typo=1)):
            with self.assertRaises(ValueError):
                check_policy(report, policy)

    def test_run_writes_snapshots_progress_and_exports(self):
        result = run_job(self.manifest, self.rules, self.root / "runs")
        self.assertEqual(result["status"], "completed")
        run = Path(result["run_directory"])
        for name in (
            "status.json",
            "report.json",
            "metrics.csv",
            "report.html",
            "samples.jsonl",
            "progress.json",
            "inputs/manifest.original.json",
            "inputs/manifest.resolved.json",
            "inputs/rules/detect.yar",
        ):
            self.assertTrue((run / name).is_file(), name)
        self.assertEqual(len((run / "samples.jsonl").read_text().splitlines()), 2)

    def test_worker_does_not_import_a_package_from_the_sample_directory(self):
        shadow = self.root / "malware_scanner"
        shadow.mkdir()
        (shadow / "__init__.py").write_text('raise RuntimeError("untrusted package imported")')
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            result = run_job(self.manifest, self.rules, self.root / "runs")
        finally:
            os.chdir(previous)
        self.assertEqual(result["status"], "completed")

    def test_bad_rules_leave_failed_run_record(self):
        self.rule.write_text("not a rule")
        result = run_job(self.manifest, self.rules, self.root / "runs")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue((Path(result["run_directory"]) / "worker.log").stat().st_size)

    def test_supervisor_kills_hung_process(self):
        original_popen = subprocess.Popen

        def sleeping_worker(*args, **kwargs):
            return original_popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)

        with patch("malware_scanner.workbench.subprocess.Popen", side_effect=sleeping_worker):
            result = run_job(self.manifest, self.rules, self.root / "runs", wall_seconds=1)
        self.assertEqual(result["status"], "timed_out")
        self.assertLess(result["elapsed_seconds"], 10)

    def test_supervisor_enforces_memory_budget(self):
        original_popen = subprocess.Popen

        def memory_worker(*args, **kwargs):
            return original_popen(
                [sys.executable, "-c", "import time; x=bytearray(20*1024*1024); time.sleep(30)"],
                **kwargs,
            )

        with patch("malware_scanner.workbench.subprocess.Popen", side_effect=memory_worker):
            result = run_job(self.manifest, self.rules, self.root / "runs", memory_mb=1)
        self.assertEqual(result["status"], "resource_limit")

    def test_merge_rejects_split_leakage(self):
        corpus = self.root / "corpus"
        corpus.mkdir()
        (corpus / "one").write_text("known bytes")
        first = inventory(corpus, "source", label="benign", split="development")
        second = copy.deepcopy(first)
        second["samples"][0]["split"] = "held_out"
        a, b = self.root / "a.json", self.root / "b.json"
        a.write_text(json.dumps(first))
        b.write_text(json.dumps(second))
        with self.assertRaisesRegex(ValueError, "split leakage"):
            merge_manifests([a, b])

    def test_html_escapes_dataset_content(self):
        from malware_scanner.artifacts import export_report

        report = evaluate(self.manifest, self.rules)
        report["dataset"] = "<script>alert(1)</script>"
        export_report(report, self.root)
        output = (self.root / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)


if __name__ == "__main__":
    unittest.main()
