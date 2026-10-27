"""Real YARA, supervised jobs, persisted artifacts and authenticated HTTP contracts."""

import copy
import json
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from test_operations import OperationsBase

from malware_scanner.artifacts import write_json
from malware_scanner.assurance import TRANSITIONS, compare, coverage, gate, main, metrics, outcome
from malware_scanner.lab import evaluate
from malware_scanner.web import Workspace, make_server


class AssuranceTests(OperationsBase):
    def setUp(self):
        super().setUp()
        self.baseline = evaluate(self.manifest, self.rules)

    def test_real_yara_comparison_and_gate(self):
        self.rule.write_text('rule detect { strings: $a="ordinary" condition: $a }')
        candidate = evaluate(self.manifest, self.rules)
        result = compare(self.baseline, candidate)
        self.assertTrue(result["comparable"])
        self.assertEqual(
            {r["change"] for r in result["transitions"]},
            {"detection_regression", "new_false_positive"},
        )
        self.assertNotEqual(result["baseline_pack_digest"], result["candidate_pack_digest"])
        self.assertEqual(gate(self.baseline, candidate, {"version": "1"})["status"], "fail")
        self.assertEqual(gate(self.baseline, self.baseline, {"version": "1"})["status"], "pass")
        reverse = compare(candidate, self.baseline)
        self.assertEqual(
            {r["change"] for r in reverse["transitions"]},
            {"new_detection", "resolved_false_positive"},
        )

    def test_all_transitions_and_unknown(self):
        positive, negative = self.baseline["samples"]
        examples = {
            "tp": positive,
            "tn": negative,
            "fn": dict(positive, matches=[], status="no_match"),
            "fp": dict(negative, matches=positive["matches"], status="matched"),
        }
        for (old, new), expected in TRANSITIONS.items():
            a, b = copy.deepcopy(self.baseline), copy.deepcopy(self.baseline)
            a["samples"] = [dict(examples[old], sha256="a" * 64)]
            b["samples"] = [dict(examples[new], sha256="a" * 64)]
            self.assertEqual(compare(a, b)["transitions"][0]["change"], expected)
        unknown = dict(positive, label="unknown", expected_rules=[])
        self.assertEqual(outcome(unknown), "unknown")
        b = copy.deepcopy(self.baseline)
        b["samples"][0] = unknown
        self.assertEqual(gate(b, b, {"version": "1"})["status"], "inconclusive")
        self.assertIsNone(metrics(dict(b, samples=[]))["recall"])
        self.assertEqual(
            gate(dict(b, samples=[]), dict(b, samples=[]), {"version": "1"})["status"],
            "inconclusive",
        )

    def test_incompatible_duplicate_missing_and_interrupted(self):
        for change in (
            {"settings": {}},
            {"yara_version": "other"},
            {"complete": False},
            {"inventory_complete": False},
        ):
            b = dict(self.baseline, **change)
            self.assertFalse(compare(self.baseline, b)["comparable"])
            self.assertEqual(gate(self.baseline, b, {"version": "1"})["status"], "inconclusive")
        b = dict(self.baseline, samples=self.baseline["samples"][:1])
        self.assertFalse(compare(self.baseline, b)["comparable"])
        with self.assertRaises(ValueError):
            compare(self.baseline, dict(b, samples=b["samples"] * 2))
        b = copy.deepcopy(self.baseline)
        b["samples"][0]["sha256"] = None
        with self.assertRaises(ValueError):
            compare(self.baseline, b)

    def test_coverage_denominators(self):
        cells = coverage(self.baseline)
        self.assertEqual(len(cells), 1)
        cell = cells[0]
        self.assertEqual(
            (cell["family"], cell["detected"], cell["denominator"]), ("Unknown family", 1, 1)
        )
        self.assertEqual(cell["state"], "insufficient_evidence")
        b = copy.deepcopy(self.baseline)
        b["samples"][0].update(matches=[], status="no_match")
        self.assertEqual(coverage(b)[0]["rate"], 0)
        b["samples"][0].update(label="unknown", expected_rules=[])
        self.assertIsNone(coverage(b)[0]["rate"])
        self.assertEqual(coverage(b)[0]["state"], "no_applicable_samples")
        self.assertEqual(coverage(dict(b, samples=[])), [])
        b["samples"][0].update(
            label="target", expected_rules=["detect.yar:detect"], status="timeout"
        )
        self.assertEqual(coverage(b)[0]["state"], "incomplete")

    def test_policy_validation_and_cli(self):
        for policy in (
            {"version": "1", "typo": 0},
            {"version": "1", "min_recall": float("nan")},
            {"version": "1", "max_regressions": True},
            {"version": "1", "require_provenance": "yes"},
        ):
            with self.assertRaises(ValueError):
                gate(self.baseline, self.baseline, policy)
        report = self.root / "report.json"
        write_json(report, self.baseline)
        policy = self.root / "policy.json"
        write_json(policy, {"version": "1", "require_provenance": True})
        output = self.root / "comparison.json"
        self.assertEqual(
            main([str(report), str(report), "--policy", str(policy), "--output", str(output)]), 3
        )
        self.assertEqual(json.loads(output.read_text())["release_gate"]["status"], "fail")


class WebTests(OperationsBase):
    def test_history_excludes_changed_contents_and_settings(self):
        report = evaluate(self.manifest, self.rules)
        changed = copy.deepcopy(report)
        changed["samples"][0]["sha256"] = "f" * 64
        for name, data in [
            ("run-a", report),
            ("run-b", report),
            ("run-c", changed),
            ("run-d", dict(report, settings={})),
        ]:
            write_json(self.workspace.runs / name / "report.json", data)
            write_json(
                self.workspace.runs / name / "status.json", dict(run_id=name, status="completed")
            )
        history = self.request("/api/overview?run=run-a")["history"]
        self.assertEqual({r["run_id"] for r in history}, {"run-a", "run-b"})

    def wait_job(self, job):
        for _ in range(200):
            result = self.request("/api/job?id=" + job["job_id"])
            if result["status"] != "running":
                return result
            time.sleep(0.1)
        self.fail("Background job did not finish")

    def test_map_observations_and_exact_metric_drilldown(self):
        report = evaluate(self.manifest, self.rules)
        for row in report["samples"]:
            row["family"] = "Dataset group"
        write_json(self.workspace.runs / "map-run" / "report.json", report)
        graph = self.request("/api/map?run=map-run")
        self.assertEqual(
            {n["type"] for n in graph["nodes"]}, {"family", "rule", "sample", "indicator"}
        )
        nodes = {n["id"]: n for n in graph["nodes"]}
        for edge in graph["edges"]:
            self.assertIn(edge["source"], nodes)
            self.assertIn(edge["target"], nodes)
            self.assertNotEqual(
                {nodes[edge["source"]]["type"], nodes[edge["target"]]["type"]}, {"family", "rule"}
            )
        family = next(n for n in graph["nodes"] if n["type"] == "family")
        self.assertEqual(family["details"]["detected_targets"], 1)
        self.assertEqual(self.request("/api/evidence?run=map-run&outcome=fp")["total"], 0)
        self.assertEqual(self.request("/api/evidence?run=map-run&outcome=tp")["total"], 1)
        self.assertEqual(self.request("/api/overview?run=map-run")["metrics"]["tp"], 1)
        self.assertEqual(self.request("/api/map?run=map-run&search=absent")["nodes"], [])

    def test_rule_editor_validation_evaluation_and_original_preservation(self):
        original = self.rule.read_text()
        source = self.request("/api/source?pack=test")
        self.assertEqual(source["source"], original)
        body = dict(
            rule_pack="test",
            filename="detect.yar",
            source="rule broken { condition: }",
            dataset="test",
            action="validate",
        )
        failed = self.wait_job(self.request("/api/rule-job", body))
        self.assertEqual(failed["status"], "rejected")
        self.assertFalse(failed["validation"]["valid"])
        self.assertNotIn(str(self.root), json.dumps(failed))
        body.update(source="rule detect { condition: true }", action="validate")
        valid = self.wait_job(self.request("/api/rule-job", body))
        self.assertTrue(valid["validation"]["valid"])
        body["action"] = "evaluate"
        run = self.wait_job(self.request("/api/rule-job", body))
        self.assertEqual(run["status"], "completed")
        report = self.workspace.report(run["run_id"])
        self.assertEqual(metrics(report)["fp"], 1)
        self.assertEqual(self.rule.read_text(), original)

    def test_rule_editor_rejects_traversal_oversized_text_and_unknown_actions(self):
        body = dict(
            rule_pack="test",
            filename="detect.yar",
            source="rule x { condition: true }",
            dataset="test",
            action="validate",
        )
        for change in (
            {"filename": "../secret.yar"},
            {"source": "x" * 12001},
            {"action": "execute"},
        ):
            with self.assertRaises(HTTPError) as caught:
                self.request("/api/rule-job", dict(body, **change))
            self.assertEqual(caught.exception.code, 400)

    def setUp(self):
        super().setUp()
        self.workspace = Workspace(
            self.root,
            catalog={"datasets": {"test": "manifest.json"}, "rule_packs": {"test": "rules"}},
        )
        self.server, self.token = make_server(self.workspace, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def request(self, path, body=None, headers=None):
        h = {"Authorization": "Bearer " + self.token}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        request = Request(
            self.url + path, data=json.dumps(body).encode() if body is not None else None, headers=h
        )
        with urlopen(request, timeout=15) as response:
            return json.loads(response.read())

    def test_http_evaluation_to_export_and_evidence(self):
        self.assertEqual(self.request("/api/history")["items"], [])
        job = self.request("/api/evaluate", {"dataset": "test", "rule_pack": "test"})
        for _ in range(150):
            result = self.request("/api/job?id=" + job["job_id"])
            if result["status"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(result["status"], "completed")
        run = result["run_id"]
        self.assertEqual(self.request("/api/history")["total"], 1)
        evidence = self.request("/api/evidence?run=" + run)
        self.assertEqual(evidence["total"], 2)
        self.assertNotIn(str(self.root), json.dumps(evidence))
        sha = evidence["items"][0]["sha256"]
        self.assertEqual(self.request("/api/evidence?run=" + run + "&sha=" + sha)["total"], 1)
        coverage_result = self.request("/api/coverage?run=" + run + "&baseline=" + run)
        self.assertEqual(coverage_result["items"][0]["delta"], 0)
        self.assertEqual(self.request("/api/rules?run=" + run)["total"], 1)
        self.assertTrue(self.request("/api/graph?run=" + run)["edges"])
        comparison = self.request(
            "/api/compare", {"baseline": run, "candidate": run, "policy": {"version": "1"}}
        )
        self.assertEqual(comparison["release_gate"]["status"], "pass")
        self.assertTrue(list((self.workspace.runs / run / "release-decisions").glob("*.json")))
        reloaded = Workspace(self.root)
        self.assertEqual(reloaded.history()[0]["run_id"], run)

    def test_different_runs_with_redacted_paths(self):
        baseline = evaluate(self.manifest, self.rules)
        self.rule.write_text("rule detect { condition: true }")
        candidate = evaluate(self.manifest, self.rules)
        for name, report in (("baseline", baseline), ("candidate", candidate)):
            write_json(self.workspace.runs / name / "report.json", report)
        result = self.request(
            "/api/compare",
            {"baseline": "baseline", "candidate": "candidate", "policy": {"version": "1"}},
        )
        self.assertEqual(result["release_gate"]["status"], "fail")
        self.assertEqual(result["candidate"]["fp"], 1)
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_auth_traversal_origin_and_unknown_catalog(self):
        for path, body, headers, status in [
            ("/api/history", None, {"Authorization": ""}, 401),
            ("/api/history", None, {"Origin": "https://evil.example"}, 403),
            ("/api/history", None, {"Host": "evil.example"}, 403),
            ("/api/evidence?run=..", None, {}, 400),
            ("/api/evaluate", {"dataset": "../secret", "rule_pack": "test"}, {}, 400),
        ]:
            with self.assertRaises(HTTPError) as caught:
                self.request(path, body, headers)
            self.assertEqual(caught.exception.code, status)
        document = json.loads(self.manifest.read_text())
        document["samples"][0]["path"] = "../outside"
        self.manifest.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            self.workspace.start("test", "test")
        with self.assertRaises(ValueError):
            Workspace(self.root, runs="../outside")

    def test_interrupted_job_and_static_security_headers(self):
        write_json(self.workspace.runs / "webjob-old.json", {"status": "running"})
        Workspace(self.root)
        self.assertEqual(
            json.loads((self.workspace.runs / "webjob-old.json").read_text())["status"],
            "interrupted",
        )
        with urlopen(self.url, timeout=10) as response:
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertIn(b"malyz3r", response.read())


if __name__ == "__main__":
    unittest.main()
