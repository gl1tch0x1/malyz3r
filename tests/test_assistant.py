import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from malware_scanner.assistant import assist, call_provider, prepare_evidence, validate_advice
from malware_scanner.lab import evaluate


class AssistantBase(unittest.TestCase):
    temp: tempfile.TemporaryDirectory[str]
    root: Path
    run_dir: Path
    report: dict[str, Any]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

        rules = self.root / "rules"
        rules.mkdir()
        (rules / "example.yar").write_text('rule Example { strings: $a = "marker" condition: $a }')
        (self.root / "private-client-file.txt").write_text("marker PRIVATE_SAMPLE_CONTENT")
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps(
                dict(
                    samples=[
                        dict(
                            path="private-client-file.txt",
                            label="benign",
                            expected_rules=[],
                            split="development",
                            provenance="PRIVATE_CLIENT_NAME",
                        )
                    ]
                )
            )
        )
        self.run_dir = self.root / "run"
        self.report = evaluate(manifest, rules, snapshot_dir=self.run_dir / "inputs")
        self.save_report()

    def save_report(self):
        (self.run_dir / "report.json").write_text(json.dumps(self.report))

    def response(self, **changes) -> dict[str, Any]:
        advice = dict(
            summary="A benign sample matched.",
            findings=[
                dict(
                    evidence_ids=["sample-000001"],
                    explanation="The rule matched a benign label.",
                    suggestion="Review development evidence before changing the rule.",
                )
            ],
            candidate_yara=None,
            limitations=["No sample bytes supplied; labels unverified."],
        )
        advice.update(changes)
        return dict(
            status="completed",
            id="response-test",
            model="test-model",
            usage={"output_tokens": 40},
            output=[
                dict(type="message", content=[dict(type="output_text", text=json.dumps(advice))])
            ],
        )


AssistantTestMixin = AssistantBase


class AssistantTests(AssistantBase):
    def test_preview_has_no_network_or_private_content(self):
        output = self.root / "preview"
        with patch("malware_scanner.assistant.call_provider") as provider:
            status = assist(self.run_dir, output, "test-model")
            provider.assert_not_called()
        self.assertEqual(status["status"], "prepared")
        text = (output / "request.json").read_text()
        for private in (
            str(self.root),
            "PRIVATE_SAMPLE_CONTENT",
            "PRIVATE_CLIENT_NAME",
            "private-client-file",
        ):
            self.assertNotIn(private, text)
        self.assertFalse(json.loads(text)["store"])
        self.assertNotIn("tools", json.loads(text))
        self.assertTrue((output / "evidence-map.json").exists())

    def test_all_non_development_splits_fail_before_network(self):
        for split in ("held_out", "unspecified", None):
            with self.subTest(split=split):
                self.report["samples"][0]["split"] = split
                self.save_report()
                with (
                    patch("malware_scanner.assistant.call_provider") as provider,
                    self.assertRaises(ValueError),
                ):
                    assist(self.run_dir, self.root / "blocked", "test-model", send=True)
                provider.assert_not_called()

    def test_source_requires_opt_in_and_hash_verification(self):
        evidence, _, _ = prepare_evidence(self.run_dir)
        self.assertNotIn("rule_sources", evidence)
        evidence, _, _ = prepare_evidence(self.run_dir, True)
        rule_sources = evidence["rule_sources"]
        self.assertIsInstance(rule_sources, dict)
        self.assertIn("example.yar", rule_sources)

        (self.run_dir / "inputs/rules/example.yar").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            prepare_evidence(self.run_dir, True)

    def test_snapshot_path_escape_is_rejected(self):
        self.report["rule_sources_sha256"] = {"../../outside": "0" * 64}
        self.save_report()
        with self.assertRaisesRegex(ValueError, "escapes"):
            prepare_evidence(self.run_dir, True)

    def test_send_requires_key_and_preserves_original_run(self):
        original = (self.run_dir / "report.json").read_bytes()
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"),
        ):
            assist(self.run_dir, self.root / "missing-key", "test-model", send=True)
        with (
            patch.dict(os.environ, {"OPENAI_API_KEY": "test-secret"}),
            patch("malware_scanner.assistant.call_provider", return_value=self.response()),
        ):
            status = assist(self.run_dir, self.root / "advice", "test-model", send=True)
        self.assertEqual(status["status"], "advice_unvalidated")
        self.assertEqual((self.run_dir / "report.json").read_bytes(), original)

        for path in (self.root / "advice").iterdir():
            self.assertNotIn("test-secret", path.read_text())

    def test_unknown_citations_refusal_and_incomplete_output_fail(self):
        bad_citation = self.response(
            findings=[dict(evidence_ids=["invented"], explanation="x", suggestion="y")]
        )
        refused = dict(
            status="completed",
            output=[dict(type="message", content=[dict(type="refusal", refusal="no")])],
        )
        for response in (
            bad_citation,
            refused,
            {"status": "incomplete"},
            {"status": "completed", "output": [None]},
        ):
            with self.subTest(response=response), self.assertRaises(ValueError):
                validate_advice(response, {"sample-000001"})

    def test_candidate_remains_text_without_compilation_or_promotion(self):
        candidate = "rule Example { condition: false }"
        with (
            patch.dict(os.environ, {"OPENAI_API_KEY": "test-secret"}),
            patch(
                "malware_scanner.assistant.call_provider",
                return_value=self.response(candidate_yara=candidate),
            ),
            patch("malware_scanner.lab.compile_rules") as compiler,
        ):
            output = self.root / "candidate"
            assist(self.run_dir, output, "test-model", send=True, include_rule_source=True)
            compiler.assert_not_called()

        self.assertEqual((output / "candidate.yar.txt").read_text(), candidate)
        self.assertFalse(list(output.glob("*.yar")))

    def test_http_failure_has_no_response_body_or_credential_leak(self):
        response = Mock(status_code=429)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch("malware_scanner.assistant.requests.post", return_value=response) as post:
            with self.assertRaisesRegex(ValueError, "HTTP 429"):
                call_provider({}, "test-secret")
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        self.assertEqual(post.call_count, 1)

    def test_invalid_model_output_leaves_failed_status(self):
        output = self.root / "invalid"
        with (
            patch.dict(os.environ, {"OPENAI_API_KEY": "test-secret"}),
            patch(
                "malware_scanner.assistant.call_provider",
                return_value=self.response(limitations=[]),
            ),
            self.assertRaises(ValueError),
        ):
            assist(self.run_dir, output, "test-model", send=True)

        self.assertEqual(json.loads((output / "status.json").read_text())["status"], "failed")
        self.assertFalse((output / "advice.json").exists())

    def test_http_success_parses_structured_envelope(self):
        response = Mock(status_code=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [json.dumps(self.response()).encode()]
        with patch("malware_scanner.assistant.requests.post", return_value=response):
            envelope = call_provider({"model": "test-model"}, "test-secret")
        advice = validate_advice(envelope, {"sample-000001"})
        self.assertIn("benign", advice["summary"])

    def test_http_response_size_is_bounded(self):
        response = Mock(status_code=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [b"x" * (1024 * 1024 + 1)]
        with (
            patch("malware_scanner.assistant.requests.post", return_value=response),
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            call_provider({}, "test-secret")
