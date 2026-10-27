"""Unit tests for controlled AI learning, candidate rules, and human-authorized promotion."""

import tempfile
import unittest
from pathlib import Path

from malware_scanner.learning import LearningPipeline
from malware_scanner.storage import Storage


class LearningTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.db_path = str(self.root / "test_learning.db")
        self.rules_dir = self.root / "rules"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        # Seed an existing base rule
        (self.rules_dir / "base.yar").write_text(
            'rule base_rule {\n  strings:\n    $s = "BASE_SIGNATURE"\n  condition:\n    $s\n}\n',
            encoding="utf-8"
        )
        self.storage = Storage(self.db_path)
        self.learning = LearningPipeline(self.storage)

    def tearDown(self):
        self.storage.close()
        self.tmpdir.cleanup()

    def test_record_feedback_and_export_manifest(self):
        inv_id = "inv-learn-01"
        sample_path = self.root / "sample.bin"
        sample_path.write_bytes(b"analyst verified payload")

        self.storage.save_investigation({
            "id": inv_id,
            "file_path": str(sample_path),
            "sha256": "aabbccddeeff",
            "file_size": len("analyst verified payload"),
            "file_type": "binary",
            "state": "awaiting_review",
            "severity": "high",
            "automated_assessment": "suspicious"
        })

        fb = self.learning.record_feedback(
            investigation_id=inv_id,
            verdict="confirmed_malicious",
            analyst="malware_lead",
            notes="Confirmed malicious drop behavior"
        )
        self.assertEqual(fb["verdict"], "confirmed_malicious")

        manifest_path = str(self.root / "exported_manifest.json")
        manifest = self.learning.export_learning_manifest(manifest_path)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(len(manifest["samples"]), 1)
        self.assertEqual(manifest["samples"][0]["sha256"], "aabbccddeeff")
        self.assertEqual(manifest["samples"][0]["label"], "target")

    def test_candidate_rule_syntax_validation_and_registration(self):
        # Invalid syntax fails closed
        with self.assertRaises(ValueError):
            self.learning.create_candidate_rule(
                rule_name="broken_rule",
                rule_source="rule broken_rule { strings: condition: NOT_VALID_SYNTAX }",
                created_by="engineer"
            )

        # Valid syntax succeeds
        valid_src = 'rule cand_rule {\n  strings:\n    $a = "TEST_INDICATOR"\n  condition:\n    $a\n}\n'
        cand = self.learning.create_candidate_rule(
            rule_name="cand_rule",
            rule_source=valid_src,
            created_by="detection_eng"
        )
        self.assertEqual(cand["status"], "draft")
        self.assertEqual(cand["rule_name"], "cand_rule")

    def test_controlled_promotion_and_rollback(self):
        rule_src = 'rule promoted_rule {\n  strings:\n    $b = "NEW_THREAT"\n  condition:\n    $b\n}\n'
        cand = self.learning.create_candidate_rule(
            rule_name="promoted_rule",
            rule_source=rule_src,
            created_by="detection_eng"
        )
        cand_id = cand["candidate_id"]

        # Human authorization required for promotion
        promoted = self.learning.promote_candidate(
            candidate_id=cand_id,
            authorized_by="security_director",
            rules_dir=str(self.rules_dir)
        )
        self.assertEqual(promoted["status"], "promoted")
        self.assertTrue((self.rules_dir / "promoted_rule.yar").is_file())

        # Test rollback
        rollback = self.learning.rollback_rule(
            candidate_id=cand_id,
            actor="security_director",
            rules_dir=str(self.rules_dir)
        )
        self.assertEqual(rollback["status"], "rolled_back")
        self.assertFalse((self.rules_dir / "promoted_rule.yar").is_file())


if __name__ == "__main__":
    unittest.main()
