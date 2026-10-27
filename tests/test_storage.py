"""Unit tests for SQLite persistent storage and investigation records."""

import tempfile
import unittest
from pathlib import Path

from malware_scanner.storage import Storage


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "test_store.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        self.storage.close()
        self.tmpdir.cleanup()

    def test_schema_init_and_health_reporting(self):
        health = self.storage.get_health()
        self.assertEqual(health["status"], "stopped")
        self.assertEqual(health["monitored_paths_count"], 0)

        self.storage.update_health(
            status="running",
            service_pid=1234,
            uptime=42.5,
            monitored_paths=3,
            failed_paths=0,
            queue_size=5,
            events_processed=100,
            events_dropped=1,
            details={"test": True}
        )

        updated = self.storage.get_health()
        self.assertEqual(updated["status"], "running")
        self.assertEqual(updated["service_pid"], 1234)
        self.assertEqual(updated["uptime_seconds"], 42.5)
        self.assertEqual(updated["monitored_paths_count"], 3)
        self.assertEqual(updated["queue_size"], 5)
        self.assertEqual(updated["events_processed"], 100)
        self.assertEqual(updated["events_dropped"], 1)
        self.assertTrue(updated["details"].get("test"))

    def test_monitored_locations_lifecycle(self):
        self.storage.set_monitored_location("/tmp/watch", enabled=True, recursive=True)
        locs = self.storage.get_monitored_locations()
        self.assertEqual(len(locs), 1)
        self.assertEqual(locs[0]["path"], "/tmp/watch")
        self.assertEqual(locs[0]["status"], "active")

        # Update location status
        self.storage.set_monitored_location("/tmp/watch", enabled=False, status="failed", error_message="Access denied")
        locs = self.storage.get_monitored_locations()
        self.assertEqual(locs[0]["status"], "failed")
        self.assertEqual(locs[0]["error_message"], "Access denied")

        # Remove location
        self.storage.remove_monitored_location("/tmp/watch")
        self.assertEqual(len(self.storage.get_monitored_locations()), 0)

    def test_investigation_lifecycle_and_evidence(self):
        inv_id = "inv-abc12345"
        self.storage.save_investigation({
            "id": inv_id,
            "file_path": "/home/user/suspicious.bin",
            "sha256": "abcdef1234567890",
            "file_size": 2048,
            "file_type": "application/x-executable-elf",
            "state": "analyzing",
            "severity": "high",
            "automated_assessment": "suspicious",
            "matched_rules": [{"id": "ruleset:test_trojan", "strings": ["$s1"]}],
        })

        retrieved = self.storage.get_investigation(inv_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["file_path"], "/home/user/suspicious.bin")
        self.assertEqual(retrieved["severity"], "high")
        self.assertEqual(len(retrieved["matched_rules"]), 1)

        # Add evidence
        self.storage.add_evidence(
            ev_id="ev-001",
            investigation_id=inv_id,
            stage="stage1",
            evidence_type="entropy",
            source="static",
            data={"entropy": 7.85}
        )

        with_ev = self.storage.get_investigation(inv_id)
        self.assertEqual(len(with_ev["evidence"]), 1)
        self.assertEqual(with_ev["evidence"][0]["data"]["entropy"], 7.85)

        # List filter by state & severity
        listing = self.storage.list_investigations(severity="high")
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["id"], inv_id)

    def test_analyst_feedback_and_learning_dataset(self):
        inv_id = "inv-feed123"
        self.storage.save_investigation({
            "id": inv_id,
            "file_path": "/tmp/sample.bin",
            "sha256": "1122334455667788",
            "file_size": 512,
            "file_type": "script",
            "state": "awaiting_review",
            "severity": "medium",
            "automated_assessment": "suspicious",
        })

        self.storage.record_feedback(
            feedback_id="fb-001",
            investigation_id=inv_id,
            sha256="1122334455667788",
            verdict="confirmed_malicious",
            analyst="senior_analyst",
            notes="Confirmed reverse shell behavior in script"
        )

        inv = self.storage.get_investigation(inv_id)
        self.assertEqual(inv["analyst_verdict"], "confirmed_malicious")
        self.assertEqual(inv["reviewed_by"], "senior_analyst")

        stats = self.storage.get_learning_stats()
        self.assertEqual(stats["total_feedback"], 1)
        self.assertEqual(stats["verdicts"]["confirmed_malicious"], 1)
        self.assertEqual(stats["dataset_records"]["target"], 1)


if __name__ == "__main__":
    unittest.main()
