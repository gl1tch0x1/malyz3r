"""Unit tests for file-system monitoring agent, stabilization, and reconciliation."""

import tempfile
import time
import unittest
from pathlib import Path

from malware_scanner.monitor import MonitoringAgent
from malware_scanner.storage import Storage


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.watch_dir = self.root / "monitored"
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(self.root / "test_monitor.db")
        self.storage = Storage(self.db_path)
        self.agent = MonitoringAgent(
            storage=self.storage,
            paths=[str(self.watch_dir)],
            exclusions=["*.tmp", "*/ignore/*"],
            max_queue_size=5,
            worker_threads=1,
            debounce_seconds=0.1,
        )

    def tearDown(self):
        self.agent.stop()
        self.storage.close()
        self.tmpdir.cleanup()

    def test_exclusion_matching(self):
        self.assertTrue(self.agent.is_excluded("/tmp/test.tmp"))
        self.assertTrue(self.agent.is_excluded("/path/to/ignore/file.txt"))
        self.assertFalse(self.agent.is_excluded(str(self.watch_dir / "target.bin")))

    def test_stabilization_detects_ready_file(self):
        sample = self.watch_dir / "ready.txt"
        sample.write_text("stable content", encoding="utf-8")
        self.assertTrue(self.agent.stabilize_file(str(sample), max_retries=2, interval=0.05))

    def test_queue_backpressure_and_drop_tracking(self):
        # Fill queue to maximum capacity
        for i in range(5):
            self.agent.enqueue_event(f"/path/test_{i}.bin", "create")
        self.assertEqual(self.agent.events_dropped, 0)

        # 6th item exceeds capacity and is dropped
        self.agent.enqueue_event("/path/test_overflow.bin", "create")
        self.assertEqual(self.agent.events_dropped, 1)

    def test_reconciliation_sweep(self):
        # Create files in monitored directory
        f1 = self.watch_dir / "file1.txt"
        f1.write_text("sample content 1", encoding="utf-8")
        f2 = self.watch_dir / "file2.txt"
        f2.write_text("sample content 2", encoding="utf-8")
        ignored = self.watch_dir / "file3.tmp"
        ignored.write_text("temp", encoding="utf-8")

        count = self.agent.run_reconciliation()
        self.assertEqual(count, 2)
        self.assertIsNotNone(self.agent.last_reconciliation_at)

        # Second sweep with unchanged files finds 0 new items
        second_count = self.agent.run_reconciliation()
        self.assertEqual(second_count, 0)

    def test_agent_start_and_graceful_stop(self):
        self.agent.start()
        self.assertTrue(self.agent.running)
        time.sleep(0.2)

        health = self.storage.get_health()
        self.assertEqual(health["status"], "running")

        self.agent.stop()
        self.assertFalse(self.agent.running)
        final_health = self.storage.get_health()
        self.assertEqual(final_health["status"], "stopped")


if __name__ == "__main__":
    unittest.main()
