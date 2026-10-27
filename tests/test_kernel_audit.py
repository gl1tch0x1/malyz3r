"""Comprehensive test suite for Linux Kernel Audit telemetry integration."""

import os
import tempfile
import time
import unittest

from malware_scanner.audit import (
    AuditAggregator,
    AuditEvent,
    AuditKernelBackend,
    AuditLogTailer,
    decode_audit_field,
    parse_audit_line,
)
from malware_scanner.monitor import MonitoringAgent
from malware_scanner.storage import Storage


class KernelAuditTests(unittest.TestCase):
    def test_decode_audit_field_plain_and_quoted(self):
        self.assertEqual(decode_audit_field(""), "")
        self.assertEqual(decode_audit_field('"hello"'), "hello")
        self.assertEqual(decode_audit_field('"/usr/bin/python3"'), "/usr/bin/python3")
        self.assertEqual(decode_audit_field("plain_value"), "plain_value")

    def test_decode_audit_field_hex_encoded(self):
        # Hex string for "/usr/bin/python3"
        hex_val = "/usr/bin/python3".encode("utf-8").hex()
        self.assertEqual(decode_audit_field(hex_val), "/usr/bin/python3")

        # Hex string for path with spaces
        hex_spaces = "/tmp/my evil tool".encode("utf-8").hex()
        self.assertEqual(decode_audit_field(hex_spaces), "/tmp/my evil tool")

    def test_parse_audit_line_syscall(self):
        line = (
            'type=SYSCALL msg=audit(1729900000.123:456): arch=c000003e syscall=59 success=yes exit=0 '
            'a0=7fffa1 a1=7fffa8 a2=7fffb0 a3=0 items=2 ppid=100 pid=200 auid=1000 uid=0 gid=0 '
            'euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="sh" exe="/bin/sh" '
            'key="malyz3r_exec"'
        )
        parsed = parse_audit_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "SYSCALL")
        self.assertEqual(parsed["event_id"], "1729900000.123:456")
        self.assertEqual(parsed["fields"]["syscall"], "59")
        self.assertEqual(parsed["fields"]["pid"], "200")
        self.assertEqual(parsed["fields"]["ppid"], "100")
        self.assertEqual(parsed["fields"]["exe"], "/bin/sh")
        self.assertEqual(parsed["fields"]["comm"], "sh")

    def test_parse_audit_line_non_audit_returns_none(self):
        self.assertIsNone(parse_audit_line(""))
        self.assertIsNone(parse_audit_line("regular syslog message without type prefix"))

    def test_audit_aggregator_multi_record_assembly(self):
        emitted_events = []

        def on_event(ev: AuditEvent):
            emitted_events.append(ev)

        agg = AuditAggregator(ttl=2.0, on_event=on_event)

        # Feed SYSCALL
        agg.feed_line(
            'type=SYSCALL msg=audit(1729900000.500:999): arch=c000003e syscall=59 success=yes exit=0 '
            'ppid=123 pid=456 uid=0 comm="python3" exe="/usr/bin/python3"'
        )
        # Feed EXECVE
        agg.feed_line(
            'type=EXECVE msg=audit(1729900000.500:999): argc=2 a0="python3" a1="/tmp/script.py"'
        )
        # Feed CWD
        agg.feed_line(
            'type=CWD msg=audit(1729900000.500:999): cwd="/home/analyst"'
        )
        # Feed PROCTITLE to complete the event
        agg.feed_line(
            'type=PROCTITLE msg=audit(1729900000.500:999): proctitle=707974686f6e33'
        )

        self.assertGreaterEqual(len(emitted_events), 1)
        ev = emitted_events[-1]
        self.assertEqual(ev.executable, "/usr/bin/python3")
        self.assertEqual(ev.pid, 456)
        self.assertEqual(ev.ppid, 123)
        self.assertEqual(ev.uid, 0)
        self.assertEqual(ev.cwd, "/home/analyst")
        self.assertEqual(ev.args, ["python3", "/tmp/script.py"])

    def test_audit_aggregator_relative_path_resolution(self):
        emitted_events = []
        agg = AuditAggregator(ttl=2.0, on_event=lambda e: emitted_events.append(e))

        # Relative executable name resolved via cwd
        agg.feed_line('type=CWD msg=audit(1729900001.000:101): cwd="/opt/malware"')
        agg.feed_line(
            'type=SYSCALL msg=audit(1729900001.000:101): arch=c000003e syscall=59 success=yes exit=0 '
            'ppid=1 pid=2 comm="dropper" exe="dropper"'
        )
        ev = agg.flush()

        self.assertIsNotNone(ev)
        self.assertEqual(len(emitted_events), 1)
        self.assertEqual(emitted_events[0].executable, os.path.normpath("/opt/malware/dropper"))

    def test_audit_aggregator_prune_stale(self):
        agg = AuditAggregator(ttl=0.1)
        # Incomplete record
        agg.feed_line('type=CWD msg=audit(1729900002.000:555): cwd="/tmp"')
        self.assertIn("1729900002.000:555", agg._records)

        time.sleep(0.2)
        agg.prune_stale()
        self.assertNotIn("1729900002.000:555", agg._records)

    def test_audit_kernel_backend_dispatch(self):
        dispatched = []

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x7fELFfake")
            temp_path = f.name

        try:
            backend = AuditKernelBackend(on_event=lambda p, t: dispatched.append((p, t)))
            backend.start()
            status = backend.get_status()
            self.assertTrue(status["enabled"])
            self.assertIn("mode", status)

            # Simulate an execution event on our existing temp binary
            event = AuditEvent(
                event_id="test:1",
                timestamp=time.time(),
                executable=temp_path,
                pid=999,
            )
            backend._handle_audit_event(event)

            self.assertEqual(len(dispatched), 1)
            self.assertEqual(dispatched[0], (temp_path, "kernel_exec"))
            self.assertEqual(backend.events_captured, 1)

            # Test virtual filesystem exclusion
            proc_event = AuditEvent(
                event_id="test:2",
                timestamp=time.time(),
                executable="/proc/1/exe",
                pid=1,
            )
            backend._handle_audit_event(proc_event)
            # Should not dispatch
            self.assertEqual(len(dispatched), 1)

            backend.stop()
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_audit_log_tailer_rotation_and_read(self):
        lines_received = []
        agg = AuditAggregator(on_event=lambda e: lines_received.append(e))

        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as f:
            log_path = f.name

        try:
            tailer = AuditLogTailer(log_path=log_path, aggregator=agg, poll_interval=0.05)
            tailer.start()
            time.sleep(0.1)

            # Write a valid audit record
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(
                    'type=SYSCALL msg=audit(1729900003.000:888): syscall=59 comm="test" exe="/bin/ls"\n'
                    'type=PROCTITLE msg=audit(1729900003.000:888): proctitle=6c73\n'
                )
                f.flush()

            time.sleep(0.2)
            tailer.stop()

            self.assertGreaterEqual(len(lines_received), 1)
            self.assertEqual(lines_received[0].executable, "/bin/ls")
        finally:
            if os.path.exists(log_path):
                os.remove(log_path)

    def test_monitoring_agent_kernel_audit_telemetry(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            watch_dir = os.path.join(tmp_dir, "watch")
            os.makedirs(watch_dir, exist_ok=True)
            db_path = os.path.join(tmp_dir, "test.db")
            storage = Storage(db_path=db_path)

            agent = MonitoringAgent(
                storage=storage,
                paths=[watch_dir],
                enable_kernel_audit=True,
                worker_threads=1,
            )
            agent.start()
            try:
                health = storage.get_health()
                self.assertEqual(health.get("status"), "running")
                details = health.get("details", {})
                self.assertIn("kernel_audit", details)
                self.assertTrue(details["kernel_audit"]["enabled"])
            finally:
                agent.stop()
                storage.close()


if __name__ == "__main__":
    unittest.main()
