"""Unit tests for Linux service daemon, systemd unit generation, and privilege separation."""

import tempfile
import unittest
from pathlib import Path

from malware_scanner.service import check_status, generate_systemd_unit, install_service
from malware_scanner.storage import Storage


class ServiceTests(unittest.TestCase):
    def test_generate_systemd_unit_security_controls(self):
        unit = generate_systemd_unit(user="malyz3r_sec", exec_start="/usr/bin/malyz3r-monitor run")
        self.assertIn("User=malyz3r_sec", unit)
        self.assertIn("ExecStart=/usr/bin/malyz3r-monitor run", unit)
        self.assertIn("Restart=on-failure", unit)
        # Verify strict privilege separation settings
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ProtectSystem=full", unit)
        self.assertIn("ProtectHome=read-only", unit)
        self.assertIn("PrivateTmp=true", unit)
        self.assertIn("ReadWritePaths=", unit)

    def test_install_service_custom_destination(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "custom.service"
            success = install_service(unit_dest=str(dest))
            self.assertTrue(success)
            self.assertTrue(dest.is_file())
            content = dest.read_text(encoding="utf-8")
            self.assertIn("[Unit]", content)
            self.assertIn("[Service]", content)
            self.assertIn("[Install]", content)

    def test_check_status_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "status.db")
            st = Storage(db_path)
            st.update_health(status="running", service_pid=9999, uptime=12.3)
            # Should print without error
            check_status(st)
            st.close()


if __name__ == "__main__":
    unittest.main()
