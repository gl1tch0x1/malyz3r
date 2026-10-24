import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from malware_scanner.benchmark import CANDIDATES, rule_source
from malware_scanner.dataset import import_archive
from malware_scanner.lab import compile_rules


class DatasetTests(unittest.TestCase):
    def test_candidate_grid_compiles_without_unused_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            for condition in CANDIDATES.values():
                Path(tmp, "webshell.yar").write_text(rule_source(condition))
                self.assertEqual(
                    compile_rules(tmp).identifiers, ["webshell.yar:PHP_Webshell_Candidate"]
                )

    def test_import_is_inert_deduplicated_and_traceable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.zip"
            data = b"<?php /* harmless test fixture, never executed */"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("repo/a.php", data)
                bundle.writestr("repo/duplicate.php", data)
                bundle.writestr("repo/ignored.exe", b"not a PHP sample")
            rows, duplicates = import_archive(
                archive,
                dict(repository="owner/repo", commit="a" * 40, label="target", label_basis="test"),
                root / "out",
                {},
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(duplicates, 1)
            self.assertEqual(rows[0]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(rows[0]["path"].endswith(".bin"))
            self.assertEqual((root / "out" / rows[0]["path"]).read_bytes(), data)
            self.assertIn("/blob/", rows[0]["provenance"])

    def test_conflicting_labels_and_archive_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.zip"
            data = b"test"
            source = dict(
                repository="owner/repo", commit="a" * 40, label="target", label_basis="test"
            )
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("repo/a.php", data)
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                import_archive(archive, source, root, {hashlib.sha256(data).hexdigest(): "benign"})
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("repo/../escape.php", data)
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                import_archive(archive, source, root, {})
