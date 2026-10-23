import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from malware_scanner.artifacts import write_json


@unittest.skipUnless(os.name == "nt", "Windows sharing violation behavior")
class ArtifactRetryTests(unittest.TestCase):
    def test_transient_sharing_violation_retries_without_losing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "progress.json"
            output.write_text('{"completed": 1}')
            original = os.replace
            calls = 0

            def transient(source, destination):
                nonlocal calls
                calls += 1
                if calls < 3:
                    raise PermissionError("temporarily held open")
                original(source, destination)

            with (
                patch("malware_scanner.artifacts.os.replace", side_effect=transient),
                patch("malware_scanner.artifacts.time.sleep"),
            ):
                write_json(output, {"completed": 2})
            self.assertEqual(calls, 3)
            self.assertEqual(json.loads(output.read_text()), {"completed": 2})
            self.assertEqual(list(Path(tmp).iterdir()), [output])

    def test_permanent_failure_preserves_previous_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "progress.json"
            output.write_text('{"completed": 1}')
            with (
                patch("malware_scanner.artifacts.os.replace", side_effect=PermissionError),
                patch("malware_scanner.artifacts.time.sleep"),
                self.assertRaises(PermissionError),
            ):
                write_json(output, {"completed": 2})
            self.assertEqual(json.loads(output.read_text()), {"completed": 1})
