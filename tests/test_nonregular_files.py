"""Refused special files must never block manifest loading or evidence pinning."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from _helpers import MEASUREMENTS_CSV, SRC_DIR, TempDirTestCase, manifest_document


VERIFY_SUMMARY = """
import json
import sys
from science_gate.verifier import verify
run = verify(sys.argv[1])
print(json.dumps({
    "exit_code": run.exit_code,
    "inputs": [record.to_dict() for record in run.result.accounting.records],
    "documents": list(run.documents),
    "pins": run.pins,
    "issues": [issue.code for issue in run.manifest_issues],
    "manifest_sha256": run.manifest_sha256,
}))
"""


@unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are unavailable on this operating system")
class NonRegularFileTests(TempDirTestCase):
    def make_fifo(self, relative: str) -> Path:
        path = self.tmp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkfifo(path)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"named pipes cannot be created ({type(exc).__name__})")
        return path

    def run_child(self, source: str, path: Path) -> dict:
        # A writerless FIFO hangs in open(), so keep a broken implementation
        # bounded and observable instead of hanging the entire test suite.
        result = subprocess.run(
            [sys.executable, "-B", "-c", source, str(path)],
            env={**os.environ, "PYTHONPATH": str(SRC_DIR)},
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_fifo_input_is_refused_without_being_opened_for_a_pin(self) -> None:
        self.make_fifo("data/measurements.csv")
        path = self.write_manifest(manifest_document())
        result = self.run_child(VERIFY_SUMMARY, path)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["inputs"][0]["state"], "REFUSED")
        self.assertIsNone(result["inputs"][0]["sha256"])
        pins = [pin for pin in result["pins"]["pinned"] if pin["role"] == "input"]
        self.assertEqual(len(pins), 1)
        self.assertIsNone(pins[0]["sha256"])
        self.assertIsNone(pins[0]["sha256_after"])

    def test_fifo_document_is_refused_without_being_opened_for_a_pin(self) -> None:
        self.write("data/measurements.csv", MEASUREMENTS_CSV)
        self.make_fifo("snapshot.json")
        document = manifest_document(accepted_snapshot="snapshot.json")
        document["checks"].append({
            "id": "snapshot", "kind": "snapshot_completeness", "version": "1", "inputs": ["measurements"]
        })
        path = self.write_manifest(document)
        result = self.run_child(VERIFY_SUMMARY, path)
        self.assertEqual(result["exit_code"], 2)
        document = next(item for item in result["documents"] if item["path"] == "snapshot.json")
        self.assertEqual(document["state"], "REFUSED")
        pins = [pin for pin in result["pins"]["pinned"] if pin["path"] == "snapshot.json"]
        self.assertEqual(len(pins), 1)
        self.assertIsNone(pins[0]["sha256"])
        self.assertIsNone(pins[0]["sha256_after"])

    def test_manifest_loader_refuses_a_fifo(self) -> None:
        path = self.make_fifo("manifest.json")
        source = """
import json
import sys
from science_gate.manifests import ManifestError, load_manifest
try:
    load_manifest(sys.argv[1])
except ManifestError as error:
    print(json.dumps({"issues": [issue.code for issue in error.issues]}))
"""
        result = self.run_child(source, path)
        self.assertEqual(result["issues"], ["MANIFEST_UNREADABLE"])

    def test_invalid_manifest_report_does_not_reopen_a_fifo_for_its_digest(self) -> None:
        path = self.make_fifo("manifest.json")
        result = self.run_child(VERIFY_SUMMARY, path)
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["issues"], ["MANIFEST_UNREADABLE"])
        self.assertIsNone(result["manifest_sha256"])
        self.assertIsNone(result["pins"])


if __name__ == "__main__":
    unittest.main()
