"""Offline deployment contract; no Hub mutation or real network calls."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("szl_studio_publish", ROOT / "studio" / "deploy_hf.py")
assert spec is not None and spec.loader is not None
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

TEST_SHA = "a" * 40


class PublisherContractTests(unittest.TestCase):
    def test_exact_source_binding_in_all_assets(self):
        files = publisher.payload(TEST_SHA)
        self.assertEqual(set(files), {"README.md", "requirements.txt", "app.py", "SOURCE.json"})
        self.assertTrue(all(isinstance(v, bytes) for v in files.values()))
        source = json.loads(files["SOURCE.json"])
        self.assertEqual(source["source_commit"], TEST_SHA)
        self.assertEqual(source["training_authority"], "NONE")
        self.assertFalse(source["biological_validation"])
        self.assertEqual(source["source_binding"], "PINNED_INSTALL_NOT_A_SIGNED_ATTESTATION")
        self.assertIn(TEST_SHA, files["app.py"].decode())
        self.assertIn(TEST_SHA, files["requirements.txt"].decode())
        self.assertIn(TEST_SHA, files["README.md"].decode())
        self.assertIn("sdk: gradio", files["README.md"].decode())
        self.assertNotIn("token", files["app.py"].decode().lower())

    def test_reject_nonimmutable_source(self):
        for bad in ("main", "latest", "", "AA" * 20, "../".join(["root"]*10), "g"*40, None):
            with self.subTest(value=bad), self.assertRaises(publisher.PublishHold):
                publisher.payload(bad)

    def test_preview_is_dry_run_with_no_hub_sdk(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "studio" / "deploy_hf.py"),
             "--source-sha", TEST_SHA],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result_json = json.loads(result.stdout)
        self.assertEqual(result_json["status"], "DRY_RUN_NO_PROVIDER_MUTATION")
        self.assertEqual(result_json["source"], TEST_SHA)
        self.assertEqual(len(result_json["files"]), 4)

    def test_refuses_create_without_publish(self):
        self.assertNotIn("api.create_repo", publisher.main.__code__.co_names)
        self.assertEqual(publisher.SPACE, "SZLHOLDINGS/szl-science-gate-studio")


if __name__ == "__main__":
    unittest.main()
