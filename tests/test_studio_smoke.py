"""Live product smoke contract's URL authority is fail-closed."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "szl_studio_smoke", ROOT / "studio" / "smoke.py")
assert spec is not None and spec.loader is not None
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class LiveSmokePolicyTests(unittest.TestCase):
    def test_local_loopback_and_exact_hf_target(self):
        self.assertEqual(smoke.endpoint("http://127.0.0.1:7860"),
                         "http://127.0.0.1:7860")
        self.assertEqual(
            smoke.endpoint("https://szlholdings-szl-science-gate-studio.hf.space/"),
            "https://szlholdings-szl-science-gate-studio.hf.space")

    def test_refuse_arbitrary_remote_hosts_paths_and_credentials(self):
        for value in (
            "http://evil.example", "https://evil.example",
            "https://szlholdings-szl-science-gate-studio.hf.space.evil.example",
            "http://szlholdings-szl-science-gate-studio.hf.space",
            "http://127.0.0.1:7860/admin",
            "http://127.0.0.1:7860?token=abc",
            "http://admin:pw@127.0.0.1:7860",
            "file:///etc/passwd", "javascript:alert(1)",
            "ftp://127.0.0.1:7860",
        ):
            with self.subTest(url=value), self.assertRaises(ValueError):
                smoke.endpoint(value)


if __name__ == "__main__":
    unittest.main()
