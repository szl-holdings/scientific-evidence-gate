"""Secret redaction applied before evidence is hashed (sections 0 and 15).

Every "secret" here is an obviously fake, synthetic value built at run time.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from science_gate._redact import REDACTED, redact, redact_text

FAKE_ENV_SECRET = "synthetic-env-value-not-a-real-secret"


class RedactTextTests(unittest.TestCase):
    def test_known_token_shapes_are_redacted(self) -> None:
        samples = [
            "ghp_" + "A" * 36,
            "github_pat_" + "B" * 30,
            "sk-" + "c" * 24,
            "AKIA" + "D" * 16,
            "xoxb-" + "1" * 12,
            "glpat-" + "e" * 20,
            "eyJ" + "f" * 10 + "." + "g" * 10 + "." + "h" * 10,
            "Bearer " + "i" * 20,
            "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
        ]
        for sample in samples:
            with self.subTest(sample=sample[:12]):
                redacted = redact_text(f"before {sample} after")
                self.assertNotIn(sample, redacted)
                self.assertIn(REDACTED, redacted)
                self.assertTrue(redacted.startswith("before "))

    def test_assignments_keep_their_label(self) -> None:
        self.assertEqual(redact_text("password = synthetic123"), f"password = {REDACTED}")
        self.assertEqual(redact_text("api_key:abcdef99"), f"api_key:{REDACTED}")

    def test_values_of_secret_named_environment_variables_are_redacted(self) -> None:
        with mock.patch.dict(os.environ, {"SYNTHETIC_SERVICE_TOKEN": FAKE_ENV_SECRET, "SYNTHETIC_AUTH": "short"}):
            self.assertEqual(redact_text(f"x {FAKE_ENV_SECRET} y"), f"x {REDACTED} y")
            # Too short to be redacted verbatim without destroying ordinary text.
            self.assertEqual(redact_text("a short word"), "a short word")

    def test_ordinary_text_is_untouched(self) -> None:
        text = "sample SYN-0001 measured 12.40 units; checksum " + "0" * 64
        self.assertEqual(redact_text(text), text)


class RedactValueTests(unittest.TestCase):
    def test_recurses_into_keys_values_and_collections(self) -> None:
        secret = "ghp_" + "Z" * 36
        value = {secret: [secret, ("ok", secret)], "set": {secret}, "n": 7, "none": None}
        redacted = redact(value)
        self.assertEqual(redacted[REDACTED], [REDACTED, ["ok", REDACTED]])
        self.assertEqual(redacted["set"], frozenset({REDACTED}))
        self.assertEqual((redacted["n"], redacted["none"]), (7, None))


if __name__ == "__main__":
    unittest.main()
