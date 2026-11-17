"""Run the actual science-gate CLI through the public synthetic product."""
from __future__ import annotations

import json
from pathlib import Path
import unittest
import zipfile

from science_gate.studio import (
    SCENARIOS, SOURCE_MATH, StudioHold, simulate_lutar, verify_scenario,
)


class StudioProductTests(unittest.TestCase):
    def test_complete_case_registry_has_falsifiable_states(self):
        expected = ["PASS", "FAIL", "FAIL", "ABSTAIN", "FAIL", "ABSTAIN"]
        self.assertEqual(len(SCENARIOS), len(expected))
        observed = [verify_scenario(k) for k in SCENARIOS]
        self.assertEqual([r["status"] for r in observed], expected)
        self.assertEqual(observed[0]["checks_executed"], 6)
        self.assertEqual(observed[0]["rows_examined"], 6)
        self.assertEqual(observed[0]["checks_failed"], 0)
        self.assertTrue(
            any(c["falsifier"] == "WITNESSED" for c in observed[0]["checks"]),
            "a PASS without a falsifier witness would be a product defect",
        )
        for row in observed:
            self.assertTrue(row["synthetic"])
            self.assertIs(row["biological_validation"], False)
            self.assertIs(row["independent_lab_reproduction"], False)
            self.assertIs(row["release_admission"], False)
            self.assertEqual(row["signing_claim"], "NONE")

    def test_tampered_digest_blocks_before_checks(self):
        tampered = verify_scenario("Tamper · original digest no longer matches")
        self.assertNotEqual(tampered["status"], "PASS")
        self.assertEqual(tampered["rows_examined"], 0)

    def test_mutated_rehashed_data_is_still_rejected_by_checks(self):
        negative = verify_scenario(
            "Duplicate · mutation re-pinned, checker must reject")
        self.assertEqual(negative["status"], "FAIL")
        self.assertEqual(negative["checks_executed"], 6)
        self.assertGreaterEqual(negative["checks_failed"], 1)

    def test_run_exports_original_machine_receipts_and_fixtures(self):
        result = verify_scenario(next(iter(SCENARIOS)), export=True)
        path = Path(result["archive"])
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.assertTrue(path.is_file())
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            self.assertIn("fixture/manifest.json", names)
            self.assertIn("fixture/data/measurements.csv", names)
            self.assertIn("run/run.json", names)
            self.assertIn("run/receipt.json", names)
            self.assertIn("run/receipt.auth.json", names)
            self.assertIn("run/ledger.jsonl", names)
            self.assertIn("run/evidence-manifest.json", names)
            self.assertIn("STUDIO_SOURCE.json", names)
            source = json.loads(z.read("STUDIO_SOURCE.json"))
            actual = json.loads(z.read("run/run.json"))
            self.assertEqual(source["scenario"], result["scenario"])
            self.assertEqual(actual["run_id"], result["run_id"])
            self.assertEqual(actual["status"], result["status"])
            self.assertEqual(source["signing_claim"], "NONE")

    def test_unlisted_names_and_paths_never_run(self):
        for invalid in ("", "main", "../../private.json", "https://evil.site",
                        123, None):
            with self.subTest(invalid=invalid), self.assertRaises(StudioHold):
                verify_scenario(invalid)

    def test_replay_is_not_reported_as_cryptographic_independence(self):
        row = verify_scenario(next(iter(SCENARIOS)))
        self.assertIn("Synthetic", row["boundary"])
        self.assertIn("not", row["boundary"].lower())
        self.assertTrue(row["ledger_head_sha256"])
        self.assertEqual(row["studio_source_sha"], "UNBOUND_LOCAL")

    def test_mathematical_fixture_has_known_equal_weight_properties(self):
        result = simulate_lutar(0.64, 0.81, False, False, False, False, False, False)
        self.assertAlmostEqual(result["lambda_2"], 0.72)
        self.assertLessEqual(result["lambda_2"], result["maximum"])
        self.assertEqual(result["permutation_delta"], 0)
        self.assertEqual(result["effective_score"], 0)
        self.assertEqual(result["admission_simulation"], "SIMULATED_HOLD")
        self.assertEqual(result["authority"], "WHAT_IF_ONLY_NO_PRODUCTION_PERMISSION")
        self.assertEqual(result["axioms_source"], SOURCE_MATH)

    def test_user_flags_can_never_authenticate_themselves(self):
        verdict = simulate_lutar(0.8, 0.8, True, True, True, True, True, True)
        self.assertAlmostEqual(verdict["effective_score"], 0.8)
        self.assertEqual(verdict["admission_simulation"], "ALL_INPUT_FLAGS_TRUE")
        self.assertEqual(verdict["authority"], "WHAT_IF_ONLY_NO_PRODUCTION_PERMISSION")
        self.assertIs(verdict["lean_refinement_proved"], False)

    def test_missing_signature_forces_zero_without_erasing_lambda(self):
        result = simulate_lutar(1, 0.25, True, True, False, True, True, True)
        self.assertAlmostEqual(result["lambda_2"], .5)
        self.assertEqual(result["effective_score"], 0)
        self.assertIn("SIGNATURE", result["missing"])

    def test_invalid_math_fails_closed(self):
        for invalid in (float("nan"), float("inf"), -0.1, 1.1, "0.8", True):
            with self.subTest(invalid=invalid), self.assertRaises(StudioHold):
                simulate_lutar(invalid, .8, False, False, False, False, False, False)
        with self.assertRaises(StudioHold):
            simulate_lutar(.8, .8, 1, False, False, False, False, False)


if __name__ == "__main__":
    unittest.main()
