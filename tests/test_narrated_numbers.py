"""Narrated-number forensics and rounding conventions (ARCHITECTURE.md 17.11; extension #7, decision D5).

(a)-(d) of the research brief run through ``verify`` on private copies of
``fixtures/numeric/narrated``, ``tie-rule`` and ``third-party``; the pure
recomputation is also tested directly for every formula. Every number,
claim and file here is synthetic.
"""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from typing import Any

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate._canonical import sha256_bytes
from science_gate.claims import (
    DERIVED_FROM_STORED,
    INDISTINGUISHABLE,
    NARRATED,
    NOT_EVALUATED,
    NOT_REPRODUCED,
    OPERANDS_UNAVAILABLE,
    ClaimResolution,
    RegisteredClaim,
    RegistryFormatError,
    narrate,
    parse_registry,
)
from science_gate.invariants import AGREES_AT_STATED_PRECISION, DISAGREES, compare_decimal, parse_decimal
from science_gate.models import CheckResult, FailureMode, Reason, Status
from science_gate.verifier import VerificationRun, verify

NUMERIC_FIXTURES = REPO_ROOT / "fixtures" / "numeric"


class FixtureProject(TempDirTestCase):
    """A private copy of one ``fixtures/numeric`` tree, with helpers that re-pin what they edit."""

    FIXTURE = "narrated"

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.project = self.tmp / self.FIXTURE
        shutil.copytree(NUMERIC_FIXTURES / self.FIXTURE, self.project)

    def path(self, relpath: str) -> Path:
        return self.project / relpath

    def registry(self) -> dict[str, Any]:
        return json.loads(self.path("claims/registry.json").read_text(encoding="utf-8"))

    def save_registry(self, document: dict[str, Any]) -> None:
        self.path("claims/registry.json").write_text(json.dumps(document, indent=2), encoding="utf-8")

    def edit_claim(self, claim_id: str, **fields: Any) -> None:
        """Replace fields of one claim; ``...`` deletes the field."""
        document = self.registry()
        (claim,) = [item for item in document["claims"] if item["claim_id"] == claim_id]
        for name, value in fields.items():
            if value is ...:
                claim.pop(name, None)
            else:
                claim[name] = value
        self.save_registry(document)

    def write_output(self, relpath: str, text: str) -> None:
        """Replace a stored output and re-pin every claim citing it, isolating the edit under test."""
        self.path(relpath).write_bytes(text.encode("utf-8"))
        document = self.registry()
        for claim in document["claims"]:
            if claim["stored_output"]["path"] == relpath:
                claim["stored_output"]["sha256"] = sha256_bytes(self.path(relpath).read_bytes())
        self.save_registry(document)

    def replace_in_manuscript(self, old: str, new: str) -> None:
        path = self.path("claims/manuscript.md")
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_bytes(text.replace(old, new).encode("utf-8"))

    def run_claims(self) -> tuple[VerificationRun, CheckResult]:
        run = verify(self.path("manifest.json"))
        (result,) = [item for item in run.result.checks if item.check_id == "claims"]
        return run, result

    def assertOutcome(self, result: CheckResult, verdict: Status, reason: Reason, *modes: FailureMode) -> None:
        self.assertEqual((result.verdict, result.reason), (verdict, reason), result.diagnostics)
        self.assertEqual(set(result.failure_modes), set(modes), result.diagnostics)


# ---------------------------------------------------------------------------
# RIVETS exactness (#7 a, b, d)
# ---------------------------------------------------------------------------


class NarratedDifferenceTest(FixtureProject):
    def narration(self, result: CheckResult) -> dict[str, Any]:
        (record,) = result.evidence["narration"]["claims"]
        return record

    def test_a_a_difference_computed_from_the_printed_operands_fails(self) -> None:
        run, result = self.run_claims()
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.NARRATED_VERIFICATION)
        record = self.narration(result)
        self.assertEqual(
            {key: record[key] for key in ("printed_operands", "stored_operands", "from_printed", "from_stored")},
            {
                "printed_operands": ["12.35", "10.25"],
                "stored_operands": ["12.346", "10.254"],
                "from_printed": ["2.10"],
                "from_stored": ["2.09"],
            },
        )
        self.assertEqual((record["outcome"], record["must_derive_from"]), (NARRATED, "stored_output"))
        self.assertTrue(any(text.startswith("NARRATED: claim 'N-DIFF'") for text in result.diagnostics))

    def test_a_without_must_derive_from_a_narrated_number_needs_human_review(self) -> None:
        self.edit_claim("N-DIFF", must_derive_from=...)
        run, result = self.run_claims()
        self.assertEqual((run.status, run.exit_code), (Status.ABSTAIN, 2))
        self.assertOutcome(result, Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW, FailureMode.NARRATED_VERIFICATION)
        self.assertEqual(self.narration(result)["outcome"], NARRATED)

    def test_b_the_difference_of_the_stored_values_passes(self) -> None:
        self.edit_claim("N-DIFF", value="2.09")
        self.write_output("outputs/summary-table.csv", "quantity,value\ndifference,2.09\n")
        self.replace_in_manuscript("was 2.10", "was 2.09")
        run, result = self.run_claims()
        self.assertOutcome(result, Status.PASS, Reason.VERIFIED)
        self.assertEqual(run.status, Status.PASS)
        record = self.narration(result)
        self.assertEqual((record["outcome"], record["indistinguishable"]), (DERIVED_FROM_STORED, False))

    def test_d_identical_recomputations_are_counted_and_never_flagged(self) -> None:
        # Stored 12.348 - 10.251 = 2.097, which also prints 2.10: the two readings cannot be told apart.
        self.write_output("outputs/measures.json", json.dumps({"alpha": "12.348", "beta": "10.251"}))
        _, result = self.run_claims()
        self.assertOutcome(result, Status.PASS, Reason.VERIFIED)
        narration = result.evidence["narration"]
        self.assertEqual((narration["evaluated"], narration["indistinguishable"]), (1, 1))
        self.assertEqual(narration["indistinguishable_rate"]["decimal"], "1")
        self.assertEqual(narration["outcomes"], {INDISTINGUISHABLE: 1})
        self.assertNotIn(FailureMode.NARRATED_VERIFICATION, result.failure_modes)

    def test_a_derivation_reproduced_by_neither_reading_fails(self) -> None:
        self.edit_claim("N-DIFF", value="2.30")
        self.write_output("outputs/summary-table.csv", "quantity,value\ndifference,2.30\n")
        self.replace_in_manuscript("was 2.10", "was 2.30")
        _, result = self.run_claims()
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        self.assertEqual(self.narration(result)["outcome"], NOT_REPRODUCED)

    def test_an_operand_without_a_located_stored_value_cannot_be_judged(self) -> None:
        document = self.registry()
        document["claims"][0]["stored_output"]["selector"] = "/gamma"
        self.save_registry(document)
        _, result = self.run_claims()
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        record = self.narration(result)
        self.assertEqual(record["outcome"], OPERANDS_UNAVAILABLE)
        self.assertIsNone(result.evidence["narration"]["indistinguishable_rate"]["decimal"])


def resolution(claim_id: str, printed: str, stored: str | None, **fields: Any) -> ClaimResolution:
    """A resolved operand or derived claim, without touching any file."""
    claim = RegisteredClaim(claim_id, value=printed, **fields)
    return ClaimResolution(claim, (), (), {}, None if stored is None else parse_decimal(stored))


class RecomputationTest(TempDirTestCase):
    """:func:`narrate` over every formula, exactly, with D5's convention sets."""

    def judge(
        self, formula: str, claim: str, operands: tuple[tuple[str, str | None], ...], **fields: Any
    ) -> dict[str, Any]:
        resolutions = {
            f"OP-{index}": resolution(f"OP-{index}", printed, stored)
            for index, (printed, stored) in enumerate(operands)
        }
        derived = RegisteredClaim("DERIVED", value=claim, formula=formula, operands=tuple(resolutions), **fields)
        return narrate(derived, resolutions)

    def test_formulas(self) -> None:
        cases = (
            # ratio: printed 1.25 / 0.35 = 3.5714..., stored 1.245 / 0.354 = 3.5169...
            ("ratio", "3.57", (("1.25", "1.245"), ("0.35", "0.354")), {}, NARRATED, ["3.57"], ["3.52"]),
            ("ratio", "3.52", (("1.25", "1.245"), ("0.35", "0.354")), {}, DERIVED_FROM_STORED, ["3.57"], ["3.52"]),
            # percent: printed 100 * 0.37 / 0.80 = 46.25 exactly, a tie at one decimal.
            ("percent", "46.3", (("0.37", "0.3749"), ("0.80", "0.7999")), {"rounding": "EITHER_HALF"}, NARRATED,
             ["46.2", "46.3"], ["46.9"]),
            ("percent", "46.3", (("0.37", "0.3749"), ("0.80", "0.7999")), {}, NOT_REPRODUCED, ["46.2"], ["46.9"]),
            # f1: printed 2 * 0.80 * 0.60 / 1.40 = 0.6857..., stored 0.804 and 0.596 give 0.6845...
            ("f1", "0.69", (("0.80", "0.804"), ("0.60", "0.596")), {}, NARRATED, ["0.69"], ["0.68"]),
            (
                "difference", "2.10", (("12.35", "12.348"), ("10.25", "10.251")), {}, INDISTINGUISHABLE,
                ["2.10"], ["2.10"],
            ),
        )
        for formula, claim, operands, fields, outcome, printed, stored in cases:
            with self.subTest(formula=formula, claim=claim, fields=fields):
                record = self.judge(formula, claim, operands, **fields)
                self.assertEqual(
                    (record["outcome"], record["from_printed"], record["from_stored"]), (outcome, printed, stored)
                )

    def test_undefined_or_unreadable_inputs_are_not_evaluated(self) -> None:
        self.assertEqual(self.judge("ratio", "1.0", (("1.0", "1.0"), ("0.0", "0.0")))["outcome"], NOT_EVALUATED)
        self.assertEqual(self.judge("ratio", "1.0", (("1.0", "1.0"), ("about two", "2.0")))["outcome"], NOT_EVALUATED)
        unavailable = self.judge("difference", "1.0", (("3.0", None), ("2.0", "2.0")))
        self.assertEqual(unavailable["outcome"], OPERANDS_UNAVAILABLE)


class DerivationRegistryTest(TempDirTestCase):
    def refused(self, claims: list[dict[str, Any]], fragment: str) -> None:
        with self.assertRaises(RegistryFormatError) as caught:
            parse_registry({"schema": "science-gate-claims/v1", "claims": claims})
        self.assertIn(fragment, str(caught.exception))

    def test_derivations_must_name_two_registered_operands(self) -> None:
        base = [{"claim_id": "A"}, {"claim_id": "B"}]
        cases = {
            "formula and operands together": {"formula": "difference"},
            "must list exactly two claim ids": {"formula": "difference", "operands": ["A", "B", "A"]},
            "names unregistered claim(s) ['Z']": {"formula": "ratio", "operands": ["A", "Z"]},
            "names the claim itself": {"formula": "ratio", "operands": ["A", "D"]},
            "formula must be one of": {"formula": "mean", "operands": ["A", "B"]},
        }
        for fragment, derivation in cases.items():
            with self.subTest(fragment=fragment):
                self.refused([*base, {"claim_id": "D", "derivation": derivation}], fragment)
        parsed = parse_registry(
            {
                "schema": "science-gate-claims/v1",
                "claims": [*base, {"claim_id": "D", "derivation": {"formula": "f1", "operands": ["A", "B"]}}],
            }
        )
        self.assertEqual((parsed.claims[2].formula, parsed.claims[2].operands), ("f1", ("A", "B")))

    def test_rounding_and_must_derive_from_are_closed_vocabularies(self) -> None:
        self.refused([{"claim_id": "A", "rounding": "HALF_UP"}], "rounding must be one of ['EITHER_HALF', 'HALF_EVEN']")
        self.refused([{"claim_id": "A", "must_derive_from": "manuscript"}], "must_derive_from must be one of")
        (claim,) = parse_registry({"schema": "science-gate-claims/v1", "claims": [{"claim_id": "A"}]}).claims
        self.assertEqual((claim.rounding, claim.must_derive_from), ("HALF_EVEN", None))


# ---------------------------------------------------------------------------
# Tie-rule fingerprints (#7 c) and EITHER_HALF (D5)
# ---------------------------------------------------------------------------


class TieRuleFingerprintTest(FixtureProject):
    FIXTURE = "tie-rule"

    def test_c_a_value_only_half_up_produces_drifted_from_the_half_even_toolchain(self) -> None:
        run, result = self.run_claims()
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
        self.assertOutcome(
            result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH, FailureMode.PROTOCOL_DRIFT
        )
        self.assertEqual(
            result.evidence["tie_rule_drift"],
            [
                {
                    "claim_id": "N-RATE",
                    "printed": "0.13",
                    "stored": "0.125",
                    "declared": ["HALF_EVEN"],
                    "fingerprint": ["CEILING", "HALF_UP"],
                }
            ],
        )
        (record,) = result.evidence["problem_claims"]
        comparison = record["value_comparison"]
        self.assertEqual((comparison["outcome"], comparison["fingerprint"]), (DISAGREES, ["CEILING", "HALF_UP"]))
        self.assertNotIn("HALF_EVEN", comparison["fingerprint"])
        self.assertEqual(comparison["reproduced_by"], [])
        self.assertTrue(any(text.startswith("TIE_RULE_DRIFT: claim 'N-RATE'") for text in result.diagnostics))

    def test_a_disagreement_no_rounding_rule_explains_is_not_drift(self) -> None:
        self.write_output("outputs/rates.json", json.dumps({"rate": "0.141"}))
        _, result = self.run_claims()
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        self.assertEqual(result.evidence["tie_rule_drift"], [])

    def test_an_exact_match_is_reproduced_by_every_rule(self) -> None:
        self.write_output("outputs/rates.json", json.dumps({"rate": "0.130"}))
        _, result = self.run_claims()
        self.assertOutcome(result, Status.PASS, Reason.VERIFIED)
        (record,) = result.evidence["resolved_claims"]
        self.assertEqual(len(record["value_comparison"]["fingerprint"]), 6)


class EitherHalfTest(FixtureProject):
    FIXTURE = "third-party"

    def test_a_third_party_number_agrees_by_half_up_and_records_the_convention(self) -> None:
        run, result = self.run_claims()
        self.assertEqual(run.status, Status.PASS)
        self.assertOutcome(result, Status.PASS, Reason.VERIFIED)
        (record,) = result.evidence["resolved_claims"]
        comparison = record["value_comparison"]
        self.assertEqual(record["rounding"], "EITHER_HALF")
        self.assertEqual(
            {key: comparison[key] for key in ("outcome", "rounding", "conventions", "reproduced_by", "rounded_stored")},
            {
                "outcome": AGREES_AT_STATED_PRECISION,
                "rounding": "ROUND_HALF_UP",
                "conventions": ["HALF_EVEN", "HALF_UP"],
                "reproduced_by": ["HALF_UP"],
                "rounded_stored": "0.13",
            },
        )

    def test_either_half_never_admits_truncation(self) -> None:
        self.write_output("outputs/rates.json", json.dumps({"rate": "0.129"}))
        self.edit_claim("N-RATE", value="0.12")
        self.replace_in_manuscript("was 0.13", "was 0.12")
        _, result = self.run_claims()
        self.assertOutcome(
            result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH, FailureMode.PROTOCOL_DRIFT
        )
        (drift,) = result.evidence["tie_rule_drift"]
        self.assertEqual((drift["declared"], drift["fingerprint"]), (["HALF_EVEN", "HALF_UP"], ["FLOOR", "TRUNCATE"]))

    def test_the_projects_own_outputs_stay_half_even(self) -> None:
        # Without EITHER_HALF the same digits disagree, as numeric_agreement's comparator always says.
        self.edit_claim("N-RATE", rounding=...)
        _, result = self.run_claims()
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(compare_decimal("0.13", "0.125").outcome, DISAGREES)


if __name__ == "__main__":
    unittest.main()
