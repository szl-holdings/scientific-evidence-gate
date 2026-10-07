"""Numeric coverage funnel (ARCHITECTURE.md 17.11, extension #17).

found -> parsed -> typed -> checkable -> checked, with named buckets for every
number that stops early and a floor below which the claims check cannot
PASS. The acceptance case is ``fixtures/numeric/coverage``: a decimal-comma
locale, a corrected p-value and a garbled comparison sign each land in their
own bucket. Every number and file here is synthetic.
"""

from __future__ import annotations

import json
import shutil
import unittest
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate._canonical import sha256_bytes
from science_gate.claims import (
    AMBIGUOUS_SEPARATOR,
    CORRECTED_VALUE,
    COVERAGE_BUCKETS,
    DECIMAL_COMMA_LOCALE,
    DECLARED_NOT_A_CLAIM,
    DECLARED_NOT_CLAIM,
    GARBLED_COMPARATOR,
    MATCHED,
    NOT_A_NUMBER,
    NOT_COMPARED,
    UNDECLARED_SEPARATOR,
    UNREGISTERED,
    ClassifiedToken,
    ManuscriptToken,
    coverage_bucket,
    numeric_coverage,
    scan_manuscript,
)
from science_gate.invariants import parse_decimal
from science_gate.models import CheckResult, FailureMode, RatioState, Reason, Status
from science_gate.numeric import candidate_readings
from science_gate.verifier import VerificationRun, verify

NUMERIC_FIXTURES = REPO_ROOT / "fixtures" / "numeric"
CLAIMS_VALID = REPO_ROOT / "fixtures" / "claims" / "valid"


def classified(
    text: str, classification: str = UNREGISTERED, claim_ids: tuple[str, ...] = (), **token: Any
) -> ClassifiedToken:
    return ClassifiedToken(ManuscriptToken(1, 1, text, parse_decimal(text), **token), classification, claim_ids)


class CoverageFixtureTest(unittest.TestCase):
    """The acceptance case: three silent-loss paths, each named."""

    @classmethod
    def setUpClass(cls) -> None:
        run = verify(NUMERIC_FIXTURES / "coverage" / "manifest.json")
        (cls.result,) = [item for item in run.result.checks if item.check_id == "claims"]
        cls.verification = run
        cls.coverage = cls.result.evidence["numeric_coverage"]

    def test_each_loss_path_lands_in_its_named_bucket(self) -> None:
        buckets = self.coverage["buckets"]
        self.assertEqual(buckets[DECIMAL_COMMA_LOCALE], [{"line": 5, "text": "0,42"}])
        self.assertEqual(buckets[CORRECTED_VALUE], [{"line": 6, "text": "0.012"}])
        self.assertEqual(buckets[GARBLED_COMPARATOR], [{"line": 7, "text": "0.05"}])
        self.assertEqual(list(buckets), list(COVERAGE_BUCKETS))
        empty = set(COVERAGE_BUCKETS) - {DECIMAL_COMMA_LOCALE, CORRECTED_VALUE, GARBLED_COMPARATOR}
        self.assertEqual({name for name in empty if buckets[name]}, set())

    def test_the_funnel_counts(self) -> None:
        counts = {key: self.coverage[key] for key in ("found", "declared", "parsed", "typed", "checkable", "checked")}
        self.assertEqual(counts, {"found": 4, "declared": 0, "parsed": 4, "typed": 2, "checkable": 1, "checked": 1})
        self.assertEqual(self.coverage["ratio"]["fraction"], "1/4")
        self.assertEqual((self.coverage["floor"], self.coverage["floor_met"]), ("1", False))

    def test_every_number_is_checked_or_in_exactly_one_bucket(self) -> None:
        bucketed = sum(self.coverage["bucket_counts"].values())
        self.assertEqual(self.coverage["found"], self.coverage["checked"] + bucketed)

    def test_below_the_floor_the_check_cannot_pass(self) -> None:
        self.assertEqual((self.verification.status, self.verification.exit_code), (Status.ABSTAIN, 2))
        self.assertNotEqual(self.result.verdict, Status.PASS)
        self.assertIn(FailureMode.OMITTED_POPULATION, self.result.failure_modes)
        (diagnostic,) = [text for text in self.result.diagnostics if text.startswith("NUMERIC_COVERAGE")]
        self.assertIn("1 of 4 undeclared manuscript number(s) checked (0.25), below the floor 1", diagnostic)
        self.assertIn("GARBLED_COMPARATOR 1", diagnostic)

    def test_the_garbled_number_was_matched_by_value_yet_not_counted_as_checked(self) -> None:
        # 0.1.0 would match "0.05" to its claim and stop there: whether the text says = or < is unknown.
        matched = self.result.evidence["manuscript_scan"]["matched_tokens"]
        (garbled,) = [item for item in matched if item["text"] == "0.05"]
        self.assertEqual((garbled["comparator_glyph"], garbled["claim_ids"]), ("¡", ["N-P"]))


class CoverageFloorTest(TempDirTestCase):
    """The floor decides PASS on a manuscript whose only loss is a garbled comparison sign."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.project = self.tmp / "coverage"
        shutil.copytree(NUMERIC_FIXTURES / "coverage", self.project)
        manuscript = self.project / "claims" / "manuscript.md"
        lines = manuscript.read_text(encoding="utf-8").splitlines(keepends=True)
        # Keep the header, the matched mean (line 4) and the garbled line; drop the comma and corrected lines.
        manuscript.write_bytes("".join(lines[:4] + lines[6:]).encode("utf-8"))

    def set_floor(self, floor: Any) -> None:
        path = self.project / "manifest.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        (check,) = [item for item in document["checks"] if item["id"] == "claims"]
        check["params"] = {"coverage_floor": floor}
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def run_claims(self) -> tuple[VerificationRun, CheckResult]:
        run = verify(self.project / "manifest.json")
        (result,) = [item for item in run.result.checks if item.check_id == "claims"]
        return run, result

    def test_a_garbled_comparison_alone_blocks_the_pass_under_the_default_floor(self) -> None:
        _, result = self.run_claims()
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(set(result.failure_modes), {FailureMode.OMITTED_POPULATION})
        coverage = result.evidence["numeric_coverage"]
        self.assertEqual((coverage["ratio"]["fraction"], coverage["floor_met"]), ("1/2", False))

    def test_a_lower_declared_floor_admits_it_and_the_comparison_is_exact(self) -> None:
        self.set_floor("0.5")
        run, result = self.run_claims()
        self.assertEqual((result.verdict, run.status), (Status.PASS, Status.PASS))
        self.assertIs(result.evidence["numeric_coverage"]["floor_met"], True)
        self.set_floor("0.5000001")
        _, result = self.run_claims()
        self.assertEqual(result.verdict, Status.ABSTAIN)

    def test_an_unusable_floor_is_an_error_never_a_weaker_check(self) -> None:
        for floor in ("1.5", "-0.1", "half", 1):
            with self.subTest(floor=floor):
                self.set_floor(floor)
                run, result = self.run_claims()
                self.assertEqual((result.verdict, run.status), (Status.ERROR, Status.ERROR))
                self.assertIn("coverage_floor", result.diagnostics[0])


class CoveragePopulationTest(TempDirTestCase):
    def copy_valid(self) -> Path:
        project = self.tmp / "valid"
        shutil.copytree(CLAIMS_VALID, project)
        return project

    def claims_result(self, project: Path) -> CheckResult:
        run = verify(project / "manifest.json")
        (result,) = [item for item in run.result.checks if item.check_id == "claims"]
        return result

    def test_declared_not_claims_leave_the_denominator(self) -> None:
        result = self.claims_result(self.copy_valid())
        coverage = result.evidence["numeric_coverage"]
        self.assertEqual((coverage["found"], coverage["declared"], coverage["checked"]), (5, 1, 4))
        self.assertEqual(coverage["buckets"][DECLARED_NOT_CLAIM], [{"line": 1, "text": "3"}])
        self.assertEqual((coverage["ratio"]["fraction"], coverage["floor_met"]), ("4/4", True))
        self.assertEqual(result.verdict, Status.PASS)

    def test_a_manuscript_of_declared_numbers_only_has_no_ratio_and_no_finding(self) -> None:
        project = self.copy_valid()
        manuscript = project / "claims" / "manuscript.md"
        manuscript.write_bytes(b"# Synthetic site summary (draft 3)\n\nNo results are printed here.\n")
        registry_path = project / "claims" / "registry.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        registry["not_claims"]["manuscript_sha256"] = sha256_bytes(manuscript.read_bytes())
        registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        result = self.claims_result(project)
        coverage = result.evidence["numeric_coverage"]
        self.assertEqual(coverage["ratio"]["state"], RatioState.ZERO_DENOMINATOR.value)
        self.assertIsNone(coverage["ratio"]["decimal"])
        self.assertIsNone(coverage["floor_met"])
        self.assertFalse(any(text.startswith("NUMERIC_COVERAGE") for text in result.diagnostics))

    def test_without_a_manuscript_nothing_is_counted_as_covered(self) -> None:
        project = self.copy_valid()
        manifest_path = project / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        del manifest["manuscript"]
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        coverage = self.claims_result(project).evidence["numeric_coverage"]
        self.assertEqual(coverage["state"], "NOT_SCANNED")
        self.assertIsNone(coverage["found"])
        self.assertEqual(coverage["ratio"]["state"], RatioState.UNAVAILABLE.value)
        self.assertIsNone(coverage["floor_met"])


class BucketTest(unittest.TestCase):
    """:func:`coverage_bucket`: one bucket per way a number can stop, in funnel order."""

    def test_every_bucket(self) -> None:
        cases = (
            (classified("2026", DECLARED_NOT_A_CLAIM), DECLARED_NOT_CLAIM),
            (classified("1.2e3"), NOT_A_NUMBER),
            (classified("1,234"), AMBIGUOUS_SEPARATOR),
            (classified("12,5"), DECIMAL_COMMA_LOCALE),
            (classified("1'234"), UNDECLARED_SEPARATOR),
            (classified("0.05", MATCHED, ("C-1",), comparator_glyph="¿"), GARBLED_COMPARATOR),
            (classified("0.012", correction_marker="bonferroni"), CORRECTED_VALUE),
            (classified("42.5"), UNREGISTERED),
            (classified("6.27", MATCHED, ("C-1", "C-2")), NOT_COMPARED),
            (classified("6.27", MATCHED, ("C-1",)), None),
        )
        for item, bucket in cases:
            with self.subTest(text=item.token.text, bucket=bucket):
                self.assertEqual(coverage_bucket(item, {"C-1"}), bucket)

    def test_a_declared_decimal_comma_is_typed(self) -> None:
        self.assertIsNone(coverage_bucket(classified("12,5", MATCHED, ("C-1",)), {"C-1"}, decimal_point=","))

    def test_the_funnel_is_monotone(self) -> None:
        items = [
            classified("1.2e3"),
            classified("1,234"),
            classified("0.012", correction_marker="adjusted"),
            classified("6.27", MATCHED, ("C-2",)),
            classified("6.27", MATCHED, ("C-1",)),
        ]
        coverage = numeric_coverage(items, {"C-1"}, floor=("0", Fraction(0)))
        stages = [coverage[key] for key in ("found", "parsed", "typed", "checkable", "checked")]
        self.assertEqual(stages, [5, 4, 3, 2, 1])
        self.assertIs(coverage["floor_met"], True)


class ScanAnnotationTest(unittest.TestCase):
    def annotations(self, text: str) -> list[tuple[str, str | None, str | None]]:
        return [(item.text, item.comparator_glyph, item.correction_marker) for item in scan_manuscript(text).tokens]

    def test_garbled_comparison_signs(self) -> None:
        self.assertEqual(self.annotations("p ¡ 0.05 and p¿0.10"), [("0.05", "¡", None), ("0.10", "¿", None)])
        self.assertEqual(self.annotations("p � 0.05"), [("0.05", "�", None)])
        self.assertEqual(self.annotations("p < 0.05 and p = 0.10"), [("0.05", None, None), ("0.10", None, None)])

    def test_correction_markers_stay_within_the_clause(self) -> None:
        self.assertEqual(self.annotations("corrected p = 0.04"), [("0.04", None, "corrected")])
        self.assertEqual(self.annotations("p = 0.012 (Bonferroni-corrected)"), [("0.012", None, "bonferroni")])
        self.assertEqual(self.annotations("Bonferroni was planned; the mean was 6.27"), [("6.27", None, None)])


class CandidateReadingsTest(unittest.TestCase):
    def values(self, text: str, **marks: Any) -> list[tuple[str, bool]]:
        return [(reading.plain, reading.declared) for reading in candidate_readings(text, **marks)]

    def test_readings(self) -> None:
        self.assertEqual(self.values("1,234", thousands=","), [("1234", True)])
        self.assertEqual(self.values("1,234"), [("1.234", False), ("1234", False)])
        self.assertEqual(self.values("12,5"), [("12.5", False)])
        self.assertEqual(self.values("0,031"), [("0.031", False)])  # a zero-led group is not grouping
        self.assertEqual(self.values("1.2e3"), [])
        (reading,) = candidate_readings("12,5")
        self.assertEqual(reading.to_dict()["marks"], [{"thousands": None, "decimal_point": ","}])
        self.assertEqual(reading.value, Decimal("12.5"))


if __name__ == "__main__":
    unittest.main()
