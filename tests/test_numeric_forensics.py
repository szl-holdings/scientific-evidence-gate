"""Numeric forensics: discrimination receipts and the GRIM family (ARCHITECTURE.md 17.11, extension #3).

Acceptance cases (a)-(f) of the research brief are pinned with their worked
values, the GRIM implementation is checked against brute-force rounding of
k/N for every N in 1..120 and every two-decimal mean in [0, 10), and every
test is shown both to pass on real (generated) data and to fail on numbers
no data could produce. Every value here is synthetic.
"""

from __future__ import annotations

import itertools
import json
import math
import shutil
import unittest
from decimal import ROUND_CEILING, ROUND_DOWN, ROUND_FLOOR, ROUND_HALF_EVEN, ROUND_HALF_UP, Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate._canonical import canonical_bytes
from science_gate.claims import RegistryFormatError, parse_registry
from science_gate.models import (
    EITHER_HALF,
    NUMERIC_OUTCOME_VERDICTS,
    ExecutionState,
    FailureMode,
    NumericOutcome,
    Ratio,
    RatioState,
    Reason,
    RoundingConvention,
    Status,
)
from science_gate.numeric import (
    MAX_ENUMERATION,
    NumericTest,
    apply_formula,
    compare_with_tolerance,
    debit,
    derived_interval,
    grim,
    grimmer,
    metric_feasibility,
    preimage,
    printed_number,
    round_fraction,
    round_with,
    rounding_fingerprint,
)
from science_gate.verifier import verify

NUMERIC_FIXTURES = REPO_ROOT / "fixtures" / "numeric"
HALF_EVEN, HALF_UP = RoundingConvention.HALF_EVEN, RoundingConvention.HALF_UP
EXACT_RULES = {
    RoundingConvention.HALF_EVEN: ROUND_HALF_EVEN,
    RoundingConvention.HALF_UP: ROUND_HALF_UP,
    RoundingConvention.TRUNCATE: ROUND_DOWN,
    RoundingConvention.CEILING: ROUND_CEILING,
    RoundingConvention.FLOOR: ROUND_FLOOR,
}


def text_of(scaled: int, decimals: int = 2) -> str:
    """Plain text of ``scaled / 10**decimals`` for non-negative values."""
    return f"{scaled // 10**decimals}.{scaled % 10**decimals:0{decimals}d}"


def sample_sd(values: tuple[int, ...]) -> Fraction:
    """The exact sample variance (n - 1 denominator)."""
    mean = Fraction(sum(values), len(values))
    return sum((value - mean) ** 2 for value in values) / (len(values) - 1)


def printed_sqrt(variance: Fraction, decimals: int = 2) -> str:
    """sqrt(variance) rounded half-even at ``decimals`` places, exactly (integer square roots, no floats)."""
    scale = 10**decimals
    target = variance * scale * scale
    low = math.isqrt(target.numerator // target.denominator)  # floor(sqrt(target)), exactly
    midpoint = Fraction(2 * low + 1, 2) ** 2
    if target > midpoint or (target == midpoint and low % 2):
        low += 1
    return text_of(low, decimals)


# ---------------------------------------------------------------------------
# The research brief's acceptance cases (a)-(f)
# ---------------------------------------------------------------------------


class AcceptanceTest(unittest.TestCase):
    def test_a_grim_rejects_5_19_from_28_and_names_the_nearest_consistent_means(self) -> None:
        test = grim("5.19", n=28)
        self.assertEqual(test.outcome, NumericOutcome.INCONSISTENT)
        self.assertEqual((test.verdict, test.reason, test.holds), (Status.FAIL, Reason.SOURCE_MISMATCH, False))
        self.assertEqual(test.evidence["nearest_consistent"], {"below": "5.18", "above": "5.21"})
        self.assertEqual(test.evidence["witness_totals"], [])

    def test_b_grim_accepts_5_18_from_28_with_discrimination_0_72(self) -> None:
        test = grim("5.18", n=28)
        self.assertEqual(test.outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(test.discrimination.decimal, "0.72")
        self.assertEqual((test.discrimination.numerator, test.discrimination.denominator), (72, 100))
        self.assertEqual((test.verdict, test.execution_state), (Status.PASS, ExecutionState.CHECKED))
        self.assertEqual(test.evidence["witness_totals"], [145])
        self.assertEqual(test.to_dict()["discrimination"], "0.72")

    def test_c_grim_at_n_150_is_not_testable_and_never_passes(self) -> None:
        test = grim("5.19", n=150)
        self.assertEqual(test.outcome, NumericOutcome.NOT_TESTABLE)
        self.assertEqual(test.execution_state, ExecutionState.NOT_APPLICABLE)
        self.assertEqual(test.discrimination.decimal, "0")
        self.assertNotEqual(test.verdict, Status.PASS)
        self.assertEqual((test.verdict, test.reason, test.holds), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, None))
        self.assertIn(FailureMode.VACUOUS_PASS, test.failure_modes)

    def test_e_impossible_classifier_metrics_have_no_valid_confusion_matrix(self) -> None:
        test = metric_feasibility({"sensitivity": "0.9000", "specificity": "0.9900"}, p=10, n=10)
        self.assertEqual(test.outcome, NumericOutcome.INCONSISTENT)
        self.assertEqual(test.evidence["n_valid_tptn_pairs"], 0)
        self.assertEqual(test.verdict, Status.FAIL)
        self.assertTrue(test.discrimination.numerator > 0)

    def test_f_a_tolerance_band_wider_than_the_value_holds_vacuously(self) -> None:
        test = compare_with_tolerance(
            "0.000000001", "0.000000002", relative="0.00001", absolute="0.00000001"
        )
        self.assertIs(test.holds, True)
        self.assertEqual(test.outcome, NumericOutcome.VACUOUSLY_CONSISTENT)
        self.assertIn(FailureMode.VACUOUS_PASS, test.failure_modes)
        self.assertEqual((test.verdict, test.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(test.evidence["band"], "0.00000001")
        self.assertIs(test.evidence["band_exceeds_expected"], True)


class GrimPropertyTest(unittest.TestCase):
    """(d): grim equals brute-force rounding of k/N, for N = 1..120 and every two-decimal mean in [0, 10)."""

    BRUTE = {
        HALF_EVEN: lambda k, n: round(Fraction(100 * k, n)),  # Fraction rounds half to even
        HALF_UP: lambda k, n: math.floor(Fraction(100 * k, n) + Fraction(1, 2)),  # k >= 0: ties go up
    }

    def test_grim_agrees_with_brute_force_rounding(self) -> None:
        for convention, rounding in self.BRUTE.items():
            mismatches: list[tuple[int, int, str]] = []
            for n in range(1, 121):
                reachable = {rounding(k, n) for k in range(0, 10 * n + 1)}
                for scaled in range(1000):
                    test = grim(text_of(scaled), n, conventions=(convention,))
                    if (test.outcome is NumericOutcome.INCONSISTENT) == (scaled in reachable):
                        mismatches.append((n, scaled, test.outcome.value))
                    if (test.outcome is NumericOutcome.NOT_TESTABLE) != (n >= 100):
                        mismatches.append((n, scaled, "testability"))
                for unit in range(10):
                    hits = sum(1 for value in reachable if 100 * unit <= value < 100 * unit + 100)
                    discrimination = grim(text_of(100 * unit), n, conventions=(convention,)).discrimination
                    if (discrimination.numerator, discrimination.denominator) != (100 - hits, 100):
                        mismatches.append((n, 100 * unit, f"discrimination {discrimination.fraction}"))
            with self.subTest(convention=convention.value):
                self.assertEqual(mismatches, [])

    def test_items_multiply_the_denominator(self) -> None:
        # 2 items per respondent, 14 respondents: totals are k / 28, as for 28 single ratings.
        self.assertEqual(grim("5.19", 14, items=2).outcome, NumericOutcome.INCONSISTENT)
        self.assertEqual(grim("5.18", 14, items=2).discrimination.decimal, "0.72")

    def test_either_half_accepts_a_tie_either_rule_produces(self) -> None:
        # 5/8 = 0.625 exactly: half-even prints 0.62, half-up 0.63.
        self.assertEqual(grim("0.63", 8, conventions=(HALF_EVEN,)).outcome, NumericOutcome.INCONSISTENT)
        self.assertEqual(grim("0.63", 8, conventions=(HALF_UP,)).outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(grim("0.63", 8).outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(grim("0.63", 8).evidence["conventions"], ["HALF_EVEN", "HALF_UP"])

    def test_negative_means_and_integers(self) -> None:
        self.assertEqual(grim("-5.18", 28).outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(grim("-5.19", 28).outcome, NumericOutcome.INCONSISTENT)
        integer = grim("5", 28)
        self.assertEqual((integer.outcome, integer.discrimination.decimal), (NumericOutcome.NOT_TESTABLE, "0"))

    def test_grids_too_large_to_count_are_unavailable_never_guessed(self) -> None:
        test = grim("0." + "1" * 17, 7)
        self.assertEqual(test.discrimination.state, RatioState.UNAVAILABLE)
        self.assertIn(test.outcome, (NumericOutcome.INCONSISTENT, NumericOutcome.NOT_TESTABLE))
        bounded = grim("0.1234560", MAX_ENUMERATION)
        self.assertEqual(
            (bounded.outcome, bounded.discrimination.state), (NumericOutcome.NOT_TESTABLE, RatioState.UNAVAILABLE)
        )

    def test_bad_arguments_are_refused(self) -> None:
        for args, kwargs in ((("5.18", 0), {}), (("5.18", 28), {"items": 0}), (("5,18", 28), {}), (("5.18", True), {})):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(ValueError):
                grim(*args, **kwargs)
        with self.assertRaises(TypeError):
            grim(5.18, 28)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Rounding, preimages and the NumericTest contract
# ---------------------------------------------------------------------------


class RoundingTest(unittest.TestCase):
    VALUES = ("0.125", "0.135", "-0.125", "2.675", "6.27", "-6.27", "0.005", "-0.005", "15.3125", "0", "9.995")

    def test_exact_conventions_match_decimal_quantize(self) -> None:
        for text, (convention, mode) in itertools.product(self.VALUES, EXACT_RULES.items()):
            for decimals in (0, 1, 2):
                with self.subTest(value=text, convention=convention.value, decimals=decimals):
                    expected = Decimal(text).quantize(Decimal(1).scaleb(-decimals), rounding=mode)
                    self.assertEqual(round_with(Decimal(text), decimals, convention), expected)

    def test_float_first_is_the_binary_float_rounded_and_read_back(self) -> None:
        for text in self.VALUES:
            with self.subTest(value=text):
                expected = Decimal(repr(round(float(text), 2)))
                self.assertEqual(round_with(Decimal(text), 2, RoundingConvention.FLOAT_FIRST), expected)
        # 2.675 is stored in binary just below the tie, so float-first prints 2.67 where exact rules print 2.68.
        self.assertEqual(round_with(Decimal("2.675"), 2, RoundingConvention.FLOAT_FIRST), Decimal("2.67"))
        self.assertEqual(round_with(Decimal("2.675"), 2, HALF_EVEN), Decimal("2.68"))

    def test_rounding_keeps_the_printed_decimals_and_never_prints_minus_zero(self) -> None:
        self.assertEqual(str(round_with(Decimal("0.1"), 2, HALF_EVEN)), "0.10")
        self.assertEqual(str(round_with(Decimal("-0.001"), 2, HALF_EVEN)), "0.00")
        self.assertEqual(str(round_fraction(Fraction(1, 3), 4, HALF_EVEN)), "0.3333")

    def test_floats_are_refused(self) -> None:
        with self.assertRaises(TypeError):
            round_with(2.675, 2, HALF_EVEN)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            round_fraction(0.1, 2, HALF_EVEN)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            printed_number(1.5)  # type: ignore[arg-type]

    def test_fingerprints(self) -> None:
        self.assertEqual(rounding_fingerprint("0.125", "0.13"), frozenset({HALF_UP, RoundingConvention.CEILING}))
        self.assertEqual(
            rounding_fingerprint("6.27", "6.2"), frozenset({RoundingConvention.TRUNCATE, RoundingConvention.FLOOR})
        )
        self.assertEqual(
            rounding_fingerprint("2.675", "2.67"),
            frozenset({RoundingConvention.TRUNCATE, RoundingConvention.FLOOR, RoundingConvention.FLOAT_FIRST}),
        )
        self.assertEqual(rounding_fingerprint("12.40", "12.4"), frozenset(RoundingConvention))
        self.assertEqual(rounding_fingerprint("0.141", "0.13"), frozenset())


class PreimageTest(unittest.TestCase):
    def test_tie_ownership_per_convention(self) -> None:
        cases = {
            ("5.18", (HALF_EVEN,)): "[5.175, 5.185]",
            ("5.17", (HALF_EVEN,)): "(5.165, 5.175)",
            ("5.17", (HALF_UP,)): "[5.165, 5.175)",
            ("-5.17", (HALF_UP,)): "(-5.175, -5.165]",
            ("5.17", tuple(EITHER_HALF)): "[5.165, 5.175)",
            ("5.17", (RoundingConvention.TRUNCATE,)): "[5.17, 5.18)",
            ("-5.17", (RoundingConvention.TRUNCATE,)): "(-5.18, -5.17]",
            ("0.00", (RoundingConvention.TRUNCATE,)): "(-0.01, 0.01)",
            ("5.17", (RoundingConvention.CEILING,)): "(5.16, 5.17]",
            ("5.17", (RoundingConvention.FLOOR,)): "[5.17, 5.18)",
        }
        for (printed, conventions), notation in cases.items():
            with self.subTest(printed=printed, conventions=conventions):
                self.assertEqual(preimage(printed, conventions=conventions).notation, notation)

    def test_preimage_is_exactly_the_set_that_rounds_to_the_printed_value(self) -> None:
        for convention in EXACT_RULES:
            for printed in ("5.18", "5.17", "0.00", "-0.03", "-5.18"):
                interval = preimage(printed, conventions=(convention,))
                centre = Decimal(printed)
                for step in range(-300, 301):
                    value = centre + Decimal(step).scaleb(-4)
                    rounds = round_with(value, 2, convention) == centre
                    if interval.contains(value) != rounds:
                        self.fail(f"{convention.value} {printed}: {value} contains={not rounds} rounds={rounds}")

    def test_float_first_has_no_exact_preimage(self) -> None:
        with self.assertRaises(ValueError):
            preimage("5.18", conventions=(RoundingConvention.FLOAT_FIRST,))

    def test_to_dict_is_exact_and_canonical(self) -> None:
        record = preimage("5.17", conventions=EITHER_HALF).to_dict()
        self.assertEqual(
            record,
            {
                "low": "5.165",
                "high": "5.175",
                "low_inclusive": True,
                "high_inclusive": False,
                "conventions": ["HALF_EVEN", "HALF_UP"],
                "notation": "[5.165, 5.175)",
            },
        )
        canonical_bytes(record)


class NumericTestContractTest(unittest.TestCase):
    def test_a_consistent_outcome_cannot_be_built_without_discrimination(self) -> None:
        for ratio in (Ratio(0, 100), Ratio(None, None), Ratio(0, 0)):
            with self.subTest(ratio=ratio.to_dict()), self.assertRaises(ValueError):
                NumericTest("grim", NumericOutcome.CONSISTENT, ratio, {})
        NumericTest("grim", NumericOutcome.CONSISTENT, Ratio(1, 100), {})

    def test_outcomes_map_through_the_models_table(self) -> None:
        for outcome, (state, verdict, reason, modes) in NUMERIC_OUTCOME_VERDICTS.items():
            test = NumericTest("t", outcome, Ratio(1, 2), {"note": "synthetic"})
            with self.subTest(outcome=outcome.value):
                self.assertEqual((test.execution_state, test.verdict, test.reason), (state, verdict, reason))
                self.assertEqual(test.failure_modes, modes)
                record = test.to_dict()
                self.assertEqual(
                    (record["outcome"], record["verdict"], record["discrimination"]),
                    (outcome.value, verdict.value, "0.5"),
                )
                canonical_bytes(record)

    def test_discrimination_travels_as_an_exact_ratio(self) -> None:
        record = grim("5.18", 28).to_dict()
        self.assertEqual(
            record["discrimination_ratio"],
            {
                "numerator": 72,
                "denominator": 100,
                "state": "DEFINED",
                "fraction": "72/100",
                "decimal": "0.72",
                "exact": True,
            },
        )


# ---------------------------------------------------------------------------
# GRIMMER and DEBIT
# ---------------------------------------------------------------------------


class GrimmerTest(unittest.TestCase):
    def test_worked_cases(self) -> None:
        # 1, 2, 3, 4, 5: mean 3.00, sample SD sqrt(2.5) = 1.58; total 15, sum of squares 55.
        consistent = grimmer("3.00", "1.58", 5)
        self.assertEqual(consistent.outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(consistent.evidence["witness"], {"total": 15, "sum_of_squares": 55})
        self.assertTrue(consistent.discrimination.numerator > 0)
        # 1.59 needs a sum of squares strictly between 55 and 56: no integer fits.
        self.assertEqual(grimmer("3.00", "1.59", 5).outcome, NumericOutcome.INCONSISTENT)
        # 1.66 needs 56, which has the wrong parity for a total of 15 (x and x**2 share parity).
        parity = grimmer("3.00", "1.66", 5)
        self.assertEqual((parity.outcome, parity.verdict), (NumericOutcome.INCONSISTENT, Status.FAIL))
        self.assertIs(parity.evidence["mean_consistent"], True)
        # The mean itself fails GRIM: every SD is then rejected.
        mean = grimmer("3.10", "1.58", 5)
        self.assertEqual((mean.outcome, mean.evidence["mean_consistent"]), (NumericOutcome.INCONSISTENT, False))
        self.assertEqual(mean.discrimination.decimal, "1")

    def test_never_rejects_real_integer_data(self) -> None:
        rejected = []
        for n in (3, 5):
            for values in itertools.combinations_with_replacement(range(1, 6), n):
                mean = text_of(round(Fraction(sum(values) * 100, n)))
                sd = printed_sqrt(sample_sd(values))
                if grimmer(mean, sd, n, conventions=(HALF_EVEN,)).outcome is NumericOutcome.INCONSISTENT:
                    rejected.append((values, mean, sd))
        self.assertEqual(rejected, [])

    def test_float_first_and_bad_arguments_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            grimmer("3.00", "1.58", 5, conventions=(RoundingConvention.FLOAT_FIRST,))
        for args in (("3.00", "1.58", 1), ("3.00", "-1.58", 5)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                grimmer(*args)


class DebitTest(unittest.TestCase):
    def test_worked_cases(self) -> None:
        # 7 ones of 20: variance 91/380, SD 0.489...: prints 0.49, never 0.48.
        test = debit("0.35", "0.49", 20)
        self.assertEqual(test.outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(test.evidence["witness"], {"ones": 7, "variance": "91/380"})
        self.assertEqual(debit("0.35", "0.48", 20).outcome, NumericOutcome.INCONSISTENT)
        self.assertEqual(debit("1.20", "0.49", 20).outcome, NumericOutcome.INCONSISTENT)

    def test_never_rejects_real_binary_data(self) -> None:
        rejected = []
        for n in range(2, 31):
            for ones in range(n + 1):
                proportion = text_of(round(Fraction(100 * ones, n)))
                sd = printed_sqrt(Fraction(ones * (n - ones), n * (n - 1)))
                if debit(proportion, sd, n, conventions=(HALF_EVEN,)).outcome is NumericOutcome.INCONSISTENT:
                    rejected.append((n, ones))
        self.assertEqual(rejected, [])


# ---------------------------------------------------------------------------
# Classifier metrics, derived intervals, tolerance comparisons
# ---------------------------------------------------------------------------


class MetricFeasibilityTest(unittest.TestCase):
    def test_a_feasible_report_has_its_matrix_and_discrimination(self) -> None:
        test = metric_feasibility({"sensitivity": "0.9000", "specificity": "0.9000"}, p=10, n=10)
        self.assertEqual(test.outcome, NumericOutcome.CONSISTENT)
        self.assertEqual((test.evidence["n_valid_tptn_pairs"], test.evidence["valid_pairs"]), (1, [{"tp": 9, "tn": 9}]))
        self.assertEqual(test.discrimination.fraction, "19980/20002")

    def test_every_metric_of_a_real_matrix_is_feasible(self) -> None:
        rejected = []
        for tp, tn in itertools.product(range(7), range(5)):
            fp, fn = 4 - tn, 6 - tp
            exact = {
                "sensitivity": Fraction(tp, 6),
                "specificity": Fraction(tn, 4),
                "precision": Fraction(tp, tp + fp) if tp + fp else None,
                "npv": Fraction(tn, tn + fn) if tn + fn else None,
                "accuracy": Fraction(tp + tn, 10),
                "balanced_accuracy": (Fraction(tp, 6) + Fraction(tn, 4)) / 2,
                "f1": Fraction(2 * tp, 2 * tp + fp + fn),
            }
            metrics = {
                name: str(round_fraction(value, 3, HALF_EVEN)) for name, value in exact.items() if value is not None
            }
            test = metric_feasibility(metrics, p=6, n=4, conventions=(HALF_EVEN,))
            found = {"tp": tp, "tn": tn} in test.evidence["valid_pairs"]
            if test.outcome is not NumericOutcome.CONSISTENT or not found:
                rejected.append((tp, tn, test.outcome.value))
        self.assertEqual(rejected, [])

    def test_unknown_metrics_and_empty_populations_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            metric_feasibility({"auc": "0.9"}, p=10, n=10)
        with self.assertRaises(ValueError):
            metric_feasibility({"accuracy": "0.9"}, p=0, n=0)
        with self.assertRaises(ValueError):
            metric_feasibility({}, p=1, n=1)


class DerivedIntervalTest(unittest.TestCase):
    def test_rounded_inputs_give_a_guaranteed_range(self) -> None:
        interval = derived_interval("difference", {"alpha": "12.35", "beta": "10.25"})
        self.assertEqual(interval.notation, "(2.09, 2.11)")
        self.assertTrue(interval.contains("2.092"))
        self.assertFalse(interval.contains("2.11"))
        ratio = derived_interval("ratio", {"a": "1.0", "b": "3.0"}, conventions=(HALF_EVEN,))
        self.assertEqual(ratio.notation, "[19/61, 21/59]")
        percent = derived_interval("percent", {"a": "1.0", "b": "4.0"})
        self.assertEqual((percent.low, percent.high), (Fraction(1900, 81), Fraction(2100, 79)))
        self.assertEqual((percent.low_inclusive, percent.high_inclusive), (True, True))

    def test_every_value_from_inputs_inside_the_preimages_lies_in_the_range(self) -> None:
        for formula in ("difference", "ratio", "percent", "f1"):
            interval = derived_interval(formula, {"a": "0.84", "b": "0.62"}, conventions=(HALF_EVEN,))
            for a, b in itertools.product(range(8355, 8446), range(6155, 6246)):
                value = apply_formula(formula, (Fraction(a, 10000), Fraction(b, 10000)))
                if not interval.contains(value):
                    self.fail(f"{formula}({a}, {b}) = {value} outside {interval.notation}")

    def test_unbounded_ranges_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            derived_interval("ratio", {"a": "1.0", "b": "0.00"})
        with self.assertRaises(ValueError):
            derived_interval("f1", {"a": "0.0", "b": "0.5"})
        with self.assertRaises(ValueError):
            derived_interval("difference", {"a": "1.0"})
        self.assertIsNone(apply_formula("ratio", (Fraction(1), Fraction(0))))


class CompareWithToleranceTest(unittest.TestCase):
    def test_outcomes(self) -> None:
        failing = compare_with_tolerance("1.00", "1.20", absolute="0.10")
        self.assertEqual(
            (failing.outcome, failing.holds, failing.verdict), (NumericOutcome.INCONSISTENT, False, Status.FAIL)
        )
        passing = compare_with_tolerance("1.00", "1.02", absolute="0.05")
        self.assertEqual(passing.outcome, NumericOutcome.CONSISTENT)
        self.assertEqual(passing.discrimination.fraction, "10/21")
        coarse = compare_with_tolerance("100", "100.0", absolute="2")
        self.assertEqual((coarse.outcome, coarse.discrimination.decimal), (NumericOutcome.NOT_TESTABLE, "0"))
        relative = compare_with_tolerance("200", "201", relative="0.01")
        self.assertEqual((relative.outcome, relative.evidence["band"]), (NumericOutcome.CONSISTENT, "2"))

    def test_negative_tolerances_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            compare_with_tolerance("1", "1", absolute="-0.1")


# ---------------------------------------------------------------------------
# Consistency tests inside the claims check, through verify()
# ---------------------------------------------------------------------------


class NumericFixtureOutcomesTest(unittest.TestCase):
    """Each committed fixture verifies to the outcome ``fixtures/numeric/expected.json`` records."""

    def test_every_fixture_matches_its_expected_outcome(self) -> None:
        expected = json.loads((NUMERIC_FIXTURES / "expected.json").read_text(encoding="utf-8"))["fixtures"]
        directories = sorted(path.name for path in NUMERIC_FIXTURES.iterdir() if path.is_dir())
        self.assertEqual(sorted(expected), directories)
        for name, want in expected.items():
            with self.subTest(fixture=name):
                run = verify(NUMERIC_FIXTURES / name / "manifest.json")
                (result,) = [item for item in run.result.checks if item.check_id == "claims"]
                self.assertEqual(
                    (run.status.value, run.result.reason.value, run.exit_code),
                    (want["status"], want["reason"], want["exit_code"]),
                )
                self.assertEqual(
                    (result.verdict.value, result.reason.value, sorted(mode.value for mode in result.failure_modes)),
                    (
                        want["claims_check"]["verdict"],
                        want["claims_check"]["reason"],
                        want["claims_check"]["failure_modes"],
                    ),
                )


def claims_result(manifest: Path) -> Any:
    run = verify(manifest)
    (result,) = [item for item in run.result.checks if item.check_id == "claims"]
    return run, result


class ClaimsConsistencyTest(TempDirTestCase):
    def test_a_consistent_mean_carries_the_check_level_discrimination(self) -> None:
        run, result = claims_result(NUMERIC_FIXTURES / "grim-consistent" / "manifest.json")
        self.assertEqual((run.status, result.verdict), (Status.PASS, Status.PASS))
        self.assertEqual(result.evidence["discrimination"], "0.72")
        self.assertEqual(result.evidence["discrimination_ratio"]["fraction"], "72/100")
        consistency = result.evidence["consistency"]
        self.assertEqual(consistency["minimum"], {"claim_id": "N-MEAN", "discrimination": "0.72"})
        # The run reports its least discriminating PASS (17.8): here the claims check.
        minimum = run.result.to_dict()["controls"]["min_discrimination"]
        self.assertEqual((minimum["check_id"], minimum["discrimination"]), ("claims", "0.72"))
        (record,) = consistency["tests"]
        self.assertEqual(
            (record["test"], record["outcome"], record["evidence"]["witness_totals"]), ("grim", "CONSISTENT", [145])
        )

    def test_an_inconsistent_mean_fails_with_its_nearest_consistent_values(self) -> None:
        run, result = claims_result(NUMERIC_FIXTURES / "grim-inconsistent" / "manifest.json")
        self.assertEqual((run.exit_code, result.verdict, result.reason), (1, Status.FAIL, Reason.SOURCE_MISMATCH))
        (record,) = result.evidence["consistency"]["tests"]
        self.assertEqual(record["evidence"]["nearest_consistent"], {"below": "5.18", "above": "5.21"})

    def test_an_untestable_mean_never_passes(self) -> None:
        run, result = claims_result(NUMERIC_FIXTURES / "grim-untestable" / "manifest.json")
        self.assertEqual((run.status, result.verdict), (Status.ABSTAIN, Status.ABSTAIN))
        self.assertEqual(result.evidence["discrimination"], "0")
        self.assertEqual(result.evidence["consistency"]["outcomes"], {"NOT_TESTABLE": 1})

    def copy_fixture(self, name: str) -> Path:
        project = self.tmp / name
        shutil.copytree(NUMERIC_FIXTURES / name, project)
        return project

    def edit_registry(self, project: Path, edit: Any) -> None:
        path = project / "claims" / "registry.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        edit(document)
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def test_the_weakest_test_sets_the_check_discrimination(self) -> None:
        project = self.copy_fixture("grim-consistent")

        def add_grimmer(document: dict[str, Any]) -> None:
            # A second, weaker test: the respondent count read as a mean of 28 equal ratings (SD 0).
            document["claims"][0]["consistency"] = {"test": "grimmer", "n": 28, "sd": "0.00"}

        self.edit_registry(project, add_grimmer)
        _, result = claims_result(project / "manifest.json")
        records = {record["claim_id"]: record for record in result.evidence["consistency"]["tests"]}
        self.assertEqual(set(records), {"N-COUNT", "N-MEAN"})
        weakest = min(
            (Fraction(record["discrimination_ratio"]["fraction"]), claim_id) for claim_id, record in records.items()
        )
        self.assertEqual(result.evidence["consistency"]["minimum"]["claim_id"], weakest[1])
        self.assertEqual(Fraction(result.evidence["discrimination_ratio"]["fraction"]), weakest[0])

    def test_an_unreadable_consistency_input_abstains(self) -> None:
        project = self.copy_fixture("grim-consistent")

        def bad_sd(document: dict[str, Any]) -> None:
            document["claims"][1]["consistency"] = {"test": "grimmer", "n": 28, "sd": "about one"}

        self.edit_registry(project, bad_sd)
        _, result = claims_result(project / "manifest.json")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))
        self.assertEqual(result.evidence["consistency"]["outcomes"], {"NOT_EVALUATED": 1})

    def test_declared_tests_are_validated(self) -> None:
        def registry(consistency: Any) -> dict[str, Any]:
            return {"schema": "science-gate-claims/v1", "claims": [{"claim_id": "C-1", "consistency": consistency}]}

        refused = {
            "test must be one of": {"test": "sprite", "n": 10},
            "got None": {"test": None, "n": 10},
            "n must be an integer >= 2": {"test": "grimmer", "n": 1, "sd": "1.0"},
            "sd does not apply to grim": {"test": "grim", "n": 10, "sd": "1.0"},
            "sd must be the printed standard deviation": {"test": "debit", "n": 10},
            "items does not apply to debit": {"test": "debit", "n": 10, "sd": "0.5", "items": 2},
            "unknown key(s) ['alpha']": {"test": "grim", "n": 10, "alpha": 1},
            "is missing ['n']": {"test": "grim"},
        }
        for fragment, consistency in refused.items():
            with self.subTest(fragment=fragment):
                with self.assertRaises(RegistryFormatError) as caught:
                    parse_registry(registry(consistency))
                self.assertIn(fragment, str(caught.exception))
        (claim,) = parse_registry(registry({"test": "grim", "n": 28, "items": 2})).claims
        self.assertEqual(claim.consistency.to_dict(), {"test": "grim", "n": 28, "items": 2, "sd": None})


if __name__ == "__main__":
    unittest.main()
