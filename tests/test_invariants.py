"""Named invariants (section 4) and the numeric rules (section 7)."""

from __future__ import annotations

import dataclasses
import unittest
from decimal import Decimal

from _helpers import TempDirTestCase, build_scenario

from science_gate._canonical import canonical_dumps
from science_gate.invariants import (
    AGREES_AT_STATED_PRECISION,
    AMBIGUOUS_SEPARATOR,
    DISAGREES,
    EXACT,
    INVARIANT_NAMES,
    INVARIANTS,
    MAX_NUMBER_LENGTH,
    NOT_A_NUMBER,
    NUMBER_PARSED,
    REQUIRES_HUMAN_REVIEW,
    VIOLATION_OUTCOMES,
    ClaimTally,
    InvariantContext,
    compare_decimal,
    evaluate_invariants,
    parse_decimal,
)
from science_gate.models import (
    CheckResult,
    ExecutionState,
    FailureMode,
    InputState,
    InvariantResult,
    Reason,
    Status,
)

CONTRACT_NAMES = (
    "checked_claims_le_invocations",
    "every_verdict_has_invocation",
    "every_invocation_has_terminal_result",
    "every_required_check_has_terminal_state",
    "pass_requires_nonempty_evidence",
    "pass_requires_complete_required_inputs",
    "pass_requires_complete_required_checks",
    "pass_requires_examined_rows",
    "input_accounting_closure",
    "ledger_chain_intact",
)


class InvariantTestCase(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.scenario = build_scenario(self)
        self.check = self.scenario.checks[0]

    def judge(self, name: str, **overrides: object) -> InvariantResult:
        result = INVARIANTS[name](self.scenario.context(**overrides))
        self.assertEqual(result.name, name)
        return result

    def assertViolated(self, name: str, fragment: str = "", **overrides: object) -> InvariantResult:
        result = self.judge(name, **overrides)
        self.assertTrue(result.applicable, result.detail)
        self.assertIs(result.holds, False, result.detail)
        self.assertIn(fragment, result.detail)
        return result

    def assertNotApplicable(self, name: str, **overrides: object) -> InvariantResult:
        result = self.judge(name, **overrides)
        self.assertEqual((result.applicable, result.holds), (False, None), result.detail)
        return result

    def replaced_check(self, **changes: object) -> tuple[CheckResult, ...]:
        return (dataclasses.replace(self.check, **changes),)


class RegistryTests(InvariantTestCase):
    def test_names_and_order_follow_the_contract(self) -> None:
        self.assertEqual(INVARIANT_NAMES, CONTRACT_NAMES)
        self.assertEqual(tuple(INVARIANTS), CONTRACT_NAMES)
        self.assertEqual(set(VIOLATION_OUTCOMES), set(CONTRACT_NAMES))

    def test_violation_outcomes_never_pass(self) -> None:
        for name, outcome in VIOLATION_OUTCOMES.items():
            with self.subTest(name=name):
                self.assertIn(outcome.status, (Status.FAIL, Status.ABSTAIN))
                self.assertIsNot(outcome.reason, Reason.VERIFIED)

    def test_a_coherent_passing_run_satisfies_every_invariant(self) -> None:
        results = evaluate_invariants(self.scenario.context())
        self.assertEqual(tuple(result.name for result in results), CONTRACT_NAMES)
        for result in results:
            with self.subTest(name=result.name):
                self.assertEqual((result.applicable, result.holds), (True, True), result.detail)

    def test_evaluation_is_deterministic(self) -> None:
        first = canonical_dumps(evaluate_invariants(self.scenario.context()))
        second = canonical_dumps(evaluate_invariants(self.scenario.context()))
        self.assertEqual(first, second)


class ExecutionInvariantTests(InvariantTestCase):
    def test_narrated_verifications_exceed_invocations(self) -> None:
        tallies = (ClaimTally("citation log claimed_verified", 8, 0),)
        self.assertViolated("checked_claims_le_invocations", "8 claimed but only 0 invoked", claim_tallies=tallies)
        tallies = (ClaimTally("citation log claimed_verified", 8, None),)
        self.assertViolated("checked_claims_le_invocations", "no invocation record", claim_tallies=tallies)

    def test_checked_results_without_ledger_invocations(self) -> None:
        self.assertViolated("checked_claims_le_invocations", "1 claimed but only 0 invoked", entries=())

    def test_nothing_claimed_is_not_applicable(self) -> None:
        self.assertNotApplicable("checked_claims_le_invocations", checks=(), claim_tallies=(ClaimTally("log", 0, 0),))

    def test_every_verdict_points_to_its_own_terminal_invocation(self) -> None:
        unlinked = self.replaced_check(invocation_id=None)
        self.assertViolated("every_verdict_has_invocation", "has no invocation_id", checks=unlinked)
        self.assertViolated(
            "every_verdict_has_invocation", "not in the ledger", checks=self.replaced_check(invocation_id="inv-000000000000")
        )
        self.assertViolated(
            "every_verdict_has_invocation",
            "disagrees with its ledger verdict",
            checks=self.replaced_check(verdict=Status.FAIL, reason=Reason.SOURCE_MISMATCH),
        )
        other = dataclasses.replace(self.check, check_id="other")
        self.assertViolated("every_verdict_has_invocation", "shares invocation", checks=(self.check, other))
        self.assertViolated("every_verdict_has_invocation", "of check 'rows'", checks=(other,))

    def test_removed_invocation_leaves_the_verdict_unbacked(self) -> None:
        invocation_id = self.check.invocation_id
        remaining = tuple(entry for entry in self.scenario.ledger.entries if entry["invocation_id"] != invocation_id)
        self.assertViolated("every_verdict_has_invocation", "not in the ledger", entries=remaining)

    def test_partial_execution_cannot_appear_complete(self) -> None:
        # Requirement 7 / 22: a started invocation with no terminal entry.
        ledger = self.scenario.ledger
        ledger.start(check_id="late", check_kind="row_count", check_version="1")
        entries = ledger.entries
        seal = ledger.seal()
        self.assertViolated(
            "every_invocation_has_terminal_result", "never reached a terminal result", entries=entries, **seal
        )
        self.assertNotApplicable("every_invocation_has_terminal_result", entries=())

    def test_every_required_check_needs_a_terminal_result(self) -> None:
        declared = {"rows": True, "reviewers": True}
        self.assertViolated("every_required_check_has_terminal_state", "'reviewers' has no result", declared_checks=declared)
        self.assertViolated(
            "every_required_check_has_terminal_state", "result says optional", checks=self.replaced_check(required=False)
        )
        unlinked = self.replaced_check(invocation_id=None)
        self.assertViolated("every_required_check_has_terminal_state", "no terminal invocation", checks=unlinked)
        self.assertNotApplicable(
            "every_required_check_has_terminal_state", declared_checks={}, checks=self.replaced_check(required=False)
        )

    def test_ledger_chain_must_match_its_seal(self) -> None:
        entries = self.scenario.ledger.entries
        self.assertViolated("ledger_chain_intact", "LENGTH_MISMATCH", entries=entries[:-1])
        self.assertViolated("ledger_chain_intact", "SEQUENCE_BREAK", entries=(entries[1], entries[0]))
        self.assertViolated("ledger_chain_intact", "UNSEALED", ledger_length=None)
        self.assertNotApplicable("ledger_chain_intact", entries=(), ledger_head_sha256=None, ledger_length=None)
        self.assertViolated("ledger_chain_intact", "LENGTH_MISMATCH", entries=())


class PassContractTests(InvariantTestCase):
    def test_pass_invariants_are_not_applicable_when_nothing_claims_pass(self) -> None:
        abstained = self.replaced_check(verdict=Status.ABSTAIN, reason=Reason.UNVERIFIED)
        for name in (
            "pass_requires_nonempty_evidence",
            "pass_requires_complete_required_inputs",
            "pass_requires_complete_required_checks",
            "pass_requires_examined_rows",
        ):
            with self.subTest(name=name):
                # Not applicable is never reported as holding.
                self.assertNotApplicable(name, checks=abstained, claimed_status=Status.ABSTAIN)

    def test_pass_requires_evidence_for_checks_and_the_run(self) -> None:
        self.assertViolated("pass_requires_nonempty_evidence", "empty evidence", checks=self.replaced_check(evidence={}))
        self.assertViolated("pass_requires_nonempty_evidence", "no evidence manifest", evidence_manifest=None)
        self.assertViolated("pass_requires_nonempty_evidence", "evidence manifest is empty", evidence_manifest=[])
        self.assertViolated("pass_requires_nonempty_evidence", "has no sha256", evidence_manifest=[{"path": "x"}])

    def test_pass_is_impossible_with_zero_examined_rows(self) -> None:
        # Requirement 3.
        self.assertViolated("pass_requires_examined_rows", "examining 0 rows", checks=self.replaced_check(rows_examined=0))
        self.assertViolated(
            "pass_requires_examined_rows", "without reporting rows examined", checks=self.replaced_check(rows_examined=None)
        )
        self.assertViolated("pass_requires_examined_rows", "examined no rows", checks=())

    def test_pass_is_impossible_when_a_required_checker_did_not_run(self) -> None:
        # Requirement 4.
        skipped = self.replaced_check(
            execution_state=ExecutionState.SKIPPED, verdict=Status.ABSTAIN, reason=Reason.PARTIAL_EXECUTION
        )
        self.assertViolated("pass_requires_complete_required_checks", "was not executed: SKIPPED", checks=skipped)
        self.assertViolated("pass_requires_complete_required_checks", "did not run", checks=())
        self.assertViolated(
            "pass_requires_complete_required_checks",
            "checks_executed=1",
            declared_checks={"rows": True, "reviewers": True},
        )
        failed = self.replaced_check(verdict=Status.FAIL, reason=Reason.SOURCE_MISMATCH)
        self.assertViolated("pass_requires_complete_required_checks", "ended FAIL", checks=failed)

    def test_pass_with_no_required_checks_would_be_vacuous(self) -> None:
        optional = self.replaced_check(required=False)
        self.assertViolated("pass_requires_complete_required_checks", "vacuous", declared_checks={}, checks=optional)

    def test_pass_requires_complete_required_inputs(self) -> None:
        accounting = self.scenario.accounting
        record = accounting.record("measurements")
        for state in (InputState.MISSING, InputState.HASH_MISMATCH, InputState.PARTIAL, InputState.EMPTY):
            with self.subTest(state=state):
                broken = dataclasses.replace(accounting, records=(dataclasses.replace(record, state=state),))
                self.assertViolated("pass_requires_complete_required_inputs", state.value, accounting=broken)
        self.assertViolated("pass_requires_complete_required_inputs", "no input accounting", accounting=None)

    def test_pass_requires_at_least_one_declared_and_opened_input(self) -> None:
        empty = build_scenario(self, inputs=[], checks=[])
        context = empty.context(checks=self.scenario.checks)
        result = INVARIANTS["pass_requires_complete_required_inputs"](context)
        self.assertIs(result.holds, False)
        self.assertIn("no input was declared", result.detail)
        self.assertIn("no input was opened", result.detail)

    def test_closure_is_judged_only_against_independent_counts(self) -> None:
        # Requirement 9's accounting side: a row missing against an INDEPENDENT count breaks closure.
        short = build_scenario(self, csv_text="sample_id,value,count\nSYN-0001,1,1\nSYN-0002,2,2\n")
        result = INVARIANTS["input_accounting_closure"](short.context())
        self.assertIs(result.holds, False)
        self.assertIn("expected 3, accounted 2", result.detail)
        self.assertEqual(VIOLATION_OUTCOMES["input_accounting_closure"].status, Status.FAIL)

    def test_observed_counts_never_make_closure_hold(self) -> None:
        document_input = {
            "id": "measurements",
            "path": "data/measurements.csv",
            "format": "csv",
            "expected_rows": 3,
            "denominator_source": "OBSERVED",
        }
        observed = build_scenario(self, inputs=[document_input])
        result = INVARIANTS["input_accounting_closure"](observed.context())
        # Only the run-level (declared inputs) closure is INDEPENDENT; the OBSERVED row count is not judged.
        self.assertEqual(result.detail, "1 INDEPENDENT closure(s) hold")
        self.assertIsNone(observed.accounting.record("measurements").closure.holds)
        self.assertNotApplicable("input_accounting_closure", accounting=None)


class ViolationOutcomeTests(unittest.TestCase):
    def test_outcomes_match_section_6_precedence(self) -> None:
        self.assertEqual(VIOLATION_OUTCOMES["ledger_chain_intact"].status, Status.FAIL)
        self.assertEqual(
            VIOLATION_OUTCOMES["checked_claims_le_invocations"].failure_mode, FailureMode.NARRATED_VERIFICATION
        )
        self.assertEqual(VIOLATION_OUTCOMES["every_verdict_has_invocation"].reason, Reason.UNVERIFIED)
        self.assertEqual(VIOLATION_OUTCOMES["pass_requires_examined_rows"].failure_mode, FailureMode.VACUOUS_PASS)
        self.assertEqual(
            VIOLATION_OUTCOMES["every_invocation_has_terminal_result"].reason, Reason.PARTIAL_EXECUTION
        )


class ClaimTallyTests(unittest.TestCase):
    def test_counts_must_be_counts(self) -> None:
        with self.assertRaises(ValueError):
            ClaimTally("", 1, 1)
        with self.assertRaises(ValueError):
            ClaimTally("log", -1, 0)
        with self.assertRaises(ValueError):
            ClaimTally("log", True, 0)  # type: ignore[arg-type]

    def test_context_defaults_are_empty_facts(self) -> None:
        context = InvariantContext()
        results = evaluate_invariants(context)
        self.assertTrue(all(not result.applicable and result.holds is None for result in results))


class ParseDecimalTests(unittest.TestCase):
    def assertParsed(self, text: object, value: str, decimals: int, **marks: str) -> None:
        parsed = parse_decimal(text, **marks)  # type: ignore[arg-type]
        self.assertEqual(parsed.state, NUMBER_PARSED, parsed.detail)
        self.assertEqual((parsed.value, parsed.decimals), (Decimal(value), decimals))
        self.assertIsInstance(parsed.value, Decimal)

    def assertState(self, text: object, state: str, **marks: str) -> None:
        parsed = parse_decimal(text, **marks)  # type: ignore[arg-type]
        self.assertEqual(parsed.state, state, parsed.detail)
        self.assertIsNone(parsed.value)
        self.assertFalse(parsed.ok)

    def test_plain_numbers(self) -> None:
        self.assertParsed("12.4", "12.4", 1)
        self.assertParsed(" 12.40 ", "12.40", 2)
        self.assertParsed("-3", "-3", 0)
        self.assertParsed("+7", "7", 0)
        self.assertParsed("−0.5", "-0.5", 1)
        self.assertParsed(1234, "1234", 0)
        self.assertParsed(Decimal("1.50"), "1.50", 2)
        self.assertParsed(Decimal("1E+3"), "1000", 0)

    def test_declared_thousands_are_removed_only_in_regular_groups(self) -> None:
        self.assertParsed("1,234", "1234", 0, thousands=",")
        self.assertParsed("1,234,567.25", "1234567.25", 2, thousands=",")
        self.assertParsed("1234", "1234", 0, thousands=",")
        self.assertParsed("1.234,5", "1234.5", 1, thousands=".", decimal_point=",")
        self.assertState("12,34", AMBIGUOUS_SEPARATOR, thousands=",")
        self.assertState(",123", AMBIGUOUS_SEPARATOR, thousands=",")
        self.assertState("1.2,34", AMBIGUOUS_SEPARATOR, thousands=",")

    def test_undeclared_separators_are_ambiguous(self) -> None:
        for text in ("1,234", "1 234", "1_234", "1'234", "1 234", "1.234.567"):
            with self.subTest(text=text):
                self.assertState(text, AMBIGUOUS_SEPARATOR)
        self.assertState("1.234", AMBIGUOUS_SEPARATOR, decimal_point=",")

    def test_non_numbers(self) -> None:
        for text in ("", "  ", "abc", "1e3", "0x10", ".5", "5.", "-", "١٢", "NaN", "Infinity"):
            with self.subTest(text=text):
                self.assertState(text, NOT_A_NUMBER)
        self.assertState("1" * (MAX_NUMBER_LENGTH + 1), NOT_A_NUMBER)
        self.assertState(Decimal("NaN"), NOT_A_NUMBER)

    def test_floats_and_booleans_are_refused(self) -> None:
        for value in (0.1, True):
            with self.subTest(value=value), self.assertRaises(TypeError):
                parse_decimal(value)  # type: ignore[arg-type]

    def test_separator_declarations_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            parse_decimal("1", thousands=",", decimal_point=",")
        for bad in ("", "12", "5", "-", "−"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_decimal("1", thousands=bad)
            with self.subTest(bad=bad, mark="decimal_point"), self.assertRaises(ValueError):
                parse_decimal("1", decimal_point=bad)

    def test_serialization_has_no_floats(self) -> None:
        self.assertEqual(
            parse_decimal("12.40").to_dict(),
            {"text": "12.40", "state": "PARSED", "value": "12.40", "decimals": 2, "detail": ""},
        )


class CompareDecimalTests(unittest.TestCase):
    def assertOutcome(self, claim: str, stored: str, outcome: str, **options: object) -> None:
        comparison = compare_decimal(claim, stored, **options)  # type: ignore[arg-type]
        self.assertEqual(comparison.outcome, outcome, comparison.detail)

    def test_exact_agreement(self) -> None:
        self.assertOutcome("12.4", "12.4", EXACT)
        self.assertOutcome("12.40", "12.4", EXACT)
        comparison = compare_decimal("12.4", "12.4")
        self.assertEqual((comparison.agrees, comparison.verdict, comparison.reason), (True, Status.PASS, Reason.VERIFIED))

    def test_agreement_at_stated_precision_rounds_the_stored_value_half_even(self) -> None:
        comparison = compare_decimal("0.1", "0.14")
        self.assertEqual(
            (comparison.outcome, comparison.precision, comparison.rounded_stored), (AGREES_AT_STATED_PRECISION, 1, "0.1")
        )
        self.assertOutcome("12.4", "12.45", AGREES_AT_STATED_PRECISION)
        self.assertOutcome("12.5", "12.45", DISAGREES)
        self.assertOutcome("0.2", "0.15", AGREES_AT_STATED_PRECISION)
        self.assertOutcome("12", "12.49", AGREES_AT_STATED_PRECISION)
        self.assertEqual(compare_decimal("0.1", "0.14").to_dict()["rounding"], "ROUND_HALF_EVEN")

    def test_rounding_cannot_create_false_agreement(self) -> None:
        # Requirement 11: both values round to 0.1, yet they differ at the precision the claim prints.
        comparison = compare_decimal("0.15", "0.14")
        self.assertEqual((comparison.outcome, comparison.agrees), (DISAGREES, False))
        self.assertEqual((comparison.verdict, comparison.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertOutcome("0.10", "0.14", DISAGREES)
        self.assertOutcome("0.1", "0.15", DISAGREES)
        self.assertOutcome("12.4", "12.3", DISAGREES)

    def test_thousands_separators_cannot_evade_comparison(self) -> None:
        # Requirement 12.
        self.assertOutcome("1,234", "1234", EXACT, thousands=",")
        self.assertOutcome("1,234", "1,235", DISAGREES, thousands=",")
        self.assertOutcome("1,234.5", "1234.46", AGREES_AT_STATED_PRECISION, thousands=",")
        undeclared = compare_decimal("1,234", "1,234")
        # Identical ambiguous strings are not agreement: nobody established what they mean.
        self.assertEqual((undeclared.outcome, undeclared.agrees), (REQUIRES_HUMAN_REVIEW, None))
        self.assertEqual((undeclared.verdict, undeclared.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))
        self.assertOutcome("1234", "1,234", REQUIRES_HUMAN_REVIEW)

    def test_unreadable_values_require_review_and_are_never_false(self) -> None:
        comparison = compare_decimal("about 12", "12")
        self.assertEqual((comparison.outcome, comparison.agrees), (REQUIRES_HUMAN_REVIEW, None))
        self.assertIn("claim 'about 12'", comparison.detail)

    def test_declared_precision_must_match_what_the_claim_prints(self) -> None:
        self.assertOutcome("12.4", "12.4", EXACT, precision_decimals=1)
        self.assertOutcome("12.4", "12.4", REQUIRES_HUMAN_REVIEW, precision_decimals=2)
        for bad in (-1, True, "1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                compare_decimal("1", "1", precision_decimals=bad)  # type: ignore[arg-type]

    def test_large_values_round_without_trapping(self) -> None:
        wide = "123456789012345678901234567890"
        self.assertOutcome(f"{wide}.1", f"{wide}.14", AGREES_AT_STATED_PRECISION)

    def test_comparisons_serialize_canonically(self) -> None:
        data = compare_decimal("0.1", "0.14").to_dict()
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["stored"]["value"], "0.14")
        canonical_dumps(data)


if __name__ == "__main__":
    unittest.main()
