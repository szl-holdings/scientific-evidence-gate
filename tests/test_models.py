"""Vocabulary and result types (section 1)."""

from __future__ import annotations

import dataclasses
import os
import unittest
from decimal import Decimal
from fractions import Fraction
from unittest import mock

from science_gate._canonical import CanonicalizationError, canonical_dumps, sha256_bytes
from science_gate._redact import REDACTED
from science_gate.models import (
    ACCOUNTING_COUNTERS,
    BUILTIN_CHECK_KINDS,
    CONTROL_KEYS,
    COUNTS_AS_DETECTED,
    EITHER_HALF,
    EMPTY_AGGREGATE_OUTCOME,
    EXECUTED_MUTATION_STATUSES,
    EXIT_CODE,
    FALSIFICATION_OUTCOMES,
    NUMERIC_OUTCOME_VERDICTS,
    REJECTION_REASONS,
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    TERMINAL_INVOCATION_RESULTS,
    UNJUSTIFIED_SHORTFALL_OUTCOME,
    AccessClass,
    AccountingCount,
    AssertionKind,
    AssertionOutcome,
    AuthStatus,
    CheckResult,
    Closure,
    DenominatorSource,
    EditorialChannel,
    EditorialStatus,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    FalsifierOutcome,
    InputAccounting,
    InputOverride,
    InputRecord,
    InputState,
    InvariantResult,
    InvocationResult,
    MetadataState,
    MutationStatus,
    NoticeType,
    NumericOutcome,
    Permissions,
    PieStage,
    Ratio,
    RatioState,
    Reason,
    ResolverState,
    RoundingConvention,
    RowCounts,
    RunResult,
    SignatureState,
    SkipJustification,
    StaleCause,
    Status,
    Validity,
    VerdictLevel,
    VerdictTransition,
    WitnessState,
    empty_controls,
    fold_verdicts,
    invocation_result_for,
    join_verdicts,
    verdict_level,
)

DIGEST = "a" * 64


def check(**overrides: object) -> CheckResult:
    values: dict[str, object] = {
        "check_id": "rows",
        "kind": "row_count",
        "version": "1",
        "required": True,
        "execution_state": ExecutionState.CHECKED,
        "verdict": Status.PASS,
        "reason": Reason.VERIFIED,
        "rows_examined": 3,
        "inputs": ("measurements",),
        "evidence": {"rows_examined": 3},
        "invocation_id": "inv-000000000001",
    }
    values.update(overrides)
    return CheckResult(**values)  # type: ignore[arg-type]


def record(input_id: str = "measurements", **overrides: object) -> InputRecord:
    counts = RowCounts(admitted=3, excluded=0, deferred=0, unresolved=0, failed=0)
    values: dict[str, object] = {
        "input_id": input_id,
        "path": f"data/{input_id}.csv",
        "required": True,
        "format": "csv",
        "state": InputState.PARSED,
        "discovered": True,
        "opened": True,
        "parsed": True,
        "sha256": DIGEST,
        "declared_sha256": None,
        "size_bytes": 64,
        "rows": 3,
        "counts": counts,
        "closure": Closure.evaluate(DenominatorSource.INDEPENDENT, 3, counts.accounted),
    }
    values.update(overrides)
    return InputRecord(**values)  # type: ignore[arg-type]


def accounting(*records: InputRecord) -> InputAccounting:
    counters = {name: AccountingCount(len(records), DenominatorSource.OBSERVED) for name in ACCOUNTING_COUNTERS}
    counters["expected"] = AccountingCount(len(records), DenominatorSource.INDEPENDENT)
    counters["examined"] = AccountingCount(None, DenominatorSource.UNAVAILABLE)
    return InputAccounting(counters, Closure.evaluate(DenominatorSource.INDEPENDENT, len(records), len(records)), records)


class VocabularyTests(unittest.TestCase):
    def assertMembers(self, enum_type: type, names: str) -> None:
        self.assertEqual([member.value for member in enum_type], names.split())
        for member in enum_type:
            self.assertEqual(member.name, member.value)

    def test_enum_spellings_match_the_contract(self) -> None:
        self.assertMembers(Status, "PASS FAIL ABSTAIN ERROR")
        self.assertMembers(
            Reason,
            "VERIFIED UNVERIFIED INVALID_BASELINE BLIND_SPOT INSUFFICIENT_EVIDENCE SOURCE_UNAVAILABLE "
            "SOURCE_MISMATCH PROTOCOL_BROKEN PARTIAL_EXECUTION OUT_OF_SCOPE REQUIRES_HUMAN_REVIEW "
            "PROTOCOL_DRIFT HARNESS_BLIND UNMEASURED_MUTANTS",
        )
        self.assertMembers(
            FailureMode,
            "VACUOUS_PASS NARRATED_VERIFICATION PARTIAL_EXECUTION DEFECTIVE_VERIFICATION OMITTED_POPULATION "
            "SOURCE_MISMATCH PROTOCOL_DRIFT EPHEMERAL_CLAIM STALE_DEPENDENCY VACUOUS_CUTOFF",
        )
        self.assertMembers(ExecutionState, "CHECKED SKIPPED NOT_APPLICABLE")
        self.assertMembers(InvocationResult, "STARTED COMPLETED ERRORED ABSTAINED")
        self.assertMembers(DenominatorSource, "INDEPENDENT OBSERVED ESTIMATED UNAVAILABLE")
        self.assertMembers(
            Validity,
            "CURRENT STALE_PENDING_REVALIDATION REVALIDATED_UNCHANGED REVALIDATED_CHANGED SUPERSEDED "
            "INVALIDATED UNRESOLVED",
        )
        self.assertMembers(
            ResolverState, "DOI_RESOLVED DOI_NOT_RESOLVED_AT_CAPTURE DOI_TARGET_MISMATCH SOURCE_UNAVAILABLE"
        )
        self.assertMembers(
            MetadataState,
            "VERIFIED_WITHIN_DECLARED_SCOPE FIELD_MISMATCH CONFLATED_ENTRY RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES",
        )
        self.assertMembers(AccessClass, "PUBLIC REFERENCE_ONLY SYNTHETIC CONTROLLED_LOCAL")
        self.assertMembers(SignatureState, "UNSIGNED SIGNED_HMAC_SHA256")

    def test_frontier_enum_spellings_match_section_17(self) -> None:
        self.assertMembers(AuthStatus, "UNSIGNED SIGNED_VERIFIED SIGNED_FAILED SIGNED_UNCHECKED")
        self.assertMembers(
            SkipJustification,
            "EMPTY_POPULATION INPUT_UNAVAILABLE SOURCE_REJECTED EVIDENCE_MALFORMED NOT_DECLARED NO_DISCRIMINATION "
            "GUARDED_ELSEWHERE",
        )
        self.assertMembers(FalsifierOutcome, "REJECTED ACCEPTED INCONCLUSIVE")
        self.assertMembers(WitnessState, "WITNESSED REFUTED UNWITNESSED NO_CASE NO_GENERATOR")
        self.assertMembers(NumericOutcome, "CONSISTENT INCONSISTENT VACUOUSLY_CONSISTENT NOT_TESTABLE")
        self.assertMembers(RoundingConvention, "HALF_EVEN HALF_UP TRUNCATE CEILING FLOOR FLOAT_FIRST")
        self.assertMembers(
            MutationStatus,
            "DETECTED BLIND_SPOT VERIFIER_ERROR TIMED_OUT FLAKY NOT_ACTIVATED NOOP_MUTATION CANONICALLY_EQUIVALENT "
            "DUPLICATE_MUTANT SUPPRESSED SKIPPED NOT_APPLICABLE",
        )
        self.assertMembers(PieStage, "NOT_READ READ_NOT_INFECTED INFECTED_NOT_PROPAGATED PROPAGATED_NOT_CHECKED")
        self.assertMembers(AssertionKind, "TESTS_RUN COMMAND_EXECUTED FILE_CHECKED DATASET_VALIDATED TOOL_CALL")
        self.assertMembers(AssertionOutcome, "BACKED NARRATED CONTRADICTED ORPHANED")
        self.assertMembers(
            EditorialStatus,
            "NOT_RETRACTED_WITHIN_SCOPE RETRACTED REINSTATED CORRECTED EXPRESSION_OF_CONCERN UNDETERMINED",
        )
        self.assertMembers(NoticeType, "RETRACTION REINSTATEMENT CORRECTION EXPRESSION_OF_CONCERN")
        self.assertMembers(EditorialChannel, "CROSSREF_UPDATED_BY CROSSREF_RETRACTION_WATCH RETRACTION_WATCH_SNAPSHOT")
        self.assertMembers(StaleCause, "UPSTREAM VERIFIER")
        self.assertMembers(RatioState, "DEFINED ZERO_DENOMINATOR UNAVAILABLE")
        self.assertMembers(VerdictLevel, "NONE PASS ABSTAIN FAIL ERROR")

    def test_authentication_outcomes_are_not_signature_declarations(self) -> None:
        # A receipt declares whether it is signed; whether the signature holds is judged later.
        self.assertNotIn("SIGNED_FAILED", {member.value for member in SignatureState})
        self.assertNotIn("SIGNED_HMAC_SHA256", {member.value for member in AuthStatus})

    def test_exit_codes_follow_status_and_are_read_only(self) -> None:
        self.assertEqual(dict(EXIT_CODE), {Status.PASS: 0, Status.FAIL: 1, Status.ABSTAIN: 2, Status.ERROR: 3})
        with self.assertRaises(TypeError):
            EXIT_CODE[Status.PASS] = 2  # type: ignore[index]

    def test_enums_render_as_their_values(self) -> None:
        self.assertEqual(str(Status.PASS), "PASS")
        self.assertEqual(f"{Reason.UNVERIFIED}", "UNVERIFIED")

    def test_started_is_the_only_non_terminal_invocation_result(self) -> None:
        self.assertEqual(set(InvocationResult) - TERMINAL_INVOCATION_RESULTS, {InvocationResult.STARTED})

    def test_ledger_result_is_derived_from_the_verdict(self) -> None:
        self.assertIs(invocation_result_for(Status.PASS), InvocationResult.COMPLETED)
        self.assertIs(invocation_result_for("FAIL"), InvocationResult.COMPLETED)
        self.assertIs(invocation_result_for(Status.ABSTAIN), InvocationResult.ABSTAINED)
        self.assertIs(invocation_result_for(Status.ERROR), InvocationResult.ERRORED)

    def test_builtin_check_kinds_are_the_section_5_table_plus_section_17_16(self) -> None:
        self.assertEqual(
            BUILTIN_CHECK_KINDS,
            {
                "row_count", "required_columns", "duplicate_rows", "snapshot_completeness", "numeric_agreement",
                "reviewer_protocol", "time_source", "verification_log", "citation_resolver", "citation_metadata",
                "claim_registry", "dependency_currency", "summary_consistency",
                "claim_join", "editorial_status", "mutation_accounting",
            },
        )


class PermissionsTests(unittest.TestCase):
    def test_defaults_allow_evaluation_only(self) -> None:
        self.assertEqual(
            Permissions().to_dict(),
            {
                "evaluation_allowed": True,
                "training_allowed": False,
                "redistribution_allowed": False,
                "derivatives_allowed": False,
                "public_display_allowed": False,
                "commercial_use_allowed": False,
            },
        )

    def test_evaluation_permission_never_implies_training(self) -> None:
        self.assertFalse(Permissions(evaluation_allowed=True).training_allowed)

    def test_non_boolean_values_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            Permissions(training_allowed="yes")  # type: ignore[arg-type]


class CheckResultTests(unittest.TestCase):
    def test_pass_and_verified_occur_only_together(self) -> None:
        with self.assertRaises(ValueError):
            check(reason=Reason.UNVERIFIED)
        with self.assertRaises(ValueError):
            check(verdict=Status.ABSTAIN, reason=Reason.VERIFIED)

    def test_pass_or_fail_requires_the_check_to_have_run(self) -> None:
        for state in (ExecutionState.SKIPPED, ExecutionState.NOT_APPLICABLE):
            with self.subTest(state=state), self.assertRaises(ValueError):
                check(execution_state=state)
            with self.subTest(state=state, verdict="FAIL"), self.assertRaises(ValueError):
                check(execution_state=state, verdict=Status.FAIL, reason=Reason.SOURCE_MISMATCH)

    def test_skipped_and_not_applicable_can_abstain_or_error(self) -> None:
        skipped = check(execution_state="SKIPPED", verdict="ABSTAIN", reason="PARTIAL_EXECUTION", rows_examined=None)
        self.assertIs(skipped.execution_state, ExecutionState.SKIPPED)
        errored = check(execution_state=ExecutionState.CHECKED, verdict=Status.ERROR, reason=Reason.PROTOCOL_BROKEN)
        self.assertIs(errored.verdict, Status.ERROR)

    def test_strings_are_coerced_and_unknown_values_refused(self) -> None:
        self.assertIs(check(verdict="PASS", reason="VERIFIED").verdict, Status.PASS)
        with self.assertRaises(ValueError):
            check(verdict="MAYBE")

    def test_sets_are_deduplicated_and_sorted(self) -> None:
        result = check(
            verdict=Status.FAIL,
            reason=Reason.SOURCE_MISMATCH,
            failure_modes=("SOURCE_MISMATCH", FailureMode.OMITTED_POPULATION, "SOURCE_MISMATCH"),
            inputs=("zeta", "alpha", "zeta"),
        )
        self.assertEqual(result.failure_modes, (FailureMode.OMITTED_POPULATION, FailureMode.SOURCE_MISMATCH))
        self.assertEqual(result.inputs, ("alpha", "zeta"))

    def test_rows_examined_must_be_a_real_count_or_none(self) -> None:
        for bad in (-1, True, 2.0, "3"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check(rows_examined=bad)
        self.assertIsNone(check(verdict="ABSTAIN", reason="INSUFFICIENT_EVIDENCE", rows_examined=None).rows_examined)

    def test_evidence_is_canonicalized_at_construction(self) -> None:
        with self.assertRaises(CanonicalizationError):
            check(evidence={"ratio": 0.5})
        result = check(evidence={"ratio": Decimal("0.50"), "states": {"b", "a"}})
        self.assertEqual(result.evidence, {"ratio": "0.50", "states": ["a", "b"]})

    def test_evidence_and_diagnostics_are_redacted(self) -> None:
        fake = "fake-synthetic-credential-0000"
        with mock.patch.dict(os.environ, {"SYNTHETIC_TEST_TOKEN": fake}):
            result = check(
                verdict=Status.ABSTAIN,
                reason=Reason.UNVERIFIED,
                evidence={"quoted": f"row said {fake}"},
                diagnostics=(f"cell value {fake}",),
            )
        rendered = canonical_dumps(result)
        self.assertNotIn(fake, rendered)
        self.assertIn(REDACTED, rendered)

    def test_to_dict_is_canonical_json(self) -> None:
        result = check()
        self.assertEqual(
            canonical_dumps(result),
            canonical_dumps(
                {
                    "check_id": "rows", "kind": "row_count", "version": "1", "required": True,
                    "execution_state": "CHECKED", "verdict": "PASS", "reason": "VERIFIED", "failure_modes": [],
                    "rows_examined": 3, "inputs": ["measurements"], "evidence": {"rows_examined": 3},
                    "diagnostics": [], "invocation_id": "inv-000000000001",
                }
            ),
        )


class InvariantResultTests(unittest.TestCase):
    def test_not_applicable_means_holds_is_none(self) -> None:
        with self.assertRaises(ValueError):
            InvariantResult("x", False, True, "vacuous")
        self.assertFalse(InvariantResult("x", False, None, "nothing to judge").violated)

    def test_applicable_must_reach_a_definite_answer(self) -> None:
        with self.assertRaises(ValueError):
            InvariantResult("x", True, None, "could not tell")
        self.assertTrue(InvariantResult("x", True, False, "broken").violated)
        self.assertFalse(InvariantResult("x", True, True, "fine").violated)


class AccountingTypesTests(unittest.TestCase):
    def test_absent_counts_are_unavailable_never_zero(self) -> None:
        self.assertEqual(
            AccountingCount(None, "UNAVAILABLE").to_dict(), {"value": None, "denominator_source": "UNAVAILABLE"}
        )
        with self.assertRaises(ValueError):
            AccountingCount(None, DenominatorSource.OBSERVED)
        with self.assertRaises(ValueError):
            AccountingCount(0, DenominatorSource.UNAVAILABLE)

    def test_row_counts_sum_only_when_every_disposition_is_known(self) -> None:
        self.assertEqual(RowCounts(1, 2, 3, 4, 5).accounted, 15)
        self.assertIsNone(RowCounts(1, 2, 3, 4, None).accounted)
        self.assertIsNone(RowCounts().accounted)

    def test_closure_is_judged_only_against_an_independent_source(self) -> None:
        self.assertTrue(Closure.evaluate("INDEPENDENT", 3, 3).holds)
        self.assertFalse(Closure.evaluate("INDEPENDENT", 3, 2).holds)
        for source in ("OBSERVED", "ESTIMATED", "UNAVAILABLE"):
            with self.subTest(source=source):
                self.assertIsNone(Closure.evaluate(source, 3, 3).holds)
        self.assertIsNone(Closure.evaluate("INDEPENDENT", 3, None).holds)

    def test_closure_cannot_claim_what_its_numbers_contradict(self) -> None:
        with self.assertRaises(ValueError):
            Closure(DenominatorSource.OBSERVED, True, 3, 3)
        with self.assertRaises(ValueError):
            Closure(DenominatorSource.INDEPENDENT, True, 3, 2)
        with self.assertRaises(ValueError):
            Closure(DenominatorSource.INDEPENDENT, True, None, None)
        self.assertEqual(
            Closure.evaluate("OBSERVED", 3, 3).to_dict(),
            {"source": "OBSERVED", "holds": None, "expected": 3, "accounted": 3},
        )

    def test_input_record_is_complete_only_when_parsed(self) -> None:
        self.assertTrue(record().complete)
        for state in set(InputState) - {InputState.PARSED}:
            with self.subTest(state=state):
                self.assertFalse(record(state=state).complete)

    def test_input_record_refuses_malformed_digests(self) -> None:
        for bad in ("A" * 64, "a" * 63, "not-a-digest"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                record(sha256=bad)

    def test_input_record_serializes_the_contract_fields(self) -> None:
        data = record().to_dict()
        for name in ("path", "sha256", "bytes", "rows", "state", "closure"):
            self.assertIn(name, data)
        self.assertEqual(data["closure"], {"source": "INDEPENDENT", "holds": True, "expected": 3, "accounted": 3})

    def test_accounting_requires_every_counter_and_sorts_records(self) -> None:
        result = accounting(record("zeta"), record("alpha"))
        self.assertEqual([item.input_id for item in result.records], ["alpha", "zeta"])
        self.assertEqual(list(result.to_dict()["counters"]), list(ACCOUNTING_COUNTERS))
        self.assertEqual(result.record("zeta").input_id, "zeta")
        with self.assertRaises(KeyError):
            result.record("absent")
        partial = dict(result.counters)
        del partial["examined"]
        with self.assertRaises(ValueError):
            dataclasses.replace(result, counters=partial)
        with self.assertRaises(ValueError):
            accounting(record("same"), record("same"))

    def test_examined_starts_unknown_and_is_filled_as_observed(self) -> None:
        result = accounting(record())
        self.assertIsNone(result.value("examined"))
        updated = result.with_examined(3)
        self.assertEqual(updated.counters["examined"].to_dict(), {"value": 3, "denominator_source": "OBSERVED"})
        self.assertIsNone(result.value("examined"))


class RunResultTests(unittest.TestCase):
    def run_result(self, **overrides: object) -> RunResult:
        values: dict[str, object] = {
            "status": Status.PASS,
            "reason": Reason.VERIFIED,
            "reasons": (),
            "failure_modes": (),
            "run_id": "run-synthetic-0001",
            "accounting": accounting(record()),
            "checks": (check(check_id="zeta"), check(check_id="alpha", invocation_id="inv-000000000002")),
            "invariants": (InvariantResult("b", True, True, ""), InvariantResult("a", False, None, "")),
            "evidence_manifest_sha256": DIGEST,
            "started_at": "2026-01-02T03:04:05Z",
            "completed_at": "2026-01-02T03:04:05Z",
            "counters": {"rows_examined": 3},
        }
        values.update(overrides)
        return RunResult(**values)  # type: ignore[arg-type]

    def test_pass_requires_verified(self) -> None:
        with self.assertRaises(ValueError):
            self.run_result(reason=Reason.UNVERIFIED)
        with self.assertRaises(ValueError):
            self.run_result(status=Status.ABSTAIN)

    def test_primary_reason_is_always_listed(self) -> None:
        result = self.run_result(status="ABSTAIN", reason="UNVERIFIED", reasons=("PARTIAL_EXECUTION",))
        self.assertEqual(result.reasons, (Reason.PARTIAL_EXECUTION, Reason.UNVERIFIED))
        self.assertEqual(result.exit_code, 2)

    def test_checks_and_invariants_are_sorted_and_unique(self) -> None:
        result = self.run_result()
        self.assertEqual([item.check_id for item in result.checks], ["alpha", "zeta"])
        self.assertEqual([item.name for item in result.invariants], ["a", "b"])
        with self.assertRaises(ValueError):
            self.run_result(checks=(check(), check()))
        with self.assertRaises(ValueError):
            self.run_result(invariants=(InvariantResult("a", False, None, ""),) * 2)

    def test_counters_refuse_floats_and_serialize_canonically(self) -> None:
        with self.assertRaises(CanonicalizationError):
            self.run_result(counters={"sensitivity": 0.5})
        first = canonical_dumps(self.run_result())
        second = canonical_dumps(self.run_result(checks=tuple(reversed(self.run_result().checks))))
        self.assertEqual(first, second)
        self.assertEqual(self.run_result().to_dict()["status"], "PASS")

    def test_controls_default_to_explicit_nulls_never_to_absent_keys(self) -> None:
        # Section 17.8: a run that produced no control says so key by key.
        controls = self.run_result().to_dict()["controls"]
        self.assertEqual(tuple(controls), CONTROL_KEYS)
        self.assertEqual(controls, empty_controls())
        self.assertEqual(controls["verdict_transitions"], [])
        self.assertTrue(all(controls[key] is None for key in CONTROL_KEYS if key != "verdict_transitions"))

    def test_controls_must_have_exactly_the_section_17_8_keys(self) -> None:
        with self.assertRaises(ValueError):
            self.run_result(controls={"plan": None})
        with self.assertRaises(ValueError):
            self.run_result(controls={**empty_controls(), "extra": 1})
        with self.assertRaises(ValueError):
            self.run_result(controls={**empty_controls(), "verdict_transitions": None})
        with self.assertRaises(CanonicalizationError):
            self.run_result(controls={**empty_controls(), "min_discrimination": {"ratio": 0.5}})
        transition = VerdictTransition(1, "check:rows", VerdictLevel.NONE, VerdictLevel.PASS, Reason.VERIFIED)
        recorded = self.run_result(controls={**empty_controls(), "verdict_transitions": [transition]})
        self.assertEqual(recorded.to_dict()["controls"]["verdict_transitions"], [transition.to_dict()])


class DecisionTableTests(unittest.TestCase):
    """The section 17 tables: each must be total over its enum and agree with D1 and D2."""

    def test_every_justified_shortfall_abstains_and_none_is_partial_execution(self) -> None:
        self.assertEqual(set(SKIP_JUSTIFICATION_OUTCOMES), set(SkipJustification))
        for label, (status, reason, modes) in SKIP_JUSTIFICATION_OUTCOMES.items():
            with self.subTest(label=label):
                self.assertIs(status, Status.ABSTAIN)
                self.assertIsNot(reason, Reason.PARTIAL_EXECUTION)
                self.assertNotIn(FailureMode.PARTIAL_EXECUTION, modes)
        self.assertEqual(
            SKIP_JUSTIFICATION_OUTCOMES[SkipJustification.EMPTY_POPULATION],
            (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.VACUOUS_PASS,)),
        )
        self.assertEqual(
            SKIP_JUSTIFICATION_OUTCOMES[SkipJustification.GUARDED_ELSEWHERE][:2],
            (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW),
        )
        self.assertEqual(SKIP_JUSTIFICATION_KEY, "skip_justification")

    def test_an_unjustified_shortfall_fails_as_partial_execution(self) -> None:
        self.assertEqual(
            UNJUSTIFIED_SHORTFALL_OUTCOME, (Status.FAIL, Reason.PARTIAL_EXECUTION, (FailureMode.PARTIAL_EXECUTION,))
        )

    def test_a_proven_miss_fails_and_unknown_coverage_abstains(self) -> None:
        self.assertEqual(set(FALSIFICATION_OUTCOMES), set(WitnessState) - {WitnessState.WITNESSED})
        self.assertEqual(
            FALSIFICATION_OUTCOMES[WitnessState.REFUTED],
            (Status.FAIL, Reason.BLIND_SPOT, (FailureMode.DEFECTIVE_VERIFICATION,)),
        )
        for state in (WitnessState.UNWITNESSED, WitnessState.NO_CASE, WitnessState.NO_GENERATOR):
            with self.subTest(state=state):
                self.assertEqual(
                    FALSIFICATION_OUTCOMES[state], (Status.ABSTAIN, Reason.BLIND_SPOT, (FailureMode.VACUOUS_PASS,))
                )

    def test_rejections_never_include_verified_or_missing_evidence(self) -> None:
        self.assertEqual(set(REJECTION_REASONS), {Status.FAIL, Status.ABSTAIN})
        self.assertEqual(REJECTION_REASONS[Status.FAIL], frozenset(set(Reason) - {Reason.VERIFIED}))
        for absent in (Reason.VERIFIED, Reason.INSUFFICIENT_EVIDENCE, Reason.SOURCE_UNAVAILABLE, Reason.OUT_OF_SCOPE):
            with self.subTest(reason=absent):
                self.assertNotIn(absent, REJECTION_REASONS[Status.ABSTAIN])

    def test_numeric_outcomes_map_to_representable_check_results(self) -> None:
        self.assertEqual(set(NUMERIC_OUTCOME_VERDICTS), set(NumericOutcome))
        passing = [outcome for outcome, row in NUMERIC_OUTCOME_VERDICTS.items() if row[1] is Status.PASS]
        self.assertEqual(passing, [NumericOutcome.CONSISTENT])
        self.assertIs(NUMERIC_OUTCOME_VERDICTS[NumericOutcome.NOT_TESTABLE][0], ExecutionState.NOT_APPLICABLE)
        self.assertIn(FailureMode.VACUOUS_PASS, NUMERIC_OUTCOME_VERDICTS[NumericOutcome.VACUOUSLY_CONSISTENT][3])
        for outcome, (state, verdict, reason, modes) in NUMERIC_OUTCOME_VERDICTS.items():
            with self.subTest(outcome=outcome):
                check(execution_state=state, verdict=verdict, reason=reason, failure_modes=modes)

    def test_either_half_is_the_two_half_rules(self) -> None:
        self.assertEqual(EITHER_HALF, {RoundingConvention.HALF_EVEN, RoundingConvention.HALF_UP})

    def test_only_detected_counts_and_timeouts_are_never_detections(self) -> None:
        self.assertEqual(set(COUNTS_AS_DETECTED), set(MutationStatus))
        self.assertEqual({status for status, counted in COUNTS_AS_DETECTED.items() if counted}, {MutationStatus.DETECTED})
        self.assertEqual(
            EXECUTED_MUTATION_STATUSES,
            {
                MutationStatus.DETECTED,
                MutationStatus.BLIND_SPOT,
                MutationStatus.VERIFIER_ERROR,
                MutationStatus.TIMED_OUT,
                MutationStatus.FLAKY,
            },
        )
        for excluded in (MutationStatus.NOT_ACTIVATED, MutationStatus.NOOP_MUTATION, MutationStatus.SKIPPED):
            with self.subTest(status=excluded):
                self.assertNotIn(excluded, EXECUTED_MUTATION_STATUSES)


class VerdictLatticeTests(unittest.TestCase):
    def test_levels_are_ordered_with_none_at_the_bottom(self) -> None:
        self.assertIs(join_verdicts([]), VerdictLevel.NONE)
        self.assertIs(join_verdicts(["PASS", VerdictLevel.ABSTAIN]), VerdictLevel.ABSTAIN)
        self.assertIs(join_verdicts([VerdictLevel.FAIL, VerdictLevel.PASS]), VerdictLevel.FAIL)
        self.assertIs(join_verdicts([VerdictLevel.FAIL, VerdictLevel.ERROR, VerdictLevel.ABSTAIN]), VerdictLevel.ERROR)
        self.assertIs(verdict_level(Status.ABSTAIN), VerdictLevel.ABSTAIN)

    def test_none_is_never_a_status_and_an_empty_aggregate_abstains(self) -> None:
        with self.assertRaises(ValueError):
            Status("NONE")
        self.assertEqual(EMPTY_AGGREGATE_OUTCOME, (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(fold_verdicts([]), (VerdictLevel.NONE, ()))

    def test_the_transition_log_records_each_rise_and_where_it_happened(self) -> None:
        level, log = fold_verdicts(
            [
                ("check:rows", Status.PASS, Reason.VERIFIED),
                ("check:snapshot", "ABSTAIN", "UNVERIFIED"),
                ("check:values", Status.PASS, Reason.VERIFIED),
                ("invariant:ledger_chain_intact", Status.FAIL, Reason.PROTOCOL_BROKEN),
                ("contract:rows_examined", Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE),
            ]
        )
        self.assertIs(level, VerdictLevel.FAIL)
        self.assertEqual(
            [item.to_dict() for item in log],
            [
                {"step": 1, "source": "check:rows", "before": "NONE", "after": "PASS", "reason": "VERIFIED"},
                {"step": 2, "source": "check:snapshot", "before": "PASS", "after": "ABSTAIN", "reason": "UNVERIFIED"},
                {
                    "step": 4,
                    "source": "invariant:ledger_chain_intact",
                    "before": "ABSTAIN",
                    "after": "FAIL",
                    "reason": "PROTOCOL_BROKEN",
                },
            ],
        )

    def test_a_transition_must_rise(self) -> None:
        with self.assertRaises(ValueError):
            VerdictTransition(1, "check:x", VerdictLevel.FAIL, VerdictLevel.PASS, Reason.VERIFIED)
        with self.assertRaises(ValueError):
            VerdictTransition(0, "check:x", VerdictLevel.NONE, VerdictLevel.PASS, Reason.VERIFIED)


class RatioTests(unittest.TestCase):
    def test_a_defined_ratio_keeps_its_counts_and_an_exact_value(self) -> None:
        ratio = Ratio(72, 100)
        self.assertEqual(
            ratio.to_dict(),
            {
                "numerator": 72,
                "denominator": 100,
                "state": "DEFINED",
                "fraction": "72/100",
                "decimal": "0.72",
                "exact": True,
            },
        )
        self.assertEqual(ratio.value, Fraction(18, 25))
        self.assertEqual(Ratio(2, 4).fraction, "2/4", "counts are shown as counted, never reduced")
        self.assertEqual((Ratio(0, 9).decimal, Ratio(5, 5).decimal), ("0", "1"))

    def test_rounding_is_half_even_and_flagged_when_inexact(self) -> None:
        self.assertEqual((Ratio(20, 21).decimal, Ratio(20, 21).exact), ("0.9524", False))
        self.assertEqual(Ratio(1, 32).decimal, "0.0312", "0.03125 rounds half-even to 0.0312")

    def test_a_zero_denominator_is_never_zero_or_one_hundred_percent(self) -> None:
        empty = Ratio(0, 0)
        self.assertIs(empty.state, RatioState.ZERO_DENOMINATOR)
        self.assertEqual((empty.value, empty.decimal, empty.exact, empty.fraction), (None, None, None, "0/0"))

    def test_an_unknown_count_is_unavailable_never_zero(self) -> None:
        for ratio in (Ratio(None, 4), Ratio(3, None), Ratio(None, None)):
            with self.subTest(ratio=ratio):
                self.assertIs(ratio.state, RatioState.UNAVAILABLE)
                self.assertEqual((ratio.value, ratio.fraction, ratio.decimal), (None, None, None))

    def test_counts_must_be_a_real_proportion(self) -> None:
        for numerator, denominator in ((5, 4), (-1, 4), (True, 4), (1, 2.0)):
            with self.subTest(numerator=numerator, denominator=denominator), self.assertRaises(ValueError):
                Ratio(numerator, denominator)  # type: ignore[arg-type]

    def test_serializes_canonically(self) -> None:
        self.assertEqual(
            canonical_dumps(Ratio(1, 3)),
            '{"decimal":"0.3333","denominator":3,"exact":false,"fraction":"1/3","numerator":1,"state":"DEFINED"}',
        )


class FalsifierCaseTests(unittest.TestCase):
    def case(self, **overrides: object) -> FalsifierCase:
        values: dict[str, object] = {
            "case_id": "drop-last-row",
            "description": "the last admitted row is removed while expected_rows stays",
            "expected_verdict": Status.FAIL,
            "expected_reason": Reason.SOURCE_MISMATCH,
            "inputs": {"measurements": InputOverride([{"sample_id": "SYN-0001", "value": "1.5"}])},
        }
        values.update(overrides)
        return FalsifierCase(**values)  # type: ignore[arg-type]

    def test_a_case_records_what_it_replaced_without_quoting_documents(self) -> None:
        case = self.case(documents={"snapshots/./accepted.json": b'{"schema":"x"}'})
        self.assertEqual(
            case.to_dict(),
            {
                "case_id": "drop-last-row",
                "description": "the last admitted row is removed while expected_rows stays",
                "expected": {"verdict": "FAIL", "reason": "SOURCE_MISMATCH"},
                "inputs": ["measurements"],
                "documents": {"snapshots/accepted.json": sha256_bytes(b'{"schema":"x"}')},
            },
        )

    def test_an_expected_rejection_must_be_one_that_shows_power_to_reject(self) -> None:
        for verdict, reason in (
            (Status.PASS, Reason.VERIFIED),
            (Status.FAIL, Reason.VERIFIED),
            (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE),
            (Status.ERROR, Reason.PROTOCOL_BROKEN),
        ):
            with self.subTest(verdict=verdict, reason=reason), self.assertRaises(ValueError):
                self.case(expected_verdict=verdict, expected_reason=reason)
        accepted = self.case(expected_verdict="ABSTAIN", expected_reason="PROTOCOL_BROKEN")
        self.assertIs(accepted.expected_verdict, Status.ABSTAIN)

    def test_a_case_must_replace_something_and_name_it_safely(self) -> None:
        bad_cases = {
            "no override": {"inputs": {}},
            "unsafe path": {"documents": {"../outside.json": b"{}"}},
            "same file twice": {"documents": {"a/b.json": b"1", "a/./b.json": b"2"}},
            "text instead of bytes": {"documents": {"a.json": "{}"}},
            "bad case id": {"case_id": "control:falsifier"},
            "plain rows instead of an override": {"inputs": {"measurements": [{"a": "1"}]}},
        }
        for label, overrides in bad_cases.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                self.case(**overrides)

    def test_overrides_refuse_values_that_cannot_be_hashed_canonically(self) -> None:
        with self.assertRaises(CanonicalizationError):
            InputOverride([{"value": 0.5}])
        with self.assertRaises(ValueError):
            InputOverride("sample_id,value")  # type: ignore[arg-type]
        override = InputOverride(({"value": Decimal("1.50")},), columns=["value"])
        self.assertEqual(override.to_dict(), {"columns": ["value"], "rows": [{"value": "1.50"}]})


if __name__ == "__main__":
    unittest.main()
