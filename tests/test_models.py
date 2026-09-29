"""Vocabulary and result types (section 1)."""

from __future__ import annotations

import dataclasses
import os
import unittest
from decimal import Decimal
from unittest import mock

from science_gate._canonical import CanonicalizationError, canonical_dumps
from science_gate._redact import REDACTED
from science_gate.models import (
    ACCOUNTING_COUNTERS,
    BUILTIN_CHECK_KINDS,
    EXIT_CODE,
    TERMINAL_INVOCATION_RESULTS,
    AccessClass,
    AccountingCount,
    CheckResult,
    Closure,
    DenominatorSource,
    ExecutionState,
    FailureMode,
    InputAccounting,
    InputRecord,
    InputState,
    InvariantResult,
    InvocationResult,
    MetadataState,
    Permissions,
    Reason,
    ResolverState,
    RowCounts,
    RunResult,
    SignatureState,
    Status,
    Validity,
    invocation_result_for,
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
            "SOURCE_MISMATCH PROTOCOL_BROKEN PARTIAL_EXECUTION OUT_OF_SCOPE REQUIRES_HUMAN_REVIEW",
        )
        self.assertMembers(
            FailureMode,
            "VACUOUS_PASS NARRATED_VERIFICATION PARTIAL_EXECUTION DEFECTIVE_VERIFICATION OMITTED_POPULATION "
            "SOURCE_MISMATCH PROTOCOL_DRIFT EPHEMERAL_CLAIM STALE_DEPENDENCY",
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

    def test_builtin_check_kinds_are_the_section_5_table(self) -> None:
        self.assertEqual(
            BUILTIN_CHECK_KINDS,
            {
                "row_count", "required_columns", "duplicate_rows", "snapshot_completeness", "numeric_agreement",
                "reviewer_protocol", "time_source", "verification_log", "citation_resolver", "citation_metadata",
                "claim_registry", "dependency_currency", "summary_consistency",
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


if __name__ == "__main__":
    unittest.main()
