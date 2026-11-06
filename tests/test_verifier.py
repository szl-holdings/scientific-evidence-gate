"""The engine: registry, built-in checks, run engine and the PASS decision (sections 5, 6 and 17)."""

from __future__ import annotations

import dataclasses
import json
import shutil
import unittest
from typing import Any

from _helpers import REPO_ROOT, TempDirTestCase, build_scenario
from _project import (
    EMPTY_MANIFEST,
    REVIEWERS,
    TIME_EVENT,
    VALID_MANIFEST,
    ProjectTestCase,
    check,
    reviews_document,
    time_document,
)

from science_gate._canonical import sha256_bytes, sha256_canonical
from science_gate.discovery import discover
from science_gate.invariants import ClaimTally
from science_gate.ledger import index_invocations
from science_gate.manifests import load_manifest
from science_gate.invariants import is_control
from science_gate.models import (
    BUILTIN_CHECK_KINDS,
    SKIP_JUSTIFICATION_KEY,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    InputOverride,
    InputState,
    InvocationResult,
    Reason,
    SkipJustification,
    Status,
    WitnessState,
)
from science_gate.verifier import (
    FALSIFIERS,
    REGISTRY,
    SUMMARY_SCHEMA,
    CheckContext,
    CheckOutcome,
    CheckUnavailable,
    DecisionInputs,
    NetworkPolicy,
    VerificationRun,
    build_snapshot,
    decide,
    ledger_evidence,
    resolve_check,
    verify,
)

# --- synthetic check functions registered only by these tests ---------------


def raising_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    raise RuntimeError("synthetic failure inside a check")


def non_outcome_check(ctx: CheckContext, spec: Any) -> Any:
    return {"verdict": "PASS"}


def vacuous_pass_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    return CheckOutcome(ExecutionState.CHECKED, Status.PASS, Reason.VERIFIED, rows_examined=0, evidence={"seen": 0})


def skipping_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    return CheckOutcome(
        ExecutionState.SKIPPED, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, rows_examined=0, evidence={"note": "no"}
    )


def labelled_skipping_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """The same skip, justified in the closed vocabulary (extension #24)."""
    evidence = {"note": "no", SKIP_JUSTIFICATION_KEY: SkipJustification.EMPTY_POPULATION.value}
    return CheckOutcome(
        ExecutionState.SKIPPED, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, rows_examined=0, evidence=evidence
    )


def free_text_skipping_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A skip "justified" only in prose: free text never justifies a skip."""
    evidence = {"note": "not needed here", SKIP_JUSTIFICATION_KEY: "BECAUSE_I_SAID_SO"}
    return CheckOutcome(
        ExecutionState.SKIPPED, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, rows_examined=0, evidence=evidence
    )


def narrating_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """Examines the rows honestly, but also claims eight verifications that no invocation record backs."""
    rows = ctx.inputs["measurements"].rows or ()
    if len(rows) < 6:
        return CheckOutcome(
            ExecutionState.CHECKED, Status.FAIL, Reason.SOURCE_MISMATCH, rows_examined=len(rows), evidence={"rows": len(rows)}
        )
    return CheckOutcome(
        ExecutionState.CHECKED,
        Status.PASS,
        Reason.VERIFIED,
        rows_examined=len(rows),
        evidence={"claimed_verified": 8, "invocation_records": 0},
        claim_tallies=(ClaimTally("citations claimed as verified", 8, 0),),
    )


def falsify_narrating(ctx: CheckContext, spec: Any, result: Any) -> tuple[FalsifierCase, ...]:
    """The narrating check does reject a short input, so its PASS is witnessed."""
    opened = ctx.inputs["measurements"]
    rows = tuple(dict(row.values) for row in opened.rows[:-1])
    override = InputOverride(rows, opened.columns)
    return (FalsifierCase("short", "one row fewer", Status.FAIL, Reason.SOURCE_MISMATCH, inputs={"measurements": override}),)


#: Kinds owned by specialist modules, which later stages implement.
SPECIALIST_KINDS = (
    "citation_metadata",
    "citation_resolver",
    "claim_join",
    "claim_registry",
    "dependency_currency",
    "editorial_status",
    "mutation_accounting",
    "verification_log",
)

TEST_REGISTRY = {
    **REGISTRY,
    "raises": f"{__name__}:raising_check",
    "returns_non_outcome": f"{__name__}:non_outcome_check",
    "vacuous_pass": f"{__name__}:vacuous_pass_check",
    "skips": f"{__name__}:skipping_check",
    "skips_with_label": f"{__name__}:labelled_skipping_check",
    "skips_with_prose": f"{__name__}:free_text_skipping_check",
    "narrates": f"{__name__}:narrating_check",
    "missing_function": f"{__name__}:no_such_function",
}
TEST_FALSIFIERS = {**FALSIFIERS, "narrates": f"{__name__}:falsify_narrating"}


class RegistryTests(unittest.TestCase):
    def test_registry_covers_exactly_the_contract_kinds(self) -> None:
        self.assertEqual(set(REGISTRY), set(BUILTIN_CHECK_KINDS))

    def test_specialist_kinds_point_at_their_owning_modules(self) -> None:
        self.assertEqual(REGISTRY["verification_log"], "science_gate.citations:check_verification_log")
        self.assertEqual(REGISTRY["citation_resolver"], "science_gate.citations:check_resolver")
        self.assertEqual(REGISTRY["citation_metadata"], "science_gate.citations:check_metadata")
        self.assertEqual(REGISTRY["claim_registry"], "science_gate.claims:check_claim_registry")
        self.assertEqual(REGISTRY["dependency_currency"], "science_gate.dependencies:check_dependency_currency")
        # Section 17.16.
        self.assertEqual(REGISTRY["claim_join"], "science_gate.assertions:check_claim_join")
        self.assertEqual(REGISTRY["editorial_status"], "science_gate.citations:check_editorial_status")
        self.assertEqual(REGISTRY["mutation_accounting"], "science_gate.mutations:check_mutation_accounting")

    def test_every_kind_names_a_negative_control_generator(self) -> None:
        # Section 17.5: a kind without a generator can never PASS, so every built-in kind has one.
        self.assertEqual(set(FALSIFIERS), set(BUILTIN_CHECK_KINDS))
        for kind, target in FALSIFIERS.items():
            with self.subTest(kind=kind):
                owner = REGISTRY[kind].partition(":")[0]
                self.assertEqual(target.partition(":")[0], owner, "a generator lives beside its checker")
                self.assertTrue(target.partition(":")[2].startswith("falsify_"))

    def test_every_generator_resolves(self) -> None:
        # Every builder has delivered its generator (section 17.1); one that stops resolving is a
        # regression, never a skip: its kind would end NO_GENERATOR and could never PASS.
        for kind, target in sorted(FALSIFIERS.items()):
            with self.subTest(kind=kind):
                self.assertTrue(callable(resolve_check(target)))

    def test_only_specialist_kinds_live_outside_the_verifier(self) -> None:
        outside = sorted(kind for kind, target in REGISTRY.items() if not target.startswith("science_gate.verifier:"))
        self.assertEqual(outside, list(SPECIALIST_KINDS))

    def test_every_target_resolves_to_a_callable(self) -> None:
        for kind, target in REGISTRY.items():
            with self.subTest(kind=kind):
                self.assertTrue(callable(resolve_check(target)))

    def test_unusable_targets_are_refused_with_a_reason(self) -> None:
        targets = ("no-colon", ":function", "module:", "science_gate.no_such_module:f", "science_gate.verifier:nope")
        for target in targets:
            with self.subTest(target=target), self.assertRaises(CheckUnavailable):
                resolve_check(target)


class FixtureTests(unittest.TestCase):
    """The committed fixtures: requirement 1 (empty) and requirement 2 (valid)."""

    def test_valid_fixture_passes_with_execution_evidence(self) -> None:
        run = verify(VALID_MANIFEST)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.PASS, Reason.VERIFIED, 0))
        kinds = {item.kind for item in run.result.checks}
        self.assertTrue(
            {"row_count", "required_columns", "duplicate_rows", "snapshot_completeness", "numeric_agreement"} <= kinds
        )
        for result in run.result.checks:
            with self.subTest(check=result.check_id):
                self.assertEqual((result.execution_state, result.verdict), (ExecutionState.CHECKED, Status.PASS))
                self.assertGreater(result.rows_examined, 0)
                self.assertTrue(result.evidence)
                self.assertIsNotNone(result.invocation_id)
                self.assertEqual(result.evidence["falsification"], WitnessState.WITNESSED.value)
        counters = run.result.counters
        self.assertEqual(counters["checks_executed"], counters["checks_expected"])
        self.assertEqual((counters["inputs_opened"], counters["rows_examined"]), (1, 6))
        self.assertTrue(all(item.holds for item in run.result.invariants if item.applicable))

    def test_empty_fixture_abstains_with_exit_2(self) -> None:
        run = verify(EMPTY_MANIFEST)
        self.assertEqual((run.status, run.exit_code), (Status.ABSTAIN, 2))
        self.assertEqual(run.result.accounting.record("measurements").state, InputState.EMPTY)
        self.assertEqual(run.result.counters["rows_examined"], 0)
        self.assertFalse([item for item in run.result.checks if item.verdict is Status.PASS])
        self.assertTrue(all(item.execution_state is ExecutionState.NOT_APPLICABLE for item in run.result.checks))
        self.assertIn(FailureMode.VACUOUS_PASS, run.result.failure_modes)


class InputCheckTests(ProjectTestCase):
    def test_starter_project_passes(self) -> None:
        self.assertEqual(self.run_verify().status, Status.PASS)

    def test_zero_examined_rows_can_never_pass(self) -> None:
        # Requirement 3: a header-only file is EMPTY; nothing is examined.
        self.write_data("sample_id,site,value,count\n")
        self.update_manifest(inputs=[{**self.manifest()["inputs"][0], "expected_rows": 0}])
        run = self.run_verify()
        self.assertEqual(run.status, Status.ABSTAIN)
        self.assertEqual(run.result.counters["rows_examined"], 0)
        self.assertIn("contract:rows_examined", [finding.source for finding in run.findings])

    def test_missing_required_file_remains_visible(self) -> None:
        # Requirement 6.
        document = self.manifest()
        document["inputs"].append({"id": "protocol", "path": "data/protocol.csv", "format": "csv"})
        self.save_manifest(document)
        run = self.run_verify()
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        record = run.result.accounting.record("protocol")
        self.assertEqual((record.state, record.sha256, record.rows), (InputState.MISSING, None, None))
        self.assertIn("input:protocol", [finding.source for finding in run.findings])
        absent = [item["name"] for item in run.evidence_manifest["absent"]]
        self.assertIn("protocol", absent)
        self.assertIn(FailureMode.OMITTED_POPULATION, run.result.failure_modes)

    def test_partial_input_cannot_appear_complete(self) -> None:
        # Requirement 7: rows beyond max_rows are counted but not admitted.
        self.update_manifest(limits={"max_rows": 3})
        run = self.run_verify()
        self.assertEqual(run.result.accounting.record("measurements").state, InputState.PARTIAL)
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.PARTIAL_EXECUTION))
        self.assertFalse([item for item in run.result.checks if item.verdict is Status.PASS])
        self.assertIn(FailureMode.PARTIAL_EXECUTION, run.result.failure_modes)
        # Accepted rows beyond max_rows were not examined; they were not deleted.
        snapshot = self.result_of(run, "snapshot")
        self.assertEqual((snapshot.verdict, snapshot.reason), (Status.ABSTAIN, Reason.PARTIAL_EXECUTION))
        not_examined = snapshot.evidence["inputs"]["measurements"]["not_examined_keys"]
        self.assertEqual(not_examined, [["SYN-0004"], ["SYN-0005"], ["SYN-0006"]])

    def test_duplicate_rows_are_detected(self) -> None:
        # Requirement 8: one exact duplicate, which also duplicates its row_key.
        lines = self.data_lines()
        self.write_data("".join(lines + [lines[1]]))
        run = self.run_verify()
        result = self.result_of(run, "duplicates")
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        evidence = result.evidence["inputs"]["measurements"]
        self.assertEqual((evidence["exact_duplicate_groups"], evidence["duplicate_key_groups"]), (1, 1))
        self.assertEqual(evidence["duplicate_keys"], [{"key": ["SYN-0001"], "lines": [2, 8]}])
        self.assertEqual(run.status, Status.FAIL)

    def test_deleted_row_is_detected_against_the_accepted_snapshot(self) -> None:
        # Requirement 9, even when the declared row count was lowered to hide it.
        lines = [line for line in self.data_lines() if not line.startswith("SYN-0003")]
        self.write_data("".join(lines))
        self.update_manifest(inputs=[{**self.manifest()["inputs"][0], "expected_rows": 5}])
        run = self.run_verify()
        result = self.result_of(run, "snapshot")
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.OMITTED_POPULATION, result.failure_modes)
        self.assertEqual(result.evidence["inputs"]["measurements"]["deleted_keys"], [["SYN-0003"]])
        self.assertEqual(self.result_of(run, "rows").verdict, Status.PASS)
        self.assertEqual(run.status, Status.FAIL)

    def test_changed_accepted_row_is_detected(self) -> None:
        self.write_data("".join(line.replace("8.00", "8.01") for line in self.data_lines()))
        result = self.result_of(self.run_verify(), "snapshot")
        self.assertEqual(result.verdict, Status.FAIL)
        self.assertEqual(result.evidence["inputs"]["measurements"]["changed_keys"], [["SYN-0005"]])
        self.assertIn(FailureMode.SOURCE_MISMATCH, result.failure_modes)

    def test_malformed_snapshot_is_protocol_broken(self) -> None:
        self.write_json("snapshots/accepted.json", {"schema": "some-other-schema/v9", "inputs": {}})
        result = self.result_of(self.run_verify(), "snapshot")
        state = (result.execution_state, result.verdict, result.reason)
        self.assertEqual(state, (ExecutionState.SKIPPED, Status.ABSTAIN, Reason.PROTOCOL_BROKEN))

    def test_missing_snapshot_abstains(self) -> None:
        (self.project / "snapshots" / "accepted.json").unlink()
        run = self.run_verify()
        result = self.result_of(run, "snapshot")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertIn("snapshots/accepted.json", [item["path"] for item in run.evidence_manifest["absent"]])

    def test_row_count_closure_against_an_independent_expectation(self) -> None:
        self.update_manifest(inputs=[{**self.manifest()["inputs"][0], "expected_rows": 7}])
        run = self.run_verify()
        result = self.result_of(run, "rows")
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.OMITTED_POPULATION, result.failure_modes)
        self.assertIn("invariant:input_accounting_closure", [finding.source for finding in run.findings])

    def test_missing_required_column_fails(self) -> None:
        self.set_checks(check("columns", "required_columns", params={"columns": ["sample_id", "batch"]}))
        result = self.result_of(self.run_verify(), "columns")
        self.assertEqual(result.verdict, Status.FAIL)
        self.assertEqual(result.evidence["inputs"]["measurements"]["missing_columns"], ["batch"])

    def test_hash_mismatch_fails_with_source_mismatch(self) -> None:
        self.write_data("".join(self.data_lines()[:-1]), declare_digest=False)
        run = self.run_verify()
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(run.result.accounting.record("measurements").state, InputState.HASH_MISMATCH)
        self.assertFalse([item for item in run.result.checks if item.verdict is Status.PASS])
        # Content that is not the declared artifact is never examined, and each check says why.
        self.assertEqual({item.reason for item in run.result.checks}, {Reason.SOURCE_MISMATCH})
        self.assertEqual({item.execution_state for item in run.result.checks}, {ExecutionState.NOT_APPLICABLE})

    def test_path_escaping_the_manifest_directory_is_an_error(self) -> None:
        self.write("outside.csv", "sample_id\nSYN-0001\n")
        self.update_manifest(inputs=[{"id": "measurements", "path": "../outside.csv", "format": "csv"}])
        self.set_checks(check("rows", "row_count"))
        run = self.run_verify()
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ERROR, Reason.PROTOCOL_BROKEN, 3))
        self.assertEqual(run.result.accounting.record("measurements").state, InputState.REFUSED)


class NumericAgreementTests(ProjectTestCase):
    def numeric(self, column: str, key: str, value: str, **params: Any) -> Any:
        params = {"column": column, "expected": [{"key": key, "value": value}], **params}
        self.set_checks(check("numbers", "numeric_agreement", params=params))
        return self.result_of(self.run_verify(), "numbers")

    def test_rounding_cannot_create_false_agreement(self) -> None:
        # Requirement 11: 0.14 rounds to 0.1, but a claim of 0.15 still disagrees.
        result = self.numeric("value", "SYN-0002", "0.15")
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(result.evidence["comparisons"][0]["outcome"], "DISAGREES")

    def test_agreement_at_stated_precision_is_reported_as_such(self) -> None:
        result = self.numeric("value", "SYN-0002", "0.1")
        self.assertEqual(result.verdict, Status.PASS)
        comparison = result.evidence["comparisons"][0]
        self.assertEqual((comparison["outcome"], comparison["precision"]), ("AGREES_AT_STATED_PRECISION", 1))

    def test_thousands_separators_cannot_evade_comparison(self) -> None:
        # Requirement 12: with the separator declared, "1,234" is compared as 1234.
        result = self.numeric("count", "SYN-0001", "1235", thousands=",")
        self.assertEqual(result.verdict, Status.FAIL)
        self.assertEqual(self.numeric("count", "SYN-0001", "1234", thousands=",").verdict, Status.PASS)

    def test_undeclared_separator_requires_human_review(self) -> None:
        result = self.numeric("count", "SYN-0001", "1234")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))

    def test_a_value_without_a_row_is_not_verified(self) -> None:
        result = self.numeric("value", "SYN-9999", "1.0")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))


class RoleDocumentCheckTests(ProjectTestCase):
    def enable_reviews(self, *reviewers: str) -> None:
        self.write_json("reviews/verdicts.json", reviews_document(*reviewers))
        self.update_manifest(reviews={"required_reviewers": REVIEWERS, "verdicts": "reviews/verdicts.json"})
        self.set_checks(check("reviews", "reviewer_protocol", inputs=()))

    def test_complete_review_protocol_passes(self) -> None:
        self.enable_reviews(*REVIEWERS)
        result = self.result_of(self.run_verify(), "reviews")
        self.assertEqual((result.verdict, result.rows_examined), (Status.PASS, 2))

    def test_missing_reviewer_is_protocol_broken(self) -> None:
        # Requirement 15.
        self.enable_reviews("reviewer-a")
        run = self.run_verify()
        result = self.result_of(run, "reviews")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
        self.assertIn(FailureMode.PROTOCOL_DRIFT, result.failure_modes)
        self.assertEqual(result.evidence["missing_reviewers"], ["reviewer-b"])
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))

    def test_duplicate_verdict_is_protocol_broken(self) -> None:
        self.enable_reviews("reviewer-a", "reviewer-b", "Reviewer-A")
        result = self.result_of(self.run_verify(), "reviews")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
        self.assertEqual(result.evidence["duplicate_verdicts"], {"reviewer-a": [1, 3]})

    def test_missing_verdicts_file_abstains(self) -> None:
        self.enable_reviews(*REVIEWERS)
        (self.project / "reviews" / "verdicts.json").unlink()
        result = self.result_of(self.run_verify(), "reviews")
        self.assertEqual((result.execution_state, result.verdict), (ExecutionState.SKIPPED, Status.ABSTAIN))

    def time_result(self, *events: dict[str, Any]) -> Any:
        self.write_json("time/events.json", time_document(*events))
        self.update_manifest(time_sources="time/events.json")
        self.set_checks(check("time", "time_source", inputs=()))
        run = self.run_verify()
        return run, self.result_of(run, "time")

    def test_consistent_observation_passes(self) -> None:
        _, result = self.time_result(TIME_EVENT)
        self.assertEqual((result.verdict, result.rows_examined), (Status.PASS, 1))

    def test_time_mismatch_is_source_mismatch(self) -> None:
        # Requirement 14: a shifted timezone no longer matches the recorded UTC.
        run, result = self.time_result({**TIME_EVENT, "timezone": "+03:00"})
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(result.evidence["outcomes"], {"UTC_MISMATCH": 1})
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))

    def test_observation_outside_the_window_is_source_mismatch(self) -> None:
        event = {**TIME_EVENT, "local_time": "2026-04-02T14:30:00", "utc": "2026-04-02T12:30:00Z"}
        _, result = self.time_result(event)
        self.assertEqual(result.verdict, Status.FAIL)
        self.assertEqual(result.evidence["outcomes"], {"OUTSIDE_WINDOW": 1})

    def test_undeclared_or_named_timezone_abstains(self) -> None:
        missing = {key: value for key, value in TIME_EVENT.items() if key != "timezone"}
        self.assertEqual(self.time_result(missing)[1].reason, Reason.INSUFFICIENT_EVIDENCE)
        named = {**TIME_EVENT, "timezone": "Region/Invented_City"}
        self.assertEqual(self.time_result(named)[1].reason, Reason.REQUIRES_HUMAN_REVIEW)

    def test_role_document_check_refuses_declared_inputs(self) -> None:
        self.enable_reviews(*REVIEWERS)
        self.set_checks(check("reviews", "reviewer_protocol"))
        result = self.result_of(self.run_verify(), "reviews")
        self.assertEqual(result.verdict, Status.ERROR)
        self.assertIn("UNEXPECTED_INPUTS", result.diagnostics[0])


PINNED_DOCUMENTS = ("claims/manuscript.md", "snapshots/accepted.json")


class SummaryConsistencyTests(ProjectTestCase):
    """Requirement 28: metadata changes beneath an unchanged PASS summary."""

    def setUp(self) -> None:
        super().setUp()
        self.write_file("claims/manuscript.md", "Synthetic manuscript text. Mean value 12.4.\n")
        self.update_manifest(manuscript="claims/manuscript.md", summary_claim="claims/summary.json")
        self.add_checks(check("summary", "summary_consistency", inputs=()))

    def write_summary(self, *, documents: tuple[str, ...] = PINNED_DOCUMENTS) -> None:
        self.write_json(
            "claims/summary.json",
            {
                "schema": SUMMARY_SCHEMA,
                "status": "PASS",
                "pinned": {
                    "inputs": {"measurements": {"sha256": self.file_digest("data/measurements.csv"), "rows": 6}},
                    "documents": {path: self.file_digest(path) for path in documents},
                },
            },
        )

    def test_summary_matching_the_recomputation_passes(self) -> None:
        self.write_summary()
        run = self.run_verify()
        self.assertEqual(self.result_of(run, "summary").verdict, Status.PASS)
        self.assertEqual(run.status, Status.PASS)

    def test_metadata_change_beneath_an_unchanged_pass_summary_is_detected(self) -> None:
        self.write_summary()
        self.write_file("claims/manuscript.md", "Synthetic manuscript text. Mean value 12.5.\n")
        result = self.result_of(self.run_verify(), "summary")
        self.assertEqual((result.verdict, result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(result.evidence["documents"]["claims/manuscript.md"]["outcome"], "CHANGED")

    def test_unpinned_metadata_is_reported_as_a_blind_spot(self) -> None:
        self.write_summary(documents=("snapshots/accepted.json",))
        result = self.result_of(self.run_verify(), "summary")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
        self.assertEqual(result.evidence["blind_spots"]["documents"], ["claims/manuscript.md"])

    def test_pass_summary_without_evidence_is_narrated(self) -> None:
        self.write_json("claims/summary.json", {"schema": SUMMARY_SCHEMA, "status": "PASS"})
        result = self.result_of(self.run_verify(), "summary")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        self.assertIn(FailureMode.NARRATED_VERIFICATION, result.failure_modes)

    def test_malformed_pin_is_protocol_broken_not_a_change(self) -> None:
        pinned = {"inputs": {"measurements": {"sha256": "not-a-digest"}}}
        self.write_json("claims/summary.json", {"schema": SUMMARY_SCHEMA, "status": "PASS", "pinned": pinned})
        result = self.result_of(self.run_verify(), "summary")
        state = (result.execution_state, result.verdict, result.reason)
        self.assertEqual(state, (ExecutionState.SKIPPED, Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
        self.assertIn("MALFORMED_DOCUMENT", result.diagnostics[0])

    def test_unchecked_metadata_change_still_changes_the_evidence_manifest(self) -> None:
        self.write_summary()
        before = self.run_verify()
        self.write_file("claims/manuscript.md", "Synthetic manuscript text, edited.\n")
        self.set_checks(*[item for item in self.manifest()["checks"] if item["id"] != "summary"])
        after = self.run_verify()
        self.assertEqual((before.status, after.status), (Status.PASS, Status.PASS))
        self.assertNotEqual(before.result.evidence_manifest_sha256, after.result.evidence_manifest_sha256)


class EngineTests(ProjectTestCase):
    def verify_with(self, *checks: dict[str, Any]) -> Any:
        self.set_checks(*checks)
        return self.run_verify(registry=TEST_REGISTRY)

    def test_a_raising_check_is_errored_and_the_run_continues(self) -> None:
        run = self.verify_with(check("rows", "row_count"), check("boom", "raises"), check("dups", "duplicate_rows"))
        boom = self.result_of(run, "boom")
        self.assertEqual((boom.verdict, boom.execution_state), (Status.ERROR, ExecutionState.SKIPPED))
        self.assertIn("CHECK_RAISED: RuntimeError", boom.diagnostics[0])
        self.assertEqual(self.result_of(run, "dups").verdict, Status.PASS)
        self.assertEqual((run.status, run.exit_code), (Status.ERROR, 3))
        trace = index_invocations(run.ledger.entries)[boom.invocation_id]
        self.assertEqual(trace.result, InvocationResult.ERRORED)

    def test_every_verdict_points_to_a_terminal_invocation(self) -> None:
        # Requirements 21 and 22, over a run mixing PASS, ERROR and ABSTAIN.
        run = self.verify_with(check("rows", "row_count"), check("boom", "raises"), check("skip", "skips"))
        traces = index_invocations(run.ledger.entries)
        subjects = [trace for trace in traces.values() if not is_control(trace.check_id)]
        self.assertEqual(len(subjects), 3)
        # The controls: one falsifier for the PASS, the comparator and the two canaries; each terminal too.
        self.assertEqual(len(traces) - len(subjects), 4)
        self.assertTrue(all(trace.terminal for trace in traces.values()))
        for result in run.result.checks:
            with self.subTest(check=result.check_id):
                trace = traces[result.invocation_id]
                self.assertTrue(trace.terminal)
                self.assertEqual((trace.check_id, trace.verdict), (result.check_id, result.verdict))
        self.assertEqual(run.ledger.open_invocations(), ())
        self.assertTrue(run.ledger.verify().intact)

    def test_terminal_entries_record_everything_the_verdict_does_not(self) -> None:
        run = self.verify_with(check("rows", "row_count"), check("boom", "raises"))
        terminal = {entry["invocation_id"]: entry for entry in run.ledger.entries if entry["completed_at"] is not None}
        for result in run.result.checks:
            with self.subTest(check=result.check_id):
                entry = terminal[result.invocation_id]
                self.assertEqual(entry["evidence"], ledger_evidence(result.to_dict()))
                self.assertEqual((entry["verdict"], entry["reason"]), (result.verdict.value, result.reason.value))

    def test_unusable_outcomes_and_params_are_errors(self) -> None:
        run = self.verify_with(
            check("bad", "returns_non_outcome"),
            check("absent", "missing_function"),
            check("cols", "required_columns"),
            check("rows", "row_count", params={"minimum": 1}),
        )
        diagnostics = {item.check_id: item.diagnostics[0] for item in run.result.checks}
        self.assertTrue(all(item.verdict is Status.ERROR for item in run.result.checks))
        self.assertIn("INVALID_OUTCOME", diagnostics["bad"])
        self.assertIn("CHECK_UNAVAILABLE", diagnostics["absent"])
        self.assertIn("MISSING_PARAM", diagnostics["cols"])
        self.assertIn("UNKNOWN_PARAM", diagnostics["rows"])

    def test_a_pass_without_rows_is_refused_before_it_is_recorded(self) -> None:
        run = self.verify_with(check("rows", "row_count"), check("empty", "vacuous_pass"))
        result = self.result_of(run, "empty")
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertIn(FailureMode.VACUOUS_PASS, result.failure_modes)
        self.assertEqual(index_invocations(run.ledger.entries)[result.invocation_id].verdict, Status.ABSTAIN)
        self.assertEqual(run.status, Status.ABSTAIN)

    def test_a_required_check_that_did_not_run_blocks_pass(self) -> None:
        # Requirement 4, under D1: an unjustified shortfall on a required check is FAIL / PARTIAL_EXECUTION.
        run = self.verify_with(check("rows", "row_count"), check("skip", "skips"))
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))
        counters = run.result.counters
        self.assertEqual((counters["checks_executed"], counters["checks_expected"]), (1, 2))
        self.assertEqual((counters["checks_shortfall"], counters["checks_justified"]), (1, 0))
        self.assertIn("contract:checks_executed", [finding.source for finding in run.findings])

    def test_a_justified_skip_abstains_and_free_text_does_not_justify(self) -> None:
        # Extension #24: only a closed-vocabulary label justifies a skip, and then it abstains.
        labelled = self.verify_with(check("rows", "row_count"), check("skip", "skips_with_label"))
        self.assertEqual((labelled.status, labelled.result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertNotIn(FailureMode.PARTIAL_EXECUTION, labelled.result.failure_modes)
        self.assertEqual(labelled.result.counters["checks_justified"], 1)
        prose = self.verify_with(check("rows", "row_count"), check("skip", "skips_with_prose"))
        skipped = self.result_of(prose, "skip")
        self.assertEqual(skipped.verdict, Status.ERROR, "an unknown label is an invalid outcome, never a justification")
        self.assertIn("INVALID_OUTCOME", skipped.diagnostics[0])

    def test_narrated_verification_becomes_unverified(self) -> None:
        # Requirement 5: claims without invocations break checked_claims_le_invocations.
        self.set_checks(check("rows", "row_count"), check("log", "narrates"))
        run = self.run_verify(registry=TEST_REGISTRY, falsifiers=TEST_FALSIFIERS)
        self.assertEqual(self.result_of(run, "log").evidence["falsification"], WitnessState.WITNESSED.value)
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        self.assertIn(FailureMode.NARRATED_VERIFICATION, run.result.failure_modes)
        (violated,) = [item for item in run.result.invariants if item.violated]
        self.assertEqual(violated.name, "checked_claims_le_invocations")

    def test_specialist_kinds_never_pass_without_their_evidence(self) -> None:
        for kind in SPECIALIST_KINDS:
            with self.subTest(kind=kind):
                run = self.verify_with(check("rows", "row_count"), check("special", kind, inputs=()))
                self.assertNotEqual(self.result_of(run, "special").verdict, Status.PASS)
                self.assertNotEqual(run.status, Status.PASS)

    def test_optional_failure_is_visible_but_not_decisive(self) -> None:
        wrong = {"column": "value", "expected": [{"key": "SYN-0002", "value": "0.2"}]}
        optional = {**check("extra", "numeric_agreement", params=wrong), "required": False}
        run = self.verify_with(check("rows", "row_count"), optional)
        self.assertEqual(self.result_of(run, "extra").verdict, Status.FAIL)
        self.assertEqual((run.status, run.result.failure_modes), (Status.PASS, ()))

    def test_verification_is_deterministic(self) -> None:
        first, second = self.run_verify(), self.run_verify()
        self.assertEqual(first.result.to_dict(), second.result.to_dict())
        self.assertEqual(first.ledger.to_jsonl(), second.ledger.to_jsonl())
        self.assertEqual(first.evidence_manifest, second.evidence_manifest)

    def test_network_is_off_unless_asked_for(self) -> None:
        self.assertFalse(self.run_verify().network.live)
        self.assertTrue(self.run_verify(live=True).network.live)

        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise OSError("synthetic: the network is not available in tests")

        self.update_manifest(citations={"live": True})
        run = self.run_verify(network=NetworkPolicy(opener=refuse))
        self.assertTrue(run.network.live)
        self.assertIs(run.network.opener, refuse)


class InvalidManifestTests(TempDirTestCase):
    def test_malformed_manifest_is_an_error_run_with_evidence(self) -> None:
        self.fixed_clock()
        path = self.write("manifest.json", "{not json")
        run = verify(path)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ERROR, Reason.PROTOCOL_BROKEN, 3))
        self.assertEqual(run.findings[0].source, "manifest")
        self.assertIn("MALFORMED_JSON", run.findings[0].detail)
        self.assertEqual(run.evidence_manifest["entries"][0]["kind"], "manifest")
        self.assertIsNone(run.result.counters["checks_expected"])
        self.assertIsNone(run.result.accounting.value("expected"))

    def test_missing_manifest_is_listed_as_absent(self) -> None:
        run = verify(self.tmp / "no-manifest-here.json")
        self.assertEqual(run.status, Status.ERROR)
        self.assertIsNone(run.manifest_sha256)
        self.assertEqual(run.evidence_manifest["absent"][0]["kind"], "manifest")


class ContextTests(ProjectTestCase):
    def test_documents_are_confined_and_never_raise(self) -> None:
        self.write_file("docs/bad.json", "{broken")
        self.write("secret.json", "{}")
        manifest = load_manifest(self.manifest_path)
        _, opened = discover(manifest)
        ctx = CheckContext(manifest, opened)
        self.assertEqual(ctx.read_document("../secret.json", role="probe").state, InputState.REFUSED)
        self.assertEqual(ctx.read_document("docs/missing.json", role="probe").state, InputState.MISSING)
        broken = ctx.read_document("docs/bad.json", role="probe")
        self.assertEqual(broken.state, InputState.PARSE_ERROR)
        self.assertIsNotNone(broken.sha256)
        self.assertEqual(ctx.accepted_snapshot.state, InputState.PARSED)
        logged = {item["path"]: item["state"] for item in ctx.read_log()}
        self.assertEqual(logged["docs/bad.json"], "PARSED")  # bytes were read; parsing is per request
        self.assertEqual(logged["docs/missing.json"], "MISSING")

    def test_only_complete_inputs_can_be_accepted_into_a_snapshot(self) -> None:
        _, opened = discover(load_manifest(EMPTY_MANIFEST))
        with self.assertRaises(ValueError):
            build_snapshot(opened.values())


DEPENDENCIES = REPO_ROOT / "fixtures" / "dependencies" / "current"
#: Node files of the dependency fixture other than its declared input (data/measurements.csv).
NODE_DOCUMENTS = [
    "analysis/run-output.json",
    "analysis/site-means.csv",
    "conclusions/conclusion-1.md",
    "conclusions/conclusion-2.md",
    "design/protocol.md",
    "evidence/admitted.csv",
    "figures/figure-1.csv",
    "figures/table-2.csv",
]


class PreloadTests(TempDirTestCase):
    """Files specialist checks read are read before any check runs (verifier.PRELOADS)."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.project = self.tmp / "project"
        shutil.copytree(DEPENDENCIES, self.project)

    def manifest(self) -> dict[str, Any]:
        return json.loads((self.project / "manifest.json").read_text(encoding="utf-8"))

    def test_node_files_are_read_before_any_check_and_feed_the_run_id(self) -> None:
        manifest = load_manifest(self.project / "manifest.json")
        _, opened = discover(manifest)
        ctx = CheckContext(manifest, opened)
        ctx.preload(spec.kind for spec in manifest.checks)
        roles = {item["path"]: item["roles"] for item in ctx.read_log()}
        self.assertEqual(roles["figures/figure-1.csv"], ["dependencies.node"])
        self.assertIn("dependencies.state", roles["graph/graph-state.json"])
        self.assertNotIn("graph/graph-state.json", ctx.preloaded_evidence(), "a missing file has no digest to pin")
        self.assertIn("figures/figure-1.csv", ctx.preloaded_evidence())
        before = verify(self.project / "manifest.json").result.run_id
        figure = self.project / "figures" / "figure-1.csv"
        figure.write_bytes(figure.read_bytes() + b"synthetic-extra,0\n")
        self.assertNotEqual(verify(self.project / "manifest.json").result.run_id, before)

    def test_kinds_without_a_preload_read_only_role_documents(self) -> None:
        manifest = load_manifest(self.project / "manifest.json")
        _, opened = discover(manifest)
        ctx = CheckContext(manifest, opened)
        ctx.preload(["row_count"])
        self.assertEqual([item["path"] for item in ctx.read_log()], ["graph/graph.json"])

    def test_a_summary_that_does_not_pin_node_files_reports_them_as_blind_spots(self) -> None:
        document = self.manifest()
        document["summary_claim"] = "claims/summary.json"
        document["checks"].append({"id": "summary", "kind": "summary_consistency", "version": "1"})
        (self.project / "manifest.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
        data = (self.project / "data" / "measurements.csv").read_bytes()
        graph = (self.project / "graph" / "graph.json").read_bytes()
        summary = {
            "schema": SUMMARY_SCHEMA,
            "status": "PASS",
            "pinned": {
                "inputs": {"measurements": {"sha256": sha256_bytes(data)}},
                "documents": {"graph/graph.json": sha256_bytes(graph)},
            },
        }
        (self.project / "claims").mkdir()
        (self.project / "claims" / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        run = verify(self.project / "manifest.json")
        (result,) = [item for item in run.result.checks if item.check_id == "summary"]
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
        # The declared input is pinned as an input, never also demanded as a document.
        self.assertEqual(result.evidence["blind_spots"], {"inputs": [], "documents": NODE_DOCUMENTS})


def replay_inputs(run: VerificationRun, **overrides: Any) -> DecisionInputs:
    """The decision inputs of a sealed run, replayed: the facts ``verify`` handed to ``decide``."""
    assert run.manifest is not None
    seal = run.ledger.seal()
    values: dict[str, Any] = {
        "accounting": run.result.accounting,
        "checks": run.result.checks,
        "declared_checks": {spec.check_id: spec.required for spec in run.manifest.checks},
        "entries": run.ledger.entries,
        "ledger_head_sha256": seal["ledger_head_sha256"],
        "ledger_length": seal["ledger_length"],
        "run_id": run.result.run_id,
        "evidence_manifest": run.evidence_manifest["entries"],
        "rows_examined": run.result.counters["rows_examined"],
        "claim_tallies": tuple(tally for _, tally in run.claim_tallies),
        "expected_plan": run.plan,
        "pins": run.pins,
        "controls": run.result.controls,
    }
    values.update(overrides)
    return DecisionInputs(**values)


class DecideTests(ProjectTestCase):
    """``decide`` over the replayed facts of a sealed PASS run: precedence and the PASS contract."""

    def setUp(self) -> None:
        super().setUp()
        self.run = self.run_verify()

    def inputs(self, **overrides: Any) -> DecisionInputs:
        return replay_inputs(self.run, **overrides)

    def test_complete_evidence_passes(self) -> None:
        decision = decide(self.inputs())
        self.assertEqual((decision.status, decision.reason, decision.findings), (Status.PASS, Reason.VERIFIED, ()))
        self.assertEqual(decision.status, self.run.status, "a replay decides exactly what the run decided")

    def test_hand_assembled_facts_without_a_plan_or_witnesses_never_pass(self) -> None:
        # The section 4 scenario has PASS results but no PLAN and no falsifier invocations.
        scenario = build_scenario(self)
        seal = scenario.ledger.seal()
        decision = decide(
            DecisionInputs(
                accounting=scenario.accounting,
                checks=scenario.checks,
                declared_checks={"rows": True},
                entries=scenario.ledger.entries,
                ledger_head_sha256=seal["ledger_head_sha256"],
                ledger_length=seal["ledger_length"],
                run_id=scenario.ledger.run_id,
                evidence_manifest=scenario.evidence_manifest,
                rows_examined=3,
            )
        )
        self.assertEqual((decision.status, decision.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))
        violated = {item.name for item in decision.invariants if item.violated}
        self.assertEqual(violated, {"plan_closure", "pass_requires_falsifier_witness"})

    def test_zero_rows_blocks_pass(self) -> None:
        decision = decide(self.inputs(rows_examined=0))
        self.assertEqual((decision.status, decision.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))

    def test_a_declared_required_check_without_a_result_blocks_pass(self) -> None:
        # D1: "no result at all" is an unjustified shortfall, FAIL / PARTIAL_EXECUTION.
        declared = {**self.inputs().declared_checks, "never_ran": True}
        decision = decide(self.inputs(declared_checks=declared))
        self.assertEqual((decision.status, decision.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))
        violated = {item.name for item in decision.invariants if item.violated}
        self.assertIn("every_required_check_has_terminal_state", violated)
        (shortfall,) = [item for item in decision.findings if item.source == "contract:checks_executed"]
        self.assertIn("'never_ran' did not execute: it has no result", shortfall.detail)

    def test_empty_evidence_manifest_blocks_pass(self) -> None:
        decision = decide(self.inputs(evidence_manifest=[]))
        self.assertEqual(decision.status, Status.ABSTAIN)
        self.assertIn("contract:evidence_manifest", [finding.source for finding in decision.findings])

    def test_truncated_ledger_fails_against_its_seal(self) -> None:
        decision = decide(self.inputs(entries=self.run.ledger.entries[:-1]))
        self.assertEqual((decision.status, decision.reason), (Status.FAIL, Reason.PROTOCOL_BROKEN))

    def test_precedence_is_error_then_fail_then_abstain(self) -> None:
        failing = dataclasses.replace(self.run.result.checks[0], verdict=Status.FAIL, reason=Reason.SOURCE_MISMATCH)
        both = decide(self.inputs(checks=(failing,), rows_examined=0))
        # G3: the content failure names the reason, ahead of the unexplained shortfalls (no results).
        self.assertEqual((both.status, both.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(Reason.INSUFFICIENT_EVIDENCE, both.reasons)
        self.assertIn(Reason.PARTIAL_EXECUTION, both.reasons)
        errored = decide(self.inputs(checks=(failing,), manifest_issues=("SCHEMA_MISMATCH at /schema: synthetic",)))
        self.assertEqual((errored.status, errored.reason), (Status.ERROR, Reason.PROTOCOL_BROKEN))

    def test_counters_are_unknown_when_nothing_was_declared(self) -> None:
        counters = decide(self.inputs(declared_checks=None)).counters
        for name in ("checks_expected", "checks_executed", "checks_shortfall", "checks_justified", "control_invocations"):
            with self.subTest(counter=name):
                self.assertIsNone(counters[name])

    def test_counters_count_controls_and_shortfalls(self) -> None:
        counters = decide(self.inputs()).counters
        # Six falsifiers (one per PASS), the comparator and the two canaries.
        self.assertEqual(
            (counters["control_invocations"], counters["checks_shortfall"], counters["checks_justified"]), (9, 0, 0)
        )


class EvidenceManifestTests(ProjectTestCase):
    def test_every_entry_is_hashed_and_the_run_records_its_digest(self) -> None:
        run = self.run_verify()
        entries = run.evidence_manifest["entries"]
        self.assertEqual(
            [item["kind"] for item in entries],
            ["manifest", "input", "document"] + ["check_evidence"] * 6 + ["ledger"],
        )
        self.assertTrue(all(len(item["sha256"]) == 64 for item in entries))
        self.assertEqual(run.result.evidence_manifest_sha256, sha256_canonical(run.evidence_manifest))
        by_check = {item["name"]: item["sha256"] for item in entries if item["kind"] == "check_evidence"}
        for result in run.result.checks:
            self.assertEqual(by_check[result.check_id], sha256_canonical(result.evidence))

    def test_evidence_manifest_is_json_safe(self) -> None:
        run = self.run_verify()
        self.assertEqual(json.loads(json.dumps(run.evidence_manifest)), run.evidence_manifest)


if __name__ == "__main__":
    unittest.main()
