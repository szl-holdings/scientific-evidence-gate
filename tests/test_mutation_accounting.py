"""Mutation bookkeeping that can fail: extension #4, decision D12 and operator M21 (ARCHITECTURE.md 17.12).

The brief's acceptance cases (a)-(f) are proved here:

- (a) the demo report lists M00 first after the baseline, detected by ``ledger_chain_intact``;
- (b) a no-op application double makes the harness HARNESS_BLIND: no sensitivity key, no count keys, exit 1;
- (c) both conservation identities hold on the demo report and its buckets are disjoint;
- (d) removing one id from every bucket and verifying the report as evidence is FAIL / UNMEASURED_MUTANTS;
- (e) a byte-identical mutant is NOOP_MUTATION, excluded from executed, with a harness-defect diagnostic;
- (f) a verify that raises is VERIFIER_ERROR: not detected, still in the denominator, and the gate fails.

"The demo report" is the report of ``demo.BLIND_SPOT_MANIFEST``, the tree
``science-gate demo`` mutates. Everything else runs on
``fixtures/mutations/activation``, a three-row synthetic tree that mutates in
about a second. All data is synthetic and every verify is offline.
"""

from __future__ import annotations

import copy
import dataclasses
import inspect
import json
import os
import unittest
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, TempDirTestCase

from science_gate import invariants, mutations
from science_gate._canonical import pretty_json_bytes, sha256_bytes, strict_loads
from science_gate.demo import BLIND_SPOT_MANIFEST
from science_gate.ledger import Ledger
from science_gate.manifests import CheckSpec
from science_gate.models import (
    COUNTS_AS_DETECTED,
    EXECUTED_MUTATION_STATUSES,
    SKIP_JUSTIFICATION_KEY,
    ExecutionState,
    FailureMode,
    InputOverride,
    InputState,
    InvariantResult,
    MutationStatus,
    Reason,
    SkipJustification,
    Status,
    WitnessState,
)
from science_gate.mutations import (
    ALL_COUNT_KEYS,
    COUNT_KEYS,
    FORCED_DETECTION_ID,
    HARNESS_BLIND_MESSAGE,
    NO_EXECUTION_MESSAGE,
    NOT_ACTIVATED_MESSAGE,
    OPERATOR_IDS,
    OPERATORS,
    UNEXECUTED_STATUSES,
    UNMEASURED_MESSAGE,
    AppliedMutant,
    BaselineSummary,
    FileEdit,
    ForcedDetection,
    MutationRecord,
    MutationReport,
    Target,
    check_mutation_accounting,
    conservation,
    falsify_mutation_accounting,
    headline,
    mutate,
    render_markdown,
)
from science_gate.verifier import CheckParamError, verify

DEMO_MANIFEST = REPO_ROOT / BLIND_SPOT_MANIFEST
ACTIVATION = REPO_ROOT / "fixtures" / "mutations" / "activation"
ACTIVATION_MANIFEST = ACTIVATION / "manifest.json"
DIGEST = "0" * 64
M01, M04, M16 = "M01_empty_input", "M04_duplicate_row", "M16_truncated_ledger"


def headings(markdown: str) -> list[str]:
    return [line[3:] for line in markdown.splitlines() if line.startswith("## ")]


def with_locate(mutation_id: str, locate: Any) -> tuple[mutations.Operator, ...]:
    """The operator table with one operator's target search replaced (a test double)."""
    return tuple(
        dataclasses.replace(operator, locate=locate) if operator.mutation_id == mutation_id else operator
        for operator in OPERATORS
    )


def fixed_clock(test_class: type[unittest.TestCase]) -> None:
    patcher = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
    patcher.start()
    test_class.addClassCleanup(patcher.stop)


# ---------------------------------------------------------------------------
# The demo report: (a), (c), D12, M21
# ---------------------------------------------------------------------------


def verify_as_evidence(test: TempDirTestCase, document: dict[str, Any]) -> tuple[Any, Any]:
    """Verify a mutation report as declared evidence of a ``mutation_accounting`` check; returns the run and check."""
    data = pretty_json_bytes(document)
    test.write("reports/mutation-report.json", data)
    manifest = {
        "schema": "science-gate-manifest/v1",
        "run_label": "synthetic-mutation-accounting",
        "inputs": [
            {
                "id": "mutation_report",
                "path": "reports/mutation-report.json",
                "format": "json",
                "required": True,
                "sha256": sha256_bytes(data),
            }
        ],
        "checks": [
            {
                "id": "accounting",
                "kind": "mutation_accounting",
                "version": "1",
                "required": True,
                "inputs": ["mutation_report"],
            }
        ],
        "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
    }
    run = verify(test.write_manifest(manifest))
    (check,) = run.result.checks
    return run, check


class DemoReportTests(TempDirTestCase):
    """One mutation run of the demo tree, shared by every test in the class."""

    report: MutationReport
    document: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)
        cls.report = mutate(DEMO_MANIFEST)
        cls.document = strict_loads(pretty_json_bytes(cls.report.to_dict()), integers_only=True)

    def test_a_m00_runs_first_after_the_baseline_and_is_detected_by_the_chain_invariant(self) -> None:
        forced = self.document["forced_detection"]
        self.assertEqual(forced["mutation_id"], "M00_forced_detection")
        self.assertIs(forced["detected"], True)
        self.assertEqual(forced["detector"], "invariant:ledger_chain_intact")
        self.assertTrue(forced["detector"].endswith("ledger_chain_intact"))
        self.assertIn("invariant:ledger_chain_intact", {item["detector"] for item in forced["fired"]})
        self.assertIn("flip the first hex digit of the sealed ledger head", forced["target"])
        order = headings(render_markdown(self.report))
        after_baseline = order[order.index("BASELINE") + 1]
        self.assertEqual(after_baseline, "FORCED DETECTION", "M00 is listed first after the baseline")
        self.assertLess(order.index("FORCED DETECTION"), order.index("DETECTED"))

    def test_m00_is_never_an_operator_and_never_counted(self) -> None:
        ids = [record["mutation_id"] for record in self.document["mutations"]]
        self.assertNotIn(FORCED_DETECTION_ID, ids)
        self.assertNotIn(FORCED_DETECTION_ID, self.document["operators"])
        self.assertEqual(self.document["generated_mutations"], len(OPERATOR_IDS))
        self.assertNotIn(FORCED_DETECTION_ID, [item for ids in self.document["buckets"].values() for item in ids])

    def test_c_both_identities_hold_and_the_buckets_are_disjoint(self) -> None:
        balance = self.document["conservation"]
        self.assertEqual(
            (balance["generated_holds"], balance["executed_holds"], balance["disjoint"], balance["holds"]),
            (True, True, True, True),
        )
        buckets = self.document["buckets"]
        self.assertEqual(set(buckets), {status.value for status in MutationStatus}, "every member has a bucket")
        filed = [item for ids in buckets.values() for item in ids]
        self.assertEqual(len(filed), len(set(filed)), "no mutant sits in two buckets")
        self.assertEqual(sorted(filed), sorted(OPERATOR_IDS))
        self.assertEqual(balance["generated"], sorted(OPERATOR_IDS))
        executed = sorted(item for status in EXECUTED_MUTATION_STATUSES for item in buckets[status.value])
        unexecuted = sorted(item for status in UNEXECUTED_STATUSES for item in buckets[status.value])
        self.assertEqual(balance["executed"], executed)
        self.assertEqual(sorted(executed + unexecuted), balance["generated"])
        for record in self.document["mutations"]:
            with self.subTest(mutation=record["mutation_id"]):
                self.assertIn(record["mutation_id"], buckets[record["status"]])

    def test_counts_are_the_bucket_sizes_and_escaped_is_executed_minus_detected(self) -> None:
        document, buckets = self.document, self.document["buckets"]
        self.assertEqual(document["executed_mutations"], len(document["conservation"]["executed"]))
        self.assertEqual(document["detected_mutations"], len(buckets["DETECTED"]))
        self.assertEqual(document["escaped_mutations"], document["executed_mutations"] - document["detected_mutations"])
        for status, key in mutations.STATUS_COUNT_KEYS.items():
            self.assertEqual(document[key], len(buckets[status.value]), key)
        # The demo tree: 16 applicable operators, M05 and M06 escape as blind spots.
        self.assertEqual((document["executed_mutations"], document["detected_mutations"]), (16, 14))
        blind = ["M05_duplicate_reviewer_verdict", "M06_missing_required_reviewer"]
        self.assertEqual(sorted(buckets["BLIND_SPOT"]), blind)
        self.assertEqual(document["sensitivity"]["fraction"], "14/16")
        self.assertEqual((document["status"], document["reason"]), ("FAIL", "BLIND_SPOT"))

    def test_sampled_and_reused_are_recorded_false(self) -> None:
        self.assertIs(self.document["sampled"], False)
        self.assertIs(self.document["reused"], False)

    def test_the_detection_table_credits_only_detected_and_is_hashed_into_the_report_id(self) -> None:
        table = self.document["counts_as_detected"]
        self.assertEqual(table, {status.value: status is MutationStatus.DETECTED for status in MutationStatus})
        crediting = MappingProxyType({**COUNTS_AS_DETECTED, MutationStatus.VERIFIER_ERROR: True})
        with mock.patch.object(mutations, "COUNTS_AS_DETECTED", crediting):
            changed = self.report.report_id
        self.assertNotEqual(changed, self.report.report_id, "a different table must give a different report id")

    def test_d12_timed_out_and_flaky_exist_never_count_and_are_never_produced(self) -> None:
        for status in (MutationStatus.TIMED_OUT, MutationStatus.FLAKY):
            with self.subTest(status=status.value):
                self.assertIn(status, EXECUTED_MUTATION_STATUSES)
                self.assertIs(COUNTS_AS_DETECTED[status], False)
                self.assertEqual(self.document["buckets"][status.value], [])
        self.assertEqual((self.document["timed_out_mutations"], self.document["flaky_mutations"]), (0, 0))
        parameters = set(inspect.signature(mutate).parameters)
        self.assertFalse({"timeout", "time_budget", "budget"} & parameters, "D12: no mutation time budget exists")

    def test_the_demo_report_verified_as_evidence_passes_with_a_witness(self) -> None:
        run, check = verify_as_evidence(self, self.document)
        self.assertEqual((check.verdict, check.reason), (Status.PASS, Reason.VERIFIED), check.diagnostics)
        self.assertEqual(check.rows_examined, len(OPERATOR_IDS))
        self.assertEqual(check.evidence["falsification"], WitnessState.WITNESSED.value)
        (witness,) = check.evidence["falsifiers"]
        self.assertEqual((witness["case_id"], witness["outcome"]), ("drop-bucket-id", "REJECTED"))
        self.assertEqual(run.status, Status.PASS, [finding.to_dict() for finding in run.findings])

    def test_d_one_id_removed_from_every_bucket_is_unmeasured_mutants(self) -> None:
        document = copy.deepcopy(self.document)
        trimmed = [ids.pop(0) for ids in document["buckets"].values() if ids]
        self.assertEqual(len(trimmed), 3, "the demo report fills DETECTED, BLIND_SPOT and NOT_APPLICABLE")
        run, check = verify_as_evidence(self, document)
        self.assertEqual((check.verdict, check.reason), (Status.FAIL, Reason.UNMEASURED_MUTANTS))
        problems = check.evidence["problems"]
        self.assertTrue(any(text.startswith("IMBALANCE: generated") for text in problems), problems)
        self.assertTrue(any(text.startswith("IMBALANCE: the executed records") for text in problems), problems)
        self.assertIn(FailureMode.OMITTED_POPULATION, check.failure_modes)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.FAIL, Reason.UNMEASURED_MUTANTS, 1))

    def test_m21_is_detected_by_plan_closure_alone(self) -> None:
        (record,) = [item for item in self.report.mutations if item.mutation_id == "M21_removed_plan"]
        self.assertIs(record.status, MutationStatus.DETECTED)
        self.assertEqual({item.detector for item in record.detecting_invariants_fired}, {"invariant:plan_closure"})
        self.assertEqual(record.activation, {"mode": "replay", "activated": True})
        self.assertEqual(record.mutant_sha256, record.mutant_canonical_sha256)


# ---------------------------------------------------------------------------
# (b) a harness that cannot see its own planted defect
# ---------------------------------------------------------------------------


def no_op_application(target: Target, root: Path) -> AppliedMutant:
    """A test double for the single application point: it changes nothing at all."""
    return AppliedMutant()


class ForcedDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)

    def test_b_a_no_op_application_double_makes_the_harness_blind(self) -> None:
        with mock.patch.object(mutations, "apply_target", side_effect=no_op_application) as double:
            report = mutate(ACTIVATION_MANIFEST)
        self.assertEqual(double.call_count, 1, "the harness stops after M00: nothing else is applied")
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.HARNESS_BLIND, 1))
        document = report.to_dict()
        self.assertNotIn("sensitivity", document)
        for key in (*ALL_COUNT_KEYS, "buckets", "conservation", "mutations"):
            self.assertNotIn(key, document)
        self.assertIsNone(report.counts)
        self.assertEqual(report.mutations, ())
        self.assertEqual(document["message"], HARNESS_BLIND_MESSAGE)
        self.assertIs(document["forced_detection"]["detected"], False)
        self.assertEqual(document["forced_detection"]["fired"], [])
        self.assertIn(HARNESS_BLIND_MESSAGE, headline(report))
        self.assertEqual(
            headings(render_markdown(report)),
            ["STATUS", "BASELINE", "FORCED DETECTION", "WHAT THIS RESULT DOES NOT PROVE"],
        )

    def test_m00_goes_through_the_single_application_point_first(self) -> None:
        with mock.patch.object(mutations, "apply_target", wraps=mutations.apply_target) as spy:
            report = mutate(ACTIVATION_MANIFEST, operators=[M16])
        first_target = spy.call_args_list[0].args[0]
        self.assertEqual(first_target.description, report.forced_detection.target)
        self.assertEqual(spy.call_count, 2, "M00, then the one selected operator")
        self.assertTrue(report.forced_detection.detected)

    def test_m00_cannot_be_selected_or_deselected(self) -> None:
        with self.assertRaises(ValueError):
            mutate(ACTIVATION_MANIFEST, operators=[FORCED_DETECTION_ID])
        report = mutate(ACTIVATION_MANIFEST, operators=[])
        self.assertTrue(report.forced_detection.detected, "M00 runs even when no operator is selected")
        self.assertEqual((report.status, report.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(report.message, NO_EXECUTION_MESSAGE)

    def test_m00_needs_its_own_detector_not_just_a_non_pass_status(self) -> None:
        blind = MappingProxyType(
            {
                **invariants.INVARIANTS,
                "ledger_chain_intact": lambda ctx: InvariantResult("ledger_chain_intact", True, True, "blind double"),
            }
        )
        with mock.patch.object(invariants, "INVARIANTS", blind):
            report = mutate(ACTIVATION_MANIFEST, operators=[])
        self.assertEqual(report.reason, Reason.HARNESS_BLIND)
        self.assertFalse(report.forced_detection.detected)


# ---------------------------------------------------------------------------
# (e) no-op, canonically equivalent and duplicate mutants
# ---------------------------------------------------------------------------


class NoveltyTests(unittest.TestCase):
    honest: MutationReport

    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)
        cls.honest = mutate(ACTIVATION_MANIFEST)

    def run_with(self, mutation_id: str, locate: Any) -> tuple[MutationReport, MutationRecord, mock.Mock]:
        with mock.patch.object(mutations, "OPERATORS", with_locate(mutation_id, locate)):
            with mock.patch.object(mutations, "verify", wraps=verify) as spy:
                report = mutate(ACTIVATION_MANIFEST)
        (record,) = [item for item in report.mutations if item.mutation_id == mutation_id]
        return report, record, spy

    def assert_not_executed(self, report: MutationReport, record: MutationRecord) -> None:
        self.assertIs(record.execution_state, ExecutionState.SKIPPED)
        self.assertIsNone(record.detected)
        self.assertIsNone(record.blind_spot)
        self.assertIsNone(record.actual_result)
        self.assertIsNone(record.activation, "a mutant that is not new is never verified")
        self.assertEqual(report.counts["executed_mutations"], self.honest.counts["executed_mutations"] - 1)
        self.assertNotIn(record.mutation_id, report.conservation["executed"])
        self.assertTrue(report.conservation["holds"])

    def test_e_a_byte_identical_mutant_is_a_noop_and_a_harness_defect(self) -> None:
        data = (ACTIVATION / "data" / "samples.csv").read_bytes()
        edit = FileEdit("data/samples.csv", data)
        report, record, spy = self.run_with(M04, lambda ctx: Target("rewrite samples.csv with its own bytes", (edit,)))
        self.assertIs(record.status, MutationStatus.NOOP_MUTATION)
        self.assert_not_executed(report, record)
        self.assertEqual(record.mutant_sha256, report.baseline.digests["tree_sha256"])
        self.assertTrue(any("HARNESS_DEFECT" in text for text in record.diagnostics), record.diagnostics)
        self.assertEqual(report.counts["noop_mutations"], 1)
        verified = [call.args[0] for call in spy.call_args_list]
        self.assertFalse(any(Path(path).parent.name == M04 for path in verified), "a no-op is never verified")

    def test_a_layout_only_change_is_canonically_equivalent(self) -> None:
        graph = strict_loads((ACTIVATION / "graph" / "graph.json").read_bytes())
        relaid = (json.dumps(graph, indent=4) + "\n").encode("utf-8")
        edit = FileEdit("graph/graph.json", relaid)
        report, record, _ = self.run_with(M04, lambda ctx: Target("re-lay out graph.json", (edit,)))
        self.assertIs(record.status, MutationStatus.CANONICALLY_EQUIVALENT)
        self.assert_not_executed(report, record)
        self.assertNotEqual(record.mutant_sha256, report.baseline.digests["tree_sha256"])
        self.assertEqual(record.mutant_canonical_sha256, report.baseline.digests["tree_canonical_sha256"])
        self.assertEqual(report.counts["canonically_equivalent_mutations"], 1)

    def test_a_declared_input_keeps_its_raw_digest_so_reencoding_it_is_not_equivalent(self) -> None:
        (m07,) = [item for item in self.honest.mutations if item.mutation_id == "M07_changed_source_hash"]
        self.assertIs(m07.status, MutationStatus.DETECTED)
        self.assertNotEqual(m07.mutant_canonical_sha256, self.honest.baseline.digests["tree_canonical_sha256"])

    def test_a_mutant_identical_to_an_earlier_one_is_a_duplicate(self) -> None:
        (m01,) = [operator for operator in OPERATORS if operator.mutation_id == M01]
        report, record, _ = self.run_with(M04, m01.locate)
        self.assertIs(record.status, MutationStatus.DUPLICATE_MUTANT)
        self.assertEqual(record.duplicate_of, M01)
        self.assert_not_executed(report, record)
        (first,) = [item for item in report.mutations if item.mutation_id == M01]
        self.assertEqual(record.mutant_sha256, first.mutant_sha256)
        self.assertEqual(report.counts["duplicate_mutations"], 1)


# ---------------------------------------------------------------------------
# (f) a verify that raises
# ---------------------------------------------------------------------------


class VerifierErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)

    def test_f_a_raising_verify_is_not_detected_keeps_the_denominator_and_fails_the_gate(self) -> None:
        honest = mutate(ACTIVATION_MANIFEST, operators=[M01, M16])

        def crash_on_m01(path: Path, **kwargs: Any) -> Any:
            if Path(path).parent.name == M01:
                raise RuntimeError("synthetic engine defect")
            return verify(path, **kwargs)

        with mock.patch.object(mutations, "verify", side_effect=crash_on_m01):
            crashed = mutate(ACTIVATION_MANIFEST, operators=[M01, M16])
        (record,) = [item for item in crashed.mutations if item.mutation_id == M01]
        self.assertIs(record.status, MutationStatus.VERIFIER_ERROR)
        self.assertIs(record.detected, False)
        self.assertIs(record.execution_state, ExecutionState.CHECKED)
        self.assertEqual(record.actual_result["status"], "ERROR")
        self.assertEqual(honest.sensitivity["fraction"], "2/2")
        self.assertEqual(crashed.sensitivity["executed"], honest.sensitivity["executed"], "same denominator")
        self.assertEqual(crashed.sensitivity["fraction"], "1/2")
        self.assertEqual(crashed.counts["verifier_error_mutations"], 1)
        self.assertEqual(crashed.counts["blind_spot_mutations"], 0)
        self.assertEqual(crashed.counts["escaped_mutations"], 1)
        self.assertEqual((crashed.status, crashed.reason, crashed.exit_code), (Status.FAIL, Reason.PROTOCOL_BROKEN, 1))


# ---------------------------------------------------------------------------
# The identities and the report status, on synthetic records
# ---------------------------------------------------------------------------


def record(mutation_id: str, status: MutationStatus, mode: str = "file") -> MutationRecord:
    """A synthetic record that satisfies every field rule of its status."""
    observed = status in EXECUTED_MUTATION_STATUSES or status is MutationStatus.NOT_ACTIVATED
    built = status not in (MutationStatus.NOT_APPLICABLE, MutationStatus.SKIPPED, MutationStatus.SUPPRESSED)
    return MutationRecord(
        mutation_id=mutation_id,
        description="synthetic",
        target=None if status is MutationStatus.NOT_APPLICABLE else "synthetic target",
        expected_result={},
        expected_detector="input:EMPTY",
        status=status,
        actual_result={"status": "FAIL"} if observed else None,
        detecting_invariants_fired=() if observed else None,
        activation={"mode": mode, "activated": status is not MutationStatus.NOT_ACTIVATED} if observed else None,
        pie_stage="NOT_READ" if status is MutationStatus.BLIND_SPOT else None,
        mutant_sha256=DIGEST if built else None,
        mutant_canonical_sha256=DIGEST if built else None,
        duplicate_of="M00_original" if status is MutationStatus.DUPLICATE_MUTANT else None,
    )


def report_of(*records: MutationRecord, **fields: Any) -> MutationReport:
    baseline = BaselineSummary(Status.PASS, Reason.VERIFIED, "run-synthetic")
    return MutationReport(
        "manifest.json", None, FIXED_TIME, baseline, OPERATOR_IDS, ForcedDetection("synthetic", True), records, **fields
    )


class ConservationTests(unittest.TestCase):
    def test_a_balanced_population_satisfies_both_identities(self) -> None:
        buckets = {MutationStatus.DETECTED: ["M2"], MutationStatus.BLIND_SPOT: ["M3"], MutationStatus.SKIPPED: ["M1"]}
        balance = conservation(["M3", "M1", "M2"], ["M3", "M2"], buckets)
        self.assertEqual(balance["generated"], ["M1", "M2", "M3"], "lists are sorted")
        self.assertEqual(balance["executed"], ["M2", "M3"])
        self.assertTrue(balance["holds"])

    def test_each_identity_fails_on_its_own(self) -> None:
        unlisted = conservation(["M1", "M2"], ["M2"], {MutationStatus.DETECTED: ["M2"]})
        holds = (unlisted["generated_holds"], unlisted["executed_holds"], unlisted["disjoint"])
        self.assertEqual(holds, (False, True, True))
        buckets = {MutationStatus.DETECTED: ["M2"], MutationStatus.SKIPPED: ["M1"]}
        inflated = conservation(["M1", "M2"], ["M1", "M2"], buckets)
        self.assertEqual((inflated["generated_holds"], inflated["executed_holds"]), (False, False))
        overlap = conservation(
            ["M1"], ["M1"], {MutationStatus.DETECTED: ["M1"], MutationStatus.NOT_ACTIVATED: ["M1"]}
        )
        self.assertFalse(overlap["disjoint"])
        self.assertFalse(overlap["holds"])

    def test_an_unexecuted_mutant_counted_as_executed_is_unmeasured(self) -> None:
        records = (record("M1", MutationStatus.DETECTED), record("M2", MutationStatus.NOT_APPLICABLE))
        honest = report_of(*records)
        self.assertEqual((honest.status, honest.counts["executed_mutations"]), (Status.PASS, 1))
        inflated = report_of(*records, executed_partition=frozenset(MutationStatus))
        outcome = (inflated.status, inflated.reason, inflated.exit_code)
        self.assertEqual(outcome, (Status.FAIL, Reason.UNMEASURED_MUTANTS, 1))
        self.assertEqual(inflated.counts["executed_mutations"], 2, "case 3 shows the counts")
        self.assertIsNone(inflated.sensitivity)
        self.assertEqual(inflated.message, UNMEASURED_MESSAGE)
        self.assertIsNone(inflated.to_dict()["sensitivity"])


class StatusPrecedenceTests(unittest.TestCase):
    """Section 17.12's report status, first match wins (cases 3-8 on synthetic records)."""

    def test_case_4_file_mutants_verified_but_none_activated(self) -> None:
        report = report_of(
            record("M1", MutationStatus.NOT_ACTIVATED),
            record("M2", MutationStatus.NOT_ACTIVATED, mode="registry"),
            record("M3", MutationStatus.DETECTED, mode="replay"),
        )
        outcome = (report.status, report.reason, report.exit_code)
        self.assertEqual(outcome, (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, 2))
        self.assertEqual(report.message, NOT_ACTIVATED_MESSAGE)
        self.assertIsNone(report.sensitivity)
        self.assertEqual(report.counts["not_activated_mutations"], 2)

    def test_case_5_nothing_executed(self) -> None:
        report = report_of(record("M1", MutationStatus.NOT_APPLICABLE), record("M2", MutationStatus.SKIPPED))
        self.assertEqual((report.status, report.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(report.message, NO_EXECUTION_MESSAGE)
        self.assertIsNone(report.sensitivity)

    def test_case_6_a_blind_spot_outranks_a_verifier_error(self) -> None:
        report = report_of(
            record("M1", MutationStatus.DETECTED),
            record("M2", MutationStatus.BLIND_SPOT),
            record("M3", MutationStatus.VERIFIER_ERROR),
        )
        self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.BLIND_SPOT))
        self.assertEqual(report.sensitivity["fraction"], "1/3")

    def test_case_7_timeouts_flakes_and_crashes_fail_the_gate_and_are_never_detections(self) -> None:
        for status in (MutationStatus.VERIFIER_ERROR, MutationStatus.TIMED_OUT, MutationStatus.FLAKY):
            with self.subTest(status=status.value):
                report = report_of(record("M1", MutationStatus.DETECTED), record("M2", status))
                self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.PROTOCOL_BROKEN))
                self.assertEqual((report.counts["detected_mutations"], report.counts["executed_mutations"]), (1, 2))
                self.assertIs([item for item in report.mutations if item.mutation_id == "M2"][0].detected, False)

    def test_case_8_pass(self) -> None:
        report = report_of(record("M1", MutationStatus.DETECTED), record("M2", MutationStatus.NOT_APPLICABLE))
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.PASS, Reason.VERIFIED, 0))
        self.assertEqual(report.sensitivity["fraction"], "1/1")

    def test_the_count_keys_are_the_six_0_1_0_keys_plus_the_new_buckets(self) -> None:
        self.assertEqual(ALL_COUNT_KEYS[: len(COUNT_KEYS)], COUNT_KEYS)
        self.assertEqual(
            set(ALL_COUNT_KEYS[len(COUNT_KEYS) :]),
            {
                "generated_mutations",
                "blind_spot_mutations",
                "verifier_error_mutations",
                "timed_out_mutations",
                "flaky_mutations",
                "not_activated_mutations",
                "noop_mutations",
                "canonically_equivalent_mutations",
                "duplicate_mutations",
                "suppressed_mutations",
            },
        )
        self.assertEqual(set(UNEXECUTED_STATUSES) | EXECUTED_MUTATION_STATUSES, set(MutationStatus))
        self.assertFalse(set(UNEXECUTED_STATUSES) & EXECUTED_MUTATION_STATUSES)


# ---------------------------------------------------------------------------
# M21 can fail
# ---------------------------------------------------------------------------


class RemovedPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)

    def test_m21_escapes_when_plan_closure_is_blind(self) -> None:
        blind = MappingProxyType(
            {**invariants.INVARIANTS, "plan_closure": lambda ctx: InvariantResult("plan_closure", True, True, "blind")}
        )
        with mock.patch.object(invariants, "INVARIANTS", blind):
            report = mutate(ACTIVATION_MANIFEST, operators=["M21_removed_plan"])
        (m21,) = [item for item in report.mutations if item.mutation_id == "M21_removed_plan"]
        self.assertIs(m21.status, MutationStatus.BLIND_SPOT, "the resealed chain is intact, so nothing else catches it")
        self.assertEqual(m21.actual_result["status"], "PASS")
        self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.BLIND_SPOT))

    def test_m21_has_no_target_without_a_plan(self) -> None:
        ledger = Ledger("run-synthetic-no-plan")
        invocation = ledger.start(check_id="rows", check_kind="row_count", check_version="1")
        ledger.finish(invocation, verdict=Status.PASS, reason=Reason.VERIFIED, evidence={})
        ctx = SimpleNamespace(baseline=SimpleNamespace(ledger=ledger, result=SimpleNamespace(run_id=ledger.run_id)))
        (m21,) = [operator for operator in OPERATORS if operator.mutation_id == "M21_removed_plan"]
        located = m21.locate(ctx)
        self.assertIsInstance(located, mutations.NotApplicable)
        self.assertIn("PLAN", located.reason)


# ---------------------------------------------------------------------------
# The mutation_accounting check and its falsifier
# ---------------------------------------------------------------------------

SPEC = CheckSpec(check_id="accounting", kind="mutation_accounting", version="1", required=True, inputs=("report",))


def synthetic_report() -> dict[str, Any]:
    """A balanced v2 report body: three generated mutants, two executed."""
    statuses = {
        "M01_empty_input": "DETECTED",
        "M04_duplicate_row": "BLIND_SPOT",
        "M08_changed_author": "NOT_APPLICABLE",
    }
    buckets = {status.value: [] for status in MutationStatus}
    for mutation_id, status in statuses.items():
        buckets[status].append(mutation_id)
    return {
        "schema": "science-gate-mutation-report/v2",
        "report_id": "mut-0000000000000000",
        "counts_as_detected": {status.value: status is MutationStatus.DETECTED for status in MutationStatus},
        "buckets": buckets,
        "mutations": [{"mutation_id": key, "status": value} for key, value in statuses.items()],
        "executed_mutations": 2,
        "detected_mutations": 1,
        "escaped_mutations": 1,
        "generated_mutations": 3,
    }


def context(values: Any, *, state: InputState = InputState.PARSED, rows: int = 1, fmt: str = "json") -> Any:
    """A minimal stand-in for CheckContext: the one declared input, as discovery would admit it."""
    opened = SimpleNamespace(
        spec=SimpleNamespace(format=fmt),
        state=state,
        sha256=DIGEST,
        rows=tuple(SimpleNamespace(index=index, line=None, values=values) for index in range(1, rows + 1)),
    )
    return SimpleNamespace(inputs={"report": opened})


class AccountingCheckTests(unittest.TestCase):
    def judge(self, report: Any, **kwargs: Any) -> Any:
        return check_mutation_accounting(context(report, **kwargs), SPEC)

    def test_a_balanced_report_passes_with_its_identities_as_evidence(self) -> None:
        outcome = self.judge(synthetic_report())
        decided = (outcome.execution_state, outcome.verdict, outcome.reason)
        self.assertEqual(decided, (ExecutionState.CHECKED, Status.PASS, Reason.VERIFIED))
        self.assertEqual(outcome.rows_examined, 3, "rows_examined is the number of records")
        self.assertTrue(outcome.evidence["conservation"]["holds"])
        self.assertEqual(outcome.evidence["problems"], [])

    def assert_unmeasured(self, report: dict[str, Any], problem: str) -> Any:
        outcome = self.judge(report)
        self.assertEqual((outcome.verdict, outcome.reason), (Status.FAIL, Reason.UNMEASURED_MUTANTS))
        self.assertIn(FailureMode.DEFECTIVE_VERIFICATION, outcome.failure_modes)
        problems = outcome.evidence["problems"]
        self.assertTrue(any(text.startswith(problem) for text in problems), problems)
        return outcome

    def test_an_id_missing_from_its_bucket_is_an_omitted_mutant_and_breaks_its_identity(self) -> None:
        unexecuted = synthetic_report()
        unexecuted["buckets"]["NOT_APPLICABLE"] = []
        outcome = self.assert_unmeasured(unexecuted, "IMBALANCE: generated")
        self.assertIn(FailureMode.OMITTED_POPULATION, outcome.failure_modes)
        balance = outcome.evidence["conservation"]
        self.assertEqual((balance["generated_holds"], balance["executed_holds"]), (False, True))
        executed = synthetic_report()
        executed["buckets"]["BLIND_SPOT"] = []
        outcome = self.assert_unmeasured(executed, "IMBALANCE: the executed records")
        self.assertIn(FailureMode.OMITTED_POPULATION, outcome.failure_modes)
        self.assertFalse(outcome.evidence["conservation"]["executed_holds"])

    def test_an_id_in_two_buckets_is_an_overlap(self) -> None:
        report = synthetic_report()
        report["buckets"]["SKIPPED"] = ["M04_duplicate_row"]
        self.assert_unmeasured(report, "OVERLAP")

    def test_a_record_filed_under_another_status_is_misfiled(self) -> None:
        report = synthetic_report()
        report["buckets"]["DETECTED"], report["buckets"]["BLIND_SPOT"] = ["M04_duplicate_row"], ["M01_empty_input"]
        self.assert_unmeasured(report, "MISFILED")

    def test_a_stated_count_the_records_contradict(self) -> None:
        report = synthetic_report()
        report["executed_mutations"] = 3
        self.assert_unmeasured(report, "COUNT_MISMATCH: executed_mutations states 3")

    def test_a_detection_table_that_credits_a_crash(self) -> None:
        report = synthetic_report()
        report["counts_as_detected"]["VERIFIER_ERROR"] = True
        self.assert_unmeasured(report, "DETECTION_TABLE_MISMATCH")

    def test_a_report_without_buckets_is_skipped_as_malformed(self) -> None:
        for name, change in (
            ("no buckets", lambda report: report.pop("buckets")),
            ("0.1.0 schema", lambda report: report.update(schema="science-gate-mutation-report/v1")),
            ("unknown status", lambda report: report["buckets"].update(KILLED=[])),
            ("record without status", lambda report: report["mutations"][0].pop("status")),
        ):
            with self.subTest(case=name):
                report = synthetic_report()
                change(report)
                outcome = self.judge(report)
                self.assertEqual((outcome.execution_state, outcome.verdict), (ExecutionState.SKIPPED, Status.ABSTAIN))
                self.assertEqual(outcome.evidence[SKIP_JUSTIFICATION_KEY], SkipJustification.EVIDENCE_MALFORMED.value)
                self.assertEqual(outcome.reason, Reason.PROTOCOL_BROKEN)
                self.assertEqual(outcome.rows_examined, 0)

    def test_inputs_that_hold_no_report_are_labelled_never_passed(self) -> None:
        cases = (
            ({"rows": 0, "state": InputState.EMPTY}, ExecutionState.NOT_APPLICABLE, SkipJustification.EMPTY_POPULATION),
            (
                {"rows": 0, "state": InputState.MISSING},
                ExecutionState.NOT_APPLICABLE,
                SkipJustification.INPUT_UNAVAILABLE,
            ),
            ({"state": InputState.HASH_MISMATCH}, ExecutionState.NOT_APPLICABLE, SkipJustification.SOURCE_REJECTED),
            ({"rows": 2}, ExecutionState.SKIPPED, SkipJustification.EVIDENCE_MALFORMED),
        )
        for kwargs, state, label in cases:
            with self.subTest(case=kwargs):
                outcome = self.judge(synthetic_report(), **kwargs)
                self.assertEqual((outcome.execution_state, outcome.verdict), (state, Status.ABSTAIN))
                self.assertEqual(outcome.evidence[SKIP_JUSTIFICATION_KEY], label.value)
        empty = synthetic_report()
        empty["mutations"], empty["buckets"] = [], {}
        outcome = self.judge(empty)
        self.assertEqual(outcome.evidence[SKIP_JUSTIFICATION_KEY], SkipJustification.EMPTY_POPULATION.value)
        self.assertNotEqual(outcome.verdict, Status.PASS)

    def test_wiring_other_than_one_json_input_is_refused(self) -> None:
        with self.assertRaises(CheckParamError):
            check_mutation_accounting(context(synthetic_report()), dataclasses.replace(SPEC, params={"strict": True}))
        with self.assertRaises(CheckParamError):
            two_inputs = dataclasses.replace(SPEC, inputs=("report", "other"))
            check_mutation_accounting(context(synthetic_report()), two_inputs)
        with self.assertRaises(CheckParamError):
            check_mutation_accounting(context(synthetic_report(), fmt="csv"), SPEC)

    def test_the_falsifier_drops_one_id_and_the_check_rejects_it(self) -> None:
        (case,) = falsify_mutation_accounting(context(synthetic_report()), SPEC, None)
        self.assertEqual(case.case_id, "drop-bucket-id")
        self.assertEqual((case.expected_verdict, case.expected_reason), (Status.FAIL, Reason.UNMEASURED_MUTANTS))
        (override,) = case.inputs.values()
        self.assertIsInstance(override, InputOverride)
        (changed,) = override.rows
        self.assertEqual(changed["buckets"]["DETECTED"], [], "the first non-empty bucket lost its first id")
        outcome = self.judge(changed)
        self.assertEqual((outcome.verdict, outcome.reason), (case.expected_verdict, case.expected_reason))

    def test_the_falsifier_has_no_case_without_a_non_empty_bucket(self) -> None:
        report = synthetic_report()
        report["buckets"] = {status.value: [] for status in MutationStatus}
        self.assertEqual(falsify_mutation_accounting(context(report), SPEC, None), ())
        self.assertEqual(falsify_mutation_accounting(context(report, rows=0), SPEC, None), ())


if __name__ == "__main__":
    unittest.main()
