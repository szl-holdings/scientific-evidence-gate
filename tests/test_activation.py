"""Activation receipts and PIE-stage attribution of blind spots: extension #11 (ARCHITECTURE.md 17.12).

The brief's acceptance cases:

- (a) a harness that verifies the original tree instead of the copy makes every file operator NOT_ACTIVATED,
  with no sensitivity figure and ABSTAIN;
- (b) an operator on a file no check opens is BLIND_SPOT / NOT_READ;
- (c) a test-only check that reads column ``value`` but ignores it lets M10 through as
  BLIND_SPOT / PROPAGATED_NOT_CHECKED;
- (d) in the demo, every detected mutant has an activation record.

``fixtures/mutations/activation`` declares a dependency graph whose DESIGN
file no check reads (no ``dependency_currency`` check is declared), and has
no ``duplicate_rows`` check, so M18 and M04 are its two blind spots. The
test-only checks below are registered through ``mutate``'s ``registry`` and
``falsifiers`` parameters, exactly as a test may register a kind with
``verify``. All data is synthetic and every verify is offline.
"""

from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import SimpleNamespace
from typing import Any, Mapping
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, TempDirTestCase

from science_gate import mutations
from science_gate._canonical import pretty_json_bytes, sha256_bytes
from science_gate.demo import BLIND_SPOT_MANIFEST
from science_gate.manifests import CheckSpec
from science_gate.models import (
    SKIP_JUSTIFICATION_KEY,
    ExecutionState,
    FalsifierCase,
    InputOverride,
    InputState,
    MutationStatus,
    PieStage,
    Reason,
    SkipJustification,
    Status,
)
from science_gate.mutations import (
    FILE_MODE,
    NOT_ACTIVATED_MESSAGE,
    REGISTRY_MODE,
    REPLAY_MODE,
    MutationReport,
    mutate,
)
from science_gate.verifier import FALSIFIERS, REGISTRY, CheckContext, CheckOutcome, Findings, verify

ACTIVATION = REPO_ROOT / "fixtures" / "mutations" / "activation"
ACTIVATION_MANIFEST = ACTIVATION / "manifest.json"
DESIGN_FILE = "graph/design/protocol.md"
M10 = "M10_changed_numeric_value"
#: The operators with a target in the activation tree that verify a copy (M16, M17 and M21 replay instead).
COPY_OPERATORS = {
    "M01_empty_input",
    "M02_missing_expected_file",
    "M04_duplicate_row",
    "M07_changed_source_hash",
    "M15_skipped_required_checker",
    "M18_changed_upstream_design",
}
REPLAY_OPERATORS = {"M16_truncated_ledger", "M17_reordered_hash_chain", "M21_removed_plan"}


def by_id(report: MutationReport) -> dict[str, Any]:
    return {record.mutation_id: record for record in report.mutations}


def fixed_clock(test_class: type[unittest.TestCase]) -> None:
    patcher = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
    patcher.start()
    test_class.addClassCleanup(patcher.stop)


# ---------------------------------------------------------------------------
# Test-only checks for (c). They are looked up by "test_activation:<name>".
# ---------------------------------------------------------------------------


def _rows_or_skip(ctx: CheckContext, spec: CheckSpec) -> tuple[Any, ...] | CheckOutcome:
    opened = ctx.inputs.get(spec.inputs[0])
    rows = opened.rows if opened is not None else None
    if rows:
        return rows
    return CheckOutcome(
        execution_state=ExecutionState.NOT_APPLICABLE,
        verdict=Status.ABSTAIN,
        reason=Reason.INSUFFICIENT_EVIDENCE,
        rows_examined=0,
        evidence={SKIP_JUSTIFICATION_KEY: SkipJustification.EMPTY_POPULATION.value},
        diagnostics=("no rows to examine",),
    )


def _judge_rows(rows: tuple[Any, ...], *, read_value: bool) -> CheckOutcome:
    """A weak oracle: it requires a sample_id on every row and never judges the value."""
    findings = Findings()
    for row in rows:
        if read_value:
            row.values["value"]  # read, then ignored: the defect under test
        if "sample_id" not in row.values:  # a membership test is not a value read
            findings.fail(Reason.SOURCE_MISMATCH, f"record {row.index} has no sample_id")
    return findings.outcome(rows_examined=len(rows), evidence={"rows_read": len(rows)})


def read_value_but_ignore_it(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    rows = _rows_or_skip(ctx, spec)
    return rows if isinstance(rows, CheckOutcome) else _judge_rows(rows, read_value=True)


def never_read_value(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    rows = _rows_or_skip(ctx, spec)
    return rows if isinstance(rows, CheckOutcome) else _judge_rows(rows, read_value=False)


def falsify_weak_oracle(ctx: CheckContext, spec: CheckSpec, result: Any) -> tuple[FalsifierCase, ...]:
    """The known-bad case the weak oracle does reject: every record without its sample_id."""
    input_id = spec.inputs[0]
    rows = ctx.inputs[input_id].rows or ()
    stripped = tuple({"value": "0"} for _ in rows)
    case = FalsifierCase(
        case_id="drop-sample-id",
        description="remove sample_id from every record",
        expected_verdict=Status.FAIL,
        expected_reason=Reason.SOURCE_MISMATCH,
        inputs={input_id: InputOverride(rows=stripped, columns=("value",))},
    )
    return (case,)


# ---------------------------------------------------------------------------
# The honest harness on the activation tree: (b) and the activation records
# ---------------------------------------------------------------------------


class ActivationTreeTests(unittest.TestCase):
    report: MutationReport
    records: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)
        cls.report = mutate(ACTIVATION_MANIFEST)
        cls.records = by_id(cls.report)

    def test_b_an_operator_on_a_file_no_check_opens_is_a_blind_spot_not_read(self) -> None:
        record = self.records["M18_changed_upstream_design"]
        self.assertIs(record.status, MutationStatus.BLIND_SPOT)
        self.assertIs(record.pie_stage, PieStage.NOT_READ)
        self.assertEqual(record.actual_result["status"], "PASS")
        activation = record.activation
        self.assertIs(activation["activated"], True, "the verify did read its copy, just not the mutated file")
        self.assertEqual(activation["mutated_paths"], [DESIGN_FILE])
        self.assertEqual(activation["mutated_paths_read"], [])
        self.assertNotIn(DESIGN_FILE, activation["files_read"])
        self.assertTrue({"manifest.json", "data/samples.csv", "graph/graph.json"} <= set(activation["files_read"]))
        self.assertTrue(record.diagnostics[0].endswith("[NOT_READ]"))

    def test_a_defect_a_check_saw_but_its_detector_never_judged_is_propagated_not_checked(self) -> None:
        record = self.records["M04_duplicate_row"]
        self.assertIs(record.status, MutationStatus.BLIND_SPOT)
        self.assertIs(record.pie_stage, PieStage.PROPAGATED_NOT_CHECKED)
        self.assertEqual(record.actual_result["status"], "FAIL", "row_count noticed; duplicate_rows was never declared")

    def test_every_detection_read_every_mutated_path_from_its_copy(self) -> None:
        for mutation_id in sorted(COPY_OPERATORS - {"M04_duplicate_row", "M18_changed_upstream_design"}):
            record = self.records[mutation_id]
            with self.subTest(mutation=mutation_id):
                self.assertIs(record.status, MutationStatus.DETECTED, record.diagnostics)
                activation = record.activation
                self.assertIs(activation["activated"], True)
                self.assertEqual(activation["mutated_paths_read"], activation["mutated_paths"])
                expected_mode = REGISTRY_MODE if mutation_id.startswith("M15") else FILE_MODE
                self.assertEqual(activation["mode"], expected_mode)
        self.assertEqual(self.records["M15_skipped_required_checker"].activation["mutated_paths"], [])
        self.assertEqual(
            self.records["M01_empty_input"].activation["mutated_paths"], ["data/samples.csv", "manifest.json"]
        )

    def test_a_deleted_file_counts_as_read(self) -> None:
        record = self.records["M02_missing_expected_file"]
        self.assertIs(record.status, MutationStatus.DETECTED)
        self.assertEqual(record.activation["mutated_paths"], ["data/samples.csv"])
        self.assertEqual(record.activation["mutated_paths_read"], ["data/samples.csv"])

    def test_a_deleted_path_is_read_when_the_run_recorded_it_missing_even_without_an_open(self) -> None:
        def run(input_state: str, document_state: str) -> Any:
            record = SimpleNamespace(path="data/samples.csv", state=InputState(input_state))
            document = {"path": "graph/graph.json", "state": document_state}
            result = SimpleNamespace(accounting=SimpleNamespace(records=(record,)))
            return SimpleNamespace(result=result, documents=(document,))

        self.assertTrue(mutations._recorded_missing(run("MISSING", "PARSED"), "data/samples.csv"))
        self.assertTrue(mutations._recorded_missing(run("PARSED", "MISSING"), "graph/graph.json"))
        self.assertFalse(mutations._recorded_missing(run("PARSED", "PARSED"), "data/samples.csv"))
        self.assertFalse(mutations._recorded_missing(run("MISSING", "MISSING"), "other.csv"))

    def test_replay_operators_record_replay_activation(self) -> None:
        for mutation_id in sorted(REPLAY_OPERATORS):
            with self.subTest(mutation=mutation_id):
                self.assertEqual(self.records[mutation_id].activation, {"mode": REPLAY_MODE, "activated": True})

    def test_activation_records_name_relative_paths_only(self) -> None:
        document = self.report.to_dict()
        text = str(pretty_json_bytes(document), "utf-8")
        self.assertNotIn("science-gate-mutate-", text, "no temporary path is recorded")
        self.assertNotIn(str(REPO_ROOT), text, "no checkout path is recorded")
        paths = []
        for record in document["mutations"]:
            activation = record["activation"] or {}
            for field in ("files_read", "mutated_paths", "mutated_paths_read"):
                for path in activation.get(field, []):
                    with self.subTest(mutation=record["mutation_id"], field=field, path=path):
                        self.assertTrue(path)
                        self.assertFalse(PurePosixPath(path).is_absolute())
                        self.assertFalse(PureWindowsPath(path).anchor)
                        self.assertNotIn("..", PurePosixPath(path).parts)
                        self.assertNotIn("..", PureWindowsPath(path).parts)
                    paths.append(path)
        # A relative path may contain separators, as may a sensitivity fraction.
        self.assertIn("data/samples.csv", paths)


# ---------------------------------------------------------------------------
# (a) a harness that verifies the original tree
# ---------------------------------------------------------------------------


class OriginalTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)

    def assert_nothing_activated(self, report: MutationReport) -> None:
        records = by_id(report)
        for mutation_id in sorted(COPY_OPERATORS):
            record = records[mutation_id]
            with self.subTest(mutation=mutation_id):
                self.assertIs(record.status, MutationStatus.NOT_ACTIVATED, record.diagnostics)
                self.assertIs(record.activation["activated"], False)
                self.assertEqual(record.activation["files_read"], [])
                self.assertIsNone(record.detected, "NOT_ACTIVATED is excluded from executed")
                self.assertIs(record.execution_state, ExecutionState.SKIPPED)
        for mutation_id in sorted(REPLAY_OPERATORS):
            self.assertIs(records[mutation_id].status, MutationStatus.DETECTED)
        outcome = (report.status, report.reason, report.exit_code)
        self.assertEqual(outcome, (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, 2))
        self.assertIsNone(report.sensitivity)
        self.assertIsNone(report.to_dict()["sensitivity"])
        self.assertEqual(report.message, NOT_ACTIVATED_MESSAGE)
        self.assertEqual(report.counts["not_activated_mutations"], len(COPY_OPERATORS))
        self.assertEqual(report.counts["executed_mutations"], len(REPLAY_OPERATORS))
        self.assertTrue(report.conservation["holds"])

    def test_a_the_h07_harness_mutant_activates_nothing(self) -> None:
        report = mutations._mutate(ACTIVATION_MANIFEST, behaviour=mutations._Behaviour(verify_original_tree=True))
        self.assert_nothing_activated(report)

    def test_a_a_verify_double_that_reads_the_source_tree_activates_nothing(self) -> None:
        real = verify

        def original_tree(path: Path, **kwargs: Any) -> Any:
            if Path(path).parent.name == "baseline":
                return real(path, **kwargs)
            return real(ACTIVATION / Path(path).name, **kwargs)

        with mock.patch.object(mutations, "verify", side_effect=original_tree):
            report = mutate(ACTIVATION_MANIFEST)
        self.assert_nothing_activated(report)


# ---------------------------------------------------------------------------
# (c) a check that reads a value and ignores it
# ---------------------------------------------------------------------------


class ValueReadTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        shutil.copytree(ACTIVATION, self.tmp / "tree")
        data = (ACTIVATION / "data" / "samples.csv").read_bytes()
        manifest = {
            "schema": "science-gate-manifest/v1",
            "run_label": "synthetic-value-reader",
            "inputs": [
                {
                    "id": "samples",
                    "path": "data/samples.csv",
                    "format": "csv",
                    "required": True,
                    "sha256": sha256_bytes(data),
                    "row_key": ["sample_id"],
                    "expected_rows": 3,
                    "denominator_source": "INDEPENDENT",
                }
            ],
            "checks": [
                {
                    "id": "values",
                    "kind": "numeric_agreement",
                    "version": "1",
                    "required": True,
                    "inputs": ["samples"],
                    "params": {"column": "value", "expected": [{"key": "SYN-ACT-001", "value": "1.5"}]},
                }
            ],
            "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
        }
        self.manifest = self.write_manifest(manifest, "tree/manifest-values.json")

    def m10(self, kind_target: str | None) -> Any:
        options: dict[str, Any] = {}
        if kind_target is not None:
            options = {
                "registry": {**REGISTRY, "numeric_agreement": kind_target},
                "falsifiers": {**FALSIFIERS, "numeric_agreement": "test_activation:falsify_weak_oracle"},
            }
        report = mutate(self.manifest, operators=[M10], **options)
        self.assertTrue(report.baseline.valid, report.baseline.findings)
        return by_id(report)[M10], report

    def test_the_real_comparator_detects_the_changed_value(self) -> None:
        record, report = self.m10(None)
        self.assertIs(record.status, MutationStatus.DETECTED, record.diagnostics)
        self.assertIn("from 1.5 to 11.5", record.target)
        self.assertEqual(report.status, Status.PASS)

    def test_c_a_check_that_reads_value_but_ignores_it_is_propagated_not_checked(self) -> None:
        record, report = self.m10("test_activation:read_value_but_ignore_it")
        self.assertIs(record.status, MutationStatus.BLIND_SPOT)
        self.assertIs(record.pie_stage, PieStage.PROPAGATED_NOT_CHECKED)
        self.assertEqual(record.actual_result["status"], "PASS")
        self.assertGreater(record.activation["value_reads"], 0)
        self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.BLIND_SPOT))

    def test_a_check_that_never_reads_the_changed_cell_is_infected_not_propagated(self) -> None:
        record, _ = self.m10("test_activation:never_read_value")
        self.assertIs(record.status, MutationStatus.BLIND_SPOT)
        self.assertIs(record.pie_stage, PieStage.INFECTED_NOT_PROPAGATED, "only the value read separates the two")


# ---------------------------------------------------------------------------
# (d) the demo's detections all carry activation records
# ---------------------------------------------------------------------------


class DemoActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)
        cls.report = mutate(REPO_ROOT / BLIND_SPOT_MANIFEST)

    def test_d_every_detected_mutant_has_an_activation_record(self) -> None:
        detected = [record for record in self.report.mutations if record.status is MutationStatus.DETECTED]
        self.assertEqual(len(detected), 14)
        for record in detected:
            activation: Mapping[str, Any] = record.to_dict()["activation"]
            with self.subTest(mutation=record.mutation_id):
                self.assertIsNotNone(activation)
                self.assertIs(activation["activated"], True)
                if activation["mode"] == REPLAY_MODE:
                    continue
                self.assertTrue(activation["files_read"], "a detection read its own copy")
                self.assertEqual(activation["mutated_paths_read"], activation["mutated_paths"])
                if activation["mode"] == FILE_MODE:
                    self.assertTrue(activation["mutated_paths"])

    def test_every_blind_spot_names_its_stage(self) -> None:
        blind = [record for record in self.report.mutations if record.status is MutationStatus.BLIND_SPOT]
        self.assertEqual(
            {record.mutation_id: record.pie_stage for record in blind},
            {
                "M05_duplicate_reviewer_verdict": PieStage.PROPAGATED_NOT_CHECKED,
                "M06_missing_required_reviewer": PieStage.PROPAGATED_NOT_CHECKED,
            },
        )


if __name__ == "__main__":
    unittest.main()
