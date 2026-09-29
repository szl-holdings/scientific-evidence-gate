"""Mutation testing of the verifier (ARCHITECTURE.md section 10).

The shared fixture is ``fixtures/mutations/rich/``: synthetic data, invented
reviewers, invented citations under the 10.5555 test prefix, and a synthetic
dependency graph. ``manifest-core.json`` uses only the verifier's own checks,
so its results do not depend on the specialist modules. ``manifest.json``
adds the claim, citation and dependency checks.

Each test copies what it edits into a private temporary directory. The
fixture itself is only ever read, and mutation testing writes nothing outside
the OS temporary directory and the chosen output directory.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR, TempDirTestCase, try_symlink

from science_gate import cli, mutations
from science_gate._canonical import pretty_json_bytes, sha256_bytes, strict_loads
from science_gate.cli import DEFAULT_RUNS_DIR, LAZY_COMMANDS
from science_gate.invariants import DISAGREES, INVARIANT_NAMES, compare_decimal
from science_gate.models import BUILTIN_CHECK_KINDS, ExecutionState, FailureMode, InputState, Reason, Status
from science_gate.mutations import (
    COUNT_KEYS,
    INVALID_BASELINE_MESSAGE,
    NO_EXECUTION_MESSAGE,
    OPERATOR_IDS,
    OPERATORS,
    REPORT_HEADINGS,
    BaselineSummary,
    Detector,
    FiredDetector,
    MutationRecord,
    MutationReport,
    NotApplicable,
    Target,
    fired_detectors,
    headline,
    mutate,
    render_markdown,
    write_mutation_report,
)
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.verifier import REGISTRY, Finding, verify

RICH = REPO_ROOT / "fixtures" / "mutations" / "rich"
CORE_MANIFEST = RICH / "manifest-core.json"
FULL_MANIFEST = RICH / "manifest.json"
EMPTY_MANIFEST = REPO_ROOT / "fixtures" / "core" / "empty" / "manifest.json"

#: The operators whose targets exist only in the full manifest (claims, citations, dependencies).
SPECIALIST_OPERATORS = {
    "M08_changed_author",
    "M09_changed_doi",
    "M13_removed_invocation",
    "M18_changed_upstream_design",
    "M19_replaced_stored_claim_output",
}
CONTRACT_OPERATOR_IDS = (
    "M01_empty_input",
    "M02_missing_expected_file",
    "M03_deleted_accepted_row",
    "M04_duplicate_row",
    "M05_duplicate_reviewer_verdict",
    "M06_missing_required_reviewer",
    "M07_changed_source_hash",
    "M08_changed_author",
    "M09_changed_doi",
    "M10_changed_numeric_value",
    "M11_changed_numeric_formatting",
    "M12_timezone_shift",
    "M13_removed_invocation",
    "M14_pass_summary_without_evidence",
    "M15_skipped_required_checker",
    "M16_truncated_ledger",
    "M17_reordered_hash_chain",
    "M18_changed_upstream_design",
    "M19_replaced_stored_claim_output",
    "M20_metadata_change_under_unchanged_pass_summary",
)
RECORD_FIELDS = {
    "mutation_id",
    "description",
    "expected_result",
    "actual_result",
    "applicable",
    "execution_state",
    "expected_detector",
    "detecting_invariants_fired",
    "detected",
    "blind_spot",
    "diagnostics",
    "target",
}


def tree_digests(root: Path) -> dict[str, str]:
    """Every file under ``root`` with its SHA-256, to prove a tree was left untouched."""
    return {
        path.relative_to(root).as_posix(): sha256_bytes(path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def headings(markdown: str) -> list[str]:
    return [line[3:] for line in markdown.splitlines() if line.startswith("## ")]


def fired_labels(record: MutationRecord) -> set[str]:
    return {item.detector for item in record.detecting_invariants_fired or ()}


class MutationTestCase(TempDirTestCase):
    """A private copy of the rich fixture under ``self.rich``, a pinned clock and no signing key."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.rich = self.tmp / "rich"
        shutil.copytree(RICH, self.rich)

    def manifest_document(self, name: str = "manifest-core.json") -> dict[str, Any]:
        return json.loads((self.rich / name).read_text(encoding="utf-8"))

    def save_manifest(self, document: dict[str, Any], name: str = "manifest-core.json") -> Path:
        path = self.rich / name
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return path

    def edit_check(self, check_id: str, **changes: Any) -> Path:
        """Change one check of the core manifest; ``remove=True`` removes it."""
        document = self.manifest_document()
        checks = []
        for item in document["checks"]:
            if item["id"] == check_id:
                if changes.get("remove"):
                    continue
                item.update(changes)
            checks.append(item)
        document["checks"] = checks
        return self.save_manifest(document)

    def context(self, name: str = "manifest.json") -> mutations._Context:
        """The operators' view of the copied fixture, whatever its baseline status."""
        run = verify(self.rich / name)
        return mutations._Context(self.rich, name, run, REGISTRY)


# ---------------------------------------------------------------------------
# The operator catalogue
# ---------------------------------------------------------------------------


class OperatorCatalogueTests(unittest.TestCase):
    def test_the_twenty_contract_operators_in_order(self) -> None:
        self.assertEqual(OPERATOR_IDS, CONTRACT_OPERATOR_IDS)
        self.assertEqual(tuple(operator.mutation_id for operator in OPERATORS), OPERATOR_IDS)

    def test_every_expected_detector_names_a_real_mechanism(self) -> None:
        states = {state.value for state in InputState}
        for operator in OPERATORS:
            with self.subTest(operator=operator.mutation_id):
                source, _, name = operator.detector.label.partition(":")
                known = {
                    "check": BUILTIN_CHECK_KINDS,
                    "invariant": set(INVARIANT_NAMES),
                    "input": states,
                    "contract": {"checks_executed", "rows_examined", "inputs_opened", "evidence_manifest"},
                }
                self.assertIn(name, known[source])
                self.assertTrue(operator.detector.statuses)
                self.assertNotIn(Status.PASS, operator.detector.statuses)
                self.assertNotIn(Status.ERROR, operator.detector.statuses, "a crashed checker is not a detection")
                vocabulary = {item.value for item in (*Reason, *FailureMode)}
                self.assertLessEqual(set(operator.detector.signals), vocabulary)

    def test_ledger_operators_are_judged_by_the_chain_invariant(self) -> None:
        by_id = {operator.mutation_id: operator for operator in OPERATORS}
        for mutation_id in ("M16_truncated_ledger", "M17_reordered_hash_chain"):
            self.assertEqual(by_id[mutation_id].detector.label, "invariant:ledger_chain_intact")

    def test_default_output_root_is_the_one_verify_uses(self) -> None:
        self.assertEqual(mutations.DEFAULT_OUTPUT_ROOT, DEFAULT_RUNS_DIR)

    def test_the_mutate_command_resolves_to_this_module(self) -> None:
        self.assertEqual(LAZY_COMMANDS["mutate"], "science_gate.mutations:cli_mutate")


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------


def fired(label: str, status: Status, reason: Reason, *modes: FailureMode, source: str = "check:x") -> FiredDetector:
    return FiredDetector(label, source, status, reason, tuple(modes), "synthetic")


class DetectorTests(unittest.TestCase):
    def test_a_finding_counts_only_from_the_named_detector_with_a_matching_status(self) -> None:
        detector = Detector("check:duplicate_rows", frozenset({Status.FAIL}))
        self.assertTrue(detector.matches(fired("check:duplicate_rows", Status.FAIL, Reason.SOURCE_MISMATCH)))
        self.assertFalse(detector.matches(fired("check:row_count", Status.FAIL, Reason.SOURCE_MISMATCH)))
        self.assertFalse(detector.matches(fired("check:duplicate_rows", Status.ABSTAIN, Reason.SOURCE_MISMATCH)))

    def test_signals_keep_an_unrelated_abstention_from_counting(self) -> None:
        detector = Detector(
            "check:snapshot_completeness", frozenset({Status.FAIL}), frozenset({FailureMode.OMITTED_POPULATION.value})
        )
        label, reason = "check:snapshot_completeness", Reason.SOURCE_MISMATCH
        deleted = fired(label, Status.FAIL, reason, FailureMode.OMITTED_POPULATION)
        changed = fired(label, Status.FAIL, reason, FailureMode.SOURCE_MISMATCH)
        self.assertTrue(detector.matches(deleted))
        self.assertFalse(detector.matches(changed))
        by_reason = Detector("check:time_source", frozenset({Status.FAIL}), frozenset({Reason.SOURCE_MISMATCH.value}))
        self.assertTrue(by_reason.matches(fired("check:time_source", Status.FAIL, Reason.SOURCE_MISMATCH)))

    def test_findings_are_labelled_by_mechanism_not_by_id(self) -> None:
        run = verify(EMPTY_MANIFEST)
        labels = {item.detector for item in fired_detectors(run.findings, run.result.checks, run.result.accounting)}
        self.assertIn("input:EMPTY", labels)
        self.assertIn("check:row_count", labels)
        self.assertTrue(all(":" in label for label in labels))
        extra = Finding(Status.FAIL, Reason.PROTOCOL_BROKEN, (), "invariant:ledger_chain_intact", "synthetic")
        (item,) = fired_detectors([extra], (), run.result.accounting)
        self.assertEqual(item.detector, "invariant:ledger_chain_intact")
        self.assertEqual(item.source, item.detector)

    def test_expected_result_states_the_rule(self) -> None:
        detector = OPERATORS[2].detector
        expected = detector.expected_result()
        self.assertEqual(expected["status"], "not PASS")
        self.assertEqual(expected["detector"], "check:snapshot_completeness")
        self.assertEqual(expected["detector_signals"], ["OMITTED_POPULATION"])
        self.assertIn("check:snapshot_completeness reports FAIL with OMITTED_POPULATION", expected["rule"])


# ---------------------------------------------------------------------------
# The core fixture, end to end (one shared run)
# ---------------------------------------------------------------------------


class CoreFixtureTests(unittest.TestCase):
    """``manifest-core.json``: every applicable operator must be caught by its expected detector."""

    report: MutationReport
    records: dict[str, MutationRecord]
    before: dict[str, str]
    after: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        patcher = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
        patcher.start()
        cls.addClassCleanup(patcher.stop)
        cls.before = tree_digests(RICH)
        cls.report = mutate(CORE_MANIFEST)
        cls.after = tree_digests(RICH)
        cls.records = {record.mutation_id: record for record in cls.report.mutations}

    def test_the_accepting_baseline_is_pass(self) -> None:
        baseline = self.report.baseline
        self.assertTrue(baseline.valid)
        self.assertEqual((baseline.status, baseline.reason), (Status.PASS, Reason.VERIFIED))
        self.assertEqual(baseline.findings, ())
        self.assertGreater(baseline.counters["rows_examined"], 0)

    def test_every_applicable_operator_is_detected_by_its_expected_detector(self) -> None:
        for operator in OPERATORS:
            record = self.records[operator.mutation_id]
            if operator.mutation_id in SPECIALIST_OPERATORS:
                continue
            with self.subTest(operator=operator.mutation_id):
                self.assertIs(record.execution_state, ExecutionState.CHECKED, record.diagnostics)
                self.assertTrue(record.detected, record.diagnostics)
                self.assertIs(record.blind_spot, False)
                self.assertNotEqual(record.actual_result["status"], Status.PASS.value)
                self.assertTrue(any(operator.detector.matches(item) for item in record.detecting_invariants_fired))
                self.assertIn(operator.detector.label, fired_labels(record))

    def test_specialist_operators_have_no_target_in_the_core_manifest(self) -> None:
        not_applicable = {record.mutation_id for record in self.report.mutations if not record.applicable}
        self.assertEqual(not_applicable, SPECIALIST_OPERATORS)
        for mutation_id in SPECIALIST_OPERATORS:
            record = self.records[mutation_id]
            with self.subTest(operator=mutation_id):
                self.assertIs(record.execution_state, ExecutionState.NOT_APPLICABLE)
                self.assertIsNone(record.detected)
                self.assertIsNone(record.blind_spot)
                self.assertIsNone(record.actual_result)
                self.assertIsNone(record.detecting_invariants_fired)
                self.assertIsNone(record.target)
                self.assertTrue(record.diagnostics[0].startswith("NOT_APPLICABLE: "))

    def test_counts_sensitivity_status_and_exit_code(self) -> None:
        self.assertEqual(
            self.report.counts,
            {
                "applicable_mutations": 15,
                "executed_mutations": 15,
                "detected_mutations": 15,
                "escaped_mutations": 0,
                "skipped_mutations": 0,
                "not_applicable_mutations": 5,
            },
        )
        sensitivity = self.report.sensitivity
        self.assertEqual((sensitivity["fraction"], sensitivity["decimal"]), ("15/15", "1.0000"))
        outcome = (self.report.status, self.report.reason, self.report.exit_code)
        self.assertEqual(outcome, (Status.PASS, Reason.VERIFIED, 0))

    def test_counts_close(self) -> None:
        counts = self.report.counts
        self.assertEqual(counts["applicable_mutations"], counts["executed_mutations"] + counts["skipped_mutations"])
        self.assertEqual(counts["executed_mutations"], counts["detected_mutations"] + counts["escaped_mutations"])
        self.assertEqual(counts["applicable_mutations"] + counts["not_applicable_mutations"], len(OPERATOR_IDS))

    def test_the_detectors_fired_for_the_named_defect(self) -> None:
        def reasons_of(mutation_id: str, label: str) -> set[str]:
            return {
                value
                for item in self.records[mutation_id].detecting_invariants_fired
                if item.detector == label
                for value in (item.reason.value, *(mode.value for mode in item.failure_modes))
            }

        self.assertIn("OMITTED_POPULATION", reasons_of("M03_deleted_accepted_row", "check:snapshot_completeness"))
        self.assertIn("SOURCE_MISMATCH", reasons_of("M07_changed_source_hash", "input:HASH_MISMATCH"))
        self.assertIn("PROTOCOL_BROKEN", reasons_of("M05_duplicate_reviewer_verdict", "check:reviewer_protocol"))
        self.assertIn("PROTOCOL_BROKEN", reasons_of("M06_missing_required_reviewer", "check:reviewer_protocol"))
        self.assertIn("SOURCE_MISMATCH", reasons_of("M12_timezone_shift", "check:time_source"))
        self.assertIn("VACUOUS_PASS", reasons_of("M14_pass_summary_without_evidence", "check:summary_consistency"))
        self.assertIn("PARTIAL_EXECUTION", reasons_of("M15_skipped_required_checker", "contract:checks_executed"))

    def test_thousands_separators_cannot_evade_comparison(self) -> None:
        record = self.records["M11_changed_numeric_formatting"]
        self.assertIn("from '1,234' to '1.234'", record.target)
        self.assertIn("check:numeric_agreement", fired_labels(record))

    def test_a_reordered_chain_is_caught_only_by_the_chain_invariant(self) -> None:
        record = self.records["M17_reordered_hash_chain"]
        self.assertEqual(record.actual_result["mode"], "sealed-run replay")
        self.assertEqual(record.actual_result["run_id"], self.report.baseline.run_id)
        self.assertEqual(fired_labels(record), {"invariant:ledger_chain_intact"})

    def test_a_truncated_ledger_breaks_the_chain_against_the_original_seal(self) -> None:
        record = self.records["M16_truncated_ledger"]
        self.assertEqual(record.actual_result["mode"], "sealed-run replay")
        fired_here = record.detecting_invariants_fired
        (chain,) = [item for item in fired_here if item.detector == "invariant:ledger_chain_intact"]
        self.assertIn("LENGTH_MISMATCH", chain.detail)

    def test_a_metadata_change_beneath_the_pass_summary_is_caught_by_the_summary(self) -> None:
        record = self.records["M20_metadata_change_under_unchanged_pass_summary"]
        self.assertIn("recorded_at", record.target)
        self.assertIn("left unchanged", record.target)
        self.assertEqual(fired_labels(record), {"check:summary_consistency"})

    def test_the_fixture_was_only_read(self) -> None:
        self.assertEqual(self.before, self.after)

    def test_the_report_is_json_safe_and_every_record_has_the_contract_fields(self) -> None:
        document = strict_loads(pretty_json_bytes(self.report.to_dict()), integers_only=True)
        self.assertEqual(document["schema"], "science-gate-mutation-report/v1")
        self.assertEqual(document["report_id"], self.report.report_id)
        self.assertLessEqual(set(COUNT_KEYS), set(document))
        self.assertEqual(document["operators"], list(OPERATOR_IDS))
        for record in document["mutations"]:
            self.assertEqual(set(record), RECORD_FIELDS)
        self.assertNotIn("science-gate-mutate-", json.dumps(document), "temporary paths must never be recorded")

    def test_markdown_sections_follow_the_contract_order(self) -> None:
        markdown = render_markdown(self.report)
        self.assertEqual(headings(markdown), list(REPORT_HEADINGS))
        self.assertIn("No executed mutation escaped.", markdown)
        self.assertIn("15/15 = 1.0000", markdown)


# ---------------------------------------------------------------------------
# Blind spots
# ---------------------------------------------------------------------------


class BlindSpotTests(MutationTestCase):
    def test_a_missing_detector_is_a_blind_spot_even_when_the_status_is_not_pass(self) -> None:
        manifest = self.edit_check("reviewers", remove=True)
        report = mutate(manifest, operators=["M05_duplicate_reviewer_verdict", "M06_missing_required_reviewer"])
        escaped = [record for record in report.mutations if record.detected is False]
        self.assertEqual(
            [record.mutation_id for record in escaped],
            ["M05_duplicate_reviewer_verdict", "M06_missing_required_reviewer"],
        )
        for record in escaped:
            with self.subTest(operator=record.mutation_id):
                # The pinned summary noticed the bytes changed, but not what was wrong.
                self.assertEqual(record.actual_result["status"], Status.FAIL.value)
                self.assertIn("check:summary_consistency", fired_labels(record))
                self.assertNotIn("check:reviewer_protocol", fired_labels(record))
                self.assertIs(record.blind_spot, True)
                self.assertTrue(record.diagnostics[0].startswith("BLIND_SPOT: the mutant verified as FAIL"))
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.BLIND_SPOT, 1))
        self.assertEqual(report.counts["escaped_mutations"], 2)
        self.assertEqual((report.sensitivity["fraction"], report.sensitivity["decimal"]), ("0/2", "0.0000"))
        markdown = render_markdown(report)
        blind = markdown.split("## BLIND SPOTS")[1].split("## SKIPPED")[0]
        self.assertIn("M05_duplicate_reviewer_verdict", blind)
        self.assertIn("M06_missing_required_reviewer", blind)

    def test_metadata_change_under_an_optional_summary_is_reported_as_a_blind_spot(self) -> None:
        manifest = self.edit_check("summary", required=False)
        report = mutate(manifest, operators=["M20_metadata_change_under_unchanged_pass_summary"])
        record = report.mutations[-1]
        self.assertEqual(record.actual_result["status"], Status.PASS.value)
        self.assertIs(record.detected, False)
        self.assertIs(record.blind_spot, True)
        self.assertTrue(record.diagnostics[0].startswith("BLIND_SPOT: the mutant verified as PASS"))
        self.assertEqual(report.exit_code, 1)

    def test_a_verifier_crash_under_a_mutant_is_not_a_detection(self) -> None:
        def crash_on_mutants(path: Path, **kwargs: Any) -> Any:
            if Path(path).parent.name != "baseline":
                raise RuntimeError("synthetic engine defect")
            return verify(path, **kwargs)

        with mock.patch.object(mutations, "verify", side_effect=crash_on_mutants):
            report = mutate(self.rich / "manifest-core.json", operators=["M01_empty_input"])
        record = report.mutations[0]
        self.assertIs(record.execution_state, ExecutionState.CHECKED)
        self.assertEqual(record.actual_result["status"], Status.ERROR.value)
        self.assertIsNone(record.actual_result["run_id"])
        self.assertEqual(fired_labels(record), {"verifier:crash"})
        self.assertIs(record.detected, False)
        self.assertEqual(report.reason, Reason.BLIND_SPOT)


# ---------------------------------------------------------------------------
# Invalid baselines
# ---------------------------------------------------------------------------


class InvalidBaselineTests(MutationTestCase):
    def assert_invalid(self, report: MutationReport) -> dict[str, Any]:
        self.assertFalse(report.baseline.valid)
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.INVALID_BASELINE, 1))
        self.assertIsNone(report.counts)
        self.assertIsNone(report.sensitivity)
        self.assertEqual(report.mutations, ())
        self.assertEqual(report.message, INVALID_BASELINE_MESSAGE)
        document = report.to_dict()
        for key in (*COUNT_KEYS, "sensitivity", "mutations"):
            self.assertNotIn(key, document)
        self.assertEqual(
            document["message"],
            "No sensitivity figure was produced because the verifier failed its accepting baseline.",
        )
        markdown = render_markdown(report)
        self.assertIn(INVALID_BASELINE_MESSAGE, markdown)
        self.assertEqual(headings(markdown), ["STATUS", "BASELINE", "WHAT THIS RESULT DOES NOT PROVE"])
        self.assertIn(INVALID_BASELINE_MESSAGE, headline(report))
        return document

    def test_a_failing_baseline_produces_no_sensitivity_and_no_counts(self) -> None:
        data = self.rich / "data" / "measurements.csv"
        data.write_bytes(data.read_bytes().replace(b"SYN-M-003,site-beta,3.5", b"SYN-M-003,site-beta,3.6"))
        document = self.assert_invalid(mutate(self.rich / "manifest-core.json"))
        self.assertEqual(document["baseline"]["status"], Status.FAIL.value)
        sources = {finding["source"] for finding in document["baseline"]["findings"]}
        self.assertIn("input:measurements", sources)

    def test_an_abstaining_baseline_is_invalid_too(self) -> None:
        report = mutate(EMPTY_MANIFEST)
        self.assert_invalid(report)
        self.assertEqual(report.baseline.status, Status.ABSTAIN)

    def test_a_missing_manifest_is_an_invalid_baseline(self) -> None:
        report = mutate(self.tmp / "absent" / "manifest.json")
        self.assert_invalid(report)
        self.assertEqual(report.baseline.status, Status.ERROR)
        self.assertIsNone(report.manifest_sha256)

    def test_an_unreadable_file_in_the_tree_is_reported_not_raised(self) -> None:
        real = Path.read_bytes

        def guarded(path: Path) -> bytes:
            if path.name == "sites.json":
                raise PermissionError(13, "Permission denied")
            return real(path)

        with mock.patch.object(Path, "read_bytes", guarded):
            report = mutate(self.rich / "manifest-core.json")
        self.assert_invalid(report)
        self.assertEqual(
            report.baseline.diagnostics, ("TREE_NOT_COPIED: data/sites.json cannot be read (Permission denied)",)
        )

    def test_a_tree_beyond_max_files_is_never_copied(self) -> None:
        document = self.manifest_document()
        document["limits"] = {"max_files": 5}
        report = mutate(self.save_manifest(document))
        self.assert_invalid(report)
        self.assertIsNone(report.baseline.status)
        self.assertTrue(report.baseline.diagnostics[0].startswith("TREE_NOT_COPIED: "))
        self.assertIn("never verified", render_markdown(report))


# ---------------------------------------------------------------------------
# Skipped and not-applicable mutations
# ---------------------------------------------------------------------------


class SkippedAndNotApplicableTests(MutationTestCase):
    def test_unselected_mutations_are_skipped_and_never_counted_as_detections(self) -> None:
        report = mutate(self.rich / "manifest-core.json", operators=["M16_truncated_ledger"])
        skipped = [record for record in report.mutations if record.execution_state is ExecutionState.SKIPPED]
        self.assertEqual(len(skipped), 14)
        for record in skipped:
            with self.subTest(operator=record.mutation_id):
                self.assertTrue(record.applicable)
                self.assertIsNone(record.detected)
                self.assertIsNone(record.blind_spot)
                self.assertIsNone(record.actual_result)
                self.assertEqual(record.diagnostics, ("SKIPPED: the operator was not selected for this run",))
        self.assertEqual(
            report.counts,
            {
                "applicable_mutations": 15,
                "executed_mutations": 1,
                "detected_mutations": 1,
                "escaped_mutations": 0,
                "skipped_mutations": 14,
                "not_applicable_mutations": 5,
            },
        )
        self.assertEqual(report.sensitivity["fraction"], "1/1")
        self.assertEqual(report.to_dict()["selected_operators"], ["M16_truncated_ledger"])
        self.assertIn("## SKIPPED", render_markdown(report))

    def test_nothing_executed_is_abstain_without_a_sensitivity_figure(self) -> None:
        report = mutate(self.rich / "manifest-core.json", operators=[])
        outcome = (report.status, report.reason, report.exit_code)
        self.assertEqual(outcome, (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, 2))
        self.assertIsNone(report.sensitivity)
        document = report.to_dict()
        self.assertIsNone(document["sensitivity"])
        self.assertEqual(document["executed_mutations"], 0)
        self.assertEqual(document["detected_mutations"], 0)
        self.assertEqual(report.message, NO_EXECUTION_MESSAGE)
        self.assertIn(NO_EXECUTION_MESSAGE, headline(report))

    def test_selecting_only_operators_without_a_target_executes_nothing(self) -> None:
        report = mutate(self.rich / "manifest-core.json", operators=["M08_changed_author"])
        self.assertEqual(report.counts["executed_mutations"], 0)
        self.assertEqual(report.counts["not_applicable_mutations"], 5)
        self.assertEqual(report.exit_code, 2)

    def test_a_mutant_that_cannot_be_built_is_skipped_not_counted(self) -> None:
        with mock.patch.object(mutations, "_apply", side_effect=OSError("synthetic write failure")):
            report = mutate(self.rich / "manifest-core.json", operators=["M01_empty_input", "M16_truncated_ledger"])
        record = report.mutations[0]
        self.assertIs(record.execution_state, ExecutionState.SKIPPED)
        self.assertIsNone(record.detected)
        self.assertIn("could not be built (OSError: synthetic write failure)", record.diagnostics[0])
        self.assertEqual((report.counts["executed_mutations"], report.counts["skipped_mutations"]), (1, 14))

    def test_ledger_operators_are_skipped_when_the_sealed_baseline_does_not_replay(self) -> None:
        real_decide = mutations.decide
        calls: list[int] = []

        def failing_replay(inputs: Any) -> Any:
            decision = real_decide(inputs)
            calls.append(1)
            return mock.Mock(wraps=decision, status=Status.ABSTAIN) if len(calls) == 1 else decision

        with mock.patch.object(mutations, "decide", side_effect=failing_replay):
            report = mutate(
                self.rich / "manifest-core.json", operators=["M16_truncated_ledger", "M17_reordered_hash_chain"]
            )
        for record in report.mutations[15:17]:
            self.assertIs(record.execution_state, ExecutionState.SKIPPED)
            self.assertTrue(record.diagnostics[0].startswith("SKIPPED: REPLAY_FAILED"))
        self.assertEqual(report.exit_code, 2)

    def test_unknown_operator_ids_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            mutate(self.rich / "manifest-core.json", operators=["M99_invented"])


# ---------------------------------------------------------------------------
# Workspace hygiene and isolation
# ---------------------------------------------------------------------------


class WorkspaceTests(MutationTestCase):
    def test_temporary_copies_are_removed_and_the_source_is_untouched(self) -> None:
        private = self.tmp / "os-temp"
        private.mkdir()
        before = tree_digests(self.rich)
        with mock.patch.object(tempfile, "tempdir", str(private)):
            mutate(self.rich / "manifest-core.json", operators=["M01_empty_input", "M02_missing_expected_file"])
        self.assertEqual(list(private.iterdir()), [])
        self.assertEqual(tree_digests(self.rich), before)

    def test_every_verify_runs_offline(self) -> None:
        with self.assertRaises(OSError):
            mutations._OFFLINE.opener("https://example.invalid/")
        with mock.patch.object(mutations, "verify", wraps=verify) as spy:
            mutate(self.rich / "manifest-core.json", operators=["M01_empty_input"])
        self.assertEqual(spy.call_count, 2)
        self.assertTrue(all(call.kwargs["network"] is mutations._OFFLINE for call in spy.call_args_list))

    def test_the_output_directory_inside_the_tree_is_not_copied(self) -> None:
        output = self.rich / "reports"
        output.mkdir()
        (output / "stale.json").write_text("{}", encoding="utf-8")
        report = mutate(self.rich / "manifest-core.json", operators=[], exclude=[output])
        self.assertIn("EXCLUDED: directory reports is the report's output directory", report.diagnostics)

    def test_links_that_leave_the_tree_are_not_followed(self) -> None:
        outside = self.write("outside/secret.txt", "synthetic outside content")
        try_symlink(self, outside, self.rich / "link.txt")
        report = mutate(self.rich / "manifest-core.json", operators=[])
        self.assertIn("LINK_SKIPPED: file link.txt resolves outside the tree", report.diagnostics)

    def test_the_workspace_path_is_scrubbed_from_recorded_text(self) -> None:
        scrub = mutations._Scrubber(self.tmp)
        self.assertEqual(scrub(f"cannot open {self.tmp}\\baseline\\x"), "cannot open <workspace>\\baseline\\x")
        self.assertEqual(scrub(f"see {self.tmp.as_posix()}/x"), "see <workspace>/x")


# ---------------------------------------------------------------------------
# Operator targets (no mutant is verified)
# ---------------------------------------------------------------------------


def locate(test: unittest.TestCase, mutation_id: str, ctx: mutations._Context) -> Target:
    (operator,) = [item for item in OPERATORS if item.mutation_id == mutation_id]
    located = operator.locate(ctx)
    test.assertIsInstance(located, Target, getattr(located, "reason", None))
    return located


def edited(target: Target, path: str) -> Any:
    (edit,) = [item for item in target.edits if item.path == path]
    return strict_loads(edit.data)


def read_json(relpath: str) -> Any:
    return strict_loads((RICH / relpath).read_bytes())


class OperatorTargetTests(unittest.TestCase):
    """Targets computed from the fixture itself: locating only reads, so both contexts are shared."""

    core: mutations._Context
    full: mutations._Context

    @classmethod
    def setUpClass(cls) -> None:
        with mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME}):
            cls.core = mutations._Context(RICH, "manifest-core.json", verify(CORE_MANIFEST), REGISTRY)
            cls.full = mutations._Context(RICH, "manifest.json", verify(FULL_MANIFEST), REGISTRY)

    def test_every_operator_has_a_target_in_the_full_manifest(self) -> None:
        for operator in OPERATORS:
            with self.subTest(operator=operator.mutation_id):
                self.assertIsInstance(operator.locate(self.full), Target)

    def test_input_edits_re_declare_the_digest_to_isolate_the_defect(self) -> None:
        operators = ("M01_empty_input", "M03_deleted_accepted_row", "M04_duplicate_row", "M10_changed_numeric_value")
        for mutation_id in operators:
            with self.subTest(operator=mutation_id):
                data = {edit.path: edit.data for edit in locate(self, mutation_id, self.core).edits}
                manifest = strict_loads(data["manifest-core.json"])
                (declared,) = [item["sha256"] for item in manifest["inputs"] if item["id"] == "measurements"]
                self.assertEqual(declared, sha256_bytes(data["data/measurements.csv"]))
                self.assertEqual(manifest["checks"], read_json("manifest-core.json")["checks"])

    def test_a_changed_source_hash_keeps_the_records_and_the_declaration(self) -> None:
        (edit,) = locate(self, "M07_changed_source_hash", self.core).edits
        original = (RICH / "data" / "measurements.csv").read_bytes()
        self.assertEqual(edit.data, original[:-1] + b"\r\n")

    def test_deleted_row_is_an_accepted_one_and_only_that_row_goes(self) -> None:
        target = locate(self, "M03_deleted_accepted_row", self.core)
        data = {edit.path: edit.data for edit in target.edits}["data/measurements.csv"]
        original = (RICH / "data" / "measurements.csv").read_bytes()
        self.assertEqual(data, original.replace(b'SYN-M-008,site-delta,19.2,"3,300"\n', b""))

    def test_changed_author(self) -> None:
        entries = edited(locate(self, "M08_changed_author", self.full), "citations/entries.json")
        original = read_json("citations/entries.json")
        self.assertEqual(entries["citations"][0]["authors"][0], {"family": "Mutant", "given": "Avery"})
        entries["citations"][0]["authors"][0] = original["citations"][0]["authors"][0]
        self.assertEqual(entries, original)

    def test_changed_doi_names_no_frozen_record(self) -> None:
        doi = edited(locate(self, "M09_changed_doi", self.full), "citations/entries.json")["citations"][0]["doi"]
        self.assertTrue(doi.startswith("10.5555/"))
        self.assertNotIn(doi.encode("utf-8"), (RICH / "citations" / "frozen.json").read_bytes())

    def test_removed_invocation_keeps_the_claimed_count(self) -> None:
        log = edited(locate(self, "M13_removed_invocation", self.full), "citations/verification-log.json")
        original = read_json("citations/verification-log.json")
        self.assertEqual(log["claimed_verified"], original["claimed_verified"])
        self.assertEqual(log["invocations"], original["invocations"][1:])
        self.assertGreater(log["claimed_verified"], len(log["invocations"]))

    def test_changed_design_leaves_the_recorded_digest(self) -> None:
        (edit,) = locate(self, "M18_changed_upstream_design", self.full).edits
        self.assertEqual(edit.path, "graph/design/protocol.md")
        (node,) = [item for item in read_json("graph/graph.json")["nodes"] if item["kind"] == "DESIGN"]
        self.assertEqual(node["recorded_sha256"], sha256_bytes((RICH / edit.path).read_bytes()))
        self.assertNotEqual(node["recorded_sha256"], sha256_bytes(edit.data))

    def test_replaced_claim_output_shifts_the_selected_value(self) -> None:
        output = edited(locate(self, "M19_replaced_stored_claim_output", self.full), "outputs/results.json")
        self.assertEqual(output["site_alpha_mean"], "16.27")
        self.assertEqual(output["sample_count"], 8)

    def test_skipped_checker_replaces_one_unique_required_kind(self) -> None:
        target = locate(self, "M15_skipped_required_checker", self.core)
        self.assertEqual(target.registry["row_count"], mutations.SKIPPED_CHECKER)
        replaced = {kind for kind, value in target.registry.items() if value != REGISTRY.get(kind)}
        self.assertEqual(replaced, {"row_count"})
        self.assertEqual(target.edits, ())

    def test_ledger_operators_tamper_with_a_copy_of_the_sealed_entries(self) -> None:
        entries = self.core.baseline.ledger.entries
        self.assertEqual(locate(self, "M16_truncated_ledger", self.core).ledger_entries, entries[:-1])
        reordered = locate(self, "M17_reordered_hash_chain", self.core).ledger_entries
        self.assertEqual((reordered[1], reordered[2]), (entries[2], entries[1]))
        self.assertEqual(self.core.baseline.ledger.entries, entries, "the baseline's own ledger is never edited")


class OperatorFallbackTests(MutationTestCase):
    """Targets in edited copies of the fixture: the M20 fallback, and operators with no target."""

    def test_metadata_change_falls_back_to_a_layout_change(self) -> None:
        document = self.manifest_document()
        del document["reviews"], document["time_sources"]
        document["checks"] = [item for item in document["checks"] if item["id"] not in ("reviewers", "timing")]
        self.save_manifest(document)
        target = locate(self, "M20_metadata_change_under_unchanged_pass_summary", self.context("manifest-core.json"))
        (edit,) = target.edits
        self.assertEqual(edit.path, "snapshots/accepted.json")
        self.assertEqual(strict_loads(edit.data), strict_loads((self.rich / edit.path).read_bytes()))
        self.assertIn("content is identical", target.description)

    def test_operators_without_targets_say_why(self) -> None:
        document = self.manifest_document()
        for key in ("accepted_snapshot", "reviews", "time_sources", "summary_claim"):
            del document[key]
        document["checks"] = [item for item in document["checks"] if item["id"] in ("rows", "columns")]
        for item in document["inputs"]:
            item.pop("sha256")
        self.save_manifest(document)
        ctx = self.context("manifest-core.json")
        absent = {
            "M03_deleted_accepted_row",
            "M05_duplicate_reviewer_verdict",
            "M06_missing_required_reviewer",
            "M07_changed_source_hash",
            "M10_changed_numeric_value",
            "M11_changed_numeric_formatting",
            "M12_timezone_shift",
            "M14_pass_summary_without_evidence",
            "M20_metadata_change_under_unchanged_pass_summary",
        }
        for operator in OPERATORS:
            if operator.mutation_id in absent:
                with self.subTest(operator=operator.mutation_id):
                    located = operator.locate(ctx)
                    self.assertIsInstance(located, NotApplicable)
                    self.assertTrue(located.reason)


# ---------------------------------------------------------------------------
# Editing helpers
# ---------------------------------------------------------------------------


class RecordFileTests(unittest.TestCase):
    def load(self, fmt: str, text: str) -> mutations._RecordFile:
        records = mutations._RecordFile.load(fmt, text.encode("utf-8"))
        assert records is not None
        return records

    def test_csv_edits_touch_only_the_record_concerned(self) -> None:
        text = 'id,note\r\nA,"two\r\nlines"\r\nB,plain\r\nC,last'
        records = self.load("csv", text)
        self.assertEqual([record.values["id"] for record in records.records], ["A", "B", "C"])
        self.assertEqual(records.without(records.records[0]).decode(), "id,note\r\nB,plain\r\nC,last")
        self.assertEqual(records.with_copy_of(records.records[2]).decode(), text + "\r\nC,last")
        changed = records.with_value(records.records[1], "note", "x,y").decode()
        self.assertEqual(changed, text.replace("B,plain", 'B,"x,y"'))

    def test_a_byte_order_mark_and_blank_lines_are_kept(self) -> None:
        records = self.load("csv", "﻿id,v\n\nA,1\n")
        self.assertEqual(records.with_copy_of(records.records[0]).decode("utf-8"), "﻿id,v\n\nA,1\nA,1\n")

    def test_jsonl_and_json_arrays(self) -> None:
        lines = self.load("jsonl", '{"id": "A", "v": "1"}\n{"id": "B", "v": 2.50}\n')
        changed = lines.with_value(lines.records[1], "v", 3).decode()
        self.assertEqual(changed, '{"id": "A", "v": "1"}\n{"id": "B", "v": 3}\n')
        array = self.load("json", '[{"id": "A", "v": 2.50}, {"id": "B"}]')
        self.assertEqual(strict_loads(array.with_copy_of(array.records[0]))[1], {"id": "A", "v": Decimal("2.50")})
        self.assertIn(b'"v": 2.50', array.without(array.records[1]))

    def test_unsplittable_files_are_not_targets(self) -> None:
        self.assertIsNone(mutations._RecordFile.load("json", b'{"not": "an array"}'))
        self.assertIsNone(mutations._RecordFile.load("csv", b"\xff\xfe"))
        self.assertIsNone(mutations._RecordFile.load("xml", b"<a/>"))


class NumberAndTimeHelperTests(unittest.TestCase):
    def test_shift_keeps_the_printed_form(self) -> None:
        cases = {
            ("12.40", None): "22.40",
            ("1,234", ","): "1,244",
            ("0.14", None): "10.14",
            ("-3", None): "7",
            ("995", ","): "1005",
            ("9,995", ","): "10,005",
        }
        for (text, thousands), expected in cases.items():
            with self.subTest(text=text):
                shifted = mutations._shift_printed_number(text, thousands=thousands, decimal_point=".")
                self.assertEqual(shifted, expected)
        self.assertIsNone(mutations._shift_printed_number("n/a", thousands=None, decimal_point="."))
        long = "1" * 60 + ".5"
        self.assertEqual(mutations._shift_printed_number(long, thousands=None, decimal_point="."), "1" * 58 + "21.5")

    def test_a_shifted_value_never_agrees_with_the_claim_it_matched(self) -> None:
        for claim, stored in (("2", "1.5"), ("12.4", "12.40"), ("0.1", "0.14"), ("27.12", "27.125"), ("1234", "1234")):
            with self.subTest(claim=claim, stored=stored):
                self.assertTrue(compare_decimal(claim, stored).agrees)
                shifted = mutations._shift_printed_number(stored, thousands=None, decimal_point=".")
                self.assertEqual(compare_decimal(claim, shifted).outcome, DISAGREES)

    def test_marks_are_exchanged(self) -> None:
        self.assertEqual(mutations._swap_marks("1,234.5", thousands=",", decimal_point="."), "1.234,5")
        self.assertEqual(mutations._swap_marks("12.40", thousands=None, decimal_point="."), "12,40")

    def test_timezones_shift_within_real_offsets(self) -> None:
        cases = {
            "+02:00": "+03:00",
            "UTC": "+01:00",
            "Z": "+01:00",
            "+14:00": "+13:00",
            "-12:00": "-11:00",
            "-00:30": "+00:30",
        }
        for zone, expected in cases.items():
            with self.subTest(zone=zone):
                self.assertEqual(mutations._shifted_timezone(zone), expected)
        for zone in ("Region/City", None, "+2:00"):
            self.assertIsNone(mutations._shifted_timezone(zone))

    def test_reencoding_changes_only_the_final_line_ending(self) -> None:
        self.assertEqual(mutations._reencoded(b"a\n"), b"a\r\n")
        self.assertEqual(mutations._reencoded(b"a\r\n"), b"a\n")
        self.assertEqual(mutations._reencoded(b"a"), b"a\n")

    def test_json_rendering_keeps_decimals_as_numbers_and_key_order(self) -> None:
        document = {"z": Decimal("0.50"), "a": [1, {"b": None}], "e": {}, "l": []}
        compact = b'{"z": 0.50, "a": [1, {"b": null}], "e": {}, "l": []}\n'
        self.assertEqual(mutations._json_bytes(document, None), compact)
        self.assertEqual(strict_loads(mutations._json_bytes(document)), document)

    def test_json_pointers(self) -> None:
        document = {"a": [{"b/c": 1}], "~x": 2}
        self.assertEqual(mutations._resolve_pointer(document, "/a/0/b~1c"), (document["a"][0], "b/c"))
        self.assertEqual(mutations._resolve_pointer(document, "/~0x"), (document, "~x"))
        self.assertIsNone(mutations._resolve_pointer(document, "/a/5"))
        self.assertIsNone(mutations._resolve_pointer(document, "a"))


# ---------------------------------------------------------------------------
# Report types and rendering
# ---------------------------------------------------------------------------


def invalid_report(detail: str = "synthetic") -> MutationReport:
    finding = {
        "status": "FAIL",
        "reason": "SOURCE_MISMATCH",
        "failure_modes": [],
        "source": "input:x",
        "detail": detail,
    }
    baseline = BaselineSummary(Status.FAIL, Reason.SOURCE_MISMATCH, "run-synthetic", {}, (finding,))
    return MutationReport("manifest.json", None, FIXED_TIME, baseline, OPERATOR_IDS)


class ReportTypeTests(unittest.TestCase):
    def record(self, **overrides: Any) -> MutationRecord:
        values: dict[str, Any] = {
            "mutation_id": "M01_empty_input",
            "description": "synthetic",
            "target": "synthetic",
            "expected_result": {},
            "expected_detector": "input:EMPTY",
            "applicable": True,
            "execution_state": ExecutionState.CHECKED,
            "actual_result": {"status": "ABSTAIN"},
            "detecting_invariants_fired": (),
            "detected": False,
        }
        values.update(overrides)
        return MutationRecord(**values)

    def test_inconsistent_records_are_unrepresentable(self) -> None:
        self.assertIs(self.record().blind_spot, True)
        with self.assertRaises(ValueError):
            self.record(execution_state=ExecutionState.NOT_APPLICABLE)
        with self.assertRaises(ValueError):
            self.record(detected=None)
        with self.assertRaises(ValueError):
            self.record(execution_state=ExecutionState.SKIPPED)
        with self.assertRaises(ValueError):
            self.record(applicable=False, execution_state=ExecutionState.NOT_APPLICABLE, actual_result=None,
                        detecting_invariants_fired=None, detected=True)

    def test_reports_cannot_mix_an_invalid_baseline_with_mutations(self) -> None:
        with self.assertRaises(ValueError):
            MutationReport("m.json", None, FIXED_TIME, invalid_report().baseline, OPERATOR_IDS, (self.record(),))
        valid = BaselineSummary(Status.PASS, Reason.VERIFIED, "run-synthetic")
        with self.assertRaises(ValueError):
            MutationReport("m.json", None, FIXED_TIME, valid, OPERATOR_IDS, (self.record(),))

    def test_recorded_text_cannot_forge_a_heading(self) -> None:
        markdown = render_markdown(invalid_report("line one\n## WHAT PASSED\nline two"))
        self.assertEqual(headings(markdown), ["STATUS", "BASELINE", "WHAT THIS RESULT DOES NOT PROVE"])
        self.assertIn("line one ## WHAT PASSED line two", markdown)

    def test_the_report_id_is_derived_from_content(self) -> None:
        first, again = invalid_report(), invalid_report()
        self.assertEqual(first.report_id, again.report_id)
        self.assertNotEqual(first.report_id, invalid_report("other").report_id)
        self.assertRegex(first.report_id, r"^mut-[0-9a-f]{16}$")


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


def mini_project(root: Path) -> Path:
    """A small synthetic project whose seven applicable operators are all caught; returns its manifest."""
    data = b"sample_id,value\nSYN-A,1\nSYN-B,2\nSYN-C,3\n"
    (root / "data").mkdir(parents=True)
    (root / "data" / "samples.csv").write_bytes(data)
    manifest = {
        "schema": "science-gate-manifest/v1",
        "run_label": "synthetic-mutation-mini",
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
            {"id": "rows", "kind": "row_count", "version": "1", "required": True, "inputs": ["samples"]},
            {"id": "duplicates", "kind": "duplicate_rows", "version": "1", "required": True, "inputs": ["samples"]},
        ],
        "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
    }
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


class CommandTests(MutationTestCase):
    def call(self, *argv: str) -> tuple[int, list[str]]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli.main(["mutate", *argv])
        return code, stdout.getvalue().splitlines()

    def test_invalid_baseline_exits_1_and_prints_the_message_first(self) -> None:
        output = self.tmp / "out"
        code, lines = self.call(str(EMPTY_MANIFEST), "--output", str(output))
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith("FAIL (INVALID_BASELINE) mut-"), lines[0])
        self.assertIn(INVALID_BASELINE_MESSAGE, lines[0])
        expected = [output / "mutation-report.json", output / "mutation-report.md"]
        self.assertEqual([Path(line) for line in lines[1:]], expected)
        document = json.loads((output / "mutation-report.json").read_text(encoding="utf-8"))
        self.assertEqual(document["reason"], "INVALID_BASELINE")
        self.assertNotIn("executed_mutations", document)

    def test_nothing_executed_exits_2(self) -> None:
        real = mutations.mutate
        arguments = argparse.Namespace(manifest=str(self.rich / "manifest-core.json"), output=str(self.tmp / "out"))
        stdout = io.StringIO()
        with mock.patch.object(mutations, "mutate", side_effect=lambda path, **kw: real(path, operators=(), **kw)):
            with contextlib.redirect_stdout(stdout):
                code = mutations.cli_mutate(arguments)
        self.assertEqual(code, 2)
        self.assertTrue(stdout.getvalue().startswith("ABSTAIN (INSUFFICIENT_EVIDENCE) mut-"))

    def test_an_unwritable_output_is_an_error_not_a_traceback(self) -> None:
        blocker = self.write("blocker", "not a directory")
        code, lines = self.call(str(EMPTY_MANIFEST), "--output", str(blocker / "out"))
        self.assertEqual(code, 3)
        self.assertTrue(lines[0].startswith("ERROR mutate: the FAIL report could not be written to "), lines)

    def run_cli(self, *args: str, cwd: Path, seed: str) -> subprocess.CompletedProcess[str]:
        hidden = (HMAC_KEY_FILE_ENV, "PYTHONHASHSEED")
        environment = {key: value for key, value in os.environ.items() if key not in hidden}
        environment.update(
            {
                "PYTHONPATH": str(SRC_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "SCIENCE_GATE_FIXED_TIME": FIXED_TIME,
                "PYTHONHASHSEED": seed,
            }
        )
        return subprocess.run(
            [sys.executable, "-m", "science_gate.cli", "mutate", *args],
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=600,
        )

    def test_reports_are_byte_identical_under_different_hash_seeds(self) -> None:
        manifest = mini_project(self.tmp / "mini")
        first_cwd = self.tmp / "first"
        first_cwd.mkdir()
        first = self.run_cli(str(manifest), cwd=first_cwd, seed="0")
        second = self.run_cli(str(manifest), "--output", str(self.tmp / "second"), cwd=self.tmp, seed="4242")
        for completed in (first, second):
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(completed.stdout.startswith("PASS (VERIFIED) mut-"), completed.stdout)
            self.assertIn(": 7/7 executed mutations detected", completed.stdout)
        report_id = first.stdout.split()[2].rstrip(":")
        default_dir = first_cwd / DEFAULT_RUNS_DIR / report_id
        written = [Path(line) for line in first.stdout.splitlines()[1:]]
        self.assertEqual(written, [default_dir / "mutation-report.json", default_dir / "mutation-report.md"])
        for name in ("mutation-report.json", "mutation-report.md"):
            with self.subTest(file=name):
                self.assertEqual((default_dir / name).read_bytes(), (self.tmp / "second" / name).read_bytes())

    def test_write_mutation_report_writes_both_files(self) -> None:
        paths = write_mutation_report(invalid_report(), self.tmp / "direct")
        self.assertEqual([path.name for path in paths], ["mutation-report.json", "mutation-report.md"])
        self.assertTrue(all(path.is_file() for path in paths))


# ---------------------------------------------------------------------------
# The full fixture (claims, citations, dependencies)
# ---------------------------------------------------------------------------


class FullFixtureTests(unittest.TestCase):
    """``manifest.json`` adds the specialist checks: each specialist operator must trip its own check."""

    def test_specialist_operators_are_detected_by_their_own_checks(self) -> None:
        with mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME}):
            run = verify(FULL_MANIFEST)
            missing = sorted(
                check.check_id
                for check in run.result.checks
                if any("NotImplementedError" in text for text in check.diagnostics)
            )
            if missing:
                self.skipTest(f"specialist checks not implemented in this build: {missing}")
            self.assertIs(run.status, Status.PASS, [finding.to_dict() for finding in run.findings])
            report = mutate(FULL_MANIFEST, operators=sorted(SPECIALIST_OPERATORS))
        executed = {record.mutation_id: record for record in report.mutations if record.detected is not None}
        self.assertEqual(set(executed), SPECIALIST_OPERATORS)
        for mutation_id, record in sorted(executed.items()):
            with self.subTest(operator=mutation_id):
                self.assertTrue(record.detected, record.diagnostics)
                self.assertIn(record.expected_detector, fired_labels(record))
        self.assertEqual((report.status, report.exit_code), (Status.PASS, 0))


if __name__ == "__main__":
    unittest.main()
