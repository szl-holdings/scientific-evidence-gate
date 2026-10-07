"""The 28 numbered requirements, one test each (ARCHITECTURE.md section 16).

Each ``test_rNN_...`` proves the specific behavior its requirement names,
not merely an exit code. The tests reuse the synthetic fixtures under
``fixtures/`` (copied into OS temporary directories before any edit) and the
synthetic starter project that ``science-gate init`` writes. No test touches
the network: every verify that could reach it runs with an injected opener
that records the call and refuses it.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR
from _project import EMPTY_MANIFEST, VALID_MANIFEST, ProjectTestCase, reviews_document, time_document

from science_gate import cli
from science_gate._canonical import sha256_bytes, sha256_canonical
from science_gate.dependencies import RevalidationOutcome, assess, load_graph
from science_gate.invariants import (
    AGREES_AT_STATED_PRECISION,
    DISAGREES,
    EXACT,
    REQUIRES_HUMAN_REVIEW,
    InvariantContext,
    compare_decimal,
    every_invocation_has_terminal_result,
    every_verdict_has_invocation,
)
from science_gate.ledger import index_invocations
from science_gate.models import (
    TERMINAL_INVOCATION_RESULTS,
    ExecutionState,
    FailureMode,
    InputState,
    InvocationResult,
    Reason,
    SignatureState,
    Status,
    Validity,
)
from science_gate.mutations import COUNT_KEYS, INVALID_BASELINE_MESSAGE, OPERATOR_IDS, mutate, render_markdown
from science_gate.packaging import Basis, Disposition, build_package
from science_gate.receipts import DISCLAIMER, HMAC_KEY_FILE_ENV, build_run_receipt, verify_receipt
from science_gate.reports import write_run
from science_gate.verifier import REGISTRY, CheckContext, CheckOutcome, NetworkPolicy, VerificationRun, verify

FIXTURES = REPO_ROOT / "fixtures"
CITATIONS = FIXTURES / "citations"
CLAIMS = FIXTURES / "claims"
RICH = FIXTURES / "mutations" / "rich"
DEPENDENCIES = FIXTURES / "dependencies" / "current"
CONTROLLED_LOCAL = FIXTURES / "packaging" / "controlled-local"

M03 = "M03_deleted_accepted_row"
M04 = "M04_duplicate_row"
M05 = "M05_duplicate_reviewer_verdict"
M06 = "M06_missing_required_reviewer"
M20 = "M20_metadata_change_under_unchanged_pass_summary"
#: Operators with no target in ``manifest-core.json``: citations, the
#: verification log, the dependency graph and stored claim outputs.
CORE_NOT_APPLICABLE = {
    "M08_changed_author",
    "M09_changed_doi",
    "M13_removed_invocation",
    "M18_changed_upstream_design",
    "M19_replaced_stored_claim_output",
}


class RecordingOpener:
    """Stands in for ``urlopen``: records each request and refuses it, as a dead network would."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(getattr(request, "full_url", request))
        raise OSError("synthetic network failure: the test network is unreachable")


# Check functions registered under extra kinds by r03, r04 and r21. The
# engine imports them lazily as "test_required:<name>".


def claims_pass_without_rows(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A defective checker: it says PASS after examining nothing."""
    return CheckOutcome(ExecutionState.CHECKED, Status.PASS, Reason.VERIFIED, rows_examined=0, evidence={"seen": 0})


def raises_while_checking(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A checker that crashes before reaching any verdict."""
    raise RuntimeError("synthetic checker crash")


def _registry(**extra: str) -> dict[str, str]:
    return {**REGISTRY, **{kind: f"{__name__}:{function}" for kind, function in extra.items()}}


class RequirementTestCase(ProjectTestCase):
    """The starter project (PASS), a pinned clock, no signing key, and helpers for the fixtures."""

    def copy_fixture(self, source: Path) -> Path:
        target = self.tmp / source.name
        shutil.copytree(source, target)
        return target

    def offline(self) -> tuple[NetworkPolicy, RecordingOpener]:
        opener = RecordingOpener()
        return NetworkPolicy(opener=opener), opener

    def input_record(self, run: VerificationRun, input_id: str) -> Any:
        (found,) = [item for item in run.result.accounting.records if item.input_id == input_id]
        return found

    def edit_check(self, check_id: str, **changes: Any) -> None:
        document = self.manifest()
        for item in document["checks"]:
            if item["id"] == check_id:
                item.update(changes)
        self.save_manifest(document)

    def set_expected_rows(self, count: int) -> None:
        document = self.manifest()
        document["inputs"][0]["expected_rows"] = count
        self.save_manifest(document)

    def report_section(self, markdown: str, heading: str) -> str:
        """The body of one ``## heading`` section of report.md."""
        return markdown.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]


class RequiredBehaviourTests(RequirementTestCase):
    # -- 1-7: the PASS contract and what it refuses -----------------------

    def test_r01_empty_input_returns_abstain_and_exit_2(self) -> None:
        run = verify(EMPTY_MANIFEST)
        self.assertEqual((run.status, run.exit_code), (Status.ABSTAIN, 2))
        self.assertEqual(self.input_record(run, "measurements").state, InputState.EMPTY)
        self.assertEqual(run.result.counters["rows_examined"], 0, "an empty input has a true count of 0 rows")
        self.assertNotIn(Reason.VERIFIED, run.result.reasons)
        # The command line agrees: exit 2 and an ABSTAIN headline, never PASS.
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli.main(["verify", str(EMPTY_MANIFEST), "--output", str(self.tmp / "empty-run")])
        self.assertEqual(code, 2)
        self.assertTrue(stdout.getvalue().startswith("ABSTAIN"), stdout.getvalue())

    def test_r02_valid_input_returns_pass_with_execution_evidence(self) -> None:
        run = verify(VALID_MANIFEST)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.PASS, Reason.VERIFIED, 0))
        counters = run.result.counters
        self.assertGreaterEqual(counters["rows_examined"], 1)
        self.assertGreaterEqual(counters["inputs_opened"], 1)
        self.assertEqual(counters["checks_executed"], counters["checks_expected"])
        self.assertEqual(counters["checks_passed"], counters["checks_expected"])
        traces = index_invocations(run.ledger.entries)
        for check in run.result.checks:
            with self.subTest(check=check.check_id):
                self.assertEqual((check.execution_state, check.verdict), (ExecutionState.CHECKED, Status.PASS))
                self.assertGreaterEqual(check.rows_examined, 1)
                self.assertTrue(check.evidence, "a PASS carries non-empty evidence")
                trace = traces[check.invocation_id]
                self.assertEqual(trace.result, InvocationResult.COMPLETED)
        entries = run.evidence_manifest["entries"]
        self.assertIn("input", {entry["kind"] for entry in entries})
        self.assertEqual(sha256_canonical(run.evidence_manifest), run.result.evidence_manifest_sha256)
        written = write_run(run, self.tmp / "run", environ={})
        document = json.loads((written.run_dir / "run.json").read_text(encoding="utf-8"))
        for field in ("rows_examined", "checks_executed", "evidence_manifest_sha256", "started_at", "completed_at"):
            self.assertIsNotNone(document[field], field)
        self.assertTrue(verify_receipt(written.run_dir / "receipt.json").ok)

    def test_r03_pass_is_impossible_with_zero_examined_rows(self) -> None:
        self.set_checks({"id": "hollow", "kind": "hollow_pass", "version": "1", "required": True, "inputs": []})
        run = self.run_verify(registry=_registry(hollow_pass="claims_pass_without_rows"))
        self.assertNotEqual(run.status, Status.PASS)
        self.assertEqual(run.result.counters["rows_examined"], 0)
        hollow = self.result_of(run, "hollow")
        self.assertNotEqual(hollow.verdict, Status.PASS, "the engine must not record a PASS that examined nothing")
        self.assertIn(FailureMode.VACUOUS_PASS, run.result.failure_modes)

    def test_r04_pass_is_impossible_when_a_required_checker_did_not_run(self) -> None:
        self.edit_check("duplicates", kind="never_runs")
        registry = {**REGISTRY, "never_runs": "science_gate.mutations:skipped_checker"}
        run = self.run_verify(registry=registry)
        self.assertNotEqual(run.status, Status.PASS)
        skipped = self.result_of(run, "duplicates")
        self.assertEqual(skipped.execution_state, ExecutionState.SKIPPED)
        counters = run.result.counters
        self.assertLess(counters["checks_executed"], counters["checks_expected"])
        self.assertIn(Reason.PARTIAL_EXECUTION, run.result.reasons)
        # A checker that crashes did not run to a verdict either: ERROR, never PASS.
        self.edit_check("duplicates", kind="crashes")
        crashed = self.run_verify(registry=_registry(crashes="raises_while_checking"))
        self.assertEqual(crashed.status, Status.ERROR)
        self.assertEqual(self.result_of(crashed, "duplicates").verdict, Status.ERROR)

    def test_r05_narrated_verification_becomes_unverified(self) -> None:
        policy, opener = self.offline()
        run = verify(CITATIONS / "narrated-log" / "manifest.json", network=policy)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.UNVERIFIED, 2))
        self.assertIn(FailureMode.NARRATED_VERIFICATION, run.result.failure_modes)
        log = self.result_of(run, "citation-log")
        self.assertEqual((log.verdict, log.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        invariants = {invariant.name: invariant for invariant in run.result.invariants}
        tally = invariants["checked_claims_le_invocations"]
        self.assertIs(tally.holds, False, "eight claimed verifications against zero invocations")
        self.assertEqual(opener.calls, [])

    def test_r06_missing_required_files_remain_visible(self) -> None:
        (self.project / "data" / "measurements.csv").unlink()
        run = self.run_verify()
        record = self.input_record(run, "measurements")
        self.assertEqual((record.state, record.required), (InputState.MISSING, True))
        self.assertIsNone(record.sha256)
        self.assertNotEqual(run.status, Status.PASS)
        written = write_run(run, self.tmp / "run", environ={})
        document = json.loads((written.run_dir / "run.json").read_text(encoding="utf-8"))
        (listed,) = [item for item in document["accounting"]["inputs"] if item["id"] == "measurements"]
        self.assertEqual(listed["state"], "MISSING")
        evidence = json.loads((written.run_dir / "evidence-manifest.json").read_text(encoding="utf-8"))
        self.assertIn(("measurements", "MISSING"), {(item["name"], item["state"]) for item in evidence["absent"]})
        report = (written.run_dir / "report.md").read_text(encoding="utf-8")
        unresolved = self.report_section(report, "WHAT REMAINS UNRESOLVED")
        self.assertIn("required input `measurements` is MISSING", unresolved)

    def test_r07_partial_execution_cannot_appear_complete(self) -> None:
        self.update_manifest(limits={"max_rows": 4})
        run = self.run_verify()
        record = self.input_record(run, "measurements")
        self.assertEqual(record.state, InputState.PARTIAL)
        self.assertEqual((record.counts.admitted, record.counts.deferred), (4, 2))
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.PARTIAL_EXECUTION))
        self.assertIn(FailureMode.PARTIAL_EXECUTION, run.result.failure_modes)
        for check in run.result.checks:
            with self.subTest(check=check.check_id):
                self.assertNotEqual(check.verdict, Status.PASS, "every check here read a PARTIAL input")
        headline = write_run(run, self.tmp / "run", environ={}).headline
        self.assertTrue(headline.startswith("ABSTAIN (PARTIAL_EXECUTION)"), headline)

    # -- 8-12: content defects the checks must catch -----------------------

    def test_r08_duplicate_rows_are_detected(self) -> None:
        lines = self.data_lines()
        self.write_data("".join(lines + [lines[2]]))
        self.set_expected_rows(7)
        run = self.run_verify()
        duplicates = self.result_of(run, "duplicates")
        self.assertEqual(duplicates.verdict, Status.FAIL)
        self.assertIn("SYN-0002", json.dumps(duplicates.evidence))
        self.assertEqual(run.status, Status.FAIL)

    def test_r09_deleted_rows_are_detected_against_an_accepted_snapshot(self) -> None:
        lines = self.data_lines()
        self.write_data("".join(line for line in lines if not line.startswith("SYN-0003")))
        self.set_expected_rows(5)
        run = self.run_verify()
        snapshot = self.result_of(run, "snapshot")
        self.assertEqual((snapshot.verdict, snapshot.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.OMITTED_POPULATION, snapshot.failure_modes)
        self.assertIn("SYN-0003", json.dumps(snapshot.evidence))
        self.assertEqual(run.status, Status.FAIL)

    def test_r10_unregistered_claims_are_detected(self) -> None:
        run = verify(CLAIMS / "unregistered" / "manifest.json")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.UNVERIFIED, 2))
        claims = self.result_of(run, "claims")
        self.assertIn(FailureMode.EPHEMERAL_CLAIM, claims.failure_modes)
        (listed,) = claims.evidence["manuscript_scan"]["unregistered_tokens"]
        self.assertEqual((listed["line"], listed["text"], listed["classification"]), (7, "42.5", "UNREGISTERED"))

    def test_r11_numeric_rounding_cannot_create_false_agreement(self) -> None:
        # Both round to 0.1, yet they are different values: never equal.
        self.assertEqual(compare_decimal("0.15", "0.14").outcome, DISAGREES)
        # The stored value is rounded to the claim's printed precision only.
        self.assertEqual(compare_decimal("0.1", "0.14").outcome, AGREES_AT_STATED_PRECISION)
        # Half-even: 27.125 rounds to 27.12, so a half-up "27.13" must not agree.
        self.assertEqual(compare_decimal("27.13", "27.125").outcome, DISAGREES)
        values = self.manifest()["checks"][4]["params"]
        values["expected"] = [{"key": "SYN-0004", "value": "27.13"}]
        self.edit_check("values", params=values)
        run = self.run_verify()
        check = self.result_of(run, "values")
        self.assertEqual((check.verdict, check.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        # A registered claim of 6.2 against a stored 6.27 (both round to 6) disagrees too.
        claims = verify(CLAIMS / "rounding" / "manifest.json")
        result = self.result_of(claims, "claims")
        self.assertEqual((result.verdict, claims.status), (Status.FAIL, Status.FAIL))
        (record,) = [item for item in result.evidence["problem_claims"] if item["claim_id"] == "C-001"]
        self.assertEqual((record["disposition"], record["value_comparison"]["outcome"]), ("VALUE_DISAGREES", DISAGREES))

    def test_r12_thousands_separators_cannot_evade_comparison(self) -> None:
        self.assertEqual(compare_decimal("1,234", "1234", thousands=",").outcome, EXACT)
        self.assertEqual(compare_decimal("1,235", "1234", thousands=",").outcome, DISAGREES)
        undeclared = compare_decimal("1,234", "1234")
        self.assertEqual((undeclared.outcome, undeclared.agrees), (REQUIRES_HUMAN_REVIEW, None))
        counts = self.manifest()["checks"][5]["params"]
        counts["expected"] = [{"key": "SYN-0006", "value": "10,501"}]
        self.edit_check("counts", params=counts)
        run = self.run_verify()
        self.assertEqual(self.result_of(run, "counts").verdict, Status.FAIL, "stored '10,500' is 10500, not 10501")
        separators = verify(CLAIMS / "separators" / "manifest.json")
        self.assertEqual((separators.status, separators.result.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))

    # -- 13: determinism ---------------------------------------------------

    def test_r13_output_is_deterministic_under_different_hash_seeds(self) -> None:
        def run_cli(seed: str, output: Path) -> subprocess.CompletedProcess[str]:
            environment = {key: value for key, value in os.environ.items() if key != HMAC_KEY_FILE_ENV}
            environment.update(
                {
                    "PYTHONPATH": str(SRC_DIR),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": seed,
                    "SCIENCE_GATE_FIXED_TIME": FIXED_TIME,
                }
            )
            command = [sys.executable, "-m", "science_gate.cli", "verify", str(RICH / "manifest.json")]
            return subprocess.run(
                [*command, "--output", str(output)], env=environment, capture_output=True, text=True, timeout=600
            )

        first, second = self.tmp / "seed-0", self.tmp / "seed-4242"
        for seed, output in (("0", first), ("4242", second)):
            completed = run_cli(seed, output)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        names = sorted(path.name for path in first.iterdir())
        self.assertEqual(names, sorted(path.name for path in second.iterdir()))
        self.assertIn("receipt.json", names)
        for name in names:
            with self.subTest(file=name):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    # -- 14-17: protocol, time and citation sources -----------------------

    def test_r14_time_mismatch_becomes_source_mismatch(self) -> None:
        mismatched = {
            "id": "obs-0001",
            "local_time": "2026-03-10T14:30:00",
            "timezone": "+02:00",
            "utc": "2026-03-10T14:30:00Z",
        }
        self.write_json("time/events.json", time_document(mismatched))
        self.update_manifest(time_sources="time/events.json")
        self.add_checks({"id": "timing", "kind": "time_source", "version": "1", "required": True, "inputs": []})
        run = self.run_verify()
        timing = self.result_of(run, "timing")
        self.assertEqual((timing.verdict, timing.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        (event,) = timing.evidence["problem_events"]
        self.assertEqual((event["outcome"], event["computed_utc"]), ("UTC_MISMATCH", "2026-03-10T12:30:00Z"))
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))

    def test_r15_missing_reviewers_become_protocol_broken(self) -> None:
        self.write_json("reviews/verdicts.json", reviews_document("reviewer-a"))
        self.update_manifest(
            reviews={"required_reviewers": ["reviewer-a", "reviewer-b"], "verdicts": "reviews/verdicts.json"}
        )
        self.add_checks({"id": "reviewers", "kind": "reviewer_protocol", "version": "1", "inputs": []})
        run = self.run_verify()
        reviewers = self.result_of(run, "reviewers")
        self.assertEqual((reviewers.verdict, reviewers.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
        self.assertEqual(reviewers.evidence["missing_reviewers"], ["reviewer-b"])
        self.assertIn(FailureMode.PROTOCOL_DRIFT, reviewers.failure_modes)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN, 2))

    def test_r16_wrong_author_and_nonexistent_doi_fixtures_work_offline(self) -> None:
        cases = {
            "wrong-author": ("citation-metadata", "C2", "FIELD_MISMATCH", ["AUTHOR_MISMATCH"]),
            "nonexistent-doi": ("doi-resolution", "C3", "RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES", None),
        }
        for name, (failing_check, citation_id, disposition, defects) in cases.items():
            with self.subTest(fixture=name):
                policy, opener = self.offline()
                run = verify(CITATIONS / name / "manifest.json", network=policy)
                self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
                self.assertEqual(self.result_of(run, failing_check).verdict, Status.FAIL)
                metadata = self.result_of(run, "citation-metadata").evidence["citations"]
                (item,) = [entry for entry in metadata if entry["citation_id"] == citation_id]
                self.assertEqual(item["primary_disposition"], disposition)
                if defects is not None:
                    self.assertEqual(item["defects"], defects)
                self.assertFalse(run.network.live)
                self.assertEqual(opener.calls, [], "the frozen record set answers everything offline")
        resolutions = self.result_of(run, "doi-resolution").evidence["resolutions"]
        states = {item["doi"]: item["state"] for item in resolutions}
        self.assertEqual(states["10.5555/sgate.fx.9999"], "DOI_NOT_RESOLVED_AT_CAPTURE")

    def test_r17_network_failure_becomes_source_unavailable(self) -> None:
        policy, opener = self.offline()
        run = verify(CITATIONS / "missing-from-frozen" / "manifest.json", live=True, network=policy)
        self.assertTrue(run.network.live)
        self.assertEqual(len(opener.calls), 1, "exactly the one DOI missing from the frozen set is fetched live")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE, 2))
        resolutions = self.result_of(run, "doi-resolution").evidence["resolutions"]
        states = {item["doi"]: item["state"] for item in resolutions}
        self.assertEqual(states["10.5555/sgate.fx.0002"], "SOURCE_UNAVAILABLE")
        metadata = self.result_of(run, "citation-metadata").evidence["citations"]
        (item,) = [entry for entry in metadata if entry["citation_id"] == "C2"]
        self.assertEqual(item["primary_disposition"], "SOURCE_UNAVAILABLE", "unavailable is never 'not found'")

    # -- 18: mutation testing ----------------------------------------------

    def test_r18_mutation_testing_reports_detections_and_blind_spots(self) -> None:
        rich = self.copy_fixture(RICH)
        report = mutate(rich / "manifest-blind-spot.json", operators=[M03, M04, M05, M06])
        records = {record.mutation_id: record for record in report.mutations}
        self.assertEqual([records[item].detected for item in (M03, M04)], [True, True])
        for mutation_id in (M05, M06):
            with self.subTest(blind_spot=mutation_id):
                record = records[mutation_id]
                self.assertEqual((record.detected, record.blind_spot), (False, True))
                self.assertEqual(record.actual_result["status"], "FAIL", "a non-PASS status alone is not a detection")
        counts = report.counts
        self.assertEqual((counts["detected_mutations"], counts["escaped_mutations"]), (2, 2))
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.BLIND_SPOT, 1))
        self.assertEqual(report.sensitivity["fraction"], "2/4")
        markdown = render_markdown(report)
        detected = markdown.split("## DETECTED")[1].split("## BLIND SPOTS")[0]
        blind = markdown.split("## BLIND SPOTS")[1].split("## SKIPPED")[0]
        self.assertIn(M03, detected)
        self.assertIn(M05, blind)
        self.assertNotIn(M05, detected)

    # -- 19-20: dependencies -------------------------------------------------

    def test_r19_upstream_changes_mark_descendants_stale(self) -> None:
        project = self.copy_fixture(DEPENDENCIES)
        with (project / "design" / "protocol.md").open("ab") as handle:
            handle.write(b"\nSynthetic amendment: the invented design changed upstream.\n")
        graph = load_graph(project, "graph/graph.json")
        detection = graph.detect_changes()
        stale = {"study-design", "admitted-evidence", "analysis-run", "site-means", "figure-1", "conclusion-1"}
        for node_id in stale:
            with self.subTest(node=node_id):
                self.assertEqual(graph.validity(node_id), Validity.STALE_PENDING_REVALIDATION)
        for node_id in ("source-snapshot", "table-2", "conclusion-2"):
            with self.subTest(unaffected=node_id):
                self.assertEqual(graph.validity(node_id), Validity.CURRENT)
        assessment = assess(graph, detection)
        self.assertEqual((assessment.status, assessment.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.STALE_DEPENDENCY, assessment.failure_modes)
        self.assertIs(assessment.publication_block["blocked"], True)
        run = verify(project / "manifest.json")
        currency = self.result_of(run, "currency")
        self.assertEqual(currency.verdict, Status.FAIL)
        self.assertIn(FailureMode.STALE_DEPENDENCY, currency.failure_modes)

    def test_r20_revalidation_distinguishes_unchanged_and_changed_results(self) -> None:
        project = self.copy_fixture(DEPENDENCIES)
        graph = load_graph(project, "graph/graph.json")
        graph.impact("study-design")
        self.assertEqual(graph.validity("conclusion-1"), Validity.STALE_PENDING_REVALIDATION)
        unchanged = graph.revalidate("study-design")
        self.assertEqual(unchanged.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual(graph.validity("study-design"), Validity.REVALIDATED_UNCHANGED)
        self.assertIn("conclusion-1", {item.node_id for item in unchanged.cleared}, "early cutoff")
        self.assertEqual(graph.validity("conclusion-1"), Validity.CURRENT)

        protocol = project / "design" / "protocol.md"
        before = graph.recorded_sha256("study-design")
        protocol.write_bytes(protocol.read_bytes() + b"\nSynthetic amendment.\n")
        changed = graph.revalidate("study-design")
        self.assertEqual(changed.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual(graph.validity("study-design"), Validity.REVALIDATED_CHANGED)
        self.assertEqual(graph.recorded_sha256("study-design"), sha256_bytes(protocol.read_bytes()))
        self.assertNotEqual(graph.recorded_sha256("study-design"), before)
        self.assertEqual(changed.cleared, ())
        self.assertIn("conclusion-1", {item.node_id for item in changed.still_pending})
        self.assertEqual(graph.validity("conclusion-1"), Validity.STALE_PENDING_REVALIDATION)
        history = [(item.from_state, item.to_state) for item in graph.history("study-design")]
        self.assertIn((Validity.REVALIDATED_UNCHANGED, Validity.REVALIDATED_CHANGED), history)

    # -- 21-24: ledger and receipts -----------------------------------------

    def test_r21_every_verdict_points_to_an_invocation(self) -> None:
        self.edit_check("duplicates", kind="crashes")
        run = self.run_verify(registry=_registry(crashes="raises_while_checking"))
        traces = index_invocations(run.ledger.entries)
        started = {entry["invocation_id"]: entry for entry in run.ledger.entries if entry["result"] == "STARTED"}
        self.assertIn(Status.ERROR, {check.verdict for check in run.result.checks})
        for check in run.result.checks:
            with self.subTest(check=check.check_id, verdict=check.verdict.value):
                trace = traces[check.invocation_id]
                self.assertEqual((trace.check_id, trace.verdict), (check.check_id, check.verdict))
                self.assertEqual(started[check.invocation_id]["check_kind"], check.kind)
        (judged,) = [item for item in run.result.invariants if item.name == "every_verdict_has_invocation"]
        self.assertIs(judged.holds, True)
        # A verdict without an invocation is a violation, not an omission.
        orphan = dataclasses.replace(run.result.checks[0], invocation_id=None)
        result = every_verdict_has_invocation(InvariantContext(entries=run.ledger.entries, checks=(orphan,)))
        self.assertIs(result.holds, False)

    def test_r22_every_invocation_has_a_terminal_result(self) -> None:
        run = self.run_verify()
        traces = index_invocations(run.ledger.entries)
        # Controls (falsifier witnesses, the canary pair, the comparator self-test) are invocations too
        # (ARCHITECTURE.md 17.5, 17.6); every declared check still has exactly one.
        subjects = [trace for trace in traces.values() if not (trace.check_id or "").startswith("control:")]
        self.assertEqual(len(subjects), len(run.result.checks))
        self.assertEqual(
            len(run.ledger.entries),
            1 + 2 * len(traces),
            "one PLAN entry, then one STARTED and one terminal entry per invocation",
        )
        for invocation_id, trace in traces.items():
            with self.subTest(invocation=invocation_id):
                self.assertIn(trace.result, TERMINAL_INVOCATION_RESULTS)
        # Drop one terminal entry: the invocation is left open, and that is detected.
        rows_invocation = self.result_of(run, "rows").invocation_id
        entries = [
            entry
            for entry in run.ledger.entries
            if not (entry["invocation_id"] == rows_invocation and entry["result"] != InvocationResult.STARTED.value)
        ]
        result = every_invocation_has_terminal_result(InvariantContext(entries=tuple(entries)))
        self.assertIs(result.holds, False)
        self.assertIn(f"{rows_invocation}: started but never reached a terminal result", result.detail)

    def test_r23_protected_content_changes_alter_receipt_hashes(self) -> None:
        def content_hash() -> str:
            run = self.run_verify()
            seal = run.ledger.seal()
            receipt = build_run_receipt(
                run.result,
                ledger_head_sha256=seal["ledger_head_sha256"],
                ledger_length=seal["ledger_length"],
                environ={},
            )
            self.assertEqual(receipt["body"]["disclaimer"], DISCLAIMER)
            return receipt["content_sha256"]

        baseline = content_hash()
        self.assertEqual(content_hash(), baseline, "the same content under the same clock gives the same receipt")
        lines = self.data_lines()
        self.write_data("".join(line.replace("SYN-0003,site-beta,3.5", "SYN-0003,site-beta,3.6") for line in lines))
        changed_data = content_hash()
        self.assertNotEqual(changed_data, baseline)
        snapshot = self.project / "snapshots" / "accepted.json"
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        snapshot.write_text(json.dumps(document, indent=4), encoding="utf-8")  # same content, different bytes
        self.assertNotEqual(content_hash(), changed_data)

    def test_r24_missing_keys_produce_unsigned(self) -> None:
        run = self.run_verify()
        seal = run.ledger.seal()

        def receipt(environ: dict[str, str]) -> dict[str, Any]:
            return build_run_receipt(
                run.result,
                ledger_head_sha256=seal["ledger_head_sha256"],
                ledger_length=seal["ledger_length"],
                environ=environ,
            )

        empty_key = self.write("keys/empty.key", b"")
        for label, environ in {
            "no variable": {},
            "missing file": {HMAC_KEY_FILE_ENV: str(self.tmp / "keys" / "absent.key")},
            "empty file": {HMAC_KEY_FILE_ENV: str(empty_key)},
        }.items():
            with self.subTest(case=label):
                unsigned = receipt(environ)
                self.assertEqual(unsigned["signature_state"], SignatureState.UNSIGNED.value)
                self.assertIsNone(unsigned["signature"])
                self.assertIsNone(unsigned["key_id"])
        key = self.write("keys/synthetic.key", b"synthetic-test-key-material-0123456789")
        signed = receipt({HMAC_KEY_FILE_ENV: str(key)})
        self.assertEqual(signed["signature_state"], SignatureState.SIGNED_HMAC_SHA256.value)
        self.assertEqual(signed["content_sha256"], receipt({})["content_sha256"], "signing never changes content")

    # -- 25: packaging -------------------------------------------------------

    def test_r25_controlled_local_packaging_excludes_protected_inputs(self) -> None:
        output = self.tmp / "package"
        result = build_package(CONTROLLED_LOCAL / "manifest.json", output, environ={})
        self.assertEqual(result.exit_code, 0)
        document = result.document
        self.assertEqual(document["corpus"]["access_class"], "CONTROLLED_LOCAL")
        self.assertTrue(document["files"])
        for item in document["files"]:
            with self.subTest(file=item["path"]):
                self.assertEqual(item["disposition"], Disposition.WITHHELD.value)
                self.assertEqual(item["basis"], Basis.ACCESS_CLASS_CONTROLLED_LOCAL.value)
                self.assertRegex(item["sha256"], "^[0-9a-f]{64}$")
                self.assertTrue(item["retrieval"])
        self.assertFalse((output / "evaluation").exists())
        for path in output.rglob("*"):
            if path.is_file():
                with self.subTest(written=path.name):
                    self.assertNotIn(b"CTLSYN-", path.read_bytes(), "protected content must never be copied")

    # -- 26-28: what mutation testing may and may not count -------------------

    def test_r26_invalid_baseline_prevents_sensitivity(self) -> None:
        report = mutate(EMPTY_MANIFEST)
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.INVALID_BASELINE, 1))
        self.assertIsNone(report.counts)
        self.assertIsNone(report.sensitivity)
        document = report.to_dict()
        self.assertEqual(document["message"], INVALID_BASELINE_MESSAGE)
        for key in (*COUNT_KEYS, "sensitivity", "mutations"):
            self.assertNotIn(key, document)
        markdown = render_markdown(report)
        self.assertIn(INVALID_BASELINE_MESSAGE, markdown)
        self.assertNotIn("## SENSITIVITY", markdown)

    def test_r27_skipped_and_non_applicable_mutations_are_not_counted_as_detections(self) -> None:
        rich = self.copy_fixture(RICH)
        report = mutate(rich / "manifest-core.json", operators=[M03])
        counts = report.counts
        self.assertEqual(
            (counts["executed_mutations"], counts["detected_mutations"], counts["escaped_mutations"]), (1, 1, 0)
        )
        self.assertEqual(counts["not_applicable_mutations"], len(CORE_NOT_APPLICABLE))
        self.assertEqual(counts["skipped_mutations"], len(OPERATOR_IDS) - 1 - len(CORE_NOT_APPLICABLE))
        for record in report.mutations:
            if record.execution_state is ExecutionState.CHECKED:
                continue
            with self.subTest(mutation=record.mutation_id, state=record.execution_state.value):
                self.assertIsNone(record.detected)
                self.assertIsNone(record.blind_spot)
                self.assertIsNone(record.actual_result)
        not_applicable = {r.mutation_id for r in report.mutations if r.execution_state is ExecutionState.NOT_APPLICABLE}
        self.assertEqual(not_applicable, CORE_NOT_APPLICABLE)
        self.assertEqual(report.sensitivity["fraction"], "1/1", "the denominator is executed mutations only")

    def test_r28_metadata_change_under_unchanged_pass_summary_is_detected_or_reported(self) -> None:
        rich = self.copy_fixture(RICH)
        caught = mutate(rich / "manifest-core.json", operators=[M20])
        (record,) = [item for item in caught.mutations if item.mutation_id == M20]
        self.assertIs(record.detected, True)
        self.assertIn("check:summary_consistency", {item.detector for item in record.detecting_invariants_fired})
        # With the summary check optional, nothing required notices: reported as a blind spot, never as PASS.
        document = json.loads((rich / "manifest-core.json").read_text(encoding="utf-8"))
        for check in document["checks"]:
            if check["id"] == "summary":
                check["required"] = False
        (rich / "manifest-optional-summary.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
        missed = mutate(rich / "manifest-optional-summary.json", operators=[M20])
        (record,) = [item for item in missed.mutations if item.mutation_id == M20]
        self.assertEqual((record.detected, record.blind_spot), (False, True))
        self.assertEqual((missed.status, missed.reason), (Status.FAIL, Reason.BLIND_SPOT))
        # A summary that leaves evidence unpinned says so itself.
        summary_path = rich / "claims" / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        del summary["pinned"]["documents"]["reviews/verdicts.json"]
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        run = verify(rich / "manifest-core.json")
        check = self.result_of(run, "summary")
        self.assertEqual((check.verdict, check.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
        self.assertEqual(check.evidence["blind_spots"]["documents"], ["reviews/verdicts.json"])
        self.assertNotEqual(run.status, Status.PASS)



class RequirementCatalogueTest(unittest.TestCase):
    def test_one_test_per_numbered_requirement(self) -> None:
        names = sorted(name for name in dir(RequiredBehaviourTests) if name.startswith("test_r"))
        self.assertEqual([name[6:8] for name in names], [f"{number:02d}" for number in range(1, 29)])


if __name__ == "__main__":
    unittest.main()
