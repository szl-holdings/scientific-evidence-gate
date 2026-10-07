"""Falsifier witnesses for every PASS, and the run-level canary (section 17.5, extension #1).

A PASS is kept only when the same checker, with the same params, rejected a
known-bad variant of the evidence it just passed, inside its own ledger
invocation. The canary proves the result builder and ledger themselves can
still record a failure. Every fixture is synthetic.
"""

from __future__ import annotations

import json
import shutil
import unittest
from typing import Any
from unittest import mock

from _project import REVIEWERS, TIME_EVENT, VALID_MANIFEST, ProjectTestCase, check, reviews_document, time_document

from science_gate import verifier
from science_gate._canonical import sha256_canonical
from science_gate.discovery import discover
from science_gate.invariants import (
    CANARY_MUST_FAIL,
    CANARY_MUST_PASS,
    COMPARATOR_CONTROL,
    InvariantContext,
    falsifier_check_id,
    is_control,
    pass_requires_falsifier_witness,
)
from science_gate.ledger import index_invocations, parse_jsonl, verify_chain
from science_gate.manifests import load_manifest
from science_gate.models import (
    ExecutionState,
    FailureMode,
    FalsifierCase,
    FalsifierOutcome,
    InputOverride,
    InputState,
    Reason,
    Status,
    WitnessState,
)
from science_gate.verifier import (
    FALSIFIERS,
    REGISTRY,
    SUMMARY_SCHEMA,
    CheckContext,
    CheckOutcome,
    VerificationRun,
    checker_sha256,
    module_source_sha256,
    params_sha256,
    verify,
)

# --- synthetic kinds and generators registered only by these tests ----------


def always_pass(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A defective checker: whatever it is shown, it passes."""
    rows = sum(len(ctx.inputs[input_id].rows or ()) for input_id in spec.inputs)
    return CheckOutcome(ExecutionState.CHECKED, Status.PASS, Reason.VERIFIED, rows_examined=rows, evidence={"rows": rows})


def falsify_always_pass(ctx: CheckContext, spec: Any, result: Any) -> tuple[FalsifierCase, ...]:
    """An empty input that any honest row checker must reject."""
    opened = ctx.inputs[spec.inputs[0]]
    override = InputOverride((dict(opened.rows[0].values),), opened.columns)
    return (FalsifierCase("one-row", "a single row", Status.FAIL, Reason.SOURCE_MISMATCH, inputs={opened.input_id: override}),)


def falsify_raises(ctx: CheckContext, spec: Any, result: Any) -> tuple[FalsifierCase, ...]:
    raise RuntimeError("synthetic generator crash")


def falsify_returns_junk(ctx: CheckContext, spec: Any, result: Any) -> Any:
    return ["not a case"]


def falsify_expects_the_wrong_rejection(ctx: CheckContext, spec: Any, result: Any) -> tuple[FalsifierCase, ...]:
    """A real known-bad case, but the rejection it names is not the one row_count gives."""
    (case,) = verifier.falsify_row_count(ctx, spec, result)
    return (FalsifierCase(case.case_id, case.description, Status.ABSTAIN, Reason.UNVERIFIED, inputs=case.inputs),)


TEST_REGISTRY = {**REGISTRY, "always_pass": f"{__name__}:always_pass", "rows_again": "science_gate.verifier:check_row_count"}
TEST_FALSIFIERS = {**FALSIFIERS, "always_pass": f"{__name__}:falsify_always_pass"}

#: The section 17.5 table for the engine's own kinds: case id and expected rejection.
BUILT_IN_CASES = {
    "row_count": ("drop-last-row", Status.FAIL, Reason.SOURCE_MISMATCH),
    "required_columns": ("drop-column", Status.FAIL, Reason.SOURCE_MISMATCH),
    "duplicate_rows": ("duplicate-first-row", Status.FAIL, Reason.SOURCE_MISMATCH),
    "snapshot_completeness": ("delete-accepted-row", Status.FAIL, Reason.SOURCE_MISMATCH),
    "numeric_agreement": ("shift-stored-value", Status.FAIL, Reason.SOURCE_MISMATCH),
    "reviewer_protocol": ("drop-required-reviewer", Status.ABSTAIN, Reason.PROTOCOL_BROKEN),
    "time_source": ("shift-utc", Status.FAIL, Reason.SOURCE_MISMATCH),
    "summary_consistency": ("alter-pinned-digest", Status.FAIL, Reason.SOURCE_MISMATCH),
}


def terminal_entries(run: VerificationRun) -> dict[str, dict[str, Any]]:
    return {entry["invocation_id"]: entry for entry in run.ledger.entries if entry.get("completed_at") is not None}


def falsifier_entries(entries: Any, subject: Any, record: dict[str, Any]) -> list[dict[str, Any]]:
    """The ledger entries of one recorded falsifier: its control id, bound to the subject's invocation."""
    terminal = [
        entry
        for entry in entries
        if entry.get("check_id") == record["control_id"]
        and entry.get("completed_at") is not None
        and entry["evidence"].get("subject_invocation_id") == subject.invocation_id
    ]
    if len(terminal) != 1:
        return terminal
    return [entry for entry in entries if entry.get("invocation_id") == terminal[0]["invocation_id"]]


class ValidDemoWitnessTests(unittest.TestCase):
    """#1 (a): the valid demo passes, and every PASS carries a ledger-backed falsifier witness."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = verify(VALID_MANIFEST)

    def test_every_pass_has_a_rejecting_falsifier_with_matching_digests(self) -> None:
        run = self.demo
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.PASS, Reason.VERIFIED, 0))
        written = parse_jsonl(run.ledger.to_jsonl())  # exactly the bytes ledger.jsonl holds
        seal = run.ledger.seal()
        chain = verify_chain(written, seal["ledger_head_sha256"], seal["ledger_length"], run_id=run.result.run_id)
        self.assertTrue(chain.intact, chain.problems)
        assert run.manifest is not None
        specs = {spec.check_id: spec for spec in run.manifest.checks}
        for result in run.result.checks:
            with self.subTest(check=result.check_id):
                self.assertIs(result.verdict, Status.PASS)
                self.assertEqual(result.evidence["falsification"], WitnessState.WITNESSED.value)
                module = REGISTRY[result.kind].partition(":")[0]
                expected_checker = checker_sha256(REGISTRY[result.kind], module_source_sha256(module))
                expected_params = params_sha256(specs[result.check_id].params)
                self.assertEqual(result.evidence["checker_sha256"], expected_checker)
                self.assertEqual(result.evidence["params_sha256"], expected_params)
                falsifiers = result.evidence["falsifiers"]
                self.assertGreaterEqual(len(falsifiers), 1)
                for record in falsifiers:
                    self.assertEqual(record["outcome"], FalsifierOutcome.REJECTED.value)
                    self.assertEqual(record["actual"]["verdict"], "FAIL")
                    self.assertEqual((record["checker_sha256"], record["params_sha256"]), (expected_checker, expected_params))
                    self.assertEqual(record["control_id"], falsifier_check_id(result.check_id, record["case_id"]))
                    # Its invocation is in ledger.jsonl: one STARTED and one terminal entry, bound to this PASS.
                    started, entry = falsifier_entries(written, result, record)
                    self.assertEqual(started["result"], "STARTED")
                    self.assertEqual(started["invocation_id"], entry["invocation_id"])
                    self.assertEqual((entry["verdict"], entry["reason"]), ("FAIL", record["actual"]["reason"]))
                    self.assertEqual(entry["evidence"]["checker_sha256"], expected_checker)
                    self.assertEqual(entry["evidence"]["params_sha256"], expected_params)
                    self.assertEqual(entry["evidence"]["control"], "falsifier")
        controls = run.result.controls["falsifiers"]
        self.assertEqual(controls["WITNESSED"], sorted(result.check_id for result in run.result.checks))
        self.assertEqual(controls["invocations"], len(run.result.checks))

    def test_each_built_in_kind_uses_its_section_17_5_case(self) -> None:
        for result in self.demo.result.checks:
            with self.subTest(check=result.check_id):
                case_id, verdict, reason = BUILT_IN_CASES[result.kind]
                (record,) = result.evidence["falsifiers"]
                self.assertEqual(record["case_id"], case_id)
                self.assertEqual(record["expected"], {"verdict": verdict.value, "reason": reason.value})

    def test_ledger_order_is_subject_started_then_falsifiers_then_subject_terminal(self) -> None:
        entries = self.demo.ledger.entries
        rows = next(result for result in self.demo.result.checks if result.check_id == "rows")
        positions = [entry["seq"] for entry in entries if entry["invocation_id"] == rows.invocation_id]
        inner = [entry["seq"] for entry in falsifier_entries(entries, rows, rows.evidence["falsifiers"][0])]
        self.assertEqual(len(positions), 2)
        self.assertTrue(positions[0] < inner[0] < inner[1] < positions[1])

    def test_falsifier_inputs_carry_their_overlay_digests(self) -> None:
        rows = next(result for result in self.demo.result.checks if result.check_id == "rows")
        started, _ = falsifier_entries(self.demo.ledger.entries, rows, rows.evidence["falsifiers"][0])
        real = self.demo.result.accounting.record("measurements").sha256
        self.assertEqual(started["input_ids"], ["measurements"])
        self.assertNotEqual(started["input_sha256s"]["measurements"], real, "the falsifier saw the overlay, not the file")


class RefutedAndMissingWitnessTests(ProjectTestCase):
    def test_b_an_always_pass_kind_is_refuted_and_fails(self) -> None:
        # #1 (b): its falsifier also PASSes, so the miss is proven (D2).
        self.add_checks(check("lenient", "always_pass"))
        run = self.run_verify(registry=TEST_REGISTRY, falsifiers=TEST_FALSIFIERS)
        lenient = self.result_of(run, "lenient")
        self.assertEqual((lenient.verdict, lenient.reason), (Status.FAIL, Reason.BLIND_SPOT))
        self.assertIn(FailureMode.DEFECTIVE_VERIFICATION, lenient.failure_modes)
        self.assertEqual(lenient.evidence["falsification"], WitnessState.REFUTED.value)
        self.assertEqual(lenient.evidence["falsifiers"][0]["outcome"], FalsifierOutcome.ACCEPTED.value)
        self.assertTrue(any(text.startswith("FALSIFIER_REFUTED:") for text in lenient.diagnostics))
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.FAIL, Reason.BLIND_SPOT, 1))
        self.assertEqual(run.result.controls["falsifiers"]["REFUTED"], ["lenient"])

    def test_c_a_kind_without_a_generator_abstains_as_a_blind_spot(self) -> None:
        # #1 (c): an honest checker, but nothing shows it could have failed here.
        self.add_checks(check("recount", "rows_again"))
        run = self.run_verify(registry=TEST_REGISTRY, falsifiers=TEST_FALSIFIERS)
        recount = self.result_of(run, "recount")
        self.assertEqual((recount.verdict, recount.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
        self.assertIn(FailureMode.VACUOUS_PASS, recount.failure_modes)
        self.assertEqual(recount.evidence["falsification"], WitnessState.NO_GENERATOR.value)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.BLIND_SPOT, 2))

    def test_an_instance_without_a_known_bad_case_abstains(self) -> None:
        # row_count can only be falsified against an INDEPENDENT expectation.
        document = self.manifest()
        document["inputs"][0]["denominator_source"] = "OBSERVED"
        self.save_manifest(document)
        self.set_checks(check("rows", "row_count"))
        run = self.run_verify()
        rows = self.result_of(run, "rows")
        self.assertEqual(rows.evidence["falsification"], WitnessState.NO_CASE.value)
        self.assertEqual((rows.verdict, rows.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
        self.assertEqual(rows.evidence["falsifiers"], [])

    def test_a_broken_generator_or_an_inconclusive_case_never_witnesses(self) -> None:
        for name in ("falsify_raises", "falsify_returns_junk", "falsify_expects_the_wrong_rejection"):
            with self.subTest(generator=name):
                falsifiers = {**FALSIFIERS, "row_count": f"{__name__}:{name}"}
                run = self.run_verify(falsifiers=falsifiers)
                rows = self.result_of(run, "rows")
                self.assertEqual(rows.evidence["falsification"], WitnessState.UNWITNESSED.value)
                self.assertEqual((rows.verdict, rows.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
                self.assertNotEqual(run.status, Status.PASS)
        inconclusive = self.result_of(self.run_verify(falsifiers=falsifiers), "rows")
        self.assertEqual(inconclusive.evidence["falsifiers"][0]["outcome"], FalsifierOutcome.INCONCLUSIVE.value)

    def test_d_a_forced_pass_builder_is_caught_by_the_canary(self) -> None:
        # #1 (d): the result builder is patched to say PASS everywhere; only the canary can notice.
        original = verifier._result_from

        def force_pass(spec: Any, invocation_id: str, outcome: Any) -> Any:
            forced = CheckOutcome(
                ExecutionState.CHECKED,
                Status.PASS,
                Reason.VERIFIED,
                rows_examined=max(outcome.rows_examined or 0, 1),
                evidence=dict(outcome.evidence) or {"forced": True},
            )
            return original(spec, invocation_id, forced)

        with mock.patch.object(verifier, "_result_from", force_pass):
            run = self.run_verify()
        self.assertEqual({result.verdict for result in run.result.checks}, {Status.PASS}, "every subject check says PASS")
        canary = run.result.controls["canary"]
        self.assertEqual(canary["must_fail"]["verdict"], "PASS")
        self.assertIs(canary["holds"], False)
        (violated,) = [item for item in run.result.invariants if item.name == "canary_controls_hold"]
        self.assertIs(violated.holds, False)
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
        self.assertIn(FailureMode.DEFECTIVE_VERIFICATION, run.result.failure_modes)
        self.assertEqual(run.result.reason, Reason.BLIND_SPOT)


class CanaryTests(unittest.TestCase):
    """The must-fail canary and its known-good twin run in every verify, after the comparator."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = verify(VALID_MANIFEST)

    def test_controls_close_the_ledger_in_order(self) -> None:
        tail = [entry["check_id"] for entry in self.demo.ledger.entries[-6:]]
        self.assertEqual(tail, [COMPARATOR_CONTROL] * 2 + [CANARY_MUST_FAIL] * 2 + [CANARY_MUST_PASS] * 2)

    def test_the_canary_is_the_duplicate_rows_checker_over_an_in_memory_input(self) -> None:
        canary = self.demo.result.controls["canary"]
        self.assertEqual((canary["must_fail"]["verdict"], canary["must_pass"]["verdict"], canary["holds"]), ("FAIL", "PASS", True))
        entries = terminal_entries(self.demo)
        for name in ("must_fail", "must_pass"):
            with self.subTest(canary=name):
                entry = entries[canary[name]["invocation_id"]]
                self.assertEqual((entry["check_kind"], entry["check_version"]), ("duplicate_rows", "1"))
                self.assertEqual(entry["input_ids"], ["control-canary"])
                self.assertEqual(entry["evidence"]["control"], "canary")

    def test_controls_are_never_results_and_never_falsified(self) -> None:
        self.assertFalse(any(is_control(result.check_id) for result in self.demo.result.checks))
        traces = index_invocations(self.demo.ledger.entries)
        falsified = {trace.check_id for trace in traces.values() if trace.check_id.startswith("control:falsifier:")}
        self.assertFalse(any(":canary" in item or ":comparator" in item for item in falsified))
        self.assertEqual(self.demo.result.counters["checks_declared"], len(self.demo.result.checks))


class BuiltInGeneratorTests(ProjectTestCase):
    """Each engine-owned kind passes on the starter project, is witnessed, and fails on its own known-bad case."""

    def setUp(self) -> None:
        super().setUp()
        self.write_json("reviews/verdicts.json", reviews_document(*REVIEWERS))
        self.write_json("time/events.json", time_document(TIME_EVENT))
        self.update_manifest(
            reviews={"required_reviewers": REVIEWERS, "verdicts": "reviews/verdicts.json"},
            time_sources="time/events.json",
            summary_claim="claims/summary.json",
        )
        pinned_documents = {path: self.file_digest(path) for path in ("snapshots/accepted.json", "reviews/verdicts.json", "time/events.json")}
        self.write_json(
            "claims/summary.json",
            {
                "schema": SUMMARY_SCHEMA,
                "status": "PASS",
                "pinned": {
                    "inputs": {"measurements": {"sha256": self.file_digest("data/measurements.csv"), "rows": 6}},
                    "documents": pinned_documents,
                },
            },
        )
        self.add_checks(
            check("reviewers", "reviewer_protocol", inputs=()),
            check("timing", "time_source", inputs=()),
            check("summary", "summary_consistency", inputs=()),
        )

    def test_every_engine_kind_is_witnessed_by_its_own_case(self) -> None:
        run = self.run_verify()
        self.assertEqual(run.status, Status.PASS)
        self.assertEqual({result.kind for result in run.result.checks}, set(BUILT_IN_CASES))
        for result in run.result.checks:
            with self.subTest(kind=result.kind):
                case_id, verdict, reason = BUILT_IN_CASES[result.kind]
                (record,) = result.evidence["falsifiers"]
                self.assertEqual((record["case_id"], record["outcome"]), (case_id, "REJECTED"))
                self.assertEqual((record["actual"]["verdict"], record["actual"]["reason"]), (verdict.value, reason.value))

    def test_the_known_bad_cases_fail_for_real_too(self) -> None:
        # Each case written to disk: the real check rejects it the same way, so the witness is not an artifact.
        lines = self.data_lines()
        self.write_data("".join(lines[:-1]))
        self.assertEqual(self.result_of(self.run_verify(), "rows").verdict, Status.FAIL)
        self.write_data("".join(lines + [lines[1]]))
        self.assertEqual(self.result_of(self.run_verify(), "duplicates").verdict, Status.FAIL)
        self.write_data("".join(line.replace("12.40", "12.50") for line in lines))
        self.assertEqual(self.result_of(self.run_verify(), "values").verdict, Status.FAIL)
        self.write_data("".join(lines))
        self.write_json("reviews/verdicts.json", reviews_document(REVIEWERS[1]))
        reviewers = self.result_of(self.run_verify(), "reviewers")
        self.assertEqual((reviewers.verdict, reviewers.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
        self.write_json("time/events.json", time_document({**TIME_EVENT, "utc": "2026-03-10T13:30:00Z"}))
        self.assertEqual(self.result_of(self.run_verify(), "timing").verdict, Status.FAIL)


class OverlayTests(ProjectTestCase):
    """CheckContext.overlay: in memory, offline, and digested by content."""

    def context(self) -> CheckContext:
        manifest = load_manifest(self.manifest_path)
        _, opened = discover(manifest)
        ctx = CheckContext(manifest, opened)
        ctx.preload(spec.kind for spec in manifest.checks)
        return ctx

    def test_an_overridden_input_is_parsed_in_memory_with_closure_re_evaluated(self) -> None:
        ctx = self.context()
        rows = tuple(dict(row.values) for row in ctx.inputs["measurements"].rows[:-1])
        override = InputOverride(rows, ctx.inputs["measurements"].columns)
        case = FalsifierCase("drop", "one row fewer", Status.FAIL, Reason.SOURCE_MISMATCH, inputs={"measurements": override})
        overlay = ctx.overlay(case)
        opened = overlay.inputs["measurements"]
        self.assertEqual((opened.state, len(opened.rows), opened.record.rows), (InputState.PARSED, 5, 5))
        self.assertEqual([row.index for row in opened.rows], [1, 2, 3, 4, 5])
        self.assertTrue(all(row.line is None for row in opened.rows))
        self.assertEqual((opened.record.closure.expected, opened.record.closure.holds), (6, False))
        self.assertEqual(opened.sha256, sha256_canonical(override.to_dict()))
        self.assertIsNone(opened.absolute_path, "nothing points at a file")
        self.assertEqual(len(ctx.inputs["measurements"].rows), 6, "the original context is untouched")

    def test_documents_are_served_from_memory_and_nothing_is_read_from_disk(self) -> None:
        ctx = self.context()
        case = FalsifierCase(
            "swap", "a replaced snapshot", Status.FAIL, Reason.SOURCE_MISMATCH, documents={"snapshots/accepted.json": b"{}"}
        )
        overlay = ctx.overlay(case)
        self.assertEqual(overlay.accepted_snapshot.content, {})
        self.assertNotEqual(ctx.accepted_snapshot.content, {})
        self.write_file("docs/present.json", "{}")
        unread = overlay.read_document("docs/present.json", role="probe")
        self.assertEqual(unread.state, InputState.OPEN_FAILED)
        self.assertIn("OVERLAY_UNREAD", unread.diagnostic)
        self.assertNotIn("docs/present.json", [item["path"] for item in ctx.read_log()])

    def test_an_overlay_is_always_offline(self) -> None:
        self.update_manifest(citations={"live": True})
        manifest = load_manifest(self.manifest_path)
        _, opened = discover(manifest)
        ctx = CheckContext(manifest, opened, verifier.NetworkPolicy(live=True))
        case = FalsifierCase("swap", "x", Status.FAIL, Reason.SOURCE_MISMATCH, documents={"a.json": b"{}"})
        self.assertFalse(ctx.overlay(case).network.live)

    def test_a_case_over_an_undeclared_input_is_refused(self) -> None:
        case = FalsifierCase("ghost", "x", Status.FAIL, Reason.SOURCE_MISMATCH, inputs={"ghost": InputOverride(())})
        with self.assertRaises(ValueError):
            self.context().overlay(case)


class ReproducibleEvidenceTests(ProjectTestCase):
    def test_witness_evidence_names_no_run_derived_identifier(self) -> None:
        # Check evidence is hashed into receipts and packages; it must reproduce on another day (18.10).
        first = self.run_verify()
        with mock.patch.dict("os.environ", {"SCIENCE_GATE_FIXED_TIME": "2031-07-08T09:10:11Z"}):
            second = self.run_verify()
        self.assertNotEqual(first.result.run_id, second.result.run_id)
        for before, after in zip(first.result.checks, second.result.checks):
            with self.subTest(check=before.check_id):
                self.assertEqual(sha256_canonical(before.evidence), sha256_canonical(after.evidence))
                self.assertNotIn(first.result.run_id, json.dumps(before.evidence))

    def test_a_witness_bound_to_another_subject_does_not_count(self) -> None:
        run = self.run_verify()
        rows = self.result_of(run, "rows")
        moved = [dict(entry) for entry in run.ledger.entries]
        for entry in moved:
            if (entry.get("check_id") or "").startswith("control:falsifier:rows:") and entry.get("completed_at"):
                entry["evidence"] = {**entry["evidence"], "subject_invocation_id": "inv-000000000000"}
        judged = pass_requires_falsifier_witness(InvariantContext(entries=tuple(moved), checks=(rows,)))
        self.assertIs(judged.holds, False)
        intact = pass_requires_falsifier_witness(InvariantContext(entries=run.ledger.entries, checks=(rows,)))
        self.assertIs(intact.holds, True)


class FixtureTreeTests(ProjectTestCase):
    def test_the_valid_fixture_stays_pass_after_being_copied(self) -> None:
        # The fixture carries no machine-specific state: a copy anywhere is witnessed the same way.
        target = self.tmp / "copy"
        shutil.copytree(VALID_MANIFEST.parent, target)
        run = verify(target / "manifest.json")
        self.assertEqual(run.status, Status.PASS)
        self.assertEqual(json.loads(json.dumps(run.result.controls))["falsifiers"]["NO_GENERATOR"], [])


if __name__ == "__main__":
    unittest.main()
