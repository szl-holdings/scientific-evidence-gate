"""Acceptance tests for the claim-to-invocation join (extension #6, ARCHITECTURE.md 17.15).

The brief's acceptance case is a sealed run plus assertions about it: one
BACKED, one citing a nonexistent invocation (NARRATED), one claiming PASS for
a FAIL invocation (CONTRADICTED), one made before its invocation completed
(NARRATED), and one FAIL invocation that nobody cites (ORPHANED). The fifth
case is an invocation, not an assertion, because ORPHANED classifies
invocations; the assertions file therefore holds four records. The run must
FAIL with the bucket counts {BACKED: 1, NARRATED: 2, CONTRADICTED: 1,
ORPHANED: >= 1}, and with a tampered ledger every assertion must be NARRATED.

Everything here is synthetic. The sealed run under ``fixtures/assertions`` is
built by :func:`build_sealed_run` with :class:`science_gate.ledger.Ledger`
(never by ``verify``), and a golden test proves the committed bytes are
exactly that output. The kind is registered for these tests through
``verify(registry=...)``, which keeps them independent of when the engine
wires ``claim_join`` into its own registry.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate._canonical import canonical_bytes, pretty_json_bytes, sha256_bytes, sha256_canonical
from science_gate._clock import FIXED_TIME_ENV
from science_gate.assertions import (
    ARTIFACT_MISMATCH,
    ARTIFACT_UNBOUND,
    BACKED,
    CITED_INVOCATION_ABSENT,
    CLAIMED_RESULT_CONTRADICTED,
    FALSIFIER_CASE_ID,
    IMPOSSIBLE_TIMELINE,
    KIND,
    LEDGER_CHAIN_BROKEN,
    LEDGER_ROLE,
    RUN_ROLE,
    SEALED_RUN_PARAM,
    Assertion,
    AssertionFormatError,
    RunSeal,
    check_claim_join,
    falsify_claim_join,
    join_claims,
    parse_assertions,
    parse_run_seal,
    preload_claim_join,
)
from science_gate.discovery import discover
from science_gate.ledger import GENESIS_SHA256, Ledger, entry_digest, invocation_id_for, parse_jsonl, verify_chain
from science_gate.manifests import UNSAFE_SUBPROCESS_REQUEST, CheckSpec, ManifestError, load_manifest
from science_gate.models import (
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    AssertionOutcome,
    CheckResult,
    ExecutionState,
    FailureMode,
    InputOverride,
    Reason,
    SkipJustification,
    Status,
)
from science_gate.verifier import REGISTRY, CheckContext, CheckOutcome, VerificationRun, verify

FIXTURES = REPO_ROOT / "fixtures" / "assertions"
FIVE_CASES = FIXTURES / "five-cases"
ALL_BACKED = FIXTURES / "all-backed"
TREES = (FIVE_CASES, ALL_BACKED)

#: The registry these tests verify with: the engine's, plus this kind.
REGISTRY_WITH_JOIN = {**REGISTRY, KIND: "science_gate.assertions:check_claim_join"}

# ---------------------------------------------------------------------------
# The synthetic sealed run (built with ledger.Ledger, never by verify)
# ---------------------------------------------------------------------------

SEALED_RUN_ID = "run-" + sha256_canonical({"fixture": "claim-join sealed run", "synthetic": True})[:16]

#: Invented digests of the artifacts the sealed run's checks examined.
MEASUREMENTS_SHA256 = sha256_bytes(b"synthetic claim-join fixture: measurements, version 1\n")
CANARY_SHA256 = sha256_bytes(b"synthetic claim-join fixture: canary input\n")
UNRELATED_SHA256 = sha256_bytes(b"synthetic claim-join fixture: an artifact no invocation examined\n")

#: ``(check_id, kind, input_id, digest, verdict, reason, started_at, completed_at, check_evidence)``.
#: Each invocation takes two entries, so the STARTED entries sit at seq 1, 3, 5, 7 and 9.
INVOCATIONS: tuple[tuple[Any, ...], ...] = (
    ("rows", "row_count", "measurements", MEASUREMENTS_SHA256, Status.PASS, Reason.VERIFIED,
     "2026-01-15T10:00:00Z", "2026-01-15T10:00:01Z", {"rows_admitted": 6}),
    ("duplicates", "duplicate_rows", "measurements", MEASUREMENTS_SHA256, Status.FAIL, Reason.SOURCE_MISMATCH,
     "2026-01-15T10:00:02Z", "2026-01-15T10:00:03Z", {"duplicate_keys": ["SYN-0003"]}),
    ("columns", "required_columns", "measurements", MEASUREMENTS_SHA256, Status.PASS, Reason.VERIFIED,
     "2026-01-15T10:00:04Z", "2026-01-15T10:00:05Z", {"columns_present": ["sample_id", "value"]}),
    ("snapshot", "snapshot_completeness", "measurements", MEASUREMENTS_SHA256, Status.FAIL, Reason.SOURCE_MISMATCH,
     "2026-01-15T10:00:06Z", "2026-01-15T10:00:07Z", {"deleted_keys": ["SYN-0005"]}),
    ("control:canary:must_fail", "duplicate_rows", "control-canary", CANARY_SHA256, Status.FAIL,
     Reason.SOURCE_MISMATCH, "2026-01-15T10:00:08Z", "2026-01-15T10:00:09Z", {"duplicate_keys": ["c1"]}),
)

#: Each invocation's id, by check id: derived from the run id and its STARTED seq.
INV = {item[0]: invocation_id_for(SEALED_RUN_ID, 2 * index + 1) for index, item in enumerate(INVOCATIONS)}

#: An invocation id that the sealed run does not contain.
NONEXISTENT_INVOCATION = "inv-000000000000"

CLAIMED_AT = "2026-01-15T10:05:00Z"


def _assertion_record(
    claim_id: str, kind: str, cites: str, claimed_result: str, *, claimed_at: str = CLAIMED_AT
) -> dict[str, Any]:
    return {
        "claim_id": claim_id,
        "kind": kind,
        "cites": cites,
        "claimed_at": claimed_at,
        "artifact_sha256": MEASUREMENTS_SHA256,
        "claimed_result": claimed_result,
    }


#: The acceptance case: what each assertion is, and the outcome the brief requires.
FIVE_CASE_ASSERTIONS = [
    # Backed: the dataset check passed before the claim, over the named artifact.
    _assertion_record("agent-claim-01", "DATASET_VALIDATED", INV["rows"], "PASS"),
    # Narrated: cites an invocation the sealed run does not contain.
    _assertion_record("agent-claim-02", "TESTS_RUN", NONEXISTENT_INVOCATION, "PASS"),
    # Contradicted: claims PASS for an invocation that recorded FAIL.
    _assertion_record("agent-claim-03", "FILE_CHECKED", INV["duplicates"], "PASS"),
    # Narrated: claimed at 10:00:04, but the invocation completed at 10:00:05.
    _assertion_record("agent-claim-04", "COMMAND_EXECUTED", INV["columns"], "PASS", claimed_at="2026-01-15T10:00:04Z"),
]
FIVE_CASE_OUTCOMES = {
    "agent-claim-01": (AssertionOutcome.BACKED, BACKED),
    "agent-claim-02": (AssertionOutcome.NARRATED, CITED_INVOCATION_ABSENT),
    "agent-claim-03": (AssertionOutcome.CONTRADICTED, CLAIMED_RESULT_CONTRADICTED),
    "agent-claim-04": (AssertionOutcome.NARRATED, IMPOSSIBLE_TIMELINE),
}

#: Honest assertions, two of which truthfully report failures.
ALL_BACKED_ASSERTIONS = [
    _assertion_record("agent-claim-01", "DATASET_VALIDATED", INV["rows"], "PASS"),
    _assertion_record("agent-claim-02", "TESTS_RUN", INV["duplicates"], "FAIL"),
    _assertion_record("agent-claim-03", "FILE_CHECKED", INV["snapshot"], "FAIL"),
]


def _at(moment: str) -> Any:
    """Pin the tool's clock to ``moment`` for the calls made inside the block."""
    return mock.patch.dict(os.environ, {FIXED_TIME_ENV: moment})


def build_sealed_run() -> tuple[bytes, bytes]:
    """The fixture's ``ledger.jsonl`` and ``run.json`` bytes, built with the real ledger.

    Each entry gets its own timestamp by pinning the clock around each call,
    which gives the run a realistic, strictly increasing timeline.
    """
    ledger = Ledger(SEALED_RUN_ID)
    for check_id, kind, input_id, digest, verdict, reason, started, completed, check_evidence in INVOCATIONS:
        with _at(started):
            invocation_id = ledger.start(
                check_id=check_id,
                check_kind=kind,
                check_version="1",
                input_ids=[input_id],
                input_sha256s={input_id: digest},
            )
        failure_modes = [] if verdict is Status.PASS else [FailureMode.SOURCE_MISMATCH.value]
        with _at(completed):
            ledger.finish(
                invocation_id,
                verdict=verdict,
                reason=reason,
                evidence={
                    "execution_state": ExecutionState.CHECKED.value,
                    "rows_examined": 6,
                    "failure_modes": failure_modes,
                    "diagnostics": [],
                    "check_evidence": check_evidence,
                },
            )
    run = {"run_id": SEALED_RUN_ID, **ledger.seal()}
    return ledger.to_jsonl(), pretty_json_bytes(run)


def assertions_bytes(records: list[Any]) -> bytes:
    return (json.dumps(records, indent=2) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def claim_join_result(run: VerificationRun) -> CheckResult:
    (result,) = [check for check in run.result.checks if check.kind == KIND]
    return result


def findings_of(run: VerificationRun) -> set[tuple[str, Status, Reason]]:
    """``(source, status, reason)`` of every finding the run's decision gathered."""
    return {(finding.source, finding.status, finding.reason) for finding in run.findings}


def outcomes_of(evidence: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """``{claim_id: (outcome, detail code)}`` from a claim_join result's evidence."""
    return {
        item["claim_id"]: (item["outcome"], item["detail"].split(":", 1)[0]) for item in evidence["assertions"]
    }


class ClaimJoinTestCase(TempDirTestCase):
    """Copies fixture trees into a private directory and runs the check on them."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def copy(self, tree: Path = ALL_BACKED, *, under: str = "") -> Path:
        """Copy a fixture tree (into ``under`` when one test needs several copies)."""
        target = self.tmp.joinpath(under, tree.name)
        shutil.copytree(tree, target)
        return target / "manifest.json"

    def edit_manifest(self, manifest: Path, edit: Any) -> None:
        document = json.loads(manifest.read_text(encoding="utf-8"))
        edit(document)
        manifest.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def write_assertions(self, manifest: Path, records: list[Any]) -> None:
        (manifest.parent / "assertions" / "assertions.json").write_bytes(assertions_bytes(records))

    def context(self, manifest: Path) -> tuple[CheckContext, CheckSpec]:
        loaded = load_manifest(manifest, registered_kinds=REGISTRY_WITH_JOIN)
        _, opened = discover(loaded)
        (spec,) = loaded.checks
        return CheckContext(loaded, opened), spec

    def check(self, manifest: Path) -> CheckOutcome:
        ctx, spec = self.context(manifest)
        return check_claim_join(ctx, spec)

    def verify(self, manifest: Path) -> VerificationRun:
        return verify(manifest, registry=REGISTRY_WITH_JOIN)

    def assert_labelled(self, outcome: CheckOutcome, state: ExecutionState, label: SkipJustification) -> None:
        """A shortfall is labelled, never PASS, and agrees with the shared justification table."""
        verdict, reason, modes = SKIP_JUSTIFICATION_OUTCOMES[label]
        self.assertEqual(outcome.execution_state, state)
        self.assertEqual(outcome.evidence[SKIP_JUSTIFICATION_KEY], label.value)
        self.assertEqual((outcome.verdict, outcome.reason, tuple(outcome.failure_modes)), (verdict, reason, modes))
        self.assertNotEqual(outcome.verdict, Status.PASS)
        self.assertEqual(outcome.rows_examined, 0)


# ---------------------------------------------------------------------------
# The fixture itself
# ---------------------------------------------------------------------------


class SealedRunFixtureTests(ClaimJoinTestCase):
    def test_committed_sealed_runs_are_exactly_the_ledger_module_output(self) -> None:
        ledger_bytes, run_bytes = build_sealed_run()
        for tree in TREES:
            with self.subTest(tree=tree.name):
                self.assertEqual((tree / "sealed-run" / "ledger.jsonl").read_bytes(), ledger_bytes)
                self.assertEqual((tree / "sealed-run" / "run.json").read_bytes(), run_bytes)

    def test_committed_assertions_are_the_documented_cases(self) -> None:
        for tree, records in ((FIVE_CASES, FIVE_CASE_ASSERTIONS), (ALL_BACKED, ALL_BACKED_ASSERTIONS)):
            with self.subTest(tree=tree.name):
                self.assertEqual(json.loads((tree / "assertions" / "assertions.json").read_bytes()), records)

    def test_sealed_run_chain_verifies_against_its_seal_and_run_id(self) -> None:
        entries = parse_jsonl((FIVE_CASES / "sealed-run" / "ledger.jsonl").read_bytes())
        seal = parse_run_seal(json.loads((FIVE_CASES / "sealed-run" / "run.json").read_bytes()))
        self.assertEqual(seal.run_id, SEALED_RUN_ID)
        chain = verify_chain(entries, seal.ledger_head_sha256, seal.ledger_length, run_id=seal.run_id)
        self.assertTrue(chain.intact, chain.problems)
        self.assertEqual(len(entries), 2 * len(INVOCATIONS))
        self.assertEqual([entry["invocation_id"] for entry in entries[::2]], [INV[item[0]] for item in INVOCATIONS])
        self.assertNotIn(NONEXISTENT_INVOCATION, {entry["invocation_id"] for entry in entries})


# ---------------------------------------------------------------------------
# Acceptance: the five cases, and the tampered chain
# ---------------------------------------------------------------------------


class FiveCaseAcceptanceTests(ClaimJoinTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.run = self.verify(FIVE_CASES / "manifest.json")
        self.result = claim_join_result(self.run)
        self.expected = json.loads((FIVE_CASES / "expected.json").read_bytes())

    def test_run_fails_with_the_brief_bucket_counts(self) -> None:
        self.assertEqual(
            (self.run.status, self.run.exit_code, self.run.result.reason), (Status.FAIL, 1, Reason.SOURCE_MISMATCH)
        )
        self.assertEqual(
            (self.result.execution_state, self.result.verdict, self.result.reason),
            (ExecutionState.CHECKED, Status.FAIL, Reason.SOURCE_MISMATCH),
        )
        counts = self.result.evidence["counts"]
        self.assertEqual({key: counts[key] for key in ("BACKED", "NARRATED", "CONTRADICTED")}, {
            "BACKED": 1, "NARRATED": 2, "CONTRADICTED": 1,
        })
        self.assertGreaterEqual(counts["ORPHANED"], 1)
        self.assertEqual(counts, self.expected["counts"])
        self.assertEqual(self.result.rows_examined, len(FIVE_CASE_ASSERTIONS))
        self.assertIn(FailureMode.SOURCE_MISMATCH, self.result.failure_modes)
        self.assertIn(FailureMode.NARRATED_VERIFICATION, self.result.failure_modes)
        self.assertEqual(
            (self.run.result.status.value, self.run.result.reason.value, self.run.exit_code),
            (self.expected["status"], self.expected["reason"], self.expected["exit_code"]),
        )

    def test_each_assertion_gets_the_outcome_the_brief_names(self) -> None:
        expected = {claim_id: (outcome.value, code) for claim_id, (outcome, code) in FIVE_CASE_OUTCOMES.items()}
        self.assertEqual(outcomes_of(self.result.evidence), expected)
        self.assertEqual(
            {claim_id: outcome for claim_id, (outcome, _) in expected.items()}, self.expected["outcomes"]
        )
        buckets = self.result.evidence["buckets"]
        self.assertEqual(buckets["BACKED"], ["agent-claim-01"])
        self.assertEqual(buckets["NARRATED"], ["agent-claim-02", "agent-claim-04"])
        self.assertEqual(buckets["CONTRADICTED"], ["agent-claim-03"])

    def test_impossible_timeline_names_both_timestamps(self) -> None:
        (late,) = [item for item in self.result.evidence["assertions"] if item["claim_id"] == "agent-claim-04"]
        self.assertTrue(late["detail"].startswith(f"{IMPOSSIBLE_TIMELINE}: "))
        self.assertIn("2026-01-15T10:00:05Z", late["detail"])  # completed_at
        self.assertIn("2026-01-15T10:00:04Z", late["detail"])  # claimed_at

    def test_orphaned_lists_the_uncited_failure_and_never_a_control(self) -> None:
        self.assertEqual(self.result.evidence["buckets"]["ORPHANED"], [INV["snapshot"]])
        self.assertEqual(self.expected["orphaned"], [INV["snapshot"]])
        self.assertNotIn(INV["control:canary:must_fail"], self.result.evidence["buckets"]["ORPHANED"])
        self.assertTrue(any(line.startswith("ORPHANED: 1 ") for line in self.result.diagnostics))

    def test_evidence_records_the_intact_chain_and_the_seal_it_was_judged_against(self) -> None:
        evidence = self.result.evidence
        self.assertTrue(evidence["chain"]["intact"])
        self.assertEqual(evidence["chain"]["observed_length"], 2 * len(INVOCATIONS))
        run_document = json.loads((FIVE_CASES / "sealed-run" / "run.json").read_bytes())
        self.assertEqual(evidence["sealed_run"]["seal"], run_document)
        self.assertEqual(
            evidence["sealed_run"]["ledger"]["sha256"],
            sha256_bytes((FIVE_CASES / "sealed-run" / "ledger.jsonl").read_bytes()),
        )
        roles = {item["path"]: item["roles"] for item in self.run.documents}
        self.assertEqual(roles["sealed-run/ledger.jsonl"], [LEDGER_ROLE])
        self.assertEqual(roles["sealed-run/run.json"], [RUN_ROLE])

    def test_the_verdict_points_to_a_terminal_invocation_of_the_new_run(self) -> None:
        terminal = [
            entry for entry in self.run.ledger.entries
            if entry["invocation_id"] == self.result.invocation_id and entry["result"] != "STARTED"
        ]
        self.assertEqual(len(terminal), 1)
        self.assertEqual((terminal[0]["verdict"], terminal[0]["reason"]), ("FAIL", "SOURCE_MISMATCH"))

    def test_evidence_is_deterministic(self) -> None:
        again = claim_join_result(self.verify(FIVE_CASES / "manifest.json"))
        self.assertEqual(sha256_canonical(again.evidence), sha256_canonical(self.result.evidence))


class TamperedChainTests(ClaimJoinTestCase):
    """With a ledger that fails verification, every assertion is NARRATED and none BACKED."""

    def tamper(self, manifest: Path, edit: Any) -> None:
        run_dir = manifest.parent / "sealed-run"
        lines = [json.loads(line) for line in (run_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
        run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        edit(lines, run)
        (run_dir / "ledger.jsonl").write_bytes(b"".join(canonical_bytes(line) + b"\n" for line in lines))
        (run_dir / "run.json").write_bytes(pretty_json_bytes(run))

    def assert_all_narrated(self, manifest: Path) -> CheckResult:
        run = self.verify(manifest)
        result = claim_join_result(run)
        self.assertFalse(result.evidence["chain"]["intact"])
        self.assertEqual(
            result.evidence["counts"], {"BACKED": 0, "NARRATED": 4, "CONTRADICTED": 0, "ORPHANED": 0}
        )
        self.assertEqual(
            {code for _, code in outcomes_of(result.evidence).values()}, {LEDGER_CHAIN_BROKEN}
        )
        self.assertEqual((result.verdict, result.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        self.assertIn(FailureMode.NARRATED_VERIFICATION, result.failure_modes)
        # The run's status is decide()'s (17.7). This check contributes an ABSTAIN, never a PASS.
        self.assertIn(("check:agent-claims", Status.ABSTAIN, Reason.UNVERIFIED), findings_of(run))
        self.assertNotEqual((run.status, run.exit_code), (Status.PASS, 0))
        return result

    def test_an_edited_verdict_turns_every_assertion_narrated(self) -> None:
        # Forging FAIL into PASS would make agent-claim-03 "backed" if the chain were not checked.
        manifest = self.copy(FIVE_CASES)

        def forge(lines: list[dict[str, Any]], run: dict[str, Any]) -> None:
            lines[3]["verdict"], lines[3]["reason"] = "PASS", "VERIFIED"

        self.tamper(manifest, forge)
        result = self.assert_all_narrated(manifest)
        self.assertTrue(any(problem.startswith("ENTRY_EDITED") for problem in result.evidence["chain"]["problems"]))

    def test_other_tampering_is_caught_the_same_way(self) -> None:
        def truncate(lines: list[dict[str, Any]], run: dict[str, Any]) -> None:
            del lines[-1]

        def reorder(lines: list[dict[str, Any]], run: dict[str, Any]) -> None:
            lines[0], lines[2] = lines[2], lines[0]

        def reseal_head(lines: list[dict[str, Any]], run: dict[str, Any]) -> None:
            run["ledger_head_sha256"] = UNRELATED_SHA256

        def foreign_run(lines: list[dict[str, Any]], run: dict[str, Any]) -> None:
            run["run_id"] = "run-0000000000000000"

        def unsealed(lines: list[dict[str, Any]], run: dict[str, Any]) -> None:
            run["ledger_length"] = None

        expected_problem = {
            truncate: "LENGTH_MISMATCH",
            reorder: "SEQUENCE_BREAK",
            reseal_head: "HEAD_MISMATCH",
            foreign_run: "FOREIGN_INVOCATION",
            unsealed: "UNSEALED",
        }
        for edit, problem in expected_problem.items():
            with self.subTest(tamper=edit.__name__):
                manifest = self.copy(FIVE_CASES, under=edit.__name__)
                self.tamper(manifest, edit)
                result = self.assert_all_narrated(manifest)
                problems = result.evidence["chain"]["problems"]
                self.assertTrue(any(item.startswith(problem) for item in problems), problems)


# ---------------------------------------------------------------------------
# PASS, and proof that the PASS could have failed
# ---------------------------------------------------------------------------


class AllBackedTests(ClaimJoinTestCase):
    def test_backed_assertions_pass_with_execution_evidence(self) -> None:
        run = self.verify(ALL_BACKED / "manifest.json")
        result = claim_join_result(run)
        expected = json.loads((ALL_BACKED / "expected.json").read_bytes())
        self.assertEqual((run.status.value, run.result.reason.value, run.exit_code), (
            expected["status"], expected["reason"], expected["exit_code"],
        ))
        self.assertEqual((result.verdict, result.reason), (Status.PASS, Reason.VERIFIED))
        self.assertEqual(result.rows_examined, len(ALL_BACKED_ASSERTIONS))
        self.assertEqual(result.evidence["counts"], expected["counts"])
        self.assertEqual(result.evidence["counts"], {"BACKED": 3, "NARRATED": 0, "CONTRADICTED": 0, "ORPHANED": 0})
        self.assertIsNotNone(result.invocation_id)
        self.assertIn(result.invocation_id, {entry["invocation_id"] for entry in run.ledger.entries})
        # Once the engine records falsification (17.5), this kind's PASS is witnessed by its own case.
        if "falsification" in result.evidence:
            self.assertEqual(result.evidence["falsification"], "WITNESSED")
            witnesses = {item["case_id"]: item["outcome"] for item in result.evidence["falsifiers"]}
            self.assertEqual(witnesses, {FALSIFIER_CASE_ID: "REJECTED"})

    def test_truthfully_reported_failures_are_backed(self) -> None:
        outcome = self.check(ALL_BACKED / "manifest.json")
        outcomes = outcomes_of(dict(outcome.evidence))
        self.assertEqual(outcomes["agent-claim-02"], ("BACKED", BACKED))
        self.assertEqual(outcomes["agent-claim-03"], ("BACKED", BACKED))
        self.assertEqual(outcome.evidence["buckets"]["ORPHANED"], [], "cited failures are not orphaned")


def result_of(spec: CheckSpec, outcome: CheckOutcome) -> CheckResult:
    """The result a falsifier generator receives for ``outcome`` (it rebuilds its case from the context)."""
    return CheckResult(
        check_id=spec.check_id,
        kind=spec.kind,
        version=spec.version,
        required=spec.required,
        execution_state=outcome.execution_state,
        verdict=outcome.verdict,
        reason=outcome.reason,
        failure_modes=outcome.failure_modes,
        rows_examined=outcome.rows_examined,
        inputs=spec.inputs,
        evidence=outcome.evidence,
        diagnostics=outcome.diagnostics,
    )


class FalsifierTests(ClaimJoinTestCase):
    def falsify(self, manifest: Path) -> tuple[Any, ...]:
        ctx, spec = self.context(manifest)
        return falsify_claim_join(ctx, spec, result_of(spec, check_claim_join(ctx, spec)))

    def test_case_flips_the_first_backed_claimed_result(self) -> None:
        (case,) = self.falsify(ALL_BACKED / "manifest.json")
        self.assertEqual(case.case_id, FALSIFIER_CASE_ID)
        self.assertEqual((case.expected_verdict, case.expected_reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(list(case.inputs), ["assertions"])
        expected_rows = [dict(record) for record in ALL_BACKED_ASSERTIONS]
        expected_rows[0]["claimed_result"] = "FAIL"
        self.assertEqual(case.inputs["assertions"], InputOverride(rows=tuple(expected_rows)))
        self.assertEqual(case.documents, {})

    def test_the_checker_rejects_the_case_as_expected(self) -> None:
        (case,) = self.falsify(ALL_BACKED / "manifest.json")
        manifest = self.copy(ALL_BACKED)
        self.write_assertions(manifest, list(case.inputs["assertions"].rows))
        outcome = self.check(manifest)
        self.assertEqual((outcome.verdict, outcome.reason), (case.expected_verdict, case.expected_reason))
        self.assertEqual(
            outcomes_of(dict(outcome.evidence))["agent-claim-01"], ("CONTRADICTED", CLAIMED_RESULT_CONTRADICTED)
        )

    def test_the_engine_overlay_serves_the_case_and_the_checker_rejects_it(self) -> None:
        """Through ``CheckContext.overlay`` (17.16): in memory, with the sealed run read once, before the case."""
        ctx, spec = self.context(ALL_BACKED / "manifest.json")
        preload_claim_join(ctx)
        outcome = check_claim_join(ctx, spec)
        self.assertEqual(outcome.verdict, Status.PASS)
        (case,) = falsify_claim_join(ctx, spec, result_of(spec, outcome))
        overlaid = check_claim_join(ctx.overlay(case), spec)
        self.assertEqual((overlaid.verdict, overlaid.reason), (case.expected_verdict, case.expected_reason))
        self.assertEqual(overlaid.evidence["counts"]["CONTRADICTED"], 1)

    def test_a_failure_claim_flips_to_pass(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.write_assertions(manifest, ALL_BACKED_ASSERTIONS[1:])
        (case,) = self.falsify(manifest)
        self.assertEqual(case.inputs["assertions"].rows[0]["claimed_result"], "PASS")

    def test_no_case_without_a_backed_assertion(self) -> None:
        manifest = self.copy(ALL_BACKED)
        narrated = _assertion_record("agent-claim-01", "TESTS_RUN", NONEXISTENT_INVOCATION, "PASS")
        self.write_assertions(manifest, [narrated])
        self.assertEqual(self.falsify(manifest), ())
        self.write_assertions(manifest, [])
        self.assertEqual(self.falsify(manifest), (), "nothing to falsify when there is nothing to join")

    def test_case_is_deterministic(self) -> None:
        first = [case.to_dict() for case in self.falsify(ALL_BACKED / "manifest.json")]
        second = [case.to_dict() for case in self.falsify(ALL_BACKED / "manifest.json")]
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# Each verdict the check can reach, alone
# ---------------------------------------------------------------------------


class CheckVerdictTests(ClaimJoinTestCase):
    def test_a_contradicted_assertion_alone_fails(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.write_assertions(manifest, [_assertion_record("agent-claim-01", "TESTS_RUN", INV["snapshot"], "PASS")])
        outcome = self.check(manifest)
        self.assertEqual((outcome.verdict, outcome.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(tuple(outcome.failure_modes), (FailureMode.SOURCE_MISMATCH,))

    def test_a_narrated_assertion_alone_abstains_and_is_never_false(self) -> None:
        manifest = self.copy(ALL_BACKED)
        record = _assertion_record("agent-claim-01", "TESTS_RUN", INV["rows"], "PASS")
        record["artifact_sha256"] = UNRELATED_SHA256
        self.write_assertions(manifest, [record])
        outcome = self.check(manifest)
        self.assertEqual((outcome.verdict, outcome.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        self.assertEqual(tuple(outcome.failure_modes), (FailureMode.NARRATED_VERIFICATION,))
        self.assertEqual(outcomes_of(dict(outcome.evidence))["agent-claim-01"], ("NARRATED", ARTIFACT_MISMATCH))

    def test_orphaned_invocations_never_decide(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.write_assertions(manifest, ALL_BACKED_ASSERTIONS[:1])
        outcome = self.check(manifest)
        self.assertEqual(outcome.verdict, Status.PASS)
        self.assertEqual(outcome.evidence["buckets"]["ORPHANED"], sorted([INV["duplicates"], INV["snapshot"]]))
        self.assertTrue(any(line.startswith("ORPHANED: 2 ") for line in outcome.diagnostics))

    def test_a_partial_assertions_input_cannot_appear_complete(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.edit_manifest(manifest, lambda document: document.update(limits={"max_rows": 2}))
        outcome = self.check(manifest)
        self.assertEqual((outcome.verdict, outcome.reason), (Status.ABSTAIN, Reason.PARTIAL_EXECUTION))
        self.assertIn(FailureMode.PARTIAL_EXECUTION, outcome.failure_modes)
        self.assertEqual(outcome.rows_examined, 2)
        self.assertEqual(outcome.evidence["counts"]["BACKED"], 2)


# ---------------------------------------------------------------------------
# The join rules (pure), on ledgers built in memory
# ---------------------------------------------------------------------------

DIGEST_A = sha256_bytes(b"synthetic artifact A\n")
DIGEST_B = sha256_bytes(b"synthetic artifact B\n")
MEMORY_RUN_ID = "run-synthetic-join"


def _assertion(
    claim_id: str = "claim-1",
    *,
    cites: str,
    claimed_at: str = "2026-01-02T03:04:05Z",
    artifact: str | None = DIGEST_A,
    claimed: str = "PASS",
    kind: str = "TESTS_RUN",
) -> Assertion:
    return Assertion(claim_id, kind, cites, claimed_at, artifact, claimed)


class JoinRuleTests(ClaimJoinTestCase):
    """The clock is pinned to 2026-01-02T03:04:05Z, so every entry completes at that instant."""

    def ledger(self, *results: tuple[str, Status, Reason]) -> Ledger:
        ledger = Ledger(MEMORY_RUN_ID)
        for check_id, verdict, reason in results:
            invocation_id = ledger.start(
                check_id=check_id, check_kind="row_count", check_version="1",
                input_ids=["data"], input_sha256s={"data": DIGEST_A},
            )
            ledger.finish(invocation_id, verdict=verdict, reason=reason)
        return ledger

    def join(self, ledger: Ledger, *assertions: Assertion) -> Any:
        seal = RunSeal(ledger.run_id, **ledger.seal())
        return join_claims(assertions, ledger.entries, seal)

    def codes(self, join: Any) -> dict[str, tuple[AssertionOutcome, str]]:
        return {item.assertion.claim_id: (item.outcome, item.code) for item in join.judgements}

    def test_rules_apply_in_order_so_a_contradiction_needs_everything_else_backed(self) -> None:
        ledger = self.ledger(("fails", Status.FAIL, Reason.SOURCE_MISMATCH))
        cited = invocation_id_for(MEMORY_RUN_ID, 1)
        join = self.join(
            ledger,
            # Absent outranks a bad artifact.
            _assertion("absent", cites="inv-ffffffffffff", artifact=DIGEST_B),
            # A late claim outranks a missing artifact.
            _assertion("late", cites=cited, claimed_at="2026-01-02T03:04:04Z", artifact=None),
            # A missing artifact outranks the contradicted verdict: narrated, not contradicted.
            _assertion("unbound", cites=cited, artifact=None),
            _assertion("mismatch", cites=cited, artifact=DIGEST_B),
            _assertion("contradicted", cites=cited),
        )
        narrated, contradicted = AssertionOutcome.NARRATED, AssertionOutcome.CONTRADICTED
        self.assertEqual(self.codes(join), {
            "absent": (narrated, CITED_INVOCATION_ABSENT),
            "late": (narrated, IMPOSSIBLE_TIMELINE),
            "unbound": (narrated, ARTIFACT_UNBOUND),
            "mismatch": (narrated, ARTIFACT_MISMATCH),
            "contradicted": (contradicted, CLAIMED_RESULT_CONTRADICTED),
        })

    def test_a_claim_made_at_the_completion_instant_is_backed(self) -> None:
        ledger = self.ledger(("passes", Status.PASS, Reason.VERIFIED))
        join = self.join(ledger, _assertion(cites=invocation_id_for(MEMORY_RUN_ID, 1)))
        self.assertEqual(self.codes(join), {"claim-1": (AssertionOutcome.BACKED, BACKED)})

    def test_a_started_invocation_without_a_terminal_result_backs_nothing(self) -> None:
        ledger = Ledger(MEMORY_RUN_ID)
        invocation_id = ledger.start(
            check_id="hangs", check_kind="row_count", check_version="1",
            input_ids=["data"], input_sha256s={"data": DIGEST_A},
        )
        join = self.join(ledger, _assertion(cites=invocation_id))
        self.assertEqual(self.codes(join), {"claim-1": (AssertionOutcome.NARRATED, CITED_INVOCATION_ABSENT)})
        self.assertIn("no terminal result", join.judgements[0].message)

    def test_uncited_fail_and_error_are_orphaned_and_any_mention_counts(self) -> None:
        ledger = self.ledger(
            ("passes", Status.PASS, Reason.VERIFIED),
            ("fails", Status.FAIL, Reason.SOURCE_MISMATCH),
            ("crashes", Status.ERROR, Reason.PROTOCOL_BROKEN),
            ("abstains", Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE),
            ("control:comparator", Status.FAIL, Reason.BLIND_SPOT),
        )
        ids = [invocation_id_for(MEMORY_RUN_ID, seq) for seq in (1, 3, 5, 7, 9)]
        self.assertEqual(self.join(ledger).orphaned, tuple(sorted(ids[1:3])))
        # Mentioned by a narrated assertion (late) is still mentioned: not silently ignored.
        late = _assertion(cites=ids[1], claimed_at="2026-01-01T00:00:00Z")
        self.assertEqual(self.join(ledger, late).orphaned, (ids[2],))

    def test_tool_call_ids_are_never_backed_without_an_importer(self) -> None:
        ledger = self.ledger(("passes", Status.PASS, Reason.VERIFIED))
        join = self.join(ledger, _assertion(cites="call_synthetic_0001", kind="TOOL_CALL"))
        self.assertEqual(self.codes(join), {"claim-1": (AssertionOutcome.NARRATED, CITED_INVOCATION_ABSENT)})

    def test_an_empty_sealed_ledger_is_intact_and_backs_nothing(self) -> None:
        join = join_claims([_assertion(cites=NONEXISTENT_INVOCATION)], (), RunSeal(MEMORY_RUN_ID, None, 0))
        self.assertTrue(join.chain.intact)
        self.assertEqual(join.counts, {"BACKED": 0, "NARRATED": 1, "CONTRADICTED": 0, "ORPHANED": 0})

    def test_a_plan_entry_at_seq_1_is_tolerated(self) -> None:
        """17.4: every 0.2 ledger starts with a PLAN entry whose invocation_id is null."""
        entries: list[dict[str, Any]] = []

        def append(fields: dict[str, Any]) -> None:
            entry = {**fields, "seq": len(entries) + 1}
            entry["prev_entry_sha256"] = entries[-1]["entry_sha256"] if entries else GENESIS_SHA256
            entry["entry_sha256"] = entry_digest(entry)
            entries.append(entry)

        common = {"input_ids": ["data"], "input_sha256s": {"data": DIGEST_A}, "started_at": "2026-01-02T03:04:05Z"}
        append({**common, "invocation_id": None, "check_id": None, "check_kind": "PLAN",
                "check_version": "science-gate-plan/v1", "completed_at": None, "result": "PLAN",
                "evidence": {"schema": "science-gate-plan/v1"}, "verdict": None, "reason": None})
        invocation_id = invocation_id_for(MEMORY_RUN_ID, 2)
        identity = {**common, "invocation_id": invocation_id, "check_id": "passes", "check_kind": "row_count",
                    "check_version": "1"}
        append({**identity, "completed_at": None, "result": "STARTED", "evidence": {}, "verdict": None,
                "reason": None})
        append({**identity, "completed_at": "2026-01-02T03:04:05Z", "result": "COMPLETED", "evidence": {},
                "verdict": "PASS", "reason": "VERIFIED"})
        seal = RunSeal(MEMORY_RUN_ID, entries[-1]["entry_sha256"], len(entries))
        join = join_claims([_assertion(cites=invocation_id)], entries, seal)
        self.assertTrue(join.chain.intact, join.chain.problems)
        self.assertEqual(join.counts["BACKED"], 1)

    def test_buckets_name_every_outcome_and_are_sorted(self) -> None:
        ledger = self.ledger(("passes", Status.PASS, Reason.VERIFIED))
        cited = invocation_id_for(MEMORY_RUN_ID, 1)
        join = self.join(ledger, _assertion("zeta", cites=cited), _assertion("alpha", cites=cited))
        self.assertEqual(list(join.buckets), [outcome.value for outcome in AssertionOutcome])
        self.assertEqual(join.buckets["BACKED"], ["alpha", "zeta"])
        self.assertEqual([item["claim_id"] for item in join.to_evidence()["assertions"]], ["zeta", "alpha"])


# ---------------------------------------------------------------------------
# Malformed and missing evidence: labelled, never PASS
# ---------------------------------------------------------------------------


class MalformedEvidenceTests(ClaimJoinTestCase):
    def test_a_malformed_record_skips_the_check_as_evidence_malformed(self) -> None:
        good = _assertion_record("agent-claim-01", "TESTS_RUN", INV["rows"], "PASS")
        cases: dict[str, Any] = {
            "unknown key": [{**good, "comment": "tests ran fine"}],
            "missing key": [{key: value for key, value in good.items() if key != "artifact_sha256"}],
            "lowercase kind": [{**good, "kind": "tests_run"}],
            "offset timestamp": [{**good, "claimed_at": "2026-01-15T11:05:00+01:00"}],
            "uppercase digest": [{**good, "artifact_sha256": MEASUREMENTS_SHA256.upper()}],
            "claimed result is a reason": [{**good, "claimed_result": "VERIFIED"}],
            "blank cites": [{**good, "cites": " "}],
            "unsafe claim id": [{**good, "claim_id": "../claim"}],
            "not an object": [good, ["agent-claim-02"]],
            "repeated claim id": [good, good],
        }
        manifest = self.copy(ALL_BACKED)
        self.edit_manifest(manifest, lambda document: document["inputs"][0].pop("row_key"))
        for label, records in cases.items():
            with self.subTest(case=label):
                self.write_assertions(manifest, records)
                outcome = self.check(manifest)
                self.assert_labelled(outcome, ExecutionState.SKIPPED, SkipJustification.EVIDENCE_MALFORMED)
                self.assertTrue(outcome.diagnostics[0].startswith("MALFORMED_ASSERTIONS"), outcome.diagnostics)

    def test_records_discovery_could_not_admit_are_malformed_too(self) -> None:
        manifest = self.copy(ALL_BACKED)
        good = _assertion_record("agent-claim-01", "TESTS_RUN", INV["rows"], "PASS")
        missing_key = {key: value for key, value in good.items() if key != "claim_id"}
        self.write_assertions(manifest, [good, missing_key])  # row_key claim_id: unresolved
        self.assert_labelled(self.check(manifest), ExecutionState.SKIPPED, SkipJustification.EVIDENCE_MALFORMED)

        jsonl = manifest.parent / "assertions" / "assertions.jsonl"
        jsonl.write_bytes(json.dumps(good).encode("utf-8") + b"\n{not json\n")
        self.edit_manifest(manifest, lambda document: document["inputs"][0].update(
            path="assertions/assertions.jsonl", format="jsonl", expected_rows=2))
        self.assert_labelled(self.check(manifest), ExecutionState.SKIPPED, SkipJustification.EVIDENCE_MALFORMED)

    def test_a_jsonl_assertions_input_is_judged_like_json(self) -> None:
        manifest = self.copy(ALL_BACKED)
        lines = b"".join(json.dumps(record).encode("utf-8") + b"\n" for record in ALL_BACKED_ASSERTIONS)
        (manifest.parent / "assertions" / "assertions.jsonl").write_bytes(lines)
        self.edit_manifest(manifest, lambda document: document["inputs"][0].update(
            path="assertions/assertions.jsonl", format="jsonl"))
        outcome = self.check(manifest)
        self.assertEqual(outcome.verdict, Status.PASS)
        self.assertEqual(outcome.evidence["counts"]["BACKED"], 3)

    def test_unusable_sealed_run_files(self) -> None:
        def remove(path: Path) -> None:
            path.unlink()

        cases = {
            ("ledger.jsonl", "missing"): (remove, SkipJustification.INPUT_UNAVAILABLE),
            ("run.json", "missing"): (remove, SkipJustification.INPUT_UNAVAILABLE),
            ("run.json", "empty"): (lambda path: path.write_bytes(b""), SkipJustification.INPUT_UNAVAILABLE),
            ("ledger.jsonl", "not JSON Lines"): (
                lambda path: path.write_bytes(b"{not json\n"), SkipJustification.EVIDENCE_MALFORMED),
            ("run.json", "not JSON"): (
                lambda path: path.write_bytes(b"{not json"), SkipJustification.EVIDENCE_MALFORMED),
            ("run.json", "no seal"): (
                lambda path: path.write_bytes(b'{"run_id": "run-x"}'), SkipJustification.EVIDENCE_MALFORMED),
            ("run.json", "length is text"): (
                lambda path: path.write_bytes(
                    json.dumps({"run_id": SEALED_RUN_ID, "ledger_head_sha256": None, "ledger_length": "10"}).encode()
                ),
                SkipJustification.EVIDENCE_MALFORMED,
            ),
        }
        for (name, label), (damage, justification) in cases.items():
            with self.subTest(file=name, damage=label):
                manifest = self.copy(ALL_BACKED, under=f"{name}-{label}")
                damage(manifest.parent / "sealed-run" / name)
                outcome = self.check(manifest)
                self.assert_labelled(outcome, ExecutionState.SKIPPED, justification)

    def test_an_empty_ledger_file_is_judged_against_its_seal(self) -> None:
        manifest = self.copy(ALL_BACKED)
        (manifest.parent / "sealed-run" / "ledger.jsonl").write_bytes(b"")
        outcome = self.check(manifest)
        self.assertEqual((outcome.verdict, outcome.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        self.assertEqual(outcome.evidence["counts"]["NARRATED"], 3)
        self.assertTrue(any(item.startswith("LENGTH_MISMATCH") for item in outcome.evidence["chain"]["problems"]))

    def test_assertion_input_shortfalls_are_labelled_and_never_pass(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.write_assertions(manifest, [])
        self.edit_manifest(manifest, lambda document: document["inputs"][0].update(expected_rows=0))
        self.assert_labelled(self.check(manifest), ExecutionState.NOT_APPLICABLE, SkipJustification.EMPTY_POPULATION)
        run = self.verify(manifest)
        self.assertIn(("check:agent-claims", Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE), findings_of(run))
        self.assertNotEqual((run.status, run.exit_code), (Status.PASS, 0), "an empty population never passes")

        (manifest.parent / "assertions" / "assertions.json").unlink()
        self.assert_labelled(self.check(manifest), ExecutionState.NOT_APPLICABLE, SkipJustification.INPUT_UNAVAILABLE)

        manifest = self.copy(FIVE_CASES)
        self.edit_manifest(manifest, lambda document: document["inputs"][0].update(sha256=UNRELATED_SHA256))
        self.assert_labelled(self.check(manifest), ExecutionState.NOT_APPLICABLE, SkipJustification.SOURCE_REJECTED)

    def test_parsers_refuse_what_the_formats_forbid(self) -> None:
        with self.assertRaises(AssertionFormatError):
            parse_run_seal(["not", "an", "object"])
        with self.assertRaises(AssertionFormatError):
            parse_run_seal({"run_id": SEALED_RUN_ID, "ledger_head_sha256": "abc", "ledger_length": 1})
        with self.assertRaises(AssertionFormatError):
            parse_run_seal({"run_id": SEALED_RUN_ID, "ledger_head_sha256": None, "ledger_length": True})
        self.assertEqual(
            parse_run_seal({"run_id": "run-x", "ledger_head_sha256": None, "ledger_length": 0, "status": "PASS"}),
            RunSeal("run-x", None, 0),
            "keys other than the seal are ignored",
        )
        (parsed,) = parse_assertions([FIVE_CASE_ASSERTIONS[0]])
        self.assertEqual(parsed.to_dict(), FIVE_CASE_ASSERTIONS[0])


# ---------------------------------------------------------------------------
# Wiring: params, inputs and preload
# ---------------------------------------------------------------------------


class WiringTests(ClaimJoinTestCase):
    def test_the_manifest_refuses_a_param_named_run_hence_sealed_run(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.edit_manifest(manifest, lambda document: document["checks"][0].update(params={"run": "sealed-run"}))
        with self.assertRaises(ManifestError) as raised:
            load_manifest(manifest, registered_kinds=REGISTRY_WITH_JOIN)
        self.assertIn(UNSAFE_SUBPROCESS_REQUEST, raised.exception.codes)

    def test_wiring_errors_are_errors_never_quiet_skips(self) -> None:
        def params(value: dict[str, Any]) -> Any:
            return lambda document: document["checks"][0].update(params=value)

        def second_input(document: dict[str, Any]) -> None:
            document["inputs"].append({"id": "extra", "path": "assertions/extra.json", "format": "json"})
            document["checks"][0]["inputs"].append("extra")

        def csv_input(document: dict[str, Any]) -> None:
            document["inputs"][0].update(path="assertions/assertions.csv", format="csv")
            document["inputs"][0].pop("row_key")
            document["inputs"][0].pop("expected_rows")
            document["inputs"][0].pop("denominator_source")

        cases = {
            "missing sealed_run": (params({}), "MISSING_PARAM"),
            "unknown param": (params({SEALED_RUN_PARAM: "sealed-run", "strict": True}), "UNKNOWN_PARAM"),
            "climbs out": (params({SEALED_RUN_PARAM: "../elsewhere"}), "INVALID_PARAM"),
            "absolute": (params({SEALED_RUN_PARAM: "/sealed-run"}), "INVALID_PARAM"),
            "not text": (params({SEALED_RUN_PARAM: 7}), "INVALID_PARAM"),
            "two inputs": (second_input, "INVALID_INPUTS"),
            "csv input": (csv_input, "INVALID_INPUTS"),
        }
        for label, (edit, code) in cases.items():
            with self.subTest(case=label):
                manifest = self.copy(ALL_BACKED, under=label)
                (manifest.parent / "assertions" / "extra.json").write_bytes(b"[]")
                (manifest.parent / "assertions" / "assertions.csv").write_bytes(b"claim_id\nx\n")
                self.edit_manifest(manifest, edit)
                run = self.verify(manifest)
                result = claim_join_result(run)
                self.assertEqual(result.verdict, Status.ERROR)
                self.assertTrue(any(code in line for line in result.diagnostics), result.diagnostics)
                self.assertEqual((run.status, run.exit_code), (Status.ERROR, 3))

    def test_preload_reads_the_sealed_run_under_its_roles(self) -> None:
        ctx, _ = self.context(ALL_BACKED / "manifest.json")
        preload_claim_join(ctx)
        log = {item["path"]: (item["roles"], item["sha256"]) for item in ctx.read_log()}
        self.assertEqual(log["sealed-run/ledger.jsonl"][0], [LEDGER_ROLE])
        self.assertEqual(log["sealed-run/run.json"][0], [RUN_ROLE])
        run_json = (ALL_BACKED / "sealed-run" / "run.json").read_bytes()
        self.assertEqual(log["sealed-run/run.json"][1], sha256_bytes(run_json))

    def test_preload_with_an_unusable_param_reads_nothing(self) -> None:
        manifest = self.copy(ALL_BACKED)
        self.edit_manifest(manifest, lambda document: document["checks"][0].update(params={}))
        ctx, _ = self.context(manifest)
        preload_claim_join(ctx)
        self.assertEqual(ctx.read_log(), ())
