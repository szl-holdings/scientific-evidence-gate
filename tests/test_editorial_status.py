"""Acceptance tests for extension #10: scoped editorial status (ARCHITECTURE.md section 17.14).

The brief's five acceptance cases:

* (a) A retraction present only in the Retraction Watch channel gives
  RETRACTED, with the channel and snapshot recorded and a document-level
  count of 1.
* (b) One channel consulted with no notice gives ABSTAIN / INSUFFICIENT_EVIDENCE.
* (c) A Retraction followed later by a Reinstatement gives REINSTATED.
* (d) Aggregator (OpenAlex-style) evidence dated inside the defect window is
  downgraded and not counted.
* (e) Advancing the snapshot digest to one containing a new notice makes the
  dependent CONCLUSION stale, and ``dependency_currency`` FAILs.

Every snapshot here is synthetic: invented digests, DOIs under 10.5555 and
invented notice ids. No Retraction Watch (or any other real) row is used or
shipped; a source name such as ``RETRACTION_WATCH_SNAPSHOT`` only labels a
channel.
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import TempDirTestCase
from test_citations import (
    FIXTURES,
    WORK_A,
    WORK_B,
    WORK_C,
    block_sockets,
    cite,
    context_for,
    entries_document,
    failing_opener,
)

from science_gate._canonical import sha256_bytes
from science_gate.citations import (
    MIN_EDITORIAL_CHANNELS,
    Notice,
    check_editorial_status,
    decide_editorial_status,
    falsify_editorial_status,
)
from science_gate.models import (
    SKIP_JUSTIFICATION_KEY,
    EditorialChannel,
    EditorialStatus,
    ExecutionState,
    FailureMode,
    NoticeType,
    Reason,
    Status,
)
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.verifier import NetworkPolicy, VerificationRun, verify

DOI_A, DOI_B, DOI_C = WORK_A["doi"], WORK_B["doi"], WORK_C["doi"]
CROSSREF = EditorialChannel.CROSSREF_UPDATED_BY.value
CROSSREF_RW = EditorialChannel.CROSSREF_RETRACTION_WATCH.value
RW_SNAPSHOT = EditorialChannel.RETRACTION_WATCH_SNAPSHOT.value
AGGREGATOR = "OPENALEX_IS_RETRACTED"
#: The aggregator defect window the brief cites as its example.
AGGREGATOR_WINDOW = {"source": AGGREGATOR, "start": "2023-12-22", "end": "2024-03-19"}
SNAPSHOTS_PATH = "editorial/snapshots.json"


def notice(doi: str, kind: str, date: str, notice_id: str) -> dict[str, Any]:
    return {"doi": doi, "type": kind, "date": date, "notice_id": notice_id}


def snapshot(
    source: str,
    captured_at: str,
    *notices: dict[str, Any],
    consulted: tuple[str, ...] = (DOI_A, DOI_B, DOI_C),
    label: str = "",
) -> dict[str, Any]:
    """One synthetic channel snapshot; its digest is invented from its source, capture time and label."""
    return {
        "source": source,
        "snapshot_sha256": hashlib.sha256(f"synthetic|{source}|{captured_at}|{label}".encode()).hexdigest(),
        "captured_at": captured_at,
        "consulted_dois": list(consulted),
        "notices": list(notices),
    }


def two_channels(*notices_rw: dict[str, Any]) -> list[dict[str, Any]]:
    """The publisher channel with nothing to say, and the Retraction Watch snapshot with ``notices_rw``."""
    return [snapshot(CROSSREF, "2026-03-01T08:00:00Z"), snapshot(RW_SNAPSHOT, "2026-03-02T08:00:00Z", *notices_rw)]


class EditorialProject(TempDirTestCase):
    """A synthetic project: three citations and one editorial-status check over a snapshot input."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        block_sockets(self)
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.root = self.tmp / "project"

    def build(
        self,
        snapshots: Any,
        *,
        windows: list[dict[str, Any]] | None = None,
        entries: Any = None,
        check: dict[str, Any] | None = None,
        input_changes: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Path:
        """Write the project; ``snapshots`` that is a string is written verbatim, None writes no file."""
        cited = entries if entries is not None else entries_document(
            cite("C1", WORK_A), cite("C2", WORK_B), cite("C3", WORK_C)
        )
        if cited != "undeclared":
            self.write("project/citations/entries.json", cited if isinstance(cited, str) else json.dumps(cited))
        if snapshots is not None:
            self.write(f"project/{SNAPSHOTS_PATH}", snapshots if isinstance(snapshots, str) else json.dumps(snapshots))
        editorial = {"id": "editorial", "kind": "editorial_status", "version": "1", "inputs": ["snapshots"]}
        if windows is not None:
            editorial["params"] = {"defect_windows": windows}
        editorial.update(check or {})
        manifest: dict[str, Any] = {
            "schema": "science-gate-manifest/v1",
            "inputs": [{"id": "snapshots", "path": SNAPSHOTS_PATH, "format": "json", **(input_changes or {})}],
            "checks": [editorial],
            "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
        }
        if cited != "undeclared":
            manifest["citations"] = {"entries": "citations/entries.json"}
        manifest.update(extra or {})
        return self.write_manifest(manifest, "project/manifest.json")

    def run_editorial(self, snapshots: Any, **build: Any) -> tuple[VerificationRun, Any]:
        run = verify(self.build(snapshots, **build), network=NetworkPolicy(opener=failing_opener()))
        (result,) = [item for item in run.result.checks if item.check_id == "editorial"]
        return run, result

    def by_doi(self, result: Any) -> dict[str, dict[str, Any]]:
        return {item["doi"]: item for item in result.evidence["dois"]}

    def assertOutcome(self, result: Any, verdict: Status, reason: Reason, *modes: FailureMode) -> None:
        self.assertEqual((result.verdict, result.reason), (verdict, reason), result.diagnostics)
        for mode in modes:
            self.assertIn(mode, result.failure_modes)


# ---------------------------------------------------------------------------
# (a)-(d)
# ---------------------------------------------------------------------------


class AcceptanceTests(EditorialProject):
    def test_a_a_retraction_only_in_the_retraction_watch_channel_is_retracted(self) -> None:
        for rw_source in (RW_SNAPSHOT, CROSSREF_RW):
            with self.subTest(channel=rw_source):
                retraction = notice(DOI_B, "RETRACTION", "2026-02-20", "RW-SYN-0002")
                snapshots = [
                    snapshot(CROSSREF, "2026-03-01T08:00:00Z"),
                    snapshot(rw_source, "2026-03-02T08:00:00Z", retraction),
                ]
                run, result = self.run_editorial(snapshots)
                self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
                item = self.by_doi(result)[DOI_B]
                rw_digest = snapshots[1]["snapshot_sha256"]
                self.assertEqual(item["status"], "RETRACTED")
                self.assertEqual(
                    item["notices"],
                    [
                        {
                            "type": "RETRACTION",
                            "date": "2026-02-20",
                            "notice_id": "RW-SYN-0002",
                            "source": rw_source,
                            "snapshot_sha256": rw_digest,
                        }
                    ],
                )
                self.assertIn({"source": rw_source, "snapshot_sha256": rw_digest}, item["channels"])
                counts = result.evidence["status_counts"]
                self.assertEqual(counts["RETRACTED"], 1)
                self.assertEqual(counts["NOT_RETRACTED_WITHIN_SCOPE"], 2)
                self.assertEqual(sum(counts.values()), 3)
                self.assertEqual(set(counts), {status.value for status in EditorialStatus})
                self.assertIn(f"snapshot {rw_digest[:12]}", result.diagnostics[0])
                outcome = (run.status, run.result.reason, run.exit_code)
                self.assertEqual(outcome, (Status.FAIL, Reason.SOURCE_MISMATCH, 1))

    def test_b_one_channel_with_no_notice_is_insufficient_evidence(self) -> None:
        _, result = self.run_editorial([snapshot(CROSSREF, "2026-03-01T08:00:00Z")])
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)
        for item in result.evidence["dois"]:
            self.assertEqual((item["status"], item["channel_sources"]), ("UNDETERMINED", [CROSSREF]))
        self.assertEqual(result.evidence["status_counts"]["UNDETERMINED"], 3)
        self.assertTrue(result.diagnostics[0].startswith("SINGLE_CHANNEL"))

    def test_b_two_snapshots_of_one_source_are_still_one_channel(self) -> None:
        snapshots = [
            snapshot(CROSSREF, "2026-03-01T08:00:00Z"),
            snapshot(CROSSREF, "2026-03-05T08:00:00Z", label="second capture"),
        ]
        _, result = self.run_editorial(snapshots)
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)
        item = self.by_doi(result)[DOI_A]
        self.assertEqual((len(item["channels"]), item["channel_sources"]), (2, [CROSSREF]))

    def test_b_a_channel_that_did_not_consult_a_doi_does_not_count_for_it(self) -> None:
        snapshots = [snapshot(CROSSREF, "2026-03-01T08:00:00Z"), snapshot(RW_SNAPSHOT, "2026-03-02T08:00:00Z",
                                                                         consulted=(DOI_A,))]
        _, result = self.run_editorial(snapshots)
        statuses = {doi: item["status"] for doi, item in self.by_doi(result).items()}
        self.assertEqual(statuses, {DOI_A: "NOT_RETRACTED_WITHIN_SCOPE", DOI_B: "UNDETERMINED", DOI_C: "UNDETERMINED"})
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)

    def test_b_no_channel_at_all_is_source_unavailable(self) -> None:
        _, result = self.run_editorial([snapshot(AGGREGATOR, "2026-03-01T08:00:00Z")])
        self.assertOutcome(result, Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
        self.assertTrue(result.diagnostics[0].startswith("NO_CHANNEL"))

    def test_c_a_later_reinstatement_supersedes_a_retraction(self) -> None:
        notices = (
            notice(DOI_A, "RETRACTION", "2025-06-01", "RW-SYN-0010"),
            notice(DOI_A, "REINSTATEMENT", "2025-09-01", "RW-SYN-0011"),
        )
        _, result = self.run_editorial(two_channels(*notices))
        self.assertEqual(self.by_doi(result)[DOI_A]["status"], "REINSTATED")
        self.assertEqual(result.verdict, Status.PASS, result.diagnostics)
        self.assertEqual([item["type"] for item in self.by_doi(result)[DOI_A]["notices"]],
                         ["RETRACTION", "REINSTATEMENT"], "notices are listed in date order")

    def test_c_order_is_by_date_across_channels_and_a_tie_is_not_supersession(self) -> None:
        cases = {
            "reinstated later in another channel": ("2025-06-01", "2025-09-01", "REINSTATED"),
            "retracted again after a reinstatement": ("2025-09-01", "2025-06-01", "RETRACTED"),
            "same day: the retraction stands": ("2025-06-01", "2025-06-01", "RETRACTED"),
        }
        for label, (retracted_on, reinstated_on, status) in cases.items():
            with self.subTest(case=label):
                snapshots = [
                    snapshot(CROSSREF, "2026-03-01T08:00:00Z",
                             notice(DOI_A, "REINSTATEMENT", reinstated_on, "CR-SYN-0001")),
                    snapshot(RW_SNAPSHOT, "2026-03-02T08:00:00Z",
                             notice(DOI_A, "RETRACTION", retracted_on, "RW-SYN-0001")),
                ]
                _, result = self.run_editorial(snapshots)
                self.assertEqual(self.by_doi(result)[DOI_A]["status"], status)
                self.assertEqual(result.verdict, Status.PASS if status == "REINSTATED" else Status.FAIL)

    def test_d_aggregator_evidence_inside_its_defect_window_is_never_counted(self) -> None:
        flag = notice(DOI_A, "RETRACTION", "2024-01-10", "OA-FLAG-0001")
        for captured_at in ("2024-01-15T08:00:00Z", "2026-03-03T08:00:00Z"):
            with self.subTest(captured_at=captured_at):
                snapshots = [*two_channels(), snapshot(AGGREGATOR, captured_at, flag)]
                _, result = self.run_editorial(snapshots, windows=[AGGREGATOR_WINDOW])
                self.assertEqual(result.verdict, Status.PASS, result.diagnostics)
                item = self.by_doi(result)[DOI_A]
                self.assertEqual(item["status"], "NOT_RETRACTED_WITHIN_SCOPE")
                self.assertEqual(item["channel_sources"], [CROSSREF, RW_SNAPSHOT])
                self.assertEqual((item["notices"], item["downgraded"]), ([], []))
                self.assertEqual(result.evidence["ignored_sources"], [AGGREGATOR])
                self.assertEqual(result.evidence["snapshots"][2]["role"], "IGNORED")
                self.assertEqual(result.evidence["defect_windows"], [AGGREGATOR_WINDOW])

    def test_d_a_channel_captured_inside_a_declared_window_is_downgraded_and_not_counted(self) -> None:
        window = {"source": RW_SNAPSHOT, "start": "2026-03-02", "end": "2026-03-10"}
        _, result = self.run_editorial(two_channels(), windows=[window])
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)
        item = self.by_doi(result)[DOI_A]
        self.assertEqual(item["channel_sources"], [CROSSREF])
        (downgraded,) = item["downgraded"]
        self.assertEqual((downgraded["source"], downgraded["window"]), (RW_SNAPSHOT, window))
        self.assertEqual(result.evidence["snapshots"][1]["role"], "DOWNGRADED")

    def test_d_window_ends_are_inclusive(self) -> None:
        for end, counted in (("2026-03-02", False), ("2026-03-01", True)):
            with self.subTest(end=end):
                window = {"source": RW_SNAPSHOT, "start": "2026-02-01", "end": end}
                _, result = self.run_editorial(two_channels(), windows=[window])
                self.assertEqual(self.by_doi(result)[DOI_A]["channel_sources"] == [CROSSREF, RW_SNAPSHOT], counted)

    def test_d_a_declared_window_cannot_hide_a_recorded_retraction(self) -> None:
        """Downgraded evidence decides nothing, but a notice it holds must reach a person, not vanish."""
        retraction = notice(DOI_B, "RETRACTION", "2026-02-20", "RW-SYN-0002")
        snapshots = [
            snapshot(CROSSREF, "2026-03-01T08:00:00Z"),
            snapshot(CROSSREF_RW, "2026-03-01T09:00:00Z"),
            snapshot(RW_SNAPSHOT, "2026-03-02T08:00:00Z", retraction),
        ]
        window = {"source": RW_SNAPSHOT, "start": "2026-03-01", "end": "2026-03-31"}
        _, result = self.run_editorial(snapshots, windows=[window])
        self.assertOutcome(result, Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW)
        item = self.by_doi(result)[DOI_B]
        self.assertEqual(item["status"], "NOT_RETRACTED_WITHIN_SCOPE", "the downgraded notice is not counted")
        self.assertEqual([entry["notice_id"] for entry in item["downgraded"][0]["notices"]], ["RW-SYN-0002"])
        self.assertTrue(result.diagnostics[0].startswith("DOWNGRADED_NOTICE"))


class StatusRuleTests(EditorialProject):
    def test_an_expression_of_concern_needs_human_review(self) -> None:
        concern = notice(DOI_C, "EXPRESSION_OF_CONCERN", "2026-01-05", "CR-SYN-0005")
        correction = notice(DOI_C, "CORRECTION", "2026-02-05", "CR-SYN-0006")
        _, result = self.run_editorial(two_channels(concern, correction))
        self.assertOutcome(result, Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW)
        self.assertEqual(self.by_doi(result)[DOI_C]["status"], "EXPRESSION_OF_CONCERN")

    def test_a_correction_is_not_a_retraction(self) -> None:
        _, result = self.run_editorial(two_channels(notice(DOI_C, "CORRECTION", "2026-02-05", "CR-SYN-0006")))
        self.assertEqual((result.verdict, self.by_doi(result)[DOI_C]["status"]), (Status.PASS, "CORRECTED"))

    def test_two_named_channels_with_no_notice_pass_as_a_scoped_statement(self) -> None:
        run, result = self.run_editorial(two_channels())
        self.assertEqual(result.verdict, Status.PASS, result.diagnostics)
        self.assertEqual(result.evidence["status_counts"]["NOT_RETRACTED_WITHIN_SCOPE"], 3)
        self.assertEqual(result.rows_examined, 2)
        self.assertIn("NOT_RETRACTED_WITHIN_SCOPE says only", result.evidence["scope"])
        self.assertEqual(result.evidence["falsification"], "WITNESSED")
        self.assertEqual(run.status, Status.PASS, [item.detail for item in run.findings])

    def test_decide_editorial_status_directly(self) -> None:
        def made(kind: str, date: str) -> Notice:
            return Notice(DOI_A, NoticeType(kind), date, f"N-{kind}-{date}")

        self.assertEqual(MIN_EDITORIAL_CHANNELS, 2)
        cases = [
            ([], 2, EditorialStatus.NOT_RETRACTED_WITHIN_SCOPE),
            ([], 1, EditorialStatus.UNDETERMINED),
            ([], 0, EditorialStatus.UNDETERMINED),
            ([made("RETRACTION", "2025-01-01")], 1, EditorialStatus.RETRACTED),
            ([made("REINSTATEMENT", "2025-01-01")], 2, EditorialStatus.REINSTATED),
            ([made("RETRACTION", "2025-01-01"), made("REINSTATEMENT", "2025-01-02")], 2, EditorialStatus.REINSTATED),
            ([made("REINSTATEMENT", "2025-01-02"), made("RETRACTION", "2025-01-02")], 2, EditorialStatus.RETRACTED),
            ([made("CORRECTION", "2025-01-02"), made("EXPRESSION_OF_CONCERN", "2025-01-01")], 2,
             EditorialStatus.EXPRESSION_OF_CONCERN),
            ([made("CORRECTION", "2025-01-02")], 1, EditorialStatus.CORRECTED),
        ]
        for notices, sources, expected in cases:
            with self.subTest(notices=[(item.kind.value, item.date) for item in notices], sources=sources):
                self.assertIs(decide_editorial_status(notices, sources), expected)


# ---------------------------------------------------------------------------
# (e) a new notice makes dependent nodes stale, through the 0.1.0 impact walk
# ---------------------------------------------------------------------------


class StalenessTests(EditorialProject):
    def node(self, node_id: str, kind: str, path: str) -> dict[str, Any]:
        return {
            "id": node_id,
            "kind": kind,
            "path": path,
            "recorded_sha256": sha256_bytes((self.root / path).read_bytes()),
            "validity": "CURRENT",
            "history": [],
        }

    def test_e_a_new_notice_makes_the_dependent_conclusion_stale(self) -> None:
        self.write("project/figures/table-1.csv", "doi,cited_in\n10.5555/sgate.test.0002,section-3\n")
        self.write("project/conclusions/conclusion-1.md", "A synthetic conclusion that relies on C2.\n")
        before = two_channels()
        manifest = self.build(before)
        graph = {
            "schema": "science-gate-graph/v1",
            "nodes": [
                self.node("editorial-snapshots", "SOURCE_SNAPSHOT", SNAPSHOTS_PATH),
                self.node("table-1", "FIGURE_OR_TABLE", "figures/table-1.csv"),
                self.node("conclusion-1", "CONCLUSION", "conclusions/conclusion-1.md"),
            ],
            "edges": [["editorial-snapshots", "table-1"], ["table-1", "conclusion-1"],
                      ["editorial-snapshots", "conclusion-1"]],
        }
        self.write("project/graph/graph.json", json.dumps(graph))
        currency = {"id": "currency", "kind": "dependency_currency", "version": "1"}
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["checks"].append(currency)
        document["dependencies"] = "graph/graph.json"
        self.write_manifest(document, "project/manifest.json")

        def judged() -> tuple[Any, Any, VerificationRun]:
            run = verify(manifest, network=NetworkPolicy(opener=failing_opener()))
            checks = {item.check_id: item for item in run.result.checks}
            return checks["editorial"], checks["currency"], run

        editorial, current, _ = judged()
        self.assertEqual(editorial.verdict, Status.PASS, editorial.diagnostics)
        self.assertNotEqual(current.verdict, Status.FAIL, current.diagnostics)
        self.assertEqual(current.evidence["not_in_good_standing"], [])

        # The channel publishes a retraction of C2's DOI; the new snapshot has a new digest.
        after = two_channels(notice(DOI_B, "RETRACTION", "2026-03-02", "RW-SYN-0099"))
        after[1]["snapshot_sha256"] = hashlib.sha256(b"synthetic|advanced RW snapshot").hexdigest()
        self.write(f"project/{SNAPSHOTS_PATH}", json.dumps(after))
        editorial, current, run = judged()
        self.assertEqual(self.by_doi(editorial)[DOI_B]["status"], "RETRACTED")
        self.assertOutcome(current, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.STALE_DEPENDENCY)
        stale = {item["id"]: item["validity"] for item in current.evidence["not_in_good_standing"]}
        self.assertEqual(stale["conclusion-1"], "STALE_PENDING_REVALIDATION")
        self.assertEqual(stale["table-1"], "STALE_PENDING_REVALIDATION")
        self.assertIn("conclusion-1", current.diagnostics[0])
        self.assertEqual(run.status, Status.FAIL)
        self.assertFalse((self.root / "graph" / "graph-state.json").exists(), "verify writes nothing")


# ---------------------------------------------------------------------------
# Inputs, params and documents that cannot be judged
# ---------------------------------------------------------------------------


class InputTests(EditorialProject):
    def assertSkipped(self, result: Any, state: ExecutionState, reason: Reason, justification: str) -> None:
        self.assertEqual((result.execution_state, result.verdict, result.reason), (state, Status.ABSTAIN, reason),
                         result.diagnostics)
        self.assertEqual(result.evidence[SKIP_JUSTIFICATION_KEY], justification)
        self.assertEqual(result.rows_examined, 0)

    def test_malformed_snapshots_are_refused_as_evidence_malformed(self) -> None:
        good = snapshot(CROSSREF, "2026-03-01T08:00:00Z")
        cases = {
            "not an object": ["CROSSREF_UPDATED_BY"],
            "unknown key": [{**good, "is_retracted": True}],
            "missing key": [{key: value for key, value in good.items() if key != "notices"}],
            "digest not hex": [{**good, "snapshot_sha256": "not-a-digest"}],
            "capture not UTC": [{**good, "captured_at": "2026-03-01 08:00"}],
            "consulted not a DOI": [{**good, "consulted_dois": ["sgate.fx.0001"]}],
            "consulted twice": [{**good, "consulted_dois": [DOI_A, DOI_A.upper()]}],
            "unknown notice type": [{**good, "notices": [notice(DOI_A, "WITHDRAWAL", "2026-01-01", "N1")]}],
            "date not a date": [{**good, "notices": [notice(DOI_A, "RETRACTION", "2026-02-30", "N1")]}],
            "date not ISO": [{**good, "notices": [notice(DOI_A, "RETRACTION", "01/02/2026", "N1")]}],
            "notice after its capture": [{**good, "notices": [notice(DOI_A, "RETRACTION", "2026-03-02", "N1")]}],
            "notice for an unconsulted DOI": [
                {**good, "consulted_dois": [DOI_A], "notices": [notice(DOI_B, "RETRACTION", "2026-01-01", "N1")]}
            ],
            "notice id repeated": [
                {**good, "notices": [notice(DOI_A, "CORRECTION", "2026-01-01", "N1"),
                                     notice(DOI_B, "CORRECTION", "2026-01-01", "N1")]}
            ],
            "snapshot listed twice": [good, dict(good)],
        }
        for label, snapshots in cases.items():
            with self.subTest(case=label):
                run, result = self.run_editorial(snapshots)
                self.assertSkipped(result, ExecutionState.SKIPPED, Reason.PROTOCOL_BROKEN, "EVIDENCE_MALFORMED")
                self.assertTrue(result.diagnostics[0].startswith("MALFORMED_INPUT"), result.diagnostics)
                self.assertNotEqual(run.status, Status.PASS)

    def test_an_input_with_nothing_to_examine_is_never_pass(self) -> None:
        cases = {
            "missing file": (None, {}, Reason.INSUFFICIENT_EVIDENCE, "INPUT_UNAVAILABLE"),
            "empty array": ("[]", {}, Reason.INSUFFICIENT_EVIDENCE, "EMPTY_POPULATION"),
            "unparseable": ("[{", {}, Reason.INSUFFICIENT_EVIDENCE, "INPUT_UNAVAILABLE"),
            "digest mismatch": (json.dumps(two_channels()), {"sha256": "0" * 64}, Reason.SOURCE_MISMATCH,
                                "SOURCE_REJECTED"),
        }
        for label, (snapshots, changes, reason, justification) in cases.items():
            with self.subTest(case=label):
                run, result = self.run_editorial(snapshots, input_changes=changes)
                self.assertSkipped(result, ExecutionState.NOT_APPLICABLE, reason, justification)
                self.assertNotEqual(run.status, Status.PASS)

    def test_the_cited_dois_must_be_available(self) -> None:
        cases = {
            "undeclared": ("undeclared", ExecutionState.NOT_APPLICABLE, Reason.OUT_OF_SCOPE, "NOT_DECLARED"),
            "no citations": (entries_document(), ExecutionState.NOT_APPLICABLE, Reason.INSUFFICIENT_EVIDENCE,
                             "EMPTY_POPULATION"),
            "broken": ("{broken", ExecutionState.SKIPPED, Reason.PROTOCOL_BROKEN, "EVIDENCE_MALFORMED"),
            "malformed": (entries_document(cite("C1", WORK_A, doi="10.5555")), ExecutionState.SKIPPED,
                          Reason.PROTOCOL_BROKEN, "EVIDENCE_MALFORMED"),
            "empty file": ("", ExecutionState.SKIPPED, Reason.INSUFFICIENT_EVIDENCE, "INPUT_UNAVAILABLE"),
        }
        for label, (entries, state, reason, justification) in cases.items():
            with self.subTest(case=label):
                _, result = self.run_editorial(two_channels(), entries=entries)
                self.assertSkipped(result, state, reason, justification)

    def test_wiring_and_params_errors_are_errors(self) -> None:
        cases = {
            "no input": ({"inputs": []}, "INVALID_INPUTS"),
            "unknown param": ({"params": {"windows": []}}, "UNKNOWN_PARAM"),
            "windows not a list": ({"params": {"defect_windows": {"source": AGGREGATOR}}}, "INVALID_PARAM"),
            "window missing a key": ({"params": {"defect_windows": [{"source": AGGREGATOR, "start": "2024-01-01"}]}},
                                     "INVALID_PARAM"),
            "window date malformed": ({"params": {"defect_windows": [{**AGGREGATOR_WINDOW, "end": "2024-02-30"}]}},
                                      "INVALID_PARAM"),
            "window ends before it starts": (
                {"params": {"defect_windows": [{**AGGREGATOR_WINDOW, "start": "2024-04-01"}]}}, "INVALID_PARAM"),
        }
        for label, (check, code) in cases.items():
            with self.subTest(case=label):
                run, result = self.run_editorial(two_channels(), check=check)
                self.assertEqual(result.verdict, Status.ERROR)
                self.assertIn(code, result.diagnostics[0])
                self.assertEqual(run.status, Status.ERROR)

    def test_the_input_must_be_json(self) -> None:
        self.write("project/editorial/snapshots.csv", "source\nCROSSREF_UPDATED_BY\n")
        _, result = self.run_editorial(two_channels(), input_changes={"path": "editorial/snapshots.csv",
                                                                      "format": "csv"})
        self.assertEqual(result.verdict, Status.ERROR)
        self.assertIn("reads a json input", result.diagnostics[0])


# ---------------------------------------------------------------------------
# The falsifier (section 17.5) and the committed fixtures
# ---------------------------------------------------------------------------


class FalsifierTests(EditorialProject):
    def test_the_case_adds_a_retraction_the_real_checker_rejects(self) -> None:
        manifest = self.build(two_channels(notice(DOI_A, "REINSTATEMENT", "2026-03-02", "RW-SYN-0020")))
        run = verify(manifest, network=NetworkPolicy(opener=failing_opener()))
        (subject,) = [item for item in run.result.checks if item.check_id == "editorial"]
        self.assertEqual(subject.verdict, Status.PASS, subject.diagnostics)
        ctx, specs = context_for(manifest)
        (case,) = falsify_editorial_status(ctx, specs["editorial"], subject)
        self.assertEqual((case.case_id, case.expected_verdict, case.expected_reason),
                         ("add-retraction", Status.FAIL, Reason.SOURCE_MISMATCH))
        rows = case.inputs["snapshots"].rows
        added = rows[1]["notices"][-1]
        self.assertEqual((added["doi"], added["type"], added["date"]), (DOI_A, "RETRACTION", "2026-03-02"),
                         "the latest counted capture, dated on its own day: a same-day reinstatement cannot win")
        self.assertRegex(added["notice_id"], r"^falsifier-[0-9a-f]{12}$")
        rejected = check_editorial_status(ctx.overlay(case), specs["editorial"])
        self.assertEqual((rejected.verdict, rejected.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(subject.evidence["falsification"], "WITNESSED")

    def test_no_case_without_a_counted_channel(self) -> None:
        run, subject = self.run_editorial([snapshot(AGGREGATOR, "2026-03-01T08:00:00Z")])
        ctx, specs = context_for(self.root / "manifest.json")
        self.assertEqual(falsify_editorial_status(ctx, specs["editorial"], subject), ())
        self.assertNotEqual(run.status, Status.PASS)

    def test_committed_editorial_fixtures(self) -> None:
        expectations = {
            "editorial-scoped": (Status.PASS, Reason.VERIFIED, {"NOT_RETRACTED_WITHIN_SCOPE": 3}),
            "editorial-retracted": (Status.FAIL, Reason.SOURCE_MISMATCH,
                                    {"RETRACTED": 1, "NOT_RETRACTED_WITHIN_SCOPE": 2}),
        }
        for name, (status, reason, counts) in expectations.items():
            with self.subTest(fixture=name):
                opener = failing_opener()
                run = verify(FIXTURES / name / "manifest.json", network=NetworkPolicy(opener=opener))
                self.assertEqual((run.status, run.result.reason), (status, reason), [f.detail for f in run.findings])
                (result,) = run.result.checks
                for key, value in counts.items():
                    self.assertEqual(result.evidence["status_counts"][key], value)
                self.assertEqual(opener.calls, [])


if __name__ == "__main__":
    unittest.main()
