"""Witnessed revalidation and verifier drift (extension #5, decision D6; ARCHITECTURE.md 17.13).

Re-hashing an untouched derived file always matches its recorded digest, so
an "unchanged" revalidation of a derived node needs a recompute witness. A
node may also name the checks whose PASS it relies on; when such a check
changes, the node is stale because of its verifier, not its data.

Every test works on a private copy of the synthetic project in
``fixtures/dependencies/witnessed``:

    source-snapshot (SOURCE_SNAPSHOT) -> analysis-run
    study-design (DESIGN)             -> analysis-run
    analysis-run (ANALYSIS_RUN) -> site-summary (RANKING_OR_MEASUREMENT, backed by check 'numeric')
    site-summary -> figure-1 (FIGURE_OR_TABLE), conclusion-1 (CONCLUSION, backed by check 'numeric')
    figure-1 -> conclusion-1

The clock is pinned to FIXED_TIME (2026-01-02T03:04:05Z), so a change
recorded by a command happens then; witnesses below start after it unless a
test says otherwise.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, TempDirTestCase

from science_gate import __version__, cli
from science_gate._canonical import sha256_bytes, sha256_canonical
from science_gate.dependencies import (
    GRAPH_STATE_FILE,
    INVALID_WITNESS_REASON,
    MALFORMED_GRAPH,
    MALFORMED_WITNESS,
    REVALIDATION_REPORT_FILE,
    UNSAFE_PATH,
    VACUOUS_CUTOFF_REASON,
    WITNESS_SCHEMA,
    WITNESS_UNAVAILABLE,
    DependencyGraph,
    GraphError,
    RecomputeWitness,
    RevalidationOutcome,
    assess,
    check_dependency_currency,
    cli_impact,
    cli_revalidate,
    load_graph,
    load_witness,
    params_sha256,
    verifier_drift,
)
from science_gate.discovery import discover
from science_gate.manifests import load_manifest
from science_gate.models import FailureMode, Reason, StaleCause, Status, Validity
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.verifier import CheckContext, CheckOutcome, verify

WITNESSED = REPO_ROOT / "fixtures" / "dependencies" / "witnessed"
GRAPH = "graph/graph.json"
STALE = Validity.STALE_PENDING_REVALIDATION
SOURCE_FILE = "data/measurements.csv"
#: The committed witnesses recompute analysis-run with both parents at their recorded digests.
RECOMPUTED = "witnesses/analysis-run-recomputed.json"
BEFORE_CHANGE = "witnesses/analysis-run-before-change.json"
#: Descendants of analysis-run, the only derived node in the fixture whose parents are both roots.
BELOW_ANALYSIS = ("site-summary", "figure-1", "conclusion-1")
#: A recompute window after the fixed clock, and the revalidation that follows it.
AFTER, AFTER_DONE, LATER = "2026-01-02T04:00:00Z", "2026-01-02T04:05:00Z", "2026-01-02T05:00:00Z"


class WitnessedProject(TempDirTestCase):
    """A fresh copy of the witnessed project, with the clock pinned and no signing key.

    The copy's backing checks are stamped with the running tool version, so a
    version bump of the tool itself does not read as drift in every test; the
    drift tests change that stamp deliberately.
    """

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.project = self.tmp / "project"
        shutil.copytree(WITNESSED, self.project)
        self.edit_backing(tool_version=__version__)

    # -- files -----------------------------------------------------------------

    @property
    def manifest_path(self) -> Path:
        return self.project / "manifest.json"

    def read_json(self, relpath: str) -> Any:
        return json.loads((self.project / relpath).read_text(encoding="utf-8"))

    def write_json(self, relpath: str, document: Any) -> None:
        path = self.project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def edit_graph(self, change: Callable[[dict[str, Any]], Any], node_id: str | None = None) -> None:
        """Apply ``change`` to one node of graph.json (every node when ``node_id`` is None)."""
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node_id is None or node["id"] == node_id:
                change(node)
        self.write_json(GRAPH, document)

    def edit_backing(self, **changes: Any) -> None:
        """Change every ``backed_by_checks`` entry of every node in graph.json."""
        self.edit_graph(lambda node: [item.update(changes) for item in node.get("backed_by_checks", [])])

    def edit_check(self, check_id: str, **changes: Any) -> None:
        document = self.read_json("manifest.json")
        for check in document["checks"]:
            if check["id"] == check_id:
                check.update(changes)
        self.write_json("manifest.json", document)

    def change_source(self) -> str:
        """Append an invented row to the source snapshot; return its new digest."""
        path = self.project / SOURCE_FILE
        path.write_bytes(path.read_bytes() + b"SYN-W-007,site-alpha,6.27\n")
        return sha256_bytes(path.read_bytes())

    def snapshot(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.project).as_posix(): path.read_bytes()
            for path in sorted(self.project.rglob("*"))
            if path.is_file()
        }

    # -- graph, check and witnesses -------------------------------------------

    def load(self) -> DependencyGraph:
        return load_graph(self.project, GRAPH)

    def currency(self) -> CheckOutcome:
        """The dependency_currency check run directly, as the engine would run it."""
        manifest = load_manifest(self.manifest_path)
        _, opened = discover(manifest)
        ctx = CheckContext(manifest, opened)
        ctx.preload(spec.kind for spec in manifest.checks)
        (spec,) = [spec for spec in manifest.checks if spec.kind == "dependency_currency"]
        return check_dependency_currency(ctx, spec)

    def witness(self, graph: DependencyGraph, node: str = "analysis-run", **overrides: Any) -> RecomputeWitness:
        """A witness for ``node`` that binds by default: after the change, every parent at its current digest.

        ``overrides`` replace single fields (``node_id`` included) without
        changing the defaults computed for ``node``.
        """
        values: dict[str, Any] = {
            "node_id": node,
            "invocation_id": "inv-" + sha256_bytes(f"synthetic recompute of {node}".encode("utf-8"))[:12],
            "started_at": AFTER,
            "completed_at": AFTER_DONE,
            "inputs": {parent: graph.recorded_sha256(parent) for parent in graph.parents(node)},
            "output_sha256": graph.recorded_sha256(node),
        }
        values.update(overrides)
        return RecomputeWitness(**values)

    def source_changed_and_settled(self) -> DependencyGraph:
        """(a)'s set-up: new source bytes, detection and impact, then the source itself settled as changed."""
        new_digest = self.change_source()
        graph = self.load()
        graph.detect_changes()
        graph.impact("source-snapshot")
        settled = graph.revalidate("source-snapshot")
        self.assertEqual(settled.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual(graph.recorded_sha256("source-snapshot"), new_digest)
        return graph


# ---------------------------------------------------------------------------
# The brief's acceptance cases (a)-(e)
# ---------------------------------------------------------------------------


class AcceptanceTests(WitnessedProject):
    def test_a_rehashing_an_untouched_derived_node_is_refused_as_vacuous_cutoff(self) -> None:
        graph = self.source_changed_and_settled()
        before = graph.recorded_sha256("analysis-run")
        result = graph.revalidate("analysis-run")
        self.assertEqual(result.outcome, RevalidationOutcome.REFUSED_VACUOUS_CUTOFF)
        self.assertEqual((result.prior_state, result.state), (STALE, STALE))
        self.assertEqual(result.observed_sha256, before, "the file really is untouched")
        self.assertEqual(result.cleared, ())
        self.assertTrue(result.diagnostic.startswith("VACUOUS_CUTOFF: 'analysis-run' is derived"))
        self.assertIsNone(result.witness)
        refusal = graph.history("analysis-run")[-1]
        self.assertEqual((refusal.from_state, refusal.to_state, refusal.reason), (STALE, STALE, VACUOUS_CUTOFF_REASON))
        self.assertEqual((refusal.witness_id, refusal.cause_category), (None, StaleCause.UPSTREAM))
        self.assertEqual(refusal.at, FIXED_TIME)
        self.assertTrue(refusal.refused)
        for node_id in ("analysis-run", *BELOW_ANALYSIS):
            self.assertEqual(graph.validity(node_id), STALE, node_id)
        graph.save_state()
        check = self.currency()
        self.assertEqual((check.verdict, check.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.STALE_DEPENDENCY, check.failure_modes)
        saved = self.read_json(f"graph/{GRAPH_STATE_FILE}")["nodes"]["analysis-run"]["history"][-1]
        expected = (VACUOUS_CUTOFF_REASON, STALE.value, STALE.value)
        self.assertEqual((saved["reason"], saved["from"], saved["to"]), expected)

    def test_b_a_valid_witness_revalidates_and_clears_what_depended_only_on_it(self) -> None:
        graph = self.source_changed_and_settled()
        witness = self.witness(graph, inputs={"source-snapshot": graph.recorded_sha256("source-snapshot")})
        self.assertEqual(graph.witness_problems("analysis-run", witness), ())
        result = graph.revalidate("analysis-run", at=LATER, witness=witness)
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual(result.state, Validity.REVALIDATED_UNCHANGED)
        self.assertEqual([item.node_id for item in result.cleared], list(BELOW_ANALYSIS))
        self.assertEqual(result.witness["witness_id"], witness.witness_id)
        self.assertIs(result.witness["consulted"], True)
        self.assertEqual(result.witness["problems"], [])
        accepted = graph.history("analysis-run")[-1]
        self.assertEqual((accepted.to_state, accepted.witness_id), (Validity.REVALIDATED_UNCHANGED, witness.witness_id))
        self.assertIn(witness.invocation_id, accepted.reason)
        for node_id in BELOW_ANALYSIS:
            self.assertEqual(graph.validity(node_id), Validity.CURRENT, node_id)
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.PASS)
        graph.save_state()
        self.assertEqual(self.currency().verdict, Status.PASS)

    def test_b_a_descendant_stale_for_another_reason_stays_stale(self) -> None:
        figure = self.project / "figures/figure-1.csv"
        figure.write_bytes(figure.read_bytes() + b"site-gamma,0.00,0\n")
        graph = self.source_changed_and_settled()
        result = graph.revalidate("analysis-run", at=LATER, witness=self.witness(graph))
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual([item.node_id for item in result.cleared], ["site-summary"])
        self.assertEqual(graph.stale_because("figure-1"), ("figure-1",))
        self.assertEqual(graph.stale_because("conclusion-1"), ("figure-1",))
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.FAIL)

    def test_c_a_witness_that_predates_the_change_is_refused(self) -> None:
        graph = self.source_changed_and_settled()
        changed_at = graph.pending_since("analysis-run").at
        self.assertEqual(changed_at, FIXED_TIME)
        for started in ("2026-01-02T02:00:00Z", changed_at):  # before, and exactly at, the change: not after it
            witness = self.witness(graph, started_at=started, completed_at=AFTER_DONE)
            with self.subTest(started_at=started):
                result = graph.revalidate("analysis-run", at=LATER, witness=witness)
                self.assertEqual(result.outcome, RevalidationOutcome.REFUSED_INVALID_WITNESS)
                self.assertEqual(result.state, STALE)
                (problem,) = result.witness["problems"]
                self.assertTrue(problem.startswith("WITNESS_PREDATES_CHANGE: "), problem)
                self.assertIn(changed_at, problem)
                refusal = graph.history("analysis-run")[-1]
                self.assertEqual((refusal.reason, refusal.witness_id), (INVALID_WITNESS_REASON, witness.witness_id))
                self.assertEqual((refusal.from_state, refusal.to_state), (STALE, STALE))
        self.assertEqual([item.node_id for item in result.cleared], [])
        for node_id in BELOW_ANALYSIS:
            self.assertEqual(graph.validity(node_id), STALE, node_id)

    def test_d_a_verifier_version_bump_makes_the_backed_nodes_stale_with_category_verifier(self) -> None:
        baseline = self.currency()
        self.assertEqual(baseline.verdict, Status.PASS, baseline.diagnostics)
        self.assertEqual(baseline.evidence["verifier_drift"], {})
        self.assertEqual(baseline.evidence["verifier_backing"], {"nodes": 2, "entries": 2, "tool_version": __version__})
        data = {relpath: blob for relpath, blob in self.snapshot().items() if relpath != "manifest.json"}
        self.edit_check("numeric", version="2")
        check = self.currency()
        self.assertEqual({k: v for k, v in self.snapshot().items() if k != "manifest.json"}, data, "no data change")
        self.assertEqual((check.verdict, check.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.STALE_DEPENDENCY, check.failure_modes)
        self.assertEqual(check.evidence["verifier_drift"], {"conclusion-1": ["numeric"], "site-summary": ["numeric"]})
        detail = check.evidence["verifier_drift_detail"][0]
        self.assertEqual(detail["differences"], {"version": {"recorded": "1", "current": "2"}})
        self.assertEqual({item["outcome"] for item in check.evidence["comparisons"]}, {"UNCHANGED"})
        stale = {view["id"]: view for view in check.evidence["not_in_good_standing"]}
        self.assertEqual(set(stale), set(BELOW_ANALYSIS), "source, design and analysis-run are unaffected")
        for node_id, view in stale.items():
            with self.subTest(node=node_id):
                self.assertEqual(view["validity"], STALE.value)
                self.assertEqual(view["stale_categories"], [StaleCause.VERIFIER.value])
        self.assertEqual(stale["site-summary"]["stale_because"], ["verifier:numeric"])
        self.assertEqual(stale["conclusion-1"]["stale_because"], ["figure-1", "site-summary", "verifier:numeric"])
        self.assertEqual(stale["figure-1"]["stale_because"], ["site-summary"])

    def test_e_rehashing_a_source_snapshot_works_as_before(self) -> None:
        graph = self.load()
        graph.impact("source-snapshot")
        unchanged = graph.revalidate("source-snapshot")
        self.assertEqual(unchanged.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual(unchanged.witness, None)
        self.assertEqual([item.node_id for item in unchanged.cleared], ["analysis-run", *BELOW_ANALYSIS])
        self.assertIsNone(graph.history("source-snapshot")[-1].witness_id)
        graph.impact("source-snapshot")
        new_digest = self.change_source()
        changed = graph.revalidate("source-snapshot")
        self.assertEqual(changed.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual(changed.recorded_sha256_after, new_digest)
        still = [item.node_id for item in changed.still_pending]
        self.assertEqual(still, ["analysis-run", "site-summary", "conclusion-1", "figure-1"])  # level by level
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.FAIL)


# ---------------------------------------------------------------------------
# D6 in detail
# ---------------------------------------------------------------------------


class DerivedNodeTests(WitnessedProject):
    def test_derived_means_having_a_parent_whatever_the_kind(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "analysis-run":
                node["kind"] = "SOURCE_SNAPSHOT"  # an odd declaration, but it has parents
        self.write_json(GRAPH, document)
        graph = self.load()
        graph.impact("study-design")
        self.assertEqual(graph.revalidate("study-design").outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        graph.impact("analysis-run")
        self.assertEqual(graph.revalidate("analysis-run").outcome, RevalidationOutcome.REFUSED_VACUOUS_CUTOFF)

    def test_a_current_derived_node_is_not_recertified_by_rehash(self) -> None:
        graph = self.load()
        result = graph.revalidate("site-summary")
        self.assertEqual(result.outcome, RevalidationOutcome.REFUSED_VACUOUS_CUTOFF)
        self.assertEqual((result.prior_state, result.state), (Validity.CURRENT, Validity.CURRENT))
        (entry,) = graph.history("site-summary")
        expected = (Validity.CURRENT, Validity.CURRENT, VACUOUS_CUTOFF_REASON)
        self.assertEqual((entry.from_state, entry.to_state, entry.reason), expected)
        self.assertIsNone(entry.cause_category, "a node in good standing has no stale cause")

    def test_a_changed_derived_file_needs_no_witness(self) -> None:
        output = self.project / "analysis/run-output.json"
        output.write_bytes(output.read_bytes() + b"\n")
        graph = self.load()
        result = graph.revalidate("analysis-run")
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual(graph.stale_because("site-summary"), ("analysis-run", "site-summary"))

    def test_each_witness_defect_is_named(self) -> None:
        graph = self.source_changed_and_settled()
        source = graph.recorded_sha256("source-snapshot")
        old_source = sha256_bytes((WITNESSED / SOURCE_FILE).read_bytes())
        cases = {
            "WITNESS_FOR_OTHER_NODE": {"node_id": "site-summary"},
            "IMPOSSIBLE_TIMELINE": {"started_at": AFTER_DONE, "completed_at": AFTER},
            "MISSING_INPUT": {"inputs": {"study-design": graph.recorded_sha256("study-design")}},
            "STALE_INPUT": {"inputs": {"source-snapshot": old_source}},
            "NOT_A_PARENT": {"inputs": {"source-snapshot": source, "figure-1": graph.recorded_sha256("figure-1")}},
            "OUTPUT_MISMATCH": {"output_sha256": "0" * 64},
        }
        for code, overrides in cases.items():
            witness = self.witness(graph, **overrides)
            with self.subTest(code=code):
                problems = graph.witness_problems("analysis-run", witness)
                self.assertEqual([problem.split(":")[0] for problem in problems], [code])
                self.assertEqual(
                    graph.revalidate("analysis-run", at=LATER, witness=witness).outcome,
                    RevalidationOutcome.REFUSED_INVALID_WITNESS,
                )
        self.assertEqual(graph.validity("analysis-run"), STALE)
        refusals = [entry for entry in graph.history("analysis-run") if entry.refused]
        self.assertEqual(len(refusals), len(cases))

    def test_a_parent_without_a_digest_cannot_be_bound(self) -> None:
        self.edit_graph(lambda node: node.update(path=None, recorded_sha256=None), "study-design")
        graph = self.load()
        graph.impact("study-design")
        problems = graph.witness_problems(
            "analysis-run", self.witness(graph, inputs={"source-snapshot": graph.recorded_sha256("source-snapshot")})
        )
        self.assertEqual([problem.split(":")[0] for problem in problems], ["MISSING_INPUT"])
        source = graph.recorded_sha256("source-snapshot")
        listed = self.witness(graph, inputs={"source-snapshot": source, "study-design": "1" * 64})
        problems = graph.witness_problems("analysis-run", listed)
        self.assertEqual([problem.split(":")[0] for problem in problems], ["UNBOUND_INPUT"])

    def test_a_pending_node_without_a_recorded_change_cannot_be_witnessed(self) -> None:
        self.edit_graph(lambda node: node.update(validity="STALE_PENDING_REVALIDATION"), "analysis-run")
        graph = self.load()
        problems = graph.witness_problems("analysis-run", self.witness(graph))
        self.assertEqual([problem.split(":")[0] for problem in problems], ["NO_RECORDED_CHANGE"])

    def test_a_witness_is_not_consulted_for_a_root_or_a_changed_file(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        stray = self.witness(graph)
        root = graph.revalidate("study-design", witness=stray)
        self.assertEqual(root.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual((root.witness["consulted"], root.witness["problems"]), (False, []))
        self.assertIsNone(graph.history("study-design")[-1].witness_id)
        output = self.project / "analysis/run-output.json"
        output.write_bytes(output.read_bytes() + b"\n")
        changed = graph.revalidate("analysis-run", witness=stray)
        self.assertEqual(changed.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertIs(changed.witness["consulted"], False)
        self.assertIsNone(graph.history("analysis-run")[-1].witness_id)

    def test_a_real_upstream_change_cannot_be_laundered_by_a_later_cutoff(self) -> None:
        graph = self.source_changed_and_settled()
        self.assertEqual(graph.stale_because("analysis-run"), ("analysis-run", "source-snapshot"))
        graph.impact("source-snapshot")  # declared again; its file is now unchanged against the new record
        rehash = graph.revalidate("source-snapshot")
        self.assertEqual(rehash.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertNotIn("analysis-run", [item.node_id for item in rehash.cleared])
        self.assertEqual(graph.validity("analysis-run"), STALE, "only a witnessed recompute may settle it")
        self.assertEqual(graph.stale_because("analysis-run"), ("analysis-run",))
        settled = graph.revalidate("analysis-run", at=LATER, witness=self.witness(graph))
        self.assertEqual(settled.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)

    def test_refusals_are_kept_in_order_and_a_later_witness_still_settles(self) -> None:
        graph = self.load()
        graph.impact("analysis-run")
        graph.revalidate("analysis-run")  # refused
        graph.revalidate("analysis-run", witness=self.witness(graph, started_at="2026-01-01T00:00:00Z"))  # refused
        accepted = graph.revalidate("analysis-run", at=LATER, witness=self.witness(graph))
        self.assertEqual([item.node_id for item in accepted.cleared], list(BELOW_ANALYSIS))
        for node_id in BELOW_ANALYSIS:
            self.assertEqual(graph.validity(node_id), Validity.CURRENT, node_id)
        reasons = [entry.reason.split(":")[0] for entry in graph.history("analysis-run")]
        self.assertEqual(reasons, ["IMPACT_ORIGIN", VACUOUS_CUTOFF_REASON, INVALID_WITNESS_REASON, "REVALIDATED"])

    def test_a_refused_cutoff_does_not_change_what_early_cutoff_restores(self) -> None:
        # A state saved before section 17 carries no own-account cause after a parent changed, so early cutoff
        # can still clear such a node. It must return to its state from before it went stale, skipping the
        # refusal (STALE to STALE) recorded since.
        graph = self.source_changed_and_settled()
        graph.revalidate("analysis-run")  # refused
        graph.save_state()
        state = self.read_json(f"graph/{GRAPH_STATE_FILE}")
        state["nodes"]["analysis-run"]["stale_because"] = ["source-snapshot"]
        self.write_json(f"graph/{GRAPH_STATE_FILE}", state)
        graph = self.load()
        graph.impact("source-snapshot")
        cleared = graph.revalidate("source-snapshot").cleared
        self.assertIn("analysis-run", [item.node_id for item in cleared])
        self.assertEqual(graph.validity("analysis-run"), Validity.CURRENT)

    def test_a_pending_publication_node_with_a_refused_cutoff_adds_vacuous_cutoff(self) -> None:
        graph = self.load()
        graph.impact("figure-1")
        graph.revalidate("figure-1")
        assessment = assess(graph, graph.detect_changes())
        self.assertEqual((assessment.status, assessment.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.VACUOUS_CUTOFF, assessment.failure_modes)
        self.assertIn(FailureMode.STALE_DEPENDENCY, assessment.failure_modes)
        graph.save_state()
        check = self.currency()
        self.assertIn(FailureMode.VACUOUS_CUTOFF, check.failure_modes)
        self.assertTrue(any("refused early cutoff" in line for line in check.diagnostics))
        # Once the node goes stale again for a new reason, the old refusal no longer counts.
        graph = self.load()
        graph.revalidate("figure-1", at=LATER, witness=self.witness(graph, "figure-1"))
        graph.impact("figure-1", at=LATER)
        self.assertNotIn(FailureMode.VACUOUS_CUTOFF, assess(graph, graph.detect_changes(at=LATER)).failure_modes)

    def test_refusals_round_trip_and_states_saved_before_section_17_still_load(self) -> None:
        graph = self.load()
        graph.impact("analysis-run")
        graph.revalidate("analysis-run", witness=self.witness(graph, started_at="2026-01-01T00:00:00Z"))
        graph.save_state()
        reloaded = self.load()
        self.assertEqual(reloaded.node_table(with_history=True), graph.node_table(with_history=True))
        self.assertTrue(reloaded.refused_cutoff_since_pending("analysis-run"))
        state = self.read_json(f"graph/{GRAPH_STATE_FILE}")
        for entry in state["nodes"].values():
            for transition in entry["history"]:
                transition.pop("witness_id")
                transition.pop("cause_category")
        self.write_json(f"graph/{GRAPH_STATE_FILE}", state)
        old = self.load()
        self.assertEqual(old.validity("analysis-run"), STALE)
        self.assertIsNone(old.history("analysis-run")[-1].witness_id)
        for bad in ({"witness_id": "wit-XYZ"}, {"cause_category": "DATA"}):
            state["nodes"]["analysis-run"]["history"][-1].update(bad)
            self.write_json(f"graph/{GRAPH_STATE_FILE}", state)
            with self.subTest(bad=bad), self.assertRaises(GraphError):
                self.load()
            state["nodes"]["analysis-run"]["history"][-1].update(witness_id=None, cause_category=None)


# ---------------------------------------------------------------------------
# Witness documents
# ---------------------------------------------------------------------------


class WitnessDocumentTests(WitnessedProject):
    def test_committed_witnesses_load_and_their_id_is_a_content_hash(self) -> None:
        witness = load_witness(self.project, RECOMPUTED)
        document = self.read_json(RECOMPUTED)
        self.assertEqual(witness.to_dict(), document)
        self.assertEqual(witness.witness_id, "wit-" + sha256_canonical(document)[:16])
        self.assertRegex(witness.witness_id, r"^wit-[0-9a-f]{16}$")
        other = load_witness(self.project, BEFORE_CHANGE)
        self.assertNotEqual(other.witness_id, witness.witness_id)
        self.assertEqual(RecomputeWitness.from_document(document), witness)

    def test_malformed_witnesses_are_refused_with_a_code(self) -> None:
        document = self.read_json(RECOMPUTED)
        cases: dict[str, Callable[[dict[str, Any]], Any]] = {
            "unknown key": lambda doc: doc.update(note="x"),
            "missing key": lambda doc: doc.pop("output_sha256"),
            "schema": lambda doc: doc.update(schema="science-gate-recompute-witness/v0"),
            "digest": lambda doc: doc.update(output_sha256="ABC"),
            "timestamp": lambda doc: doc.update(started_at="2026-01-02 04:00:00"),
            "node id": lambda doc: doc.update(node_id="no spaces"),
            "inputs type": lambda doc: doc.update(inputs=["source-snapshot"]),
            "input digest": lambda doc: doc["inputs"].update({"study-design": None}),
        }
        for name, change in cases.items():
            copy = json.loads(json.dumps(document))
            change(copy)
            self.write_json("witnesses/bad.json", copy)
            with self.subTest(case=name), self.assertRaises(GraphError) as caught:
                load_witness(self.project, "witnesses/bad.json")
            self.assertEqual(caught.exception.code, MALFORMED_WITNESS)
        (self.project / "witnesses/bad.json").write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
        with self.assertRaises(GraphError) as caught:
            load_witness(self.project, "witnesses/bad.json")
        self.assertEqual(caught.exception.code, MALFORMED_WITNESS)

    def test_missing_and_unsafe_witness_paths_are_refused(self) -> None:
        with self.assertRaises(GraphError) as caught:
            load_witness(self.project, "witnesses/none.json")
        self.assertEqual(caught.exception.code, WITNESS_UNAVAILABLE)
        with self.assertRaises(GraphError) as caught:
            load_witness(self.project, "../outside.json")
        self.assertEqual(caught.exception.code, UNSAFE_PATH)

    def test_the_schema_constant_matches_the_documents(self) -> None:
        self.assertEqual(self.read_json(RECOMPUTED)["schema"], WITNESS_SCHEMA)


# ---------------------------------------------------------------------------
# Verifier drift
# ---------------------------------------------------------------------------


class VerifierDriftTests(WitnessedProject):
    def test_the_recorded_params_digest_is_the_section_17_4_formula(self) -> None:
        (numeric,) = [spec for spec in load_manifest(self.manifest_path).checks if spec.check_id == "numeric"]
        (node,) = [node for node in self.read_json(GRAPH)["nodes"] if node["id"] == "site-summary"]
        backing = node["backed_by_checks"][0]
        self.assertEqual(backing["params_sha256"], params_sha256(numeric))
        self.assertEqual(params_sha256(numeric), sha256_canonical(dict(numeric.params)))

    def test_every_backing_field_and_a_removed_check_drift(self) -> None:
        params = {"column": "mean_value", "expected": [{"key": "site-alpha", "value": "6.27"}]}
        cases: dict[str, tuple[Callable[[], None], str]] = {
            "params": (lambda: self.edit_check("numeric", params=params), "params_sha256"),
            "kind": (lambda: self.edit_backing(kind="row_count"), "kind"),
            "tool version": (lambda: self.edit_backing(tool_version="0.0.1"), "tool_version"),
            "removed check": (lambda: self.edit_backing(check_id="retired"), "check_id"),
        }
        pristine = self.snapshot()
        for name, (change, field) in cases.items():
            for relpath, data in pristine.items():
                (self.project / relpath).write_bytes(data)
            change()
            with self.subTest(case=name):
                check = self.currency()
                self.assertEqual(check.verdict, Status.FAIL)
                self.assertEqual(set(check.evidence["verifier_drift"]), {"conclusion-1", "site-summary"})
                self.assertEqual(list(check.evidence["verifier_drift_detail"][0]["differences"]), [field])

    def test_drift_is_marked_in_memory_with_category_verifier(self) -> None:
        self.edit_check("numeric", version="2")
        graph = self.load()
        drift = verifier_drift(graph, load_manifest(self.manifest_path).checks)
        found = [(entry.node_id, entry.check_id) for entry in drift]
        self.assertEqual(found, [("conclusion-1", "numeric"), ("site-summary", "numeric")])
        transitions = graph.mark_verifier_drift(drift)
        self.assertEqual([node_id for node_id, _ in transitions], ["site-summary", "conclusion-1", "figure-1"])
        self.assertEqual({entry.cause_category for _, entry in transitions}, {StaleCause.VERIFIER})
        self.assertTrue(graph.history("site-summary")[-1].reason.startswith("VERIFIER_DRIFT: "))
        self.assertEqual(graph.stale_because("site-summary"), ("verifier:numeric",))
        self.assertEqual(graph.stale_categories("figure-1"), (StaleCause.VERIFIER,))
        for node_id in ("source-snapshot", "study-design", "analysis-run"):
            self.assertEqual(graph.validity(node_id), Validity.CURRENT, node_id)
            self.assertEqual(graph.stale_categories(node_id), ())

    def test_early_cutoff_never_removes_a_verifier_cause_and_the_state_round_trips(self) -> None:
        self.edit_check("numeric", version="2")
        graph = self.load()
        graph.mark_verifier_drift(verifier_drift(graph, load_manifest(self.manifest_path).checks))
        graph.impact("study-design")
        graph.revalidate("study-design")  # root, unchanged: cutoff runs down to analysis-run and beyond
        self.assertEqual(graph.validity("site-summary"), STALE)
        self.assertIn("verifier:numeric", graph.stale_because("site-summary"))
        graph.save_state()
        reloaded = self.load()
        self.assertEqual(reloaded.stale_because("site-summary"), graph.stale_because("site-summary"))
        self.assertEqual(reloaded.stale_categories("conclusion-1"), (StaleCause.VERIFIER,))

    def test_both_categories_when_data_and_verifier_change(self) -> None:
        self.edit_check("numeric", version="2")
        self.change_source()
        check = self.currency()
        stale = {view["id"]: view["stale_categories"] for view in check.evidence["not_in_good_standing"]}
        self.assertEqual(stale["source-snapshot"], ["UPSTREAM"])
        self.assertEqual(stale["site-summary"], ["UPSTREAM", "VERIFIER"])

    def test_verify_writes_nothing_and_reports_the_drift(self) -> None:
        self.edit_check("numeric", version="2")
        before = self.snapshot()
        run = verify(self.manifest_path)
        self.assertEqual(self.snapshot(), before)
        (currency,) = [check for check in run.result.checks if check.kind == "dependency_currency"]
        self.assertEqual(currency.verdict, Status.FAIL)
        drifted = {"conclusion-1": ["numeric"], "site-summary": ["numeric"]}
        self.assertEqual(currency.evidence["verifier_drift"], drifted)
        self.assertNotEqual(run.status, Status.PASS)

    def test_malformed_backing_declarations_are_refused(self) -> None:
        def backing(**changes: Any) -> Callable[[dict[str, Any]], Any]:
            return lambda node: node.update(backed_by_checks=[{**node["backed_by_checks"][0], **changes}])

        cases = {
            "unknown key": backing(note="x"),
            "params digest": backing(params_sha256="ABC"),
            "empty version": backing(version=""),
            "check id": backing(check_id="has space"),
            "twice": lambda node: node.update(backed_by_checks=node["backed_by_checks"] * 2),
            "not a list": lambda node: node.update(backed_by_checks={"check_id": "numeric"}),
        }
        pristine = self.read_json(GRAPH)
        for name, change in cases.items():
            self.write_json(GRAPH, pristine)
            self.edit_graph(change, "site-summary")
            with self.subTest(case=name), self.assertRaises(GraphError) as caught:
                self.load()
            self.assertEqual(caught.exception.code, MALFORMED_GRAPH)


# ---------------------------------------------------------------------------
# revalidate --witness on the command line
# ---------------------------------------------------------------------------


class CommandLineTests(WitnessedProject):
    def run_command(
        self, function: Callable[[argparse.Namespace], int], artifact: str, **extra: Any
    ) -> tuple[int, list[str]]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = function(argparse.Namespace(artifact_id=artifact, manifest=str(self.manifest_path), **extra))
        return code, buffer.getvalue().splitlines()

    def revalidate(self, witness: str | None) -> tuple[int, list[str], dict[str, Any]]:
        path = None if witness is None else str(self.project / witness)
        code, lines = self.run_command(cli_revalidate, "analysis-run", witness=path)
        return code, lines, self.read_json(f"graph/{REVALIDATION_REPORT_FILE}")

    def test_revalidate_refuses_a_rehash_and_a_stale_witness_then_accepts_a_recompute(self) -> None:
        code, _ = self.run_command(cli_impact, "analysis-run")
        self.assertEqual(code, 1)
        code, lines, report = self.revalidate(None)
        self.assertEqual(code, 1, lines[0])  # publication is still blocked
        self.assertIn("REFUSED_VACUOUS_CUTOFF", lines[0])
        self.assertEqual(report["revalidate"]["outcome"], "REFUSED_VACUOUS_CUTOFF")
        self.assertIn("VACUOUS_CUTOFF", [mode for item in report["findings"] for mode in item["failure_modes"]])
        self.assertIn("- recompute witness: none supplied", lines)

        code, lines, report = self.revalidate(BEFORE_CHANGE)
        self.assertEqual(code, 1, lines[0])
        self.assertEqual(report["revalidate"]["outcome"], "REFUSED_INVALID_WITNESS")
        (problem,) = report["revalidate"]["witness"]["problems"]
        self.assertTrue(problem.startswith("WITNESS_PREDATES_CHANGE"), problem)
        self.assertTrue(any(line.startswith("  - refused: WITNESS_PREDATES_CHANGE") for line in lines))

        code, lines, report = self.revalidate(RECOMPUTED)
        self.assertEqual(code, 0, lines[0])
        self.assertIn("REVALIDATED_UNCHANGED; 3 descendant(s) cleared by early cutoff", lines[0])
        witness_id = load_witness(self.project, RECOMPUTED).witness_id
        self.assertEqual(report["revalidate"]["witness"]["witness_id"], witness_id)
        history = self.read_json(f"graph/{GRAPH_STATE_FILE}")["nodes"]["analysis-run"]["history"]
        self.assertEqual(
            [(entry["to"], entry["reason"].split(":")[0], entry["witness_id"]) for entry in history],
            [
                (STALE.value, "IMPACT_ORIGIN", None),
                (STALE.value, VACUOUS_CUTOFF_REASON, None),
                (STALE.value, INVALID_WITNESS_REASON, load_witness(self.project, BEFORE_CHANGE).witness_id),
                (Validity.REVALIDATED_UNCHANGED.value, "REVALIDATED", witness_id),
            ],
        )

    def test_the_witness_flag_is_wired_into_the_cli(self) -> None:
        manifest = str(self.manifest_path)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(cli.main(["impact", "analysis-run", "--manifest", manifest]), 1)
            witness = str(self.project / RECOMPUTED)
            self.assertEqual(cli.main(["revalidate", "analysis-run", "--manifest", manifest, "--witness", witness]), 0)
        report = self.read_json(f"graph/{REVALIDATION_REPORT_FILE}")
        self.assertEqual(report["revalidate"]["outcome"], "REVALIDATED_UNCHANGED")
        self.assertEqual(report["revalidate"]["witness"]["witness_id"], load_witness(self.project, RECOMPUTED).witness_id)

    def test_an_unusable_witness_file_exits_3_and_writes_nothing(self) -> None:
        self.write_json("witnesses/broken.json", {"schema": WITNESS_SCHEMA})
        cases = (("witnesses/absent.json", WITNESS_UNAVAILABLE), ("witnesses/broken.json", MALFORMED_WITNESS))
        for witness, code_name in cases:
            before = self.snapshot()
            with self.subTest(witness=witness):
                code, lines = self.run_command(cli_revalidate, "analysis-run", witness=str(self.project / witness))
                self.assertEqual((code, len(lines)), (3, 1))
                self.assertTrue(lines[0].startswith(f"ERROR revalidate: {code_name}"), lines[0])
                self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
