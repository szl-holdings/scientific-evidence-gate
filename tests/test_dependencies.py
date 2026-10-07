"""Dependency graph, impact walks, revalidation and the dependency_currency check (section 8).

Every test works on a private copy of the committed synthetic project in
``fixtures/dependencies/current`` (or on small invented graphs written into a
temporary directory). The committed fixtures themselves are only ever read.
The graph in that project:

    source-snapshot -> admitted-evidence, table-2
    study-design    -> admitted-evidence, analysis-run
    admitted-evidence -> analysis-run -> site-means -> figure-1, conclusion-1
    figure-1 -> conclusion-1
    table-2 -> conclusion-2

Section 17 additions tested here: the closed skip justifications of the
check's unexamined outcomes (#24), the dependency_currency falsifier (17.5)
and the schema keys of 17.13. Witnessed revalidation and verifier drift
have their own module (test_witnessed_revalidation.py), as does the
what-if (test_staleness_whatif.py).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR, TempDirTestCase

from science_gate import cli
from science_gate._canonical import sha256_bytes, strict_loads
from science_gate.dependencies import (
    BACKING_KEYS,
    FALSIFIER_MARK,
    GRAPH_CYCLE,
    GRAPH_SCHEMA,
    GRAPH_STATE_FILE,
    GRAPH_STATE_SCHEMA,
    GRAPH_UNAVAILABLE,
    IMPACT_REPORT_FILE,
    IMPACT_REPORT_SCHEMA,
    MALFORMED_GRAPH,
    MALFORMED_STATE,
    NODE_KEYS,
    NODE_ROLE,
    REQUIRED_GRAPH_KEYS,
    REQUIRED_NODE_KEYS,
    REQUIRED_STATE_TRANSITION_KEYS,
    REQUIRED_TRANSITION_KEYS,
    REVALIDATION_REPORT_FILE,
    STATE_KEYS,
    STATE_NODE_KEYS,
    STATE_ROLE,
    TRANSITION_KEYS,
    UNKNOWN_ARTIFACT,
    UNSAFE_PATH,
    WHAT_IF_SCHEMA,
    WITNESS_KEYS,
    WITNESS_SCHEMA,
    Assessment,
    DependencyGraph,
    DigestComparison,
    GraphCycleError,
    GraphError,
    NodeKind,
    RecomputeWitness,
    RevalidationOutcome,
    assess,
    check_dependency_currency,
    falsify_dependency_currency,
    load_graph,
    parse_graph,
)
from science_gate.discovery import discover
from science_gate.manifests import CheckSpec, load_manifest
from science_gate.models import (
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    CheckResult,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    FalsifierOutcome,
    Reason,
    SkipJustification,
    StaleCause,
    Status,
    Validity,
)
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.verifier import CheckContext, CheckOutcome, VerificationRun, verify

FIXTURES = REPO_ROOT / "fixtures" / "dependencies"
CURRENT = FIXTURES / "current"
CYCLE = FIXTURES / "cycle"
GRAPH = "graph/graph.json"
STALE = Validity.STALE_PENDING_REVALIDATION

#: The fixture's descendants of ``study-design``, in walk order (depth, then id).
DESIGN_DESCENDANTS = ["admitted-evidence", "analysis-run", "site-means", "conclusion-1", "figure-1"]
ALL_NODES = [
    "admitted-evidence",
    "analysis-run",
    "conclusion-1",
    "conclusion-2",
    "figure-1",
    "site-means",
    "source-snapshot",
    "study-design",
    "table-2",
]
#: A secret-shaped value planted in the environment by the redaction test.
PLANTED_SECRET = "synthetic-secret-value-0001"
_ANY_DIGEST = "0" * 64


def graph_document(nodes: list[dict[str, Any]], edges: list[list[str]], **extra: Any) -> dict[str, Any]:
    return {"schema": GRAPH_SCHEMA, "nodes": nodes, "edges": edges, **extra}


def bare_node(node_id: str, kind: str = "ANALYSIS_RUN", validity: str = "CURRENT", **extra: Any) -> dict[str, Any]:
    """A node without a file."""
    return {"id": node_id, "kind": kind, "path": None, "recorded_sha256": None, "validity": validity, **extra}


def parse(document: dict[str, Any]) -> DependencyGraph:
    return parse_graph(document, graph_path=GRAPH, graph_sha256=_ANY_DIGEST)


def recompute_witness(graph: DependencyGraph, node_id: str) -> RecomputeWitness:
    """A witness that binds: started after the fixed clock, every parent at its current digest."""
    inputs = {parent: graph.recorded_sha256(parent) for parent in graph.parents(node_id)}
    return RecomputeWitness(
        node_id=node_id,
        invocation_id="inv-" + sha256_bytes(f"synthetic recompute of {node_id}".encode("utf-8"))[:12],
        started_at="2026-01-02T04:00:00Z",
        completed_at="2026-01-02T04:05:00Z",
        inputs={parent: digest for parent, digest in inputs.items() if digest is not None},
        output_sha256=graph.recorded_sha256(node_id),
    )


def currency_context(manifest_path: Path) -> tuple[CheckContext, CheckSpec]:
    """A check context as the engine builds one (inputs discovered, files preloaded), and the currency spec.

    Calling the check directly keeps these tests about the check itself, not
    about how the engine later folds its result into a run.
    """
    manifest = load_manifest(manifest_path)
    _, opened = discover(manifest)
    ctx = CheckContext(manifest, opened)
    ctx.preload(spec.kind for spec in manifest.checks)
    (spec,) = [spec for spec in manifest.checks if spec.kind == "dependency_currency"]
    return ctx, spec


def run_currency(manifest_path: Path) -> CheckOutcome:
    ctx, spec = currency_context(manifest_path)
    return check_dependency_currency(ctx, spec)


class GraphProject(TempDirTestCase):
    """A fresh copy of the synthetic dependency project, with the clock pinned and no signing key."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.project = self.tmp / "project"
        shutil.copytree(CURRENT, self.project)

    @property
    def manifest_path(self) -> Path:
        return self.project / "manifest.json"

    def load(self) -> DependencyGraph:
        return load_graph(self.project, GRAPH)

    def append(self, relpath: str, text: str = "a synthetic edit\n") -> None:
        with open(self.project / relpath, "ab") as handle:
            handle.write(text.encode("utf-8"))

    def remove(self, relpath: str) -> None:
        (self.project / relpath).unlink()

    def read_json(self, relpath: str) -> Any:
        return json.loads((self.project / relpath).read_text(encoding="utf-8"))

    def write_json(self, relpath: str, document: Any) -> None:
        path = self.project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def file_node(self, node_id: str, kind: str, relpath: str, **extra: Any) -> dict[str, Any]:
        """Write an invented file for a node and return the node, with its digest recorded."""
        data = f"synthetic content of {node_id}\n".encode("utf-8")
        path = self.project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        node = {"id": node_id, "kind": kind, "path": relpath, "recorded_sha256": sha256_bytes(data)}
        return {**node, "validity": "CURRENT", **extra}

    def write_graph(self, nodes: list[dict[str, Any]], edges: list[list[str]]) -> None:
        self.write_json(GRAPH, graph_document(nodes, edges))

    def snapshot(self) -> dict[str, bytes]:
        """Every file in the project, for proving what a command did and did not write."""
        return {
            path.relative_to(self.project).as_posix(): path.read_bytes()
            for path in sorted(self.project.rglob("*"))
            if path.is_file()
        }

    def run_verify(self) -> VerificationRun:
        return verify(self.manifest_path)

    def currency(self, run: VerificationRun) -> Any:
        (found,) = [check for check in run.result.checks if check.kind == "dependency_currency"]
        return found

    def run_cli(self, *args: str) -> tuple[int, list[str]]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(list(args))
        return code, buffer.getvalue().splitlines()


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


class ParseGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = strict_loads((CURRENT / GRAPH).read_bytes())

    def assert_refused(self, document: Any, code: str = MALFORMED_GRAPH) -> GraphError:
        with self.assertRaises(GraphError) as caught:
            parse(document)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception

    def test_fixture_graph_parses_with_sorted_nodes_and_a_topological_order(self) -> None:
        graph = parse(self.document)
        self.assertEqual([node.node_id for node in graph.nodes], ALL_NODES)
        self.assertEqual(len(graph.edges), 10)
        self.assertEqual(sorted(graph.edges), list(graph.edges))
        position = {node_id: index for index, node_id in enumerate(graph.topological_order)}
        for parent, child in graph.edges:
            self.assertLess(position[parent], position[child])
        self.assertEqual(graph.state_path, "graph/graph-state.json")
        self.assertEqual({node.kind for node in graph.nodes}, set(NodeKind))

    def test_schema_key_is_optional_but_must_match_when_present(self) -> None:
        del self.document["schema"]
        self.assertEqual(len(parse(self.document).nodes), 9)
        self.document["schema"] = "science-gate-graph/v2"
        self.assert_refused(self.document)

    def test_unknown_keys_are_refused_at_every_level(self) -> None:
        cases = (
            lambda doc: doc.update(notes="x"),
            lambda doc: doc["nodes"][0].update(recorded_sha265=_ANY_DIGEST),
            lambda doc: doc["nodes"][0].update(
                validity="STALE_PENDING_REVALIDATION",
                history=[{"at": FIXED_TIME, "from": "CURRENT", "to": "STALE_PENDING_REVALIDATION",
                          "reason": "declared", "comment": "x"}],
            ),
        )
        for edit in cases:
            document = json.loads(json.dumps(self.document))
            edit(document)
            with self.subTest(edit=edit):
                self.assertIn("unknown key", str(self.assert_refused(document)))

    def test_every_required_node_key_must_be_present(self) -> None:
        for key in sorted(REQUIRED_NODE_KEYS):
            document = json.loads(json.dumps(self.document))
            del document["nodes"][0][key]
            with self.subTest(key=key):
                self.assert_refused(document)

    def test_invalid_values_are_refused(self) -> None:
        cases = {
            "kind": "PREPRINT",
            "validity": "FALSE",
            "recorded_sha256": "ABC",
            "id": "no spaces allowed",
            "path": 42,
        }
        for key, value in cases.items():
            document = json.loads(json.dumps(self.document))
            document["nodes"][0][key] = value
            with self.subTest(key=key):
                self.assert_refused(document)

    def test_a_digest_without_a_file_is_refused(self) -> None:
        node = bare_node("orphan-digest", recorded_sha256=_ANY_DIGEST)
        self.assert_refused(graph_document([node], []))

    def test_node_paths_that_could_leave_the_manifest_directory_are_unsafe(self) -> None:
        for path in ("../outside.txt", "/etc/passwd", "C:/outside.txt", "a/../../outside.txt"):
            node = {**bare_node("escape"), "path": path, "recorded_sha256": _ANY_DIGEST}
            with self.subTest(path=path):
                self.assert_refused(graph_document([node], []), UNSAFE_PATH)

    def test_duplicates_are_refused(self) -> None:
        twice = graph_document([bare_node("a"), bare_node("a")], [])
        self.assertIn("declared twice", str(self.assert_refused(twice)))
        same_file = [
            {**bare_node("a"), "path": "x/data.csv", "recorded_sha256": _ANY_DIGEST},
            {**bare_node("b"), "path": "x/./data.csv", "recorded_sha256": _ANY_DIGEST},
        ]
        self.assertIn("same file", str(self.assert_refused(graph_document(same_file, []))))
        repeated = graph_document([bare_node("a"), bare_node("b")], [["a", "b"], ["a", "b"]])
        self.assertIn("repeats the edge", str(self.assert_refused(repeated)))

    def test_edges_must_be_pairs_of_declared_nodes(self) -> None:
        nodes = [bare_node("a"), bare_node("b")]
        for edges in ([["a"]], [["a", "b", "c"]], ["ab"], [["a", "ghost"]], [[1, "b"]], {"a": "b"}):
            with self.subTest(edges=edges):
                self.assert_refused(graph_document(nodes, edges))

    def test_a_node_cannot_name_a_file_this_tool_writes(self) -> None:
        for name in (GRAPH_STATE_FILE, IMPACT_REPORT_FILE, REVALIDATION_REPORT_FILE):
            node = {**bare_node("self-referential"), "path": f"graph/{name}", "recorded_sha256": _ANY_DIGEST}
            with self.subTest(name=name):
                self.assertIn("this tool writes", str(self.assert_refused(graph_document([node], []))))

    def test_declared_history_must_end_in_the_declared_validity(self) -> None:
        entry = {"at": FIXED_TIME, "from": "CURRENT", "to": "REVALIDATED_UNCHANGED", "reason": "declared review"}
        consistent = bare_node("a", validity="REVALIDATED_UNCHANGED", history=[entry])
        self.assertEqual(len(parse(graph_document([consistent], [])).history("a")), 1)
        self.assert_refused(graph_document([bare_node("a", history=[entry])], []))
        bad_time = {**entry, "at": "2026-01-02 03:04:05"}
        self.assert_refused(graph_document([bare_node("a", validity="REVALIDATED_UNCHANGED", history=[bad_time])], []))

    def test_a_cycle_is_named_in_edge_order(self) -> None:
        nodes = [bare_node("c-design", "DESIGN"), bare_node("c-analysis"), bare_node("c-conclusion", "CONCLUSION")]
        edges = [["c-design", "c-analysis"], ["c-analysis", "c-conclusion"], ["c-conclusion", "c-analysis"]]
        with self.assertRaises(GraphCycleError) as caught:
            parse(graph_document(nodes, edges))
        self.assertEqual(caught.exception.code, GRAPH_CYCLE)
        self.assertEqual(caught.exception.cycle, ("c-analysis", "c-conclusion", "c-analysis"))
        self.assertEqual(caught.exception.to_dict()["cycle"], ["c-analysis", "c-conclusion", "c-analysis"])

    def test_cycle_report_does_not_depend_on_declaration_order(self) -> None:
        nodes = [bare_node(name) for name in ("n1", "n2", "n3", "n4", "n5")]
        edges = [["n1", "n2"], ["n2", "n3"], ["n3", "n4"], ["n4", "n2"], ["n4", "n5"]]
        seen = set()
        shuffler = random.Random(20260102)
        for _ in range(6):
            shuffler.shuffle(nodes)
            shuffler.shuffle(edges)
            with self.assertRaises(GraphCycleError) as caught:
                parse(graph_document(list(nodes), list(edges)))
            seen.add(caught.exception.cycle)
        self.assertEqual(seen, {("n2", "n3", "n4", "n2")})

    def test_a_self_loop_is_a_cycle(self) -> None:
        with self.assertRaises(GraphCycleError) as caught:
            parse(graph_document([bare_node("loop")], [["loop", "loop"]]))
        self.assertEqual(caught.exception.cycle, ("loop", "loop"))


# ---------------------------------------------------------------------------
# Impact walks
# ---------------------------------------------------------------------------


class ImpactTests(GraphProject):
    def test_impact_marks_the_origin_and_every_descendant_and_nothing_else(self) -> None:
        graph = self.load()
        impact = graph.impact("study-design")
        self.assertEqual([item.node_id for item in impact.descendants], DESIGN_DESCENDANTS)
        self.assertEqual(impact.prior_state, Validity.CURRENT)
        self.assertEqual(impact.state, STALE)
        for node_id in ["study-design", *DESIGN_DESCENDANTS]:
            self.assertEqual(graph.validity(node_id), STALE, node_id)
        for node_id in ("source-snapshot", "table-2", "conclusion-2"):
            self.assertEqual(graph.validity(node_id), Validity.CURRENT, node_id)

    def test_traversal_helpers_follow_the_declared_edges(self) -> None:
        graph = self.load()
        self.assertEqual(graph.descendants("study-design"), tuple(DESIGN_DESCENDANTS))
        self.assertEqual(graph.descendants("conclusion-2"), ())
        self.assertEqual(graph.parents("conclusion-1"), ("figure-1", "site-means"))
        self.assertEqual(
            graph.ancestors("conclusion-1"),
            ("admitted-evidence", "analysis-run", "figure-1", "site-means", "source-snapshot", "study-design"),
        )

    def test_walk_is_breadth_first_in_sorted_order_with_shortest_paths(self) -> None:
        impact = self.load().impact("source-snapshot")
        walk = [(item.depth, item.node_id, item.path_from_changed_node) for item in impact.descendants]
        self.assertEqual(
            walk,
            [
                (1, "admitted-evidence", ("source-snapshot", "admitted-evidence")),
                (1, "table-2", ("source-snapshot", "table-2")),
                (2, "analysis-run", ("source-snapshot", "admitted-evidence", "analysis-run")),
                (2, "conclusion-2", ("source-snapshot", "table-2", "conclusion-2")),
                (3, "site-means", ("source-snapshot", "admitted-evidence", "analysis-run", "site-means")),
                (
                    4,
                    "conclusion-1",
                    ("source-snapshot", "admitted-evidence", "analysis-run", "site-means", "conclusion-1"),
                ),
                (4, "figure-1", ("source-snapshot", "admitted-evidence", "analysis-run", "site-means", "figure-1")),
            ],
        )
        self.assertEqual([item.publication_node for item in impact.descendants].count(True), 4)

    def test_every_affected_parent_is_recorded_as_a_cause(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        self.assertEqual(graph.stale_because("study-design"), ("study-design",))
        self.assertEqual(graph.stale_because("analysis-run"), ("admitted-evidence", "study-design"))
        self.assertEqual(graph.stale_because("conclusion-1"), ("figure-1", "site-means"))

    def test_each_transition_is_appended_to_history_with_the_contract_fields(self) -> None:
        graph = self.load()
        impact = graph.impact("study-design")
        self.assertEqual([node_id for node_id, _ in impact.transitions], ["study-design", *DESIGN_DESCENDANTS])
        (entry,) = graph.history("figure-1")
        record = entry.to_dict()
        self.assertLessEqual(REQUIRED_TRANSITION_KEYS, set(record))
        self.assertEqual((record["at"], record["from"], record["to"]), (FIXED_TIME, "CURRENT", STALE.value))
        self.assertEqual(record["trigger"], "study-design")
        self.assertIn("study-design -> analysis-run -> site-means -> figure-1", record["reason"])
        self.assertEqual(record["recorded_sha256_before"], record["recorded_sha256_after"])

    def test_nothing_is_called_false_or_invalidated(self) -> None:
        graph = self.load()
        impact = graph.impact("source-snapshot")
        states = {graph.validity(node.node_id) for node in graph.nodes}
        self.assertNotIn(Validity.INVALIDATED, states)
        self.assertLessEqual(states, {STALE, Validity.CURRENT})
        for _, entry in impact.transitions:
            self.assertNotIn("INVALIDATED", entry.reason)
            self.assertNotIn("false", entry.reason.lower())

    def test_repeating_an_impact_records_no_new_transition(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        again = graph.impact("study-design")
        self.assertEqual(again.transitions, ())
        self.assertEqual({item.prior_state for item in again.descendants}, {STALE})

    def test_states_declared_by_people_are_kept(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "figure-1":
                node["validity"] = "SUPERSEDED"
        self.write_json(GRAPH, document)
        graph = self.load()
        impact = graph.impact("site-means")
        self.assertEqual(graph.validity("figure-1"), Validity.SUPERSEDED)
        figure = next(item for item in impact.descendants if item.node_id == "figure-1")
        self.assertEqual((figure.prior_state, figure.state), (Validity.SUPERSEDED, Validity.SUPERSEDED))
        self.assertEqual(graph.validity("conclusion-1"), STALE)

    def test_an_unknown_artifact_is_refused(self) -> None:
        with self.assertRaises(GraphError) as caught:
            self.load().impact("no-such-artifact")
        self.assertEqual(caught.exception.code, UNKNOWN_ARTIFACT)

    def test_impact_does_not_depend_on_declaration_order(self) -> None:
        expected = self.load().impact("source-snapshot").to_dict()
        document = self.read_json(GRAPH)
        document["nodes"].reverse()
        document["edges"].reverse()
        self.write_json(GRAPH, document)
        self.assertEqual(self.load().impact("source-snapshot").to_dict(), expected)


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


class DetectChangesTests(GraphProject):
    def test_an_unchanged_project_detects_nothing(self) -> None:
        graph = self.load()
        detection = graph.detect_changes()
        self.assertEqual(detection.files_hashed, 9)
        self.assertEqual(detection.outcome_counts()["UNCHANGED"], 9)
        self.assertEqual(detection.transitions, ())

    def test_a_changed_file_makes_its_node_and_every_descendant_stale(self) -> None:
        self.append("design/protocol.md")
        graph = self.load()
        detection = graph.detect_changes()
        self.assertEqual(detection.ids(DigestComparison.CHANGED), ("study-design",))
        (observation,) = [item for item in detection.observations if item.node_id == "study-design"]
        self.assertEqual(observation.observed_sha256, sha256_bytes((self.project / "design/protocol.md").read_bytes()))
        self.assertNotEqual(observation.observed_sha256, observation.recorded_sha256)
        for node_id in ["study-design", *DESIGN_DESCENDANTS]:
            self.assertEqual(graph.validity(node_id), STALE, node_id)
        self.assertIn("study-design", graph.stale_because("study-design"))
        design_entry = graph.history("study-design")[-1]
        self.assertEqual(design_entry.observed_sha256, observation.observed_sha256)

    def test_a_missing_file_is_unresolved_and_its_descendants_are_pending(self) -> None:
        self.remove("design/protocol.md")
        graph = self.load()
        detection = graph.detect_changes()
        self.assertEqual(detection.ids(DigestComparison.UNAVAILABLE), ("study-design",))
        self.assertEqual(graph.validity("study-design"), Validity.UNRESOLVED)
        self.assertIn("FILE_UNAVAILABLE: MISSING", graph.history("study-design")[-1].reason)
        for node_id in DESIGN_DESCENDANTS:
            self.assertEqual(graph.validity(node_id), STALE, node_id)

    def test_missing_baselines_and_fileless_nodes_are_reported_as_such(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "conclusion-2":
                node["recorded_sha256"] = None
            if node["id"] == "table-2":
                node.update(path=None, recorded_sha256=None)
        self.write_json(GRAPH, document)
        detection = self.load().detect_changes()
        self.assertEqual(detection.ids(DigestComparison.NO_BASELINE), ("conclusion-2",))
        self.assertEqual(detection.ids(DigestComparison.NO_FILE), ("table-2",))
        self.assertEqual(detection.files_hashed, 8)

    def test_detection_repairs_a_state_saved_before_an_edge_was_added(self) -> None:
        graph = self.load()
        graph.impact("table-2")
        graph.save_state()
        document = self.read_json(GRAPH)
        document["edges"].append(["table-2", "figure-1"])
        self.write_json(GRAPH, document)
        graph = self.load()
        self.assertTrue(graph.state_info.graph_changed_since_state)
        self.assertEqual(graph.validity("figure-1"), Validity.CURRENT)
        detection = graph.detect_changes()
        self.assertEqual(graph.validity("figure-1"), STALE)
        self.assertIn("table-2", graph.stale_because("figure-1"))
        self.assertIn("figure-1", [node_id for node_id, _ in detection.transitions])


# ---------------------------------------------------------------------------
# Revalidation
# ---------------------------------------------------------------------------


class RevalidateTests(GraphProject):
    def test_an_unchanged_digest_clears_descendants_by_early_cutoff(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        result = graph.revalidate("study-design")
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual(result.state, Validity.REVALIDATED_UNCHANGED)
        self.assertEqual(result.recorded_sha256_before, result.recorded_sha256_after)
        self.assertEqual(
            [item.node_id for item in result.cleared],
            ["admitted-evidence", "analysis-run", "site-means", "figure-1", "conclusion-1"],
        )
        for node_id in DESIGN_DESCENDANTS:
            self.assertEqual(graph.validity(node_id), Validity.CURRENT, node_id)
            self.assertEqual(graph.stale_because(node_id), ())
        # The original stale state and the correction are both in the history.
        self.assertEqual([(e.from_state, e.to_state) for e in graph.history("figure-1")],
                         [(Validity.CURRENT, STALE), (STALE, Validity.CURRENT)])
        self.assertIn("EARLY_CUTOFF", graph.history("figure-1")[-1].reason)
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.PASS)

    def test_a_changed_digest_is_recorded_and_the_children_stay_stale(self) -> None:
        graph = self.load()
        original = graph.recorded_sha256("study-design")
        graph.impact("study-design")
        self.append("design/protocol.md")
        result = graph.revalidate("study-design")
        current = sha256_bytes((self.project / "design/protocol.md").read_bytes())
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual((result.recorded_sha256_before, result.recorded_sha256_after), (original, current))
        self.assertEqual(graph.recorded_sha256("study-design"), current)
        self.assertEqual(result.cleared, ())
        for node_id in DESIGN_DESCENDANTS:
            self.assertEqual(graph.validity(node_id), STALE, node_id)
        last = graph.history("study-design")[-1]
        self.assertEqual((last.recorded_sha256_before, last.recorded_sha256_after), (original, current))
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.FAIL)

    def test_after_a_real_change_early_cutoff_clears_only_what_no_longer_depends_on_it(self) -> None:
        # Section 17.13 (D6) changed this test: the two derived nodes now
        # settle only with recompute witnesses, and each direct child of the
        # changed design is pending on its own account as well.
        graph = self.load()
        graph.impact("study-design")
        self.append("design/protocol.md")
        graph.revalidate("study-design")
        self.assertEqual(graph.stale_because("admitted-evidence"), ("admitted-evidence", "study-design"))
        rehashed = graph.revalidate("admitted-evidence")
        self.assertEqual(rehashed.outcome, RevalidationOutcome.REFUSED_VACUOUS_CUTOFF)
        admitted = graph.revalidate("admitted-evidence", witness=recompute_witness(graph, "admitted-evidence"))
        self.assertEqual(admitted.outcome, RevalidationOutcome.REVALIDATED_UNCHANGED)
        self.assertEqual(admitted.cleared, ())
        self.assertEqual(graph.stale_because("analysis-run"), ("analysis-run", "study-design"))
        analysis = graph.revalidate("analysis-run", witness=recompute_witness(graph, "analysis-run"))
        self.assertEqual([item.node_id for item in analysis.cleared], ["site-means", "figure-1", "conclusion-1"])
        assessment = assess(graph, graph.detect_changes())
        self.assertEqual(assessment.status, Status.PASS)
        self.assertIs(assessment.publication_block["blocked"], False)

    def test_a_node_whose_own_file_changed_is_not_cleared_by_an_upstream_cutoff(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        self.append("figures/figure-1.csv")
        graph.detect_changes()
        graph.revalidate("study-design")
        self.assertEqual(graph.validity("site-means"), Validity.CURRENT)
        self.assertEqual(graph.validity("figure-1"), STALE)
        self.assertEqual(graph.stale_because("figure-1"), ("figure-1",))
        self.assertEqual(graph.validity("conclusion-1"), STALE)
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.FAIL)

    def test_revalidation_is_refused_while_an_ancestor_is_pending(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        before = graph.node_view("figure-1", with_history=True)
        result = graph.revalidate("figure-1")
        self.assertEqual(result.outcome, RevalidationOutcome.REFUSED_UPSTREAM_PENDING)
        self.assertEqual(result.pending_ancestors, ("admitted-evidence", "analysis-run", "site-means", "study-design"))
        self.assertEqual(result.transitions, ())
        self.assertEqual(graph.node_view("figure-1", with_history=True), before)

    def test_a_node_without_a_file_cannot_be_revalidated(self) -> None:
        design = self.file_node("design", "DESIGN", "files/design.txt")
        self.write_graph([design, bare_node("claim", "CONCLUSION")], [["design", "claim"]])
        graph = self.load()
        result = graph.revalidate("claim")
        self.assertEqual(result.outcome, RevalidationOutcome.NO_FILE_TO_HASH)
        self.assertEqual(result.transitions, ())
        graph.impact("design")
        self.assertEqual(graph.revalidate("claim").outcome, RevalidationOutcome.REFUSED_UPSTREAM_PENDING)
        graph.revalidate("design")
        self.assertEqual(graph.validity("claim"), Validity.CURRENT)  # cleared by early cutoff

    def test_an_unreadable_file_becomes_unresolved_and_keeps_descendants_pending(self) -> None:
        self.remove("figures/figure-1.csv")
        graph = self.load()
        result = graph.revalidate("figure-1")
        self.assertEqual(result.outcome, RevalidationOutcome.FILE_UNAVAILABLE)
        self.assertIn("MISSING", result.diagnostic)
        self.assertEqual(graph.validity("figure-1"), Validity.UNRESOLVED)
        self.assertEqual([item.node_id for item in result.still_pending], ["conclusion-1"])
        self.assertEqual(graph.validity("conclusion-1"), STALE)

    def test_recording_a_new_digest_can_never_hide_the_change_downstream(self) -> None:
        self.append("analysis/run-output.json")
        graph = self.load()
        result = graph.revalidate("analysis-run")
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual([item.node_id for item in result.still_pending], ["site-means", "conclusion-1", "figure-1"])
        assessment = assess(graph, graph.detect_changes())
        self.assertEqual(assessment.status, Status.FAIL)
        self.assertEqual(assessment.publication_block["stale_publication_nodes"], ["conclusion-1", "figure-1"])

    def test_a_missing_baseline_is_recorded_by_revalidation(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "conclusion-2":
                node["recorded_sha256"] = None
        self.write_json(GRAPH, document)
        graph = self.load()
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.ABSTAIN)
        result = graph.revalidate("conclusion-2")
        self.assertEqual(result.outcome, RevalidationOutcome.REVALIDATED_CHANGED)
        self.assertEqual((result.recorded_sha256_before, result.recorded_sha256_after),
                         (None, sha256_bytes((self.project / "conclusions/conclusion-2.md").read_bytes())))
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.PASS)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class StateTests(GraphProject):
    def stale_state(self) -> dict[str, Any]:
        graph = self.load()
        graph.impact("study-design")
        graph.save_state()
        return self.read_json(f"graph/{GRAPH_STATE_FILE}")

    def assert_state_refused(self, state: Any) -> None:
        self.write_json(f"graph/{GRAPH_STATE_FILE}", state)
        with self.assertRaises(GraphError) as caught:
            self.load()
        self.assertEqual(caught.exception.code, MALFORMED_STATE, str(caught.exception))

    def test_state_round_trips_with_history_and_causes(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        self.append("design/protocol.md")
        graph.revalidate("study-design")
        graph.save_state()
        reloaded = self.load()
        self.assertEqual(reloaded.node_table(with_history=True), graph.node_table(with_history=True))
        self.assertTrue(reloaded.state_info.present)
        self.assertIs(reloaded.state_info.graph_changed_since_state, False)
        state_bytes = (self.project / "graph" / GRAPH_STATE_FILE).read_bytes()
        self.assertEqual(reloaded.state_info.sha256, sha256_bytes(state_bytes))

    def test_saving_writes_only_graph_state_next_to_the_graph(self) -> None:
        before = self.snapshot()
        graph = self.load()
        graph.impact("study-design")
        path = graph.save_state()
        self.assertEqual(path, (self.project / "graph" / GRAPH_STATE_FILE).resolve())
        after = self.snapshot()
        self.assertEqual(set(after) - set(before), {f"graph/{GRAPH_STATE_FILE}"})
        self.assertEqual({key: after[key] for key in before}, before)  # graph.json is never rewritten
        state = self.read_json(f"graph/{GRAPH_STATE_FILE}")
        self.assertEqual(set(state), STATE_KEYS)
        self.assertEqual(state["schema"], GRAPH_STATE_SCHEMA)
        self.assertEqual(state["graph"], {"path": GRAPH, "sha256": sha256_bytes(before[GRAPH])})
        self.assertEqual(set(state["nodes"]), set(ALL_NODES))
        for entry in state["nodes"].values():
            self.assertEqual(set(entry), STATE_NODE_KEYS)
            for transition in entry["history"]:
                self.assertEqual(set(transition), TRANSITION_KEYS)

    def test_an_unusable_state_is_refused_never_ignored(self) -> None:
        state = self.stale_state()

        def edited(change: Any) -> dict[str, Any]:
            copy = json.loads(json.dumps(state))
            change(copy)
            return copy

        cases = {
            "schema": lambda doc: doc.update(schema="science-gate-graph-state/v0"),
            "unknown key": lambda doc: doc.update(note="x"),
            "other graph": lambda doc: doc["graph"].update(path="elsewhere/graph.json"),
            "validity edited without history": lambda doc: doc["nodes"]["conclusion-1"].update(validity="CURRENT"),
            "digest edited without history": lambda doc: doc["nodes"]["figure-1"].update(
                recorded_sha256=_ANY_DIGEST
            ),
            "stale without cause": lambda doc: doc["nodes"]["figure-1"].update(stale_because=[]),
            "current with causes": lambda doc: doc["nodes"]["figure-1"].update(
                validity="CURRENT",
                history=[*doc["nodes"]["figure-1"]["history"], {
                    **doc["nodes"]["figure-1"]["history"][-1], "from": STALE.value, "to": "CURRENT"}],
            ),
            "incomplete transition": lambda doc: doc["nodes"]["figure-1"]["history"][-1].pop("trigger"),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.assert_state_refused(edited(change))
        (self.project / "graph" / GRAPH_STATE_FILE).write_bytes(b"{not json")
        with self.assertRaises(GraphError) as caught:
            self.load()
        self.assertEqual(caught.exception.code, MALFORMED_STATE)

    def test_editing_graph_json_cannot_clear_a_recorded_stale_mark(self) -> None:
        self.stale_state()
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            node["validity"] = "CURRENT"
        self.write_json(GRAPH, document)
        graph = self.load()
        self.assertTrue(graph.state_info.graph_changed_since_state)
        self.assertEqual(graph.validity("conclusion-1"), STALE)
        self.assertEqual(assess(graph, graph.detect_changes()).status, Status.FAIL)

    def test_untouched_nodes_follow_graph_json_and_orphans_are_reported(self) -> None:
        state = self.stale_state()
        state["nodes"]["retired-node"] = {"validity": "CURRENT", "recorded_sha256": None, "stale_because": [],
                                          "history": []}
        self.write_json(f"graph/{GRAPH_STATE_FILE}", state)
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "table-2":
                node["recorded_sha256"] = _ANY_DIGEST
        self.write_json(GRAPH, document)
        graph = self.load()
        self.assertEqual(graph.state_info.orphaned_nodes, ("retired-node",))
        self.assertEqual(graph.recorded_sha256("table-2"), _ANY_DIGEST)
        self.assertIn("table-2", graph.detect_changes().ids(DigestComparison.CHANGED))

    def test_a_graph_without_a_root_cannot_save(self) -> None:
        with self.assertRaises(ValueError):
            parse(strict_loads((CURRENT / GRAPH).read_bytes())).save_state()


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


class AssessTests(GraphProject):
    def assessed(self) -> Any:
        graph = self.load()
        return assess(graph, graph.detect_changes())

    def test_a_current_graph_passes(self) -> None:
        assessment = self.assessed()
        self.assertEqual((assessment.status, assessment.reason), (Status.PASS, Reason.VERIFIED))
        self.assertEqual(assessment.findings, ())
        self.assertIs(assessment.publication_block["blocked"], False)
        self.assertEqual(assessment.counts["files_hashed"], 9)
        self.assertEqual(assessment.counts["publication_nodes"], 4)

    def test_a_stale_publication_node_fails_with_stale_dependency(self) -> None:
        graph = self.load()
        graph.impact("table-2")
        assessment = assess(graph, graph.detect_changes())
        self.assertEqual((assessment.status, assessment.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.STALE_DEPENDENCY, assessment.failure_modes)
        self.assertIs(assessment.publication_block["blocked"], True)
        self.assertEqual(assessment.publication_block["stale_publication_nodes"], ["conclusion-2", "table-2"])

    def test_an_unreadable_publication_node_leaves_the_block_undetermined(self) -> None:
        self.remove("conclusions/conclusion-2.md")
        assessment = self.assessed()
        self.assertEqual((assessment.status, assessment.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertIsNone(assessment.publication_block["blocked"])
        self.assertEqual(assessment.publication_block["undetermined_publication_nodes"], ["conclusion-2"])

    def test_a_stale_intermediate_node_alone_abstains(self) -> None:
        design = self.file_node("design", "DESIGN", "files/design.txt")
        analysis = self.file_node("analysis", "ANALYSIS_RUN", "files/analysis.txt")
        claim = self.file_node("claim", "CONCLUSION", "files/claim.txt")
        self.write_graph([design, analysis, claim], [["design", "analysis"]])
        graph = self.load()
        graph.impact("design")
        assessment = assess(graph, graph.detect_changes())
        self.assertEqual(assessment.status, Status.ABSTAIN)
        self.assertIn(FailureMode.STALE_DEPENDENCY, assessment.failure_modes)
        self.assertIsNone(assessment.publication_block["blocked"])

    def test_declared_states_alone_are_narrated_not_verified(self) -> None:
        self.write_graph([bare_node("design", "DESIGN"), bare_node("claim", "CONCLUSION")], [["design", "claim"]])
        assessment = self.assessed()
        self.assertEqual((assessment.status, assessment.reason), (Status.ABSTAIN, Reason.UNVERIFIED))
        self.assertIn(FailureMode.NARRATED_VERIFICATION, assessment.failure_modes)

    def test_a_graph_without_publication_nodes_has_nothing_to_gate(self) -> None:
        self.write_graph([self.file_node("design", "DESIGN", "files/design.txt")], [])
        assessment = self.assessed()
        self.assertEqual(assessment.status, Status.ABSTAIN)
        self.assertIn("no CONCLUSION or FIGURE_OR_TABLE", assessment.findings[0].detail)

    def test_a_publication_node_declared_invalidated_needs_human_review(self) -> None:
        entry = {"at": FIXED_TIME, "from": "CURRENT", "to": "INVALIDATED", "reason": "declared by a reviewer"}
        claim = self.file_node("claim", "CONCLUSION", "files/claim.txt", validity="INVALIDATED", history=[entry])
        self.write_graph([claim], [])
        assessment = self.assessed()
        self.assertEqual((assessment.status, assessment.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))


# ---------------------------------------------------------------------------
# The dependency_currency check inside verify
# ---------------------------------------------------------------------------


class CurrencyCheckTests(GraphProject):
    def edit_manifest(self, change: Any) -> None:
        document = self.read_json("manifest.json")
        change(document)
        self.write_json("manifest.json", document)

    def test_the_fixture_project_passes_and_every_node_file_is_evidence(self) -> None:
        run = self.run_verify()
        self.assertEqual(run.status, Status.PASS, [finding.detail for finding in run.findings])
        check = self.currency(run)
        self.assertEqual((check.execution_state, check.verdict), (ExecutionState.CHECKED, Status.PASS))
        self.assertEqual(check.rows_examined, 9)
        self.assertEqual(check.evidence["counts"]["files_hashed"], 9)
        self.assertEqual(check.evidence["comparisons_total"], 9)
        self.assertIs(check.evidence["publication_block"]["blocked"], False)
        documents = {item["path"]: item for item in run.documents}
        for node in self.read_json(GRAPH)["nodes"]:
            self.assertIn(NODE_ROLE, documents[node["path"]]["roles"])
            self.assertEqual(documents[node["path"]]["sha256"], node["recorded_sha256"])
        state = documents[f"graph/{GRAPH_STATE_FILE}"]
        self.assertEqual((state["roles"], state["state"]), ([STATE_ROLE], "MISSING"))

    def test_a_changed_upstream_design_fails_the_run(self) -> None:
        self.append("design/protocol.md")
        run = self.run_verify()
        check = self.currency(run)
        self.assertEqual((check.verdict, check.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(FailureMode.STALE_DEPENDENCY, check.failure_modes)
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
        self.assertEqual(check.evidence["publication_block"]["stale_publication_nodes"], ["conclusion-1", "figure-1"])
        changed = [item["id"] for item in check.evidence["comparisons"] if item["outcome"] == "CHANGED"]
        self.assertEqual(changed, ["study-design"])

    def test_a_saved_stale_state_fails_the_run_until_revalidated(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        graph.save_state()
        self.assertEqual(self.run_verify().status, Status.FAIL)
        graph = self.load()
        graph.revalidate("study-design")
        graph.save_state()
        run = self.run_verify()
        self.assertEqual(run.status, Status.PASS)
        self.assertTrue(self.currency(run).evidence["state_record"]["present"])

    def test_an_unusable_state_abstains_and_is_never_ignored(self) -> None:
        graph = self.load()
        graph.impact("study-design")
        graph.save_state()
        state_path = self.project / "graph" / GRAPH_STATE_FILE
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["nodes"]["conclusion-1"]["validity"] = "CURRENT"
        for data in (b"{not json", b"", json.dumps(state).encode("utf-8")):
            state_path.write_bytes(data)
            with self.subTest(data=data[:12]):
                check = self.currency(self.run_verify())
                self.assertEqual((check.verdict, check.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
                self.assertEqual(check.execution_state, ExecutionState.SKIPPED)
                self.assertIn("never ignored", check.diagnostics[0])

    def test_a_cycle_is_an_error_run(self) -> None:
        run = verify(CYCLE / "manifest.json")
        check = self.currency(run)
        self.assertEqual((check.verdict, check.reason), (Status.ERROR, Reason.PROTOCOL_BROKEN))
        self.assertEqual(check.evidence["error"]["cycle"], ["cycle-analysis", "cycle-conclusion", "cycle-analysis"])
        self.assertEqual((run.status, run.exit_code), (Status.ERROR, 3))

    def test_an_unsafe_node_path_is_an_error(self) -> None:
        document = self.read_json(GRAPH)
        document["nodes"][0]["path"] = "../outside.csv"
        self.write_json(GRAPH, document)
        check = self.currency(self.run_verify())
        self.assertEqual(check.verdict, Status.ERROR)
        self.assertEqual(check.evidence["error"]["code"], UNSAFE_PATH)

    def test_a_malformed_or_missing_graph_abstains(self) -> None:
        document = self.read_json(GRAPH)
        document["edges"].append(["study-design", "ghost"])
        self.write_json(GRAPH, document)
        check = self.currency(self.run_verify())
        self.assertEqual((check.verdict, check.reason), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN))
        self.assertTrue(check.diagnostics[0].startswith("MALFORMED_DOCUMENT"))
        self.remove(GRAPH)
        check = self.currency(self.run_verify())
        self.assertEqual((check.execution_state, check.verdict), (ExecutionState.SKIPPED, Status.ABSTAIN))
        self.assertEqual(check.reason, Reason.INSUFFICIENT_EVIDENCE)

    def test_no_declared_graph_is_not_applicable_never_pass(self) -> None:
        self.edit_manifest(lambda document: document.pop("dependencies"))
        run = self.run_verify()
        check = self.currency(run)
        self.assertEqual((check.execution_state, check.verdict), (ExecutionState.NOT_APPLICABLE, Status.ABSTAIN))
        self.assertEqual(check.reason, Reason.OUT_OF_SCOPE)
        self.assertEqual(run.status, Status.ABSTAIN)

    def test_params_or_inputs_make_the_check_an_error(self) -> None:
        def with_extra(**extra: Any) -> Any:
            return lambda document: document["checks"][1].update(extra)

        for change in (with_extra(params={"strict": True}), with_extra(inputs=["measurements"])):
            self.edit_manifest(change)
            check = self.currency(self.run_verify())
            with self.subTest(diagnostic=check.diagnostics[0]):
                self.assertEqual(check.verdict, Status.ERROR)
                self.assertTrue(check.diagnostics[0].startswith("INVALID_PARAMS"))
            shutil.copy(CURRENT / "manifest.json", self.manifest_path)

    def test_the_check_never_writes(self) -> None:
        before = self.snapshot()
        self.append("design/protocol.md")
        edited = self.snapshot()
        self.run_verify()
        self.assertEqual(self.snapshot(), edited)
        self.assertNotEqual(edited, before)
        self.assertFalse((self.project / "graph" / GRAPH_STATE_FILE).exists())

    def test_a_node_file_change_changes_the_evidence_manifest(self) -> None:
        first = self.run_verify().result.evidence_manifest_sha256
        self.append("conclusions/conclusion-2.md")
        self.assertNotEqual(self.run_verify().result.evidence_manifest_sha256, first)


# ---------------------------------------------------------------------------
# Closed skip justifications (extension #24, section 17.7)
# ---------------------------------------------------------------------------


class SkipJustificationTests(GraphProject):
    """Every outcome that examined nothing names why, from the closed vocabulary."""

    def assert_labelled(self, justification: SkipJustification, state: ExecutionState) -> CheckOutcome:
        outcome = run_currency(self.manifest_path)
        self.assertEqual(outcome.execution_state, state)
        self.assertEqual(outcome.rows_examined, 0)
        self.assertEqual(SkipJustification(outcome.evidence[SKIP_JUSTIFICATION_KEY]), justification)
        # The run-level row for the label agrees with the check's own verdict and reason.
        verdict, reason, _ = SKIP_JUSTIFICATION_OUTCOMES[justification]
        self.assertEqual((outcome.verdict, outcome.reason), (verdict, reason))
        return outcome

    def test_no_declared_graph_is_not_declared(self) -> None:
        document = self.read_json("manifest.json")
        document.pop("dependencies")
        self.write_json("manifest.json", document)
        self.assert_labelled(SkipJustification.NOT_DECLARED, ExecutionState.NOT_APPLICABLE)

    def test_a_missing_graph_is_input_unavailable(self) -> None:
        self.remove(GRAPH)
        self.assert_labelled(SkipJustification.INPUT_UNAVAILABLE, ExecutionState.SKIPPED)

    def test_unparseable_or_malformed_evidence_is_evidence_malformed(self) -> None:
        (self.project / GRAPH).write_bytes(b"{not json")
        self.assert_labelled(SkipJustification.EVIDENCE_MALFORMED, ExecutionState.SKIPPED)
        self.write_graph([bare_node("a"), bare_node("b")], [["a", "ghost"]])
        self.assert_labelled(SkipJustification.EVIDENCE_MALFORMED, ExecutionState.SKIPPED)
        shutil.copy(CURRENT / GRAPH, self.project / GRAPH)
        (self.project / "graph" / GRAPH_STATE_FILE).write_bytes(b"{not json")
        self.assert_labelled(SkipJustification.EVIDENCE_MALFORMED, ExecutionState.SKIPPED)
        (self.project / "graph" / GRAPH_STATE_FILE).write_text('{"schema": "x"}', encoding="utf-8")
        self.assert_labelled(SkipJustification.EVIDENCE_MALFORMED, ExecutionState.SKIPPED)

    def test_a_graph_without_nodes_is_an_empty_population(self) -> None:
        self.write_graph([], [])
        outcome = self.assert_labelled(SkipJustification.EMPTY_POPULATION, ExecutionState.NOT_APPLICABLE)
        self.assertEqual(outcome.reason, Reason.INSUFFICIENT_EVIDENCE)

    def test_an_error_carries_no_label_and_a_judged_graph_needs_none(self) -> None:
        outcome = run_currency(CYCLE / "manifest.json")
        self.assertEqual(outcome.verdict, Status.ERROR)
        self.assertNotIn(SKIP_JUSTIFICATION_KEY, outcome.evidence)
        judged = run_currency(self.manifest_path)
        self.assertEqual((judged.execution_state, judged.verdict), (ExecutionState.CHECKED, Status.PASS))
        self.assertNotIn(SKIP_JUSTIFICATION_KEY, judged.evidence)


# ---------------------------------------------------------------------------
# The dependency_currency falsifier (section 17.5)
# ---------------------------------------------------------------------------


def blind_assess(graph: DependencyGraph, detection: Any) -> Assessment:
    """A deliberately blind assessment: whatever the graph says, PASS."""
    real = assess(graph, detection)
    return Assessment(Status.PASS, Reason.VERIFIED, (), (), real.publication_block, real.counts)


def falsifier_outcome(case: FalsifierCase, outcome: CheckOutcome) -> FalsifierOutcome:
    """Section 17.5, step 3: REJECTED on the expected rejection, ACCEPTED on PASS, else INCONCLUSIVE."""
    if (outcome.verdict, outcome.reason) == (case.expected_verdict, case.expected_reason):
        return FalsifierOutcome.REJECTED
    return FalsifierOutcome.ACCEPTED if outcome.verdict is Status.PASS else FalsifierOutcome.INCONCLUSIVE


class FalsifierTests(GraphProject):
    """``falsify_dependency_currency`` builds known-bad evidence the check must reject."""

    def passing(self) -> tuple[CheckContext, CheckSpec, CheckResult]:
        """A context in which the currency check passes, with that check's result."""
        ctx, spec = currency_context(self.manifest_path)
        outcome = check_dependency_currency(ctx, spec)
        self.assertEqual(outcome.verdict, Status.PASS, outcome.diagnostics)
        result = CheckResult(
            check_id=spec.check_id,
            kind=spec.kind,
            version=spec.version,
            required=spec.required,
            execution_state=outcome.execution_state,
            verdict=outcome.verdict,
            reason=outcome.reason,
            rows_examined=outcome.rows_examined,
            evidence=outcome.evidence,
        )
        return ctx, spec, result

    def replay(self, case: FalsifierCase) -> CheckOutcome:
        """Serve the case's replacement bytes and run the same check (the engine does this in memory)."""
        for relpath, data in case.documents.items():
            (self.project / relpath).write_bytes(data)
        return run_currency(self.manifest_path)

    def test_a_pass_yields_a_publication_file_case_that_the_check_rejects(self) -> None:
        ctx, spec, result = self.passing()
        reads, files = ctx.read_log(), self.snapshot()
        (case,) = falsify_dependency_currency(ctx, spec, result)
        self.assertEqual(ctx.read_log(), reads, "the generator reads only what the context already served")
        self.assertEqual(self.snapshot(), files, "the generator writes nothing")
        self.assertEqual(falsify_dependency_currency(*self.passing()), (case,), "the generator is deterministic")
        self.assertEqual(case.case_id, "change-publication-file")
        self.assertEqual((case.expected_verdict, case.expected_reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        original = (self.project / "conclusions/conclusion-1.md").read_bytes()
        self.assertEqual(dict(case.documents), {"conclusions/conclusion-1.md": original + FALSIFIER_MARK})
        self.assertEqual(dict(case.inputs), {})
        self.assertIn("'conclusion-1'", case.description)
        replayed = self.replay(case)
        self.assertEqual(falsifier_outcome(case, replayed), FalsifierOutcome.REJECTED)
        self.assertIn(FailureMode.STALE_DEPENDENCY, replayed.failure_modes)
        self.assertEqual(replayed.evidence["publication_block"]["stale_publication_nodes"], ["conclusion-1"])

    def test_the_engine_witnesses_a_currency_pass_with_this_case(self) -> None:
        check = self.currency(self.run_verify())
        self.assertEqual(check.verdict, Status.PASS)
        self.assertEqual(check.evidence["falsification"], "WITNESSED")
        (falsifier,) = check.evidence["falsifiers"]
        self.assertEqual((falsifier["case_id"], falsifier["outcome"]), ("change-publication-file", "REJECTED"))
        self.assertEqual(falsifier["actual"]["verdict"], "FAIL")

    def test_the_case_tells_a_working_check_from_a_blind_one(self) -> None:
        (case,) = falsify_dependency_currency(*self.passing())
        working = self.replay(case)
        with mock.patch("science_gate.dependencies.assess", blind_assess):
            blind = run_currency(self.manifest_path)
        self.assertEqual(falsifier_outcome(case, working), FalsifierOutcome.REJECTED)
        self.assertEqual(falsifier_outcome(case, blind), FalsifierOutcome.ACCEPTED)

    def test_publication_nodes_without_files_fall_back_to_an_upstream_file(self) -> None:
        design = self.file_node("design", "DESIGN", "files/design.txt")
        self.write_graph([design, bare_node("claim", "CONCLUSION")], [["design", "claim"]])
        (case,) = falsify_dependency_currency(*self.passing())
        self.assertEqual(case.case_id, "change-upstream-file")
        self.assertEqual(list(case.documents), ["files/design.txt"])
        self.assertEqual(falsifier_outcome(case, self.replay(case)), FalsifierOutcome.REJECTED)

    def test_no_case_when_no_file_backed_node_reaches_a_publication_node(self) -> None:
        design = self.file_node("design", "DESIGN", "files/design.txt")
        self.write_graph([design, bare_node("claim", "CONCLUSION")], [])
        ctx, spec = currency_context(self.manifest_path)
        self.assertEqual(falsify_dependency_currency(ctx, spec, None), ())  # type: ignore[arg-type]
        document = self.read_json("manifest.json")
        document.pop("dependencies")
        self.write_json("manifest.json", document)
        ctx, spec = currency_context(self.manifest_path)
        self.assertEqual(falsify_dependency_currency(ctx, spec, None), ())  # type: ignore[arg-type]

    def test_the_saved_state_decides_which_digests_are_current(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "conclusion-1":
                node["recorded_sha256"] = None
        self.write_json(GRAPH, document)
        graph = self.load()
        graph.revalidate("conclusion-1")  # records the first digest, in graph-state.json only
        graph.save_state()
        (case,) = falsify_dependency_currency(*self.passing())
        # Without the saved state conclusion-1 would have no digest to change, and conclusion-2 would be chosen.
        self.assertEqual(list(case.documents), ["conclusions/conclusion-1.md"])
        self.assertEqual(falsifier_outcome(case, self.replay(case)), FalsifierOutcome.REJECTED)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


class CommandLineTests(GraphProject):
    def test_impact_prints_headline_then_paths_then_the_markdown_report(self) -> None:
        code, lines = self.run_cli("impact", "study-design", "--manifest", str(self.manifest_path))
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith("FAIL (SOURCE_MISMATCH) impact study-design: 5 descendant(s)"), lines[0])
        self.assertTrue(lines[0].endswith("publication BLOCKED"), lines[0])
        written = [Path(lines[1]), Path(lines[2])]
        self.assertEqual([path.name for path in written], [GRAPH_STATE_FILE, IMPACT_REPORT_FILE])
        self.assertTrue(all(path.is_file() and path.parent == (self.project / "graph").resolve() for path in written))
        self.assertEqual(lines[3], "")
        headings = [line for line in lines[4:] if line.startswith("#")]
        self.assertEqual(
            headings,
            [
                "# Dependency impact report: `study-design`",
                "## STATUS",
                "## WHAT WAS COMPARED",
                "## WHAT CHANGED",
                "## DESCENDANTS MARKED STALE_PENDING_REVALIDATION",
                "## PUBLICATION BLOCK",
                "## TRANSITIONS RECORDED",
                "## NODE STATES",
                "## WHAT THIS DOES NOT PROVE",
            ],
        )
        report = self.read_json(f"graph/{IMPACT_REPORT_FILE}")
        self.assertEqual(report["schema"], IMPACT_REPORT_SCHEMA)
        self.assertEqual((report["status"], report["artifact_id"]), ("FAIL", "study-design"))
        self.assertEqual([item["id"] for item in report["impact"]["descendants"]], DESIGN_DESCENDANTS)
        self.assertIs(report["publication_block"]["blocked"], True)
        state = self.read_json(f"graph/{GRAPH_STATE_FILE}")
        self.assertEqual(state["nodes"]["conclusion-1"]["validity"], STALE.value)
        self.assertNotIn("INVALIDATED", "\n".join(lines))

    def test_revalidation_distinguishes_unchanged_and_changed_results(self) -> None:
        manifest = str(self.manifest_path)
        self.run_cli("impact", "study-design", "--manifest", manifest)
        code, lines = self.run_cli("revalidate", "study-design", "--manifest", manifest)
        self.assertEqual(code, 0, lines[0])
        self.assertIn("REVALIDATED_UNCHANGED; 5 descendant(s) cleared by early cutoff", lines[0])
        self.assertEqual(Path(lines[2]).name, REVALIDATION_REPORT_FILE)

        self.run_cli("impact", "study-design", "--manifest", manifest)
        self.append("design/protocol.md")
        code, lines = self.run_cli("revalidate", "study-design", "--manifest", manifest)
        self.assertEqual(code, 1, lines[0])
        self.assertIn("REVALIDATED_CHANGED; 0 descendant(s) cleared", lines[0])
        report = self.read_json(f"graph/{REVALIDATION_REPORT_FILE}")
        node = report["revalidate"]["node"]
        self.assertNotEqual(node["recorded_sha256_before"], node["recorded_sha256_after"])
        self.assertEqual([item["id"] for item in report["revalidate"]["still_pending"]], DESIGN_DESCENDANTS)
        history = self.read_json(f"graph/{GRAPH_STATE_FILE}")["nodes"]["study-design"]["history"]
        # impact, unchanged revalidation, impact, changed revalidation: every state is kept.
        self.assertEqual(
            [entry["to"] for entry in history],
            [STALE.value, "REVALIDATED_UNCHANGED", STALE.value, "REVALIDATED_CHANGED"],
        )
        self.assertEqual(history[-1]["recorded_sha256_before"], history[0]["recorded_sha256_before"])
        self.assertEqual(history[-1]["recorded_sha256_after"], node["recorded_sha256_after"])

    def test_a_refused_revalidation_leaves_the_node_pending(self) -> None:
        manifest = str(self.manifest_path)
        self.run_cli("impact", "study-design", "--manifest", manifest)
        code, lines = self.run_cli("revalidate", "figure-1", "--manifest", manifest)
        self.assertEqual(code, 1)  # publication is still blocked, so FAIL outranks the refusal
        self.assertIn("REFUSED_UPSTREAM_PENDING", lines[0])
        report = self.read_json(f"graph/{REVALIDATION_REPORT_FILE}")
        self.assertEqual(report["revalidate"]["outcome"], "REFUSED_UPSTREAM_PENDING")
        self.assertEqual(report["findings"][0]["status"], "ABSTAIN")
        self.assertEqual(self.read_json(f"graph/{GRAPH_STATE_FILE}")["nodes"]["figure-1"]["validity"], STALE.value)

    def test_detected_changes_are_persisted_with_the_action(self) -> None:
        self.append("figures/table-2.csv")
        self.run_cli("impact", "study-design", "--manifest", str(self.manifest_path))
        state = self.read_json(f"graph/{GRAPH_STATE_FILE}")["nodes"]
        self.assertEqual(state["table-2"]["validity"], STALE.value)
        self.assertIn("DETECTED_CHANGE", state["table-2"]["history"][0]["reason"])
        self.assertEqual(state["conclusion-2"]["validity"], STALE.value)

    def test_commands_that_cannot_act_exit_3_and_write_nothing(self) -> None:
        manifest = str(self.manifest_path)
        no_graph = self.read_json("manifest.json")
        no_graph.pop("dependencies")
        self.write_json("other-manifest.json", no_graph)
        cases = [
            (("impact", "no-such-artifact", "--manifest", manifest), UNKNOWN_ARTIFACT),
            (("revalidate", "study-design", "--manifest", str(self.project / "other-manifest.json")), "declares no"),
            (("impact", "study-design", "--manifest", str(self.project / "missing.json")), "MANIFEST_NOT_FOUND"),
        ]
        for args, expected in cases:
            before = self.snapshot()
            with self.subTest(args=args[:2]):
                code, lines = self.run_cli(*args)
                self.assertEqual(code, 3)
                self.assertEqual(len(lines), 1)
                self.assertTrue(lines[0].startswith(f"ERROR {args[0]}: "), lines[0])
                self.assertIn(expected, lines[0])
                self.assertEqual(self.snapshot(), before)

    def test_a_graph_that_cannot_be_used_exits_3(self) -> None:
        self.remove(GRAPH)
        code, lines = self.run_cli("impact", "study-design", "--manifest", str(self.manifest_path))
        self.assertEqual((code, len(lines)), (3, 1))
        self.assertIn(GRAPH_UNAVAILABLE, lines[0])
        code, lines = self.run_cli("impact", "cycle-design", "--manifest", str(CYCLE / "manifest.json"))
        self.assertEqual(code, 3)
        self.assertIn("GRAPH_CYCLE", lines[0])
        self.assertFalse((CYCLE / "graph" / GRAPH_STATE_FILE).exists())

    def test_a_damaged_state_is_left_untouched(self) -> None:
        damaged = b'{"schema": "science-gate-graph-state/v1", "nodes": '
        (self.project / "graph" / GRAPH_STATE_FILE).write_bytes(damaged)
        before = self.snapshot()
        code, lines = self.run_cli("revalidate", "study-design", "--manifest", str(self.manifest_path))
        self.assertEqual(code, 3)
        self.assertIn(MALFORMED_STATE, lines[0])
        self.assertEqual(self.snapshot(), before)

    def test_secrets_never_reach_reports_or_output(self) -> None:
        os.environ["SYNTHETIC_API_TOKEN"] = PLANTED_SECRET
        entry = {"at": FIXED_TIME, "from": "CURRENT", "to": "REVALIDATED_UNCHANGED",
                 "reason": f"reviewed with {PLANTED_SECRET}"}
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "conclusion-1":
                node.update(validity="REVALIDATED_UNCHANGED", history=[entry])
        self.write_json(GRAPH, document)
        code, lines = self.run_cli("impact", "site-means", "--manifest", str(self.manifest_path))
        self.assertEqual(code, 1)
        self.assertNotIn(PLANTED_SECRET, "\n".join(lines))
        report = (self.project / "graph" / IMPACT_REPORT_FILE).read_text(encoding="utf-8")
        self.assertIn("reviewed with [REDACTED]", report)  # the declared history is shown, redacted
        for name in (GRAPH_STATE_FILE, IMPACT_REPORT_FILE):
            self.assertNotIn(PLANTED_SECRET, (self.project / "graph" / name).read_text(encoding="utf-8"))

    def test_output_is_identical_under_different_hash_seeds(self) -> None:
        outputs = []
        for seed in ("0", "4242"):
            project = self.tmp / f"seed-{seed}"
            shutil.copytree(CURRENT, project)
            environment = {key: value for key, value in os.environ.items() if key != HMAC_KEY_FILE_ENV}
            environment.update(
                {
                    "PYTHONPATH": str(SRC_DIR),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": seed,
                    "SCIENCE_GATE_FIXED_TIME": FIXED_TIME,
                }
            )
            completed = subprocess.run(
                [sys.executable, "-m", "science_gate.cli", "impact", "source-snapshot", "--manifest",
                 str(project / "manifest.json")],
                cwd=self.tmp,
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
            )
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            lines = completed.stdout.splitlines()
            files = tuple((project / "graph" / name).read_bytes() for name in (GRAPH_STATE_FILE, IMPACT_REPORT_FILE))
            outputs.append((lines[0], lines[3:], files))
        self.assertEqual(outputs[0], outputs[1])


# ---------------------------------------------------------------------------
# The documentation schema
# ---------------------------------------------------------------------------


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = strict_loads((REPO_ROOT / "schemas" / "graph.schema.json").read_bytes())
        cls.defs = cls.schema["$defs"]

    def test_top_level_matches_the_parser(self) -> None:
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema["$id"], GRAPH_SCHEMA)
        self.assertEqual(self.schema["properties"]["schema"]["const"], GRAPH_SCHEMA)
        self.assertEqual(set(self.schema["required"]), REQUIRED_GRAPH_KEYS)

    def test_enumerations_and_required_keys_match_the_parser(self) -> None:
        self.assertEqual(set(self.defs["node"]["required"]), REQUIRED_NODE_KEYS)
        self.assertEqual(self.defs["node_kind"]["enum"], [kind.value for kind in NodeKind])
        self.assertEqual(self.defs["validity"]["enum"], [validity.value for validity in Validity])
        self.assertEqual(set(self.defs["transition"]["required"]), REQUIRED_TRANSITION_KEYS)
        # A state saved before section 17 lacks witness_id and cause_category and must stay readable.
        self.assertEqual(set(self.defs["state_transition"]["required"]), REQUIRED_STATE_TRANSITION_KEYS)

    def test_nodes_and_transitions_match_the_parser(self) -> None:
        # Red until integration applies this builder's schemas/graph.schema.json request (section 17.18).
        self.assertEqual(set(self.defs["node"]["properties"]), NODE_KEYS)
        self.assertEqual(set(self.defs["transition"]["properties"]), TRANSITION_KEYS)
        backed = self.defs["node"]["properties"]["backed_by_checks"]
        self.assertEqual(backed["items"], {"$ref": "#/$defs/backing_check"})
        backing = self.defs["backing_check"]
        self.assertEqual((set(backing["properties"]), set(backing["required"])), (BACKING_KEYS, BACKING_KEYS))
        self.assertEqual(self.defs["stale_cause"]["enum"], [cause.value for cause in StaleCause])
        cause = self.defs["graph_state"]["properties"]["nodes"]["additionalProperties"]["properties"]["stale_because"]
        patterns = [item["pattern"] for item in cause["items"]["anyOf"] if "pattern" in item]
        self.assertEqual(len(patterns), 1)
        self.assertTrue(re.search(patterns[0], "verifier:numeric"))
        self.assertFalse(re.search(patterns[0], "verifier:"))

    def test_witness_and_what_if_documents_are_described(self) -> None:
        # Red until integration applies this builder's schemas/graph.schema.json request (section 17.18).
        witness = self.defs["recompute_witness"]
        self.assertEqual(witness["$id"], WITNESS_SCHEMA)
        self.assertEqual((set(witness["properties"]), set(witness["required"])), (WITNESS_KEYS, WITNESS_KEYS))
        self.assertEqual(self.defs["what_if_report"]["$id"], WHAT_IF_SCHEMA)

    def test_graph_state_matches_what_is_written(self) -> None:
        state = self.defs["graph_state"]
        self.assertEqual(state["$id"], GRAPH_STATE_SCHEMA)
        self.assertEqual(set(state["properties"]), STATE_KEYS)
        self.assertEqual(set(state["properties"]["nodes"]["additionalProperties"]["properties"]), STATE_NODE_KEYS)
        self.assertEqual(self.defs["impact_report"]["$id"], IMPACT_REPORT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
