"""Dependency graph, impact walks and revalidation (ARCHITECTURE.md section 8).

A conclusion, figure or table is only as current as the artifacts it was
derived from. When an upstream artifact changes, everything downstream has to
be re-established before it is published again. This module keeps that
bookkeeping explicit and auditable:

* ``graph.json`` declares the artifacts (nodes) and what derives from what
  (edges ``[parent, child]``). A cycle leaves no order in which revalidation
  could happen, so it is an ERROR.
* :meth:`DependencyGraph.detect_changes` compares each node file's SHA-256
  with its recorded digest. A changed node becomes STALE_PENDING_REVALIDATION
  and an unreadable one UNRESOLVED; either starts an impact walk.
* :meth:`DependencyGraph.impact` walks descendants breadth-first, one level
  at a time in sorted order, and marks them STALE_PENDING_REVALIDATION. It
  never calls anything false or INVALIDATED: a stale conclusion may still
  hold. It just has not been re-established since its inputs moved.
* :meth:`DependencyGraph.revalidate` re-hashes one node. An unchanged digest
  gives REVALIDATED_UNCHANGED and clears the descendants that were pending
  only because of that node (early cutoff, cascading). A changed digest gives
  REVALIDATED_CHANGED, records the new digest and keeps its descendants stale,
  or makes them stale. Recording a new digest therefore can never hide a
  change from the artifacts derived from it.
* Every transition is appended to the node's history as
  ``{at, from, to, reason}``, together with the recorded digest before and
  after, so both the original and the corrected state are preserved.
* ``graph-state.json`` next to the graph persists the result. It is written
  only through :func:`~science_gate._safeio.safe_write`. ``graph.json`` itself
  is never rewritten: it stays the human-authored declaration.

The ``dependency_currency`` check runs the same detection in memory and never
writes. It FAILs with STALE_DEPENDENCY while any CONCLUSION or FIGURE_OR_TABLE
is STALE_PENDING_REVALIDATION.

Conventions:

* Node paths are relative to the **manifest directory**, like every other
  path a manifest declares. They are not relative to the graph file.
* Staleness has causes. ``stale_because`` lists, for each pending node, the
  direct parents that are pending or changed, plus the node itself when its
  own file changed or its stale state was declared. Early cutoff removes one
  cause, and clears a node only when no cause is left.
* A node cannot be revalidated while any of its ancestors is still pending.
  Otherwise a descendant could be cleared before the upstream result it
  depends on is known, and that later result could never reach it.
* Only :meth:`~DependencyGraph.revalidate` ever clears a pending state.
  Detection and impact walks only mark. SUPERSEDED and INVALIDATED are
  declared by people. Detection and impact walks keep them unchanged, and
  this tool never sets them.
"""

from __future__ import annotations

import argparse
import heapq
import posixpath
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence, TextIO

from ._canonical import StrictJSONError, pretty_json_bytes, sha256_bytes, sha256_canonical, strict_loads
from ._clock import ClockError, now, parse_utc
from ._redact import redact, redact_text
from ._safeio import SafeIOError, UnsafePathError, comparison_key, normalize_relpath, safe_read, safe_write
from .manifests import DEFAULT_LIMITS, IDENTIFIER_PATTERN, CheckSpec, ManifestError, load_manifest
from .models import EXIT_CODE, ExecutionState, FailureMode, InputState, Reason, Status, Validity
from .verifier import MAX_LISTED, CheckContext, CheckOutcome, CheckParamError, Document

__all__ = [
    "GRAPH_SCHEMA",
    "GRAPH_STATE_SCHEMA",
    "IMPACT_REPORT_SCHEMA",
    "GRAPH_STATE_FILE",
    "IMPACT_REPORT_FILE",
    "REVALIDATION_REPORT_FILE",
    "STATE_ROLE",
    "NODE_ROLE",
    "GRAPH_KEYS",
    "REQUIRED_GRAPH_KEYS",
    "NODE_KEYS",
    "REQUIRED_NODE_KEYS",
    "TRANSITION_KEYS",
    "REQUIRED_TRANSITION_KEYS",
    "STATE_KEYS",
    "STATE_GRAPH_KEYS",
    "STATE_NODE_KEYS",
    "PUBLICATION_KINDS",
    "PENDING_STATES",
    "GOOD_STANDING_STATES",
    "HUMAN_DECLARED_STATES",
    "CURRENCY_RULE",
    "DOES_NOT_PROVE",
    "MALFORMED_GRAPH",
    "UNSAFE_PATH",
    "GRAPH_CYCLE",
    "MALFORMED_STATE",
    "UNKNOWN_ARTIFACT",
    "GRAPH_UNAVAILABLE",
    "STATE_UNAVAILABLE",
    "NodeKind",
    "DigestComparison",
    "RevalidationOutcome",
    "GraphError",
    "GraphCycleError",
    "Observation",
    "Observer",
    "file_observer",
    "Transition",
    "Node",
    "StateInfo",
    "NodeObservation",
    "Detection",
    "DescendantImpact",
    "Impact",
    "ClearedNode",
    "Revalidation",
    "CurrencyFinding",
    "Assessment",
    "DependencyGraph",
    "parse_graph",
    "load_graph",
    "assess",
    "build_report",
    "render_markdown",
    "headline",
    "check_dependency_currency",
    "preload_graph_files",
    "cli_impact",
    "cli_revalidate",
]

GRAPH_SCHEMA = "science-gate-graph/v1"
GRAPH_STATE_SCHEMA = "science-gate-graph-state/v1"
IMPACT_REPORT_SCHEMA = "science-gate-impact/v1"

#: Files this module writes, all in the graph's directory.
GRAPH_STATE_FILE = "graph-state.json"
IMPACT_REPORT_FILE = "impact-report.json"
REVALIDATION_REPORT_FILE = "revalidation-report.json"
_REPORT_FILES = {"impact": IMPACT_REPORT_FILE, "revalidate": REVALIDATION_REPORT_FILE}

#: Roles under which the check reads files through ``CheckContext``, so they
#: appear, with their digests, in the run's evidence manifest.
STATE_ROLE = "dependencies.state"
NODE_ROLE = "dependencies.node"

#: ``schema`` is optional in graph.json (section 8 names only nodes and edges);
#: when present it must equal :data:`GRAPH_SCHEMA`.
GRAPH_KEYS = frozenset({"schema", "nodes", "edges"})
REQUIRED_GRAPH_KEYS = frozenset({"nodes", "edges"})
NODE_KEYS = frozenset({"id", "kind", "path", "recorded_sha256", "validity", "history"})
REQUIRED_NODE_KEYS = frozenset({"id", "kind", "path", "recorded_sha256", "validity"})
#: The contract's ``{at, from, to, reason}`` plus what makes a transition
#: auditable: which node triggered it and the digests involved.
TRANSITION_KEYS = frozenset(
    {"at", "from", "to", "reason", "trigger", "recorded_sha256_before", "recorded_sha256_after", "observed_sha256"}
)
REQUIRED_TRANSITION_KEYS = frozenset({"at", "from", "to", "reason"})
STATE_KEYS = frozenset({"schema", "graph", "updated_at", "nodes"})
STATE_GRAPH_KEYS = frozenset({"path", "sha256"})
STATE_NODE_KEYS = frozenset({"validity", "recorded_sha256", "stale_because", "history"})

MALFORMED_GRAPH = "MALFORMED_GRAPH"
UNSAFE_PATH = "UNSAFE_PATH"
GRAPH_CYCLE = "GRAPH_CYCLE"
MALFORMED_STATE = "MALFORMED_STATE"
UNKNOWN_ARTIFACT = "UNKNOWN_ARTIFACT"
GRAPH_UNAVAILABLE = "GRAPH_UNAVAILABLE"
STATE_UNAVAILABLE = "STATE_UNAVAILABLE"

#: A problem with the graph declaration itself, not with the evidence it
#: points at: the check reports ERROR for these, as it does for an unsafe manifest.
_DECLARATION_ERRORS = frozenset({GRAPH_CYCLE, UNSAFE_PATH})

PENDING_STATES = frozenset({Validity.STALE_PENDING_REVALIDATION, Validity.UNRESOLVED})
GOOD_STANDING_STATES = frozenset({Validity.CURRENT, Validity.REVALIDATED_UNCHANGED, Validity.REVALIDATED_CHANGED})
HUMAN_DECLARED_STATES = frozenset({Validity.SUPERSEDED, Validity.INVALIDATED})

CURRENCY_RULE = (
    "publication is blocked while any CONCLUSION or FIGURE_OR_TABLE node is STALE_PENDING_REVALIDATION; "
    "a node file whose digest differs from its recorded digest is STALE_PENDING_REVALIDATION, and so is "
    "every descendant of a pending node"
)
_SCOPE = (
    "currency of recorded artifact digests only: nothing is re-run, and no conclusion is judged true or false"
)

DOES_NOT_PROVE = (
    "A matching digest shows only that a file on disk is byte-identical to the digest recorded for it. It does "
    "not show that the artifact was regenerated, that the analysis behind it is correct, or that any conclusion "
    "is scientifically valid.",
    "STALE_PENDING_REVALIDATION means an upstream artifact changed, or was declared changed, after this node was "
    "last established. It is not a finding that the node is wrong, and this tool never marks a node false.",
    "Early cutoff clears a descendant because the upstream digest it depends on is unchanged. The descendant's "
    "own file is not re-read when it is cleared.",
    "Only declared edges are tracked. A dependency that the graph does not declare cannot make anything stale.",
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_STALE = Validity.STALE_PENDING_REVALIDATION
_RANK = {Status.PASS: 0, Status.ABSTAIN: 1, Status.FAIL: 2, Status.ERROR: 3}


class NodeKind(str, Enum):
    """What an artifact in the dependency graph is (section 8)."""

    SOURCE_SNAPSHOT = "SOURCE_SNAPSHOT"
    DESIGN = "DESIGN"
    ADMITTED_EVIDENCE = "ADMITTED_EVIDENCE"
    ANALYSIS_RUN = "ANALYSIS_RUN"
    RANKING_OR_MEASUREMENT = "RANKING_OR_MEASUREMENT"
    FIGURE_OR_TABLE = "FIGURE_OR_TABLE"
    CONCLUSION = "CONCLUSION"

    def __str__(self) -> str:
        return str.__str__(self)


#: The kinds that get published. Their staleness blocks publication.
PUBLICATION_KINDS = frozenset({NodeKind.CONCLUSION, NodeKind.FIGURE_OR_TABLE})


class DigestComparison(str, Enum):
    """How a node's file compared with its recorded digest during detection."""

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    NO_BASELINE = "NO_BASELINE"
    UNAVAILABLE = "UNAVAILABLE"
    NO_FILE = "NO_FILE"

    def __str__(self) -> str:
        return str.__str__(self)


class RevalidationOutcome(str, Enum):
    """What one revalidation did. Only the first two change the node's standing."""

    REVALIDATED_UNCHANGED = "REVALIDATED_UNCHANGED"
    REVALIDATED_CHANGED = "REVALIDATED_CHANGED"
    REFUSED_UPSTREAM_PENDING = "REFUSED_UPSTREAM_PENDING"
    NO_FILE_TO_HASH = "NO_FILE_TO_HASH"
    FILE_UNAVAILABLE = "FILE_UNAVAILABLE"

    def __str__(self) -> str:
        return str.__str__(self)


class GraphError(ValueError):
    """A graph or graph state that cannot be used, with a stable ``code``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.detail = message

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": redact_text(self.detail)}


class GraphCycleError(GraphError):
    """The graph has a cycle. ``cycle`` lists it in edge order, first node repeated last."""

    def __init__(self, cycle: Sequence[str]) -> None:
        self.cycle = tuple(cycle)
        super().__init__(GRAPH_CYCLE, "the graph has a cycle, so no revalidation order exists: " + " -> ".join(cycle))

    def to_dict(self) -> dict[str, Any]:
        return {**super().to_dict(), "cycle": list(self.cycle)}


# ---------------------------------------------------------------------------
# Reading node files
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """What reading one node file produced.

    ``state`` reuses :class:`~science_gate.models.InputState`: PARSED or EMPTY
    when bytes were read (``sha256`` is then set), otherwise MISSING, REFUSED
    or OPEN_FAILED, with a diagnostic.
    """

    state: InputState
    sha256: str | None = None
    diagnostic: str | None = None


#: Reads the file at a manifest-relative path. The check reads through its
#: ``CheckContext``, so every file lands in the evidence manifest. The CLI
#: reads through :func:`file_observer`. Both use the same safe read.
Observer = Callable[[str], Observation]


def file_observer(root: str | Path, max_bytes: int) -> Observer:
    """An :data:`Observer` over files under ``root``, with the same rules as a check's reads.

    Paths are confined to ``root`` (``..`` and symlink escapes are refused) and
    to ``max_bytes``. A failure is returned as an Observation, never raised.
    """

    def observe(relpath: str) -> Observation:
        try:
            data = safe_read(root, relpath, max_bytes=max_bytes)
        except FileNotFoundError:
            return Observation(InputState.MISSING, diagnostic=f"MISSING: no file at {relpath}")
        except SafeIOError as exc:
            return Observation(InputState.REFUSED, diagnostic=f"REFUSED: {exc}")
        except OSError as exc:  # str(exc) would carry a machine-specific absolute path
            return Observation(InputState.OPEN_FAILED, diagnostic=f"OPEN_FAILED: {exc.strerror or type(exc).__name__}")
        state = InputState.PARSED if data else InputState.EMPTY
        return Observation(state, sha256_bytes(data), None if data else f"EMPTY: {relpath} has no content")

    return observe


def _context_observer(ctx: CheckContext) -> Observer:
    """An :data:`Observer` that reads through the check context (and so into the evidence manifest)."""

    def observe(relpath: str) -> Observation:
        document = ctx.read_document(relpath, role=NODE_ROLE, parse="bytes")
        return Observation(document.state, document.sha256, document.diagnostic)

    return observe


# ---------------------------------------------------------------------------
# Declarations: transitions and nodes
# ---------------------------------------------------------------------------


def _object(value: Any, where: str, allowed: frozenset[str], required: frozenset[str], code: str) -> Mapping[str, Any]:
    """A JSON object with only ``allowed`` keys and every ``required`` one.

    Unknown keys are refused rather than ignored: a typo such as
    ``recorded_sha265`` would otherwise silently drop the digest that makes a
    change detectable.
    """
    if not isinstance(value, Mapping):
        raise GraphError(code, f"{where} must be a JSON object")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise GraphError(code, f"{where} has unknown key(s) {unknown}")
    missing = sorted(required - set(value))
    if missing:
        raise GraphError(code, f"{where} is missing {missing}")
    return value


def _digest(value: Any, where: str, code: str) -> str | None:
    """None, or a lowercase hex SHA-256.

    A malformed recorded digest would compare unequal to every real one and
    pose as a content change, when the record itself is what is broken.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise GraphError(code, f"{where} must be null or 64 lowercase hex characters")
    return value


def _validity(value: Any, where: str, code: str) -> Validity:
    try:
        return Validity(value)
    except ValueError:
        raise GraphError(code, f"{where}: {value!r} is not one of {[item.value for item in Validity]}") from None


def _identifier(value: Any, where: str, code: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise GraphError(code, f"{where} must be an identifier matching {IDENTIFIER_PATTERN.pattern}")
    return value


def _timestamp(value: Any, where: str, code: str) -> str:
    try:
        parse_utc(value)
    except ClockError as exc:
        raise GraphError(code, f"{where}: {exc}") from None
    return value


@dataclass(frozen=True)
class Transition:
    """One change of a node's validity, as appended to its history.

    ``recorded_sha256_before`` and ``recorded_sha256_after`` keep the original
    and the corrected digest side by side. ``observed_sha256`` is the digest
    read from disk when the transition happened, if one was read.
    """

    at: str
    from_state: Validity
    to_state: Validity
    reason: str
    trigger: str | None = None
    recorded_sha256_before: str | None = None
    recorded_sha256_after: str | None = None
    observed_sha256: str | None = None

    def __post_init__(self) -> None:
        # Reasons can quote diagnostics or declared text, and they are written
        # to graph-state.json and reports, so they are redacted here, once.
        object.__setattr__(self, "reason", redact_text(self.reason))

    @classmethod
    def from_dict(cls, value: Any, where: str, *, code: str, complete: bool) -> Transition:
        """Parse a history entry. ``complete`` requires every key (as this tool writes them)."""
        item = _object(value, where, TRANSITION_KEYS, TRANSITION_KEYS if complete else REQUIRED_TRANSITION_KEYS, code)
        reason = item["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise GraphError(code, f"{where}.reason must be a non-empty string")
        trigger = item.get("trigger")
        return cls(
            at=_timestamp(item["at"], f"{where}.at", code),
            from_state=_validity(item["from"], f"{where}.from", code),
            to_state=_validity(item["to"], f"{where}.to", code),
            reason=reason,
            trigger=None if trigger is None else _identifier(trigger, f"{where}.trigger", code),
            recorded_sha256_before=_digest(item.get("recorded_sha256_before"), f"{where}.recorded_sha256_before", code),
            recorded_sha256_after=_digest(item.get("recorded_sha256_after"), f"{where}.recorded_sha256_after", code),
            observed_sha256=_digest(item.get("observed_sha256"), f"{where}.observed_sha256", code),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "from": self.from_state.value,
            "to": self.to_state.value,
            "reason": self.reason,
            "trigger": self.trigger,
            "recorded_sha256_before": self.recorded_sha256_before,
            "recorded_sha256_after": self.recorded_sha256_after,
            "observed_sha256": self.observed_sha256,
        }


@dataclass(frozen=True)
class Node:
    """A declared artifact, exactly as ``graph.json`` states it.

    Validated on construction, so a Node can never carry an unsafe path, a
    digest with nothing to hash, or a history that does not end in its
    declared state.
    """

    node_id: str
    kind: NodeKind
    path: str | None
    recorded_sha256: str | None
    validity: Validity
    history: tuple[Transition, ...] = ()

    def __post_init__(self) -> None:
        where = f"node {self.node_id!r}"
        _identifier(self.node_id, f"node id {self.node_id!r}", MALFORMED_GRAPH)
        try:
            object.__setattr__(self, "kind", NodeKind(self.kind))
        except ValueError:
            kinds = [item.value for item in NodeKind]
            raise GraphError(MALFORMED_GRAPH, f"{where}: kind {self.kind!r} is not one of {kinds}") from None
        object.__setattr__(self, "validity", _validity(self.validity, f"{where}.validity", MALFORMED_GRAPH))
        if self.path is not None:
            if not isinstance(self.path, str):
                raise GraphError(MALFORMED_GRAPH, f"{where}.path must be a string or null")
            try:
                object.__setattr__(self, "path", normalize_relpath(self.path))
            except UnsafePathError as exc:
                raise GraphError(UNSAFE_PATH, f"{where}.path: {exc}") from None
        _digest(self.recorded_sha256, f"{where}.recorded_sha256", MALFORMED_GRAPH)
        if self.path is None and self.recorded_sha256 is not None:
            raise GraphError(MALFORMED_GRAPH, f"{where} records a digest but has no file to hash")
        object.__setattr__(self, "history", tuple(self.history))
        if self.history and self.history[-1].to_state is not self.validity:
            raise GraphError(
                MALFORMED_GRAPH,
                f"{where}: history ends in {self.history[-1].to_state.value} but validity is {self.validity.value}",
            )

    @property
    def publication(self) -> bool:
        """True for the kinds whose staleness blocks publication."""
        return self.kind in PUBLICATION_KINDS


@dataclass
class _NodeState:
    """The mutable, current state of one node: what graph-state.json persists.

    ``history`` holds only the transitions this tool made. The declared
    history stays on :class:`Node`, so graph.json is never rewritten.
    """

    validity: Validity
    recorded_sha256: str | None
    stale_because: set[str] = field(default_factory=set)
    history: list[Transition] = field(default_factory=list)

    @classmethod
    def declared(cls, node: Node) -> _NodeState:
        # A node declared pending is pending on its own account: only
        # revalidating it can clear it, never an upstream early cutoff.
        causes = {node.node_id} if node.validity in PENDING_STATES else set()
        return cls(node.validity, node.recorded_sha256, causes)


@dataclass(frozen=True)
class StateInfo:
    """Where the persisted state came from, and how it relates to graph.json."""

    path: str
    present: bool = False
    sha256: str | None = None
    graph_changed_since_state: bool | None = None
    orphaned_nodes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "present": self.present,
            "sha256": self.sha256,
            "graph_changed_since_state": self.graph_changed_since_state,
            "orphaned_nodes": list(self.orphaned_nodes),
        }


# ---------------------------------------------------------------------------
# Operation results
# ---------------------------------------------------------------------------


def _journal_dicts(entries: Iterable[tuple[str, Transition]]) -> list[dict[str, Any]]:
    return [{"node": node_id, **entry.to_dict()} for node_id, entry in entries]


@dataclass(frozen=True)
class NodeObservation:
    """One node's digest comparison during detection."""

    node_id: str
    path: str | None
    recorded_sha256: str | None
    observed_sha256: str | None
    outcome: DigestComparison
    diagnostic: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "path": self.path,
            "recorded_sha256": self.recorded_sha256,
            "observed_sha256": self.observed_sha256,
            "outcome": self.outcome.value,
            "diagnostic": None if self.diagnostic is None else redact_text(self.diagnostic),
        }


@dataclass(frozen=True)
class Detection:
    """The result of :meth:`DependencyGraph.detect_changes`."""

    observations: tuple[NodeObservation, ...]
    transitions: tuple[tuple[str, Transition], ...]

    @property
    def files_hashed(self) -> int:
        """Node files whose bytes were actually read and hashed."""
        return sum(1 for item in self.observations if item.observed_sha256 is not None)

    def ids(self, outcome: DigestComparison) -> tuple[str, ...]:
        return tuple(item.node_id for item in self.observations if item.outcome is outcome)

    def outcome_counts(self) -> dict[str, int]:
        return {outcome.value: len(self.ids(outcome)) for outcome in DigestComparison}

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [item.to_dict() for item in self.observations],
            "outcomes": self.outcome_counts(),
            "files_hashed": self.files_hashed,
            "transitions": _journal_dicts(self.transitions),
        }


@dataclass(frozen=True)
class DescendantImpact:
    """One descendant reached by an impact walk, and how the walk left it."""

    node_id: str
    kind: NodeKind
    depth: int
    path_from_changed_node: tuple[str, ...]
    prior_state: Validity
    state: Validity

    @property
    def publication_node(self) -> bool:
        return self.kind in PUBLICATION_KINDS

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind.value,
            "depth": self.depth,
            "path_from_changed_node": list(self.path_from_changed_node),
            "prior_state": self.prior_state.value,
            "state": self.state.value,
            "publication_node": self.publication_node,
        }


@dataclass(frozen=True)
class Impact:
    """The result of :meth:`DependencyGraph.impact`."""

    origin: str
    kind: NodeKind
    prior_state: Validity
    state: Validity
    descendants: tuple[DescendantImpact, ...]
    transitions: tuple[tuple[str, Transition], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": {
                "id": self.origin,
                "kind": self.kind.value,
                "prior_state": self.prior_state.value,
                "state": self.state.value,
            },
            "descendants": [item.to_dict() for item in self.descendants],
            "transitions": _journal_dicts(self.transitions),
        }


@dataclass(frozen=True)
class ClearedNode:
    """A descendant cleared by early cutoff, restored to its state before it went stale."""

    node_id: str
    kind: NodeKind
    state: Validity
    cleared_because: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind.value,
            "prior_state": _STALE.value,
            "state": self.state.value,
            "cleared_because": self.cleared_because,
        }


@dataclass(frozen=True)
class Revalidation:
    """The result of :meth:`DependencyGraph.revalidate`."""

    node_id: str
    kind: NodeKind
    outcome: RevalidationOutcome
    prior_state: Validity
    state: Validity
    recorded_sha256_before: str | None
    recorded_sha256_after: str | None
    observed_sha256: str | None
    diagnostic: str | None
    pending_ancestors: tuple[str, ...]
    cleared: tuple[ClearedNode, ...]
    still_pending: tuple[DescendantImpact, ...]
    transitions: tuple[tuple[str, Transition], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": {
                "id": self.node_id,
                "kind": self.kind.value,
                "prior_state": self.prior_state.value,
                "state": self.state.value,
                "recorded_sha256_before": self.recorded_sha256_before,
                "recorded_sha256_after": self.recorded_sha256_after,
                "observed_sha256": self.observed_sha256,
            },
            "outcome": self.outcome.value,
            "diagnostic": None if self.diagnostic is None else redact_text(self.diagnostic),
            "pending_ancestors": list(self.pending_ancestors),
            "cleared": [item.to_dict() for item in self.cleared],
            "still_pending": [item.to_dict() for item in self.still_pending],
            "transitions": _journal_dicts(self.transitions),
        }


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------

#: Marks "keep the recorded digest as it is" in :meth:`DependencyGraph._transition`.
_KEEP: Any = object()


def _topological_order(
    ids: Sequence[str], parents: Mapping[str, tuple[str, ...]], children: Mapping[str, tuple[str, ...]]
) -> tuple[str, ...]:
    """Kahn's algorithm, always taking the smallest ready id: one deterministic order.

    Raises :class:`GraphCycleError` naming one concrete cycle.
    """
    indegree = {node_id: len(parents[node_id]) for node_id in ids}
    ready = [node_id for node_id in ids if indegree[node_id] == 0]
    heapq.heapify(ready)
    order: list[str] = []
    while ready:
        node_id = heapq.heappop(ready)
        order.append(node_id)
        for child in children[node_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(ready, child)
    if len(order) != len(ids):
        raise GraphCycleError(_find_cycle(set(ids) - set(order), parents))
    return tuple(order)


def _find_cycle(remaining: set[str], parents: Mapping[str, tuple[str, ...]]) -> list[str]:
    """One cycle among the nodes Kahn's algorithm could not order.

    Every such node has a parent that is also left over, so following the
    smallest remaining parent must eventually revisit a node. The loop is
    reported in edge (parent -> child) order, starting at its smallest id.
    """
    node_id = min(remaining)
    trail: list[str] = []
    position: dict[str, int] = {}
    while node_id not in position:
        position[node_id] = len(trail)
        trail.append(node_id)
        node_id = min(parent for parent in parents[node_id] if parent in remaining)
    loop = trail[position[node_id]:]
    loop.reverse()  # the trail follows parents; the edges run the other way
    start = loop.index(min(loop))
    loop = loop[start:] + loop[:start]
    return [*loop, loop[0]]


class DependencyGraph:
    """A validated dependency graph together with its current (mutable) state.

    Build one with :func:`parse_graph` or :func:`load_graph`. Operations
    change the in-memory state and return a result object. Only
    :meth:`save_state` writes anything.
    """

    def __init__(
        self,
        nodes: Iterable[Node],
        edges: Iterable[Sequence[str]],
        *,
        graph_path: str,
        graph_sha256: str,
        root: str | Path | None = None,
        max_bytes: int | None = None,
    ) -> None:
        try:
            self.graph_path = normalize_relpath(graph_path)
        except UnsafePathError as exc:
            raise GraphError(UNSAFE_PATH, f"graph path: {exc}") from None
        if _digest(graph_sha256, "graph_sha256", MALFORMED_GRAPH) is None:
            raise GraphError(MALFORMED_GRAPH, "graph_sha256 is required: the saved state is tied to it")
        self.graph_sha256 = graph_sha256
        self.root = None if root is None else Path(root)
        self.max_bytes = DEFAULT_LIMITS["max_file_bytes"] if max_bytes is None else max_bytes
        self._nodes: dict[str, Node] = {}
        for node in sorted(nodes, key=lambda item: item.node_id):
            if node.node_id in self._nodes:
                raise GraphError(MALFORMED_GRAPH, f"node id {node.node_id!r} is declared twice")
            self._nodes[node.node_id] = node
        self._check_paths()
        self._edges = self._validated_edges(edges)
        parents: dict[str, list[str]] = {node_id: [] for node_id in self._nodes}
        children: dict[str, list[str]] = {node_id: [] for node_id in self._nodes}
        for parent, child in self._edges:  # sorted, so every adjacency list is sorted too
            parents[child].append(parent)
            children[parent].append(child)
        self._parents = {node_id: tuple(items) for node_id, items in parents.items()}
        self._children = {node_id: tuple(items) for node_id, items in children.items()}
        self._order = _topological_order(tuple(self._nodes), self._parents, self._children)
        self._state = {node_id: _NodeState.declared(node) for node_id, node in self._nodes.items()}
        self._journal: list[tuple[str, Transition]] = []
        self.state_info = StateInfo(self.state_path)

    # -- construction helpers ------------------------------------------------

    def _check_paths(self) -> None:
        """Refuse two nodes naming one file, and nodes naming a file this module writes.

        A node pointing at graph-state.json or a report would change on every
        command and so could never be current.
        """
        written = {comparison_key(self.state_path): self.state_path}
        for command in _REPORT_FILES:
            written[comparison_key(self.report_path(command))] = self.report_path(command)
        seen: dict[str, str] = {}
        for node in self._nodes.values():
            if node.path is None:
                continue
            key = comparison_key(node.path)
            if key in written:
                raise GraphError(MALFORMED_GRAPH, f"node {node.node_id!r} names {written[key]}, which this tool writes")
            if key in seen:
                raise GraphError(MALFORMED_GRAPH, f"nodes {seen[key]!r} and {node.node_id!r} name the same file")
            seen[key] = node.node_id

    def _validated_edges(self, edges: Iterable[Sequence[str]]) -> tuple[tuple[str, str], ...]:
        """Every edge as a sorted ``(parent, child)`` tuple; unknown ends and repeats are refused.

        A self-loop is left in: it is a cycle, and the topological sort names it.
        """
        pairs: set[tuple[str, str]] = set()
        for index, edge in enumerate(edges):
            where = f"edges[{index}]"
            if isinstance(edge, (str, bytes)) or not isinstance(edge, Sequence) or len(edge) != 2:
                raise GraphError(MALFORMED_GRAPH, f"{where} must be a [parent, child] pair")
            parent, child = edge
            for end in (parent, child):
                if not isinstance(end, str) or end not in self._nodes:
                    raise GraphError(MALFORMED_GRAPH, f"{where} names {end!r}, which is not a declared node")
            if (parent, child) in pairs:
                raise GraphError(MALFORMED_GRAPH, f"{where} repeats the edge {parent!r} -> {child!r}")
            pairs.add((parent, child))
        return tuple(sorted(pairs))

    # -- read access -----------------------------------------------------------

    @property
    def state_path(self) -> str:
        """``graph-state.json`` in the graph's directory, relative to the manifest directory."""
        return posixpath.join(posixpath.dirname(self.graph_path), GRAPH_STATE_FILE)

    def report_path(self, command: str) -> str:
        """Where the JSON report of ``impact`` or ``revalidate`` is written, next to the state."""
        return posixpath.join(posixpath.dirname(self.graph_path), _REPORT_FILES[command])

    @property
    def nodes(self) -> tuple[Node, ...]:
        """The declared nodes, sorted by id."""
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[tuple[str, str], ...]:
        """Every ``(parent, child)`` edge, sorted."""
        return self._edges

    @property
    def topological_order(self) -> tuple[str, ...]:
        """Parents before children; ties broken by id."""
        return self._order

    def require(self, node_id: str) -> Node:
        """The node with ``node_id``, or :class:`GraphError` UNKNOWN_ARTIFACT."""
        if node_id not in self._nodes:
            known = ", ".join(list(self._nodes)[:MAX_LISTED])
            raise GraphError(UNKNOWN_ARTIFACT, f"the graph has no node {node_id!r} (nodes: {known})")
        return self._nodes[node_id]

    def parents(self, node_id: str) -> tuple[str, ...]:
        """The direct parents of ``node_id``, sorted."""
        return self._parents[self.require(node_id).node_id]

    def validity(self, node_id: str) -> Validity:
        return self._state[self.require(node_id).node_id].validity

    def recorded_sha256(self, node_id: str) -> str | None:
        return self._state[self.require(node_id).node_id].recorded_sha256

    def stale_because(self, node_id: str) -> tuple[str, ...]:
        return tuple(sorted(self._state[self.require(node_id).node_id].stale_because))

    def history(self, node_id: str) -> tuple[Transition, ...]:
        """The declared history followed by every transition this tool made."""
        node = self.require(node_id)
        return (*node.history, *self._state[node_id].history)

    def ancestors(self, node_id: str) -> tuple[str, ...]:
        """Every node upstream of ``node_id``, sorted."""
        seen: set[str] = set()
        queue = deque(self.parents(node_id))
        while queue:
            current = queue.popleft()
            if current not in seen:
                seen.add(current)
                queue.extend(self._parents[current])
        return tuple(sorted(seen))

    def descendants(self, node_id: str) -> tuple[str, ...]:
        """Every node downstream of ``node_id``, level by level, each level sorted."""
        return tuple(item[0] for item in self._levels(node_id))

    def node_view(self, node_id: str, *, with_history: bool = False) -> dict[str, Any]:
        """One node's declaration and current state, JSON-safe."""
        node = self.require(node_id)
        state = self._state[node_id]
        view: dict[str, Any] = {
            "id": node.node_id,
            "kind": node.kind.value,
            "path": node.path,
            "publication_node": node.publication,
            "validity": state.validity.value,
            "recorded_sha256": state.recorded_sha256,
            "stale_because": sorted(state.stale_because),
        }
        if with_history:
            view["history"] = [entry.to_dict() for entry in self.history(node_id)]
        return view

    def node_table(self, *, with_history: bool = False) -> list[dict[str, Any]]:
        return [self.node_view(node_id, with_history=with_history) for node_id in self._nodes]

    # -- persistence -------------------------------------------------------------

    def apply_state(self, document: Any, *, sha256: str | None = None) -> None:
        """Adopt a parsed ``graph-state.json``. The whole document is validated first.

        For a node the tool has transitioned (non-empty state history), the
        state is authoritative: editing graph.json cannot clear a stale mark
        or swap a recorded digest. For a node the tool never touched,
        graph.json's declaration is used, plus any recorded stale causes.
        A node in the state that the graph no longer declares is reported in
        :attr:`state_info` and otherwise ignored.
        """
        if self._journal or self.state_info.present:
            raise RuntimeError("apply_state must be called once, on a freshly loaded graph")
        code = MALFORMED_STATE
        top = _object(document, "graph state", STATE_KEYS, STATE_KEYS, code)
        if top["schema"] != GRAPH_STATE_SCHEMA:
            raise GraphError(code, f"schema must be {GRAPH_STATE_SCHEMA!r}, got {top['schema']!r}")
        reference = _object(top["graph"], "graph state 'graph'", STATE_GRAPH_KEYS, STATE_GRAPH_KEYS, code)
        path = reference["path"]
        if not isinstance(path, str) or comparison_key(path) != comparison_key(self.graph_path):
            raise GraphError(code, f"the state was written for graph {path!r}, not {self.graph_path!r}")
        recorded_graph = _digest(reference["sha256"], "graph state 'graph.sha256'", code)
        if recorded_graph is None:
            raise GraphError(code, "graph state 'graph.sha256' must be a digest")
        _timestamp(top["updated_at"], "graph state 'updated_at'", code)
        if not isinstance(top["nodes"], Mapping):
            raise GraphError(code, "graph state 'nodes' must be an object keyed by node id")
        adopted: dict[str, _NodeState] = {}
        orphaned: list[str] = []
        for node_id, entry in sorted(top["nodes"].items()):
            parsed = self._parse_state_entry(node_id, entry)
            if node_id in self._nodes:
                adopted[node_id] = parsed
            else:
                orphaned.append(node_id)
        for node_id, parsed in adopted.items():
            if parsed.history:
                self._state[node_id] = parsed
            elif self._state[node_id].validity is _STALE:
                self._state[node_id].stale_because |= parsed.stale_because
        self.state_info = StateInfo(
            path=self.state_path,
            present=True,
            sha256=sha256,
            graph_changed_since_state=recorded_graph != self.graph_sha256,
            orphaned_nodes=tuple(orphaned),
        )

    def _parse_state_entry(self, node_id: str, entry: Any) -> _NodeState:
        code = MALFORMED_STATE
        where = f"graph state node {node_id!r}"
        _identifier(node_id, where, code)
        item = _object(entry, where, STATE_NODE_KEYS, STATE_NODE_KEYS, code)
        validity = _validity(item["validity"], f"{where}.validity", code)
        recorded = _digest(item["recorded_sha256"], f"{where}.recorded_sha256", code)
        causes = item["stale_because"]
        if not isinstance(causes, list):
            raise GraphError(code, f"{where}.stale_because must be a list of node ids")
        stale_because = {_identifier(cause, f"{where}.stale_because", code) for cause in causes}
        if len(stale_because) != len(causes):
            raise GraphError(code, f"{where}.stale_because repeats a node id")
        if not isinstance(item["history"], list):
            raise GraphError(code, f"{where}.history must be a list")
        history = [
            Transition.from_dict(value, f"{where}.history[{index}]", code=code, complete=True)
            for index, value in enumerate(item["history"])
        ]
        if history:
            # The history must explain the state. A hand edit that changes
            # the validity or the digest without a transition is refused.
            last = history[-1]
            if last.to_state is not validity or last.recorded_sha256_after != recorded:
                raise GraphError(code, f"{where}: validity and recorded digest do not match the last history entry")
            if validity in GOOD_STANDING_STATES and stale_because:
                raise GraphError(code, f"{where} is {validity.value} but lists stale causes {sorted(stale_because)}")
            if validity is _STALE and not stale_because:
                raise GraphError(code, f"{where} is {validity.value} but records no cause")
            node = self._nodes.get(node_id)
            if node is not None and node.path is None and recorded is not None:
                raise GraphError(code, f"{where} records a digest but the node has no file")
        return _NodeState(validity, recorded, stale_because, history)

    def state_document(self, *, at: str | None = None) -> dict[str, Any]:
        """The ``graph-state.json`` document for the current state."""
        return {
            "schema": GRAPH_STATE_SCHEMA,
            "graph": {"path": self.graph_path, "sha256": self.graph_sha256},
            "updated_at": at or now(),
            "nodes": {
                node_id: {
                    "validity": state.validity.value,
                    "recorded_sha256": state.recorded_sha256,
                    "stale_because": sorted(state.stale_because),
                    "history": [entry.to_dict() for entry in state.history],
                }
                for node_id, state in self._state.items()
            },
        }

    def save_state(self, *, at: str | None = None) -> Path:
        """Write ``graph-state.json`` next to the graph through a safe write; return its path."""
        if self.root is None:
            raise ValueError("this graph has no root directory to save its state under")
        return safe_write(self.root, self.state_path, pretty_json_bytes(self.state_document(at=at)))

    # -- state changes -----------------------------------------------------------

    def _observer(self, observe: Observer | None) -> Observer:
        if observe is not None:
            return observe
        if self.root is None:
            raise ValueError("pass an observer: this graph has no root directory to read node files from")
        return file_observer(self.root, self.max_bytes)

    def _transition(
        self,
        node_id: str,
        to_state: Validity,
        reason: str,
        *,
        at: str,
        trigger: str,
        observed_sha256: str | None = None,
        recorded_sha256: Any = _KEEP,
    ) -> None:
        state = self._state[node_id]
        after = state.recorded_sha256 if recorded_sha256 is _KEEP else recorded_sha256
        entry = Transition(
            at=at,
            from_state=state.validity,
            to_state=to_state,
            reason=reason,
            trigger=trigger,
            recorded_sha256_before=state.recorded_sha256,
            recorded_sha256_after=after,
            observed_sha256=observed_sha256,
        )
        state.validity = to_state
        state.recorded_sha256 = after
        state.history.append(entry)
        self._journal.append((node_id, entry))

    def _levels(self, origin: str) -> list[tuple[str, int, tuple[str, ...]]]:
        """Descendants of ``origin`` as ``(id, depth, path)``: breadth-first, each level sorted.

        A node's path is taken from the first parent, in sorted order, that
        reaches it at the smallest depth, so it is one of the shortest paths
        and the same one on every run.
        """
        routes: dict[str, tuple[str, ...]] = {origin: (origin,)}
        frontier: tuple[str, ...] = (origin,)
        found: list[tuple[str, int, tuple[str, ...]]] = []
        depth = 0
        while frontier:
            depth += 1
            reached: dict[str, tuple[str, ...]] = {}
            for parent in frontier:
                for child in self._children[parent]:
                    if child not in routes and child not in reached:
                        reached[child] = (*routes[parent], child)
            for child in sorted(reached):
                found.append((child, depth, reached[child]))
            routes.update(reached)
            frontier = tuple(sorted(reached))
        return found

    def _mark_descendants(self, origin: str, event: str, at: str) -> tuple[DescendantImpact, ...]:
        """Mark every descendant of ``origin`` STALE_PENDING_REVALIDATION, recording causes.

        Every edge inside the affected subgraph adds its parent to the child's
        ``stale_because``, so a node reached along two paths needs both
        upstream nodes cleared before early cutoff can clear it. Descendants
        that are already pending, or whose state was declared by a person,
        keep their state.
        """
        levels = self._levels(origin)
        for parent in (origin, *(node_id for node_id, _, _ in levels)):
            for child in self._children[parent]:
                self._state[child].stale_because.add(parent)
        impacts: list[DescendantImpact] = []
        for node_id, depth, route in levels:
            prior = self._state[node_id].validity
            if prior in GOOD_STANDING_STATES:
                reason = f"IMPACT: upstream {origin!r} {event}; path from the changed node: {' -> '.join(route)}"
                self._transition(node_id, _STALE, reason, at=at, trigger=origin)
            node = self._nodes[node_id]
            impacts.append(DescendantImpact(node_id, node.kind, depth, route, prior, self._state[node_id].validity))
        return tuple(impacts)

    def _prior_to_stale(self, node_id: str) -> Validity | None:
        """The state a node had just before it last went stale, if that was a good standing."""
        for entry in reversed(self.history(node_id)):
            if entry.to_state is _STALE:
                return entry.from_state if entry.from_state in GOOD_STANDING_STATES else None
        return None

    def _cutoff(self, origin: str, at: str) -> tuple[ClearedNode, ...]:
        """Early cutoff after ``origin`` was revalidated unchanged, cascading downstream.

        A descendant is cleared only when ``origin`` (or a node cleared
        because of it) was its last remaining cause. It returns to the state
        it had before it went stale.
        """
        cleared: list[ClearedNode] = []
        queue = deque([origin])
        while queue:
            upstream = queue.popleft()
            for child in self._children[upstream]:
                state = self._state[child]
                if upstream not in state.stale_because:
                    continue
                state.stale_because.discard(upstream)
                if state.stale_because or state.validity is not _STALE:
                    continue
                restored = self._prior_to_stale(child)
                if restored is None:
                    # Nothing says what state to return to: stay stale, on its own account.
                    state.stale_because.add(child)
                    continue
                reason = (
                    f"EARLY_CUTOFF: upstream {origin!r} was revalidated unchanged, and {child!r} was pending "
                    f"only because of {upstream!r}"
                )
                self._transition(child, restored, reason, at=at, trigger=origin)
                cleared.append(ClearedNode(child, self._nodes[child].kind, restored, upstream))
                queue.append(child)
        return tuple(cleared)

    def detect_changes(self, observe: Observer | None = None, *, at: str | None = None) -> Detection:
        """Compare every node file with its recorded digest, then propagate.

        A changed file makes its node STALE_PENDING_REVALIDATION and an
        unreadable one UNRESOLVED; both start an impact walk. Afterwards every
        pending node's descendants are made pending too, which also repairs
        a state saved before an edge was added to graph.json. Nothing is
        cleared here: only :meth:`revalidate` clears.
        """
        observe = self._observer(observe)
        at = at or now()
        start = len(self._journal)
        observations: list[NodeObservation] = []
        origins: list[tuple[str, str]] = []
        for node_id in self._order:
            node, state = self._nodes[node_id], self._state[node_id]
            if node.path is None:
                observations.append(NodeObservation(node_id, None, None, None, DigestComparison.NO_FILE))
                continue
            seen = observe(node.path)
            recorded = state.recorded_sha256
            if seen.sha256 is None:
                outcome = DigestComparison.UNAVAILABLE
                if state.validity in GOOD_STANDING_STATES or state.validity is _STALE:
                    reason = f"FILE_UNAVAILABLE: {seen.diagnostic or seen.state.value}"
                    self._transition(node_id, Validity.UNRESOLVED, reason, at=at, trigger=node_id)
                origins.append((node_id, "is unavailable: its file could not be read"))
            elif recorded is None:
                outcome = DigestComparison.NO_BASELINE
            elif seen.sha256 == recorded:
                outcome = DigestComparison.UNCHANGED
            else:
                outcome = DigestComparison.CHANGED
                if state.validity in GOOD_STANDING_STATES or state.validity is Validity.UNRESOLVED:
                    reason = "DETECTED_CHANGE: the file digest differs from the recorded digest"
                    self._transition(node_id, _STALE, reason, at=at, trigger=node_id, observed_sha256=seen.sha256)
                if state.validity is _STALE:
                    state.stale_because.add(node_id)
                origins.append((node_id, "changed: its file digest differs from the recorded digest"))
            observations.append(NodeObservation(node_id, node.path, recorded, seen.sha256, outcome, seen.diagnostic))
        # A walk from a node covers its whole subtree, so a node already
        # reached by an earlier walk (origins run in topological order) is skipped.
        covered: set[str] = set()
        for node_id, event in origins:
            if node_id not in covered:
                covered.add(node_id)
                covered.update(item.node_id for item in self._mark_descendants(node_id, event, at))
        for node_id in self._order:
            validity = self._state[node_id].validity
            if node_id not in covered and validity in PENDING_STATES:
                covered.add(node_id)
                covered.update(item.node_id for item in self._mark_descendants(node_id, f"is {validity.value}", at))
        return Detection(tuple(observations), tuple(self._journal[start:]))

    def impact(self, artifact_id: str, *, at: str | None = None) -> Impact:
        """``artifact_id`` was changed (or is declared changed): mark it and its descendants pending.

        The origin itself becomes STALE_PENDING_REVALIDATION too, because its
        content has not yet been re-established. :meth:`revalidate` on the
        origin is the next step. Nothing is marked false or INVALIDATED.
        """
        node = self.require(artifact_id)
        at = at or now()
        start = len(self._journal)
        state = self._state[artifact_id]
        prior = state.validity
        if prior in GOOD_STANDING_STATES:
            reason = f"IMPACT_ORIGIN: {artifact_id!r} was declared changed and is pending revalidation"
            self._transition(artifact_id, _STALE, reason, at=at, trigger=artifact_id)
        if state.validity is _STALE:
            state.stale_because.add(artifact_id)
        descendants = self._mark_descendants(artifact_id, "was declared changed", at)
        return Impact(artifact_id, node.kind, prior, state.validity, descendants, tuple(self._journal[start:]))

    def revalidate(self, artifact_id: str, observe: Observer | None = None, *, at: str | None = None) -> Revalidation:
        """Re-hash ``artifact_id`` and settle it as REVALIDATED_UNCHANGED or REVALIDATED_CHANGED.

        Refused (state untouched) while any ancestor is pending, and for a
        node without a file. An unreadable file makes the node UNRESOLVED and
        its descendants pending.
        """
        node = self.require(artifact_id)
        observe = self._observer(observe)
        at = at or now()
        start = len(self._journal)
        state = self._state[artifact_id]
        prior, before = state.validity, state.recorded_sha256

        def result(outcome: RevalidationOutcome, **extra: Any) -> Revalidation:
            values: dict[str, Any] = {
                "observed_sha256": None,
                "diagnostic": None,
                "pending_ancestors": (),
                "cleared": (),
                "still_pending": (),
            }
            values.update(extra)
            return Revalidation(
                node_id=artifact_id,
                kind=node.kind,
                outcome=outcome,
                prior_state=prior,
                state=state.validity,
                recorded_sha256_before=before,
                recorded_sha256_after=state.recorded_sha256,
                transitions=tuple(self._journal[start:]),
                **values,
            )

        pending = tuple(item for item in self.ancestors(artifact_id) if self._state[item].validity in PENDING_STATES)
        if pending:
            return result(RevalidationOutcome.REFUSED_UPSTREAM_PENDING, pending_ancestors=pending)
        if node.path is None:
            return result(RevalidationOutcome.NO_FILE_TO_HASH)
        seen = observe(node.path)
        if seen.sha256 is None:
            diagnostic = seen.diagnostic or seen.state.value
            if prior is not Validity.UNRESOLVED:
                reason = f"REVALIDATION_FAILED: {diagnostic}"
                self._transition(artifact_id, Validity.UNRESOLVED, reason, at=at, trigger=artifact_id)
            event = "could not be revalidated: its file is unavailable"
            still = self._mark_descendants(artifact_id, event, at)
            return result(RevalidationOutcome.FILE_UNAVAILABLE, diagnostic=diagnostic, still_pending=still)
        if seen.sha256 == before:
            reason = "REVALIDATED: the file digest equals the recorded digest"
            self._transition(
                artifact_id, Validity.REVALIDATED_UNCHANGED, reason, at=at, trigger=artifact_id,
                observed_sha256=seen.sha256,
            )
            state.stale_because.clear()
            cleared = self._cutoff(artifact_id, at)
            return result(RevalidationOutcome.REVALIDATED_UNCHANGED, observed_sha256=seen.sha256, cleared=cleared)
        reason = (
            "REVALIDATED: the file digest differs from the recorded digest; the new digest is recorded and the "
            "previous one is kept in this entry"
        )
        self._transition(
            artifact_id, Validity.REVALIDATED_CHANGED, reason, at=at, trigger=artifact_id,
            observed_sha256=seen.sha256, recorded_sha256=seen.sha256,
        )
        state.stale_because.clear()
        still = self._mark_descendants(artifact_id, "was revalidated with a changed digest", at)
        return result(RevalidationOutcome.REVALIDATED_CHANGED, observed_sha256=seen.sha256, still_pending=still)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def parse_graph(
    document: Any,
    *,
    graph_path: str,
    graph_sha256: str,
    root: str | Path | None = None,
    max_bytes: int | None = None,
) -> DependencyGraph:
    """Validate a parsed ``graph.json`` and build the graph.

    ``graph_path`` is the graph's path relative to the manifest directory; the
    state file and reports live beside it. Raises :class:`GraphError` (or
    :class:`GraphCycleError`) with a named code.
    """
    top = _object(document, "graph", GRAPH_KEYS, REQUIRED_GRAPH_KEYS, MALFORMED_GRAPH)
    if "schema" in top and top["schema"] != GRAPH_SCHEMA:
        raise GraphError(MALFORMED_GRAPH, f"schema must be {GRAPH_SCHEMA!r} when present, got {top['schema']!r}")
    if not isinstance(top["nodes"], list):
        raise GraphError(MALFORMED_GRAPH, "nodes must be a list")
    if not isinstance(top["edges"], list):
        raise GraphError(MALFORMED_GRAPH, "edges must be a list")
    nodes = []
    for index, item in enumerate(top["nodes"]):
        where = f"nodes[{index}]"
        entry = _object(item, where, NODE_KEYS, REQUIRED_NODE_KEYS, MALFORMED_GRAPH)
        history = entry.get("history", [])
        if not isinstance(history, list):
            raise GraphError(MALFORMED_GRAPH, f"{where}.history must be a list")
        nodes.append(
            Node(
                node_id=entry["id"],
                kind=entry["kind"],
                path=entry["path"],
                recorded_sha256=entry["recorded_sha256"],
                validity=entry["validity"],
                history=tuple(
                    Transition.from_dict(value, f"{where}.history[{number}]", code=MALFORMED_GRAPH, complete=False)
                    for number, value in enumerate(history)
                ),
            )
        )
    return DependencyGraph(
        nodes, top["edges"], graph_path=graph_path, graph_sha256=graph_sha256, root=root, max_bytes=max_bytes
    )


def _read_json(root: Path, relpath: str, max_bytes: int, *, unavailable: str, malformed: str) -> tuple[Any, str]:
    """Read and strictly parse one JSON file; FileNotFoundError passes through as absence."""
    try:
        data = safe_read(root, relpath, max_bytes=max_bytes)
    except FileNotFoundError:
        raise
    except SafeIOError as exc:
        raise GraphError(unavailable, f"{relpath} was refused: {exc}") from None
    except OSError as exc:
        raise GraphError(unavailable, f"{relpath} cannot be read: {exc.strerror or type(exc).__name__}") from None
    try:
        return strict_loads(data), sha256_bytes(data)
    except StrictJSONError as exc:
        raise GraphError(malformed, f"{relpath}: {exc}") from None


def load_graph(
    root: str | Path, graph_path: str, *, max_bytes: int = DEFAULT_LIMITS["max_file_bytes"]
) -> DependencyGraph:
    """Load ``graph_path`` (relative to ``root``, the manifest directory) and its saved state.

    A missing ``graph-state.json`` means no state has been saved yet. A state
    file that exists but cannot be read or parsed raises: it is never
    silently replaced, because that would discard its stale marks and history.
    """
    root = Path(root)
    try:
        clean = normalize_relpath(graph_path)
    except UnsafePathError as exc:
        raise GraphError(UNSAFE_PATH, f"graph path: {exc}") from None
    try:
        document, digest = _read_json(root, clean, max_bytes, unavailable=GRAPH_UNAVAILABLE, malformed=MALFORMED_GRAPH)
    except FileNotFoundError:
        raise GraphError(GRAPH_UNAVAILABLE, f"no graph file at {clean}") from None
    graph = parse_graph(document, graph_path=clean, graph_sha256=digest, root=root, max_bytes=max_bytes)
    try:
        state, state_digest = _read_json(
            root, graph.state_path, max_bytes, unavailable=STATE_UNAVAILABLE, malformed=MALFORMED_STATE
        )
    except FileNotFoundError:
        return graph
    graph.apply_state(state, sha256=state_digest)
    return graph


# ---------------------------------------------------------------------------
# Assessment: does the graph's state block publication?
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CurrencyFinding:
    """One reason the graph is not (or not provably) current."""

    status: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason.value,
            "failure_modes": sorted(mode.value for mode in self.failure_modes),
            "detail": redact_text(self.detail),
        }


@dataclass(frozen=True)
class Assessment:
    """The currency verdict over a graph, after detection."""

    status: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...]
    findings: tuple[CurrencyFinding, ...]
    publication_block: Mapping[str, Any]
    counts: Mapping[str, Any]


def _decide(findings: Sequence[CurrencyFinding]) -> tuple[Status, Reason, tuple[FailureMode, ...]]:
    """ERROR > FAIL > ABSTAIN > PASS; the first finding at the winning level names the reason."""
    if not findings:
        return Status.PASS, Reason.VERIFIED, ()
    top = max(_RANK[finding.status] for finding in findings)
    primary = next(finding for finding in findings if _RANK[finding.status] == top)
    modes = sorted({mode for finding in findings for mode in finding.failure_modes}, key=lambda mode: mode.value)
    return primary.status, primary.reason, tuple(modes)


def _names(ids: Sequence[str]) -> str:
    """At most :data:`MAX_LISTED` ids, with the rest counted, never silently dropped."""
    shown = ", ".join(repr(item) for item in ids[:MAX_LISTED])
    return shown + (f" and {len(ids) - MAX_LISTED} more" if len(ids) > MAX_LISTED else "")


def assess(graph: DependencyGraph, detection: Detection) -> Assessment:
    """Judge publication currency from the graph's state and the digests just compared.

    PASS needs every node in good standing, at least one node file actually
    hashed, and at least one publication node. A stale CONCLUSION or
    FIGURE_OR_TABLE is a FAIL (STALE_DEPENDENCY). Everything short of proof
    (unreadable files, missing baselines, pending intermediate nodes,
    states declared by people) is ABSTAIN. None of it is a PASS.
    """
    nodes = graph.nodes
    validity = {node.node_id: graph.validity(node.node_id) for node in nodes}

    def ids(predicate: Callable[[Node], bool]) -> list[str]:
        return [node.node_id for node in nodes if predicate(node)]

    stale_publication = ids(lambda node: node.publication and validity[node.node_id] is _STALE)
    unresolved = ids(lambda node: validity[node.node_id] is Validity.UNRESOLVED)
    stale_other = ids(lambda node: not node.publication and validity[node.node_id] is _STALE)
    declared = ids(lambda node: node.publication and validity[node.node_id] in HUMAN_DECLARED_STATES)
    no_baseline = list(detection.ids(DigestComparison.NO_BASELINE))
    publication = ids(lambda node: node.publication)

    findings: list[CurrencyFinding] = []
    if stale_publication:
        findings.append(
            CurrencyFinding(
                Status.FAIL,
                Reason.SOURCE_MISMATCH,
                (FailureMode.STALE_DEPENDENCY,),
                f"publication blocked: CONCLUSION/FIGURE_OR_TABLE node(s) {_names(stale_publication)} are "
                "STALE_PENDING_REVALIDATION",
            )
        )
    if unresolved:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (),
                f"node(s) {_names(unresolved)} are UNRESOLVED: their files could not be read, so their currency "
                "is unknown",
            )
        )
    if no_baseline:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (),
                f"node(s) {_names(no_baseline)} have a file but no recorded digest, so a change cannot be "
                "detected; revalidate them to record one",
            )
        )
    if stale_other:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (FailureMode.STALE_DEPENDENCY,),
                f"node(s) {_names(stale_other)} are STALE_PENDING_REVALIDATION: they block no publication node, "
                "but the graph is not current",
            )
        )
    if declared:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.REQUIRES_HUMAN_REVIEW,
                (),
                f"publication node(s) {_names(declared)} are declared SUPERSEDED or INVALIDATED by a person; "
                "this tool does not decide whether they may be published",
            )
        )
    if not publication:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (),
                "the graph declares no CONCLUSION or FIGURE_OR_TABLE node, so there is no publication to gate",
            )
        )
    if detection.files_hashed == 0:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.UNVERIFIED,
                (FailureMode.NARRATED_VERIFICATION,),
                "no node file was hashed: currency would rest on declared states alone",
            )
        )
    status, reason, modes = _decide(findings)
    blocked: bool | None = True if stale_publication else (False if status is Status.PASS else None)
    publication_block = {
        "blocked": blocked,
        "rule": CURRENCY_RULE,
        "publication_nodes": len(publication),
        "stale_publication_nodes": stale_publication,
        "undetermined_publication_nodes": [
            node_id for node_id in publication if validity[node_id] is Validity.UNRESOLVED or node_id in declared
        ],
    }
    counts = {
        "nodes": len(nodes),
        "edges": len(graph.edges),
        "publication_nodes": len(publication),
        "files_hashed": detection.files_hashed,
        "comparisons": detection.outcome_counts(),
        "validity": {item.value: sum(1 for value in validity.values() if value is item) for item in Validity},
    }
    return Assessment(status, reason, modes, tuple(findings), publication_block, counts)


# ---------------------------------------------------------------------------
# The dependency_currency check
# ---------------------------------------------------------------------------


def _first(items: Sequence[Any]) -> list[Any]:
    return list(items[:MAX_LISTED])


def _unexamined(
    execution_state: ExecutionState, verdict: Status, reason: Reason, diagnostic: str, evidence: Mapping[str, Any]
) -> CheckOutcome:
    """An outcome for a graph that could not be judged: never PASS, and no node examined."""
    return CheckOutcome(
        execution_state=execution_state,
        verdict=verdict,
        reason=reason,
        rows_examined=0,
        evidence=evidence,
        diagnostics=(diagnostic,),
    )


def _graph_error_outcome(error: GraphError, evidence: dict[str, Any]) -> CheckOutcome:
    """A cycle or an unsafe path is ERROR (the declaration is unusable); other defects ABSTAIN."""
    evidence["error"] = error.to_dict()
    if error.code in _DECLARATION_ERRORS:
        return _unexamined(ExecutionState.SKIPPED, Status.ERROR, Reason.PROTOCOL_BROKEN, str(error), evidence)
    path = evidence["graph"]["path"]
    diagnostic = f"MALFORMED_DOCUMENT: dependencies ({path}): {error}"
    return _unexamined(ExecutionState.SKIPPED, Status.ABSTAIN, Reason.PROTOCOL_BROKEN, diagnostic, evidence)


def _state_outcome(state: Document, evidence: dict[str, Any]) -> CheckOutcome:
    """A graph-state.json that exists but cannot be used is never ignored.

    Ignoring it would silently drop its stale marks, which is exactly how a
    blocked publication could be made to look current.
    """
    diagnostic = (
        f"{STATE_UNAVAILABLE}: {state.path} exists but is {state.state}: {state.diagnostic}; "
        "a saved graph state is never ignored"
    )
    return _unexamined(ExecutionState.SKIPPED, Status.ABSTAIN, Reason.PROTOCOL_BROKEN, diagnostic, evidence)


def preload_graph_files(ctx: CheckContext) -> None:
    """Read the saved graph state and every node file, before any check runs (``verifier.PRELOADS``).

    Reading them up front puts their digests into the run id and in front of
    ``summary_consistency``, which then reports an unpinned node file as a
    blind spot. The dependency_currency check later reads the same bytes
    from the context. An unusable graph reads nothing here: the check
    reports why.
    """
    document = ctx.role_document("dependencies")
    if not document.loaded:
        return
    try:
        graph = parse_graph(
            document.content,
            graph_path=document.path,
            graph_sha256=document.sha256,
            root=ctx.root,
            max_bytes=ctx.limits.max_file_bytes,
        )
    except GraphError:
        return
    ctx.read_document(graph.state_path, role=STATE_ROLE, parse="json")
    for node in graph.nodes:
        if node.path is not None:
            ctx.read_document(node.path, role=NODE_ROLE, parse="bytes")


def check_dependency_currency(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Publication is blocked by stale dependencies (kind ``dependency_currency``).

    Reads the manifest's ``dependencies`` graph and the ``graph-state.json``
    beside it, hashes every node file through the check context (so each
    one is in the evidence manifest), runs detection in memory and judges
    the result with :func:`assess`. It never writes. A cycle or an unsafe
    node path is ERROR. A malformed graph or state is ABSTAIN with
    PROTOCOL_BROKEN. A stale CONCLUSION or FIGURE_OR_TABLE is FAIL with
    STALE_DEPENDENCY.
    """
    if spec.params:
        raise CheckParamError(f"UNKNOWN_PARAM: dependency_currency does not accept {sorted(spec.params)}")
    if spec.inputs:
        raise CheckParamError(
            "UNEXPECTED_INPUTS: dependency_currency reads the manifest's dependencies graph and takes no inputs"
        )
    document = ctx.role_document("dependencies")
    evidence: dict[str, Any] = {"graph": document.to_dict(), "rule": CURRENCY_RULE, "scope": _SCOPE}
    if not document.declared:
        return _unexamined(
            ExecutionState.NOT_APPLICABLE,
            Status.ABSTAIN,
            Reason.OUT_OF_SCOPE,
            "the manifest declares no dependencies graph",
            evidence,
        )
    if not document.loaded:
        reason = Reason.PROTOCOL_BROKEN if document.state is InputState.PARSE_ERROR else Reason.INSUFFICIENT_EVIDENCE
        diagnostic = f"dependencies ({document.path}) unavailable: {document.diagnostic or document.state}"
        return _unexamined(ExecutionState.SKIPPED, Status.ABSTAIN, reason, diagnostic, evidence)
    try:
        graph = parse_graph(
            document.content,
            graph_path=document.path,
            graph_sha256=document.sha256,
            root=ctx.root,
            max_bytes=ctx.limits.max_file_bytes,
        )
    except GraphError as exc:
        return _graph_error_outcome(exc, evidence)
    state = ctx.read_document(graph.state_path, role=STATE_ROLE, parse="json")
    evidence["state"] = state.to_dict()
    if state.state is not InputState.MISSING:
        if not state.loaded:
            return _state_outcome(state, evidence)
        try:
            graph.apply_state(state.content, sha256=state.sha256)
        except GraphError as exc:
            evidence["error"] = exc.to_dict()
            diagnostic = f"{exc}; a saved graph state is never ignored"
            return _unexamined(ExecutionState.SKIPPED, Status.ABSTAIN, Reason.PROTOCOL_BROKEN, diagnostic, evidence)
    if not graph.nodes:
        return _unexamined(
            ExecutionState.NOT_APPLICABLE,
            Status.ABSTAIN,
            Reason.INSUFFICIENT_EVIDENCE,
            "the dependencies graph declares no nodes",
            evidence,
        )
    detection = graph.detect_changes(_context_observer(ctx))
    assessment = assess(graph, detection)
    comparisons = [item.to_dict() for item in detection.observations]
    table = graph.node_table()
    evidence.update(
        {
            "state_record": graph.state_info.to_dict(),
            "counts": dict(assessment.counts),
            "publication_block": dict(assessment.publication_block),
            "comparisons": _first(comparisons),
            "comparisons_total": len(comparisons),
            "comparisons_sha256": sha256_canonical(comparisons),
            "not_in_good_standing": _first(
                [view for view in table if Validity(view["validity"]) not in GOOD_STANDING_STATES]
            ),
            "node_table_sha256": sha256_canonical(table),
            "transitions_in_memory": len(detection.transitions),
        }
    )
    return CheckOutcome(
        execution_state=ExecutionState.CHECKED,
        verdict=assessment.status,
        reason=assessment.reason,
        failure_modes=assessment.failure_modes,
        rows_examined=len(graph.nodes),
        evidence=evidence,
        diagnostics=tuple(finding.detail for finding in assessment.findings),
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def _revalidation_findings(result: Revalidation) -> tuple[CurrencyFinding, ...]:
    """Why a revalidation could not settle its node. A settled one adds nothing."""
    node_id = result.node_id
    if result.outcome is RevalidationOutcome.REFUSED_UPSTREAM_PENDING:
        detail = (
            f"REFUSED_UPSTREAM_PENDING: {node_id!r} cannot be revalidated while upstream node(s) "
            f"{_names(result.pending_ancestors)} are pending; revalidate them first"
        )
    elif result.outcome is RevalidationOutcome.NO_FILE_TO_HASH:
        detail = (
            f"NO_FILE_TO_HASH: {node_id!r} declares no file, so its content cannot be re-hashed; it stays "
            f"{result.state.value}"
        )
    elif result.outcome is RevalidationOutcome.FILE_UNAVAILABLE:
        detail = f"FILE_UNAVAILABLE: {node_id!r} could not be re-hashed: {result.diagnostic}"
    else:
        return ()
    return (CurrencyFinding(Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (), detail),)


def build_report(
    *,
    command: str,
    graph: DependencyGraph,
    before: Detection,
    action: Impact | Revalidation,
    after: Detection,
    assessment: Assessment,
    at: str,
) -> dict[str, Any]:
    """The JSON report of one ``impact`` or ``revalidate`` command (``science-gate-impact/v1``).

    ``before`` is the detection run before acting, ``after`` the one the
    assessment is based on. The command's status combines the action's own
    findings (a refused revalidation, say) with the assessment's.
    """
    if command not in _REPORT_FILES:
        raise ValueError(f"unknown command {command!r}")
    action_findings = _revalidation_findings(action) if isinstance(action, Revalidation) else ()
    findings = (*action_findings, *assessment.findings)
    status, reason, modes = _decide(findings)
    artifact_id = action.origin if isinstance(action, Impact) else action.node_id
    transitions = (*before.transitions, *action.transitions, *after.transitions)
    report = {
        "schema": IMPACT_REPORT_SCHEMA,
        "command": command,
        "artifact_id": artifact_id,
        "at": at,
        "status": status.value,
        "reason": reason.value,
        "failure_modes": [mode.value for mode in modes],
        "findings": [finding.to_dict() for finding in findings],
        "graph": {"path": graph.graph_path, "sha256": graph.graph_sha256},
        "state": graph.state_info.to_dict(),
        "detection": before.to_dict(),
        command: action.to_dict(),
        "publication_block": dict(assessment.publication_block),
        "counts": dict(assessment.counts),
        "transitions": _journal_dicts(transitions),
        "nodes": graph.node_table(with_history=True),
        "does_not_prove": list(DOES_NOT_PROVE),
    }
    return redact(report)


def _block_text(blocked: bool | None) -> str:
    return {True: "BLOCKED", False: "not blocked"}.get(blocked, "UNDETERMINED")


def headline(report: Mapping[str, Any]) -> str:
    """The one-line status headline printed first by ``impact`` and ``revalidate``."""
    command, artifact_id = report["command"], report["artifact_id"]
    lead = f"{report['status']} ({report['reason']}) {command} {artifact_id}"
    block = f"publication {_block_text(report['publication_block']['blocked'])}"
    if command == "impact":
        descendants = report["impact"]["descendants"]
        marked = sum(1 for item in descendants if item["prior_state"] != item["state"])
        return f"{lead}: {len(descendants)} descendant(s) reached, {marked} newly STALE_PENDING_REVALIDATION; {block}"
    action = report["revalidate"]
    cleared = len(action["cleared"])
    return f"{lead}: {action['outcome']}; {cleared} descendant(s) cleared by early cutoff; {block}"


def _code(value: Any) -> str:
    """Inline code for an id, path or digest. A None renders as a plain dash."""
    if value is None:
        return "-"
    return "`" + str(value).replace("`", "'").replace("\n", " ") + "`"


def _cell(value: Any) -> str:
    """Text for a table cell: pipes escaped, newlines flattened."""
    return "-" if value is None else str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _short(digest: str | None) -> str:
    return _code(None if digest is None else digest[:16])


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]], empty: str) -> list[str]:
    if not rows:
        return [empty]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def _descendant_rows(items: Sequence[Mapping[str, Any]]) -> list[list[str]]:
    return [
        [
            str(item["depth"]),
            _code(item["id"]),
            item["kind"],
            item["prior_state"],
            item["state"],
            _cell(" -> ".join(item["path_from_changed_node"])),
        ]
        for item in items
    ]


_DESCENDANT_HEADERS = ("depth", "node", "kind", "prior state", "state", "path from the changed node")


def _impact_sections(action: Mapping[str, Any]) -> list[str]:
    origin = action["origin"]
    lines = [
        "## WHAT CHANGED",
        "",
        f"{_code(origin['id'])} ({origin['kind']}) was declared changed: {origin['prior_state']} -> "
        f"{origin['state']}.",
        "",
        "## DESCENDANTS MARKED STALE_PENDING_REVALIDATION",
        "",
    ]
    lines += _table(_DESCENDANT_HEADERS, _descendant_rows(action["descendants"]), "The node has no descendants.")
    return lines


def _revalidation_sections(action: Mapping[str, Any]) -> list[str]:
    node = action["node"]
    lines = [
        "## REVALIDATION",
        "",
        f"- node: {_code(node['id'])} ({node['kind']})",
        f"- outcome: {action['outcome']}",
        f"- state: {node['prior_state']} -> {node['state']}",
        f"- recorded digest before: {_code(node['recorded_sha256_before'])}",
        f"- recorded digest after: {_code(node['recorded_sha256_after'])}",
        f"- digest read now: {_code(node['observed_sha256'])}",
    ]
    if action["pending_ancestors"]:
        lines.append("- pending upstream: " + ", ".join(_code(item) for item in action["pending_ancestors"]))
    if action["diagnostic"]:
        lines.append(f"- diagnostic: {_cell(action['diagnostic'])}")
    lines += ["", "## CLEARED BY EARLY CUTOFF", ""]
    rows = [
        [_code(item["id"]), item["kind"], item["prior_state"], item["state"], _code(item["cleared_because"])]
        for item in action["cleared"]
    ]
    headers = ("node", "kind", "prior state", "state", "last cause removed")
    lines += _table(headers, rows, "No descendant was cleared.")
    lines += ["", "## STILL PENDING REVALIDATION", ""]
    lines += _table(_DESCENDANT_HEADERS, _descendant_rows(action["still_pending"]), "No descendant was marked.")
    return lines


def render_markdown(report: Mapping[str, Any]) -> str:
    """The human-readable form of a report, printed after the headline and paths."""
    command = report["command"]
    title = "impact" if command == "impact" else "revalidation"
    block = report["publication_block"]
    counts = report["counts"]
    modes = ", ".join(report["failure_modes"]) or "none"
    lines = [
        f"# Dependency {title} report: {_code(report['artifact_id'])}",
        "",
        "## STATUS",
        "",
        f"{report['status']} ({report['reason']}); failure modes: {modes}. "
        f"Publication: {_block_text(block['blocked'])}.",
        "",
    ]
    findings = [f"- {item['status']} ({item['reason']}): {_cell(item['detail'])}" for item in report["findings"]]
    lines += [*(findings or ["No finding."]), "", "## WHAT WAS COMPARED", ""]
    detection = report["detection"]
    lines.append(
        f"{counts['nodes']} node(s), {counts['edges']} edge(s). Before acting, {detection['files_hashed']} node "
        "file digest(s) were compared with the recorded digests (digests shortened to 16 hex characters here; "
        "the JSON report has them in full)."
    )
    lines.append("")
    rows = [
        [
            _code(item["id"]),
            _code(item["path"]),
            _short(item["recorded_sha256"]),
            _short(item["observed_sha256"]),
            item["outcome"],
        ]
        for item in detection["observations"]
    ]
    lines += _table(("node", "file", "recorded", "read now", "outcome"), rows, "The graph has no nodes.")
    lines.append("")
    action = report[command]
    lines += _impact_sections(action) if command == "impact" else _revalidation_sections(action)
    stale = ", ".join(_code(item) for item in block["stale_publication_nodes"]) or "none"
    undetermined = ", ".join(_code(item) for item in block["undetermined_publication_nodes"]) or "none"
    lines += [
        "",
        "## PUBLICATION BLOCK",
        "",
        f"- rule: {block['rule']}",
        f"- blocked: {_block_text(block['blocked'])}",
        f"- stale publication nodes: {stale}",
        f"- undetermined publication nodes: {undetermined}",
        "",
        "## TRANSITIONS RECORDED",
        "",
    ]
    rows = [
        [_code(item["node"]), item["from"], item["to"], item["at"], _cell(item["reason"])]
        for item in report["transitions"]
    ]
    lines += _table(("node", "from", "to", "at", "reason"), rows, "No transition was recorded.")
    lines += ["", "## NODE STATES", ""]
    rows = [
        [
            _code(item["id"]),
            item["kind"],
            item["validity"],
            _short(item["recorded_sha256"]),
            ", ".join(_code(cause) for cause in item["stale_because"]) or "-",
            str(len(item["history"])),
        ]
        for item in report["nodes"]
    ]
    lines += _table(("node", "kind", "validity", "recorded", "stale because", "history entries"), rows, "No nodes.")
    lines += ["", "## WHAT THIS DOES NOT PROVE", ""]
    lines += [f"- {item}" for item in report["does_not_prove"]]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Command line: impact and revalidate
# ---------------------------------------------------------------------------


class _CommandError(Exception):
    """A reason the command cannot act at all. It exits 3 and writes nothing."""


def _emit(stream: TextIO, text: str) -> None:
    """Write one redacted line, escaping what the stream's encoding cannot represent.

    A Windows console may use a legacy code page, and a path it cannot encode
    must not turn a verdict into a traceback.
    """
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(redact_text(text).encode(encoding, "backslashreplace").decode(encoding) + "\n")


def _open_graph(manifest_path: str) -> DependencyGraph:
    """Load the manifest's graph and saved state for a command, or raise :class:`_CommandError`."""
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        raise _CommandError(f"invalid manifest ({', '.join(exc.codes)}): {exc}") from None
    if manifest.dependencies is None:
        raise _CommandError("the manifest declares no 'dependencies' graph")
    try:
        return load_graph(manifest.root, manifest.dependencies, max_bytes=manifest.limits.max_file_bytes)
    except GraphError as exc:
        raise _CommandError(str(exc)) from None


def _run(command: str, args: argparse.Namespace, out: TextIO) -> int:
    """Shared body of ``impact`` and ``revalidate``.

    Detection runs first and its result is persisted with the action's, so
    the saved state never lags behind the files on disk. A graph or state
    that cannot be used stops the command before anything is written.
    """
    error = EXIT_CODE[Status.ERROR]
    try:
        graph = _open_graph(args.manifest)
        graph.require(args.artifact_id)
    except (_CommandError, GraphError) as exc:
        _emit(out, f"ERROR {command}: {exc}")
        return error
    at = now()
    before = graph.detect_changes(at=at)
    action: Impact | Revalidation
    if command == "impact":
        action = graph.impact(args.artifact_id, at=at)
    else:
        action = graph.revalidate(args.artifact_id, at=at)
    after = graph.detect_changes(at=at)
    report = build_report(
        command=command, graph=graph, before=before, action=action, after=after, assessment=assess(graph, after), at=at
    )
    try:
        state_path = graph.save_state(at=at)
    except (SafeIOError, OSError) as exc:
        _emit(out, f"ERROR {command}: the graph state could not be written: {exc}")
        return error
    try:
        report_path = safe_write(graph.root, graph.report_path(command), pretty_json_bytes(report))
    except (SafeIOError, OSError) as exc:
        _emit(out, f"ERROR {command}: {state_path} was written, but the report could not be: {exc}")
        return error
    _emit(out, headline(report))
    _emit(out, str(state_path))
    _emit(out, str(report_path))
    _emit(out, "")
    for line in render_markdown(report).splitlines():
        _emit(out, line)
    return EXIT_CODE[Status(report["status"])]


def cli_impact(args: argparse.Namespace) -> int:
    """``science-gate impact ARTIFACT_ID --manifest MANIFEST``; returns the exit code.

    Runs detection, marks the artifact and its descendants
    STALE_PENDING_REVALIDATION, saves ``graph-state.json`` and
    ``impact-report.json`` next to the graph, and prints the headline, the
    two paths, a blank line and the markdown report. The status is FAIL while
    publication is blocked, which after an impact on a node upstream of a
    publication node it always is.
    """
    return _run("impact", args, sys.stdout)


def cli_revalidate(args: argparse.Namespace) -> int:
    """``science-gate revalidate ARTIFACT_ID --manifest MANIFEST``; returns the exit code.

    Runs detection, re-hashes the artifact (REVALIDATED_UNCHANGED with early
    cutoff, or REVALIDATED_CHANGED with its descendants kept stale), saves
    ``graph-state.json`` and ``revalidation-report.json`` next to the graph,
    and prints the headline, the two paths, a blank line and the markdown
    report. The status is PASS only when the whole graph is then current.
    """
    return _run("revalidate", args, sys.stdout)
