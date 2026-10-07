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
* A *derived* node (one with at least one parent) is a different matter
  (decision D6, extension #5). Its file is an output, and re-hashing an
  untouched output always matches, so "unchanged" would say nothing about
  whether it still follows from its changed inputs. It becomes
  REVALIDATED_UNCHANGED only with a :class:`RecomputeWitness`: an invocation
  that started after the change, consumed the parents' current digests and
  reproduced the recorded output digest. Without one the cutoff is refused as
  VACUOUS_CUTOFF, and the refusal is kept in the node's history. Root nodes
  keep the plain re-hash rule.
* Every transition is appended to the node's history as
  ``{at, from, to, reason}``, together with the recorded digest before and
  after, the witness that backed it and its cause category, so both the
  original and the corrected state are preserved.
* ``graph-state.json`` next to the graph persists the result. It is written
  only through :func:`~science_gate._safeio.safe_write`. ``graph.json`` itself
  is never rewritten: it stays the human-authored declaration.

The ``dependency_currency`` check runs the same detection in memory and never
writes. It FAILs with STALE_DEPENDENCY while any CONCLUSION or FIGURE_OR_TABLE
is STALE_PENDING_REVALIDATION. Nodes may also name the checks whose earlier
PASS they rely on (``backed_by_checks``); when such a check's kind, version,
params or the tool version differ from the current manifest, the verifier
changed beneath the node, and the check marks it and its descendants stale
with cause category VERIFIER (:func:`verifier_drift`).

:func:`what_if` turns the detector on itself (extension #22): it injects a
synthetic digest change into one artifact, in memory, and requires every
declared descendant to go stale and the currency assessment to FAIL. A
staleness detector that never reports stale would otherwise pass unnoticed.

Conventions:

* Node paths are relative to the **manifest directory**, like every other
  path a manifest declares. They are not relative to the graph file.
* Staleness has causes. ``stale_because`` lists, for each pending node, the
  direct parents that are pending or changed, plus the node itself when its
  own file changed, its stale state was declared, or a parent was
  revalidated with a changed digest (the node consumed the old content, so
  only its own revalidation can settle it). Early cutoff removes one cause,
  and clears a node only when no cause is left.
* A node cannot be revalidated while any of its ancestors is still pending.
  Otherwise a descendant could be cleared before the upstream result it
  depends on is known, and that later result could never reach it.
* Only :meth:`~DependencyGraph.revalidate` ever clears a pending state.
  Detection and impact walks only mark. SUPERSEDED and INVALIDATED are
  declared by people. Detection and impact walks keep them unchanged, and
  this tool never sets them.
* A stale cause is a parent id, the node's own id, or ``verifier:<check_id>``
  for verifier drift. Node and check ids never contain ``:``, so the three
  cannot be confused.
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
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence, TextIO

from . import __version__
from ._canonical import StrictJSONError, pretty_json_bytes, sha256_bytes, sha256_canonical, strict_loads
from ._clock import ClockError, now, parse_utc
from ._redact import redact, redact_text
from ._safeio import SafeIOError, UnsafePathError, comparison_key, normalize_relpath, safe_read, safe_write
from .manifests import DEFAULT_LIMITS, IDENTIFIER_PATTERN, CheckSpec, ManifestError, load_manifest
from .models import (
    EXIT_CODE,
    SKIP_JUSTIFICATION_KEY,
    CheckResult,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    InputState,
    Reason,
    SkipJustification,
    StaleCause,
    Status,
    Validity,
)
from .verifier import MAX_LISTED, CheckContext, CheckOutcome, CheckParamError, Document

__all__ = [
    "GRAPH_SCHEMA",
    "GRAPH_STATE_SCHEMA",
    "IMPACT_REPORT_SCHEMA",
    "WITNESS_SCHEMA",
    "WHAT_IF_SCHEMA",
    "GRAPH_STATE_FILE",
    "IMPACT_REPORT_FILE",
    "REVALIDATION_REPORT_FILE",
    "STATE_ROLE",
    "NODE_ROLE",
    "GRAPH_KEYS",
    "REQUIRED_GRAPH_KEYS",
    "NODE_KEYS",
    "REQUIRED_NODE_KEYS",
    "BACKING_KEYS",
    "TRANSITION_KEYS",
    "REQUIRED_TRANSITION_KEYS",
    "REQUIRED_STATE_TRANSITION_KEYS",
    "STATE_KEYS",
    "STATE_GRAPH_KEYS",
    "STATE_NODE_KEYS",
    "WITNESS_KEYS",
    "DRIFT_FIELDS",
    "VERIFIER_CAUSE_PREFIX",
    "VACUOUS_CUTOFF_REASON",
    "INVALID_WITNESS_REASON",
    "REFUSED_CUTOFF_REASONS",
    "PUBLICATION_KINDS",
    "PENDING_STATES",
    "GOOD_STANDING_STATES",
    "HUMAN_DECLARED_STATES",
    "CURRENCY_RULE",
    "DOES_NOT_PROVE",
    "WHAT_IF_DOES_NOT_PROVE",
    "FALSIFIER_MARK",
    "MALFORMED_GRAPH",
    "UNSAFE_PATH",
    "GRAPH_CYCLE",
    "MALFORMED_STATE",
    "UNKNOWN_ARTIFACT",
    "GRAPH_UNAVAILABLE",
    "STATE_UNAVAILABLE",
    "MALFORMED_WITNESS",
    "WITNESS_UNAVAILABLE",
    "INVALID_MANIFEST",
    "NO_GRAPH_DECLARED",
    "NodeKind",
    "DigestComparison",
    "RevalidationOutcome",
    "WhatIfOutcome",
    "GraphError",
    "GraphCycleError",
    "Observation",
    "Observer",
    "file_observer",
    "Transition",
    "BackingCheck",
    "Node",
    "RecomputeWitness",
    "load_witness",
    "StateInfo",
    "NodeObservation",
    "Detection",
    "DescendantImpact",
    "Impact",
    "ClearedNode",
    "Revalidation",
    "DriftEntry",
    "CurrencyFinding",
    "Assessment",
    "WhatIfDescendant",
    "WhatIfReport",
    "DependencyGraph",
    "parse_graph",
    "load_graph",
    "open_graph",
    "params_sha256",
    "verifier_drift",
    "assess",
    "build_report",
    "render_markdown",
    "headline",
    "check_dependency_currency",
    "preload_graph_files",
    "falsify_dependency_currency",
    "what_if",
    "what_if_headline",
    "render_what_if",
    "cli_impact",
    "cli_revalidate",
    "cli_what_if",
]

GRAPH_SCHEMA = "science-gate-graph/v1"
GRAPH_STATE_SCHEMA = "science-gate-graph-state/v1"
IMPACT_REPORT_SCHEMA = "science-gate-impact/v1"
WITNESS_SCHEMA = "science-gate-recompute-witness/v1"
WHAT_IF_SCHEMA = "science-gate-what-if/v1"

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
NODE_KEYS = frozenset({"id", "kind", "path", "recorded_sha256", "validity", "history", "backed_by_checks"})
REQUIRED_NODE_KEYS = frozenset({"id", "kind", "path", "recorded_sha256", "validity"})
#: One ``backed_by_checks`` entry: the check as it was when its PASS was recorded.
BACKING_KEYS = frozenset({"check_id", "kind", "version", "params_sha256", "tool_version"})
#: The contract's ``{at, from, to, reason}`` plus what makes a transition
#: auditable: which node triggered it, the digests involved, the recompute
#: witness that backed it and the category of the staleness it concerns.
TRANSITION_KEYS = frozenset(
    {
        "at",
        "from",
        "to",
        "reason",
        "trigger",
        "recorded_sha256_before",
        "recorded_sha256_after",
        "observed_sha256",
        "witness_id",
        "cause_category",
    }
)
REQUIRED_TRANSITION_KEYS = frozenset({"at", "from", "to", "reason"})
#: What a transition in graph-state.json must carry. ``witness_id`` and
#: ``cause_category`` are written on every transition but read as null when
#: absent, so a state saved before they existed stays usable instead of
#: blocking every command (a saved state is never silently discarded).
REQUIRED_STATE_TRANSITION_KEYS = TRANSITION_KEYS - {"witness_id", "cause_category"}
STATE_KEYS = frozenset({"schema", "graph", "updated_at", "nodes"})
STATE_GRAPH_KEYS = frozenset({"path", "sha256"})
STATE_NODE_KEYS = frozenset({"validity", "recorded_sha256", "stale_because", "history"})
WITNESS_KEYS = frozenset(
    {"schema", "node_id", "invocation_id", "started_at", "completed_at", "inputs", "output_sha256"}
)
#: The ``backed_by_checks`` fields compared with the current manifest and tool.
DRIFT_FIELDS = ("kind", "version", "params_sha256", "tool_version")

#: Prefix of a stale cause that is a drifted check rather than a node.
VERIFIER_CAUSE_PREFIX = "verifier:"
#: History reasons of a refused cutoff (section 17.13): exactly these strings.
VACUOUS_CUTOFF_REASON = "VACUOUS_CUTOFF"
INVALID_WITNESS_REASON = "INVALID_WITNESS"
REFUSED_CUTOFF_REASONS = frozenset({VACUOUS_CUTOFF_REASON, INVALID_WITNESS_REASON})

MALFORMED_GRAPH = "MALFORMED_GRAPH"
UNSAFE_PATH = "UNSAFE_PATH"
GRAPH_CYCLE = "GRAPH_CYCLE"
MALFORMED_STATE = "MALFORMED_STATE"
UNKNOWN_ARTIFACT = "UNKNOWN_ARTIFACT"
GRAPH_UNAVAILABLE = "GRAPH_UNAVAILABLE"
STATE_UNAVAILABLE = "STATE_UNAVAILABLE"
MALFORMED_WITNESS = "MALFORMED_WITNESS"
WITNESS_UNAVAILABLE = "WITNESS_UNAVAILABLE"
INVALID_MANIFEST = "INVALID_MANIFEST"
NO_GRAPH_DECLARED = "NO_GRAPH_DECLARED"

#: A problem with the graph declaration itself, not with the evidence it
#: points at: the check reports ERROR for these, as it does for an unsafe manifest.
_DECLARATION_ERRORS = frozenset({GRAPH_CYCLE, UNSAFE_PATH})

PENDING_STATES = frozenset({Validity.STALE_PENDING_REVALIDATION, Validity.UNRESOLVED})
GOOD_STANDING_STATES = frozenset({Validity.CURRENT, Validity.REVALIDATED_UNCHANGED, Validity.REVALIDATED_CHANGED})
HUMAN_DECLARED_STATES = frozenset({Validity.SUPERSEDED, Validity.INVALIDATED})

CURRENCY_RULE = (
    "publication is blocked while any CONCLUSION or FIGURE_OR_TABLE node is STALE_PENDING_REVALIDATION; "
    "a node file whose digest differs from its recorded digest is STALE_PENDING_REVALIDATION, and so is "
    "a node whose backing check changed (verifier drift), and every descendant of a pending node"
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
    "A recompute witness is a record supplied to this tool. It is checked against the change (start time, parent "
    "digests, output digest), not re-executed, so it is only as trustworthy as the process that wrote it.",
    "Verifier drift compares each node's declared backing checks with the current manifest and tool version. It "
    "does not re-run the earlier verification, and a check the node does not declare cannot drift.",
)

#: Appended to a node file's bytes by :func:`falsify_dependency_currency`, so
#: the falsified copy always differs from the original.
FALSIFIER_MARK = b"\nscience-gate falsifier: this line changes the file digest\n"

WHAT_IF_DOES_NOT_PROVE = (
    "The what-if reads no node file and writes nothing. Every digest is taken from its record and the injected "
    "digest is synthetic: it exercises the staleness walk and the currency rule on this graph, not the files on "
    "disk. Run verify for their currency.",
    "A PASS shows that a change to this artifact would mark every declared descendant stale and block "
    "publication. A dependency the graph does not declare is outside what it can show.",
    "Descendants that were already pending, or that a person declared SUPERSEDED or INVALIDATED, cannot show "
    "whether the walk reaches them; they are listed, never counted as marked.",
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_WITNESS_ID = re.compile(r"wit-[0-9a-f]{16}")
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
    """What one revalidation did. Only the first two change the node's standing.

    The two REFUSED_*_CUTOFF outcomes are decision D6: a derived node whose
    file is unchanged needs a valid recompute witness. Without one the node
    stays as it was and the refusal is recorded in its history.
    """

    REVALIDATED_UNCHANGED = "REVALIDATED_UNCHANGED"
    REVALIDATED_CHANGED = "REVALIDATED_CHANGED"
    REFUSED_UPSTREAM_PENDING = "REFUSED_UPSTREAM_PENDING"
    REFUSED_VACUOUS_CUTOFF = "REFUSED_VACUOUS_CUTOFF"
    REFUSED_INVALID_WITNESS = "REFUSED_INVALID_WITNESS"
    NO_FILE_TO_HASH = "NO_FILE_TO_HASH"
    FILE_UNAVAILABLE = "FILE_UNAVAILABLE"

    def __str__(self) -> str:
        return str.__str__(self)


class WhatIfOutcome(str, Enum):
    """How one declared descendant came out of a staleness what-if (extension #22).

    Only MARKED shows the walk working: the node was in good standing and the
    injected change made it STALE_PENDING_REVALIDATION. A node that was
    already pending, or whose state a person declared, cannot show whether
    the walk reaches it, because the walk leaves both unchanged by design.
    NOT_MARKED is anything else: a descendant the detector missed.
    """

    MARKED = "MARKED"
    ALREADY_PENDING = "ALREADY_PENDING"
    DECLARED_BY_PERSON = "DECLARED_BY_PERSON"
    NOT_MARKED = "NOT_MARKED"

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


def _required_digest(value: Any, where: str, code: str) -> str:
    """A lowercase hex SHA-256 that may not be null."""
    digest = _digest(value, where, code)
    if digest is None:
        raise GraphError(code, f"{where} must be 64 lowercase hex characters")
    return digest


def _text(value: Any, where: str, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GraphError(code, f"{where} must be a non-empty string")
    return value


def _cause(value: Any, where: str, code: str) -> str:
    """A stale cause: a node id, or ``verifier:<check_id>`` for verifier drift."""
    if isinstance(value, str) and value.startswith(VERIFIER_CAUSE_PREFIX):
        _identifier(value[len(VERIFIER_CAUSE_PREFIX):], where, code)
        return value
    return _identifier(value, where, code)


def _witness_id(value: Any, where: str, code: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _WITNESS_ID.fullmatch(value):
        raise GraphError(code, f"{where} must be null or 'wit-' followed by 16 lowercase hex characters")
    return value


def _stale_cause(value: Any, where: str, code: str) -> StaleCause | None:
    if value is None:
        return None
    try:
        return StaleCause(value)
    except ValueError:
        allowed = [item.value for item in StaleCause]
        raise GraphError(code, f"{where}: {value!r} is not null or one of {allowed}") from None


@dataclass(frozen=True)
class Transition:
    """One change of a node's validity, as appended to its history.

    ``recorded_sha256_before`` and ``recorded_sha256_after`` keep the original
    and the corrected digest side by side. ``observed_sha256`` is the digest
    read from disk when the transition happened, if one was read.
    ``witness_id`` names the recompute witness a revalidation accepted or
    refused. ``cause_category`` says whether a move into (or a refusal to
    leave) STALE_PENDING_REVALIDATION came from data upstream or from the
    verifier; it is null on every other transition.

    A transition whose ``from`` equals its ``to`` records a refused change:
    the refusal is evidence too, so it is kept rather than dropped.
    """

    at: str
    from_state: Validity
    to_state: Validity
    reason: str
    trigger: str | None = None
    recorded_sha256_before: str | None = None
    recorded_sha256_after: str | None = None
    observed_sha256: str | None = None
    witness_id: str | None = None
    cause_category: StaleCause | None = None

    def __post_init__(self) -> None:
        # Reasons can quote diagnostics or declared text, and they are written
        # to graph-state.json and reports, so they are redacted here, once.
        object.__setattr__(self, "reason", redact_text(self.reason))
        if self.cause_category is not None:
            object.__setattr__(self, "cause_category", StaleCause(self.cause_category))

    @property
    def refused(self) -> bool:
        """True for the record of a refused early cutoff (section 17.13)."""
        return self.from_state is self.to_state and self.reason in REFUSED_CUTOFF_REASONS

    @classmethod
    def from_dict(cls, value: Any, where: str, *, code: str, complete: bool) -> Transition:
        """Parse a history entry. ``complete`` requires every key a saved state carries."""
        required = REQUIRED_STATE_TRANSITION_KEYS if complete else REQUIRED_TRANSITION_KEYS
        item = _object(value, where, TRANSITION_KEYS, required, code)
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
            witness_id=_witness_id(item.get("witness_id"), f"{where}.witness_id", code),
            cause_category=_stale_cause(item.get("cause_category"), f"{where}.cause_category", code),
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
            "witness_id": self.witness_id,
            "cause_category": None if self.cause_category is None else self.cause_category.value,
        }


@dataclass(frozen=True)
class BackingCheck:
    """A check whose earlier PASS a node relies on (``backed_by_checks``, extension #5).

    It records the check as it was when that PASS was produced: kind,
    version, params digest (the section 17.4 formula, :func:`params_sha256`)
    and the tool version. When any of them differs from the current manifest
    and tool, the verifier changed beneath the node even though no data did,
    so the node is no longer established (cause category VERIFIER).
    """

    check_id: str
    kind: str
    version: str
    params_sha256: str
    tool_version: str

    def __post_init__(self) -> None:
        where = f"backing check {self.check_id!r}"
        _identifier(self.check_id, f"{where}.check_id", MALFORMED_GRAPH)
        for name in ("kind", "version", "tool_version"):
            _text(getattr(self, name), f"{where}.{name}", MALFORMED_GRAPH)
        _required_digest(self.params_sha256, f"{where}.params_sha256", MALFORMED_GRAPH)

    @classmethod
    def from_dict(cls, value: Any, where: str) -> BackingCheck:
        item = _object(value, where, BACKING_KEYS, BACKING_KEYS, MALFORMED_GRAPH)
        return cls(item["check_id"], item["kind"], item["version"], item["params_sha256"], item["tool_version"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "kind": self.kind,
            "version": self.version,
            "params_sha256": self.params_sha256,
            "tool_version": self.tool_version,
        }


@dataclass(frozen=True)
class Node:
    """A declared artifact, exactly as ``graph.json`` states it.

    Validated on construction, so a Node can never carry an unsafe path, a
    digest with nothing to hash, a history that does not end in its declared
    state, or the same backing check twice.
    """

    node_id: str
    kind: NodeKind
    path: str | None
    recorded_sha256: str | None
    validity: Validity
    history: tuple[Transition, ...] = ()
    backed_by_checks: tuple[BackingCheck, ...] = ()

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
        backing = tuple(sorted(self.backed_by_checks, key=lambda item: item.check_id))
        if any(not isinstance(item, BackingCheck) for item in backing):
            raise GraphError(MALFORMED_GRAPH, f"{where}.backed_by_checks must hold backing checks")
        ids = [item.check_id for item in backing]
        if len(set(ids)) != len(ids):
            raise GraphError(MALFORMED_GRAPH, f"{where}.backed_by_checks names a check twice")
        object.__setattr__(self, "backed_by_checks", backing)

    @property
    def publication(self) -> bool:
        """True for the kinds whose staleness blocks publication."""
        return self.kind in PUBLICATION_KINDS


@dataclass(frozen=True)
class RecomputeWitness:
    """Evidence that a derived node was recomputed after its inputs changed (extension #5, D6).

    A derived node's file is an output. Re-hashing it while it is untouched
    always matches its recorded digest, so a matching digest alone cannot show
    that the node still follows from its changed inputs. A witness names the
    invocation that recomputed the node, when it ran, the parent digests it
    consumed (``inputs``) and the output digest it produced. A revalidation
    accepts it only when all of these bind to the change
    (:meth:`DependencyGraph.witness_problems`).

    The document form is ``science-gate-recompute-witness/v1`` with exactly
    :data:`WITNESS_KEYS`. ``witness_id`` is a content hash of that document,
    so two different witnesses never share an id.
    """

    node_id: str
    invocation_id: str
    started_at: str
    completed_at: str
    inputs: Mapping[str, str]
    output_sha256: str

    def __post_init__(self) -> None:
        code = MALFORMED_WITNESS
        _identifier(self.node_id, "witness node_id", code)
        _identifier(self.invocation_id, "witness invocation_id", code)
        _timestamp(self.started_at, "witness started_at", code)
        _timestamp(self.completed_at, "witness completed_at", code)
        if not isinstance(self.inputs, Mapping):
            raise GraphError(code, "witness inputs must be an object {parent_node_id: sha256}")
        inputs = {
            _identifier(parent, "witness inputs key", code): _required_digest(
                digest, f"witness inputs[{parent!r}]", code
            )
            for parent, digest in self.inputs.items()
        }
        object.__setattr__(self, "inputs", MappingProxyType(dict(sorted(inputs.items()))))
        _required_digest(self.output_sha256, "witness output_sha256", code)

    @classmethod
    def from_document(cls, document: Any) -> RecomputeWitness:
        """Validate a parsed witness document: exactly :data:`WITNESS_KEYS` and the right schema."""
        item = _object(document, "recompute witness", WITNESS_KEYS, WITNESS_KEYS, MALFORMED_WITNESS)
        if item["schema"] != WITNESS_SCHEMA:
            raise GraphError(MALFORMED_WITNESS, f"schema must be {WITNESS_SCHEMA!r}, got {item['schema']!r}")
        return cls(
            node_id=item["node_id"],
            invocation_id=item["invocation_id"],
            started_at=item["started_at"],
            completed_at=item["completed_at"],
            inputs=item["inputs"],
            output_sha256=item["output_sha256"],
        )

    @property
    def witness_id(self) -> str:
        """``wit-`` plus the first 16 hex of the document's canonical SHA-256 (D11)."""
        return "wit-" + sha256_canonical(self.to_dict())[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": WITNESS_SCHEMA,
            "node_id": self.node_id,
            "invocation_id": self.invocation_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "inputs": dict(self.inputs),
            "output_sha256": self.output_sha256,
        }


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
    """The result of :meth:`DependencyGraph.revalidate`.

    ``witness`` describes the recompute witness that was supplied, if any:
    its id, whether the rule for this node consulted it (only a derived node
    with an unchanged file needs one), and every problem found with it.
    """

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
    witness: Mapping[str, Any] | None = None

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
            "witness": None if self.witness is None else dict(self.witness),
            "pending_ancestors": list(self.pending_ancestors),
            "cleared": [item.to_dict() for item in self.cleared],
            "still_pending": [item.to_dict() for item in self.still_pending],
            "transitions": _journal_dicts(self.transitions),
        }


@dataclass(frozen=True)
class DriftEntry:
    """One backing check of one node that no longer matches the current verifier.

    ``differences`` maps each differing field of :data:`DRIFT_FIELDS` to
    ``{recorded, current}``. A check the manifest no longer declares is the
    single difference ``check_id: {recorded: <id>, current: null}``.
    """

    node_id: str
    check_id: str
    differences: Mapping[str, Mapping[str, str | None]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": self.node_id,
            "check_id": self.check_id,
            "differences": {name: dict(values) for name, values in sorted(self.differences.items())},
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

    def stale_categories(self, node_id: str) -> tuple[StaleCause, ...]:
        """Why ``node_id`` is pending, by category: UPSTREAM data, the VERIFIER, or both.

        Empty for a node in good standing or declared by a person.
        """
        self.require(node_id)
        return self._category_table()[node_id]

    def _category_table(self) -> dict[str, tuple[StaleCause, ...]]:
        """The categories of every pending node, derived from the recorded causes.

        A ``verifier:`` cause is VERIFIER. The node's own id, or a parent that
        is no longer pending (its change was recorded), is UPSTREAM. A parent
        that is still pending passes on its own categories, so a descendant of
        a drifted node is VERIFIER too. Parents come first in topological
        order, so each node's parents are settled before it. A cause that is
        not an earlier node (a saved state can name a parent whose edge has
        since been removed) counts as UPSTREAM.
        """
        table: dict[str, tuple[StaleCause, ...]] = {}
        for node_id in self._order:
            state = self._state[node_id]
            found: set[StaleCause] = set()
            if state.validity in PENDING_STATES:
                for cause in state.stale_because:
                    if cause.startswith(VERIFIER_CAUSE_PREFIX):
                        found.add(StaleCause.VERIFIER)
                    elif cause in table and self._state[cause].validity in PENDING_STATES:
                        found.update(table[cause] or (StaleCause.UPSTREAM,))
                    else:
                        found.add(StaleCause.UPSTREAM)
            table[node_id] = tuple(sorted(found, key=lambda item: item.value))
        return table

    def node_view(
        self,
        node_id: str,
        *,
        with_history: bool = False,
        categories: Mapping[str, tuple[StaleCause, ...]] | None = None,
    ) -> dict[str, Any]:
        """One node's declaration and current state, JSON-safe."""
        node = self.require(node_id)
        state = self._state[node_id]
        table = self._category_table() if categories is None else categories
        view: dict[str, Any] = {
            "id": node.node_id,
            "kind": node.kind.value,
            "path": node.path,
            "publication_node": node.publication,
            "validity": state.validity.value,
            "recorded_sha256": state.recorded_sha256,
            "stale_because": sorted(state.stale_because),
            "stale_categories": [item.value for item in table[node_id]],
            "backed_by_checks": [item.to_dict() for item in node.backed_by_checks],
        }
        if with_history:
            view["history"] = [entry.to_dict() for entry in self.history(node_id)]
        return view

    def node_table(self, *, with_history: bool = False) -> list[dict[str, Any]]:
        categories = self._category_table()
        return [self.node_view(node_id, with_history=with_history, categories=categories) for node_id in self._nodes]

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
        stale_because = {_cause(cause, f"{where}.stale_because", code) for cause in causes}
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
        witness_id: str | None = None,
        cause_category: StaleCause | None = None,
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
            witness_id=witness_id,
            cause_category=cause_category,
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

    def _mark_descendants(
        self, origin: str, event: str, at: str, *, category: StaleCause = StaleCause.UPSTREAM
    ) -> tuple[DescendantImpact, ...]:
        """Mark every descendant of ``origin`` STALE_PENDING_REVALIDATION, recording causes.

        Every edge inside the affected subgraph adds its parent to the child's
        ``stale_because``, so a node reached along two paths needs both
        upstream nodes cleared before early cutoff can clear it. Descendants
        that are already pending, or whose state was declared by a person,
        keep their state. ``category`` says whether the origin's data or its
        verifier changed.
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
                self._transition(node_id, _STALE, reason, at=at, trigger=origin, cause_category=category)
            node = self._nodes[node_id]
            impacts.append(DescendantImpact(node_id, node.kind, depth, route, prior, self._state[node_id].validity))
        return tuple(impacts)

    def _prior_to_stale(self, node_id: str) -> Validity | None:
        """The state a node had just before it last went stale, if that was a good standing.

        A refused cutoff (STALE to STALE) is not a move into staleness, so it
        is skipped: it must not hide the state the node is to return to.
        """
        for entry in reversed(self.history(node_id)):
            if entry.to_state is _STALE and entry.from_state is not _STALE:
                return entry.from_state if entry.from_state in GOOD_STANDING_STATES else None
        return None

    def pending_since(self, node_id: str) -> Transition | None:
        """The transition that last made ``node_id`` pending (STALE_PENDING_REVALIDATION or UNRESOLVED).

        This is when the change a recompute must follow was recorded. None
        when no recorded transition made the node pending, for example a node
        declared pending in graph.json without a history.
        """
        for entry in reversed(self.history(node_id)):
            if entry.to_state in PENDING_STATES and entry.from_state is not entry.to_state:
                return entry
        return None

    def refused_cutoff_since_pending(self, node_id: str) -> bool:
        """True when a cutoff of ``node_id`` was refused after it last became pending."""
        for entry in reversed(self.history(node_id)):
            if entry.refused:
                return True
            if entry.to_state in PENDING_STATES and entry.from_state is not entry.to_state:
                return False
        return False

    def witness_problems(self, node_id: str, witness: RecomputeWitness) -> tuple[str, ...]:
        """Every reason ``witness`` cannot show that ``node_id`` was recomputed after its change.

        Empty means the witness binds. It must name this node; start no
        earlier than the change (strictly after the transition that last made
        the node pending) and finish no earlier than it starts; list each
        stale-causing parent at that parent's current recorded digest (every
        parent with a recorded digest when the node is pending on its own
        account); list nothing but parents, each at its current digest; and
        have produced exactly the node's recorded digest. Each problem is a
        line starting with a stable code.
        """
        state = self._state[self.require(node_id).node_id]
        problems: list[str] = []
        if witness.node_id != node_id:
            problems.append(f"WITNESS_FOR_OTHER_NODE: the witness recomputed {witness.node_id!r}, not {node_id!r}")
        started, completed = parse_utc(witness.started_at), parse_utc(witness.completed_at)
        if started > completed:
            problems.append(
                f"IMPOSSIBLE_TIMELINE: the recompute started at {witness.started_at}, after it completed at "
                f"{witness.completed_at}"
            )
        since = self.pending_since(node_id)
        if since is None:
            if state.validity in PENDING_STATES:
                problems.append(
                    f"NO_RECORDED_CHANGE: {node_id!r} has no recorded transition into {state.validity.value}, so no "
                    "recompute can be shown to follow the change"
                )
        elif started <= parse_utc(since.at):
            problems.append(
                f"WITNESS_PREDATES_CHANGE: the recompute started at {witness.started_at}, not after the change "
                f"recorded at {since.at}"
            )
        parents = self._parents[node_id]
        causes = sorted(cause for cause in state.stale_because if cause in parents)
        required = causes or [parent for parent in parents if self._state[parent].recorded_sha256 is not None]
        for parent in required:
            if parent not in witness.inputs:
                problems.append(f"MISSING_INPUT: the witness does not list parent {parent!r}")
        for parent, digest in witness.inputs.items():
            recorded = self._state[parent].recorded_sha256 if parent in parents else None
            if parent not in parents:
                problems.append(f"NOT_A_PARENT: the witness lists {parent!r}, which is not a parent of {node_id!r}")
            elif recorded is None:
                problems.append(f"UNBOUND_INPUT: parent {parent!r} has no recorded digest the witness could match")
            elif digest != recorded:
                problems.append(
                    f"STALE_INPUT: the recompute consumed {parent!r} at {digest}, but its current recorded digest "
                    f"is {recorded}"
                )
        if witness.output_sha256 != state.recorded_sha256:
            problems.append(
                f"OUTPUT_MISMATCH: the recompute produced {witness.output_sha256}, but {node_id!r} is recorded as "
                f"{state.recorded_sha256}"
            )
        return tuple(problems)

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
                    self._transition(
                        node_id, _STALE, reason, at=at, trigger=node_id, observed_sha256=seen.sha256,
                        cause_category=StaleCause.UPSTREAM,
                    )
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
        categories = self._category_table()
        for node_id in self._order:
            validity = self._state[node_id].validity
            if node_id not in covered and validity in PENDING_STATES:
                covered.add(node_id)
                # A node pending only for verifier reasons passes that category on.
                only_verifier = categories[node_id] == (StaleCause.VERIFIER,)
                category = StaleCause.VERIFIER if only_verifier else StaleCause.UPSTREAM
                walk = self._mark_descendants(node_id, f"is {validity.value}", at, category=category)
                covered.update(item.node_id for item in walk)
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
            self._transition(
                artifact_id, _STALE, reason, at=at, trigger=artifact_id, cause_category=StaleCause.UPSTREAM
            )
        if state.validity is _STALE:
            state.stale_because.add(artifact_id)
        descendants = self._mark_descendants(artifact_id, "was declared changed", at)
        return Impact(artifact_id, node.kind, prior, state.validity, descendants, tuple(self._journal[start:]))

    def revalidate(
        self,
        artifact_id: str,
        observe: Observer | None = None,
        *,
        at: str | None = None,
        witness: RecomputeWitness | None = None,
    ) -> Revalidation:
        """Re-hash ``artifact_id`` and settle it as REVALIDATED_UNCHANGED or REVALIDATED_CHANGED.

        Refused (state untouched) while any ancestor is pending, and for a
        node without a file. An unreadable file makes the node UNRESOLVED and
        its descendants pending. A changed digest is recorded as
        REVALIDATED_CHANGED for every node.

        An unchanged digest settles a root node by itself. A derived node (one
        with at least one parent) also needs ``witness``, a recompute that
        binds to the change (:meth:`witness_problems`), because re-hashing an
        untouched output always matches (D6). Without one the outcome is
        REFUSED_VACUOUS_CUTOFF; with an invalid one, REFUSED_INVALID_WITNESS.
        Either way the node keeps its state, nothing downstream is cleared,
        and the refusal is appended to its history.
        """
        node = self.require(artifact_id)
        observe = self._observer(observe)
        at = at or now()
        start = len(self._journal)
        state = self._state[artifact_id]
        prior, before = state.validity, state.recorded_sha256
        derived = bool(self._parents[artifact_id])

        def witness_view(*, consulted: bool, problems: Sequence[str] = ()) -> dict[str, Any] | None:
            if witness is None:
                return None
            return {
                "witness_id": witness.witness_id,
                "node_id": witness.node_id,
                "invocation_id": witness.invocation_id,
                "started_at": witness.started_at,
                "completed_at": witness.completed_at,
                "consulted": consulted,
                "problems": list(problems),
            }

        def result(outcome: RevalidationOutcome, **extra: Any) -> Revalidation:
            values: dict[str, Any] = {
                "observed_sha256": None,
                "diagnostic": None,
                "pending_ancestors": (),
                "cleared": (),
                "still_pending": (),
                "witness": witness_view(consulted=False),
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
        if seen.sha256 == before and derived:
            problems = () if witness is None else self.witness_problems(artifact_id, witness)
            if witness is None or problems:
                # The refusal is evidence too: it is recorded, the node keeps
                # its state, and nothing downstream is cleared.
                since = self.pending_since(artifact_id)
                category = since.cause_category if since is not None and prior in PENDING_STATES else None
                self._transition(
                    artifact_id, prior, VACUOUS_CUTOFF_REASON if witness is None else INVALID_WITNESS_REASON,
                    at=at, trigger=artifact_id, observed_sha256=seen.sha256,
                    witness_id=None if witness is None else witness.witness_id, cause_category=category,
                )
                if witness is None:
                    outcome = RevalidationOutcome.REFUSED_VACUOUS_CUTOFF
                    diagnostic = (
                        f"VACUOUS_CUTOFF: {artifact_id!r} is derived from {_names(self._parents[artifact_id])}; its "
                        "file is unchanged, but re-hashing an untouched output always matches, so a recompute "
                        "witness that started after the change is needed"
                    )
                else:
                    outcome = RevalidationOutcome.REFUSED_INVALID_WITNESS
                    diagnostic = f"INVALID_WITNESS: {witness.witness_id} was refused: " + "; ".join(problems)
                return result(
                    outcome,
                    observed_sha256=seen.sha256,
                    diagnostic=diagnostic,
                    witness=witness_view(consulted=True, problems=problems),
                )
            reason = (
                f"REVALIDATED: the file digest equals the recorded digest, and recompute witness "
                f"{witness.witness_id} (invocation {witness.invocation_id}) reproduced it after the change"
            )
            self._transition(
                artifact_id, Validity.REVALIDATED_UNCHANGED, reason, at=at, trigger=artifact_id,
                observed_sha256=seen.sha256, witness_id=witness.witness_id,
            )
            state.stale_because.clear()
            cleared = self._cutoff(artifact_id, at)
            return result(
                RevalidationOutcome.REVALIDATED_UNCHANGED,
                observed_sha256=seen.sha256,
                cleared=cleared,
                witness=witness_view(consulted=True),
            )
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
        # Each direct child consumed the old content, so it now needs its own
        # revalidation (a witnessed recompute, when it is derived). Without
        # its own cause, a later declared impact on this node followed by an
        # unchanged re-hash would clear the child by early cutoff and launder
        # this real change without any recompute (D6).
        for child in self._children[artifact_id]:
            if self._state[child].validity is _STALE:
                self._state[child].stale_because.add(child)
        return result(RevalidationOutcome.REVALIDATED_CHANGED, observed_sha256=seen.sha256, still_pending=still)

    def mark_verifier_drift(
        self, drift: Iterable[DriftEntry], *, at: str | None = None
    ) -> tuple[tuple[str, Transition], ...]:
        """Mark each drifted node and its descendants STALE_PENDING_REVALIDATION, cause category VERIFIER.

        A drifted node gains the cause ``verifier:<check_id>`` for each of its
        drifted checks. Early cutoff never removes such a cause, so only a
        fresh declaration (re-recording the backing check after re-running
        it) can clear it. States declared by people and already-pending
        states are kept, as in every walk. Returns the transitions made.
        """
        at = at or now()
        start = len(self._journal)
        drifted: dict[str, set[str]] = {}
        for entry in drift:
            drifted.setdefault(self.require(entry.node_id).node_id, set()).add(entry.check_id)
        for node_id in self._order:
            if node_id not in drifted:
                continue
            checks = sorted(drifted[node_id])
            listed = _names(checks)
            state = self._state[node_id]
            if state.validity in GOOD_STANDING_STATES:
                reason = (
                    f"VERIFIER_DRIFT: backing check(s) {listed} differ from the current manifest or tool version, "
                    "or are no longer declared, so the PASS this node relied on no longer stands for the "
                    "current verifier"
                )
                self._transition(node_id, _STALE, reason, at=at, trigger=node_id, cause_category=StaleCause.VERIFIER)
            if state.validity is _STALE:
                state.stale_because.update(VERIFIER_CAUSE_PREFIX + check_id for check_id in checks)
            self._mark_descendants(
                node_id, f"is backed by drifted check(s) {listed}", at, category=StaleCause.VERIFIER
            )
        return tuple(self._journal[start:])


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
        backing = entry.get("backed_by_checks", [])
        if not isinstance(backing, list):
            raise GraphError(MALFORMED_GRAPH, f"{where}.backed_by_checks must be a list")
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
                backed_by_checks=tuple(
                    BackingCheck.from_dict(value, f"{where}.backed_by_checks[{number}]")
                    for number, value in enumerate(backing)
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


def open_graph(manifest_path: str | Path) -> DependencyGraph:
    """Load the dependency graph a manifest declares, with its saved state (for the commands).

    Raises :class:`GraphError`: INVALID_MANIFEST, NO_GRAPH_DECLARED, or any
    code :func:`load_graph` raises.
    """
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        raise GraphError(INVALID_MANIFEST, f"invalid manifest ({', '.join(exc.codes)}): {exc}") from None
    if manifest.dependencies is None:
        raise GraphError(NO_GRAPH_DECLARED, "the manifest declares no 'dependencies' graph")
    return load_graph(manifest.root, manifest.dependencies, max_bytes=manifest.limits.max_file_bytes)


def load_witness(
    root: str | Path, relpath: str, *, max_bytes: int = DEFAULT_LIMITS["max_file_bytes"]
) -> RecomputeWitness:
    """Read and validate the recompute witness at ``relpath`` under ``root``.

    The read is confined to ``root`` like every other read. Raises
    :class:`GraphError`: WITNESS_UNAVAILABLE (missing, refused or unreadable),
    MALFORMED_WITNESS (not strict JSON, or not a valid witness document) or
    UNSAFE_PATH.
    """
    try:
        clean = normalize_relpath(relpath)
    except UnsafePathError as exc:
        raise GraphError(UNSAFE_PATH, f"witness path: {exc}") from None
    try:
        document, _ = _read_json(
            Path(root), clean, max_bytes, unavailable=WITNESS_UNAVAILABLE, malformed=MALFORMED_WITNESS
        )
    except FileNotFoundError:
        raise GraphError(WITNESS_UNAVAILABLE, f"no witness file at {clean}") from None
    return RecomputeWitness.from_document(document)


# ---------------------------------------------------------------------------
# Verifier drift: the check behind a node changed, not its data
# ---------------------------------------------------------------------------


def params_sha256(spec: CheckSpec) -> str:
    """The digest of a check's params, by the formula every module uses (section 17.4)."""
    return sha256_canonical(dict(spec.params))


def verifier_drift(
    graph: DependencyGraph, checks: Iterable[CheckSpec], *, tool_version: str = __version__
) -> tuple[DriftEntry, ...]:
    """Every backing check of every node that differs from ``checks`` and ``tool_version``.

    A node's ``backed_by_checks`` records each check as it was when its PASS
    was produced. When the current manifest gives that check another kind,
    version or params digest, the tool version differs, or the check is gone,
    the earlier PASS no longer speaks for the current verifier. Pure: nothing
    is marked here (see :meth:`DependencyGraph.mark_verifier_drift`).
    """
    current = {spec.check_id: spec for spec in checks}
    found: list[DriftEntry] = []
    for node in graph.nodes:
        for backing in node.backed_by_checks:
            spec = current.get(backing.check_id)
            differences: dict[str, dict[str, str | None]]
            if spec is None:
                differences = {"check_id": {"recorded": backing.check_id, "current": None}}
            else:
                now_values = {
                    "kind": spec.kind,
                    "version": spec.version,
                    "params_sha256": params_sha256(spec),
                    "tool_version": tool_version,
                }
                differences = {
                    name: {"recorded": getattr(backing, name), "current": now_values[name]}
                    for name in DRIFT_FIELDS
                    if getattr(backing, name) != now_values[name]
                }
            if differences:
                found.append(DriftEntry(node.node_id, backing.check_id, MappingProxyType(differences)))
    return tuple(found)


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
    states declared by people) is ABSTAIN. None of it is a PASS. A pending
    publication node whose cutoff was refused since it last became pending
    adds the failure mode VACUOUS_CUTOFF: someone tried to clear it by
    re-hashing (or with a witness that did not bind) instead of recomputing.
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
    refused = ids(
        lambda node: node.publication
        and validity[node.node_id] in PENDING_STATES
        and graph.refused_cutoff_since_pending(node.node_id)
    )

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
    if refused:
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (FailureMode.VACUOUS_CUTOFF,),
                f"publication node(s) {_names(refused)} stay pending after a refused early cutoff: an untouched "
                "derived file was re-hashed, or a recompute witness did not bind to the change, instead of a "
                "recompute being witnessed",
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
    execution_state: ExecutionState,
    verdict: Status,
    reason: Reason,
    diagnostic: str,
    evidence: Mapping[str, Any],
    *,
    justification: SkipJustification | None,
) -> CheckOutcome:
    """An outcome for a graph that could not be judged: never PASS, and no node examined.

    An ABSTAIN must name its closed-vocabulary ``justification`` (extension
    #24, section 17.7): free text never explains a skip. An ERROR carries
    none, because its own ERROR decides the run.
    """
    if (verdict is Status.ERROR) != (justification is None):
        raise ValueError("an unexamined ABSTAIN needs a SkipJustification, and an ERROR takes none")
    labelled = dict(evidence)
    if justification is not None:
        labelled[SKIP_JUSTIFICATION_KEY] = justification
    return CheckOutcome(
        execution_state=execution_state,
        verdict=verdict,
        reason=reason,
        rows_examined=0,
        evidence=labelled,
        diagnostics=(diagnostic,),
    )


def _graph_error_outcome(error: GraphError, evidence: dict[str, Any]) -> CheckOutcome:
    """A cycle or an unsafe path is ERROR (the declaration is unusable); other defects ABSTAIN."""
    evidence["error"] = error.to_dict()
    if error.code in _DECLARATION_ERRORS:
        return _unexamined(
            ExecutionState.SKIPPED, Status.ERROR, Reason.PROTOCOL_BROKEN, str(error), evidence, justification=None
        )
    path = evidence["graph"]["path"]
    diagnostic = f"MALFORMED_DOCUMENT: dependencies ({path}): {error}"
    return _unexamined(
        ExecutionState.SKIPPED,
        Status.ABSTAIN,
        Reason.PROTOCOL_BROKEN,
        diagnostic,
        evidence,
        justification=SkipJustification.EVIDENCE_MALFORMED,
    )


def _state_outcome(state: Document, evidence: dict[str, Any]) -> CheckOutcome:
    """A graph-state.json that exists but cannot be used is never ignored.

    Ignoring it would silently drop its stale marks, which is exactly how a
    blocked publication could be made to look current.
    """
    diagnostic = (
        f"{STATE_UNAVAILABLE}: {state.path} exists but is {state.state}: {state.diagnostic}; "
        "a saved graph state is never ignored"
    )
    return _unexamined(
        ExecutionState.SKIPPED,
        Status.ABSTAIN,
        Reason.PROTOCOL_BROKEN,
        diagnostic,
        evidence,
        justification=SkipJustification.EVIDENCE_MALFORMED,
    )


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


def _drift_evidence(graph: DependencyGraph, drift: Sequence[DriftEntry]) -> dict[str, Any]:
    """What the verifier-drift comparison looked at and found.

    The backing counts are always shown, so an empty ``verifier_drift`` from
    a graph that declares no backing checks cannot read as "no drift found".
    """
    backed = [node for node in graph.nodes if node.backed_by_checks]
    by_node: dict[str, list[str]] = {}
    for entry in drift:
        by_node.setdefault(entry.node_id, []).append(entry.check_id)
    return {
        "verifier_backing": {
            "nodes": len(backed),
            "entries": sum(len(node.backed_by_checks) for node in backed),
            "tool_version": __version__,
        },
        "verifier_drift": {node_id: sorted(ids) for node_id, ids in sorted(by_node.items())},
        "verifier_drift_detail": _first([entry.to_dict() for entry in drift]),
    }


def check_dependency_currency(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Publication is blocked by stale dependencies (kind ``dependency_currency``).

    Reads the manifest's ``dependencies`` graph and the ``graph-state.json``
    beside it, hashes every node file through the check context (so each
    one is in the evidence manifest), runs detection in memory, compares
    every node's ``backed_by_checks`` with the manifest's checks and the tool
    version (verifier drift), and judges the result with :func:`assess`. It
    never writes. A cycle or an unsafe node path is ERROR. A malformed graph
    or state is ABSTAIN with PROTOCOL_BROKEN. A stale CONCLUSION or
    FIGURE_OR_TABLE is FAIL with STALE_DEPENDENCY.
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
            justification=SkipJustification.NOT_DECLARED,
        )
    if not document.loaded:
        malformed = document.state is InputState.PARSE_ERROR
        diagnostic = f"dependencies ({document.path}) unavailable: {document.diagnostic or document.state}"
        return _unexamined(
            ExecutionState.SKIPPED,
            Status.ABSTAIN,
            Reason.PROTOCOL_BROKEN if malformed else Reason.INSUFFICIENT_EVIDENCE,
            diagnostic,
            evidence,
            justification=SkipJustification.EVIDENCE_MALFORMED if malformed else SkipJustification.INPUT_UNAVAILABLE,
        )
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
            return _unexamined(
                ExecutionState.SKIPPED,
                Status.ABSTAIN,
                Reason.PROTOCOL_BROKEN,
                f"{exc}; a saved graph state is never ignored",
                evidence,
                justification=SkipJustification.EVIDENCE_MALFORMED,
            )
    if not graph.nodes:
        return _unexamined(
            ExecutionState.NOT_APPLICABLE,
            Status.ABSTAIN,
            Reason.INSUFFICIENT_EVIDENCE,
            "the dependencies graph declares no nodes",
            evidence,
            justification=SkipJustification.EMPTY_POPULATION,
        )
    at = now()
    detection = graph.detect_changes(_context_observer(ctx), at=at)
    drift = verifier_drift(graph, ctx.manifest.checks)
    drift_transitions = graph.mark_verifier_drift(drift, at=at)
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
            "transitions_in_memory": len(detection.transitions) + len(drift_transitions),
            **_drift_evidence(graph, drift),
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


def _falsifier_target(graph: DependencyGraph) -> tuple[Node, str] | None:
    """The node whose file a falsifier changes, and the case id.

    A publication node's own file is the direct case (section 17.5). A graph
    whose publication nodes have no file still has a known-bad case: change a
    file-backed node upstream of one. Only nodes in good standing with a
    recorded digest qualify, so the change is one the check must detect.
    """
    candidates = [
        node
        for node in graph.nodes
        if node.path is not None
        and graph.recorded_sha256(node.node_id) is not None
        and graph.validity(node.node_id) in GOOD_STANDING_STATES
    ]
    for node in candidates:
        if node.publication:
            return node, "change-publication-file"
    for node in candidates:
        if any(graph.require(item).publication for item in graph.descendants(node.node_id)):
            return node, "change-upstream-file"
    return None


def falsify_dependency_currency(
    ctx: CheckContext, spec: CheckSpec, result: CheckResult
) -> tuple[FalsifierCase, ...]:
    """A known-bad case for a ``dependency_currency`` PASS (falsifier generator, section 17.5).

    The case gives one node file different bytes (the original plus
    :data:`FALSIFIER_MARK`), so its digest no longer equals the recorded one.
    A working currency check must then find a publication node stale and
    FAIL with SOURCE_MISMATCH; one that still passes is blind to the very
    change it exists to catch. The case depends only on the graph and files
    the context serves (``spec`` and ``result`` are part of the generator
    signature). It reads only through ``ctx`` and writes nothing. ``()`` when
    no file-backed node reaches a publication node, or the graph or saved
    state cannot be used (the check would not have passed then).
    """
    document = ctx.role_document("dependencies")
    if not document.loaded:
        return ()
    try:
        graph = parse_graph(
            document.content,
            graph_path=document.path,
            graph_sha256=document.sha256,
            root=ctx.root,
            max_bytes=ctx.limits.max_file_bytes,
        )
        state = ctx.read_document(graph.state_path, role=STATE_ROLE, parse="json")
        if state.state is not InputState.MISSING:
            if not state.loaded:
                return ()
            graph.apply_state(state.content, sha256=state.sha256)
    except GraphError:
        return ()
    target = _falsifier_target(graph)
    if target is None:
        return ()
    node, case_id = target
    current = ctx.read_document(node.path, role=NODE_ROLE, parse="bytes")
    if current.content is None:
        return ()
    return (
        FalsifierCase(
            case_id=case_id,
            description=(
                f"the file of {node.kind.value} node {node.node_id!r} ({node.path}) gets different bytes, so its "
                "digest no longer equals the recorded digest and a publication node must go stale"
            ),
            expected_verdict=Status.FAIL,
            expected_reason=Reason.SOURCE_MISMATCH,
            documents={node.path: current.content + FALSIFIER_MARK},
        ),
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
    elif result.outcome is RevalidationOutcome.REFUSED_VACUOUS_CUTOFF:
        detail = f"{result.diagnostic}; it stays {result.state.value}"
        return (CurrencyFinding(Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.VACUOUS_CUTOFF,), detail),)
    elif result.outcome is RevalidationOutcome.REFUSED_INVALID_WITNESS:
        detail = f"{result.diagnostic}; {node_id!r} stays {result.state.value}"
        return (CurrencyFinding(Status.ABSTAIN, Reason.UNVERIFIED, (FailureMode.VACUOUS_CUTOFF,), detail),)
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
    witness = action["witness"]
    if witness is None:
        lines.append("- recompute witness: none supplied")
    else:
        use = "consulted" if witness["consulted"] else "not consulted (this node revalidates without one)"
        lines.append(
            f"- recompute witness: {_code(witness['witness_id'])} for {_code(witness['node_id'])}, invocation "
            f"{_code(witness['invocation_id'])}, {witness['started_at']} to {witness['completed_at']}; {use}"
        )
        lines += [f"  - refused: {_cell(problem)}" for problem in witness["problems"]]
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
            ", ".join(item["stale_categories"]) or "-",
            str(len(item["history"])),
        ]
        for item in report["nodes"]
    ]
    headers = ("node", "kind", "validity", "recorded", "stale because", "cause category", "history entries")
    lines += _table(headers, rows, "No nodes.")
    lines += ["", "## WHAT THIS DOES NOT PROVE", ""]
    lines += [f"- {item}" for item in report["does_not_prove"]]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# What-if: mutation-testing the staleness detector (extension #22)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WhatIfDescendant:
    """One declared descendant of the what-if's artifact, before and after the injected change."""

    node_id: str
    kind: NodeKind
    publication_node: bool
    prior_state: Validity
    state: Validity
    outcome: WhatIfOutcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind.value,
            "publication_node": self.publication_node,
            "prior_state": self.prior_state.value,
            "state": self.state.value,
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True)
class WhatIfReport:
    """The result of :func:`what_if` (``science-gate-what-if/v1``).

    ``injection`` and ``assessment`` are None when the artifact has no
    declared descendant, because nothing was injected then.
    """

    artifact_id: str
    kind: NodeKind
    at: str
    status: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...]
    execution_state: ExecutionState
    findings: tuple[CurrencyFinding, ...]
    injection: Mapping[str, Any] | None
    graph: Mapping[str, Any]
    state: Mapping[str, Any]
    descendants: tuple[WhatIfDescendant, ...]
    assessment: Mapping[str, Any] | None
    transitions: tuple[tuple[str, Transition], ...]

    def counts(self) -> dict[str, int]:
        """How many declared descendants ended in each :class:`WhatIfOutcome`."""
        counts = {"declared_descendants": len(self.descendants)}
        counts.update({item.value: sum(1 for d in self.descendants if d.outcome is item) for item in WhatIfOutcome})
        return counts

    def body(self) -> dict[str, Any]:
        """Every field but the id, JSON-safe and redacted: what the id is computed over."""
        return redact(
            {
                "schema": WHAT_IF_SCHEMA,
                "artifact": {"id": self.artifact_id, "kind": self.kind.value},
                "at": self.at,
                "status": self.status.value,
                "reason": self.reason.value,
                "failure_modes": [mode.value for mode in self.failure_modes],
                "execution_state": self.execution_state.value,
                "findings": [finding.to_dict() for finding in self.findings],
                "injection": None if self.injection is None else dict(self.injection),
                "graph": dict(self.graph),
                "state": dict(self.state),
                "descendants": [item.to_dict() for item in self.descendants],
                "counts": self.counts(),
                "assessment": None if self.assessment is None else dict(self.assessment),
                "transitions": _journal_dicts(self.transitions),
                "does_not_prove": list(WHAT_IF_DOES_NOT_PROVE),
            }
        )

    @property
    def what_if_id(self) -> str:
        """``wif-`` plus 16 hex of the canonical digest of :meth:`body` (D11)."""
        return "wif-" + sha256_canonical(self.body())[:16]

    def to_dict(self) -> dict[str, Any]:
        return {"what_if_id": self.what_if_id, **self.body()}


def _declared_descendants(edges: Iterable[tuple[str, str]], origin: str) -> tuple[str, ...]:
    """Every node reachable from ``origin`` along the declared edges, sorted.

    Computed straight from the edge list, deliberately not through the walk
    under test, so a defect in the walk cannot also shrink what it is judged
    against.
    """
    pairs = tuple(edges)
    reached: set[str] = set()
    frontier = {origin}
    while frontier:
        frontier = {child for parent, child in pairs if parent in frontier and child not in reached}
        reached |= frontier
    reached.discard(origin)
    return tuple(sorted(reached))


def _unread_observer(digests: Mapping[str, str | None]) -> Observer:
    """An observer that reads no file: each path yields the digest given for it.

    A path with no digest yields a fixed placeholder, so a node without a
    recorded digest compares as NO_BASELINE rather than as an unreadable file.
    """

    def observe(relpath: str) -> Observation:
        digest = digests.get(relpath)
        if digest is None:
            digest = sha256_bytes(b"science-gate what-if: no recorded digest for " + relpath.encode("utf-8"))
        return Observation(InputState.PARSED, digest)

    return observe


def _what_if_outcome(prior: Validity, after: Validity) -> WhatIfOutcome:
    if prior in GOOD_STANDING_STATES and after is _STALE:
        return WhatIfOutcome.MARKED
    if prior in PENDING_STATES and after in PENDING_STATES:
        return WhatIfOutcome.ALREADY_PENDING
    if prior in HUMAN_DECLARED_STATES and after is prior:
        return WhatIfOutcome.DECLARED_BY_PERSON
    return WhatIfOutcome.NOT_MARKED


def _inject_change(
    graph: DependencyGraph, node: Node, recorded: Mapping[str, str | None], at: str
) -> tuple[dict[str, Any], tuple[tuple[str, Transition], ...], Detection]:
    """Give ``node`` a synthetic change and let detection walk from it.

    A node with a file and a recorded digest gets a synthetic digest, so the
    change travels the same detection path a real edit would. A node with no
    file or no recorded digest has no digest to change, so it is declared
    changed through :meth:`DependencyGraph.impact` instead.
    """
    digest = graph.recorded_sha256(node.node_id)
    injection: dict[str, Any] = {"node": node.node_id, "path": node.path, "recorded_sha256": digest}
    if node.path is not None and digest is not None:
        injected = sha256_bytes(b"science-gate what-if: injected change of " + digest.encode("ascii"))
        detection = graph.detect_changes(_unread_observer({**recorded, node.path: injected}), at=at)
        return {**injection, "mode": "digest", "injected_sha256": injected}, detection.transitions, detection
    impact = graph.impact(node.node_id, at=at)
    detection = graph.detect_changes(_unread_observer(recorded), at=at)
    transitions = (*impact.transitions, *detection.transitions)
    return {**injection, "mode": "declared_change", "injected_sha256": None}, transitions, detection


def what_if(manifest_path: str | Path, artifact_id: str, *, at: str | None = None) -> WhatIfReport:
    """Mutation-test the staleness detector on one artifact (extension #22). Writes nothing.

    On the manifest's graph and saved state, in memory, every node is first
    taken at its recorded digest (no file is read), so the injected change is
    the only one. Then ``artifact_id`` gets a synthetic digest change and
    detection walks from it. The result is:

    * PASS when every declared descendant (computed from the edges, not by
      the walk) went from good standing to STALE_PENDING_REVALIDATION, or was
      pending or declared by a person already, at least one was marked, and,
      when a publication node is among them, the currency assessment FAILs
      and names every stale one.
    * FAIL / BLIND_SPOT when a descendant was missed, or the assessment would
      not block a stale publication descendant: the detector is vacuous there.
    * ABSTAIN / INSUFFICIENT_EVIDENCE with VACUOUS_PASS when no descendant was
      in good standing before, so the walk could not show anything.
    * NOT_APPLICABLE, ABSTAIN / INSUFFICIENT_EVIDENCE, when the artifact has
      no declared descendant.

    Raises :class:`GraphError` as :func:`open_graph` does, and
    UNKNOWN_ARTIFACT.
    """
    graph = open_graph(manifest_path)
    node = graph.require(artifact_id)
    at = at or now()
    common: dict[str, Any] = {
        "artifact_id": artifact_id,
        "kind": node.kind,
        "at": at,
        "graph": {"path": graph.graph_path, "sha256": graph.graph_sha256},
        "state": graph.state_info.to_dict(),
    }
    declared = _declared_descendants(graph.edges, artifact_id)
    if not declared:
        finding = CurrencyFinding(
            Status.ABSTAIN,
            Reason.INSUFFICIENT_EVIDENCE,
            (),
            f"{artifact_id!r} has no declared descendants: a change to it can make nothing else stale, so there "
            "is no walk to test",
        )
        return WhatIfReport(
            **common,
            status=finding.status,
            reason=finding.reason,
            failure_modes=(),
            execution_state=ExecutionState.NOT_APPLICABLE,
            findings=(finding,),
            injection=None,
            descendants=(),
            assessment=None,
            transitions=(),
        )
    recorded = {item.path: graph.recorded_sha256(item.node_id) for item in graph.nodes if item.path is not None}
    graph.detect_changes(_unread_observer(recorded), at=at)  # settle the saved state's own pending marks first
    prior = {node_id: graph.validity(node_id) for node_id in declared}
    injection, transitions, detection = _inject_change(graph, node, recorded, at)
    descendants = tuple(
        WhatIfDescendant(
            node_id,
            graph.require(node_id).kind,
            graph.require(node_id).publication,
            prior[node_id],
            graph.validity(node_id),
            _what_if_outcome(prior[node_id], graph.validity(node_id)),
        )
        for node_id in declared
    )
    assessment = assess(graph, detection)
    listed = list(assessment.publication_block["stale_publication_nodes"])
    publication = [item.node_id for item in descendants if item.publication_node]
    stale_publication = [item.node_id for item in descendants if item.publication_node and item.state is _STALE]
    holds: bool | None = None
    if publication:
        holds = not stale_publication or (
            assessment.status is Status.FAIL and set(stale_publication) <= set(listed)
        )
    findings: list[CurrencyFinding] = []
    missed = [item.node_id for item in descendants if item.outcome is WhatIfOutcome.NOT_MARKED]
    if missed:
        findings.append(
            CurrencyFinding(
                Status.FAIL,
                Reason.BLIND_SPOT,
                (FailureMode.DEFECTIVE_VERIFICATION,),
                f"the injected change of {artifact_id!r} left declared descendant(s) {_names(missed)} without "
                "STALE_PENDING_REVALIDATION: the staleness detector is blind to them",
            )
        )
    if holds is False:
        findings.append(
            CurrencyFinding(
                Status.FAIL,
                Reason.BLIND_SPOT,
                (FailureMode.DEFECTIVE_VERIFICATION,),
                f"publication descendant(s) {_names(stale_publication)} are STALE_PENDING_REVALIDATION after the "
                f"injection, but the currency assessment is {assessment.status.value} and names "
                f"{_names(listed) or 'no stale publication node'}: it would not block their publication",
            )
        )
    if not any(item.outcome is WhatIfOutcome.MARKED for item in descendants):
        findings.append(
            CurrencyFinding(
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (FailureMode.VACUOUS_PASS,),
                "no declared descendant was in good standing before the injection (each was already pending or "
                "declared by a person), so the walk had nothing it could visibly mark",
            )
        )
    status, reason, modes = _decide(findings)
    return WhatIfReport(
        **common,
        status=status,
        reason=reason,
        failure_modes=modes,
        execution_state=ExecutionState.CHECKED,
        findings=tuple(findings),
        injection=injection,
        descendants=descendants,
        assessment={
            "status": assessment.status.value,
            "reason": assessment.reason.value,
            "failure_modes": [mode.value for mode in assessment.failure_modes],
            "stale_publication_nodes": listed,
            "publication_descendants": publication,
            "stale_publication_descendants": stale_publication,
            "holds": holds,
        },
        transitions=transitions,
    )


def what_if_headline(report: Mapping[str, Any]) -> str:
    """The one-line headline ``what-if`` prints first."""
    lead = f"{report['status']} ({report['reason']}) what-if {report['artifact']['id']} {report['what_if_id']}"
    counts = report["counts"]
    if report["assessment"] is None:
        return f"{lead}: no declared descendants, nothing to inject"
    marked, declared = counts[WhatIfOutcome.MARKED.value], counts["declared_descendants"]
    return (
        f"{lead}: {marked} of {declared} declared descendant(s) newly marked STALE_PENDING_REVALIDATION; "
        f"currency assessment {report['assessment']['status']}"
    )


def render_what_if(report: Mapping[str, Any]) -> str:
    """The Markdown form of a what-if report, printed after the headline and a blank line."""
    artifact = report["artifact"]
    modes = ", ".join(report["failure_modes"]) or "none"
    lines = [
        f"# Staleness what-if: {_code(artifact['id'])}",
        "",
        "## STATUS",
        "",
        f"{report['status']} ({report['reason']}); failure modes: {modes}; execution: {report['execution_state']}; "
        f"id {_code(report['what_if_id'])}.",
        "",
    ]
    findings = [f"- {item['status']} ({item['reason']}): {_cell(item['detail'])}" for item in report["findings"]]
    lines += [*(findings or ["No finding."]), "", "## INJECTED CHANGE", ""]
    injection = report["injection"]
    if injection is None:
        lines.append("Nothing was injected: the artifact has no declared descendant.")
    else:
        lines += [
            f"- node: {_code(injection['node'])} ({artifact['kind']}), file {_code(injection['path'])}",
            f"- mode: {injection['mode']}",
            f"- recorded digest: {_code(injection['recorded_sha256'])}",
            f"- injected digest: {_code(injection['injected_sha256'])}",
            "- no file was read or written; every other node was taken at its recorded digest",
        ]
    lines += ["", "## DECLARED DESCENDANTS", ""]
    rows = [
        [
            _code(item["id"]),
            item["kind"],
            "yes" if item["publication_node"] else "no",
            item["prior_state"],
            item["state"],
            item["outcome"],
        ]
        for item in report["descendants"]
    ]
    headers = ("node", "kind", "publication", "before", "after", "outcome")
    lines += _table(headers, rows, "The artifact has no declared descendants.")
    lines += ["", "## CURRENCY ASSESSMENT AFTER THE INJECTION", ""]
    assessment = report["assessment"]
    if assessment is None:
        lines.append("Not run: nothing was injected.")
    else:
        holds = {True: "yes", False: "NO", None: "not applicable (no publication descendant)"}[assessment["holds"]]
        descendants = ", ".join(_code(item) for item in assessment["publication_descendants"]) or "none"
        named = ", ".join(_code(item) for item in assessment["stale_publication_nodes"]) or "none"
        lines += [
            f"- status: {assessment['status']} ({assessment['reason']})",
            f"- publication descendants: {descendants}",
            f"- stale publication nodes named by the assessment: {named}",
            f"- would block every stale publication descendant: {holds}",
        ]
    lines += ["", "## TRANSITIONS IN MEMORY", ""]
    rows = [[_code(item["node"]), item["from"], item["to"], _cell(item["reason"])] for item in report["transitions"]]
    lines += _table(("node", "from", "to", "reason"), rows, "No transition was made.")
    lines += ["", "## WHAT THIS DOES NOT PROVE", ""]
    lines += [f"- {item}" for item in report["does_not_prove"]]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Command line: impact, revalidate and what-if
# ---------------------------------------------------------------------------


def _emit(stream: TextIO, text: str) -> None:
    """Write one redacted line, escaping what the stream's encoding cannot represent.

    A Windows console may use a legacy code page, and a path it cannot encode
    must not turn a verdict into a traceback.
    """
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(redact_text(text).encode(encoding, "backslashreplace").decode(encoding) + "\n")


def _command_witness(args: argparse.Namespace, graph: DependencyGraph) -> RecomputeWitness | None:
    """The witness named by ``revalidate --witness PATH``, or None.

    Like every command-line path, PATH is relative to the current directory;
    the read is confined to the directory that holds the file. The attribute
    is optional so the command works with a parser that has no such flag.
    """
    value = getattr(args, "witness", None)
    if value is None:
        return None
    path = Path(value)
    return load_witness(path.parent, path.name, max_bytes=graph.max_bytes)


def _run(command: str, args: argparse.Namespace, out: TextIO) -> int:
    """Shared body of ``impact`` and ``revalidate``.

    Detection runs first and its result is persisted with the action's, so
    the saved state never lags behind the files on disk. A graph, state or
    witness that cannot be used stops the command before anything is written.
    """
    error = EXIT_CODE[Status.ERROR]
    try:
        graph = open_graph(args.manifest)
        graph.require(args.artifact_id)
        witness = _command_witness(args, graph) if command == "revalidate" else None
    except GraphError as exc:
        _emit(out, f"ERROR {command}: {exc}")
        return error
    at = now()
    before = graph.detect_changes(at=at)
    action: Impact | Revalidation
    if command == "impact":
        action = graph.impact(args.artifact_id, at=at)
    else:
        action = graph.revalidate(args.artifact_id, at=at, witness=witness)
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
    """``science-gate revalidate ARTIFACT_ID --manifest MANIFEST [--witness PATH]``; returns the exit code.

    Runs detection, re-hashes the artifact (REVALIDATED_UNCHANGED with early
    cutoff, or REVALIDATED_CHANGED with its descendants kept stale), saves
    ``graph-state.json`` and ``revalidation-report.json`` next to the graph,
    and prints the headline, the two paths, a blank line and the markdown
    report. A derived node with an unchanged file needs ``--witness``, a
    recompute witness document; without a valid one the refusal is recorded
    and the node stays pending (D6). The status is PASS only when the whole
    graph is then current.
    """
    return _run("revalidate", args, sys.stdout)


def cli_what_if(args: argparse.Namespace) -> int:
    """``science-gate what-if ARTIFACT_ID --manifest MANIFEST``; returns the exit code. Writes nothing.

    Prints the headline, a blank line and the Markdown report of
    :func:`what_if`. A graph that cannot be used, or an unknown artifact,
    prints one ERROR line and exits 3.
    """
    out = sys.stdout
    try:
        report = what_if(args.manifest, args.artifact_id)
    except GraphError as exc:
        _emit(out, f"ERROR what-if: {exc}")
        return EXIT_CODE[Status.ERROR]
    document = report.to_dict()
    _emit(out, what_if_headline(document))
    _emit(out, "")
    for line in render_what_if(document).splitlines():
        _emit(out, line)
    return EXIT_CODE[report.status]
