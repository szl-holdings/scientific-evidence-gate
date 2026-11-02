"""The verification engine: registry, built-in checks, run engine and decision
(ARCHITECTURE.md sections 5 and 6).

Three things live here together because they share one contract and must not
drift apart:

* **The registry** maps each check ``kind`` to a ``"module:function"`` string
  that is imported only when a manifest uses it. A missing or broken
  specialist module therefore affects only the runs that need it, and it does
  so visibly, as an ERROR result for that one check.
* **The built-in checks** owned by this module (the section 5 table).
* **The engine and** :func:`decide`. Every declared check runs inside a ledger
  invocation, even after an earlier check failed. :func:`decide` then applies
  the PASS contract and the ERROR > FAIL > ABSTAIN > PASS precedence.

The governing rule is that a passing check must emit enough evidence to prove
that it had the opportunity to fail. The engine enforces this in five ways.
A check that reports PASS without rows, evidence or discrimination is
downgraded before its verdict is recorded. Every would-be PASS is replayed
against known-bad variants of its own evidence (its **falsifier witness**,
section 17.5) and keeps its PASS only if the same checker, with the same
params, rejected one of them. Every run also executes controls that judge the
harness rather than the data: a must-fail canary and its known-good twin, and
a comparator self-test. The run commits to a **PLAN** and pins its evidence
and check modules before anything executes, and a single gated audit hook
records any write to a pinned file. Finally, invariants are evaluated against
the status the run is about to claim, and every finding that blocks PASS is
kept, with its source, so the reports can say exactly why.
"""

from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import TOOL_NAME, __version__, _audit
from . import invariants as _invariants
from ._canonical import (
    SizeLimitExceeded,
    StrictJSONError,
    canonical_bytes,
    sha256_bytes,
    sha256_canonical,
    sha256_file,
    strict_loads,
)
from ._clock import ClockError, format_utc, now, parse_utc
from ._redact import redact_text, redaction_scope
from ._safeio import (
    ABSOLUTE_PATH,
    DRIVE_PATH,
    EMPTY_PATH,
    INVALID_PATH,
    PATH_TRAVERSAL,
    RESERVED_NAME,
    SYMLINK_ESCAPE,
    SYMLINK_LOOP,
    SafeIOError,
    UnsafePathError,
    normalize_relpath,
    resolve_under_root,
    safe_read,
)
from .discovery import OpenedInput, Row, discover, row_key_of
from .invariants import (
    CANARY_MUST_FAIL,
    CANARY_MUST_PASS,
    COMPARATOR_CONTROL,
    DISAGREES,
    PLANNED_CONTROLS,
    VIOLATION_OUTCOMES,
    ClaimTally,
    InvariantContext,
    evaluate_invariants,
    falsifier_check_id,
    is_control,
    parse_decimal,
)
from .ledger import PLAN_SCHEMA, InvocationTrace, Ledger, index_invocations
from .manifests import MAX_MANIFEST_BYTES, CheckSpec, InputSpec, Manifest, ManifestError, ManifestIssue, load_manifest
from .models import (
    ACCOUNTING_COUNTERS,
    EMPTY_AGGREGATE_OUTCOME,
    FALSIFICATION_OUTCOMES,
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    UNJUSTIFIED_SHORTFALL_OUTCOME,
    AccountingCount,
    AssertionOutcome,
    CheckResult,
    Closure,
    DenominatorSource,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    FalsifierOutcome,
    InputAccounting,
    InputOverride,
    InputRecord,
    InputState,
    InvariantResult,
    Ratio,
    RatioState,
    Reason,
    RowCounts,
    RunResult,
    SkipJustification,
    Status,
    VerdictLevel,
    VerdictTransition,
    WitnessState,
    empty_controls,
    fold_verdicts,
)

__all__ = [
    "REGISTRY",
    "FALSIFIERS",
    "ROLE_DOCUMENTS",
    "DEFAULT_USER_AGENT",
    "SNAPSHOT_SCHEMA",
    "REVIEWS_SCHEMA",
    "TIME_SOURCES_SCHEMA",
    "SUMMARY_SCHEMA",
    "EVIDENCE_MANIFEST_SCHEMA",
    "MAX_LISTED",
    "NetworkPolicy",
    "Document",
    "CheckContext",
    "CheckOutcome",
    "CheckParamError",
    "CheckUnavailable",
    "PRELOADS",
    "Findings",
    "memory_input",
    "takes_no_inputs",
    "document_unavailable",
    "malformed_document",
    "resolve_check",
    "row_digest",
    "build_snapshot",
    "check_row_count",
    "check_required_columns",
    "check_duplicate_rows",
    "check_snapshot_completeness",
    "check_numeric_agreement",
    "check_reviewer_protocol",
    "check_time_source",
    "check_summary_consistency",
    "falsify_row_count",
    "falsify_required_columns",
    "falsify_duplicate_rows",
    "falsify_snapshot_completeness",
    "falsify_numeric_agreement",
    "falsify_reviewer_protocol",
    "falsify_time_source",
    "falsify_summary_consistency",
    "module_source_sha256",
    "params_sha256",
    "checker_sha256",
    "ledger_evidence",
    "run_checks",
    "build_plan",
    "Finding",
    "DecisionInputs",
    "Decision",
    "run_counters",
    "decide",
    "build_evidence_manifest",
    "VerificationRun",
    "verify",
]

#: Every kind in the section 5 table, mapped to where its check function lives.
#: Specialist kinds are imported lazily, so this module never imports them.
REGISTRY: Mapping[str, str] = MappingProxyType(
    {
        "row_count": "science_gate.verifier:check_row_count",
        "required_columns": "science_gate.verifier:check_required_columns",
        "duplicate_rows": "science_gate.verifier:check_duplicate_rows",
        "snapshot_completeness": "science_gate.verifier:check_snapshot_completeness",
        "numeric_agreement": "science_gate.verifier:check_numeric_agreement",
        "reviewer_protocol": "science_gate.verifier:check_reviewer_protocol",
        "time_source": "science_gate.verifier:check_time_source",
        "verification_log": "science_gate.citations:check_verification_log",
        "citation_resolver": "science_gate.citations:check_resolver",
        "citation_metadata": "science_gate.citations:check_metadata",
        "claim_registry": "science_gate.claims:check_claim_registry",
        "dependency_currency": "science_gate.dependencies:check_dependency_currency",
        "summary_consistency": "science_gate.verifier:check_summary_consistency",
        "claim_join": "science_gate.assertions:check_claim_join",
        "editorial_status": "science_gate.citations:check_editorial_status",
        "mutation_accounting": "science_gate.mutations:check_mutation_accounting",
    }
)

#: Files a specialist check reads beyond the role documents (stored claim
#: outputs, dependency node files, saved graph state, a sealed run's ledger),
#: keyed by check kind. Each ``"module:function"`` takes the
#: :class:`CheckContext` and reads those files through it before any check
#: runs. Reading them up front puts their digests into the run id, so two
#: runs over different files never share an id, and lets
#: ``summary_consistency`` see them as evidence it should pin.
PRELOADS: Mapping[str, str] = MappingProxyType(
    {
        "claim_registry": "science_gate.claims:preload_stored_outputs",
        "dependency_currency": "science_gate.dependencies:preload_graph_files",
        "claim_join": "science_gate.assertions:preload_claim_join",
    }
)

#: The negative-control generator of each kind (section 17.5):
#: ``falsify(ctx, spec, result) -> tuple[FalsifierCase, ...]``. A kind with no
#: entry, or whose generator cannot be imported, has no way to show that its
#: checker can reject anything, so it can never PASS (NO_GENERATOR).
FALSIFIERS: Mapping[str, str] = MappingProxyType(
    {
        "row_count": "science_gate.verifier:falsify_row_count",
        "required_columns": "science_gate.verifier:falsify_required_columns",
        "duplicate_rows": "science_gate.verifier:falsify_duplicate_rows",
        "snapshot_completeness": "science_gate.verifier:falsify_snapshot_completeness",
        "numeric_agreement": "science_gate.verifier:falsify_numeric_agreement",
        "reviewer_protocol": "science_gate.verifier:falsify_reviewer_protocol",
        "time_source": "science_gate.verifier:falsify_time_source",
        "summary_consistency": "science_gate.verifier:falsify_summary_consistency",
        "verification_log": "science_gate.citations:falsify_verification_log",
        "citation_resolver": "science_gate.citations:falsify_resolver",
        "citation_metadata": "science_gate.citations:falsify_metadata",
        "editorial_status": "science_gate.citations:falsify_editorial_status",
        "claim_registry": "science_gate.claims:falsify_claim_registry",
        "dependency_currency": "science_gate.dependencies:falsify_dependency_currency",
        "claim_join": "science_gate.assertions:falsify_claim_join",
        "mutation_accounting": "science_gate.mutations:falsify_mutation_accounting",
    }
)

#: Role documents a manifest can declare: ``(role, parse mode)``. The role
#: name is the manifest field, dotted for nested fields. The manuscript is
#: prose; every other role document is JSON.
ROLE_DOCUMENTS: tuple[tuple[str, str], ...] = (
    ("accepted_snapshot", "json"),
    ("claims", "json"),
    ("manuscript", "text"),
    ("dependencies", "json"),
    ("citations.entries", "json"),
    ("citations.log", "json"),
    ("citations.frozen", "json"),
    ("reviews.verdicts", "json"),
    ("time_sources", "json"),
    ("summary_claim", "json"),
)

DEFAULT_USER_AGENT = f"{TOOL_NAME}/{__version__} (local evidence gate)"

SNAPSHOT_SCHEMA = "science-gate-snapshot/v1"
REVIEWS_SCHEMA = "science-gate-reviews/v1"
TIME_SOURCES_SCHEMA = "science-gate-time-sources/v1"
SUMMARY_SCHEMA = "science-gate-summary/v1"
EVIDENCE_MANIFEST_SCHEMA = "science-gate-evidence-manifest/v1"

#: Evidence lists at most this many individual items (duplicate groups,
#: deleted keys, problem events). The full count is always given, so a
#: badly broken input cannot bloat every output file.
MAX_LISTED = 20

#: ``_safeio`` codes that mean a declared path tried to leave the manifest
#: directory. Discovery marks such inputs REFUSED; the run treats the
#: manifest itself as unsafe (ERROR), not merely the evidence as missing.
_PATH_SAFETY_CODES = (
    ABSOLUTE_PATH,
    DRIVE_PATH,
    EMPTY_PATH,
    INVALID_PATH,
    PATH_TRAVERSAL,
    RESERVED_NAME,
    SYMLINK_ESCAPE,
    SYMLINK_LOOP,
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------------------
# Context and outcome types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkPolicy:
    """Whether checks may reach the network, and how (section 9).

    Live access is off unless ``--live`` or the manifest's ``citations.live``
    asks for it. ``opener`` stands in for ``urllib.request.urlopen``: tests
    inject a failing opener so that no code path they exercise can touch the
    network, and adapters must call nothing else.
    """

    live: bool = False
    opener: Callable[..., Any] | None = field(default=None, compare=False)
    timeout_seconds: int = 10
    user_agent: str = DEFAULT_USER_AGENT

    def to_dict(self) -> dict[str, Any]:
        return {
            "live": self.live,
            "timeout_seconds": self.timeout_seconds,
            "user_agent": self.user_agent,
            "opener": "injected" if self.opener is not None else "urllib",
        }


@dataclass(frozen=True)
class Document:
    """A role document (snapshot, verdicts, time sources, ...) as a check sees it.

    ``state`` reuses :class:`~science_gate.models.InputState`: PARSED, EMPTY,
    MISSING, REFUSED, OPEN_FAILED or PARSE_ERROR. It is None only when the
    manifest does not declare the document at all. ``sha256`` is set whenever
    bytes were read, even if they then failed to parse, so the digest of what
    was actually on disk is always recorded.
    """

    role: str
    path: str | None
    declared: bool
    state: InputState | None
    sha256: str | None = None
    size_bytes: int | None = None
    content: Any = None
    diagnostic: str | None = None

    @property
    def loaded(self) -> bool:
        return self.state is InputState.PARSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "declared": self.declared,
            "state": None if self.state is None else self.state.value,
            "sha256": self.sha256,
            "bytes": self.size_bytes,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True)
class _FileRead:
    """The single read of one file under the manifest root."""

    state: InputState
    sha256: str | None = None
    size_bytes: int | None = None
    data: bytes | None = None
    diagnostic: str | None = None


def memory_input(
    spec: InputSpec,
    override: InputOverride,
    *,
    base_columns: tuple[str, ...] | None = None,
    base_document: Any = None,
) -> OpenedInput:
    """An in-memory, fully PARSED input holding ``override``'s records (falsifier overlays, the canary).

    The record counts every row as admitted and re-evaluates closure against
    the spec's own ``expected_rows`` and ``denominator_source``, so a
    falsifier that drops a row meets exactly the rule a real deletion would.
    The digest is the canonical digest of the override itself: it names what
    the check saw and can never be mistaken for a file on disk.
    """
    # CSV records are read-only {column: str} mappings, exactly as discovery admits them.
    csv_like = spec.format == "csv"
    rows = tuple(
        Row(index, None, MappingProxyType(dict(values)) if csv_like and isinstance(values, Mapping) else values)
        for index, values in enumerate(override.rows, start=1)
    )
    count = len(rows)
    counts = RowCounts(admitted=count, excluded=0, deferred=0, unresolved=0, failed=0)
    record = InputRecord(
        input_id=spec.input_id,
        path=spec.path,
        required=spec.required,
        format=spec.format,
        state=InputState.PARSED,
        discovered=True,
        opened=True,
        parsed=True,
        sha256=sha256_canonical(override.to_dict()),
        declared_sha256=spec.sha256,
        size_bytes=None,
        rows=count,
        counts=counts,
        closure=Closure.evaluate(spec.denominator_source, spec.expected_rows, count),
        diagnostics=("IN_MEMORY: records supplied by a control, not read from disk",),
    )
    columns = override.columns if override.columns is not None else base_columns
    document: Any = None
    if spec.format == "json":
        values = [row.values for row in rows]
        document = values[0] if len(values) == 1 and not isinstance(base_document, list) else values
    return OpenedInput(spec, record, None, columns if csv_like else None, rows, document)


@dataclass(frozen=True, eq=False)
class CheckContext:
    """Everything a check may look at (section 5).

    The manifest, the opened inputs, the accepted snapshot, the manifest
    directory, the limits and the network policy. Files beyond the declared
    inputs are read only through :meth:`read_document`. It reads each file
    once, confines it to the manifest directory and the size limit, and
    records its digest, so every file a check relied on appears in the
    evidence manifest.

    ``run_id`` is bound (:meth:`bind_run_id`) before any check runs, so a
    check can derive run-specific nonces from it. :meth:`overlay` builds the
    in-memory variant a falsifier runs against; an overlay never reads the
    disk, so a negative control can never touch, or be touched by, the files
    the run is judging.
    """

    manifest: Manifest
    inputs: Mapping[str, OpenedInput]
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    run_id: str | None = None
    _files: dict[str, _FileRead] = field(default_factory=dict, init=False, repr=False)
    _roles: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False)
    _preloaded: set[str] = field(default_factory=set, init=False, repr=False)
    _sealed: bool = field(default=False, init=False, repr=False)

    def bind_run_id(self, run_id: str) -> None:
        """Record the run id once, before any check runs; a different second id is refused."""
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        if self.run_id is not None and self.run_id != run_id:
            raise ValueError(f"this context already belongs to run {self.run_id!r}")
        object.__setattr__(self, "run_id", run_id)

    def _derive(
        self,
        inputs: Mapping[str, OpenedInput],
        *,
        files: dict[str, _FileRead] | None = None,
        roles: dict[str, set[str]] | None = None,
        preloaded: set[str] | None = None,
        sealed: bool | None = None,
    ) -> CheckContext:
        """A context over other inputs. Omitted caches are shared with this one, not copied.

        A sealed context (an overlay or a control) is also offline: a
        negative control is answered from memory and never makes a request.
        """
        network = dataclasses.replace(self.network, live=False) if sealed else self.network
        derived = CheckContext(self.manifest, inputs, network, self.run_id)
        object.__setattr__(derived, "_files", self._files if files is None else files)
        object.__setattr__(derived, "_roles", self._roles if roles is None else roles)
        object.__setattr__(derived, "_preloaded", self._preloaded if preloaded is None else preloaded)
        object.__setattr__(derived, "_sealed", self._sealed if sealed is None else sealed)
        return derived

    def overlay(self, case: FalsifierCase) -> CheckContext:
        """An in-memory copy of this context with ``case``'s inputs and documents replaced (section 17.5).

        Each overridden input becomes a PARSED input whose rows are numbered
        1..n, whose counts admit all n, whose closure is re-evaluated against
        the input's own declared expectation, and whose digest is the
        canonical digest of the override. Overridden documents are served
        through the normal parse rules. Files this context never read are
        reported as unavailable rather than read: nothing touches the disk.
        """
        undeclared = sorted(set(case.inputs) - set(self.inputs))
        if undeclared:
            raise ValueError(f"case {case.case_id!r} overrides undeclared input(s) {undeclared}")
        inputs = dict(self.inputs)
        for input_id, override in case.inputs.items():
            base = self.inputs[input_id]
            inputs[input_id] = memory_input(base.spec, override, base_columns=base.columns, base_document=base.document)
        files = dict(self._files)
        for path, data in case.documents.items():
            files[path] = _FileRead(
                InputState.PARSED if data else InputState.EMPTY,
                sha256_bytes(data),
                len(data),
                data,
                None if data else f"EMPTY: {path} has no content",
            )
        roles = {path: set(names) for path, names in self._roles.items()}
        return self._derive(inputs, files=files, roles=roles, preloaded=set(self._preloaded), sealed=True)

    @property
    def root(self) -> Path:
        """The manifest directory; every declared path is relative to it."""
        return self.manifest.root

    @property
    def limits(self) -> Any:
        return self.manifest.limits

    @property
    def accepted_snapshot(self) -> Document:
        return self.role_document("accepted_snapshot")

    def role_path(self, role: str) -> str | None:
        """The path the manifest declares for ``role``, or None."""
        section, _, name = role.partition(".")
        value = getattr(self.manifest, section, None)
        if name:
            value = getattr(value, name, None) if value is not None else None
        return value if isinstance(value, str) else None

    def role_document(self, role: str) -> Document:
        """The declared document for ``role``, parsed per :data:`ROLE_DOCUMENTS`."""
        modes = dict(ROLE_DOCUMENTS)
        if role not in modes:
            raise KeyError(f"unknown role {role!r}")
        path = self.role_path(role)
        if path is None:
            return Document(role, None, False, None)
        return self.read_document(path, role=role, parse=modes[role])

    def read_document(self, relpath: str, *, role: str, parse: str = "json") -> Document:
        """Read a file under the manifest directory as ``json``, ``text`` or ``bytes``.

        Never raises for a bad file: a missing, refused, unreadable or
        unparseable file comes back as a Document whose state says so.
        """
        if parse not in ("json", "text", "bytes"):
            raise ValueError(f"unknown parse mode {parse!r}")
        key, raw = self._read(relpath)
        self._roles.setdefault(key, set()).add(role)
        base = Document(role, key, True, raw.state, raw.sha256, raw.size_bytes, None, raw.diagnostic)
        if raw.state is not InputState.PARSED or raw.data is None:
            return base
        if parse == "bytes":
            return dataclasses.replace(base, content=raw.data)
        try:
            text = raw.data.decode("utf-8-sig")
            content = text if parse == "text" else strict_loads(text)
        except UnicodeDecodeError as exc:
            return dataclasses.replace(base, state=InputState.PARSE_ERROR, diagnostic=f"NOT_UTF8: byte {exc.start}")
        except StrictJSONError as exc:
            return dataclasses.replace(base, state=InputState.PARSE_ERROR, diagnostic=f"PARSE_ERROR: {exc}")
        return dataclasses.replace(base, content=content)

    def preload_roles(self) -> None:
        """Read every declared role document before any check runs.

        Reading up front means every check sees the same bytes, and every
        declared document is hashed into the evidence manifest even when no
        check consumes it. That is what makes a change to, say, citation
        metadata beneath an otherwise unchanged run visible in the receipt.
        """
        for role, _ in ROLE_DOCUMENTS:
            self.role_document(role)

    def preload(self, kinds: Iterable[str], preloads: Mapping[str, str] = PRELOADS) -> None:
        """Read every role document, then the files the declared check kinds name (:data:`PRELOADS`).

        Everything read here is read before any check runs, so it is the
        same for every check and it can feed the run id. A preload that
        cannot be imported is skipped: the check of that kind is then
        unavailable too, and the engine records it as ERROR.
        """
        self.preload_roles()
        for kind in sorted(set(kinds) & set(preloads)):
            try:
                read_files = resolve_check(preloads[kind])
            except CheckUnavailable:
                continue
            read_files(self)
        self._preloaded.update(self._files)

    def preloaded_evidence(self) -> tuple[str, ...]:
        """Paths read by :meth:`preload` that exist and were hashed, sorted."""
        return tuple(sorted(path for path in self._preloaded if self._files[path].sha256 is not None))

    def read_log(self) -> tuple[dict[str, Any], ...]:
        """Every file read through this context, sorted by path, without content."""
        return tuple(
            {
                "path": path,
                "roles": sorted(self._roles.get(path, ())),
                "state": raw.state.value,
                "sha256": raw.sha256,
                "bytes": raw.size_bytes,
                "diagnostic": raw.diagnostic,
            }
            for path, raw in sorted(self._files.items())
        )

    def _read(self, relpath: str) -> tuple[str, _FileRead]:
        try:
            key = normalize_relpath(relpath)
        except UnsafePathError as exc:
            return relpath, self._files.setdefault(relpath, _FileRead(InputState.REFUSED, diagnostic=f"REFUSED: {exc}"))
        if key not in self._files:
            if self._sealed:
                # An overlay or control context answers only from memory.
                return key, _FileRead(InputState.OPEN_FAILED, diagnostic=f"OVERLAY_UNREAD: {key} is not in memory")
            self._files[key] = self._read_file(key)
        return key, self._files[key]

    def _read_file(self, key: str) -> _FileRead:
        try:
            data = safe_read(self.manifest.root, key, max_bytes=self.manifest.limits.max_file_bytes)
        except FileNotFoundError:
            return _FileRead(InputState.MISSING, diagnostic=f"MISSING: no file at {key}")
        except SafeIOError as exc:
            return _FileRead(InputState.REFUSED, diagnostic=f"REFUSED: {exc}")
        except OSError as exc:  # str(exc) would carry a machine-specific absolute path
            return _FileRead(InputState.OPEN_FAILED, diagnostic=f"OPEN_FAILED: {exc.strerror or type(exc).__name__}")
        state = InputState.PARSED if data else InputState.EMPTY
        diagnostic = None if data else f"EMPTY: {key} has no content"
        return _FileRead(state, sha256_bytes(data), len(data), data, diagnostic)


@dataclass(frozen=True)
class CheckOutcome:
    """What a check function returns (section 5).

    ``claim_tallies`` extends the contract's field list. A check that reads
    *claimed* verifications (a citation log's ``claimed_verified``, say)
    reports them here, and the engine feeds them to the
    ``checked_claims_le_invocations`` invariant.
    """

    execution_state: ExecutionState
    verdict: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...] = ()
    rows_examined: int | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()
    claim_tallies: tuple[ClaimTally, ...] = ()


class CheckParamError(ValueError):
    """A check's ``params`` (or input wiring) are unusable.

    Raised by a check function. Like any exception from a check, the engine
    records it as an ERRORED invocation with verdict ERROR. A typo in params
    must never quietly weaken a check.
    """


class CheckUnavailable(LookupError):
    """A registry target that cannot be imported or is not callable."""


def resolve_check(target: str) -> Callable[[CheckContext, CheckSpec], CheckOutcome]:
    """Import ``"module:function"`` and return the function."""
    module_name, separator, function_name = target.partition(":")
    if not separator or not module_name or not function_name:
        raise CheckUnavailable(f"{target!r} is not a 'module:function' target")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise CheckUnavailable(f"cannot import {module_name}: {exc}") from None
    function = getattr(module, function_name, None)
    if not callable(function):
        raise CheckUnavailable(f"{module_name} has no callable {function_name!r}")
    return function


# ---------------------------------------------------------------------------
# Helpers shared by the built-in checks
# ---------------------------------------------------------------------------


class _FormatError(ValueError):
    """A role document whose structure does not match its declared schema."""


class Findings:
    """Collects one check's findings and turns them into a single outcome.

    A definite contradiction (FAIL) outranks missing evidence (ABSTAIN), and
    PASS is returned only when nothing at all was found. The first finding at
    the winning level supplies the reason, so the outcome is deterministic.
    Specialist checks use this same class, so every check folds its findings
    into a verdict by one rule.
    """

    def __init__(self) -> None:
        self._levels: list[tuple[Status, Reason]] = []
        self.failure_modes: set[FailureMode] = set()
        self.diagnostics: list[str] = []

    def fail(self, reason: Reason, detail: str, *modes: FailureMode) -> None:
        self._add(Status.FAIL, reason, detail, modes)

    def abstain(self, reason: Reason, detail: str, *modes: FailureMode) -> None:
        self._add(Status.ABSTAIN, reason, detail, modes)

    def _add(self, status: Status, reason: Reason, detail: str, modes: Iterable[FailureMode]) -> None:
        self._levels.append((status, reason))
        self.failure_modes.update(modes)
        self.diagnostics.append(detail)

    def first_reason(self, default: Reason) -> Reason:
        """The reason of the first finding recorded so far, or ``default``."""
        return self._levels[0][1] if self._levels else default

    def _modes(self) -> tuple[FailureMode, ...]:
        """Sorted, so no value ever depends on set iteration (hash-seed) order."""
        return tuple(sorted(self.failure_modes, key=lambda mode: mode.value))

    def outcome(
        self,
        *,
        rows_examined: int | None,
        evidence: Mapping[str, Any],
        execution_state: ExecutionState = ExecutionState.CHECKED,
        claim_tallies: tuple[ClaimTally, ...] = (),
    ) -> CheckOutcome:
        verdict, reason = Status.PASS, Reason.VERIFIED
        for status in (Status.FAIL, Status.ABSTAIN):
            chosen = [item for item in self._levels if item[0] is status]
            if chosen:
                verdict, reason = chosen[0]
                break
        return CheckOutcome(
            execution_state=execution_state,
            verdict=verdict,
            reason=reason,
            failure_modes=self._modes(),
            rows_examined=rows_examined,
            evidence=evidence,
            diagnostics=tuple(self.diagnostics),
            claim_tallies=claim_tallies,
        )

    def not_applicable(
        self, reason: Reason, detail: str, evidence: Mapping[str, Any], *, justification: SkipJustification
    ) -> CheckOutcome:
        """Nothing to examine: never PASS, and 0 rows is the true count.

        The closed-vocabulary ``justification`` is required (extension #24):
        free text alone never excuses a required check from running, and an
        unlabelled shortfall is FAIL / PARTIAL_EXECUTION (D1).
        """
        return CheckOutcome(
            execution_state=ExecutionState.NOT_APPLICABLE,
            verdict=Status.ABSTAIN,
            reason=reason,
            failure_modes=self._modes(),
            rows_examined=0,
            evidence=_labelled(evidence, justification),
            diagnostics=(*self.diagnostics, detail),
        )


def _labelled(evidence: Mapping[str, Any], justification: SkipJustification) -> dict[str, Any]:
    """``evidence`` plus its skip justification, under :data:`SKIP_JUSTIFICATION_KEY`."""
    return {**evidence, SKIP_JUSTIFICATION_KEY: SkipJustification(justification).value}


def _params(spec: CheckSpec, allowed: Iterable[str] = (), required: Iterable[str] = ()) -> Mapping[str, Any]:
    """Return the params after refusing unknown and missing keys."""
    allowed_set, required_set = frozenset(allowed), frozenset(required)
    unknown = sorted(set(spec.params) - allowed_set)
    if unknown:
        raise CheckParamError(f"UNKNOWN_PARAM: {spec.kind} does not accept {unknown}")
    missing = sorted(required_set - set(spec.params))
    if missing:
        raise CheckParamError(f"MISSING_PARAM: {spec.kind} requires {missing}")
    return spec.params


def takes_no_inputs(spec: CheckSpec, source: str) -> None:
    """Refuse declared inputs on a check that reads a role document instead.

    Accepting them would let a reader believe the check examined those
    inputs when it never looks at them.
    """
    if spec.inputs:
        raise CheckParamError(f"UNEXPECTED_INPUTS: {spec.kind} reads the manifest's {source} and takes no inputs")


def _text_list(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise CheckParamError(f"INVALID_PARAM: {name} must be a non-empty list of strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise CheckParamError(f"INVALID_PARAM: {name} must contain only non-empty strings")
    if len(set(value)) != len(value):
        raise CheckParamError(f"INVALID_PARAM: {name} repeats an entry")
    return tuple(value)


def _position(row: Row) -> int:
    """Where a record is: its physical line when known, else its record index."""
    return row.line if row.line is not None else row.index


def _positions_label(opened: OpenedInput) -> str:
    return "records" if opened.spec.format == "json" else "lines"


def _listed(items: Sequence[Any]) -> list[Any]:
    return list(items[:MAX_LISTED])


def _input_summary(opened: OpenedInput) -> dict[str, Any]:
    return {
        "state": opened.state.value,
        "sha256": opened.sha256,
        "rows_admitted": None if opened.rows is None else len(opened.rows),
    }


#: How an input that cannot be (fully) examined affects a check that uses it.
_UNUSABLE_INPUT: Mapping[InputState, tuple[Reason, tuple[FailureMode, ...]]] = MappingProxyType(
    {
        InputState.MISSING: (Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.EMPTY: (Reason.INSUFFICIENT_EVIDENCE, ()),
        InputState.REFUSED: (Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.OPEN_FAILED: (Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.PARSE_ERROR: (Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.HASH_MISMATCH: (Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,)),
    }
)


def _examinable(ctx: CheckContext, spec: CheckSpec, findings: Findings) -> list[OpenedInput]:
    """The check's inputs that have admitted rows, in declaration order.

    Each input that cannot be examined adds an ABSTAIN finding. A PARTIAL
    input can be examined, but its result can never be complete, so it also
    adds an ABSTAIN finding: partial execution must not appear complete.
    """
    usable: list[OpenedInput] = []
    for input_id in spec.inputs:
        opened = ctx.inputs.get(input_id)
        if opened is None:
            findings.abstain(Reason.INSUFFICIENT_EVIDENCE, f"input {input_id!r} was never discovered")
            continue
        if opened.usable:
            usable.append(opened)
            if opened.state is InputState.PARTIAL:
                counts = opened.record.counts
                findings.abstain(
                    Reason.PARTIAL_EXECUTION,
                    f"input {input_id!r} is PARTIAL: {counts.admitted} of {opened.record.rows} records admitted",
                    FailureMode.PARTIAL_EXECUTION,
                    FailureMode.OMITTED_POPULATION,
                )
            continue
        reason, modes = _UNUSABLE_INPUT[opened.state]
        findings.abstain(reason, f"input {input_id!r} is {opened.state.value}: not examined", *modes)
    return usable


#: Input states whose content cannot be examined at all, and why (17.7).
_UNAVAILABLE_STATES = frozenset(
    {InputState.MISSING, InputState.REFUSED, InputState.OPEN_FAILED, InputState.PARSE_ERROR}
)


def _population_justification(ctx: CheckContext, spec: CheckSpec) -> SkipJustification:
    """Why a check's inputs left nothing to examine, in the closed vocabulary.

    The most serious cause wins: content that is not the declared artifact
    (SOURCE_REJECTED), then content that could not be read
    (INPUT_UNAVAILABLE), then a genuinely empty population.
    """
    states = [ctx.inputs[input_id].state if input_id in ctx.inputs else None for input_id in spec.inputs]
    if InputState.HASH_MISMATCH in states:
        return SkipJustification.SOURCE_REJECTED
    if None in states or _UNAVAILABLE_STATES & set(states):
        return SkipJustification.INPUT_UNAVAILABLE
    return SkipJustification.EMPTY_POPULATION


def _no_rows_to_examine(
    ctx: CheckContext, spec: CheckSpec, findings: Findings, evidence: Mapping[str, Any]
) -> CheckOutcome:
    """NOT_APPLICABLE, citing the first recorded cause (e.g. SOURCE_MISMATCH for a digest mismatch)."""
    if not spec.inputs:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE,
            f"{spec.kind} was given no inputs",
            evidence,
            justification=SkipJustification.NOT_DECLARED,
        )
    reason = findings.first_reason(Reason.INSUFFICIENT_EVIDENCE)
    return findings.not_applicable(
        reason, "no input has rows to examine", evidence, justification=_population_justification(ctx, spec)
    )


def document_unavailable(document: Document, evidence: Mapping[str, Any]) -> CheckOutcome:
    """A declared role document that could not be read or parsed: never PASS.

    Absence or damage is missing evidence (ABSTAIN), not a verdict about content.
    """
    damaged = document.state is InputState.PARSE_ERROR
    reason = Reason.PROTOCOL_BROKEN if damaged else Reason.INSUFFICIENT_EVIDENCE
    label = SkipJustification.EVIDENCE_MALFORMED if damaged else SkipJustification.INPUT_UNAVAILABLE
    detail = document.diagnostic or f"{document.role} is {document.state}"
    return CheckOutcome(
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ABSTAIN,
        reason=reason,
        rows_examined=0,
        evidence=_labelled({**evidence, "document": document.to_dict()}, label),
        diagnostics=(f"{document.role} ({document.path}) unavailable: {detail}",),
    )


def malformed_document(document: Document, problem: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    """A role document that parsed but does not match its schema: SKIPPED as EVIDENCE_MALFORMED."""
    return CheckOutcome(
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ABSTAIN,
        reason=Reason.PROTOCOL_BROKEN,
        rows_examined=0,
        evidence=_labelled({**evidence, "document": document.to_dict()}, SkipJustification.EVIDENCE_MALFORMED),
        diagnostics=(f"MALFORMED_DOCUMENT: {document.role} ({document.path}): {problem}",),
    )


def _object(value: Any, where: str, allowed: Iterable[str], required: Iterable[str] = ()) -> Mapping[str, Any]:
    """A JSON object with exactly the allowed keys (unknown keys are refused)."""
    if not isinstance(value, Mapping):
        raise _FormatError(f"{where} must be a JSON object")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise _FormatError(f"{where} has unknown key(s) {unknown}")
    missing = sorted(set(required) - set(value))
    if missing:
        raise _FormatError(f"{where} is missing {missing}")
    return value


def _schema(document: Mapping[str, Any], expected: str) -> None:
    if document.get("schema") != expected:
        raise _FormatError(f"schema must be {expected!r}, got {document.get('schema')!r}")


def _hex_digest(value: Any, where: str) -> str:
    """A recorded SHA-256 must be well formed.

    A malformed recorded digest would otherwise compare unequal to every real
    one and pose as a content change (FAIL), when the record itself is broken.
    """
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise _FormatError(f"{where} must be 64 lowercase hex characters")
    return value


def _string_key(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise _FormatError(f"{where} must be a non-empty list of non-empty strings")
    return tuple(value)


def row_digest(values: Any) -> str:
    """SHA-256 of one record's canonical form: what "unchanged" means for a row.

    CSV records are ``{column: string}``, so the digest does not depend on
    column order, quoting or line endings, only on the values themselves.
    """
    return sha256_canonical(values)


# ---------------------------------------------------------------------------
# Built-in checks: inputs
# ---------------------------------------------------------------------------


def check_row_count(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Rows examined must be at least one, and must close against an INDEPENDENT ``expected_rows``.

    Closure compares every record seen (admitted, excluded, deferred,
    unresolved, failed) with the declared expectation. More records than
    expected is a mismatch. Fewer means a population was omitted.
    """
    _params(spec)
    findings = Findings()
    usable = _examinable(ctx, spec, findings)
    per_input = {input_id: _input_summary(ctx.inputs[input_id]) for input_id in spec.inputs if input_id in ctx.inputs}
    if not usable:
        return _no_rows_to_examine(ctx, spec, findings, {"inputs": per_input})
    for opened in usable:
        closure = opened.record.closure
        per_input[opened.input_id].update(
            {"row_counts": opened.record.counts.to_dict(), "closure": closure.to_dict()}
        )
        if closure.holds is False:
            short = closure.accounted < closure.expected
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"input {opened.input_id!r}: expected {closure.expected} records ({closure.source.value}), "
                f"accounted for {closure.accounted}",
                FailureMode.OMITTED_POPULATION if short else FailureMode.SOURCE_MISMATCH,
            )
        elif closure.source is not DenominatorSource.INDEPENDENT:
            per_input[opened.input_id]["closure_note"] = (
                f"not enforced: the expectation is {closure.source.value}, not INDEPENDENT"
            )
    rows = sum(len(opened.rows) for opened in usable)
    return findings.outcome(rows_examined=rows, evidence={"inputs": per_input, "rows_admitted_total": rows})


def check_required_columns(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Every declared column must be present in every admitted record.

    For CSV, the header is the column set, and discovery fails any record
    whose field count differs from it, so header presence covers every
    admitted row. JSON records are checked one by one.
    """
    columns = _text_list(_params(spec, ("columns",), ("columns",))["columns"], "columns")
    findings = Findings()
    usable = _examinable(ctx, spec, findings)
    per_input = {input_id: _input_summary(ctx.inputs[input_id]) for input_id in spec.inputs if input_id in ctx.inputs}
    evidence: dict[str, Any] = {"columns": list(columns), "inputs": per_input}
    if not usable:
        return _no_rows_to_examine(ctx, spec, findings, evidence)
    for opened in usable:
        summary = per_input[opened.input_id]
        if opened.spec.format == "csv":
            header = opened.columns or ()
            missing = [name for name in columns if name not in header]
            summary.update({"header": list(header), "missing_columns": missing})
            if missing:
                findings.fail(
                    Reason.SOURCE_MISMATCH,
                    f"input {opened.input_id!r} lacks column(s) {missing}",
                    FailureMode.SOURCE_MISMATCH,
                )
            continue
        lacking: dict[str, list[int]] = {}
        for row in opened.rows:
            for name in columns:
                if not isinstance(row.values, Mapping) or name not in row.values:
                    lacking.setdefault(name, []).append(_position(row))
        label = _positions_label(opened)
        summary["records_lacking"] = {
            name: {"count": len(where), label: _listed(where)} for name, where in sorted(lacking.items())
        }
        if lacking:
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"input {opened.input_id!r}: records lack column(s) {sorted(lacking)}",
                FailureMode.SOURCE_MISMATCH,
            )
    return findings.outcome(rows_examined=sum(len(opened.rows) for opened in usable), evidence=evidence)


def check_duplicate_rows(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Exact duplicate records, and records that share a declared ``row_key``.

    Exact duplicates are reported by position only, never by content.
    Duplicate keys are reported with the key, which is an identifier the
    manifest itself declared.
    """
    _params(spec)
    findings = Findings()
    usable = _examinable(ctx, spec, findings)
    per_input = {input_id: _input_summary(ctx.inputs[input_id]) for input_id in spec.inputs if input_id in ctx.inputs}
    if not usable:
        return _no_rows_to_examine(ctx, spec, findings, {"inputs": per_input})
    for opened in usable:
        key_fields = opened.spec.row_key
        exact: dict[str, list[int]] = {}
        keyed: dict[tuple[str, ...], list[int]] = {}
        for row in opened.rows:
            exact.setdefault(row_digest(row.values), []).append(_position(row))
            key = row_key_of(row.values, key_fields) if key_fields else None
            if key is not None:
                keyed.setdefault(key, []).append(_position(row))
        exact_groups = sorted((positions for positions in exact.values() if len(positions) > 1), key=lambda p: p[0])
        key_groups = sorted(
            ((key, positions) for key, positions in keyed.items() if len(positions) > 1), key=lambda item: item[1][0]
        )
        label = _positions_label(opened)
        per_input[opened.input_id].update(
            {
                "row_key": list(key_fields),
                "exact_duplicate_groups": len(exact_groups),
                "exact_duplicate_extra_rows": sum(len(group) - 1 for group in exact_groups),
                "exact_duplicates": [{label: group} for group in _listed(exact_groups)],
                "duplicate_key_groups": len(key_groups),
                "duplicate_keys": [{"key": list(key), label: where} for key, where in _listed(key_groups)],
            }
        )
        if not key_fields:
            per_input[opened.input_id]["key_note"] = "no row_key declared: only exact duplicates were checked"
        if exact_groups:
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"input {opened.input_id!r}: {len(exact_groups)} group(s) of exact duplicate records",
                FailureMode.SOURCE_MISMATCH,
            )
        if key_groups:
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"input {opened.input_id!r}: {len(key_groups)} row_key value(s) occur more than once",
                FailureMode.SOURCE_MISMATCH,
            )
    return findings.outcome(rows_examined=sum(len(opened.rows) for opened in usable), evidence={"inputs": per_input})


@dataclass(frozen=True)
class _AcceptedInput:
    """The rows of one input that a snapshot accepted."""

    row_key: tuple[str, ...]
    rows: tuple[tuple[tuple[str, ...] | None, str], ...]


def _parse_snapshot(document: Any) -> dict[str, _AcceptedInput]:
    """Validate a snapshot document (``science-gate-snapshot/v1``)."""
    top = _object(document, "snapshot", ("schema", "inputs"), ("schema", "inputs"))
    _schema(top, SNAPSHOT_SCHEMA)
    if not isinstance(top["inputs"], Mapping):
        raise _FormatError("snapshot inputs must be an object keyed by input id")
    accepted: dict[str, _AcceptedInput] = {}
    for input_id, entry in top["inputs"].items():
        where = f"snapshot inputs[{input_id!r}]"
        entry = _object(entry, where, ("row_key", "rows"), ("rows",))
        key_fields = _string_key(entry["row_key"], f"{where}.row_key") if entry.get("row_key") else ()
        if not isinstance(entry["rows"], list):
            raise _FormatError(f"{where}.rows must be a list")
        rows: list[tuple[tuple[str, ...] | None, str]] = []
        seen: set[tuple[str, ...]] = set()
        for index, item in enumerate(entry["rows"]):
            row_where = f"{where}.rows[{index}]"
            item = _object(item, row_where, ("key", "sha256") if key_fields else ("sha256",), ("sha256",))
            digest = _hex_digest(item["sha256"], f"{row_where}.sha256")
            key = None
            if key_fields:
                key = _string_key(item.get("key"), f"{row_where}.key")
                if len(key) != len(key_fields):
                    raise _FormatError(f"{row_where}.key must have {len(key_fields)} part(s)")
                if key in seen:
                    raise _FormatError(f"{row_where}.key {list(key)} is accepted twice")
                seen.add(key)
            rows.append((key, digest))
        accepted[input_id] = _AcceptedInput(key_fields, tuple(rows))
    return accepted


def _report_absent(opened: OpenedInput, count: int, what: str, findings: Findings) -> None:
    """Accepted rows not among the admitted records: deleted only if the input is complete.

    When some records were deferred, unresolved or malformed, the missing
    rows may simply be among them. That is unexamined evidence (ABSTAIN),
    not a proven deletion (FAIL).
    """
    if opened.state is InputState.PARSED:
        findings.fail(
            Reason.SOURCE_MISMATCH,
            f"input {opened.input_id!r}: {count} accepted row(s) {what}",
            FailureMode.OMITTED_POPULATION,
        )
    else:
        findings.abstain(
            Reason.INSUFFICIENT_EVIDENCE,
            f"input {opened.input_id!r} is {opened.state.value}: {count} accepted row(s) are not among the admitted "
            "records and may be among those not examined",
            FailureMode.OMITTED_POPULATION,
        )


def _compare_snapshot(opened: OpenedInput, accepted: _AcceptedInput, findings: Findings) -> dict[str, Any]:
    """Compare one input's admitted rows with its accepted rows."""
    summary: dict[str, Any] = {
        "accepted_rows": len(accepted.rows),
        "row_key": list(accepted.row_key),
        "input_complete": opened.state is InputState.PARSED,
    }
    if not accepted.row_key:
        current = Counter(row_digest(row.values) for row in opened.rows)
        lost = Counter(digest for _, digest in accepted.rows) - current
        missing = sum(lost.values())
        summary.update({"present_unchanged": len(accepted.rows) - missing, "deleted_or_changed": missing})
        summary["key_note"] = "no row_key: a changed row cannot be told apart from a deleted one"
        if missing:
            _report_absent(opened, missing, "are missing or changed", findings)
        return summary
    current_keys: dict[tuple[str, ...], list[str]] = {}
    unkeyed = 0
    for row in opened.rows:
        key = row_key_of(row.values, accepted.row_key)
        if key is None:
            unkeyed += 1
        else:
            current_keys.setdefault(key, []).append(row_digest(row.values))
    absent = [list(key) for key, _ in accepted.rows if key not in current_keys]
    changed = [list(key) for key, digest in accepted.rows if key in current_keys and digest not in current_keys[key]]
    accepted_keys = {key for key, _ in accepted.rows}
    # Absent from a complete input means deleted; from a partial one, merely unseen.
    absent_label = "deleted" if opened.state is InputState.PARSED else "not_examined"
    summary.update(
        {
            "present_unchanged": len(accepted.rows) - len(absent) - len(changed),
            absent_label: len(absent),
            f"{absent_label}_keys": _listed(absent),
            "changed": len(changed),
            "changed_keys": _listed(changed),
            "added": sum(1 for key in current_keys if key not in accepted_keys),
            "rows_without_snapshot_key": unkeyed,
        }
    )
    if absent:
        _report_absent(opened, len(absent), "were deleted", findings)
    if changed:
        findings.fail(
            Reason.SOURCE_MISMATCH,
            f"input {opened.input_id!r}: {len(changed)} accepted row(s) changed",
            FailureMode.SOURCE_MISMATCH,
        )
    return summary


def check_snapshot_completeness(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Rows accepted in the snapshot must still be present and unchanged.

    A deleted accepted row is FAIL with OMITTED_POPULATION, and a changed one
    is FAIL with SOURCE_MISMATCH. Rows added since the snapshot are counted
    but are not a failure: the snapshot vouches only for what it accepted.
    """
    _params(spec)
    snapshot = ctx.accepted_snapshot
    findings = Findings()
    evidence: dict[str, Any] = {"snapshot": snapshot.to_dict()}
    if not snapshot.declared:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE,
            "the manifest declares no accepted_snapshot",
            evidence,
            justification=SkipJustification.NOT_DECLARED,
        )
    if not snapshot.loaded:
        return document_unavailable(snapshot, evidence)
    try:
        accepted = _parse_snapshot(snapshot.content)
    except _FormatError as exc:
        return malformed_document(snapshot, str(exc), evidence)
    usable = _examinable(ctx, spec, findings)
    per_input: dict[str, Any] = {}
    compared: list[OpenedInput] = []
    for opened in usable:
        entry = accepted.get(opened.input_id)
        if entry is None or not entry.rows:
            findings.abstain(Reason.INSUFFICIENT_EVIDENCE, f"the snapshot accepts no rows of input {opened.input_id!r}")
            continue
        compared.append(opened)
        per_input[opened.input_id] = {**_input_summary(opened), **_compare_snapshot(opened, entry, findings)}
    evidence["inputs"] = per_input
    if not compared:
        return _no_rows_to_examine(ctx, spec, findings, evidence)
    return findings.outcome(rows_examined=sum(len(opened.rows) for opened in compared), evidence=evidence)


def build_snapshot(inputs: Iterable[OpenedInput]) -> dict[str, Any]:
    """Accept the current admitted rows of complete inputs as a snapshot document.

    Only PARSED inputs can be accepted: a snapshot of a partial input would
    vouch for a population that was never fully seen.
    """
    entries: dict[str, Any] = {}
    for opened in sorted(inputs, key=lambda item: item.input_id):
        if opened.state is not InputState.PARSED or opened.rows is None:
            raise ValueError(f"input {opened.input_id!r} is {opened.state.value}; only PARSED inputs can be accepted")
        key_fields = opened.spec.row_key
        rows = []
        for row in opened.rows:
            item: dict[str, Any] = {"sha256": row_digest(row.values)}
            if key_fields:
                item["key"] = list(row_key_of(row.values, key_fields) or ())
            rows.append(item)
        entries[opened.input_id] = {"row_key": list(key_fields), "rows": rows} if key_fields else {"rows": rows}
    return {"schema": SNAPSHOT_SCHEMA, "inputs": entries}


def _expected_values(value: Any) -> list[tuple[tuple[str, ...], Any, int | None]]:
    """Validate ``params.expected``: ``[{key, value, precision_decimals?}, ...]``."""
    if not isinstance(value, list) or not value:
        raise CheckParamError("INVALID_PARAM: expected must be a non-empty list of {key, value}")
    entries: list[tuple[tuple[str, ...], Any, int | None]] = []
    seen: set[tuple[str, ...]] = set()
    for index, item in enumerate(value):
        where = f"expected[{index}]"
        if not isinstance(item, Mapping):
            raise CheckParamError(f"INVALID_PARAM: {where} must be an object")
        unknown = sorted(set(item) - {"key", "value", "precision_decimals"})
        if unknown or "key" not in item or "value" not in item:
            raise CheckParamError(f"INVALID_PARAM: {where} needs key and value (unknown: {unknown})")
        raw_key = item["key"]
        key = (raw_key,) if isinstance(raw_key, str) else raw_key
        if not isinstance(key, (list, tuple)) or not key or any(not isinstance(part, str) or not part for part in key):
            raise CheckParamError(f"INVALID_PARAM: {where}.key must be a string or a list of strings")
        key = tuple(key)
        if key in seen:
            raise CheckParamError(f"INVALID_PARAM: {where}.key {list(key)} is declared twice")
        seen.add(key)
        claimed = item["value"]
        if isinstance(claimed, bool) or not isinstance(claimed, (str, int, Decimal)):
            raise CheckParamError(f"INVALID_PARAM: {where}.value must be a printed number (string)")
        precision = item.get("precision_decimals")
        if precision is not None and (isinstance(precision, bool) or not isinstance(precision, int) or precision < 0):
            raise CheckParamError(f"INVALID_PARAM: {where}.precision_decimals must be a non-negative integer")
        entries.append((key, claimed, precision))
    return entries


def check_numeric_agreement(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Declared values must agree with the stored values they cite (section 7 rules).

    ``params``: ``column`` (where the stored value is), ``expected`` (a list
    of ``{key, value, precision_decimals?}`` located by the input's
    ``row_key``), and optionally ``thousands`` and ``decimal_point``. Every
    comparison goes through :func:`~science_gate.invariants.compare_decimal`,
    looked up on the module at call time so the comparator the self-test
    judged is the one used. Rounding therefore never creates agreement, and a
    separator never evades comparison: undeclared, it makes the value
    ambiguous, never equal.

    Each comparison also records its **discrimination**: how many of the 21
    nearest printable claims the comparator would reject (section 17.8). The
    check records the weakest as ``discrimination`` and
    ``discrimination_ratio``; agreement from a comparison that could reject
    nothing is refused as vacuous.
    """
    params = _params(spec, ("column", "expected", "thousands", "decimal_point"), ("column", "expected"))
    column = params["column"]
    if not isinstance(column, str) or not column:
        raise CheckParamError("INVALID_PARAM: column must be a non-empty string")
    thousands, decimal_point = params.get("thousands"), params.get("decimal_point", ".")
    try:
        parse_decimal("0", thousands=thousands, decimal_point=decimal_point)
    except (TypeError, ValueError) as exc:
        raise CheckParamError(f"INVALID_PARAM: {exc}") from None
    expected = _expected_values(params["expected"])
    if len(spec.inputs) != 1:
        raise CheckParamError("INVALID_INPUTS: numeric_agreement compares exactly one input")
    findings = Findings()
    usable = _examinable(ctx, spec, findings)
    evidence: dict[str, Any] = {
        "input": spec.inputs[0],
        "column": column,
        "thousands": thousands,
        "decimal_point": decimal_point,
    }
    if not usable:
        return _no_rows_to_examine(ctx, spec, findings, evidence)
    opened = usable[0]
    key_fields = opened.spec.row_key
    if not key_fields:
        raise CheckParamError(f"INVALID_INPUTS: input {opened.input_id!r} must declare row_key to locate values")
    index: dict[tuple[str, ...], list[Row]] = {}
    for row in opened.rows:
        key = row_key_of(row.values, key_fields)
        if key is not None:
            index.setdefault(key, []).append(row)
    comparisons: list[dict[str, Any]] = []
    outcomes: Counter[str] = Counter()
    ratios: list[Ratio] = []
    for key, claimed, precision in expected:
        entry: dict[str, Any] = {"key": list(key), "claimed": claimed}
        comparisons.append(entry)
        rows = index.get(key, [])
        stored = rows[0].values.get(column) if len(rows) == 1 and isinstance(rows[0].values, Mapping) else None
        if not rows:
            entry["outcome"] = "ROW_NOT_FOUND"
            findings.abstain(Reason.INSUFFICIENT_EVIDENCE, f"no row has key {list(key)}")
        elif len(rows) > 1:
            entry["outcome"] = "AMBIGUOUS_KEY"
            findings.abstain(Reason.REQUIRES_HUMAN_REVIEW, f"key {list(key)} matches {len(rows)} rows")
        elif stored is None:
            entry["outcome"] = "COLUMN_ABSENT"
            findings.abstain(Reason.INSUFFICIENT_EVIDENCE, f"row {list(key)} has no value in column {column!r}")
        elif isinstance(stored, bool) or not isinstance(stored, (str, int, Decimal)):
            entry["outcome"] = "NOT_A_PRINTED_NUMBER"
            findings.abstain(Reason.REQUIRES_HUMAN_REVIEW, f"row {list(key)}: {column!r} is not a printed number")
        else:
            comparison = _invariants.compare_decimal(
                claimed, stored, thousands=thousands, decimal_point=decimal_point, precision_decimals=precision
            )
            entry.update(comparison.to_dict())
            ratio = _invariants.comparison_discrimination(
                claimed, stored, thousands=thousands, decimal_point=decimal_point, precision_decimals=precision
            )
            ratios.append(ratio)
            entry["discrimination"] = ratio.to_dict()
            if comparison.outcome == DISAGREES:
                findings.fail(
                    Reason.SOURCE_MISMATCH, f"key {list(key)}: {comparison.detail}", FailureMode.SOURCE_MISMATCH
                )
            elif comparison.agrees is None:
                findings.abstain(Reason.REQUIRES_HUMAN_REVIEW, f"key {list(key)}: {comparison.detail}")
        outcomes[entry["outcome"]] += 1
    evidence.update(
        {"rows_indexed": len(opened.rows), "comparisons": comparisons, "outcomes": dict(sorted(outcomes.items()))}
    )
    weakest = _weakest(ratios)
    if weakest is not None:
        evidence["discrimination"] = weakest.decimal
        evidence["discrimination_ratio"] = weakest.to_dict()
    compared = sum(1 for entry in comparisons if entry["outcome"] != "ROW_NOT_FOUND")
    return findings.outcome(rows_examined=compared, evidence=evidence)


def _weakest(ratios: Sequence[Ratio]) -> Ratio | None:
    """The least discriminating ratio: the first undefined one, else the minimum by exact value (first on ties).

    An undefined ratio wins because "could not be measured" is weaker than
    any measured discrimination; it must never be skipped as if absent.
    """
    weakest: Ratio | None = None
    lowest: Fraction | None = None
    for ratio in ratios:
        value = ratio.value
        if value is None:
            return ratio
        if lowest is None or value < lowest:
            weakest, lowest = ratio, value
    return weakest


# ---------------------------------------------------------------------------
# Built-in checks: role documents
# ---------------------------------------------------------------------------


def _parse_verdicts(document: Any) -> list[Mapping[str, Any]]:
    """Validate a reviews document (``science-gate-reviews/v1``)."""
    top = _object(document, "reviews document", ("schema", "verdicts"), ("schema", "verdicts"))
    _schema(top, REVIEWS_SCHEMA)
    if not isinstance(top["verdicts"], list):
        raise _FormatError("verdicts must be a list")
    verdicts = []
    for index, item in enumerate(top["verdicts"]):
        where = f"verdicts[{index}]"
        item = _object(item, where, ("reviewer", "verdict", "subject", "recorded_at"), ("reviewer", "verdict"))
        for name in ("reviewer", "verdict"):
            if not isinstance(item[name], str) or not item[name].strip():
                raise _FormatError(f"{where}.{name} must be a non-empty string")
        verdicts.append(item)
    return verdicts


def check_reviewer_protocol(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Every required reviewer has exactly one verdict (section 5).

    A missing reviewer or a duplicate verdict is ABSTAIN with PROTOCOL_BROKEN
    and PROTOCOL_DRIFT. The check establishes that the protocol was
    followed, not what the reviewers concluded. Names are compared after
    trimming and case folding, so "Reviewer-A" cannot pose as a second reviewer.
    """
    _params(spec)
    takes_no_inputs(spec, "reviews.verdicts document")
    findings = Findings()
    reviews = ctx.manifest.reviews
    if reviews is None:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE,
            "the manifest declares no review protocol",
            {},
            justification=SkipJustification.NOT_DECLARED,
        )
    document = ctx.role_document("reviews.verdicts")
    evidence: dict[str, Any] = {"required_reviewers": list(reviews.required_reviewers)}
    if not document.loaded:
        return document_unavailable(document, evidence)
    try:
        verdicts = _parse_verdicts(document.content)
    except _FormatError as exc:
        return malformed_document(document, str(exc), evidence)

    def identity(name: str) -> str:
        return name.strip().casefold()

    positions: dict[str, list[int]] = {}
    spelled: dict[str, str] = {}
    for position, verdict in enumerate(verdicts, start=1):
        who = identity(verdict["reviewer"])
        positions.setdefault(who, []).append(position)
        spelled.setdefault(who, verdict["reviewer"])
    required = {identity(name): name for name in reviews.required_reviewers}
    missing = [name for who, name in sorted(required.items()) if who not in positions]
    duplicates = {spelled[who]: where for who, where in sorted(positions.items()) if len(where) > 1}
    unexpected = sorted(spelled[who] for who in positions if who not in required)
    evidence.update(
        {
            "verdicts": document.to_dict(),
            "verdicts_recorded": len(verdicts),
            "reviewers_present": sorted(spelled[who] for who in positions if who in required),
            "missing_reviewers": missing,
            "duplicate_verdicts": duplicates,
            "unexpected_reviewers": unexpected,
            "verdict_values": dict(sorted(Counter(item["verdict"] for item in verdicts).items())),
            "scope": "protocol completeness only; the content of the verdicts is not judged",
        }
    )
    if missing:
        findings.abstain(
            Reason.PROTOCOL_BROKEN, f"required reviewer(s) {missing} recorded no verdict", FailureMode.PROTOCOL_DRIFT
        )
    if duplicates:
        findings.abstain(
            Reason.PROTOCOL_BROKEN,
            f"reviewer(s) {sorted(duplicates)} recorded more than one verdict",
            FailureMode.PROTOCOL_DRIFT,
        )
    return findings.outcome(rows_examined=len(verdicts), evidence=evidence)


_OFFSET = re.compile(r"([+-])(\d{2}):(\d{2})")
_LOCAL_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_EVENT_KEYS = ("id", "local_time", "timezone", "utc", "source")


def _utc_offset(text: str) -> timedelta | str:
    """The offset a timezone designation declares, or a named problem.

    Only fixed offsets that are in use somewhere on Earth (-12:00 to +14:00,
    minutes 00, 30 or 45) and ``UTC``/``Z`` are accepted. Named zones such as
    ``Region/City`` are not resolved: their offset depends on a time zone
    database whose version would silently change results between machines.
    """
    if text in ("UTC", "Z"):
        return timedelta(0)
    match = _OFFSET.fullmatch(text)
    if match is None:
        return "TIMEZONE_NAMED" if "/" in text else "TIMEZONE_INVALID"
    sign, hours, minutes = match.group(1), int(match.group(2)), int(match.group(3))
    offset = timedelta(hours=hours, minutes=minutes) * (-1 if sign == "-" else 1)
    if minutes not in (0, 30, 45) or not timedelta(hours=-12) <= offset <= timedelta(hours=14):
        return "TIMEZONE_INVALID"
    return offset


def _judge_event(event: Mapping[str, Any], window: tuple[datetime, datetime]) -> dict[str, Any]:
    """Evaluate one observation: declared zone, normalized UTC, agreement and window."""
    result: dict[str, Any] = {key: event.get(key) for key in ("id", "local_time", "timezone", "utc")}
    zone, local, utc_text = event.get("timezone"), event.get("local_time"), event.get("utc")
    if not isinstance(zone, str) or not zone:
        return {**result, "outcome": "TIMEZONE_MISSING"}
    offset = _utc_offset(zone)
    if isinstance(offset, str):
        return {**result, "outcome": offset}
    if not isinstance(utc_text, str) or not utc_text:
        return {**result, "outcome": "UTC_MISSING"}
    try:
        utc = parse_utc(utc_text)
    except ClockError:
        return {**result, "outcome": "UTC_INVALID"}
    if not isinstance(local, str) or not local:
        return {**result, "outcome": "LOCAL_TIME_MISSING"}
    if not _LOCAL_TIME.fullmatch(local):
        return {**result, "outcome": "LOCAL_TIME_INVALID"}
    try:
        computed = datetime.fromisoformat(local).replace(tzinfo=timezone.utc) - offset
    except ValueError:
        return {**result, "outcome": "LOCAL_TIME_INVALID"}
    result["computed_utc"] = format_utc(computed)
    if computed != utc:
        return {**result, "outcome": "UTC_MISMATCH"}
    result["in_window"] = window[0] <= utc <= window[1]
    return {**result, "outcome": "CONSISTENT" if result["in_window"] else "OUTSIDE_WINDOW"}


#: Per-event outcomes and what each means for the check.
_EVENT_FINDINGS: Mapping[str, tuple[Status, Reason, tuple[FailureMode, ...]]] = MappingProxyType(
    {
        "TIMEZONE_MISSING": (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        "TIMEZONE_NAMED": (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW, ()),
        "TIMEZONE_INVALID": (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW, ()),
        "UTC_MISSING": (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        "UTC_INVALID": (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        "LOCAL_TIME_MISSING": (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        "LOCAL_TIME_INVALID": (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        "UTC_MISMATCH": (Status.FAIL, Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,)),
        "OUTSIDE_WINDOW": (Status.FAIL, Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,)),
    }
)


def _parse_time_sources(document: Any) -> tuple[tuple[datetime, datetime], list[Mapping[str, Any]]]:
    """Validate a time-sources document (``science-gate-time-sources/v1``)."""
    top = _object(document, "time sources", ("schema", "window", "events"), ("schema", "window", "events"))
    _schema(top, TIME_SOURCES_SCHEMA)
    window = _object(top["window"], "window", ("start", "end"), ("start", "end"))
    try:
        start, end = parse_utc(window["start"]), parse_utc(window["end"])
    except ClockError as exc:
        raise _FormatError(f"window: {exc}") from None
    if start > end:
        raise _FormatError("window start is after its end")
    if not isinstance(top["events"], list):
        raise _FormatError("events must be a list")
    seen: set[str] = set()
    events = []
    for index, item in enumerate(top["events"]):
        item = _object(item, f"events[{index}]", _EVENT_KEYS, ("id",))
        if not isinstance(item["id"], str) or not item["id"] or item["id"] in seen:
            raise _FormatError(f"events[{index}].id must be a unique non-empty string")
        seen.add(item["id"])
        events.append(item)
    return (start, end), events


def check_time_source(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Each observation declares its timezone and its normalized UTC, and they agree
    with each other and with the requested window.

    A disagreement between the local time, the declared offset and the
    recorded UTC, or an observation outside the window, is FAIL with
    SOURCE_MISMATCH. A missing or unresolvable declaration is ABSTAIN.
    """
    _params(spec)
    takes_no_inputs(spec, "time_sources document")
    findings = Findings()
    document = ctx.role_document("time_sources")
    evidence: dict[str, Any] = {"document": document.to_dict()}
    if not document.declared:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE,
            "the manifest declares no time_sources",
            evidence,
            justification=SkipJustification.NOT_DECLARED,
        )
    if not document.loaded:
        return document_unavailable(document, evidence)
    try:
        window, events = _parse_time_sources(document.content)
    except _FormatError as exc:
        return malformed_document(document, str(exc), evidence)
    evidence["window"] = {"start": format_utc(window[0]), "end": format_utc(window[1])}
    if not events:
        return findings.not_applicable(
            Reason.INSUFFICIENT_EVIDENCE,
            "the time sources list no events",
            evidence,
            justification=SkipJustification.EMPTY_POPULATION,
        )
    judged = [_judge_event(event, window) for event in events]
    problems = [item for item in judged if item["outcome"] != "CONSISTENT"]
    for item in problems:
        status, reason, modes = _EVENT_FINDINGS[item["outcome"]]
        detail = f"event {item['id']!r}: {item['outcome']}"
        if status is Status.FAIL:
            findings.fail(reason, detail, *modes)
        else:
            findings.abstain(reason, detail, *modes)
    evidence.update(
        {
            "events_examined": len(judged),
            "outcomes": dict(sorted(Counter(item["outcome"] for item in judged).items())),
            "problem_events": _listed(problems),
            "rule": (
                "timezone must be UTC, Z or a fixed offset; local_time - offset must equal utc; "
                "window start <= utc <= window end"
            ),
        }
    )
    return findings.outcome(rows_examined=len(judged), evidence=evidence)


def _parse_summary(document: Any) -> tuple[str, dict[str, Mapping[str, Any]], dict[str, str]]:
    """Validate a stored summary (``science-gate-summary/v1``)."""
    top = _object(document, "summary", ("schema", "status", "pinned", "run_id", "recorded_at"), ("schema", "status"))
    _schema(top, SUMMARY_SCHEMA)
    if not isinstance(top["status"], str):
        raise _FormatError("status must be a string")
    pinned = _object(top.get("pinned", {}), "pinned", ("inputs", "documents"))
    inputs = pinned.get("inputs", {})
    if not isinstance(inputs, Mapping):
        raise _FormatError("pinned.inputs must be an object keyed by input id")
    pinned_inputs: dict[str, Mapping[str, Any]] = {}
    for input_id, item in inputs.items():
        where = f"pinned.inputs[{input_id!r}]"
        item = _object(item, where, ("sha256", "rows"), ("sha256",))
        _hex_digest(item["sha256"], f"{where}.sha256")
        rows = item.get("rows")
        if rows is not None and (isinstance(rows, bool) or not isinstance(rows, int) or rows < 0):
            raise _FormatError(f"{where}.rows must be a non-negative integer")
        pinned_inputs[input_id] = item
    documents = pinned.get("documents", {})
    if not isinstance(documents, Mapping):
        raise _FormatError("pinned.documents must map paths to sha256 digests")
    pinned_documents: dict[str, str] = {}
    for path, digest in documents.items():
        where = f"pinned.documents[{path!r}]"
        try:
            key = normalize_relpath(path)
        except UnsafePathError as exc:
            raise _FormatError(f"{where}: {exc}") from None
        if key in pinned_documents:
            raise _FormatError(f"{where} names the same file as another pin")
        pinned_documents[key] = _hex_digest(digest, where)
    return top["status"], pinned_inputs, pinned_documents


def _compare_pinned_input(
    ctx: CheckContext, input_id: str, pin: Mapping[str, Any], findings: Findings
) -> dict[str, Any]:
    """Compare one pinned input with what this run read."""
    entry: dict[str, Any] = {"pinned_sha256": pin["sha256"], "pinned_rows": pin.get("rows")}
    opened = ctx.inputs.get(input_id)
    if opened is None:
        findings.fail(
            Reason.SOURCE_MISMATCH,
            f"the summary pins input {input_id!r}, which this manifest does not declare",
            FailureMode.SOURCE_MISMATCH,
        )
        return {**entry, "outcome": "NOT_DECLARED"}
    entry.update({"current_sha256": opened.sha256, "current_rows": opened.record.rows})
    if opened.sha256 is None:
        findings.abstain(
            Reason.INSUFFICIENT_EVIDENCE, f"input {input_id!r} is {opened.state.value}", FailureMode.OMITTED_POPULATION
        )
        return {**entry, "outcome": "UNAVAILABLE"}
    if opened.sha256 != pin["sha256"] or (pin.get("rows") is not None and pin["rows"] != opened.record.rows):
        findings.fail(
            Reason.SOURCE_MISMATCH,
            f"input {input_id!r} differs from what the PASS summary pinned",
            FailureMode.SOURCE_MISMATCH,
        )
        return {**entry, "outcome": "CHANGED"}
    if pin.get("rows") == 0:
        findings.abstain(
            Reason.UNVERIFIED, f"the summary pins input {input_id!r} with 0 rows", FailureMode.VACUOUS_PASS
        )
        return {**entry, "outcome": "VACUOUS"}
    return {**entry, "outcome": "UNCHANGED"}


def _compare_pinned_document(ctx: CheckContext, path: str, digest: str, findings: Findings) -> dict[str, Any]:
    """Compare one pinned document's digest with the bytes on disk now."""
    current = ctx.read_document(path, role="summary_claim.pinned", parse="bytes")
    entry: dict[str, Any] = {"pinned_sha256": digest, "current_sha256": current.sha256, "state": current.state}
    if current.sha256 is None:
        findings.abstain(Reason.INSUFFICIENT_EVIDENCE, f"pinned document {path} is unavailable: {current.diagnostic}")
        return {**entry, "outcome": "UNAVAILABLE"}
    if current.sha256 != digest:
        findings.fail(
            Reason.SOURCE_MISMATCH, f"document {path} changed beneath the PASS summary", FailureMode.SOURCE_MISMATCH
        )
        return {**entry, "outcome": "CHANGED"}
    return {**entry, "outcome": "UNCHANGED"}


def check_summary_consistency(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """A stored PASS summary must match what this run actually recomputed.

    The summary pins input digests (and optionally row counts) and document
    digests. Each pin is compared with the bytes this run read. A PASS
    summary that pins nothing is narrated, not evidenced. Any declared
    evidence file the summary does not pin is a **blind spot**: a change
    there would slip beneath an unchanged PASS. Blind spots are listed, and
    they keep the check from passing (ABSTAIN with BLIND_SPOT).
    """
    _params(spec)
    takes_no_inputs(spec, "summary_claim document")
    findings = Findings()
    document = ctx.role_document("summary_claim")
    evidence: dict[str, Any] = {"summary": document.to_dict()}
    if not document.declared:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE,
            "the manifest declares no summary_claim",
            evidence,
            justification=SkipJustification.NOT_DECLARED,
        )
    if not document.loaded:
        return document_unavailable(document, evidence)
    try:
        status, pinned_inputs, pinned_documents = _parse_summary(document.content)
    except _FormatError as exc:
        return malformed_document(document, str(exc), evidence)
    evidence["stored_status"] = status
    if status != Status.PASS.value:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE,
            f"the stored summary claims {status}, not PASS: there is no PASS to confirm",
            evidence,
            justification=SkipJustification.NOT_DECLARED,
        )
    if not pinned_inputs and not pinned_documents:
        findings.abstain(
            Reason.UNVERIFIED,
            "the stored summary claims PASS but pins no evidence",
            FailureMode.NARRATED_VERIFICATION,
            FailureMode.VACUOUS_PASS,
        )
        return findings.outcome(rows_examined=0, evidence=evidence)

    compared_inputs = {
        input_id: _compare_pinned_input(ctx, input_id, pin, findings) for input_id, pin in sorted(pinned_inputs.items())
    }
    compared_documents = {
        path: _compare_pinned_document(ctx, path, digest, findings) for path, digest in sorted(pinned_documents.items())
    }
    # Every evidence file other than the summary itself should be pinned:
    # each declared role document, and each file a specialist check reads
    # (stored claim outputs, dependency node files), as preloaded before any
    # check ran. Declared inputs are pinned as inputs instead. Role paths
    # were validated by the manifest, so they normalize.
    own_role = "summary_claim"
    evidence_documents = {
        normalize_relpath(path)
        for role, _ in ROLE_DOCUMENTS
        if role != own_role and (path := ctx.role_path(role)) is not None
    }
    evidence_documents.update(ctx.preloaded_evidence())
    evidence_documents -= {document.path, *(opened.record.path for opened in ctx.inputs.values())}
    blind_inputs = sorted(input_id for input_id in ctx.inputs if input_id not in pinned_inputs)
    blind_documents = sorted(path for path in evidence_documents if path not in pinned_documents)
    evidence.update(
        {
            "inputs": compared_inputs,
            "documents": compared_documents,
            "blind_spots": {"inputs": blind_inputs, "documents": blind_documents},
        }
    )
    if blind_inputs or blind_documents:
        findings.abstain(
            Reason.BLIND_SPOT,
            f"BLIND_SPOT: the PASS summary does not pin input(s) {blind_inputs} or document(s) {blind_documents}; "
            "a change there would not be detected by this check",
        )
    return findings.outcome(rows_examined=len(compared_inputs) + len(compared_documents), evidence=evidence)


# ---------------------------------------------------------------------------
# Falsifier generators for the built-in kinds (section 17.5)
# ---------------------------------------------------------------------------
#
# Each generator builds the known-bad variant of exactly the evidence its
# check just passed, and names the rejection that variant must provoke. They
# read only through ``ctx``, write nothing, and return () when this instance
# admits no known-bad case (which leaves the PASS unwitnessed, never PASS).


def _record_values(values: Any) -> Any:
    """A record as plain data: CSV rows become ordinary dicts."""
    return dict(values) if isinstance(values, Mapping) else values


def _with_rows(opened: OpenedInput, rows: Iterable[Any], columns: tuple[str, ...] | None = None) -> InputOverride:
    """An override holding ``rows`` (record values) under ``columns`` or the input's own header."""
    return InputOverride(tuple(_record_values(values) for values in rows), columns if columns else opened.columns)


def _rows_of(ctx: CheckContext, spec: CheckSpec) -> list[OpenedInput]:
    """The check's inputs that have admitted rows, in declaration order."""
    found = []
    for input_id in spec.inputs:
        opened = ctx.inputs.get(input_id)
        if opened is not None and opened.usable and opened.rows:
            found.append(opened)
    return found


def falsify_row_count(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``drop-last-row``: one admitted row fewer than an INDEPENDENT expectation must FAIL."""
    overrides = {
        opened.input_id: _with_rows(opened, (row.values for row in opened.rows[:-1]))
        for opened in _rows_of(ctx, spec)
        if opened.spec.denominator_source is DenominatorSource.INDEPENDENT and opened.spec.expected_rows is not None
    }
    if not overrides:
        return ()
    return (
        FalsifierCase(
            "drop-last-row",
            "the last admitted row of each input with an INDEPENDENT expected_rows removed",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            inputs=overrides,
        ),
    )


def falsify_required_columns(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``drop-column``: the first declared column removed from the header and from every record must FAIL."""
    columns = spec.params.get("columns")
    if not isinstance(columns, list) or not columns or not isinstance(columns[0], str):
        return ()
    dropped = columns[0]
    overrides: dict[str, InputOverride] = {}
    for input_id in spec.inputs:
        opened = ctx.inputs.get(input_id)
        if opened is None or not opened.usable or opened.rows is None:
            continue
        rows = [
            {name: value for name, value in row.values.items() if name != dropped}
            if isinstance(row.values, Mapping)
            else row.values
            for row in opened.rows
        ]
        # A CSV header keeps every other column (possibly none); other formats have no header.
        header = None if opened.columns is None else tuple(name for name in opened.columns if name != dropped)
        overrides[input_id] = InputOverride(tuple(rows), header)
    if not overrides:
        return ()
    return (
        FalsifierCase(
            "drop-column",
            f"declared column {dropped!r} removed from the header and every record",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            inputs=overrides,
        ),
    )


def falsify_duplicate_rows(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``duplicate-first-row``: a copy of the first admitted row appended must FAIL."""
    overrides = {
        opened.input_id: _with_rows(opened, (*(row.values for row in opened.rows), opened.rows[0].values))
        for opened in _rows_of(ctx, spec)
    }
    if not overrides:
        return ()
    return (
        FalsifierCase(
            "duplicate-first-row",
            "a copy of the first admitted row appended to each input",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            inputs=overrides,
        ),
    )


def falsify_snapshot_completeness(
    ctx: CheckContext, spec: CheckSpec, result: CheckResult
) -> tuple[FalsifierCase, ...]:
    """``delete-accepted-row``: the first admitted row the snapshot accepts, removed, must FAIL."""
    snapshot = ctx.accepted_snapshot
    if not snapshot.loaded:
        return ()
    try:
        accepted = _parse_snapshot(snapshot.content)
    except _FormatError:
        return ()
    overrides: dict[str, InputOverride] = {}
    for opened in _rows_of(ctx, spec):
        entry = accepted.get(opened.input_id)
        if entry is None or not entry.rows:
            continue
        if entry.row_key:
            keys = {key for key, _ in entry.rows}
            hits = [row_key_of(row.values, entry.row_key) in keys for row in opened.rows]
        else:
            digests = {digest for _, digest in entry.rows}
            hits = [row_digest(row.values) in digests for row in opened.rows]
        if True not in hits:
            continue
        removed = hits.index(True)
        overrides[opened.input_id] = _with_rows(
            opened, (row.values for position, row in enumerate(opened.rows) if position != removed)
        )
    if not overrides:
        return ()
    return (
        FalsifierCase(
            "delete-accepted-row",
            "the first admitted row the accepted snapshot vouches for removed from each input",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            inputs=overrides,
        ),
    )


def falsify_numeric_agreement(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``shift-stored-value``: the first compared stored value set one printed unit above its claim must FAIL.

    The shifted value is ``claim + 10**-d`` (``d`` = the claim's printed
    decimals), printed with ``d`` decimals and no grouping, so it is the
    nearest value the claim must not agree with.
    """
    params = spec.params
    column = params.get("column")
    thousands, decimal_point = params.get("thousands"), params.get("decimal_point", ".")
    if len(spec.inputs) != 1 or not isinstance(column, str):
        return ()
    opened = ctx.inputs.get(spec.inputs[0])
    if opened is None or not opened.usable or not opened.rows or not opened.spec.row_key:
        return ()
    expected = _expected_values(params.get("expected"))
    index: dict[tuple[str, ...], list[int]] = {}
    for position, row in enumerate(opened.rows):
        key = row_key_of(row.values, opened.spec.row_key)
        if key is not None:
            index.setdefault(key, []).append(position)
    for key, claimed, _precision in expected:
        positions = index.get(key, [])
        if len(positions) != 1 or not isinstance(opened.rows[positions[0]].values, Mapping):
            continue
        target = opened.rows[positions[0]].values
        if target.get(column) is None:
            continue
        parsed = parse_decimal(claimed, thousands=thousands, decimal_point=decimal_point)
        if not parsed.ok or parsed.value is None or parsed.decimals is None:
            continue
        unit = Decimal((0, (1,), -parsed.decimals))
        shifted = format((parsed.value + unit).quantize(unit), "f")
        if decimal_point != ".":
            shifted = shifted.replace(".", decimal_point)
        rows = [
            {**_record_values(row.values), column: shifted} if position == positions[0] else row.values
            for position, row in enumerate(opened.rows)
        ]
        return (
            FalsifierCase(
                "shift-stored-value",
                f"the stored {column!r} of key {list(key)} set to {shifted}, one printed unit above the claim",
                Status.FAIL,
                Reason.SOURCE_MISMATCH,
                inputs={opened.input_id: _with_rows(opened, rows)},
            ),
        )
    return ()


def _json_document(document: Document) -> tuple[str, Mapping[str, Any]] | None:
    """A loaded role document's path and JSON object, or None."""
    if not document.loaded or document.path is None or not isinstance(document.content, Mapping):
        return None
    return document.path, document.content


def falsify_reviewer_protocol(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``drop-required-reviewer``: every verdict of the first required reviewer removed must be PROTOCOL_BROKEN."""
    reviews = ctx.manifest.reviews
    loaded = _json_document(ctx.role_document("reviews.verdicts"))
    if reviews is None or not reviews.required_reviewers or loaded is None:
        return ()
    path, content = loaded
    verdicts = content.get("verdicts")
    if not isinstance(verdicts, list):
        return ()
    first = reviews.required_reviewers[0].strip().casefold()
    kept = [
        item
        for item in verdicts
        if not (isinstance(item, Mapping) and isinstance(item.get("reviewer"), str))
        or item["reviewer"].strip().casefold() != first
    ]
    return (
        FalsifierCase(
            "drop-required-reviewer",
            f"every verdict of required reviewer {reviews.required_reviewers[0]!r} removed",
            Status.ABSTAIN,
            Reason.PROTOCOL_BROKEN,
            documents={path: canonical_bytes({**content, "verdicts": kept})},
        ),
    )


def falsify_time_source(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``shift-utc``: one hour added to the first event's recorded UTC must FAIL."""
    loaded = _json_document(ctx.role_document("time_sources"))
    if loaded is None:
        return ()
    path, content = loaded
    events = content.get("events")
    if not isinstance(events, list) or not events or not isinstance(events[0], Mapping):
        return ()
    try:
        shifted = format_utc(parse_utc(events[0].get("utc")) + timedelta(hours=1))
    except (ClockError, TypeError, ValueError):
        return ()
    changed = [{**events[0], "utc": shifted}, *events[1:]]
    return (
        FalsifierCase(
            "shift-utc",
            f"one hour added to the recorded utc of event {events[0].get('id')!r}",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            documents={path: canonical_bytes({**content, "events": changed})},
        ),
    )


def _other_digest(digest: str) -> str:
    """A well-formed digest that differs from ``digest`` and is derived from it, never random."""
    return sha256_bytes(f"science-gate falsifier: replaced {digest}".encode("utf-8"))


def falsify_summary_consistency(
    ctx: CheckContext, spec: CheckSpec, result: CheckResult
) -> tuple[FalsifierCase, ...]:
    """``alter-pinned-digest``: the first pinned input digest (else document digest), replaced, must FAIL."""
    loaded = _json_document(ctx.role_document("summary_claim"))
    if loaded is None:
        return ()
    path, content = loaded
    pinned = content.get("pinned")
    if not isinstance(pinned, Mapping):
        return ()
    for section in ("inputs", "documents"):
        pins = pinned.get(section)
        if not isinstance(pins, Mapping) or not pins:
            continue
        name = sorted(pins)[0]
        pin = pins[name]
        if section == "inputs" and isinstance(pin, Mapping) and isinstance(pin.get("sha256"), str):
            replaced: Any = {**pin, "sha256": _other_digest(pin["sha256"])}
        elif section == "documents" and isinstance(pin, str):
            replaced = _other_digest(pin)
        else:
            continue
        altered = {**content, "pinned": {**pinned, section: {**pins, name: replaced}}}
        return (
            FalsifierCase(
                "alter-pinned-digest",
                f"the summary's pinned digest of {section[:-1]} {name!r} replaced",
                Status.FAIL,
                Reason.SOURCE_MISMATCH,
                documents={path: canonical_bytes(altered)},
            ),
        )
    return ()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def ledger_evidence(check: Mapping[str, Any]) -> dict[str, Any]:
    """What a terminal ledger entry records for a check result, given its ``to_dict()`` form.

    The terminal entry carries every part of the result that the verdict,
    reason and identity fields do not, so the result can be rebuilt from the
    sealed ledger alone. Taking the serialized form lets ``report RUN_DIR``
    apply this same function to a ``run.json`` check and compare the output
    with the ledger. There is one definition, so the two cannot drift apart.
    """
    return {
        "execution_state": check.get("execution_state"),
        "rows_examined": check.get("rows_examined"),
        "failure_modes": check.get("failure_modes"),
        "diagnostics": check.get("diagnostics"),
        "check_evidence": check.get("evidence"),
    }


def _errored(spec: CheckSpec, invocation_id: str, diagnostic: str) -> CheckResult:
    """The result recorded for a check that raised or returned something unusable."""
    return CheckResult(
        check_id=spec.check_id,
        kind=spec.kind,
        version=spec.version,
        required=spec.required,
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ERROR,
        reason=Reason.PROTOCOL_BROKEN,
        failure_modes=(FailureMode.DEFECTIVE_VERIFICATION,),
        rows_examined=None,
        inputs=spec.inputs,
        evidence={"error": diagnostic},
        diagnostics=(diagnostic,),
        invocation_id=invocation_id,
    )


def _discrimination_problem(evidence: Mapping[str, Any]) -> str | None:
    """Why a recorded ``discrimination_ratio`` cannot back a PASS; None when it can or none is recorded."""
    if "discrimination_ratio" not in evidence:
        return None
    ratio = evidence["discrimination_ratio"]
    if not isinstance(ratio, Mapping) or ratio.get("state") != RatioState.DEFINED.value:
        return "its discrimination is not defined"
    numerator = ratio.get("numerator")
    if isinstance(numerator, bool) or not isinstance(numerator, int) or numerator < 1:
        return "its comparison could not have rejected any nearby value (discrimination 0)"
    return None


def _refuse_vacuous_pass(outcome: CheckOutcome) -> CheckOutcome:
    """A check may not PASS without examined rows, non-empty evidence and, where measured, discrimination.

    Built-in checks never try. This guard makes the rule hold for every
    registered check, so the verdict written to the ledger is already honest.
    A PASS whose evidence records a ``discrimination_ratio`` that is
    undefined or zero (section 17.8) came from a comparison that could not
    have failed, so it abstains too.
    """
    if outcome.verdict is not Status.PASS:
        return outcome
    if not outcome.rows_examined or not outcome.evidence:
        missing = "rows examined" if not outcome.rows_examined else "evidence"
        diagnostic = f"VACUOUS_PASS_REFUSED: the check reported PASS with no {missing}"
    else:
        problem = _discrimination_problem(outcome.evidence)
        if problem is None:
            return outcome
        diagnostic = f"NO_DISCRIMINATION: the check reported PASS but {problem}"
    return dataclasses.replace(
        outcome,
        verdict=Status.ABSTAIN,
        reason=Reason.INSUFFICIENT_EVIDENCE,
        failure_modes=(*outcome.failure_modes, FailureMode.VACUOUS_PASS),
        diagnostics=(*outcome.diagnostics, diagnostic),
    )


def _check_justification(outcome: CheckOutcome) -> None:
    """Refuse a skip label outside the closed vocabulary, or on anything but a skipped abstention (17.7)."""
    if not isinstance(outcome.evidence, Mapping) or SKIP_JUSTIFICATION_KEY not in outcome.evidence:
        return
    label = outcome.evidence[SKIP_JUSTIFICATION_KEY]
    try:
        SkipJustification(label)
    except ValueError:
        raise ValueError(f"{SKIP_JUSTIFICATION_KEY} {label!r} is not a SkipJustification") from None
    skipped = ExecutionState(outcome.execution_state) in (ExecutionState.SKIPPED, ExecutionState.NOT_APPLICABLE)
    if not skipped or Status(outcome.verdict) is not Status.ABSTAIN:
        raise ValueError(f"{SKIP_JUSTIFICATION_KEY} may label only a SKIPPED or NOT_APPLICABLE result that abstains")


def _result_from(
    spec: CheckSpec, invocation_id: str, outcome: Any
) -> tuple[CheckResult, tuple[ClaimTally, ...]]:
    """The single result builder: every check, falsifier and canary result is built here."""
    if not isinstance(outcome, CheckOutcome):
        raise TypeError(f"a check must return CheckOutcome, not {type(outcome).__name__}")
    if any(not isinstance(tally, ClaimTally) for tally in outcome.claim_tallies):
        raise TypeError("claim_tallies must contain ClaimTally instances")
    _check_justification(outcome)
    outcome = _refuse_vacuous_pass(outcome)
    result = CheckResult(
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
        invocation_id=invocation_id,
    )
    return result, tuple(outcome.claim_tallies)


CheckFunction = Callable[[CheckContext, CheckSpec], CheckOutcome]


def _invoke(
    function: CheckFunction, ctx: CheckContext, spec: CheckSpec, invocation_id: str
) -> tuple[CheckResult, tuple[ClaimTally, ...], CheckOutcome | None]:
    """Call one check function and build its result. Never raises: every failure becomes an ERROR result."""
    try:
        outcome = function(ctx, spec)
    except CheckParamError as exc:
        return _errored(spec, invocation_id, f"INVALID_PARAMS: {exc}"), (), None
    except Exception as exc:  # the contract: a check that raises is ERRORED, never a crash
        message = f"CHECK_RAISED: {type(exc).__name__}" + (f": {exc}" if str(exc) else "")
        return _errored(spec, invocation_id, message), (), None
    try:
        result, tallies = _result_from(spec, invocation_id, outcome)
    except (TypeError, ValueError) as exc:
        return _errored(spec, invocation_id, f"INVALID_OUTCOME: {exc}"), (), None
    return result, tallies, outcome


def _module_origin(module_name: str) -> Path | None:
    """The source file of ``module_name``, found without importing it, or None."""
    try:
        found = importlib.util.find_spec(module_name)
    except (ImportError, ValueError):
        return None
    origin = getattr(found, "origin", None) if found is not None else None
    if not isinstance(origin, str):
        return None
    path = Path(origin)
    return path if path.is_file() else None


def module_source_sha256(module_name: str) -> str | None:
    """SHA-256 of a module's source file; None when the module or its file cannot be found."""
    origin = _module_origin(module_name)
    if origin is None:
        return None
    try:
        return sha256_file(origin)[0]
    except OSError:
        return None


def params_sha256(params: Mapping[str, Any]) -> str:
    """``sha256_canonical(dict(params))``: the digest of a check's params, as every module computes it (17.4)."""
    return sha256_canonical(dict(params))


def checker_sha256(target: str, module_sha256: str | None) -> str:
    """The digest naming a checker: its ``module:function`` target and its module's source digest (17.4)."""
    return sha256_canonical({"target": target, "module_sha256": module_sha256})


class _Checkers:
    """Checker digests for one run, computed from each module's source once."""

    def __init__(self, registry: Mapping[str, str], module_digests: Mapping[str, str | None]) -> None:
        self._registry = registry
        self._modules = dict(module_digests)

    def digest(self, kind: str) -> str:
        target = self._registry.get(kind, "")
        module = target.partition(":")[0]
        if module not in self._modules:
            self._modules[module] = module_source_sha256(module)
        return checker_sha256(target, self._modules[module])


def _validated_cases(cases: Any, ctx: CheckContext) -> tuple[FalsifierCase, ...]:
    """A generator's return value, refused unless it is distinct cases over declared inputs."""
    if not isinstance(cases, (list, tuple)):
        raise TypeError(f"a falsifier generator must return a tuple of FalsifierCase, not {type(cases).__name__}")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, FalsifierCase):
            raise TypeError(f"a falsifier generator returned {type(case).__name__}, not FalsifierCase")
        if case.case_id in seen:
            raise ValueError(f"case id {case.case_id!r} is returned twice")
        seen.add(case.case_id)
        undeclared = sorted(set(case.inputs) - set(ctx.inputs))
        if undeclared:
            raise ValueError(f"case {case.case_id!r} overrides undeclared input(s) {undeclared}")
    return tuple(cases)


@dataclass(frozen=True)
class _Subject:
    """The would-be PASS a falsifier tests: the same function, spec and digests for every case."""

    spec: CheckSpec
    function: CheckFunction
    invocation_id: str
    checker_sha256: str
    params_sha256: str


def _run_falsifier(ctx: CheckContext, subject: _Subject, case: FalsifierCase, ledger: Ledger) -> dict[str, Any]:
    """Run the subject's checker over one known-bad overlay, inside its own ledger invocation."""
    spec = subject.spec
    overlay = ctx.overlay(case)
    control_id = falsifier_check_id(spec.check_id, case.case_id)
    digests = {input_id: overlay.inputs[input_id].sha256 if input_id in overlay.inputs else None for input_id in spec.inputs}
    invocation_id = ledger.start(
        check_id=control_id,
        check_kind=spec.kind,
        check_version=spec.version,
        input_ids=spec.inputs,
        input_sha256s=digests,
    )
    with _audit.current_check(control_id):
        result, _, _ = _invoke(subject.function, overlay, spec, invocation_id)
    if (result.verdict, result.reason) == (case.expected_verdict, case.expected_reason):
        outcome = FalsifierOutcome.REJECTED
    elif result.verdict is Status.PASS:
        outcome = FalsifierOutcome.ACCEPTED
    else:
        outcome = FalsifierOutcome.INCONCLUSIVE
    ledger.finish(
        invocation_id,
        verdict=result.verdict,
        reason=result.reason,
        evidence={
            "control": "falsifier",
            "subject_check_id": spec.check_id,
            "subject_invocation_id": subject.invocation_id,
            "case": case.to_dict(),
            "checker_sha256": subject.checker_sha256,
            "params_sha256": subject.params_sha256,
            "outcome": outcome.value,
        },
    )
    # The record names its invocation by its ledger check id, never by the run-derived invocation id:
    # check evidence must stay a function of content, so a packaged run reproduces on another day (18.10).
    # The ledger binds the two: the falsifier's terminal entry names the subject's invocation.
    return {
        "case_id": case.case_id,
        "description": case.description,
        "control_id": control_id,
        "checker_sha256": subject.checker_sha256,
        "params_sha256": subject.params_sha256,
        "expected": {"verdict": case.expected_verdict.value, "reason": case.expected_reason.value},
        "actual": {
            "verdict": result.verdict.value,
            "reason": result.reason.value,
            "execution_state": result.execution_state.value,
        },
        "outcome": outcome.value,
    }


def _witness(
    ctx: CheckContext,
    subject: _Subject,
    preliminary: CheckResult,
    ledger: Ledger,
    falsifiers: Mapping[str, str],
    records: list[dict[str, Any]],
) -> tuple[WitnessState, str]:
    """Generate and run the subject's falsifiers; return the witness state and, unless WITNESSED, why."""
    kind = subject.spec.kind
    target = falsifiers.get(kind)
    if target is None:
        return WitnessState.NO_GENERATOR, f"no negative-control generator is registered for kind {kind!r}"
    try:
        generator = resolve_check(target)
    except CheckUnavailable as exc:
        return WitnessState.NO_GENERATOR, f"the negative-control generator for {kind!r} is unavailable: {exc}"
    try:
        # Preparing a case is not a check examining the data, so its reads are attributed to nobody.
        with _audit.current_check(None):
            cases = _validated_cases(generator(ctx, subject.spec, preliminary), ctx)
    except Exception as exc:  # a broken generator leaves the PASS unwitnessed, never PASS
        return WitnessState.UNWITNESSED, f"the generator for {kind!r} failed: {type(exc).__name__}: {exc}"
    if not cases:
        return WitnessState.NO_CASE, f"the generator found no known-bad case for this {kind} instance"
    records.extend(_run_falsifier(ctx, subject, case, ledger) for case in cases)
    accepted = [record["case_id"] for record in records if record["outcome"] == FalsifierOutcome.ACCEPTED.value]
    if accepted:
        return WitnessState.REFUTED, f"known-bad case(s) {accepted} were accepted as PASS: the checker cannot reject them"
    if any(record["outcome"] == FalsifierOutcome.REJECTED.value for record in records):
        return WitnessState.WITNESSED, ""
    shown = "; ".join(
        f"{record['case_id']} ended {record['actual']['verdict']}/{record['actual']['reason']}, "
        f"expected {record['expected']['verdict']}/{record['expected']['reason']}"
        for record in records
    )
    return WitnessState.UNWITNESSED, f"no known-bad case produced its expected rejection: {shown}"


def _falsified(
    ctx: CheckContext,
    subject: _Subject,
    preliminary: CheckResult,
    outcome: CheckOutcome,
    ledger: Ledger,
    falsifiers: Mapping[str, str],
) -> CheckResult:
    """The subject's final result: its PASS kept only when WITNESSED (section 17.5, D2).

    The witness evidence is added in every case, and the final result is
    built by the same result builder as every other result.
    """
    records: list[dict[str, Any]] = []
    state, detail = _witness(ctx, subject, preliminary, ledger, falsifiers, records)
    evidence = {
        **outcome.evidence,
        "falsification": state.value,
        "checker_sha256": subject.checker_sha256,
        "params_sha256": subject.params_sha256,
        "falsifiers": records,
    }
    final = dataclasses.replace(outcome, evidence=evidence)
    if state is not WitnessState.WITNESSED:
        status, reason, modes = FALSIFICATION_OUTCOMES[state]
        final = dataclasses.replace(
            final,
            verdict=status,
            reason=reason,
            failure_modes=(*outcome.failure_modes, *modes),
            diagnostics=(*outcome.diagnostics, f"FALSIFIER_{state.value}: {detail}"),
        )
    try:
        return _result_from(subject.spec, subject.invocation_id, final)[0]
    except (TypeError, ValueError) as exc:
        return _errored(subject.spec, subject.invocation_id, f"INVALID_OUTCOME: {exc}")


def _run_one(
    ctx: CheckContext,
    spec: CheckSpec,
    ledger: Ledger,
    registry: Mapping[str, str],
    falsifiers: Mapping[str, str],
    checkers: _Checkers,
) -> tuple[CheckResult, tuple[ClaimTally, ...]]:
    """Run one check inside its ledger invocation, falsify a would-be PASS, and always close the invocation.

    Ledger order: the subject's STARTED entry, then each falsifier's STARTED
    and terminal entries, then the subject's terminal entry, which records
    the final (possibly downgraded) verdict.
    """
    digests = {input_id: ctx.inputs[input_id].sha256 if input_id in ctx.inputs else None for input_id in spec.inputs}
    invocation_id = ledger.start(
        check_id=spec.check_id,
        check_kind=spec.kind,
        check_version=spec.version,
        input_ids=spec.inputs,
        input_sha256s=digests,
    )
    tallies: tuple[ClaimTally, ...] = ()
    try:
        function = resolve_check(registry[spec.kind])
    except (KeyError, CheckUnavailable) as exc:
        result = _errored(spec, invocation_id, f"CHECK_UNAVAILABLE: {exc}")
    else:
        with _audit.current_check(spec.check_id):
            result, tallies, outcome = _invoke(function, ctx, spec, invocation_id)
        if result.verdict is Status.PASS and outcome is not None:
            subject = _Subject(spec, function, invocation_id, checkers.digest(spec.kind), params_sha256(spec.params))
            result = _falsified(ctx, subject, result, outcome, ledger, falsifiers)
    ledger.finish(invocation_id, verdict=result.verdict, reason=result.reason, evidence=ledger_evidence(result.to_dict()))
    return result, tallies


def _recording_view(ctx: CheckContext) -> CheckContext:
    """The same context with every mapping-valued row wrapped so value reads are reported (17.6, 17.12)."""
    inputs: dict[str, OpenedInput] = {}
    for input_id, opened in ctx.inputs.items():
        if opened.rows is None:
            inputs[input_id] = opened
            continue
        rows = tuple(
            Row(row.index, row.line, _audit.RecordingMapping(row.values, input_id, row.index))
            if isinstance(row.values, Mapping)
            else row
            for row in opened.rows
        )
        inputs[input_id] = dataclasses.replace(opened, rows=rows)
    return ctx._derive(inputs)


def run_checks(
    ctx: CheckContext,
    specs: Iterable[CheckSpec],
    ledger: Ledger,
    registry: Mapping[str, str] = REGISTRY,
    falsifiers: Mapping[str, str] = FALSIFIERS,
    module_digests: Mapping[str, str | None] | None = None,
) -> tuple[tuple[CheckResult, ...], tuple[tuple[str, ClaimTally], ...]]:
    """Run every declared check, in manifest order, each in its own invocation.

    A failing or crashing check never stops the run: the remaining checks
    still execute, so one early FAIL cannot hide a later problem. Every
    would-be PASS is falsified before its verdict is recorded. Returns the
    results and the ``(check_id, ClaimTally)`` pairs the checks reported.
    ``module_digests`` supplies the source digests already pinned, so a
    checker digest names exactly the module the PLAN pinned.
    """
    view = _recording_view(ctx) if _audit.values_requested() else ctx
    checkers = _Checkers(registry, module_digests or {})
    results: list[CheckResult] = []
    tallies: list[tuple[str, ClaimTally]] = []
    for spec in specs:
        result, reported = _run_one(view, spec, ledger, registry, falsifiers, checkers)
        results.append(result)
        tallies.extend((spec.check_id, tally) for tally in reported)
    return tuple(results), tuple(tallies)


# ---------------------------------------------------------------------------
# Run-level controls: comparator self-test and canary (sections 17.5, 17.6)
# ---------------------------------------------------------------------------

COMPARATOR_KIND = "comparator_self_test"
CANARY_INPUT = "control-canary"
_CANARY_COLUMNS = ("id", "value")
_CANARY_SPEC = InputSpec(input_id=CANARY_INPUT, path=CANARY_INPUT, format="csv")
#: ``(control id, rows, expected verdict)``: an exact duplicate must FAIL; two distinct rows must PASS.
_CANARIES: tuple[tuple[str, tuple[tuple[str, str], ...], Status], ...] = (
    (CANARY_MUST_FAIL, (("c1", "1"), ("c1", "1")), Status.FAIL),
    (CANARY_MUST_PASS, (("c1", "1"), ("c2", "2")), Status.PASS),
)


def _run_comparator_control(ledger: Ledger) -> dict[str, Any]:
    """Invocation ``control:comparator``: PASS only if the live comparator told every known pair apart."""
    invocation_id = ledger.start(check_id=COMPARATOR_CONTROL, check_kind=COMPARATOR_KIND, check_version="1")
    with _audit.current_check(COMPARATOR_CONTROL):
        pairs = [dict(pair) for pair in _invariants.run_comparator_self_test()]
    holds = all(pair["actual"] == pair["expected"] for pair in pairs)
    verdict, reason = (Status.PASS, Reason.VERIFIED) if holds else (Status.FAIL, Reason.BLIND_SPOT)
    ledger.finish(invocation_id, verdict=verdict, reason=reason, evidence={"control": "comparator", "pairs": pairs, "holds": holds})
    return {"invocation_id": invocation_id, "pairs": pairs, "holds": holds}


def _run_canary(ctx: CheckContext, ledger: Ledger, control_id: str, rows: Sequence[tuple[str, str]]) -> dict[str, Any]:
    """One canary: ``check_duplicate_rows`` over an in-memory CSV, through the same builder and ledger as every check."""
    override = InputOverride(tuple(dict(zip(_CANARY_COLUMNS, row)) for row in rows), _CANARY_COLUMNS)
    opened = memory_input(_CANARY_SPEC, override)
    canary_ctx = ctx._derive({CANARY_INPUT: opened}, files={}, roles={}, preloaded=set(), sealed=True)
    spec = CheckSpec(check_id=control_id, kind="duplicate_rows", version="1", required=True, inputs=(CANARY_INPUT,))
    invocation_id = ledger.start(
        check_id=control_id,
        check_kind=spec.kind,
        check_version=spec.version,
        input_ids=spec.inputs,
        input_sha256s={CANARY_INPUT: opened.sha256},
    )
    with _audit.current_check(control_id):
        result, _, _ = _invoke(check_duplicate_rows, canary_ctx, spec, invocation_id)
    ledger.finish(
        invocation_id,
        verdict=result.verdict,
        reason=result.reason,
        evidence={"control": "canary", **ledger_evidence(result.to_dict())},
    )
    return {"invocation_id": invocation_id, "verdict": result.verdict.value, "reason": result.reason.value}


def _run_canaries(ctx: CheckContext, ledger: Ledger) -> dict[str, Any]:
    """The must-fail canary and its known-good twin; ``holds`` only when each ended as it must."""
    summary: dict[str, Any] = {}
    holds = True
    for control_id, rows, expected in _CANARIES:
        name = control_id.rsplit(":", 1)[1]
        summary[name] = _run_canary(ctx, ledger, control_id, rows)
        holds = holds and summary[name]["verdict"] == expected.value
    summary["holds"] = holds
    return summary


# ---------------------------------------------------------------------------
# PLAN and harness pins (sections 17.4, 17.6)
# ---------------------------------------------------------------------------

#: The module that holds the engine itself; it is pinned in every run.
ENGINE_MODULE = "science_gate.verifier"


@dataclass(frozen=True)
class _Pin:
    """One pinned file: what it is, how the run names it, and its digest before anything ran."""

    role: str
    path: str
    sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "path": self.path, "sha256": self.sha256}


def _pin_location(manifest: Manifest, role: str, path: str) -> Path | None:
    """The file a pin names: a module's source, or a path confined to the manifest directory."""
    if role == "check_module":
        return _module_origin(path)
    try:
        return resolve_under_root(manifest.root, path)
    except (SafeIOError, OSError, ValueError):
        return None


def _pin_digest(manifest: Manifest, role: str, path: str) -> str | None:
    """The current digest of a pinned file, by the one rule used before and after the run; None when unreadable."""
    location = _pin_location(manifest, role, path)
    if location is None:
        return None
    limit = None if role == "check_module" else max(manifest.limits.max_file_bytes, MAX_MANIFEST_BYTES)
    try:
        # Discovery and document loading refuse special files. Pinning must
        # preserve that boundary: opening a writerless FIFO would block here.
        if not location.is_file():
            return None
        return sha256_file(location, max_bytes=limit)[0]
    except (OSError, SizeLimitExceeded):
        return None


def _display_path(path: str) -> str:
    """A declared path as reports show it: normalized when it is safe, verbatim otherwise."""
    try:
        return normalize_relpath(path)
    except UnsafePathError:
        return path


def _harness_pins(
    manifest: Manifest, ctx: CheckContext, registry: Mapping[str, str], falsifiers: Mapping[str, str]
) -> tuple[_Pin, ...]:
    """Pin the manifest, every declared input, every file read so far, and every module that will judge them.

    Taken after preloading and before the PLAN, so the PLAN commits to the
    exact bytes the checks will see and to the code that will judge them.
    """
    wanted = {("manifest", manifest.path.name)}
    wanted |= {("input", _display_path(spec.path)) for spec in manifest.inputs}
    wanted |= {("document", item["path"]) for item in ctx.read_log()}
    kinds = {spec.kind for spec in manifest.checks}
    modules = {ENGINE_MODULE}
    modules |= {table[kind].partition(":")[0] for table in (registry, falsifiers) for kind in kinds if kind in table}
    wanted |= {("check_module", module) for module in modules}
    return tuple(_Pin(role, path, _pin_digest(manifest, role, path)) for role, path in sorted(wanted))


def _watched(manifest: Manifest, pins: Sequence[_Pin]) -> dict[str, str]:
    """Every spelling the audit hook may report for a pinned file, mapped to the pin's path."""
    watched: dict[str, str] = {}
    for pin in pins:
        location = _pin_location(manifest, pin.role, pin.path)
        if location is not None:
            watched[_audit.normalize_path(location)] = pin.path
            watched[_audit.normalize_path(location, resolve=True)] = pin.path
    return watched


def _pin_report(
    manifest: Manifest, pins: Sequence[_Pin], watched: Mapping[str, str], recorder: _audit.AuditRecorder
) -> dict[str, Any]:
    """Re-hash every pin from disk and list every write that touched one (``DecisionInputs.pins``)."""
    pinned = [{**pin.to_dict(), "sha256_after": _pin_digest(manifest, pin.role, pin.path)} for pin in pins]
    writes: list[dict[str, str]] = []
    for event in recorder.writes:
        item = {"path": watched.get(event.path, event.path), "action": event.action, "event": event.event}
        if item not in writes:
            writes.append(item)
    return {"pinned": pinned, "writes": writes, "hook_errors": recorder.errors}


def build_plan(
    manifest: Manifest,
    accounting: InputAccounting,
    pins: Sequence[Mapping[str, Any]],
    run_id: str,
    registry: Mapping[str, str] = REGISTRY,
) -> dict[str, Any]:
    """The body of the run's PLAN entry (section 17.4): what this run commits to before executing.

    Inputs come from the accounting records joined to their declarations,
    with the population each input must have (``expected_rows`` and its
    source). Checks carry their params and checker digests, so a changed
    checker or a weakened parameter is a different plan. ``pins`` are the
    harness pins; a checker digest reuses its module's pinned digest.
    """
    records = {record.input_id: record for record in accounting.records}
    inputs = []
    for spec in sorted(manifest.inputs, key=lambda item: item.input_id):
        record = records.get(spec.input_id)
        inputs.append(
            {
                "input_id": spec.input_id,
                "required": record.required if record is not None else spec.required,
                "format": record.format if record is not None else spec.format,
                "declared_sha256": record.declared_sha256 if record is not None else spec.sha256,
                "row_key": list(spec.row_key),
                "expected_rows": spec.expected_rows,
                "denominator_source": spec.denominator_source.value,
            }
        )
    modules = {pin["path"]: pin["sha256"] for pin in pins if pin.get("role") == "check_module"}
    checkers = _Checkers(registry, modules)
    checks = [
        {
            "check_id": spec.check_id,
            "kind": spec.kind,
            "version": spec.version,
            "required": spec.required,
            "inputs": sorted(spec.inputs),
            "params_sha256": params_sha256(spec.params),
            "checker_sha256": checkers.digest(spec.kind),
        }
        for spec in sorted(manifest.checks, key=lambda item: item.check_id)
    ]
    return {
        "schema": PLAN_SCHEMA,
        "run_id": run_id,
        "manifest_sha256": manifest.sha256,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "inputs": inputs,
        "checks": checks,
        "pins": sorted(
            ({"role": pin["role"], "path": pin["path"], "sha256": pin["sha256"]} for pin in pins),
            key=lambda pin: (pin["role"], pin["path"]),
        ),
        "controls": sorted(PLANNED_CONTROLS),
    }


def _examined_inputs(checks: Iterable[CheckResult], inputs: Mapping[str, OpenedInput]) -> set[str]:
    """Inputs with admitted rows that at least one executed check consumed."""
    return {
        input_id
        for check in checks
        if check.execution_state is ExecutionState.CHECKED
        for input_id in check.inputs
        if input_id in inputs and inputs[input_id].usable
    }


def _rows_examined(checks: Sequence[CheckResult], inputs: Mapping[str, OpenedInput]) -> int:
    """The run's ``rows_examined`` (G1): distinct admitted data rows of declared inputs an executed check consumed.

    Each row counts once, however many checks read it. Comparisons, pins,
    verdicts, events, citations and claims are never rows, so a check that
    compared a digest cannot make a header-only input look examined.
    """
    return sum(len(inputs[input_id].rows or ()) for input_id in _examined_inputs(checks, inputs))


# ---------------------------------------------------------------------------
# Decision (section 6, amended by 17.7)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One reason the run is not (or not yet) a PASS, and where it came from.

    ``source`` is ``manifest``, ``input:<id>``, ``check:<id>``,
    ``invariant:<name>`` or ``contract:<rule>``.
    """

    status: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...]
    source: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason.value,
            "failure_modes": sorted(mode.value for mode in self.failure_modes),
            "source": self.source,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class DecisionInputs:
    """The facts :func:`decide` judges. Every field is data; nothing is re-read.

    ``declared_checks`` maps each declared check id to ``required``. It is
    None only when the manifest could not be read, in which case the number of
    expected checks is unknown, not zero. ``expected_plan``, ``pins`` and
    ``controls`` (section 17) are optional, so a sealed run can be replayed;
    an absent one leaves its invariant not applicable rather than holding.
    """

    accounting: InputAccounting
    checks: tuple[CheckResult, ...] = ()
    declared_checks: Mapping[str, bool] | None = None
    entries: tuple[Mapping[str, Any], ...] = ()
    ledger_head_sha256: str | None = None
    ledger_length: int | None = None
    run_id: str | None = None
    evidence_manifest: Sequence[Mapping[str, Any]] | None = None
    rows_examined: int | None = None
    claim_tallies: tuple[ClaimTally, ...] = ()
    manifest_issues: tuple[str, ...] = ()
    expected_plan: Mapping[str, Any] | None = None
    pins: Mapping[str, Any] | None = None
    controls: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Decision:
    """The decided status, with every finding and invariant that led to it, and the lattice's transition log."""

    status: Status
    reason: Reason
    reasons: tuple[Reason, ...]
    failure_modes: tuple[FailureMode, ...]
    findings: tuple[Finding, ...]
    invariants: tuple[InvariantResult, ...]
    counters: Mapping[str, Any]
    transitions: tuple[VerdictTransition, ...] = ()


@dataclass(frozen=True)
class _Shortfall:
    """A required check that did not execute, why, and the closed-vocabulary label it carries (if any)."""

    check_id: str
    why: str
    justification: SkipJustification | None


def _executed(check: CheckResult, traces: Mapping[str, InvocationTrace]) -> bool:
    """Executed means CHECKED with a terminal ledger invocation; anything less is a shortfall."""
    trace = traces.get(check.invocation_id) if check.invocation_id else None
    return check.execution_state is ExecutionState.CHECKED and trace is not None and trace.terminal


def _justification_of(check: CheckResult) -> SkipJustification | None:
    """The label of a skipped abstention, or None. A label on anything else justifies nothing."""
    if check.execution_state is ExecutionState.CHECKED or check.verdict is not Status.ABSTAIN:
        return None
    try:
        return SkipJustification(check.evidence.get(SKIP_JUSTIFICATION_KEY))
    except ValueError:
        return None


def _shortfalls(
    checks: Sequence[CheckResult], declared_checks: Mapping[str, bool] | None, traces: Mapping[str, InvocationTrace]
) -> tuple[_Shortfall, ...] | None:
    """Every required check that did not execute, in check-id order (G2). None when nothing is known to be required.

    A result whose verdict is ERROR is not a shortfall: its own ERROR
    decides the run.
    """
    if declared_checks is None:
        return None
    by_id = {check.check_id: check for check in checks}
    found: list[_Shortfall] = []
    for check_id in sorted(check_id for check_id, required in declared_checks.items() if required):
        check = by_id.get(check_id)
        if check is None:
            found.append(_Shortfall(check_id, "it has no result", None))
            continue
        if check.verdict is Status.ERROR or _executed(check, traces):
            continue
        why = (
            "its result has no terminal invocation"
            if check.execution_state is ExecutionState.CHECKED
            else f"it was {check.execution_state.value}"
        )
        found.append(_Shortfall(check_id, why, _justification_of(check)))
    return tuple(found)


def run_counters(
    accounting: InputAccounting,
    checks: Sequence[CheckResult],
    declared_checks: Mapping[str, bool] | None,
    entries: Sequence[Mapping[str, Any]],
    rows_examined: int | None,
) -> dict[str, Any]:
    """The PASS-contract counters (section 6), plus a few that explain them.

    Check counters count **required** checks, so ``checks_executed`` is
    comparable with ``checks_expected``. A required check counts as executed
    only if it reached CHECKED *and* its invocation has a terminal ledger
    entry. ``checks_shortfall`` counts required checks that did not execute
    (ERROR excluded) and ``checks_justified`` those of them carrying a
    closed-vocabulary label. Unknown values are None, never zero.
    """
    traces = index_invocations(entries)
    known = declared_checks is not None
    required_ids = sorted(check_id for check_id, required in (declared_checks or {}).items() if required)
    by_id = {check.check_id: check for check in checks}
    required = [by_id[check_id] for check_id in required_ids if check_id in by_id]
    shortfalls = _shortfalls(checks, declared_checks, traces)

    def count(predicate: Callable[[CheckResult], bool]) -> int | None:
        return sum(1 for check in required if predicate(check)) if known else None

    return {
        "expected_inputs": accounting.value("expected"),
        "inputs_discovered": accounting.value("discovered"),
        "inputs_opened": accounting.value("opened"),
        "inputs_parsed": accounting.value("parsed"),
        "inputs_examined": accounting.value("examined"),
        "rows_examined": rows_examined,
        "checks_declared": len(declared_checks) if known else None,
        "checks_expected": len(required_ids) if known else None,
        "checks_executed": count(lambda check: _executed(check, traces)),
        "checks_passed": count(lambda check: check.verdict is Status.PASS),
        "checks_failed": count(lambda check: check.verdict is Status.FAIL),
        "checks_abstained": count(lambda check: check.verdict is Status.ABSTAIN),
        "checks_errored": count(lambda check: check.verdict is Status.ERROR),
        "checks_skipped": count(lambda check: check.execution_state is ExecutionState.SKIPPED),
        "checks_not_applicable": count(lambda check: check.execution_state is ExecutionState.NOT_APPLICABLE),
        "checks_shortfall": None if shortfalls is None else len(shortfalls),
        "checks_justified": None if shortfalls is None else sum(1 for item in shortfalls if item.justification),
        "control_invocations": sum(1 for trace in traces.values() if is_control(trace.check_id)) if known else None,
    }


#: What a required input that is not PARSED means for the run.
_INPUT_STATE_FINDINGS: Mapping[InputState, tuple[Status, Reason, tuple[FailureMode, ...]]] = MappingProxyType(
    {
        InputState.MISSING: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.EMPTY: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.VACUOUS_PASS,)),
        InputState.PARTIAL: (
            Status.ABSTAIN,
            Reason.PARTIAL_EXECUTION,
            (FailureMode.PARTIAL_EXECUTION, FailureMode.OMITTED_POPULATION),
        ),
        InputState.REFUSED: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.OPEN_FAILED: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
        InputState.PARSE_ERROR: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.OMITTED_POPULATION,)),
    }
)


def _is_unsafe_path(diagnostics: Iterable[str]) -> bool:
    return any(text.startswith(f"REFUSED: {code}:") for text in diagnostics for code in _PATH_SAFETY_CODES)


def _input_findings(accounting: InputAccounting) -> list[Finding]:
    """Inputs: unsafe paths are ERROR, digest mismatches FAIL, incomplete required inputs ABSTAIN."""
    findings: list[Finding] = []
    for record in accounting.records:
        source = f"input:{record.input_id}"
        detail = "; ".join(record.diagnostics) or record.state.value
        if record.state is InputState.REFUSED and _is_unsafe_path(record.diagnostics):
            findings.append(Finding(Status.ERROR, Reason.PROTOCOL_BROKEN, (), source, f"unsafe path: {detail}"))
        elif record.state is InputState.HASH_MISMATCH:
            findings.append(
                Finding(Status.FAIL, Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,), source, detail)
            )
        elif record.required and record.state is not InputState.PARSED:
            status, reason, modes = _INPUT_STATE_FINDINGS[record.state]
            findings.append(Finding(status, reason, modes, source, f"required input is {record.state.value}: {detail}"))
    return findings


def _check_findings(checks: Sequence[CheckResult]) -> list[Finding]:
    """Checks: any ERROR is ERROR; a required FAIL or ABSTAIN counts; optional results are shown, not decisive."""
    findings: list[Finding] = []
    for check in sorted(checks, key=lambda item: item.check_id):
        if check.verdict is Status.PASS or (not check.required and check.verdict is not Status.ERROR):
            continue
        detail = f"{check.kind} {check.execution_state.value} {check.verdict.value}"
        if check.diagnostics:
            detail += ": " + "; ".join(check.diagnostics)
        findings.append(Finding(check.verdict, check.reason, check.failure_modes, f"check:{check.check_id}", detail))
    return findings


def _contract_findings(
    counters: Mapping[str, Any],
    evidence_manifest: Sequence[Mapping[str, Any]] | None,
    shortfalls: Sequence[_Shortfall] | None,
) -> list[Finding]:
    """The PASS contract's counting rules (section 6), each as its own finding.

    ``contract:checks_executed`` gives one finding per required check that
    did not execute (G2): a closed-vocabulary label contributes its row of
    ``SKIP_JUSTIFICATION_OUTCOMES`` (always ABSTAIN); anything else,
    including no result at all, is ``UNJUSTIFIED_SHORTFALL_OUTCOME``, FAIL /
    PARTIAL_EXECUTION (D1).
    """
    findings: list[Finding] = []
    vacuous = (FailureMode.VACUOUS_PASS,)

    def abstain(rule: str, reason: Reason, modes: tuple[FailureMode, ...], detail: str) -> None:
        findings.append(Finding(Status.ABSTAIN, reason, modes, f"contract:{rule}", detail))

    if counters["expected_inputs"] == 0:
        abstain("inputs_opened", Reason.INSUFFICIENT_EVIDENCE, vacuous, "no input was declared")
    elif counters["inputs_opened"] is not None and counters["inputs_opened"] < 1:
        abstain("inputs_opened", Reason.INSUFFICIENT_EVIDENCE, vacuous, "no input was opened")
    rows = counters["rows_examined"]
    if rows is None or rows < 1:
        detail = f"rows_examined={rows} (distinct data rows of declared inputs); a PASS needs at least 1"
        abstain("rows_examined", Reason.INSUFFICIENT_EVIDENCE, vacuous, detail)
    expected, executed = counters["checks_expected"], counters["checks_executed"]
    if expected == 0:
        abstain("checks_expected", Reason.INSUFFICIENT_EVIDENCE, vacuous, "no required check was declared")
    for shortfall in shortfalls or ():
        tally = f"checks_executed={executed} of checks_expected={expected}"
        if shortfall.justification is not None:
            status, reason, modes = SKIP_JUSTIFICATION_OUTCOMES[shortfall.justification]
            detail = f"required check {shortfall.check_id!r} did not execute: {shortfall.why}, justified as "
            detail += f"{shortfall.justification.value} ({tally})"
        else:
            status, reason, modes = UNJUSTIFIED_SHORTFALL_OUTCOME
            detail = f"required check {shortfall.check_id!r} did not execute: {shortfall.why}, with no "
            detail += f"closed-vocabulary justification ({tally})"
        findings.append(Finding(status, reason, modes, "contract:checks_executed", detail))
    if not evidence_manifest:
        abstain("evidence_manifest", Reason.INSUFFICIENT_EVIDENCE, vacuous, "the evidence manifest is empty")
    return findings


@dataclass(frozen=True)
class _Settled:
    status: Status
    reason: Reason
    reasons: tuple[Reason, ...]
    failure_modes: tuple[FailureMode, ...]
    transitions: tuple[VerdictTransition, ...]


def _settle(checks: Sequence[CheckResult], findings: Sequence[Finding]) -> _Settled:
    """Join the verdict lattice and choose the primary reason (17.7).

    The status is the join of every required PASS (in check-id order) and
    every finding (in gathering order). Nothing at all is NONE, which
    resolves to ``EMPTY_AGGREGATE_OUTCOME``: an empty aggregate never PASSes.
    The primary reason is the first finding at the top status, except that
    at FAIL a PARTIAL_EXECUTION finding counts only when no other FAIL
    finding exists (G3): a content failure names the reason, and an
    unexplained shortfall names it otherwise.
    """
    passing = sorted(check.check_id for check in checks if check.required and check.verdict is Status.PASS)
    contributions = [(f"check:{check_id}", Status.PASS, Reason.VERIFIED) for check_id in passing]
    contributions += [(finding.source, finding.status, finding.reason) for finding in findings]
    level, transitions = fold_verdicts(contributions)
    modes = tuple(sorted({mode for finding in findings for mode in finding.failure_modes}, key=lambda mode: mode.value))
    if level is VerdictLevel.NONE:
        status, reason = EMPTY_AGGREGATE_OUTCOME
        return _Settled(status, reason, (reason,), (*modes, FailureMode.VACUOUS_PASS), transitions)
    status = Status(level.value)
    if status is Status.PASS:
        return _Settled(Status.PASS, Reason.VERIFIED, (Reason.VERIFIED,), (), transitions)
    top = [finding for finding in findings if finding.status is status]
    if status is Status.FAIL:
        top = [finding for finding in top if finding.reason is not Reason.PARTIAL_EXECUTION] or top
    reasons = tuple(dict.fromkeys(finding.reason for finding in findings))
    return _Settled(status, top[0].reason, reasons, modes, transitions)


def decide(inputs: DecisionInputs) -> Decision:
    """Apply the PASS contract and the verdict lattice (sections 6 and 17.7).

    Findings are gathered in a fixed order: manifest, inputs, checks
    (by id), contract counters, then invariants (in ``INVARIANT_NAMES``
    order). That order is also the tie-break for the primary reason. The
    invariants are evaluated *after* a tentative status is known, and with
    that status as the run's claim, so the ``pass_requires_*`` invariants
    judge exactly the PASS the run is about to report. Any violation then
    outranks the tentative PASS.

    Only required checks decide FAIL and ABSTAIN. An optional check's
    non-PASS result stays visible in its own record but does not decide the
    run. The exception is ERROR, which always does: a crashed checker means
    the tool itself misbehaved.
    """
    # Manifest issues can quote manifest text verbatim, so they are redacted like diagnostics.
    findings: list[Finding] = [
        Finding(Status.ERROR, Reason.PROTOCOL_BROKEN, (), "manifest", redact_text(issue))
        for issue in inputs.manifest_issues
    ]
    counters = run_counters(
        inputs.accounting, inputs.checks, inputs.declared_checks, inputs.entries, inputs.rows_examined
    )
    if not inputs.manifest_issues:
        findings += _input_findings(inputs.accounting)
        findings += _check_findings(inputs.checks)
        shortfalls = _shortfalls(inputs.checks, inputs.declared_checks, index_invocations(inputs.entries))
        findings += _contract_findings(counters, inputs.evidence_manifest, shortfalls)
    tentative = _settle(inputs.checks, findings).status
    invariants = evaluate_invariants(
        InvariantContext(
            entries=inputs.entries,
            checks=inputs.checks,
            accounting=inputs.accounting,
            declared_checks=inputs.declared_checks or {},
            claimed_status=tentative,
            evidence_manifest=inputs.evidence_manifest,
            ledger_head_sha256=inputs.ledger_head_sha256,
            ledger_length=inputs.ledger_length,
            run_id=inputs.run_id,
            claim_tallies=inputs.claim_tallies,
            expected_plan=inputs.expected_plan,
            pins=inputs.pins,
            controls=inputs.controls,
            rows_examined=inputs.rows_examined,
        )
    )
    for invariant in invariants:
        if invariant.violated:
            outcome = VIOLATION_OUTCOMES[invariant.name]
            source = f"invariant:{invariant.name}"
            findings.append(
                Finding(outcome.status, outcome.reason, (outcome.failure_mode,), source, invariant.detail)
            )
    settled = _settle(inputs.checks, findings)
    return Decision(
        settled.status,
        settled.reason,
        settled.reasons,
        settled.failure_modes,
        tuple(findings),
        invariants,
        counters,
        settled.transitions,
    )


# ---------------------------------------------------------------------------
# Run-level controls summary (section 17.8)
# ---------------------------------------------------------------------------


def _min_discrimination(checks: Sequence[CheckResult]) -> dict[str, Any] | None:
    """The least discriminating PASS, by exact value over results that record ``discrimination_ratio``."""
    best: tuple[Fraction, CheckResult] | None = None
    for check in sorted(checks, key=lambda item: item.check_id):
        ratio = check.evidence.get("discrimination_ratio")
        if check.verdict is not Status.PASS or not isinstance(ratio, Mapping):
            continue
        try:
            value = Ratio(ratio.get("numerator"), ratio.get("denominator")).value
        except ValueError:
            continue
        if value is not None and (best is None or value < best[0]):
            best = (value, check)
    if best is None:
        return None
    check = best[1]
    return {
        "check_id": check.check_id,
        "discrimination": check.evidence.get("discrimination"),
        "ratio": check.evidence["discrimination_ratio"],
    }


def _claim_join_totals(checks: Sequence[CheckResult]) -> dict[str, int] | None:
    """The outcome counts of every ``claim_join`` result, summed; None when none recorded counts."""
    totals: dict[str, int] | None = None
    for check in checks:
        counts = check.evidence.get("counts")
        if check.kind != "claim_join" or not isinstance(counts, Mapping):
            continue
        totals = totals or {outcome.value: 0 for outcome in AssertionOutcome}
        for outcome in AssertionOutcome:
            value = counts.get(outcome.value)
            if isinstance(value, int) and not isinstance(value, bool):
                totals[outcome.value] += value
    return totals


def _run_controls(
    *,
    plan: Mapping[str, Any],
    plan_entry: Mapping[str, Any],
    checks: Sequence[CheckResult],
    entries: Sequence[Mapping[str, Any]],
    canary: Mapping[str, Any],
    comparator: Mapping[str, Any],
    pins: Mapping[str, Any],
) -> dict[str, Any]:
    """``RunResult.controls`` before the decision adds its transition log."""
    witnesses: dict[str, Any] = {state.value: [] for state in WitnessState}
    for check in sorted(checks, key=lambda item: item.check_id):
        state = check.evidence.get("falsification")
        if state in witnesses:
            witnesses[state].append(check.check_id)
    witnesses["invocations"] = sum(
        1
        for trace in index_invocations(entries).values()
        if trace.check_id is not None and trace.check_id.startswith(_invariants.FALSIFIER_PREFIX)
    )
    changed = [item["path"] for item in pins["pinned"] if item["sha256"] != item["sha256_after"]]
    return {
        "plan": {
            "entry_sha256": plan_entry["entry_sha256"],
            "manifest_sha256": plan["manifest_sha256"],
            "checks_planned": len(plan["checks"]),
            "inputs_planned": len(plan["inputs"]),
            "pins": len(plan["pins"]),
        },
        "falsifiers": witnesses,
        "canary": dict(canary),
        "comparator_self_test": dict(comparator),
        "pins": {
            "pinned": len(pins["pinned"]),
            "changed": changed,
            "writes": list(pins["writes"]),
            "holds": not changed and not pins["writes"] and not pins["hook_errors"],
        },
        "min_discrimination": _min_discrimination(checks),
        "claim_join": _claim_join_totals(checks),
        "verdict_transitions": [],
    }


# ---------------------------------------------------------------------------
# Evidence manifest and the verify() entry point
# ---------------------------------------------------------------------------


def build_evidence_manifest(
    *,
    manifest_name: str,
    manifest_sha256: str | None,
    accounting: InputAccounting,
    documents: Sequence[Mapping[str, Any]],
    checks: Sequence[CheckResult],
    ledger_bytes: bytes,
    ledger_length: int,
) -> dict[str, Any]:
    """One entry per piece of evidence, each with its SHA-256 (section 12).

    Evidence that does not exist (a missing input, an unreadable document) has
    no digest, so it cannot be an entry. It is listed under ``absent`` instead,
    and never silently dropped.
    """
    entries: list[dict[str, Any]] = []
    absent: list[dict[str, Any]] = []
    if manifest_sha256 is not None:
        entries.append({"kind": "manifest", "name": "manifest", "path": manifest_name, "sha256": manifest_sha256})
    else:
        absent.append({"kind": "manifest", "name": "manifest", "path": manifest_name, "state": "UNREADABLE"})
    for record in accounting.records:
        item = {"kind": "input", "name": record.input_id, "path": record.path, "state": record.state.value}
        if record.sha256 is None:
            absent.append({**item, "required": record.required})
        else:
            entries.append({**item, "sha256": record.sha256, "bytes": record.size_bytes})
    for document in documents:
        item = {
            "kind": "document",
            "name": ",".join(document["roles"]),
            "path": document["path"],
            "state": document["state"],
        }
        if document["sha256"] is None:
            absent.append(item)
        else:
            entries.append({**item, "sha256": document["sha256"], "bytes": document["bytes"]})
    for check in sorted(checks, key=lambda item: item.check_id):
        entries.append(
            {
                "kind": "check_evidence",
                "name": check.check_id,
                "invocation_id": check.invocation_id,
                "sha256": sha256_canonical(check.evidence),
            }
        )
    entries.append(
        {
            "kind": "ledger",
            "name": "ledger",
            "path": "ledger.jsonl",
            "sha256": sha256_bytes(ledger_bytes),
            "entries": ledger_length,
        }
    )
    return {"schema": EVIDENCE_MANIFEST_SCHEMA, "entries": entries, "absent": absent}


@dataclass(frozen=True)
class VerificationRun:
    """Everything one ``verify`` produced, ready for :mod:`science_gate.reports`.

    ``plan`` is the PLAN body the ledger opens with (None for an invalid
    manifest); ``controls`` mirrors ``RunResult.controls``.
    """

    result: RunResult
    ledger: Ledger
    findings: tuple[Finding, ...]
    evidence_manifest: Mapping[str, Any]
    manifest_name: str
    manifest_sha256: str | None
    manifest: Manifest | None = None
    manifest_issues: tuple[ManifestIssue, ...] = ()
    documents: tuple[Mapping[str, Any], ...] = ()
    claim_tallies: tuple[tuple[str, ClaimTally], ...] = ()
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    plan: Mapping[str, Any] | None = None
    pins: Mapping[str, Any] | None = None

    @property
    def status(self) -> Status:
        return self.result.status

    @property
    def exit_code(self) -> int:
        return self.result.exit_code

    @property
    def controls(self) -> Mapping[str, Any]:
        return self.result.controls


def _unavailable_accounting() -> InputAccounting:
    """Accounting for a run whose manifest could not be read: every count unknown."""
    counters = {name: AccountingCount(None, DenominatorSource.UNAVAILABLE) for name in ACCOUNTING_COUNTERS}
    return InputAccounting(counters, Closure(DenominatorSource.UNAVAILABLE, None, None, None), ())


def _digest_if_readable(path: Path) -> str | None:
    """SHA-256 of a manifest file that failed validation, when its bytes can be read."""
    try:
        if not path.is_file():
            return None
        return sha256_file(path, max_bytes=MAX_MANIFEST_BYTES)[0]
    except (OSError, SizeLimitExceeded):
        return None


def _run_id(material: Mapping[str, Any]) -> str:
    """``run-`` plus 16 hex of a content hash: never random, stable under a fixed clock (D11)."""
    return "run-" + sha256_canonical(material)[:16]


def _finish(
    *,
    run_id: str,
    started_at: str,
    accounting: InputAccounting,
    checks: tuple[CheckResult, ...],
    evidence: Mapping[str, Any],
    decision_inputs: DecisionInputs,
    controls: Mapping[str, Any],
) -> tuple[RunResult, Decision]:
    decision = decide(decision_inputs)
    result = RunResult(
        status=decision.status,
        reason=decision.reason,
        reasons=decision.reasons,
        failure_modes=decision.failure_modes,
        run_id=run_id,
        accounting=accounting,
        checks=checks,
        invariants=decision.invariants,
        evidence_manifest_sha256=sha256_canonical(evidence),
        started_at=started_at,
        completed_at=now(),
        counters=decision.counters,
        controls={**controls, "verdict_transitions": [item.to_dict() for item in decision.transitions]},
    )
    return result, decision


def _invalid_manifest_run(path: Path, error: ManifestError, started_at: str, network: NetworkPolicy) -> VerificationRun:
    """An ERROR run for a manifest that is missing, malformed or unsafe. Nothing else is read or planned."""
    digest = _digest_if_readable(path)
    issues = tuple(str(issue) for issue in error.issues)
    run_id = _run_id({"manifest": path.name, "manifest_sha256": digest, "issues": issues, "started_at": started_at})
    ledger = Ledger(run_id)
    accounting = _unavailable_accounting()
    evidence = build_evidence_manifest(
        manifest_name=path.name,
        manifest_sha256=digest,
        accounting=accounting,
        documents=(),
        checks=(),
        ledger_bytes=ledger.to_jsonl(),
        ledger_length=0,
    )
    result, decision = _finish(
        run_id=run_id,
        started_at=started_at,
        accounting=accounting,
        checks=(),
        evidence=evidence,
        decision_inputs=DecisionInputs(
            accounting=accounting,
            ledger_length=0,
            run_id=run_id,
            evidence_manifest=evidence["entries"],
            rows_examined=0,
            manifest_issues=issues,
        ),
        controls=empty_controls(),
    )
    return VerificationRun(
        result=result,
        ledger=ledger,
        findings=decision.findings,
        evidence_manifest=evidence,
        manifest_name=path.name,
        manifest_sha256=digest,
        manifest_issues=error.issues,
        network=network,
    )


def verify(
    manifest_path: str | Path,
    *,
    live: bool = False,
    network: NetworkPolicy | None = None,
    registry: Mapping[str, str] = REGISTRY,
    falsifiers: Mapping[str, str] = FALSIFIERS,
) -> VerificationRun:
    """Verify the manifest at ``manifest_path`` and return the decided run.

    Live network access is enabled by ``live=True`` or the manifest's
    ``citations.live``. An injected ``network`` policy supplies the opener
    and limits, and the two switches can only turn live access on, never off.
    ``registry`` and ``falsifiers`` exist so tests can register extra kinds
    and their negative-control generators. The registry must map every kind
    a manifest names; a kind without a generator can never PASS.

    Exceptions raised by checks are recorded as ERROR results. An exception
    escaping this function is a defect in the engine itself.
    """
    # One run redacts thousands of strings; the environment is read once for all of them.
    with redaction_scope():
        return _verify(Path(manifest_path), live=live, network=network, registry=registry, falsifiers=falsifiers)


def _verify(
    path: Path,
    *,
    live: bool,
    network: NetworkPolicy | None,
    registry: Mapping[str, str],
    falsifiers: Mapping[str, str],
) -> VerificationRun:
    """The body of :func:`verify`, run inside one redaction scope."""
    started_at = now()
    _audit.install()
    base_policy = network or NetworkPolicy()
    try:
        manifest = load_manifest(path, registered_kinds=registry)
    except ManifestError as exc:
        policy = dataclasses.replace(base_policy, live=base_policy.live or live)
        return _invalid_manifest_run(path, exc, started_at, policy)
    manifest_live = bool(manifest.citations is not None and manifest.citations.live)
    policy = dataclasses.replace(base_policy, live=base_policy.live or live or manifest_live)

    accounting, opened = discover(manifest)
    ctx = CheckContext(manifest, opened, policy)
    ctx.preload(spec.kind for spec in manifest.checks)
    run_id = _run_id(
        {
            "manifest_sha256": manifest.sha256,
            "inputs": {input_id: item.sha256 for input_id, item in opened.items()},
            "documents": {item["path"]: item["sha256"] for item in ctx.read_log()},
            "started_at": started_at,
            "tool": __version__,
        }
    )
    ctx.bind_run_id(run_id)
    pins = _harness_pins(manifest, ctx, registry, falsifiers)
    plan = build_plan(manifest, accounting, [pin.to_dict() for pin in pins], run_id, registry)
    ledger = Ledger(run_id)
    plan_entry = ledger.plan(plan)
    watched = _watched(manifest, pins)
    module_digests = {pin.path: pin.sha256 for pin in pins if pin.role == "check_module"}
    with _audit.recording(watch=watched) as recorder:
        checks, tallies = run_checks(ctx, manifest.checks, ledger, registry, falsifiers, module_digests)
        comparator = _run_comparator_control(ledger)
        canary = _run_canaries(ctx, ledger)
    pin_report = _pin_report(manifest, pins, watched, recorder)
    rows = _rows_examined(checks, opened)
    accounting = accounting.with_examined(len(_examined_inputs(checks, opened)))
    documents = ctx.read_log()
    seal = ledger.seal()
    evidence = build_evidence_manifest(
        manifest_name=manifest.path.name,
        manifest_sha256=manifest.sha256,
        accounting=accounting,
        documents=documents,
        checks=checks,
        ledger_bytes=ledger.to_jsonl(),
        ledger_length=seal["ledger_length"],
    )
    controls = _run_controls(
        plan=plan,
        plan_entry=plan_entry,
        checks=checks,
        entries=ledger.entries,
        canary=canary,
        comparator=comparator,
        pins=pin_report,
    )
    result, decision = _finish(
        run_id=run_id,
        started_at=started_at,
        accounting=accounting,
        checks=checks,
        evidence=evidence,
        decision_inputs=DecisionInputs(
            accounting=accounting,
            checks=checks,
            declared_checks={spec.check_id: spec.required for spec in manifest.checks},
            entries=ledger.entries,
            ledger_head_sha256=seal["ledger_head_sha256"],
            ledger_length=seal["ledger_length"],
            run_id=run_id,
            evidence_manifest=evidence["entries"],
            rows_examined=rows,
            claim_tallies=tuple(tally for _, tally in tallies),
            expected_plan=plan,
            pins=pin_report,
            controls=controls,
        ),
        controls=controls,
    )
    return VerificationRun(
        result=result,
        ledger=ledger,
        findings=decision.findings,
        evidence_manifest=evidence,
        manifest_name=manifest.path.name,
        manifest_sha256=manifest.sha256,
        manifest=manifest,
        documents=documents,
        claim_tallies=tallies,
        network=policy,
        plan=plan,
        pins=pin_report,
    )
