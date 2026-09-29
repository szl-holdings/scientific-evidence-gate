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
that it had the opportunity to fail. The engine enforces this in three ways.
A check that reports PASS without rows or evidence is downgraded before its
verdict is recorded. Invariants are evaluated against the status the run is
about to claim. And every finding that blocks PASS is kept, with its source,
so the reports can say exactly why.
"""

from __future__ import annotations

import dataclasses
import importlib
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import TOOL_NAME, __version__
from ._canonical import (
    SizeLimitExceeded,
    StrictJSONError,
    sha256_bytes,
    sha256_canonical,
    sha256_file,
    strict_loads,
)
from ._clock import ClockError, format_utc, now, parse_utc
from ._redact import redact_text
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
    safe_read,
)
from .discovery import OpenedInput, Row, discover, row_key_of
from .invariants import (
    DISAGREES,
    VIOLATION_OUTCOMES,
    ClaimTally,
    InvariantContext,
    compare_decimal,
    evaluate_invariants,
    parse_decimal,
)
from .ledger import Ledger, index_invocations
from .manifests import MAX_MANIFEST_BYTES, CheckSpec, Manifest, ManifestError, ManifestIssue, load_manifest
from .models import (
    ACCOUNTING_COUNTERS,
    AccountingCount,
    CheckResult,
    Closure,
    DenominatorSource,
    ExecutionState,
    FailureMode,
    InputAccounting,
    InputState,
    InvariantResult,
    Reason,
    RunResult,
    Status,
)

__all__ = [
    "REGISTRY",
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
    "run_checks",
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

_RANK: Mapping[Status, int] = MappingProxyType({Status.PASS: 0, Status.ABSTAIN: 1, Status.FAIL: 2, Status.ERROR: 3})
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


@dataclass(frozen=True, eq=False)
class CheckContext:
    """Everything a check may look at (section 5).

    The manifest, the opened inputs, the accepted snapshot, the manifest
    directory, the limits and the network policy. Files beyond the declared
    inputs are read only through :meth:`read_document`. It reads each file
    once, confines it to the manifest directory and the size limit, and
    records its digest, so every file a check relied on appears in the
    evidence manifest.
    """

    manifest: Manifest
    inputs: Mapping[str, OpenedInput]
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    _files: dict[str, _FileRead] = field(default_factory=dict, init=False, repr=False)
    _roles: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False)

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


class _Findings:
    """Collects one check's findings and turns them into a single outcome.

    A definite contradiction (FAIL) outranks missing evidence (ABSTAIN), and
    PASS is returned only when nothing at all was found. The first finding at
    the winning level supplies the reason, so the outcome is deterministic.
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
        )

    def not_applicable(self, reason: Reason, detail: str, evidence: Mapping[str, Any]) -> CheckOutcome:
        """Nothing to examine: never PASS, and 0 rows is the true count."""
        return CheckOutcome(
            execution_state=ExecutionState.NOT_APPLICABLE,
            verdict=Status.ABSTAIN,
            reason=reason,
            failure_modes=self._modes(),
            rows_examined=0,
            evidence=evidence,
            diagnostics=(*self.diagnostics, detail),
        )


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


def _takes_no_inputs(spec: CheckSpec, source: str) -> None:
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


def _examinable(ctx: CheckContext, spec: CheckSpec, findings: _Findings) -> list[OpenedInput]:
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


def _no_rows_to_examine(spec: CheckSpec, findings: _Findings, evidence: Mapping[str, Any]) -> CheckOutcome:
    """NOT_APPLICABLE, citing the first recorded cause (e.g. SOURCE_MISMATCH for a digest mismatch)."""
    if not spec.inputs:
        return findings.not_applicable(Reason.OUT_OF_SCOPE, f"{spec.kind} was given no inputs", evidence)
    reason = findings.first_reason(Reason.INSUFFICIENT_EVIDENCE)
    return findings.not_applicable(reason, "no input has rows to examine", evidence)


def _document_unavailable(document: Document, evidence: Mapping[str, Any]) -> CheckOutcome:
    """A declared role document that could not be read or parsed: never PASS.

    Absence or damage is missing evidence (ABSTAIN), not a verdict about content.
    """
    reason = Reason.PROTOCOL_BROKEN if document.state is InputState.PARSE_ERROR else Reason.INSUFFICIENT_EVIDENCE
    detail = document.diagnostic or f"{document.role} is {document.state}"
    return CheckOutcome(
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ABSTAIN,
        reason=reason,
        rows_examined=0,
        evidence={**evidence, "document": document.to_dict()},
        diagnostics=(f"{document.role} ({document.path}) unavailable: {detail}",),
    )


def _malformed_document(document: Document, problem: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    return CheckOutcome(
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ABSTAIN,
        reason=Reason.PROTOCOL_BROKEN,
        rows_examined=0,
        evidence={**evidence, "document": document.to_dict()},
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
    findings = _Findings()
    usable = _examinable(ctx, spec, findings)
    per_input = {input_id: _input_summary(ctx.inputs[input_id]) for input_id in spec.inputs if input_id in ctx.inputs}
    if not usable:
        return _no_rows_to_examine(spec, findings, {"inputs": per_input})
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
    findings = _Findings()
    usable = _examinable(ctx, spec, findings)
    per_input = {input_id: _input_summary(ctx.inputs[input_id]) for input_id in spec.inputs if input_id in ctx.inputs}
    evidence: dict[str, Any] = {"columns": list(columns), "inputs": per_input}
    if not usable:
        return _no_rows_to_examine(spec, findings, evidence)
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
    findings = _Findings()
    usable = _examinable(ctx, spec, findings)
    per_input = {input_id: _input_summary(ctx.inputs[input_id]) for input_id in spec.inputs if input_id in ctx.inputs}
    if not usable:
        return _no_rows_to_examine(spec, findings, {"inputs": per_input})
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


def _report_absent(opened: OpenedInput, count: int, what: str, findings: _Findings) -> None:
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


def _compare_snapshot(opened: OpenedInput, accepted: _AcceptedInput, findings: _Findings) -> dict[str, Any]:
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
    findings = _Findings()
    evidence: dict[str, Any] = {"snapshot": snapshot.to_dict()}
    if not snapshot.declared:
        return findings.not_applicable(Reason.OUT_OF_SCOPE, "the manifest declares no accepted_snapshot", evidence)
    if not snapshot.loaded:
        return _document_unavailable(snapshot, evidence)
    try:
        accepted = _parse_snapshot(snapshot.content)
    except _FormatError as exc:
        return _malformed_document(snapshot, str(exc), evidence)
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
        return _no_rows_to_examine(spec, findings, evidence)
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
    comparison goes through :func:`~science_gate.invariants.compare_decimal`.
    Rounding therefore never creates agreement, and a separator never evades
    comparison: undeclared, it makes the value ambiguous, never equal.
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
    findings = _Findings()
    usable = _examinable(ctx, spec, findings)
    evidence: dict[str, Any] = {
        "input": spec.inputs[0],
        "column": column,
        "thousands": thousands,
        "decimal_point": decimal_point,
    }
    if not usable:
        return _no_rows_to_examine(spec, findings, evidence)
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
            comparison = compare_decimal(
                claimed, stored, thousands=thousands, decimal_point=decimal_point, precision_decimals=precision
            )
            entry.update(comparison.to_dict())
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
    compared = sum(1 for entry in comparisons if entry["outcome"] != "ROW_NOT_FOUND")
    return findings.outcome(rows_examined=compared, evidence=evidence)


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
    _takes_no_inputs(spec, "reviews.verdicts document")
    findings = _Findings()
    reviews = ctx.manifest.reviews
    if reviews is None:
        return findings.not_applicable(Reason.OUT_OF_SCOPE, "the manifest declares no review protocol", {})
    document = ctx.role_document("reviews.verdicts")
    evidence: dict[str, Any] = {"required_reviewers": list(reviews.required_reviewers)}
    if not document.loaded:
        return _document_unavailable(document, evidence)
    try:
        verdicts = _parse_verdicts(document.content)
    except _FormatError as exc:
        return _malformed_document(document, str(exc), evidence)

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
    _takes_no_inputs(spec, "time_sources document")
    findings = _Findings()
    document = ctx.role_document("time_sources")
    evidence: dict[str, Any] = {"document": document.to_dict()}
    if not document.declared:
        return findings.not_applicable(Reason.OUT_OF_SCOPE, "the manifest declares no time_sources", evidence)
    if not document.loaded:
        return _document_unavailable(document, evidence)
    try:
        window, events = _parse_time_sources(document.content)
    except _FormatError as exc:
        return _malformed_document(document, str(exc), evidence)
    evidence["window"] = {"start": format_utc(window[0]), "end": format_utc(window[1])}
    if not events:
        return findings.not_applicable(Reason.INSUFFICIENT_EVIDENCE, "the time sources list no events", evidence)
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
    ctx: CheckContext, input_id: str, pin: Mapping[str, Any], findings: _Findings
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


def _compare_pinned_document(ctx: CheckContext, path: str, digest: str, findings: _Findings) -> dict[str, Any]:
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
    _takes_no_inputs(spec, "summary_claim document")
    findings = _Findings()
    document = ctx.role_document("summary_claim")
    evidence: dict[str, Any] = {"summary": document.to_dict()}
    if not document.declared:
        return findings.not_applicable(Reason.OUT_OF_SCOPE, "the manifest declares no summary_claim", evidence)
    if not document.loaded:
        return _document_unavailable(document, evidence)
    try:
        status, pinned_inputs, pinned_documents = _parse_summary(document.content)
    except _FormatError as exc:
        return _malformed_document(document, str(exc), evidence)
    evidence["stored_status"] = status
    if status != Status.PASS.value:
        return findings.not_applicable(
            Reason.OUT_OF_SCOPE, f"the stored summary claims {status}, not PASS: there is no PASS to confirm", evidence
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
    # Every declared evidence file other than the summary itself should be
    # pinned. Role paths were validated by the manifest, so they normalize.
    own_role = "summary_claim"
    declared_documents = {
        normalize_relpath(path)
        for role, _ in ROLE_DOCUMENTS
        if role != own_role and (path := ctx.role_path(role)) is not None
    }
    blind_inputs = sorted(input_id for input_id in ctx.inputs if input_id not in pinned_inputs)
    blind_documents = sorted(path for path in declared_documents if path not in pinned_documents)
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
# Engine
# ---------------------------------------------------------------------------


def _ledger_evidence(result: CheckResult) -> dict[str, Any]:
    """What the terminal ledger entry records: enough to rebuild the result."""
    return {
        "execution_state": result.execution_state,
        "rows_examined": result.rows_examined,
        "failure_modes": list(result.failure_modes),
        "diagnostics": list(result.diagnostics),
        "check_evidence": result.evidence,
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


def _refuse_vacuous_pass(outcome: CheckOutcome) -> CheckOutcome:
    """A check may not PASS without examined rows and non-empty evidence.

    Built-in checks never try. This guard makes the rule hold for every
    registered check, so the verdict written to the ledger is already honest.
    """
    if outcome.verdict is not Status.PASS or (outcome.rows_examined and outcome.evidence):
        return outcome
    missing = "rows examined" if not outcome.rows_examined else "evidence"
    return dataclasses.replace(
        outcome,
        verdict=Status.ABSTAIN,
        reason=Reason.INSUFFICIENT_EVIDENCE,
        failure_modes=(*outcome.failure_modes, FailureMode.VACUOUS_PASS),
        diagnostics=(*outcome.diagnostics, f"VACUOUS_PASS_REFUSED: the check reported PASS with no {missing}"),
    )


def _run_one(
    ctx: CheckContext, spec: CheckSpec, ledger: Ledger, registry: Mapping[str, str]
) -> tuple[CheckResult, tuple[ClaimTally, ...]]:
    """Run one check inside its ledger invocation. Always closes the invocation."""
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
        try:
            outcome = function(ctx, spec)
        except CheckParamError as exc:
            result = _errored(spec, invocation_id, f"INVALID_PARAMS: {exc}")
        except Exception as exc:  # the contract: a check that raises is ERRORED, never a crash
            message = f"CHECK_RAISED: {type(exc).__name__}" + (f": {exc}" if str(exc) else "")
            result = _errored(spec, invocation_id, message)
        else:
            try:
                result, tallies = _result_from(spec, invocation_id, outcome)
            except (TypeError, ValueError) as exc:
                result = _errored(spec, invocation_id, f"INVALID_OUTCOME: {exc}")
    ledger.finish(invocation_id, verdict=result.verdict, reason=result.reason, evidence=_ledger_evidence(result))
    return result, tallies


def _result_from(
    spec: CheckSpec, invocation_id: str, outcome: Any
) -> tuple[CheckResult, tuple[ClaimTally, ...]]:
    if not isinstance(outcome, CheckOutcome):
        raise TypeError(f"a check must return CheckOutcome, not {type(outcome).__name__}")
    if any(not isinstance(tally, ClaimTally) for tally in outcome.claim_tallies):
        raise TypeError("claim_tallies must contain ClaimTally instances")
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


def run_checks(
    ctx: CheckContext,
    specs: Iterable[CheckSpec],
    ledger: Ledger,
    registry: Mapping[str, str] = REGISTRY,
) -> tuple[tuple[CheckResult, ...], tuple[tuple[str, ClaimTally], ...]]:
    """Run every declared check, in manifest order, each in its own invocation.

    A failing or crashing check never stops the run: the remaining checks
    still execute, so one early FAIL cannot hide a later problem. Returns the
    results and the ``(check_id, ClaimTally)`` pairs the checks reported.
    """
    results: list[CheckResult] = []
    tallies: list[tuple[str, ClaimTally]] = []
    for spec in specs:
        result, reported = _run_one(ctx, spec, ledger, registry)
        results.append(result)
        tallies.extend((spec.check_id, tally) for tally in reported)
    return tuple(results), tuple(tallies)


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
    """Distinct rows examined in scope.

    Admitted rows of each input that an executed check consumed are counted
    once, however many checks read them. Checks that read no declared input
    (reviewer verdicts, time events) add the records they examined.
    """
    from_inputs = sum(len(inputs[input_id].rows or ()) for input_id in _examined_inputs(checks, inputs))
    standalone = sum(
        check.rows_examined
        for check in checks
        if check.execution_state is ExecutionState.CHECKED and not check.inputs and check.rows_examined is not None
    )
    return from_inputs + standalone


# ---------------------------------------------------------------------------
# Decision (section 6)
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
    expected checks is unknown, not zero.
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


@dataclass(frozen=True)
class Decision:
    """The decided status, with every finding and invariant that led to it."""

    status: Status
    reason: Reason
    reasons: tuple[Reason, ...]
    failure_modes: tuple[FailureMode, ...]
    findings: tuple[Finding, ...]
    invariants: tuple[InvariantResult, ...]
    counters: Mapping[str, Any]


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
    entry. Unknown values are None, never zero.
    """
    traces = index_invocations(entries)
    known = declared_checks is not None
    required_ids = sorted(check_id for check_id, required in (declared_checks or {}).items() if required)
    by_id = {check.check_id: check for check in checks}
    required = [by_id[check_id] for check_id in required_ids if check_id in by_id]

    def count(predicate: Callable[[CheckResult], bool]) -> int | None:
        return sum(1 for check in required if predicate(check)) if known else None

    def executed(check: CheckResult) -> bool:
        trace = traces.get(check.invocation_id) if check.invocation_id else None
        return check.execution_state is ExecutionState.CHECKED and trace is not None and trace.terminal

    return {
        "expected_inputs": accounting.value("expected"),
        "inputs_discovered": accounting.value("discovered"),
        "inputs_opened": accounting.value("opened"),
        "inputs_parsed": accounting.value("parsed"),
        "inputs_examined": accounting.value("examined"),
        "rows_examined": rows_examined,
        "checks_declared": len(declared_checks) if known else None,
        "checks_expected": len(required_ids) if known else None,
        "checks_executed": count(executed),
        "checks_passed": count(lambda check: check.verdict is Status.PASS),
        "checks_failed": count(lambda check: check.verdict is Status.FAIL),
        "checks_abstained": count(lambda check: check.verdict is Status.ABSTAIN),
        "checks_errored": count(lambda check: check.verdict is Status.ERROR),
        "checks_skipped": count(lambda check: check.execution_state is ExecutionState.SKIPPED),
        "checks_not_applicable": count(lambda check: check.execution_state is ExecutionState.NOT_APPLICABLE),
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
    counters: Mapping[str, Any], evidence_manifest: Sequence[Mapping[str, Any]] | None
) -> list[Finding]:
    """The PASS contract's counting rules (section 6), each as its own finding."""
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
        detail = f"rows_examined is {rows}; a PASS needs at least 1"
        abstain("rows_examined", Reason.INSUFFICIENT_EVIDENCE, vacuous, detail)
    expected, executed = counters["checks_expected"], counters["checks_executed"]
    if expected == 0:
        abstain("checks_expected", Reason.INSUFFICIENT_EVIDENCE, vacuous, "no required check was declared")
    elif expected is not None and executed != expected:
        abstain(
            "checks_executed",
            Reason.PARTIAL_EXECUTION,
            (FailureMode.PARTIAL_EXECUTION,),
            f"checks_executed={executed} of checks_expected={expected}",
        )
    if not evidence_manifest:
        abstain("evidence_manifest", Reason.INSUFFICIENT_EVIDENCE, vacuous, "the evidence manifest is empty")
    return findings


def _combine(findings: Sequence[Finding]) -> tuple[Status, Reason, tuple[Reason, ...], tuple[FailureMode, ...]]:
    """Precedence ERROR > FAIL > ABSTAIN > PASS; the first finding at the top level names the reason."""
    if not findings:
        return Status.PASS, Reason.VERIFIED, (Reason.VERIFIED,), ()
    top = max(_RANK[finding.status] for finding in findings)
    primary = next(finding for finding in findings if _RANK[finding.status] == top)
    reasons = tuple(dict.fromkeys(finding.reason for finding in findings))
    modes = tuple(sorted({mode for finding in findings for mode in finding.failure_modes}, key=lambda mode: mode.value))
    return primary.status, primary.reason, reasons, modes


def decide(inputs: DecisionInputs) -> Decision:
    """Apply the PASS contract and the status precedence (section 6).

    Findings are gathered in a fixed order: manifest, inputs, checks,
    contract counters, then invariants. That order is also the tie-break for
    the primary reason. The invariants are evaluated *after* a tentative
    status is known, and with that status as the run's claim, so the
    ``pass_requires_*`` invariants judge exactly the PASS the run is about to
    report. Any violation then outranks the tentative PASS.

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
        findings += _contract_findings(counters, inputs.evidence_manifest)
    tentative = _combine(findings)[0]
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
        )
    )
    for invariant in invariants:
        if invariant.violated:
            outcome = VIOLATION_OUTCOMES[invariant.name]
            source = f"invariant:{invariant.name}"
            findings.append(
                Finding(outcome.status, outcome.reason, (outcome.failure_mode,), source, invariant.detail)
            )
    status, reason, reasons, modes = _combine(findings)
    return Decision(status, reason, reasons, modes, tuple(findings), invariants, counters)


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
    """Everything one ``verify`` produced, ready for :mod:`science_gate.reports`."""

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

    @property
    def status(self) -> Status:
        return self.result.status

    @property
    def exit_code(self) -> int:
        return self.result.exit_code


def _unavailable_accounting() -> InputAccounting:
    """Accounting for a run whose manifest could not be read: every count unknown."""
    counters = {name: AccountingCount(None, DenominatorSource.UNAVAILABLE) for name in ACCOUNTING_COUNTERS}
    return InputAccounting(counters, Closure(DenominatorSource.UNAVAILABLE, None, None, None), ())


def _digest_if_readable(path: Path) -> str | None:
    """SHA-256 of a manifest file that failed validation, when its bytes can be read."""
    try:
        return sha256_file(path, max_bytes=MAX_MANIFEST_BYTES)[0]
    except (OSError, SizeLimitExceeded):
        return None


def _run_id(material: Mapping[str, Any]) -> str:
    """``run-`` plus 16 hex of a content hash: never random, stable under a fixed clock."""
    return "run-" + sha256_canonical(material)[:16]


def _finish(
    *,
    run_id: str,
    started_at: str,
    accounting: InputAccounting,
    checks: tuple[CheckResult, ...],
    evidence: Mapping[str, Any],
    decision_inputs: DecisionInputs,
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
    )
    return result, decision


def _invalid_manifest_run(path: Path, error: ManifestError, started_at: str, network: NetworkPolicy) -> VerificationRun:
    """An ERROR run for a manifest that is missing, malformed or unsafe. Nothing else is read."""
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
) -> VerificationRun:
    """Verify the manifest at ``manifest_path`` and return the decided run.

    Live network access is enabled by ``live=True`` or the manifest's
    ``citations.live``. An injected ``network`` policy supplies the opener
    and limits, and the two switches can only turn live access on, never off.
    ``registry`` exists so tests can register extra kinds. It must map every
    kind a manifest names.

    Exceptions raised by checks are recorded as ERROR results. An exception
    escaping this function is a defect in the engine itself.
    """
    path = Path(manifest_path)
    started_at = now()
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
    ctx.preload_roles()
    run_id = _run_id(
        {
            "manifest_sha256": manifest.sha256,
            "inputs": {input_id: item.sha256 for input_id, item in opened.items()},
            "documents": {item["path"]: item["sha256"] for item in ctx.read_log()},
            "started_at": started_at,
            "tool": __version__,
        }
    )
    ledger = Ledger(run_id)
    checks, tallies = run_checks(ctx, manifest.checks, ledger, registry)
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
        ),
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
    )
