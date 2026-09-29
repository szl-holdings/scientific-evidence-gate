"""Shared vocabulary and result types (ARCHITECTURE.md section 1).

Every enum value defined here ends up in hashed, persisted output, so the
spellings are part of the contract and must not drift. The result types are
frozen dataclasses that validate themselves on construction. Some outcomes are
not merely unlikely but *unrepresentable*:

* a ``PASS`` whose reason is anything but ``VERIFIED`` (and the reverse);
* a PASS or FAIL verdict from a check that did not reach ``CHECKED``: a
  verdict about content requires having examined the content;
* an input-accounting closure that claims to hold without an INDEPENDENT
  denominator, or that claims to hold while its own numbers disagree;
* an absent count that carries a source other than UNAVAILABLE.

Whether a PASS carried enough evidence (examined rows, non-empty evidence,
complete inputs) is judged by :mod:`science_gate.invariants`. Those judgements
yield ABSTAIN rather than a construction error, so they stay visible in the
report.

``to_dict()`` output is JSON-safe (canonical rules: no floats), and its sets are
sorted, so a result serializes identically on every run.

Text that can quote input content (check evidence and diagnostics, input
diagnostics) is passed through :func:`science_gate._redact.redact` when a
result is constructed. Redacting at construction, before anything is hashed,
is the only point where a secret can be removed without breaking a hash later.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, TypeVar

from ._canonical import normalize
from ._redact import redact, redact_text

__all__ = [
    "Status",
    "EXIT_CODE",
    "Reason",
    "FailureMode",
    "ExecutionState",
    "InvocationResult",
    "TERMINAL_INVOCATION_RESULTS",
    "invocation_result_for",
    "DenominatorSource",
    "Validity",
    "ResolverState",
    "MetadataState",
    "AccessClass",
    "SignatureState",
    "InputState",
    "BUILTIN_CHECK_KINDS",
    "ACCOUNTING_COUNTERS",
    "Permissions",
    "CheckResult",
    "InvariantResult",
    "AccountingCount",
    "RowCounts",
    "Closure",
    "InputRecord",
    "InputAccounting",
    "RunResult",
]


class _Vocabulary(str, Enum):
    """Base for every vocabulary enum: ``str()`` and f-strings yield the value.

    Without this, ``f"{Status.PASS}"`` would render as ``Status.PASS`` and leak
    Python class names into human-readable reports.
    """

    def __str__(self) -> str:
        return str.__str__(self)


class Status(_Vocabulary):
    """Run and check verdicts. Precedence when combining: ERROR > FAIL > ABSTAIN > PASS."""

    PASS = "PASS"
    FAIL = "FAIL"
    ABSTAIN = "ABSTAIN"
    ERROR = "ERROR"


#: Process exit code for each status. 2 always means ABSTAIN, never a usage error.
EXIT_CODE: Mapping[Status, int] = MappingProxyType(
    {Status.PASS: 0, Status.FAIL: 1, Status.ABSTAIN: 2, Status.ERROR: 3}
)


class Reason(_Vocabulary):
    """Why a verdict was reached. ``VERIFIED`` is reserved for PASS."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INVALID_BASELINE = "INVALID_BASELINE"
    BLIND_SPOT = "BLIND_SPOT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    PROTOCOL_BROKEN = "PROTOCOL_BROKEN"
    PARTIAL_EXECUTION = "PARTIAL_EXECUTION"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"


class FailureMode(_Vocabulary):
    """Taxonomy of the ways a verification can mislead."""

    VACUOUS_PASS = "VACUOUS_PASS"
    NARRATED_VERIFICATION = "NARRATED_VERIFICATION"
    PARTIAL_EXECUTION = "PARTIAL_EXECUTION"
    DEFECTIVE_VERIFICATION = "DEFECTIVE_VERIFICATION"
    OMITTED_POPULATION = "OMITTED_POPULATION"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    PROTOCOL_DRIFT = "PROTOCOL_DRIFT"
    EPHEMERAL_CLAIM = "EPHEMERAL_CLAIM"
    STALE_DEPENDENCY = "STALE_DEPENDENCY"


class ExecutionState(_Vocabulary):
    """Whether a check actually examined anything."""

    CHECKED = "CHECKED"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class InvocationResult(_Vocabulary):
    """Ledger state of one invocation. ``STARTED`` is the only non-terminal value."""

    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    ERRORED = "ERRORED"
    ABSTAINED = "ABSTAINED"


TERMINAL_INVOCATION_RESULTS = frozenset(
    {InvocationResult.COMPLETED, InvocationResult.ERRORED, InvocationResult.ABSTAINED}
)

_RESULT_FOR_VERDICT: Mapping[Status, InvocationResult] = MappingProxyType(
    {
        Status.PASS: InvocationResult.COMPLETED,
        Status.FAIL: InvocationResult.COMPLETED,
        Status.ABSTAIN: InvocationResult.ABSTAINED,
        Status.ERROR: InvocationResult.ERRORED,
    }
)


def invocation_result_for(verdict: Status | str) -> InvocationResult:
    """Return the terminal ledger result implied by a verdict.

    The ledger derives the result from the verdict instead of accepting both,
    so an entry can never say COMPLETED while its verdict says ERROR.
    """
    return _RESULT_FOR_VERDICT[Status(verdict)]


class DenominatorSource(_Vocabulary):
    """Provenance of an expected count. Only INDEPENDENT can close accounting."""

    INDEPENDENT = "INDEPENDENT"
    OBSERVED = "OBSERVED"
    ESTIMATED = "ESTIMATED"
    UNAVAILABLE = "UNAVAILABLE"


class Validity(_Vocabulary):
    """Currency of a node in the dependency graph."""

    CURRENT = "CURRENT"
    STALE_PENDING_REVALIDATION = "STALE_PENDING_REVALIDATION"
    REVALIDATED_UNCHANGED = "REVALIDATED_UNCHANGED"
    REVALIDATED_CHANGED = "REVALIDATED_CHANGED"
    SUPERSEDED = "SUPERSEDED"
    INVALIDATED = "INVALIDATED"
    UNRESOLVED = "UNRESOLVED"


class ResolverState(_Vocabulary):
    """Per-DOI outcome of citation resolution."""

    DOI_RESOLVED = "DOI_RESOLVED"
    DOI_NOT_RESOLVED_AT_CAPTURE = "DOI_NOT_RESOLVED_AT_CAPTURE"
    DOI_TARGET_MISMATCH = "DOI_TARGET_MISMATCH"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"


class MetadataState(_Vocabulary):
    """Per-citation outcome of metadata comparison."""

    VERIFIED_WITHIN_DECLARED_SCOPE = "VERIFIED_WITHIN_DECLARED_SCOPE"
    FIELD_MISMATCH = "FIELD_MISMATCH"
    CONFLATED_ENTRY = "CONFLATED_ENTRY"
    RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES = "RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES"


class AccessClass(_Vocabulary):
    """How a corpus may be handled. CONTROLLED_LOCAL and REFERENCE_ONLY are never copied."""

    PUBLIC = "PUBLIC"
    REFERENCE_ONLY = "REFERENCE_ONLY"
    SYNTHETIC = "SYNTHETIC"
    CONTROLLED_LOCAL = "CONTROLLED_LOCAL"


class SignatureState(_Vocabulary):
    """Whether a receipt carries an HMAC signature."""

    UNSIGNED = "UNSIGNED"
    SIGNED_HMAC_SHA256 = "SIGNED_HMAC_SHA256"


class InputState(_Vocabulary):
    """Disposition of one declared input after discovery (section 3).

    Only ``PARSED`` is complete. Every other state is visible in the report and
    blocks PASS for a required input.
    """

    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    EMPTY = "EMPTY"
    MISSING = "MISSING"
    REFUSED = "REFUSED"
    OPEN_FAILED = "OPEN_FAILED"
    PARSE_ERROR = "PARSE_ERROR"
    HASH_MISMATCH = "HASH_MISMATCH"


#: Check kinds defined by the contract (section 5). A manifest may name only
#: registered kinds; the verifier's registry must cover exactly this set.
BUILTIN_CHECK_KINDS = frozenset(
    {
        "row_count",
        "required_columns",
        "duplicate_rows",
        "snapshot_completeness",
        "numeric_agreement",
        "reviewer_protocol",
        "time_source",
        "verification_log",
        "citation_resolver",
        "citation_metadata",
        "claim_registry",
        "dependency_currency",
        "summary_consistency",
    }
)

#: Run-level input-accounting counters, in funnel order.
ACCOUNTING_COUNTERS = (
    "expected",
    "discovered",
    "opened",
    "parsed",
    "examined",
    "admitted",
    "excluded",
    "deferred",
    "unresolved",
    "failed",
)

_E = TypeVar("_E", bound=Enum)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _set(instance: object, name: str, value: Any) -> None:
    """Assign on a frozen dataclass during ``__post_init__`` normalization."""
    object.__setattr__(instance, name, value)


def _coerce(enum_type: type[_E], value: Any, name: str) -> _E:
    """Accept an enum member or its string value; refuse anything else."""
    try:
        return enum_type(value)
    except ValueError:
        raise ValueError(f"{name}: {value!r} is not a valid {enum_type.__name__}") from None


def _enum_set(enum_type: type[_E], values: Iterable[Any], name: str) -> tuple[_E, ...]:
    """Coerce, de-duplicate and sort enum values (they are sets, not sequences)."""
    return tuple(sorted({_coerce(enum_type, value, name) for value in values}, key=lambda item: item.value))


def _optional_count(value: Any, name: str) -> int | None:
    """Accept None or a non-negative int (never a bool or a float)."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name}: expected a non-negative int or None, got {value!r}")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name}: expected a bool, got {value!r}")
    return value


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name}: expected a non-empty string, got {value!r}")
    return value


def _optional_digest(value: Any, name: str) -> str | None:
    """Accept None or a lowercase 64-character hex SHA-256 digest."""
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise ValueError(f"{name}: expected a lowercase hex SHA-256 digest, got {value!r}")
    return value


@dataclass(frozen=True)
class Permissions:
    """What a corpus may be used for. Every default is the restrictive one
    except evaluation, which is the purpose of the tool. Evaluation permission
    never implies training permission.
    """

    evaluation_allowed: bool = True
    training_allowed: bool = False
    redistribution_allowed: bool = False
    derivatives_allowed: bool = False
    public_display_allowed: bool = False
    commercial_use_allowed: bool = False

    def __post_init__(self) -> None:
        for item in dataclasses.fields(self):
            _require_bool(getattr(self, item.name), item.name)

    def to_dict(self) -> dict[str, bool]:
        return {item.name: getattr(self, item.name) for item in dataclasses.fields(self)}


@dataclass(frozen=True)
class CheckResult:
    """The recorded outcome of one check, pointing at its ledger invocation."""

    check_id: str
    kind: str
    version: str
    required: bool
    execution_state: ExecutionState
    verdict: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...] = ()
    rows_examined: int | None = None
    inputs: tuple[str, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()
    invocation_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.check_id, "check_id")
        _require_text(self.kind, "kind")
        _require_text(self.version, "version")
        _require_bool(self.required, "required")
        _set(self, "execution_state", _coerce(ExecutionState, self.execution_state, "execution_state"))
        _set(self, "verdict", _coerce(Status, self.verdict, "verdict"))
        _set(self, "reason", _coerce(Reason, self.reason, "reason"))
        _set(self, "failure_modes", _enum_set(FailureMode, self.failure_modes, "failure_modes"))
        _set(self, "rows_examined", _optional_count(self.rows_examined, "rows_examined"))
        _set(self, "inputs", tuple(sorted({_require_text(item, "inputs") for item in self.inputs})))
        if not isinstance(self.evidence, Mapping):
            raise ValueError("evidence must be a mapping")
        # Normalizing here fails fast at the check that produced bad evidence
        # (a float, say) instead of at report time, far from the cause.
        _set(self, "evidence", normalize(redact(self.evidence)))
        _set(self, "diagnostics", tuple(redact_text(_require_text(item, "diagnostics")) for item in self.diagnostics))
        if self.invocation_id is not None:
            _require_text(self.invocation_id, "invocation_id")
        if (self.verdict is Status.PASS) != (self.reason is Reason.VERIFIED):
            raise ValueError("verdict PASS and reason VERIFIED must occur together")
        if self.verdict in (Status.PASS, Status.FAIL) and self.execution_state is not ExecutionState.CHECKED:
            raise ValueError(
                f"a {self.verdict.value} verdict requires execution_state CHECKED, "
                f"not {self.execution_state.value}"
            )

    def to_dict(self) -> dict[str, Any]:
        return normalize(
            {
                "check_id": self.check_id,
                "kind": self.kind,
                "version": self.version,
                "required": self.required,
                "execution_state": self.execution_state,
                "verdict": self.verdict,
                "reason": self.reason,
                "failure_modes": list(self.failure_modes),
                "rows_examined": self.rows_examined,
                "inputs": list(self.inputs),
                "evidence": self.evidence,
                "diagnostics": list(self.diagnostics),
                "invocation_id": self.invocation_id,
            }
        )


@dataclass(frozen=True)
class InvariantResult:
    """The outcome of one named invariant.

    ``holds`` is None exactly when the invariant is not applicable. An
    applicable invariant must reach a definite True or False, so "could not
    tell" can never masquerade as "holds".
    """

    name: str
    applicable: bool
    holds: bool | None
    detail: str

    def __post_init__(self) -> None:
        _require_text(self.name, "name")
        _require_bool(self.applicable, "applicable")
        if not isinstance(self.detail, str):
            raise ValueError("detail must be a string")
        if not self.applicable and self.holds is not None:
            raise ValueError(f"{self.name}: a non-applicable invariant must have holds=None")
        if self.applicable and not isinstance(self.holds, bool):
            raise ValueError(f"{self.name}: an applicable invariant must have holds True or False")

    @property
    def violated(self) -> bool:
        """True only for an applicable invariant that definitely does not hold."""
        return self.applicable and self.holds is False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "applicable": self.applicable, "holds": self.holds, "detail": self.detail}


@dataclass(frozen=True)
class AccountingCount:
    """A counter value together with the provenance of that value.

    An absent value (None) must be UNAVAILABLE and an UNAVAILABLE source must
    have no value: a missing count is never reported as zero.
    """

    value: int | None
    source: DenominatorSource

    def __post_init__(self) -> None:
        _set(self, "value", _optional_count(self.value, "value"))
        _set(self, "source", _coerce(DenominatorSource, self.source, "source"))
        if (self.value is None) != (self.source is DenominatorSource.UNAVAILABLE):
            raise ValueError("an absent count must be UNAVAILABLE, and UNAVAILABLE must have no value")

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "denominator_source": self.source.value}


@dataclass(frozen=True)
class RowCounts:
    """Row dispositions within one input. None means "not known", never zero."""

    admitted: int | None = None
    excluded: int | None = None
    deferred: int | None = None
    unresolved: int | None = None
    failed: int | None = None

    def __post_init__(self) -> None:
        for item in dataclasses.fields(self):
            _set(self, item.name, _optional_count(getattr(self, item.name), item.name))

    @property
    def accounted(self) -> int | None:
        """Sum of all dispositions, or None if any disposition is unknown."""
        values = [getattr(self, item.name) for item in dataclasses.fields(self)]
        return None if any(value is None for value in values) else sum(values)

    def to_dict(self) -> dict[str, int | None]:
        return {item.name: getattr(self, item.name) for item in dataclasses.fields(self)}


@dataclass(frozen=True)
class Closure:
    """Whether everything expected was accounted for (section 3).

    Closure is only meaningful against an INDEPENDENT expectation: comparing a
    count with a number derived from the same observation proves nothing. So
    ``holds`` is None for any other source, and also when either side is
    unknown. When ``holds`` is set it must agree with the numbers.
    """

    source: DenominatorSource
    holds: bool | None
    expected: int | None
    accounted: int | None

    def __post_init__(self) -> None:
        _set(self, "source", _coerce(DenominatorSource, self.source, "source"))
        _set(self, "expected", _optional_count(self.expected, "expected"))
        _set(self, "accounted", _optional_count(self.accounted, "accounted"))
        if self.holds is None:
            return
        _require_bool(self.holds, "holds")
        if self.source is not DenominatorSource.INDEPENDENT:
            raise ValueError("closure can only hold or break against an INDEPENDENT source")
        if self.expected is None or self.accounted is None:
            raise ValueError("closure needs both expected and accounted counts to hold or break")
        if self.holds != (self.expected == self.accounted):
            raise ValueError("closure.holds contradicts its expected and accounted counts")

    @classmethod
    def evaluate(cls, source: DenominatorSource | str, expected: int | None, accounted: int | None) -> Closure:
        """Build a closure, deciding ``holds`` by the rules above."""
        source = _coerce(DenominatorSource, source, "source")
        evaluable = source is DenominatorSource.INDEPENDENT and expected is not None and accounted is not None
        return cls(source, (expected == accounted) if evaluable else None, expected, accounted)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source.value, "holds": self.holds, "expected": self.expected, "accounted": self.accounted}


@dataclass(frozen=True)
class InputRecord:
    """Accounting record for one declared input.

    ``discovered``, ``opened`` and ``parsed`` record how far through the funnel
    the input got. ``rows`` counts every data record seen (None when it could
    not be counted). ``counts`` splits those records by disposition, and
    ``closure`` compares them against the declared expectation.
    """

    input_id: str
    path: str
    required: bool
    format: str
    state: InputState
    discovered: bool
    opened: bool
    parsed: bool
    sha256: str | None
    declared_sha256: str | None
    size_bytes: int | None
    rows: int | None
    counts: RowCounts
    closure: Closure
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.input_id, "input_id")
        _require_text(self.path, "path")
        _require_bool(self.required, "required")
        _require_text(self.format, "format")
        _set(self, "state", _coerce(InputState, self.state, "state"))
        for name in ("discovered", "opened", "parsed"):
            _require_bool(getattr(self, name), name)
        _optional_digest(self.sha256, "sha256")
        _optional_digest(self.declared_sha256, "declared_sha256")
        _set(self, "size_bytes", _optional_count(self.size_bytes, "size_bytes"))
        _set(self, "rows", _optional_count(self.rows, "rows"))
        if not isinstance(self.counts, RowCounts):
            raise ValueError("counts must be a RowCounts")
        if not isinstance(self.closure, Closure):
            raise ValueError("closure must be a Closure")
        _set(self, "diagnostics", tuple(redact_text(_require_text(item, "diagnostics")) for item in self.diagnostics))

    @property
    def complete(self) -> bool:
        """True only when the input was fully parsed and matched any declared digest."""
        return self.state is InputState.PARSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.input_id,
            "path": self.path,
            "required": self.required,
            "format": self.format,
            "state": self.state.value,
            "discovered": self.discovered,
            "opened": self.opened,
            "parsed": self.parsed,
            "sha256": self.sha256,
            "declared_sha256": self.declared_sha256,
            "bytes": self.size_bytes,
            "rows": self.rows,
            "row_counts": self.counts.to_dict(),
            "closure": self.closure.to_dict(),
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class InputAccounting:
    """Run-level input accounting: funnel counters, closure and per-input records.

    Counters count *inputs* (files); rows are accounted per input in
    :class:`InputRecord`. ``examined`` is unknown after discovery and is filled
    in by the verifier through :meth:`with_examined` once checks have run.
    """

    counters: Mapping[str, AccountingCount]
    closure: Closure
    records: tuple[InputRecord, ...]

    def __post_init__(self) -> None:
        if set(self.counters) != set(ACCOUNTING_COUNTERS):
            raise ValueError(f"counters must be exactly {ACCOUNTING_COUNTERS}")
        for name, count in self.counters.items():
            if not isinstance(count, AccountingCount):
                raise ValueError(f"counter {name!r} must be an AccountingCount")
        _set(self, "counters", MappingProxyType({name: self.counters[name] for name in ACCOUNTING_COUNTERS}))
        records = tuple(sorted(self.records, key=lambda record: record.input_id))
        ids = [record.input_id for record in records]
        if len(ids) != len(set(ids)):
            raise ValueError("input records must have unique ids")
        _set(self, "records", records)

    def value(self, name: str) -> int | None:
        """Return a counter's value (None when unknown)."""
        return self.counters[name].value

    def record(self, input_id: str) -> InputRecord:
        """Return the record for ``input_id`` (KeyError if undeclared)."""
        for record in self.records:
            if record.input_id == input_id:
                return record
        raise KeyError(input_id)

    def with_examined(self, examined: int) -> InputAccounting:
        """Return a copy whose ``examined`` counter is an observed value."""
        counters = dict(self.counters)
        counters["examined"] = AccountingCount(examined, DenominatorSource.OBSERVED)
        return dataclasses.replace(self, counters=counters)

    def to_dict(self) -> dict[str, Any]:
        return {
            "counters": {name: count.to_dict() for name, count in self.counters.items()},
            "closure": self.closure.to_dict(),
            "inputs": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True)
class RunResult:
    """The decided outcome of a run, with everything needed to audit it.

    Checks are stored sorted by id and invariants by name, so the serialized
    form never depends on the order in which work happened to finish.
    """

    status: Status
    reason: Reason
    reasons: tuple[Reason, ...]
    failure_modes: tuple[FailureMode, ...]
    run_id: str
    accounting: InputAccounting
    checks: tuple[CheckResult, ...]
    invariants: tuple[InvariantResult, ...]
    evidence_manifest_sha256: str | None
    started_at: str
    completed_at: str
    counters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _set(self, "status", _coerce(Status, self.status, "status"))
        _set(self, "reason", _coerce(Reason, self.reason, "reason"))
        # The primary reason is always one of the listed reasons.
        _set(self, "reasons", _enum_set(Reason, (*self.reasons, self.reason), "reasons"))
        _set(self, "failure_modes", _enum_set(FailureMode, self.failure_modes, "failure_modes"))
        _require_text(self.run_id, "run_id")
        if not isinstance(self.accounting, InputAccounting):
            raise ValueError("accounting must be an InputAccounting")
        if any(not isinstance(check, CheckResult) for check in self.checks):
            raise ValueError("checks must be CheckResult instances")
        checks = tuple(sorted(self.checks, key=lambda check: check.check_id))
        if len({check.check_id for check in checks}) != len(checks):
            raise ValueError("check results must have unique check ids")
        _set(self, "checks", checks)
        if any(not isinstance(invariant, InvariantResult) for invariant in self.invariants):
            raise ValueError("invariants must be InvariantResult instances")
        invariants = tuple(sorted(self.invariants, key=lambda invariant: invariant.name))
        if len({invariant.name for invariant in invariants}) != len(invariants):
            raise ValueError("invariant results must have unique names")
        _set(self, "invariants", invariants)
        _optional_digest(self.evidence_manifest_sha256, "evidence_manifest_sha256")
        _require_text(self.started_at, "started_at")
        _require_text(self.completed_at, "completed_at")
        if not isinstance(self.counters, Mapping):
            raise ValueError("counters must be a mapping")
        _set(self, "counters", normalize(self.counters))
        if (self.status is Status.PASS) != (self.reason is Reason.VERIFIED):
            raise ValueError("status PASS and reason VERIFIED must occur together")

    @property
    def exit_code(self) -> int:
        return EXIT_CODE[self.status]

    def to_dict(self) -> dict[str, Any]:
        return normalize(
            {
                "status": self.status,
                "reason": self.reason,
                "reasons": list(self.reasons),
                "failure_modes": list(self.failure_modes),
                "run_id": self.run_id,
                "accounting": self.accounting.to_dict(),
                "checks": [check.to_dict() for check in self.checks],
                "invariants": [invariant.to_dict() for invariant in self.invariants],
                "evidence_manifest_sha256": self.evidence_manifest_sha256,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "counters": self.counters,
            }
        )
