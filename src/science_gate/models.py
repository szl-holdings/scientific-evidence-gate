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

The frontier-extension vocabulary (ARCHITECTURE.md section 17.3) lives here
too, with the small decision tables and value types that several modules
must agree on: skip justifications, falsifier cases, the verdict lattice,
:class:`Ratio`, and the mutation-status partition. Keeping each table in one
place is what lets independently built modules reach the same verdict.

Text that can quote input content (check evidence and diagnostics, input
diagnostics) is passed through :func:`science_gate._redact.redact` when a
result is constructed. Redacting at construction, before anything is hashed,
is the only point where a secret can be removed without breaking a hash later.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from enum import Enum
from fractions import Fraction
from types import MappingProxyType
from typing import Any, ClassVar, Iterable, Mapping, TypeVar

from ._canonical import normalize, sha256_bytes
from ._redact import redact, redact_text
from ._safeio import UnsafePathError, normalize_relpath

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
    "AuthStatus",
    "InputState",
    "SkipJustification",
    "SKIP_JUSTIFICATION_KEY",
    "SKIP_JUSTIFICATION_OUTCOMES",
    "UNJUSTIFIED_SHORTFALL_OUTCOME",
    "FalsifierOutcome",
    "WitnessState",
    "FALSIFICATION_OUTCOMES",
    "REJECTION_REASONS",
    "NumericOutcome",
    "NUMERIC_OUTCOME_VERDICTS",
    "RoundingConvention",
    "EITHER_HALF",
    "MutationStatus",
    "EXECUTED_MUTATION_STATUSES",
    "COUNTS_AS_DETECTED",
    "PieStage",
    "AssertionKind",
    "AssertionOutcome",
    "EditorialStatus",
    "NoticeType",
    "EditorialChannel",
    "StaleCause",
    "RatioState",
    "VerdictLevel",
    "EMPTY_AGGREGATE_OUTCOME",
    "verdict_level",
    "join_verdicts",
    "VerdictTransition",
    "fold_verdicts",
    "BUILTIN_CHECK_KINDS",
    "CONTROL_KEYS",
    "empty_controls",
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
    "Ratio",
    "InputOverride",
    "FalsifierCase",
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
    """Why a verdict was reached. ``VERIFIED`` is reserved for PASS.

    ``PROTOCOL_DRIFT`` (the verification protocol itself changed after it was
    planned), ``HARNESS_BLIND`` and ``UNMEASURED_MUTANTS`` (a mutation harness
    that cannot vouch for its own bookkeeping) were added by section 17.
    """

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
    PROTOCOL_DRIFT = "PROTOCOL_DRIFT"
    HARNESS_BLIND = "HARNESS_BLIND"
    UNMEASURED_MUTANTS = "UNMEASURED_MUTANTS"


class FailureMode(_Vocabulary):
    """Taxonomy of the ways a verification can mislead.

    ``VACUOUS_CUTOFF`` (section 17) is an early cutoff claimed by re-hashing a
    derived artifact instead of recomputing it.
    """

    VACUOUS_PASS = "VACUOUS_PASS"
    NARRATED_VERIFICATION = "NARRATED_VERIFICATION"
    PARTIAL_EXECUTION = "PARTIAL_EXECUTION"
    DEFECTIVE_VERIFICATION = "DEFECTIVE_VERIFICATION"
    OMITTED_POPULATION = "OMITTED_POPULATION"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    PROTOCOL_DRIFT = "PROTOCOL_DRIFT"
    EPHEMERAL_CLAIM = "EPHEMERAL_CLAIM"
    STALE_DEPENDENCY = "STALE_DEPENDENCY"
    VACUOUS_CUTOFF = "VACUOUS_CUTOFF"


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
    """Whether a receipt carries an HMAC signature (what the signer declared)."""

    UNSIGNED = "UNSIGNED"
    SIGNED_HMAC_SHA256 = "SIGNED_HMAC_SHA256"


class AuthStatus(_Vocabulary):
    """What re-checking a receipt's authentication established (section 17.9).

    Kept apart from :class:`SignatureState` because a receipt can only
    *declare* that it is signed; whether the signature holds is a judgement
    made later, by a verifier holding the key, and is never written into the
    statement it judges. ``SIGNED_UNCHECKED`` means signed, but no matching
    key was available, so nothing about the signature is known.
    """

    UNSIGNED = "UNSIGNED"
    SIGNED_VERIFIED = "SIGNED_VERIFIED"
    SIGNED_FAILED = "SIGNED_FAILED"
    SIGNED_UNCHECKED = "SIGNED_UNCHECKED"


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


class SkipJustification(_Vocabulary):
    """Closed vocabulary that may justify a required check not executing (extension #24, D1).

    Free text never justifies a skip: a SKIPPED or NOT_APPLICABLE result
    without one of these labels is an unexplained shortfall, which section
    17.7 makes FAIL / PARTIAL_EXECUTION.
    """

    EMPTY_POPULATION = "EMPTY_POPULATION"
    INPUT_UNAVAILABLE = "INPUT_UNAVAILABLE"
    SOURCE_REJECTED = "SOURCE_REJECTED"
    EVIDENCE_MALFORMED = "EVIDENCE_MALFORMED"
    NOT_DECLARED = "NOT_DECLARED"
    NO_DISCRIMINATION = "NO_DISCRIMINATION"
    GUARDED_ELSEWHERE = "GUARDED_ELSEWHERE"


#: The ``CheckResult.evidence`` key that carries a :class:`SkipJustification`
#: value. Carrying it in evidence (rather than a new field) means a label is
#: hashed into the receipt with the rest of the check's evidence.
SKIP_JUSTIFICATION_KEY = "skip_justification"

#: What a required check that did not execute contributes to the run, by its
#: justification (section 17.7). Every justified shortfall abstains; none is
#: PARTIAL_EXECUTION, which is reserved for unexplained shortfalls.
SKIP_JUSTIFICATION_OUTCOMES: Mapping[SkipJustification, tuple[Status, Reason, tuple[FailureMode, ...]]] = (
    MappingProxyType(
        {
            SkipJustification.EMPTY_POPULATION: (
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (FailureMode.VACUOUS_PASS,),
            ),
            SkipJustification.INPUT_UNAVAILABLE: (
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (FailureMode.OMITTED_POPULATION,),
            ),
            SkipJustification.SOURCE_REJECTED: (Status.ABSTAIN, Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,)),
            SkipJustification.EVIDENCE_MALFORMED: (Status.ABSTAIN, Reason.PROTOCOL_BROKEN, ()),
            SkipJustification.NOT_DECLARED: (Status.ABSTAIN, Reason.OUT_OF_SCOPE, ()),
            SkipJustification.NO_DISCRIMINATION: (
                Status.ABSTAIN,
                Reason.INSUFFICIENT_EVIDENCE,
                (FailureMode.VACUOUS_PASS,),
            ),
            SkipJustification.GUARDED_ELSEWHERE: (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW, ()),
        }
    )
)

#: What a required planned check contributes when it did not execute and
#: carries no justification (decision D1).
UNJUSTIFIED_SHORTFALL_OUTCOME: tuple[Status, Reason, tuple[FailureMode, ...]] = (
    Status.FAIL,
    Reason.PARTIAL_EXECUTION,
    (FailureMode.PARTIAL_EXECUTION,),
)


class FalsifierOutcome(_Vocabulary):
    """How one negative-control run of a checker ended (extension #1).

    REJECTED: the checker gave the case's expected rejection. ACCEPTED: it
    passed known-bad input, which proves a miss. INCONCLUSIVE: anything else.
    """

    REJECTED = "REJECTED"
    ACCEPTED = "ACCEPTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class WitnessState(_Vocabulary):
    """Whether a PASS carries proof that its checker could have failed (extension #1)."""

    WITNESSED = "WITNESSED"
    REFUTED = "REFUTED"
    UNWITNESSED = "UNWITNESSED"
    NO_CASE = "NO_CASE"
    NO_GENERATOR = "NO_GENERATOR"


#: What a would-be PASS becomes when it is not WITNESSED (decision D2): a
#: proven miss FAILs, unknown coverage ABSTAINs. WITNESSED keeps the PASS.
FALSIFICATION_OUTCOMES: Mapping[WitnessState, tuple[Status, Reason, tuple[FailureMode, ...]]] = MappingProxyType(
    {
        WitnessState.REFUTED: (Status.FAIL, Reason.BLIND_SPOT, (FailureMode.DEFECTIVE_VERIFICATION,)),
        WitnessState.UNWITNESSED: (Status.ABSTAIN, Reason.BLIND_SPOT, (FailureMode.VACUOUS_PASS,)),
        WitnessState.NO_CASE: (Status.ABSTAIN, Reason.BLIND_SPOT, (FailureMode.VACUOUS_PASS,)),
        WitnessState.NO_GENERATOR: (Status.ABSTAIN, Reason.BLIND_SPOT, (FailureMode.VACUOUS_PASS,)),
    }
)

#: The rejections a falsifier case may expect. A FAIL rejection may carry
#: any reason but VERIFIED. An ABSTAIN rejection must name content the
#: checker judged; "the evidence was missing" shows no power to reject.
REJECTION_REASONS: Mapping[Status, frozenset[Reason]] = MappingProxyType(
    {
        Status.FAIL: frozenset(set(Reason) - {Reason.VERIFIED}),
        Status.ABSTAIN: frozenset(
            {
                Reason.UNVERIFIED,
                Reason.PROTOCOL_BROKEN,
                Reason.REQUIRES_HUMAN_REVIEW,
                Reason.SOURCE_MISMATCH,
                Reason.PROTOCOL_DRIFT,
            }
        ),
    }
)


class NumericOutcome(_Vocabulary):
    """Outcome of an exact numeric-consistency test (extension #3).

    VACUOUSLY_CONSISTENT: the test held but could not have failed (for
    example a tolerance band wider than the value). NOT_TESTABLE: the test
    has no power at this precision, so it was not applied.
    """

    CONSISTENT = "CONSISTENT"
    INCONSISTENT = "INCONSISTENT"
    VACUOUSLY_CONSISTENT = "VACUOUSLY_CONSISTENT"
    NOT_TESTABLE = "NOT_TESTABLE"


#: How a numeric outcome maps onto a check result: (execution_state,
#: verdict, reason, failure modes). A CONSISTENT outcome may still only PASS
#: when its discrimination is greater than zero (section 17.8).
NUMERIC_OUTCOME_VERDICTS: Mapping[
    NumericOutcome, tuple[ExecutionState, Status, Reason, tuple[FailureMode, ...]]
] = MappingProxyType(
    {
        NumericOutcome.CONSISTENT: (ExecutionState.CHECKED, Status.PASS, Reason.VERIFIED, ()),
        NumericOutcome.INCONSISTENT: (
            ExecutionState.CHECKED,
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            (FailureMode.SOURCE_MISMATCH,),
        ),
        NumericOutcome.VACUOUSLY_CONSISTENT: (
            ExecutionState.CHECKED,
            Status.ABSTAIN,
            Reason.INSUFFICIENT_EVIDENCE,
            (FailureMode.VACUOUS_PASS,),
        ),
        NumericOutcome.NOT_TESTABLE: (
            ExecutionState.NOT_APPLICABLE,
            Status.ABSTAIN,
            Reason.INSUFFICIENT_EVIDENCE,
            (FailureMode.VACUOUS_PASS,),
        ),
    }
)


class RoundingConvention(_Vocabulary):
    """A way of reducing a stored value to printed precision (extensions #3 and #7, D5).

    FLOAT_FIRST models a toolchain that converts to binary floating point
    before rounding; it is computed transiently and never stored as a float.
    """

    HALF_EVEN = "HALF_EVEN"
    HALF_UP = "HALF_UP"
    TRUNCATE = "TRUNCATE"
    CEILING = "CEILING"
    FLOOR = "FLOOR"
    FLOAT_FIRST = "FLOAT_FIRST"


#: The convention set for third-party numbers (decision D5): either
#: half-rounding rule reproduces a printed value.
EITHER_HALF: frozenset[RoundingConvention] = frozenset({RoundingConvention.HALF_EVEN, RoundingConvention.HALF_UP})


class MutationStatus(_Vocabulary):
    """The one closed status of each generated mutant (extensions #4 and #11, D12).

    The executed partition is :data:`EXECUTED_MUTATION_STATUSES`; every
    other status is generated but not executed. Only DETECTED counts as a
    detection (:data:`COUNTS_AS_DETECTED`): a crash, a timeout or a flaky
    outcome is never credited.
    """

    DETECTED = "DETECTED"
    BLIND_SPOT = "BLIND_SPOT"
    VERIFIER_ERROR = "VERIFIER_ERROR"
    TIMED_OUT = "TIMED_OUT"
    FLAKY = "FLAKY"
    NOT_ACTIVATED = "NOT_ACTIVATED"
    NOOP_MUTATION = "NOOP_MUTATION"
    CANONICALLY_EQUIVALENT = "CANONICALLY_EQUIVALENT"
    DUPLICATE_MUTANT = "DUPLICATE_MUTANT"
    SUPPRESSED = "SUPPRESSED"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


#: ``executed = detected + blind_spot + verifier_error + timed_out + flaky``.
EXECUTED_MUTATION_STATUSES: frozenset[MutationStatus] = frozenset(
    {
        MutationStatus.DETECTED,
        MutationStatus.BLIND_SPOT,
        MutationStatus.VERIFIER_ERROR,
        MutationStatus.TIMED_OUT,
        MutationStatus.FLAKY,
    }
)

#: The table a mutation report hashes into its body: only DETECTED is a detection.
COUNTS_AS_DETECTED: Mapping[MutationStatus, bool] = MappingProxyType(
    {status: status is MutationStatus.DETECTED for status in MutationStatus}
)


class PieStage(_Vocabulary):
    """Where an undetected mutation stopped (extension #11): read, infect, propagate, check."""

    NOT_READ = "NOT_READ"
    READ_NOT_INFECTED = "READ_NOT_INFECTED"
    INFECTED_NOT_PROPAGATED = "INFECTED_NOT_PROPAGATED"
    PROPAGATED_NOT_CHECKED = "PROPAGATED_NOT_CHECKED"


class AssertionKind(_Vocabulary):
    """What an asserted action claims to have done (extension #6)."""

    TESTS_RUN = "TESTS_RUN"
    COMMAND_EXECUTED = "COMMAND_EXECUTED"
    FILE_CHECKED = "FILE_CHECKED"
    DATASET_VALIDATED = "DATASET_VALIDATED"
    TOOL_CALL = "TOOL_CALL"


class AssertionOutcome(_Vocabulary):
    """How an assertion joins the execution record (extension #6).

    ORPHANED classifies an invocation, not an assertion: a failing
    invocation that no assertion mentions.
    """

    BACKED = "BACKED"
    NARRATED = "NARRATED"
    CONTRADICTED = "CONTRADICTED"
    ORPHANED = "ORPHANED"


class EditorialStatus(_Vocabulary):
    """The editorial standing of a cited work, scoped to the channels consulted (extension #10).

    NOT_RETRACTED_WITHIN_SCOPE is a statement about named channels only, and
    needs at least two of them. UNDETERMINED is everything that cannot be
    stated (fewer than two channels, or none available).
    """

    NOT_RETRACTED_WITHIN_SCOPE = "NOT_RETRACTED_WITHIN_SCOPE"
    RETRACTED = "RETRACTED"
    REINSTATED = "REINSTATED"
    CORRECTED = "CORRECTED"
    EXPRESSION_OF_CONCERN = "EXPRESSION_OF_CONCERN"
    UNDETERMINED = "UNDETERMINED"


class NoticeType(_Vocabulary):
    """A dated editorial notice attached to a work (extension #10)."""

    RETRACTION = "RETRACTION"
    REINSTATEMENT = "REINSTATEMENT"
    CORRECTION = "CORRECTION"
    EXPRESSION_OF_CONCERN = "EXPRESSION_OF_CONCERN"


class EditorialChannel(_Vocabulary):
    """A source that counts toward editorial scope. Aggregator flags are never channels."""

    CROSSREF_UPDATED_BY = "CROSSREF_UPDATED_BY"
    CROSSREF_RETRACTION_WATCH = "CROSSREF_RETRACTION_WATCH"
    RETRACTION_WATCH_SNAPSHOT = "RETRACTION_WATCH_SNAPSHOT"


class StaleCause(_Vocabulary):
    """Why a dependency node went stale (extension #5): its data upstream, or its verifier."""

    UPSTREAM = "UPSTREAM"
    VERIFIER = "VERIFIER"


class RatioState(_Vocabulary):
    """Whether a :class:`Ratio` has a value. A zero denominator is never 0% or 100%."""

    DEFINED = "DEFINED"
    ZERO_DENOMINATOR = "ZERO_DENOMINATOR"
    UNAVAILABLE = "UNAVAILABLE"


class VerdictLevel(_Vocabulary):
    """The verdict lattice (extension #23), in ascending order: NONE < PASS < ABSTAIN < FAIL < ERROR.

    NONE is the bottom: the join of nothing. It is never a run status; an
    aggregate that stays NONE resolves to :data:`EMPTY_AGGREGATE_OUTCOME`, so
    an empty aggregate can never read as PASS.
    """

    NONE = "NONE"
    PASS = "PASS"
    ABSTAIN = "ABSTAIN"
    FAIL = "FAIL"
    ERROR = "ERROR"


#: What an aggregate with no contribution at all decides.
EMPTY_AGGREGATE_OUTCOME: tuple[Status, Reason] = (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)

_LEVEL_RANK: Mapping[VerdictLevel, int] = MappingProxyType({level: rank for rank, level in enumerate(VerdictLevel)})


def verdict_level(status: Status | str) -> VerdictLevel:
    """The lattice element of a status."""
    return VerdictLevel(Status(status).value)


def join_verdicts(levels: Iterable[VerdictLevel | str]) -> VerdictLevel:
    """Least upper bound of ``levels``; NONE for an empty iterable."""
    result = VerdictLevel.NONE
    for item in levels:
        level = VerdictLevel(item)
        if _LEVEL_RANK[level] > _LEVEL_RANK[result]:
            result = level
    return result


@dataclass(frozen=True)
class VerdictTransition:
    """One step at which a running verdict join rose, and what raised it."""

    step: int
    source: str
    before: VerdictLevel
    after: VerdictLevel
    reason: Reason

    def __post_init__(self) -> None:
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step < 1:
            raise ValueError(f"step must be a positive int, got {self.step!r}")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("source must be a non-empty string")
        object.__setattr__(self, "before", VerdictLevel(self.before))
        object.__setattr__(self, "after", VerdictLevel(self.after))
        object.__setattr__(self, "reason", Reason(self.reason))
        if _LEVEL_RANK[self.after] <= _LEVEL_RANK[self.before]:
            raise ValueError("a transition must raise the verdict level")

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "source": self.source,
            "before": self.before.value,
            "after": self.after.value,
            "reason": self.reason.value,
        }


def fold_verdicts(
    contributions: Iterable[tuple[str, Status | str, Reason | str]],
) -> tuple[VerdictLevel, tuple[VerdictTransition, ...]]:
    """Join ``(source, status, reason)`` contributions in order and log each rise.

    Steps are numbered over all contributions, so the log shows where in
    the gathering order each rise happened. Contributions that do not raise
    the join are not logged.
    """
    level = VerdictLevel.NONE
    log: list[VerdictTransition] = []
    for step, (source, status, reason) in enumerate(contributions, start=1):
        candidate = verdict_level(status)
        if _LEVEL_RANK[candidate] > _LEVEL_RANK[level]:
            log.append(VerdictTransition(step, source, level, candidate, Reason(reason)))
            level = candidate
    return level, tuple(log)


#: Check kinds defined by the contract (section 5, plus the three of section
#: 17.16). A manifest may name only registered kinds; the verifier's registry
#: must cover exactly this set.
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
        "claim_join",
        "editorial_status",
        "mutation_accounting",
    }
)

#: The keys of ``RunResult.controls`` (section 17.8), in a fixed order. Each
#: is null when the run produced no such control (an invalid manifest, say),
#: except ``verdict_transitions``, which is always a list.
CONTROL_KEYS = (
    "plan",
    "falsifiers",
    "canary",
    "comparator_self_test",
    "pins",
    "min_discrimination",
    "claim_join",
    "verdict_transitions",
)


def empty_controls() -> dict[str, Any]:
    """The controls of a run that executed nothing: every control unknown, no transitions."""
    return {**{key: None for key in CONTROL_KEYS}, "verdict_transitions": []}

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
    ``controls`` (section 17.8) summarizes the checker's own evidence: the
    PLAN, the falsifier witnesses, the canary, the comparator self-test, the
    harness pins and the verdict transitions. It has exactly
    :data:`CONTROL_KEYS`, so a missing control is an explicit null.
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
    controls: Mapping[str, Any] = field(default_factory=empty_controls)

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
        if not isinstance(self.controls, Mapping) or set(self.controls) != set(CONTROL_KEYS):
            raise ValueError(f"controls must have exactly the keys {CONTROL_KEYS}")
        if not isinstance(self.controls["verdict_transitions"], (list, tuple)):
            raise ValueError("controls.verdict_transitions must be a list")
        _set(self, "controls", normalize({key: self.controls[key] for key in CONTROL_KEYS}))
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
                "controls": self.controls,
            }
        )


@dataclass(frozen=True)
class Ratio:
    """A proportion of a counted population: ``numerator`` of ``denominator`` (extension #23).

    The type exists so that a missing or empty population can never be
    rendered as a percentage. Unknown counts give UNAVAILABLE, and a zero
    denominator gives ZERO_DENOMINATOR; both have no value and no decimal,
    so 0/0 can never read as 0% or 100%. Comparisons against a threshold
    must use :attr:`value` (an exact :class:`~fractions.Fraction`), never
    the rounded :attr:`decimal`.
    """

    numerator: int | None
    denominator: int | None

    #: Decimal places of :attr:`decimal` (ROUND_HALF_EVEN, trailing zeros removed).
    DECIMAL_PLACES: ClassVar[int] = 4

    def __post_init__(self) -> None:
        _set(self, "numerator", _optional_count(self.numerator, "numerator"))
        _set(self, "denominator", _optional_count(self.denominator, "denominator"))
        if self.numerator is not None and self.denominator is not None and self.numerator > self.denominator:
            raise ValueError(f"a proportion cannot exceed its population: {self.numerator}/{self.denominator}")

    @property
    def state(self) -> RatioState:
        if self.numerator is None or self.denominator is None:
            return RatioState.UNAVAILABLE
        return RatioState.ZERO_DENOMINATOR if self.denominator == 0 else RatioState.DEFINED

    @property
    def value(self) -> Fraction | None:
        """The exact proportion, or None when it is not DEFINED."""
        if self.numerator is None or self.denominator is None or self.denominator == 0:
            return None
        return Fraction(self.numerator, self.denominator)

    @property
    def fraction(self) -> str | None:
        """``"n/d"`` exactly as counted (never reduced), or None when a count is unknown."""
        if self.numerator is None or self.denominator is None:
            return None
        return f"{self.numerator}/{self.denominator}"

    @property
    def decimal(self) -> str | None:
        """The proportion rounded half-even to :data:`DECIMAL_PLACES`, without trailing zeros.

        ``"0.72"`` for 72/100, ``"0"`` for 0/100, ``"1"`` for 5/5. None
        unless DEFINED. :attr:`exact` says whether rounding lost anything.
        """
        value = self.value
        if value is None:
            return None
        quantum = Decimal(1).scaleb(-self.DECIMAL_PLACES)
        rounded = (Decimal(value.numerator) / Decimal(value.denominator)).quantize(quantum, rounding=ROUND_HALF_EVEN)
        return format(rounded.normalize(), "f")

    @property
    def exact(self) -> bool | None:
        """True when :attr:`decimal` equals the proportion exactly; None unless DEFINED."""
        value, decimal = self.value, self.decimal
        if value is None or decimal is None:
            return None
        return Fraction(Decimal(decimal)) == value

    def to_dict(self) -> dict[str, Any]:
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "state": self.state.value,
            "fraction": self.fraction,
            "decimal": self.decimal,
            "exact": self.exact,
        }


#: A falsifier case id: short, portable, and safe inside a ledger check id.
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


@dataclass(frozen=True)
class InputOverride:
    """Replacement admitted records for one declared input, inside a falsifier overlay only.

    ``rows`` are record values exactly as discovery admits them (``{column:
    str}`` for CSV, parsed JSON values otherwise). ``columns`` is the CSV
    header, or None to keep the input's own. Nothing here is ever written to
    disk: the engine builds an in-memory input from it.
    """

    rows: tuple[Any, ...]
    columns: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rows, (list, tuple)):
            raise ValueError("rows must be a list or tuple of record values")
        # Normalizing refuses floats and other non-canonical values up front,
        # at the generator that produced them, not later inside the engine.
        _set(self, "rows", tuple(normalize(list(self.rows))))
        if self.columns is not None:
            if not isinstance(self.columns, (list, tuple)):
                raise ValueError("columns must be a list or tuple of names, or None")
            _set(self, "columns", tuple(_require_text(name, "columns") for name in self.columns))

    def to_dict(self) -> dict[str, Any]:
        return {"columns": None if self.columns is None else list(self.columns), "rows": list(self.rows)}


@dataclass(frozen=True)
class FalsifierCase:
    """A known-bad variant of a check's evidence, and the rejection it must provoke (extension #1).

    A falsifier generator returns cases; the engine replays the *same*
    checker with the *same* params over an in-memory overlay in which the
    named inputs and documents are replaced. A case is data only, so a
    specialist module can produce one without depending on how the engine
    builds the overlay. ``documents`` maps manifest-relative paths (role
    documents and preloaded files) to replacement bytes. Keys are
    normalized, so two spellings of one path cannot both appear.
    """

    case_id: str
    description: str
    expected_verdict: Status
    expected_reason: Reason
    inputs: Mapping[str, InputOverride] = field(default_factory=dict)
    documents: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not _CASE_ID.fullmatch(self.case_id):
            raise ValueError(f"case_id must match {_CASE_ID.pattern}, got {self.case_id!r}")
        _require_text(self.description, "description")
        _set(self, "expected_verdict", _coerce(Status, self.expected_verdict, "expected_verdict"))
        _set(self, "expected_reason", _coerce(Reason, self.expected_reason, "expected_reason"))
        if self.expected_reason not in REJECTION_REASONS.get(self.expected_verdict, frozenset()):
            raise ValueError(
                f"{self.expected_verdict.value} / {self.expected_reason.value} is not a rejection a falsifier may expect"
            )
        inputs: dict[str, InputOverride] = {}
        for input_id, override in dict(self.inputs).items():
            if not isinstance(override, InputOverride):
                raise ValueError(f"inputs[{input_id!r}] must be an InputOverride")
            inputs[_require_text(input_id, "inputs")] = override
        documents: dict[str, bytes] = {}
        for path, data in dict(self.documents).items():
            if not isinstance(data, bytes):
                raise ValueError(f"documents[{path!r}] must be bytes")
            try:
                key = normalize_relpath(_require_text(path, "documents"))
            except UnsafePathError as exc:
                raise ValueError(f"documents[{path!r}]: {exc}") from None
            if key in documents:
                raise ValueError(f"documents names {key!r} twice")
            documents[key] = data
        if not inputs and not documents:
            raise ValueError("a falsifier case must replace at least one input or document")
        _set(self, "inputs", MappingProxyType(dict(sorted(inputs.items()))))
        _set(self, "documents", MappingProxyType(dict(sorted(documents.items()))))

    def to_dict(self) -> dict[str, Any]:
        """The case as recorded in evidence: replaced documents appear only as digests."""
        return {
            "case_id": self.case_id,
            "description": self.description,
            "expected": {"verdict": self.expected_verdict.value, "reason": self.expected_reason.value},
            "inputs": sorted(self.inputs),
            "documents": {path: sha256_bytes(data) for path, data in self.documents.items()},
        }
