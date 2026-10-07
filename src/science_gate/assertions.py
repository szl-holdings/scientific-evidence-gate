"""Claim-to-invocation join: are an agent's claims of work backed by execution records? (extension #6).

Agents and their harnesses often *say* that tests ran, a dataset was
validated or a file was checked. The text alone proves nothing: a narrated
verification reads exactly like a real one. This module joins each such
assertion to the hash-chained ledger of a sealed run, deterministically and
without reading prose, and classifies it:

* **BACKED**: the cited invocation is terminal in an intact chain, it
  completed no later than the assertion was made, it examined the artifact
  the assertion names, and its verdict is the result the assertion claims.
* **NARRATED**: there is no such record, or the record cannot be the one
  meant. The invocation is absent or never finished, it completed after the
  claim was made, or it never examined the named artifact.
* **CONTRADICTED**: the record exists and fits, but its verdict differs
  from the claimed result.
* **ORPHANED**: classifies *invocations*, not assertions. A terminal FAIL or
  ERROR that no assertion mentions is a failure someone may have silently
  ignored. It is listed, and it never decides the verdict.

The rules are applied in that order, and the order matters. An assertion is
CONTRADICTED only when everything else about it is backed, so a FAIL from
this check always rests on a recorded fact (the verdict), never on missing
evidence. Missing evidence only ever makes an assertion NARRATED, which
abstains.

A ledger whose chain does not verify against its seal backs nothing: every
assertion is NARRATED, and no invocation is reported ORPHANED, because a
record that fails verification is not evidence in either direction. The seal
itself (``run_id``, ``ledger_head_sha256``, ``ledger_length``) is read from
the sealed run's ``run.json`` and is *not* authenticated here; that is the
receipt's job. A forger who rebuilds the whole chain and rewrites the seal
consistently is caught by the receipt, not by this join.

The OpenTelemetry ``execute_tool`` span importer that the research brief
mentions is deliberately not built in this stage (ARCHITECTURE.md 17.15). An
assertion that cites a tool-call id therefore finds no invocation and is
NARRATED: an unimported record never counts as backing.

The check reads exactly one declared JSON (or JSON Lines) input of assertion
records, and the sealed run named by its ``sealed_run`` param. The contract
text names that param ``run``. Manifests refuse a key named ``run`` at any
depth (``UNSAFE_SUBPROCESS_REQUEST``, section 2), so a param of that name
could never reach this check.
"""

from __future__ import annotations

import dataclasses
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ._clock import ClockError, parse_utc
from ._safeio import UnsafePathError, normalize_relpath
from .discovery import OpenedInput
from .ledger import (
    ChainVerification,
    InvocationTrace,
    LedgerFormatError,
    index_invocations,
    parse_jsonl,
    verify_chain,
)
from .manifests import IDENTIFIER_PATTERN, CheckSpec
from .models import (
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    AssertionKind,
    AssertionOutcome,
    CheckResult,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    InputOverride,
    InputState,
    Reason,
    SkipJustification,
    Status,
)
from .verifier import MAX_LISTED, CheckContext, CheckOutcome, CheckParamError, Document, Findings

__all__ = [
    "KIND",
    "SEALED_RUN_PARAM",
    "LEDGER_FILE",
    "RUN_FILE",
    "LEDGER_ROLE",
    "RUN_ROLE",
    "ASSERTION_KEYS",
    "RUN_SEAL_KEYS",
    "CONTROL_PREFIX",
    "INPUT_FORMATS",
    "BACKED",
    "CITED_INVOCATION_ABSENT",
    "IMPOSSIBLE_TIMELINE",
    "ARTIFACT_UNBOUND",
    "ARTIFACT_MISMATCH",
    "CLAIMED_RESULT_CONTRADICTED",
    "LEDGER_CHAIN_BROKEN",
    "FALSIFIER_CASE_ID",
    "AssertionFormatError",
    "Assertion",
    "RunSeal",
    "AssertionJudgement",
    "ClaimJoin",
    "parse_assertions",
    "parse_run_seal",
    "join_claims",
    "preload_claim_join",
    "check_claim_join",
    "falsify_claim_join",
]

#: The check kind this module provides (ARCHITECTURE.md 17.16).
KIND = "claim_join"

#: The check param naming the sealed run directory, relative to the manifest.
SEALED_RUN_PARAM = "sealed_run"

#: The files of a sealed run that the join reads, and the roles they are read under.
LEDGER_FILE = "ledger.jsonl"
RUN_FILE = "run.json"
LEDGER_ROLE = "claim_join.ledger"
RUN_ROLE = "claim_join.run"

#: Exactly the keys of one assertion record. Unknown keys are refused, so a
#: misspelled field cannot silently drop out of the judgement.
ASSERTION_KEYS = ("claim_id", "kind", "cites", "claimed_at", "artifact_sha256", "claimed_result")

#: The only ``run.json`` keys the join reads: the seal of the ledger.
RUN_SEAL_KEYS = ("run_id", "ledger_head_sha256", "ledger_length")

#: Check ids of the engine's own control invocations (falsifiers, canary,
#: comparator). Their FAIL verdicts are expected, so they are never ORPHANED.
CONTROL_PREFIX = "control:"

#: Input formats whose records are parsed JSON values.
INPUT_FORMATS = ("json", "jsonl")

# Detail codes. Each assertion's ``detail`` starts with exactly one of them.
BACKED = "BACKED"
CITED_INVOCATION_ABSENT = "CITED_INVOCATION_ABSENT"
IMPOSSIBLE_TIMELINE = "IMPOSSIBLE_TIMELINE"
ARTIFACT_UNBOUND = "ARTIFACT_UNBOUND"
ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
CLAIMED_RESULT_CONTRADICTED = "CLAIMED_RESULT_CONTRADICTED"
LEDGER_CHAIN_BROKEN = "LEDGER_CHAIN_BROKEN"

#: The one known-bad case :func:`falsify_claim_join` builds.
FALSIFIER_CASE_ID = "flip-claimed-result"

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class AssertionFormatError(ValueError):
    """An assertion record or a sealed run's seal that does not match its format."""


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass(frozen=True)
class Assertion:
    """One claim that some work was done, citing the invocation that did it.

    Validated on construction, so a malformed assertion cannot reach the join.
    ``claimed_at`` stays the exact string the record carried; it is parsed
    here only to prove that it is an ISO-8601 UTC instant.
    """

    claim_id: str
    kind: AssertionKind
    cites: str
    claimed_at: str
    artifact_sha256: str | None
    claimed_result: Status

    def __post_init__(self) -> None:
        if not isinstance(self.claim_id, str) or not IDENTIFIER_PATTERN.fullmatch(self.claim_id):
            raise AssertionFormatError(f"claim_id must match {IDENTIFIER_PATTERN.pattern}, got {self.claim_id!r}")
        try:
            object.__setattr__(self, "kind", AssertionKind(self.kind))
        except ValueError:
            allowed = sorted(member.value for member in AssertionKind)
            raise AssertionFormatError(f"kind must be one of {allowed}, got {self.kind!r}") from None
        if not isinstance(self.cites, str) or not self.cites.strip():
            raise AssertionFormatError("cites must be a non-empty string")
        try:
            parse_utc(self.claimed_at)
        except ClockError as exc:
            raise AssertionFormatError(f"claimed_at: {exc}") from None
        if self.artifact_sha256 is not None and not (
            isinstance(self.artifact_sha256, str) and _SHA256_HEX.fullmatch(self.artifact_sha256)
        ):
            raise AssertionFormatError("artifact_sha256 must be null or 64 lowercase hex characters")
        try:
            object.__setattr__(self, "claimed_result", Status(self.claimed_result))
        except ValueError:
            allowed = sorted(member.value for member in Status)
            raise AssertionFormatError(
                f"claimed_result must be one of {allowed}, got {self.claimed_result!r}"
            ) from None

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "kind": self.kind.value,
            "cites": self.cites,
            "claimed_at": self.claimed_at,
            "artifact_sha256": self.artifact_sha256,
            "claimed_result": self.claimed_result.value,
        }


@dataclass(frozen=True)
class RunSeal:
    """The seal of a sealed run's ledger, as its ``run.json`` records it.

    ``ledger_length`` None means the run was never sealed. That is
    representable on purpose: the chain verifier then reports UNSEALED, and
    an unsealed ledger backs nothing.
    """

    run_id: str
    ledger_head_sha256: str | None
    ledger_length: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise AssertionFormatError("run_id must be a non-empty string")
        head = self.ledger_head_sha256
        if head is not None and not (isinstance(head, str) and _SHA256_HEX.fullmatch(head)):
            raise AssertionFormatError("ledger_head_sha256 must be null or 64 lowercase hex characters")
        if self.ledger_length is not None and not _is_count(self.ledger_length):
            raise AssertionFormatError("ledger_length must be null or a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "ledger_head_sha256": self.ledger_head_sha256,
            "ledger_length": self.ledger_length,
        }


def parse_assertions(records: Sequence[Any]) -> tuple[Assertion, ...]:
    """Validate assertion records, in order. Raises :class:`AssertionFormatError`.

    Every key is required (``artifact_sha256`` may be null) and no other key
    is allowed. Claim ids must be unique, because the evidence buckets are
    keyed by them and a repeated id would make two claims indistinguishable.
    """
    assertions: list[Assertion] = []
    seen: set[str] = set()
    for position, record in enumerate(records, start=1):
        where = f"assertion record {position}"
        if not isinstance(record, Mapping):
            raise AssertionFormatError(f"{where} must be a JSON object")
        unknown = sorted(set(record) - set(ASSERTION_KEYS))
        missing = [name for name in ASSERTION_KEYS if name not in record]
        if unknown or missing:
            raise AssertionFormatError(f"{where}: unknown key(s) {unknown}, missing key(s) {missing}")
        try:
            assertion = Assertion(**{name: record[name] for name in ASSERTION_KEYS})
        except AssertionFormatError as exc:
            raise AssertionFormatError(f"{where}: {exc}") from None
        if assertion.claim_id in seen:
            raise AssertionFormatError(f"{where}: claim_id {assertion.claim_id!r} repeats an earlier record")
        seen.add(assertion.claim_id)
        assertions.append(assertion)
    return tuple(assertions)


def parse_run_seal(document: Any) -> RunSeal:
    """Read the seal from a ``run.json`` document; every other key is ignored.

    All three keys must be present. A document without them is not a run
    record this tool wrote, so it is malformed evidence rather than an
    unsealed run.
    """
    if not isinstance(document, Mapping):
        raise AssertionFormatError("run.json must be a JSON object")
    missing = [name for name in RUN_SEAL_KEYS if name not in document]
    if missing:
        raise AssertionFormatError(f"run.json is missing {missing}")
    return RunSeal(**{name: document[name] for name in RUN_SEAL_KEYS})


@dataclass(frozen=True)
class AssertionJudgement:
    """How one assertion joined the ledger: its outcome, a detail code and an explanation."""

    assertion: Assertion
    outcome: AssertionOutcome
    code: str
    message: str

    @property
    def detail(self) -> str:
        return f"{self.code}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.assertion.claim_id,
            "kind": self.assertion.kind.value,
            "cites": self.assertion.cites,
            "outcome": self.outcome.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ClaimJoin:
    """The result of :func:`join_claims`.

    ``orphaned`` holds invocation ids, sorted; every other bucket holds
    claim ids.
    """

    chain: ChainVerification
    judgements: tuple[AssertionJudgement, ...]
    orphaned: tuple[str, ...]

    def bucket(self, outcome: AssertionOutcome) -> tuple[str, ...]:
        """The sorted ids in one outcome's bucket."""
        if outcome is AssertionOutcome.ORPHANED:
            return self.orphaned
        return tuple(sorted(item.assertion.claim_id for item in self.judgements if item.outcome is outcome))

    @property
    def buckets(self) -> dict[str, list[str]]:
        """Every outcome, including the empty ones, so an absent bucket never reads as unknown."""
        return {outcome.value: list(self.bucket(outcome)) for outcome in AssertionOutcome}

    @property
    def counts(self) -> dict[str, int]:
        return {outcome.value: len(self.bucket(outcome)) for outcome in AssertionOutcome}

    def to_evidence(self) -> dict[str, Any]:
        return {
            "chain": self.chain.to_dict(),
            "assertions": [item.to_dict() for item in self.judgements],
            "buckets": self.buckets,
            "counts": self.counts,
        }


def _judge(
    assertion: Assertion,
    traces: Mapping[str, InvocationTrace],
    by_seq: Mapping[int, Mapping[str, Any]],
) -> AssertionJudgement:
    """Apply the join rules to one assertion, first match wins (17.15 step 2)."""

    def judged(outcome: AssertionOutcome, code: str, message: str) -> AssertionJudgement:
        return AssertionJudgement(assertion, outcome, code, message)

    narrated = AssertionOutcome.NARRATED
    cites = assertion.cites
    trace = traces.get(cites)
    if trace is None:
        return judged(narrated, CITED_INVOCATION_ABSENT, f"the sealed run has no invocation {cites!r}")
    if not trace.terminal:
        problems = "; ".join(trace.problems) or "no terminal entry"
        return judged(narrated, CITED_INVOCATION_ABSENT, f"{cites} has no terminal result ({problems})")
    terminal = by_seq[trace.terminal_seq]
    completed_at = terminal.get("completed_at")
    try:
        completed = parse_utc(completed_at)
    except ClockError:
        return judged(
            narrated,
            IMPOSSIBLE_TIMELINE,
            f"{cites} records completed_at {completed_at!r}, which is not a UTC instant, so it cannot "
            f"precede claimed_at {assertion.claimed_at}",
        )
    if completed > parse_utc(assertion.claimed_at):
        return judged(
            narrated,
            IMPOSSIBLE_TIMELINE,
            f"{cites} completed_at {completed_at} is after claimed_at {assertion.claimed_at}",
        )
    if assertion.artifact_sha256 is None:
        return judged(
            narrated,
            ARTIFACT_UNBOUND,
            f"the assertion names no artifact_sha256, so it cannot be bound to what {cites} examined",
        )
    digests = terminal.get("input_sha256s")
    bound = sorted(
        input_id
        for input_id, digest in (digests.items() if isinstance(digests, Mapping) else ())
        if digest == assertion.artifact_sha256
    )
    if not bound:
        return judged(
            narrated,
            ARTIFACT_MISMATCH,
            f"artifact_sha256 {assertion.artifact_sha256} is not among the input digests {cites} recorded",
        )
    recorded = f"{cites} ({trace.check_id}) recorded {trace.verdict.value} / {trace.reason.value}"
    if trace.verdict is not assertion.claimed_result:
        return judged(
            AssertionOutcome.CONTRADICTED,
            CLAIMED_RESULT_CONTRADICTED,
            f"claimed {assertion.claimed_result.value}, but {recorded}",
        )
    return judged(
        AssertionOutcome.BACKED,
        BACKED,
        f"{recorded} at {completed_at}, over input(s) {bound}",
    )


def join_claims(assertions: Sequence[Assertion], entries: Sequence[Mapping[str, Any]], seal: RunSeal) -> ClaimJoin:
    """Join assertions to a sealed ledger (ARCHITECTURE.md 17.15). Pure: reads nothing else.

    The chain is verified first, with the run id, so entries transplanted
    from another run count as tampering. A broken chain makes every assertion
    NARRATED and lists no ORPHANED invocation. Otherwise each assertion is
    judged by :func:`_judge`, and every terminal FAIL or ERROR invocation
    that no assertion cites (controls excluded) is ORPHANED. "Cites" means
    mentioned by any assertion, whatever that assertion's own outcome.
    """
    chain = verify_chain(entries, seal.ledger_head_sha256, seal.ledger_length, run_id=seal.run_id)
    if not chain.intact:
        message = f"the sealed run's ledger fails verification ({chain.problems[0]}), so it backs nothing"
        judgements = tuple(
            AssertionJudgement(assertion, AssertionOutcome.NARRATED, LEDGER_CHAIN_BROKEN, message)
            for assertion in assertions
        )
        return ClaimJoin(chain, judgements, ())
    traces = index_invocations(entries)
    by_seq = {entry["seq"]: entry for entry in entries}
    judgements = tuple(_judge(assertion, traces, by_seq) for assertion in assertions)
    cited = {assertion.cites for assertion in assertions}
    orphaned = tuple(
        invocation_id
        for invocation_id, trace in traces.items()
        if trace.terminal
        and trace.verdict in (Status.FAIL, Status.ERROR)
        and not (trace.check_id or "").startswith(CONTROL_PREFIX)
        and invocation_id not in cited
    )
    return ClaimJoin(chain, judgements, orphaned)


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


def _sealed_run_dir(spec: CheckSpec) -> str:
    """The validated, normalized ``sealed_run`` param.

    An unusable value is a wiring error (ERROR), never a quiet skip: a typo
    here must not turn into "nothing to join".
    """
    unknown = sorted(set(spec.params) - {SEALED_RUN_PARAM})
    if unknown:
        raise CheckParamError(f"UNKNOWN_PARAM: {KIND} accepts only {SEALED_RUN_PARAM!r}, got {unknown}")
    if SEALED_RUN_PARAM not in spec.params:
        raise CheckParamError(f"MISSING_PARAM: {KIND} requires {SEALED_RUN_PARAM!r}")
    try:
        return normalize_relpath(spec.params[SEALED_RUN_PARAM])
    except UnsafePathError as exc:
        raise CheckParamError(f"INVALID_PARAM: {SEALED_RUN_PARAM}: {exc}") from None


def preload_claim_join(ctx: CheckContext) -> None:
    """Read each declared claim_join check's sealed run before any check runs (``verifier.PRELOADS``).

    Reading up front puts both files' digests into the run id and in front
    of ``summary_consistency``, and every check then sees the same bytes. A
    check with an unusable param reads nothing here; the check itself
    reports the error.
    """
    for spec in ctx.manifest.checks:
        if spec.kind != KIND:
            continue
        try:
            run_dir = _sealed_run_dir(spec)
        except CheckParamError:
            continue
        ctx.read_document(posixpath.join(run_dir, LEDGER_FILE), role=LEDGER_ROLE, parse="bytes")
        ctx.read_document(posixpath.join(run_dir, RUN_FILE), role=RUN_ROLE, parse="json")


def _not_executed(
    state: ExecutionState, label: SkipJustification, detail: str, evidence: Mapping[str, Any]
) -> CheckOutcome:
    """A labelled shortfall (D1, #24). Verdict, reason and modes come from the shared table.

    Taking them from ``SKIP_JUSTIFICATION_OUTCOMES`` keeps this check's own
    verdict identical to what the engine charges the run for the same label.
    """
    verdict, reason, modes = SKIP_JUSTIFICATION_OUTCOMES[label]
    return CheckOutcome(
        execution_state=state,
        verdict=verdict,
        reason=reason,
        failure_modes=modes,
        rows_examined=0,
        evidence={**evidence, SKIP_JUSTIFICATION_KEY: label.value},
        diagnostics=(detail,),
    )


#: An assertions input in one of these states has no records to judge.
_UNAVAILABLE_INPUT_STATES = frozenset(
    {InputState.MISSING, InputState.REFUSED, InputState.OPEN_FAILED, InputState.PARSE_ERROR}
)


def _assertions_input(ctx: CheckContext, spec: CheckSpec) -> OpenedInput:
    """The check's single assertions input.

    Manifests refuse check inputs that name no declared input, and discovery
    opens every declared input, so the lookup cannot miss.
    """
    if len(spec.inputs) != 1:
        raise CheckParamError(f"INVALID_INPUTS: {KIND} takes exactly one input of assertions, got {len(spec.inputs)}")
    opened = ctx.inputs[spec.inputs[0]]
    if opened.spec.format not in INPUT_FORMATS:
        raise CheckParamError(
            f"INVALID_INPUTS: {KIND} reads JSON assertion records, not {opened.spec.format!r} "
            f"(input {opened.input_id!r})"
        )
    return opened


def _input_summary(opened: OpenedInput) -> dict[str, Any]:
    return {
        "input_id": opened.input_id,
        "state": opened.state.value,
        "sha256": opened.sha256,
        "row_counts": opened.record.counts.to_dict(),
    }


@dataclass(frozen=True)
class _Prepared:
    """Everything the join needs, validated, plus the evidence gathered so far."""

    opened: OpenedInput
    assertions: tuple[Assertion, ...]
    entries: tuple[dict[str, Any], ...]
    seal: RunSeal
    evidence: dict[str, Any]


def _input_shortfall(opened: OpenedInput, evidence: Mapping[str, Any]) -> CheckOutcome | None:
    """The labelled outcome for an assertions input that cannot be judged in full, or None.

    The labels follow the engine's rules for an input with nothing to
    examine (17.7). A record that discovery could not read, or that lacks its
    row key, is a malformed assertion (17.15). A PARTIAL input whose only
    shortfall is deferred records (beyond ``max_rows``) is still judged; the
    check then adds a PARTIAL_EXECUTION finding. None therefore guarantees
    admitted records to judge.
    """
    not_applicable = ExecutionState.NOT_APPLICABLE
    input_id = opened.input_id
    if opened.state in _UNAVAILABLE_INPUT_STATES:
        return _not_executed(
            not_applicable,
            SkipJustification.INPUT_UNAVAILABLE,
            f"assertions input {input_id!r} is {opened.state.value}: no assertion was judged",
            evidence,
        )
    if opened.state is InputState.HASH_MISMATCH:
        return _not_executed(
            not_applicable,
            SkipJustification.SOURCE_REJECTED,
            f"assertions input {input_id!r} does not match its declared digest: no assertion was judged",
            evidence,
        )
    counts = opened.record.counts
    unreadable = (counts.failed or 0) + (counts.unresolved or 0)
    if unreadable:
        detail = "; ".join(opened.record.diagnostics) or f"{unreadable} record(s) not admitted"
        return _not_executed(
            ExecutionState.SKIPPED,
            SkipJustification.EVIDENCE_MALFORMED,
            f"MALFORMED_ASSERTIONS: {unreadable} record(s) of {input_id!r} could not be read: {detail}",
            evidence,
        )
    if not opened.rows:
        return _not_executed(
            not_applicable,
            SkipJustification.EMPTY_POPULATION,
            f"assertions input {input_id!r} holds no assertion: there is nothing to join",
            evidence,
        )
    return None


def _records(opened: OpenedInput) -> list[Any]:
    """The admitted assertion records, as parsed JSON values, in input order."""
    return [row.values for row in opened.rows or ()]


def _document_shortfall(document: Document, evidence: Mapping[str, Any]) -> CheckOutcome:
    """A sealed-run file that is missing, unreadable or unparseable: the run cannot back anything."""
    label = (
        SkipJustification.EVIDENCE_MALFORMED
        if document.state is InputState.PARSE_ERROR
        else SkipJustification.INPUT_UNAVAILABLE
    )
    detail = document.diagnostic or f"state {document.state}"
    return _not_executed(
        ExecutionState.SKIPPED, label, f"{document.role} ({document.path}) unavailable: {detail}", evidence
    )


def _malformed(document: Document, problem: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    return _not_executed(
        ExecutionState.SKIPPED,
        SkipJustification.EVIDENCE_MALFORMED,
        f"MALFORMED_DOCUMENT: {document.role} ({document.path}): {problem}",
        evidence,
    )


def _prepare(ctx: CheckContext, spec: CheckSpec) -> _Prepared | CheckOutcome:
    """Read and validate the assertions and the sealed run, or explain why they cannot be joined.

    The population (the assertions) is judged before the sealed run, so an
    empty or unreadable assertions input is reported as such even when the
    run is also unusable.
    """
    run_dir = _sealed_run_dir(spec)
    opened = _assertions_input(ctx, spec)
    ledger_document = ctx.read_document(posixpath.join(run_dir, LEDGER_FILE), role=LEDGER_ROLE, parse="bytes")
    run_document = ctx.read_document(posixpath.join(run_dir, RUN_FILE), role=RUN_ROLE, parse="json")
    evidence: dict[str, Any] = {
        "input": _input_summary(opened),
        "sealed_run": {"path": run_dir, "ledger": ledger_document.to_dict(), "run": run_document.to_dict()},
    }

    shortfall = _input_shortfall(opened, evidence)
    if shortfall is not None:
        return shortfall
    try:
        assertions = parse_assertions(_records(opened))
    except AssertionFormatError as exc:
        return _not_executed(
            ExecutionState.SKIPPED,
            SkipJustification.EVIDENCE_MALFORMED,
            f"MALFORMED_ASSERTIONS: {opened.input_id!r}: {exc}",
            evidence,
        )

    # An empty ledger file is a ledger with no entries; its seal decides whether that is honest.
    if ledger_document.state not in (InputState.PARSED, InputState.EMPTY):
        return _document_shortfall(ledger_document, evidence)
    if not run_document.loaded:
        return _document_shortfall(run_document, evidence)
    try:
        entries = parse_jsonl(ledger_document.content or b"")
    except LedgerFormatError as exc:
        return _malformed(ledger_document, str(exc), evidence)
    try:
        seal = parse_run_seal(run_document.content)
    except AssertionFormatError as exc:
        return _malformed(run_document, str(exc), evidence)
    evidence["sealed_run"]["seal"] = seal.to_dict()
    return _Prepared(opened, assertions, entries, seal, evidence)


def _listed(ids: Sequence[str]) -> list[str]:
    """At most :data:`~science_gate.verifier.MAX_LISTED` ids; callers always give the full count too."""
    return list(ids[:MAX_LISTED])


def check_claim_join(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Every assertion of work must be backed by a terminal invocation of the sealed run (kind ``claim_join``).

    FAIL / SOURCE_MISMATCH when any assertion is CONTRADICTED: the record
    exists, fits the claim, and says otherwise. Otherwise ABSTAIN / UNVERIFIED
    with NARRATED_VERIFICATION when any assertion is NARRATED. Otherwise PASS.
    ORPHANED invocations are listed in the evidence and diagnostics and never
    decide. ``rows_examined`` is the number of assertions judged. A PASS says
    the assertions match the records, not that the work they describe was
    adequate.
    """
    prepared = _prepare(ctx, spec)
    if isinstance(prepared, CheckOutcome):
        return prepared
    join = join_claims(prepared.assertions, prepared.entries, prepared.seal)

    findings = Findings()
    if prepared.opened.state is InputState.PARTIAL:
        counts = prepared.opened.record.counts
        findings.abstain(
            Reason.PARTIAL_EXECUTION,
            f"assertions input {prepared.opened.input_id!r} is PARTIAL: {counts.admitted} of "
            f"{prepared.opened.record.rows} records judged",
            FailureMode.PARTIAL_EXECUTION,
            FailureMode.OMITTED_POPULATION,
        )
    contradicted = join.bucket(AssertionOutcome.CONTRADICTED)
    if contradicted:
        findings.fail(
            Reason.SOURCE_MISMATCH,
            f"CONTRADICTED: {len(contradicted)} assertion(s) claim a result their cited invocation contradicts: "
            f"{_listed(contradicted)}",
            FailureMode.SOURCE_MISMATCH,
        )
    narrated = join.bucket(AssertionOutcome.NARRATED)
    if narrated:
        cause = f" (the ledger chain is broken: {join.chain.problems[0]})" if not join.chain.intact else ""
        findings.abstain(
            Reason.UNVERIFIED,
            f"NARRATED_VERIFICATION: {len(narrated)} assertion(s) have no execution record that backs them{cause}: "
            f"{_listed(narrated)}",
            FailureMode.NARRATED_VERIFICATION,
        )
    outcome = findings.outcome(
        rows_examined=len(prepared.assertions), evidence={**prepared.evidence, **join.to_evidence()}
    )
    if not join.orphaned:
        return outcome
    orphaned = (
        f"ORPHANED: {len(join.orphaned)} failing invocation(s) that no assertion mentions: {_listed(join.orphaned)}"
    )
    return dataclasses.replace(outcome, diagnostics=(*outcome.diagnostics, orphaned))


# ---------------------------------------------------------------------------
# Falsifier (extension #1)
# ---------------------------------------------------------------------------


def _flipped(status: Status) -> Status:
    """A claimed result that differs from ``status``: PASS becomes FAIL, anything else PASS."""
    return Status.FAIL if status is Status.PASS else Status.PASS


def falsify_claim_join(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """The known-bad case for a claim_join PASS: the first BACKED assertion's ``claimed_result`` flipped.

    The flipped assertion still cites a real, timely, artifact-bound
    invocation, so a checker that can reject must call it CONTRADICTED:
    FAIL / SOURCE_MISMATCH. The case is rebuilt from the context rather than
    from ``result`` (which the generator contract supplies), so a PASS cannot
    steer its own falsification. Returns ``()`` when nothing is BACKED.
    """
    prepared = _prepare(ctx, spec)
    if isinstance(prepared, CheckOutcome):
        return ()
    join = join_claims(prepared.assertions, prepared.entries, prepared.seal)
    target = next((item.assertion for item in join.judgements if item.outcome is AssertionOutcome.BACKED), None)
    if target is None:
        return ()
    flipped = _flipped(target.claimed_result)
    rows = []
    for values in _records(prepared.opened):
        record = dict(values)
        if record.get("claim_id") == target.claim_id:
            record["claimed_result"] = flipped.value
        rows.append(record)
    return (
        FalsifierCase(
            case_id=FALSIFIER_CASE_ID,
            description=(
                f"claimed_result of BACKED assertion {target.claim_id!r} flipped from "
                f"{target.claimed_result.value} to {flipped.value}"
            ),
            expected_verdict=Status.FAIL,
            expected_reason=Reason.SOURCE_MISMATCH,
            inputs={prepared.opened.input_id: InputOverride(rows=tuple(rows))},
        ),
    )
