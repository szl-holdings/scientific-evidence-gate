"""Citation checks in three layers (ARCHITECTURE.md section 9).

Each layer answers a narrower question than the one after it. None of them
establishes that a cited work supports the claim it is cited for:

1. ``verification_log`` (structural, fully offline). Does every verification
   a log *claims* point to a complete invocation record? A claim with no
   record is narrated, not shown: UNVERIFIED with NARRATED_VERIFICATION. The
   claimed counts are also reported as
   :class:`~science_gate.invariants.ClaimTally` values, so the run-level
   ``checked_claims_le_invocations`` invariant sees them.
2. ``citation_resolver``. What did a resolver answer for each cited DOI? The
   answer comes from the frozen capture; live lookups happen only when live
   access is enabled, and only for DOIs the capture cannot answer. Absence
   is SOURCE_UNAVAILABLE, never "not found".
3. ``citation_metadata``. Does the cited metadata match the work the DOI
   actually reached? Every citation gets exactly one ``primary_disposition``
   and a list of ``defects``, which may overlap. A replacement candidate
   (another record that resembles the citation) is listed for a person to
   review and is never used as ground truth.

The documents, each read through the check context so that its digest enters
the evidence manifest:

* ``citations.entries`` (``science-gate-citations/v1``): the citations as written.
* ``citations.log``: an external verifier's log, in the contract's format.
* ``citations.frozen`` (``science-gate-citations-frozen/v1``): captured resolver answers.

Two design points matter for reproducibility. A DOI with a usable frozen
record is always answered from that record, even under ``--live``, so a live
run is still a replay wherever a capture exists. And each DOI is looked up
live at most once per run, so the resolver and metadata layers judge the same
answer. All three checks read role documents only, and refuse declared
inputs and params rather than appear to have examined them.
"""

from __future__ import annotations

import dataclasses
import unicodedata
import weakref
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Sequence

from ._clock import ClockError, parse_utc
from .adapters import frozen as frozen_adapter
from .adapters import live as live_adapter
from .adapters.frozen import FrozenRecordSet
from .adapters.records import (
    SOURCE_LIVE,
    Author,
    RecordFormatError,
    Resolution,
    Work,
    is_sha256,
    parse_work,
    require_object,
)
from .invariants import ClaimTally
from .manifests import IDENTIFIER_PATTERN, CheckSpec
from .models import ExecutionState, FailureMode, InputState, MetadataState, Reason, ResolverState, Status
from .verifier import MAX_LISTED, CheckContext, CheckOutcome, CheckParamError, Document, Findings

__all__ = [
    "ENTRIES_SCHEMA",
    "LOG_SCHEMA",
    "ENTRIES_KEYS",
    "CITATION_KEYS",
    "LOG_KEYS",
    "LOG_REQUIRED_KEYS",
    "VERIFIER_KEYS",
    "LOG_ENTRY_KEYS",
    "INVOCATION_KEYS",
    "CLAIMED_STATUSES",
    "Defect",
    "SOURCE_UNAVAILABLE_DISPOSITION",
    "DISPOSITIONS",
    "Citation",
    "parse_entries",
    "normalize_text",
    "check_verification_log",
    "check_resolver",
    "check_metadata",
]

ENTRIES_SCHEMA = "science-gate-citations/v1"
LOG_SCHEMA = "science-gate-verification-log/v1"

ENTRIES_KEYS = ("schema", "citations")
CITATION_KEYS = ("citation_id", "doi", "title", "authors", "year", "journal", "volume", "issue")

#: The contract fixes the log's fields. ``schema`` is optional because logs
#: come from other tools; when present it must name this format. A log with
#: no ``invocations`` key records no invocation at all, which is reported as
#: such (``None``), never as zero.
LOG_KEYS = ("schema", "claimed_verified", "verifier", "entries", "invocations")
LOG_REQUIRED_KEYS = ("claimed_verified", "verifier", "entries")
VERIFIER_KEYS = ("name", "version")
LOG_ENTRY_KEYS = ("citation_id", "claimed_status")
INVOCATION_KEYS = ("invocation_id", "citation_id", "request", "response_sha256", "retrieved_at")

#: A status the tool does not know is refused: guessing its meaning could
#: either narrate a verification or hide one.
CLAIMED_VERIFIED = "VERIFIED"
CLAIMED_STATUSES = (CLAIMED_VERIFIED, "NOT_VERIFIED")

#: Per-entry outcomes of the log check.
BACKED, NARRATED, NOT_CLAIMED = "BACKED", "NARRATED", "NOT_CLAIMED"

#: Per-field outcomes of the metadata comparison.
MATCH, MISMATCH, ORDER_DIFFERS, NOT_CITED, NOT_IN_RECORD = (
    "MATCH",
    "MISMATCH",
    "ORDER_DIFFERS",
    "NOT_CITED",
    "NOT_IN_RECORD",
)


class Defect(str, Enum):
    """Metadata defect types. A citation can carry several at once."""

    DOI_WORK_MISMATCH = "DOI_WORK_MISMATCH"
    TITLE_MISMATCH = "TITLE_MISMATCH"
    AUTHOR_MISMATCH = "AUTHOR_MISMATCH"
    AUTHOR_ORDER_MISMATCH = "AUTHOR_ORDER_MISMATCH"
    YEAR_MISMATCH = "YEAR_MISMATCH"
    JOURNAL_MISMATCH = "JOURNAL_MISMATCH"
    VOLUME_MISMATCH = "VOLUME_MISMATCH"
    ISSUE_MISMATCH = "ISSUE_MISMATCH"
    CONFLATED_ENTRY = "CONFLATED_ENTRY"


#: A citation whose DOI reached no usable answer has no metadata outcome to
#: report, and "not found" would be false. Its disposition reuses the
#: resolver's SOURCE_UNAVAILABLE, so the gap stays visible as a gap.
SOURCE_UNAVAILABLE_DISPOSITION = ResolverState.SOURCE_UNAVAILABLE.value
DISPOSITIONS = (*(state.value for state in MetadataState), SOURCE_UNAVAILABLE_DISPOSITION)

_FIELD_DEFECTS: Mapping[str, Defect] = {
    "doi": Defect.DOI_WORK_MISMATCH,
    "title": Defect.TITLE_MISMATCH,
    "year": Defect.YEAR_MISMATCH,
    "journal": Defect.JOURNAL_MISMATCH,
    "volume": Defect.VOLUME_MISMATCH,
    "issue": Defect.ISSUE_MISMATCH,
}

LOG_SCOPE = (
    "structural only: each claimed verification must point to a complete invocation record "
    "(request, response_sha256, retrieved_at); this does not show that any citation is correct"
)
RESOLVER_SCOPE = (
    "what a resolver answered for each cited DOI, from the frozen capture, and live only where enabled and the "
    "capture has no usable record; this does not show that a work supports the claim it is cited for"
)
COMPARISON_RULES: Mapping[str, str] = {
    "reference": (
        "only the work the cited DOI reached (DOI_RESOLVED or DOI_TARGET_MISMATCH) is compared; "
        "replacement candidates are listed for review and never used as ground truth"
    ),
    "doi": "exact, after removing resolver prefixes and folding ASCII case",
    "title": "NFKC, casefolded, punctuation turned into spaces, whitespace collapsed",
    "authors": (
        "family names normalized like titles; a different set is AUTHOR_MISMATCH, the same set in another order "
        "is AUTHOR_ORDER_MISMATCH; given names are compared by first initial when either side is abbreviated, "
        "and not compared when either side omits them"
    ),
    "year": "exact",
    "journal, volume, issue": "normalized like titles, and compared only when both sides give them",
    "conflation": (
        "CONFLATED_ENTRY when the citation's DOI, title and author set each match some resolved record, "
        "but no single record matches every one of them that matches any"
    ),
}


# ---------------------------------------------------------------------------
# Outcome helpers
# ---------------------------------------------------------------------------


def _not_applicable(reason: Reason, detail: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    """Nothing to examine: never PASS, and zero rows is the true count."""
    return CheckOutcome(
        ExecutionState.NOT_APPLICABLE, Status.ABSTAIN, reason, rows_examined=0, evidence=evidence, diagnostics=(detail,)
    )


def _unreadable(document: Document, evidence: Mapping[str, Any]) -> CheckOutcome:
    """A declared document that is missing, refused, empty or unparseable: evidence is missing, not wrong."""
    reason = Reason.PROTOCOL_BROKEN if document.state is InputState.PARSE_ERROR else Reason.INSUFFICIENT_EVIDENCE
    detail = document.diagnostic or f"state {document.state}"
    return CheckOutcome(
        ExecutionState.SKIPPED,
        Status.ABSTAIN,
        reason,
        rows_examined=0,
        evidence=evidence,
        diagnostics=(f"{document.role} ({document.path}) unavailable: {detail}",),
    )


def _malformed(document: Document, problem: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    return CheckOutcome(
        ExecutionState.SKIPPED,
        Status.ABSTAIN,
        Reason.PROTOCOL_BROKEN,
        rows_examined=0,
        evidence=evidence,
        diagnostics=(f"MALFORMED_DOCUMENT: {document.role} ({document.path}): {problem}",),
    )


def _refuse_params_and_inputs(spec: CheckSpec, source: str) -> None:
    """These checks read role documents; accepting inputs or params would misstate what they examined."""
    if spec.params:
        raise CheckParamError(f"UNKNOWN_PARAM: {spec.kind} accepts no params, got {sorted(spec.params)}")
    if spec.inputs:
        raise CheckParamError(f"UNEXPECTED_INPUTS: {spec.kind} reads the manifest's {source} and takes no inputs")


def _listed(items: Sequence[Any]) -> list[Any]:
    """At most :data:`~science_gate.verifier.MAX_LISTED` items; callers always give the full count too."""
    return list(items[:MAX_LISTED])


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Citation:
    """One citation as written. ``work.doi`` is in comparison form."""

    citation_id: str
    work: Work


def parse_entries(document: Any) -> tuple[Citation, ...]:
    """Validate a citations document (``science-gate-citations/v1``).

    Every citation needs an identifier, a valid DOI, a title and at least one
    author. Raises :class:`~science_gate.adapters.records.RecordFormatError`.
    """
    top = require_object(document, "citations document", ENTRIES_KEYS, ENTRIES_KEYS)
    if top["schema"] != ENTRIES_SCHEMA:
        raise RecordFormatError(f"schema must be {ENTRIES_SCHEMA!r}, got {top['schema']!r}")
    if not isinstance(top["citations"], list):
        raise RecordFormatError("citations must be a list")
    citations: list[Citation] = []
    seen: set[str] = set()
    for index, item in enumerate(top["citations"]):
        where = f"citations[{index}]"
        work = parse_work(item, where, extra_keys=("citation_id",))
        citation_id = item.get("citation_id")
        if not isinstance(citation_id, str) or not IDENTIFIER_PATTERN.fullmatch(citation_id):
            raise RecordFormatError(f"{where}.citation_id must match {IDENTIFIER_PATTERN.pattern}")
        if citation_id in seen:
            raise RecordFormatError(f"{where}.citation_id {citation_id!r} is used twice")
        seen.add(citation_id)
        citations.append(Citation(citation_id, work))
    return tuple(citations)


@dataclass(frozen=True)
class _Invocation:
    """One invocation record from a verification log.

    ``problems`` names each evidence field that is missing or malformed. An
    invocation with problems backs no claim: without a request, a response
    digest and a time, there is nothing to show that anything was checked.
    """

    invocation_id: str
    citation_id: str
    problems: tuple[str, ...]


@dataclass(frozen=True)
class _Log:
    claimed_verified: int
    verifier: Mapping[str, str]
    entries: tuple[tuple[str, str], ...]
    invocations: tuple[_Invocation, ...] | None


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_utc(value: Any) -> bool:
    try:
        parse_utc(value)
    except ClockError:
        return False
    return True


_INVOCATION_EVIDENCE: Mapping[str, Callable[[Any], bool]] = {
    "request": _is_text,
    "response_sha256": is_sha256,
    "retrieved_at": _is_utc,
}


def _text_field(item: Mapping[str, Any], name: str, where: str) -> str:
    value = item.get(name)
    if not _is_text(value):
        raise RecordFormatError(f"{where}.{name} must be a non-empty string")
    return value


def _parse_invocation(value: Any, where: str) -> _Invocation:
    item = require_object(value, where, INVOCATION_KEYS, ("invocation_id", "citation_id"))
    problems = tuple(
        f"MISSING_FIELD: {name}" if item.get(name) is None else f"INVALID_FIELD: {name}"
        for name, valid in _INVOCATION_EVIDENCE.items()
        if item.get(name) is None or not valid(item[name])
    )
    return _Invocation(
        _text_field(item, "invocation_id", where), _text_field(item, "citation_id", where), problems
    )


def _parse_log(document: Any) -> _Log:
    """Validate a verification log in the contract's format."""
    top = require_object(document, "verification log", LOG_KEYS, LOG_REQUIRED_KEYS)
    if "schema" in top and top["schema"] != LOG_SCHEMA:
        raise RecordFormatError(f"schema must be {LOG_SCHEMA!r} when given, got {top['schema']!r}")
    claimed = top["claimed_verified"]
    if isinstance(claimed, bool) or not isinstance(claimed, int) or claimed < 0:
        raise RecordFormatError("claimed_verified must be a non-negative integer")
    verifier = require_object(top["verifier"], "verifier", VERIFIER_KEYS, VERIFIER_KEYS)
    for name in VERIFIER_KEYS:
        _text_field(verifier, name, "verifier")
    if not isinstance(top["entries"], list):
        raise RecordFormatError("entries must be a list")
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, value in enumerate(top["entries"]):
        where = f"entries[{index}]"
        item = require_object(value, where, LOG_ENTRY_KEYS, LOG_ENTRY_KEYS)
        citation_id = _text_field(item, "citation_id", where)
        if item["claimed_status"] not in CLAIMED_STATUSES:
            raise RecordFormatError(f"{where}.claimed_status must be one of {list(CLAIMED_STATUSES)}")
        if citation_id in seen:
            raise RecordFormatError(f"{where}.citation_id {citation_id!r} is logged twice")
        seen.add(citation_id)
        entries.append((citation_id, item["claimed_status"]))
    invocations: tuple[_Invocation, ...] | None = None
    if top.get("invocations") is not None:
        if not isinstance(top["invocations"], list):
            raise RecordFormatError("invocations must be a list")
        invocations = tuple(
            _parse_invocation(value, f"invocations[{index}]") for index, value in enumerate(top["invocations"])
        )
        ids = Counter(invocation.invocation_id for invocation in invocations)
        repeated = sorted(invocation_id for invocation_id, count in ids.items() if count > 1)
        if repeated:
            raise RecordFormatError(f"invocation_id(s) {repeated} are used more than once")
    return _Log(claimed, {name: verifier[name] for name in VERIFIER_KEYS}, tuple(entries), invocations)


# ---------------------------------------------------------------------------
# Layer 1: verification_log
# ---------------------------------------------------------------------------


def _invocation_summary(log: _Log) -> dict[str, Any]:
    if log.invocations is None:
        return {
            "state": "NOT_RECORDED",
            "detail": "the log has no invocations list: no invocation record exists (unknown, not zero)",
            "total": None,
            "complete": None,
        }
    logged = {citation_id for citation_id, _ in log.entries}
    incomplete = [
        {"invocation_id": item.invocation_id, "citation_id": item.citation_id, "problems": list(item.problems)}
        for item in log.invocations
        if item.problems
    ]
    unmatched = [item.invocation_id for item in log.invocations if item.citation_id not in logged]
    return {
        "state": "RECORDED",
        "total": len(log.invocations),
        "complete": len(log.invocations) - len(incomplete),
        "incomplete_count": len(incomplete),
        "incomplete": _listed(incomplete),
        "without_log_entry_count": len(unmatched),
        "without_log_entry": _listed(unmatched),
    }


def _log_coverage(ctx: CheckContext, logged: Sequence[str], findings: Findings) -> dict[str, Any]:
    """Compare the logged citation ids with the bibliography, when one is declared.

    A declared bibliography that cannot be read is missing evidence (ABSTAIN):
    it must not quietly shrink the check's scope. With none declared, coverage
    is reported as not assessed.
    """
    document = ctx.role_document("citations.entries")
    if not document.declared:
        return {"state": "NOT_ASSESSED", "detail": "the manifest declares no citations.entries to compare the log with"}
    problem = document.diagnostic
    citations: tuple[Citation, ...] | None = None
    if document.loaded:
        try:
            citations = parse_entries(document.content)
        except RecordFormatError as exc:
            problem = f"MALFORMED_DOCUMENT: {exc}"
    if citations is None:
        findings.abstain(
            Reason.INSUFFICIENT_EVIDENCE,
            f"COVERAGE_UNAVAILABLE: citations.entries ({document.path}) could not be used: {problem}",
        )
        return {"state": "UNAVAILABLE", "entries": document.to_dict(), "detail": problem}
    bibliography = [citation.citation_id for citation in citations]
    logged_ids, known_ids = set(logged), set(bibliography)
    missing = [citation_id for citation_id in bibliography if citation_id not in logged_ids]
    unknown = [citation_id for citation_id in logged if citation_id not in known_ids]
    if missing:
        findings.abstain(
            Reason.INSUFFICIENT_EVIDENCE,
            f"NOT_IN_LOG: {len(missing)} citation(s) of citations.entries are not in the log: {_listed(missing)}",
            FailureMode.OMITTED_POPULATION,
        )
    if unknown:
        findings.abstain(
            Reason.PROTOCOL_BROKEN,
            f"UNKNOWN_CITATION: the log names {len(unknown)} citation(s) that citations.entries does not list: "
            f"{_listed(unknown)}",
            FailureMode.PROTOCOL_DRIFT,
        )
    return {
        "state": "ASSESSED",
        "entries": document.to_dict(),
        "bibliography_citations": len(bibliography),
        "not_in_log_count": len(missing),
        "not_in_log": _listed(missing),
        "unknown_count": len(unknown),
        "unknown": _listed(unknown),
    }


def check_verification_log(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 1: every claimed verification must point to a complete invocation record.

    A citation claimed VERIFIED with no complete record is UNVERIFIED with
    NARRATED_VERIFICATION, and so is a ``claimed_verified`` headline larger
    than the entries claimed VERIFIED. Both counts are also reported as
    claim tallies, so ``claimed_verified`` greater than the invocations
    breaks the ``checked_claims_le_invocations`` invariant. A citation the
    log does not claim is UNVERIFIED without being narrated. The check is
    structural: a PASS says the claims are backed by records, not that any
    citation is right.
    """
    _refuse_params_and_inputs(spec, "citations.log document")
    document = ctx.role_document("citations.log")
    evidence: dict[str, Any] = {"log": document.to_dict(), "scope": LOG_SCOPE}
    if not document.declared:
        return _not_applicable(Reason.OUT_OF_SCOPE, "the manifest declares no citations.log", evidence)
    if not document.loaded:
        return _unreadable(document, evidence)
    try:
        log = _parse_log(document.content)
    except RecordFormatError as exc:
        return _malformed(document, str(exc), evidence)
    if not log.entries and not log.claimed_verified:
        return _not_applicable(
            Reason.INSUFFICIENT_EVIDENCE, "the log itemizes no citation and claims no verification", evidence
        )

    backing: dict[str, list[str]] = {}
    for invocation in log.invocations or ():
        if not invocation.problems:
            backing.setdefault(invocation.citation_id, []).append(invocation.invocation_id)
    outcomes: dict[str, str] = {}
    for citation_id, claimed_status in log.entries:
        if claimed_status != CLAIMED_VERIFIED:
            outcomes[citation_id] = NOT_CLAIMED
        else:
            outcomes[citation_id] = BACKED if citation_id in backing else NARRATED
    by_outcome = {
        name: [citation_id for citation_id, outcome in outcomes.items() if outcome == name]
        for name in (BACKED, NARRATED, NOT_CLAIMED)
    }
    itemized_verified = len(by_outcome[BACKED]) + len(by_outcome[NARRATED])

    findings = Findings()
    if by_outcome[NARRATED]:
        findings.abstain(
            Reason.UNVERIFIED,
            f"NARRATED_VERIFICATION: {len(by_outcome[NARRATED])} citation(s) claimed VERIFIED with no complete "
            f"invocation record: {_listed(by_outcome[NARRATED])}",
            FailureMode.NARRATED_VERIFICATION,
        )
    if log.claimed_verified > itemized_verified:
        findings.abstain(
            Reason.UNVERIFIED,
            f"NARRATED_VERIFICATION: claimed_verified={log.claimed_verified} but only {itemized_verified} "
            "entries are claimed VERIFIED",
            FailureMode.NARRATED_VERIFICATION,
        )
    elif log.claimed_verified < itemized_verified:
        findings.abstain(
            Reason.PROTOCOL_BROKEN,
            f"INCONSISTENT_LOG: claimed_verified={log.claimed_verified} but {itemized_verified} entries are "
            "claimed VERIFIED",
            FailureMode.DEFECTIVE_VERIFICATION,
        )
    if by_outcome[NOT_CLAIMED]:
        findings.abstain(
            Reason.UNVERIFIED,
            f"NOT_CLAIMED: the log does not claim {len(by_outcome[NOT_CLAIMED])} citation(s) as verified: "
            f"{_listed(by_outcome[NOT_CLAIMED])}",
        )
    coverage = _log_coverage(ctx, [citation_id for citation_id, _ in log.entries], findings)

    # None (no invocation list at all) stays None: an absent record is never a zero count.
    recorded = None if log.invocations is None else sum(1 for item in log.invocations if not item.problems)
    backed = None if log.invocations is None else len(by_outcome[BACKED])
    tallies = (
        ClaimTally(f"{spec.check_id}: claimed_verified vs complete invocation records", log.claimed_verified, recorded),
        ClaimTally(f"{spec.check_id}: entries claimed VERIFIED vs entries with a record", itemized_verified, backed),
    )
    evidence.update(
        {
            "verifier": dict(log.verifier),
            "claimed_verified": log.claimed_verified,
            "entries_itemized": len(log.entries),
            "entries_claimed_verified": itemized_verified,
            "invocation_records": _invocation_summary(log),
            "outcomes": {name: len(ids) for name, ids in by_outcome.items()},
            "backed": [{"citation_id": cid, "invocation_ids": backing[cid]} for cid in by_outcome[BACKED]],
            "narrated": _listed(by_outcome[NARRATED]),
            "not_claimed": _listed(by_outcome[NOT_CLAIMED]),
            "coverage": coverage,
        }
    )
    return findings.outcome(rows_examined=len(log.entries), evidence=evidence, claim_tallies=tallies)


# ---------------------------------------------------------------------------
# Resolution shared by layers 2 and 3
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Prepared:
    """The citations and the frozen set a resolver or metadata check works from."""

    citations: tuple[Citation, ...]
    frozen: FrozenRecordSet | None
    frozen_unavailable: str
    evidence: dict[str, Any]


def _prepare(ctx: CheckContext) -> _Prepared | CheckOutcome:
    """Load the citations and the frozen set, or return the outcome that ends the check early."""
    entries = ctx.role_document("citations.entries")
    evidence: dict[str, Any] = {"entries": entries.to_dict()}
    if not entries.declared:
        return _not_applicable(Reason.OUT_OF_SCOPE, "the manifest declares no citations.entries", evidence)
    if not entries.loaded:
        return _unreadable(entries, evidence)
    try:
        citations = parse_entries(entries.content)
    except RecordFormatError as exc:
        return _malformed(entries, str(exc), evidence)
    if not citations:
        return _not_applicable(Reason.INSUFFICIENT_EVIDENCE, "citations.entries lists no citation", evidence)
    frozen_document = ctx.role_document("citations.frozen")
    evidence.update({"frozen": frozen_document.to_dict(), "network": ctx.network.to_dict()})
    frozen: FrozenRecordSet | None = None
    unavailable = "NO_FROZEN_SET: the manifest declares no citations.frozen"
    if frozen_document.loaded:
        try:
            frozen = frozen_adapter.parse_frozen(frozen_document.content)
        except RecordFormatError as exc:
            return _malformed(frozen_document, str(exc), evidence)
    elif frozen_document.declared:
        unavailable = f"FROZEN_SET_UNAVAILABLE: {frozen_document.diagnostic or frozen_document.state}"
    return _Prepared(citations, frozen, unavailable, evidence)


#: Live answers of each run, keyed by its check context and then by DOI. The
#: resolver and metadata layers must judge the same response, and a DOI is
#: fetched at most once per run. The entry disappears with the context.
_LIVE_ANSWERS: weakref.WeakKeyDictionary[CheckContext, dict[str, Resolution]] = weakref.WeakKeyDictionary()


def _resolve(ctx: CheckContext, prepared: _Prepared) -> dict[str, Resolution]:
    """One answer per cited DOI: the frozen record, else (only when live) the live resolver."""
    answers: dict[str, Resolution] = {}
    for citation in prepared.citations:
        doi = citation.work.doi
        if doi in answers:
            continue
        answer = frozen_adapter.resolve(doi, prepared.frozen, prepared.frozen_unavailable)
        if answer.state is ResolverState.SOURCE_UNAVAILABLE and ctx.network.live:
            live_answers = _LIVE_ANSWERS.setdefault(ctx, {})
            if doi not in live_answers:
                keep_body = ctx.manifest.corpus.permissions.redistribution_allowed
                live_answers[doi] = live_adapter.resolve(doi, ctx.network, keep_body=keep_body)
            live_answer = live_answers[doi]
            answer = dataclasses.replace(live_answer, diagnostics=(*answer.diagnostics, *live_answer.diagnostics))
        answers[doi] = answer
    return answers


# ---------------------------------------------------------------------------
# Layer 2: citation_resolver
# ---------------------------------------------------------------------------


def check_resolver(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 2: each cited DOI must resolve, in the frozen capture, to the work it names.

    DOI_TARGET_MISMATCH (the resolver returned a work with another DOI) and
    DOI_NOT_RESOLVED_AT_CAPTURE (a captured NOT_FOUND answer) are FAIL with
    SOURCE_MISMATCH. SOURCE_UNAVAILABLE (no usable record, or a live lookup
    that failed) is ABSTAIN. Each DOI's evidence carries all six provenance
    fields, so every resolution can be traced to what was asked and when.
    """
    _refuse_params_and_inputs(spec, "citations.entries and citations.frozen documents")
    prepared = _prepare(ctx)
    if isinstance(prepared, CheckOutcome):
        return prepared
    answers = _resolve(ctx, prepared)
    cited_as: dict[str, list[str]] = {}
    for citation in prepared.citations:
        cited_as.setdefault(citation.work.doi, []).append(citation.citation_id)
    findings = Findings()
    for doi, citation_ids in cited_as.items():
        answer = answers[doi]
        label = f"{doi} (cited as {', '.join(citation_ids)})"
        if answer.state is ResolverState.DOI_TARGET_MISMATCH and answer.work is not None:
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"DOI_TARGET_MISMATCH: {label} reached the work {answer.work.doi}",
                FailureMode.SOURCE_MISMATCH,
            )
        elif answer.state is ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE:
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"DOI_NOT_RESOLVED_AT_CAPTURE: {label} did not resolve when captured at "
                f"{answer.provenance['retrieved_at']}",
                FailureMode.SOURCE_MISMATCH,
            )
        elif answer.state is ResolverState.SOURCE_UNAVAILABLE:
            findings.abstain(
                Reason.SOURCE_UNAVAILABLE, f"SOURCE_UNAVAILABLE: {label}: {'; '.join(answer.diagnostics)}"
            )
    # Every examined DOI has exactly one state, so a zero total here is a real count.
    totals = Counter(answer.state for answer in answers.values())
    evidence = {
        **prepared.evidence,
        "scope": RESOLVER_SCOPE,
        "dois_examined": len(cited_as),
        "state_totals": {state.value: totals.get(state, 0) for state in ResolverState},
        "resolutions": [{**answers[doi].to_dict(), "citation_ids": ids} for doi, ids in cited_as.items()],
    }
    return findings.outcome(rows_examined=len(prepared.citations), evidence=evidence)


# ---------------------------------------------------------------------------
# Layer 3: citation_metadata
# ---------------------------------------------------------------------------


def normalize_text(value: str) -> str:
    """Comparison form of free text: NFKC, casefolded, punctuation as spaces, whitespace collapsed.

    "Grid-Free  Methods." and "grid free methods" compare equal; a changed
    word never does.
    """
    folded = unicodedata.normalize("NFKC", value).casefold()
    spaced = "".join(" " if unicodedata.category(char).startswith("P") else char for char in folded)
    return " ".join(spaced.split())


def _families(authors: Sequence[Author]) -> list[str]:
    return [normalize_text(author.family) for author in authors]


def _abbreviated(given: str) -> bool:
    return all(len(token) == 1 for token in given.split())


def _given_compatible(cited: str | None, recorded: str | None) -> bool:
    """Given names agree when they are equal, or share a first initial where either is abbreviated.

    An omitted given name cannot contradict anything, so it is not compared.
    """
    left, right = normalize_text(cited or ""), normalize_text(recorded or "")
    if not left or not right:
        return True
    if _abbreviated(left) or _abbreviated(right):
        return left[0] == right[0]
    return left == right


def _compare_authors(cited: Sequence[Author], recorded: Sequence[Author]) -> dict[str, Any]:
    shown = {"cited": [author.display() for author in cited], "recorded": [author.display() for author in recorded]}
    cited_families, recorded_families = _families(cited), _families(recorded)
    if sorted(cited_families) != sorted(recorded_families):
        return {"outcome": MISMATCH, **shown}
    if cited_families != recorded_families:
        return {"outcome": ORDER_DIFFERS, **shown}
    positions = [
        position
        for position, (left, right) in enumerate(zip(cited, recorded), start=1)
        if not _given_compatible(left.given, right.given)
    ]
    if positions:
        return {"outcome": MISMATCH, "given_name_positions": positions, **shown}
    return {"outcome": MATCH}


def _compare_value(cited: str | None, recorded: str | None, same: Callable[[str, str], bool]) -> dict[str, Any]:
    if cited is None:
        return {"outcome": NOT_CITED}
    if recorded is None:
        return {"outcome": NOT_IN_RECORD}
    if same(cited, recorded):
        return {"outcome": MATCH}
    return {"outcome": MISMATCH, "cited": cited, "recorded": recorded}


def _exact(left: str, right: str) -> bool:
    return left == right


def _normalized(left: str, right: str) -> bool:
    return normalize_text(left) == normalize_text(right)


def _compare_fields(cited: Work, recorded: Work) -> tuple[dict[str, dict[str, Any]], set[Defect]]:
    """Compare every field; return the per-field outcomes and the defects they imply."""
    fields = {
        "doi": _compare_value(cited.doi, recorded.doi, _exact),
        "title": _compare_value(cited.title, recorded.title, _normalized),
        "authors": _compare_authors(cited.authors, recorded.authors),
        "year": _compare_value(cited.year, recorded.year, _exact),
        "journal": _compare_value(cited.journal, recorded.journal, _normalized),
        "volume": _compare_value(cited.volume, recorded.volume, _normalized),
        "issue": _compare_value(cited.issue, recorded.issue, _normalized),
    }
    defects = {defect for name, defect in _FIELD_DEFECTS.items() if fields[name]["outcome"] == MISMATCH}
    if fields["authors"]["outcome"] == MISMATCH:
        defects.add(Defect.AUTHOR_MISMATCH)
    elif fields["authors"]["outcome"] == ORDER_DIFFERS:
        defects.add(Defect.AUTHOR_ORDER_MISMATCH)
    return fields, defects


def _identity_matches(cited: Work, pool: Sequence[Work]) -> dict[str, list[str]]:
    """Which reference works the citation's identifying fields match, by field.

    Only the DOI, the title and the author set identify a work. Year,
    journal, volume and issue are shared by many works, so a coincidence
    there says nothing about which work was meant.
    """
    title, families = normalize_text(cited.title), sorted(_families(cited.authors))
    matches = {
        "doi": [work.doi for work in pool if work.doi == cited.doi],
        "title": [work.doi for work in pool if normalize_text(work.title) == title],
        "authors": [work.doi for work in pool if sorted(_families(work.authors)) == families],
    }
    return {name: dois for name, dois in matches.items() if dois}


def _conflation(matches: Mapping[str, list[str]]) -> dict[str, list[str]] | None:
    """The field-to-work matches when no single work explains all of them, else None."""
    if len(matches) < 2:
        return None
    if set.intersection(*(set(dois) for dois in matches.values())):
        return None
    return dict(matches)


@dataclass(frozen=True)
class _Assessment:
    """The metadata outcome of one citation."""

    citation: Citation
    answer: Resolution
    primary: str
    defects: tuple[Defect, ...]
    fields: Mapping[str, Mapping[str, Any]]
    conflation: Mapping[str, list[str]] | None
    candidates: tuple[Mapping[str, Any], ...]

    @property
    def compared(self) -> bool:
        return self.answer.work is not None

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "citation_id": self.citation.citation_id,
            "doi": self.citation.work.doi,
            "resolver_state": self.answer.state.value,
            "reference": None
            if self.answer.work is None
            else {"doi": self.answer.work.doi, "source": self.answer.source},
            "primary_disposition": self.primary,
            "defects": [defect.value for defect in self.defects],
            "fields": dict(self.fields),
            "fields_not_compared": sorted(
                name for name, item in self.fields.items() if item["outcome"] in (NOT_CITED, NOT_IN_RECORD)
            ),
            "conflation": None if self.conflation is None else dict(self.conflation),
        }
        if self.candidates:
            document["replacement_candidates"] = list(self.candidates)
            document["replacement_candidates_note"] = "listed for human review; never used as ground truth"
        return document


def _assess(citation: Citation, answer: Resolution, pool: Sequence[Work]) -> _Assessment:
    """Give one citation its primary disposition and its (possibly overlapping) defects.

    Precedence: CONFLATED_ENTRY, then (with no reference record)
    RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES or SOURCE_UNAVAILABLE, then
    FIELD_MISMATCH, then VERIFIED_WITHIN_DECLARED_SCOPE.
    """
    fields: dict[str, dict[str, Any]] = {}
    defects: set[Defect] = set()
    if answer.work is not None:
        fields, defects = _compare_fields(citation.work, answer.work)
    matches = _identity_matches(citation.work, pool)
    conflation = _conflation(matches)
    candidates: tuple[Mapping[str, Any], ...] = ()
    if conflation is not None:
        defects.add(Defect.CONFLATED_ENTRY)
        primary = MetadataState.CONFLATED_ENTRY.value
    elif answer.work is None:
        primary = (
            MetadataState.RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES.value
            if answer.state is ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE
            else SOURCE_UNAVAILABLE_DISPOSITION
        )
    elif defects:
        primary = MetadataState.FIELD_MISMATCH.value
    else:
        primary = MetadataState.VERIFIED_WITHIN_DECLARED_SCOPE.value
    if answer.work is None:
        resembling = sorted(set(matches.get("title", ())) | set(matches.get("authors", ())))
        candidates = tuple(
            {"doi": doi, "matched_fields": [name for name in ("title", "authors") if doi in matches.get(name, ())]}
            for doi in resembling
        )
    ordered = tuple(defect for defect in Defect if defect in defects)
    return _Assessment(citation, answer, primary, ordered, fields, conflation, candidates)


def _reference_pool(frozen: FrozenRecordSet | None, answers: Mapping[str, Resolution]) -> tuple[Work, ...]:
    """Every work a usable resolver answer returned, one per work DOI, sorted by DOI."""
    works = {work.doi: work for work in (frozen.resolved_works() if frozen is not None else ())}
    for doi in sorted(answers):
        answer = answers[doi]
        if answer.source == SOURCE_LIVE and answer.work is not None:
            works.setdefault(answer.work.doi, answer.work)
    return tuple(works[doi] for doi in sorted(works))


def check_metadata(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 3: the cited metadata must match the work the cited DOI reached.

    CONFLATED_ENTRY and FIELD_MISMATCH are FAIL with SOURCE_MISMATCH.
    RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES and SOURCE_UNAVAILABLE are
    ABSTAIN: with no reference record, the metadata was not compared, so
    nothing about it is known. Disposition totals are mutually exclusive;
    defect totals are not.
    """
    _refuse_params_and_inputs(spec, "citations.entries and citations.frozen documents")
    prepared = _prepare(ctx)
    if isinstance(prepared, CheckOutcome):
        return prepared
    answers = _resolve(ctx, prepared)
    pool = _reference_pool(prepared.frozen, answers)
    findings = Findings()
    assessments = [_assess(citation, answers[citation.work.doi], pool) for citation in prepared.citations]
    for item in assessments:
        label = f"citation {item.citation.citation_id} ({item.citation.work.doi})"
        if item.primary in (MetadataState.CONFLATED_ENTRY.value, MetadataState.FIELD_MISMATCH.value):
            defects = ", ".join(defect.value for defect in item.defects)
            findings.fail(Reason.SOURCE_MISMATCH, f"{item.primary}: {label}: {defects}", FailureMode.SOURCE_MISMATCH)
        elif item.primary == MetadataState.RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES.value:
            findings.abstain(
                Reason.INSUFFICIENT_EVIDENCE,
                f"{item.primary}: {label}: the recorded queries found no record, so its metadata was not compared",
            )
        elif item.primary == SOURCE_UNAVAILABLE_DISPOSITION:
            findings.abstain(
                Reason.SOURCE_UNAVAILABLE,
                f"SOURCE_UNAVAILABLE: {label}: no reference record could be obtained, so its metadata was not compared",
            )
    dispositions = Counter(item.primary for item in assessments)
    defect_counts = Counter(defect for item in assessments for defect in item.defects)
    not_compared = [item.citation.citation_id for item in assessments if not item.compared]
    evidence = {
        **prepared.evidence,
        "rules": dict(COMPARISON_RULES),
        "reference_pool": [work.doi for work in pool],
        "citations": [item.to_dict() for item in assessments],
        "disposition_totals": {name: dispositions.get(name, 0) for name in DISPOSITIONS},
        "defect_totals": {defect.value: defect_counts.get(defect, 0) for defect in Defect},
        "defect_totals_scope": (
            f"field defects cover the {len(assessments) - len(not_compared)} of {len(assessments)} citation(s) "
            "compared with a reference record; CONFLATED_ENTRY covers all; a citation can carry several defects"
        ),
        "not_compared": not_compared,
    }
    return findings.outcome(rows_examined=len(assessments), evidence=evidence)
