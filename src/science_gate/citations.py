"""Citation checks in three layers, plus editorial status (ARCHITECTURE.md sections 9 and 17.14).

Each layer answers a narrower question than the one after it. None of them
establishes that a cited work supports the claim it is cited for:

1. ``verification_log`` (structural, fully offline). Does every verification
   a log *claims* point to a complete, possible invocation record? A claim
   with no record is narrated, not shown: UNVERIFIED with
   NARRATED_VERIFICATION. So is a record retrieved before the cited DOI was
   registered: nothing can be verified before it exists. The claimed counts
   are also reported as :class:`~science_gate.invariants.ClaimTally` values,
   so the run-level ``checked_claims_le_invocations`` invariant sees them.
2. ``citation_resolver``. What did a resolver answer for each cited DOI? The
   answer comes from the frozen capture; live lookups happen only when live
   access is enabled, and only for DOIs the capture cannot answer. Absence
   is SOURCE_UNAVAILABLE, never "not found". Every positive answer needs a
   negative control (extension #8): a canary DOI under the same prefix that
   must not resolve. A resolver that resolves its canary vouches for
   nothing, so every DOI under that prefix becomes SOURCE_UNAVAILABLE.
3. ``citation_metadata``. Does the cited metadata match the work the DOI
   actually reached? Every citation gets exactly one ``primary_disposition``
   and a list of ``defects``, which may overlap. A replacement candidate
   (another record that resembles the citation) is listed for a person to
   review and is never used as ground truth.

``editorial_status`` (extension #10) asks what named editorial channels
recorded about each cited work: retractions, reinstatements, corrections and
expressions of concern. "Not retracted" is only ever a scoped statement over
at least two named channels; an aggregator's flag is never a channel.

The documents, each read through the check context so that its digest enters
the evidence manifest:

* ``citations.entries`` (``science-gate-citations/v1``): the citations as written.
* ``citations.log``: an external verifier's log, in the contract's format.
* ``citations.frozen`` (``science-gate-citations-frozen/v1``): captured resolver answers and canaries.

Two design points matter for reproducibility. A DOI with a usable frozen
record is always answered from that record, even under ``--live``, so a live
run is still a replay wherever a capture exists. And each DOI (and each live
canary) is looked up at most once per run, falsifier overlays included, so
every layer and every negative control judges the same answer.

Each check here also has a falsifier generator (section 17.5): a known-bad
variant of exactly the evidence it just passed, and the rejection that
variant must provoke. A PASS that cannot be shown to reject it is never a
PASS.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
import unicodedata
import weakref
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from ._canonical import canonical_bytes, normalize, sha256_canonical
from ._clock import parse_utc
from .adapters import frozen as frozen_adapter
from .adapters import live as live_adapter
from .adapters.frozen import FROZEN_SCHEMA, NOT_FOUND, FrozenRecordSet
from .adapters.records import (
    HANDLE_NOT_FOUND,
    PROVENANCE_FIELDS,
    SOURCE_FROZEN,
    SOURCE_LIVE,
    Author,
    CanaryCheck,
    RecordFormatError,
    Resolution,
    Work,
    doi_prefix,
    is_sha256,
    is_utc,
    normalize_doi,
    parse_work,
    require_object,
)
from .invariants import ClaimTally
from .manifests import IDENTIFIER_PATTERN, CheckSpec, Manifest
from .models import (
    SKIP_JUSTIFICATION_KEY,
    CheckResult,
    EditorialChannel,
    EditorialStatus,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    InputOverride,
    InputState,
    MetadataState,
    NoticeType,
    Reason,
    ResolverState,
    SkipJustification,
    Status,
)
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
    "SNAPSHOT_KEYS",
    "NOTICE_KEYS",
    "DEFECT_WINDOW_KEYS",
    "EDITORIAL_PARAMS",
    "MIN_EDITORIAL_CHANNELS",
    "Defect",
    "SOURCE_UNAVAILABLE_DISPOSITION",
    "DISPOSITIONS",
    "Citation",
    "Notice",
    "ChannelSnapshot",
    "DefectWindow",
    "EditorialAssessment",
    "parse_entries",
    "parse_snapshots",
    "parse_defect_windows",
    "decide_editorial_status",
    "assess_editorial",
    "normalize_text",
    "check_verification_log",
    "check_resolver",
    "check_metadata",
    "check_editorial_status",
    "falsify_verification_log",
    "falsify_resolver",
    "falsify_metadata",
    "falsify_editorial_status",
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

#: The editorial-status input: one JSON array of channel snapshots, each
#: carrying the notices it holds for the DOIs it was consulted about.
SNAPSHOT_KEYS = ("source", "snapshot_sha256", "captured_at", "consulted_dois", "notices")
NOTICE_KEYS = ("doi", "type", "date", "notice_id")
DEFECT_WINDOW_KEYS = ("source", "start", "end")
EDITORIAL_PARAMS = ("defect_windows",)

#: "Not retracted" is a statement over at least this many distinct named channels.
MIN_EDITORIAL_CHANNELS = 2

#: Assessment of one snapshot for one cited DOI.
COUNTED, DOWNGRADED, IGNORED = "COUNTED", "DOWNGRADED", "IGNORED"

_CHANNELS = frozenset(channel.value for channel in EditorialChannel)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


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
    "(request, response_sha256, retrieved_at) that is possible; this does not show that any citation is correct"
)
TIMELINE_RULE = (
    "an invocation retrieved before the cited DOI's registration (registered_at in its frozen record) cannot have "
    "verified it, so it backs no claim; invocations whose DOI has no recorded registration are not judged"
)
RESOLVER_SCOPE = (
    "what a resolver answered for each cited DOI, from the frozen capture, and live only where enabled and the "
    "capture has no usable record; this does not show that a work supports the claim it is cited for"
)
CANARY_RULE = (
    "every prefix the capture answered needs a frozen canary record, and every prefix with a live DOI_RESOLVED "
    "answer needs a live canary <prefix>/science-gate-canary-<sha256(run_id)[:12]>; a canary holds only with body "
    "responseCode 100; a canary that resolves is a proven miss (FAIL / BLIND_SPOT) and every DOI under its prefix "
    "is SOURCE_UNAVAILABLE; a missing or unconfirmed canary leaves coverage unknown (ABSTAIN / BLIND_SPOT)"
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
EDITORIAL_SCOPE = (
    "what named editorial channels recorded about each cited DOI, from snapshots identified by digest (recorded as "
    "declared, never re-fetched); NOT_RETRACTED_WITHIN_SCOPE says only that at least two named channels recorded "
    "no retraction; this does not show that a work is sound"
)
EDITORIAL_RULES: Mapping[str, str] = {
    "channels": (
        "a channel is a snapshot whose source is "
        + ", ".join(sorted(_CHANNELS))
        + " and that consulted the DOI; the scoped statement counts distinct sources; any other source (an "
        "aggregator's retraction flag, for example) is ignored and never counted"
    ),
    "ordering": (
        "notices are ordered by date; the latest RETRACTION or REINSTATEMENT decides, and a reinstatement "
        "supersedes a retraction only when it is dated strictly later"
    ),
    "fallback": (
        "without either, EXPRESSION_OF_CONCERN, then CORRECTED, then NOT_RETRACTED_WITHIN_SCOPE with at least "
        f"{MIN_EDITORIAL_CHANNELS} channels, otherwise UNDETERMINED"
    ),
    "defect_windows": (
        "a snapshot captured inside a declared defect window for its source is downgraded: it is not a channel and "
        "its notices do not decide, but a notice it holds for a cited DOI needs human review"
    ),
}


# ---------------------------------------------------------------------------
# Outcome helpers
# ---------------------------------------------------------------------------


def _skip(
    state: ExecutionState,
    reason: Reason,
    justification: SkipJustification,
    detail: str,
    evidence: Mapping[str, Any],
    *modes: FailureMode,
) -> CheckOutcome:
    """A check that examined nothing: never PASS, zero rows, and a closed-vocabulary label (section 17.7).

    The label travels in the evidence, so it is hashed with it; without one
    an unexecuted required check would be an unexplained shortfall (D1).
    """
    return CheckOutcome(
        state,
        Status.ABSTAIN,
        reason,
        failure_modes=modes,
        rows_examined=0,
        evidence={**evidence, SKIP_JUSTIFICATION_KEY: justification.value},
        diagnostics=(detail,),
    )


def _not_applicable(
    reason: Reason, detail: str, evidence: Mapping[str, Any], justification: SkipJustification
) -> CheckOutcome:
    """Nothing to examine: never PASS, and zero rows is the true count."""
    return _skip(ExecutionState.NOT_APPLICABLE, reason, justification, detail, evidence)


def _unreadable(document: Document, evidence: Mapping[str, Any]) -> CheckOutcome:
    """A declared document that is missing, refused, empty or unparseable: evidence is missing, not wrong."""
    malformed = document.state is InputState.PARSE_ERROR
    reason = Reason.PROTOCOL_BROKEN if malformed else Reason.INSUFFICIENT_EVIDENCE
    justification = SkipJustification.EVIDENCE_MALFORMED if malformed else SkipJustification.INPUT_UNAVAILABLE
    detail = document.diagnostic or f"state {document.state}"
    return _skip(
        ExecutionState.SKIPPED,
        reason,
        justification,
        f"{document.role} ({document.path}) unavailable: {detail}",
        evidence,
    )


def _malformed(document: Document, problem: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    return _skip(
        ExecutionState.SKIPPED,
        Reason.PROTOCOL_BROKEN,
        SkipJustification.EVIDENCE_MALFORMED,
        f"MALFORMED_DOCUMENT: {document.role} ({document.path}): {problem}",
        evidence,
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


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _text_field(item: Mapping[str, Any], name: str, where: str) -> str:
    value = item.get(name)
    if not _is_text(value):
        raise RecordFormatError(f"{where}.{name} must be a non-empty string")
    return value


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


def _cited_dois(citations: Sequence[Citation]) -> dict[str, list[str]]:
    """Each cited DOI once, in citation order, with the citation ids that cite it."""
    cited_as: dict[str, list[str]] = {}
    for citation in citations:
        cited_as.setdefault(citation.work.doi, []).append(citation.citation_id)
    return cited_as


@dataclass(frozen=True)
class _Invocation:
    """One invocation record from a verification log.

    ``problems`` names each evidence field that is missing or malformed. An
    invocation with problems backs no claim: without a request, a response
    digest and a time, there is nothing to show that anything was checked.
    ``retrieved_at`` is the recorded time, valid whenever ``problems`` is empty.
    """

    invocation_id: str
    citation_id: str
    retrieved_at: Any
    problems: tuple[str, ...]


@dataclass(frozen=True)
class _Log:
    claimed_verified: int
    verifier: Mapping[str, str]
    entries: tuple[tuple[str, str], ...]
    invocations: tuple[_Invocation, ...] | None


_INVOCATION_EVIDENCE: Mapping[str, Callable[[Any], bool]] = {
    "request": _is_text,
    "response_sha256": is_sha256,
    "retrieved_at": is_utc,
}


def _parse_invocation(value: Any, where: str) -> _Invocation:
    item = require_object(value, where, INVOCATION_KEYS, ("invocation_id", "citation_id"))
    problems = tuple(
        f"MISSING_FIELD: {name}" if item.get(name) is None else f"INVALID_FIELD: {name}"
        for name, valid in _INVOCATION_EVIDENCE.items()
        if item.get(name) is None or not valid(item[name])
    )
    return _Invocation(
        _text_field(item, "invocation_id", where),
        _text_field(item, "citation_id", where),
        item.get("retrieved_at"),
        problems,
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


def _invocation_summary(log: _Log, impossible: int) -> dict[str, Any]:
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
        "impossible_timeline_count": impossible,
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


@dataclass(frozen=True)
class _Registrations:
    """When each cited DOI was registered, as the frozen capture states it (extension #8).

    ``state`` is ASSESSED when both the bibliography and the capture could be
    read, NOT_ASSESSED when either is undeclared, and UNAVAILABLE when either
    is unusable. ``by_citation`` maps a citation id to its DOI and the
    registration time (None when the capture does not state one).
    """

    state: str
    detail: str | None
    by_citation: Mapping[str, tuple[str, str | None]] = field(default_factory=dict)


def _registrations(ctx: CheckContext) -> _Registrations:
    entries, frozen = ctx.role_document("citations.entries"), ctx.role_document("citations.frozen")
    undeclared = [document.role for document in (entries, frozen) if not document.declared]
    if undeclared:
        return _Registrations("NOT_ASSESSED", f"the manifest declares no {' or '.join(undeclared)}")
    for document in (entries, frozen):
        if not document.loaded:
            problem = document.diagnostic or f"state {document.state}"
            return _Registrations("UNAVAILABLE", f"{document.role} ({document.path}): {problem}")
    try:
        citations = parse_entries(entries.content)
        captured = frozen_adapter.parse_frozen(frozen.content)
    except RecordFormatError as exc:
        return _Registrations("UNAVAILABLE", f"MALFORMED_DOCUMENT: {exc}")
    return _Registrations(
        "ASSESSED",
        None,
        {item.citation_id: (item.work.doi, captured.registration(item.work.doi)) for item in citations},
    )


def _impossible_timelines(log: _Log, registrations: _Registrations) -> tuple[list[dict[str, Any]], int, int]:
    """Complete invocations retrieved before their DOI was registered, plus how many were judged and not."""
    impossible: list[dict[str, Any]] = []
    judged = unknown = 0
    for item in log.invocations or ():
        if item.problems:
            continue
        doi, registered = registrations.by_citation.get(item.citation_id, (None, None))
        if registered is None:
            unknown += 1
            continue
        judged += 1
        if parse_utc(item.retrieved_at) < parse_utc(registered):
            impossible.append(
                {
                    "invocation_id": item.invocation_id,
                    "citation_id": item.citation_id,
                    "doi": doi,
                    "retrieved_at": item.retrieved_at,
                    "registered_at": registered,
                }
            )
    return impossible, judged, unknown


def check_verification_log(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 1: every claimed verification must point to a complete, possible invocation record.

    A citation claimed VERIFIED with no complete record is UNVERIFIED with
    NARRATED_VERIFICATION, and so is a ``claimed_verified`` headline larger
    than the entries claimed VERIFIED. An invocation retrieved before the
    DOI's registration (an impossible timeline, extension #8) backs nothing,
    and is itself reported with both timestamps. Both counts are also
    reported as claim tallies, so ``claimed_verified`` greater than the
    invocations breaks the ``checked_claims_le_invocations`` invariant. A
    citation the log does not claim is UNVERIFIED without being narrated.
    The check is structural: a PASS says the claims are backed by records,
    not that any citation is right.
    """
    _refuse_params_and_inputs(spec, "citations.log document")
    document = ctx.role_document("citations.log")
    evidence: dict[str, Any] = {"log": document.to_dict(), "scope": LOG_SCOPE}
    if not document.declared:
        return _not_applicable(
            Reason.OUT_OF_SCOPE, "the manifest declares no citations.log", evidence, SkipJustification.NOT_DECLARED
        )
    if not document.loaded:
        return _unreadable(document, evidence)
    try:
        log = _parse_log(document.content)
    except RecordFormatError as exc:
        return _malformed(document, str(exc), evidence)
    if not log.entries and not log.claimed_verified:
        return _not_applicable(
            Reason.INSUFFICIENT_EVIDENCE,
            "the log itemizes no citation and claims no verification",
            evidence,
            SkipJustification.EMPTY_POPULATION,
        )

    registrations = _registrations(ctx)
    impossible, judged, unknown = _impossible_timelines(log, registrations)
    impossible_ids = {item["invocation_id"] for item in impossible}
    backing: dict[str, list[str]] = {}
    for invocation in log.invocations or ():
        if not invocation.problems and invocation.invocation_id not in impossible_ids:
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
    for item in impossible:
        findings.abstain(
            Reason.UNVERIFIED,
            f"IMPOSSIBLE_TIMELINE: invocation {item['invocation_id']} for {item['citation_id']} ({item['doi']}) was "
            f"retrieved at {item['retrieved_at']}, before the DOI was registered at {item['registered_at']}",
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
    recorded = None if log.invocations is None else sum(len(ids) for ids in backing.values())
    backed = None if log.invocations is None else len(by_outcome[BACKED])
    tallies = (
        ClaimTally(f"{spec.check_id}: claimed_verified vs complete invocation records", log.claimed_verified, recorded),
        ClaimTally(f"{spec.check_id}: entries claimed VERIFIED vs entries with a record", itemized_verified, backed),
    )
    assessed = registrations.state == "ASSESSED"
    evidence.update(
        {
            "verifier": dict(log.verifier),
            "claimed_verified": log.claimed_verified,
            "entries_itemized": len(log.entries),
            "entries_claimed_verified": itemized_verified,
            "invocation_records": _invocation_summary(log, len(impossible)),
            "outcomes": {name: len(ids) for name, ids in by_outcome.items()},
            "backed": [{"citation_id": cid, "invocation_ids": backing[cid]} for cid in by_outcome[BACKED]],
            "narrated": _listed(by_outcome[NARRATED]),
            "not_claimed": _listed(by_outcome[NOT_CLAIMED]),
            "coverage": coverage,
            "timeline": {
                "state": registrations.state,
                "detail": registrations.detail,
                "rule": TIMELINE_RULE,
                "invocations_judged": judged if assessed else None,
                "registration_unknown": unknown if assessed else None,
                "impossible_count": len(impossible) if assessed else None,
                "impossible": _listed(impossible),
            },
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
        return _not_applicable(
            Reason.OUT_OF_SCOPE, "the manifest declares no citations.entries", evidence, SkipJustification.NOT_DECLARED
        )
    if not entries.loaded:
        return _unreadable(entries, evidence)
    try:
        citations = parse_entries(entries.content)
    except RecordFormatError as exc:
        return _malformed(entries, str(exc), evidence)
    if not citations:
        return _not_applicable(
            Reason.INSUFFICIENT_EVIDENCE,
            "citations.entries lists no citation",
            evidence,
            SkipJustification.EMPTY_POPULATION,
        )
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


@dataclass
class _LiveRun:
    """What one run asked the network: one answer per DOI, one canary per prefix."""

    answers: dict[str, Resolution] = field(default_factory=dict)
    canaries: dict[str, CanaryCheck] = field(default_factory=dict)


#: Live lookups of each run, keyed by the identity of the run's manifest
#: object. The resolver and metadata layers, and every falsifier overlay of
#: the run (which shares that object), must judge the same responses, and a
#: DOI is fetched at most once per run. A new run loads a new manifest, so
#: it asks again; the entry disappears with the manifest.
_LIVE_RUNS: dict[int, _LiveRun] = {}


def _live_run(manifest: Manifest) -> _LiveRun:
    key = id(manifest)
    run = _LIVE_RUNS.get(key)
    if run is None:
        run = _LIVE_RUNS[key] = _LiveRun()
        weakref.finalize(manifest, _LIVE_RUNS.pop, key, None)
    return run


@dataclass(frozen=True)
class _Resolved:
    """One answer per cited DOI, and the negative controls that vouch for them.

    ``canaries`` holds the frozen controls (one per prefix the capture
    answered); ``live_canaries`` the live ones (one per prefix with a live
    DOI_RESOLVED answer). Answers under a prefix whose canary resolved are
    already SOURCE_UNAVAILABLE here, so both layers see the same downgrade.
    """

    answers: Mapping[str, Resolution]
    canaries: Mapping[str, CanaryCheck]
    live_canaries: Mapping[str, CanaryCheck]

    def controls(self) -> tuple[CanaryCheck, ...]:
        """Every control consulted: frozen ones by prefix, then live ones by prefix."""
        return (
            *(self.canaries[prefix] for prefix in sorted(self.canaries)),
            *(self.live_canaries[prefix] for prefix in sorted(self.live_canaries)),
        )

    @property
    def distrusted(self) -> frozenset[str]:
        """Prefixes whose canary resolved: no answer under them can be trusted."""
        return frozenset(check.prefix for check in self.controls() if check.resolved)


def _distrust(answer: Resolution, canary: CanaryCheck) -> Resolution:
    """The answer for a DOI under a prefix whose canary resolved: SOURCE_UNAVAILABLE, never DOI_RESOLVED."""
    detail = (
        f"CANARY_RESOLVED: the {canary.source} canary {canary.doi} for prefix {canary.prefix} maps to "
        f"{canary.state.value}, so no {answer.state.value} answer under that prefix can be trusted"
    )
    return Resolution(
        doi=answer.doi,
        state=ResolverState.SOURCE_UNAVAILABLE,
        source=answer.source,
        provenance=answer.provenance,
        http_status=answer.http_status,
        handle_response_code=answer.handle_response_code,
        diagnostics=(*answer.diagnostics, detail),
        body=answer.body,
    )


def _resolve(ctx: CheckContext, prepared: _Prepared) -> _Resolved:
    """Answer every cited DOI and run the negative controls those answers need.

    The frozen record answers first; only when live access is on and the
    capture has no usable record is the live resolver asked. A prefix the
    capture answered needs the capture's canary; a prefix with a live
    positive needs a live canary, asked only then (a canary vouches for
    positives, so a run whose live lookups all fail makes no extra call).
    """
    live = _live_run(ctx.manifest) if ctx.network.live else None
    answers: dict[str, Resolution] = {}
    for doi in _cited_dois(prepared.citations):
        answer = frozen_adapter.resolve(doi, prepared.frozen, prepared.frozen_unavailable)
        if answer.state is ResolverState.SOURCE_UNAVAILABLE and live is not None:
            if doi not in live.answers:
                keep_body = ctx.manifest.corpus.permissions.redistribution_allowed
                live.answers[doi] = live_adapter.resolve(doi, ctx.network, keep_body=keep_body)
            fetched = live.answers[doi]
            answer = dataclasses.replace(fetched, diagnostics=(*answer.diagnostics, *fetched.diagnostics))
        answers[doi] = answer
    captured = sorted({doi_prefix(doi) for doi, answer in answers.items() if answer.source == SOURCE_FROZEN})
    canaries = {prefix: frozen_adapter.canary_check(prefix, prepared.frozen) for prefix in captured}
    live_canaries: dict[str, CanaryCheck] = {}
    if live is not None:
        positives = sorted(
            {
                doi_prefix(doi)
                for doi, answer in answers.items()
                if answer.source == SOURCE_LIVE and answer.state is ResolverState.DOI_RESOLVED
            }
        )
        for prefix in positives:
            if prefix not in live.canaries:
                live.canaries[prefix] = live_adapter.canary_check(prefix, ctx.run_id, ctx.network)
            live_canaries[prefix] = live.canaries[prefix]
    resolved = _Resolved(answers, canaries, live_canaries)
    distrusted = {check.prefix: check for check in resolved.controls() if check.resolved}
    if not distrusted:
        return resolved
    downgraded = {
        doi: _distrust(answer, distrusted[doi_prefix(doi)]) if doi_prefix(doi) in distrusted else answer
        for doi, answer in answers.items()
    }
    return _Resolved(downgraded, canaries, live_canaries)


# ---------------------------------------------------------------------------
# Layer 2: citation_resolver
# ---------------------------------------------------------------------------


def _canary_findings(resolved: _Resolved, cited: Iterable[str], findings: Findings) -> None:
    """A proven miss FAILs with BLIND_SPOT; a missing or unconfirmed control ABSTAINs with BLIND_SPOT (D2)."""
    dois = list(cited)
    for check in resolved.controls():
        label = f"{check.source} canary for prefix {check.prefix}" if check.doi else f"canary for prefix {check.prefix}"
        if check.resolved:
            under = [doi for doi in dois if doi_prefix(doi) == check.prefix]
            findings.fail(
                Reason.BLIND_SPOT,
                f"CANARY_RESOLVED: the {label} ({check.doi}) maps to {check.state.value}: a resolver that resolves "
                f"a DOI that cannot exist vouches for nothing, so the {len(under)} cited DOI(s) under "
                f"{check.prefix} are reported SOURCE_UNAVAILABLE",
                FailureMode.VACUOUS_PASS,
            )
        elif not check.holds:
            findings.abstain(
                Reason.BLIND_SPOT,
                f"CANARY_NOT_HELD: the {label} does not hold ({check.detail}); the positive answers under "
                f"{check.prefix} have no negative control",
                FailureMode.VACUOUS_PASS,
            )


def check_resolver(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 2: each cited DOI must resolve, in the frozen capture, to the work it names.

    DOI_TARGET_MISMATCH (the resolver returned a work with another DOI) and
    DOI_NOT_RESOLVED_AT_CAPTURE (a captured NOT_FOUND answer, or a Handle
    body code 100 or 200) are FAIL with SOURCE_MISMATCH. SOURCE_UNAVAILABLE
    (no usable record, a live lookup that failed, a capture older than the
    DOI's registration) is ABSTAIN. Every prefix needs a holding canary
    (:data:`CANARY_RULE`): one that resolved is FAIL / BLIND_SPOT and makes
    every DOI under it SOURCE_UNAVAILABLE; one missing is ABSTAIN /
    BLIND_SPOT. Each DOI's evidence carries all six provenance fields, so
    every resolution can be traced to what was asked and when.
    """
    _refuse_params_and_inputs(spec, "citations.entries and citations.frozen documents")
    prepared = _prepare(ctx)
    if isinstance(prepared, CheckOutcome):
        return prepared
    resolved = _resolve(ctx, prepared)
    answers = resolved.answers
    cited_as = _cited_dois(prepared.citations)
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
    _canary_findings(resolved, cited_as, findings)
    # Every examined DOI has exactly one state, so a zero total here is a real count.
    totals = Counter(answer.state for answer in answers.values())
    evidence = {
        **prepared.evidence,
        "scope": RESOLVER_SCOPE,
        "dois_examined": len(cited_as),
        "state_totals": {state.value: totals.get(state, 0) for state in ResolverState},
        "resolutions": [{**answers[doi].to_dict(), "citation_ids": ids} for doi, ids in cited_as.items()],
        "canary_rule": CANARY_RULE,
        "canaries": {prefix: check.to_dict() for prefix, check in sorted(resolved.canaries.items())},
        "live_canaries": {prefix: check.to_dict() for prefix, check in sorted(resolved.live_canaries.items())},
        "distrusted_prefixes": sorted(resolved.distrusted),
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


def _reference_pool(
    frozen: FrozenRecordSet | None, answers: Mapping[str, Resolution], distrusted: frozenset[str]
) -> tuple[Work, ...]:
    """Every work a trusted resolver answer returned, one per work DOI, sorted by DOI.

    Works under a prefix whose canary resolved are left out: a resolver that
    answers for DOIs that cannot exist could have invented them.
    """
    captured = frozen.resolved_works() if frozen is not None else ()
    works = {work.doi: work for work in captured if doi_prefix(work.doi) not in distrusted}
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
    defect totals are not. Answers come from the same resolution as the
    resolver layer, canary downgrades included.
    """
    _refuse_params_and_inputs(spec, "citations.entries and citations.frozen documents")
    prepared = _prepare(ctx)
    if isinstance(prepared, CheckOutcome):
        return prepared
    resolved = _resolve(ctx, prepared)
    answers = resolved.answers
    pool = _reference_pool(prepared.frozen, answers, resolved.distrusted)
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
        "distrusted_prefixes": sorted(resolved.distrusted),
    }
    return findings.outcome(rows_examined=len(assessments), evidence=evidence)


# ---------------------------------------------------------------------------
# Editorial status (extension #10)
# ---------------------------------------------------------------------------


def _calendar_date(value: Any, where: str) -> str:
    """A ``YYYY-MM-DD`` calendar date; ISO dates order correctly as text, so the text is kept."""
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError(f"{where} must be a YYYY-MM-DD date")
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{where} {value!r} is not a real date") from None
    return value


@dataclass(frozen=True)
class Notice:
    """One dated editorial notice for one DOI, as a snapshot recorded it."""

    doi: str
    kind: NoticeType
    date: str
    notice_id: str

    def to_dict(self, snapshot: ChannelSnapshot) -> dict[str, Any]:
        """The notice with the identity of the snapshot that holds it."""
        return {
            "type": self.kind.value,
            "date": self.date,
            "notice_id": self.notice_id,
            "source": snapshot.source,
            "snapshot_sha256": snapshot.snapshot_sha256,
        }


@dataclass(frozen=True)
class ChannelSnapshot:
    """What one source recorded at one capture, identified by the snapshot's digest.

    The digest identifies the external snapshot (a channel's export, say);
    it is recorded as declared, because the snapshot itself is not shipped.
    """

    source: str
    snapshot_sha256: str
    captured_at: str
    consulted: tuple[str, ...]
    notices: tuple[Notice, ...]

    @property
    def is_channel(self) -> bool:
        return self.source in _CHANNELS

    def identity(self) -> dict[str, str]:
        return {"source": self.source, "snapshot_sha256": self.snapshot_sha256}

    def notices_for(self, doi: str) -> tuple[Notice, ...]:
        return tuple(notice for notice in self.notices if notice.doi == doi)

    def window(self, windows: Sequence[DefectWindow]) -> DefectWindow | None:
        """The first declared defect window for this snapshot's source that contains its capture."""
        return next((item for item in windows if item.source == self.source and item.contains(self.captured_at)), None)

    def role(self, windows: Sequence[DefectWindow]) -> str:
        """COUNTED (a channel), DOWNGRADED (a channel captured inside a defect window) or IGNORED (no channel)."""
        if not self.is_channel:
            return IGNORED
        return COUNTED if self.window(windows) is None else DOWNGRADED


@dataclass(frozen=True)
class DefectWindow:
    """A declared period in which a source is known to have published defective editorial data."""

    source: str
    start: str
    end: str

    def contains(self, captured_at: str) -> bool:
        """True when the capture's UTC calendar date falls inside the window, both ends included."""
        return self.start <= captured_at[:10] <= self.end

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "start": self.start, "end": self.end}


def _parse_notice(value: Any, where: str, consulted: set[str], captured_on: str) -> Notice:
    item = require_object(value, where, NOTICE_KEYS, NOTICE_KEYS)
    doi = normalize_doi(item["doi"])
    if doi is None:
        raise RecordFormatError(f"{where}.doi {item['doi']!r} is not a DOI")
    if doi not in consulted:
        raise RecordFormatError(f"{where} is a notice for {doi}, which the snapshot did not consult")
    try:
        notice_type = NoticeType(item["type"])
    except ValueError:
        raise RecordFormatError(f"{where}.type must be one of {[kind.value for kind in NoticeType]}") from None
    try:
        dated = _calendar_date(item["date"], f"{where}.date")
    except ValueError as exc:
        raise RecordFormatError(str(exc)) from None
    if dated > captured_on:
        raise RecordFormatError(f"{where} is dated {dated}, after its snapshot was captured ({captured_on})")
    return Notice(doi, notice_type, dated, _text_field(item, "notice_id", where))


def _parse_snapshot(value: Any, where: str) -> ChannelSnapshot:
    item = require_object(value, where, SNAPSHOT_KEYS, SNAPSHOT_KEYS)
    source = _text_field(item, "source", where)
    if not is_sha256(item["snapshot_sha256"]):
        raise RecordFormatError(f"{where}.snapshot_sha256 must be a lowercase SHA-256 hex digest")
    if not is_utc(item["captured_at"]):
        raise RecordFormatError(f"{where}.captured_at must be ISO-8601 UTC with a Z suffix")
    if not isinstance(item["consulted_dois"], list) or not isinstance(item["notices"], list):
        raise RecordFormatError(f"{where}.consulted_dois and {where}.notices must be lists")
    consulted: list[str] = []
    for index, raw in enumerate(item["consulted_dois"]):
        doi = normalize_doi(raw)
        if doi is None:
            raise RecordFormatError(f"{where}.consulted_dois[{index}] {raw!r} is not a DOI")
        if doi in consulted:
            raise RecordFormatError(f"{where}.consulted_dois lists {doi} twice")
        consulted.append(doi)
    captured_on = item["captured_at"][:10]
    notices = tuple(
        _parse_notice(raw, f"{where}.notices[{index}]", set(consulted), captured_on)
        for index, raw in enumerate(item["notices"])
    )
    repeated = sorted(name for name, count in Counter(notice.notice_id for notice in notices).items() if count > 1)
    if repeated:
        raise RecordFormatError(f"{where} repeats notice_id(s) {repeated}")
    return ChannelSnapshot(source, item["snapshot_sha256"], item["captured_at"], tuple(consulted), notices)


def parse_snapshots(records: Sequence[Any]) -> tuple[ChannelSnapshot, ...]:
    """Validate the editorial input's records: one channel snapshot each.

    Unknown keys, malformed DOIs or dates, a notice for a DOI the snapshot
    did not consult, a notice dated after its capture, and one snapshot
    listed twice are all refused: each would let the input claim more than
    it recorded. Raises :class:`~science_gate.adapters.records.RecordFormatError`.
    """
    snapshots = tuple(_parse_snapshot(value, f"records[{index}]") for index, value in enumerate(records))
    identities = Counter((item.source, item.snapshot_sha256) for item in snapshots)
    repeated = sorted(f"{source}:{digest[:12]}" for (source, digest), count in identities.items() if count > 1)
    if repeated:
        raise RecordFormatError(f"snapshot(s) {repeated} are listed more than once")
    return snapshots


def parse_defect_windows(spec: CheckSpec) -> tuple[DefectWindow, ...]:
    """The check's ``defect_windows`` param. Unknown params and malformed windows are refused (ERROR)."""
    unknown = sorted(set(spec.params) - set(EDITORIAL_PARAMS))
    if unknown:
        raise CheckParamError(f"UNKNOWN_PARAM: {spec.kind} accepts only {list(EDITORIAL_PARAMS)}, got {unknown}")
    raw = spec.params.get("defect_windows", [])
    if not isinstance(raw, (list, tuple)):
        raise CheckParamError("INVALID_PARAM: defect_windows must be a list of {source, start, end}")
    windows: list[DefectWindow] = []
    for index, value in enumerate(raw):
        where = f"defect_windows[{index}]"
        try:
            item = require_object(value, where, DEFECT_WINDOW_KEYS, DEFECT_WINDOW_KEYS)
            window = DefectWindow(
                _text_field(item, "source", where),
                _calendar_date(item["start"], f"{where}.start"),
                _calendar_date(item["end"], f"{where}.end"),
            )
        except ValueError as exc:  # RecordFormatError is a ValueError
            raise CheckParamError(f"INVALID_PARAM: {exc}") from None
        if window.start > window.end:
            raise CheckParamError(f"INVALID_PARAM: {where} ends before it starts")
        windows.append(window)
    return tuple(windows)


#: Tie-break order for notices on the same date, so evidence order never depends on input order.
_NOTICE_ORDER: Mapping[NoticeType, int] = {kind: rank for rank, kind in enumerate(NoticeType)}


def decide_editorial_status(notices: Sequence[Notice], channel_sources: int) -> EditorialStatus:
    """The editorial status that counted notices and the number of distinct channels support.

    The latest RETRACTION or REINSTATEMENT decides, and a reinstatement
    supersedes only when dated strictly later: on the same date nothing shows
    which came last, so the retraction stands. Without either, an expression
    of concern outranks a correction. "Not retracted" needs at least
    :data:`MIN_EDITORIAL_CHANNELS` channels; with fewer, nothing can be said.
    """
    retracted = [notice.date for notice in notices if notice.kind is NoticeType.RETRACTION]
    reinstated = [notice.date for notice in notices if notice.kind is NoticeType.REINSTATEMENT]
    if retracted or reinstated:
        if reinstated and (not retracted or max(reinstated) > max(retracted)):
            return EditorialStatus.REINSTATED
        return EditorialStatus.RETRACTED
    kinds = {notice.kind for notice in notices}
    if NoticeType.EXPRESSION_OF_CONCERN in kinds:
        return EditorialStatus.EXPRESSION_OF_CONCERN
    if NoticeType.CORRECTION in kinds:
        return EditorialStatus.CORRECTED
    if channel_sources >= MIN_EDITORIAL_CHANNELS:
        return EditorialStatus.NOT_RETRACTED_WITHIN_SCOPE
    return EditorialStatus.UNDETERMINED


@dataclass(frozen=True)
class EditorialAssessment:
    """The editorial status of one cited DOI, with every snapshot that bore on it."""

    doi: str
    citation_ids: tuple[str, ...]
    status: EditorialStatus
    channels: tuple[ChannelSnapshot, ...]
    notices: tuple[tuple[Notice, ChannelSnapshot], ...]
    downgraded: tuple[tuple[ChannelSnapshot, DefectWindow], ...]

    @property
    def sources(self) -> tuple[str, ...]:
        """Distinct channel sources; two snapshots of one source are still one channel."""
        return tuple(sorted({snapshot.source for snapshot in self.channels}))

    @property
    def downgraded_notices(self) -> tuple[tuple[Notice, ChannelSnapshot], ...]:
        return tuple(
            (notice, snapshot) for snapshot, _ in self.downgraded for notice in snapshot.notices_for(self.doi)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "doi": self.doi,
            "citation_ids": list(self.citation_ids),
            "status": self.status.value,
            "channels": [snapshot.identity() for snapshot in self.channels],
            "channel_sources": list(self.sources),
            "notices": [notice.to_dict(snapshot) for notice, snapshot in self.notices],
            "downgraded": [
                {
                    **snapshot.identity(),
                    "captured_at": snapshot.captured_at,
                    "window": window.to_dict(),
                    "notices": [notice.to_dict(snapshot) for notice in snapshot.notices_for(self.doi)],
                }
                for snapshot, window in self.downgraded
            ],
        }


def assess_editorial(
    doi: str,
    citation_ids: Sequence[str],
    snapshots: Sequence[ChannelSnapshot],
    windows: Sequence[DefectWindow],
) -> EditorialAssessment:
    """Judge one DOI: its channels, the notices they count, and the snapshots a defect window downgrades.

    Only channel snapshots that consulted the DOI bear on it. Of those, one
    captured inside a defect window for its source is downgraded; the rest
    are its channels, and only their notices decide.
    """
    bearing = [snapshot for snapshot in snapshots if snapshot.is_channel and doi in snapshot.consulted]
    channels = [snapshot for snapshot in bearing if snapshot.role(windows) == COUNTED]
    downgraded = [
        (snapshot, window) for snapshot in bearing if (window := snapshot.window(windows)) is not None
    ]
    notices = sorted(
        ((notice, snapshot) for snapshot in channels for notice in snapshot.notices_for(doi)),
        key=lambda pair: (
            pair[0].date,
            _NOTICE_ORDER[pair[0].kind],
            pair[1].source,
            pair[1].snapshot_sha256,
            pair[0].notice_id,
        ),
    )
    sources = {snapshot.source for snapshot in channels}
    status = decide_editorial_status([notice for notice, _ in notices], len(sources))
    return EditorialAssessment(doi, tuple(citation_ids), status, tuple(channels), tuple(notices), tuple(downgraded))


def _editorial_input(ctx: CheckContext, spec: CheckSpec) -> str:
    """The one declared JSON input holding the channel snapshots; any other wiring is refused (ERROR)."""
    if len(spec.inputs) != 1:
        raise CheckParamError(
            f"INVALID_INPUTS: {spec.kind} takes exactly one declared JSON input of channel snapshots, "
            f"got {list(spec.inputs)}"
        )
    input_id = spec.inputs[0]
    opened = ctx.inputs.get(input_id)
    if opened is not None and opened.spec.format != "json":
        raise CheckParamError(
            f"INVALID_INPUTS: {spec.kind} reads a json input, and {input_id!r} is {opened.spec.format}"
        )
    return input_id


#: How an editorial input with nothing to examine is reported: reason, justification, failure modes.
#: Any state not listed (missing, refused, unreadable, unparseable) is INPUT_UNAVAILABLE.
_UNUSABLE_EDITORIAL_INPUT: Mapping[InputState, tuple[Reason, SkipJustification, tuple[FailureMode, ...]]] = (
    MappingProxyType(
        {
            InputState.EMPTY: (Reason.INSUFFICIENT_EVIDENCE, SkipJustification.EMPTY_POPULATION, ()),
            InputState.HASH_MISMATCH: (
                Reason.SOURCE_MISMATCH,
                SkipJustification.SOURCE_REJECTED,
                (FailureMode.SOURCE_MISMATCH,),
            ),
        }
    )
)
_INPUT_UNAVAILABLE = (
    Reason.INSUFFICIENT_EVIDENCE,
    SkipJustification.INPUT_UNAVAILABLE,
    (FailureMode.OMITTED_POPULATION,),
)


def _editorial_findings(assessments: Sequence[EditorialAssessment], findings: Findings) -> None:
    """Record findings by category, so the primary reason follows section 17.14's order."""
    for item in assessments:
        if item.status is EditorialStatus.RETRACTED:
            notice, snapshot = next(
                (notice, snapshot)
                for notice, snapshot in reversed(item.notices)
                if notice.kind is NoticeType.RETRACTION
            )
            findings.fail(
                Reason.SOURCE_MISMATCH,
                f"RETRACTED: {item.doi} (cited as {', '.join(item.citation_ids)}): RETRACTION {notice.notice_id} "
                f"dated {notice.date} in the {snapshot.source} snapshot {snapshot.snapshot_sha256[:12]}",
                FailureMode.SOURCE_MISMATCH,
            )
    for item in assessments:
        if item.status is EditorialStatus.EXPRESSION_OF_CONCERN:
            findings.abstain(
                Reason.REQUIRES_HUMAN_REVIEW,
                f"EXPRESSION_OF_CONCERN: {item.doi} (cited as {', '.join(item.citation_ids)}) carries an expression "
                "of concern",
            )
    for item in assessments:
        if item.downgraded_notices and item.status is not EditorialStatus.RETRACTED:
            names = ", ".join(f"{notice.kind.value} {notice.notice_id}" for notice, _ in item.downgraded_notices)
            findings.abstain(
                Reason.REQUIRES_HUMAN_REVIEW,
                f"DOWNGRADED_NOTICE: {item.doi} has notice(s) {names} only in snapshot(s) captured inside a declared "
                "defect window; they are not counted, and a declared window must not hide them",
            )
    for item in assessments:
        if item.status in (EditorialStatus.RETRACTED, EditorialStatus.EXPRESSION_OF_CONCERN):
            continue
        if len(item.sources) == 1:
            findings.abstain(
                Reason.INSUFFICIENT_EVIDENCE,
                f"SINGLE_CHANNEL: {item.doi} was consulted in one named channel ({item.sources[0]}); a scoped "
                f"statement needs at least {MIN_EDITORIAL_CHANNELS}",
            )
        elif not item.sources:
            findings.abstain(
                Reason.SOURCE_UNAVAILABLE,
                f"NO_CHANNEL: no named channel consulted {item.doi}; its editorial status is unknown",
            )


def check_editorial_status(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Editorial status of every cited DOI, scoped to named channels (extension #10).

    The input is one declared JSON array of channel snapshots
    (:data:`SNAPSHOT_KEYS`); cited DOIs come from ``citations.entries``;
    params may declare ``defect_windows``. FAIL / SOURCE_MISMATCH when any DOI
    is RETRACTED; ABSTAIN / REQUIRES_HUMAN_REVIEW on an expression of concern
    or a notice only a downgraded snapshot holds; ABSTAIN /
    INSUFFICIENT_EVIDENCE when a DOI has a single channel; ABSTAIN /
    SOURCE_UNAVAILABLE when it has none; PASS otherwise. A PASS is a scoped
    statement about named channels, never about the work's soundness.
    """
    windows = parse_defect_windows(spec)
    input_id = _editorial_input(ctx, spec)
    opened = ctx.inputs.get(input_id)
    entries = ctx.role_document("citations.entries")
    evidence: dict[str, Any] = {
        "scope": EDITORIAL_SCOPE,
        "rules": dict(EDITORIAL_RULES),
        "entries": entries.to_dict(),
        "defect_windows": [window.to_dict() for window in windows],
        "input": {
            "input_id": input_id,
            "state": None if opened is None else opened.state.value,
            "sha256": None if opened is None else opened.sha256,
        },
    }
    if not entries.declared:
        return _not_applicable(
            Reason.OUT_OF_SCOPE,
            "the manifest declares no citations.entries, so no DOI is cited",
            evidence,
            SkipJustification.NOT_DECLARED,
        )
    if not entries.loaded:
        return _unreadable(entries, evidence)
    try:
        citations = parse_entries(entries.content)
    except RecordFormatError as exc:
        return _malformed(entries, str(exc), evidence)
    if not citations:
        return _not_applicable(
            Reason.INSUFFICIENT_EVIDENCE,
            "citations.entries lists no citation",
            evidence,
            SkipJustification.EMPTY_POPULATION,
        )
    if opened is None or not opened.usable or not opened.rows:
        state = InputState.MISSING if opened is None else opened.state
        # A usable input with no admitted record (every row key blank, say) is an empty population too.
        key = InputState.EMPTY if opened is not None and opened.usable else state
        reason, justification, modes = _UNUSABLE_EDITORIAL_INPUT.get(key, _INPUT_UNAVAILABLE)
        return _skip(
            ExecutionState.NOT_APPLICABLE,
            reason,
            justification,
            f"input {input_id!r} is {state.value} with no admitted channel snapshot to examine",
            evidence,
            *modes,
        )
    findings = Findings()
    if opened.state is InputState.PARTIAL:
        counts = opened.record.counts
        findings.abstain(
            Reason.PARTIAL_EXECUTION,
            f"input {input_id!r} is PARTIAL: {counts.admitted} of {opened.record.rows} records admitted",
            FailureMode.PARTIAL_EXECUTION,
            FailureMode.OMITTED_POPULATION,
        )
    try:
        snapshots = parse_snapshots([row.values for row in opened.rows])
    except RecordFormatError as exc:
        return _skip(
            ExecutionState.SKIPPED,
            Reason.PROTOCOL_BROKEN,
            SkipJustification.EVIDENCE_MALFORMED,
            f"MALFORMED_INPUT: {input_id!r}: {exc}",
            evidence,
        )
    assessments = [
        assess_editorial(doi, citation_ids, snapshots, windows)
        for doi, citation_ids in _cited_dois(citations).items()
    ]
    _editorial_findings(assessments, findings)
    statuses = Counter(item.status for item in assessments)
    ignored = sorted({snapshot.source for snapshot in snapshots if not snapshot.is_channel})
    evidence.update(
        {
            "snapshots": [
                {
                    **snapshot.identity(),
                    "captured_at": snapshot.captured_at,
                    "role": snapshot.role(windows),
                    "consulted": len(snapshot.consulted),
                    "notices": len(snapshot.notices),
                }
                for snapshot in snapshots
            ],
            "ignored_sources": ignored,
            "dois_examined": len(assessments),
            "dois": [item.to_dict() for item in assessments],
            "status_counts": {status.value: statuses.get(status, 0) for status in EditorialStatus},
        }
    )
    return findings.outcome(rows_examined=len(snapshots), evidence=evidence)


# ---------------------------------------------------------------------------
# Falsifier generators (section 17.5)
# ---------------------------------------------------------------------------
#
# Each builds a known-bad variant of exactly the evidence its check just
# passed, and names the rejection the variant must provoke. They read only
# through ``ctx``, write nothing, and return () when this instance admits no
# known-bad case, which leaves the PASS unwitnessed (never a PASS).


def _plain(value: Any) -> Any:
    """A deep, JSON-safe copy of parsed content that a generator may edit."""
    return normalize(value)


def falsify_verification_log(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``drop-backing-invocations``: the first claimed VERIFIED entry left without any invocation must be UNVERIFIED."""
    document = ctx.role_document("citations.log")
    if not document.loaded or document.path is None:
        return ()
    try:
        log = _parse_log(document.content)
    except RecordFormatError:
        return ()
    recorded = {item.citation_id for item in log.invocations or () if not item.problems}
    target = next(
        (cid for cid, claimed in log.entries if claimed == CLAIMED_VERIFIED and cid in recorded),
        None,
    )
    if target is None:
        return ()
    content = _plain(document.content)
    content["invocations"] = [item for item in content["invocations"] if item.get("citation_id") != target]
    return (
        FalsifierCase(
            "drop-backing-invocations",
            f"every invocation recorded for {target}, the first citation claimed VERIFIED, removed from the log",
            Status.ABSTAIN,
            Reason.UNVERIFIED,
            documents={document.path: canonical_bytes(content)},
        ),
    )


def falsify_resolver(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``capture-not-found``: the first resolved DOI's record replaced by a captured NOT_FOUND must FAIL.

    The replacement keeps the original answer's provenance and adds body
    code 100, so it is a usable, definite "not found". A frozen record always
    answers before the live resolver, so this works for live answers too.
    """
    frozen_document = ctx.role_document("citations.frozen")
    prepared = _prepare(ctx)
    if not frozen_document.declared or frozen_document.path is None or isinstance(prepared, CheckOutcome):
        return ()
    answers = _resolve(ctx, prepared).answers
    target = next((answer for answer in answers.values() if answer.state is ResolverState.DOI_RESOLVED), None)
    if target is None:
        return ()
    replacement = {
        "doi": target.doi,
        "outcome": NOT_FOUND,
        "http_status": 404,
        "handle_response_code": HANDLE_NOT_FOUND,
        "work": None,
        **{name: target.provenance.get(name) for name in PROVENANCE_FIELDS},
    }
    records = _plain(frozen_document.content)["records"] if frozen_document.loaded else []
    position = next(
        (index for index, item in enumerate(records) if normalize_doi(item.get("doi")) == target.doi),
        None,
    )
    if position is None:
        records.append(replacement)
    else:
        records[position] = replacement
    return (
        FalsifierCase(
            "capture-not-found",
            f"the frozen answer for {target.doi}, the first resolved DOI, replaced by a captured NOT_FOUND",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            documents={frozen_document.path: canonical_bytes({"schema": FROZEN_SCHEMA, "records": records})},
        ),
    )


def falsify_metadata(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``replace-first-author``: the first citation's first author changed must be a FIELD_MISMATCH (FAIL)."""
    document = ctx.role_document("citations.entries")
    if not document.loaded or document.path is None:
        return ()
    try:
        citations = parse_entries(document.content)
    except RecordFormatError:
        return ()
    if not citations:
        return ()
    content = _plain(document.content)
    first_author = content["citations"][0]["authors"][0]
    original = first_author["family"]
    first_author["family"] = f"{original}-falsified"
    return (
        FalsifierCase(
            "replace-first-author",
            f"the first author of citation {citations[0].citation_id} renamed from {original!r}",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            documents={document.path: canonical_bytes(content)},
        ),
    )


def falsify_editorial_status(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """``add-retraction``: a RETRACTION notice for the first cited DOI must FAIL.

    The notice goes into the counted channel snapshot captured last and is
    dated on that capture's day. Every counted notice is dated no later than
    its own capture, so no reinstatement can be strictly later, and the
    retraction must decide.
    """
    entries = ctx.role_document("citations.entries")
    if len(spec.inputs) != 1 or not entries.loaded:
        return ()
    opened = ctx.inputs.get(spec.inputs[0])
    if opened is None or not opened.usable or not opened.rows:
        return ()
    try:
        citations = parse_entries(entries.content)
        windows = parse_defect_windows(spec)
        snapshots = parse_snapshots([row.values for row in opened.rows])
    except (RecordFormatError, CheckParamError):
        return ()
    if not citations:
        return ()
    doi = citations[0].work.doi
    counted = assess_editorial(doi, (citations[0].citation_id,), snapshots, windows).channels
    if not counted:
        return ()
    latest = max(counted, key=lambda snapshot: parse_utc(snapshot.captured_at))
    position = snapshots.index(latest)
    rows = [_plain(row.values) for row in opened.rows]
    notice_id = "falsifier-" + sha256_canonical({"doi": doi, "snapshot": latest.identity()})[:12]
    rows[position]["notices"].append(
        {"doi": doi, "type": NoticeType.RETRACTION.value, "date": latest.captured_at[:10], "notice_id": notice_id}
    )
    return (
        FalsifierCase(
            "add-retraction",
            f"a RETRACTION notice for {doi} added to the {latest.source} snapshot {latest.snapshot_sha256[:12]}",
            Status.FAIL,
            Reason.SOURCE_MISMATCH,
            inputs={opened.input_id: InputOverride(tuple(rows))},
        ),
    )
