"""Frozen resolver adapter: answers from a recorded response set, offline.

A frozen set (``science-gate-citations-frozen/v1``) is a capture of what a
resolver answered for each DOI, made once and then replayed. Replaying makes
citation results reproducible and keeps every default code path off the
network.

These rules decide what a frozen set may claim:

* **Provenance is per record.** A record missing any of the six provenance
  fields, or holding a malformed one, makes *that* DOI SOURCE_UNAVAILABLE.
  The other records still count.
* **Absence is not "not found".** A DOI the set has no record for is
  SOURCE_UNAVAILABLE. Only a record that captured a NOT_FOUND answer yields
  DOI_NOT_RESOLVED_AT_CAPTURE, and even that describes the capture, not the
  existence of the work.
* **Body codes decide** (section 17.14). When a record carries the Handle
  ``handle_response_code``, that code alone decides its state: 1 resolves,
  100 and 200 do not, anything else is no answer. The HTTP status never
  decides, because "values not found" arrives behind HTTP 200.
* **A capture cannot predate the work.** A record retrieved before the DOI's
  ``registered_at`` says nothing about it: SOURCE_UNAVAILABLE ("snapshot
  predates registration"), never "not found".
* **Positives need a negative control.** A record marked ``canary`` asks
  about ``<prefix>/science-gate-canary-<12 hex>``, a DOI that must not
  exist. It is captured with the set and vouches for the set's positive
  answers under its prefix (:func:`canary_check`). Canary records never
  serve as reference works.

Structural problems (unknown keys, a malformed work, two records for one DOI,
two canaries for one prefix) make the whole set unusable, and
:func:`parse_frozen` raises. Picking one of two conflicting captures would
mean choosing ground truth by position.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .._clock import parse_utc
from ..models import ResolverState
from .records import (
    HANDLE_NOT_FOUND,
    PROVENANCE_FIELDS,
    SOURCE_FROZEN,
    SOURCE_NONE,
    CanaryCheck,
    RecordFormatError,
    Resolution,
    Work,
    doi_prefix,
    is_canary_doi,
    is_utc,
    normalize_doi,
    parse_work,
    provenance_problems,
    require_object,
    state_for_handle_code,
)

__all__ = [
    "FROZEN_SCHEMA",
    "FROZEN_KEYS",
    "RECORD_KEYS",
    "OUTCOMES",
    "FrozenRecord",
    "FrozenRecordSet",
    "parse_frozen",
    "resolve",
    "canary_check",
]

FROZEN_SCHEMA = "science-gate-citations-frozen/v1"
FROZEN_KEYS = ("schema", "records")

#: What the resolver answered at capture time. ERROR means it failed to answer.
FOUND, NOT_FOUND, RESOLVER_ERROR = "FOUND", "NOT_FOUND", "ERROR"
OUTCOMES = (FOUND, NOT_FOUND, RESOLVER_ERROR)

RECORD_KEYS = (
    "doi",
    "outcome",
    "http_status",
    "handle_response_code",
    "canary",
    "registered_at",
    "work",
    *PROVENANCE_FIELDS,
)

_REFERENCE_STATES = (ResolverState.DOI_RESOLVED, ResolverState.DOI_TARGET_MISMATCH)


@dataclass(frozen=True)
class FrozenRecord:
    """One captured resolver answer, keyed by the DOI that was requested.

    ``control_problems`` lists every reason the record cannot be trusted at
    all: missing or malformed provenance, a malformed or impossible
    registration date, or (without a body code) an outcome that contradicts
    the rest of the record. :attr:`problems` adds what stops a trusted record
    from serving as a cited DOI's reference. A record with problems resolves
    to SOURCE_UNAVAILABLE.
    """

    doi: str
    outcome: str
    http_status: int | None
    work: Work | None
    provenance: Mapping[str, Any]
    control_problems: tuple[str, ...] = ()
    handle_response_code: int | None = None
    canary: bool = False
    registered_at: str | None = None
    provenance_complete: bool = True

    @property
    def decided_state(self) -> ResolverState:
        """The state the recorded facts give: the body code alone when present, else the outcome."""
        if self.handle_response_code is not None:
            state = state_for_handle_code(self.handle_response_code)
        elif self.outcome == FOUND:
            state = ResolverState.DOI_RESOLVED
        elif self.outcome == NOT_FOUND:
            state = ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE
        else:
            state = ResolverState.SOURCE_UNAVAILABLE
        if state is ResolverState.DOI_RESOLVED and self.work is not None and self.work.doi != self.doi:
            return ResolverState.DOI_TARGET_MISMATCH
        return state

    @property
    def problems(self) -> tuple[str, ...]:
        """Everything that stops this record from answering for its DOI.

        Body code 1 says the DOI resolves, but without a captured work there
        is nothing to compare a citation with, so the record cannot vouch.
        """
        if self.control_problems or self.decided_state not in _REFERENCE_STATES or self.work is not None:
            return self.control_problems
        return (
            f"NO_REFERENCE_WORK: body responseCode {self.handle_response_code} says the DOI resolves, "
            "but the capture kept no work to compare with",
        )

    @property
    def usable(self) -> bool:
        return not self.problems

    @property
    def registration(self) -> str | None:
        """The DOI's registration time as this record states it, when the record can be trusted to state it."""
        return self.registered_at if self.provenance_complete and is_utc(self.registered_at) else None

    def _code_note(self) -> tuple[str, ...]:
        """Say so when the body code overrode an outcome or HTTP status that disagreed with it."""
        if self.handle_response_code is None:
            return ()
        outcome_says = {FOUND: ResolverState.DOI_RESOLVED, NOT_FOUND: ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE}
        code_state = state_for_handle_code(self.handle_response_code)
        if outcome_says.get(self.outcome, ResolverState.SOURCE_UNAVAILABLE) is code_state:
            return ()
        return (
            f"HANDLE_CODE_DECIDES: body responseCode {self.handle_response_code} decides; the recorded outcome "
            f"{self.outcome} and HTTP status {self.http_status} are not used",
        )

    def resolution(self) -> Resolution:
        """This record's answer, with its state derived from the recorded facts only."""
        base = {
            "doi": self.doi,
            "source": SOURCE_FROZEN,
            "provenance": self.provenance,
            "http_status": self.http_status,
            "handle_response_code": self.handle_response_code,
        }
        if self.problems:
            return Resolution(state=ResolverState.SOURCE_UNAVAILABLE, diagnostics=self.problems, **base)
        state, note = self.decided_state, self._code_note()
        captured_at = self.provenance["retrieved_at"]
        if state is ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE:
            if self.handle_response_code is None:
                detail = f"NOT_FOUND_AT_CAPTURE: the resolver found no work in the capture of {captured_at}"
            else:
                detail = (
                    f"HANDLE_NOT_RESOLVED_AT_CAPTURE: body responseCode {self.handle_response_code} in the capture "
                    f"of {captured_at}"
                )
            return Resolution(state=state, diagnostics=(detail, *note), **base)
        if state is ResolverState.SOURCE_UNAVAILABLE:
            if self.handle_response_code is None:
                detail = "RESOLVER_ERROR_AT_CAPTURE: the resolver did not answer when the record was captured"
            else:
                detail = (
                    f"HANDLE_CODE_UNUSABLE: body responseCode {self.handle_response_code} answers nothing about "
                    "the DOI"
                )
            return Resolution(state=state, diagnostics=(detail, *note), **base)
        if state is ResolverState.DOI_RESOLVED:
            return Resolution(state=state, work=self.work, diagnostics=note, **base)
        work = self.work  # decided_state gives DOI_TARGET_MISMATCH only for a record that captured a work
        detail = f"TARGET_MISMATCH: the resolver returned the work {work.doi}"  # type: ignore[union-attr]
        return Resolution(state=state, work=work, diagnostics=(detail, *note), **base)


@dataclass(frozen=True)
class FrozenRecordSet:
    """A parsed frozen set: exactly one record per requested DOI, and at most one canary per prefix."""

    records: Mapping[str, FrozenRecord]
    canaries: Mapping[str, FrozenRecord] = field(default_factory=dict)

    def resolved_works(self) -> tuple[Work, ...]:
        """Works that usable FOUND records returned, one per work DOI, sorted by DOI.

        These are the only frozen works that may serve as reference records;
        a canary's work never does. When several records returned the same
        work DOI, the record that requested that DOI itself wins, then the
        lowest requested DOI, so the choice never depends on file order.
        """
        chosen: dict[str, tuple[tuple[bool, str], Work]] = {}
        for record in self.records.values():
            if record.canary or not record.usable or record.work is None:
                continue
            if record.decided_state not in _REFERENCE_STATES:
                continue
            rank = (record.work.doi != record.doi, record.doi)
            if record.work.doi not in chosen or rank < chosen[record.work.doi][0]:
                chosen[record.work.doi] = (rank, record.work)
        return tuple(chosen[doi][1] for doi in sorted(chosen))

    def registration(self, doi: str) -> str | None:
        """When the capture says ``doi`` was registered, or None if it does not say so credibly."""
        record = self.records.get(doi)
        return None if record is None else record.registration


def _status(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise RecordFormatError(f"{where} must be an HTTP status code (100-599)")
    return value


def _handle_code(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RecordFormatError(f"{where} must be a non-negative Handle responseCode")
    return value


def _consistency_problems(outcome: str, status: int | None, work: Work | None) -> tuple[str, ...]:
    """Contradictions inside one record that carries no body code. Such a record cannot vouch for anything."""
    problems: list[str] = []
    if outcome == FOUND and work is None:
        problems.append("OUTCOME_CONFLICT: a FOUND record carries no work")
    if outcome != FOUND and work is not None:
        problems.append(f"OUTCOME_CONFLICT: a {outcome} record carries a work")
    if outcome == FOUND and status is not None and not 200 <= status <= 299:
        problems.append(f"OUTCOME_CONFLICT: a FOUND record has HTTP status {status}")
    return tuple(problems)


def _timeline_problems(retrieved_at: Any, registered_at: Any) -> tuple[str, ...]:
    """A malformed registration date, or a capture made before the DOI existed."""
    if registered_at is None:
        return ()
    if not is_utc(registered_at):
        return ("INVALID_FIELD: registered_at",)
    if is_utc(retrieved_at) and parse_utc(retrieved_at) < parse_utc(registered_at):
        return (
            f"SNAPSHOT_PREDATES_REGISTRATION: captured at {retrieved_at}, but the DOI was registered at "
            f"{registered_at}; the capture cannot say whether it resolves",
        )
    return ()


def _record(value: Any, where: str) -> FrozenRecord:
    item = require_object(value, where, RECORD_KEYS, ("doi", "outcome"))
    doi = normalize_doi(item["doi"])
    if doi is None:
        raise RecordFormatError(f"{where}.doi {item['doi']!r} is not a DOI")
    outcome = item["outcome"]
    if outcome not in OUTCOMES:
        raise RecordFormatError(f"{where}.outcome must be one of {list(OUTCOMES)}")
    canary = item.get("canary", False)
    if not isinstance(canary, bool):
        raise RecordFormatError(f"{where}.canary must be true or false")
    if canary and not is_canary_doi(doi):
        raise RecordFormatError(f"{where} is a canary, but {doi} is not <prefix>/science-gate-canary-<12 hex>")
    status = _status(item.get("http_status"), f"{where}.http_status")
    code = _handle_code(item.get("handle_response_code"), f"{where}.handle_response_code")
    work = None if item.get("work") is None else parse_work(item["work"], f"{where}.work")
    missing_provenance = provenance_problems(item)
    consistency = _consistency_problems(outcome, status, work) if code is None else ()
    return FrozenRecord(
        doi=doi,
        outcome=outcome,
        http_status=status,
        work=work,
        provenance={name: item.get(name) for name in PROVENANCE_FIELDS},
        control_problems=(
            *missing_provenance,
            *_timeline_problems(item.get("retrieved_at"), item.get("registered_at")),
            *consistency,
        ),
        handle_response_code=code,
        canary=canary,
        registered_at=item.get("registered_at"),
        provenance_complete=not missing_provenance,
    )


def parse_frozen(document: Any) -> FrozenRecordSet:
    """Validate a frozen set document and index its records by requested DOI.

    Raises :class:`~science_gate.adapters.records.RecordFormatError` for a
    structural problem. Missing provenance is not structural; it is recorded
    in the affected record's ``problems``.
    """
    top = require_object(document, "frozen set", FROZEN_KEYS, FROZEN_KEYS)
    if top["schema"] != FROZEN_SCHEMA:
        raise RecordFormatError(f"schema must be {FROZEN_SCHEMA!r}, got {top['schema']!r}")
    if not isinstance(top["records"], list):
        raise RecordFormatError("records must be a list")
    records: dict[str, FrozenRecord] = {}
    canaries: dict[str, FrozenRecord] = {}
    for index, value in enumerate(top["records"]):
        record = _record(value, f"records[{index}]")
        if record.doi in records:
            raise RecordFormatError(f"records[{index}] captures {record.doi} a second time")
        records[record.doi] = record
        if record.canary:
            prefix = doi_prefix(record.doi)
            if prefix in canaries:
                raise RecordFormatError(f"records[{index}] is a second canary for prefix {prefix}")
            canaries[prefix] = record
    return FrozenRecordSet(records, canaries)


def resolve(doi: str, frozen: FrozenRecordSet | None, unavailable: str = "NO_FROZEN_SET") -> Resolution:
    """Look ``doi`` (in comparison form) up in the frozen set.

    ``unavailable`` names why there is no set at all when ``frozen`` is None,
    for example that the manifest declares none or that its file is missing.
    Either way, and for a DOI the set does not contain, the answer is
    SOURCE_UNAVAILABLE: nothing was asked, so nothing was "not found".
    """
    record = None if frozen is None else frozen.records.get(doi)
    if record is not None:
        return record.resolution()
    detail = (
        unavailable
        if frozen is None
        else "NOT_IN_FROZEN_SET: no answer was captured for this DOI; this is not evidence that it does not exist"
    )
    return Resolution(doi=doi, state=ResolverState.SOURCE_UNAVAILABLE, source=SOURCE_NONE, diagnostics=(detail,))


def canary_check(prefix: str, frozen: FrozenRecordSet | None) -> CanaryCheck:
    """The frozen set's negative control for ``prefix``.

    It holds only for a trusted record that captured NOT_FOUND, no work and
    body code 100. A canary the capture mapped to a work (or to body code 1)
    is a proven miss. Anything else (no canary, an untrusted one, "values
    not found") leaves the set's positives under the prefix unvouched.
    """
    record = None if frozen is None else frozen.canaries.get(prefix)
    if record is None:
        return CanaryCheck(
            prefix=prefix,
            source=SOURCE_NONE,
            doi=None,
            state=ResolverState.SOURCE_UNAVAILABLE,
            handle_response_code=None,
            holds=False,
            detail=f"NO_CANARY: the frozen set holds no canary record for prefix {prefix}",
        )
    common = {
        "prefix": prefix,
        "source": SOURCE_FROZEN,
        "doi": record.doi,
        "handle_response_code": record.handle_response_code,
        "provenance": record.provenance,
    }
    if record.control_problems:
        detail = "CANARY_UNUSABLE: " + "; ".join(record.control_problems)
        return CanaryCheck(state=ResolverState.SOURCE_UNAVAILABLE, holds=False, detail=detail, **common)
    state = record.decided_state
    holds = (
        state is ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE
        and record.outcome == NOT_FOUND
        and record.work is None
        and record.handle_response_code == HANDLE_NOT_FOUND
    )
    captured_at = record.provenance["retrieved_at"]
    if holds:
        detail = f"CANARY_HOLDS: captured NOT_FOUND with body responseCode 100 at {captured_at}"
    elif state in _REFERENCE_STATES:
        detail = f"CANARY_RESOLVED: the capture of {captured_at} maps a DOI that cannot exist to {state.value}"
    else:
        detail = (
            "CANARY_NOT_CONFIRMED: a canary needs outcome NOT_FOUND, no work and body responseCode 100; "
            f"captured outcome {record.outcome} with responseCode {record.handle_response_code}"
        )
    return CanaryCheck(state=state, holds=holds, detail=detail, **common)
