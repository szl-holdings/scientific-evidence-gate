"""Frozen resolver adapter: answers from a recorded response set, offline.

A frozen set (``science-gate-citations-frozen/v1``) is a capture of what a
resolver answered for each DOI, made once and then replayed. Replaying makes
citation results reproducible and keeps every default code path off the
network.

Two rules decide what a frozen set may claim:

* **Provenance is per record.** A record missing any of the six provenance
  fields, or holding a malformed one, makes *that* DOI SOURCE_UNAVAILABLE.
  The other records still count.
* **Absence is not "not found".** A DOI the set has no record for is
  SOURCE_UNAVAILABLE. Only a record that captured a NOT_FOUND answer yields
  DOI_NOT_RESOLVED_AT_CAPTURE, and even that describes the capture, not the
  existence of the work.

Structural problems (unknown keys, a malformed work, two records for one DOI)
make the whole set unusable, and :func:`parse_frozen` raises. Picking one of
two conflicting captures would mean choosing ground truth by position.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..models import ResolverState
from .records import (
    PROVENANCE_FIELDS,
    SOURCE_FROZEN,
    SOURCE_NONE,
    RecordFormatError,
    Resolution,
    Work,
    normalize_doi,
    parse_work,
    provenance_problems,
    require_object,
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
]

FROZEN_SCHEMA = "science-gate-citations-frozen/v1"
FROZEN_KEYS = ("schema", "records")

#: What the resolver answered at capture time. ERROR means it failed to answer.
FOUND, NOT_FOUND, RESOLVER_ERROR = "FOUND", "NOT_FOUND", "ERROR"
OUTCOMES = (FOUND, NOT_FOUND, RESOLVER_ERROR)

RECORD_KEYS = ("doi", "outcome", "http_status", "work", *PROVENANCE_FIELDS)


@dataclass(frozen=True)
class FrozenRecord:
    """One captured resolver answer, keyed by the DOI that was requested.

    ``problems`` lists every reason the record cannot vouch for its DOI:
    missing or malformed provenance, or an outcome that contradicts the rest
    of the record. A record with problems resolves to SOURCE_UNAVAILABLE.
    """

    doi: str
    outcome: str
    http_status: int | None
    work: Work | None
    provenance: Mapping[str, Any]
    problems: tuple[str, ...]

    @property
    def usable(self) -> bool:
        return not self.problems

    def resolution(self) -> Resolution:
        """This record's answer, with its state derived from the recorded facts only."""
        base = {
            "doi": self.doi,
            "source": SOURCE_FROZEN,
            "provenance": self.provenance,
            "http_status": self.http_status,
        }
        if self.problems:
            return Resolution(state=ResolverState.SOURCE_UNAVAILABLE, diagnostics=self.problems, **base)
        if self.outcome == NOT_FOUND:
            captured_at = self.provenance["retrieved_at"]
            detail = f"NOT_FOUND_AT_CAPTURE: the resolver found no work in the capture of {captured_at}"
            return Resolution(state=ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE, diagnostics=(detail,), **base)
        # Without problems, only an ERROR record lacks a work: a FOUND one
        # without a work was flagged as an OUTCOME_CONFLICT above.
        if self.outcome == RESOLVER_ERROR or self.work is None:
            detail = "RESOLVER_ERROR_AT_CAPTURE: the resolver did not answer when the record was captured"
            return Resolution(state=ResolverState.SOURCE_UNAVAILABLE, diagnostics=(detail,), **base)
        if self.work.doi == self.doi:
            return Resolution(state=ResolverState.DOI_RESOLVED, work=self.work, **base)
        detail = f"TARGET_MISMATCH: the resolver returned the work {self.work.doi}"
        return Resolution(state=ResolverState.DOI_TARGET_MISMATCH, work=self.work, diagnostics=(detail,), **base)


@dataclass(frozen=True)
class FrozenRecordSet:
    """A parsed frozen set: exactly one record per requested DOI."""

    records: Mapping[str, FrozenRecord]

    def resolved_works(self) -> tuple[Work, ...]:
        """Works that usable FOUND records returned, one per work DOI, sorted by DOI.

        These are the only frozen works that may serve as reference records.
        When several records returned the same work DOI, the record that
        requested that DOI itself wins, then the lowest requested DOI, so
        the choice never depends on file order.
        """
        chosen: dict[str, tuple[tuple[bool, str], Work]] = {}
        for record in self.records.values():
            if not record.usable or record.work is None:
                continue
            rank = (record.work.doi != record.doi, record.doi)
            if record.work.doi not in chosen or rank < chosen[record.work.doi][0]:
                chosen[record.work.doi] = (rank, record.work)
        return tuple(chosen[doi][1] for doi in sorted(chosen))


def _status(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise RecordFormatError(f"{where} must be an HTTP status code (100-599)")
    return value


def _consistency_problems(outcome: str, status: int | None, work: Work | None) -> tuple[str, ...]:
    """Contradictions inside one record. Such a record cannot vouch for anything."""
    problems: list[str] = []
    if outcome == FOUND and work is None:
        problems.append("OUTCOME_CONFLICT: a FOUND record carries no work")
    if outcome != FOUND and work is not None:
        problems.append(f"OUTCOME_CONFLICT: a {outcome} record carries a work")
    if outcome == FOUND and status is not None and not 200 <= status <= 299:
        problems.append(f"OUTCOME_CONFLICT: a FOUND record has HTTP status {status}")
    return tuple(problems)


def _record(value: Any, where: str) -> FrozenRecord:
    item = require_object(value, where, RECORD_KEYS, ("doi", "outcome"))
    doi = normalize_doi(item["doi"])
    if doi is None:
        raise RecordFormatError(f"{where}.doi {item['doi']!r} is not a DOI")
    outcome = item["outcome"]
    if outcome not in OUTCOMES:
        raise RecordFormatError(f"{where}.outcome must be one of {list(OUTCOMES)}")
    status = _status(item.get("http_status"), f"{where}.http_status")
    work = None if item.get("work") is None else parse_work(item["work"], f"{where}.work")
    return FrozenRecord(
        doi=doi,
        outcome=outcome,
        http_status=status,
        work=work,
        provenance={name: item.get(name) for name in PROVENANCE_FIELDS},
        problems=(*provenance_problems(item), *_consistency_problems(outcome, status, work)),
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
    for index, value in enumerate(top["records"]):
        record = _record(value, f"records[{index}]")
        if record.doi in records:
            raise RecordFormatError(f"records[{index}] captures {record.doi} a second time")
        records[record.doi] = record
    return FrozenRecordSet(records)


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
