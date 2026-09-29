"""Record types shared by the frozen and live resolver adapters (ARCHITECTURE.md section 9).

Both adapters answer the same question, "what did a resolver say about this
DOI?", and must answer it in the same shape. Otherwise the citation checks
would need two code paths, and a live answer could be judged by looser rules
than a frozen one. This module holds that shape:

* :class:`Work`, the minimum bibliographic metadata the tool keeps about a
  work. Citation entries, frozen records and live responses are all parsed
  into it by :func:`parse_work`, so every side of a comparison has passed the
  same validation.
* :class:`Resolution`, one resolver answer for one DOI: its
  :class:`~science_gate.models.ResolverState`, the provenance that says where
  the answer came from, and the returned work. The work is set **only** when
  the answer is usable as a reference (``DOI_RESOLVED`` or
  ``DOI_TARGET_MISMATCH``), so a record with broken provenance can never be
  used as ground truth by accident.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .._clock import ClockError, parse_utc
from ..models import ResolverState

__all__ = [
    "PROVENANCE_FIELDS",
    "WORK_KEYS",
    "AUTHOR_KEYS",
    "SOURCE_FROZEN",
    "SOURCE_LIVE",
    "SOURCE_NONE",
    "RecordFormatError",
    "Author",
    "Work",
    "Resolution",
    "normalize_doi",
    "is_sha256",
    "require_object",
    "parse_work",
    "provenance_problems",
]

#: Every resolver answer must say when it was retrieved, what was asked, a
#: digest of the response, which resolver answered and under which schema, and
#: whether a live refresh produced it. An answer that cannot say all six is not
#: evidence, so its DOI is SOURCE_UNAVAILABLE.
PROVENANCE_FIELDS = (
    "retrieved_at",
    "request_url_or_query",
    "response_sha256",
    "resolver_identity",
    "resolver_schema_version",
    "live_refresh_performed",
)

#: The minimum metadata kept about a work. Nothing else from a response (no
#: abstract, no references, no body) is kept unless redistribution is allowed.
WORK_KEYS = ("doi", "title", "authors", "year", "journal", "volume", "issue")
AUTHOR_KEYS = ("family", "given")

#: Where a :class:`Resolution` came from. ``none`` means no resolver answered.
SOURCE_FROZEN = "frozen"
SOURCE_LIVE = "live"
SOURCE_NONE = "none"

#: A DOI is ``10.`` plus a registrant code of 4 to 9 digits, a slash, and a
#: suffix without whitespace.
_DOI = re.compile(r"10\.\d{4,9}/\S+")

#: Resolver prefixes that may precede a DOI as written in a citation. They are
#: matched without regard to ASCII case.
_DOI_PREFIXES = ("https://doi.org/", "http://doi.org/", "https://dx.doi.org/", "http://dx.doi.org/", "doi:")

#: DOI names are case-insensitive for ASCII letters only, so only those are
#: folded; ``str.lower`` would also fold non-ASCII letters, which are distinct.
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_YEAR = re.compile(r"\d{4}")


class RecordFormatError(ValueError):
    """A citation, frozen or log document whose structure does not match its schema.

    Raised for structural problems only (wrong types, unknown keys, duplicate
    identities). Missing *provenance* is not structural: it is reported per
    record, so one incomplete record cannot hide the others.
    """


def normalize_doi(value: Any) -> str | None:
    """Return ``value`` as a DOI in comparison form, or None if it is not a DOI.

    Resolver prefixes are removed and ASCII letters are lower-cased, so
    ``https://doi.org/10.5555/ABC`` and ``doi:10.5555/abc`` compare equal.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    folded = text.translate(_ASCII_LOWER)
    for prefix in _DOI_PREFIXES:
        if folded.startswith(prefix):
            text = text[len(prefix) :]
            break
    if not _DOI.fullmatch(text):
        return None
    return text.translate(_ASCII_LOWER)


def is_sha256(value: Any) -> bool:
    """True for a lowercase 64-character hex digest."""
    return isinstance(value, str) and _SHA256_HEX.fullmatch(value) is not None


def require_object(
    value: Any, where: str, allowed: Iterable[str], required: Iterable[str] = ()
) -> Mapping[str, Any]:
    """A JSON object with no unknown keys and every required key.

    Unknown keys are refused rather than ignored: a misspelled field would
    otherwise silently drop the evidence it was meant to carry.
    """
    if not isinstance(value, Mapping):
        raise RecordFormatError(f"{where} must be a JSON object")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise RecordFormatError(f"{where} has unknown key(s) {unknown}")
    missing = sorted(set(required) - set(value))
    if missing:
        raise RecordFormatError(f"{where} is missing {missing}")
    return value


@dataclass(frozen=True)
class Author:
    """One author as cited or recorded. ``given`` is None when it was not given."""

    family: str
    given: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"family": self.family, "given": self.given}

    def display(self) -> str:
        return self.family if not self.given else f"{self.family}, {self.given}"


@dataclass(frozen=True)
class Work:
    """The minimum metadata of one work. ``doi`` is always in comparison form."""

    doi: str
    title: str
    authors: tuple[Author, ...]
    year: str | None = None
    journal: str | None = None
    volume: str | None = None
    issue: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "doi": self.doi,
            "title": self.title,
            "authors": [author.to_dict() for author in self.authors],
            "year": self.year,
            "journal": self.journal,
            "volume": self.volume,
            "issue": self.issue,
        }


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RecordFormatError(f"{where} must be a non-empty string")
    return value.strip()


def _optional_text(value: Any, where: str) -> str | None:
    return None if value is None else _text(value, where)


def _label(value: Any, where: str) -> str | None:
    """A volume or issue: printed as text, but a bare JSON integer is accepted."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return str(value)
    return _text(value, where)


def _year(value: Any, where: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and 1000 <= value <= 9999:
        return str(value)
    if isinstance(value, str) and _YEAR.fullmatch(value.strip()):
        return value.strip()
    raise RecordFormatError(f"{where} must be a four-digit year")


def _author(value: Any, where: str) -> Author:
    item = require_object(value, where, AUTHOR_KEYS, ("family",))
    return Author(_text(item["family"], f"{where}.family"), _optional_text(item.get("given"), f"{where}.given"))


def parse_work(value: Any, where: str, *, extra_keys: Iterable[str] = ()) -> Work:
    """Validate one work in the shared shape and return it.

    ``extra_keys`` lets a caller (a citation entry, say) carry its own keys
    beside the work fields; the caller validates those. A work needs a valid
    DOI, a title and at least one author, because those identify it; the
    remaining fields are compared only when both sides have them.
    """
    item = require_object(value, where, (*WORK_KEYS, *extra_keys), ("doi", "title", "authors"))
    doi = normalize_doi(item["doi"])
    if doi is None:
        raise RecordFormatError(f"{where}.doi {item['doi']!r} is not a DOI (10.<registrant>/<suffix>)")
    authors = item["authors"]
    if not isinstance(authors, list) or not authors:
        raise RecordFormatError(f"{where}.authors must be a non-empty list")
    return Work(
        doi=doi,
        title=_text(item["title"], f"{where}.title"),
        authors=tuple(_author(author, f"{where}.authors[{index}]") for index, author in enumerate(authors)),
        year=_year(item.get("year"), f"{where}.year"),
        journal=_optional_text(item.get("journal"), f"{where}.journal"),
        volume=_label(item.get("volume"), f"{where}.volume"),
        issue=_label(item.get("issue"), f"{where}.issue"),
    )


def _is_utc(value: Any) -> bool:
    try:
        parse_utc(value)
    except ClockError:
        return False
    return True


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


_PROVENANCE_CHECKS: Mapping[str, Callable[[Any], bool]] = {
    "retrieved_at": _is_utc,
    "request_url_or_query": _is_text,
    "response_sha256": is_sha256,
    "resolver_identity": _is_text,
    "resolver_schema_version": _is_text,
    "live_refresh_performed": lambda value: isinstance(value, bool),
}


def provenance_problems(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Name every provenance field that is missing or malformed, in contract order."""
    problems: list[str] = []
    for name in PROVENANCE_FIELDS:
        value = record.get(name)
        if value is None:
            problems.append(f"MISSING_PROVENANCE: {name}")
        elif not _PROVENANCE_CHECKS[name](value):
            problems.append(f"INVALID_PROVENANCE: {name}")
    return tuple(problems)


@dataclass(frozen=True)
class Resolution:
    """One resolver answer for one DOI.

    ``work`` is set only for ``DOI_RESOLVED`` and ``DOI_TARGET_MISMATCH``:
    those are the only answers that name a work the DOI actually reached.
    ``provenance`` always lists all six fields, with None where one is absent,
    so a reader sees exactly what an answer could and could not vouch for.
    ``body`` is the response text, kept only when redistribution is allowed.
    """

    doi: str
    state: ResolverState
    source: str
    work: Work | None = None
    provenance: Mapping[str, Any] = field(default_factory=dict)
    http_status: int | None = None
    diagnostics: tuple[str, ...] = ()
    body: str | None = None

    def __post_init__(self) -> None:
        referenced = self.state in (ResolverState.DOI_RESOLVED, ResolverState.DOI_TARGET_MISMATCH)
        if referenced != (self.work is not None):
            raise ValueError(f"a {self.state.value} resolution {'needs' if referenced else 'cannot carry'} a work")
        if self.source not in (SOURCE_FROZEN, SOURCE_LIVE, SOURCE_NONE):
            raise ValueError(f"unknown resolution source {self.source!r}")

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "doi": self.doi,
            "state": self.state.value,
            "source": self.source,
            "returned_doi": None if self.work is None else self.work.doi,
            "http_status": self.http_status,
            "provenance": {name: self.provenance.get(name) for name in PROVENANCE_FIELDS},
            "diagnostics": list(self.diagnostics),
        }
        if self.body is not None:
            document["body"] = self.body
        return document
