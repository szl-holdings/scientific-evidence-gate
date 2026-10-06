"""Claim registry and manuscript scan (ARCHITECTURE.md section 7).

A number printed in a manuscript is a claim. The ``claim_registry`` check asks
two questions about every such number:

* **Can it be traced?** Every registered claim is resolved along the chain
  CLAIM -> ANALYSIS RECIPE -> CODE VERSION -> ENVIRONMENT -> INPUT MANIFEST ->
  STORED OUTPUT -> REVIEW STATE -> PUBLICATION LOCATION, and every missing
  link is listed. A claim without a reproducible derivation is UNVERIFIED with
  EPHEMERAL_CLAIM. It is never called false: absent evidence says nothing
  about whether the number is right, only that nothing durable stands behind it.
* **Is it registered at all?** Every numeric token in the manuscript is either
  matched to a registered claim value or listed as UNREGISTERED with its line
  number, and the check then abstains with UNVERIFIED.

What this tool can confirm is kept separate from what it can only record. It
never starts a process, so it cannot re-run an analysis. The recipe, code
version, environment, input-manifest digest, review state and publication
location are therefore checked for presence only and reported as DECLARED.
The stored output is the one link it can test. Its bytes are hashed against
the recorded digest, and the value its selector points at is compared with the
claim through :func:`~science_gate.invariants.compare_decimal`. That way,
rounding cannot create agreement, and an undeclared thousands separator can
never make two numbers look equal or different.

The registry format (``science-gate-claims/v1``) is documented in
``schemas/claims.schema.json``.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from ._safeio import UnsafePathError, normalize_relpath
from .invariants import DISAGREES, MAX_NUMBER_LENGTH, ParsedDecimal, compare_decimal, parse_decimal
from .manifests import IDENTIFIER_PATTERN, CheckSpec
from .models import ExecutionState, FailureMode, InputState, Reason, Status
from .verifier import MAX_LISTED, CheckContext, CheckOutcome, CheckParamError, Document

__all__ = [
    "CLAIMS_SCHEMA",
    "CHAIN",
    "LINK_FIELDS",
    "DERIVATION_LINKS",
    "REGISTRY_KEYS",
    "CLAIM_KEYS",
    "DERIVATION_KEYS",
    "STORED_OUTPUT_KEYS",
    "CSV_SELECTOR_KEYS",
    "NOT_CLAIMS_KEYS",
    "NOT_CLAIM_TOKEN_KEYS",
    "STORED_OUTPUT_ROLE",
    "preload_stored_outputs",
    "DECLARED",
    "MISSING",
    "DIGEST_MATCHES",
    "DIGEST_MISMATCH",
    "DIGEST_NOT_RECORDED",
    "UNAVAILABLE",
    "RESOLVED",
    "STORED_OUTPUT_CHANGED",
    "VALUE_DISAGREES",
    "EPHEMERAL_CLAIM",
    "INCOMPLETE_CHAIN",
    "STORED_OUTPUT_UNAVAILABLE",
    "VALUE_NOT_LOCATED",
    "HUMAN_REVIEW",
    "DISPOSITION_OUTCOMES",
    "MATCHED",
    "UNREGISTERED",
    "DECLARED_NOT_A_CLAIM",
    "EXEMPTIONS_NONE",
    "EXEMPTIONS_APPLIED",
    "EXEMPTIONS_STALE",
    "SCAN_RULE",
    "SCOPE",
    "RegistryFormatError",
    "CsvSelector",
    "StoredOutputRef",
    "RegisteredClaim",
    "NotClaim",
    "Registry",
    "parse_registry",
    "resolve_json_pointer",
    "ClaimResolution",
    "resolve_claim",
    "ManuscriptToken",
    "ManuscriptScan",
    "scan_manuscript",
    "ClassifiedToken",
    "classify_tokens",
    "check_claim_registry",
]

CLAIMS_SCHEMA = "science-gate-claims/v1"

#: The chain every claim is resolved along, in order (section 7).
CHAIN: tuple[str, ...] = (
    "CLAIM",
    "ANALYSIS_RECIPE",
    "CODE_VERSION",
    "ENVIRONMENT",
    "INPUT_MANIFEST",
    "STORED_OUTPUT",
    "REVIEW_STATE",
    "PUBLICATION_LOCATION",
)

#: The registry fields behind each link, as dotted names. A link is present
#: only when every one of its fields is.
LINK_FIELDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "CLAIM": ("statement", "value"),
        "ANALYSIS_RECIPE": ("derivation.analysis_recipe",),
        "CODE_VERSION": ("derivation.code_version",),
        "ENVIRONMENT": ("derivation.environment",),
        "INPUT_MANIFEST": ("derivation.input_manifest_sha256",),
        "STORED_OUTPUT": ("stored_output.path", "stored_output.sha256", "stored_output.selector"),
        "REVIEW_STATE": ("review_state",),
        "PUBLICATION_LOCATION": ("publication_location",),
    }
)

#: The links that make a derivation reproducible. A claim missing any of them
#: is EPHEMERAL_CLAIM: the number exists in the text and nowhere durable.
DERIVATION_LINKS = frozenset({"ANALYSIS_RECIPE", "CODE_VERSION", "ENVIRONMENT", "INPUT_MANIFEST", "STORED_OUTPUT"})

REGISTRY_KEYS = ("schema", "claims", "not_claims")
CLAIM_KEYS = (
    "claim_id",
    "statement",
    "value",
    "unit",
    "precision_decimals",
    "derivation",
    "stored_output",
    "review_state",
    "publication_location",
)
DERIVATION_KEYS = ("analysis_recipe", "code_version", "environment", "input_manifest_sha256")
STORED_OUTPUT_KEYS = ("path", "sha256", "selector")
CSV_SELECTOR_KEYS = ("row", "column")
NOT_CLAIMS_KEYS = ("manuscript_sha256", "tokens")
NOT_CLAIM_TOKEN_KEYS = ("line", "text", "reason")

#: The role under which stored outputs are read. Every file a check reads
#: through the context lands in the evidence manifest, so a replaced stored
#: output changes the run's receipt even where no claim pins it.
STORED_OUTPUT_ROLE = "claims.stored_output"

# Link states. DECLARED means "recorded in the registry": this tool does not
# re-execute analyses, so it never claims to have confirmed such a link.
DECLARED = "DECLARED"
MISSING = "MISSING"
DIGEST_MATCHES = "DIGEST_MATCHES"
DIGEST_MISMATCH = "DIGEST_MISMATCH"
DIGEST_NOT_RECORDED = "DIGEST_NOT_RECORDED"
UNAVAILABLE = "UNAVAILABLE"

# Claim dispositions. Each claim gets exactly one: its most severe problem, or
# RESOLVED when it has none.
RESOLVED = "RESOLVED"
STORED_OUTPUT_CHANGED = "STORED_OUTPUT_CHANGED"
VALUE_DISAGREES = "VALUE_DISAGREES"
EPHEMERAL_CLAIM = "EPHEMERAL_CLAIM"
INCOMPLETE_CHAIN = "INCOMPLETE_CHAIN"
STORED_OUTPUT_UNAVAILABLE = "STORED_OUTPUT_UNAVAILABLE"
VALUE_NOT_LOCATED = "VALUE_NOT_LOCATED"
HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"

#: Every problem a claim can have, most severe first, and what it means for
#: the check. Only a contradiction of recorded facts (a replaced stored
#: output, a value that disagrees with it) is FAIL. Everything that is merely
#: missing or unreadable abstains, so absent evidence never reads as "false".
DISPOSITION_OUTCOMES: Mapping[str, tuple[Status, Reason, tuple[FailureMode, ...]]] = MappingProxyType(
    {
        STORED_OUTPUT_CHANGED: (Status.FAIL, Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,)),
        VALUE_DISAGREES: (Status.FAIL, Reason.SOURCE_MISMATCH, (FailureMode.SOURCE_MISMATCH,)),
        EPHEMERAL_CLAIM: (Status.ABSTAIN, Reason.UNVERIFIED, (FailureMode.EPHEMERAL_CLAIM,)),
        INCOMPLETE_CHAIN: (Status.ABSTAIN, Reason.UNVERIFIED, ()),
        STORED_OUTPUT_UNAVAILABLE: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        VALUE_NOT_LOCATED: (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, ()),
        HUMAN_REVIEW: (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW, ()),
    }
)
_PRECEDENCE = {kind: rank for rank, kind in enumerate(DISPOSITION_OUTCOMES)}

# How each manuscript token is classified.
MATCHED = "MATCHED"
UNREGISTERED = "UNREGISTERED"
DECLARED_NOT_A_CLAIM = "DECLARED_NOT_A_CLAIM"

# Whether the registry's ``not_claims`` exemptions were applied.
EXEMPTIONS_NONE = "NONE_DECLARED"
EXEMPTIONS_APPLIED = "APPLIED"
EXEMPTIONS_STALE = "NOT_APPLIED_MANUSCRIPT_CHANGED"

SCAN_RULE = (
    "Every run of ASCII digits, with an optional sign, separators between digit groups and an exponent, is a "
    "numeric token. Digits glued on the left to a letter or underscore, directly or through one of - / . # "
    "(identifiers such as SYN-0001, v2 or Fig.2), are not numbers. URLs and DOIs are masked up to the next "
    "whitespace. A token matches a claim only when its value and printed decimals equal the registered value "
    "under the declared separators; rounding never produces a match."
)

SCOPE = (
    "Each registered claim is traced along its recorded chain. The recipe, code version, environment, "
    "input-manifest digest, review state and publication location are checked for presence only (DECLARED), "
    "because this tool does not re-run analyses. Stored outputs are checked by SHA-256 and by value. "
    "A claim's manuscript_lines are shown for reference and are not judged. Scientific validity is not established."
)

#: Diagnostics quote at most this many manuscript locations; evidence lists up to MAX_LISTED.
_QUOTED_LOCATIONS = 5

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_BAD_POINTER_ESCAPE = re.compile(r"~(?![01])")
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]{0,8}")

#: URLs and DOIs are identifiers whose digits are not claims. They are blanked
#: out (same length, so columns stay true) before numbers are looked for.
_MASKED = (
    re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+"),
    re.compile(r"\b10\.[0-9]{4,9}/\S+"),
)
_NUMBER = re.compile(
    r"(?P<sign>[+\-\u2212])?"
    r"(?P<body>[0-9]+(?:[.,'_\u00a0\u2009\u202f\u2019][0-9]+)*)"
    r"(?:[eE][+\-\u2212]?[0-9]+)?"
)
#: Marks that glue digits to a preceding word, as in SYN-0001, doi.org/10 or Fig.2.
_JOINERS = frozenset("-/.#")


# ---------------------------------------------------------------------------
# The registry document
# ---------------------------------------------------------------------------


class RegistryFormatError(ValueError):
    """The registry does not match ``science-gate-claims/v1``.

    The check then abstains with PROTOCOL_BROKEN. A malformed registry is a
    broken record, not evidence about any claim, so it is never a FAIL.
    """


@dataclass(frozen=True)
class CsvSelector:
    """Locates one cell of a CSV stored output: the single row whose cells equal ``row``, in ``column``."""

    row: tuple[tuple[str, str], ...]
    column: str

    def to_dict(self) -> dict[str, Any]:
        return {"row": dict(self.row), "column": self.column}


#: A JSON Pointer (RFC 6901) into a JSON stored output, or a CSV cell selector.
Selector = str | CsvSelector


@dataclass(frozen=True)
class StoredOutputRef:
    """Where a claim's value is stored, the digest the registry pinned, and how to find the value."""

    path: str | None = None
    sha256: str | None = None
    selector: Selector | None = None

    def selector_dict(self) -> Any:
        return self.selector.to_dict() if isinstance(self.selector, CsvSelector) else self.selector


@dataclass(frozen=True)
class RegisteredClaim:
    """One registry entry. An absent, null or blank field is None, which makes its link MISSING."""

    claim_id: str
    statement: str | None = None
    value: str | None = None
    unit: str | None = None
    precision_decimals: int | None = None
    analysis_recipe: str | None = None
    code_version: str | None = None
    environment: str | None = None
    input_manifest_sha256: str | None = None
    stored_output: StoredOutputRef = field(default_factory=StoredOutputRef)
    review_state: str | None = None
    publication_location: str | None = None

    def field_value(self, dotted: str) -> Any:
        """The value of a :data:`LINK_FIELDS` name such as ``derivation.code_version``."""
        section, _, leaf = dotted.partition(".")
        if section == "stored_output":
            return getattr(self.stored_output, leaf)
        return getattr(self, leaf or section)

    def missing_fields(self, link: str) -> tuple[str, ...]:
        return tuple(name for name in LINK_FIELDS[link] if self.field_value(name) is None)


@dataclass(frozen=True)
class NotClaim:
    """A manuscript number declared not to be a claim (a year, a section number), with the reason."""

    line: int
    text: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "text": self.text, "reason": self.reason}


@dataclass(frozen=True)
class Registry:
    """A validated registry.

    ``not_claims`` apply only to the manuscript whose SHA-256 is
    ``not_claims_manuscript_sha256``. An exemption keyed by line number is a
    statement about one exact text. After an edit, the same line may carry a
    real claim, so the exemptions must be reviewed again.
    """

    claims: tuple[RegisteredClaim, ...] = ()
    not_claims: tuple[NotClaim, ...] = ()
    not_claims_manuscript_sha256: str | None = None


def _object(value: Any, where: str, allowed: Iterable[str], required: Iterable[str] = ()) -> Mapping[str, Any]:
    """A JSON object with only the allowed keys.

    Unknown keys are refused: a typo such as ``"sha265"`` would otherwise
    drop a pinned digest silently and turn a checked link into an unchecked one.
    """
    if not isinstance(value, Mapping):
        raise RegistryFormatError(f"{where} must be a JSON object")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise RegistryFormatError(f"{where} has unknown key(s) {unknown}")
    missing = sorted(set(required) - set(value))
    if missing:
        raise RegistryFormatError(f"{where} is missing {missing}")
    return value


def _section(obj: Mapping[str, Any], key: str, where: str, allowed: Iterable[str]) -> Mapping[str, Any]:
    """An optional nested object. Absent or null is empty, so each of its fields reads as missing."""
    value = obj.get(key)
    return {} if value is None else _object(value, f"{where}.{key}", allowed)


def _optional_text(obj: Mapping[str, Any], key: str, where: str) -> str | None:
    """A string field, where null, absent and blank all mean missing."""
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RegistryFormatError(f"{where}.{key} must be a string or null")
    return value if value.strip() else None


def _optional_digest(obj: Mapping[str, Any], key: str, where: str) -> str | None:
    """A recorded SHA-256 must be well formed.

    A malformed digest would compare unequal to every real one, and so would
    pose as a replaced file (FAIL) when it is the record that is broken.
    """
    text = _optional_text(obj, key, where)
    if text is not None and not _SHA256_HEX.fullmatch(text):
        raise RegistryFormatError(f"{where}.{key} must be 64 lowercase hex characters")
    return text


def _bounded(value: Decimal) -> bool:
    """Whether a JSON number can be printed in plain notation without building a huge string."""
    exponent = value.as_tuple().exponent
    if not isinstance(exponent, int):
        return False
    return abs(exponent) <= MAX_NUMBER_LENGTH and abs(value.adjusted()) <= MAX_NUMBER_LENGTH


def _printed_value(value: Any, where: str) -> str | None:
    """The claim value as printed. A JSON number is accepted and rendered in plain notation.

    Floats never occur here, because the strict loader reads fractions as
    ``Decimal`` and so keeps the printed precision (``12.40`` stays ``12.40``).
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise RegistryFormatError(f'{where}.value must be a printed number such as "12.40", or null')
    if isinstance(value, Decimal):
        if not _bounded(value):
            raise RegistryFormatError(f"{where}.value has more than {MAX_NUMBER_LENGTH} digits in plain notation")
        return format(value, "f")
    text = str(value)
    return text if text.strip() else None


def _parse_selector(value: Any, where: str) -> Selector | None:
    """A JSON Pointer string (``""`` selects the whole document) or ``{row, column}`` for CSV."""
    if value is None:
        return None
    if isinstance(value, str):
        if value and not value.startswith("/"):
            raise RegistryFormatError(f"{where} must be a JSON Pointer: empty or starting with '/'")
        if _BAD_POINTER_ESCAPE.search(value):
            raise RegistryFormatError(f"{where} has a '~' not followed by 0 or 1")
        return value
    obj = _object(value, where, CSV_SELECTOR_KEYS, CSV_SELECTOR_KEYS)
    row, column = obj["row"], obj["column"]
    if (
        not isinstance(row, Mapping)
        or not row
        or any(not isinstance(name, str) or not name or not isinstance(cell, str) for name, cell in row.items())
    ):
        raise RegistryFormatError(f"{where}.row must map one or more column names to cell strings")
    if not isinstance(column, str) or not column:
        raise RegistryFormatError(f"{where}.column must be a non-empty string")
    return CsvSelector(tuple(sorted(row.items())), column)


def _parse_stored_output(obj: Mapping[str, Any], where: str) -> StoredOutputRef:
    section = _section(obj, "stored_output", where, STORED_OUTPUT_KEYS)
    where = f"{where}.stored_output"
    path = _optional_text(section, "path", where)
    if path is not None:
        try:
            path = normalize_relpath(path)
        except UnsafePathError as exc:
            raise RegistryFormatError(f"{where}.path is refused: {exc}") from None
    return StoredOutputRef(
        path=path,
        sha256=_optional_digest(section, "sha256", where),
        selector=_parse_selector(section.get("selector"), f"{where}.selector"),
    )


def _parse_claim(item: Any, where: str) -> RegisteredClaim:
    """One claim. Only ``claim_id`` is structurally required: every other gap is a *listed* missing link."""
    obj = _object(item, where, CLAIM_KEYS, ("claim_id",))
    claim_id = obj["claim_id"]
    if not isinstance(claim_id, str) or not IDENTIFIER_PATTERN.fullmatch(claim_id):
        raise RegistryFormatError(f"{where}.claim_id must match {IDENTIFIER_PATTERN.pattern}")
    precision = obj.get("precision_decimals")
    if precision is not None and (isinstance(precision, bool) or not isinstance(precision, int) or precision < 0):
        raise RegistryFormatError(f"{where}.precision_decimals must be a non-negative integer or null")
    derivation = _section(obj, "derivation", where, DERIVATION_KEYS)
    derivation_where = f"{where}.derivation"
    return RegisteredClaim(
        claim_id=claim_id,
        statement=_optional_text(obj, "statement", where),
        value=_printed_value(obj.get("value"), where),
        unit=_optional_text(obj, "unit", where),
        precision_decimals=precision,
        analysis_recipe=_optional_text(derivation, "analysis_recipe", derivation_where),
        code_version=_optional_text(derivation, "code_version", derivation_where),
        environment=_optional_text(derivation, "environment", derivation_where),
        input_manifest_sha256=_optional_digest(derivation, "input_manifest_sha256", derivation_where),
        stored_output=_parse_stored_output(obj, where),
        review_state=_optional_text(obj, "review_state", where),
        publication_location=_optional_text(obj, "publication_location", where),
    )


def _parse_not_claims(value: Any) -> tuple[tuple[NotClaim, ...], str | None]:
    if value is None:
        return (), None
    obj = _object(value, "not_claims", NOT_CLAIMS_KEYS, NOT_CLAIMS_KEYS)
    digest = _optional_digest(obj, "manuscript_sha256", "not_claims")
    if digest is None:
        raise RegistryFormatError("not_claims.manuscript_sha256 must pin the manuscript that was reviewed")
    if not isinstance(obj["tokens"], list):
        raise RegistryFormatError("not_claims.tokens must be a list")
    exemptions: list[NotClaim] = []
    seen: set[tuple[int, str]] = set()
    for index, item in enumerate(obj["tokens"]):
        where = f"not_claims.tokens[{index}]"
        entry = _object(item, where, NOT_CLAIM_TOKEN_KEYS, NOT_CLAIM_TOKEN_KEYS)
        line = entry["line"]
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise RegistryFormatError(f"{where}.line must be a positive integer")
        text, reason = _optional_text(entry, "text", where), _optional_text(entry, "reason", where)
        if text is None or reason is None:
            raise RegistryFormatError(f"{where} needs a non-blank text and reason")
        if (line, text) in seen:
            raise RegistryFormatError(f"{where} repeats line {line} text {text!r}")
        seen.add((line, text))
        exemptions.append(NotClaim(line, text, reason))
    return tuple(exemptions), digest


def parse_registry(document: Any) -> Registry:
    """Validate a registry document (``science-gate-claims/v1``) and return it.

    Raises :class:`RegistryFormatError` for any structural problem: a wrong
    schema, an unknown key, a wrong type, a malformed digest or selector, an
    unsafe stored-output path, or a claim id registered twice.
    """
    top = _object(document, "registry", REGISTRY_KEYS, ("schema", "claims"))
    if top["schema"] != CLAIMS_SCHEMA:
        raise RegistryFormatError(f"schema must be {CLAIMS_SCHEMA!r}, got {top['schema']!r}")
    if not isinstance(top["claims"], list):
        raise RegistryFormatError("claims must be a list")
    claims: list[RegisteredClaim] = []
    seen: set[str] = set()
    for index, item in enumerate(top["claims"]):
        claim = _parse_claim(item, f"claims[{index}]")
        if claim.claim_id in seen:
            raise RegistryFormatError(f"claims[{index}].claim_id {claim.claim_id!r} is registered twice")
        seen.add(claim.claim_id)
        claims.append(claim)
    not_claims, digest = _parse_not_claims(top.get("not_claims"))
    return Registry(tuple(claims), not_claims, digest)


def preload_stored_outputs(ctx: CheckContext) -> None:
    """Read every stored output the registry names, before any check runs (``verifier.PRELOADS``).

    Reading them up front puts their digests into the run id and in front of
    ``summary_consistency``, which then reports an unpinned stored output as
    a blind spot. The claim_registry check later reads the same bytes from
    the context. An unusable registry reads nothing here: the check reports
    why.
    """
    registry_document = ctx.role_document("claims")
    if not registry_document.loaded:
        return
    try:
        registry = parse_registry(registry_document.content)
    except RegistryFormatError:
        return
    for claim in registry.claims:
        if claim.stored_output.path is not None:
            ctx.read_document(claim.stored_output.path, role=STORED_OUTPUT_ROLE, parse="bytes")


# ---------------------------------------------------------------------------
# Stored outputs: find the value a selector points at
# ---------------------------------------------------------------------------

_LOCATED = "LOCATED"

#: Why a stored value could not be located, and what that means for the claim.
_NOT_LOCATED: Mapping[str, str] = MappingProxyType(
    {
        "SELECTOR_NOT_FOUND": VALUE_NOT_LOCATED,
        "ROW_NOT_FOUND": VALUE_NOT_LOCATED,
        "COLUMN_ABSENT": VALUE_NOT_LOCATED,
        "VALUE_EMPTY": VALUE_NOT_LOCATED,
        "OUTPUT_UNPARSEABLE": VALUE_NOT_LOCATED,
        "AMBIGUOUS_ROW": HUMAN_REVIEW,
        "NOT_A_PRINTED_NUMBER": HUMAN_REVIEW,
    }
)


@dataclass(frozen=True)
class _Located:
    """The stored value a selector points at (``code`` LOCATED), or why there is none."""

    code: str
    value: Any = None
    detail: str = ""


def resolve_json_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    """Resolve an RFC 6901 JSON Pointer. Returns ``(found, value)``; never raises for a missing path."""
    if pointer == "":
        return True, document
    current = document
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not _ARRAY_INDEX.fullmatch(token) or int(token) >= len(current):
                return False, None
            current = current[int(token)]
        else:
            return False, None
    return True, current


def _as_stored_number(value: Any, where: str) -> _Located:
    """Accept only a printed number: a string, an integer, or a bounded JSON decimal."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return _Located("VALUE_EMPTY", detail=f"{where} holds no value")
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        return _Located("NOT_A_PRINTED_NUMBER", detail=f"{where} holds a {type(value).__name__}, not a number")
    if isinstance(value, Decimal) and not _bounded(value):
        return _Located("NOT_A_PRINTED_NUMBER", detail=f"{where} has more than {MAX_NUMBER_LENGTH} digits")
    return _Located(_LOCATED, value)


def _locate_in_json(document: Any, pointer: str) -> _Located:
    found, value = resolve_json_pointer(document, pointer)
    if not found:
        return _Located("SELECTOR_NOT_FOUND", detail=f"JSON Pointer {pointer!r} selects nothing")
    return _as_stored_number(value, f"JSON Pointer {pointer!r}")


def _locate_in_csv(text: str, selector: CsvSelector) -> _Located:
    """The one cell in ``selector.column`` of the one row whose cells equal ``selector.row``.

    Cells are compared as exact strings, as discovery keeps them. A ragged
    record makes the whole output unparseable rather than being skipped,
    because a skipped record could be the very row the claim cites.
    """
    try:
        records = [record for record in csv.reader(io.StringIO(text, newline="")) if record]
    except csv.Error as exc:
        return _Located("OUTPUT_UNPARSEABLE", detail=f"CSV: {exc}")
    if not records:
        return _Located("OUTPUT_UNPARSEABLE", detail="CSV has no header row")
    header = records[0]
    if len(set(header)) != len(header):
        return _Located("OUTPUT_UNPARSEABLE", detail="CSV header repeats a column name")
    wanted = [name for name, _ in selector.row] + [selector.column]
    absent = [name for name in wanted if name not in header]
    if absent:
        return _Located("COLUMN_ABSENT", detail=f"CSV has no column(s) {absent}")
    position = {name: header.index(name) for name in wanted}
    matches: list[list[str]] = []
    for number, record in enumerate(records[1:], start=1):
        if len(record) != len(header):
            return _Located(
                "OUTPUT_UNPARSEABLE", detail=f"CSV record {number} has {len(record)} fields, the header {len(header)}"
            )
        if all(record[position[name]] == cell for name, cell in selector.row):
            matches.append(record)
    if not matches:
        return _Located("ROW_NOT_FOUND", detail=f"no CSV row has {dict(selector.row)}")
    if len(matches) > 1:
        return _Located("AMBIGUOUS_ROW", detail=f"{len(matches)} CSV rows have {dict(selector.row)}")
    return _as_stored_number(matches[0][position[selector.column]], f"CSV column {selector.column!r}")


def _parse_mode(selector: Selector | None) -> str:
    """How to read a stored output: JSON for a pointer, text for a CSV selector, raw bytes when there is neither."""
    if selector is None:
        return "bytes"
    return "text" if isinstance(selector, CsvSelector) else "json"


# ---------------------------------------------------------------------------
# Resolving one claim along the chain
# ---------------------------------------------------------------------------


def _not_compared(detail: str) -> dict[str, Any]:
    """A comparison that did not happen. ``agrees`` is None: unknown, never False."""
    return {"outcome": "NOT_COMPARED", "agrees": None, "detail": detail}


@dataclass(frozen=True)
class ClaimResolution:
    """One claim resolved along the chain: every link's state, every problem found, and the value comparison."""

    claim: RegisteredClaim
    links: tuple[Mapping[str, Any], ...]
    problems: tuple[tuple[str, str], ...]
    comparison: Mapping[str, Any]

    @property
    def missing_links(self) -> tuple[str, ...]:
        return tuple(link["link"] for link in self.links if link["state"] == MISSING)

    @property
    def disposition(self) -> str:
        """The single most severe problem, or RESOLVED."""
        return self.problems[0][0] if self.problems else RESOLVED

    def to_dict(self, manuscript_lines: Sequence[int] | None) -> dict[str, Any]:
        """The evidence record. ``manuscript_lines`` is None when no manuscript was scanned, never []."""
        return {
            "claim_id": self.claim.claim_id,
            "value": self.claim.value,
            "unit": self.claim.unit,
            "precision_decimals": self.claim.precision_decimals,
            "disposition": self.disposition,
            "problems": [{"disposition": kind, "detail": detail} for kind, detail in self.problems],
            "missing_links": list(self.missing_links),
            "links": [dict(link) for link in self.links],
            "value_comparison": dict(self.comparison),
            "manuscript_lines": None if manuscript_lines is None else list(manuscript_lines),
        }


def _stored_output_link(
    ctx: CheckContext, claim: RegisteredClaim, thousands: str | None, decimal_point: str
) -> tuple[dict[str, Any], list[tuple[str, str]], dict[str, Any]]:
    """Test the one link this tool can test: the stored output's digest, then its value.

    The file is read whenever a path is recorded, even if other fields are
    missing. Its current digest is then always in the evidence, and a value
    that disagrees is reported even for an otherwise ephemeral claim.
    """
    ref = claim.stored_output
    missing = claim.missing_fields("STORED_OUTPUT")
    record: dict[str, Any] = {
        "link": "STORED_OUTPUT",
        "path": ref.path,
        "recorded_sha256": ref.sha256,
        "selector": ref.selector_dict(),
        "current_sha256": None,
        "document_state": None,
    }
    if missing:
        record["missing_fields"] = list(missing)
    problems: list[tuple[str, str]] = []
    if ref.path is None:
        record.update(state=MISSING, digest=None)
        return record, problems, _not_compared("the claim names no stored output")

    mode = _parse_mode(ref.selector)
    document = ctx.read_document(ref.path, role=STORED_OUTPUT_ROLE, parse=mode)
    record.update(current_sha256=document.sha256, document_state=document.state.value)
    if document.sha256 is None:
        digest = UNAVAILABLE
        problems.append((STORED_OUTPUT_UNAVAILABLE, f"stored output {ref.path} is unavailable: {document.diagnostic}"))
    elif ref.sha256 is None:
        digest = DIGEST_NOT_RECORDED
    elif document.sha256 != ref.sha256:
        digest = DIGEST_MISMATCH
        problems.append(
            (
                STORED_OUTPUT_CHANGED,
                f"stored output {ref.path} no longer matches its recorded sha256 "
                f"(recorded {ref.sha256[:12]}..., found {document.sha256[:12]}...)",
            )
        )
    else:
        digest = DIGEST_MATCHES
    record.update(digest=digest, state=MISSING if missing else digest)

    if claim.value is None or ref.selector is None:
        return record, problems, _not_compared("the claim has no value" if claim.value is None else "no selector")
    if not document.loaded:
        if document.sha256 is not None:
            problems.append(
                (STORED_OUTPUT_UNAVAILABLE, f"stored output {ref.path} cannot be read as {mode}: {document.diagnostic}")
            )
        return record, problems, _not_compared(f"the stored output is {document.state.value}")
    if isinstance(ref.selector, CsvSelector):
        located = _locate_in_csv(document.content, ref.selector)
    else:
        located = _locate_in_json(document.content, ref.selector)
    if located.code != _LOCATED:
        problems.append((_NOT_LOCATED[located.code], f"stored output {ref.path}: {located.code}: {located.detail}"))
        return record, problems, {**_not_compared(located.detail), "locate": located.code}
    comparison = compare_decimal(
        claim.value,
        located.value,
        thousands=thousands,
        decimal_point=decimal_point,
        precision_decimals=claim.precision_decimals,
    )
    if comparison.outcome == DISAGREES:
        problems.append((VALUE_DISAGREES, f"value {claim.value!r}: {comparison.detail}"))
    elif comparison.agrees is None:
        problems.append((HUMAN_REVIEW, f"value {claim.value!r}: {comparison.detail}"))
    return record, problems, comparison.to_dict()


def resolve_claim(
    ctx: CheckContext, claim: RegisteredClaim, *, thousands: str | None = None, decimal_point: str = "."
) -> ClaimResolution:
    """Resolve ``claim`` along :data:`CHAIN`, listing every missing link.

    Problems are kept in severity order, so the first one is the claim's
    disposition. A missing derivation link gives EPHEMERAL_CLAIM, and a
    missing link elsewhere gives INCOMPLETE_CHAIN. Neither is ever a FAIL.
    """
    stored_output, problems, comparison = _stored_output_link(ctx, claim, thousands, decimal_point)
    links: list[dict[str, Any]] = []
    for link in CHAIN:
        if link == "STORED_OUTPUT":
            links.append(stored_output)
            continue
        missing = claim.missing_fields(link)
        record = {"link": link, "state": MISSING if missing else DECLARED}
        if missing:
            record["missing_fields"] = list(missing)
        else:
            record["declared"] = {name: claim.field_value(name) for name in LINK_FIELDS[link]}
        links.append(record)
    absent = [record["link"] for record in links if record["state"] == MISSING]
    underived = [link for link in absent if link in DERIVATION_LINKS]
    if underived:
        problems.append((EPHEMERAL_CLAIM, f"no reproducible derivation: missing link(s) {', '.join(underived)}"))
    elsewhere = [link for link in absent if link not in DERIVATION_LINKS]
    if elsewhere:
        problems.append((INCOMPLETE_CHAIN, f"missing link(s) {', '.join(elsewhere)}"))
    problems.sort(key=lambda problem: _PRECEDENCE[problem[0]])
    return ClaimResolution(claim, tuple(links), tuple(problems), comparison)


# ---------------------------------------------------------------------------
# The manuscript scan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManuscriptToken:
    """A numeric token: its 1-based line and column, the text as printed, and what it parses to."""

    line: int
    column: int
    text: str
    number: ParsedDecimal


@dataclass(frozen=True)
class ManuscriptScan:
    """Every numeric token in a manuscript, and how many digit runs were set aside as identifiers."""

    lines: int
    tokens: tuple[ManuscriptToken, ...]
    identifier_digits_skipped: int
    urls_and_dois_masked: int


def _is_word(char: str) -> bool:
    return char.isalpha() or char == "_"


def _glued_to_word(line: str, start: int) -> bool:
    """Whether the digits starting at ``start`` belong to an identifier (SYN-0001, v2, Fig.2)."""
    before = line[start - 1] if start > 0 else ""
    if _is_word(before):
        return True
    return before in _JOINERS and start > 1 and _is_word(line[start - 2])


def _mask_identifiers(line: str) -> tuple[str, int]:
    """Blank out URLs and DOIs, keeping every column where it was."""
    masked = 0
    for pattern in _MASKED:
        found = [match.span() for match in pattern.finditer(line)]
        for begin, end in found:
            line = line[:begin] + " " * (end - begin) + line[end:]
        masked += len(found)
    return line, masked


def scan_manuscript(text: str, *, thousands: str | None = None, decimal_point: str = ".") -> ManuscriptScan:
    """Find every numeric token in ``text`` (rules in :data:`SCAN_RULE`).

    Lines are split on ``\\n``, ``\\r\\n`` and ``\\r`` only, so line numbers
    agree with what an editor shows. A minus or plus sign is kept only when
    it does not join two things: in "3-5" the dash is a range, and "5" is
    positive. Parsing goes through
    :func:`~science_gate.invariants.parse_decimal`, so an undeclared
    separator makes a token ambiguous. It is never guessed.
    """
    physical = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if physical[-1] == "":
        physical.pop()
    tokens: list[ManuscriptToken] = []
    skipped = masked = 0
    for number, raw in enumerate(physical, start=1):
        line, count = _mask_identifiers(raw)
        masked += count
        for match in _NUMBER.finditer(line):
            start = match.start()
            if _glued_to_word(line, start):
                skipped += 1
                continue
            if match.group("sign") and start > 0 and line[start - 1].isalnum():
                start = match.start("body")
            token = line[start : match.end()]
            parsed = parse_decimal(token, thousands=thousands, decimal_point=decimal_point)
            tokens.append(ManuscriptToken(number, start + 1, token, parsed))
    return ManuscriptScan(len(physical), tuple(tokens), skipped, masked)


@dataclass(frozen=True)
class ClassifiedToken:
    """A manuscript token classified as MATCHED, UNREGISTERED or DECLARED_NOT_A_CLAIM."""

    token: ManuscriptToken
    classification: str
    claim_ids: tuple[str, ...] = ()
    detail: str = ""

    @property
    def readable(self) -> bool:
        return self.token.number.ok

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "line": self.token.line,
            "column": self.token.column,
            "text": self.token.text,
            "classification": self.classification,
            "number_state": self.token.number.state,
        }
        if self.claim_ids:
            record["claim_ids"] = list(self.claim_ids)
        if self.detail:
            record["detail"] = self.detail
        return record


def _claim_values(
    claims: Iterable[RegisteredClaim], thousands: str | None, decimal_point: str
) -> tuple[dict[tuple[Decimal, int], list[str]], dict[Decimal, list[tuple[str, int]]]]:
    """Index the readable claim values by (value, printed decimals), and by value alone for hints."""
    exact: dict[tuple[Decimal, int], list[str]] = {}
    by_value: dict[Decimal, list[tuple[str, int]]] = {}
    for claim in claims:
        if claim.value is None:
            continue
        parsed = parse_decimal(claim.value, thousands=thousands, decimal_point=decimal_point)
        if parsed.ok:
            exact.setdefault((parsed.value, parsed.decimals), []).append(claim.claim_id)
            by_value.setdefault(parsed.value, []).append((claim.claim_id, parsed.decimals))
    return exact, by_value


def classify_tokens(
    tokens: Iterable[ManuscriptToken],
    claims: Iterable[RegisteredClaim],
    exemptions: Mapping[tuple[int, str], NotClaim],
    *,
    thousands: str | None = None,
    decimal_point: str = ".",
) -> tuple[ClassifiedToken, ...]:
    """Match each token to the claims whose value it prints, or classify it UNREGISTERED.

    A match needs the same value **and** the same printed decimals. "12.40"
    states more precision than a registered "12.4", so it is a different
    claim. A token that cannot be read unambiguously is UNREGISTERED with its
    parse state, and it is never matched on its raw text. ``exemptions`` maps
    ``(line, text)`` to a reviewed :class:`NotClaim`.
    """
    exact, by_value = _claim_values(claims, thousands, decimal_point)
    classified: list[ClassifiedToken] = []
    for token in tokens:
        exemption = exemptions.get((token.line, token.text))
        number = token.number
        if exemption is not None:
            classified.append(ClassifiedToken(token, DECLARED_NOT_A_CLAIM, detail=exemption.reason))
        elif not number.ok:
            classified.append(ClassifiedToken(token, UNREGISTERED, detail=f"{number.state}: {number.detail}"))
        elif (number.value, number.decimals) in exact:
            classified.append(ClassifiedToken(token, MATCHED, tuple(exact[(number.value, number.decimals)])))
        else:
            near = [f"{claim_id} ({decimals} decimal(s))" for claim_id, decimals in by_value.get(number.value, ())]
            detail = f"equals {', '.join(near)} but prints {number.decimals} decimal(s)" if near else ""
            classified.append(ClassifiedToken(token, UNREGISTERED, detail=detail))
    return tuple(classified)


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


class _Verdict:
    """Collects one check's findings and turns them into a single outcome.

    FAIL outranks ABSTAIN, and PASS is returned only when nothing was found.
    The first finding at the winning level names the reason. Diagnostics are
    kept apart from findings, so a thousand problem claims can all count
    toward the verdict while the text quotes only the first few.
    """

    def __init__(self) -> None:
        self._levels: list[tuple[Status, Reason]] = []
        self._modes: set[FailureMode] = set()
        self.diagnostics: list[str] = []

    def add(
        self, status: Status, reason: Reason, modes: Iterable[FailureMode] = (), diagnostic: str | None = None
    ) -> None:
        self._levels.append((status, reason))
        self._modes.update(modes)
        if diagnostic is not None:
            self.diagnostics.append(diagnostic)

    def first_reason(self, default: Reason) -> Reason:
        return self._levels[0][1] if self._levels else default

    def _sorted_modes(self) -> tuple[FailureMode, ...]:
        return tuple(sorted(self._modes, key=lambda mode: mode.value))

    def outcome(self, *, rows_examined: int, evidence: Mapping[str, Any]) -> CheckOutcome:
        verdict, reason = Status.PASS, Reason.VERIFIED
        for status in (Status.FAIL, Status.ABSTAIN):
            chosen = [level for level in self._levels if level[0] is status]
            if chosen:
                verdict, reason = chosen[0]
                break
        return CheckOutcome(
            execution_state=ExecutionState.CHECKED,
            verdict=verdict,
            reason=reason,
            failure_modes=self._sorted_modes(),
            rows_examined=rows_examined,
            evidence=evidence,
            diagnostics=tuple(self.diagnostics),
        )

    def not_applicable(self, reason: Reason, detail: str, evidence: Mapping[str, Any]) -> CheckOutcome:
        """Nothing to examine: never PASS, and 0 is then the true count."""
        return CheckOutcome(
            execution_state=ExecutionState.NOT_APPLICABLE,
            verdict=Status.ABSTAIN,
            reason=reason,
            failure_modes=self._sorted_modes(),
            rows_examined=0,
            evidence=evidence,
            diagnostics=(*self.diagnostics, detail),
        )


def _skipped(reason: Reason, diagnostic: str, evidence: Mapping[str, Any]) -> CheckOutcome:
    """The registry could not be used at all: the check did not run, and says why."""
    return CheckOutcome(
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ABSTAIN,
        reason=reason,
        rows_examined=0,
        evidence=evidence,
        diagnostics=(diagnostic,),
    )


def _number_format(spec: CheckSpec) -> tuple[str | None, str]:
    """``params``: optional ``thousands`` and ``decimal_point``. Unknown keys are refused.

    A typo in params must never quietly weaken the check. The engine records
    the :class:`CheckParamError` as an ERROR result.
    """
    unknown = sorted(set(spec.params) - {"thousands", "decimal_point"})
    if unknown:
        raise CheckParamError(f"UNKNOWN_PARAM: {spec.kind} does not accept {unknown}")
    if spec.inputs:
        raise CheckParamError(
            f"UNEXPECTED_INPUTS: {spec.kind} reads the manifest's claims registry and manuscript and takes no inputs"
        )
    thousands, decimal_point = spec.params.get("thousands"), spec.params.get("decimal_point", ".")
    try:
        parse_decimal("0", thousands=thousands, decimal_point=decimal_point)
    except (TypeError, ValueError) as exc:
        raise CheckParamError(f"INVALID_PARAM: {exc}") from None
    return thousands, decimal_point


def _record_claims(resolutions: Sequence[ClaimResolution], verdict: _Verdict) -> None:
    """Every problem of every claim counts. Diagnostics name the first MAX_LISTED claims with problems."""
    troubled = [resolution for resolution in resolutions if resolution.problems]
    for index, resolution in enumerate(troubled):
        for position, (kind, _) in enumerate(resolution.problems):
            status, reason, modes = DISPOSITION_OUTCOMES[kind]
            diagnostic = None
            if position == 0 and index < MAX_LISTED:
                details = "; ".join(detail for _, detail in resolution.problems)
                diagnostic = f"claim {resolution.claim.claim_id!r} {resolution.disposition}: {details}"
            verdict.add(status, reason, modes, diagnostic)
    if len(troubled) > MAX_LISTED:
        remaining = len(troubled) - MAX_LISTED
        verdict.diagnostics.append(f"{remaining} more claim(s) with problems; see evidence dispositions")


def _quoted(items: Sequence[ClassifiedToken]) -> str:
    shown = ", ".join(f"line {item.token.line} {item.token.text!r}" for item in items[:_QUOTED_LOCATIONS])
    return shown + (", ..." if len(items) > _QUOTED_LOCATIONS else "")


def _exemptions(registry: Registry, manuscript: Document) -> tuple[str, dict[tuple[int, str], NotClaim]]:
    """Apply ``not_claims`` only to the exact manuscript they were reviewed on."""
    if not registry.not_claims:
        return EXEMPTIONS_NONE, {}
    if registry.not_claims_manuscript_sha256 != manuscript.sha256:
        return EXEMPTIONS_STALE, {}
    return EXEMPTIONS_APPLIED, {(item.line, item.text): item for item in registry.not_claims}


def _scan(
    manuscript: Document,
    registry: Registry,
    verdict: _Verdict,
    thousands: str | None,
    decimal_point: str,
) -> tuple[dict[str, Any], int, dict[str, list[int]] | None]:
    """Scan the manuscript and record its findings.

    Returns the scan evidence, the number of tokens examined, and the lines
    on which each claim's value is printed. The lines are None when nothing
    was scanned, so "not looked at" never reads as "not found".
    """
    if not manuscript.declared:
        verdict.add(
            Status.ABSTAIN,
            Reason.BLIND_SPOT,
            (),
            "BLIND_SPOT: the manifest declares no manuscript, so numbers published outside the registry "
            "cannot be detected",
        )
        return {"state": "NOT_DECLARED"}, 0, None
    if not manuscript.loaded:
        reason = Reason.PROTOCOL_BROKEN if manuscript.state is InputState.PARSE_ERROR else Reason.INSUFFICIENT_EVIDENCE
        verdict.add(
            Status.ABSTAIN,
            reason,
            (),
            f"manuscript ({manuscript.path}) unavailable: {manuscript.diagnostic}; "
            "unregistered numbers could not be scanned",
        )
        return {"state": "UNAVAILABLE"}, 0, None

    scan = scan_manuscript(manuscript.content, thousands=thousands, decimal_point=decimal_point)
    state, exemptions = _exemptions(registry, manuscript)
    classified = classify_tokens(
        scan.tokens, registry.claims, exemptions, thousands=thousands, decimal_point=decimal_point
    )
    unregistered = [item for item in classified if item.classification == UNREGISTERED and item.readable]
    unreadable = [item for item in classified if item.classification == UNREGISTERED and not item.readable]
    exempted = [item for item in classified if item.classification == DECLARED_NOT_A_CLAIM]
    used = {(item.token.line, item.token.text) for item in exempted}
    unused = [item for key, item in exemptions.items() if key not in used]

    if unregistered:
        verdict.add(
            Status.ABSTAIN,
            Reason.UNVERIFIED,
            (FailureMode.EPHEMERAL_CLAIM,),
            f"UNREGISTERED: {len(unregistered)} manuscript number(s) match no registered claim: "
            f"{_quoted(unregistered)}",
        )
    if unreadable:
        verdict.add(
            Status.ABSTAIN,
            Reason.REQUIRES_HUMAN_REVIEW,
            (),
            f"UNREADABLE: {len(unreadable)} manuscript number(s) cannot be read unambiguously under the declared "
            f"separators: {_quoted(unreadable)}",
        )
    if state == EXEMPTIONS_STALE:
        verdict.add(
            Status.ABSTAIN,
            Reason.REQUIRES_HUMAN_REVIEW,
            (),
            f"not_claims was reviewed on manuscript sha256 {registry.not_claims_manuscript_sha256[:12]}..., "
            f"not the current {manuscript.sha256[:12]}...; none of its {len(registry.not_claims)} exemption(s) "
            "were applied",
        )
    if unused:
        shown = ", ".join(f"line {item.line} {item.text!r}" for item in unused[:_QUOTED_LOCATIONS])
        verdict.add(
            Status.ABSTAIN,
            Reason.REQUIRES_HUMAN_REVIEW,
            (),
            f"{len(unused)} not_claims exemption(s) match no manuscript number: {shown}",
        )

    lines_by_claim: dict[str, list[int]] = {claim.claim_id: [] for claim in registry.claims}
    for item in classified:
        for claim_id in item.claim_ids:
            if item.token.line not in lines_by_claim[claim_id]:
                lines_by_claim[claim_id].append(item.token.line)
    counts = Counter(item.classification for item in classified)
    evidence = {
        "state": "SCANNED",
        "lines_scanned": scan.lines,
        "numeric_tokens": len(scan.tokens),
        "classifications": {name: counts.get(name, 0) for name in (MATCHED, UNREGISTERED, DECLARED_NOT_A_CLAIM)},
        "unreadable": len(unreadable),
        "unregistered_tokens": [item.to_dict() for item in classified if item.classification == UNREGISTERED][
            :MAX_LISTED
        ],
        "matched_tokens": [item.to_dict() for item in classified if item.classification == MATCHED][:MAX_LISTED],
        "declared_not_claims": [item.to_dict() for item in exempted][:MAX_LISTED],
        "skipped": {
            "identifier_digit_runs": scan.identifier_digits_skipped,
            "urls_and_dois": scan.urls_and_dois_masked,
        },
        "exemptions": {
            "state": state,
            "declared": len(registry.not_claims),
            "reviewed_manuscript_sha256": registry.not_claims_manuscript_sha256,
            "applied": len(used),
            "unused": [item.to_dict() for item in unused][:MAX_LISTED],
        },
        "rule": SCAN_RULE,
    }
    return evidence, len(scan.tokens), lines_by_claim


def check_claim_registry(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Trace registered claims and scan the manuscript for unregistered numbers (kind ``claim_registry``).

    ``params``: optional ``thousands`` and ``decimal_point``. They apply to
    the manuscript, the registered values and the stored outputs alike. The
    check reads the manifest's ``claims`` and ``manuscript`` documents and
    takes no inputs.

    * Neither document declared: NOT_APPLICABLE.
    * Registry unreadable or malformed: SKIPPED, ABSTAIN (never FAIL).
    * A replaced stored output, or a value that disagrees with it: FAIL with
      SOURCE_MISMATCH.
    * A missing derivation link: ABSTAIN with UNVERIFIED and EPHEMERAL_CLAIM.
    * A manuscript number that matches no claim: ABSTAIN with UNVERIFIED,
      listed with its line number.
    * No manuscript declared: ABSTAIN with BLIND_SPOT, because unregistered
      numbers cannot be looked for.

    ``rows_examined`` counts the claims examined plus the manuscript tokens
    examined.
    """
    thousands, decimal_point = _number_format(spec)
    registry_document = ctx.role_document("claims")
    manuscript = ctx.role_document("manuscript")
    verdict = _Verdict()
    evidence: dict[str, Any] = {
        "registry": registry_document.to_dict(),
        "manuscript": manuscript.to_dict(),
        "number_format": {"thousands": thousands, "decimal_point": decimal_point},
        "chain": list(CHAIN),
        "scope": SCOPE,
    }
    if not registry_document.declared and not manuscript.declared:
        return verdict.not_applicable(
            Reason.OUT_OF_SCOPE, "the manifest declares neither a claim registry nor a manuscript", evidence
        )

    registry = Registry()
    if registry_document.declared:
        if not registry_document.loaded:
            reason = (
                Reason.PROTOCOL_BROKEN
                if registry_document.state is InputState.PARSE_ERROR
                else Reason.INSUFFICIENT_EVIDENCE
            )
            return _skipped(
                reason, f"claims ({registry_document.path}) unavailable: {registry_document.diagnostic}", evidence
            )
        try:
            registry = parse_registry(registry_document.content)
        except RegistryFormatError as exc:
            return _skipped(
                Reason.PROTOCOL_BROKEN, f"MALFORMED_DOCUMENT: claims ({registry_document.path}): {exc}", evidence
            )
    else:
        verdict.add(
            Status.ABSTAIN,
            Reason.UNVERIFIED,
            (FailureMode.EPHEMERAL_CLAIM,),
            "the manifest declares a manuscript but no claim registry: no number in it can be traced to a derivation",
        )

    resolutions = [
        resolve_claim(ctx, claim, thousands=thousands, decimal_point=decimal_point) for claim in registry.claims
    ]
    _record_claims(resolutions, verdict)
    scan_evidence, tokens_examined, lines_by_claim = _scan(manuscript, registry, verdict, thousands, decimal_point)

    def lines_of(claim_id: str) -> list[int] | None:
        return None if lines_by_claim is None else lines_by_claim[claim_id]

    troubled = [resolution for resolution in resolutions if resolution.problems]
    resolved = [resolution for resolution in resolutions if not resolution.problems]
    evidence.update(
        {
            "claims_examined": len(resolutions),
            "dispositions": dict(sorted(Counter(resolution.disposition for resolution in resolutions).items())),
            "problem_claims": [item.to_dict(lines_of(item.claim.claim_id)) for item in troubled[:MAX_LISTED]],
            "resolved_claims": [item.to_dict(lines_of(item.claim.claim_id)) for item in resolved[:MAX_LISTED]],
            "listed_limit": MAX_LISTED,
            "manuscript_scan": scan_evidence,
            "records_examined": {"claims": len(resolutions), "manuscript_tokens": tokens_examined},
        }
    )
    examined = len(resolutions) + tokens_examined
    if examined == 0:
        return verdict.not_applicable(
            verdict.first_reason(Reason.INSUFFICIENT_EVIDENCE),
            "nothing to examine: the registry lists no claims and no manuscript number was scanned",
            evidence,
        )
    return verdict.outcome(rows_examined=examined, evidence=evidence)
