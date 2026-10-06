"""Manifest loading and validation (ARCHITECTURE.md section 2).

A manifest declares what a run is expected to examine. It is untrusted input,
so validation runs before anything else touches the filesystem, and every
violation is collected as a :class:`ManifestIssue` with a stable code and a
JSON Pointer. The whole set is then raised together as :class:`ManifestError`.
Callers report ERROR / PROTOCOL_BROKEN with those diagnostics and never a
traceback.

Strictness beyond the top level is deliberate. Unknown keys are refused at
*every* object level, not only the top: a typo such as ``"sha265"`` would
otherwise silently drop a declared digest, turning a checked input into an
unchecked one. The only free-form object is a check's ``params``, which
belongs to the check kind. Even there, subprocess-shaped keys are refused.

Input paths are only type-checked here. Their safety (traversal, symlinks,
size) is judged by discovery, which marks an unsafe input REFUSED so that it
stays visible in the input accounting (section 3). Paths in role fields
(``claims``, ``reviews.verdicts``, ...) have no accounting row to carry such a
state, so an unsafe role path is refused here with ``UNSAFE_PATH``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

from ._canonical import StrictJSONError, sha256_bytes, strict_loads
from ._safeio import UnsafePathError, comparison_key, normalize_relpath
from .models import BUILTIN_CHECK_KINDS, AccessClass, DenominatorSource, Permissions, Reason, Status

__all__ = [
    "MANIFEST_SCHEMA",
    "MAX_MANIFEST_BYTES",
    "TOP_LEVEL_KEYS",
    "REQUIRED_TOP_LEVEL_KEYS",
    "INPUT_KEYS",
    "REQUIRED_INPUT_KEYS",
    "CHECK_KEYS",
    "REQUIRED_CHECK_KEYS",
    "CITATIONS_KEYS",
    "REVIEWS_KEYS",
    "CORPUS_KEYS",
    "SOURCE_LICENSE_KEYS",
    "APPROVED_REDACTION_KEYS",
    "DEFAULT_LIMITS",
    "UNSAFE_KEYS",
    "INPUT_FORMATS",
    "IDENTIFIER_PATTERN",
    "ManifestIssue",
    "ManifestError",
    "InputSpec",
    "CheckSpec",
    "Limits",
    "CitationsSpec",
    "ReviewsSpec",
    "SourceLicense",
    "ApprovedRedaction",
    "CorpusSpec",
    "Manifest",
    "load_manifest",
    "parse_manifest",
]

MANIFEST_SCHEMA = "science-gate-manifest/v1"

#: A manifest is a small declaration; anything larger is refused before parsing
#: so a hostile file cannot exhaust memory in the JSON parser.
MAX_MANIFEST_BYTES = 8 * 1024 * 1024

TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "run_label",
        "inputs",
        "accepted_snapshot",
        "checks",
        "claims",
        "manuscript",
        "dependencies",
        "citations",
        "reviews",
        "time_sources",
        "limits",
        "corpus",
        "summary_claim",
    }
)
REQUIRED_TOP_LEVEL_KEYS = frozenset({"schema", "inputs", "checks"})
INPUT_KEYS = frozenset(
    {"id", "path", "required", "format", "sha256", "row_key", "expected_rows", "denominator_source"}
)
REQUIRED_INPUT_KEYS = frozenset({"id", "path", "format"})
CHECK_KEYS = frozenset({"id", "kind", "version", "required", "inputs", "params"})
REQUIRED_CHECK_KEYS = frozenset({"id", "kind", "version"})
CITATIONS_KEYS = frozenset({"entries", "log", "frozen", "live"})
REVIEWS_KEYS = frozenset({"required_reviewers", "verdicts"})
CORPUS_KEYS = frozenset({"access_class", "permissions", "source_licenses", "approved_redactions"})
#: The two text fields of each ``corpus.source_licenses`` and ``corpus.approved_redactions`` entry.
SOURCE_LICENSE_KEYS = ("source", "license")
APPROVED_REDACTION_KEYS = ("target", "description")
DEFAULT_LIMITS: Mapping[str, int] = MappingProxyType(
    {"max_file_bytes": 52_428_800, "max_files": 10_000, "max_rows": 1_000_000}
)

#: Keys that would ask for a process to be started. The package never starts
#: one, so a manifest that asks is refused rather than silently ignored.
#: Matching is case-insensitive.
UNSAFE_KEYS = frozenset({"command", "cmd", "shell", "exec", "script", "run", "subprocess", "entrypoint"})

INPUT_FORMATS = ("csv", "json", "jsonl")

#: Identifiers appear in file names, SARIF rule ids and HTML, so they are
#: restricted to a portable character set.
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

_ROLE_PATH_FIELDS = ("accepted_snapshot", "claims", "manuscript", "dependencies", "time_sources", "summary_claim")

MANIFEST_NOT_FOUND = "MANIFEST_NOT_FOUND"
MANIFEST_UNREADABLE = "MANIFEST_UNREADABLE"
MANIFEST_TOO_LARGE = "MANIFEST_TOO_LARGE"
MALFORMED_JSON = "MALFORMED_JSON"
SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
UNKNOWN_KEY = "UNKNOWN_KEY"
UNSAFE_SUBPROCESS_REQUEST = "UNSAFE_SUBPROCESS_REQUEST"
UNSAFE_PATH = "UNSAFE_PATH"
MISSING_FIELD = "MISSING_FIELD"
INVALID_TYPE = "INVALID_TYPE"
INVALID_VALUE = "INVALID_VALUE"
DUPLICATE_ID = "DUPLICATE_ID"
DUPLICATE_PATH = "DUPLICATE_PATH"
UNREGISTERED_CHECK_KIND = "UNREGISTERED_CHECK_KIND"
UNKNOWN_INPUT_REFERENCE = "UNKNOWN_INPUT_REFERENCE"


@dataclass(frozen=True)
class ManifestIssue:
    """One validation finding: a stable ``code``, where it is, and why."""

    code: str
    pointer: str
    message: str

    def __str__(self) -> str:
        return f"{self.code} at {self.pointer or '/'}: {self.message}"

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "pointer": self.pointer, "message": self.message}


class ManifestError(Exception):
    """A manifest that cannot be used. The run outcome is ERROR / PROTOCOL_BROKEN."""

    status = Status.ERROR
    reason = Reason.PROTOCOL_BROKEN

    def __init__(self, issues: Iterable[ManifestIssue]) -> None:
        self.issues = tuple(issues)
        if not self.issues:
            raise ValueError("ManifestError needs at least one issue")
        super().__init__("; ".join(str(issue) for issue in self.issues))

    @property
    def codes(self) -> tuple[str, ...]:
        """Distinct issue codes, in the order they were first found."""
        return tuple(dict.fromkeys(issue.code for issue in self.issues))


@dataclass(frozen=True)
class InputSpec:
    """A declared input. ``path`` is as written, relative to the manifest directory."""

    input_id: str
    path: str
    format: str
    required: bool = True
    sha256: str | None = None
    row_key: tuple[str, ...] = ()
    expected_rows: int | None = None
    denominator_source: DenominatorSource = DenominatorSource.UNAVAILABLE


@dataclass(frozen=True)
class CheckSpec:
    """A declared check. Non-integer numbers in ``params`` arrive as ``Decimal``."""

    check_id: str
    kind: str
    version: str
    required: bool = True
    inputs: tuple[str, ...] = ()
    params: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class Limits:
    """Resource limits applied before and while inputs are opened."""

    max_file_bytes: int = DEFAULT_LIMITS["max_file_bytes"]
    max_files: int = DEFAULT_LIMITS["max_files"]
    max_rows: int = DEFAULT_LIMITS["max_rows"]


@dataclass(frozen=True)
class CitationsSpec:
    """Citation evidence files. Live lookups are off unless explicitly enabled."""

    entries: str | None = None
    log: str | None = None
    frozen: str | None = None
    live: bool = False


@dataclass(frozen=True)
class ReviewsSpec:
    """The review protocol: who must review, and where their verdicts are."""

    required_reviewers: tuple[str, ...]
    verdicts: str


@dataclass(frozen=True)
class SourceLicense:
    """The license a data source is declared to carry. Recorded as declared, never verified."""

    source: str
    license: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "license": self.license}


@dataclass(frozen=True)
class ApprovedRedaction:
    """A redaction the data owner declared approved for one target (a file, column or field)."""

    target: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "description": self.description}


@dataclass(frozen=True)
class CorpusSpec:
    """Access class, permissions, source licenses and approved redactions of the corpus.

    When a manifest does not declare a corpus, it is treated as
    CONTROLLED_LOCAL, the most restrictive class. Its data is then never
    copied by packaging, because an undeclared corpus must not be assumed
    redistributable. ``source_licenses`` and ``approved_redactions`` are None
    when not declared, which packaging reports as NOT_DECLARED; an empty
    tuple means the manifest declared an empty list.
    """

    access_class: AccessClass = AccessClass.CONTROLLED_LOCAL
    permissions: Permissions = field(default_factory=Permissions)
    source_licenses: tuple[SourceLicense, ...] | None = None
    approved_redactions: tuple[ApprovedRedaction, ...] | None = None


@dataclass(frozen=True)
class Manifest:
    """A validated manifest. ``root`` is the resolved manifest directory."""

    path: Path
    root: Path
    sha256: str
    run_label: str | None
    inputs: tuple[InputSpec, ...]
    checks: tuple[CheckSpec, ...]
    limits: Limits
    corpus: CorpusSpec
    accepted_snapshot: str | None = None
    claims: str | None = None
    manuscript: str | None = None
    dependencies: str | None = None
    citations: CitationsSpec | None = None
    reviews: ReviewsSpec | None = None
    time_sources: str | None = None
    summary_claim: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)
    schema: str = MANIFEST_SCHEMA

    def referenced_paths(self) -> tuple[tuple[str, str], ...]:
        """Every declared path as ``(json_pointer, path)``, in document order."""
        found: list[tuple[str, str]] = [
            (f"/inputs/{index}/path", spec.path) for index, spec in enumerate(self.inputs)
        ]
        for name in _ROLE_PATH_FIELDS:
            value = getattr(self, name)
            if value is not None:
                found.append((f"/{name}", value))
        if self.citations is not None:
            for name in ("entries", "log", "frozen"):
                value = getattr(self.citations, name)
                if value is not None:
                    found.append((f"/citations/{name}", value))
        if self.reviews is not None:
            found.append(("/reviews/verdicts", self.reviews.verdicts))
        return tuple(found)


def _pointer(base: str, token: str | int) -> str:
    """Append one RFC 6901 reference token to a JSON Pointer."""
    text = str(token).replace("~", "~0").replace("/", "~1")
    return f"{base}/{text}"


def _unsafe_key_pointers(value: Any, pointer: str = "") -> Iterator[str]:
    """Yield the pointer of every subprocess-shaped key, at any depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = _pointer(pointer, key)
            if key.casefold() in UNSAFE_KEYS:
                yield child
            yield from _unsafe_key_pointers(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _unsafe_key_pointers(item, _pointer(pointer, index))


class _Validator:
    """Collects issues while converting a parsed document into specs.

    Each method validates one value and returns the converted value, or None
    after recording an issue. Validation continues past errors so that one run
    reports every problem at once.
    """

    def __init__(self, registered_kinds: frozenset[str]) -> None:
        self.registered_kinds = registered_kinds
        self.issues: list[ManifestIssue] = []

    def add(self, code: str, pointer: str, message: str) -> None:
        self.issues.append(ManifestIssue(code, pointer, message))

    def keys(self, obj: Mapping[str, Any], allowed: frozenset[str], required: frozenset[str], pointer: str) -> None:
        for key in obj:
            # Unsafe keys were already reported with their own code.
            if key not in allowed and key.casefold() not in UNSAFE_KEYS:
                self.add(UNKNOWN_KEY, _pointer(pointer, key), f"unknown key {key!r}")
        for key in sorted(required - set(obj)):
            self.add(MISSING_FIELD, _pointer(pointer, key), f"required key {key!r} is missing")

    def mapping(self, value: Any, pointer: str, what: str) -> dict[str, Any] | None:
        if isinstance(value, dict):
            return value
        self.add(INVALID_TYPE, pointer, f"{what} must be a JSON object")
        return None

    def text(self, value: Any, pointer: str, what: str) -> str | None:
        if isinstance(value, str) and value.strip():
            return value
        self.add(INVALID_TYPE, pointer, f"{what} must be a non-empty string")
        return None

    def identifier(self, value: Any, pointer: str) -> str | None:
        text = self.text(value, pointer, "identifier")
        if text is not None and not IDENTIFIER_PATTERN.fullmatch(text):
            self.add(INVALID_VALUE, pointer, f"{text!r} must match {IDENTIFIER_PATTERN.pattern}")
            return None
        return text

    def input_path(self, value: Any, pointer: str) -> str | None:
        text = self.text(value, pointer, "path")
        if text is not None and "\x00" in text:
            self.add(INVALID_VALUE, pointer, "path contains a NUL byte")
            return None
        return text

    def role_path(self, value: Any, pointer: str) -> str | None:
        text = self.input_path(value, pointer)
        if text is None:
            return None
        try:
            normalize_relpath(text)
        except UnsafePathError as exc:
            self.add(UNSAFE_PATH, pointer, str(exc))
            return None
        return text

    def optional_role_path(self, obj: Mapping[str, Any], key: str, pointer: str) -> str | None:
        value = obj.get(key)
        return None if value is None else self.role_path(value, _pointer(pointer, key))

    def boolean(self, obj: Mapping[str, Any], key: str, pointer: str, default: bool) -> bool:
        value = obj.get(key, default)
        if isinstance(value, bool):
            return value
        self.add(INVALID_TYPE, _pointer(pointer, key), f"{key!r} must be true or false")
        return default

    def count(self, value: Any, pointer: str, *, minimum: int) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            self.add(INVALID_TYPE, pointer, "must be an integer")
            return None
        if value < minimum:
            self.add(INVALID_VALUE, pointer, f"must be at least {minimum}")
            return None
        return value

    def text_list(self, value: Any, pointer: str, what: str) -> tuple[str, ...] | None:
        if not isinstance(value, list):
            self.add(INVALID_TYPE, pointer, f"{what} must be a list of strings")
            return None
        items: list[str] = []
        for index, item in enumerate(value):
            text = self.text(item, _pointer(pointer, index), what)
            if text is None:
                return None
            if text in items:
                self.add(DUPLICATE_ID, _pointer(pointer, index), f"{text!r} is listed twice")
                return None
            items.append(text)
        return tuple(items)

    def enum(self, enum_type: type[Any], value: Any, pointer: str) -> Any:
        try:
            return enum_type(value)
        except ValueError:
            allowed = ", ".join(member.value for member in enum_type)
            self.add(INVALID_VALUE, pointer, f"{value!r} is not one of: {allowed}")
            return None

    # -- sections ---------------------------------------------------------

    def inputs(self, value: Any, pointer: str) -> tuple[InputSpec, ...]:
        if not isinstance(value, list):
            self.add(INVALID_TYPE, pointer, "inputs must be a list")
            return ()
        specs: list[InputSpec] = []
        seen: set[str] = set()
        for index, item in enumerate(value):
            spec = self.input_spec(item, _pointer(pointer, index))
            if spec is None:
                continue
            if spec.input_id in seen:
                self.add(
                    DUPLICATE_ID,
                    _pointer(_pointer(pointer, index), "id"),
                    f"input id {spec.input_id!r} is declared twice",
                )
                continue
            seen.add(spec.input_id)
            specs.append(spec)
        return tuple(specs)

    def input_spec(self, item: Any, pointer: str) -> InputSpec | None:
        obj = self.mapping(item, pointer, "input")
        if obj is None:
            return None
        before = len(self.issues)
        self.keys(obj, INPUT_KEYS, REQUIRED_INPUT_KEYS, pointer)
        input_id = self.identifier(obj["id"], _pointer(pointer, "id")) if "id" in obj else None
        path = self.input_path(obj["path"], _pointer(pointer, "path")) if "path" in obj else None
        fmt = obj.get("format")
        if "format" in obj and fmt not in INPUT_FORMATS:
            allowed = ", ".join(INPUT_FORMATS)
            self.add(INVALID_VALUE, _pointer(pointer, "format"), f"{fmt!r} is not one of: {allowed}")
        required = self.boolean(obj, "required", pointer, True)
        digest = obj.get("sha256")
        if digest is not None and not (isinstance(digest, str) and _SHA256_HEX.fullmatch(digest)):
            self.add(INVALID_VALUE, _pointer(pointer, "sha256"), "sha256 must be 64 lowercase hex characters")
        row_key = self.text_list(obj.get("row_key", []), _pointer(pointer, "row_key"), "row_key")
        expected = obj.get("expected_rows")
        if expected is not None:
            expected = self.count(expected, _pointer(pointer, "expected_rows"), minimum=0)
        source = DenominatorSource.UNAVAILABLE
        if obj.get("denominator_source") is not None:
            source_pointer = _pointer(pointer, "denominator_source")
            source = self.enum(DenominatorSource, obj["denominator_source"], source_pointer)
        self.denominator_rules(obj, source, pointer)
        if len(self.issues) != before:
            return None
        return InputSpec(
            input_id=input_id,
            path=path,
            format=fmt,
            required=required,
            sha256=digest,
            row_key=row_key,
            expected_rows=expected,
            denominator_source=source,
        )

    def denominator_rules(self, obj: Mapping[str, Any], source: DenominatorSource | None, pointer: str) -> None:
        """An expected count is meaningless without its provenance, and vice versa.

        A count is never silently promoted to INDEPENDENT: when a manifest gives
        ``expected_rows`` it must also say where that number came from.
        """
        has_count = obj.get("expected_rows") is not None
        has_source = obj.get("denominator_source") is not None
        source_pointer = _pointer(pointer, "denominator_source")
        if has_count and not has_source:
            self.add(MISSING_FIELD, source_pointer, "expected_rows requires a declared denominator_source")
        elif source is not None and has_source:
            if source is DenominatorSource.UNAVAILABLE and has_count:
                self.add(INVALID_VALUE, source_pointer, "UNAVAILABLE cannot have expected_rows")
            elif source is not DenominatorSource.UNAVAILABLE and not has_count:
                message = f"denominator_source {source.value} requires expected_rows"
                self.add(MISSING_FIELD, _pointer(pointer, "expected_rows"), message)

    def checks(self, value: Any, pointer: str, input_ids: frozenset[str]) -> tuple[CheckSpec, ...]:
        if not isinstance(value, list):
            self.add(INVALID_TYPE, pointer, "checks must be a list")
            return ()
        specs: list[CheckSpec] = []
        seen: set[str] = set()
        for index, item in enumerate(value):
            spec = self.check_spec(item, _pointer(pointer, index), input_ids)
            if spec is None:
                continue
            if spec.check_id in seen:
                self.add(
                    DUPLICATE_ID,
                    _pointer(_pointer(pointer, index), "id"),
                    f"check id {spec.check_id!r} is declared twice",
                )
                continue
            seen.add(spec.check_id)
            specs.append(spec)
        return tuple(specs)

    def check_spec(self, item: Any, pointer: str, input_ids: frozenset[str]) -> CheckSpec | None:
        obj = self.mapping(item, pointer, "check")
        if obj is None:
            return None
        before = len(self.issues)
        self.keys(obj, CHECK_KEYS, REQUIRED_CHECK_KEYS, pointer)
        check_id = self.identifier(obj["id"], _pointer(pointer, "id")) if "id" in obj else None
        kind = self.text(obj["kind"], _pointer(pointer, "kind"), "kind") if "kind" in obj else None
        if kind is not None and kind not in self.registered_kinds:
            self.add(UNREGISTERED_CHECK_KIND, _pointer(pointer, "kind"), f"check kind {kind!r} is not registered")
        version = self.text(obj["version"], _pointer(pointer, "version"), "version") if "version" in obj else None
        required = self.boolean(obj, "required", pointer, True)
        inputs_pointer = _pointer(pointer, "inputs")
        referenced = self.text_list(obj.get("inputs", []), inputs_pointer, "input reference") or ()
        for index, input_id in enumerate(referenced):
            if input_id not in input_ids:
                self.add(UNKNOWN_INPUT_REFERENCE, _pointer(inputs_pointer, index), f"no input has id {input_id!r}")
        params = self.mapping(obj.get("params", {}), _pointer(pointer, "params"), "params")
        if len(self.issues) != before:
            return None
        return CheckSpec(check_id, kind, version, required, referenced, MappingProxyType(dict(params)))

    def limits(self, value: Any, pointer: str) -> Limits:
        obj = self.mapping(value, pointer, "limits")
        if obj is None:
            return Limits()
        self.keys(obj, frozenset(DEFAULT_LIMITS), frozenset(), pointer)
        values = dict(DEFAULT_LIMITS)
        for key in DEFAULT_LIMITS:
            if key in obj:
                checked = self.count(obj[key], _pointer(pointer, key), minimum=1)
                if checked is not None:
                    values[key] = checked
        return Limits(**values)

    def corpus(self, value: Any, pointer: str) -> CorpusSpec:
        obj = self.mapping(value, pointer, "corpus")
        if obj is None:
            return CorpusSpec()
        self.keys(obj, CORPUS_KEYS, frozenset({"access_class"}), pointer)
        access = AccessClass.CONTROLLED_LOCAL
        if "access_class" in obj:
            access = self.enum(AccessClass, obj["access_class"], _pointer(pointer, "access_class")) or access
        licenses = redactions = None
        if "source_licenses" in obj:
            where = _pointer(pointer, "source_licenses")
            pairs = self.text_pairs(obj["source_licenses"], where, SOURCE_LICENSE_KEYS)
            licenses = tuple(SourceLicense(*pair) for pair in pairs)
        if "approved_redactions" in obj:
            where = _pointer(pointer, "approved_redactions")
            pairs = self.text_pairs(obj["approved_redactions"], where, APPROVED_REDACTION_KEYS)
            redactions = tuple(ApprovedRedaction(*pair) for pair in pairs)
        permissions = self.permissions(obj.get("permissions", {}), _pointer(pointer, "permissions"))
        return CorpusSpec(access, permissions, licenses, redactions)

    def text_pairs(self, value: Any, pointer: str, names: tuple[str, str]) -> tuple[tuple[str, str], ...]:
        """A list of objects holding exactly the two text fields ``names``; the first must not repeat.

        A malformed entry is reported and dropped, so validation fails and
        nothing half-declared reaches a package.
        """
        if not isinstance(value, list):
            self.add(INVALID_TYPE, pointer, f"must be a list of objects with {list(names)}")
            return ()
        pairs: list[tuple[str, str]] = []
        for index, item in enumerate(value):
            where = _pointer(pointer, index)
            obj = self.mapping(item, where, "entry")
            if obj is None:
                continue
            self.keys(obj, frozenset(names), frozenset(names), where)
            texts = [self.text(obj.get(name), _pointer(where, name), name) for name in names if name in obj]
            if len(texts) != len(names) or None in texts:
                continue
            if any(pair[0] == texts[0] for pair in pairs):
                self.add(DUPLICATE_ID, _pointer(where, names[0]), f"{texts[0]!r} is listed twice")
                continue
            pairs.append((texts[0], texts[1]))
        return tuple(pairs)

    def permissions(self, value: Any, pointer: str) -> Permissions:
        obj = self.mapping(value, pointer, "permissions")
        if obj is None:
            return Permissions()
        allowed = frozenset(Permissions().to_dict())
        self.keys(obj, allowed, frozenset(), pointer)
        chosen = {key: self.boolean(obj, key, pointer, default) for key, default in Permissions().to_dict().items()}
        return Permissions(**chosen)

    def citations(self, value: Any, pointer: str) -> CitationsSpec | None:
        obj = self.mapping(value, pointer, "citations")
        if obj is None:
            return None
        self.keys(obj, CITATIONS_KEYS, frozenset(), pointer)
        return CitationsSpec(
            entries=self.optional_role_path(obj, "entries", pointer),
            log=self.optional_role_path(obj, "log", pointer),
            frozen=self.optional_role_path(obj, "frozen", pointer),
            live=self.boolean(obj, "live", pointer, False),
        )

    def reviews(self, value: Any, pointer: str) -> ReviewsSpec | None:
        obj = self.mapping(value, pointer, "reviews")
        if obj is None:
            return None
        self.keys(obj, REVIEWS_KEYS, REVIEWS_KEYS, pointer)
        reviewers = None
        if "required_reviewers" in obj:
            reviewers = self.text_list(obj["required_reviewers"], _pointer(pointer, "required_reviewers"), "reviewer")
            if reviewers == ():
                message = "a review protocol needs at least one reviewer"
                self.add(INVALID_VALUE, _pointer(pointer, "required_reviewers"), message)
                reviewers = None
        verdicts = self.role_path(obj["verdicts"], _pointer(pointer, "verdicts")) if "verdicts" in obj else None
        if reviewers is None or verdicts is None:
            return None
        return ReviewsSpec(reviewers, verdicts)

    def duplicate_paths(self, paths: Iterable[tuple[str, str]]) -> None:
        first_seen: dict[str, str] = {}
        for pointer, path in paths:
            key = comparison_key(path)
            if key in first_seen:
                self.add(DUPLICATE_PATH, pointer, f"{path!r} names the same file as {first_seen[key]}")
            else:
                first_seen[key] = pointer


def _declared_input_ids(document: Mapping[str, Any]) -> frozenset[str]:
    """Every string id written in ``inputs``, valid or not.

    Check references are resolved against this set rather than the validated
    inputs, so one malformed input does not cascade into spurious
    UNKNOWN_INPUT_REFERENCE findings.
    """
    items = document.get("inputs")
    if not isinstance(items, list):
        return frozenset()
    return frozenset(item["id"] for item in items if isinstance(item, dict) and isinstance(item.get("id"), str))


def _too_large() -> ManifestIssue:
    return ManifestIssue(MANIFEST_TOO_LARGE, "", f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")


def parse_manifest(
    data: bytes,
    *,
    manifest_path: str | Path,
    registered_kinds: Iterable[str] = BUILTIN_CHECK_KINDS,
) -> Manifest:
    """Validate manifest bytes and return a :class:`Manifest`.

    ``manifest_path`` locates the manifest directory, against which every
    declared path is relative. Raises :class:`ManifestError` listing every
    violation found.
    """
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError([_too_large()])
    try:
        document = strict_loads(data)
    except StrictJSONError as exc:
        raise ManifestError([ManifestIssue(MALFORMED_JSON, "", str(exc))]) from None
    if not isinstance(document, dict):
        raise ManifestError([ManifestIssue(MALFORMED_JSON, "", "the manifest must be a JSON object")])

    validator = _Validator(frozenset(registered_kinds))
    for pointer in _unsafe_key_pointers(document):
        message = "manifests cannot request a process; this tool never starts one"
        validator.add(UNSAFE_SUBPROCESS_REQUEST, pointer, message)
    if document.get("schema") != MANIFEST_SCHEMA:
        # Every other field's meaning depends on the schema version, so further
        # findings would be noise.
        validator.add(SCHEMA_MISMATCH, "/schema", f"expected {MANIFEST_SCHEMA!r}, got {document.get('schema')!r}")
        raise ManifestError(validator.issues)
    validator.keys(document, TOP_LEVEL_KEYS, REQUIRED_TOP_LEVEL_KEYS, "")

    run_label = None
    if document.get("run_label") is not None:
        run_label = validator.text(document["run_label"], "/run_label", "run_label")
    inputs = validator.inputs(document["inputs"], "/inputs") if "inputs" in document else ()
    declared_ids = _declared_input_ids(document)
    checks = validator.checks(document["checks"], "/checks", declared_ids) if "checks" in document else ()
    sections = {name: document.get(name) for name in ("limits", "corpus", "citations", "reviews")}
    optional_sections = {
        "limits": Limits() if sections["limits"] is None else validator.limits(sections["limits"], "/limits"),
        "corpus": CorpusSpec() if sections["corpus"] is None else validator.corpus(sections["corpus"], "/corpus"),
        "citations": None if sections["citations"] is None else validator.citations(sections["citations"], "/citations"),
        "reviews": None if sections["reviews"] is None else validator.reviews(sections["reviews"], "/reviews"),
    }
    role_paths = {name: validator.optional_role_path(document, name, "") for name in _ROLE_PATH_FIELDS}

    resolved = Path(manifest_path).resolve()
    manifest = Manifest(
        path=resolved,
        root=resolved.parent,
        sha256=sha256_bytes(data),
        run_label=run_label,
        inputs=inputs,
        checks=checks,
        raw=document,
        **optional_sections,
        **role_paths,
    )
    validator.duplicate_paths(manifest.referenced_paths())
    if validator.issues:
        raise ManifestError(validator.issues)
    return manifest


def load_manifest(path: str | Path, *, registered_kinds: Iterable[str] = BUILTIN_CHECK_KINDS) -> Manifest:
    """Read and validate the manifest file at ``path``.

    A missing, unreadable or oversized file raises :class:`ManifestError`
    like any other invalid manifest, so callers need only one handler.
    """
    location = Path(path)
    try:
        if location.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError([_too_large()])
        with open(location, "rb") as handle:
            data = handle.read(MAX_MANIFEST_BYTES + 1)
    except FileNotFoundError:
        raise ManifestError([ManifestIssue(MANIFEST_NOT_FOUND, "", f"no manifest at {location.name!r}")]) from None
    except OSError as exc:
        issue = ManifestIssue(MANIFEST_UNREADABLE, "", f"cannot read manifest: {exc.strerror or exc}")
        raise ManifestError([issue]) from None
    return parse_manifest(data, manifest_path=location, registered_kinds=registered_kinds)
