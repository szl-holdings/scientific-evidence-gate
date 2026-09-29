"""Input discovery and accounting (ARCHITECTURE.md section 3).

``discover(manifest)`` walks every declared input and records how far it got
through the funnel: discovered, opened, parsed. It gives each input exactly
one :class:`~science_gate.models.InputState`. Nothing is dropped. A missing,
refused, empty or corrupt input stays in the accounting with its state and
diagnostics, and absent counts are ``None``, never zero.

Design points:

* **Safety before opening.** The path must resolve under the manifest
  directory (symlinks included), the file must be a regular file no larger
  than ``max_file_bytes``, and the input's position must be within
  ``max_files``. A violation marks the input REFUSED without opening it.
* **One pass, one truth.** Each file is read exactly once, through a reader
  that hashes and counts bytes as the parser consumes them. The digest and
  the parsed rows therefore describe the same bytes, even if the file
  changes on disk mid-run. The byte budget is enforced again during the read.
* **Values stay strings.** CSV cells are never converted. Numbers are
  interpreted only by :func:`science_gate.invariants.parse_decimal`, so
  locale, rounding or separator mistakes cannot happen silently here. JSON
  numbers with a fraction arrive as ``Decimal``, never float.
* **Row dispositions.** Every data record seen is exactly one of: admitted,
  excluded, deferred (beyond ``max_rows``, counted but not admitted),
  unresolved (a declared ``row_key`` is blank or absent) or failed
  (malformed). Discovery excludes nothing, so ``excluded`` is a true zero.
  Closure compares the sum with ``expected_rows``, and does so only when that
  expectation is INDEPENDENT.
"""

from __future__ import annotations

import csv
import hashlib
import io
import stat
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO, Callable, Mapping, Sequence, TextIO

from ._canonical import HASH_CHUNK_BYTES, SizeLimitExceeded, StrictJSONError, strict_loads
from ._safeio import FILE_TOO_LARGE, NOT_A_REGULAR_FILE, UnsafePathError, normalize_relpath, resolve_under_root
from .manifests import InputSpec, Limits, Manifest
from .models import (
    AccountingCount,
    Closure,
    DenominatorSource,
    InputAccounting,
    InputRecord,
    InputState,
    RowCounts,
)

__all__ = ["Row", "OpenedInput", "discover", "row_key_of", "MAX_LISTED_POSITIONS"]

#: Diagnostics list at most this many line numbers, so one badly broken file
#: cannot bloat every report; the full count is always given.
MAX_LISTED_POSITIONS = 20

_BUCKET_FOR_STATE = MappingProxyType(
    {
        InputState.PARSED: "admitted",
        InputState.PARTIAL: "deferred",
        InputState.EMPTY: "unresolved",
        InputState.REFUSED: "failed",
        InputState.OPEN_FAILED: "failed",
        InputState.PARSE_ERROR: "failed",
        InputState.HASH_MISMATCH: "failed",
    }
)


@dataclass(frozen=True)
class Row:
    """One admitted data record.

    ``index`` is its 1-based position among all data records in the file.
    ``line`` is the physical line where it ended (CSV, JSONL), or None for
    JSON arrays. ``values`` is a read-only ``{column: str}`` mapping for CSV
    and the parsed JSON value otherwise.
    """

    index: int
    line: int | None
    values: Any


@dataclass(frozen=True)
class OpenedInput:
    """A declared input after discovery: its accounting record and content.

    ``rows`` holds only *admitted* records. It is ``None`` whenever the content
    must not be examined (missing, refused, unparseable, or not the artifact
    the manifest declared) and ``()`` for a genuinely empty input.
    """

    spec: InputSpec
    record: InputRecord
    absolute_path: Path | None
    columns: tuple[str, ...] | None = None
    rows: tuple[Row, ...] | None = None
    document: Any = None

    @property
    def input_id(self) -> str:
        return self.spec.input_id

    @property
    def state(self) -> InputState:
        return self.record.state

    @property
    def sha256(self) -> str | None:
        return self.record.sha256

    @property
    def usable(self) -> bool:
        """True when there is admitted content a check may examine.

        A PARTIAL input is usable, but the run still cannot PASS on it: the
        PASS invariants require every input a passing check used to be complete.
        """
        return self.record.state in (InputState.PARSED, InputState.PARTIAL)


class _ParseFailure(Exception):
    """The file as a whole could not be parsed; carries a named diagnostic."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")


class _HashingReader(io.RawIOBase):
    """Raw stream that SHA-256-hashes and counts every byte it passes on.

    Placing the hash beneath the parser is what guarantees that the digest in
    the record covers exactly the bytes that were parsed.
    """

    def __init__(self, raw: BinaryIO, max_bytes: int) -> None:
        super().__init__()
        self._raw = raw
        self._max_bytes = max_bytes
        self._digest = hashlib.sha256()
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        count = self._raw.readinto(buffer) or 0
        self.bytes_read += count
        if self.bytes_read > self._max_bytes:
            raise SizeLimitExceeded(f"file grew beyond {self._max_bytes} bytes while being read")
        self._digest.update(memoryview(buffer)[:count])
        return count

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


@dataclass
class _Tally:
    """Accumulates row dispositions while a parser streams records."""

    spec: InputSpec
    max_rows: int
    columns: tuple[str, ...] | None = None
    document: Any = None
    rows: list[Row] = field(default_factory=list)
    total: int = 0
    deferred: int = 0
    failed_at: list[int] = field(default_factory=list)
    unresolved_at: list[int] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def at_limit(self) -> bool:
        """True when the next record would be beyond ``max_rows``."""
        return self.total >= self.max_rows

    def add(self, line: int | None, values: Any, *, malformed: bool = False) -> None:
        """Classify one data record into exactly one disposition."""
        self.total += 1
        position = line if line is not None else self.total
        if self.total > self.max_rows:
            self.deferred += 1
        elif malformed:
            self.failed_at.append(position)
        elif self.spec.row_key and row_key_of(values, self.spec.row_key) is None:
            self.unresolved_at.append(position)
        else:
            self.rows.append(Row(self.total, line, values))

    def counts(self) -> RowCounts:
        return RowCounts(
            admitted=len(self.rows),
            excluded=0,
            deferred=self.deferred,
            unresolved=len(self.unresolved_at),
            failed=len(self.failed_at),
        )

    def summarize(self, position_label: str) -> None:
        """Turn non-admitted dispositions into named diagnostics."""
        if self.failed_at:
            self.diagnostics.append(
                f"MALFORMED_RECORDS: {len(self.failed_at)} record(s) could not be parsed "
                f"({position_label} {_list_positions(self.failed_at)})"
            )
        if self.unresolved_at:
            self.diagnostics.append(
                f"UNRESOLVED_ROW_KEY: {len(self.unresolved_at)} record(s) have a blank or missing "
                f"row_key {list(self.spec.row_key)} ({position_label} {_list_positions(self.unresolved_at)})"
            )
        if self.deferred:
            self.diagnostics.append(
                f"ROWS_DEFERRED: {self.deferred} record(s) beyond max_rows={self.max_rows} "
                "were counted but not admitted"
            )


def _list_positions(positions: Sequence[int]) -> str:
    shown = ", ".join(str(position) for position in positions[:MAX_LISTED_POSITIONS])
    hidden = len(positions) - MAX_LISTED_POSITIONS
    return f"{shown}, and {hidden} more" if hidden > 0 else shown


def row_key_of(values: Any, key_fields: Sequence[str]) -> tuple[str, ...] | None:
    """Return a record's key as a tuple of strings, or None if it has no usable key.

    A key part must be a non-blank string or a number (numbers are rendered
    with ``str``). Booleans, nulls, nested values and blank strings cannot
    identify a record. Returning None, instead of a placeholder, keeps two
    blank keys from colliding as "duplicates".
    """
    if not isinstance(values, Mapping):
        return None
    parts: list[str] = []
    for name in key_fields:
        value = values.get(name)
        if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
            return None
        text = value if isinstance(value, str) else str(value)
        if not text.strip():
            return None
        parts.append(text)
    return tuple(parts)


def _parse_csv(stream: TextIO, tally: _Tally) -> None:
    """Parse CSV strictly with the stdlib reader; cells stay strings."""
    reader = csv.reader(stream, strict=True)
    blank_lines = 0
    try:
        for fields in reader:
            if not fields:
                blank_lines += 1
                continue
            if tally.columns is None:
                tally.columns = _validate_header(fields)
                missing = [name for name in tally.spec.row_key if name not in tally.columns]
                if missing:
                    tally.diagnostics.append(f"ROW_KEY_COLUMN_MISSING: row_key column(s) {missing} not in the header")
                continue
            if tally.at_limit:
                tally.add(reader.line_num, None)
                continue
            if len(fields) != len(tally.columns):
                tally.add(reader.line_num, None, malformed=True)
                continue
            tally.add(reader.line_num, MappingProxyType(dict(zip(tally.columns, fields))))
    except csv.Error as exc:
        raise _ParseFailure("MALFORMED_CSV", f"line {reader.line_num}: {exc}") from None
    if blank_lines:
        tally.diagnostics.append(f"BLANK_LINES_IGNORED: {blank_lines} blank line(s) are not records")
    tally.summarize("lines")


def _validate_header(fields: list[str]) -> tuple[str, ...]:
    """Refuse headers whose columns cannot be referenced unambiguously."""
    if any(not name.strip() for name in fields):
        raise _ParseFailure("INVALID_HEADER", "a header column name is blank")
    duplicates = sorted({name for name in fields if fields.count(name) > 1})
    if duplicates:
        raise _ParseFailure("DUPLICATE_COLUMN", f"header repeats column(s) {duplicates}")
    return tuple(fields)


def _parse_json(stream: TextIO, tally: _Tally) -> None:
    """Parse one strict JSON document.

    A top-level array contributes one record per element. ``null``, ``{}``,
    ``[]`` and a blank file are empty. Any other value is a single record.
    """
    text = stream.read()
    if not text.strip():
        return
    try:
        document = strict_loads(text)
    except StrictJSONError as exc:
        raise _ParseFailure(exc.kind, str(exc).split(": ", 1)[1]) from None
    tally.document = document
    if isinstance(document, list):
        records = document
    elif document is None or (isinstance(document, dict) and not document):
        records = []
    else:
        records = [document]
    for value in records:
        tally.add(None, value)
    tally.summarize("records")


def _parse_jsonl(stream: TextIO, tally: _Tally) -> None:
    """Parse JSON Lines. A malformed line fails only that record."""
    blank_lines = 0
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            blank_lines += 1
            continue
        if tally.at_limit:
            tally.add(line_number, None)
            continue
        try:
            value = strict_loads(line)
        except StrictJSONError:
            tally.add(line_number, None, malformed=True)
            continue
        tally.add(line_number, value)
    if blank_lines:
        tally.diagnostics.append(f"BLANK_LINES_IGNORED: {blank_lines} blank line(s) are not records")
    tally.summarize("lines")


_PARSERS: Mapping[str, Callable[[TextIO, _Tally], None]] = MappingProxyType(
    {"csv": _parse_csv, "json": _parse_json, "jsonl": _parse_jsonl}
)


def _drain(stream: BinaryIO) -> None:
    """Read whatever the parser left unread so the digest covers the whole file."""
    while stream.read(HASH_CHUNK_BYTES):
        pass


def _display_path(path: str) -> str:
    """The path as reported: normalized when safe, verbatim otherwise.

    Never absolute-resolved, so reports are identical on every machine.
    """
    try:
        return normalize_relpath(path)
    except UnsafePathError:
        return path


class _Outcome:
    """Builds the :class:`OpenedInput` for one declared input."""

    def __init__(self, spec: InputSpec) -> None:
        self.spec = spec
        self.path = _display_path(spec.path)

    def build(
        self,
        state: InputState,
        diagnostics: Sequence[str],
        *,
        discovered: bool = False,
        opened: bool = False,
        parsed: bool = False,
        absolute_path: Path | None = None,
        sha256: str | None = None,
        size_bytes: int | None = None,
        counts: RowCounts | None = None,
        tally: _Tally | None = None,
        expose_content: bool = False,
    ) -> OpenedInput:
        counts = counts or RowCounts()
        record = InputRecord(
            input_id=self.spec.input_id,
            path=self.path,
            required=self.spec.required,
            format=self.spec.format,
            state=state,
            discovered=discovered,
            opened=opened,
            parsed=parsed,
            sha256=sha256,
            declared_sha256=self.spec.sha256,
            size_bytes=size_bytes,
            rows=counts.accounted,
            counts=counts,
            closure=Closure.evaluate(self.spec.denominator_source, self.spec.expected_rows, counts.accounted),
            diagnostics=tuple(diagnostics),
        )
        if not (expose_content and tally is not None):
            return OpenedInput(self.spec, record, absolute_path)
        return OpenedInput(self.spec, record, absolute_path, tally.columns, tuple(tally.rows), tally.document)

    def refused(self, diagnostic: str, **kwargs: Any) -> OpenedInput:
        return self.build(InputState.REFUSED, [f"REFUSED: {diagnostic}"], **kwargs)


def _open_input(spec: InputSpec, root: Path, limits: Limits, position: int) -> OpenedInput:
    """Take one declared input through safety checks, hashing and parsing."""
    outcome = _Outcome(spec)
    if position >= limits.max_files:
        return outcome.refused(f"FILE_COUNT_LIMIT: input #{position + 1} exceeds max_files={limits.max_files}")
    try:
        real_path = resolve_under_root(root, spec.path)
    except UnsafePathError as exc:
        return outcome.refused(str(exc))
    except OSError as exc:  # e.g. a directory on the way that cannot be read
        return outcome.build(InputState.OPEN_FAILED, [f"OPEN_FAILED: cannot resolve path: {exc.strerror or exc}"])
    try:
        info = real_path.stat()
    except FileNotFoundError:
        which = "required" if spec.required else "optional"
        return outcome.build(InputState.MISSING, [f"MISSING: {which} input not found at {outcome.path}"])
    except OSError as exc:
        return outcome.build(InputState.OPEN_FAILED, [f"OPEN_FAILED: cannot stat: {exc.strerror or exc}"])
    if not stat.S_ISREG(info.st_mode):
        return outcome.refused(f"{NOT_A_REGULAR_FILE}: not a regular file", discovered=True)
    if info.st_size > limits.max_file_bytes:
        message = f"{FILE_TOO_LARGE}: {info.st_size} bytes exceeds max_file_bytes={limits.max_file_bytes}"
        return outcome.refused(message, discovered=True, size_bytes=info.st_size)

    tally = _Tally(spec, limits.max_rows)
    failure: str | None = None
    try:
        with open(real_path, "rb", buffering=0) as raw:
            reader = _HashingReader(raw, limits.max_file_bytes)
            # The text layer is bound to a name and closed only after the
            # drain: an unreferenced TextIOWrapper closes its buffer as soon as
            # it is collected, which would stop the digest short of the end.
            with io.TextIOWrapper(io.BufferedReader(reader), encoding="utf-8-sig", newline="") as text:
                try:
                    _PARSERS[spec.format](text, tally)
                except _ParseFailure as exc:
                    failure = str(exc)
                except UnicodeDecodeError as exc:
                    failure = f"NOT_UTF8: invalid UTF-8 at decoded offset {exc.start}"
                _drain(text.buffer)
    except SizeLimitExceeded as exc:
        return outcome.refused(f"{FILE_TOO_LARGE}: {exc}", discovered=True, opened=True)
    except OSError as exc:
        message = f"OPEN_FAILED: {exc.strerror or exc}"
        return outcome.build(InputState.OPEN_FAILED, [message], discovered=True)

    common: dict[str, Any] = {
        "discovered": True,
        "opened": True,
        "absolute_path": real_path,
        "sha256": reader.hexdigest(),
        "size_bytes": reader.bytes_read,
    }
    diagnostics = list(tally.diagnostics)
    if failure is not None:
        diagnostics.insert(0, f"PARSE_ERROR: {failure}")
    if spec.sha256 is not None and reader.hexdigest() != spec.sha256:
        diagnostics.insert(0, f"HASH_MISMATCH: declared {spec.sha256} but computed {reader.hexdigest()}")
        # Content that is not the declared artifact is never admitted: when the
        # record count is known, every record is counted as failed.
        counts = None if failure else RowCounts(admitted=0, excluded=0, deferred=0, unresolved=0, failed=tally.total)
        return outcome.build(InputState.HASH_MISMATCH, diagnostics, parsed=failure is None, counts=counts, **common)
    if failure is not None:
        return outcome.build(InputState.PARSE_ERROR, diagnostics, **common)
    counts = tally.counts()
    if tally.total == 0:
        state = InputState.EMPTY
        diagnostics.insert(0, "EMPTY: the input contains no data records")
    elif counts.admitted != tally.total:
        state = InputState.PARTIAL
    else:
        state = InputState.PARSED
    return outcome.build(state, diagnostics, parsed=True, counts=counts, tally=tally, expose_content=True, **common)


def _bucket(record: InputRecord) -> str:
    """The input-level disposition used for run-level closure.

    A missing optional input was declared out of scope, so it is *excluded*.
    A missing required input is *unresolved*, never silently dropped.
    """
    if record.state is InputState.MISSING:
        return "unresolved" if record.required else "excluded"
    return _BUCKET_FOR_STATE[record.state]


def _accounting(records: Sequence[InputRecord]) -> InputAccounting:
    """Aggregate per-input records into run-level counters and closure.

    ``expected`` is INDEPENDENT because it comes from the manifest's
    declaration, made before anything was observed. ``examined`` is not known
    until checks run, so it starts UNAVAILABLE.
    """
    buckets = {name: 0 for name in ("admitted", "excluded", "deferred", "unresolved", "failed")}
    for record in records:
        buckets[_bucket(record)] += 1

    def observed(value: int) -> AccountingCount:
        return AccountingCount(value, DenominatorSource.OBSERVED)

    counters = {
        "expected": AccountingCount(len(records), DenominatorSource.INDEPENDENT),
        "discovered": observed(sum(record.discovered for record in records)),
        "opened": observed(sum(record.opened for record in records)),
        "parsed": observed(sum(record.parsed for record in records)),
        "examined": AccountingCount(None, DenominatorSource.UNAVAILABLE),
        **{name: observed(count) for name, count in buckets.items()},
    }
    closure = Closure.evaluate(DenominatorSource.INDEPENDENT, len(records), sum(buckets.values()))
    return InputAccounting(counters=counters, closure=closure, records=tuple(records))


def discover(manifest: Manifest) -> tuple[InputAccounting, dict[str, OpenedInput]]:
    """Discover, hash and parse every declared input of ``manifest``.

    Returns the input accounting and a mapping of *every* declared input id
    (in sorted order) to its :class:`OpenedInput`, including inputs that are
    missing or refused. Checks can therefore always see why content is
    absent.
    """
    opened = [
        _open_input(spec, manifest.root, manifest.limits, position)
        for position, spec in enumerate(manifest.inputs)
    ]
    accounting = _accounting([item.record for item in opened])
    return accounting, {item.input_id: item for item in sorted(opened, key=lambda item: item.input_id)}
