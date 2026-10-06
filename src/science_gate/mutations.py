"""Mutation testing of the verifier itself (ARCHITECTURE.md section 10).

A verifier that has never been seen to fail proves nothing by passing. This
module injects known defects into copies of an accepted evidence tree and
records whether the verifier catches each one *for the right reason*.

1. **Baseline.** The manifest's directory tree is copied into a temporary
   workspace and verified. Unless that untouched copy is PASS, the report is
   INVALID_BASELINE. It then has no sensitivity figure and no count keys at
   all: a verifier that rejects good evidence cannot be credited with
   rejecting bad evidence.
2. **Mutations.** Each of the twenty operators looks for its target in the
   pristine copy. An operator with no target is NOT_APPLICABLE. Otherwise its
   edits are applied to a fresh copy, which is verified. The two ledger
   operators (M16, M17) instead tamper with the baseline's sealed ledger and
   replay the sealed run through :func:`~science_gate.verifier.decide`, so
   ``ledger_chain_intact`` judges the tampered entries against the original
   seal.
3. **Detection.** A mutation is *detected* only if the status is not PASS
   **and** the operator's expected detector produced a finding with a
   matching status and signal. Any other mutation executed without that is
   *escaped* and reported as a BLIND_SPOT. This includes one that another
   detector happened to catch, and one that made the verifier crash. The
   signal requirement keeps a check from being credited when it merely
   abstained because, say, its input could not be read.
4. **Counts and sensitivity.** Skipped and not-applicable mutations are
   counted, but never as detections. Sensitivity is detected/executed, given
   only when at least one mutation executed against a valid baseline.

Operators that change an input's bytes also re-declare that input's digest in
the copied manifest. A digest mismatch makes an input unexaminable, which
would stop the content detector under test from running at all. The digest
mechanism has its own operator (M07). Every verify runs offline: the injected
network opener refuses every request, so mutation testing never touches the
network, even for a manifest that asks for live lookups.

Mutation testing measures how the verifier reacts to the injected defects on
this one evidence tree. It says nothing about defects of other kinds, and
nothing about scientific validity.
"""

from __future__ import annotations

import argparse
import copy
import csv
import dataclasses
import io
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Context, Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence, TextIO

from . import TOOL_NAME, __version__
from ._canonical import StrictJSONError, pretty_json_bytes, sha256_bytes, sha256_canonical, strict_loads
from ._clock import now
from ._safeio import (
    SafeIOError,
    UnsafePathError,
    is_within,
    normalize_relpath,
    resolve_under_root,
    safe_read,
    safe_write,
)
from .discovery import row_key_of
from .invariants import parse_decimal
from .manifests import CheckSpec, InputSpec, Limits, Manifest, ManifestError, load_manifest
from .models import EXIT_CODE, CheckResult, ExecutionState, FailureMode, InputAccounting, Reason, Status
from .receipts import build_run_receipt
from .reports import render_html, run_document
from .verifier import (
    REGISTRY,
    CheckContext,
    CheckOutcome,
    DecisionInputs,
    Finding,
    NetworkPolicy,
    VerificationRun,
    decide,
    row_digest,
    verify,
)

__all__ = [
    "MUTATION_REPORT_SCHEMA",
    "MUTATION_REPORT_JSON",
    "MUTATION_REPORT_MD",
    "MUTATION_REPORT_HTML",
    "INVALID_BASELINE_MESSAGE",
    "NO_EXECUTION_MESSAGE",
    "COUNT_KEYS",
    "OPERATOR_IDS",
    "SKIPPED_CHECKER",
    "DEFAULT_OUTPUT_ROOT",
    "REPORT_HEADINGS",
    "Detector",
    "FiredDetector",
    "FileEdit",
    "Target",
    "NotApplicable",
    "Operator",
    "OPERATORS",
    "MutationRecord",
    "BaselineSummary",
    "MutationReport",
    "fired_detectors",
    "skipped_checker",
    "mutate",
    "headline",
    "render_markdown",
    "write_mutation_report",
    "cli_mutate",
]

MUTATION_REPORT_SCHEMA = "science-gate-mutation-report/v1"
MUTATION_REPORT_JSON = "mutation-report.json"
MUTATION_REPORT_MD = "mutation-report.md"
MUTATION_REPORT_HTML = "mutation-report.html"

#: Printed, verbatim, whenever the accepting baseline is not PASS (section 10).
INVALID_BASELINE_MESSAGE = "No sensitivity figure was produced because the verifier failed its accepting baseline."
NO_EXECUTION_MESSAGE = "No sensitivity figure was produced because no mutation was executed."

#: The count keys of a report with a valid baseline. An INVALID_BASELINE report omits every one of them.
COUNT_KEYS = (
    "applicable_mutations",
    "executed_mutations",
    "detected_mutations",
    "escaped_mutations",
    "skipped_mutations",
    "not_applicable_mutations",
)

#: The required operators, with their stable ids, in report order (section 10).
OPERATOR_IDS = (
    "M01_empty_input",
    "M02_missing_expected_file",
    "M03_deleted_accepted_row",
    "M04_duplicate_row",
    "M05_duplicate_reviewer_verdict",
    "M06_missing_required_reviewer",
    "M07_changed_source_hash",
    "M08_changed_author",
    "M09_changed_doi",
    "M10_changed_numeric_value",
    "M11_changed_numeric_formatting",
    "M12_timezone_shift",
    "M13_removed_invocation",
    "M14_pass_summary_without_evidence",
    "M15_skipped_required_checker",
    "M16_truncated_ledger",
    "M17_reordered_hash_chain",
    "M18_changed_upstream_design",
    "M19_replaced_stored_claim_output",
    "M20_metadata_change_under_unchanged_pass_summary",
)

#: The registry target that M15 substitutes for a required checker.
SKIPPED_CHECKER = "science_gate.mutations:skipped_checker"

#: Where ``mutate`` writes without ``--output``: the root ``verify`` uses too
#: (``cli.DEFAULT_RUNS_DIR``, which a test keeps equal). It is not imported,
#: because a library module should not depend on the command line.
DEFAULT_OUTPUT_ROOT = "science-gate-runs"

#: The headings of ``mutation-report.md``, in order. An INVALID_BASELINE
#: report has only the first two and the last, because nothing else happened.
REPORT_HEADINGS = (
    "STATUS",
    "BASELINE",
    "SENSITIVITY",
    "DETECTED",
    "BLIND SPOTS",
    "SKIPPED",
    "NOT APPLICABLE",
    "WHAT THIS RESULT DOES NOT PROVE",
)

_NOT_PROVEN = (
    "Mutation testing measures how this verifier reacted to the injected defects on this one evidence tree. "
    "Defects of other kinds, or the same defects in other trees, may still go undetected.",
    "A detected mutation shows that a detector fired, not that the evidence it guards is scientifically valid. "
    "Scientific validity is not established by this tool.",
    "Every verify ran offline with a network opener that refuses all requests; live citation lookups were not "
    "exercised.",
)

#: Diagnostic code for a manifest tree that cannot be copied into the workspace.
_TREE_ERROR = "TREE_NOT_COPIED"

#: Exact arithmetic for any number ``parse_decimal`` accepts (at most 100
#: characters). The default 28-digit context would round a long value, and a
#: rounded mutant could agree with its claim by accident.
_EXACT = Context(prec=256)
_WHITESPACE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FiredDetector:
    """One finding of a verified mutant, labelled by the detector that raised it.

    ``detector`` is ``check:<kind>``, ``input:<STATE>``, ``invariant:<name>``,
    ``contract:<rule>`` or ``manifest``. ``source`` is the finding's own
    source, which names the check or input by id.
    """

    detector: str
    source: str
    status: Status
    reason: Reason
    failure_modes: tuple[FailureMode, ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "source": self.source,
            "status": self.status.value,
            "reason": self.reason.value,
            "failure_modes": [mode.value for mode in self.failure_modes],
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Detector:
    """The mechanism an operator's defect must trip, and what counts as tripping it.

    A finding from ``label`` counts only if its status is in ``statuses`` and,
    when ``signals`` is non-empty, its reason or one of its failure modes is
    among them. Without the signals, a check would be credited for abstaining
    for an unrelated reason, such as an input it could not read.
    """

    label: str
    statuses: frozenset[Status]
    signals: frozenset[str] = frozenset()

    def matches(self, fired: FiredDetector) -> bool:
        if fired.detector != self.label or fired.status not in self.statuses:
            return False
        if not self.signals:
            return True
        return bool(self.signals & {fired.reason.value, *(mode.value for mode in fired.failure_modes)})

    def expected_result(self) -> dict[str, Any]:
        return {
            "status": "not PASS",
            "detector": self.label,
            "detector_statuses": sorted(status.value for status in self.statuses),
            "detector_signals": sorted(self.signals),
            "rule": f"the status is not PASS and {self.describe()}",
        }

    def describe(self) -> str:
        statuses = " or ".join(sorted(status.value for status in self.statuses))
        signals = f" with {' or '.join(sorted(self.signals))}" if self.signals else ""
        return f"{self.label} reports {statuses}{signals}"


def fired_detectors(
    findings: Iterable[Finding], checks: Iterable[CheckResult], accounting: InputAccounting
) -> tuple[FiredDetector, ...]:
    """Label every finding with the detector that raised it, sorted by detector then source.

    Findings are exactly what kept a run from passing (section 6), so a
    detector "fired" if and only if it produced one. A check is labelled by
    its kind and an input by its state, because operators name detectors by
    mechanism, not by the ids a particular manifest happens to use.
    """
    kinds = {check.check_id: check.kind for check in checks}
    states = {record.input_id: record.state.value for record in accounting.records}
    labelled = []
    for finding in findings:
        prefix, _, name = finding.source.partition(":")
        if prefix == "check":
            label = f"check:{kinds.get(name, name)}"
        elif prefix == "input":
            label = f"input:{states.get(name, 'UNKNOWN')}"
        else:
            label = finding.source
        labelled.append(
            FiredDetector(label, finding.source, finding.status, finding.reason, finding.failure_modes, finding.detail)
        )
    return tuple(sorted(labelled, key=lambda item: (item.detector, item.source, item.status.value, item.detail)))


def _detector(label: str, *statuses: Status, signals: Iterable[str] = ()) -> Detector:
    return Detector(label, frozenset(statuses), frozenset(signals))


# ---------------------------------------------------------------------------
# Editing helpers
# ---------------------------------------------------------------------------


def _encode_json(value: Any, indent: int | None, level: int = 0) -> str:
    """JSON text that keeps key order and writes Decimals as numbers.

    Documents are read with :func:`strict_loads`, which turns every
    non-integer number into a Decimal. Writing a Decimal back as a string
    would change the document's meaning, not merely its bytes.
    """
    if isinstance(value, Decimal):
        return str(value)
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, Mapping):
        brackets = "{}"
        items = [
            f"{json.dumps(key, ensure_ascii=False)}: {_encode_json(item, indent, level + 1)}"
            for key, item in value.items()
        ]
    elif isinstance(value, list):
        brackets = "[]"
        items = [_encode_json(item, indent, level + 1) for item in value]
    else:
        raise TypeError(f"{type(value).__name__} is not a JSON value")
    if not items:
        return brackets
    if indent is None:
        return brackets[0] + ", ".join(items) + brackets[1]
    inner = "\n" + " " * (indent * (level + 1))
    return brackets[0] + inner + ("," + inner).join(items) + "\n" + " " * (indent * level) + brackets[1]


def _json_bytes(document: Any, indent: int | None = 2) -> bytes:
    return (_encode_json(document, indent) + "\n").encode("utf-8")


def _line_ending(line: str) -> str:
    for ending in ("\r\n", "\n", "\r"):
        if line.endswith(ending):
            return ending
    return ""


@dataclass(frozen=True)
class _Record:
    """One data record of an input file. ``first``/``stop`` index lines (CSV, JSONL) or array elements (JSON)."""

    values: Any
    first: int
    stop: int
    line: int | None


class _RecordFile:
    """An input file split into data records, so that one record can be edited alone.

    For CSV and JSON Lines an edit replaces only the physical lines of that
    record, so every other byte stays as it was. A JSON array is re-rendered,
    which keeps every other element's content. A byte-order mark is kept.
    """

    def __init__(self, fmt: str, text: str) -> None:
        self.fmt = fmt
        self._bom = "﻿" if text.startswith("﻿") else ""
        text = text[len(self._bom) :]
        self.header: tuple[str, ...] = ()
        self._lines: list[str] = []
        self._document: list[Any] = []
        if fmt == "json":
            document = strict_loads(text)
            if not isinstance(document, list):
                raise ValueError("only a top-level JSON array holds separable records")
            self._document = document
            self.records = tuple(_Record(value, index, index + 1, None) for index, value in enumerate(document))
            return
        self._lines = list(io.StringIO(text, newline=""))
        self.records = self._csv_records() if fmt == "csv" else self._jsonl_records()

    @classmethod
    def load(cls, fmt: str, data: bytes | None) -> _RecordFile | None:
        """The parsed file, or None when it cannot be split into records."""
        if data is None or fmt not in ("csv", "json", "jsonl"):
            return None
        try:
            return cls(fmt, data.decode("utf-8"))
        except (UnicodeDecodeError, StrictJSONError, csv.Error, ValueError):
            return None

    def _csv_records(self) -> tuple[_Record, ...]:
        reader = csv.reader(iter(self._lines), strict=True)
        records = []
        previous = 0
        for fields in reader:
            first, previous = previous, reader.line_num
            if not fields:
                continue
            if not self.header:
                self.header = tuple(fields)
            elif len(fields) == len(self.header):
                records.append(_Record(dict(zip(self.header, fields)), first, previous, previous))
        return tuple(records)

    def _jsonl_records(self) -> tuple[_Record, ...]:
        records = []
        for index, line in enumerate(self._lines):
            if not line.strip():
                continue
            try:
                records.append(_Record(strict_loads(line), index, index + 1, index + 1))
            except StrictJSONError:
                continue
        return tuple(records)

    def _render(self, lines: Sequence[str]) -> bytes:
        return (self._bom + "".join(lines)).encode("utf-8")

    def _render_document(self, document: list[Any]) -> bytes:
        return (self._bom + _encode_json(document, 2) + "\n").encode("utf-8")

    def without(self, record: _Record) -> bytes:
        """The file with ``record`` removed."""
        if self.fmt == "json":
            return self._render_document(self._document[: record.first] + self._document[record.stop :])
        return self._render(self._lines[: record.first] + self._lines[record.stop :])

    def with_copy_of(self, record: _Record) -> bytes:
        """The file with an exact copy of ``record`` right after it."""
        if self.fmt == "json":
            document = list(self._document)
            document.insert(record.stop, copy.deepcopy(self._document[record.first]))
            return self._render_document(document)
        block = self._lines[record.first : record.stop]
        separator = [] if _line_ending(block[-1]) else [_line_ending(self._lines[0]) or "\n"]
        return self._render(self._lines[: record.stop] + separator + block + self._lines[record.stop :])

    def with_value(self, record: _Record, column: str, value: Any) -> bytes:
        """The file with ``record``'s ``column`` set to ``value``."""
        if self.fmt == "json":
            document = list(self._document)
            document[record.first] = {**self._document[record.first], column: value}
            return self._render_document(document)
        ending = _line_ending(self._lines[record.stop - 1])
        if self.fmt == "jsonl":
            replacement = _encode_json({**record.values, column: value}, None) + ending
        else:
            buffer = io.StringIO()
            # "\r\n" makes the writer quote any field holding either character; the
            # record's own line ending is restored afterwards.
            csv.writer(buffer, lineterminator="\r\n").writerow(
                [value if name == column else record.values[name] for name in self.header]
            )
            replacement = buffer.getvalue()[:-2] + ending
        return self._render(self._lines[: record.first] + [replacement] + self._lines[record.stop :])


def _render_number(value: Decimal, decimals: int, *, grouping: str | None, decimal_point: str) -> str:
    """Print ``value`` with ``decimals`` places, the given decimal mark and optional digit grouping."""
    text = format(value.quantize(Decimal(1).scaleb(-decimals), context=_EXACT), "f")
    sign = "-" if text.startswith("-") else ""
    integer, _, fraction = text.lstrip("-").partition(".")
    if grouping:
        integer = f"{int(integer):,}".replace(",", grouping)
    return sign + integer + (decimal_point + fraction if fraction else "")


def _shift_printed_number(text: str, *, thousands: str | None, decimal_point: str) -> str | None:
    """``text`` plus ten, printed the same way (same decimals, same grouping), or None if unreadable.

    Ten, not one: rounding moves a value by at most half a unit, so a shift
    of more than one unit always changes the rounded value at any precision.
    Plus one would not: with half-even rounding, 1.5 and 2.5 both round to 2.
    """
    parsed = parse_decimal(text, thousands=thousands, decimal_point=decimal_point)
    if not parsed.ok or parsed.value is None or parsed.decimals is None:
        return None
    grouping = thousands if thousands and thousands in text else None
    shifted = _EXACT.add(parsed.value, 10)
    return _render_number(shifted, parsed.decimals, grouping=grouping, decimal_point=decimal_point)


def _shift_stored_value(value: Any, *, thousands: str | None, decimal_point: str) -> Any:
    """A stored value plus ten, keeping its JSON type; None when it is not a printed number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value + 10
    if isinstance(value, Decimal):
        return _EXACT.add(value, 10)
    if isinstance(value, str):
        return _shift_printed_number(value, thousands=thousands, decimal_point=decimal_point)
    return None


def _swap_marks(text: str, *, thousands: str | None, decimal_point: str) -> str:
    """Exchange the decimal mark and the grouping mark, turning 1,234.5 into 1.234,5."""
    grouping = thousands or ("," if decimal_point == "." else ".")
    return text.translate({ord(decimal_point): grouping, ord(grouping): decimal_point})


_OFFSET = re.compile(r"([+-])(\d{2}):(\d{2})")


def _shifted_timezone(zone: Any) -> str | None:
    """The declared zone moved by one hour, or None when it is not a fixed offset.

    The shift stays inside the offsets in use on Earth (-12:00 to +14:00), so
    the mutant is a plausible, wrong, declaration rather than an invalid one.
    """
    if zone in ("UTC", "Z"):
        return "+01:00"
    match = _OFFSET.fullmatch(zone) if isinstance(zone, str) else None
    if match is None:
        return None
    minutes = (int(match.group(2)) * 60 + int(match.group(3))) * (-1 if match.group(1) == "-" else 1)
    minutes += 60 if minutes + 60 <= 14 * 60 else -60
    sign = "-" if minutes < 0 else "+"
    return f"{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def _different(current: Any, preferred: str, fallback: str) -> str:
    """``preferred``, unless the document already holds it: a mutation must change something."""
    return preferred if current != preferred else fallback


def _walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    """Every JSON object in ``value``, depth-first in document order."""
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk_objects(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_objects(item)


def _resolve_pointer(document: Any, pointer: str) -> tuple[Any, Any] | None:
    """The container and key that an RFC 6901 JSON Pointer names, or None."""
    if not pointer.startswith("/"):
        return None
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]]
    container: Any = None
    key: Any = None
    current = document
    for token in tokens:
        if isinstance(current, dict) and token in current:
            container, key, current = current, token, current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            container, key, current = current, int(token), current[int(token)]
        else:
            return None
    return (container, key) if container is not None else None


# ---------------------------------------------------------------------------
# Targets and the operator context
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileEdit:
    """Replace the file at ``path`` (relative to the tree) with ``data``; ``None`` deletes it."""

    path: str
    data: bytes | None


@dataclass(frozen=True)
class Target:
    """What an applicable operator will do, computed from the pristine copy.

    ``edits`` rewrite files in a fresh copy. ``registry`` replaces the check
    registry for that copy's verify. ``ledger_entries`` marks a sealed-run
    operator: the entries are a tampered copy of the baseline's ledger, judged
    against the baseline's original seal.
    """

    description: str
    edits: tuple[FileEdit, ...] = ()
    registry: Mapping[str, str] | None = None
    ledger_entries: tuple[Mapping[str, Any], ...] | None = None


@dataclass(frozen=True)
class NotApplicable:
    """Why an operator has no target in this tree."""

    reason: str


class _Context:
    """The pristine copy and its accepted baseline, as the operators see them."""

    def __init__(self, root: Path, manifest_name: str, baseline: VerificationRun, registry: Mapping[str, str]) -> None:
        if baseline.manifest is None:
            raise ValueError("a context needs a baseline with a loaded manifest")
        self.root = root
        self.manifest_name = manifest_name
        self.baseline = baseline
        self.manifest: Manifest = baseline.manifest
        self.registry = registry

    def read(self, relpath: str) -> bytes | None:
        """The bytes of a file in the pristine copy, or None when it cannot be read."""
        try:
            return safe_read(self.root, relpath, max_bytes=self.manifest.limits.max_file_bytes)
        except (OSError, SafeIOError):
            return None

    def read_json(self, relpath: str) -> Any:
        data = self.read(relpath)
        if data is None:
            return None
        try:
            return strict_loads(data)
        except StrictJSONError:
            return None

    def role_path(self, role: str) -> str | None:
        """The normalized path the manifest declares for ``role`` (dotted for nested fields)."""
        section, _, name = role.partition(".")
        value = getattr(self.manifest, section, None)
        if name:
            value = getattr(value, name, None) if value is not None else None
        if not isinstance(value, str):
            return None
        try:
            return normalize_relpath(value)
        except UnsafePathError:
            return None

    def role_document(self, role: str) -> tuple[str, Any] | None:
        """``(path, parsed JSON)`` for a declared role document, or None."""
        path = self.role_path(role)
        if path is None:
            return None
        document = self.read_json(path)
        return None if document is None else (path, document)

    def input_file(self, spec: InputSpec) -> tuple[str, bytes] | None:
        """``(normalized path, bytes)`` of a declared input, or None when it cannot be read."""
        try:
            path = normalize_relpath(spec.path)
        except UnsafePathError:
            return None
        data = self.read(path)
        return None if data is None else (path, data)

    def records(self, spec: InputSpec) -> tuple[str, bytes, _RecordFile] | None:
        """``(path, bytes, records)`` of a declared input that splits into records, or None."""
        found = self.input_file(spec)
        records = _RecordFile.load(spec.format, found[1]) if found is not None else None
        return None if found is None or records is None else (found[0], found[1], records)

    def input_edits(self, spec: InputSpec, path: str, data: bytes) -> tuple[FileEdit, ...]:
        """Replace an input's bytes and, if the manifest declares its digest, re-declare it."""
        edits = [FileEdit(path, data)]
        if spec.sha256 is not None:
            document = copy.deepcopy(dict(self.manifest.raw))
            for item in document["inputs"]:
                if item.get("id") == spec.input_id:
                    item["sha256"] = sha256_bytes(data)
            edits.append(FileEdit(self.manifest_name, _json_bytes(document)))
        return tuple(edits)


def _redeclared(spec: InputSpec) -> str:
    if spec.sha256 is None:
        return ""
    return "; its declared digest is re-declared so a digest mismatch cannot mask the detector under test"


def _key_label(record: _Record, spec: InputSpec) -> str:
    key = row_key_of(record.values, spec.row_key) if spec.row_key else None
    where = f"line {record.line}" if record.line is not None else f"element {record.first + 1}"
    return f"{where} (key {list(key)})" if key else where


# ---------------------------------------------------------------------------
# The twenty operators
# ---------------------------------------------------------------------------


def _locate_empty_input(ctx: _Context) -> Target | NotApplicable:
    for spec in ctx.manifest.inputs:
        found = ctx.input_file(spec) if spec.required else None
        if found is not None and found[1]:
            return Target(
                f"truncate required input {spec.input_id!r} ({found[0]}) to zero bytes{_redeclared(spec)}",
                ctx.input_edits(spec, found[0], b""),
            )
    return NotApplicable("no required input has content to remove")


def _locate_missing_file(ctx: _Context) -> Target | NotApplicable:
    for spec in ctx.manifest.inputs:
        found = ctx.input_file(spec) if spec.required else None
        if found is not None:
            return Target(f"delete required input {spec.input_id!r} ({found[0]})", (FileEdit(found[0], None),))
    return NotApplicable("no required input file exists to delete")


def _accepted_digests(snapshot: Any, input_id: str) -> set[str]:
    entry = snapshot.get("inputs", {}).get(input_id) if isinstance(snapshot, dict) else None
    rows = entry.get("rows") if isinstance(entry, dict) else None
    return {row["sha256"] for row in rows or () if isinstance(row, dict) and isinstance(row.get("sha256"), str)}


def _locate_deleted_accepted_row(ctx: _Context) -> Target | NotApplicable:
    snapshot = ctx.role_document("accepted_snapshot")
    if snapshot is None:
        return NotApplicable("the manifest declares no readable accepted_snapshot")
    for spec in ctx.manifest.inputs:
        accepted = _accepted_digests(snapshot[1], spec.input_id)
        loaded = ctx.records(spec) if accepted else None
        if loaded is None:
            continue
        path, _, records = loaded
        chosen = [record for record in records.records if row_digest(record.values) in accepted]
        if chosen:
            record = chosen[-1]
            return Target(
                f"delete the accepted record at {_key_label(record, spec)} of input {spec.input_id!r} ({path})"
                f"{_redeclared(spec)}",
                ctx.input_edits(spec, path, records.without(record)),
            )
    return NotApplicable("no input has a record accepted in the snapshot")


def _locate_duplicate_row(ctx: _Context) -> Target | NotApplicable:
    for spec in ctx.manifest.inputs:
        loaded = ctx.records(spec)
        if loaded is None or not loaded[2].records:
            continue
        path, _, records = loaded
        record = records.records[-1]
        return Target(
            f"duplicate the record at {_key_label(record, spec)} of input {spec.input_id!r} ({path})"
            f"{_redeclared(spec)}",
            ctx.input_edits(spec, path, records.with_copy_of(record)),
        )
    return NotApplicable("no input has a record to duplicate")


def _verdicts(ctx: _Context) -> tuple[str, dict[str, Any], list[Any]] | None:
    if ctx.manifest.reviews is None:
        return None
    found = ctx.role_document("reviews.verdicts")
    if found is None or not isinstance(found[1], dict) or not isinstance(found[1].get("verdicts"), list):
        return None
    return found[0], found[1], found[1]["verdicts"]


def _reviewer(verdict: Any) -> str | None:
    name = verdict.get("reviewer") if isinstance(verdict, dict) else None
    return name.strip().casefold() if isinstance(name, str) else None


def _locate_duplicate_verdict(ctx: _Context) -> Target | NotApplicable:
    found = _verdicts(ctx)
    if found is None or not found[2]:
        return NotApplicable("the manifest declares no readable reviewer verdicts")
    path, document, verdicts = found
    required = {name.strip().casefold() for name in ctx.manifest.reviews.required_reviewers}
    chosen = next((verdict for verdict in verdicts if _reviewer(verdict) in required), verdicts[0])
    mutated = {**document, "verdicts": [*verdicts, copy.deepcopy(chosen)]}
    name = chosen.get("reviewer") if isinstance(chosen, dict) else None
    return Target(
        f"record reviewer {name!r}'s verdict a second time in {path}", (FileEdit(path, _json_bytes(mutated)),)
    )


def _locate_missing_reviewer(ctx: _Context) -> Target | NotApplicable:
    found = _verdicts(ctx)
    if found is None:
        return NotApplicable("the manifest declares no readable reviewer verdicts")
    path, document, verdicts = found
    for name in ctx.manifest.reviews.required_reviewers:
        identity = name.strip().casefold()
        kept = [verdict for verdict in verdicts if _reviewer(verdict) != identity]
        if len(kept) < len(verdicts):
            mutated = {**document, "verdicts": kept}
            return Target(
                f"remove every verdict of required reviewer {name!r} from {path}",
                (FileEdit(path, _json_bytes(mutated)),),
            )
    return NotApplicable("no required reviewer has a recorded verdict to remove")


def _reencoded(data: bytes) -> bytes:
    """The same records with a different final line ending, so only the digest changes."""
    if data.endswith(b"\r\n"):
        return data[:-2] + b"\n"
    if data.endswith(b"\n"):
        return data[:-1] + b"\r\n"
    return data + b"\n"


def _locate_changed_source_hash(ctx: _Context) -> Target | NotApplicable:
    for spec in ctx.manifest.inputs:
        found = ctx.input_file(spec) if spec.sha256 is not None else None
        if found is None or not found[1]:
            continue
        path, data = found
        return Target(
            f"re-encode the final line ending of input {spec.input_id!r} ({path}) without re-declaring its digest; "
            "the parsed records are unchanged, so only the digest can catch it",
            (FileEdit(path, _reencoded(data)),),
        )
    return NotApplicable("no input with a declared digest has content to change")


#: Fields that may carry an author's name, in the order M08 prefers them.
_NAME_FIELDS = ("family", "last", "surname", "name", "literal")


def _locate_changed_author(ctx: _Context) -> Target | NotApplicable:
    found = ctx.role_document("citations.entries")
    if found is None:
        return NotApplicable("the manifest declares no readable citation entries")
    path, document = found
    mutated = copy.deepcopy(document)
    for entry in _walk_objects(mutated):
        authors = entry.get("authors")
        if not isinstance(authors, list) or not authors:
            continue
        first = authors[0]
        if isinstance(first, str):
            authors[0] = "Mutant, Quinn" if first != "Mutant, Quinn" else "Mutant, Rowan"
        elif isinstance(first, dict):
            name_field = next((key for key in _NAME_FIELDS if isinstance(first.get(key), str)), None)
            if name_field is None:
                continue
            first[name_field] = "Mutant" if first[name_field] != "Mutant" else "Mutantson"
        else:
            continue
        who = entry.get("citation_id") or entry.get("doi") or entry.get("title")
        return Target(
            f"replace the first author of citation entry {who!r} in {path} with an invented name",
            (FileEdit(path, _json_bytes(mutated)),),
        )
    return NotApplicable("no citation entry lists authors")


def _locate_changed_doi(ctx: _Context) -> Target | NotApplicable:
    found = ctx.role_document("citations.entries")
    if found is None:
        return NotApplicable("the manifest declares no readable citation entries")
    path, document = found
    known = b"".join(ctx.read(item) or b"" for item in (path, ctx.role_path("citations.frozen")) if item)
    replacement = "10.5555/sg.mutant.m09"
    while replacement.encode("utf-8") in known:
        replacement += "x"
    mutated = copy.deepcopy(document)
    for entry in _walk_objects(mutated):
        if isinstance(entry.get("doi"), str) and entry["doi"].strip():
            old, entry["doi"] = entry["doi"], replacement
            return Target(
                f"change the DOI {old!r} in {path} to {replacement!r}, which no frozen record holds",
                (FileEdit(path, _json_bytes(mutated)),),
            )
    return NotApplicable("no citation entry carries a DOI")


#: One value a numeric_agreement check cites: ``(check, input, path, bytes, records, record, column, stored)``.
_Candidate = tuple[CheckSpec, InputSpec, str, bytes, _RecordFile, _Record, str, Any]


def _agreement_candidates(ctx: _Context) -> Iterator[_Candidate]:
    """Each stored value a numeric_agreement check cites, located by the input's row key."""
    inputs = {spec.input_id: spec for spec in ctx.manifest.inputs}
    for check in ctx.manifest.checks:
        column = check.params.get("column")
        expected = check.params.get("expected")
        if check.kind != "numeric_agreement" or len(check.inputs) != 1 or not isinstance(column, str):
            continue
        spec = inputs.get(check.inputs[0])
        loaded = ctx.records(spec) if spec is not None and spec.row_key else None
        if loaded is None or not isinstance(expected, list):
            continue
        path, data, records = loaded
        for item in expected:
            key = item.get("key") if isinstance(item, Mapping) else None
            key = (key,) if isinstance(key, str) else tuple(key) if isinstance(key, list) else None
            matches = [record for record in records.records if key and row_key_of(record.values, spec.row_key) == key]
            if len(matches) != 1 or not isinstance(matches[0].values, Mapping):
                continue
            stored = matches[0].values.get(column)
            if stored is not None:
                yield check, spec, path, data, records, matches[0], column, stored


def _marks(check: CheckSpec) -> tuple[str | None, str]:
    thousands = check.params.get("thousands")
    decimal_point = check.params.get("decimal_point", ".")
    decimal_point = decimal_point if isinstance(decimal_point, str) else "."
    return (thousands if isinstance(thousands, str) else None), decimal_point


def _locate_changed_numeric_value(ctx: _Context) -> Target | NotApplicable:
    for check, spec, path, _, records, record, column, stored in _agreement_candidates(ctx):
        thousands, decimal_point = _marks(check)
        changed = _shift_stored_value(stored, thousands=thousands, decimal_point=decimal_point)
        if changed is None:
            continue
        return Target(
            f"change the stored {column!r} at {_key_label(record, spec)} of input {spec.input_id!r} from {stored} to "
            f"{changed}, a value that numeric_agreement check {check.check_id!r} cites{_redeclared(spec)}",
            ctx.input_edits(spec, path, records.with_value(record, column, changed)),
        )
    return NotApplicable("no numeric_agreement check cites a stored value that can be read as a number")


def _is_grouped(check: CheckSpec, stored: str) -> bool:
    thousands = _marks(check)[0]
    return thousands is not None and thousands in stored


def _locate_changed_numeric_formatting(ctx: _Context) -> Target | NotApplicable:
    candidates = [item for item in _agreement_candidates(ctx) if isinstance(item[7], str)]
    # Prefer a value printed with declared digit grouping: that is where a separator could evade comparison.
    grouped = [item for item in candidates if _is_grouped(item[0], item[7])]
    for check, spec, path, _, records, record, column, stored in grouped + candidates:
        thousands, decimal_point = _marks(check)
        swapped = _swap_marks(stored, thousands=thousands, decimal_point=decimal_point)
        if swapped == stored:
            continue
        return Target(
            f"reprint the stored {column!r} at {_key_label(record, spec)} of input {spec.input_id!r} from {stored!r} "
            f"to {swapped!r} (decimal and grouping marks exchanged), a value that numeric_agreement check "
            f"{check.check_id!r} cites{_redeclared(spec)}",
            ctx.input_edits(spec, path, records.with_value(record, column, swapped)),
        )
    return NotApplicable("no cited stored value is printed with a decimal or grouping mark")


def _locate_timezone_shift(ctx: _Context) -> Target | NotApplicable:
    found = ctx.role_document("time_sources")
    events = found[1].get("events") if found is not None and isinstance(found[1], dict) else None
    if not isinstance(events, list):
        return NotApplicable("the manifest declares no readable time sources")
    path, document = found
    for index, event in enumerate(events):
        shifted = _shifted_timezone(event.get("timezone")) if isinstance(event, dict) else None
        if shifted is None:
            continue
        mutated = copy.deepcopy(document)
        mutated["events"][index]["timezone"] = shifted
        return Target(
            f"shift the declared timezone of event {event.get('id')!r} in {path} from {event['timezone']!r} to "
            f"{shifted!r}, leaving its local time and recorded UTC unchanged",
            (FileEdit(path, _json_bytes(mutated)),),
        )
    return NotApplicable("no time event declares a fixed-offset timezone")


def _locate_removed_invocation(ctx: _Context) -> Target | NotApplicable:
    found = ctx.role_document("citations.log")
    invocations = found[1].get("invocations") if found is not None and isinstance(found[1], dict) else None
    if not isinstance(invocations, list) or not invocations:
        return NotApplicable("the manifest declares no citation verification log with invocation records")
    path, document = found
    removed = invocations[0]
    mutated = {**document, "invocations": invocations[1:]}
    who = removed.get("citation_id") if isinstance(removed, dict) else None
    return Target(
        f"remove the invocation record for citation {who!r} from {path}, leaving claimed_verified at "
        f"{document.get('claimed_verified')!r}",
        (FileEdit(path, _json_bytes(mutated)),),
    )


def _pass_summary(ctx: _Context) -> tuple[str, dict[str, Any]] | None:
    found = ctx.role_document("summary_claim")
    if found is None or not isinstance(found[1], dict) or found[1].get("status") != Status.PASS.value:
        return None
    return found


def _locate_summary_without_evidence(ctx: _Context) -> Target | NotApplicable:
    found = _pass_summary(ctx)
    pinned = found[1].get("pinned") if found is not None else None
    if not isinstance(pinned, dict) or not any(pinned.values()):
        return NotApplicable("the manifest declares no stored PASS summary that pins evidence")
    path, document = found
    mutated = {key: value for key, value in document.items() if key != "pinned"}
    return Target(
        f"remove every pinned digest from the stored PASS summary {path}, leaving its PASS status",
        (FileEdit(path, _json_bytes(mutated)),),
    )


def _locate_skipped_checker(ctx: _Context) -> Target | NotApplicable:
    required = [spec for spec in ctx.manifest.checks if spec.required]
    if not required:
        return NotApplicable("the manifest declares no required check")
    kinds = [spec.kind for spec in ctx.manifest.checks]
    # A kind used by one check only lets exactly one checker be skipped.
    spec = next((item for item in required if kinds.count(item.kind) == 1), required[0])
    return Target(
        f"replace the {spec.kind} checker behind required check {spec.check_id!r} with one that returns SKIPPED "
        "without examining anything",
        registry=MappingProxyType({**ctx.registry, spec.kind: SKIPPED_CHECKER}),
    )


def _describe_entry(entry: Mapping[str, Any]) -> str:
    return f"seq {entry.get('seq')}, the {entry.get('result')} entry of check {entry.get('check_id')!r}"


def _locate_truncated_ledger(ctx: _Context) -> Target | NotApplicable:
    entries = ctx.baseline.ledger.entries
    if not entries:
        return NotApplicable("the sealed baseline ledger has no entries")
    return Target(
        f"drop the last sealed ledger entry ({_describe_entry(entries[-1])}) and keep the original seal "
        f"(ledger_length {len(entries)})",
        ledger_entries=entries[:-1],
    )


def _locate_reordered_chain(ctx: _Context) -> Target | NotApplicable:
    entries = list(ctx.baseline.ledger.entries)
    if len(entries) < 3:
        return NotApplicable("the sealed baseline ledger has fewer than three entries to reorder")
    entries[1], entries[2] = entries[2], entries[1]
    return Target(
        f"swap sealed ledger entries 2 and 3 ({_describe_entry(entries[2])} and {_describe_entry(entries[1])}), "
        "leaving each entry's own hash intact; the invocations still read as plausibly interleaved",
        ledger_entries=tuple(entries),
    )


_DESIGN_AMENDMENT = b"\nSynthetic amendment injected by mutation M18: the design changed upstream.\n"


def _locate_changed_design(ctx: _Context) -> Target | NotApplicable:
    found = ctx.role_document("dependencies")
    nodes = found[1].get("nodes") if found is not None and isinstance(found[1], dict) else None
    if not isinstance(nodes, list):
        return NotApplicable("the manifest declares no readable dependency graph")
    for node in nodes:
        if not isinstance(node, dict) or node.get("kind") != "DESIGN" or not isinstance(node.get("path"), str):
            continue
        try:
            path = normalize_relpath(node["path"])
        except UnsafePathError:
            continue
        data = ctx.read(path)
        if data is not None:
            return Target(
                f"amend the file of DESIGN node {node.get('id')!r} ({path}) and leave its recorded_sha256 in "
                f"{found[0]} unchanged",
                (FileEdit(path, data + _DESIGN_AMENDMENT),),
            )
    return NotApplicable("no DESIGN node of the dependency graph has a readable file")


def _replaced_output(data: bytes, selector: Any) -> tuple[bytes, str]:
    """A replacement for a stored output: its selected number shifted by ten, or a marked copy."""
    try:
        document = strict_loads(data)
    except StrictJSONError:
        document = None
    located = _resolve_pointer(document, selector) if isinstance(selector, str) else None
    if located is not None:
        container, key = located
        changed = _shift_stored_value(container[key], thousands=None, decimal_point=".")
        if changed is not None:
            old = container[key]
            container[key] = changed
            return _json_bytes(document), f"its value at {selector} from {old} to {changed}"
    return data + b"\nreplaced by mutation M19\n", "its bytes"


def _locate_replaced_claim_output(ctx: _Context) -> Target | NotApplicable:
    found = ctx.role_document("claims")
    if found is None:
        return NotApplicable("the manifest declares no readable claim registry")
    for claim in _walk_objects(found[1]):
        output = claim.get("stored_output")
        if not isinstance(output, dict) or not isinstance(output.get("path"), str):
            continue
        try:
            path = normalize_relpath(output["path"])
        except UnsafePathError:
            continue
        data = ctx.read(path)
        if data is None:
            continue
        replacement, what = _replaced_output(data, output.get("selector"))
        return Target(
            f"replace the stored output {path} of claim {claim.get('claim_id')!r} (changing {what}) and leave the "
            "registry's recorded digest unchanged",
            (FileEdit(path, replacement),),
        )
    return NotApplicable("no registered claim has a readable stored output")


def _locate_metadata_change(ctx: _Context) -> Target | NotApplicable:
    summary = _pass_summary(ctx)
    if summary is None:
        return NotApplicable("the manifest declares no stored PASS summary to hold unchanged")
    unchanged = f"; the stored PASS summary {summary[0]} is left unchanged"
    found = _verdicts(ctx)
    if found is not None and found[2] and isinstance(found[2][0], dict):
        path, document, verdicts = found
        stamp = _different(verdicts[0].get("recorded_at"), "2026-06-30T00:00:00Z", "2026-07-01T00:00:00Z")
        mutated = copy.deepcopy(document)
        mutated["verdicts"][0]["recorded_at"] = stamp
        return Target(
            f"change the recorded_at metadata of the first verdict in {path} to {stamp}{unchanged}",
            (FileEdit(path, _json_bytes(mutated)),),
        )
    events = ctx.role_document("time_sources")
    if events is not None and isinstance(events[1], dict) and isinstance(events[1].get("events"), list):
        path, document = events
        first = document["events"][0] if document["events"] else None
        if isinstance(first, dict):
            label = _different(first.get("source"), "synthetic-relabelled-source", "synthetic-other-source")
            mutated = copy.deepcopy(document)
            mutated["events"][0]["source"] = label
            return Target(
                f"change the source label of event {first.get('id')!r} in {path} to {label!r}{unchanged}",
                (FileEdit(path, _json_bytes(mutated)),),
            )
    return _layout_change(ctx, summary[0], unchanged)


#: JSON evidence documents M20's fallback may re-lay-out, in the order it tries them.
_LAYOUT_ROLES = (
    "accepted_snapshot",
    "claims",
    "dependencies",
    "citations.entries",
    "citations.log",
    "citations.frozen",
)


def _layout_change(ctx: _Context, summary_path: str, unchanged: str) -> Target | NotApplicable:
    """Fallback for M20: rewrite a JSON evidence document's layout; its content stays identical."""
    for role in _LAYOUT_ROLES:
        found = ctx.role_document(role)
        if found is None or found[0] == summary_path:
            continue
        original = ctx.read(found[0])
        for indent in (4, None):
            rewritten = _json_bytes(found[1], indent)
            if rewritten != original:
                return Target(
                    f"rewrite the layout of {found[0]} (no metadata field was available; the content is identical)"
                    f"{unchanged}",
                    (FileEdit(found[0], rewritten),),
                )
    return NotApplicable("no declared JSON evidence document can be changed beneath the PASS summary")


@dataclass(frozen=True)
class Operator:
    """One mutation operator: the defect it injects, how it finds a target, and what must catch it."""

    mutation_id: str
    summary: str
    detector: Detector
    locate: Callable[[_Context], Target | NotApplicable] = field(repr=False, compare=False)


_FAIL, _ABSTAIN = Status.FAIL, Status.ABSTAIN

#: The operators, in :data:`OPERATOR_IDS` order.
OPERATORS: tuple[Operator, ...] = (
    Operator(
        "M01_empty_input",
        "A required input is emptied to zero bytes.",
        _detector("input:EMPTY", _ABSTAIN),
        _locate_empty_input,
    ),
    Operator(
        "M02_missing_expected_file",
        "A required input file is deleted.",
        _detector("input:MISSING", _ABSTAIN),
        _locate_missing_file,
    ),
    Operator(
        "M03_deleted_accepted_row",
        "A record accepted in the snapshot is deleted from its input.",
        _detector("check:snapshot_completeness", _FAIL, signals=[FailureMode.OMITTED_POPULATION.value]),
        _locate_deleted_accepted_row,
    ),
    Operator(
        "M04_duplicate_row",
        "A record is duplicated within its input.",
        _detector("check:duplicate_rows", _FAIL),
        _locate_duplicate_row,
    ),
    Operator(
        "M05_duplicate_reviewer_verdict",
        "A required reviewer's verdict is recorded twice.",
        _detector("check:reviewer_protocol", _ABSTAIN, signals=[Reason.PROTOCOL_BROKEN.value]),
        _locate_duplicate_verdict,
    ),
    Operator(
        "M06_missing_required_reviewer",
        "Every verdict of a required reviewer is removed.",
        _detector("check:reviewer_protocol", _ABSTAIN, signals=[Reason.PROTOCOL_BROKEN.value]),
        _locate_missing_reviewer,
    ),
    Operator(
        "M07_changed_source_hash",
        "An input's bytes change while its declared digest does not.",
        _detector("input:HASH_MISMATCH", _FAIL, signals=[Reason.SOURCE_MISMATCH.value]),
        _locate_changed_source_hash,
    ),
    Operator(
        "M08_changed_author",
        "The first author of a citation entry is replaced.",
        _detector("check:citation_metadata", _FAIL, signals=[Reason.SOURCE_MISMATCH.value]),
        _locate_changed_author,
    ),
    Operator(
        "M09_changed_doi",
        "A citation entry's DOI is changed to one that no frozen record holds.",
        _detector("check:citation_resolver", _ABSTAIN, signals=[Reason.SOURCE_UNAVAILABLE.value]),
        _locate_changed_doi,
    ),
    Operator(
        "M10_changed_numeric_value",
        "A stored value that a claim cites is changed.",
        _detector("check:numeric_agreement", _FAIL, signals=[Reason.SOURCE_MISMATCH.value]),
        _locate_changed_numeric_value,
    ),
    Operator(
        "M11_changed_numeric_formatting",
        "A cited stored value is reprinted with its decimal and grouping marks exchanged.",
        _detector(
            "check:numeric_agreement",
            _FAIL,
            _ABSTAIN,
            signals=[Reason.SOURCE_MISMATCH.value, Reason.REQUIRES_HUMAN_REVIEW.value],
        ),
        _locate_changed_numeric_formatting,
    ),
    Operator(
        "M12_timezone_shift",
        "An observation's declared timezone shifts by one hour.",
        _detector("check:time_source", _FAIL, signals=[Reason.SOURCE_MISMATCH.value]),
        _locate_timezone_shift,
    ),
    Operator(
        "M13_removed_invocation",
        "An invocation record behind a claimed citation verification is removed.",
        _detector(
            "check:verification_log",
            _ABSTAIN,
            _FAIL,
            signals=[FailureMode.NARRATED_VERIFICATION.value, Reason.UNVERIFIED.value],
        ),
        _locate_removed_invocation,
    ),
    Operator(
        "M14_pass_summary_without_evidence",
        "A stored PASS summary loses every pinned digest.",
        _detector(
            "check:summary_consistency",
            _ABSTAIN,
            signals=[FailureMode.NARRATED_VERIFICATION.value, FailureMode.VACUOUS_PASS.value],
        ),
        _locate_summary_without_evidence,
    ),
    Operator(
        "M15_skipped_required_checker",
        "A required checker is skipped instead of run.",
        _detector("contract:checks_executed", _ABSTAIN, signals=[Reason.PARTIAL_EXECUTION.value]),
        _locate_skipped_checker,
    ),
    Operator(
        "M16_truncated_ledger",
        "The sealed ledger loses its last entry.",
        _detector("invariant:ledger_chain_intact", _FAIL),
        _locate_truncated_ledger,
    ),
    Operator(
        "M17_reordered_hash_chain",
        "Two sealed ledger entries swap places.",
        _detector("invariant:ledger_chain_intact", _FAIL),
        _locate_reordered_chain,
    ),
    Operator(
        "M18_changed_upstream_design",
        "An upstream DESIGN artifact changes beneath its recorded digest.",
        _detector("check:dependency_currency", _FAIL, signals=[FailureMode.STALE_DEPENDENCY.value]),
        _locate_changed_design,
    ),
    Operator(
        "M19_replaced_stored_claim_output",
        "A registered claim's stored output is replaced.",
        _detector("check:claim_registry", _FAIL, _ABSTAIN, signals=[Reason.SOURCE_MISMATCH.value]),
        _locate_replaced_claim_output,
    ),
    Operator(
        "M20_metadata_change_under_unchanged_pass_summary",
        "Evidence metadata changes while the stored PASS summary stays the same.",
        _detector("check:summary_consistency", _FAIL, signals=[Reason.SOURCE_MISMATCH.value]),
        _locate_metadata_change,
    ),
)


def skipped_checker(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """The stand-in M15 registers for a required checker: it examines nothing and says so.

    It reports SKIPPED honestly. What M15 tests is that the PASS contract
    notices a required check that did not execute
    (``checks_executed != checks_expected``), not merely that the check abstained.
    """
    return CheckOutcome(
        execution_state=ExecutionState.SKIPPED,
        verdict=Status.ABSTAIN,
        reason=Reason.INSUFFICIENT_EVIDENCE,
        rows_examined=None,
        evidence={"skipped_by": "M15_skipped_required_checker"},
        diagnostics=(f"SKIPPED: mutation M15 replaced the {spec.kind} checker, so nothing was examined",),
    )


# ---------------------------------------------------------------------------
# Report types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutationRecord:
    """The outcome of one operator (section 10).

    Only an executed (CHECKED) mutation has an actual result, fired detectors
    and a definite ``detected``. For a skipped or not-applicable mutation they
    are None, so it can never be read as detected or as escaped.
    ``blind_spot`` is derived from ``detected`` and cannot disagree with it.
    """

    mutation_id: str
    description: str
    target: str | None
    expected_result: Mapping[str, Any]
    expected_detector: str
    applicable: bool
    execution_state: ExecutionState
    actual_result: Mapping[str, Any] | None = None
    detecting_invariants_fired: tuple[FiredDetector, ...] | None = None
    detected: bool | None = None
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.applicable != (self.execution_state is not ExecutionState.NOT_APPLICABLE):
            raise ValueError("a mutation is NOT_APPLICABLE exactly when it is not applicable")
        executed = self.execution_state is ExecutionState.CHECKED
        facts = (self.actual_result, self.detecting_invariants_fired, self.detected)
        if executed and any(fact is None for fact in facts):
            raise ValueError("an executed mutation needs an actual result, fired detectors and a detection outcome")
        if not executed and any(fact is not None for fact in facts):
            raise ValueError("a mutation that did not execute has no actual result and no detection outcome")

    @property
    def blind_spot(self) -> bool | None:
        return None if self.detected is None else not self.detected

    def to_dict(self) -> dict[str, Any]:
        fired = self.detecting_invariants_fired
        return {
            "mutation_id": self.mutation_id,
            "description": self.description,
            "target": self.target,
            "expected_result": dict(self.expected_result),
            "actual_result": None if self.actual_result is None else dict(self.actual_result),
            "applicable": self.applicable,
            "execution_state": self.execution_state.value,
            "expected_detector": self.expected_detector,
            "detecting_invariants_fired": None if fired is None else [item.to_dict() for item in fired],
            "detected": self.detected,
            "blind_spot": self.blind_spot,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class BaselineSummary:
    """What verifying the untouched copy showed. ``status`` is None when verify never ran."""

    status: Status | None
    reason: Reason | None
    run_id: str | None
    counters: Mapping[str, Any] = field(default_factory=dict)
    findings: tuple[Mapping[str, Any], ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return self.status is Status.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": None if self.status is None else self.status.value,
            "reason": None if self.reason is None else self.reason.value,
            "run_id": self.run_id,
            "counters": dict(self.counters),
            "findings": [dict(item) for item in self.findings],
            "diagnostics": list(self.diagnostics),
        }


_BASELINE_COUNTERS = ("expected_inputs", "inputs_opened", "rows_examined", "checks_expected", "checks_executed")


@dataclass(frozen=True)
class MutationReport:
    """The result of :func:`mutate`. Status, counts and sensitivity derive from the records."""

    manifest_name: str
    manifest_sha256: str | None
    generated_at: str
    baseline: BaselineSummary
    selected: tuple[str, ...]
    mutations: tuple[MutationRecord, ...] = ()
    diagnostics: tuple[str, ...] = ()
    #: The baseline run's ``run.json`` document, for the HTML view only. It is
    #: not part of the report body, so it never affects ``report_id``.
    baseline_run: Mapping[str, Any] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.baseline.valid and self.mutations:
            raise ValueError("no mutation runs against an invalid baseline")
        if self.baseline.valid and tuple(record.mutation_id for record in self.mutations) != OPERATOR_IDS:
            raise ValueError("a report with a valid baseline records every operator, in order")

    @property
    def executed(self) -> tuple[MutationRecord, ...]:
        return tuple(record for record in self.mutations if record.execution_state is ExecutionState.CHECKED)

    @property
    def counts(self) -> dict[str, int] | None:
        """The six counts, or None for an invalid baseline (the keys are then omitted entirely)."""
        if not self.baseline.valid:
            return None
        states = [record.execution_state for record in self.mutations]
        return {
            "applicable_mutations": sum(record.applicable for record in self.mutations),
            "executed_mutations": len(self.executed),
            "detected_mutations": sum(record.detected is True for record in self.mutations),
            "escaped_mutations": sum(record.detected is False for record in self.mutations),
            "skipped_mutations": states.count(ExecutionState.SKIPPED),
            "not_applicable_mutations": states.count(ExecutionState.NOT_APPLICABLE),
        }

    @property
    def sensitivity(self) -> dict[str, Any] | None:
        """detected/executed as an exact fraction and a decimal string; None without a valid baseline and execution."""
        counts = self.counts
        if counts is None or counts["executed_mutations"] == 0:
            return None
        detected, executed = counts["detected_mutations"], counts["executed_mutations"]
        decimal = (Decimal(detected) / Decimal(executed)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_EVEN)
        return {
            "detected": detected,
            "executed": executed,
            "fraction": f"{detected}/{executed}",
            "decimal": str(decimal),
            "decimal_rounding": "ROUND_HALF_EVEN to 4 places",
        }

    @property
    def status(self) -> Status:
        counts = self.counts
        if counts is None:
            return Status.FAIL
        if counts["executed_mutations"] == 0:
            return Status.ABSTAIN
        return Status.FAIL if counts["escaped_mutations"] else Status.PASS

    @property
    def reason(self) -> Reason:
        counts = self.counts
        if counts is None:
            return Reason.INVALID_BASELINE
        if counts["executed_mutations"] == 0:
            return Reason.INSUFFICIENT_EVIDENCE
        return Reason.BLIND_SPOT if counts["escaped_mutations"] else Reason.VERIFIED

    @property
    def exit_code(self) -> int:
        """0: valid baseline, no blind spot. 1: INVALID_BASELINE or any blind spot. 2: nothing executed."""
        return EXIT_CODE[self.status]

    @property
    def message(self) -> str:
        counts = self.counts
        if counts is None:
            return INVALID_BASELINE_MESSAGE
        if counts["executed_mutations"] == 0:
            return NO_EXECUTION_MESSAGE
        return (
            f"{counts['detected_mutations']} of {counts['executed_mutations']} executed mutations were detected by "
            f"their expected detector; {counts['escaped_mutations']} escaped as blind spots."
        )

    def _body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema": MUTATION_REPORT_SCHEMA,
            "status": self.status.value,
            "reason": self.reason.value,
            "exit_code": self.exit_code,
            "message": self.message,
            "manifest": {"file": self.manifest_name, "sha256": self.manifest_sha256},
            "generated_at": self.generated_at,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "baseline": self.baseline.to_dict(),
            "operators": list(OPERATOR_IDS),
            "selected_operators": list(self.selected),
            "network": "offline: every verify ran with a network opener that refuses all requests",
            "diagnostics": list(self.diagnostics),
            "not_proven": list(_NOT_PROVEN),
        }
        counts = self.counts
        if counts is not None:
            body.update(counts)
            body["sensitivity"] = self.sensitivity
            body["mutations"] = [record.to_dict() for record in self.mutations]
        return body

    @property
    def report_id(self) -> str:
        """``mut-`` plus 16 hex of the report's content hash: never random, stable under a fixed clock."""
        return "mut-" + sha256_canonical(self._body())[:16]

    def to_dict(self) -> dict[str, Any]:
        return {"report_id": self.report_id, **self._body()}


# ---------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------


def _refuse_network(*args: Any, **kwargs: Any) -> Any:
    """The opener every mutation verify runs with: mutation testing never touches the network."""
    raise OSError("network access is disabled during mutation testing")


_OFFLINE = NetworkPolicy(opener=_refuse_network)


class _TreeError(Exception):
    """The manifest's tree cannot be copied into the workspace."""


def _inside(path: Path, others: Sequence[Path]) -> bool:
    return any(is_within(other, path) for other in others)


def _copy_tree(source: Path, destination: Path, limits: Limits, exclude: Sequence[Path]) -> tuple[str, ...]:
    """Copy every regular file under ``source`` into ``destination`` through safe writes.

    Links that resolve outside the tree, and the excluded directories, are
    left out and listed in the returned notes. A tree with more than
    ``max_files`` files, or a file over ``max_file_bytes``, is refused: the
    tree is copied once per mutation, so it must be an evidence tree, not a
    home directory. Notes and errors name relative paths only.
    """
    if not source.is_dir():
        return ()
    root = source.resolve()
    notes: list[str] = []
    count = 0
    for directory, subdirectories, files in os.walk(root):
        current = Path(directory)
        kept = []
        for name in sorted(subdirectories):
            path = current / name
            relpath = path.relative_to(root).as_posix()
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError):
                resolved = None
            if resolved is None or not is_within(root, resolved):
                notes.append(f"LINK_SKIPPED: directory {relpath} resolves outside the tree")
            elif _inside(resolved, exclude):
                notes.append(f"EXCLUDED: directory {relpath} is the report's output directory")
            else:
                kept.append(name)
        subdirectories[:] = kept
        for name in sorted(files):
            path = current / name
            relpath = path.relative_to(root).as_posix()
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError):
                resolved = None
            if resolved is None or not is_within(root, resolved):
                notes.append(f"LINK_SKIPPED: file {relpath} resolves outside the tree")
                continue
            count += 1
            if count > limits.max_files:
                raise _TreeError(f"{_TREE_ERROR}: the tree holds more than max_files={limits.max_files} files")
            try:
                if path.stat().st_size > limits.max_file_bytes:
                    raise _TreeError(f"{_TREE_ERROR}: {relpath} exceeds max_file_bytes={limits.max_file_bytes}")
                data = path.read_bytes()
            except OSError as exc:
                problem = exc.strerror or type(exc).__name__
                raise _TreeError(f"{_TREE_ERROR}: {relpath} cannot be read ({problem})") from None
            try:
                safe_write(destination, relpath, data)
            except UnsafePathError as exc:
                raise _TreeError(f"{_TREE_ERROR}: {relpath} cannot be copied safely ({exc.code})") from None
    return tuple(notes)


def _apply(edits: Iterable[FileEdit], root: Path) -> None:
    for edit in edits:
        if edit.data is None:
            resolve_under_root(root, edit.path).unlink()
        else:
            safe_write(root, edit.path, edit.data)


class _Scrubber:
    """Removes the random workspace path from recorded text, so reports stay byte-identical across runs."""

    def __init__(self, workspace: Path) -> None:
        spellings = {str(workspace), str(workspace.resolve())}
        spellings |= {text.replace("\\", "/") for text in spellings}
        spellings |= {text.replace("\\", "\\\\") for text in spellings if "\\" in text}
        self._spellings = sorted(spellings, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for spelling in self._spellings:
            text = text.replace(spelling, "<workspace>")
        return text


def _replay_inputs(run: VerificationRun, entries: Sequence[Mapping[str, Any]]) -> DecisionInputs:
    """The decision inputs of a sealed run, with ``entries`` in place of its ledger and its original seal."""
    seal = run.ledger.seal()
    result = run.result
    return DecisionInputs(
        accounting=result.accounting,
        checks=result.checks,
        declared_checks={spec.check_id: spec.required for spec in run.manifest.checks} if run.manifest else None,
        entries=tuple(entries),
        ledger_head_sha256=seal["ledger_head_sha256"],
        ledger_length=seal["ledger_length"],
        run_id=result.run_id,
        evidence_manifest=run.evidence_manifest["entries"],
        rows_examined=result.counters.get("rows_examined"),
        claim_tallies=tuple(tally for _, tally in run.claim_tallies),
    )


def _outcome(
    status: Status,
    reason: Reason,
    reasons: Iterable[Reason],
    modes: Iterable[FailureMode],
    run_id: str | None,
    mode: str,
) -> dict[str, Any]:
    return {
        "mode": mode,
        "status": status.value,
        "reason": reason.value,
        "reasons": sorted(item.value for item in reasons),
        "failure_modes": sorted(item.value for item in modes),
        "run_id": run_id,
    }


class _Harness:
    """Runs each operator against the pristine copy of one accepted baseline."""

    def __init__(self, ctx: _Context, workspace: Path, selected: frozenset[str], scrub: _Scrubber) -> None:
        self.ctx = ctx
        self.workspace = workspace
        self.selected = selected
        self.scrub = scrub
        replay = decide(_replay_inputs(ctx.baseline, ctx.baseline.ledger.entries))
        self.replay_problem = (
            None
            if replay.status is Status.PASS
            else f"REPLAY_FAILED: the sealed baseline replays as {replay.status.value}, not PASS"
        )

    def run(self, operator: Operator) -> MutationRecord:
        common = {
            "mutation_id": operator.mutation_id,
            "description": operator.summary,
            "expected_result": operator.detector.expected_result(),
            "expected_detector": operator.detector.label,
        }
        located = operator.locate(self.ctx)
        if isinstance(located, NotApplicable):
            return MutationRecord(
                **common,
                target=None,
                applicable=False,
                execution_state=ExecutionState.NOT_APPLICABLE,
                diagnostics=(f"NOT_APPLICABLE: {located.reason}",),
            )
        skipped = {
            **common,
            "target": located.description,
            "applicable": True,
            "execution_state": ExecutionState.SKIPPED,
        }
        if operator.mutation_id not in self.selected:
            return MutationRecord(**skipped, diagnostics=("SKIPPED: the operator was not selected for this run",))
        if located.ledger_entries is not None and self.replay_problem is not None:
            return MutationRecord(**skipped, diagnostics=(f"SKIPPED: {self.replay_problem}",))
        try:
            actual, fired = self._execute(operator, located)
        except (OSError, SafeIOError, _TreeError) as exc:
            detail = self.scrub(f"{type(exc).__name__}: {exc}")
            return MutationRecord(**skipped, diagnostics=(f"SKIPPED: the mutant could not be built ({detail})",))
        detected = actual["status"] != Status.PASS.value and any(operator.detector.matches(item) for item in fired)
        diagnostics = () if detected else (self._escape_note(operator.detector, actual, fired),)
        return MutationRecord(
            **{**skipped, "execution_state": ExecutionState.CHECKED},
            actual_result=actual,
            detecting_invariants_fired=fired,
            detected=detected,
            diagnostics=diagnostics,
        )

    def _execute(self, operator: Operator, target: Target) -> tuple[dict[str, Any], tuple[FiredDetector, ...]]:
        baseline = self.ctx.baseline
        if target.ledger_entries is not None:
            decision = decide(_replay_inputs(baseline, target.ledger_entries))
            fired = fired_detectors(decision.findings, baseline.result.checks, baseline.result.accounting)
            actual = _outcome(
                decision.status,
                decision.reason,
                decision.reasons,
                decision.failure_modes,
                baseline.result.run_id,
                "sealed-run replay",
            )
            return actual, self._scrubbed(fired)
        mutant = self.workspace / operator.mutation_id
        try:
            _copy_tree(self.ctx.root, mutant, self.ctx.manifest.limits, ())
            _apply(target.edits, mutant)
            try:
                registry = target.registry or self.ctx.registry
                run = verify(mutant / self.ctx.manifest_name, network=_OFFLINE, registry=registry)
            except Exception as exc:  # an engine crash under a mutant is a finding about the verifier, not the harness
                message = self.scrub(f"VERIFIER_RAISED: {type(exc).__name__}: {exc}")
                crash = FiredDetector("verifier:crash", "verifier", Status.ERROR, Reason.PROTOCOL_BROKEN, (), message)
                broken = (Reason.PROTOCOL_BROKEN,)
                actual = _outcome(Status.ERROR, Reason.PROTOCOL_BROKEN, broken, (), None, "fresh copy")
                return actual, (crash,)
        finally:
            shutil.rmtree(mutant, ignore_errors=True)
        result = run.result
        fired = fired_detectors(run.findings, result.checks, result.accounting)
        actual = _outcome(
            result.status, result.reason, result.reasons, result.failure_modes, result.run_id, "fresh copy"
        )
        return actual, self._scrubbed(fired)

    def _scrubbed(self, fired: Iterable[FiredDetector]) -> tuple[FiredDetector, ...]:
        return tuple(dataclasses.replace(item, detail=self.scrub(item.detail)) for item in fired)

    @staticmethod
    def _escape_note(detector: Detector, actual: Mapping[str, Any], fired: Sequence[FiredDetector]) -> str:
        if actual["status"] == Status.PASS.value:
            return f"BLIND_SPOT: the mutant verified as PASS; expected {detector.describe()}"
        others = sorted({item.detector for item in fired})
        return (
            f"BLIND_SPOT: the mutant verified as {actual['status']}, but {detector.describe()} did not fire "
            f"(fired: {', '.join(others) or 'nothing'})"
        )


def _manifest_digest(path: Path) -> str | None:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError:
        return None


def _limits(path: Path, registry: Mapping[str, str]) -> Limits:
    """The manifest's own limits when it loads; the defaults otherwise (verify will then report why)."""
    try:
        return load_manifest(path, registered_kinds=registry).limits
    except ManifestError:
        return Limits()


def _scrubbed_value(value: Any, scrub: _Scrubber) -> Any:
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, Mapping):
        return {key: _scrubbed_value(item, scrub) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrubbed_value(item, scrub) for item in value]
    return value


def _baseline_document(run: VerificationRun, scrub: _Scrubber) -> dict[str, Any]:
    """The baseline's ``run.json`` document, for the page :func:`write_mutation_report` renders.

    The baseline run lives only in the deleted workspace, so its receipt is
    built here, unsigned, and never written. The page shows that receipt's
    content hash; ``report RUN_DIR`` cannot re-verify a run nobody wrote.
    """
    seal = run.ledger.seal()
    receipt = build_run_receipt(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"], environ={}
    )
    return _scrubbed_value(run_document(run, receipt), scrub)


def _baseline_summary(run: VerificationRun, scrub: _Scrubber) -> BaselineSummary:
    counters = {name: run.result.counters.get(name) for name in _BASELINE_COUNTERS}
    findings = tuple({**finding.to_dict(), "detail": scrub(finding.detail)} for finding in run.findings)
    return BaselineSummary(run.result.status, run.result.reason, run.result.run_id, counters, findings)


def mutate(
    manifest_path: str | Path,
    *,
    operators: Iterable[str] | None = None,
    registry: Mapping[str, str] = REGISTRY,
    exclude: Iterable[str | Path] = (),
) -> MutationReport:
    """Mutation-test the verifier against the evidence tree of ``manifest_path``.

    ``operators`` selects which applicable operators execute. The others are
    recorded as SKIPPED, and every operator is still checked for
    applicability. ``registry`` is passed to every verify, like
    :func:`~science_gate.verifier.verify`'s. ``exclude`` lists directories of
    the tree not to copy (the report's own output directory, say).
    Temporary copies live in the OS temporary directory and are removed
    before this function returns. The source tree is only ever read.
    """
    selected = OPERATOR_IDS if operators is None else tuple(operators)
    unknown = sorted(set(selected) - set(OPERATOR_IDS))
    if unknown:
        raise ValueError(f"unknown mutation operator(s) {unknown}; known: {list(OPERATOR_IDS)}")
    source = Path(manifest_path)
    generated_at = now()
    report = {
        "manifest_name": source.name,
        "manifest_sha256": _manifest_digest(source),
        "generated_at": generated_at,
        "selected": tuple(item for item in OPERATOR_IDS if item in selected),
    }
    excluded = [Path(item).resolve() for item in exclude]
    with tempfile.TemporaryDirectory(prefix="science-gate-mutate-", ignore_cleanup_errors=True) as directory:
        workspace = Path(directory)
        scrub = _Scrubber(workspace)
        pristine = workspace / "baseline"
        try:
            notes = _copy_tree(source.parent, pristine, _limits(source, registry), excluded)
        except _TreeError as exc:
            return MutationReport(**report, baseline=BaselineSummary(None, None, None, diagnostics=(str(exc),)))
        baseline = verify(pristine / source.name, network=_OFFLINE, registry=registry)
        summary = _baseline_summary(baseline, scrub)
        report["baseline_run"] = _baseline_document(baseline, scrub)
        if not summary.valid or baseline.manifest is None:
            return MutationReport(**report, baseline=summary, diagnostics=notes)
        harness = _Harness(_Context(pristine, source.name, baseline, registry), workspace, frozenset(selected), scrub)
        records = tuple(harness.run(operator) for operator in OPERATORS)
    return MutationReport(**report, baseline=summary, mutations=records, diagnostics=notes)


# ---------------------------------------------------------------------------
# Rendering and the command
# ---------------------------------------------------------------------------


def _line(value: Any) -> str:
    """One line of text: recorded values can hold newlines, which must never start a heading."""
    return _WHITESPACE.sub(" ", "unknown" if value is None else str(value)).strip()


def _fired_line(item: FiredDetector) -> str:
    modes = f" [{', '.join(mode.value for mode in item.failure_modes)}]" if item.failure_modes else ""
    return f"{item.detector} ({item.source}) {item.status.value} {item.reason.value}{modes}"


def _record_lines(record: MutationRecord) -> list[str]:
    lines = [f"- `{record.mutation_id}`: {_line(record.target or record.description)}"]
    lines.append(f"  - expected: {_line(record.expected_result.get('rule'))}")
    actual = record.actual_result
    if actual is not None:
        lines.append(f"  - actual: {actual['status']} ({actual['reason']}), {actual['mode']}")
    for item in record.detecting_invariants_fired or ():
        lines.append(f"  - fired: {_line(_fired_line(item))}")
    lines.extend(f"  - {_line(text)}" for text in record.diagnostics)
    return lines


def _section(title: str, records: Sequence[MutationRecord], empty: str) -> list[str]:
    lines = [f"## {title}", ""]
    for record in records:
        lines.extend(_record_lines(record))
    return [*lines, *([empty] if not records else []), ""]


def headline(report: MutationReport) -> str:
    """The one-line status headline ``science-gate mutate`` prints first."""
    start = f"{report.status.value} ({report.reason.value}) {report.report_id}"
    counts = report.counts
    if counts is None:
        baseline = report.baseline
        was = f"{baseline.status.value} ({baseline.reason.value})" if baseline.status else "not verified"
        return f"{start}: the accepting baseline was {was}. {INVALID_BASELINE_MESSAGE}"
    tail = f"{counts['skipped_mutations']} skipped, {counts['not_applicable_mutations']} not applicable"
    if report.sensitivity is None:
        return f"{start}: no mutation was executed ({tail}). {NO_EXECUTION_MESSAGE}"
    return (
        f"{start}: {counts['detected_mutations']}/{counts['executed_mutations']} executed mutations detected, "
        f"{counts['escaped_mutations']} blind spot(s), {tail}; sensitivity {report.sensitivity['fraction']}"
    )


def render_markdown(report: MutationReport) -> str:
    """The human report. Headings follow :data:`REPORT_HEADINGS`."""
    baseline = report.baseline
    lines = [
        "# Mutation report",
        "",
        "## STATUS",
        "",
        f"**{report.status.value}** ({report.reason.value}), exit code {report.exit_code}.",
        "",
        report.message,
        "",
        f"Report `{report.report_id}` for manifest `{_line(report.manifest_name)}` "
        f"(sha256 `{_line(report.manifest_sha256)}`), generated {report.generated_at}.",
        "",
        "## BASELINE",
        "",
    ]
    if baseline.status is None:
        lines.append("The untouched copy was never verified: the manifest's tree could not be copied.")
    else:
        lines.append(
            f"The untouched copy verified as **{baseline.status.value}** ({baseline.reason.value}), run "
            f"`{baseline.run_id}`: "
            + ", ".join(f"{name} {_line(baseline.counters.get(name))}" for name in _BASELINE_COUNTERS)
            + "."
        )
    lines.extend(
        f"- finding {_line(item['source'])}: {item['status']} {item['reason']}: {_line(item['detail'])}"
        for item in baseline.findings
    )
    lines.extend(f"- {_line(text)}" for text in (*baseline.diagnostics, *report.diagnostics))
    lines.append("")
    counts = report.counts
    if counts is not None:
        sensitivity = report.sensitivity
        figure = (
            f"{sensitivity['fraction']} = {sensitivity['decimal']} ({sensitivity['decimal_rounding']})."
            if sensitivity
            else NO_EXECUTION_MESSAGE
        )
        lines += ["## SENSITIVITY", "", figure, ""]
        lines += [f"- {name}: {counts[name]}" for name in COUNT_KEYS] + [""]
        by_state = {
            "DETECTED": [record for record in report.mutations if record.detected is True],
            "BLIND SPOTS": [record for record in report.mutations if record.detected is False],
            "SKIPPED": [record for record in report.mutations if record.execution_state is ExecutionState.SKIPPED],
            "NOT APPLICABLE": [
                record for record in report.mutations if record.execution_state is ExecutionState.NOT_APPLICABLE
            ],
        }
        empty = {
            "DETECTED": "No mutation was detected.",
            "BLIND SPOTS": "No executed mutation escaped.",
            "SKIPPED": "No applicable mutation was skipped.",
            "NOT APPLICABLE": "Every operator found a target.",
        }
        for title, records in by_state.items():
            lines += _section(title, records, empty[title])
    lines += ["## WHAT THIS RESULT DOES NOT PROVE", "", *(f"- {text}" for text in _NOT_PROVEN), ""]
    return "\n".join(lines)


def write_mutation_report(report: MutationReport, output_dir: str | Path) -> tuple[Path, ...]:
    """Write ``mutation-report.json``, ``mutation-report.md`` and ``mutation-report.html`` with safe writes.

    The page is the section 12 view: the baseline run's evidence boundary
    with the detected-versus-blind-spot constellation. Like ``report.html``
    it is a view, not evidence, so without an HTML renderer only the JSON
    and Markdown reports are written. Returns the paths in write order.
    """
    root = Path(output_dir)
    paths = [
        safe_write(root, MUTATION_REPORT_JSON, pretty_json_bytes(report.to_dict())),
        safe_write(root, MUTATION_REPORT_MD, render_markdown(report).encode("utf-8")),
    ]
    html, _ = render_html(report.baseline_run or {}, root, mutation=report.to_dict(), name=MUTATION_REPORT_HTML)
    if html is not None:
        paths.append(safe_write(root, MUTATION_REPORT_HTML, html.encode("utf-8")))
    return tuple(paths)


def _emit(stream: TextIO, text: str) -> None:
    """Write one line, escaping what the stream's encoding cannot represent (a legacy console code page)."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")


def cli_mutate(args: argparse.Namespace) -> int:
    """``science-gate mutate MANIFEST [--output DIR]``; returns the exit code.

    Writes ``mutation-report.json``, ``mutation-report.md`` and
    ``mutation-report.html`` into ``--output`` (default
    ``./science-gate-runs/<report_id>/``), then prints
    the headline and the paths. Exit 0 means a valid baseline and no blind
    spot. Exit 1 means INVALID_BASELINE or at least one blind spot. Exit 2
    means nothing executed. Exit 3 means the report could not be written.
    """
    output = Path(args.output) if args.output else None
    report = mutate(args.manifest, exclude=(output,) if output is not None else ())
    target = output if output is not None else Path(DEFAULT_OUTPUT_ROOT) / report.report_id
    try:
        paths = write_mutation_report(report, target)
    except (SafeIOError, OSError) as exc:
        _emit(sys.stdout, f"ERROR mutate: the {report.status.value} report could not be written to {target}: {exc}")
        return EXIT_CODE[Status.ERROR]
    _emit(sys.stdout, headline(report))
    for path in paths:
        _emit(sys.stdout, str(path))
    return report.exit_code
