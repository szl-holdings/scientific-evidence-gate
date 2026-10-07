"""Mutation testing of the verifier itself (ARCHITECTURE.md sections 10 and 17.12).

A verifier that has never been seen to fail proves nothing by passing. This
module injects known defects into copies of an accepted evidence tree and
records whether the verifier catches each one *for the right reason*. It
also refuses to trust its own bookkeeping: every number it reports must
balance, and the harness must catch a defect it planted itself before any
of its figures count.

1. **Baseline.** The manifest's directory tree is copied into a temporary
   workspace and verified. Unless that untouched copy is PASS, the report is
   INVALID_BASELINE. It then has no sensitivity figure and no count keys at
   all: a verifier that rejects good evidence cannot be credited with
   rejecting bad evidence.
2. **Forced detection.** ``M00_forced_detection`` runs next. It flips one
   hex digit of the baseline's sealed ledger head and replays the sealed run
   through :func:`~science_gate.verifier.decide`, which must report
   ``ledger_chain_intact``. A harness that cannot see a defect it planted
   itself is HARNESS_BLIND: no counts, no sensitivity figure. M00 is a
   control, never an operator, and it is never counted.
3. **Mutants.** Each of the twenty-one operators looks for its target in the
   pristine copy. An operator with no target is NOT_APPLICABLE. Otherwise
   :func:`apply_target`, the single application point, applies it: file
   edits to a fresh copy, or a tampered ledger to replay against a seal. A
   mutant whose raw digest equals the baseline's is NOOP_MUTATION (a harness
   defect); one equal to the baseline only after JSON canonicalization is
   CANONICALLY_EQUIVALENT; one equal to an earlier mutant is
   DUPLICATE_MUTANT. None of those is verified.
4. **Activation.** Every other file mutant is verified inside an audit
   recording of its own copy (:mod:`science_gate._audit`). It counts as
   DETECTED only if the status is not PASS, the operator's expected detector
   produced a matching finding, *and* every mutated path was read from the
   mutant copy. A verify that never touched its copy, or that detected
   without reading the mutated files, is NOT_ACTIVATED and is not executed.
   A verify that raises is VERIFIER_ERROR, never a detection. Every other
   executed mutant is a BLIND_SPOT, attributed to the stage where the defect
   stopped (:class:`~science_gate.models.PieStage`): never read, read but
   parsed identically, infecting but never reaching a check, or seen by a
   check that still let it through.
5. **Bookkeeping.** Each generated mutant has exactly one
   :class:`~science_gate.models.MutationStatus`. Two conservation identities
   over sorted id lists must hold: generated = executed + the seven
   unexecuted buckets, and executed = the five executed buckets. An
   imbalance is UNMEASURED_MUTANTS. Only DETECTED is a detection
   (:data:`~science_gate.models.COUNTS_AS_DETECTED`, a table hashed into the
   report id). Sensitivity is detected/executed, and is given only for a
   balanced report with at least one executed mutant.

The harness is itself mutated (:func:`mutate_harness`, extension #13): seven
known-wrong variants of it run over the same tree, and each must change the
result. A harness mutant that changes nothing shows the tree cannot tell that
defect of the harness apart from the honest harness.

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
import collections
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

from . import TOOL_NAME, __version__, _audit
from ._canonical import (
    CanonicalizationError,
    StrictJSONError,
    normalize,
    pretty_json_bytes,
    sha256_bytes,
    sha256_canonical,
    strict_loads,
)
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
from .discovery import OpenedInput, discover, row_key_of
from .invariants import parse_decimal
from .ledger import is_plan_entry, reseal
from .manifests import CheckSpec, InputSpec, Limits, Manifest, ManifestError, load_manifest
from .models import (
    COUNTS_AS_DETECTED,
    EXECUTED_MUTATION_STATUSES,
    EXIT_CODE,
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    CheckResult,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    InputAccounting,
    InputOverride,
    InputState,
    MutationStatus,
    PieStage,
    Ratio,
    Reason,
    SkipJustification,
    Status,
)
from .receipts import build_run_receipt
from .reports import render_html, run_document
from .verifier import (
    REGISTRY,
    CheckContext,
    CheckOutcome,
    CheckParamError,
    DecisionInputs,
    Finding,
    Findings,
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
    "HARNESS_REPORT_SCHEMA",
    "HARNESS_REPORT_JSON",
    "HARNESS_REPORT_MD",
    "INVALID_BASELINE_MESSAGE",
    "HARNESS_BLIND_MESSAGE",
    "UNMEASURED_MESSAGE",
    "NOT_ACTIVATED_MESSAGE",
    "NO_EXECUTION_MESSAGE",
    "COUNT_KEYS",
    "STATUS_COUNT_KEYS",
    "ALL_COUNT_KEYS",
    "UNEXECUTED_STATUSES",
    "OPERATOR_IDS",
    "FORCED_DETECTION_ID",
    "HARNESS_MUTANT_IDS",
    "SKIPPED_CHECKER",
    "DEFAULT_OUTPUT_ROOT",
    "REPORT_HEADINGS",
    "HARNESS_REPORT_HEADINGS",
    "FILE_MODE",
    "REGISTRY_MODE",
    "REPLAY_MODE",
    "Detector",
    "FiredDetector",
    "FileEdit",
    "Replay",
    "Target",
    "NotApplicable",
    "AppliedMutant",
    "apply_target",
    "Operator",
    "OPERATORS",
    "FORCED_DETECTION",
    "MutationRecord",
    "ForcedDetection",
    "BaselineSummary",
    "MutationReport",
    "conservation",
    "fired_detectors",
    "skipped_checker",
    "mutate",
    "HarnessRecord",
    "HarnessReport",
    "mutate_harness",
    "check_mutation_accounting",
    "falsify_mutation_accounting",
    "headline",
    "render_markdown",
    "write_mutation_report",
    "harness_headline",
    "render_harness_markdown",
    "write_harness_report",
    "cli_mutate",
]

MUTATION_REPORT_SCHEMA = "science-gate-mutation-report/v2"
MUTATION_REPORT_JSON = "mutation-report.json"
MUTATION_REPORT_MD = "mutation-report.md"
MUTATION_REPORT_HTML = "mutation-report.html"
HARNESS_REPORT_SCHEMA = "science-gate-harness-report/v1"
HARNESS_REPORT_JSON = "harness-report.json"
HARNESS_REPORT_MD = "harness-report.md"

#: Printed, verbatim, whenever the accepting baseline is not PASS (section 10).
INVALID_BASELINE_MESSAGE = "No sensitivity figure was produced because the verifier failed its accepting baseline."
#: Printed when M00_forced_detection was not detected (section 17.12, case 2).
HARNESS_BLIND_MESSAGE = (
    "No sensitivity figure was produced because the harness did not detect the defect it planted itself "
    "(M00_forced_detection)."
)
#: Printed when the conservation identities fail (section 17.12, case 3).
UNMEASURED_MESSAGE = "No sensitivity figure was produced because the mutation bookkeeping does not balance."
#: Printed when file mutants were verified but none read its own copy (section 17.12, case 4).
NOT_ACTIVATED_MESSAGE = (
    "No sensitivity figure was produced because no file mutant was activated: no verify read its mutant copy."
)
NO_EXECUTION_MESSAGE = "No sensitivity figure was produced because no mutation was executed."

#: The 0.1.0 count keys. A report without measured bookkeeping (INVALID_BASELINE,
#: HARNESS_BLIND) omits every count key.
COUNT_KEYS = (
    "applicable_mutations",
    "executed_mutations",
    "detected_mutations",
    "escaped_mutations",
    "skipped_mutations",
    "not_applicable_mutations",
)

#: One count key per status bucket that the 0.1.0 keys do not already name.
STATUS_COUNT_KEYS: Mapping[MutationStatus, str] = MappingProxyType(
    {
        MutationStatus.BLIND_SPOT: "blind_spot_mutations",
        MutationStatus.VERIFIER_ERROR: "verifier_error_mutations",
        MutationStatus.TIMED_OUT: "timed_out_mutations",
        MutationStatus.FLAKY: "flaky_mutations",
        MutationStatus.NOT_ACTIVATED: "not_activated_mutations",
        MutationStatus.NOOP_MUTATION: "noop_mutations",
        MutationStatus.CANONICALLY_EQUIVALENT: "canonically_equivalent_mutations",
        MutationStatus.DUPLICATE_MUTANT: "duplicate_mutations",
        MutationStatus.SUPPRESSED: "suppressed_mutations",
    }
)

#: Every count key of a measured report, in report order.
ALL_COUNT_KEYS = (*COUNT_KEYS, "generated_mutations", *STATUS_COUNT_KEYS.values())

#: The executed buckets, in the order the second identity lists them.
EXECUTED_STATUSES = (
    MutationStatus.DETECTED,
    MutationStatus.BLIND_SPOT,
    MutationStatus.VERIFIER_ERROR,
    MutationStatus.TIMED_OUT,
    MutationStatus.FLAKY,
)

#: Generated but not executed, in the order the first identity lists them.
UNEXECUTED_STATUSES = (
    MutationStatus.NOT_APPLICABLE,
    MutationStatus.SUPPRESSED,
    MutationStatus.NOOP_MUTATION,
    MutationStatus.CANONICALLY_EQUIVALENT,
    MutationStatus.DUPLICATE_MUTANT,
    MutationStatus.SKIPPED,
    MutationStatus.NOT_ACTIVATED,
)

#: The required operators, with their stable ids, in report order (sections 10 and 17.12).
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
    "M21_removed_plan",
)

#: The harness control that runs first after a valid baseline. Never an operator, never counted.
FORCED_DETECTION_ID = "M00_forced_detection"

#: The harness mutants of extension #13, in report order.
HARNESS_MUTANT_IDS = (
    "H01_apply_noop",
    "H02_status_only_detection",
    "H03_crash_credited",
    "H04_unexecuted_counted",
    "H05_baseline_unchecked",
    "H06_replay_reseals",
    "H07_reads_original_tree",
)

#: The registry target that M15 substitutes for a required checker.
SKIPPED_CHECKER = "science_gate.mutations:skipped_checker"

#: Where ``mutate`` writes without ``--output``: the root ``verify`` uses too
#: (``cli.DEFAULT_RUNS_DIR``, which a test keeps equal). It is not imported,
#: because a library module should not depend on the command line.
DEFAULT_OUTPUT_ROOT = "science-gate-runs"

#: The headings of ``mutation-report.md``, in order. An INVALID_BASELINE
#: report has only the first two and the last, and a HARNESS_BLIND report
#: the first three and the last, because nothing else happened.
REPORT_HEADINGS = (
    "STATUS",
    "BASELINE",
    "FORCED DETECTION",
    "SENSITIVITY",
    "CONSERVATION",
    "DETECTED",
    "BLIND SPOTS",
    "VERIFIER ERRORS",
    "NOT ACTIVATED",
    "NOT EXECUTED",
    "SKIPPED",
    "NOT APPLICABLE",
    "WHAT THIS RESULT DOES NOT PROVE",
)

#: The headings of ``harness-report.md``, in order.
HARNESS_REPORT_HEADINGS = ("STATUS", "HONEST HARNESS", "HARNESS MUTANTS", "WHAT THIS RESULT DOES NOT PROVE")

#: How a target changes what is verified: files of a copy, the checker registry, or a sealed ledger.
FILE_MODE = "file"
REGISTRY_MODE = "registry"
REPLAY_MODE = "replay"

_NOT_PROVEN = (
    "Mutation testing measures how this verifier reacted to the injected defects on this one evidence tree. "
    "Defects of other kinds, or the same defects in other trees, may still go undetected.",
    "A detected mutation shows that a detector fired, not that the evidence it guards is scientifically valid. "
    "Scientific validity is not established by this tool.",
    "Every verify ran offline with a network opener that refuses all requests; live citation lookups were not "
    "exercised.",
    "Activation is judged from file opens seen by one in-process audit hook. Reads made by a subprocess or by a C "
    "extension that bypasses Python's audited file APIs are invisible to it.",
    "Nothing was sampled and nothing was reused: every applicable operator was generated, applied and judged "
    "afresh in this call.",
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
class Replay:
    """A sealed ledger to replay through ``decide()``: ``entries`` judged against the seal given here.

    ``invocation_ids`` maps old invocation ids to new ones when the entries
    were resealed, so that the run's results can follow their invocations.
    """

    entries: tuple[Mapping[str, Any], ...]
    ledger_head_sha256: str | None
    ledger_length: int | None
    invocation_ids: Mapping[str, str] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        """SHA-256 of the canonical ``(entries, seal)``: the identity of a replay mutant."""
        seal = {"ledger_head_sha256": self.ledger_head_sha256, "ledger_length": self.ledger_length}
        return sha256_canonical({"entries": [dict(entry) for entry in self.entries], "seal": seal})


@dataclass(frozen=True)
class Target:
    """What an applicable operator will do, computed from the pristine copy.

    ``edits`` rewrite files in a fresh copy. ``registry`` replaces the check
    registry for that copy's verify. ``replay`` marks a sealed-run operator:
    a tampered copy of the baseline's ledger and the seal to judge it by.
    """

    description: str
    edits: tuple[FileEdit, ...] = ()
    registry: Mapping[str, str] | None = None
    replay: Replay | None = None

    @property
    def mode(self) -> str:
        """REPLAY_MODE, REGISTRY_MODE (a checker swapped, no file edited) or FILE_MODE."""
        if self.replay is not None:
            return REPLAY_MODE
        return REGISTRY_MODE if self.registry is not None and not self.edits else FILE_MODE


@dataclass(frozen=True)
class NotApplicable:
    """Why an operator has no target in this tree."""

    reason: str


@dataclass(frozen=True)
class AppliedMutant:
    """What :func:`apply_target` produced: the files of the mutant copy, or the ledger to replay.

    ``files`` maps every relative path of the copy to its SHA-256 (None for
    a replay). ``registry`` is the checker registry to verify with, None
    meaning the baseline's. ``replay`` is the ledger to replay, None meaning
    the baseline's own, as sealed: what applying nothing leaves.
    """

    files: Mapping[str, str] | None = None
    registry: Mapping[str, str] | None = None
    replay: Replay | None = None


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
# The operators (M01-M21) and the M00 control
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


def _sealed(ctx: _Context) -> tuple[tuple[Mapping[str, Any], ...], str | None, int | None]:
    """The baseline's sealed entries, head and length."""
    seal = ctx.baseline.ledger.seal()
    return tuple(ctx.baseline.ledger.entries), seal["ledger_head_sha256"], seal["ledger_length"]


def _locate_forced_detection(ctx: _Context) -> Target | NotApplicable:
    entries, head, length = _sealed(ctx)
    if not entries or not isinstance(head, str) or not head:
        return NotApplicable("the sealed baseline ledger has no head digest to flip")
    flipped = ("0" if head[0] != "0" else "1") + head[1:]
    return Target(
        f"flip the first hex digit of the sealed ledger head ({head[:12]}... to {flipped[:12]}...) and replay the "
        "sealed run against it",
        replay=Replay(entries, flipped, length),
    )


def _locate_truncated_ledger(ctx: _Context) -> Target | NotApplicable:
    entries, head, length = _sealed(ctx)
    if not entries:
        return NotApplicable("the sealed baseline ledger has no entries")
    return Target(
        f"drop the last sealed ledger entry ({_describe_entry(entries[-1])}) and keep the original seal "
        f"(ledger_length {len(entries)})",
        replay=Replay(entries[:-1], head, length),
    )


def _locate_reordered_chain(ctx: _Context) -> Target | NotApplicable:
    sealed, head, length = _sealed(ctx)
    entries = list(sealed)
    if len(entries) < 3:
        return NotApplicable("the sealed baseline ledger has fewer than three entries to reorder")
    entries[1], entries[2] = entries[2], entries[1]
    return Target(
        f"swap sealed ledger entries 2 and 3 ({_describe_entry(entries[2])} and {_describe_entry(entries[1])}), "
        "leaving each entry's own hash intact; the invocations still read as plausibly interleaved",
        replay=Replay(tuple(entries), head, length),
    )


def _locate_removed_plan(ctx: _Context) -> Target | NotApplicable:
    """M21: the ledger without its PLAN, resealed by a forger thorough enough to leave no chain evidence.

    Removing an entry renames every later invocation. Entry evidence also
    names invocations (a falsifier's terminal entry names its subject's), so
    the forger renames those too and reseals again over the rewritten
    evidence. Only a fact outside the chain, the missing PLAN, remains.
    """
    entries, _, _ = _sealed(ctx)
    if not entries or not is_plan_entry(entries[0]):
        return NotApplicable("the sealed baseline ledger does not open with a PLAN entry")
    run_id = ctx.baseline.result.run_id
    renames = reseal(entries[1:], run_id).invocation_ids
    rewritten = [{**entry, "evidence": _renamed(entry.get("evidence"), renames)} for entry in entries[1:]]
    resealed = reseal(rewritten, run_id)
    return Target(
        f"remove the PLAN entry and reseal the remaining {resealed.ledger_length} entries as one consistent chain "
        "(new seq, invocation ids, links and head), as a thorough forger would; the results follow their renamed "
        "invocations",
        replay=Replay(
            resealed.entries, resealed.ledger_head_sha256, resealed.ledger_length, resealed.invocation_ids
        ),
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
        # D1: an unjustified shortfall on a required planned check is FAIL / PARTIAL_EXECUTION.
        _detector("contract:checks_executed", _FAIL, signals=[Reason.PARTIAL_EXECUTION.value]),
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
    Operator(
        "M21_removed_plan",
        "The PLAN entry is removed and the ledger resealed around the gap.",
        _detector("invariant:plan_closure", _FAIL),
        _locate_removed_plan,
    ),
)

#: M00, the harness's own control: not an operator, never counted, never selectable.
FORCED_DETECTION = Operator(
    FORCED_DETECTION_ID,
    "One hex digit of the sealed ledger head is flipped and the sealed run replayed.",
    _detector("invariant:ledger_chain_intact", _FAIL),
    _locate_forced_detection,
)


def skipped_checker(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """The stand-in M15 registers for a required checker: it examines nothing and says so.

    It reports SKIPPED honestly, and deliberately carries no
    :class:`~science_gate.models.SkipJustification`: what M15 tests is that
    the PASS contract treats an unexplained shortfall on a required planned
    check as FAIL / PARTIAL_EXECUTION (decision D1), not merely that the
    check abstained.
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
# Mutant identity: tree digests
# ---------------------------------------------------------------------------


def _tree_files(root: Path) -> dict[str, str]:
    """Every regular file under ``root``, by POSIX relative path, with its SHA-256, sorted."""
    files: dict[str, str] = {}
    for directory, subdirectories, names in os.walk(root):
        subdirectories.sort()
        for name in sorted(names):
            path = Path(directory) / name
            files[path.relative_to(root).as_posix()] = sha256_bytes(path.read_bytes())
    return dict(sorted(files.items()))


def _mutant_digest(files: Mapping[str, str], registry: Mapping[str, str]) -> str:
    """The identity of a copy-verified mutant: its sorted ``[relpath, sha256]`` pairs and its checker registry.

    The registry belongs to the mutant because M15 changes a checker, not a
    file. Without it, M15 would look byte-identical to the baseline.
    """
    return sha256_canonical(
        {
            "files": [[path, digest] for path, digest in sorted(files.items())],
            "registry": [[kind, target] for kind, target in sorted(registry.items())],
        }
    )


def _declared_digest_paths(root: Path, manifest_name: str) -> frozenset[str]:
    """Paths of inputs whose digest the manifest declares: their raw bytes are evidence, not layout."""
    try:
        document = strict_loads((root / manifest_name).read_bytes())
    except (OSError, StrictJSONError, UnicodeDecodeError):
        return frozenset()
    declared = set()
    inputs = document.get("inputs") if isinstance(document, dict) else None
    for item in inputs if isinstance(inputs, list) else ():
        if isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("sha256"), str):
            try:
                declared.add(normalize_relpath(item["path"]))
            except UnsafePathError:
                continue
    return frozenset(declared)


def _canonical_files(root: Path, files: Mapping[str, str], manifest_name: str) -> dict[str, str]:
    """``files`` with each JSON file whose digest the manifest does not declare replaced by its canonical digest.

    Two trees with equal canonical digests differ only in JSON layout (key
    order, whitespace), which no check is meant to read. A declared input
    keeps its raw digest: there the bytes themselves are the evidence.
    """
    declared = _declared_digest_paths(root, manifest_name)
    canonical: dict[str, str] = {}
    for relpath, digest in files.items():
        if relpath.endswith(".json") and relpath not in declared:
            try:
                digest = sha256_canonical(strict_loads((root / relpath).read_bytes()))
            except (OSError, StrictJSONError, CanonicalizationError, UnicodeDecodeError):
                pass
        canonical[relpath] = digest
    return canonical


def _mutated_paths(before: Mapping[str, str], after: Mapping[str, str]) -> tuple[str, ...]:
    """Paths added, removed or changed between two trees: what the mutant actually changed."""
    return tuple(sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path)))


def _path_key(relpath: str) -> str:
    """A relative path in the form the audit hook reports it (``os.path.normcase``d, ``/``-separated)."""
    return os.path.normcase(relpath).replace(os.sep, "/")


# ---------------------------------------------------------------------------
# Activation and infection (extension #11)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Reads:
    """What one mutant verify read from its own copy, from one audit recording."""

    opened: frozenset[str]
    value_reads: tuple[_audit.ValueRead, ...]

    @classmethod
    def of(cls, recorder: _audit.AuditRecorder, root: Path) -> _Reads:
        prefixes = sorted(
            {_audit.normalize_path(root).rstrip(os.sep), _audit.normalize_path(root, resolve=True).rstrip(os.sep)},
            key=len,
            reverse=True,
        )
        opened = set()
        for event in recorder.events:
            for prefix in prefixes:
                if event.path.startswith(prefix + os.sep):
                    opened.add(event.path[len(prefix) + 1 :].replace(os.sep, "/"))
                    break
        return cls(frozenset(opened), recorder.value_reads)


def _recorded_missing(run: VerificationRun, relpath: str) -> bool:
    """True when the run itself recorded ``relpath`` as MISSING: how a deleted file is "read"."""
    for record in run.result.accounting.records:
        if record.path == relpath and record.state is InputState.MISSING:
            return True
    return any(item.get("path") == relpath and item.get("state") == InputState.MISSING.value for item in run.documents)


class _TreeView:
    """Parsed views of one tree's files, for infection analysis. Each view is computed at most once."""

    def __init__(self, root: Path, manifest: Manifest | None, manifest_name: str) -> None:
        self.root = root
        self.manifest = manifest
        self.manifest_name = manifest_name
        self._opened: Mapping[str, OpenedInput] | None = None

    @property
    def inputs_by_path(self) -> dict[str, str]:
        if self.manifest is None:
            return {}
        found = {}
        for spec in self.manifest.inputs:
            try:
                found[normalize_relpath(spec.path)] = spec.input_id
            except UnsafePathError:
                continue
        return found

    def opened(self) -> Mapping[str, OpenedInput]:
        """The declared inputs as discovery admits them (computed once, outside any recording)."""
        if self._opened is None:
            self._opened = {} if self.manifest is None else discover(self.manifest)[1]
        return self._opened

    def rows(self, input_id: str) -> tuple[Any, ...] | None:
        opened = self.opened().get(input_id)
        return None if opened is None else opened.rows

    def parsed_digest(self, relpath: str) -> str | None:
        """What a check could see of ``relpath``: admitted rows of an input, a parsed document, else the bytes.

        For the manifest, re-declared input digests are left out: an operator
        that re-declares a digest does so only to keep the mutant examinable,
        and that bookkeeping is not an infection.
        """
        input_id = self.inputs_by_path.get(relpath)
        if input_id is not None:
            opened = self.opened().get(input_id)
            if opened is None or opened.rows is None:
                return None
            try:
                return sha256_canonical([row.values for row in opened.rows])
            except CanonicalizationError:  # e.g. an integer beyond the canonical bound: fall back to the bytes
                return opened.sha256
        try:
            data = (self.root / relpath).read_bytes()
        except OSError:
            return None
        try:
            parsed = strict_loads(data)
        except (StrictJSONError, UnicodeDecodeError):
            return sha256_bytes(data)
        if relpath == self.manifest_name and isinstance(parsed, dict) and isinstance(parsed.get("inputs"), list):
            parsed = {
                **parsed,
                "inputs": [
                    {key: value for key, value in item.items() if key != "sha256"} if isinstance(item, dict) else item
                    for item in parsed["inputs"]
                ],
            }
        try:
            return sha256_canonical(parsed)
        except CanonicalizationError:
            return sha256_bytes(data)


def _changed_cells(before: Sequence[Any] | None, after: Sequence[Any] | None) -> set[tuple[int, str]]:
    """``(row index, column)`` of every admitted cell that differs; ``"*"`` marks a whole row."""
    old = {row.index: row.values for row in before or ()}
    new = {row.index: row.values for row in after or ()}
    cells: set[tuple[int, str]] = set()
    for index in set(old) | set(new):
        first, second = old.get(index), new.get(index)
        if first == second:
            continue
        if isinstance(first, Mapping) and isinstance(second, Mapping):
            cells |= {(index, column) for column in set(first) | set(second) if first.get(column) != second.get(column)}
        else:
            cells.add((index, "*"))
    return cells


def _stable(value: Any) -> Any:
    """``value`` without invocation ids, which differ between any two runs and say nothing about content."""
    if isinstance(value, Mapping):
        return {key: _stable(item) for key, item in value.items() if key != "invocation_id"}
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    return value


def _pie_stage(*, read: bool, infected: bool, propagated: bool) -> PieStage:
    """Where an undetected defect stopped, in the order a defect must travel."""
    if not read:
        return PieStage.NOT_READ
    if not infected:
        return PieStage.READ_NOT_INFECTED
    if not propagated:
        return PieStage.INFECTED_NOT_PROPAGATED
    return PieStage.PROPAGATED_NOT_CHECKED


# ---------------------------------------------------------------------------
# Report types
# ---------------------------------------------------------------------------

#: Statuses whose verify (or replay) actually ran to an outcome that is recorded.
_OBSERVED_STATUSES = frozenset(EXECUTED_MUTATION_STATUSES | {MutationStatus.NOT_ACTIVATED})
#: Statuses with no mutant at all: nothing was applied, so there is no digest.
_UNBUILT_STATUSES = frozenset({MutationStatus.NOT_APPLICABLE, MutationStatus.SKIPPED, MutationStatus.SUPPRESSED})


@dataclass(frozen=True)
class MutationRecord:
    """The outcome of one operator (sections 10 and 17.12): exactly one :class:`MutationStatus`.

    ``execution_state``, ``applicable``, ``detected`` and ``blind_spot``
    derive from the status, so they cannot disagree with it. Only an
    executed mutant has a definite ``detected``; for every other status it
    is None, so nothing unexecuted can ever be read as detected or escaped.
    A NOT_ACTIVATED mutant keeps the outcome its verify produced, as
    evidence of what ran, but it is not executed.
    """

    mutation_id: str
    description: str
    target: str | None
    expected_result: Mapping[str, Any]
    expected_detector: str
    status: MutationStatus
    actual_result: Mapping[str, Any] | None = None
    detecting_invariants_fired: tuple[FiredDetector, ...] | None = None
    activation: Mapping[str, Any] | None = None
    pie_stage: PieStage | None = None
    mutant_sha256: str | None = None
    mutant_canonical_sha256: str | None = None
    duplicate_of: str | None = None
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", MutationStatus(self.status))
        if self.pie_stage is not None:
            object.__setattr__(self, "pie_stage", PieStage(self.pie_stage))
        status = self.status
        if (self.target is None) != (status is MutationStatus.NOT_APPLICABLE):
            raise ValueError("a mutation has a target exactly when it is applicable")
        observed = status in _OBSERVED_STATUSES
        facts = (self.actual_result, self.detecting_invariants_fired, self.activation)
        if observed and any(fact is None for fact in facts):
            raise ValueError(f"a {status.value} mutation needs an actual result, fired detectors and an activation")
        if not observed and any(fact is not None for fact in facts):
            raise ValueError(f"a {status.value} mutation was never verified, so it has no outcome or activation")
        if (self.pie_stage is not None) != (status is MutationStatus.BLIND_SPOT):
            raise ValueError("a PIE stage is recorded for a BLIND_SPOT, and only for one")
        if (self.duplicate_of is not None) != (status is MutationStatus.DUPLICATE_MUTANT):
            raise ValueError("duplicate_of names the earlier mutant of a DUPLICATE_MUTANT, and only of one")
        digests = (self.mutant_sha256, self.mutant_canonical_sha256)
        if status in _UNBUILT_STATUSES and any(digest is not None for digest in digests):
            raise ValueError(f"a {status.value} mutation was never built, so it has no digest")
        if status not in _UNBUILT_STATUSES and any(digest is None for digest in digests):
            raise ValueError(f"a {status.value} mutation was built, so it has both digests")

    @property
    def executed(self) -> bool:
        return self.status in EXECUTED_MUTATION_STATUSES

    @property
    def applicable(self) -> bool:
        return self.status is not MutationStatus.NOT_APPLICABLE

    @property
    def execution_state(self) -> ExecutionState:
        if self.executed:
            return ExecutionState.CHECKED
        return ExecutionState.NOT_APPLICABLE if not self.applicable else ExecutionState.SKIPPED

    @property
    def detected(self) -> bool | None:
        return COUNTS_AS_DETECTED[self.status] if self.executed else None

    @property
    def blind_spot(self) -> bool | None:
        return self.status is MutationStatus.BLIND_SPOT if self.executed else None

    def to_dict(self) -> dict[str, Any]:
        fired = self.detecting_invariants_fired
        return {
            "mutation_id": self.mutation_id,
            "description": self.description,
            "target": self.target,
            "status": self.status.value,
            "expected_result": dict(self.expected_result),
            "actual_result": None if self.actual_result is None else dict(self.actual_result),
            "applicable": self.applicable,
            "execution_state": self.execution_state.value,
            "expected_detector": self.expected_detector,
            "detecting_invariants_fired": None if fired is None else [item.to_dict() for item in fired],
            "detected": self.detected,
            "blind_spot": self.blind_spot,
            "activation": None if self.activation is None else dict(self.activation),
            "pie_stage": None if self.pie_stage is None else self.pie_stage.value,
            "mutant_sha256": self.mutant_sha256,
            "mutant_canonical_sha256": self.mutant_canonical_sha256,
            "duplicate_of": self.duplicate_of,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class ForcedDetection:
    """M00: the harness's own planted defect, and whether it saw it (extension #4)."""

    target: str | None
    detected: bool
    fired: tuple[FiredDetector, ...] = ()
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "mutation_id": FORCED_DETECTION_ID,
            "target": self.target,
            "detected": self.detected,
            "detector": FORCED_DETECTION.detector.label,
            "fired": [item.to_dict() for item in self.fired],
        }


@dataclass(frozen=True)
class BaselineSummary:
    """What verifying the untouched copy showed. ``status`` is None when verify never ran.

    ``digests`` identifies the baseline the mutants are compared with: its
    raw and canonical tree digests and the digest of its sealed ledger.
    """

    status: Status | None
    reason: Reason | None
    run_id: str | None
    counters: Mapping[str, Any] = field(default_factory=dict)
    findings: tuple[Mapping[str, Any], ...] = ()
    diagnostics: tuple[str, ...] = ()
    digests: Mapping[str, str | None] = field(default_factory=dict)

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
            "digests": dict(self.digests),
        }


_BASELINE_COUNTERS = ("expected_inputs", "inputs_opened", "rows_examined", "checks_expected", "checks_executed")


def conservation(
    generated: Iterable[str], executed: Iterable[str], buckets: Mapping[MutationStatus, Iterable[str]]
) -> dict[str, Any]:
    """The two conservation identities of section 17.12, over sorted id lists.

    ``generated = executed ⊎ NOT_APPLICABLE ⊎ SUPPRESSED ⊎ NOOP_MUTATION ⊎
    CANONICALLY_EQUIVALENT ⊎ DUPLICATE_MUTANT ⊎ SKIPPED ⊎ NOT_ACTIVATED`` and
    ``executed = DETECTED ⊎ BLIND_SPOT ⊎ VERIFIER_ERROR ⊎ TIMED_OUT ⊎
    FLAKY``. The lists are compared as sorted multisets, so a mutant counted
    twice, or not at all, breaks an identity; ``disjoint`` additionally
    requires that no id sits in two buckets.
    """
    generated_ids = sorted(generated)
    executed_ids = sorted(executed)
    unexecuted = [item for status in UNEXECUTED_STATUSES for item in buckets.get(status, ())]
    executed_buckets = [item for status in EXECUTED_STATUSES for item in buckets.get(status, ())]
    every = [item for status in MutationStatus for item in buckets.get(status, ())]
    generated_holds = generated_ids == sorted(executed_ids + unexecuted)
    executed_holds = executed_ids == sorted(executed_buckets)
    disjoint = len(every) == len(set(every))
    return {
        "generated": generated_ids,
        "executed": executed_ids,
        "generated_holds": generated_holds,
        "executed_holds": executed_holds,
        "disjoint": disjoint,
        "holds": generated_holds and executed_holds and disjoint,
    }


@dataclass(frozen=True)
class MutationReport:
    """The result of :func:`mutate`. Status, counts, buckets and sensitivity all derive from the records.

    ``executed_partition`` is the set of statuses the bookkeeping counts as
    executed. It is :data:`~science_gate.models.EXECUTED_MUTATION_STATUSES`
    in every honest report; only the H04 harness mutant widens it, and the
    conservation identities then expose the inflated denominator.
    """

    manifest_name: str
    manifest_sha256: str | None
    generated_at: str
    baseline: BaselineSummary
    selected: tuple[str, ...]
    forced_detection: ForcedDetection | None = None
    mutations: tuple[MutationRecord, ...] = ()
    diagnostics: tuple[str, ...] = ()
    executed_partition: frozenset[MutationStatus] = EXECUTED_MUTATION_STATUSES
    #: The baseline run's ``run.json`` document, for the HTML view only. It is
    #: not part of the report body, so it never affects ``report_id``.
    baseline_run: Mapping[str, Any] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.baseline.valid and (self.mutations or self.forced_detection is not None):
            raise ValueError("nothing runs against an invalid baseline, not even the forced detection")
        if self.baseline.valid and self.forced_detection is None:
            raise ValueError("a valid baseline is always followed by the forced detection")
        if self.forced_detection is not None and not self.forced_detection.detected and self.mutations:
            raise ValueError("no operator runs once the harness has missed its own forced defect")

    @property
    def measured(self) -> bool:
        """True when the bookkeeping can be reported: a valid baseline and a harness that saw M00."""
        return self.baseline.valid and self.forced_detection is not None and self.forced_detection.detected

    @property
    def buckets(self) -> dict[MutationStatus, list[str]]:
        """Every :class:`MutationStatus`, with the sorted ids of the records in it."""
        grouped: dict[MutationStatus, list[str]] = {status: [] for status in MutationStatus}
        for record in self.mutations:
            grouped[record.status].append(record.mutation_id)
        return {status: sorted(ids) for status, ids in grouped.items()}

    @property
    def conservation(self) -> dict[str, Any]:
        generated = [record.mutation_id for record in self.mutations]
        executed = [record.mutation_id for record in self.mutations if record.status in self.executed_partition]
        return conservation(generated, executed, self.buckets)

    @property
    def counts(self) -> dict[str, int] | None:
        """Every count key, or None when the bookkeeping is not measured (the keys are then omitted)."""
        if not self.measured:
            return None
        buckets = self.buckets
        executed = len(self.conservation["executed"])
        detected = sum(1 for record in self.mutations if COUNTS_AS_DETECTED[record.status])
        counts = {
            "applicable_mutations": len(self.mutations) - len(buckets[MutationStatus.NOT_APPLICABLE]),
            "executed_mutations": executed,
            "detected_mutations": detected,
            "escaped_mutations": executed - detected,
            "skipped_mutations": len(buckets[MutationStatus.SKIPPED]),
            "not_applicable_mutations": len(buckets[MutationStatus.NOT_APPLICABLE]),
            "generated_mutations": len(self.mutations),
        }
        counts.update({key: len(buckets[status]) for status, key in STATUS_COUNT_KEYS.items()})
        return counts

    def _none_activated(self) -> bool:
        """File mutants reached a verdict, and not one of them read its own copy (case 4)."""
        verified = [
            record
            for record in self.mutations
            if record.activation is not None
            and record.activation.get("mode") in (FILE_MODE, REGISTRY_MODE)
            and record.status in (MutationStatus.DETECTED, MutationStatus.BLIND_SPOT, MutationStatus.NOT_ACTIVATED)
        ]
        return bool(verified) and all(record.status is MutationStatus.NOT_ACTIVATED for record in verified)

    def _decision(self) -> tuple[Status, Reason, str | None]:
        """Status, reason and the no-figure message, first match wins (section 17.12)."""
        if not self.baseline.valid:
            return Status.FAIL, Reason.INVALID_BASELINE, INVALID_BASELINE_MESSAGE
        if not self.measured:
            return Status.FAIL, Reason.HARNESS_BLIND, HARNESS_BLIND_MESSAGE
        if not self.conservation["holds"]:
            return Status.FAIL, Reason.UNMEASURED_MUTANTS, UNMEASURED_MESSAGE
        if self._none_activated():
            return Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, NOT_ACTIVATED_MESSAGE
        counts = self.counts or {}
        if not counts.get("executed_mutations"):
            return Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, NO_EXECUTION_MESSAGE
        buckets = self.buckets
        if buckets[MutationStatus.BLIND_SPOT]:
            return Status.FAIL, Reason.BLIND_SPOT, None
        unreliable = (MutationStatus.VERIFIER_ERROR, MutationStatus.TIMED_OUT, MutationStatus.FLAKY)
        if any(buckets[status] for status in unreliable):
            return Status.FAIL, Reason.PROTOCOL_BROKEN, None
        return Status.PASS, Reason.VERIFIED, None

    @property
    def status(self) -> Status:
        return self._decision()[0]

    @property
    def reason(self) -> Reason:
        return self._decision()[1]

    @property
    def exit_code(self) -> int:
        """0 PASS; 1 INVALID_BASELINE, HARNESS_BLIND, UNMEASURED_MUTANTS, a blind spot or a verifier error; 2 ABSTAIN.

        A report that cannot be written is the command's exit 3, not this property's.
        """
        return EXIT_CODE[self.status]

    @property
    def sensitivity(self) -> dict[str, Any] | None:
        """detected/executed as an exact fraction and a decimal string, only for a measured, balanced, executed run."""
        if self._decision()[2] is not None:
            return None
        counts = self.counts or {}
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
    def message(self) -> str:
        no_figure = self._decision()[2]
        if no_figure is not None:
            return no_figure
        counts = self.counts or {}
        return (
            f"{counts['detected_mutations']} of {counts['executed_mutations']} executed mutations were detected by "
            f"their expected detector; {counts['escaped_mutations']} escaped ({counts['blind_spot_mutations']} blind "
            f"spot(s), {counts['verifier_error_mutations']} verifier error(s))."
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
            "sampled": False,
            "reused": False,
            "counts_as_detected": {status.value: COUNTS_AS_DETECTED[status] for status in MutationStatus},
            "forced_detection": None if self.forced_detection is None else self.forced_detection.to_dict(),
            "diagnostics": list(self.diagnostics),
            "not_proven": list(_NOT_PROVEN),
        }
        counts = self.counts
        if counts is not None:
            body.update(counts)
            body["sensitivity"] = self.sensitivity
            body["buckets"] = {status.value: ids for status, ids in self.buckets.items()}
            body["conservation"] = self.conservation
            body["mutations"] = [record.to_dict() for record in self.mutations]
        return body

    @property
    def report_id(self) -> str:
        """``mut-`` plus 16 hex of the report's content hash, including the detection table: never random."""
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


class _ProbeCrash(RuntimeError):
    """Raised in place of a mutant's verify by the harness self-test's crash probe."""


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


def apply_target(target: Target, root: Path) -> AppliedMutant:
    """The single application point for every operator, M00 included (section 17.12).

    A replay target writes nothing and hands back its tampered ledger. Any
    other target's edits are written into ``root``, a fresh copy of the
    pristine tree, and the copy's file digests are returned. The harness
    looks this function up at call time, so a test double, or the H01
    harness mutant, can stand in for it.
    """
    if target.replay is not None:
        return AppliedMutant(replay=target.replay)
    _apply(target.edits, root)
    return AppliedMutant(files=_tree_files(root), registry=target.registry)


def _apply_nothing(target: Target, root: Path) -> AppliedMutant:
    """H01's application point: the tree stays as copied and the ledger as sealed."""
    return AppliedMutant() if target.replay is not None else AppliedMutant(files=_tree_files(root))


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


def _renamed(value: Any, renames: Mapping[str, str]) -> Any:
    """``value`` with every string that is a renamed invocation id replaced by its new id."""
    if isinstance(value, str):
        return renames.get(value, value)
    if isinstance(value, Mapping):
        return {key: _renamed(item, renames) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_renamed(item, renames) for item in value]
    return value


def _replay_inputs(run: VerificationRun, replay: Replay) -> DecisionInputs:
    """The decision inputs of a sealed run, with ``replay``'s entries judged against ``replay``'s seal.

    Every other recorded fact is the run's own, so only the ledger differs
    from what ``verify`` decided. When the ledger was resealed (M21), each
    result and its evidence follow their renamed invocations, as a thorough
    forger would make them: only facts the chain cannot rewrite remain to
    expose the edit.
    """
    renames = dict(replay.invocation_ids)
    result = run.result
    checks = result.checks
    controls = run.controls
    if renames:
        checks = tuple(
            dataclasses.replace(
                check,
                invocation_id=renames.get(check.invocation_id, check.invocation_id) if check.invocation_id else None,
                evidence=_renamed(check.evidence, renames),
            )
            for check in checks
        )
        controls = _renamed(controls, renames)
    return DecisionInputs(
        accounting=result.accounting,
        checks=checks,
        declared_checks={spec.check_id: spec.required for spec in run.manifest.checks} if run.manifest else None,
        entries=tuple(replay.entries),
        ledger_head_sha256=replay.ledger_head_sha256,
        ledger_length=replay.ledger_length,
        run_id=result.run_id,
        evidence_manifest=run.evidence_manifest["entries"],
        rows_examined=result.counters.get("rows_examined"),
        claim_tallies=tuple(tally for _, tally in run.claim_tallies),
        expected_plan=run.plan,
        pins=run.pins,
        controls=controls,
    )


def _actual(
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


@dataclass(frozen=True)
class _Behaviour:
    """How the harness behaves. :data:`_HONEST` is the real harness.

    Each harness mutant of extension #13 sets exactly one of the first seven
    fields, replacing one honest step with a known-wrong one;
    :func:`mutate_harness` is the only caller that sets them.
    ``crash_mutant_verifies`` is not a defect but a probe condition: it makes
    every mutant's verify raise, which no correct engine does on its own, so
    that crediting a crash (H03) becomes observable.
    """

    apply_nothing: bool = False  # H01: application changes nothing
    status_only_detection: bool = False  # H02: any non-PASS status counts as detection
    credit_crashes: bool = False  # H03: a raising verify counts as DETECTED
    count_generated_as_executed: bool = False  # H04: every generated mutant is counted as executed
    skip_baseline_check: bool = False  # H05: the baseline is assumed PASS without looking
    reseal_replays: bool = False  # H06: a tampered ledger is resealed before it is replayed
    verify_original_tree: bool = False  # H07: each mutant's verify reads the pristine tree
    crash_mutant_verifies: bool = False  # probe: every mutant's verify raises


_HONEST = _Behaviour()


class _Harness:
    """Runs M00 and then each operator against the pristine copy of one accepted baseline."""

    def __init__(
        self,
        ctx: _Context,
        workspace: Path,
        selected: frozenset[str],
        scrub: _Scrubber,
        *,
        behaviour: _Behaviour,
        falsifiers: Mapping[str, str] | None,
    ) -> None:
        self.ctx = ctx
        self.workspace = workspace
        self.selected = selected
        self.scrub = scrub
        self.behaviour = behaviour
        self.verify_options: dict[str, Any] = {"network": _OFFLINE}
        if falsifiers is not None:
            self.verify_options["falsifiers"] = falsifiers
        seal = ctx.baseline.ledger.seal()
        self.baseline_replay = Replay(
            tuple(ctx.baseline.ledger.entries), seal["ledger_head_sha256"], seal["ledger_length"]
        )
        self.baseline_files = _tree_files(ctx.root)
        self.baseline_view = _TreeView(ctx.root, ctx.manifest, ctx.manifest_name)
        canonical = _canonical_files(ctx.root, self.baseline_files, ctx.manifest_name)
        self.digests = {
            "tree_sha256": _mutant_digest(self.baseline_files, ctx.registry),
            "tree_canonical_sha256": _mutant_digest(canonical, ctx.registry),
            "ledger_sha256": self.baseline_replay.digest,
        }
        #: First mutant seen with each raw digest, for DUPLICATE_MUTANT.
        self.seen: dict[str, str] = {}
        replay = decide(_replay_inputs(ctx.baseline, self.baseline_replay))
        self.replay_problem = (
            None
            if replay.status is Status.PASS
            else f"REPLAY_FAILED: the sealed baseline replays as {replay.status.value}, not PASS"
        )

    # -- the steps the harness mutants replace ------------------------------

    def _apply(self, target: Target, root: Path) -> AppliedMutant:
        application = _apply_nothing if self.behaviour.apply_nothing else apply_target
        return application(target, root)

    def _replay_of(self, applied: AppliedMutant) -> Replay:
        """The ledger to replay: what was applied, or the baseline as sealed when nothing was."""
        replay = applied.replay or self.baseline_replay
        if not self.behaviour.reseal_replays:
            return replay
        resealed = reseal(replay.entries, self.ctx.baseline.result.run_id)
        renames = {old: resealed.invocation_ids.get(new, new) for old, new in replay.invocation_ids.items()}
        for old, new in resealed.invocation_ids.items():
            renames.setdefault(old, new)
        return Replay(resealed.entries, resealed.ledger_head_sha256, resealed.ledger_length, renames)

    def _detected(self, detector: Detector, actual: Mapping[str, Any], fired: Sequence[FiredDetector]) -> bool:
        """The 0.1.0 detection rule: not PASS, and the expected detector produced a matching finding."""
        if actual["status"] == Status.PASS.value:
            return False
        if self.behaviour.status_only_detection:
            return True
        return any(detector.matches(item) for item in fired)

    # -- M00 ------------------------------------------------------------------

    def forced_detection(self) -> ForcedDetection:
        """Plant M00 through the same application point as every operator, and require the chain to notice."""
        located = FORCED_DETECTION.locate(self.ctx)
        if isinstance(located, NotApplicable):
            return ForcedDetection(None, False, diagnostics=(f"NOT_APPLICABLE: {located.reason}",))
        actual, fired = self._replay_outcome(self._replay_of(self._apply(located, self.ctx.root)))
        detected = self._detected(FORCED_DETECTION.detector, actual, fired)
        note = () if detected else (self._escape_note(FORCED_DETECTION.detector, actual, fired),)
        return ForcedDetection(located.description, detected, fired, note)

    # -- operators ------------------------------------------------------------

    def run(self, operator: Operator) -> MutationRecord:
        common: dict[str, Any] = {
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
                status=MutationStatus.NOT_APPLICABLE,
                diagnostics=(f"NOT_APPLICABLE: {located.reason}",),
            )
        common["target"] = located.description
        if operator.mutation_id not in self.selected:
            note = "SKIPPED: the operator was not selected for this run"
            return MutationRecord(**common, status=MutationStatus.SKIPPED, diagnostics=(note,))
        if located.mode == REPLAY_MODE:
            if self.replay_problem is not None:
                note = f"SKIPPED: {self.replay_problem}"
                return MutationRecord(**common, status=MutationStatus.SKIPPED, diagnostics=(note,))
            return self._run_replay(operator, located, common)
        return self._run_copy(operator, located, common)

    def _novelty(
        self, mutation_id: str, raw: str, canonical: str, base_raw: str, base_canonical: str
    ) -> dict[str, Any]:
        """NOOP, CANONICALLY_EQUIVALENT or DUPLICATE status fields, or ``{}`` for a new mutant."""
        first = self.seen.setdefault(raw, mutation_id)
        if raw == base_raw:
            return {
                "status": MutationStatus.NOOP_MUTATION,
                "diagnostics": (
                    "NOOP_MUTATION: HARNESS_DEFECT: the mutant is byte-identical to the baseline, so the operator "
                    "changed nothing; it was not verified",
                ),
            }
        if canonical == base_canonical:
            return {
                "status": MutationStatus.CANONICALLY_EQUIVALENT,
                "diagnostics": (
                    "CANONICALLY_EQUIVALENT: the mutant differs from the baseline only in JSON layout; it was not "
                    "verified",
                ),
            }
        if first != mutation_id:
            return {
                "status": MutationStatus.DUPLICATE_MUTANT,
                "duplicate_of": first,
                "diagnostics": (f"DUPLICATE_MUTANT: byte-identical to the mutant of {first}; it was not verified",),
            }
        return {}

    def _replay_outcome(self, replay: Replay) -> tuple[dict[str, Any], tuple[FiredDetector, ...]]:
        baseline = self.ctx.baseline
        decision = decide(_replay_inputs(baseline, replay))
        fired = fired_detectors(decision.findings, baseline.result.checks, baseline.result.accounting)
        actual = _actual(
            decision.status,
            decision.reason,
            decision.reasons,
            decision.failure_modes,
            baseline.result.run_id,
            "sealed-run replay",
        )
        return actual, self._scrubbed(fired)

    def _run_replay(self, operator: Operator, target: Target, common: Mapping[str, Any]) -> MutationRecord:
        replay = self._replay_of(self._apply(target, self.ctx.root))
        digest = replay.digest
        built = {**common, "mutant_sha256": digest, "mutant_canonical_sha256": digest}
        base = self.digests["ledger_sha256"]
        novelty = self._novelty(operator.mutation_id, digest, digest, base, base)
        if novelty:
            return MutationRecord(**built, **novelty)
        actual, fired = self._replay_outcome(replay)
        detected = self._detected(operator.detector, actual, fired)
        outcome = {
            "actual_result": actual,
            "detecting_invariants_fired": fired,
            "activation": {"mode": REPLAY_MODE, "activated": True},
        }
        if detected:
            return MutationRecord(**built, **outcome, status=MutationStatus.DETECTED)
        # decide() reads every entry and the seal, so a missed replay defect was seen and not checked.
        return MutationRecord(
            **built,
            **outcome,
            status=MutationStatus.BLIND_SPOT,
            pie_stage=PieStage.PROPAGATED_NOT_CHECKED,
            diagnostics=(self._escape_note(operator.detector, actual, fired),),
        )

    def _run_copy(self, operator: Operator, target: Target, common: Mapping[str, Any]) -> MutationRecord:
        mutant = self.workspace / operator.mutation_id
        try:
            try:
                _copy_tree(self.ctx.root, mutant, self.ctx.manifest.limits, ())
                applied = self._apply(target, mutant)
                files = applied.files if applied.files is not None else _tree_files(mutant)
                registry = applied.registry if applied.registry is not None else self.ctx.registry
                canonical = _canonical_files(mutant, files, self.ctx.manifest_name)
            except (OSError, SafeIOError, _TreeError) as exc:
                detail = self.scrub(f"{type(exc).__name__}: {exc}")
                return MutationRecord(
                    **common,
                    status=MutationStatus.SKIPPED,
                    diagnostics=(f"SKIPPED: the mutant could not be built ({detail})",),
                )
            raw = _mutant_digest(files, registry)
            canonical_digest = _mutant_digest(canonical, registry)
            built = {**common, "mutant_sha256": raw, "mutant_canonical_sha256": canonical_digest}
            novelty = self._novelty(
                operator.mutation_id,
                raw,
                canonical_digest,
                self.digests["tree_sha256"],
                self.digests["tree_canonical_sha256"],
            )
            if novelty:
                return MutationRecord(**built, **novelty)
            return self._verify_copy(operator, target, built, mutant, files, registry)
        finally:
            shutil.rmtree(mutant, ignore_errors=True)

    def _verify_copy(
        self,
        operator: Operator,
        target: Target,
        built: Mapping[str, Any],
        mutant: Path,
        files: Mapping[str, str],
        registry: Mapping[str, str],
    ) -> MutationRecord:
        """Verify one mutant copy inside an audit recording of that copy, then judge activation and detection."""
        verified = (self.ctx.root if self.behaviour.verify_original_tree else mutant) / self.ctx.manifest_name
        run: VerificationRun | None = None
        crash: Exception | None = None
        with _audit.recording(under=[mutant], record_values=True) as recorder:
            try:
                if self.behaviour.crash_mutant_verifies:
                    raise _ProbeCrash("the harness self-test's crash probe replaced this verify")
                run = verify(verified, registry=registry, **self.verify_options)
            except Exception as exc:  # an engine crash under a mutant is a finding about the verifier, not the harness
                crash = exc
        reads = _Reads.of(recorder, mutant)
        mutated = _mutated_paths(self.baseline_files, files)
        spelled = {_path_key(path): path for path in (*self.baseline_files, *files)}
        read = [path for path in mutated if _path_key(path) in reads.opened or (run and _recorded_missing(run, path))]
        activation = {
            "mode": target.mode,
            "activated": bool(reads.opened),
            "files_read": sorted(spelled.get(key, key) for key in reads.opened),
            "mutated_paths": list(mutated),
            "mutated_paths_read": read,
            "value_reads": len(reads.value_reads),
        }
        if crash is not None or run is None:
            message = self.scrub(f"VERIFIER_RAISED: {type(crash).__name__}: {crash}")
            fired = (FiredDetector("verifier:crash", "verifier", Status.ERROR, Reason.PROTOCOL_BROKEN, (), message),)
            actual = _actual(Status.ERROR, Reason.PROTOCOL_BROKEN, (Reason.PROTOCOL_BROKEN,), (), None, "fresh copy")
            status = MutationStatus.DETECTED if self.behaviour.credit_crashes else MutationStatus.VERIFIER_ERROR
            outcome = {"actual_result": actual, "detecting_invariants_fired": fired, "activation": activation}
            return MutationRecord(**built, **outcome, status=status, diagnostics=(f"{status.value}: {message}",))
        result = run.result
        fired = self._scrubbed(fired_detectors(run.findings, result.checks, result.accounting))
        actual = _actual(
            result.status, result.reason, result.reasons, result.failure_modes, result.run_id, "fresh copy"
        )
        detected = self._detected(operator.detector, actual, fired)
        unread = [path for path in mutated if path not in read]
        activated = bool(reads.opened) and not (detected and unread)
        outcome = {
            "actual_result": actual,
            "detecting_invariants_fired": fired,
            "activation": {**activation, "activated": activated},
        }
        if not reads.opened:
            note = "NOT_ACTIVATED: the verify opened no file of the mutant copy"
            return MutationRecord(**built, **outcome, status=MutationStatus.NOT_ACTIVATED, diagnostics=(note,))
        if detected and unread:
            note = f"NOT_ACTIVATED: the expected detector fired, but {unread} was never read from the mutant copy"
            return MutationRecord(**built, **outcome, status=MutationStatus.NOT_ACTIVATED, diagnostics=(note,))
        if detected:
            return MutationRecord(**built, **outcome, status=MutationStatus.DETECTED)
        stage = self._stage(target, run, mutant, mutated, read, reads)
        note = self._escape_note(operator.detector, actual, fired)
        return MutationRecord(
            **built,
            **outcome,
            status=MutationStatus.BLIND_SPOT,
            pie_stage=stage,
            diagnostics=(f"{note} [{stage.value}]",),
        )

    def _stage(
        self,
        target: Target,
        run: VerificationRun,
        mutant: Path,
        mutated: Sequence[str],
        read: Sequence[str],
        reads: _Reads,
    ) -> PieStage:
        """Attribute a BLIND_SPOT to the PIE stage where its defect stopped.

        A registry mutant changes a checker rather than a file, so its defect
        is in the verifier from the start: only propagation is in question.
        """
        before = {check.check_id: _stable(check.evidence) for check in self.ctx.baseline.result.checks}
        after = {check.check_id: _stable(check.evidence) for check in run.result.checks}
        if target.mode == REGISTRY_MODE:
            return _pie_stage(read=True, infected=True, propagated=before != after)
        view = _TreeView(mutant, run.manifest, self.ctx.manifest_name)
        infected = any(self.baseline_view.parsed_digest(path) != view.parsed_digest(path) for path in mutated)
        inputs = self.baseline_view.inputs_by_path
        mutated_inputs = {inputs[path] for path in mutated if path in inputs}
        touched = False
        for input_id in sorted(mutated_inputs):
            cells = _changed_cells(self.baseline_view.rows(input_id), view.rows(input_id))
            touched = touched or any(
                item.input_id == input_id
                and ((item.row_index, item.column) in cells or (item.row_index, "*") in cells)
                for item in reads.value_reads
            )
        consumers = (
            set(before) | set(after)
            if any(path not in inputs for path in mutated)
            else {check.check_id for check in run.result.checks if mutated_inputs & set(check.inputs)}
        )
        changed = any(before.get(check_id) != after.get(check_id) for check_id in consumers)
        return _pie_stage(read=bool(read), infected=infected, propagated=touched or changed)

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
    falsifiers: Mapping[str, str] | None = None,
    exclude: Iterable[str | Path] = (),
) -> MutationReport:
    """Mutation-test the verifier against the evidence tree of ``manifest_path``.

    ``operators`` selects which applicable operators execute. The others are
    recorded as SKIPPED, and every operator is still checked for
    applicability. M00 is not an operator: it always runs after a valid
    baseline and cannot be deselected. ``registry`` and ``falsifiers`` are
    passed to every verify, like :func:`~science_gate.verifier.verify`'s
    (None keeps the verifier's own falsifiers). ``exclude`` lists
    directories of the tree not to copy (the report's own output directory,
    say). Temporary copies live in the OS temporary directory and are removed
    before this function returns. The source tree is only ever read.
    """
    return _mutate(
        manifest_path, operators=operators, registry=registry, falsifiers=falsifiers, exclude=exclude, behaviour=_HONEST
    )


def _mutate(
    manifest_path: str | Path,
    *,
    operators: Iterable[str] | None = None,
    registry: Mapping[str, str] = REGISTRY,
    falsifiers: Mapping[str, str] | None = None,
    exclude: Iterable[str | Path] = (),
    behaviour: _Behaviour,
) -> MutationReport:
    """:func:`mutate`, with the harness's behaviour as a parameter so that :func:`mutate_harness` can vary it."""
    selected = OPERATOR_IDS if operators is None else tuple(operators)
    unknown = sorted(set(selected) - set(OPERATOR_IDS))
    if unknown:
        raise ValueError(f"unknown mutation operator(s) {unknown}; known: {list(OPERATOR_IDS)}")
    source = Path(manifest_path)
    report: dict[str, Any] = {
        "manifest_name": source.name,
        "manifest_sha256": _manifest_digest(source),
        "generated_at": now(),
        "selected": tuple(item for item in OPERATOR_IDS if item in selected),
    }
    if behaviour.count_generated_as_executed:
        report["executed_partition"] = frozenset(MutationStatus)
    excluded = [Path(item).resolve() for item in exclude]
    verify_options: dict[str, Any] = {"network": _OFFLINE, "registry": registry}
    if falsifiers is not None:
        verify_options["falsifiers"] = falsifiers
    with tempfile.TemporaryDirectory(prefix="science-gate-mutate-", ignore_cleanup_errors=True) as directory:
        workspace = Path(directory)
        scrub = _Scrubber(workspace)
        pristine = workspace / "baseline"
        try:
            notes = _copy_tree(source.parent, pristine, _limits(source, registry), excluded)
        except _TreeError as exc:
            return MutationReport(**report, baseline=BaselineSummary(None, None, None, diagnostics=(str(exc),)))
        baseline = verify(pristine / source.name, **verify_options)
        summary = _baseline_summary(baseline, scrub)
        report["baseline_run"] = _baseline_document(baseline, scrub)
        if behaviour.skip_baseline_check and baseline.manifest is not None:
            summary = dataclasses.replace(summary, status=Status.PASS, reason=Reason.VERIFIED)
        if not summary.valid or baseline.manifest is None:
            return MutationReport(**report, baseline=summary, diagnostics=notes)
        harness = _Harness(
            _Context(pristine, source.name, baseline, registry),
            workspace,
            frozenset(selected),
            scrub,
            behaviour=behaviour,
            falsifiers=falsifiers,
        )
        summary = dataclasses.replace(summary, digests=dict(harness.digests))
        forced = harness.forced_detection()
        if not forced.detected:
            return MutationReport(**report, baseline=summary, forced_detection=forced, diagnostics=notes)
        records = tuple(harness.run(operator) for operator in OPERATORS)
    return MutationReport(**report, baseline=summary, forced_detection=forced, mutations=records, diagnostics=notes)


# ---------------------------------------------------------------------------
# Harness self-mutation (extension #13)
# ---------------------------------------------------------------------------

#: The probe every harness mutant runs over.
_GIVEN_TREE = "given tree"
#: H05's probe: the same tree with its first required input emptied, so the baseline is not PASS.
_EMPTIED_INPUT = "emptied first required input"
#: H03's probe: the same tree, with every mutant's verify raising.
_CRASHING_VERIFIER = "crashing verifier"


@dataclass(frozen=True)
class _HarnessMutant:
    harness_mutant_id: str
    description: str
    behaviour: _Behaviour
    probe: str | None = None


_HARNESS_MUTANTS: tuple[_HarnessMutant, ...] = (
    _HarnessMutant(
        "H01_apply_noop",
        "The application point changes nothing: copies stay pristine and replayed ledgers stay sealed.",
        _Behaviour(apply_nothing=True),
    ),
    _HarnessMutant(
        "H02_status_only_detection",
        "Any non-PASS status counts as a detection, whichever detector fired.",
        _Behaviour(status_only_detection=True),
    ),
    _HarnessMutant(
        "H03_crash_credited",
        "A verify that raises counts as DETECTED instead of VERIFIER_ERROR.",
        _Behaviour(credit_crashes=True),
        _CRASHING_VERIFIER,
    ),
    _HarnessMutant(
        "H04_unexecuted_counted",
        "Every generated mutant is counted as executed, including those that never ran.",
        _Behaviour(count_generated_as_executed=True),
    ),
    _HarnessMutant(
        "H05_baseline_unchecked",
        "The baseline is assumed PASS without looking, so mutants run against a rejecting verifier.",
        _Behaviour(skip_baseline_check=True),
        _EMPTIED_INPUT,
    ),
    _HarnessMutant(
        "H06_replay_reseals",
        "A tampered ledger is resealed before it is replayed, so its chain verifies again.",
        _Behaviour(reseal_replays=True),
    ),
    _HarnessMutant(
        "H07_reads_original_tree",
        "Each mutant's verify reads the pristine tree instead of the mutant copy.",
        _Behaviour(verify_original_tree=True),
    ),
)


@dataclass(frozen=True)
class HarnessRecord:
    """One harness mutant: whether any result of the honest harness changed under it, and what did."""

    harness_mutant_id: str
    description: str
    killed: bool
    differences: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.killed != bool(self.differences):
            raise ValueError("a harness mutant is killed exactly when some result differs")

    def to_dict(self) -> dict[str, Any]:
        return {
            "harness_mutant_id": self.harness_mutant_id,
            "description": self.description,
            "killed": self.killed,
            "differences": list(self.differences),
        }


@dataclass(frozen=True)
class HarnessReport:
    """The result of :func:`mutate_harness`: PASS only when every harness mutant was killed."""

    manifest_name: str
    manifest_sha256: str | None
    generated_at: str
    honest: tuple[Mapping[str, Any], ...]
    records: tuple[HarnessRecord, ...] = ()
    diagnostics: tuple[str, ...] = ()
    #: The honest harness's report on the given tree, so ``mutate --harness``
    #: can write it too. Its id is in ``honest``; the report itself is not part
    #: of the body, so it never affects ``report_id``.
    honest_report: MutationReport | None = field(default=None, compare=False, repr=False)

    @property
    def baseline_valid(self) -> bool:
        return bool(self.honest) and self.honest[0].get("reason") != Reason.INVALID_BASELINE.value

    @property
    def harness_sensitivity(self) -> Ratio:
        """killed/7. Unknown, never zero, when the honest harness had no valid baseline to judge against."""
        killed = sum(record.killed for record in self.records) if self.baseline_valid else None
        return Ratio(killed, len(HARNESS_MUTANT_IDS))

    @property
    def status(self) -> Status:
        complete = tuple(record.harness_mutant_id for record in self.records) == HARNESS_MUTANT_IDS
        killed = complete and all(record.killed for record in self.records)
        return Status.PASS if self.baseline_valid and killed else Status.FAIL

    @property
    def reason(self) -> Reason:
        if not self.baseline_valid:
            return Reason.INVALID_BASELINE
        return Reason.VERIFIED if self.status is Status.PASS else Reason.HARNESS_BLIND

    @property
    def exit_code(self) -> int:
        return EXIT_CODE[self.status]

    @property
    def message(self) -> str:
        if not self.baseline_valid:
            return (
                "No harness sensitivity was produced because the honest harness rejected its baseline. "
                + INVALID_BASELINE_MESSAGE
            )
        survivors = [record.harness_mutant_id for record in self.records if not record.killed]
        ratio = self.harness_sensitivity
        if not survivors:
            return f"Every harness mutant changed the result: harness sensitivity {ratio.fraction}."
        return (
            f"Harness sensitivity {ratio.fraction}: {', '.join(survivors)} left every result unchanged, so this tree "
            "cannot tell those harness defects apart from the honest harness."
        )

    def _body(self) -> dict[str, Any]:
        return {
            "schema": HARNESS_REPORT_SCHEMA,
            "status": self.status.value,
            "reason": self.reason.value,
            "exit_code": self.exit_code,
            "message": self.message,
            "manifest": {"file": self.manifest_name, "sha256": self.manifest_sha256},
            "generated_at": self.generated_at,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "harness_mutants": list(HARNESS_MUTANT_IDS),
            "honest": [dict(item) for item in self.honest],
            "records": [record.to_dict() for record in self.records],
            "harness_sensitivity": self.harness_sensitivity.to_dict(),
            "diagnostics": list(self.diagnostics),
            "not_proven": list(_HARNESS_NOT_PROVEN),
        }

    @property
    def report_id(self) -> str:
        """``har-`` plus 16 hex of the report's content hash."""
        return "har-" + sha256_canonical(self._body())[:16]

    def to_dict(self) -> dict[str, Any]:
        return {"report_id": self.report_id, **self._body()}


_HARNESS_NOT_PROVEN = (
    "A killed harness mutant shows that this tree's results depend on the harness step it replaced. It does not "
    "show that the honest harness has no other defect.",
    "The crash probe makes every mutant's verify raise, because a correct engine never raises on its own; "
    "crediting a crash is therefore judged on a probe, not on a real engine failure.",
    "Scientific validity is not established by this tool.",
)


def _summary(probe: str, report: MutationReport) -> dict[str, Any]:
    return {
        "probe": probe,
        "report_id": report.report_id,
        "status": report.status.value,
        "reason": report.reason.value,
        "counts": report.counts,
    }


def _differences(probe: str, honest: MutationReport, variant: MutationReport) -> list[str]:
    """Every difference in status, reason, a record's status or a count, each named after its probe."""
    found: list[str] = []
    for name in ("status", "reason"):
        before, after = getattr(honest, name).value, getattr(variant, name).value
        if before != after:
            found.append(f"{probe}: {name} {before} -> {after}")
    old = {record.mutation_id: record.status.value for record in honest.mutations}
    new = {record.mutation_id: record.status.value for record in variant.mutations}
    for mutation_id in sorted(set(old) | set(new)):
        if old.get(mutation_id) != new.get(mutation_id):
            found.append(f"{probe}: {mutation_id} {old.get(mutation_id, 'absent')} -> {new.get(mutation_id, 'absent')}")
    before_counts, after_counts = honest.counts or {}, variant.counts or {}
    for key in ALL_COUNT_KEYS:
        if before_counts.get(key) != after_counts.get(key):
            found.append(f"{probe}: {key} {before_counts.get(key, 'absent')} -> {after_counts.get(key, 'absent')}")
    return found


def _emptied_copy(
    source: Path, destination: Path, registry: Mapping[str, str], exclude: Sequence[Path]
) -> tuple[Path | None, str | None]:
    """A copy of the tree whose first required input is emptied, or None with the reason it cannot exist."""
    try:
        manifest = load_manifest(source, registered_kinds=registry)
    except ManifestError:
        return None, "the manifest does not load, so no required input can be emptied"
    spec = next((item for item in manifest.inputs if item.required), None)
    if spec is None:
        return None, "the manifest declares no required input to empty"
    try:
        _copy_tree(source.parent, destination, manifest.limits, exclude)
        safe_write(destination, normalize_relpath(spec.path), b"")
    except (OSError, SafeIOError, _TreeError) as exc:
        return None, f"the copy could not be built ({type(exc).__name__})"
    return destination / source.name, None


def mutate_harness(
    manifest_path: str | Path,
    *,
    registry: Mapping[str, str] = REGISTRY,
    falsifiers: Mapping[str, str] | None = None,
    exclude: Iterable[str | Path] = (),
) -> HarnessReport:
    """Mutate the mutation harness itself (extension #13) over the PASS-baseline tree of ``manifest_path``.

    The honest harness and each of the seven harness mutants run over the
    given tree. Two mutants need a condition the tree alone cannot supply:
    H05 also runs over a copy whose first required input was emptied (so the
    baseline is not PASS), and H03 also runs with every mutant's verify
    raising (no correct engine raises by itself). Each extra probe is run
    once with the honest harness too. A harness mutant is killed when its
    status, reason, any record's status or any count differs from the honest
    harness on the same probe. Every probe is offline and temporary.
    """
    source = Path(manifest_path)
    excluded = [Path(item).resolve() for item in exclude]
    generated_at = now()

    def run(path: Path, behaviour: _Behaviour) -> MutationReport:
        return _mutate(path, registry=registry, falsifiers=falsifiers, exclude=excluded, behaviour=behaviour)

    honest = run(source, _HONEST)
    base = {
        "manifest_name": source.name,
        "manifest_sha256": _manifest_digest(source),
        "generated_at": generated_at,
        "honest_report": honest,
    }
    if not honest.baseline.valid:
        return HarnessReport(**base, honest=(_summary(_GIVEN_TREE, honest),))
    with tempfile.TemporaryDirectory(prefix="science-gate-harness-", ignore_cleanup_errors=True) as directory:
        emptied, unavailable = _emptied_copy(source, Path(directory) / "emptied", registry, excluded)
        probes: dict[str, tuple[Path | None, Callable[[_Behaviour], _Behaviour]]] = {
            _EMPTIED_INPUT: (emptied, lambda behaviour: behaviour),
            _CRASHING_VERIFIER: (source, lambda behaviour: dataclasses.replace(behaviour, crash_mutant_verifies=True)),
        }
        honest_runs = {_GIVEN_TREE: honest}
        diagnostics = [] if unavailable is None else [f"PROBE_UNAVAILABLE: {_EMPTIED_INPUT}: {unavailable}"]
        records = []
        for mutant in _HARNESS_MUTANTS:
            differences = _differences(_GIVEN_TREE, honest, run(source, mutant.behaviour))
            path, condition = probes[mutant.probe] if mutant.probe is not None else (None, None)
            if mutant.probe is not None and path is not None and condition is not None:
                if mutant.probe not in honest_runs:
                    honest_runs[mutant.probe] = run(path, condition(_HONEST))
                variant = run(path, condition(mutant.behaviour))
                differences += _differences(mutant.probe, honest_runs[mutant.probe], variant)
            killed = bool(differences)
            records.append(HarnessRecord(mutant.harness_mutant_id, mutant.description, killed, tuple(differences)))
    honest_summaries = tuple(_summary(probe, report) for probe, report in honest_runs.items())
    return HarnessReport(**base, honest=honest_summaries, records=tuple(records), diagnostics=tuple(diagnostics))


# ---------------------------------------------------------------------------
# The mutation_accounting check (section 17.12)
# ---------------------------------------------------------------------------


class _AccountingFormatError(ValueError):
    """A mutation report whose structure cannot carry its own bookkeeping."""


@dataclass(frozen=True)
class _Accounting:
    """The parts of a mutation report that its bookkeeping is recomputed from."""

    report_id: Any
    records: tuple[tuple[str, MutationStatus], ...]
    buckets: Mapping[MutationStatus, tuple[str, ...]]
    stated_counts: Mapping[str, int]
    detection_table: Mapping[str, Any] | None


def _parse_accounting(report: Any) -> _Accounting:
    if not isinstance(report, Mapping):
        raise _AccountingFormatError("the input is not a JSON object")
    if report.get("schema") != MUTATION_REPORT_SCHEMA:
        raise _AccountingFormatError(f"schema must be {MUTATION_REPORT_SCHEMA!r}, got {report.get('schema')!r}")
    raw_buckets = report.get("buckets")
    if not isinstance(raw_buckets, Mapping):
        raise _AccountingFormatError("the report has no buckets, so its bookkeeping cannot be recomputed")
    known = {status.value for status in MutationStatus}
    unknown = sorted(set(raw_buckets) - known)
    if unknown:
        raise _AccountingFormatError(f"buckets names statuses outside the closed vocabulary: {unknown}")
    buckets: dict[MutationStatus, tuple[str, ...]] = {}
    for name, ids in raw_buckets.items():
        if not isinstance(ids, list) or any(not isinstance(item, str) for item in ids):
            raise _AccountingFormatError(f"buckets[{name!r}] must be a list of mutation ids")
        buckets[MutationStatus(name)] = tuple(ids)
    raw_records = report.get("mutations")
    if not isinstance(raw_records, list):
        raise _AccountingFormatError("the report has no list of mutation records")
    records = []
    for position, item in enumerate(raw_records, start=1):
        mutation_id = item.get("mutation_id") if isinstance(item, Mapping) else None
        status = item.get("status") if isinstance(item, Mapping) else None
        if not isinstance(mutation_id, str) or status not in known:
            raise _AccountingFormatError(
                f"record {position} lacks a mutation_id or a status from the closed vocabulary"
            )
        records.append((mutation_id, MutationStatus(status)))
    stated = {}
    for key in ALL_COUNT_KEYS:
        if key in report:
            value = report[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise _AccountingFormatError(f"{key} must be an integer")
            stated[key] = value
    table = report.get("counts_as_detected")
    if table is not None and not isinstance(table, Mapping):
        raise _AccountingFormatError("counts_as_detected must be an object")
    return _Accounting(report.get("report_id"), tuple(records), buckets, stated, table)


def _accounting_problems(parsed: _Accounting) -> tuple[dict[str, Any], list[str], bool]:
    """Recompute the identities from records and buckets: ``(conservation, problems, population omitted)``."""
    generated = [mutation_id for mutation_id, _ in parsed.records]
    executed = [mutation_id for mutation_id, status in parsed.records if status in EXECUTED_MUTATION_STATUSES]
    balance = conservation(generated, executed, parsed.buckets)
    problems: list[str] = []
    listed = collections.Counter(item for ids in parsed.buckets.values() for item in ids)
    expected = collections.Counter(generated)
    missing, extra = sorted((expected - listed).elements()), sorted((listed - expected).elements())
    if not balance["generated_holds"]:
        problems.append(
            f"IMBALANCE: generated != executed + unexecuted buckets; unlisted {missing}, unrecorded {extra}"
        )
    if not balance["executed_holds"]:
        problems.append("IMBALANCE: the executed records are not exactly the DETECTED, BLIND_SPOT, VERIFIER_ERROR, "
                        "TIMED_OUT and FLAKY buckets")
    if not balance["disjoint"]:
        repeated = sorted(item for item, count in listed.items() if count > 1)
        problems.append(f"OVERLAP: {repeated} sit in more than one bucket")
    for mutation_id, status in parsed.records:
        if mutation_id not in parsed.buckets.get(status, ()):
            problems.append(f"MISFILED: {mutation_id} has status {status.value}, but that bucket does not list it")
    if len(set(generated)) != len(generated):
        problems.append(f"DUPLICATE_RECORD: {sorted(item for item, count in expected.items() if count > 1)}")
    statuses = collections.Counter(status for _, status in parsed.records)
    recomputed = {
        "applicable_mutations": len(generated) - statuses[MutationStatus.NOT_APPLICABLE],
        "executed_mutations": len(executed),
        "detected_mutations": statuses[MutationStatus.DETECTED],
        "escaped_mutations": len(executed) - statuses[MutationStatus.DETECTED],
        "skipped_mutations": statuses[MutationStatus.SKIPPED],
        "not_applicable_mutations": statuses[MutationStatus.NOT_APPLICABLE],
        "generated_mutations": len(generated),
        **{key: statuses[status] for status, key in STATUS_COUNT_KEYS.items()},
    }
    for key, value in sorted(parsed.stated_counts.items()):
        if recomputed[key] != value:
            problems.append(f"COUNT_MISMATCH: {key} states {value}, the records give {recomputed[key]}")
    table = {status.value: COUNTS_AS_DETECTED[status] for status in MutationStatus}
    if parsed.detection_table is not None and dict(parsed.detection_table) != table:
        problems.append("DETECTION_TABLE_MISMATCH: counts_as_detected credits a status other than DETECTED")
    return balance, problems, bool(missing)


def _unexamined(
    state: ExecutionState, label: SkipJustification, detail: str, evidence: Mapping[str, Any]
) -> CheckOutcome:
    """A mutation_accounting result that examined nothing, labelled so the shortfall is justified (17.7)."""
    status, reason, modes = SKIP_JUSTIFICATION_OUTCOMES[label]
    return CheckOutcome(
        execution_state=state,
        verdict=status,
        reason=reason,
        failure_modes=modes,
        rows_examined=0,
        evidence={**evidence, SKIP_JUSTIFICATION_KEY: label.value},
        diagnostics=(detail,),
    )


#: How an input that cannot be examined labels the check's shortfall.
_UNEXAMINABLE: Mapping[InputState, SkipJustification] = MappingProxyType(
    {
        InputState.MISSING: SkipJustification.INPUT_UNAVAILABLE,
        InputState.REFUSED: SkipJustification.INPUT_UNAVAILABLE,
        InputState.OPEN_FAILED: SkipJustification.INPUT_UNAVAILABLE,
        InputState.PARSE_ERROR: SkipJustification.INPUT_UNAVAILABLE,
        InputState.HASH_MISMATCH: SkipJustification.SOURCE_REJECTED,
        InputState.EMPTY: SkipJustification.EMPTY_POPULATION,
        InputState.PARTIAL: SkipJustification.EVIDENCE_MALFORMED,
    }
)


def _report_input(ctx: CheckContext, spec: CheckSpec) -> tuple[str, OpenedInput | None]:
    """The one declared JSON input a mutation_accounting check reads; refuses any other wiring."""
    if spec.params:
        raise CheckParamError(f"UNKNOWN_PARAM: mutation_accounting does not accept {sorted(spec.params)}")
    if len(spec.inputs) != 1:
        raise CheckParamError("INVALID_INPUTS: mutation_accounting takes exactly one declared JSON input")
    input_id = spec.inputs[0]
    opened = ctx.inputs.get(input_id)
    if opened is not None and opened.spec.format != "json":
        raise CheckParamError(f"INVALID_INPUTS: input {input_id!r} must have format json, not {opened.spec.format}")
    return input_id, opened


def check_mutation_accounting(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Recompute a mutation report's bookkeeping from its own records and buckets (kind ``mutation_accounting``).

    The input is one declared JSON input holding a ``mutation-report.json``.
    Both conservation identities are recomputed: the generated ids come from
    the records, the executed ids from the records' statuses, and the rest
    from the buckets. An imbalance, an overlap, a record filed under another
    status, a stated count the records contradict, or a detection table
    that credits anything but DETECTED is FAIL / UNMEASURED_MUTANTS. A PASS
    says only that the report's bookkeeping balances, not that the verifier
    it measured detected anything. A report without buckets cannot be
    recomputed: SKIPPED, labelled EVIDENCE_MALFORMED.
    """
    input_id, opened = _report_input(ctx, spec)
    evidence: dict[str, Any] = {"input": input_id}
    if opened is None:
        detail = f"input {input_id!r} was never discovered"
        return _unexamined(ExecutionState.NOT_APPLICABLE, SkipJustification.INPUT_UNAVAILABLE, detail, evidence)
    evidence["input_sha256"] = opened.sha256
    if opened.state is not InputState.PARSED:
        label = _UNEXAMINABLE.get(opened.state, SkipJustification.INPUT_UNAVAILABLE)
        detail = f"input {input_id!r} is {opened.state.value}: no mutation report to recompute"
        return _unexamined(ExecutionState.NOT_APPLICABLE, label, detail, evidence)
    rows = opened.rows or ()
    if len(rows) != 1:
        detail = f"MALFORMED_REPORT: input {input_id!r} holds {len(rows)} records, not one mutation report object"
        return _unexamined(ExecutionState.SKIPPED, SkipJustification.EVIDENCE_MALFORMED, detail, evidence)
    try:
        parsed = _parse_accounting(rows[0].values)
    except _AccountingFormatError as exc:
        detail = f"MALFORMED_REPORT: {exc}"
        return _unexamined(ExecutionState.SKIPPED, SkipJustification.EVIDENCE_MALFORMED, detail, evidence)
    evidence["report_id"] = parsed.report_id
    if not parsed.records:
        detail = "the mutation report records no mutant, so there is no bookkeeping to recompute"
        return _unexamined(ExecutionState.NOT_APPLICABLE, SkipJustification.EMPTY_POPULATION, detail, evidence)
    balance, problems, omitted = _accounting_problems(parsed)
    evidence.update(
        {
            "records": len(parsed.records),
            "conservation": balance,
            "bucket_sizes": {status.value: len(parsed.buckets.get(status, ())) for status in MutationStatus},
            "problems": problems,
        }
    )
    findings = Findings()
    modes = (FailureMode.DEFECTIVE_VERIFICATION, *((FailureMode.OMITTED_POPULATION,) if omitted else ()))
    for problem in problems:
        findings.fail(Reason.UNMEASURED_MUTANTS, problem, *modes)
    return findings.outcome(rows_examined=len(parsed.records), evidence=evidence)


def falsify_mutation_accounting(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]:
    """The known-bad case for ``mutation_accounting``: one id removed from the first non-empty bucket.

    The mutant is then generated but listed nowhere, so the first identity
    must break and the check must answer FAIL / UNMEASURED_MUTANTS. Reads
    only through ``ctx``, writes nothing, and returns ``()`` when the input
    holds no report with a non-empty bucket.
    """
    if len(spec.inputs) != 1:
        return ()
    input_id = spec.inputs[0]
    opened = ctx.inputs.get(input_id)
    rows = opened.rows if opened is not None else None
    if not rows or len(rows) != 1 or not isinstance(rows[0].values, Mapping):
        return ()
    try:
        report = normalize(rows[0].values)
    except CanonicalizationError:
        return ()
    buckets = report.get("buckets")
    if not isinstance(buckets, dict):
        return ()
    for status in MutationStatus:
        ids = buckets.get(status.value)
        if isinstance(ids, list) and ids:
            removed = ids[0]
            changed = {**report, "buckets": {**buckets, status.value: ids[1:]}}
            case = FalsifierCase(
                case_id="drop-bucket-id",
                description=f"remove {removed!r} from the {status.value} bucket, leaving its record in place",
                expected_verdict=Status.FAIL,
                expected_reason=Reason.UNMEASURED_MUTANTS,
                inputs={input_id: InputOverride(rows=(changed,))},
            )
            return (case,)
    return ()


# ---------------------------------------------------------------------------
# Rendering and the command
# ---------------------------------------------------------------------------


def _line(value: Any) -> str:
    """One line of text: recorded values can hold newlines, which must never start a heading."""
    return _WHITESPACE.sub(" ", "unknown" if value is None else str(value)).strip()


def _fired_line(item: FiredDetector) -> str:
    modes = f" [{', '.join(mode.value for mode in item.failure_modes)}]" if item.failure_modes else ""
    return f"{item.detector} ({item.source}) {item.status.value} {item.reason.value}{modes}"


def _activation_line(activation: Mapping[str, Any]) -> str:
    if activation.get("mode") == REPLAY_MODE:
        return "activation: replay of the sealed run (activated)"
    state = "activated" if activation.get("activated") else "not activated"
    read, mutated = activation.get("mutated_paths_read") or [], activation.get("mutated_paths") or []
    return (
        f"activation: {activation.get('mode')} mutant, {state}; {len(activation.get('files_read') or [])} file(s) "
        f"read from the copy; mutated paths read {len(read)}/{len(mutated)}; {activation.get('value_reads')} value "
        "read(s)"
    )


def _record_lines(record: MutationRecord) -> list[str]:
    lines = [f"- `{record.mutation_id}` ({record.status.value}): {_line(record.target or record.description)}"]
    lines.append(f"  - expected: {_line(record.expected_result.get('rule'))}")
    actual = record.actual_result
    if actual is not None:
        lines.append(f"  - actual: {actual['status']} ({actual['reason']}), {actual['mode']}")
    for item in record.detecting_invariants_fired or ():
        lines.append(f"  - fired: {_line(_fired_line(item))}")
    if record.activation is not None:
        lines.append(f"  - {_line(_activation_line(record.activation))}")
    if record.pie_stage is not None:
        lines.append(f"  - stage: {record.pie_stage.value}")
    if record.duplicate_of is not None:
        lines.append(f"  - duplicate of: `{record.duplicate_of}`")
    lines.extend(f"  - {_line(text)}" for text in record.diagnostics)
    return lines


def _section(title: str, records: Sequence[MutationRecord], empty: str) -> list[str]:
    lines = [f"## {title}", ""]
    for record in records:
        lines.extend(_record_lines(record))
    return [*lines, *([empty] if not records else []), ""]


#: The record sections of a measured report: heading, statuses, text when empty.
_RECORD_SECTIONS: tuple[tuple[str, tuple[MutationStatus, ...], str], ...] = (
    ("DETECTED", (MutationStatus.DETECTED,), "No mutation was detected."),
    ("BLIND SPOTS", (MutationStatus.BLIND_SPOT,), "No executed mutation escaped as a blind spot."),
    (
        "VERIFIER ERRORS",
        (MutationStatus.VERIFIER_ERROR, MutationStatus.TIMED_OUT, MutationStatus.FLAKY),
        "No verify raised, timed out or flaked.",
    ),
    ("NOT ACTIVATED", (MutationStatus.NOT_ACTIVATED,), "Every verified mutant read its own copy."),
    (
        "NOT EXECUTED",
        (
            MutationStatus.NOOP_MUTATION,
            MutationStatus.CANONICALLY_EQUIVALENT,
            MutationStatus.DUPLICATE_MUTANT,
            MutationStatus.SUPPRESSED,
        ),
        "No mutant was a no-op, an equivalent, a duplicate or suppressed.",
    ),
    ("SKIPPED", (MutationStatus.SKIPPED,), "No applicable mutation was skipped."),
    ("NOT APPLICABLE", (MutationStatus.NOT_APPLICABLE,), "Every operator found a target."),
)


def headline(report: MutationReport) -> str:
    """The one-line status headline ``science-gate mutate`` prints first."""
    start = f"{report.status.value} ({report.reason.value}) {report.report_id}"
    if not report.baseline.valid:
        baseline = report.baseline
        was = f"{baseline.status.value} ({baseline.reason.value})" if baseline.status else "not verified"
        return f"{start}: the accepting baseline was {was}. {INVALID_BASELINE_MESSAGE}"
    counts = report.counts
    if counts is None:
        return f"{start}: {FORCED_DETECTION_ID} was not detected. {HARNESS_BLIND_MESSAGE}"
    tail = (
        f"{counts['skipped_mutations']} skipped, {counts['not_applicable_mutations']} not applicable, "
        f"{counts['not_activated_mutations']} not activated"
    )
    sensitivity = report.sensitivity
    if sensitivity is None:
        return f"{start}: {counts['executed_mutations']} executed ({tail}). {report.message}"
    return (
        f"{start}: {counts['detected_mutations']}/{counts['executed_mutations']} executed mutations detected, "
        f"{counts['blind_spot_mutations']} blind spot(s), {counts['verifier_error_mutations']} verifier error(s), "
        f"{tail}; sensitivity {sensitivity['fraction']}"
    )


def _forced_lines(forced: ForcedDetection) -> list[str]:
    seen = "detected" if forced.detected else "NOT detected"
    lines = [
        "## FORCED DETECTION",
        "",
        f"`{FORCED_DETECTION_ID}` {seen} by `{FORCED_DETECTION.detector.label}`: {_line(forced.target)}.",
    ]
    lines.extend(f"- fired: {_line(_fired_line(item))}" for item in forced.fired)
    lines.extend(f"- {_line(text)}" for text in forced.diagnostics)
    return [*lines, ""]


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
        f"(sha256 `{_line(report.manifest_sha256)}`), generated {report.generated_at}. Sampled: no. Reused: no.",
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
    lines.extend(f"- digest {name}: `{_line(value)}`" for name, value in sorted(baseline.digests.items()))
    lines.extend(
        f"- finding {_line(item['source'])}: {item['status']} {item['reason']}: {_line(item['detail'])}"
        for item in baseline.findings
    )
    lines.extend(f"- {_line(text)}" for text in (*baseline.diagnostics, *report.diagnostics))
    lines.append("")
    if report.forced_detection is not None:
        lines += _forced_lines(report.forced_detection)
    counts = report.counts
    if counts is not None:
        sensitivity = report.sensitivity
        figure = (
            f"{sensitivity['fraction']} = {sensitivity['decimal']} ({sensitivity['decimal_rounding']})."
            if sensitivity
            else report.message
        )
        lines += ["## SENSITIVITY", "", figure, ""]
        lines += [f"- {name}: {counts[name]}" for name in ALL_COUNT_KEYS] + [""]
        balance = report.conservation
        lines += [
            "## CONSERVATION",
            "",
            f"- generated = executed + unexecuted buckets: {'holds' if balance['generated_holds'] else 'FAILS'}",
            f"- executed = DETECTED + BLIND_SPOT + VERIFIER_ERROR + TIMED_OUT + FLAKY: "
            f"{'holds' if balance['executed_holds'] else 'FAILS'}",
            f"- buckets disjoint: {'yes' if balance['disjoint'] else 'NO'}",
            "- detection table: only DETECTED counts as detected",
            "",
        ]
        for title, statuses, empty in _RECORD_SECTIONS:
            chosen = [record for record in report.mutations if record.status in statuses]
            lines += _section(title, chosen, empty)
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


def harness_headline(report: HarnessReport) -> str:
    """The one-line headline ``science-gate mutate --harness`` prints first."""
    return f"{report.status.value} ({report.reason.value}) {report.report_id}: {report.message}"


def render_harness_markdown(report: HarnessReport) -> str:
    """The human harness report. Headings follow :data:`HARNESS_REPORT_HEADINGS`."""
    ratio = report.harness_sensitivity
    figure = (
        f"{ratio.fraction} = {ratio.decimal}" if ratio.decimal is not None else f"unavailable ({ratio.state.value})"
    )
    lines = [
        "# Harness mutation report",
        "",
        "## STATUS",
        "",
        f"**{report.status.value}** ({report.reason.value}), exit code {report.exit_code}.",
        "",
        report.message,
        "",
        f"Harness sensitivity: {figure}.",
        "",
        f"Report `{report.report_id}` for manifest `{_line(report.manifest_name)}` "
        f"(sha256 `{_line(report.manifest_sha256)}`), generated {report.generated_at}.",
        "",
        "## HONEST HARNESS",
        "",
    ]
    for item in report.honest:
        lines.append(
            f"- {item['probe']}: {item['status']} ({item['reason']}), report `{item['report_id']}`"
        )
    lines.extend(f"- {_line(text)}" for text in report.diagnostics)
    lines += ["", "## HARNESS MUTANTS", ""]
    for record in report.records:
        outcome = "killed" if record.killed else "SURVIVED"
        lines.append(f"- `{record.harness_mutant_id}` {outcome}: {record.description}")
        lines.extend(f"  - {_line(text)}" for text in record.differences)
    if not report.records:
        lines.append("No harness mutant ran: the honest harness had no valid baseline to compare against.")
    lines += ["", "## WHAT THIS RESULT DOES NOT PROVE", "", *(f"- {text}" for text in _HARNESS_NOT_PROVEN), ""]
    return "\n".join(lines)


def write_harness_report(report: HarnessReport, output_dir: str | Path) -> tuple[Path, ...]:
    """Write ``harness-report.json`` and ``harness-report.md`` with safe writes; returns the paths in write order."""
    root = Path(output_dir)
    return (
        safe_write(root, HARNESS_REPORT_JSON, pretty_json_bytes(report.to_dict())),
        safe_write(root, HARNESS_REPORT_MD, render_harness_markdown(report).encode("utf-8")),
    )


def _emit(stream: TextIO, text: str) -> None:
    """Write one line, escaping what the stream's encoding cannot represent (a legacy console code page)."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")


#: Status severity for combining the mutation and harness outcomes of ``mutate --harness``.
_SEVERITY = (Status.PASS, Status.ABSTAIN, Status.FAIL, Status.ERROR)


def cli_mutate(args: argparse.Namespace) -> int:
    """``science-gate mutate MANIFEST [--output DIR] [--harness]``; returns the exit code.

    Writes ``mutation-report.json``, ``mutation-report.md`` and
    ``mutation-report.html`` into ``--output`` (default
    ``./science-gate-runs/<report_id>/``), then prints the headline and the
    paths. With ``--harness`` it also mutates the harness itself
    (:func:`mutate_harness`): the mutation report is then the honest
    harness's, ``harness-report.json`` and ``harness-report.md`` are written
    beside it, the harness headline is printed second, and the exit code is
    that of the more severe of the two outcomes. Exit 0 means PASS, 1 FAIL
    (an invalid baseline, a blind harness, unbalanced bookkeeping, a blind
    spot or a verifier error), 2 ABSTAIN, and 3 that a report could not be
    written.
    """
    output = Path(args.output) if args.output else None
    exclude = (output,) if output is not None else ()
    harness = mutate_harness(args.manifest, exclude=exclude) if getattr(args, "harness", False) else None
    report = harness.honest_report if harness is not None else None
    report = report if report is not None else mutate(args.manifest, exclude=exclude)
    target = output if output is not None else Path(DEFAULT_OUTPUT_ROOT) / report.report_id
    statuses = [report.status] + ([harness.status] if harness is not None else [])
    worst = max(statuses, key=_SEVERITY.index)
    try:
        paths = list(write_mutation_report(report, target))
        if harness is not None:
            paths += write_harness_report(harness, target)
    except (SafeIOError, OSError) as exc:
        _emit(sys.stdout, f"ERROR mutate: the {worst.value} report could not be written to {target}: {exc}")
        return EXIT_CODE[Status.ERROR]
    _emit(sys.stdout, headline(report))
    if harness is not None:
        _emit(sys.stdout, harness_headline(harness))
    for path in paths:
        _emit(sys.stdout, str(path))
    return EXIT_CODE[worst]
