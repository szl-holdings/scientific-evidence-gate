"""The execution ledger: a hash-chained record of check invocations (section 4).

A verdict is only as trustworthy as the evidence that the check behind it
actually ran. The ledger is that evidence. It is **append-only**, and each
invocation contributes two entries:

1. a ``STARTED`` entry, written *before* the check runs, and
2. a terminal entry (``COMPLETED``, ``ERRORED`` or ``ABSTAINED``) written after.

Two entries rather than one rewritten entry is deliberate. Rewriting would
make the ledger mutable, so an entry could silently change after it was
hashed. With two entries, a check that crashed or hung leaves a visible
``STARTED`` with no terminal partner, and ``every_invocation_has_terminal_result``
can prove it.

Each entry's ``entry_sha256`` is the SHA-256 of its canonical JSON with that
field omitted, and each entry records its predecessor's hash in
``prev_entry_sha256`` (the first entry points at :data:`GENESIS_SHA256`). The
run seals the ledger with its head hash and length. :func:`verify_chain`
therefore detects edited, reordered, inserted and truncated entries.

``seq`` is 1-based, so the last entry's ``seq`` equals ``ledger_length``.

Every ``verify`` ledger opens with one **PLAN** entry (section 17.4): the
checks, inputs, population denominators and harness pins the run committed
to *before* anything executed, hash-chained ahead of the first STARTED entry.
A population that shrinks after results are seen therefore contradicts a
hash the run already sealed. The PLAN has no invocation id, so the
invocation index ignores it, and :func:`reseal` exists so that tests and the
mutation harness can forge exactly what a thorough tamperer would.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from ._canonical import (
    CanonicalizationError,
    StrictJSONError,
    canonical_bytes,
    normalize,
    sha256_bytes,
    sha256_canonical,
    strict_loads,
)
from ._clock import now
from ._redact import redact
from .models import TERMINAL_INVOCATION_RESULTS, InvocationResult, Reason, Status, invocation_result_for

__all__ = [
    "GENESIS_SHA256",
    "ENTRY_FIELDS",
    "IDENTITY_FIELDS",
    "PLAN_RESULT",
    "PLAN_KIND",
    "PLAN_SCHEMA",
    "LedgerError",
    "LedgerFormatError",
    "ChainVerification",
    "InvocationTrace",
    "ResealResult",
    "Ledger",
    "invocation_id_for",
    "entry_digest",
    "verify_chain",
    "index_invocations",
    "is_plan_entry",
    "plan_of",
    "reseal",
    "parse_jsonl",
]

#: ``prev_entry_sha256`` of the first entry. A fixed value (rather than, say,
#: None) keeps every entry the same shape, so one rule verifies every link.
GENESIS_SHA256 = "0" * 64

#: Exactly the fields of a ledger entry, in contract order.
ENTRY_FIELDS = (
    "seq",
    "invocation_id",
    "check_id",
    "check_kind",
    "check_version",
    "input_ids",
    "input_sha256s",
    "started_at",
    "completed_at",
    "result",
    "evidence",
    "verdict",
    "reason",
    "prev_entry_sha256",
    "entry_sha256",
)

#: Fields that describe *what* was invoked. A terminal entry must repeat its
#: STARTED entry's values exactly, or it closes a different invocation.
IDENTITY_FIELDS = ("check_id", "check_kind", "check_version", "input_ids", "input_sha256s", "started_at")

#: The PLAN entry's ``result`` and ``check_kind``, and its body's schema.
PLAN_RESULT = "PLAN"
PLAN_KIND = "PLAN"
PLAN_SCHEMA = "science-gate-plan/v1"

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class LedgerError(Exception):
    """Misuse of the ledger API, such as finishing an invocation twice."""


class LedgerFormatError(ValueError):
    """A serialized ledger that cannot be read back as JSON Lines entries."""

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"MALFORMED_LEDGER: line {line}: {message}")
        self.line = line


def invocation_id_for(run_id: str, seq: int) -> str:
    """Return ``inv-<first 12 hex of sha256(run_id + ":" + seq)>``.

    Derived from content, never random, so the same run replayed with the same
    inputs yields the same identifiers.
    """
    return "inv-" + sha256_bytes(f"{run_id}:{seq}".encode("utf-8"))[:12]


def entry_digest(entry: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical entry with ``entry_sha256`` omitted."""
    return sha256_canonical({key: value for key, value in entry.items() if key != "entry_sha256"})


@dataclass(frozen=True)
class ChainVerification:
    """Outcome of :func:`verify_chain`. ``intact`` is True only with no problems."""

    intact: bool
    problems: tuple[str, ...]
    observed_length: int
    observed_head: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "problems": list(self.problems),
            "observed_length": self.observed_length,
            "observed_head": self.observed_head,
        }


def _is_seq(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def verify_chain(
    entries: Sequence[Mapping[str, Any]],
    head: str | None,
    length: int | None,
    *,
    run_id: str | None = None,
) -> ChainVerification:
    """Check that ``entries`` are exactly the sealed ledger.

    ``head`` and ``length`` are the sealed ``ledger_head_sha256`` and
    ``ledger_length``. The empty ledger's head is None. A None ``length``
    means the ledger was never sealed, which is itself a problem: without a
    seal, silently dropping the last entries cannot be detected.

    When ``run_id`` is given, every STARTED entry's ``invocation_id`` must be
    the one derived from that run and its ``seq``, which catches entries
    transplanted from another run whose chain was then rebuilt.

    Each tamper is reported where it happened: an edited entry whose stored
    hash was left alone fails its own hash check, while an edited entry that
    was re-hashed breaks the link from its successor (or the sealed head).
    """
    problems: list[str] = []
    previous = GENESIS_SHA256
    for position, entry in enumerate(entries, start=1):
        if not isinstance(entry, Mapping):
            problems.append(f"MALFORMED_ENTRY: entry {position} is not an object")
            previous = None
            continue
        missing = [name for name in ENTRY_FIELDS if name not in entry]
        unexpected = sorted(name for name in entry if name not in ENTRY_FIELDS)
        if missing or unexpected:
            problems.append(f"MALFORMED_ENTRY: entry {position} missing {missing}, unexpected {unexpected}")
        seq = entry.get("seq")
        if not _is_seq(seq) or seq != position:
            problems.append(f"SEQUENCE_BREAK: entry at position {position} has seq {seq!r}")
        if entry.get("prev_entry_sha256") != previous:
            problems.append(f"CHAIN_BREAK: entry {position} does not link to the entry before it")
        try:
            recomputed = entry_digest(entry)
        except CanonicalizationError as exc:
            problems.append(f"MALFORMED_ENTRY: entry {position} is not canonical: {exc}")
        else:
            if entry.get("entry_sha256") != recomputed:
                problems.append(f"ENTRY_EDITED: entry {position} does not match its entry_sha256")
        if (
            run_id is not None
            and entry.get("result") == InvocationResult.STARTED.value
            and _is_seq(seq)
            and entry.get("invocation_id") != invocation_id_for(run_id, seq)
        ):
            problems.append(f"FOREIGN_INVOCATION: entry {position} has an invocation_id not derived from this run")
        previous = entry.get("entry_sha256")

    observed_head = None
    if entries and isinstance(entries[-1], Mapping):
        observed_head = entries[-1].get("entry_sha256")
    if length is None:
        problems.append("UNSEALED: no sealed ledger_length to compare against")
    elif not _is_seq(length) or length != len(entries):
        problems.append(f"LENGTH_MISMATCH: sealed length {length!r}, found {len(entries)} entries")
    if length is not None and head != observed_head:
        problems.append(f"HEAD_MISMATCH: sealed head {head!r}, found {observed_head!r}")
    return ChainVerification(not problems, tuple(problems), len(entries), observed_head)


@dataclass(frozen=True)
class InvocationTrace:
    """Everything the ledger says about one invocation.

    ``problems`` lists structural defects (a close without a start, two
    closes, a close that names a different check). ``terminal`` is True only
    when exactly one well-formed terminal entry follows the STARTED entry.
    """

    invocation_id: str
    check_id: str | None
    start_seq: int | None
    terminal_seq: int | None
    result: InvocationResult | None
    verdict: Status | None
    reason: Reason | None
    problems: tuple[str, ...]

    @property
    def terminal(self) -> bool:
        return self.terminal_seq is not None and not self.problems


def _enum_or_none(enum_type: type[Any], value: Any) -> Any:
    try:
        return enum_type(value)
    except ValueError:
        return None


def _trace(invocation_id: str, group: Sequence[Mapping[str, Any]]) -> InvocationTrace:
    """Judge one invocation's entries, in ledger order."""
    problems: list[str] = []
    start = group[0]
    if start.get("result") != InvocationResult.STARTED.value:
        problems.append(f"{invocation_id}: first entry is {start.get('result')!r}, not STARTED")
    rest = group[1:]
    terminals = [
        entry for entry in rest if _enum_or_none(InvocationResult, entry.get("result")) in TERMINAL_INVOCATION_RESULTS
    ]
    if len(terminals) != len(rest):
        problems.append(f"{invocation_id}: {len(rest) - len(terminals)} later entry(ies) are not terminal results")
    if len(terminals) > 1:
        problems.append(f"{invocation_id}: {len(terminals)} terminal results; exactly one is allowed")
    terminal = terminals[0] if len(terminals) == 1 else None
    result = verdict = reason = None
    if terminal is not None:
        for name in IDENTITY_FIELDS:
            if terminal.get(name) != start.get(name):
                problems.append(f"{invocation_id}: terminal entry changes {name}")
        result = InvocationResult(terminal["result"])
        verdict = _enum_or_none(Status, terminal.get("verdict"))
        reason = _enum_or_none(Reason, terminal.get("reason"))
        if verdict is None or reason is None:
            problems.append(f"{invocation_id}: terminal entry lacks a valid verdict and reason")
        elif invocation_result_for(verdict) is not result:
            problems.append(f"{invocation_id}: result {result.value} contradicts verdict {verdict.value}")
        if terminal.get("completed_at") is None:
            problems.append(f"{invocation_id}: terminal entry has no completed_at")
    check_id = start.get("check_id")
    start_seq = start.get("seq")
    return InvocationTrace(
        invocation_id=invocation_id,
        check_id=check_id if isinstance(check_id, str) else None,
        start_seq=start_seq if _is_seq(start_seq) else None,
        terminal_seq=terminal.get("seq") if terminal is not None and _is_seq(terminal.get("seq")) else None,
        result=result,
        verdict=verdict,
        reason=reason,
        problems=tuple(problems),
    )


def index_invocations(entries: Iterable[Mapping[str, Any]]) -> dict[str, InvocationTrace]:
    """Group ledger entries by ``invocation_id`` and judge each invocation.

    Entries without a string ``invocation_id`` cannot belong to any
    invocation; they are the chain verifier's concern, not this index's.
    The result is keyed and ordered by invocation id.
    """
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for entry in entries:
        if isinstance(entry, Mapping) and isinstance(entry.get("invocation_id"), str):
            groups.setdefault(entry["invocation_id"], []).append(entry)
    return {invocation_id: _trace(invocation_id, groups[invocation_id]) for invocation_id in sorted(groups)}


def is_plan_entry(entry: Mapping[str, Any]) -> bool:
    """True for an entry recording a run's pre-committed PLAN."""
    return isinstance(entry, Mapping) and entry.get("result") == PLAN_RESULT and entry.get("check_kind") == PLAN_KIND


def plan_of(entries: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The PLAN body, when entry 1 is a PLAN and no other entry is; otherwise None.

    A second PLAN would let a run commit to one plan and execute another, so
    an ambiguous ledger has no plan at all.
    """
    if not entries or not is_plan_entry(entries[0]):
        return None
    if any(is_plan_entry(entry) for entry in entries[1:]):
        return None
    body = entries[0].get("evidence")
    return body if isinstance(body, Mapping) else None


@dataclass(frozen=True)
class ResealResult:
    """A ledger rebuilt by :func:`reseal`, with its new seal and the invocation ids it renamed."""

    entries: tuple[dict[str, Any], ...]
    ledger_head_sha256: str | None
    ledger_length: int
    invocation_ids: Mapping[str, str]


def reseal(entries: Sequence[Mapping[str, Any]], run_id: str) -> ResealResult:
    """Renumber, re-derive ids, re-link and re-hash ``entries`` as one consistent chain.

    This is what a thorough forger would do after deleting or editing
    entries: every hash and link verifies again, and every STARTED entry's
    id is derived afresh from ``run_id`` and its new ``seq`` (its terminal
    entry follows the rename). Only facts that live *outside* the chain, such
    as a PLAN that no longer matches the manifest, can then expose the edit.
    """
    renamed: dict[str, str] = {}
    rebuilt: list[dict[str, Any]] = []
    previous = GENESIS_SHA256
    for seq, original in enumerate(entries, start=1):
        entry = copy.deepcopy(dict(original))
        entry["seq"] = seq
        current = entry.get("invocation_id")
        if isinstance(current, str):
            if entry.get("result") == InvocationResult.STARTED.value:
                renamed[current] = invocation_id_for(run_id, seq)
            entry["invocation_id"] = renamed.get(current, current)
        entry["prev_entry_sha256"] = previous
        entry["entry_sha256"] = entry_digest(entry)
        previous = entry["entry_sha256"]
        rebuilt.append(entry)
    head = rebuilt[-1]["entry_sha256"] if rebuilt else None
    return ResealResult(tuple(rebuilt), head, len(rebuilt), dict(sorted(renamed.items())))


def parse_jsonl(data: bytes | str) -> tuple[dict[str, Any], ...]:
    """Read a serialized ledger back into entries.

    Parsing is strict and integers-only (the ledger is written canonically),
    and a blank line anywhere but the end is refused: blank lines never occur
    in a ledger this tool wrote, so one signals tampering or corruption.
    Raises :class:`LedgerFormatError`.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LedgerFormatError(1, f"not valid UTF-8 at byte {exc.start}") from None
    else:
        text = data
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    entries: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            raise LedgerFormatError(number, "blank line")
        try:
            value = strict_loads(line, integers_only=True)
        except StrictJSONError as exc:
            raise LedgerFormatError(number, str(exc)) from None
        if not isinstance(value, dict):
            raise LedgerFormatError(number, "an entry must be a JSON object")
        entries.append(value)
    return tuple(entries)


def _sorted_unique_ids(values: Iterable[str], what: str) -> list[str]:
    items = list(values)
    if any(not isinstance(item, str) or not item for item in items):
        raise ValueError(f"{what} must be non-empty strings")
    if len(set(items)) != len(items):
        raise ValueError(f"{what} must not repeat")
    return sorted(items)


class Ledger:
    """An in-memory, append-only ledger for one run.

    Entries are stored normalized and are only ever handed out as copies, so
    no caller can edit an entry after it was hashed.
    """

    verify_chain = staticmethod(verify_chain)

    def __init__(self, run_id: str) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        self._run_id = run_id
        self._entries: list[dict[str, Any]] = []
        self._open: dict[str, dict[str, Any]] = {}

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(entry) for entry in self._entries)

    @property
    def head_sha256(self) -> str | None:
        """Hash of the last entry, or None for an empty ledger."""
        return self._entries[-1]["entry_sha256"] if self._entries else None

    def __len__(self) -> int:
        return len(self._entries)

    def open_invocations(self) -> tuple[str, ...]:
        """Invocations that were started and not yet finished, sorted."""
        return tuple(sorted(self._open))

    def plan(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Record the run's PLAN as entry 1 and return a copy of the entry.

        The PLAN must come first, before any invocation starts: a plan written
        after results exist commits to nothing. ``input_ids`` and
        ``input_sha256s`` repeat the planned inputs and their declared digests
        (None when undeclared), so the entry has exactly the shape of every
        other entry.
        """
        if self._entries:
            raise LedgerError("the PLAN must be the first entry of the ledger")
        if not isinstance(body, Mapping):
            raise ValueError("a PLAN body must be a mapping")
        planned = body.get("inputs", [])
        if not isinstance(planned, (list, tuple)) or any(not isinstance(item, Mapping) for item in planned):
            raise ValueError("a PLAN body's inputs must be a list of objects")
        ids = _sorted_unique_ids((item.get("input_id") for item in planned), "planned input ids")
        declared = {item["input_id"]: item.get("declared_sha256") for item in planned}
        entry = self._append(
            {
                "seq": 1,
                "invocation_id": None,
                "check_id": None,
                "check_kind": PLAN_KIND,
                "check_version": PLAN_SCHEMA,
                "input_ids": ids,
                "input_sha256s": {input_id: declared[input_id] for input_id in ids},
                "started_at": now(),
                "completed_at": None,
                "result": PLAN_RESULT,
                "evidence": redact(body),
                "verdict": None,
                "reason": None,
            }
        )
        return copy.deepcopy(entry)

    def start(
        self,
        *,
        check_id: str,
        check_kind: str,
        check_version: str,
        input_ids: Iterable[str] = (),
        input_sha256s: Mapping[str, str | None] | None = None,
    ) -> str:
        """Record that a check is about to run and return its invocation id.

        ``input_sha256s`` maps each input id to the digest the check will see
        (None when the input has no digest, for example because it is
        missing). Omitted digests are recorded as None, never guessed.
        """
        for name, value in (("check_id", check_id), ("check_kind", check_kind), ("check_version", check_version)):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        ids = _sorted_unique_ids(input_ids, "input_ids")
        digests = dict(input_sha256s or {})
        if not set(digests) <= set(ids):
            raise ValueError(f"input_sha256s names inputs not in input_ids: {sorted(set(digests) - set(ids))}")
        for input_id, digest in digests.items():
            if digest is not None and not (isinstance(digest, str) and _SHA256_HEX.fullmatch(digest)):
                raise ValueError(f"input_sha256s[{input_id!r}] must be a lowercase hex SHA-256 digest or None")
        seq = len(self._entries) + 1
        invocation_id = invocation_id_for(self._run_id, seq)
        entry = self._append(
            {
                "seq": seq,
                "invocation_id": invocation_id,
                "check_id": check_id,
                "check_kind": check_kind,
                "check_version": check_version,
                "input_ids": ids,
                "input_sha256s": {input_id: digests.get(input_id) for input_id in ids},
                "started_at": now(),
                "completed_at": None,
                "result": InvocationResult.STARTED,
                "evidence": {},
                "verdict": None,
                "reason": None,
            }
        )
        self._open[invocation_id] = entry
        return invocation_id

    def finish(
        self,
        invocation_id: str,
        *,
        verdict: Status | str,
        reason: Reason | str,
        evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the terminal result of a started invocation; return a copy of the entry.

        The ledger ``result`` is derived from ``verdict`` rather than accepted
        separately, so the two can never disagree. Evidence is redacted and
        normalized before hashing: floats are refused here, at the check that
        produced them.
        """
        start = self._open.get(invocation_id)
        if start is None:
            known = any(entry["invocation_id"] == invocation_id for entry in self._entries)
            raise LedgerError(f"cannot finish invocation {invocation_id!r}: {'already finished' if known else 'unknown'}")
        verdict = Status(verdict)
        reason = Reason(reason)
        if (verdict is Status.PASS) != (reason is Reason.VERIFIED):
            raise ValueError("verdict PASS and reason VERIFIED must occur together")
        if evidence is not None and not isinstance(evidence, Mapping):
            raise ValueError("evidence must be a mapping")
        body = normalize(redact(evidence or {}))
        entry = self._append(
            {
                "seq": len(self._entries) + 1,
                "invocation_id": invocation_id,
                **{name: start[name] for name in IDENTITY_FIELDS},
                "completed_at": now(),
                "result": invocation_result_for(verdict),
                "evidence": body,
                "verdict": verdict,
                "reason": reason,
            }
        )
        del self._open[invocation_id]
        return copy.deepcopy(entry)

    def seal(self) -> dict[str, Any]:
        """The values a run records to make truncation detectable."""
        return {"ledger_head_sha256": self.head_sha256, "ledger_length": len(self._entries)}

    def verify(self) -> ChainVerification:
        """Verify this ledger against its own current seal."""
        return verify_chain(self._entries, self.head_sha256, len(self._entries), run_id=self._run_id)

    def to_jsonl(self) -> bytes:
        """Serialize as JSON Lines: one canonical entry per line, ``\\n``-terminated."""
        return b"".join(canonical_bytes(entry) + b"\n" for entry in self._entries)

    def _append(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        entry = normalize(fields)
        entry["prev_entry_sha256"] = self.head_sha256 or GENESIS_SHA256
        entry["entry_sha256"] = entry_digest(entry)
        self._entries.append(entry)
        return entry
