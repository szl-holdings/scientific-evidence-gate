"""``report.html``: the evidence-boundary hologram (ARCHITECTURE.md section 12).

:func:`render` turns a ``run.json`` document, and optionally a mutation
report, into one self-contained HTML page. The page is a *view*, not
evidence. It reads only the dicts it is given. It never decides, repairs or
upgrades a result, and it shows every figure as recorded. Three rules shape
the module.

**Nothing absent may look present.**

* A null count is drawn as "unknown", never as an empty bar that reads as 0.
* A closure without an INDEPENDENT denominator is "not evaluable", never
  "holds".
* A plane is lit only by the facets of evidence the document records.
* A document that says PASS while its own figures break the section 6
  contract is labelled *unsupported* instead of being shown as a clean PASS.

**Every value from the document is hostile until it is escaped.**

A ``run.json`` can be hand-edited, so each value goes through three steps
before output:

1. It is redacted again, because the page is an output file too.
2. Control, bidi-override, invisible and lone-surrogate characters are
   replaced with U+FFFD. Text therefore cannot reorder itself on screen, hide
   a difference, or make the UTF-8 encoding of the page fail.
3. It is HTML-escaped.

Values only ever reach element text and quoted attribute values. They never
reach attribute names, CSS, URLs or scripts. CSS classes come only from
fixed tables in this module. The page has no script at all, and its
Content-Security-Policy forbids scripts and every external request. A missed
escape could therefore still neither run code nor contact another host.

**The same document renders to the same bytes.** There is no clock, no
randomness and no hash-order iteration. Geometry is rounded to two decimals.

Every figure has a text equivalent (a table or a list) next to it, for
screen readers and so that two pages can be diffed.
"""

from __future__ import annotations

import html
import json
import math
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from ._canonical import CanonicalizationError, sha256_canonical
from ._redact import redact_text
from ._validators import ROWS_EXAMINED_MEANING
from .invariants import INVARIANT_NAMES
from .ledger import invocation_id_for

__all__ = [
    "render",
    "FACET_STATES",
    "INVARIANT_STATES",
    "MUTATION_GROUPS",
    "NO_SENSITIVITY_SENTENCE",
    "VALIDITY_LABEL",
]

#: The label the Scientific Validity plane always carries (section 12).
VALIDITY_LABEL = "not established by this tool"

#: Printed instead of any sensitivity figure when the mutation baseline is invalid (section 10).
NO_SENSITIVITY_SENTENCE = "No sensitivity figure was produced because the verifier failed its accepting baseline."

# ---------------------------------------------------------------------------
# Vocabulary of the view
# ---------------------------------------------------------------------------

#: How much light one facet of evidence gives its plane. LIT and BROKEN both
#: mean that evidence exists. Only LIT supports the run; BROKEN contradicts it.
LIT, PARTIAL, BROKEN, DARK = "LIT", "PARTIAL", "BROKEN", "DARK"
FACET_STATES = (LIT, PARTIAL, BROKEN, DARK)
_FACET_WEIGHT = {LIT: 1.0, PARTIAL: 0.5, BROKEN: 0.0, DARK: 0.0}
_FACET_STYLE = {
    LIT: ("accent", "check"),
    PARTIAL: ("accent", "half"),
    BROKEN: ("critical", "cross"),
    DARK: ("muted", "hollow"),
}
_FACET_MEANING = {
    LIT: "evidence recorded and consistent",
    PARTIAL: "only part of the evidence recorded",
    BROKEN: "evidence recorded that contradicts the run",
    DARK: "no evidence recorded",
}

HOLDS, VIOLATED, NOT_APPLICABLE, UNDETERMINED, NOT_RECORDED = (
    "HOLDS",
    "VIOLATED",
    "NOT_APPLICABLE",
    "UNDETERMINED",
    "NOT_RECORDED",
)
INVARIANT_STATES = (HOLDS, VIOLATED, NOT_APPLICABLE, UNDETERMINED, NOT_RECORDED)
_INVARIANT_STYLE = {
    HOLDS: ("good", "check"),
    VIOLATED: ("critical", "cross"),
    NOT_APPLICABLE: ("muted", "dash"),
    UNDETERMINED: ("warning", "question"),
    NOT_RECORDED: ("warning", "question"),
}

#: Invariants about *what was executed* belong to the Integrity plane; the
#: rest judge the declared evaluation and belong to the Performance plane.
_TRACE_INVARIANTS = (
    "checked_claims_le_invocations",
    "every_invocation_has_terminal_result",
    "every_verdict_has_invocation",
)
_INTEGRITY_INVARIANTS = frozenset(("ledger_chain_intact", *_TRACE_INVARIANTS))
_EVALUATION_INVARIANTS = tuple(name for name in INVARIANT_NAMES if name not in _INTEGRITY_INVARIANTS)

_STATUS_STYLE = {
    "PASS": ("good", "check"),
    "FAIL": ("critical", "cross"),
    "ABSTAIN": ("warning", "question"),
    "ERROR": ("serious", "bang"),
}
_UNKNOWN_STYLE = ("muted", "question")

DETECTED, BLIND_SPOT, UNRESOLVED, SKIPPED, NOT_APPLICABLE_MUTATION, NOT_EXECUTED_MUTATION = (
    "DETECTED",
    "BLIND_SPOT",
    "UNRESOLVED",
    "SKIPPED",
    "NOT_APPLICABLE",
    "NOT_EXECUTED",
)
MUTATION_GROUPS = (DETECTED, BLIND_SPOT, UNRESOLVED, SKIPPED, NOT_APPLICABLE_MUTATION, NOT_EXECUTED_MUTATION)
_MUTATION_STYLE = {
    DETECTED: ("good", "check"),
    BLIND_SPOT: ("critical", "cross"),
    UNRESOLVED: ("warning", "question"),
    SKIPPED: ("muted", "dash"),
    NOT_APPLICABLE_MUTATION: ("muted", "dash"),
    NOT_EXECUTED_MUTATION: ("muted", "dash"),
}
#: Report v2 statuses (ARCHITECTURE.md 17.12) of mutants that were built or
#: considered but never executed. They are neither skipped operators nor
#: inapplicable ones, so they get their own group and are never counted as
#: either: a NOT_ACTIVATED mutant read nothing, a NOOP or equivalent mutant
#: changed nothing, a duplicate repeats an earlier mutant.
_UNEXECUTED_V2_STATUSES = frozenset(
    {"NOT_ACTIVATED", "NOOP_MUTATION", "CANONICALLY_EQUIVALENT", "DUPLICATE_MUTANT", "SUPPRESSED"}
)
#: Report v2 statuses of executed mutants that no check detected for a reason
#: other than a blind spot. They count as escaped (executed minus detected),
#: and the page says why instead of calling them blind spots without comment.
_ESCAPED_V2_STATUSES = frozenset({"VERIFIER_ERROR", "TIMED_OUT", "FLAKY"})
#: The six section 10 counts, in the order the page shows them, with their labels.
_MUTATION_COUNTS = (
    ("applicable_mutations", "Applicable"),
    ("executed_mutations", "Executed"),
    ("detected_mutations", "Detected"),
    ("escaped_mutations", "Blind spots"),
    ("skipped_mutations", "Skipped"),
    ("not_applicable_mutations", "Not applicable"),
)
_MUTATION_COUNT_KEYS = tuple(key for key, _ in _MUTATION_COUNTS)

_FUNNEL = ("expected", "discovered", "opened", "parsed", "examined")
_DISPOSITIONS = ("admitted", "excluded", "deferred", "unresolved", "failed")
#: Status colors where a disposition has a status meaning. "deferred" takes
#: the accent because warning beside unresolved fails the color-separation
#: floor. Each segment is also labelled in the legend and the table.
_DISPOSITION_TONE = {
    "admitted": "good",
    "excluded": "muted",
    "deferred": "accent",
    "unresolved": "warning",
    "failed": "critical",
}

_GLYPH_TEXT = {
    "check": "\u2713",
    "cross": "\u2715",
    "question": "?",
    "bang": "!",
    "dash": "\u2013",
    "half": "\u25d0",
    "hollow": "\u25cb",
}

#: Beyond these sizes a figure draws a prefix and says how many more items
#: are in its table. Tables are never truncated.
_MAX_LATTICE_ROWS = 80
_MAX_INPUT_ROWS = 40
_MAX_RING_SEGMENTS = 60
_MAX_CHAIN_LINKS = 40
_MAX_STARS_PER_GROUP = 150
#: The masthead names at most this many decisive findings; the Findings section lists all of them.
_WHY_LIMIT = 3
#: invocation positions are derived by hashing every seq up to ledger_length.
#: A tampered length must not make rendering slow.
_MAX_DERIVED_SEQ = 50_000

# ---------------------------------------------------------------------------
# Reading an untrusted document
# ---------------------------------------------------------------------------


def _dict(value: Any) -> Mapping[str, Any]:
    """``value`` if it is a JSON object, else an empty one, so a tampered field never raises."""
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strs(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    """A count, or None. ``True`` is not a count; ``1.0`` is not one either (floats never enter run files)."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(value: Any) -> str | None:
    """A non-empty string, or None. An empty hash or name is as absent as a missing one."""
    return value if isinstance(value, str) and value else None


def _is(value: Any, expected: str) -> bool:
    """Equality with a vocabulary word that cannot raise or coerce: a list is never PASS."""
    return isinstance(value, str) and value == expected


def _style(
    table: Mapping[str, tuple[str, str]], value: Any, default: tuple[str, str] = _UNKNOWN_STYLE
) -> tuple[str, str]:
    """Look up ``(tone, glyph)`` for a vocabulary value. An unhashable value must not raise."""
    return table.get(value, default) if isinstance(value, str) else default


def _plain(value: Any) -> str:
    """Any JSON value as display text. Structured values are shown as sorted JSON rather than dropped."""
    if isinstance(value, str):
        return value
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=lambda item: type(item).__name__)
    except (TypeError, ValueError, RecursionError):
        return type(value).__name__


def _count(value: Any) -> str:
    """A count for people. A missing count reads "unknown", never 0."""
    number = _int(value)
    return "unknown" if number is None else str(number)


def _short_hash(value: Any) -> str:
    text = _str(value)
    if text is None:
        return "none"
    return text if len(text) <= 18 else f"{text[:10]}\u2026{text[-6:]}"


# ---------------------------------------------------------------------------
# Text safety
# ---------------------------------------------------------------------------

#: C0/C1 controls (tab, newline and carriage return allowed); bidi marks,
#: embeddings, overrides and isolates; zero-width, soft-hyphen and filler
#: characters that render as nothing, so two different ids could look alike;
#: interlinear annotation marks; the BOM; and lone surrogates, which cannot
#: be encoded as UTF-8 at all.
_UNSAFE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2069\u3164\ufeff\uffa0\ufff9-\ufffb\ud800-\udfff]"
)


#: Cleaned text by display string, for the render in progress (None outside one).
#: ``redact_text`` re-reads the whole environment on every call, and a page shows
#: the same few hundred strings many times over. Cleaning depends only on the
#: string and the environment, which a single render does not see change, so a
#: memo scoped to one :func:`render` call cannot serve a stale redaction.
_CLEANED: ContextVar[dict[str, str] | None] = ContextVar("science_gate_html_cleaned", default=None)


def _clean(value: Any) -> str:
    """Display text, redacted, with every character that can hide or reorder text made visible."""
    text = _plain(value)
    memo = _CLEANED.get()
    cleaned = memo.get(text) if memo is not None else None
    if cleaned is None:
        cleaned = _UNSAFE.sub("\ufffd", redact_text(text))
        if memo is not None:
            memo[text] = cleaned
    return cleaned


def _e(value: Any) -> str:
    """Escape a value for element content or a double-quoted attribute value."""
    return html.escape(_clean(value), quote=True)


def _clip(value: Any, limit: int) -> str:
    """Escaped text cut to ``limit`` characters for a label inside a figure.

    It cuts before escaping, so an entity is never split. The full value is
    always in the figure's table.
    """
    text = _clean(value)
    if len(text) > limit:
        text = text[: max(limit - 1, 1)] + "\u2026"
    return html.escape(text, quote=True)


# ---------------------------------------------------------------------------
# What the document establishes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Facet:
    """One piece of evidence a plane can be lit by; ``detail`` is plain text, escaped on output."""

    name: str
    state: str
    detail: str


@dataclass(frozen=True)
class _Plane:
    key: str
    title: str
    question: str
    facets: tuple[_Facet, ...]
    boundary: Any

    def count(self, state: str) -> int:
        return sum(1 for facet in self.facets if facet.state == state)

    @property
    def light(self) -> float:
        """Mean facet weight, from 0 (dark) to 1 (every facet lit). A plane always has its full facet list."""
        return sum(_FACET_WEIGHT[facet.state] for facet in self.facets) / len(self.facets)

    @property
    def reached(self) -> bool:
        """True when some evidence supports this plane, which is what lets the evidence beam reach it."""
        return any(facet.state in (LIT, PARTIAL) for facet in self.facets)

    def summary(self) -> str:
        parts = [f"{self.count(LIT)} of {len(self.facets)} facets lit"]
        parts += [f"{self.count(state)} {state.lower()}" for state in (PARTIAL, BROKEN) if self.count(state)]
        return " \u00b7 ".join(parts)


@dataclass(frozen=True)
class _InvariantRow:
    name: Any
    state: str
    detail: Any

    @property
    def plane(self) -> str:
        if not isinstance(self.name, str) or self.name not in INVARIANT_NAMES:
            return "unregistered"
        return "integrity" if self.name in _INTEGRITY_INVARIANTS else "performance"


@dataclass(frozen=True)
class _Cell:
    """One node of the check lattice. ``filled`` separates presence from absence without relying on color."""

    label: str
    tone: str
    glyph: str | None
    filled: bool


@dataclass(frozen=True)
class _LatticeRow:
    check_id: Any
    kind: Any
    required: bool | None
    declared: bool
    result: Mapping[str, Any] | None

    @property
    def expected(self) -> _Cell:
        if not self.declared:
            return _Cell("NOT DECLARED", "warning", "question", False)
        if self.required is False:
            return _Cell("OPTIONAL", "accent", None, False)
        return _Cell("REQUIRED", "accent", None, True)

    @property
    def executed(self) -> _Cell:
        if self.result is None:
            return _Cell("NO RESULT", "warning", "question", False)
        state = self.result.get("execution_state")
        if _is(state, "CHECKED"):
            return _Cell("CHECKED", "accent", None, True)
        if _is(state, "SKIPPED"):
            return _Cell("SKIPPED", "warning", "dash", False)
        if _is(state, "NOT_APPLICABLE"):
            return _Cell("NOT_APPLICABLE", "muted", "dash", False)
        return _Cell(_plain(state), "muted", "question", False)

    @property
    def terminal(self) -> _Cell:
        if self.result is None:
            return _Cell("NO RESULT", "warning", "question", False)
        if _str(self.result.get("invocation_id")) is None:
            return _Cell("NO INVOCATION", "critical", "bang", False)
        verdict = self.result.get("verdict")
        tone, glyph = _style(_STATUS_STYLE, verdict)
        return _Cell(_plain(verdict), tone, glyph, isinstance(verdict, str) and verdict in _STATUS_STYLE)

    @property
    def is_terminal(self) -> bool:
        return self.result is not None and _str(self.result.get("invocation_id")) is not None


def _accounting_inputs(doc: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return _dicts(_dict(doc.get("accounting")).get("inputs"))


def _invariant_rows(doc: Mapping[str, Any]) -> list[_InvariantRow]:
    """Recorded invariants in document order, then every contract invariant the document does not record.

    A contract invariant with no recorded outcome is shown as NOT_RECORDED.
    It is never simply left out.
    """
    rows = []
    for item in _dicts(doc.get("invariants")):
        applicable, holds = item.get("applicable"), item.get("holds")
        if applicable is True:
            state = HOLDS if holds is True else VIOLATED if holds is False else UNDETERMINED
        elif applicable is False:
            state = NOT_APPLICABLE
        else:
            state = UNDETERMINED
        rows.append(_InvariantRow(item.get("name"), state, item.get("detail")))
    recorded = {row.name for row in rows if isinstance(row.name, str)}
    rows += [
        _InvariantRow(name, NOT_RECORDED, "the run document records no outcome for this contract invariant")
        for name in INVARIANT_NAMES
        if name not in recorded
    ]
    return rows


def _lattice_rows(doc: Mapping[str, Any]) -> list[_LatticeRow]:
    """Declared checks in manifest order joined to their results, then results nothing declared.

    A declared check with no result stays in the lattice as NO RESULT, so a
    checker that never ran is visible rather than absent.
    """
    results = _dicts(doc.get("checks"))
    by_id: dict[str, Mapping[str, Any]] = {}
    for result in results:
        check_id = result.get("check_id")
        if isinstance(check_id, str):
            by_id.setdefault(check_id, result)
    rows: list[_LatticeRow] = []
    used: set[int] = set()
    for spec in _dicts(_dict(doc.get("declared")).get("checks")):
        check_id = spec.get("id")
        result = by_id.get(check_id) if isinstance(check_id, str) else None
        if result is not None:
            used.add(id(result))
        required = spec.get("required") if isinstance(spec.get("required"), bool) else None
        rows.append(_LatticeRow(check_id, spec.get("kind"), required, True, result))
    for result in results:
        if id(result) not in used:
            required = result.get("required") if isinstance(result.get("required"), bool) else None
            rows.append(_LatticeRow(result.get("check_id"), result.get("kind"), required, False, result))
    return rows


def _invariant_group_facet(
    name: str, invariants: Sequence[_InvariantRow], members: Sequence[str], what: str
) -> _Facet:
    """Light a facet from a group of invariants: every member must be recorded and hold."""
    states = {member: [row.state for row in invariants if row.name == member] for member in members}
    violated = [member for member in members if VIOLATED in states[member]]
    if violated:
        return _Facet(name, BROKEN, "violated: " + ", ".join(violated))
    holding = [member for member in members if states[member] and all(state == HOLDS for state in states[member])]
    if len(holding) == len(members):
        return _Facet(name, LIT, f"all {len(members)} {what} invariants recorded as holding")
    if holding:
        rest = ", ".join(f"{member} {'/'.join(states[member])}" for member in members if member not in holding)
        return _Facet(name, PARTIAL, f"{len(holding)} of {len(members)} {what} invariants hold; {rest}")
    return _Facet(name, DARK, f"none of the {len(members)} {what} invariants was applicable and holding")


def _digest_outcome(item: Mapping[str, Any]) -> str:
    """``match``, ``mismatch`` or ``not compared`` for an input that declares a digest."""
    computed = _str(item.get("sha256"))
    if _is(item.get("state"), "HASH_MISMATCH") or (computed is not None and computed != item.get("declared_sha256")):
        return "mismatch"
    return "match" if computed is not None else "not compared"


def _integrity_facets(doc: Mapping[str, Any], invariants: Sequence[_InvariantRow]) -> tuple[_Facet, ...]:
    """Was this the exact artifact, input, execution and version claimed?"""
    inputs = _accounting_inputs(doc)
    facets = []

    hashed = sum(1 for item in inputs if _str(item.get("sha256")))
    if not inputs:
        facets.append(_Facet("Input digests", DARK, "no declared input was recorded, so nothing was hashed"))
    else:
        state = LIT if hashed == len(inputs) else PARTIAL if hashed else DARK
        detail = f"SHA-256 recorded for {hashed} of {len(inputs)} declared input(s)"
        facets.append(_Facet("Input digests", state, detail))

    declared = [item for item in inputs if _str(item.get("declared_sha256"))]
    outcomes = [_digest_outcome(item) for item in declared]
    mismatched = [_plain(item.get("id")) for item, outcome in zip(declared, outcomes) if outcome == "mismatch"]
    matched = outcomes.count("match")
    if mismatched:
        detail = (
            f"{len(mismatched)} of {len(declared)} declared digest(s) differ from the computed SHA-256: "
            + ", ".join(mismatched)
        )
        facets.append(_Facet("Declared digests", BROKEN, detail))
    elif not declared:
        facets.append(_Facet("Declared digests", DARK, "no input declares an expected digest, so none was compared"))
    elif matched == len(declared):
        facets.append(_Facet("Declared digests", LIT, f"{matched} of {len(declared)} declared digest(s) match"))
    else:
        detail = (
            f"{matched} of {len(declared)} declared digest(s) match; "
            f"{len(declared) - matched} could not be compared because the input was not read"
        )
        facets.append(_Facet("Declared digests", PARTIAL, detail))

    length, head = _int(doc.get("ledger_length")), _str(doc.get("ledger_head_sha256"))
    if length is None:
        facets.append(_Facet("Ledger sealed", DARK, "the ledger length is not recorded"))
    elif length < 0:
        facets.append(_Facet("Ledger sealed", BROKEN, f"the recorded ledger length {length} is impossible"))
    elif length == 0:
        facets.append(_Facet("Ledger sealed", DARK, "the ledger is empty: no invocation was recorded"))
    elif head is None:
        facets.append(_Facet("Ledger sealed", BROKEN, f"{length} entries recorded but no head hash"))
    else:
        facets.append(_Facet("Ledger sealed", LIT, f"{length} entries sealed under head {head}"))

    reverification = doc.get("reverification")
    rechecked = _dict(_dict(reverification).get("ledger"))
    chain = [row for row in invariants if row.name == "ledger_chain_intact"]
    if rechecked.get("intact") is False:
        facets.append(_Facet("Hash chain", BROKEN, "re-verification found the ledger hash chain broken"))
    elif any(row.state == VIOLATED for row in chain):
        facets.append(_Facet("Hash chain", BROKEN, "; ".join(_plain(row.detail) for row in chain)))
    elif chain and all(row.state == HOLDS for row in chain):
        facets.append(_Facet("Hash chain", LIT, "; ".join(_plain(row.detail) for row in chain)))
    else:
        facets.append(_Facet("Hash chain", DARK, "the ledger chain was not evaluated"))

    facets.append(_invariant_group_facet("Execution trace", invariants, _TRACE_INVARIANTS, "trace"))

    evidence = _str(doc.get("evidence_manifest_sha256"))
    facets.append(
        _Facet("Evidence manifest", LIT, f"hashed: {evidence}")
        if evidence
        else _Facet("Evidence manifest", DARK, "no evidence manifest digest is recorded")
    )

    receipt = _dict(doc.get("receipt"))
    content = _str(receipt.get("content_sha256"))
    facets.append(
        _Facet("Receipt", LIT, f"content sha256 {content}")
        if content
        else _Facet("Receipt", DARK, "no receipt content hash is recorded")
    )

    signature = receipt.get("signature_state")
    verified = _dict(_dict(reverification).get("receipt")).get("signature_verified")
    if _is(signature, "SIGNED_HMAC_SHA256"):
        key = f"key id {_plain(receipt.get('key_id'))}"
        if verified is False:
            facets.append(_Facet("Signature", BROKEN, f"HMAC-SHA256 signature did not verify ({key})"))
        elif isinstance(reverification, dict) and verified is not True:
            facets.append(_Facet("Signature", PARTIAL, f"HMAC-SHA256 signed, but not checked here ({key})"))
        else:
            facets.append(_Facet("Signature", LIT, f"HMAC-SHA256 signed ({key})"))
    elif _is(signature, "UNSIGNED"):
        facets.append(_Facet("Signature", DARK, "UNSIGNED: the content hash detects accidental change only"))
    else:
        facets.append(_Facet("Signature", DARK, f"signature state not recorded ({_plain(signature)})"))

    if not isinstance(reverification, dict):
        facets.append(
            _Facet(
                "Re-verification",
                DARK,
                "not re-verified: this page was rendered when the run was written "
                "(science-gate report RUN_DIR re-verifies it)",
            )
        )
    elif reverification.get("ok") is True:
        facets.append(_Facet("Re-verification", LIT, "receipt, ledger chain and run.json re-verified from disk"))
    else:
        problems = _strs(reverification.get("problems"))
        facets.append(_Facet("Re-verification", BROKEN, f"re-verification failed with {len(problems)} problem(s)"))
    return tuple(facets)


def _performance_facets(
    doc: Mapping[str, Any], invariants: Sequence[_InvariantRow], lattice: Sequence[_LatticeRow]
) -> tuple[_Facet, ...]:
    """How did the fixed system behave on the declared evaluation?"""
    facets = []

    opened, expected = _int(doc.get("inputs_opened")), _int(doc.get("expected_inputs"))
    if opened is None:
        facets.append(_Facet("Inputs opened", DARK, "inputs_opened is not recorded"))
    elif opened == 0:
        facets.append(_Facet("Inputs opened", DARK, f"0 of {_count(expected)} inputs opened"))
    else:
        state = LIT if expected is not None and opened >= expected else PARTIAL
        facets.append(_Facet("Inputs opened", state, f"{opened} of {_count(expected)} inputs opened"))

    required = [item for item in _accounting_inputs(doc) if item.get("required") is True]
    unparsed = [item for item in required if not _is(item.get("state"), "PARSED")]
    parsed = len(required) - len(unparsed)
    if not required:
        facets.append(_Facet("Required inputs parsed", DARK, "no required input is recorded"))
    else:
        others = ", ".join(f"{_plain(item.get('id'))} {_plain(item.get('state'))}" for item in unparsed)
        detail = f"{parsed} of {len(required)} required input(s) PARSED" + (f"; {others}" if others else "")
        state = LIT if not unparsed else PARTIAL if parsed else DARK
        facets.append(_Facet("Required inputs parsed", state, detail))

    rows = _int(doc.get("rows_examined"))
    if rows is None:
        facets.append(_Facet("Rows examined", DARK, "rows_examined is not recorded"))
    elif rows < 1:
        facets.append(_Facet("Rows examined", DARK, f"rows_examined {rows}: a PASS is impossible"))
    else:
        # One name per quantity (G5): the run figure is always rows_examined, with its one meaning.
        facets.append(_Facet("Rows examined", LIT, f"rows_examined {rows} ({ROWS_EXAMINED_MEANING})"))

    executed, expected_checks = _int(doc.get("checks_executed")), _int(doc.get("checks_expected"))
    ratio = f"{_count(executed)} of {_count(expected_checks)} required checks executed"
    if executed is None or expected_checks is None:
        facets.append(_Facet("Required checks executed", DARK, ratio))
    elif executed > expected_checks:
        facets.append(_Facet("Required checks executed", BROKEN, ratio + ": more than were expected"))
    elif expected_checks == 0:
        facets.append(_Facet("Required checks executed", DARK, "no required check was declared"))
    elif executed == expected_checks:
        facets.append(_Facet("Required checks executed", LIT, ratio))
    else:
        facets.append(_Facet("Required checks executed", PARTIAL if executed else DARK, ratio + ": partial execution"))

    required_rows = [row for row in lattice if row.required is not False]
    verdicts = [row.result.get("verdict") if row.result is not None else None for row in required_rows]
    bad = sum(1 for verdict in verdicts if _is(verdict, "FAIL") or _is(verdict, "ERROR"))
    passed = sum(1 for row, verdict in zip(required_rows, verdicts) if _is(verdict, "PASS") and row.is_terminal)
    ratio = f"{passed} of {len(required_rows)} required check(s) PASS"
    if not required_rows:
        facets.append(_Facet("Required checks passed", DARK, "no required check is declared"))
    elif bad:
        facets.append(_Facet("Required checks passed", BROKEN, f"{ratio}; {bad} FAIL or ERROR"))
    elif passed == len(required_rows):
        facets.append(_Facet("Required checks passed", LIT, ratio))
    else:
        facets.append(_Facet("Required checks passed", PARTIAL if passed else DARK, f"{ratio}; the rest did not pass"))

    facets.append(_closure_facet("Input closure", _dict(_dict(doc.get("accounting")).get("closure"))))

    inputs = _accounting_inputs(doc)
    closures = [_dict(item.get("closure")).get("holds") for item in inputs]
    evaluable = [holds for holds in closures if isinstance(holds, bool)]
    if not inputs:
        facets.append(_Facet("Row closures", DARK, "no input is recorded"))
    elif False in evaluable:
        broken = evaluable.count(False)
        detail = f"{broken} of {len(inputs)} input(s) do not close against their INDEPENDENT expected_rows"
        facets.append(_Facet("Row closures", BROKEN, detail))
    elif len(evaluable) == len(inputs):
        facets.append(_Facet("Row closures", LIT, f"{len(inputs)} of {len(inputs)} input(s) close"))
    elif evaluable:
        detail = f"{len(evaluable)} of {len(inputs)} input(s) close; the rest have no INDEPENDENT expected_rows"
        facets.append(_Facet("Row closures", PARTIAL, detail))
    else:
        facets.append(_Facet("Row closures", DARK, "no input declares an INDEPENDENT expected_rows"))

    facets.append(_invariant_group_facet("Evaluation invariants", invariants, _EVALUATION_INVARIANTS, "evaluation"))
    return tuple(facets)


def _closure_facet(name: str, closure: Mapping[str, Any]) -> _Facet:
    holds, source = closure.get("holds"), _plain(closure.get("source"))
    counts = f"{_count(closure.get('accounted'))} accounted of {_count(closure.get('expected'))} expected ({source})"
    if holds is True:
        return _Facet(name, LIT, counts)
    if holds is False:
        return _Facet(name, BROKEN, counts)
    return _Facet(name, DARK, f"not evaluable: no INDEPENDENT expectation ({source})")


def _planes(
    doc: Mapping[str, Any], invariants: Sequence[_InvariantRow], lattice: Sequence[_LatticeRow]
) -> tuple[_Plane, _Plane]:
    boundary = _dict(doc.get("evidence_boundary"))
    return (
        _Plane(
            "integrity",
            "Integrity",
            "Was this the exact artifact, input, execution and version claimed?",
            _integrity_facets(doc, invariants),
            boundary.get("integrity"),
        ),
        _Plane(
            "performance",
            "Performance",
            "How did the fixed system behave on the declared evaluation?",
            _performance_facets(doc, invariants, lattice),
            boundary.get("performance"),
        ),
    )


def _pass_contract_gaps(
    doc: Mapping[str, Any], lattice: Sequence[_LatticeRow], invariants: Sequence[_InvariantRow]
) -> list[str]:
    """Where a document that says PASS contradicts the PASS contract (section 6) with its own figures.

    ``verify`` cannot produce such a document. Only an edited one can, and
    this page must not display that as a clean PASS. Returns plain-text gaps,
    and an empty list for any status other than PASS.
    """
    if not _is(doc.get("status"), "PASS"):
        return []
    gaps = []
    if not _is(doc.get("reason"), "VERIFIED"):
        gaps.append(f"reason is {_plain(doc.get('reason'))}, but a PASS is always VERIFIED")
    records = _accounting_inputs(doc)
    # A tuple, not a set: a tampered id may be unhashable, and membership must not raise.
    recorded_ids = tuple(item.get("id") for item in records)
    for item in records:
        if item.get("required") is True and not _is(item.get("state"), "PARSED"):
            gaps.append(f"required input {_plain(item.get('id'))} is {_plain(item.get('state'))}, not PARSED")
    for spec in _dicts(_dict(doc.get("declared")).get("inputs")):
        if spec.get("required") is not False and spec.get("id") not in recorded_ids:
            gaps.append(f"declared required input {_plain(spec.get('id'))} has no accounting record")
    opened, rows = _int(doc.get("inputs_opened")), _int(doc.get("rows_examined"))
    if opened is None or opened < 1:
        gaps.append(f"inputs_opened is {_count(opened)}; a PASS needs at least 1")
    if rows is None or rows < 1:
        gaps.append(f"rows_examined is {_count(rows)}; a PASS needs at least 1")
    executed, expected = _int(doc.get("checks_executed")), _int(doc.get("checks_expected"))
    if executed is None or expected is None or executed != expected:
        gaps.append(f"checks_executed is {_count(executed)} but checks_expected is {_count(expected)}")
    for row in lattice:
        if row.required is False:
            continue
        name = _plain(row.check_id)
        if row.result is None:
            gaps.append(f"required check {name} has no recorded result")
        elif not (_is(row.result.get("verdict"), "PASS") and _is(row.result.get("execution_state"), "CHECKED")):
            verdict, state = _plain(row.result.get("verdict")), _plain(row.result.get("execution_state"))
            gaps.append(f"required check {name} is {state} {verdict}, not CHECKED PASS")
        elif not row.is_terminal:
            gaps.append(f"required check {name} has no invocation")
    for row in invariants:
        if row.state in (VIOLATED, UNDETERMINED, NOT_RECORDED):
            gaps.append(f"invariant {_plain(row.name)} is {row.state}")
    if not _str(doc.get("evidence_manifest_sha256")):
        gaps.append("no evidence manifest digest is recorded")
    return gaps


@dataclass(frozen=True)
class _LedgerView:
    """The sealed chain as far as run.json shows it: its length, its head, and where invocations start."""

    length: int | None
    head: str | None
    starts: Mapping[int, tuple[Mapping[str, Any], ...]]
    unplaced: tuple[Mapping[str, Any], ...]
    without_invocation: tuple[Mapping[str, Any], ...]
    derived: bool


def _ledger_view(doc: Mapping[str, Any]) -> _LedgerView:
    """Place each check's invocation on the chain.

    run.json carries the seal (length and head), not the entries. An
    invocation id is ``inv-`` plus 12 hex of ``sha256(run_id:seq)``, where
    seq is the 1-based position of its STARTED entry (section 4). So the
    position of every STARTED entry can be derived exactly, and an id that
    matches no position up to ``ledger_length`` stands out. Terminal entries
    are not identifiable from run.json and are not guessed.
    """
    length, head, run_id = _int(doc.get("ledger_length")), _str(doc.get("ledger_head_sha256")), _str(doc.get("run_id"))
    derived = run_id is not None and length is not None and 0 <= length <= _MAX_DERIVED_SEQ
    index = {invocation_id_for(run_id, seq): seq for seq in range(1, length + 1)} if derived else {}
    starts: dict[int, list[Mapping[str, Any]]] = {}
    unplaced, without = [], []
    for check in _dicts(doc.get("checks")):
        invocation = _str(check.get("invocation_id"))
        if invocation is None:
            without.append(check)
        elif derived:
            seq = index.get(invocation)
            if seq is None:
                unplaced.append(check)
            else:
                starts.setdefault(seq, []).append(check)
    return _LedgerView(
        length,
        head,
        {seq: tuple(items) for seq, items in sorted(starts.items())},
        tuple(unplaced),
        tuple(without),
        derived,
    )


FIRED, NOT_FIRED, FIRING_NOT_RECORDED, NOT_EXECUTED = "FIRED", "NOT FIRED", "NOT RECORDED", "NOT EXECUTED"
_FIRING_STYLE = {
    FIRED: ("good", "check"),
    NOT_FIRED: ("critical", "cross"),
    FIRING_NOT_RECORDED: ("warning", "question"),
    NOT_EXECUTED: ("muted", "dash"),
}


@dataclass(frozen=True)
class _DetectorRule:
    """What counts as the expected detector firing, as the mutation record itself states it (section 10).

    A fired finding matches when it comes from ``label``, has one of
    ``statuses``, and, when ``signals`` is non-empty, raises one of them as
    its reason or a failure mode. A record that does not state statuses or
    signals is matched on the label alone, which is the most it allows.
    """

    label: Any
    statuses: tuple[str, ...]
    signals: tuple[str, ...]

    def matches(self, fired: Any) -> bool:
        label = _str(self.label)
        if label is None:
            return False
        if not isinstance(fired, dict):
            return _is(fired, label)
        if not _is(fired.get("detector"), label):
            return False
        status = fired.get("status")
        if self.statuses and not (isinstance(status, str) and status in self.statuses):
            return False
        raised = [fired.get("reason"), *_strs(fired.get("failure_modes"))]
        return not self.signals or any(isinstance(signal, str) and signal in self.signals for signal in raised)


def _detector_rule(record: Mapping[str, Any]) -> _DetectorRule:
    """The record's detector rule: ``expected_result`` states it in full; ``expected_detector`` names it."""
    expected = _dict(record.get("expected_result"))
    label = expected.get("detector") if _str(expected.get("detector")) else record.get("expected_detector")
    return _DetectorRule(
        label, tuple(_strs(expected.get("detector_statuses"))), tuple(_strs(expected.get("detector_signals")))
    )


def _actual_status(record: Mapping[str, Any]) -> str | None:
    """The status the mutant's verify recorded: ``actual_result.status``, or the result itself when it is a word."""
    actual = record.get("actual_result")
    value = actual.get("status") if isinstance(actual, dict) else actual
    return value if isinstance(value, str) else None


def _firing(record: Mapping[str, Any], rule: _DetectorRule) -> str:
    """Whether the record's own evidence shows its expected detector firing.

    Only an executed mutation can fire anything. A skipped or not-applicable
    record is NOT EXECUTED even if it carries a fired list, which it should
    not; that list is still shown as recorded.
    """
    if not _is(record.get("execution_state"), "CHECKED") or record.get("applicable") is False:
        return NOT_EXECUTED
    fired = record.get("detecting_invariants_fired")
    if not isinstance(fired, list):
        return FIRING_NOT_RECORDED
    return FIRED if any(rule.matches(item) for item in fired) else NOT_FIRED


@dataclass(frozen=True)
class _Mutation:
    record: Mapping[str, Any]
    rule: _DetectorRule
    firing: str
    group: str
    note: str | None

    @property
    def mutation_id(self) -> Any:
        return self.record.get("mutation_id")

    @property
    def short(self) -> str:
        """``M03`` for ``M03_deleted_accepted_row``; the table shows the full id."""
        text = _plain(self.mutation_id)
        match = re.match(r"M\d+", text)
        return match.group(0) if match else text[:6]


def _classify_mutation(record: Mapping[str, Any], firing: str) -> tuple[str, str | None]:
    """Group one mutation record. A detection counts only when the record's own evidence supports it.

    A mutation that was skipped, not applicable, or has no recorded execution
    state is never a detection, whatever its ``detected`` field says
    (requirement 27). An executed mutation is a detection only when the
    record says so *and* its recorded evidence agrees: the actual status is
    not PASS and the expected detector is among the fired detectors. A claim
    the evidence contradicts is grouped UNRESOLVED. A blind spot the evidence
    seems to contradict stays a blind spot, because the page never upgrades
    a result. Every disagreement is reported as a note.
    """
    state, detected, blind = record.get("execution_state"), record.get("detected"), record.get("blind_spot")
    status = record.get("status")
    claims = " but the record says detected=true; it is not counted as a detection" if detected is True else ""
    if status in _UNEXECUTED_V2_STATUSES and not _is(state, "CHECKED"):
        return NOT_EXECUTED_MUTATION, f"status {status}: never executed, so never counted" + claims
    if record.get("applicable") is False or _is(state, "NOT_APPLICABLE"):
        return NOT_APPLICABLE_MUTATION, ("not applicable" + claims) if claims else None
    if _is(state, "SKIPPED"):
        return SKIPPED, ("skipped" + claims) if claims else None
    if not _is(state, "CHECKED"):
        return UNRESOLVED, f"execution state {_plain(state)} is not CHECKED" + claims
    actual = _actual_status(record)
    if detected is True:
        if _is(actual, "PASS"):
            return UNRESOLVED, "the actual result is PASS" + claims
        if firing == NOT_FIRED:
            return UNRESOLVED, "the expected detector is not among the recorded fired detectors" + claims
        if firing == FIRING_NOT_RECORDED:
            return UNRESOLVED, "no fired detector is recorded" + claims
        return DETECTED, "the record also says blind_spot=true" if blind is True else None
    if detected is False:
        if status in _ESCAPED_V2_STATUSES:
            return BLIND_SPOT, f"status {status}: executed and not detected, so it counts as escaped"
        notes = ["the record says blind_spot=false although nothing detected it"] if blind is False else []
        if firing == FIRED and actual is not None and actual != "PASS":
            notes.append(
                "its recorded evidence shows the expected detector firing on a non-PASS result; it stays a blind spot"
            )
        return BLIND_SPOT, "; ".join(notes) or None
    return UNRESOLVED, "executed, but no detection result is recorded"


def _mutation(record: Mapping[str, Any]) -> _Mutation:
    rule = _detector_rule(record)
    firing = _firing(record, rule)
    return _Mutation(record, rule, firing, *_classify_mutation(record, firing))


@dataclass(frozen=True)
class _MutationView:
    mutations: tuple[_Mutation, ...]
    baseline_status: Any
    baseline_valid: bool
    counts: Mapping[str, int | None]
    tallies: Mapping[str, int]
    #: ``(fraction, decimal, rounding)`` as the report states them, shown only when the records agree.
    sensitivity: tuple[Any, Any, Any] | None
    discrepancies: tuple[str, ...]

    def group(self, name: str) -> list[_Mutation]:
        return [item for item in self.mutations if item.group == name]


def _tally(mutations: Sequence[_Mutation]) -> dict[str, int]:
    """The section 10 counts recomputed from the records.

    Executed means applicable and CHECKED. A record that says CHECKED but
    also not applicable is grouped as not applicable, and is not counted as
    executed either, so the tallies always agree with the constellation.
    """
    groups = [item.group for item in mutations]
    return {
        "applicable_mutations": len(groups) - groups.count(NOT_APPLICABLE_MUTATION),
        "executed_mutations": sum(
            1
            for item in mutations
            if item.group in (DETECTED, BLIND_SPOT, UNRESOLVED) and _is(item.record.get("execution_state"), "CHECKED")
        ),
        "detected_mutations": groups.count(DETECTED),
        "escaped_mutations": groups.count(BLIND_SPOT),
        "skipped_mutations": groups.count(SKIPPED),
        "not_applicable_mutations": groups.count(NOT_APPLICABLE_MUTATION),
    }


def _mutation_view(report: Mapping[str, Any]) -> _MutationView:
    """Read a mutation report (section 10) without trusting its arithmetic.

    The baseline is valid only when the report records a baseline status of
    PASS and nothing in it names INVALID_BASELINE. Counts are re-tallied from
    the records, and any disagreement with the report's own counts or status
    is listed. A sensitivity figure is shown only when the baseline is valid,
    at least one mutation executed, and the figure the report carries is the
    one its records give. Otherwise none is shown, even if the report
    carries one.
    """
    mutations = tuple(
        sorted(
            (_mutation(record) for record in _dicts(report.get("mutations"))),
            key=lambda item: (_plain(item.mutation_id), _plain(item.record.get("description"))),
        )
    )
    baseline = _dict(report.get("baseline"))
    status = baseline.get("status")
    invalid = any(
        _is(value, "INVALID_BASELINE")
        for value in (report.get("status"), report.get("reason"), baseline.get("status"), baseline.get("reason"))
    )
    valid = _is(status, "PASS") and not invalid
    present = [key for key in _MUTATION_COUNT_KEYS if key in report]
    counts = {key: _int(report.get(key)) for key in _MUTATION_COUNT_KEYS}
    tallies = _tally(mutations)
    figure = _dict(report.get("sensitivity"))
    # Anything non-null under "sensitivity" is a figure the report carries, even a malformed one.
    carries_figure = report.get("sensitivity") is not None
    sensitivity = None
    if valid:
        discrepancies = [
            f"the report states {key} {_count(counts[key])}, but its records give {tally}"
            for key, tally in tallies.items()
            if key in present and counts[key] != tally
        ]
        unresolved = sum(1 for item in mutations if item.group == UNRESOLVED)
        if _is(report.get("status"), "PASS") and (tallies["escaped_mutations"] or unresolved):
            discrepancies.append(
                f"the report states PASS, but its records include {tallies['escaped_mutations']} blind spot(s) "
                f"and {unresolved} unresolved mutation(s)"
            )
        executed, detected = tallies["executed_mutations"], tallies["detected_mutations"]
        if carries_figure and executed > 0:
            if _is(figure.get("fraction"), f"{detected}/{executed}"):
                sensitivity = (figure["fraction"], figure.get("decimal"), figure.get("decimal_rounding"))
            else:
                discrepancies.append(
                    f"the report states sensitivity {_plain(figure.get('fraction'))}, but its records give "
                    f"{detected}/{executed}; no figure is shown"
                )
    else:
        discrepancies = (
            [f"the report carries {', '.join(present)} although its baseline is invalid; not shown"] if present else []
        )
        if carries_figure:
            discrepancies.append("the report carries a sensitivity figure although its baseline is invalid; not shown")
    return _MutationView(mutations, status, valid, counts, tallies, sensitivity, tuple(discrepancies))


# ---------------------------------------------------------------------------
# SVG primitives
# ---------------------------------------------------------------------------


def _n(value: float) -> str:
    """A coordinate with at most two decimals and never ``-0``, so geometry serializes identically."""
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return "0" if text in ("-0", "") else text


def _points(points: Iterable[tuple[float, float]]) -> str:
    return " ".join(f"{_n(x)},{_n(y)}" for x, y in points)


def _svg(key: str, width: float, height: float, title: str, desc: str, body: Iterable[str], css: str) -> str:
    """An accessible inline SVG. ``key`` is a constant from this module, never document text."""
    return (
        f'<svg class="{css}" viewBox="0 0 {_n(width)} {_n(height)}" role="img" '
        f'aria-labelledby="{key}-title {key}-desc" focusable="false">'
        f'<title id="{key}-title">{_e(title)}</title><desc id="{key}-desc">{_e(desc)}</desc>'
        + "".join(body)
        + "</svg>"
    )


def _line(css: str, x1: float, y1: float, x2: float, y2: float) -> str:
    return f'<line class="{css}" x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}"/>'


def _text(x: float, y: float, content: str, css: str, anchor: str = "start") -> str:
    """An SVG text element. ``content`` must already be escaped."""
    anchor_attr = "" if anchor == "start" else f' text-anchor="{anchor}"'
    return f'<text class="{css}" x="{_n(x)}" y="{_n(y)}"{anchor_attr}>{content}</text>'


def _glyph_path(kind: str, cx: float, cy: float, size: float) -> str:
    """Stroke path data for a glyph centered on (cx, cy). It is drawn, not typeset, so no font is needed."""
    s = size / 2

    def at(dx: float, dy: float) -> str:
        return f"{_n(cx + dx * s)} {_n(cy + dy * s)}"

    shapes = {
        "check": f"M{at(-0.75, 0.05)}L{at(-0.2, 0.6)}L{at(0.8, -0.6)}",
        "cross": f"M{at(-0.6, -0.6)}L{at(0.6, 0.6)}M{at(0.6, -0.6)}L{at(-0.6, 0.6)}",
        "dash": f"M{at(-0.6, 0)}L{at(0.6, 0)}",
        "bang": f"M{at(0, -0.75)}L{at(0, 0.2)}M{at(0, 0.66)}L{at(0, 0.67)}",
        "question": f"M{at(-0.5, -0.4)}C{at(-0.5, -1.0)} {at(0.55, -1.0)} {at(0.5, -0.35)}"
        f"C{at(0.45, 0.05)} {at(0, 0.02)} {at(0, 0.3)}M{at(0, 0.67)}L{at(0, 0.68)}",
    }
    return shapes.get(kind, "")


def _glyph(kind: str | None, cx: float, cy: float, size: float, *, on_fill: bool) -> str:
    """A drawn glyph, or nothing for a kind that has no stroke shape (the legend-only ``half`` and ``hollow``)."""
    path = _glyph_path(kind, cx, cy, size) if kind is not None else ""
    if not path:
        return ""
    css = "glyph glyph-on" if on_fill else "glyph glyph-tone"
    width = max(1.3, size * 0.17)
    return f'<path class="{css}" stroke-width="{_n(width)}" d="{path}"/>'


def _marker(tone: str, glyph: str | None, cx: float, cy: float, r: float, *, filled: bool = True) -> str:
    """A status disc, filled with the tone or hollow; the glyph repeats the meaning, so color is never alone."""
    if not filled:
        return (
            f'<g class="t-{tone}"><circle class="hollow" cx="{_n(cx)}" cy="{_n(cy)}" r="{_n(r)}"/>'
            f"{_glyph(glyph, cx, cy, r * 1.1, on_fill=False)}</g>"
        )
    return (
        f'<g class="t-{tone}"><circle class="fill-tone" cx="{_n(cx)}" cy="{_n(cy)}" r="{_n(r)}"/>'
        f"{_glyph(glyph, cx, cy, r * 1.1, on_fill=True)}</g>"
    )


def _bar(x: float, y: float, width: float, height: float, css: str, *, rounded: bool = True) -> str:
    """A bar grown from a square baseline to a 4px rounded data end."""
    if width <= 0:
        return ""
    radius = min(4.0, width, height / 2) if rounded else 0.0
    if radius < 1:
        return f'<rect class="{css}" x="{_n(x)}" y="{_n(y)}" width="{_n(width)}" height="{_n(height)}"/>'
    end = x + width
    path = (
        f"M{_n(x)} {_n(y)}H{_n(end - radius)}A{_n(radius)} {_n(radius)} 0 0 1 {_n(end)} {_n(y + radius)}"
        f"V{_n(y + height - radius)}A{_n(radius)} {_n(radius)} 0 0 1 {_n(end - radius)} {_n(y + height)}"
        f"H{_n(x)}Z"
    )
    return f'<path class="{css}" d="{path}"/>'


def _tip(content: str) -> str:
    """A native tooltip. ``content`` must already be escaped. Tooltips add to the tables; they never replace them."""
    return f"<title>{content}</title>"


# ---------------------------------------------------------------------------
# The hologram: three stacked planes
# ---------------------------------------------------------------------------

_PLANE_W, _PLANE_H, _PLANE_STEP = 400.0, 140.0, 118.0
_HOLO_CX, _HOLO_TOP = 232.0, 92.0
_HOLO_LABEL_X = _HOLO_CX + _PLANE_W / 2 + 46
_HOLO_W, _HOLO_H = 740.0, 472.0


def _plane_point(cy: float, u: float, v: float) -> tuple[float, float]:
    """Map plane coordinates (u along the upper-left edge, v along the lower-left edge) to the page."""
    return (_HOLO_CX - _PLANE_W / 2 + (u + v) * _PLANE_W / 2, cy + (v - u) * _PLANE_H / 2)


def _plane_quad(cy: float, u0: float, u1: float, v0: float, v1: float) -> str:
    return _points(
        [_plane_point(cy, u0, v0), _plane_point(cy, u1, v0), _plane_point(cy, u1, v1), _plane_point(cy, u0, v1)]
    )


def _plane_grid(cy: float, css: str) -> str:
    lines = []
    for f in (0.25, 0.5, 0.75):
        for start, end in (((f, 0.0), (f, 1.0)), ((0.0, f), (1.0, f))):
            x1, y1 = _plane_point(cy, *start)
            x2, y2 = _plane_point(cy, *end)
            lines.append(f'<line class="{css}" x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}"/>')
    return "".join(lines)


def _lit_plane(plane: _Plane, cy: float) -> str:
    """A translucent plane whose brightness is the mean light of its facets, one tile per facet."""
    light = plane.light
    edge = "plane-edge broken" if plane.count(BROKEN) else "plane-edge"
    parts = [f'<g class="plane plane-{plane.key}">']
    if light > 0:
        parts.append(
            f'<polygon class="plane-fill" filter="url(#hg-glow)" fill-opacity="{_n(0.32 * light)}" '
            f'points="{_plane_quad(cy, 0, 1, 0, 1)}"/>'
        )
    parts.append(
        f'<polygon class="plane-fill" fill-opacity="{_n(0.05 + 0.2 * light)}" points="{_plane_quad(cy, 0, 1, 0, 1)}"/>'
    )
    parts.append(_plane_grid(cy, "plane-grid"))
    parts.append(
        f'<polygon class="{edge}" stroke-opacity="{_n(0.4 + 0.5 * light)}" points="{_plane_quad(cy, 0, 1, 0, 1)}"/>'
    )
    count = len(plane.facets)
    rows = 1 if count <= 5 else 2
    cols = max(1, math.ceil(count / rows))
    du, dv = 0.4 / cols, 0.13
    for index, facet in enumerate(plane.facets):
        row, col = divmod(index, cols)
        uc, vc = (col + 0.5) / cols, 0.5 + (row - (rows - 1) / 2) * 0.36
        quad = _plane_quad(cy, uc - du, uc + du, vc - dv, vc + dv)
        tip = _tip(_e(f"{plane.title} \u00b7 {facet.name}: {facet.state}, {facet.detail}"))
        parts.append(f'<g class="tile tile-{facet.state.lower()}">{tip}')
        if facet.state == LIT:
            parts.append(f'<polygon class="tile-lit" filter="url(#hg-glow)" points="{quad}"/>')
            parts.append(f'<polygon class="tile-lit" points="{quad}"/>')
        elif facet.state == PARTIAL:
            parts.append(f'<polygon class="tile-lit" points="{_plane_quad(cy, uc - du, uc, vc - dv, vc + dv)}"/>')
            parts.append(f'<polygon class="tile-outline" points="{quad}"/>')
        elif facet.state == BROKEN:
            x, y = _plane_point(cy, uc, vc)
            parts.append(f'<polygon class="tile-broken" points="{quad}"/>')
            parts.append(f'<g class="t-critical">{_glyph("cross", x, y, 11, on_fill=True)}</g>')
        else:
            parts.append(f'<polygon class="tile-dark" points="{quad}"/>')
        parts.append("</g>")
    parts.append("</g>")
    return "".join(parts)


def _void_plane(cy: float) -> str:
    """Scientific validity: always dark, and always labelled as outside what this tool can establish."""
    return (
        '<g class="plane plane-validity">'
        f'<polygon class="plane-void" points="{_plane_quad(cy, 0, 1, 0, 1)}"/>'
        + _plane_grid(cy, "plane-void-grid")
        + _text(_HOLO_CX, cy - 2, "NOT ESTABLISHED", "void-text", "middle")
        + _text(_HOLO_CX, cy + 15, "by this tool", "void-sub", "middle")
        + "</g>"
    )


def _plane_label(cy: float, title: str, subtitle: str) -> str:
    x0 = _HOLO_CX + _PLANE_W / 2
    return (
        f'<line class="leader" x1="{_n(x0 + 8)}" y1="{_n(cy)}" x2="{_n(_HOLO_LABEL_X - 10)}" y2="{_n(cy)}"/>'
        + _text(_HOLO_LABEL_X, cy - 3, _e(title), "sv-title")
        + _text(_HOLO_LABEL_X, cy + 16, _e(subtitle), "sv-sub")
    )


def _hologram_svg(integrity: _Plane, performance: _Plane) -> str:
    cy_validity = _HOLO_TOP
    cy_performance = _HOLO_TOP + _PLANE_STEP
    cy_integrity = _HOLO_TOP + 2 * _PLANE_STEP
    base = cy_integrity + _PLANE_H / 2 + 28
    top = cy_performance if integrity.reached and performance.reached else cy_integrity if integrity.reached else None
    # userSpaceOnUse: a vertical line has a zero-width bounding box, which
    # makes an objectBoundingBox gradient (the default) silently not paint.
    parts = [
        "<defs>"
        '<filter id="hg-glow" x="-40%" y="-60%" width="180%" height="220%"><feGaussianBlur stdDeviation="7"/></filter>'
        f'<linearGradient id="hg-beam" gradientUnits="userSpaceOnUse" x1="{_n(_HOLO_CX)}" y1="{_n(base)}" '
        f'x2="{_n(_HOLO_CX)}" y2="{_n(_HOLO_TOP)}">'
        '<stop class="beam-stop-base" offset="0"/><stop class="beam-stop-top" offset="1"/></linearGradient>'
        "</defs>"
    ]
    for upper, lower in ((cy_validity, cy_performance), (cy_performance, cy_integrity)):
        for u, v in ((0.0, 0.0), (1.0, 1.0), (0.0, 1.0)):
            x1, y1 = _plane_point(upper, u, v)
            x2, y2 = _plane_point(lower, u, v)
            parts.append(f'<line class="connector" x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}"/>')
    if top is not None:
        parts.append(
            f'<line class="beam" stroke="url(#hg-beam)" x1="{_n(_HOLO_CX)}" y1="{_n(base)}" '
            f'x2="{_n(_HOLO_CX)}" y2="{_n(top)}"/>'
            f'<circle class="beam-cap" cx="{_n(_HOLO_CX)}" cy="{_n(top)}" r="3.5"/>'
        )
    parts.append(f'<circle class="beam-source" cx="{_n(_HOLO_CX)}" cy="{_n(base)}" r="4.5"/>')
    parts.append(_text(_HOLO_CX + 14, base + 4, "evidence recorded by this run", "sv-small"))
    parts.append(_lit_plane(integrity, cy_integrity))
    parts.append(_lit_plane(performance, cy_performance))
    parts.append(_void_plane(cy_validity))
    parts.append(_plane_label(cy_integrity, integrity.title, integrity.summary()))
    parts.append(_plane_label(cy_performance, performance.title, performance.summary()))
    parts.append(_plane_label(cy_validity, "Scientific validity", VALIDITY_LABEL.capitalize()))
    reached = [plane.title for plane in (integrity, performance) if plane.reached]
    desc = (
        f"Integrity plane: {integrity.summary()}. Performance plane: {performance.summary()}. "
        f"Scientific validity plane: dark, {VALIDITY_LABEL}. The evidence beam reaches "
        + (" and ".join(reached) if reached else "no plane")
        + "; it never reaches scientific validity."
    )
    return _svg("hologram", _HOLO_W, _HOLO_H, "Evidence-boundary hologram", desc, parts, "hologram-svg")


# ---------------------------------------------------------------------------
# Accounting funnel
# ---------------------------------------------------------------------------


def _counter(counters: Mapping[str, Any], name: str) -> tuple[int | None, Any]:
    entry = _dict(counters.get(name))
    return _int(entry.get("value")), entry.get("denominator_source")


def _closure_words(closure: Mapping[str, Any]) -> tuple[str, str, str]:
    """``(tone, glyph, text)`` for a closure block. A null ``holds`` is never shown as holding."""
    holds, source = closure.get("holds"), _plain(closure.get("source"))
    counts = f"{_count(closure.get('accounted'))} accounted of {_count(closure.get('expected'))} expected"
    if holds is True:
        return "good", "check", f"Closure holds \u00b7 {counts} \u00b7 {source}"
    if holds is False:
        return "critical", "cross", f"Closure BROKEN \u00b7 {counts} \u00b7 {source}"
    return "muted", "question", f"Closure not evaluable \u00b7 no INDEPENDENT expectation \u00b7 {source}"


def _stack(x: float, y: float, height: float, scale: float, values: Sequence[tuple[str, int | None]]) -> str:
    """Disposition segments separated by 2px surface gaps; only the final segment has a rounded end."""
    shown = [(name, value) for name, value in values if value]
    parts, cursor = [], x
    for index, (name, value) in enumerate(shown):
        width = max(2.0, value * scale)
        last = index == len(shown) - 1
        drawn = width if last else max(1.0, width - 2)
        tip = _tip(_e(f"{name}: {value}"))
        bar = _bar(cursor, y, drawn, height, "fill-tone", rounded=last)
        parts.append(f'<g class="t-{_DISPOSITION_TONE[name]}">{tip}{bar}</g>')
        cursor += width
    return "".join(parts)


def _accounting_svg(doc: Mapping[str, Any]) -> str:
    accounting = _dict(doc.get("accounting"))
    counters = _dict(accounting.get("counters"))
    stages = [(name, *_counter(counters, name)) for name in _FUNNEL]
    dispositions = [(name, _counter(counters, name)[0]) for name in _DISPOSITIONS]
    known = [value for _, value, _ in stages if value is not None]
    accounted = sum(value for _, value in dispositions if value is not None)
    scale_max = max(known + [accounted, 1])
    label_x, bar_x, bar_max, bar_h, row_h, top = 108.0, 116.0, 290.0, 16.0, 30.0, 52.0
    scale = bar_max / scale_max
    parts = []
    stage_ys = [top + index * row_h for index in range(len(stages))]
    stack_y = top + len(stages) * row_h + 10
    expected = stages[0][1]
    parts.append(_line("sv-axis", bar_x, top - 8, bar_x, stack_y + bar_h + 6))
    if expected is not None:
        target = bar_x + expected * scale
        parts.append(_line("target", target, top - 16, target, stack_y + bar_h + 8))
        parts.append(_text(target, top - 22, f"expected {expected}", "sv-small", "middle"))
    for (name, value, source), y in zip(stages, stage_ys):
        parts.append(_text(label_x, y + 12, _e(name), "sv-label", "end"))
        tip = _tip(_e(f"{name}: {_count(value)} ({_plain(source)})"))
        if value is None:
            parts.append(f"<g>{tip}{_marker('muted', 'question', bar_x + 9, y + bar_h / 2, 7, filled=False)}</g>")
            parts.append(_text(bar_x + 24, y + 12, "unknown", "sv-sub"))
            continue
        width = value * scale
        parts.append(f'<g class="t-accent">{tip}{_bar(bar_x, y, width, bar_h, "fill-tone")}</g>')
        suffix = f" \u00b7 {_e(source)}" if name == "expected" and source is not None else ""
        parts.append(_text(bar_x + width + 8, y + 12, f"{value}{suffix}", "sv-value"))
    parts.append(_text(label_x, stack_y + 12, "accounted", "sv-label", "end"))
    missing = [name for name, value in dispositions if value is None]
    parts.append(_stack(bar_x, stack_y, bar_h, scale, dispositions))
    if len(missing) == len(dispositions):
        stack_note = "unknown"
    elif missing:
        stack_note = f"{accounted} + unknown ({', '.join(missing)})"
    else:
        stack_note = str(accounted)
    parts.append(_text(bar_x + accounted * scale + 8, stack_y + 12, _e(stack_note), "sv-value"))
    tone, glyph, words = _closure_words(_dict(accounting.get("closure")))
    badge_y = stack_y + bar_h + 34
    parts.append(_marker(tone, glyph, 20, badge_y - 4, 9))
    parts.append(_text(36, badge_y, _e(words), "sv-label"))

    inputs = _accounting_inputs(doc)
    shown = inputs[:_MAX_INPUT_ROWS]
    y = badge_y + 40
    parts.append(_text(16, y, "Rows per input (each on its own scale; the tick marks expected_rows)", "sv-small"))
    y += 16
    for item in shown:
        counts = _dict(item.get("row_counts"))
        values = [(name, _int(counts.get(name))) for name in _DISPOSITIONS]
        closure = _dict(item.get("closure"))
        expected_rows = _int(closure.get("expected"))
        rows_accounted = sum(value for _, value in values if value is not None)
        local_max = max(expected_rows or 0, rows_accounted, _int(item.get("rows")) or 0, 1)
        local_scale = (bar_max - 60) / local_max
        parts.append(_text(label_x, y + 12, _clip(item.get("id"), 15), "sv-label", "end"))
        parts.append(_stack(bar_x, y, bar_h, local_scale, values))
        if expected_rows is not None:
            tick = bar_x + expected_rows * local_scale
            parts.append(_line("target", tick, y - 4, tick, y + bar_h + 4))
        row_tone, row_glyph, _ = _closure_words(closure)
        end = bar_x + max(rows_accounted * local_scale, (expected_rows or 0) * local_scale)
        parts.append(_marker(row_tone, row_glyph, end + 16, y + bar_h / 2, 7))
        label = f"{rows_accounted} of {_count(expected_rows)} \u00b7 {_plain(item.get('state'))}"
        parts.append(_text(end + 30, y + 12, _clip(label, 34), "sv-value"))
        y += row_h
    if not inputs:
        parts.append(_text(16, y + 12, "No input was recorded.", "sv-sub"))
        y += row_h
    elif len(inputs) > len(shown):
        parts.append(_text(16, y + 12, f"{len(inputs) - len(shown)} more input(s) are listed in the table.", "sv-sub"))
        y += row_h
    funnel = ", ".join(f"{name} {_count(value)}" for name, value, _ in stages)
    desc = f"Input funnel: {funnel}. Accounted {stack_note}. {words}."
    return _svg("accounting", 540, y + 8, "Input-accounting funnel", desc, parts, "panel-svg")


# ---------------------------------------------------------------------------
# Check lattice
# ---------------------------------------------------------------------------


def _cell(cell: _Cell, cx: float, cy: float, tip: str) -> str:
    size = 22.0
    x, y = cx - size / 2, cy - size / 2
    shape = "fill-tone" if cell.filled else "hollow"
    return (
        f'<g class="t-{cell.tone}">{tip}<rect class="{shape}" x="{_n(x)}" y="{_n(y)}" width="{_n(size)}" '
        f'height="{_n(size)}" rx="5"/>{_glyph(cell.glyph, cx, cy, 12, on_fill=cell.filled)}</g>'
    )


def _lattice_svg(rows: Sequence[_LatticeRow]) -> str:
    columns = (300.0, 386.0, 472.0)
    width, top, step = 590.0, 78.0, 36.0
    shown = rows[:_MAX_LATTICE_ROWS]
    required = sum(1 for row in rows if row.declared and row.required is not False)
    optional = sum(1 for row in rows if row.declared and row.required is False)
    checked = sum(1 for row in rows if row.executed.label == "CHECKED")
    terminal = sum(1 for row in rows if row.is_terminal)
    parts = []
    headers = (
        ("EXPECTED", f"{required} required" + (f" + {optional}" if optional else "")),
        ("EXECUTED", f"{checked} checked"),
        ("TERMINAL", f"{terminal} with invocation"),
    )
    for x, (title, count) in zip(columns, headers):
        parts.append(_text(x, 24, title, "sv-caps", "middle"))
        parts.append(_text(x, 42, _e(count), "sv-small", "middle"))
    parts.append(_text(width - 12, 24, "ROWS", "sv-caps", "end"))
    parts.append(f'<line class="sv-grid" x1="12" y1="{_n(top - 22)}" x2="{_n(width - 12)}" y2="{_n(top - 22)}"/>')
    for index, row in enumerate(shown):
        y = top + index * step
        parts.append(_text(16, y - 2, _clip(row.check_id, 26), "sv-label"))
        parts.append(_text(16, y + 12, _clip(row.kind, 34), "sv-small"))
        cells = (row.expected, row.executed, row.terminal)
        flows = (row.result is not None, row.is_terminal)
        for (x1, x2), flows_on in zip(zip(columns, columns[1:]), flows):
            if flows_on:
                parts.append(f'<line class="flow" x1="{_n(x1 + 12)}" y1="{_n(y)}" x2="{_n(x2 - 12)}" y2="{_n(y)}"/>')
        for x, cell, stage in zip(columns, cells, ("expected", "executed", "terminal")):
            parts.append(_cell(cell, x, y, _tip(_e(f"{_plain(row.check_id)} {stage}: {cell.label}"))))
        examined = row.result.get("rows_examined") if row.result is not None else None
        parts.append(_text(width - 12, y + 4, _e(_count(examined)), "sv-value", "end"))
    height = top + max(len(shown), 1) * step
    if not rows:
        parts.append(_text(16, top + 4, "No check was declared or recorded.", "sv-sub"))
    elif len(rows) > len(shown):
        parts.append(_text(16, height, f"{len(rows) - len(shown)} more check(s) are listed in the table.", "sv-sub"))
        height += step
    desc = (
        f"{len(rows)} check(s): {required} required and {optional} optional expected, {checked} executed "
        f"(CHECKED), {terminal} terminal with an invocation."
    )
    return _svg("lattice", width, height, "Check lattice", desc, parts, "panel-svg")


# ---------------------------------------------------------------------------
# Invariant ring
# ---------------------------------------------------------------------------


_RING_CENTER = 160.0


def _polar(radius: float, angle: float) -> str:
    return f"{_n(_RING_CENTER + radius * math.cos(angle))} {_n(_RING_CENTER + radius * math.sin(angle))}"


def _ring_svg(rows: Sequence[_InvariantRow]) -> str:
    """One segment per invariant. ``rows`` is never empty: every contract invariant has a row, recorded or not."""
    size, center, outer, inner = 2 * _RING_CENTER, _RING_CENTER, 118.0, 92.0
    shown = rows[:_MAX_RING_SEGMENTS]
    parts = []
    step = 2 * math.pi / len(shown)
    gap = min(3.0 / ((outer + inner) / 2), step * 0.25)
    for index, row in enumerate(shown):
        a0 = -math.pi / 2 + index * step + gap / 2
        a1 = a0 + step - gap
        large = 1 if a1 - a0 > math.pi else 0
        path = (
            f"M{_polar(outer, a0)}A{_n(outer)} {_n(outer)} 0 {large} 1 {_polar(outer, a1)}"
            f"L{_polar(inner, a1)}A{_n(inner)} {_n(inner)} 0 {large} 0 {_polar(inner, a0)}Z"
        )
        tone, glyph = _INVARIANT_STYLE[row.state]
        filled = row.state in (HOLDS, VIOLATED)
        tip = _tip(_e(f"{index + 1}. {_plain(row.name)}: {row.state}, {_plain(row.detail)}"))
        middle, mid_r = (a0 + a1) / 2, (outer + inner) / 2
        gx, gy = center + mid_r * math.cos(middle), center + mid_r * math.sin(middle)
        arc_length = (a1 - a0) * mid_r
        mark = _glyph(glyph, gx, gy, 11, on_fill=filled) if arc_length >= 16 else ""
        shape = "fill-tone" if filled else "hollow"
        parts.append(f'<g class="t-{tone}">{tip}<path class="{shape}" d="{path}"/>{mark}</g>')
        lx, ly = center + (outer + 16) * math.cos(middle), center + (outer + 16) * math.sin(middle)
        parts.append(_text(lx, ly + 4, str(index + 1), "sv-small", "middle"))
    applicable = [row for row in rows if row.state in (HOLDS, VIOLATED, UNDETERMINED)]
    holding = sum(1 for row in rows if row.state == HOLDS)
    violated = sum(1 for row in rows if row.state == VIOLATED)
    parts.append(_text(center, center + 2, f"{holding} of {len(applicable)}", "ring-figure", "middle"))
    parts.append(_text(center, center + 22, "applicable hold", "sv-small", "middle"))
    others = [f"{violated} violated"] if violated else []
    missing = sum(1 for row in rows if row.state == NOT_RECORDED)
    others += [f"{missing} not recorded"] if missing else []
    if others:
        parts.append(_text(center, center + 38, " \u00b7 ".join(others), "sv-small", "middle"))
    if len(rows) > len(shown):
        parts.append(_text(center, size - 6, f"{len(rows) - len(shown)} more in the list", "sv-small", "middle"))
    states = ", ".join(f"{sum(1 for row in rows if row.state == state)} {state}" for state in INVARIANT_STATES)
    desc = f"{len(rows)} invariant(s): {states}."
    return _svg("invariants", size, size, "Invariant ring", desc, parts, "ring-svg")


# ---------------------------------------------------------------------------
# Ledger chain strip
# ---------------------------------------------------------------------------


def _chain_svg(ledger: _LedgerView) -> str:
    width, height, left, area_end, link_y, link_h = 960.0, 132.0, 16.0, 736.0, 40.0, 30.0
    parts = []
    length = ledger.length
    if length is None or length <= 0:
        label = "length not recorded" if length is None else "empty ledger" if length == 0 else "invalid length"
        parts.append(
            f'<rect class="link-empty" x="{_n(left)}" y="{_n(link_y)}" width="200" height="{_n(link_h)}" rx="7"/>'
        )
        parts.append(_text(left + 100, link_y + 19, label, "sv-small", "middle"))
        last_x = left + 200
    else:
        if length <= _MAX_CHAIN_LINKS:
            slots: list[int | None] = list(range(1, length + 1))
        else:
            half = _MAX_CHAIN_LINKS // 2
            slots = [*range(1, half + 1), None, *range(length - half + 1, length + 1)]
        slot_w = (area_end - left) / len(slots)
        link_w = min(58.0, slot_w - 6)
        previous_end = None
        for index, seq in enumerate(slots):
            x = left + index * slot_w + (slot_w - link_w) / 2
            if seq is None:
                hidden = length - _MAX_CHAIN_LINKS
                parts.append(_text(x + link_w / 2, link_y + 19, f"\u22ef {hidden} \u22ef", "sv-small", "middle"))
                previous_end = None
                continue
            if previous_end is not None:
                parts.append(_line("chain-link", previous_end, link_y + link_h / 2, x, link_y + link_h / 2))
            checks = ledger.starts.get(seq, ())
            names = ", ".join(_plain(check.get("check_id")) for check in checks)
            if checks:
                tip = _tip(_e(f"entry {seq}: STARTED record of {names}"))
                css, label_css = "link-start", "link-seq-on"
            else:
                tip = _tip(_e(f"entry {seq}"))
                css, label_css = "link", "link-seq"
            parts.append(
                f'<g>{tip}<rect class="{css}" x="{_n(x)}" y="{_n(link_y)}" width="{_n(link_w)}" '
                f'height="{_n(link_h)}" rx="7"/>'
            )
            if link_w >= 18:
                parts.append(_text(x + link_w / 2, link_y + 19, str(seq), label_css, "middle"))
            parts.append("</g>")
            if checks and link_w >= 30:
                label = _clip(names, max(3, int(link_w / 6.2)))
                parts.append(_text(x + link_w / 2, link_y + link_h + 16, label, "sv-small", "middle"))
            previous_end = x + link_w
        last_x = previous_end if previous_end is not None else area_end
    head_x = 760.0
    parts.append(
        f'<line class="chain-link head-arrow" x1="{_n(last_x)}" y1="{_n(link_y + link_h / 2)}" '
        f'x2="{_n(head_x - 6)}" y2="{_n(link_y + link_h / 2)}"/>'
        f'<path class="arrow-tip" d="M{_n(head_x - 12)} {_n(link_y + link_h / 2 - 5)}L{_n(head_x - 3)} '
        f'{_n(link_y + link_h / 2)}L{_n(head_x - 12)} {_n(link_y + link_h / 2 + 5)}Z"/>'
    )
    parts.append(
        f'<g><title>{_e("head " + _plain(ledger.head))}</title>'
        f'<rect class="head" x="{_n(head_x)}" y="{_n(link_y - 8)}" width="184" height="{_n(link_h + 16)}" rx="10"/>'
        + _text(head_x + 14, link_y + 8, "HEAD", "sv-caps")
        + _text(head_x + 14, link_y + 27, _e(_short_hash(ledger.head)), "sv-mono")
        + "</g>"
    )
    placed = sum(len(items) for items in ledger.starts.values())
    parts.append(
        _text(
            left,
            height - 12,
            _e(
                f"{_count(length)} entries \u00b7 {placed} invocation start(s) placed from their ids"
                + (f" \u00b7 {len(ledger.unplaced)} not placeable" if ledger.unplaced else "")
                + (f" \u00b7 {len(ledger.without_invocation)} without invocation" if ledger.without_invocation else "")
            ),
            "sv-sub",
        )
    )
    desc = (
        f"Ledger chain of {_count(length)} entries sealed under head {_plain(ledger.head)}; "
        f"{placed} invocation start(s) placed."
    )
    return _svg("ledger", width, height, "Ledger chain strip", desc, parts, "wide-svg")


# ---------------------------------------------------------------------------
# Mutation constellation
# ---------------------------------------------------------------------------

_GOLDEN_ANGLE = math.pi * (3 - math.sqrt(5))


def _constellation_edges(
    positions: Sequence[tuple[float, float]],
) -> list[tuple[tuple[float, float], tuple[float, float]]]:
    """Join each star to its nearest earlier star.

    Stars sit on a spiral, so spiral order is not spatial order, and joining
    consecutive stars draws crossing zig-zags. Nearest-earlier joins form a
    tree that reads as a constellation. Ties go to the earlier star, so the
    drawing is deterministic.
    """
    edges = []
    for index in range(1, len(positions)):
        x, y = positions[index]
        nearest = min(
            range(index), key=lambda other: ((positions[other][0] - x) ** 2 + (positions[other][1] - y) ** 2, other)
        )
        edges.append((positions[nearest], positions[index]))
    return edges


def _constellation_svg(view: _MutationView) -> str:
    groups = [
        ("Detected", DETECTED, view.group(DETECTED)),
        ("Blind spots", BLIND_SPOT, view.group(BLIND_SPOT)),
        (
            "Not executed",
            SKIPPED,
            view.group(SKIPPED) + view.group(NOT_APPLICABLE_MUTATION) + view.group(NOT_EXECUTED_MUTATION),
        ),
    ]
    if view.group(UNRESOLVED):
        groups.insert(2, ("Unresolved", UNRESOLVED, view.group(UNRESOLVED)))
    width = 960.0
    slot = width / len(groups)
    radius_cap = min(slot / 2 - 30, 112.0)
    # Stars sit on a spiral whose radius grows with the square root of the
    # count, so the field is only as tall as its largest cluster needs.
    counts = [len(members[:_MAX_STARS_PER_GROUP]) for *_, members in groups]
    spacings = [min(26.0, radius_cap / math.sqrt(max(count, 1))) for count in counts]
    reach = max(spacing * math.sqrt(max(count - 0.5, 0.5)) for spacing, count in zip(spacings, counts))
    cy = 64 + reach
    height = cy + reach + 44
    parts = []
    for index, ((title, group, members), spacing) in enumerate(zip(groups, spacings)):
        cx = slot * index + slot / 2
        parts.append(_text(cx, 28, _e(f"{title.upper()} \u00b7 {len(members)}"), "sv-caps", "middle"))
        shown = members[:_MAX_STARS_PER_GROUP]
        positions = [
            (cx + spacing * math.sqrt(k + 0.5) * math.cos(k * _GOLDEN_ANGLE),
             cy + spacing * math.sqrt(k + 0.5) * math.sin(k * _GOLDEN_ANGLE))
            for k in range(len(shown))
        ]
        tone, _ = _MUTATION_STYLE[group]
        for (x1, y1), (x2, y2) in _constellation_edges(positions):
            parts.append(
                f'<line class="star-line t-{tone}" x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}"/>'
            )
        for item, (x, y) in zip(shown, positions):
            star_tone, glyph = _MUTATION_STYLE[item.group]
            executed = item.group in (DETECTED, BLIND_SPOT)
            radius = 9.0 if item.group in (DETECTED, BLIND_SPOT, UNRESOLVED) else 6.0
            tip = _tip(_e(f"{_plain(item.mutation_id)}: {item.group}" + (f" ({item.note})" if item.note else "")))
            halo = (
                f'<circle class="star-halo t-{star_tone}" cx="{_n(x)}" cy="{_n(y)}" r="{_n(radius + 5)}"/>'
                if item.group == BLIND_SPOT
                else ""
            )
            parts.append(f"<g>{tip}{halo}{_marker(star_tone, glyph, x, y, radius, filled=executed)}</g>")
            if len(shown) <= 30:
                parts.append(_text(x, y + radius + 12, _clip(item.short, 6), "sv-small", "middle"))
        if not members:
            parts.append(_text(cx, cy + 4, "none", "sv-sub", "middle"))
        elif len(members) > len(shown):
            parts.append(_text(cx, height - 10, f"{len(members) - len(shown)} more in the table", "sv-small", "middle"))
    desc = "; ".join(f"{title}: {len(members)}" for title, _, members in groups) + "."
    return _svg("mutations", width, height, "Mutation constellation", desc, parts, "wide-svg")


# ---------------------------------------------------------------------------
# HTML building blocks
# ---------------------------------------------------------------------------


def _pill(word: Any, tone: str, glyph: str | None) -> str:
    dot = f'<span class="pill-dot" aria-hidden="true">{_GLYPH_TEXT.get(glyph or "", "")}</span>'
    return f'<span class="pill t-{tone}">{dot}{_e(word)}</span>'


def _status_pill(value: Any) -> str:
    return _pill(value, *_style(_STATUS_STYLE, value))


def _code(value: Any) -> str:
    """An identifier, kept whole: a table scrolls rather than split ``columns`` into ``colu mns``."""
    return f"<code>{_e(value)}</code>"


def _hash(value: Any) -> str:
    """A digest or path, which may break anywhere because it has no natural break points."""
    return f'<code class="wrap">{_e(value)}</code>'


def _wbr(value: Any, separators: str = "_:") -> str:
    """Escaped text with a ``<wbr>`` break opportunity after each separator.

    The break is inserted into the already-escaped text. No separator used
    here is ever part of an HTML entity, so no entity can be split.
    """
    text = _e(value)
    for separator in separators:
        text = text.replace(separator, separator + "<wbr>")
    return text


def _breakable(value: Any, separators: str = "_:") -> str:
    """An identifier that may wrap after ``_`` or ``:``, so ``invariant:ledger_chain_intact`` stays readable.

    It wraps only there, never inside a word.
    """
    return f'<code class="brk">{_wbr(value, separators)}</code>'


def _path(value: Any) -> str:
    """A relative path that wraps after a separator, so ``data/measurements.csv`` never breaks mid-name."""
    return _breakable(value, "/\\_-")


def _sub(content: str, *, words: bool = False) -> str:
    """A secondary line inside a table cell; ``content`` must already be escaped.

    A line may break anywhere, because diagnostics quote ids with no spaces.
    ``words`` keeps words whole instead, for a line such as an evidence digest
    whose short hash must not be split.
    """
    css = "cell-sub words" if words else "cell-sub"
    return f'<div class="{css}">{content}</div>'


def _chips(values: Any) -> str:
    items = values if isinstance(values, list) else []
    if not items:
        return '<span class="muted">none</span>'
    return " ".join(f'<span class="chip">{_e(item)}</span>' for item in items)


def _table(
    caption: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    equivalent_of: str | None,
    empty: str,
    css: str = "",
) -> str:
    """A table of already-escaped cells.

    ``equivalent_of`` names the figure the table is the text equivalent of;
    None marks a table that stands on its own. ``css`` is an extra class
    from this module's own constants, never document text.
    """
    head = "".join(f'<th scope="col">{_e(header)}</th>' for header in headers)
    if rows:
        body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    else:
        body = f'<tr><td colspan="{len(headers)}" class="muted">{_e(empty)}</td></tr>'
    marker = f' data-equivalent-of="{equivalent_of}"' if equivalent_of is not None else ""
    classes = f"table-wrap {css}" if css else "table-wrap"
    return (
        f'<div class="{classes}"{marker} role="region" tabindex="0" '
        f'aria-label="{_e(caption)}"><table><caption>{_e(caption)}</caption>'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _figure(key: str, svg: str, caption: str, scroll: str) -> str:
    return (
        f'<figure class="viz" data-visual="{key}"><div class="viz-scroll {scroll}" tabindex="0">{svg}</div>'
        f"<figcaption>{caption}</figcaption></figure>"
    )


def _legend(items: Sequence[tuple[str, str, str]]) -> str:
    """Legend entries ``(tone, swatch kind, label)``: a named swatch, so identity never rests on color alone."""
    entries = "".join(
        f'<li><span class="swatch sw-{kind} t-{tone}" aria-hidden="true"></span>{_e(label)}</li>'
        for tone, kind, label in items
    )
    return f'<ul class="legend">{entries}</ul>'


def _section(key: str, title: str, lede: str, body: str) -> str:
    """A page section. ``key`` is a constant anchor; ``body`` is already-escaped HTML."""
    return (
        f'<section id="{key}" class="panel" aria-labelledby="{key}-heading">'
        f'<div class="section-head"><h2 id="{key}-heading">{html.escape(title)}</h2>'
        f"<p>{html.escape(lede)}</p></div>{body}</section>"
    )


# ---------------------------------------------------------------------------
# Page sections
# ---------------------------------------------------------------------------


def _verdict_disc(tone: str, glyph: str) -> str:
    return (
        f'<svg class="verdict-disc t-{tone}" viewBox="0 0 56 56" aria-hidden="true" focusable="false">'
        f'<circle class="fill-tone" cx="28" cy="28" r="28"/>{_glyph(glyph, 28, 28, 26, on_fill=True)}</svg>'
    )


def _ratio(part: Any, whole: Any) -> str:
    """``part / whole`` as escaped text; a ratio of two unknowns is one "unknown", not "unknown / unknown"."""
    if _int(part) is None and _int(whole) is None:
        return "unknown"
    return f"{_e(_count(part))} / {_e(_count(whole))}"


def _stat(label: str, value: str, note: str, *, known: bool) -> str:
    """A stat tile; ``value`` and ``note`` are already-escaped HTML."""
    css = "stat-value" if known else "stat-value unknown"
    return (
        f'<div class="stat"><div class="stat-label">{_e(label)}</div><div class="{css}">{value}</div>'
        f'<div class="stat-note">{note}</div></div>'
    )


def _why(doc: Mapping[str, Any]) -> str:
    """The recorded grounds for a status other than PASS, so the first screen says why and not only what.

    The grounds are the findings recorded with the displayed status, in the
    order the decision weighed them. A status with no such finding is said to
    be unexplained rather than left blank, because a verdict without grounds
    is itself a defect worth seeing. A failed re-verification is explained by
    its own banner instead: the recorded findings belong to the status it
    rejected, so listing them here would explain the wrong verdict.
    """
    status = doc.get("status")
    if not isinstance(status, str) or status not in _STATUS_STYLE or status == "PASS":
        return ""
    reverification = doc.get("reverification")
    if isinstance(reverification, dict) and reverification.get("ok") is not True:
        return ""
    grounds = [
        f"<strong>{_e(finding.get('reason'))}</strong> {_code(finding.get('source'))} "
        f'<span class="why-detail">{_e(finding.get("detail"))}</span>'
        for finding in _dicts(doc.get("findings"))
        if _is(finding.get("status"), status)
    ]
    if not grounds:
        body = '<p class="why-none">No recorded finding carries this status, so nothing on record explains it.</p>'
    else:
        items = "".join(f"<li>{ground}</li>" for ground in grounds[:_WHY_LIMIT])
        more = len(grounds) - _WHY_LIMIT
        tail = f'<p class="why-more"><a href="#findings">{more} more under Findings</a></p>' if more > 0 else ""
        body = f'<ol class="why-list">{items}</ol>{tail}'
    return f'<div class="why"><p class="why-label">Why {_e(status)}</p>{body}</div>'


def _masthead(
    doc: Mapping[str, Any], gaps: Sequence[str], invariants: Sequence[_InvariantRow], readable: bool
) -> str:
    status, reason = doc.get("status"), doc.get("reason")
    manifest = _dict(doc.get("manifest"))
    label = manifest.get("run_label") if _str(manifest.get("run_label")) else doc.get("run_id")
    title = label if _str(label) else "Unidentified run"
    tone, glyph = _style(_STATUS_STYLE, status)
    qualifier = ""
    if gaps:
        tone, glyph = "critical", "bang"
        qualifier = (
            '<p class="verdict-note">Recorded PASS, <strong>unsupported</strong>: this document contradicts '
            "the PASS contract with its own figures. See the contradiction list below.</p>"
        )
    recorded = doc.get("recorded_status")
    reasons_label, modes_label, stats_note = "Reasons", "Failure modes", ""
    if recorded is not None:
        qualifier += (
            f'<p class="verdict-note">Re-verification failed, so the recorded status {_e(recorded)} '
            "is not trusted.</p>"
        )
        reasons_label, modes_label = "Recorded reasons", "Recorded failure modes"
        stats_note = (
            '<p class="stats-note">The figures below are shown as recorded. Re-verification did not confirm '
            "them.</p>"
        )
    if not readable:
        qualifier += '<p class="verdict-note">The run document is not a JSON object: nothing in it can be shown.</p>'
    executed, expected = doc.get("checks_executed"), doc.get("checks_expected")
    opened, expected_inputs = doc.get("inputs_opened"), doc.get("expected_inputs")
    rows = doc.get("rows_examined")
    applicable = [row for row in invariants if row.state in (HOLDS, VIOLATED, UNDETERMINED)]
    holding = sum(1 for row in invariants if row.state == HOLDS)
    stats = "".join(
        (
            _stat(
                "Required checks executed",
                _ratio(executed, expected),
                "reached CHECKED with a terminal invocation",
                known=_int(executed) is not None and _int(expected) is not None,
            ),
            _stat("Rows examined", _e(_count(rows)), ROWS_EXAMINED_MEANING, known=_int(rows) is not None),
            _stat(
                "Inputs opened",
                _ratio(opened, expected_inputs),
                "of the declared inputs",
                known=_int(opened) is not None and _int(expected_inputs) is not None,
            ),
            _stat(
                "Invariants holding",
                f"{holding} / {len(applicable)}",
                f"applicable, of {len(invariants)} listed",
                known=True,
            ),
        )
    )
    meta = [
        ("Run", _code(doc.get("run_id"))),
        ("Started", _e(doc.get("started_at"))),
        ("Completed", _e(doc.get("completed_at"))),
        ("Manifest", f"{_code(manifest.get('file'))} sha256 {_hash(manifest.get('sha256'))}"),
        ("Evidence manifest", _hash(doc.get("evidence_manifest_sha256"))),
        ("Ledger", f"{_e(_count(doc.get('ledger_length')))} entries, head {_hash(doc.get('ledger_head_sha256'))}"),
        (
            "Receipt",
            f"{_hash(_dict(doc.get('receipt')).get('content_sha256'))} "
            f"{_e(_dict(doc.get('receipt')).get('signature_state'))}",
        ),
    ]
    rows_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in meta)
    return (
        '<header class="masthead">'
        '<p class="eyebrow">scientific-evidence-gate \u00b7 evidence-boundary hologram</p>'
        f"<h1>{_e(title)}</h1>"
        f'<div class="verdict t-{tone}" id="status">{_verdict_disc(tone, glyph)}'
        f'<div class="verdict-body"><div class="verdict-line"><span class="verdict-word">{_e(status)}</span>'
        f'<span class="verdict-reason">{_e(reason)} \u00b7 exit code {_e(_count(doc.get("exit_code")))}</span></div>'
        f'<dl class="verdict-chips"><div><dt>{reasons_label}</dt><dd>{_chips(doc.get("reasons"))}</dd></div>'
        f'<div><dt>{modes_label}</dt><dd>{_chips(doc.get("failure_modes"))}</dd></div></dl>'
        f"{_why(doc)}{qualifier}</div></div>"
        f'{stats_note}<div class="stats">{stats}</div>'
        f'<dl class="meta">{rows_html}</dl>'
        '<p class="scope">This page shows integrity and the declared evaluation only. '
        f"Scientific validity is {VALIDITY_LABEL}.</p>"
        "</header>"
    )


def _banners(doc: Mapping[str, Any], gaps: Sequence[str]) -> str:
    parts = []
    if gaps:
        items = "".join(f"<li>{_e(gap)}</li>" for gap in gaps)
        parts.append(
            '<section class="banner t-critical" role="alert" aria-labelledby="contradiction-heading">'
            '<h2 id="contradiction-heading">Contradiction: a PASS this document does not support</h2>'
            "<p>The document records PASS, but its own contents fail the PASS contract (ARCHITECTURE.md section 6). "
            "Treat this PASS as unsupported.</p>"
            f"<ul>{items}</ul></section>"
        )
    reverification = doc.get("reverification")
    if isinstance(reverification, dict) and reverification.get("ok") is not True:
        items = "".join(f"<li>{_e(problem)}</li>" for problem in _strs(reverification.get("problems")))
        parts.append(
            '<section class="banner t-serious" role="alert" aria-labelledby="reverification-failed-heading">'
            '<h2 id="reverification-failed-heading">Re-verification failed</h2>'
            f"<p>The run directory did not re-verify, so the page shows status {_e(doc.get('status'))}. "
            f"The recorded status was {_e(doc.get('recorded_status'))}. The recorded content below is shown only for "
            "inspection.</p>"
            f"<ul>{items}</ul></section>"
        )
    return "".join(parts)


def _toc(entries: Sequence[tuple[str, str]]) -> str:
    links = "".join(f'<li><a href="#{key}">{html.escape(title)}</a></li>' for key, title in entries)
    return f'<nav aria-label="Sections"><ul class="toc">{links}</ul></nav>'


def _facet_list(plane: _Plane) -> str:
    items = []
    for facet in plane.facets:
        tone, glyph = _FACET_STYLE[facet.state]
        items.append(
            f'<li>{_pill(facet.state, tone, glyph)}<span class="facet-name">{_e(facet.name)}</span>'
            f'<span class="facet-detail">{_e(facet.detail)}</span></li>'
        )
    return f'<ul class="facets">{"".join(items)}</ul>'


def _hologram_section(doc: Mapping[str, Any], integrity: _Plane, performance: _Plane) -> str:
    figure = _figure(
        "hologram",
        _hologram_svg(integrity, performance),
        "Three stacked planes. Each plane is lit only by the evidence this run recorded for it. The beam rises "
        "through the planes that evidence reaches and stops below scientific validity, which stays dark.",
        "scroll-wide",
    )
    legend = _legend(
        [(_FACET_STYLE[state][0], state.lower(), f"{state}: {_FACET_MEANING[state]}") for state in FACET_STATES]
    )
    boundary = _dict(doc.get("evidence_boundary"))
    cards = []
    for plane in (integrity, performance):
        cards.append(
            f'<article class="plane-card"><h3>{_e(plane.title)} '
            f'<span class="card-sum">{_e(plane.summary())}</span></h3>'
            f'<p class="plane-question">{_e(plane.question)}</p>{_facet_list(plane)}'
            f'<p class="recorded">Recorded statement: {_e(plane.boundary)}</p></article>'
        )
    cards.append(
        '<article class="plane-card void"><h3>Scientific validity '
        f'<span class="card-sum">{_e(VALIDITY_LABEL)}</span></h3>'
        '<p class="plane-question">Does the conclusion hold in the intended domain?</p>'
        "<p>This plane is always drawn dark. No check in this run, whatever its verdict, bears on whether any "
        "conclusion is true in its intended domain. That question is outside what this tool can establish.</p>"
        f'<p class="recorded">Recorded statement: {_e(boundary.get("scientific_validity"))}</p></article>'
    )
    equivalent = f'<div class="planes" data-equivalent-of="hologram">{"".join(cards)}</div>'
    return _section(
        "hologram",
        "Evidence boundary",
        "Integrity, performance and scientific validity, kept apart",
        f'<div class="stage">{figure}</div>{legend}{equivalent}',
    )


def _accounting_section(doc: Mapping[str, Any]) -> str:
    accounting = _dict(doc.get("accounting"))
    counters = _dict(accounting.get("counters"))
    figure = _figure(
        "accounting",
        _accounting_svg(doc),
        "Declared input files move from expected to examined. Each is accounted for exactly once as admitted, "
        "excluded, deferred, unresolved or failed. Closure is enforced only against an INDEPENDENT expectation. "
        "An unknown count is drawn as unknown, never as zero.",
        "scroll-panel",
    )
    legend = _legend([(_DISPOSITION_TONE[name], "fill", name) for name in _DISPOSITIONS])
    counter_rows = [
        [_e(name), _e(_count(_counter(counters, name)[0])), _e(_counter(counters, name)[1])]
        for name in (*_FUNNEL, *_DISPOSITIONS)
    ]
    tone, glyph, words = _closure_words(_dict(accounting.get("closure")))
    closure_line = f'<p class="closure-line">{_pill(words, tone, glyph)}</p>'
    input_rows = []
    for item in _accounting_inputs(doc):
        counts = _dict(item.get("row_counts"))
        row_tone, row_glyph, row_words = _closure_words(_dict(item.get("closure")))
        input_rows.append(
            [_code(item.get("id")), _e(item.get("state")), _e(_count(item.get("rows")))]
            + [_e(_count(counts.get(name))) for name in _DISPOSITIONS]
            + [_e(_count(_dict(item.get("closure")).get("expected"))), _pill(row_words, row_tone, row_glyph)]
        )
    counters_table = _table(
        "Input funnel and dispositions (declared input files)",
        ("Counter", "Value", "Denominator source"),
        counter_rows,
        equivalent_of="accounting",
        empty="no counters recorded",
    )
    rows_table = _table(
        "Row accounting per input",
        ("Input", "State", "Records", *_DISPOSITIONS, "Expected rows", "Row closure"),
        input_rows,
        equivalent_of="accounting",
        empty="no input was recorded",
    )
    return _section(
        "accounting",
        "Input accounting",
        "expected \u2192 discovered \u2192 opened \u2192 parsed \u2192 examined",
        f'<div class="split"><div>{figure}{legend}</div><div>{closure_line}{counters_table}</div></div>{rows_table}',
    )


def _evidence_digest(check: Mapping[str, Any]) -> str:
    """The canonical SHA-256 of a check's evidence, the value its receipt attests.

    Returns an explanation instead when the evidence cannot be canonicalized.
    """
    evidence = check.get("evidence")
    if not isinstance(evidence, dict):
        return "no evidence object"
    try:
        digest = sha256_canonical(evidence)
    except (CanonicalizationError, RecursionError):
        return f"{len(evidence)} field(s), not canonical"
    return f"{len(evidence)} field(s), sha256 {_short_hash(digest)}"


def _check_cells(row: _LatticeRow) -> list[str]:
    """One row of the lattice's table. A declared check with no result keeps its row, with empty details.

    Each secondary fact sits under the one it qualifies: the kind under the
    check, the reason under the verdict, the evidence digest under the
    invocation that recorded it, and the diagnostics under the failure
    modes. Seven columns fit a laptop screen, so nothing needs a sideways
    scroll to be seen.
    """
    expected, executed, terminal = (
        _pill(cell.label, cell.tone, cell.glyph) for cell in (row.expected, row.executed, row.terminal)
    )
    check = _code(row.check_id) + _sub(_e(row.kind))
    if row.result is None:
        return [check, expected, executed, terminal, "", "", ""]
    result = row.result
    diagnostics = result.get("diagnostics")
    return [
        check,
        expected,
        executed,
        terminal + _sub(_wbr(result.get("reason"), "_"), words=True),
        _e(_count(result.get("rows_examined"))),
        _code(result.get("invocation_id")) + _sub(_e(_evidence_digest(result)), words=True),
        _chips(result.get("failure_modes"))
        + "".join(_sub(_e(text)) for text in (diagnostics if isinstance(diagnostics, list) else [])),
    ]


def _lattice_section(doc: Mapping[str, Any], lattice: Sequence[_LatticeRow]) -> str:
    figure = _figure(
        "lattice",
        _lattice_svg(lattice),
        "Each row is a check: declared (expected), examined its inputs (executed), and closed by a ledger "
        "invocation with a verdict (terminal). A missing flow line marks where a check stopped.",
        "scroll-panel",
    )
    counters = _dict(doc.get("counters"))
    recorded = [
        (name, counters[name] if name in counters else doc.get(name))
        for name in (
            "checks_declared",
            "checks_expected",
            "checks_executed",
            "checks_passed",
            "checks_failed",
            "checks_abstained",
            "checks_errored",
            "checks_skipped",
            "checks_not_applicable",
        )
    ]
    counter_html = "".join(f"<div><dt>{name}</dt><dd>{_e(_count(value))}</dd></div>" for name, value in recorded)
    side = (
        '<div class="side"><h3>Recorded counters</h3>'
        '<p class="muted small">checks_expected and checks_executed count required checks only; executed means '
        "CHECKED with a terminal invocation.</p>"
        f'<dl class="counter-list" data-equivalent-of="lattice">{counter_html}</dl></div>'
    )
    legend = _legend(
        [
            ("accent", "fill", "expected and required, or executed (CHECKED)"),
            ("accent", "hollow", "optional"),
            ("good", "fill", "PASS"),
            ("critical", "fill", "FAIL"),
            ("warning", "fill", "ABSTAIN"),
            ("serious", "fill", "ERROR"),
            ("muted", "hollow", "not applicable, skipped or missing"),
        ]
    )
    table = _table(
        "Checks: expected, executed, terminal",
        ("Check and kind", "Expected", "Executed", "Terminal and reason", "Subject records examined",
         "Invocation and evidence",
         "Failure modes and diagnostics"),
        [_check_cells(row) for row in lattice],
        equivalent_of="lattice",
        empty="no check was declared or recorded",
        css="check-table",
    )
    tallies = [
        [_code(item.get("check_id")), _e(item.get("subject")), _e(_count(item.get("claimed"))),
         _e(_count(item.get("invocations")))]
        for item in _dicts(doc.get("claim_tallies"))
    ]
    tally_table = (
        _table(
            "Claimed versus invoked (checked_claims_le_invocations)",
            ("Check", "Subject", "Claimed", "Invocations"),
            tallies,
            equivalent_of="lattice",
            empty="none",
        )
        if tallies
        else ""
    )
    return _section(
        "lattice",
        "Check lattice",
        "expected vs executed vs terminal",
        f'<div class="split"><div>{figure}{legend}</div>{side}</div>{table}{tally_table}',
    )


def _invariant_section(invariants: Sequence[_InvariantRow]) -> str:
    figure = _figure(
        "invariants",
        _ring_svg(invariants),
        "One segment per invariant, numbered as in the list. A filled segment is applicable and was evaluated. "
        "A hollow one is not applicable or has no recorded outcome.",
        "scroll-ring",
    )
    # A list item laid out as a grid loses its marker, so the number the ring
    # refers to is written out. The ``value`` keeps the list's own numbering.
    items = []
    for index, row in enumerate(invariants, start=1):
        tone, glyph = _INVARIANT_STYLE[row.state]
        items.append(
            f'<li value="{index}"><span class="inv-num" aria-hidden="true">{index}</span>'
            f'{_pill(row.state, tone, glyph)}<span class="facet-name">{_code(row.name)}</span>'
            f'<span class="plane-tag">{row.plane}</span><span class="facet-detail">{_e(row.detail)}</span></li>'
        )
    listing = f'<ol class="invariant-list" data-equivalent-of="invariants">{"".join(items)}</ol>'
    return _section(
        "invariants",
        "Invariant ring",
        "every applicable invariant must hold for a PASS",
        f'<div class="ring-layout">{figure}{listing}</div>',
    )


def _ledger_section(doc: Mapping[str, Any]) -> str:
    ledger = _ledger_view(doc)
    figure = _figure(
        "ledger",
        _chain_svg(ledger),
        "Each link is one ledger entry, and each entry hashes the entry before it. A filled link is the STARTED "
        "entry of a check's invocation, placed exactly by recomputing inv-sha256(run_id:seq). The other entries "
        "(terminal results) are in ledger.jsonl and are not identified from run.json.",
        "scroll-wide",
    )
    rows = [
        [_e(seq), _code(check.get("invocation_id")), _code(check.get("check_id")), _status_pill(check.get("verdict"))]
        for seq, checks in ledger.starts.items()
        for check in checks
    ]
    table = _table(
        "Invocation starts placed on the chain",
        ("Seq", "Invocation", "Check", "Verdict"),
        rows,
        equivalent_of="ledger",
        empty="no invocation start could be placed",
    )
    facts = [
        ("Entries", _e(_count(ledger.length))),
        ("Head", _hash(ledger.head)),
    ]
    if not ledger.derived:
        facts.append(
            ("Positions", '<span class="muted">not derived: the run id or ledger length is missing or too large</span>')
        )
    if ledger.unplaced:
        facts.append(
            (
                "Not placeable",
                ", ".join(
                    f"{_code(check.get('invocation_id'))} ({_e(check.get('check_id'))})" for check in ledger.unplaced
                )
                + " \u2014 no seq up to the ledger length derives these ids",
            )
        )
    if ledger.without_invocation:
        facts.append(
            ("Without invocation", ", ".join(_code(check.get("check_id")) for check in ledger.without_invocation))
        )
    reverification = doc.get("reverification")
    if isinstance(reverification, dict):
        observed = _dict(reverification.get("ledger"))
        same_head = observed.get("observed_head") == ledger.head and ledger.head is not None
        facts.append(
            (
                "Re-verified",
                f"chain intact {_e(observed.get('intact'))}, {_e(_count(observed.get('observed_length')))} entries "
                f"observed, head {_hash(observed.get('observed_head'))} "
                + ("(matches the seal)" if same_head else "(does not match the seal)"),
            )
        )
    fact_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    return _section(
        "ledger",
        "Ledger chain",
        "append-only, hash-chained, sealed by its head",
        f'{figure}<dl class="meta compact" data-equivalent-of="ledger">{fact_html}</dl>{table}',
    )


def _result_text(value: Any) -> Any:
    """A mutation's expected or actual result as people read it.

    A result that states its rule shows the rule; one with a status shows
    ``STATUS (REASON)``. Any other value is shown as recorded.
    """
    if isinstance(value, dict):
        if _str(value.get("rule")):
            return value["rule"]
        if _str(value.get("status")):
            return f"{value['status']} ({_plain(value.get('reason'))})"
    return value


def _fired_label(item: Any) -> Any:
    """A fired detector as ``detector STATUS``; an item of any other shape is kept as recorded."""
    if isinstance(item, dict) and "detector" in item:
        return f"{_plain(item.get('detector'))} {_plain(item.get('status'))}"
    return item


def _fired_cell(item: _Mutation) -> str:
    """The detectors a mutant's verify fired, with the expected one first and marked.

    The expected detector is what decides a detection, so it is listed in
    the open. The other findings are folded into a ``details`` element: they
    stay in the page (and in its text) but do not bury the one that matters.
    """
    fired = item.record.get("detecting_invariants_fired")
    if not isinstance(fired, list):
        return '<span class="muted">none recorded</span>'
    if not fired:
        return '<span class="muted">none</span>'
    hits = [entry for entry in fired if item.rule.matches(entry)]
    others = [entry for entry in fired if not item.rule.matches(entry)]
    parts = []
    if hits:
        rows = "".join(
            f'<li class="hit">{_e(_fired_label(entry))}<em class="hit-tag">expected</em></li>' for entry in hits
        )
        parts.append(f'<ul class="fired">{rows}</ul>')
    if others:
        summary = (
            f"{len(others)} other finding(s)" if hits else f"{len(others)} finding(s), none from the expected detector"
        )
        rows = "".join(f"<li>{_e(_fired_label(entry))}</li>" for entry in others)
        parts.append(f'<details class="fired-more"><summary>{summary}</summary><ul class="fired">{rows}</ul></details>')
    return "".join(parts)


def _mutation_head(report: Mapping[str, Any]) -> str:
    """The mutation report's own outcome and identity, as recorded.

    The page does not re-decide the report's status. It shows it beside the
    records, and :func:`_mutation_view` lists anything the records contradict.
    """
    manifest = _dict(report.get("manifest"))
    operators, selected = report.get("operators"), report.get("selected_operators")
    selection = (
        f"{len(selected)} of {len(operators)} operators selected"
        if isinstance(operators, list) and isinstance(selected, list)
        else "operator selection not recorded"
    )
    facts = [
        ("Report", _code(report.get("report_id"))),
        ("Generated", _e(report.get("generated_at"))),
        ("Manifest", f"{_code(manifest.get('file'))} sha256 {_hash(manifest.get('sha256'))}"),
        ("Operators", _e(selection)),
        ("Baseline run", _code(_dict(report.get("baseline")).get("run_id"))),
    ]
    rows = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    message = report.get("message")
    return (
        '<div class="mut-head"><p class="kicker">Mutation report, as recorded</p>'
        f'<div class="mut-line">{_status_pill(report.get("status"))}<span class="mut-reason">'
        f'{_e(report.get("reason"))} \u00b7 exit code {_e(_count(report.get("exit_code")))}</span></div>'
        + (f'<p class="mut-message">{_e(message)}</p>' if message is not None else "")
        + f'<dl class="meta compact">{rows}</dl></div>'
    )


def _mutation_figures(report: Mapping[str, Any], view: _MutationView) -> str:
    """Baseline and sensitivity tiles, the six counts, and why a figure is missing when it is."""
    baseline = _dict(report.get("baseline"))
    reason = baseline.get("reason")
    note = (f"{_e(reason)} \u00b7 " if reason is not None else "") + "must be PASS for any figure"
    tiles = [_stat("Baseline", _e(view.baseline_status), note, known=view.baseline_valid)]
    if not view.baseline_valid:
        diagnostics = "".join(f"<li>{_e(text)}</li>" for text in _strs(baseline.get("diagnostics")))
        return (
            f'<div class="stats">{"".join(tiles)}</div>'
            f'<div class="notice t-serious"><p>{_e(NO_SENSITIVITY_SENTENCE)}</p>'
            + (f"<ul>{diagnostics}</ul>" if diagnostics else "")
            + "</div>"
        )
    if view.sensitivity is not None:
        fraction, decimal, rounding = view.sensitivity
        detail = f"detected / executed = {_e(decimal)}" + (f" ({_e(rounding)})" if rounding is not None else "")
        tiles.append(_stat("Sensitivity", _e(fraction), detail, known=True))
    else:
        why_none = "no figure: nothing executed, or none the records support"
        tiles.append(_stat("Sensitivity", "none", why_none, known=False))
    unknown = ' class="unknown"'
    strip = "".join(
        f"<div><dt>{_e(label)}</dt><dd{'' if view.counts[key] is not None else unknown}>"
        f"{_e(_count(view.counts[key]))}</dd></div>"
        for key, label in _MUTATION_COUNTS
    )
    return (
        f'<div class="stats">{"".join(tiles)}</div>'
        f'<dl class="count-strip">{strip}</dl>'
        '<p class="small muted strip-note">Counts as the report states them. The page re-tallies them from the '
        "records below and lists any disagreement.</p>"
    )


def _mutation_row(item: _Mutation) -> list[str]:
    """One table row. Notes sit under the outcome they qualify, so a disagreement is read with the group.

    Only a disagreement between the record and its own evidence is
    highlighted. The record's diagnostics (such as why an operator did not
    apply) are ordinary lines, so the highlight keeps its meaning.
    """
    record = item.record
    target = record.get("target")
    firing_tone, firing_glyph = _FIRING_STYLE[item.firing]
    note = f'<div class="cell-note">{_e(item.note)}</div>' if item.note else ""
    diagnostics = "".join(_sub(_e(text)) for text in _strs(record.get("diagnostics")))
    # The recorded execution state is shown when it adds to the group: CHECKED
    # under DETECTED does, a second SKIPPED under SKIPPED does not.
    state = record.get("execution_state")
    state_line = "" if _is(state, item.group) else _sub(_e(state))
    return [
        _breakable(item.mutation_id)
        + _sub(_e(record.get("description")))
        # The target is a sentence ("delete the accepted record at line 7 ..."), not an identifier, so it wraps.
        + (_sub(f"Target: {_e(target)}") if target is not None else ""),
        _pill(item.group, *_MUTATION_STYLE[item.group]) + state_line + note + diagnostics,
        _e(_result_text(record.get("expected_result"))),
        _e(_result_text(record.get("actual_result"))),
        _pill(item.firing, firing_tone, firing_glyph) + _sub(_breakable(item.rule.label)),
        _fired_cell(item),
    ]


def _mutation_section(report: Any) -> str:
    if not isinstance(report, dict):
        return _section(
            "mutations",
            "Mutation constellation",
            "detected vs blind spot",
            '<p class="muted">The mutation report is not a JSON object, so nothing in it can be shown and no '
            "sensitivity figure is given.</p>",
        )
    view = _mutation_view(report)
    discrepancies = "".join(f"<li>{_e(text)}</li>" for text in view.discrepancies)
    discrepancy_html = (
        f'<div class="notice t-warning"><p>The mutation report is inconsistent with its own records:</p>'
        f"<ul>{discrepancies}</ul></div>"
        if discrepancies
        else ""
    )
    figure = (
        _figure(
            "mutations",
            _constellation_svg(view),
            "Each star is one mutation of the verifier's input. Detected: the status left PASS and the expected "
            "detector fired. Blind spot: it executed and nothing caught it. Skipped and not-applicable mutations "
            "are drawn apart and never count as detections.",
            "scroll-wide",
        )
        if view.mutations
        else ""
    )
    table = _table(
        "Mutations",
        ("Mutation", "Outcome and notes", "Expected result", "Actual result", "Expected detector", "Detectors fired"),
        [_mutation_row(item) for item in view.mutations],
        equivalent_of="mutations",
        empty="no mutation record",
        css="mutation-table",
    )
    diagnostics = "".join(f"<li>{_e(text)}</li>" for text in _strs(report.get("diagnostics")))
    not_proven = "".join(f"<li>{_e(text)}</li>" for text in _strs(report.get("not_proven")))
    return _section(
        "mutations",
        "Mutation constellation",
        "detected vs blind spot",
        _mutation_head(report)
        + _mutation_figures(report, view)
        + discrepancy_html
        + figure
        + table
        + (f'<h3 class="sub-h">Report diagnostics</h3><ul class="plain-list">{diagnostics}</ul>' if diagnostics else "")
        + (
            f'<h3 class="sub-h">What this mutation report does not prove</h3><ul class="plain-list">{not_proven}</ul>'
            if not_proven
            else ""
        ),
    )


def _findings_section(doc: Mapping[str, Any]) -> str:
    """Every recorded finding, then every manifest issue.

    Manifest issues get their own table because they are sometimes the only
    explanation there is: a re-rendered run whose run.json is unusable
    carries nothing else.
    """
    items = []
    for finding in _dicts(doc.get("findings")):
        items.append(
            f"<li>{_status_pill(finding.get('status'))} <strong>{_e(finding.get('reason'))}</strong> "
            f"{_code(finding.get('source'))} {_chips(finding.get('failure_modes'))}"
            f'<div class="finding-detail">{_e(finding.get("detail"))}</div></li>'
        )
    body = f'<ol class="findings">{"".join(items)}</ol>' if items else '<p class="muted">No finding was recorded.</p>'
    issues = [
        # An empty pointer is the document root, written "/" as the manifest module prints it.
        [_code(issue.get("code")), _code("/" if issue.get("pointer") == "" else issue.get("pointer")),
         _e(issue.get("message"))]
        for issue in _dicts(_dict(doc.get("manifest")).get("issues"))
    ]
    if issues:
        body += _table(
            "Manifest issues", ("Code", "Where", "Message"), issues, equivalent_of=None, empty="none"
        )
    return _section("findings", "Findings", "in the order the decision weighed them", body)


def _required_word(value: Any) -> str:
    """Only the booleans count: ``1`` is not ``true`` here, and a list is not a flag."""
    return "required" if value is True else "optional" if value is False else "unknown"


def _digest_cell(computed: Any, declared: Any, outcome: str) -> str:
    """The computed SHA-256, with the declared one beneath it and how the two compare.

    Both digests share one column so that each can wrap in two lines instead
    of being squeezed into a column of four-character fragments.
    """
    if _str(declared) is None:
        return _hash(computed) + _sub("no digest declared")
    verdict = f"<strong>{_e(outcome)}</strong>" if outcome == "mismatch" else _e(outcome)
    return _hash(computed) + _sub(f"declared {_hash(declared)} \u00b7 {verdict}")


def _inputs_section(doc: Mapping[str, Any]) -> str:
    records = _accounting_inputs(doc)
    # A tuple, not a set: a tampered id may be unhashable, and membership must not raise.
    recorded = tuple(item.get("id") for item in records)
    rows = [
        [
            _code(item.get("id")),
            _e(_required_word(item.get("required"))),
            _path(item.get("path")),
            _e(item.get("state")),
            _digest_cell(item.get("sha256"), item.get("declared_sha256"), _digest_outcome(item)),
            _e(_count(item.get("bytes"))),
            "<br>".join(_e(text) for text in _strs(item.get("diagnostics"))) or '<span class="muted">none</span>',
        ]
        for item in records
    ]
    rows += [
        [_code(spec.get("id")), _e("declared"), _path(spec.get("path")), _e("NO RECORD"),
         _digest_cell(None, spec.get("sha256"), "not compared"), _e("unknown"),
         _e("declared in the manifest but absent from the accounting")]
        for spec in _dicts(_dict(doc.get("declared")).get("inputs"))
        if spec.get("id") not in recorded
    ]
    inputs = _table(
        "Inputs",
        ("Input", "Required", "Path", "State", "SHA-256 computed, then declared", "Bytes", "Diagnostics"),
        rows,
        equivalent_of="accounting",
        empty="no input was declared or recorded",
        css="input-table",
    )
    documents = _table(
        "Other documents read",
        ("Path", "Roles", "State", "SHA-256", "Bytes", "Diagnostic"),
        [
            [_path(item.get("path")), _chips(item.get("roles")), _e(item.get("state")), _hash(item.get("sha256")),
             _e(_count(item.get("bytes"))), _e(item.get("diagnostic"))]
            for item in _dicts(doc.get("documents"))
        ],
        equivalent_of="accounting",
        empty="none",
    )
    return _section("inputs", "Inputs and documents", "every declared file, including missing ones", inputs + documents)


def _signature_check(receipt: Mapping[str, Any]) -> str:
    """What re-verification established about the receipt's signature, in words.

    ``signature_verified`` is None both for an unsigned receipt and for a
    signed one checked without its key. The two are told apart, because
    "not checked" must never read as "verified" or as "nothing to check".
    """
    verified = receipt.get("signature_verified")
    if verified is True:
        return "signature verified"
    if verified is False:
        return "signature did NOT verify"
    if _is(receipt.get("signature_state"), "UNSIGNED"):
        return "no signature to verify"
    return "signature not checked"


def _reverification_section(reverification: Mapping[str, Any]) -> str:
    receipt = _dict(reverification.get("receipt"))
    ledger = _dict(reverification.get("ledger"))
    ok = reverification.get("ok") is True
    facts = [
        ("Result", _pill("PASSED" if ok else "FAILED", "good" if ok else "critical", "check" if ok else "cross")),
        (
            "Receipt",
            f"content intact {_e(receipt.get('content_intact'))} \u00b7 signature {_e(receipt.get('signature_state'))} "
            f"\u00b7 {_e(_signature_check(receipt))}",
        ),
        (
            "Ledger chain",
            f"intact {_e(ledger.get('intact'))} \u00b7 {_e(_count(ledger.get('observed_length')))} entries \u00b7 head "
            f"{_hash(ledger.get('observed_head'))}",
        ),
    ]
    for item in _dicts(reverification.get("invariants")):
        name, holds, detail = _breakable(item.get("name")), _e(item.get("holds")), _e(item.get("detail"))
        facts.append((f"Invariant {name}", f"holds {holds}: {detail}"))
    fact_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    problems = "".join(f"<li>{_e(text)}</li>" for text in _strs(reverification.get("problems")))
    notes = "".join(f"<li>{_e(text)}</li>" for text in _strs(reverification.get("notes")))
    lists = [
        f'<ul class="plain-list">{items}</ul>' if items else '<p class="muted">none</p>' for items in (problems, notes)
    ]
    body = (
        f'<dl class="meta compact">{fact_html}</dl>'
        f'<h3 class="sub-h">Problems</h3>{lists[0]}<h3 class="sub-h">Not checked</h3>{lists[1]}'
    )
    return _section("reverification", "Re-verification", "science-gate report RUN_DIR re-read this directory", body)


def _boundary_section(doc: Mapping[str, Any]) -> str:
    live = _dict(doc.get("network")).get("live") is True
    items = [
        f"Scientific validity: {VALIDITY_LABEL}. Whether any conclusion holds in its intended domain is outside what "
        "this tool can show.",
        "A PASS shows only that the declared checks had the opportunity to fail on the declared inputs and did not. "
        "It says nothing about inputs, checks or questions that were not declared, and nothing about whether the "
        "declared expectations were the right ones.",
        "Network: live lookups were enabled for this run."
        if live
        else "Network: no live lookup was performed; nothing was confirmed against an external source.",
    ]
    listing = "".join(f"<li>{_e(item)}</li>" for item in items)
    return _section(
        "boundary",
        "What this result does not prove",
        "read before relying on any status above",
        f'<ul class="plain-list">{listing}</ul><p class="disclaimer">{_e(doc.get("disclaimer"))}</p>',
    )


def _footer(doc: Mapping[str, Any]) -> str:
    tool = _dict(doc.get("tool"))
    return (
        '<footer class="footer">'
        f"<p>Rendered from {_e(doc.get('schema'))} by {_e(tool.get('name'))} {_e(tool.get('version'))}. "
        "This page is self-contained: no scripts, no external requests, no web fonts. "
        "The same document always renders to the same bytes.</p></footer>"
    )


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

_LIGHT = {
    "page": "#f9f9f7",
    "surface": "#fcfcfb",
    "surface-2": "#f3f2ee",
    "ink": "#0b0b0b",
    "ink-2": "#52514e",
    "muted": "#898781",
    "grid": "#e1e0d9",
    "axis": "#c3c2b7",
    "border": "rgba(11,11,11,0.10)",
    "accent": "#2a78d6",
    "accent-soft": "rgba(42,120,214,0.13)",
    "good-soft": "rgba(12,163,12,0.12)",
    "warning-soft": "rgba(250,178,25,0.20)",
    "serious-soft": "rgba(236,131,90,0.18)",
    "critical-soft": "rgba(208,59,59,0.12)",
    "muted-soft": "rgba(137,135,129,0.14)",
    "void": "#141413",
    "void-edge": "#3d3d3a",
    "void-ink": "#b9b8b0",
    "void-grid": "rgba(255,255,255,0.07)",
    "stage-glow": "rgba(42,120,214,0.10)",
    "shadow": "0 1px 2px rgba(11,11,11,0.04), 0 10px 30px rgba(11,11,11,0.05)",
}
_DARK = {
    **_LIGHT,
    "page": "#0d0d0d",
    "surface": "#1a1a19",
    "surface-2": "#222220",
    "ink": "#ffffff",
    "ink-2": "#c3c2b7",
    "grid": "#2c2c2a",
    "axis": "#383835",
    "border": "rgba(255,255,255,0.10)",
    "accent": "#3987e5",
    "accent-soft": "rgba(57,135,229,0.20)",
    "good-soft": "rgba(12,163,12,0.20)",
    "warning-soft": "rgba(250,178,25,0.18)",
    "serious-soft": "rgba(236,131,90,0.18)",
    "critical-soft": "rgba(208,59,59,0.22)",
    "muted-soft": "rgba(137,135,129,0.20)",
    "void": "#050505",
    "void-edge": "#4a4a46",
    "void-ink": "#a9a89f",
    "stage-glow": "rgba(57,135,229,0.16)",
    "shadow": "none",
}


def _variables(theme: Mapping[str, str]) -> str:
    return "".join(f"--{name}:{value};" for name, value in theme.items())


_CSS = (
    ":root{color-scheme:light;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;"
    "--on-good:#ffffff;--on-warning:#0b0b0b;--on-serious:#0b0b0b;--on-critical:#ffffff;--on-accent:#ffffff;"
    "--on-muted:#ffffff;"
    + _variables(_LIGHT)
    + "}"
    '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;'
    + _variables(_DARK)
    + "}}"
    ':root[data-theme="dark"]{color-scheme:dark;'
    + _variables(_DARK)
    + "}"
    """
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.page{max-width:1180px;margin:0 auto;padding:28px 16px 64px}
@media (min-width:760px){.page{padding:44px 32px 88px}}
h1,h2,h3{margin:0;line-height:1.2;letter-spacing:-0.01em}
h1{font-size:30px;font-weight:700;overflow-wrap:anywhere}
h2{font-size:20px;font-weight:650}
h3{font-size:15px;font-weight:650}
p{margin:0}
code{font-family:ui-monospace,"Cascadia Mono","SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:.9em}
code.wrap{overflow-wrap:anywhere}
td code:not(.wrap):not(.brk){white-space:nowrap}
code.brk{overflow-wrap:break-word}
.small{font-size:12px}
.muted{color:var(--ink-2)}
.t-good{--tone:var(--good);--tone-soft:var(--good-soft);--on-tone:var(--on-good)}
.t-warning{--tone:var(--warning);--tone-soft:var(--warning-soft);--on-tone:var(--on-warning)}
.t-serious{--tone:var(--serious);--tone-soft:var(--serious-soft);--on-tone:var(--on-serious)}
.t-critical{--tone:var(--critical);--tone-soft:var(--critical-soft);--on-tone:var(--on-critical)}
.t-accent{--tone:var(--accent);--tone-soft:var(--accent-soft);--on-tone:var(--on-accent)}
.t-muted{--tone:var(--muted);--tone-soft:var(--muted-soft);--on-tone:var(--on-muted)}
.masthead{display:grid;gap:18px}
.eyebrow{font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-2)}
.verdict{display:flex;align-items:center;gap:20px;padding:20px 22px;background:var(--surface);
  border:1px solid var(--border);border-left:6px solid var(--tone);border-radius:16px;box-shadow:var(--shadow)}
.verdict-disc{width:56px;height:56px;flex:none}
@media (max-width:560px){.verdict{flex-direction:column;align-items:flex-start;gap:12px;padding:18px}
  .verdict-disc{width:44px;height:44px}.verdict-chips dt{min-width:0;width:100%}}
.verdict-body{display:grid;gap:8px;min-width:0}
.verdict-line{display:flex;align-items:baseline;flex-wrap:wrap;gap:6px 14px}
.verdict-word{font-size:44px;font-weight:750;letter-spacing:-0.02em;line-height:1;overflow-wrap:anywhere}
.verdict-reason{font-size:15px;color:var(--ink-2)}
.verdict-chips{display:grid;gap:5px;margin:0;font-size:13px;color:var(--ink-2)}
.verdict-chips div{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px}
.verdict-chips dt{min-width:124px}
.verdict-chips dd{margin:0;display:flex;flex-wrap:wrap;gap:4px}
.why{display:grid;gap:6px;padding:10px 14px;border-radius:10px;background:var(--tone-soft)}
.why-label,.kicker{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-2)}
.why-list{margin:0;padding-left:20px;display:grid;gap:6px;font-size:13px}
.why-list li{overflow-wrap:anywhere}
.why-detail{color:var(--ink-2)}
.why-none,.why-more{font-size:13px}
.why-more a,.fired-more summary{color:var(--accent)}
.verdict-note{font-size:14px;padding:8px 12px;border-radius:10px;background:var(--tone-soft)}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;background:var(--surface-2);
  border:1px solid var(--border);font-size:12px;color:var(--ink)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px 16px}
.stat-label{font-size:12px;color:var(--ink-2)}
.stat-value{font-size:26px;font-weight:650;margin-top:2px;overflow-wrap:anywhere}
.stat-value.unknown{color:var(--muted)}
.stat-note{font-size:12px;color:var(--ink-2)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:8px 24px;margin:0;
  font-size:13px}
.meta div{display:grid;grid-template-columns:130px minmax(0,1fr);gap:10px;padding:6px 0;
  border-top:1px solid var(--grid)}
.meta dt{color:var(--ink-2);min-width:0;overflow-wrap:anywhere}
.meta dd{margin:0;min-width:0;overflow-wrap:anywhere}
.meta.compact{margin-top:14px}
.scope{font-size:13px;color:var(--ink-2)}
.banner{margin-top:22px;padding:16px 20px;border-radius:14px;border:1px solid var(--tone);background:var(--tone-soft)}
.banner h2{font-size:17px;margin-bottom:6px}
.banner ul{margin:10px 0 0;padding-left:20px}
.toc{display:flex;flex-wrap:wrap;gap:8px;margin:24px 0 0;padding:0;list-style:none}
.toc a{display:inline-block;padding:4px 12px;border-radius:999px;border:1px solid var(--border);
  background:var(--surface);color:var(--ink-2);text-decoration:none;font-size:13px}
.toc a:hover,.toc a:focus-visible{color:var(--ink);border-color:var(--accent);outline:none}
.panel{margin-top:24px;background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:22px;
  box-shadow:var(--shadow)}
.section-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:6px 16px;
  margin-bottom:16px}
.section-head p{font-size:13px;color:var(--ink-2)}
.stage{border-radius:14px;padding:8px;
  background:radial-gradient(90% 80% at 32% 58%,var(--stage-glow),transparent 70%),var(--surface-2)}
.viz{margin:0}
.viz-scroll{overflow-x:auto}
.viz-scroll:focus-visible,.table-wrap:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.viz svg{display:block;width:100%;height:auto}
.scroll-wide svg{min-width:560px}
.scroll-panel svg{min-width:440px;max-width:620px}
.scroll-ring svg{min-width:260px;max-width:360px;margin:0 auto}
.hologram-svg{max-width:880px;margin:0 auto}
figcaption{font-size:13px;color:var(--ink-2);margin-top:10px}
.split{display:grid;gap:24px;grid-template-columns:minmax(0,1fr)}
@media (min-width:980px){.split{grid-template-columns:minmax(0,1.1fr) minmax(0,1fr)}}
.side{display:grid;gap:8px;align-content:start;padding:16px;border:1px solid var(--border);border-radius:14px;
  background:var(--surface-2)}
.counter-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:0 18px;margin:4px 0 0;
  font-size:13px}
.counter-list div{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-top:1px solid var(--grid)}
.counter-list dt{color:var(--ink-2)}
.counter-list dd{margin:0;font-variant-numeric:tabular-nums;font-weight:600}
.ring-layout{display:grid;gap:24px;grid-template-columns:minmax(0,1fr);align-items:center}
@media (min-width:900px){.ring-layout{grid-template-columns:360px minmax(0,1fr)}}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:12px 0 0;padding:0;list-style:none;font-size:12px;
  color:var(--ink-2)}
.legend li{display:inline-flex;align-items:center;gap:7px}
.swatch{display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid var(--tone)}
.sw-fill,.sw-lit{background:var(--tone)}
.sw-partial{background:linear-gradient(90deg,var(--tone) 50%,transparent 50%)}
.sw-broken{background:var(--tone)}
.sw-hollow,.sw-dark{background:transparent}
.planes{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));margin-top:18px}
.plane-card{border:1px solid var(--border);border-radius:14px;padding:16px;background:var(--surface);display:grid;
  gap:10px;align-content:start}
.plane-card h3{display:flex;flex-wrap:wrap;justify-content:space-between;gap:4px 12px}
.card-sum{font-size:12px;font-weight:500;color:var(--ink-2)}
.plane-question{font-size:13px;color:var(--ink-2)}
.plane-card.void{background:var(--void);border-color:var(--void-edge);color:var(--void-ink)}
.plane-card.void h3,.plane-card.void .card-sum,.plane-card.void .plane-question{color:var(--void-ink)}
.recorded{font-size:12px;color:var(--ink-2);overflow-wrap:anywhere}
.plane-card.void .recorded{color:var(--void-ink)}
.facets,.invariant-list,.findings{margin:0;padding:0;display:grid;gap:10px}
.facets{list-style:none;grid-template-columns:auto minmax(0,1fr)}
.invariant-list{list-style:none;grid-template-columns:auto auto minmax(0,1fr) auto}
.facets li,.invariant-list li{grid-column:1 / -1;display:grid;grid-template-columns:auto minmax(0,1fr);
  grid-template-columns:subgrid;gap:2px 10px;align-items:baseline;font-size:13px}
.invariant-list li{grid-template-columns:auto auto minmax(0,1fr) auto;grid-template-columns:subgrid}
.inv-num{min-width:1.4em;text-align:right;color:var(--ink-2);font-variant-numeric:tabular-nums}
.facets .pill,.invariant-list .pill{justify-self:start}
.facet-name{font-weight:600;min-width:0;overflow-wrap:anywhere}
.facet-detail{grid-column:2 / -1;color:var(--ink-2);font-size:12px;overflow-wrap:anywhere}
.invariant-list .facet-detail{grid-column:3 / -1}
.plane-tag{font-size:11px;color:var(--ink-2);text-transform:uppercase;letter-spacing:.06em}
@media (max-width:560px){.invariant-list{grid-template-columns:auto auto minmax(0,1fr)}
  .invariant-list li{grid-template-columns:auto auto minmax(0,1fr);grid-template-columns:subgrid}
  .plane-tag{grid-column:3}}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 9px 2px 3px;border-radius:999px;
  background:var(--tone-soft);color:var(--ink);font-size:12px;font-weight:600;white-space:nowrap;max-width:100%}
.pill-dot{display:inline-grid;place-items:center;width:17px;height:17px;border-radius:50%;background:var(--tone);
  color:var(--on-tone);font-size:11px;line-height:1;flex:none}
.closure-line{margin-bottom:4px}
.closure-line .pill,td .pill{white-space:normal}
.stats-note{font-size:13px;color:var(--ink-2);margin-bottom:-6px}
.table-wrap{overflow-x:auto;margin-top:14px;border:1px solid var(--border);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
caption{text-align:left;padding:10px 12px;font-weight:600;font-size:13px}
th,td{padding:7px 10px;text-align:left;vertical-align:top;border-top:1px solid var(--grid)}
td:last-child{min-width:200px}
thead th{background:var(--surface-2);font-size:12px;font-weight:600;color:var(--ink-2)}
.findings{padding-left:24px}
.findings li{font-size:13px}
.finding-detail{color:var(--ink-2);margin-top:4px;overflow-wrap:anywhere}
.notice{margin-top:14px;padding:12px 16px;border-radius:12px;background:var(--tone-soft);border:1px solid var(--tone);
  font-size:14px}
.notice ul{margin:8px 0 0;padding-left:20px}
.mut-head{display:grid;gap:8px;margin-bottom:16px}
.mut-line{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px}
.mut-line .pill{font-size:13px}
.mut-reason{font-size:14px;color:var(--ink-2)}
.mut-message{font-size:14px}
.count-strip{display:flex;flex-wrap:wrap;gap:1px;margin:12px 0 0;background:var(--grid);border:1px solid var(--border);
  border-radius:14px;overflow:hidden}
.count-strip div{flex:1 1 120px;background:var(--surface);padding:10px 16px}
.count-strip dt{font-size:12px;color:var(--ink-2)}
.count-strip dd{margin:0;font-size:22px;font-weight:650;font-variant-numeric:tabular-nums}
.count-strip dd.unknown{color:var(--muted)}
.strip-note{margin-top:6px}
.cell-sub{font-size:12px;color:var(--ink-2);margin-top:3px;overflow-wrap:anywhere}
.cell-sub.words{overflow-wrap:normal}
.cell-note{font-size:12px;margin-top:6px;padding:4px 8px;border-radius:8px;background:var(--warning-soft);
  overflow-wrap:anywhere}
.fired{margin:0;padding:0;list-style:none;display:grid;gap:3px;font-size:12px}
.fired li{overflow-wrap:anywhere;color:var(--ink-2)}
.fired li.hit{color:var(--ink);font-weight:600}
.hit-tag{font-style:normal;font-size:10.5px;font-weight:650;margin-left:6px;padding:0 6px;border-radius:999px;
  background:var(--good-soft);color:var(--ink)}
.fired-more{margin-top:4px;font-size:12px}
.fired-more summary{cursor:pointer}
.fired-more .fired{margin-top:4px}
.mutation-table td{min-width:110px}
.mutation-table td:first-child{min-width:190px}
.mutation-table td:last-child{min-width:220px}
.mutation-table td .pill{white-space:nowrap}
.input-table td:nth-child(5){min-width:250px}
.input-table td:last-child{overflow-wrap:anywhere}
.check-table td:first-child{min-width:150px}
.check-table td:last-child{min-width:220px}
.sub-h{margin:22px 0 8px}
.plain-list{margin:0;padding-left:20px;display:grid;gap:8px;font-size:14px}
.disclaimer{margin-top:14px;font-size:13px;color:var(--ink-2)}
.footer{margin-top:28px;font-size:12px;color:var(--ink-2)}
svg text{font-family:inherit}
.sv-title{font-size:16px;font-weight:650;fill:var(--ink)}
.sv-sub{font-size:12px;fill:var(--ink-2)}
.sv-small{font-size:10.5px;fill:var(--ink-2)}
.sv-caps{font-size:10.5px;font-weight:650;letter-spacing:.08em;fill:var(--ink-2)}
.sv-label{font-size:12.5px;fill:var(--ink)}
.sv-value{font-size:12px;fill:var(--ink-2);font-variant-numeric:tabular-nums}
.sv-mono{font-family:ui-monospace,"Cascadia Mono","SFMono-Regular",Consolas,monospace;font-size:12px;fill:var(--ink)}
.sv-axis{stroke:var(--axis);stroke-width:1}
.sv-grid{stroke:var(--grid);stroke-width:1}
.fill-tone{fill:var(--tone)}
.hollow{fill:var(--surface);stroke:var(--tone);stroke-width:1.5}
.glyph{fill:none;stroke-linecap:round;stroke-linejoin:round}
.glyph-on{stroke:var(--on-tone)}
.glyph-tone{stroke:var(--tone)}
.target{stroke:var(--ink-2);stroke-width:1.25}
.flow{stroke:var(--accent);stroke-width:2;stroke-linecap:round;opacity:.55}
.connector{stroke:var(--axis);stroke-width:1}
.leader{stroke:var(--axis);stroke-width:1}
.plane-fill{fill:var(--accent)}
.plane-edge{fill:none;stroke:var(--accent);stroke-width:1.25}
.plane-edge.broken{stroke:var(--critical);stroke-width:2}
.plane-grid{stroke:var(--accent);stroke-width:.75;opacity:.22}
.plane-void{fill:var(--void);stroke:var(--void-edge);stroke-width:1.25}
.plane-void-grid{stroke:var(--void-grid);stroke-width:.75}
.void-text{fill:var(--void-ink);font-size:11px;font-weight:650;letter-spacing:.18em}
.void-sub{fill:var(--void-ink);font-size:11px}
.tile-lit{fill:var(--accent)}
.tile-outline{fill:none;stroke:var(--accent);stroke-width:1.25}
.tile-dark{fill:none;stroke:var(--muted);stroke-width:1.25}
.tile-broken{fill:var(--critical)}
.beam{stroke-width:3;stroke-linecap:round}
.beam-stop-base{stop-color:var(--accent);stop-opacity:.95}
.beam-stop-top{stop-color:var(--accent);stop-opacity:.15}
.beam-cap{fill:var(--accent)}
.beam-source{fill:var(--accent)}
.ring-figure{font-size:26px;font-weight:650;fill:var(--ink)}
.link{fill:var(--surface);stroke:var(--axis);stroke-width:1.25}
.link-start{fill:var(--accent);stroke:var(--accent);stroke-width:1.25}
.link-empty{fill:none;stroke:var(--axis);stroke-width:1.25}
.link-seq{font-size:10.5px;fill:var(--ink-2)}
.link-seq-on{font-size:10.5px;fill:var(--on-accent);font-weight:650}
.chain-link{stroke:var(--accent);stroke-width:2;opacity:.6}
.arrow-tip{fill:var(--accent);opacity:.8}
.head{fill:var(--accent-soft);stroke:var(--accent);stroke-width:1.25}
.star-line{stroke:var(--tone);stroke-width:1;opacity:.35}
.star-halo{fill:none;stroke:var(--tone);stroke-width:1.5;opacity:.55}
@media print{body{background:#ffffff}.panel,.verdict,.stat{box-shadow:none}.viz-scroll,.table-wrap{overflow:visible}}
"""
)

#: No scripts, no plugins, no frames, no requests. Inline styles are the only
#: resource the page needs. ``form-action`` and ``base-uri`` close the last
#: two navigation vectors that ``default-src`` does not cover.
_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def render(run: Any, mutation: Any = None) -> str:
    """Render ``report.html`` for a ``run.json`` document, optionally with a mutation report.

    ``run`` is the run document as a dict (see
    :func:`science_gate.reports.run_document`). A re-rendered run may also
    carry ``reverification`` and, when that failed, ``recorded_status``.
    Anything else, including a value that is not a dict, still renders: its
    missing parts are shown as missing, and the function never raises on
    the document's shape.

    ``mutation`` is a section 10 mutation report (``mutation-report.json``).
    The renderer reads:

    * ``mutations``: the list of records, with ``mutation_id``,
      ``description``, ``target``, ``expected_result`` (its ``rule``, and
      the ``detector``, ``detector_statuses`` and ``detector_signals`` that
      define the expected detector), ``actual_result``, ``applicable``,
      ``execution_state``, ``expected_detector``,
      ``detecting_invariants_fired``, ``detected``, ``blind_spot`` and
      ``diagnostics``;
    * the six count keys, at top level;
    * ``baseline`` (``status``, ``reason``, ``run_id``, ``diagnostics``),
      where any ``status`` or ``reason`` of ``INVALID_BASELINE`` also
      invalidates the baseline;
    * ``sensitivity`` (``fraction``, ``decimal``, ``decimal_rounding``);
    * the report's own ``status``, ``reason``, ``exit_code``, ``message``,
      ``report_id``, ``generated_at``, ``manifest``, ``operators``,
      ``selected_operators``, ``diagnostics`` and ``not_proven``, shown as
      recorded.

    A detection is counted only when the record's own evidence supports it,
    and the sensitivity figure is shown only when the baseline is valid, at
    least one mutation executed, and the figure equals the one the records
    give.
    """
    token = _CLEANED.set({})
    try:
        return _page(run, mutation)
    finally:
        _CLEANED.reset(token)


def _page(run: Any, mutation: Any) -> str:
    """The whole page; :func:`render` documents what it reads."""
    doc = _dict(run)
    invariants = _invariant_rows(doc)
    lattice = _lattice_rows(doc)
    integrity, performance = _planes(doc, invariants, lattice)
    gaps = _pass_contract_gaps(doc, lattice, invariants)
    reverification = doc.get("reverification")
    sections = [
        ("hologram", "Evidence boundary", _hologram_section(doc, integrity, performance)),
        ("accounting", "Input accounting", _accounting_section(doc)),
        ("lattice", "Check lattice", _lattice_section(doc, lattice)),
        ("invariants", "Invariant ring", _invariant_section(invariants)),
        ("ledger", "Ledger chain", _ledger_section(doc)),
    ]
    if mutation is not None:
        sections.append(("mutations", "Mutations", _mutation_section(mutation)))
    sections += [
        ("findings", "Findings", _findings_section(doc)),
        ("inputs", "Inputs", _inputs_section(doc)),
    ]
    if isinstance(reverification, dict):
        sections.append(("reverification", "Re-verification", _reverification_section(reverification)))
    sections.append(("boundary", "Not proven", _boundary_section(doc)))
    title = f"{_plain(doc.get('status'))} \u00b7 {_plain(doc.get('run_id'))} \u00b7 science-gate report"
    page = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="color-scheme" content="light dark">',
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        '<main class="page">',
        _masthead(doc, gaps, invariants, isinstance(run, dict)),
        _banners(doc, gaps),
        _toc([(key, name) for key, name, _ in sections]),
        *(body for _, _, body in sections),
        _footer(doc),
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(page) + "\n"
