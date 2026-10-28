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
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from ._canonical import CanonicalizationError, sha256_canonical
from ._redact import redact_text, redaction_scope
from ._validators import ROWS_EXAMINED_MEANING
from .invariants import (
    CANARY_MUST_FAIL,
    CANARY_MUST_PASS,
    COMPARATOR_CONTROL,
    COMPARATOR_PAIRS,
    INVARIANT_NAMES,
    PLANNED_CONTROLS,
)
from .ledger import invocation_id_for
from .models import EXECUTED_MUTATION_STATUSES, AssertionOutcome, MutationStatus, PieStage, Ratio, WitnessState

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

#: Invariants about *what was executed*, as planned, from pinned files,
#: belong to the Integrity plane. Invariants about whether the checkers could
#: have failed are the Performance plane's CHECKER part (D4); the rest judge
#: the declared evaluation, its RUN part.
_TRACE_INVARIANTS = (
    "checked_claims_le_invocations",
    "every_invocation_has_terminal_result",
    "every_verdict_has_invocation",
)
_PLAN_INVARIANTS = ("plan_closure", "plan_matches_manifest")
_INTEGRITY_INVARIANTS = frozenset(("ledger_chain_intact", *_TRACE_INVARIANTS, *_PLAN_INVARIANTS, "harness_pins_intact"))
_CHECKER_INVARIANTS = frozenset(("comparator_self_test", "canary_controls_hold", "pass_requires_falsifier_witness"))
_EVALUATION_INVARIANTS = tuple(
    name for name in INVARIANT_NAMES if name not in _INTEGRITY_INVARIANTS and name not in _CHECKER_INVARIANTS
)
#: The tag an invariant carries in the ring's list: its plane, and for Performance its D4 part.
_INVARIANT_TAGS = {"integrity": "integrity", "checker": "performance: checker", "run": "performance: run"}

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
    # A mutant built but never executed (a no-op, a duplicate, one nothing read)
    # points at the harness or the operator, so it is marked, not greyed out.
    NOT_EXECUTED_MUTATION: ("warning", "dash"),
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
#: The conservation identities of report v2 (17.12), as ordered partitions:
#: generated = executed + these, and executed = these.
_UNEXECUTED_PARTITION = tuple(
    status.value
    for status in (
        MutationStatus.NOT_APPLICABLE,
        MutationStatus.SUPPRESSED,
        MutationStatus.NOOP_MUTATION,
        MutationStatus.CANONICALLY_EQUIVALENT,
        MutationStatus.DUPLICATE_MUTANT,
        MutationStatus.SKIPPED,
        MutationStatus.NOT_ACTIVATED,
    )
)
_EXECUTED_PARTITION = tuple(status.value for status in MutationStatus if status in EXECUTED_MUTATION_STATUSES)
_BUCKET_TONE = {
    MutationStatus.DETECTED.value: "good",
    MutationStatus.BLIND_SPOT.value: "critical",
    MutationStatus.VERIFIER_ERROR.value: "serious",
    MutationStatus.TIMED_OUT.value: "serious",
    MutationStatus.FLAKY.value: "serious",
    MutationStatus.NOT_APPLICABLE.value: "muted",
    MutationStatus.SKIPPED.value: "muted",
    MutationStatus.SUPPRESSED.value: "warning",
    MutationStatus.NOOP_MUTATION.value: "warning",
    MutationStatus.CANONICALLY_EQUIVALENT.value: "warning",
    MutationStatus.DUPLICATE_MUTANT.value: "warning",
    MutationStatus.NOT_ACTIVATED.value: "warning",
}
#: Where an undetected defect stopped mattering (17.12), in the order a defect travels.
_PIE_STAGES = tuple(stage.value for stage in PieStage)
_PIE_MEANING = {
    PieStage.NOT_READ.value: "the mutated file was never read",
    PieStage.READ_NOT_INFECTED.value: "read, but parsed values were unchanged",
    PieStage.INFECTED_NOT_PROPAGATED.value: "the changed value reached no check",
    PieStage.PROPAGATED_NOT_CHECKED.value: "a check saw the change and still passed",
}
_NO_STAGE = "NO STAGE RECORDED"

#: Falsifier witness states (17.5). Only WITNESSED shows that a PASS could
#: have failed; REFUTED proves a miss; the others leave coverage unknown.
_WITNESS_STYLE = {
    WitnessState.WITNESSED.value: ("good", "check"),
    WitnessState.REFUTED.value: ("critical", "cross"),
    WitnessState.UNWITNESSED.value: ("warning", "question"),
    WitnessState.NO_CASE.value: ("warning", "question"),
    WitnessState.NO_GENERATOR.value: ("warning", "question"),
}
_WITNESS_MEANING = {
    WitnessState.WITNESSED.value: "a known-bad case of its own input was rejected as expected",
    WitnessState.REFUTED.value: "a known-bad case was accepted as PASS: the checker cannot reject it",
    WitnessState.UNWITNESSED.value: "no known-bad case produced its expected rejection",
    WitnessState.NO_CASE.value: "the generator found no known-bad case for this instance",
    WitnessState.NO_GENERATOR.value: "no negative-control generator exists for this kind",
}
#: How one negative control compared with what it had to do. A falsifier
#: records its own outcome word; the other controls are judged here, by
#: equality of the recorded expected and actual values, and never assumed.
_CONTROL_STYLE = {
    "REJECTED": ("good", "check"),
    "ACCEPTED": ("critical", "cross"),
    "INCONCLUSIVE": ("warning", "question"),
    "AS REQUIRED": ("good", "check"),
    "NOT AS REQUIRED": ("critical", "cross"),
    "HOLDS": ("good", "check"),
    "DOES NOT HOLD": ("critical", "cross"),
    "RESOLVED": ("critical", "cross"),
    "NOT HELD": ("warning", "question"),
    "NOT RECORDED": ("warning", "question"),
    **{state: style for state, style in _WITNESS_STYLE.items() if state != WitnessState.WITNESSED.value},
}
_JOIN_OUTCOMES = tuple(outcome.value for outcome in AssertionOutcome)
_JOIN_STYLE = {
    AssertionOutcome.BACKED.value: ("good", "check"),
    AssertionOutcome.NARRATED.value: ("warning", "question"),
    AssertionOutcome.CONTRADICTED.value: ("critical", "cross"),
    AssertionOutcome.ORPHANED.value: ("serious", "bang"),
}
_JOIN_MEANING = {
    AssertionOutcome.BACKED.value: "a terminal invocation backs the claim",
    AssertionOutcome.NARRATED.value: "nothing in the sealed run backs it",
    AssertionOutcome.CONTRADICTED.value: "the invocation recorded otherwise",
    AssertionOutcome.ORPHANED.value: "a failure no assertion mentions",
}

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
_MAX_CONTROL_ROWS = 60
_MAX_DISCRIMINATION_ROWS = 40
_MAX_PLAN_CELLS = 60
_MAX_JOIN_PER_BUCKET = 24
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


def _controls(doc: Mapping[str, Any]) -> Mapping[str, Any]:
    """The run's checker controls (17.8); an absent or malformed block holds nothing."""
    return _dict(doc.get("controls"))


def _evidence(check: Mapping[str, Any]) -> Mapping[str, Any]:
    return _dict(check.get("evidence"))


def _verdict_text(value: Any) -> str:
    """``VERDICT / REASON`` from a recorded ``{verdict, reason}`` object, as recorded."""
    record = _dict(value)
    if not record:
        return "not recorded"
    return f"{_plain(record.get('verdict'))} / {_plain(record.get('reason'))}"


def _cases(check: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The falsifier cases a check's evidence records, in the order they ran (17.5)."""
    return _dicts(_evidence(check).get("falsifiers"))


def _witnessed(check: Mapping[str, Any]) -> bool:
    """True only when the check records WITNESSED *and* at least one case that was REJECTED.

    The state word alone is not enough: section 17.5 makes the rejected case
    the witness, so a WITNESSED label over no rejected case is not one. A
    case counts as rejected only when its recorded outcome says so *and* its
    own required and recorded results agree (:func:`_case_outcome`).
    """
    return _is(_evidence(check).get("falsification"), WitnessState.WITNESSED.value) and any(
        _rejected(case) for case in _cases(check)
    )


def _rejected(case: Mapping[str, Any]) -> bool:
    """A falsifier case that both records REJECTED and whose own results give REJECTED."""
    return _is(case.get("outcome"), "REJECTED") and _case_outcome(case) == "REJECTED"


def _witness_counts(doc: Mapping[str, Any]) -> tuple[int, int]:
    """``(witnessed, passed)`` over the run's check results."""
    passed = [check for check in _dicts(doc.get("checks")) if _is(check.get("verdict"), "PASS")]
    return sum(1 for check in passed if _witnessed(check)), len(passed)


@dataclass(frozen=True)
class _RatioView:
    """A recorded ratio (17.3), rebuilt from its own counts rather than trusted.

    ``ratio`` is the :class:`~science_gate.models.Ratio` the counts define, or
    None when the counts cannot define one (missing, negative, or a part
    larger than its whole). ``problem`` says when the record disagrees with
    its own counts. A ratio without a value is never drawn or read as 0% or
    100% (extension #23).
    """

    ratio: Ratio | None
    problem: str | None

    @property
    def defined(self) -> bool:
        return self.ratio is not None and self.ratio.value is not None and self.problem is None

    def text(self) -> str:
        if self.ratio is None:
            base = "no value" if self.problem else "not recorded"
        elif self.ratio.value is None:
            counted = f", {self.ratio.fraction} as counted" if self.ratio.fraction else ""
            base = f"no value ({self.ratio.state.value}{counted})"
        else:
            base = f"{self.ratio.fraction} = {self.ratio.decimal}"
        return f"{base}: {self.problem}" if self.problem else base


def _ratio_view(value: Any) -> _RatioView:
    record = _dict(value)
    if not record:
        return _RatioView(None, None)
    try:
        ratio = Ratio(_int(record.get("numerator")), _int(record.get("denominator")))
    except (TypeError, ValueError) as exc:
        return _RatioView(None, f"its counts define no ratio: {exc}")
    differing = sorted(
        key for key, rebuilt in ratio.to_dict().items() if key in record and not _same(record.get(key), rebuilt)
    )
    problem = f"the record's own {', '.join(differing)} disagree with its counts" if differing else None
    return _RatioView(ratio, problem)


def _same(recorded: Any, rebuilt: Any) -> bool:
    """Exact JSON equality that never treats ``True`` as ``1``."""
    return type(recorded) is type(rebuilt) and recorded == rebuilt


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
class _FacetGroup:
    """Facets that answer one part of a plane's question; Performance has D4's CHECKER and RUN parts."""

    name: str
    question: str
    facets: tuple[_Facet, ...]


@dataclass(frozen=True)
class _Plane:
    key: str
    title: str
    question: str
    groups: tuple[_FacetGroup, ...]
    boundary: Any

    @property
    def facets(self) -> tuple[_Facet, ...]:
        return tuple(facet for group in self.groups for facet in group.facets)

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
        """``integrity``, ``checker`` or ``run`` (the two D4 parts of Performance), or ``unregistered``."""
        if not isinstance(self.name, str) or self.name not in INVARIANT_NAMES:
            return "unregistered"
        if self.name in _INTEGRITY_INVARIANTS:
            return "integrity"
        return "checker" if self.name in _CHECKER_INVARIANTS else "run"


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

    @property
    def witness(self) -> _Cell:
        """Whether this result shows that its checker could have failed (17.5).

        Only a would-be PASS is falsified, so a result that never reached one
        is NOT FALSIFIED, which is not a defect. A PASS with no witness record
        is NOT RECORDED, and a WITNESSED label without a rejected case is not
        drawn as witnessed.
        """
        if self.result is None:
            return _Cell("NO RESULT", "warning", "question", False)
        state = _evidence(self.result).get("falsification")
        if state is None:
            if _is(self.result.get("verdict"), "PASS"):
                return _Cell("NOT RECORDED", "warning", "question", False)
            return _Cell("NOT FALSIFIED", "muted", "dash", False)
        if _is(state, WitnessState.WITNESSED.value) and not _witnessed(self.result):
            return _Cell("NO REJECTED CASE", "warning", "question", False)
        tone, glyph = _style(_WITNESS_STYLE, state)
        return _Cell(_plain(state), tone, glyph, _is(state, WitnessState.WITNESSED.value) or _is(state, "REFUTED"))


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


def _invariant_states(invariants: Sequence[_InvariantRow], name: str) -> tuple[list[str], list[str]]:
    """``(states, details of violations)`` recorded for one invariant name."""
    rows = [row for row in invariants if row.name == name]
    return [row.state for row in rows], [_plain(row.detail) for row in rows if row.state == VIOLATED]


def _control_facet(
    name: str,
    control: Any,
    invariant: str,
    invariants: Sequence[_InvariantRow],
    describe: Callable[[Mapping[str, Any]], str],
    missing: str,
) -> _Facet:
    """A facet lit by one recorded run control (17.8) together with the invariant that judges it.

    LIT needs both: the control records ``holds: true`` and its invariant is
    recorded as holding. Either one saying otherwise breaks the facet. A
    control that is not recorded leaves the facet dark, never lit, whatever
    the invariant says. ``describe`` turns the control into plain text.
    """
    states, violations = _invariant_states(invariants, invariant)
    violated = f"{invariant} violated: {'; '.join(violations)}" if violations else ""
    if not isinstance(control, dict):
        return _Facet(name, BROKEN, f"{missing}; {violated}") if violated else _Facet(name, DARK, missing)
    text = describe(control)
    holds = control.get("holds")
    if holds is False or violated:
        return _Facet(name, BROKEN, "; ".join(part for part in (text, violated) if part))
    if holds is True and states and all(state == HOLDS for state in states):
        return _Facet(name, LIT, f"{text}; {invariant} holds")
    return _Facet(name, PARTIAL, f"{text}; recorded holds {_plain(holds)}, {invariant} {'/'.join(states)}")


def _canary_text(control: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{twin} gave {_verdict_text(control.get(twin))} (required {required})"
        for twin, required in (("must_fail", "FAIL"), ("must_pass", "PASS"))
    )


def _comparator_text(control: Mapping[str, Any]) -> str:
    pairs = _dicts(control.get("pairs"))
    as_expected = sum(1 for pair in pairs if _str(pair.get("actual")) and pair.get("actual") == pair.get("expected"))
    return f"{as_expected} of {len(pairs)} known pair(s) compared as expected"


def _pins_text(control: Mapping[str, Any]) -> str:
    changed = _strs(control.get("changed"))
    writes = [_plain(_dict(item).get("path")) for item in _dicts(control.get("writes"))]
    return (
        f"{_count(control.get('pinned'))} file(s) pinned before the PLAN; changed: {', '.join(changed) or 'none'}; "
        f"written during the run: {', '.join(writes) or 'none'}"
    )


def _plan_facet(doc: Mapping[str, Any], invariants: Sequence[_InvariantRow]) -> _Facet:
    """The PLAN (17.4): recorded at ledger entry 1, equal to the manifest, and closed by what ran."""
    name = "Plan committed"
    plan = _controls(doc).get("plan")
    states = {member: _invariant_states(invariants, member) for member in _PLAN_INVARIANTS}
    violations = [f"{member} violated: {'; '.join(states[member][1])}" for member in _PLAN_INVARIANTS if states[member][1]]
    if violations:
        return _Facet(name, BROKEN, "; ".join(violations))
    if not isinstance(plan, dict):
        return _Facet(name, DARK, "no PLAN is recorded, so nothing shows what the run committed to before it ran")
    head = (
        f"PLAN at ledger entry 1 committed {_count(plan.get('checks_planned'))} check(s), "
        f"{_count(plan.get('inputs_planned'))} input(s) and {_count(plan.get('pins'))} pin(s)"
    )
    holding = [member for member in _PLAN_INVARIANTS if all(state == HOLDS for state in states[member][0])]
    if len(holding) == len(_PLAN_INVARIANTS):
        return _Facet(name, LIT, f"{head}; plan_closure and plan_matches_manifest hold")
    rest = ", ".join(f"{member} {'/'.join(states[member][0])}" for member in _PLAN_INVARIANTS if member not in holding)
    return _Facet(name, PARTIAL, f"{head}; {rest}")


def _witness_facet(doc: Mapping[str, Any], invariants: Sequence[_InvariantRow]) -> _Facet:
    """Every PASS carries a falsifier witness (17.5): its checker rejected a known-bad case of its own input."""
    name = "Falsifier witnesses"
    checks = _dicts(doc.get("checks"))
    states, violations = _invariant_states(invariants, "pass_requires_falsifier_witness")
    refuted = [_plain(check.get("check_id")) for check in checks if _is(_evidence(check).get("falsification"), "REFUTED")]
    if refuted or violations:
        parts = [f"REFUTED (a known-bad case passed): {', '.join(refuted)}"] if refuted else []
        parts += [f"pass_requires_falsifier_witness violated: {'; '.join(violations)}"] if violations else []
        return _Facet(name, BROKEN, "; ".join(parts))
    witnessed, passed = _witness_counts(doc)
    lacking = [
        f"{_plain(check.get('check_id'))} {_plain(_evidence(check).get('falsification'))}"
        for check in checks
        if _evidence(check).get("falsification") is not None and not _witnessed(check)
    ]
    lacking += [
        f"{_plain(check.get('check_id'))} PASS without a witness record"
        for check in checks
        if _is(check.get("verdict"), "PASS") and _evidence(check).get("falsification") is None
    ]
    ratio = f"{witnessed} of {passed} PASS result(s) witnessed"
    invariant_note = [] if all(state == HOLDS for state in states) else [
        f"pass_requires_falsifier_witness {'/'.join(states)}"
    ]
    if not passed and not lacking:
        return _Facet(name, DARK, "no check reached PASS, so no checker had a PASS to witness")
    if passed and witnessed == passed and not lacking and not invariant_note:
        return _Facet(name, LIT, f"{ratio}: each checker rejected a known-bad case of its own input")
    return _Facet(name, PARTIAL if witnessed else DARK, "; ".join([ratio, *lacking, *invariant_note]))


def _digest_outcome(item: Mapping[str, Any]) -> str:
    """``match``, ``mismatch`` or ``not compared`` for an input that declares a digest."""
    computed = _str(item.get("sha256"))
    if _is(item.get("state"), "HASH_MISMATCH") or (computed is not None and computed != item.get("declared_sha256")):
        return "mismatch"
    return "match" if computed is not None else "not compared"


def _integrity_groups(doc: Mapping[str, Any], invariants: Sequence[_InvariantRow]) -> tuple[_FacetGroup, ...]:
    """Was this the exact artifact, input, execution and version claimed?

    Three parts: the artifact (the bytes read, and the harness that read
    them), the execution (planned, then sealed in the ledger), and the
    attestation (the receipt and any re-check of it).
    """
    inputs = _accounting_inputs(doc)
    facets = [
        _plan_facet(doc, invariants),
        _control_facet(
            "Harness pins",
            _controls(doc).get("pins"),
            "harness_pins_intact",
            invariants,
            _pins_text,
            "harness pins are not recorded, so nothing shows the checked files and checkers were left alone",
        ),
    ]

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
    return _grouped(
        facets,
        (
            ("Artifact", "the exact inputs, and the harness that read them",
             ("Input digests", "Declared digests", "Harness pins", "Evidence manifest")),
            ("Execution", "planned before it ran, then sealed",
             ("Plan committed", "Ledger sealed", "Hash chain", "Execution trace")),
            ("Attestation", "the receipt, and any re-check of it", ("Receipt", "Signature", "Re-verification")),
        ),
    )


def _grouped(
    facets: Sequence[_Facet], layout: Sequence[tuple[str, str, Sequence[str]]]
) -> tuple[_FacetGroup, ...]:
    """Arrange facets into named groups by facet name. Every facet is built exactly once, so none can be lost."""
    by_name = {facet.name: facet for facet in facets}
    groups = tuple(
        _FacetGroup(name, question, tuple(by_name.pop(member) for member in members))
        for name, question, members in layout
    )
    if by_name:
        raise AssertionError(f"facets without a group: {sorted(by_name)}")
    return groups


def _performance_groups(
    doc: Mapping[str, Any], invariants: Sequence[_InvariantRow], lattice: Sequence[_LatticeRow]
) -> tuple[_FacetGroup, ...]:
    """How did the fixed system behave on the declared evaluation?

    Two labelled parts, as in the receipt's performance statement (D4):
    CHECKER (could the checks have failed?) and RUN (what they concluded).
    """
    controls = _controls(doc)
    checker = (
        _witness_facet(doc, invariants),
        _control_facet(
            "Run canary",
            controls.get("canary"),
            "canary_controls_hold",
            invariants,
            _canary_text,
            "the must-fail canary and its must-pass twin are not recorded",
        ),
        _control_facet(
            "Comparator self-test",
            controls.get("comparator_self_test"),
            "comparator_self_test",
            invariants,
            _comparator_text,
            "the comparator self-test is not recorded",
        ),
    )
    return (
        _FacetGroup("Checker", "could the checks have failed?", checker),
        _FacetGroup("Run", "what the declared checks concluded", _run_facets(doc, invariants, lattice)),
    )


def _run_facets(
    doc: Mapping[str, Any], invariants: Sequence[_InvariantRow], lattice: Sequence[_LatticeRow]
) -> tuple[_Facet, ...]:
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
            _integrity_groups(doc, invariants),
            boundary.get("integrity"),
        ),
        _Plane(
            "performance",
            "Performance",
            "How did the fixed system behave on the declared evaluation?",
            _performance_groups(doc, invariants, lattice),
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
        elif not _witnessed(row.result):
            state = _plain(_evidence(row.result).get("falsification") or "not recorded")
            gaps.append(f"required check {name} is PASS without a falsifier witness (falsification {state})")
    for row in invariants:
        if row.state in (VIOLATED, UNDETERMINED, NOT_RECORDED):
            gaps.append(f"invariant {_plain(row.name)} is {row.state}")
    if not _str(doc.get("evidence_manifest_sha256")):
        gaps.append("no evidence manifest digest is recorded")
    controls = _controls(doc)
    if not isinstance(controls.get("plan"), dict):
        gaps.append("no PLAN is recorded in controls.plan")
    for key, label in (("canary", "the run canary"), ("comparator_self_test", "the comparator self-test"),
                       ("pins", "the harness pins")):
        control = controls.get(key)
        if not isinstance(control, dict):
            gaps.append(f"{label} is not recorded (controls.{key})")
        elif control.get("holds") is not True:
            gaps.append(f"{label} records holds {_plain(control.get('holds'))}, not true (controls.{key})")
    return gaps


PLAN_ENTRY, STARTED_ENTRY, TERMINAL_ENTRY = "PLAN", "STARTED", "TERMINAL"


@dataclass(frozen=True)
class _LedgerEntry:
    """One ledger entry as run.json lets the page identify it.

    ``family`` is ``plan``, ``check``, ``falsifier`` or ``control``.
    ``owner`` is the check or control id the entry belongs to, and ``span``
    the invocation it sits inside: a falsifier's entries sit inside its
    subject check's span. ``outcome`` is what a terminal entry recorded, as
    run.json records it, and ``verdict`` its verdict word, when it has one.
    """

    seq: int
    phase: str
    family: str
    owner: Any
    span: Any
    invocation: str | None
    outcome: str | None
    verdict: Any = None


@dataclass(frozen=True)
class _LedgerView:
    """The sealed chain as far as run.json shows it.

    ``starts`` places each check result's STARTED entry exactly. ``entries``
    holds every entry when ``complete``, and otherwise only the entries
    placed exactly from a recorded invocation id. ``falsifier_invocations``
    maps ``(check position, case position)`` to a falsifier's invocation id,
    and is empty unless ``complete``.
    """

    length: int | None
    head: str | None
    starts: Mapping[int, tuple[Mapping[str, Any], ...]]
    unplaced: tuple[Mapping[str, Any], ...]
    without_invocation: tuple[Mapping[str, Any], ...]
    derived: bool
    entries: Mapping[int, _LedgerEntry]
    complete: bool
    note: str
    falsifier_invocations: Mapping[tuple[int, int], str]


def _control_records(doc: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any], str]]:
    """The planned controls in ledger order (17.6), each with its record and the outcome it records."""
    controls = _controls(doc)
    comparator, canary = _dict(controls.get("comparator_self_test")), _dict(controls.get("canary"))
    return [
        (COMPARATOR_CONTROL, comparator, f"holds {_plain(comparator.get('holds'))}" if comparator else "not recorded"),
        (CANARY_MUST_FAIL, _dict(canary.get("must_fail")), _verdict_text(canary.get("must_fail"))),
        (CANARY_MUST_PASS, _dict(canary.get("must_pass")), _verdict_text(canary.get("must_pass"))),
    ]


def _ledger_view(doc: Mapping[str, Any]) -> _LedgerView:
    """Identify the ledger's entries from run.json, and say how far that identification goes.

    run.json carries the seal (length and head), not the entries. An
    invocation id is ``inv-`` plus 12 hex of ``sha256(run_id:seq)``, where
    seq is the 1-based position of its STARTED entry (section 4). So every
    STARTED entry of a check or control with a recorded id is placed
    exactly, and an id that matches no position up to ``ledger_length``
    stands out.

    The rest follows the ledger order of section 17.5: the PLAN is entry 1;
    a check's falsifiers run between its STARTED and terminal entries, two
    entries each, in the order its evidence lists them. Those positions are
    a prediction, so they are accepted only when the predicted entries tile
    the sealed length exactly, with no entry claimed twice and none left
    over. Otherwise only the exact placements are shown, and nothing is
    guessed.
    """
    length, head, run_id = _int(doc.get("ledger_length")), _str(doc.get("ledger_head_sha256")), _str(doc.get("run_id"))
    derived = run_id is not None and length is not None and 0 <= length <= _MAX_DERIVED_SEQ
    index = {invocation_id_for(run_id, seq): seq for seq in range(1, length + 1)} if derived and run_id else {}
    starts: dict[int, list[Mapping[str, Any]]] = {}
    unplaced, without = [], []
    exact: list[_LedgerEntry] = []
    predicted: list[_LedgerEntry] = []
    falsifier_seqs: dict[tuple[int, int], int] = {}
    for position, check in enumerate(_dicts(doc.get("checks"))):
        invocation = _str(check.get("invocation_id"))
        if invocation is None:
            without.append(check)
            continue
        seq = index.get(invocation)
        if seq is None:
            if derived:
                unplaced.append(check)
            continue
        starts.setdefault(seq, []).append(check)
        owner = check.get("check_id")
        exact.append(_LedgerEntry(seq, STARTED_ENTRY, "check", owner, owner, invocation, None))
        cases = _cases(check)
        for number, case in enumerate(cases):
            at = seq + 1 + 2 * number
            falsifier_seqs[(position, number)] = at
            control = case.get("control_id")
            actual = _dict(case.get("actual"))
            predicted.append(_LedgerEntry(at, STARTED_ENTRY, "falsifier", control, owner, None, None))
            predicted.append(
                _LedgerEntry(
                    at + 1, TERMINAL_ENTRY, "falsifier", control, owner, None, _verdict_text(actual),
                    actual.get("verdict"),
                )
            )
        end = seq + 1 + 2 * len(cases)
        predicted.append(
            _LedgerEntry(
                end, TERMINAL_ENTRY, "check", owner, owner, invocation, _verdict_text(check), check.get("verdict")
            )
        )
    unplaced_controls = []
    for control_id, record, outcome in _control_records(doc):
        invocation = _str(record.get("invocation_id"))
        seq = index.get(invocation) if invocation is not None else None
        if seq is None:
            unplaced_controls.append(control_id)
            continue
        exact.append(_LedgerEntry(seq, STARTED_ENTRY, "control", control_id, control_id, invocation, None))
        predicted.append(
            _LedgerEntry(
                seq + 1, TERMINAL_ENTRY, "control", control_id, control_id, invocation, outcome, record.get("verdict")
            )
        )
    if isinstance(_controls(doc).get("plan"), dict):
        predicted.append(_LedgerEntry(1, PLAN_ENTRY, "plan", "PLAN", "PLAN", None, None))
    every = exact + predicted
    seqs = [entry.seq for entry in every]
    problems = []
    if not derived:
        problems.append("positions not derived: the run id or ledger length is missing or too large")
    if unplaced or without or unplaced_controls:
        problems.append("some recorded invocations could not be placed")
    if len(set(seqs)) != len(seqs):
        problems.append("two predicted entries claim the same position")
    if derived and sorted(set(seqs)) != list(range(1, (length or 0) + 1)):
        problems.append(f"the predicted entries cover {len(set(seqs))} position(s), not the {length} sealed")
    complete = not problems and length is not None and length > 0
    if complete and run_id is not None:
        entries = {entry.seq: _with_invocation(entry, run_id) for entry in every}
        falsifiers = {key: invocation_id_for(run_id, seq) for key, seq in falsifier_seqs.items()}
        note = (
            f"all {length} entries identified from run.json: their positions follow the ledger order of "
            "ARCHITECTURE.md 17.5 and tile the sealed length exactly"
        )
    else:
        entries = {entry.seq: entry for entry in sorted(exact, key=lambda item: item.seq)}
        falsifiers = {}
        note = (
            "only invocation starts with a recorded id are placed: " + "; ".join(problems)
            if problems
            else "the ledger is empty"
        )
    return _LedgerView(
        length,
        head,
        {seq: tuple(items) for seq, items in sorted(starts.items())},
        tuple(unplaced),
        tuple(without),
        derived,
        dict(sorted(entries.items())),
        complete,
        note,
        falsifiers,
    )


def _with_invocation(entry: _LedgerEntry, run_id: str) -> _LedgerEntry:
    """A falsifier entry with its invocation id, derived from its STARTED position once the tiling holds."""
    if entry.family != "falsifier" or entry.invocation is not None:
        return entry
    started = entry.seq if entry.phase == STARTED_ENTRY else entry.seq - 1
    return replace(entry, invocation=invocation_id_for(run_id, started))


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

    @property
    def stage(self) -> str:
        """The PIE stage (17.12) a blind spot records, or :data:`_NO_STAGE` when it records none the page knows."""
        stage = self.record.get("pie_stage")
        return stage if isinstance(stage, str) and stage in _PIE_STAGES else _NO_STAGE


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
    if isinstance(status, str) and status in _UNEXECUTED_V2_STATUSES and not _is(state, "CHECKED"):
        duplicate = record.get("duplicate_of")
        of = f" (a duplicate of {_plain(duplicate)})" if duplicate is not None else ""
        return NOT_EXECUTED_MUTATION, f"status {status}{of}: never executed, so never counted" + claims
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
        if isinstance(status, str) and status in _ESCAPED_V2_STATUSES:
            return BLIND_SPOT, f"status {status}: executed and not detected, so it counts as escaped"
        stage = record.get("pie_stage")
        notes = [f"stopped mattering at {stage}"] if isinstance(stage, str) else []
        if blind is False:
            notes.append("the record says blind_spot=false although nothing detected it")
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
class _Conservation:
    """The two identities of report v2 (17.12), recomputed from the recorded buckets.

    generated = executed + NOT_APPLICABLE + SUPPRESSED + NOOP_MUTATION +
    CANONICALLY_EQUIVALENT + DUPLICATE_MUTANT + SKIPPED + NOT_ACTIVATED, and
    executed = DETECTED + BLIND_SPOT + VERIFIER_ERROR + TIMED_OUT + FLAKY,
    each over disjoint id lists. ``sizes`` holds each bucket's size, or None
    when the report records no usable list for it. Each identity is None
    when there are no buckets to recompute it from, so an identity that was
    never recorded can never read as holding.
    """

    recorded: Mapping[str, Any]
    sizes: Mapping[str, int | None]
    members: Mapping[str, tuple[str, ...]]
    generated: int
    executed: int | None
    generated_holds: bool | None
    executed_holds: bool | None
    disjoint: bool | None
    problems: tuple[str, ...]

    @property
    def available(self) -> bool:
        return self.generated_holds is not None

    @property
    def holds(self) -> bool | None:
        checks = (self.generated_holds, self.executed_holds, self.disjoint)
        if None in checks:
            return None
        return all(checks)


def _conservation(report: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> _Conservation:
    """Recompute both identities from ``buckets``, against the records the report lists.

    The generated side is the report's own list of records (every generated
    mutant has one), and the recorded ``conservation.generated`` and
    ``conservation.executed`` lists when present. A bucket that is missing,
    not a list of ids, or named outside the vocabulary breaks the identity
    it belongs to, because a mutant in it is unaccounted for.
    """
    recorded = _dict(report.get("conservation"))
    buckets = report.get("buckets")
    record_ids = sorted(_plain(record.get("mutation_id")) for record in records)
    if not isinstance(buckets, dict):
        return _Conservation(recorded, {}, {}, len(record_ids), None, None, None, None, ())
    statuses = (*_EXECUTED_PARTITION, *_UNEXECUTED_PARTITION)
    problems = []
    members: dict[str, tuple[str, ...]] = {}
    sizes: dict[str, int | None] = {}
    for status in statuses:
        value = buckets.get(status)
        ids = _strs(value)
        if not isinstance(value, list) or len(ids) != len(value):
            problems.append(f"bucket {status} is not a list of mutation ids")
            sizes[status] = None
        else:
            sizes[status] = len(ids)
        members[status] = tuple(ids)
    unknown = sorted(_plain(key) for key in buckets if not (isinstance(key, str) and key in statuses))
    if unknown:
        problems.append(f"bucket(s) outside the vocabulary: {', '.join(unknown)}")
    every = [identifier for status in statuses for identifier in members[status]]
    disjoint = len(every) == len(set(every))
    if not disjoint:
        problems.append("a mutation id appears in more than one bucket, or twice in one")
    executed_ids = sorted(identifier for status in _EXECUTED_PARTITION for identifier in members[status])
    generated_lists = [record_ids] + ([sorted(_strs(recorded["generated"]))] if "generated" in recorded else [])
    generated_holds = not unknown and None not in sizes.values() and all(sorted(every) == ids for ids in generated_lists)
    if not generated_holds:
        problems.append("the buckets do not add up to the generated mutants")
    executed_lists = [
        sorted(_plain(record.get("mutation_id")) for record in records
               if isinstance(record.get("status"), str) and record["status"] in _EXECUTED_PARTITION)
    ] + ([sorted(_strs(recorded["executed"]))] if "executed" in recorded else [])
    executed_holds = all(sizes[status] is not None for status in _EXECUTED_PARTITION) and all(
        executed_ids == ids for ids in executed_lists
    )
    if not executed_holds:
        problems.append("the executed buckets do not add up to the executed mutants")
    for record in records:
        identifier, status = record.get("mutation_id"), record.get("status")
        if isinstance(status, str) and status in members and _plain(identifier) not in members[status]:
            problems.append(f"{_plain(identifier)} records status {status}, but bucket {status} does not list it")
    return _Conservation(
        recorded, sizes, members, len(record_ids), len(executed_ids), generated_holds, executed_holds, disjoint,
        tuple(problems),
    )


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
    conservation: _Conservation
    #: ``forced_detection`` as recorded: the harness control M00, never counted (17.12).
    forced: Mapping[str, Any]

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
    conservation = _conservation(report, _dicts(report.get("mutations")))
    recorded_holds = conservation.recorded.get("holds")
    if conservation.available and recorded_holds is True and conservation.holds is not True:
        discrepancies.append(
            "the report records conservation holds, but its buckets do not: " + "; ".join(conservation.problems)
        )
    elif conservation.holds is True and recorded_holds is False:
        discrepancies.append("the report records conservation failing, but its buckets add up")
    elif not conservation.available and recorded_holds is True:
        discrepancies.append("the report records conservation holds, but it records no buckets to show it")
    return _MutationView(
        mutations,
        status,
        valid,
        counts,
        tallies,
        sensitivity,
        tuple(discrepancies),
        conservation,
        _dict(report.get("forced_detection")),
    )


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


_TILES_PER_ROW = 4


def _tile_rows(plane: _Plane) -> list[tuple[_Facet, ...]]:
    """Each facet group on rows of its own, at most :data:`_TILES_PER_ROW` tiles wide, so a group reads as a band."""
    rows = [
        group.facets[start : start + _TILES_PER_ROW]
        for group in plane.groups
        for start in range(0, len(group.facets), _TILES_PER_ROW)
    ]
    return rows or [()]


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
    rows = _tile_rows(plane)
    cols = max(1, *(len(row) for row in rows))
    spacing = min(0.36, 0.9 / len(rows))
    du, dv = 0.4 / cols, min(0.13, spacing * 0.38)
    placed = [
        (facet, (cols - len(row)) / 2 + col, row_index)
        for row_index, row in enumerate(rows)
        for col, facet in enumerate(row)
    ]
    for facet, col, row in placed:
        uc, vc = (col + 0.5) / cols, 0.5 + (row - (len(rows) - 1) / 2) * spacing
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
    columns = (290.0, 372.0, 454.0, 536.0)
    width, top, step = 660.0, 78.0, 36.0
    shown = rows[:_MAX_LATTICE_ROWS]
    required = sum(1 for row in rows if row.declared and row.required is not False)
    optional = sum(1 for row in rows if row.declared and row.required is False)
    checked = sum(1 for row in rows if row.executed.label == "CHECKED")
    terminal = sum(1 for row in rows if row.is_terminal)
    witnessed = sum(1 for row in rows if row.witness.label == WitnessState.WITNESSED.value)
    parts = []
    headers = (
        ("EXPECTED", f"{required} required" + (f" + {optional}" if optional else "")),
        ("EXECUTED", f"{checked} checked"),
        ("TERMINAL", f"{terminal} with invocation"),
        ("WITNESS", f"{witnessed} could fail"),
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
        cells = (row.expected, row.executed, row.terminal, row.witness)
        # A witness flows from a terminal verdict only when the result records a falsification.
        falsified = row.result is not None and _evidence(row.result).get("falsification") is not None
        flows = (row.result is not None, row.is_terminal, row.is_terminal and falsified)
        for (x1, x2), flows_on in zip(zip(columns, columns[1:]), flows):
            if flows_on:
                parts.append(f'<line class="flow" x1="{_n(x1 + 12)}" y1="{_n(y)}" x2="{_n(x2 - 12)}" y2="{_n(y)}"/>')
        for x, cell, stage in zip(columns, cells, ("expected", "executed", "terminal", "witness")):
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
        f"(CHECKED), {terminal} terminal with an invocation, {witnessed} witnessed as able to fail."
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


_CHAIN_PER_ROW, _CHAIN_SLOT, _CHAIN_LINK_W, _CHAIN_LINK_H, _CHAIN_ROW_STEP = 16, 44.0, 36.0, 26.0, 80.0
_CHAIN_LEFT, _CHAIN_TOP, _CHAIN_HEAD_X = 16.0, 34.0, 760.0


def _chain_slots(length: int) -> list[int | None]:
    """The seqs the strip draws: all of them, or the first and last halves around one elision marker (None)."""
    if length <= _MAX_CHAIN_LINKS:
        return list(range(1, length + 1))
    half = _MAX_CHAIN_LINKS // 2
    return [*range(1, half + 1), None, *range(length - half + 1, length + 1)]


def _link_style(entry: _LedgerEntry | None) -> tuple[str, str, str]:
    """``(tone attribute, rect class, label class)`` for one link, from its role alone (never document text)."""
    if entry is None:
        return "", "link", "link-seq"
    if entry.family == "plan":
        return "", "link-plan", "link-seq"
    if entry.family == "falsifier":
        return "", "link-falsifier", "link-seq"
    if entry.family == "control":
        return "", "link-control", "link-seq"
    if entry.phase == STARTED_ENTRY:
        return "", "link-start", "link-seq-on"
    tone, _ = _style(_STATUS_STYLE, entry.verdict)
    return f' class="t-{tone}"', "fill-tone", "link-seq-tone"


def _link_tip(seq: int, entry: _LedgerEntry | None) -> str:
    if entry is None:
        return _tip(_e(f"entry {seq}: not identified from run.json"))
    words = f"entry {seq}: {entry.phase} of {entry.family} {_plain(entry.owner)}"
    if entry.invocation is not None:
        words += f", invocation {entry.invocation}"
    if entry.outcome is not None:
        words += f", recorded {entry.outcome}"
    return _tip(_e(words))


def _span_brackets(row: Sequence[int | None], ledger: _LedgerView, y: float, seen: set[str]) -> list[str]:
    """A bracket under each run of links that belong to one invocation, labelled once per invocation.

    An invocation that wraps onto the next row gets a bracket on each row,
    and its label only on the first. ``seen`` carries the labelled spans
    across rows.
    """
    runs: list[tuple[str, Any, int, int]] = []
    for column, seq in enumerate(row):
        entry = ledger.entries.get(seq) if seq is not None else None
        if entry is None:
            continue
        key = _plain(entry.span)
        if runs and runs[-1][0] == key and runs[-1][3] == column - 1:
            runs[-1] = (key, runs[-1][1], runs[-1][2], column)
        else:
            runs.append((key, entry.span, column, column))
    parts: list[str] = []
    top, low = y + _CHAIN_LINK_H + 5, y + _CHAIN_LINK_H + 10
    for key, span, first, last in runs:
        x0 = _CHAIN_LEFT + first * _CHAIN_SLOT + 2
        x1 = _CHAIN_LEFT + last * _CHAIN_SLOT + _CHAIN_LINK_W - 2
        parts.append(f'<path class="bracket" d="M{_n(x0)} {_n(top)}V{_n(low)}H{_n(x1)}V{_n(top)}"/>')
        if key not in seen:
            seen.add(key)
            label = _clip(_short_id(span), max(4, int((x1 - x0) / 6.4)))
            parts.append(_text((x0 + x1) / 2, low + 13, label, "sv-small", "middle"))
    return parts


def _chain_svg(ledger: _LedgerView) -> str:
    """The sealed chain, wrapped into rows: one link per entry, styled by its role, then the head.

    Links are drawn in the role run.json identifies (the PLAN, a check's
    STARTED and terminal entries, falsifier and control entries); an entry
    it cannot identify is drawn plain. A bracket under the links groups each
    invocation, with its falsifiers inside it.
    """
    width, left, top = 960.0, _CHAIN_LEFT, _CHAIN_TOP
    parts: list[str] = []
    length = ledger.length
    if length is None or length <= 0:
        label = "length not recorded" if length is None else "empty ledger" if length == 0 else "invalid length"
        parts.append(
            f'<rect class="link-empty" x="{_n(left)}" y="{_n(top)}" width="200" height="{_n(_CHAIN_LINK_H)}" rx="7"/>'
        )
        parts.append(_text(left + 100, top + 17, label, "sv-small", "middle"))
        rows_drawn, end = 1, (left + 200, top + _CHAIN_LINK_H / 2)
    else:
        slots = _chain_slots(length)
        rows = [slots[start : start + _CHAIN_PER_ROW] for start in range(0, len(slots), _CHAIN_PER_ROW)]
        previous: tuple[float, float] | None = None
        seen: set[str] = set()
        for row_index, row in enumerate(rows):
            y = top + row_index * _CHAIN_ROW_STEP
            mid = y + _CHAIN_LINK_H / 2
            for column, seq in enumerate(row):
                x = left + column * _CHAIN_SLOT
                if seq is None:
                    hidden = length - _MAX_CHAIN_LINKS
                    parts.append(_text(x + _CHAIN_LINK_W / 2, y + 17, f"\u22ef {hidden} \u22ef", "sv-small", "middle"))
                    previous = None
                    continue
                if previous is not None and column == 0:
                    # The chain wraps: down from the last row's end, back along the gutter, into this row.
                    turn = previous[1] + _CHAIN_ROW_STEP - _CHAIN_LINK_H / 2 - 12
                    parts.append(
                        f'<path class="chain-link wrap" d="M{_n(previous[0])} {_n(previous[1])}'
                        f'H{_n(previous[0] + 5)}V{_n(turn)}H{_n(left - 9)}V{_n(mid)}H{_n(x)}"/>'
                    )
                elif previous is not None:
                    parts.append(_line("chain-link", previous[0], mid, x, mid))
                entry = ledger.entries.get(seq)
                tone, rect, label_css = _link_style(entry)
                parts.append(
                    f'<g{tone}>{_link_tip(seq, entry)}<rect class="{rect}" x="{_n(x)}" y="{_n(y)}" '
                    f'width="{_n(_CHAIN_LINK_W)}" height="{_n(_CHAIN_LINK_H)}" rx="6"/>'
                    + _text(x + _CHAIN_LINK_W / 2, y + 17, str(seq), label_css, "middle")
                    + "</g>"
                )
                previous = (x + _CHAIN_LINK_W, mid)
            parts.extend(_span_brackets(row, ledger, y, seen))
        rows_drawn = len(rows)
        last_mid = top + (rows_drawn - 1) * _CHAIN_ROW_STEP + _CHAIN_LINK_H / 2
        end = previous if previous is not None else (left + len(rows[-1]) * _CHAIN_SLOT, last_mid)
    head_x, (end_x, end_y) = _CHAIN_HEAD_X, end
    parts.append(
        f'<line class="chain-link head-arrow" x1="{_n(end_x)}" y1="{_n(end_y)}" x2="{_n(head_x - 6)}" '
        f'y2="{_n(end_y)}"/><path class="arrow-tip" d="M{_n(head_x - 12)} {_n(end_y - 5)}L{_n(head_x - 3)} '
        f'{_n(end_y)}L{_n(head_x - 12)} {_n(end_y + 5)}Z"/>'
    )
    parts.append(
        f'<g><title>{_e("head " + _plain(ledger.head))}</title>'
        f'<rect class="head" x="{_n(head_x)}" y="{_n(end_y - 22)}" width="184" height="44" rx="10"/>'
        + _text(head_x + 14, end_y - 4, "HEAD", "sv-caps")
        + _text(head_x + 14, end_y + 14, _e(_short_hash(ledger.head)), "sv-mono")
        + "</g>"
    )
    height = top + rows_drawn * _CHAIN_ROW_STEP + 14
    placed = sum(len(items) for items in ledger.starts.values())
    identified = "every entry identified" if ledger.complete else f"{placed} check start(s) placed from their ids"
    parts.append(
        _text(
            left,
            height - 10,
            _e(
                f"{_count(length)} entries \u00b7 {identified}"
                + (f" \u00b7 {len(ledger.unplaced)} not placeable" if ledger.unplaced else "")
                + (f" \u00b7 {len(ledger.without_invocation)} without invocation" if ledger.without_invocation else "")
            ),
            "sv-sub",
        )
    )
    desc = f"Ledger chain of {_count(length)} entries sealed under head {_plain(ledger.head)}; {ledger.note}."
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


def _cluster_caption(members: Sequence[_Mutation], fallback: str) -> str:
    """The recorded statuses inside one cluster, counted (``NOOP_MUTATION 2, SKIPPED 1``), or ``fallback``."""
    counts: dict[str, int] = {}
    for item in members:
        status = item.record.get("status")
        # A record before v2 has no status word; the group the page placed it in names it instead.
        word = status if isinstance(status, str) else item.group
        counts[word] = counts.get(word, 0) + 1
    return ", ".join(f"{word} {counts[word]}" for word in sorted(counts)) or fallback


def _constellation_svg(view: _MutationView) -> str:
    """Clusters of stars, one per outcome group, and under them where each blind spot stopped mattering.

    Mutants that were built or considered but never executed (17.12) have a
    cluster of their own, apart from skipped and inapplicable operators, so
    neither can be read as the other or as a detection.
    """
    groups = [
        ("Detected", DETECTED, view.group(DETECTED), "the expected detector fired"),
        ("Blind spots", BLIND_SPOT, view.group(BLIND_SPOT), "executed, and nothing caught it"),
        ("Never executed", NOT_EXECUTED_MUTATION, view.group(NOT_EXECUTED_MUTATION), "no unactivated, no-op or duplicate"),
        (
            "Skipped or N/A",
            SKIPPED,
            view.group(SKIPPED) + view.group(NOT_APPLICABLE_MUTATION),
            "no skipped or inapplicable operator",
        ),
    ]
    if view.group(UNRESOLVED):
        groups.insert(2, ("Unresolved", UNRESOLVED, view.group(UNRESOLVED), "the record contradicts itself"))
    width = 960.0
    slot = width / len(groups)
    radius_cap = min(slot / 2 - 30, 112.0)
    # Stars sit on a spiral whose radius grows with the square root of the
    # count, so the field is only as tall as its largest cluster needs.
    counts = [len(members[:_MAX_STARS_PER_GROUP]) for _, _, members, _ in groups]
    spacings = [min(26.0, radius_cap / math.sqrt(max(count, 1))) for count in counts]
    reach = max(spacing * math.sqrt(max(count - 0.5, 0.5)) for spacing, count in zip(spacings, counts))
    cy = 80 + reach
    height = cy + reach + 44
    parts = []
    for index, ((title, group, members, quiet), spacing) in enumerate(zip(groups, spacings)):
        cx = slot * index + slot / 2
        parts.append(_text(cx, 28, _e(f"{title.upper()} \u00b7 {len(members)}"), "sv-caps", "middle"))
        caption = _cluster_caption(members, quiet) if group in (NOT_EXECUTED_MUTATION, SKIPPED) else quiet
        parts.append(_text(cx, 44, _clip(caption, int(slot / 6.2)), "sv-small", "middle"))
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
            parts.append(_star(item, x, y))
            if len(shown) <= 30:
                radius = 9.0 if item.group in (DETECTED, BLIND_SPOT, UNRESOLVED) else 6.0
                parts.append(_text(x, y + radius + 12, _clip(item.short, 6), "sv-small", "middle"))
        if not members:
            parts.append(_text(cx, cy + 4, "none", "sv-sub", "middle"))
        elif len(members) > len(shown):
            parts.append(_text(cx, height - 10, f"{len(members) - len(shown)} more in the table", "sv-small", "middle"))
    ladder, ladder_height = _pie_ladder(view.group(BLIND_SPOT), height + 6, width)
    parts.extend(ladder)
    desc = "; ".join(f"{title}: {len(members)}" for title, _, members, _ in groups) + "."
    if view.group(BLIND_SPOT):
        desc += " Blind spots by PIE stage: " + "; ".join(
            f"{stage} {sum(1 for item in view.group(BLIND_SPOT) if item.stage == stage)}"
            for stage in (*_PIE_STAGES, _NO_STAGE)
        ) + "."
    return _svg("mutations", width, height + ladder_height, "Mutation constellation", desc, parts, "wide-svg")


def _star(item: _Mutation, x: float, y: float) -> str:
    """One mutation's star: filled only when it executed, ringed when it is a blind spot."""
    tone, glyph = _MUTATION_STYLE[item.group]
    executed = item.group in (DETECTED, BLIND_SPOT)
    radius = 9.0 if item.group in (DETECTED, BLIND_SPOT, UNRESOLVED) else 6.0
    status = item.record.get("status")
    words = f"{_plain(item.mutation_id)}: {item.group}" + (f", status {status}" if isinstance(status, str) else "")
    tip = _tip(_e(words + (f" ({item.note})" if item.note else "")))
    halo = (
        f'<circle class="star-halo t-{tone}" cx="{_n(x)}" cy="{_n(y)}" r="{_n(radius + 5)}"/>'
        if item.group == BLIND_SPOT
        else ""
    )
    return f"<g>{tip}{halo}{_marker(tone, glyph, x, y, radius, filled=executed)}</g>"


_LADDER_PER_COLUMN = 10
#: Below a stage header and its two-line meaning, where the first blind spot of the column sits.
_LADDER_FIRST_ROW = 52


def _wrapped(text: str, limit: int) -> list[str]:
    """``text`` (a constant of this module) broken at spaces into lines of at most ``limit`` characters, at most two.

    SVG text does not wrap by itself. A second line that would still be too
    long is cut with an ellipsis.
    """
    lines: list[str] = []
    for word in text.split():
        if lines and len(lines[-1]) + 1 + len(word) <= limit:
            lines[-1] += " " + word
        else:
            lines.append(word)
    if len(lines) > 2:
        lines = [lines[0], " ".join(lines[1:])]
    return [line if len(line) <= limit else line[: max(limit - 1, 1)] + "\u2026" for line in lines]


def _pie_ladder(blind: Sequence[_Mutation], top: float, width: float) -> tuple[list[str], float]:
    """Blind spots placed on the PIE stages (17.12), in the order a defect travels: read, infect, propagate, check.

    A blind spot with no recorded stage (a record before v2, or an escape
    such as VERIFIER_ERROR that has none) gets a column of its own rather
    than a guessed stage. Returns the parts and the height they take.
    """
    if not blind:
        return [], 0.0
    stages = list(_PIE_STAGES) + ([_NO_STAGE] if any(item.stage == _NO_STAGE for item in blind) else [])
    column = width / len(stages)
    parts = [
        f'<line class="sv-grid" x1="12" y1="{_n(top)}" x2="{_n(width - 12)}" y2="{_n(top)}"/>',
        _text(16, top + 22, "BLIND SPOTS BY PIE STAGE: where each undetected defect stopped mattering", "sv-caps"),
    ]
    head_y = top + 48
    deepest = 0
    for index, stage in enumerate(stages):
        x0 = index * column + 16
        members = [item for item in blind if item.stage == stage]
        parts.append(_text(x0, head_y, _e(f"{stage} \u00b7 {len(members)}"), "sv-label"))
        meaning = _PIE_MEANING.get(stage, "the record names no stage")
        for line, words in enumerate(_wrapped(meaning, int((column - 20) / 5.6))):
            parts.append(_text(x0, head_y + 15 + line * 13, _e(words), "sv-small"))
        if index < len(_PIE_STAGES) - 1:
            ax = (index + 1) * column - 4
            parts.append(
                f'<path class="arrow-tip" d="M{_n(ax - 8)} {_n(head_y - 9)}L{_n(ax)} {_n(head_y - 4)}'
                f'L{_n(ax - 8)} {_n(head_y + 1)}Z"/>'
            )
        shown = members[:_LADDER_PER_COLUMN]
        for row, item in enumerate(shown):
            y = head_y + _LADDER_FIRST_ROW + row * 24
            parts.append(_star(item, x0 + 9, y))
            parts.append(_text(x0 + 26, y + 4, _clip(item.mutation_id, int((column - 40) / 6.2)), "sv-small"))
        hidden = len(members) - len(shown)
        if hidden:
            y = head_y + _LADDER_FIRST_ROW + len(shown) * 24
            parts.append(_text(x0, y + 4, f"{hidden} more in the table", "sv-small"))
        deepest = max(deepest, len(shown) + (1 if hidden else 0))
    return parts, 48 + _LADDER_FIRST_ROW + max(deepest, 1) * 24 + 10


_CONSERVATION_BAR_X, _CONSERVATION_BAR_W = 156.0, 500.0
#: The top bar's first segment: every executed mutant, which the second bar splits by outcome.
_EXECUTED_SEGMENT = "EXECUTED"


def _segments(
    sizes: Mapping[str, int | None], order: Sequence[str], x: float, scale: float, y: float, height: float
) -> tuple[list[str], float]:
    """Stacked bucket segments with 2px gaps; a segment wide enough carries its count. Returns the end x."""
    parts, cursor = [], x
    for status in order:
        size = sizes.get(status)
        if not size:
            continue
        wide = size * scale
        drawn = max(1.0, wide - 2)
        tone = "accent" if status == _EXECUTED_SEGMENT else _BUCKET_TONE.get(status, "muted")
        tip = _tip(_e(f"{status}: {size}"))
        label = (
            _text(cursor + drawn / 2, y + height / 2 + 4, str(size), "sv-on", "middle") if drawn >= 22 else ""
        )
        parts.append(f'<g class="t-{tone}">{tip}{_bar(cursor, y, drawn, height, "fill-tone", rounded=False)}{label}</g>')
        cursor += wide
    return parts, cursor


def _conservation_svg(view: _MutationView) -> str:
    """Both conservation identities (17.12) as two linked bars, with the harness control M00 beside them.

    The top bar is every generated mutant split into the executed ones and
    each never-executed bucket; its executed segment opens into the second
    bar, the executed mutants split by outcome. A bucket with no members is
    named under its bar instead of being drawn as a sliver.
    """
    cons = view.conservation
    width, top, bar_h = 960.0, 46.0, 22.0
    x, w = _CONSERVATION_BAR_X, _CONSERVATION_BAR_W
    parts = [_text(16, 22, "CONSERVATION: every generated mutant lands in exactly one bucket", "sv-caps")]
    generated = cons.generated
    executed = cons.executed or 0
    scale = w / generated if generated else 0.0
    second = top + 92
    rows = (
        ("generated", generated, top, (_EXECUTED_SEGMENT, *_UNEXECUTED_PARTITION)),
        ("executed", executed, second, _EXECUTED_PARTITION),
    )
    sizes = {**cons.sizes, _EXECUTED_SEGMENT: executed}
    for label, total, y, order in rows:
        parts.append(_text(16, y + 15, _e(label), "sv-label"))
        parts.append(_text(x - 10, y + 15, _e(str(total)), "sv-value", "end"))
        drawn, end = _segments(sizes, order, x, scale, y, bar_h)
        parts.extend(drawn)
        empty = [status for status in order if sizes.get(status) == 0]
        unknown = [status for status in order if sizes.get(status) is None]
        notes = ([f"0 in {', '.join(empty)}"] if empty else []) + (
            [f"not recorded: {', '.join(unknown)}"] if unknown else []
        )
        if notes:
            parts.append(_text(x, y + bar_h + 16, _clip("; ".join(notes), 110), "sv-small"))
    if generated and executed:
        right = x + executed * scale
        parts.append(
            f'<path class="fan" d="M{_n(x)} {_n(top + bar_h)}L{_n(x)} {_n(second)}'
            f'L{_n(right)} {_n(second)}L{_n(right)} {_n(top + bar_h)}Z"/>'
        )
    parts.extend(_forced_detection_box(view.forced, 690.0, 34.0))
    holds = {True: "holds", False: "does NOT hold", None: "not recomputable"}
    desc = (
        f"generated {generated} = executed {executed} + "
        + " + ".join(f"{status} {_count(cons.sizes.get(status))}" for status in _UNEXECUTED_PARTITION)
        + f"; executed {executed} = "
        + " + ".join(f"{status} {_count(cons.sizes.get(status))}" for status in _EXECUTED_PARTITION)
        + f". Recomputed from the buckets: {holds[cons.holds]}. M00: {_forced_words(view.forced)}."
    )
    return _svg("conservation", width, second + bar_h + 34, "Conservation identities", desc, parts, "wide-svg")


def _forced_words(forced: Mapping[str, Any]) -> str:
    """M00 as recorded: detected by its detector, not detected, or not recorded. Never assumed to have held."""
    detected = forced.get("detected")
    if detected is True:
        return f"detected by {_plain(forced.get('detector'))}"
    if detected is False:
        return "NOT detected: the harness did not see its own planted defect"
    return "not recorded"


def _forced_detection_box(forced: Mapping[str, Any], x: float, y: float) -> list[str]:
    detected = forced.get("detected")
    tone, glyph = ("good", "check") if detected is True else ("critical", "cross") if detected is False else (
        "warning", "question"
    )
    tip = _tip(_e(f"M00_forced_detection: {_forced_words(forced)}; {_plain(forced.get('target'))}"))
    # Detected: "detected by" over the detector's name. Otherwise the outcome alone, on two lines if it is long.
    words = ("detected by", _plain(forced.get("detector"))) if detected is True else (_forced_words(forced), "")
    return [
        f'<g>{tip}<rect class="control-box" x="{_n(x)}" y="{_n(y)}" width="254" height="112" rx="12"/>',
        _text(x + 14, y + 22, "HARNESS CONTROL", "sv-caps"),
        _marker(tone, glyph, x + 26, y + 50, 12),
        _text(x + 48, y + 46, "M00 forced detection", "sv-label"),
        _text(x + 48, y + 62, _clip(words[0], 32), "sv-small"),
        _text(x + 48, y + 76, _clip(words[1], 32), "sv-small"),
        _text(x + 14, y + 100, "planted first; never counted", "sv-small"),
        "</g>",
    ]


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
    witnessed, passed = _witness_counts(doc)
    witness_note = (
        "each checker rejected a known-bad case of its own input"
        if passed
        else "no check reached PASS, so none needed a witness"
    )
    stats = "".join(
        (
            _stat("PASS results witnessed", f"{witnessed} / {passed}", witness_note, known=passed > 0),
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
    """The plane's facets under their group headings, in the order the plane draws them, back row first."""
    items = []
    for group in plane.groups:
        items.append(
            f'<li class="facet-group"><span class="group-name">{html.escape(group.name)}</span>'
            f'<span class="group-question">{html.escape(group.question)}</span></li>'
        )
        for facet in group.facets:
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


def _skip_line(result: Mapping[str, Any]) -> str:
    """Why a required check did not execute, as its evidence labels it (#24); an unlabelled skip says so (D1)."""
    if not (_is(result.get("execution_state"), "SKIPPED") or _is(result.get("execution_state"), "NOT_APPLICABLE")):
        return ""
    label = _evidence(result).get("skip_justification")
    if label is None:
        return _sub("<strong>no justification recorded</strong>")
    return _sub(f"justified: {_wbr(label, '_')}", words=True)


def _witness_line(row: _LatticeRow) -> str:
    """The witness cell in words: its state and how many known-bad cases were rejected as expected."""
    cell = row.witness
    cases = _cases(row.result) if row.result is not None else []
    if not cases:
        return f"witness {cell.label}"
    rejected = sum(1 for case in cases if _rejected(case))
    return f"witness {cell.label}: {rejected} of {len(cases)} case(s) rejected"


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
    evidence = _evidence(result)
    if "discrimination_ratio" in evidence:
        check += _sub(f"discrimination {_e(_ratio_view(evidence.get('discrimination_ratio')).text())}", words=True)
    diagnostics = result.get("diagnostics")
    return [
        check,
        expected,
        executed + _skip_line(result),
        terminal + _sub(_wbr(result.get("reason"), "_"), words=True) + _sub(_e(_witness_line(row)), words=True),
        _e(_count(result.get("rows_examined"))),
        _code(result.get("invocation_id")) + _sub(_e(_evidence_digest(result)), words=True),
        _chips(result.get("failure_modes"))
        + "".join(_sub(_e(text)) for text in (diagnostics if isinstance(diagnostics, list) else [])),
    ]


def _lattice_section(doc: Mapping[str, Any], lattice: Sequence[_LatticeRow]) -> str:
    figure = _figure(
        "lattice",
        _lattice_svg(lattice),
        "Each row is a check: declared (expected), examined its inputs (executed), closed by a ledger invocation "
        "with a verdict (terminal), and, for a PASS, shown able to fail by rejecting a known-bad case of its own "
        "input (witness). A missing flow line marks where a check stopped.",
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
            "checks_justified",
            "checks_shortfall",
            "control_invocations",
        )
    ]
    counter_html = "".join(f"<div><dt>{name}</dt><dd>{_e(_count(value))}</dd></div>" for name, value in recorded)
    side = (
        '<div class="side"><h3>Recorded counters</h3>'
        '<p class="muted small">checks_expected and checks_executed count required checks only; executed means '
        "CHECKED with a terminal invocation. A shortfall is a required check that did not execute; it is "
        "justified only by a closed-vocabulary label. Control invocations (falsifiers, canary, comparator) are "
        "never counted as checks.</p>"
        f'<dl class="counter-list" data-equivalent-of="lattice">{counter_html}</dl></div>'
    )
    legend = _legend(
        [
            ("accent", "fill", "expected and required, or executed (CHECKED)"),
            ("accent", "hollow", "optional"),
            ("good", "fill", "PASS, or witnessed: a known-bad case was rejected"),
            ("critical", "fill", "FAIL, or refuted: a known-bad case passed"),
            ("warning", "fill", "ABSTAIN"),
            ("warning", "hollow", "witness missing or not recorded"),
            ("serious", "fill", "ERROR"),
            ("muted", "hollow", "not applicable, skipped, or not falsified"),
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
        "expected vs executed vs terminal vs witnessed",
        f'<div class="split"><div>{figure}{legend}</div>{side}</div>{table}{tally_table}',
    )


# ---------------------------------------------------------------------------
# Checker controls: could the checks have failed? (17.5, 17.6, 17.14)
# ---------------------------------------------------------------------------

#: Resolver states that count as a resolution, so a canary in one of them is a proven miss (17.14).
_RESOLVING_STATES = ("DOI_RESOLVED", "DOI_TARGET_MISMATCH")

#: The families of negative control, in the order the figure stacks them: ``(key, title, what it must show)``.
_CONTROL_FAMILIES = (
    ("falsifier", "Falsifier witnesses", "each PASS re-run on a known-bad case of its own input"),
    ("canary", "Run canary", "a planted duplicate must FAIL; its twin must PASS"),
    ("comparator", "Comparator self-test", "three known pairs through the live comparator"),
    ("resolver", "Resolver canaries", "a DOI that cannot exist must not resolve"),
    ("pins", "Harness pins", "pinned files unchanged and never written"),
)
#: The canary twins' fixed inputs (17.5). They are part of the contract, not of the run, and are labelled so.
_CANARY_TWINS = (
    (CANARY_MUST_FAIL, "must_fail", "FAIL", "an in-memory CSV holding one row twice"),
    (CANARY_MUST_PASS, "must_pass", "PASS", "an in-memory CSV holding two distinct rows"),
)


def _case_outcome(case: Mapping[str, Any]) -> str:
    """A falsifier case's outcome, recomputed from its own required and recorded results (17.5, step 3).

    REJECTED when the recorded verdict and reason equal the required ones,
    ACCEPTED when the recorded verdict is PASS, INCONCLUSIVE otherwise, and
    NOT RECORDED without a recorded verdict. The page shows this rather than
    the case's own outcome word, and notes any disagreement, so a relabelled
    case cannot look like a witness.
    """
    expected, actual = _dict(case.get("expected")), _dict(case.get("actual"))
    verdict = actual.get("verdict")
    if not isinstance(verdict, str):
        return "NOT RECORDED"
    if verdict == "PASS":
        return "ACCEPTED"
    same_reason = _str(actual.get("reason")) is not None and _is(expected.get("reason"), actual.get("reason"))
    return "REJECTED" if _is(expected.get("verdict"), verdict) and same_reason else "INCONCLUSIVE"


@dataclass(frozen=True)
class _ControlRow:
    """One negative control: what it had to do, and what the run recorded it doing.

    ``family`` and ``outcome`` are words of this module; ``label``,
    ``detail``, ``required`` and ``recorded`` are document text, escaped on
    output. ``note`` records a disagreement inside the record itself.
    """

    family: str
    label: Any
    detail: Any
    required: Any
    recorded: Any
    outcome: str
    note: str | None = None

    @property
    def style(self) -> tuple[str, str]:
        return _style(_CONTROL_STYLE, self.outcome)


def _falsifier_rows(doc: Mapping[str, Any]) -> list[_ControlRow]:
    rows = []
    for check in _dicts(doc.get("checks")):
        state, cases, owner = _evidence(check).get("falsification"), _cases(check), check.get("check_id")
        for case in cases:
            outcome = _case_outcome(case)
            recorded = case.get("outcome")
            note = None if _is(recorded, outcome) else f"the case records {_plain(recorded)}; its own results give {outcome}"
            rows.append(
                _ControlRow(
                    "falsifier",
                    owner,
                    f"{_plain(case.get('case_id'))}: {_plain(case.get('description'))}",
                    _verdict_text(case.get("expected")),
                    _verdict_text(case.get("actual")),
                    outcome,
                    note,
                )
            )
        if state is not None and not cases:
            meaning = _WITNESS_MEANING.get(state, "") if isinstance(state, str) else ""
            rows.append(
                _ControlRow("falsifier", owner, meaning or "no case ran", "a known-bad case", "none ran", _plain(state))
            )
        elif state is None and _is(check.get("verdict"), "PASS"):
            rows.append(
                _ControlRow("falsifier", owner, "no witness record", "a known-bad case", "nothing recorded",
                            "NOT RECORDED")
            )
    return rows


def _canary_rows(controls: Mapping[str, Any]) -> list[_ControlRow]:
    canary = _dict(controls.get("canary"))
    rows = []
    for control_id, twin, required, fixed in _CANARY_TWINS:
        record = _dict(canary.get(twin))
        verdict = record.get("verdict")
        outcome = (
            "NOT RECORDED" if not isinstance(verdict, str) else "AS REQUIRED" if verdict == required else "NOT AS REQUIRED"
        )
        rows.append(_ControlRow("canary", control_id, f"duplicate_rows over {fixed}", required,
                                _verdict_text(record), outcome))
    return rows


def _comparator_rows(controls: Mapping[str, Any]) -> list[_ControlRow]:
    """The comparator's pairs, judged against the contract's three pairs (17.6), not against the record alone.

    A record whose own expectation was edited cannot pass a pair the
    contract requires to disagree. A contract pair the record lacks is NOT
    RECORDED, and a recorded pair the contract does not name is listed with
    a note.
    """
    pairs = _dicts(_dict(controls.get("comparator_self_test")).get("pairs"))
    rows = []
    for claim, stored, required in COMPARATOR_PAIRS:
        recorded = [pair for pair in pairs if _is(pair.get("claim"), claim) and _is(pair.get("stored"), stored)]
        label = f"claim {claim} vs stored {stored}"
        if len(recorded) != 1:
            why = "not recorded" if not recorded else f"recorded {len(recorded)} times"
            rows.append(_ControlRow("comparator", label, f"contract pair {why}", required, "not recorded",
                                    "NOT RECORDED"))
            continue
        pair = recorded[0]
        actual = pair.get("actual")
        outcome = (
            "NOT RECORDED" if not isinstance(actual, str) else "AS REQUIRED" if actual == required else "NOT AS REQUIRED"
        )
        note = None if _is(pair.get("expected"), required) else (
            f"the record expects {_plain(pair.get('expected'))}; the contract requires {required}"
        )
        rows.append(_ControlRow("comparator", label, "compared through the live comparator", required,
                                _plain(actual), outcome, note))
    known = {(claim, stored) for claim, stored, _ in COMPARATOR_PAIRS}
    for pair in pairs:
        claim, stored = pair.get("claim"), pair.get("stored")
        if isinstance(claim, str) and isinstance(stored, str) and (claim, stored) in known:
            continue
        actual = pair.get("actual")
        outcome = "AS REQUIRED" if _str(actual) and actual == pair.get("expected") else "NOT AS REQUIRED"
        rows.append(_ControlRow("comparator", f"claim {_plain(claim)} vs stored {_plain(stored)}",
                                "not one of the contract's pairs", _plain(pair.get("expected")), _plain(actual),
                                outcome, "a pair the contract does not name"))
    return rows


def _resolver_checks(doc: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [check for check in _dicts(doc.get("checks")) if _is(check.get("kind"), "citation_resolver")]


def _canary_outcome(record: Mapping[str, Any]) -> str:
    """RESOLVED (a proven miss), HOLDS, NOT HELD (coverage unknown) or NOT RECORDED, from the record (17.14).

    A canary whose state is a resolution is RESOLVED whatever its ``holds``
    says, so a relabelled record cannot read as holding.
    """
    state = record.get("state")
    if isinstance(state, str) and state in _RESOLVING_STATES:
        return "RESOLVED"
    holds = record.get("holds")
    return "HOLDS" if holds is True else "NOT HELD" if holds is False else "NOT RECORDED"


def _resolver_rows(doc: Mapping[str, Any]) -> list[_ControlRow]:
    rows = []
    for check in _resolver_checks(doc):
        evidence = _evidence(check)
        for key, source in (("canaries", "frozen"), ("live_canaries", "live")):
            canaries = _dict(evidence.get(key))
            for prefix in sorted(canaries, key=_plain):
                record = _dict(canaries[prefix])
                recorded = f"{_plain(record.get('state'))}, body code {_plain(record.get('handle_response_code'))}"
                rows.append(
                    _ControlRow(
                        "resolver",
                        f"{_plain(check.get('check_id'))}: prefix {_plain(prefix)} ({source})",
                        record.get("doi") if record.get("doi") is not None else "no canary record",
                        "not resolved, body code 100",
                        recorded,
                        _canary_outcome(record),
                    )
                )
    return rows


def _pins_rows(controls: Mapping[str, Any]) -> list[_ControlRow]:
    pins = controls.get("pins")
    if not isinstance(pins, dict):
        return [_ControlRow("pins", "harness pins", "not recorded", "unchanged and unwritten", "not recorded",
                            "NOT RECORDED")]
    changed, writes = _strs(pins.get("changed")), _dicts(pins.get("writes"))
    holds = pins.get("holds")
    if holds is False or changed or writes:
        outcome = "DOES NOT HOLD"
    else:
        outcome = "HOLDS" if holds is True else "NOT RECORDED"
    return [
        _ControlRow(
            "pins",
            f"{_count(pins.get('pinned'))} pinned file(s)",
            "manifest, inputs, documents and checker modules, hashed before the PLAN",
            "unchanged and unwritten",
            f"{len(changed)} changed, {len(writes)} write(s)",
            outcome,
        )
    ]


def _control_rows(doc: Mapping[str, Any]) -> list[_ControlRow]:
    controls = _controls(doc)
    return (
        _falsifier_rows(doc)
        + _canary_rows(controls)
        + _comparator_rows(controls)
        + _resolver_rows(doc)
        + _pins_rows(controls)
    )


def _controls_svg(rows: Sequence[_ControlRow]) -> str:
    """Every negative control as a dumbbell: what it had to do, joined to what the run recorded.

    A held control joins a hollow required mark to a filled mark of its
    outcome's tone with a solid bar; a control that did not do what it had
    to has a dashed bar, so a miss shows without reading a word.
    """
    width, required_x, recorded_x = 960.0, 514.0, 628.0
    parts = [
        _text(required_x, 20, "REQUIRED", "sv-caps", "middle"),
        _text(recorded_x, 20, "RECORDED", "sv-caps", "middle"),
        _text(width - 16, 20, "OUTCOME", "sv-caps", "end"),
    ]
    y = 30.0
    good = {"REJECTED", "AS REQUIRED", "HOLDS"}
    for family, title, purpose in _CONTROL_FAMILIES:
        members = [row for row in rows if row.family == family]
        if not members:
            continue
        y += 40
        parts.append(_text(16, y, _e(f"{title.upper()} \u00b7 {len(members)}"), "sv-caps"))
        parts.append(_text(250, y, _e(purpose), "sv-small"))
        parts.append(f'<line class="sv-grid" x1="12" y1="{_n(y + 7)}" x2="{_n(width - 12)}" y2="{_n(y + 7)}"/>')
        shown = members[:_MAX_CONTROL_ROWS]
        for row in shown:
            y += 36
            mid = y - 4
            tone, glyph = row.style
            words = (
                f"{_plain(row.label)}: {_plain(row.detail)}; required {_plain(row.required)}, recorded "
                f"{_plain(row.recorded)}; {row.outcome}" + (f" ({row.note})" if row.note else "")
            )
            dash = "" if row.outcome in good else " missed"
            parts.append(
                f"<g>{_tip(_e(words))}"
                + _text(16, mid - 3, _clip(row.label, 44), "sv-label")
                + _text(16, mid + 12, _clip(row.detail, 52), "sv-small")
                + _text(required_x - 14, mid + 4, _clip(row.required, 27), "sv-value", "end")
                + _marker("accent", None, required_x, mid, 6, filled=False)
                + f'<line class="dumbbell t-{tone}{dash}" x1="{_n(required_x + 8)}" y1="{_n(mid)}" '
                f'x2="{_n(recorded_x - 11)}" y2="{_n(mid)}"/>'
                + _marker(tone, glyph, recorded_x, mid, 9)
                + _text(recorded_x + 16, mid + 4, _clip(row.recorded, 27), "sv-value")
                + _text(width - 16, mid + 4, _e(row.outcome), "sv-label", "end")
                + "</g>"
            )
        if len(members) > len(shown):
            y += 24
            parts.append(_text(16, y, f"{len(members) - len(shown)} more in the table", "sv-small"))
    counts = "; ".join(
        f"{title}: {sum(1 for row in rows if row.family == family and row.outcome in good)} of "
        f"{sum(1 for row in rows if row.family == family)} as required"
        for family, title, _ in _CONTROL_FAMILIES
        if any(row.family == family for row in rows)
    )
    return _svg("controls", width, y + 24, "Negative controls", f"{counts}.", parts, "wide-svg")


def _note(text: str) -> str:
    """A highlighted line in a table cell, kept for a record that disagrees with itself or with the contract."""
    return f'<div class="cell-note">{_e(text)}</div>'


def _same_checker(check: Mapping[str, Any], case: Mapping[str, Any]) -> str:
    """Whether a falsifier ran the subject's own checker and params, by the digests both record (17.5)."""
    evidence = _evidence(check)
    differing = [
        name
        for name in ("checker_sha256", "params_sha256")
        if not (_str(case.get(name)) and case.get(name) == evidence.get(name))
    ]
    if not differing:
        return "same checker and params digests"
    return "NO: " + " and ".join(f"{name} differs or is missing" for name in differing)


def _falsifier_table(doc: Mapping[str, Any], ledger: _LedgerView) -> str:
    """One row per falsifier case (17.5), as the text equivalent of the witness part of the controls figure.

    Each row gives the check and its witness state, the known-bad input,
    what the case had to give and what it gave, the ledger invocation that
    ran it, and whether it ran the subject's own checker and params.
    """
    rows = []
    unfalsified = []
    for position, check in enumerate(_dicts(doc.get("checks"))):
        state, cases = _evidence(check).get("falsification"), _cases(check)
        owner = _code(check.get("check_id")) + _sub(_e(check.get("kind")), words=True)
        if state is None and not cases:
            if _is(check.get("verdict"), "PASS"):
                missing = _pill("NOT RECORDED", "warning", "question")
                rows.append([owner + _sub(missing), _e("no witness record"),
                             _e("a known-bad case rejected") + _sub("recorded: nothing"), missing, "", ""])
            else:
                unfalsified.append(check.get("check_id"))
            continue
        state_pill = _pill(state, *_style(_WITNESS_STYLE, state))
        if not cases:
            meaning = _WITNESS_MEANING.get(state, "no case ran") if isinstance(state, str) else "no case ran"
            rows.append([owner + _sub(state_pill), _e(meaning), _e("a known-bad case") + _sub("recorded: none ran"),
                         state_pill, "", ""])
            continue
        for number, case in enumerate(cases):
            outcome = _case_outcome(case)
            recorded = case.get("outcome")
            note = "" if _is(recorded, outcome) else _note(f"the case records {_plain(recorded)}")
            invocation = ledger.falsifier_invocations.get((position, number))
            where = (
                _sub(f"invocation {_code(invocation)}, derived from its ledger position")
                if invocation
                else _sub("invocation not derivable from run.json; ledger.jsonl holds it")
            )
            expected_id = f"control:falsifier:{_plain(check.get('check_id'))}:{_plain(case.get('case_id'))}"
            id_note = "" if _is(case.get("control_id"), expected_id) else _note(f"expected ledger id {expected_id}")
            actual = _dict(case.get("actual"))
            rows.append(
                [
                    owner + (_sub(state_pill) if number == 0 else ""),
                    _code(case.get("case_id")) + _sub(_e(case.get("description"))),
                    _e(_verdict_text(case.get("expected")))
                    + _sub(f"recorded: {_e(_verdict_text(actual))} \u00b7 {_e(actual.get('execution_state'))}"),
                    _pill(outcome, *_style(_CONTROL_STYLE, outcome)) + note,
                    _breakable(case.get("control_id")) + where + id_note,
                    _e(_same_checker(check, case)),
                ]
            )
    table = _table(
        "Falsifier witnesses: each PASS re-run on a known-bad case of its own input",
        ("Check and witness", "Control input (known-bad case)", "Required, then recorded", "Outcome",
         "Ledger control and invocation", "Same checker"),
        rows,
        equivalent_of="controls",
        empty="no check reached a would-be PASS, so none was falsified",
        css="control-table",
    )
    if unfalsified:
        listed = ", ".join(_code(item) for item in unfalsified)
        table += f'<p class="small muted table-note">Not falsified (no would-be PASS to witness): {listed}</p>'
    return table


def _witness_lists(doc: Mapping[str, Any]) -> list[str]:
    """Where ``controls.falsifiers`` disagrees with the checks' own witness states; empty when they agree."""
    recorded = _controls(doc).get("falsifiers")
    if not isinstance(recorded, dict):
        return ["controls.falsifiers is not recorded"]
    problems = []
    checks = _dicts(doc.get("checks"))
    for state in _WITNESS_STYLE:
        own = sorted(_plain(c.get("check_id")) for c in checks if _is(_evidence(c).get("falsification"), state))
        listed = recorded.get(state)
        if not isinstance(listed, list) or sorted(_plain(item) for item in listed) != own:
            problems.append(f"controls.falsifiers.{state} lists {_plain(listed)}, the checks give {own}")
    invocations = sum(len(_cases(check)) for check in checks)
    if _int(recorded.get("invocations")) != invocations:
        problems.append(
            f"controls.falsifiers.invocations is {_plain(recorded.get('invocations'))}, the checks record "
            f"{invocations} case(s)"
        )
    return problems


def _control_cells(rows: Sequence[_ControlRow], family: str) -> list[list[str]]:
    return [
        [
            _breakable(row.label),
            _e(row.detail),
            _e(row.required),
            _e(row.recorded),
            _pill(row.outcome, *row.style) + (_note(row.note) if row.note else ""),
        ]
        for row in rows
        if row.family == family
    ]


def _resolver_table(doc: Mapping[str, Any]) -> str:
    """Per-prefix resolver canaries (17.14): one table row per canary, then the prefixes no longer trusted."""
    checks = _resolver_checks(doc)
    if not checks:
        return ""
    rows = []
    for check in checks:
        evidence = _evidence(check)
        for key, source in (("canaries", "frozen"), ("live_canaries", "live")):
            canaries = _dict(evidence.get(key))
            for prefix in sorted(canaries, key=_plain):
                record = _dict(canaries[prefix])
                provenance = _dict(record.get("provenance"))
                outcome = _canary_outcome(record)
                rows.append(
                    [
                        _code(check.get("check_id")) + _sub(_e(source)),
                        _code(prefix),
                        _hash(record.get("doi")),
                        _e(record.get("state")) + _sub(f"body code {_e(record.get('handle_response_code'))}"),
                        _e(provenance.get("retrieved_at")) + _sub(_e(provenance.get("resolver_identity"))),
                        _pill(outcome, *_style(_CONTROL_STYLE, outcome)) + _sub(_e(record.get("detail"))),
                    ]
                )
        distrusted = _strs(evidence.get("distrusted_prefixes"))
        if distrusted:
            rows.append(
                [
                    _code(check.get("check_id")),
                    ", ".join(_code(prefix) for prefix in distrusted),
                    _e("distrusted prefix"),
                    _e("every DOI under it is reported SOURCE_UNAVAILABLE, never DOI_RESOLVED"),
                    "",
                    _pill("RESOLVED", *_style(_CONTROL_STYLE, "RESOLVED")),
                ]
            )
    return _table(
        "Resolver canaries, per prefix the run touched",
        ("Resolver check", "Prefix", "Canary DOI", "State", "Captured", "Outcome"),
        rows,
        equivalent_of="controls",
        empty="the resolver records no canary for any prefix",
    )


def _min_discrimination_text(doc: Mapping[str, Any]) -> str:
    weakest = _controls(doc).get("min_discrimination")
    if not isinstance(weakest, dict):
        return "no PASS result records a discrimination ratio"
    ratio = _ratio_view(weakest.get("ratio"))
    return f"{_plain(weakest.get('check_id'))}: {ratio.text()} of its grid rejected"


def _claim_join_text(doc: Mapping[str, Any]) -> str:
    counts = _controls(doc).get("claim_join")
    if not isinstance(counts, dict):
        return "no claim_join check ran"
    return ", ".join(f"{outcome} {_count(counts.get(outcome))}" for outcome in _JOIN_OUTCOMES)


def _controls_section(doc: Mapping[str, Any], invariants: Sequence[_InvariantRow], ledger: _LedgerView) -> str:
    controls = _controls(doc)
    rows = _control_rows(doc)
    figure = _figure(
        "controls",
        _controls_svg(rows),
        "Each line is one negative control the run executed: on the left what it had to do, on the right what "
        "the run recorded. A dashed bar is a control that did not do what it had to. A falsifier re-runs a "
        "PASS check's own checker on a known-bad case of its input, so a PASS that survives it could have failed.",
        "scroll-wide",
    )
    legend = _legend(
        [
            ("accent", "hollow", "what the control had to do"),
            ("good", "fill", "as required: rejected, held"),
            ("critical", "fill", "a proven miss: accepted, resolved, broken"),
            ("warning", "fill", "not recorded, or coverage unknown"),
        ]
    )
    comparator = _dict(controls.get("comparator_self_test"))
    canary = _dict(controls.get("canary"))
    canary_rows = []
    for control_id, twin, required, fixed in _CANARY_TWINS:
        record = _dict(canary.get(twin))
        row = next(item for item in rows if item.family == "canary" and item.label == control_id)
        canary_rows.append(
            [_breakable(control_id), _e(f"duplicate_rows over {fixed} (fixed by ARCHITECTURE.md 17.5)"),
             _e(required), _e(_verdict_text(record)), _code(record.get("invocation_id")), _pill(row.outcome, *row.style)]
        )
    tables = (
        _falsifier_table(doc, ledger)
        + _table(
            "Run canary: the same checker path on input fixed by the contract",
            ("Twin", "Input", "Required", "Recorded", "Invocation", "Outcome"),
            canary_rows,
            equivalent_of="controls",
            empty="no canary",
        )
        + _table(
            f"Comparator self-test (invocation {_plain(comparator.get('invocation_id'))})",
            ("Pair", "How", "Required by the contract", "Recorded", "Outcome"),
            _control_cells(rows, "comparator"),
            equivalent_of="controls",
            empty="no pair",
        )
        + _resolver_table(doc)
    )
    checker_invariants = [row for row in invariants if row.plane == "checker"]
    facts = [
        ("Harness pins", _e(_pins_text(_dict(controls.get("pins"))) if isinstance(controls.get("pins"), dict)
                            else "not recorded")),
        ("Write detection", _e("in-process file access only: subprocess and C-extension I/O are invisible to the "
                               "harness hook (D10)")),
        ("Weakest discrimination", _e(_min_discrimination_text(doc))),
        ("Claim-to-invocation join", _e(_claim_join_text(doc))),
        *(
            (f"Invariant {_breakable(row.name)}", f"{_pill(row.state, *_INVARIANT_STYLE[row.state])} {_e(row.detail)}")
            for row in checker_invariants
        ),
    ]
    disagreements = _witness_lists(doc)
    notice = (
        '<div class="notice t-warning"><p>The run\'s witness summary disagrees with its checks:</p><ul>'
        + "".join(f"<li>{_e(text)}</li>" for text in disagreements)
        + "</ul></div>"
        if disagreements
        else ""
    )
    fact_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    return _section(
        "controls",
        "Checker controls",
        "could the checks have failed? (the CHECKER part of performance)",
        f"{figure}{legend}{notice}<dl class=\"meta compact\" data-equivalent-of=\"controls\">{fact_html}</dl>{tables}",
    )


# ---------------------------------------------------------------------------
# Numeric discrimination (17.8, 17.11)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Discrimination:
    """A check's discrimination: the share of a stated grid of nearby values it would reject."""

    check: Mapping[str, Any]
    ratio: _RatioView
    #: ``(entry label, its ratio, its grid or note)`` for each compared value or consistency test.
    entries: tuple[tuple[str, _RatioView, str], ...]


#: The grid numeric_agreement and the comparator probe (17.8): 21 claims around the printed claim.
_AGREEMENT_GRID = "21 claims: the printed claim plus or minus up to 10 units of its last printed digit"


def _discriminations(doc: Mapping[str, Any]) -> list[_Discrimination]:
    items = []
    for check in _dicts(doc.get("checks")):
        evidence = _evidence(check)
        if "discrimination_ratio" not in evidence:
            continue
        entries: list[tuple[str, _RatioView, str]] = []
        for comparison in _dicts(evidence.get("comparisons")):
            if "discrimination" in comparison:
                stored = _dict(comparison.get("stored")).get("text")
                label = (
                    f"key {_plain(comparison.get('key'))}: claim {_plain(comparison.get('claimed'))} "
                    f"vs stored {_plain(stored)}"
                )
                entries.append((label, _ratio_view(comparison.get("discrimination")), _AGREEMENT_GRID))
        for test in _dicts(_dict(evidence.get("consistency")).get("tests")):
            grid = _dict(test.get("evidence")).get("grid")
            label = f"{_plain(test.get('claim_id'))} {_plain(test.get('test'))}: {_plain(test.get('outcome'))}"
            entries.append((label, _ratio_view(test.get("discrimination_ratio")), _plain(grid) if grid else ""))
        items.append(_Discrimination(check, _ratio_view(evidence.get("discrimination_ratio")), tuple(entries)))
    return items


def _weakest(items: Sequence[_Discrimination]) -> Any:
    """The check id the page computes as the weakest PASS (17.8): least exact value, ties to the first check id."""
    passed = [
        item for item in items
        if _is(item.check.get("verdict"), "PASS") and item.ratio.defined and item.ratio.ratio is not None
    ]
    if not passed:
        return None
    best = min(passed, key=lambda item: (item.ratio.ratio.value, _plain(item.check.get("check_id"))))
    return best.check.get("check_id")


def _discrimination_svg(items: Sequence[_Discrimination], weakest: Any) -> str:
    """One bar per check, filled by the share of its grid it would reject; a ratio without a value is never filled."""
    width, track_x, track_w, step = 860.0, 250.0, 360.0, 46.0
    shown = items[:_MAX_DISCRIMINATION_ROWS]
    parts = [_text(track_x, 22, "SHARE OF ITS GRID THE CHECK WOULD REJECT", "sv-caps")]
    y = 40.0
    for item in shown:
        check = item.check
        parts.append(_text(16, y + 12, _clip(check.get("check_id"), 30), "sv-label"))
        parts.append(_text(16, y + 27, _clip(f"{_plain(check.get('kind'))} \u00b7 {_plain(check.get('verdict'))}", 36),
                           "sv-small"))
        tip = _tip(_e(f"{_plain(check.get('check_id'))}: {item.ratio.text()}"))
        ratio = item.ratio.ratio
        if item.ratio.defined and ratio is not None and ratio.value is not None and ratio.denominator:
            parts.append(f'<g>{tip}<rect class="track" x="{_n(track_x)}" y="{_n(y + 6)}" width="{_n(track_w)}" '
                         f'height="16" rx="4"/>')
            fill = float(ratio.value) * track_w
            parts.append(f'<g class="t-accent">{_bar(track_x, y + 6, fill, 16, "fill-tone")}</g>')
            if ratio.denominator <= 30:
                for unit in range(1, ratio.denominator):
                    tick = track_x + unit * track_w / ratio.denominator
                    parts.append(_line("tick", tick, y + 6, tick, y + 22))
            parts.append("</g>")
        else:
            parts.append(f'<g>{tip}<rect class="track undefined" x="{_n(track_x)}" y="{_n(y + 6)}" '
                         f'width="{_n(track_w)}" height="16" rx="4"/></g>')
        parts.append(_text(track_x + track_w + 12, y + 19, _clip(item.ratio.text(), 34), "sv-value"))
        if weakest is not None and _is(check.get("check_id"), weakest):
            parts.append(_text(track_x + track_w + 12, y + 33, "weakest PASS", "sv-small"))
        y += step
    if len(items) > len(shown):
        parts.append(_text(16, y + 12, f"{len(items) - len(shown)} more in the table", "sv-small"))
        y += step
    desc = "; ".join(f"{_plain(item.check.get('check_id'))} {item.ratio.text()}" for item in items) + "."
    return _svg("discrimination", width, y + 6, "Numeric discrimination", desc, parts, "wide-svg")


def _discrimination_section(doc: Mapping[str, Any]) -> str:
    items = _discriminations(doc)
    weakest = _weakest(items)
    figure = _figure(
        "discrimination",
        _discrimination_svg(items, weakest),
        "How sharp each numeric check was: of a stated grid of values near the one it checked, the share it would "
        "have rejected. A PASS needs more than zero. A ratio without a value (a zero or unknown denominator) is "
        "drawn as an empty dashed track, never as 0% or 100%.",
        "scroll-wide",
    )
    rows = []
    for item in items:
        check = item.check
        rows.append(
            [_code(check.get("check_id")) + _sub(_wbr(check.get("kind"), "_"), words=True), _e("whole check (its minimum)"),
             _e(item.ratio.text()), _e(_plain(_dict(_evidence(check).get("discrimination_ratio")).get("state"))),
             _e("weakest PASS" if weakest is not None and _is(check.get("check_id"), weakest) else "")]
        )
        rows += [
            ["", _e(label), _e(ratio.text()), _e(ratio.ratio.state.value if ratio.ratio else "not recorded"), _e(grid)]
            for label, ratio, grid in item.entries
        ]
    table = _table(
        "Discrimination per check and per compared value",
        ("Check", "Entry", "Rejected of its grid", "State", "Grid and note"),
        rows,
        equivalent_of="discrimination",
        empty="no check records a discrimination ratio",
    )
    recorded_id = _dict(_controls(doc).get("min_discrimination")).get("check_id")
    agreement = ""
    if not (_is(recorded_id, weakest) or (recorded_id is None and weakest is None)):
        disagreement = (
            f"run.json records the weakest PASS as {_plain(recorded_id)}, but its checks give {_plain(weakest)}"
        )
        agreement = f'<div class="notice t-warning"><p>{_e(disagreement)}</p></div>'
    line = (
        '<p class="closure-line">Weakest discrimination among PASS results, as recorded: '
        f"{_e(_min_discrimination_text(doc))}</p>"
    )
    return _section(
        "discrimination",
        "Numeric discrimination",
        "how much of a nearby grid each numeric check would reject",
        f"{line}{agreement}{figure}{table}",
    )


# ---------------------------------------------------------------------------
# Plan and closure (17.4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PlanItem:
    """One item the PLAN commits to: a declared check or a planned control, and what run.json records for it."""

    item_id: Any
    family: str
    kind: Any
    required: Any
    invocation: str | None
    outcome: str

    @property
    def closed(self) -> bool:
        """True when run.json records a terminal invocation for the item (an id on its result or control)."""
        return self.invocation is not None


def _plan_items(doc: Mapping[str, Any]) -> list[_PlanItem]:
    """The planned checks (the manifest's, which ``plan_matches_manifest`` ties to the PLAN) and the planned controls."""
    results: dict[str, Mapping[str, Any]] = {}
    for result in _dicts(doc.get("checks")):
        if isinstance(result.get("check_id"), str):
            results.setdefault(result["check_id"], result)
    items = []
    for spec in _dicts(_dict(doc.get("declared")).get("checks")):
        check_id = spec.get("id")
        result = results.get(check_id) if isinstance(check_id, str) else None
        invocation = _str(result.get("invocation_id")) if result is not None else None
        outcome = _verdict_text(result) if result is not None else "no result recorded"
        items.append(_PlanItem(check_id, "check", spec.get("kind"), spec.get("required"), invocation, outcome))
    records = {control_id: (record, outcome) for control_id, record, outcome in _control_records(doc)}
    for control_id in PLANNED_CONTROLS:
        record, outcome = records.get(control_id, ({}, "not recorded"))
        items.append(_PlanItem(control_id, "control", "control", True, _str(record.get("invocation_id")), outcome))
    return items


def _plan_svg(plan: Any, items: Sequence[_PlanItem]) -> str:
    """The PLAN token, then one cell per planned item: closed when run.json records its terminal invocation.

    Checks are squares and controls circles; a closed item is filled with a
    check mark, an open one hollow with a cross, so a gap shows by shape and
    mark as well as by color.
    """
    width, cells_x, slot, per_row, row_step, first = 960.0, 214.0, 61.0, 12, 78.0, 60.0
    record = _dict(plan)
    parts = [
        '<rect class="plan-token" x="16" y="40" width="170" height="66" rx="10"/>',
        _text(30, 62, "PLAN", "sv-caps"),
        _text(30, 80, "ledger entry 1" if record else "not recorded", "sv-small"),
        _text(30, 96, _e(_short_hash(record.get("entry_sha256"))), "sv-mono"),
        f'<path class="arrow-tip" d="M{_n(cells_x - 16)} 68L{_n(cells_x - 7)} 73L{_n(cells_x - 16)} 78Z"/>',
        _line("chain-link", 186, 73, cells_x - 14, 73),
    ]
    shown = items[:_MAX_PLAN_CELLS]
    # Each family is named once, above its first cell: the planned checks, then the contract's controls.
    for family, title in (("check", "CHECKS"), ("control", "CONTROLS")):
        members = [index for index, item in enumerate(shown) if item.family == family]
        if members:
            row, column = divmod(members[0], per_row)
            count = sum(1 for item in items if item.family == family)
            label = _e(f"{title} \u00b7 {count}")
            parts.append(_text(cells_x + column * slot + 2, first - 10 + row * row_step, label, "sv-caps"))
    y = first
    for index, item in enumerate(shown):
        row, column = divmod(index, per_row)
        x, y = cells_x + column * slot + 15, first + row * row_step
        tone, glyph = ("good", "check") if item.closed else ("critical", "cross")
        words = f"{_plain(item.item_id)} ({item.family}): " + (
            f"terminal invocation {item.invocation}, recorded {item.outcome}" if item.closed else
            f"no terminal invocation recorded ({item.outcome})"
        )
        if item.family == "check":
            shape = "fill-tone" if item.closed else "hollow"
            mark = (f'<rect class="{shape}" x="{_n(x - 13)}" y="{_n(y)}" width="26" height="26" rx="6"/>'
                    + _glyph(glyph, x, y + 13, 13, on_fill=item.closed))
            parts.append(f'<g class="t-{tone}">{_tip(_e(words))}{mark}</g>')
        else:
            parts.append(f"<g>{_tip(_e(words))}{_marker(tone, glyph, x, y + 13, 13, filled=item.closed)}</g>")
        parts.append(_text(x, y + 42, _clip(_short_id(item.item_id), 9), "sv-small", "middle"))
    closed = sum(1 for item in items if item.closed)
    bottom = y + 62
    if len(items) > len(shown):
        parts.append(_text(cells_x, bottom, f"{len(items) - len(shown)} more in the table", "sv-small"))
        bottom += 18
    parts.append(_text(16, bottom, _e(f"{closed} of {len(items)} planned item(s) closed by a terminal invocation "
                                       "recorded in run.json"), "sv-sub"))
    desc = (
        f"PLAN {'recorded at ledger entry 1' if record else 'not recorded'}; {len(items)} planned item(s), "
        f"{closed} closed: " + ", ".join(f"{_plain(item.item_id)} {'closed' if item.closed else 'OPEN'}" for item in items)
        + "."
    )
    return _svg("plan", width, bottom + 12, "Plan closure", desc, parts, "wide-svg")


def _short_id(value: Any) -> str:
    """A planned control's last word (``must_fail``) or a check's id, for a label under its cell."""
    text = _plain(value)
    return text.rsplit(":", 1)[-1] if text.startswith("control:") else text


def _plan_section(doc: Mapping[str, Any], invariants: Sequence[_InvariantRow]) -> str:
    plan = _controls(doc).get("plan")
    record = _dict(plan)
    items = _plan_items(doc)
    figure = _figure(
        "plan",
        _plan_svg(plan, items),
        "Before any check ran, the run wrote a PLAN as ledger entry 1: every declared check and every planned "
        "control (the canary twins and the comparator). Each cell is one planned item, closed when run.json records "
        "its terminal invocation. plan_closure checks the same against the ledger itself.",
        "scroll-wide",
    )
    manifest = _dict(doc.get("manifest")).get("sha256")
    committed = record.get("manifest_sha256")
    declared = _dict(doc.get("declared"))
    pins = _controls(doc).get("pins")
    same = "the manifest this run read" if _str(committed) and committed == manifest else (
        f"this run read manifest sha256 {_plain(manifest)}"
    )
    facts = [
        ("PLAN entry", f"ledger entry 1, entry sha256 {_hash(record.get('entry_sha256'))}" if record
         else _e("not recorded: nothing shows what the run committed to before its checks ran")),
        ("Manifest", f"{_hash(committed)} ({_e(same)})" if record else _e("not recorded")),
        ("Planned",
         _e(f"{_count(record.get('inputs_planned'))} input(s), {_count(record.get('checks_planned'))} check(s), "
            f"{_count(record.get('pins'))} pin(s), and the {len(PLANNED_CONTROLS)} contract controls")
         if record else _e("not recorded")),
        ("Declared",
         _e(f"{len(_dicts(declared.get('inputs')))} input(s) and {len(_dicts(declared.get('checks')))} check(s) "
            f"in the manifest; {_count(_dict(pins).get('pinned'))} file(s) pinned by the harness")),
    ]
    for name in _PLAN_INVARIANTS:
        for row in (row for row in invariants if row.name == name):
            facts.append((f"Invariant {_breakable(name)}", f"{_pill(row.state, *_INVARIANT_STYLE[row.state])} {_e(row.detail)}"))
    gaps = [item for item in items if not item.closed]
    mismatches = []
    if record:
        for key, count, what in (
            ("checks_planned", len(_dicts(declared.get("checks"))), "checks"),
            ("inputs_planned", len(_dicts(declared.get("inputs"))), "inputs"),
        ):
            if _int(record.get(key)) != count:
                mismatches.append(f"the PLAN records {key} {_plain(record.get(key))}, but run.json declares {count} {what}")
        if isinstance(pins, dict) and _int(record.get("pins")) != _int(pins.get("pinned")):
            mismatches.append(
                f"the PLAN records {_plain(record.get('pins'))} pin(s), but the harness reports "
                f"{_plain(pins.get('pinned'))} pinned"
            )
    notices = ""
    if gaps:
        listed = "".join(f"<li>{_code(item.item_id)} ({_e(item.family)}): {_e(item.outcome)}</li>" for item in gaps)
        notices += (
            '<div class="notice t-critical"><p>Planned but not closed by a terminal invocation in run.json (an '
            f"unexecuted planned item is a failure, D1):</p><ul>{listed}</ul></div>"
        )
    if mismatches:
        notices += (
            '<div class="notice t-warning"><p>The PLAN summary disagrees with the rest of run.json:</p><ul>'
            + "".join(f"<li>{_e(text)}</li>" for text in mismatches)
            + "</ul></div>"
        )
    table = _table(
        "Planned items and their terminal invocations",
        ("Planned item", "Kind", "Required", "Terminal invocation", "Recorded", "Closed"),
        [
            [_breakable(item.item_id), _e(item.kind), _e(_required_word(item.required)), _code(item.invocation),
             _e(item.outcome),
             _pill("CLOSED", "good", "check") if item.closed else _pill("OPEN", "critical", "cross")]
            for item in items
        ],
        equivalent_of="plan",
        empty="nothing was planned",
    )
    fact_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    return _section(
        "plan",
        "Plan closure",
        "committed before any check ran, then closed by what ran",
        f'{figure}{notices}<dl class="meta compact" data-equivalent-of="plan">{fact_html}</dl>{table}',
    )


# ---------------------------------------------------------------------------
# Claim-to-invocation join (17.15)
# ---------------------------------------------------------------------------


def _claim_join_results(doc: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [check for check in _dicts(doc.get("checks")) if _is(check.get("kind"), "claim_join")]


def _join_members(results: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Every bucket's members across the claim_join results, in result order (17.15)."""
    members: dict[str, list[str]] = {outcome: [] for outcome in _JOIN_OUTCOMES}
    for result in results:
        buckets = _dict(_evidence(result).get("buckets"))
        for outcome in _JOIN_OUTCOMES:
            members[outcome] += [_plain(item) for item in _strs(buckets.get(outcome))]
    return members


def _claim_join_svg(members: Mapping[str, Sequence[str]]) -> str:
    """Four columns, one per join outcome, with one mark per assertion (or, for ORPHANED, per invocation)."""
    width, column = 960.0, 240.0
    parts = []
    deepest = 0
    for index, outcome in enumerate(_JOIN_OUTCOMES):
        x = index * column + 16
        listed = list(members.get(outcome, ()))
        tone, glyph = _JOIN_STYLE[outcome]
        parts.append(_text(x, 26, _e(f"{outcome} \u00b7 {len(listed)}"), "sv-caps"))
        parts.append(_text(x, 42, _clip(_JOIN_MEANING[outcome], 38), "sv-small"))
        shown = listed[:_MAX_JOIN_PER_BUCKET]
        for row, identifier in enumerate(shown):
            y = 70 + row * 26
            parts.append(f"<g>{_tip(_e(f'{outcome}: {identifier}'))}{_marker(tone, glyph, x + 9, y, 9)}</g>")
            parts.append(_text(x + 26, y + 4, _clip(identifier, 30), "sv-label"))
        if not listed:
            parts.append(_text(x, 74, "none", "sv-sub"))
        hidden = len(listed) - len(shown)
        if hidden:
            parts.append(_text(x, 70 + len(shown) * 26 + 4, f"{hidden} more in the table", "sv-small"))
        deepest = max(deepest, len(shown) + (1 if hidden else 0), 1)
    desc = "; ".join(f"{outcome} {len(members.get(outcome, ()))}" for outcome in _JOIN_OUTCOMES) + "."
    return _svg("claim-join", width, 70 + deepest * 26 + 10, "Claim-to-invocation join", desc, parts, "wide-svg")


def _claims_section(doc: Mapping[str, Any]) -> str:
    """Asserted actions joined to a sealed run's ledger (#6): which claims the execution record backs."""
    results = _claim_join_results(doc)
    members = _join_members(results)
    figure = _figure(
        "claim-join",
        _claim_join_svg(members),
        "Each assertion an agent or author made about what ran is joined to the sealed run it cites. BACKED: a "
        "terminal invocation in an intact chain backs it. NARRATED: nothing does. CONTRADICTED: the invocation "
        "recorded another result. ORPHANED lists failing invocations no assertion mentions; it does not decide.",
        "scroll-wide",
    )
    assertion_rows = []
    facts = []
    recomputed: dict[str, int] = {outcome: 0 for outcome in _JOIN_OUTCOMES}
    problems = []
    for result in results:
        evidence = _evidence(result)
        check_id = result.get("check_id")
        for assertion in _dicts(evidence.get("assertions")):
            outcome = assertion.get("outcome")
            assertion_rows.append(
                [_code(assertion.get("claim_id")) + _sub(_e(check_id)), _e(assertion.get("kind")),
                 _code(assertion.get("cites")), _pill(outcome, *_style(_JOIN_STYLE, outcome)),
                 _e(assertion.get("detail"))]
            )
        counts = evidence.get("counts")
        buckets = _dict(evidence.get("buckets"))
        if isinstance(counts, dict):
            for outcome in _JOIN_OUTCOMES:
                recomputed[outcome] += _int(counts.get(outcome)) or 0
                if _int(counts.get(outcome)) != len(_strs(buckets.get(outcome))):
                    problems.append(
                        f"{_plain(check_id)} counts {outcome} {_plain(counts.get(outcome))}, but its bucket lists "
                        f"{len(_strs(buckets.get(outcome)))}"
                    )
            tally = ", ".join(f"{outcome} {_count(counts.get(outcome))}" for outcome in _JOIN_OUTCOMES)
        else:
            label = _evidence(result).get("skip_justification")
            tally = f"unknown: no counts recorded ({_plain(result.get('execution_state'))}, {_plain(label)})"
        seal = _dict(_dict(evidence.get("sealed_run")).get("seal"))
        chain = _dict(evidence.get("chain"))
        chain_text = (
            f"intact {_plain(chain.get('intact'))}, {_count(chain.get('observed_length'))} entries observed, head "
            f"{_short_hash(chain.get('observed_head'))}"
            + (f"; problems: {'; '.join(_strs(chain.get('problems')))}" if _strs(chain.get("problems")) else "")
        )
        facts += [
            (f"{_e(check_id)} verdict", f"{_status_pill(result.get('verdict'))} {_e(result.get('reason'))}"),
            ("Counts", _e(tally)),
            ("Sealed run", f"{_path(_dict(evidence.get('sealed_run')).get('path'))} {_e(seal.get('run_id'))}, "
                           f"{_e(_count(seal.get('ledger_length')))} entries, head {_hash(seal.get('ledger_head_sha256'))}"),
            ("Chain", _e(chain_text)),
        ]
    mirrored = _controls(doc).get("claim_join")
    with_counts = [result for result in results if isinstance(_evidence(result).get("counts"), dict)]
    if with_counts and not (isinstance(mirrored, dict) and all(
        _int(mirrored.get(outcome)) == recomputed[outcome] for outcome in _JOIN_OUTCOMES
    )):
        problems.append(f"controls.claim_join records {_plain(mirrored)}, but the claim_join results sum to {recomputed}")
    if not with_counts and mirrored is not None:
        problems.append(f"controls.claim_join records {_plain(mirrored)}, but no claim_join result carries counts")
    facts.append(("Mirrored in controls", _e(_claim_join_text(doc))))
    notice = (
        '<div class="notice t-warning"><p>The join\'s counts disagree with its own records:</p><ul>'
        + "".join(f"<li>{_e(text)}</li>" for text in problems)
        + "</ul></div>"
        if problems
        else ""
    )
    orphaned = [[_code(identifier), _e("a terminal FAIL or ERROR invocation that no assertion cites")]
                for identifier in members[AssertionOutcome.ORPHANED.value]]
    tables = _table(
        "Assertions and how they join the sealed run",
        ("Claim", "Kind", "Cites", "Outcome", "Detail"),
        assertion_rows,
        equivalent_of="claim-join",
        empty="no assertion was recorded",
    ) + _table(
        "Orphaned invocations (listed, never decisive)",
        ("Invocation", "Why it is listed"),
        orphaned,
        equivalent_of="claim-join",
        empty="none",
    )
    fact_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    return _section(
        "claims",
        "Claim join",
        "asserted actions joined to the ledger of the run they cite",
        f'{notice}{figure}<dl class="meta compact" data-equivalent-of="claim-join">{fact_html}</dl>{tables}',
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
            f'<span class="plane-tag">{_INVARIANT_TAGS.get(row.plane, row.plane)}</span>'
            f'<span class="facet-detail">{_e(row.detail)}</span></li>'
        )
    listing = f'<ol class="invariant-list" data-equivalent-of="invariants">{"".join(items)}</ol>'
    return _section(
        "invariants",
        "Invariant ring",
        "every applicable invariant must hold for a PASS",
        f'<div class="ring-layout">{figure}{listing}</div>',
    )


def _ledger_section(doc: Mapping[str, Any], ledger: _LedgerView) -> str:
    figure = _figure(
        "ledger",
        _chain_svg(ledger),
        "Each link is one ledger entry, and each entry hashes the entry before it. STARTED entries are placed "
        "exactly by recomputing inv-sha256(run_id:seq). The PLAN, the terminal entries and each check's falsifier "
        "runs are placed by the ledger order of ARCHITECTURE.md 17.5, and only when they then fill the sealed "
        "length exactly; otherwise they are drawn plain and not guessed. A bracket groups each invocation with "
        "the falsifiers that ran inside it.",
        "scroll-wide",
    )
    legend = _legend(
        [
            ("accent", "plan", "PLAN (entry 1)"),
            ("accent", "fill", "a check's STARTED entry"),
            ("good", "fill", "a check's terminal entry, in its verdict's color"),
            ("accent", "dashed", "a falsifier run inside its check"),
            ("muted", "hollow", "a control (comparator, canary twin)"),
            ("muted", "plain", "not identified from run.json"),
        ]
    )
    rows = [
        [
            _e(seq),
            _e(entry.phase),
            _e(entry.family) + _sub(_breakable(entry.owner)),
            _code(entry.invocation) if entry.invocation is not None else '<span class="muted">none</span>',
            _e(entry.outcome) if entry.outcome is not None else "",
        ]
        for seq, entry in ledger.entries.items()
    ]
    table = _table(
        "Ledger entries identified from run.json" if ledger.complete else "Ledger entries placed exactly from their ids",
        ("Seq", "Entry", "Belongs to", "Invocation", "Recorded"),
        rows,
        equivalent_of="ledger",
        empty="no entry could be identified",
    )
    facts = [
        ("Entries", _e(_count(ledger.length))),
        ("Head", _hash(ledger.head)),
        ("Identified", _e(ledger.note)),
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
        f'{figure}{legend}<dl class="meta compact" data-equivalent-of="ledger">{fact_html}</dl>{table}',
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


def _harness_controls(report: Mapping[str, Any]) -> tuple[str, str]:
    """The v2 harness controls (17.12) as recorded: M00's forced detection and the conservation identities.

    A report without them (an INVALID_BASELINE report, or one written before
    v2) shows "not recorded", never a control that held.
    """
    holds = _dict(report.get("conservation")).get("holds")
    conservation_text = "holds" if holds is True else "does NOT hold" if holds is False else "not recorded"
    return _forced_words(_dict(report.get("forced_detection"))), conservation_text


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
    forced_text, conservation_text = _harness_controls(report)
    facts += [("Forced detection (M00)", _e(forced_text)), ("Conservation", _e(conservation_text))]
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


def _identity_word(value: bool | None) -> str:
    return "holds" if value is True else "does NOT hold" if value is False else "not recorded"


def _conservation_part(view: _MutationView) -> str:
    """The conservation identities and M00 (17.12), drawn and then listed, both recomputed rather than trusted.

    A report without buckets and without a forced detection (one written
    before v2, or an INVALID_BASELINE report) shows a sentence saying so,
    never an identity that held.
    """
    cons, forced = view.conservation, view.forced
    if not cons.available and not forced:
        return (
            '<p class="muted small table-note">This report records no buckets and no forced detection (M00), so '
            "the conservation identities and the harness control cannot be shown.</p>"
        )
    figure = _figure(
        "conservation",
        _conservation_svg(view),
        "Every generated mutant must land in exactly one bucket: the executed ones, or one of the reasons a mutant "
        "never executed (not applicable, suppressed, a no-op, canonically equivalent, a duplicate, skipped, or not "
        "activated). The executed mutants open into their outcomes. Only DETECTED counts as a detection. M00 is a "
        "defect the harness plants in its own sealed run first; it is never counted.",
        "scroll-wide",
    )
    rows = []
    for part, statuses in (("executed", _EXECUTED_PARTITION), ("not executed", _UNEXECUTED_PARTITION)):
        for status in statuses:
            size = cons.sizes.get(status)
            members = cons.members.get(status, ())
            rows.append(
                [
                    _pill(status, _BUCKET_TONE.get(status, "muted"), None),
                    _e(part),
                    _e(_count(size)),
                    ", ".join(_code(item) for item in members) or '<span class="muted">none</span>',
                ]
            )
    buckets = _table(
        "Mutation buckets, as recorded",
        ("Bucket", "Part of", "Count", "Mutations"),
        rows,
        equivalent_of="conservation",
        empty="no buckets are recorded",
    )
    recorded = cons.recorded
    generated_sum = " + ".join(f"{status} {_count(cons.sizes.get(status))}" for status in _UNEXECUTED_PARTITION)
    executed_sum = " + ".join(f"{status} {_count(cons.sizes.get(status))}" for status in _EXECUTED_PARTITION)
    facts = [
        (
            "Generated",
            _e(f"{cons.generated} = executed {_count(cons.executed)} + {generated_sum}: "
               f"{_identity_word(cons.generated_holds)} (recomputed); the report records "
               f"{_identity_word(recorded.get('generated_holds'))}"),
        ),
        (
            "Executed",
            _e(f"{_count(cons.executed)} = {executed_sum}: {_identity_word(cons.executed_holds)} (recomputed); the "
               f"report records {_identity_word(recorded.get('executed_holds'))}"),
        ),
        (
            "Disjoint",
            _e(f"{'yes' if cons.disjoint else 'NO' if cons.disjoint is False else 'not recorded'} (recomputed); the "
               f"report records {_plain(recorded.get('disjoint'))}"),
        ),
        ("Problems", _e("; ".join(cons.problems)) if cons.problems else '<span class="muted">none</span>'),
    ]
    fired = [
        f"{_plain(item.get('detector'))} {_plain(item.get('status'))}" if isinstance(item, dict) else _plain(item)
        for item in (forced.get("fired") if isinstance(forced.get("fired"), list) else [])
    ]
    m00 = _table(
        "Harness control M00 (never counted)",
        ("Control", "Planted defect", "Required detector", "Detected", "Fired"),
        [
            [
                _breakable(forced.get("mutation_id") or "M00_forced_detection"),
                _e(forced.get("target")),
                _breakable(forced.get("detector")),
                _e(_forced_words(forced)),
                "<br>".join(_e(item) for item in fired) or '<span class="muted">none recorded</span>',
            ]
        ],
        equivalent_of="conservation",
        empty="not recorded",
    )
    fact_html = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in facts)
    return f'{figure}<dl class="meta compact single" data-equivalent-of="conservation">{fact_html}</dl>{m00}{buckets}'


def _pie_table(view: _MutationView) -> str:
    """The blind spots by PIE stage (17.12), in the order a defect travels, as text."""
    blind = view.group(BLIND_SPOT)
    if not blind:
        return ""
    stages = list(_PIE_STAGES) + ([_NO_STAGE] if any(item.stage == _NO_STAGE for item in blind) else [])
    rows = [
        [
            _code(stage) if stage != _NO_STAGE else _e(stage),
            _e(_PIE_MEANING.get(stage, "the record names no stage (a report before v2, or an escape with none)")),
            ", ".join(_code(item.mutation_id) for item in blind if item.stage == stage)
            or '<span class="muted">none</span>',
        ]
        for stage in stages
    ]
    return _table(
        "Blind spots by PIE stage: where each undetected defect stopped mattering",
        ("Stage", "Meaning", "Blind spots"),
        rows,
        equivalent_of="mutations",
        empty="no blind spot",
    )


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
            "detector fired. Blind spot: it executed and nothing caught it; below, each blind spot sits on the PIE "
            "stage where the defect stopped mattering. Mutants never executed (not activated, no-op, equivalent, "
            "duplicate, suppressed) and skipped or inapplicable operators are drawn apart and never count as "
            "detections.",
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
        + _conservation_part(view)
        + figure
        + _pie_table(view)
        + table
        + (f'<h3 class="sub-h">Report diagnostics</h3><ul class="plain-list">{diagnostics}</ul>' if diagnostics else "")
        + (
            f'<h3 class="sub-h">What this mutation report does not prove</h3><ul class="plain-list">{not_proven}</ul>'
            if not_proven
            else ""
        ),
    )


def _transitions(doc: Mapping[str, Any]) -> str:
    """The verdict lattice's log (#23): each step at which the run's verdict rose, and what raised it."""
    recorded = _controls(doc).get("verdict_transitions")
    if not isinstance(recorded, list):
        listing = '<p class="muted">The verdict transitions are not recorded.</p>'
    elif not recorded:
        listing = (
            '<p class="muted">No contribution was recorded, so the empty aggregate decided '
            "(ABSTAIN / INSUFFICIENT_EVIDENCE, never PASS).</p>"
        )
    else:
        steps = []
        for item in recorded:
            step = _dict(item)
            steps.append(
                f"<li>{_e(step.get('before'))} \u2192 <strong>{_e(step.get('after'))}</strong> at step "
                f"{_e(_count(step.get('step')))}: {_code(step.get('source'))} {_e(step.get('reason'))}</li>"
            )
        listing = f'<ol class="plain-list">{"".join(steps)}</ol>'
    return f'<h3 class="sub-h">How the verdict rose (NONE &lt; PASS &lt; ABSTAIN &lt; FAIL &lt; ERROR)</h3>{listing}'


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
    body += _transitions(doc)
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
        "A falsifier witness shows that a checker rejected one known-bad case built from its own input. It does not "
        "show that the checker catches every defect, and a discrimination figure covers only its stated grid.",
        "Write detection sees in-process file access only: subprocess and C-extension I/O are invisible to the "
        "harness hook, and a write from another thread is caught only by the post-run re-hash.",
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
.meta.single{grid-template-columns:minmax(0,1fr)}
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
.scroll-panel svg{min-width:440px;max-width:680px}
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
.facets .facet-group{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;margin-top:4px;padding-top:8px;
  border-top:1px solid var(--grid)}
.facets .facet-group:first-child{margin-top:0;padding-top:0;border-top:0}
.plane-card.void .facet-group{border-top-color:var(--void-edge)}
.group-name{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-2)}
.group-question{font-size:12px;color:var(--ink-2)}
.link-plan{fill:var(--accent-soft);stroke:var(--accent);stroke-width:2}
.link-falsifier{fill:var(--surface);stroke:var(--accent);stroke-width:1.25;stroke-dasharray:3 2}
.link-control{fill:var(--surface);stroke:var(--ink-2);stroke-width:1.5}
.link-seq-tone{font-size:10.5px;fill:var(--on-tone);font-weight:650}
.chain-link.wrap{fill:none}
.bracket{fill:none;stroke:var(--axis);stroke-width:1}
.sw-plan{background:var(--accent-soft);border-width:2px}
.sw-dashed{background:transparent;border-style:dashed}
.sw-plain{background:var(--surface);border-color:var(--axis)}
.dumbbell{stroke:var(--tone);stroke-width:2;opacity:.7}
.dumbbell.missed{stroke-dasharray:4 3;opacity:1}
.control-box{fill:var(--surface);stroke:var(--axis);stroke-width:1.25}
.plan-token{fill:var(--accent-soft);stroke:var(--accent);stroke-width:1.5}
.track{fill:var(--surface-2);stroke:var(--axis);stroke-width:1}
.track.undefined{fill:none;stroke-dasharray:4 3}
.tick{stroke:var(--surface);stroke-width:1;opacity:.85}
.fan{fill:var(--accent);opacity:.1}
.sv-on{font-size:11px;font-weight:650;fill:var(--on-tone)}
.table-note{margin-top:8px}
.control-table td:first-child{min-width:150px}
.control-table td:nth-child(2){min-width:220px}
.control-table td:nth-child(5){min-width:200px}
.control-table td .pill{white-space:nowrap}
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
    # One redaction scope per render reads the secret-named environment once for the whole page, instead of
    # once per string; a fresh scope on every call still sees a secret set since the last render.
    token = _CLEANED.set({})
    try:
        with redaction_scope():
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
    ledger = _ledger_view(doc)
    sections = [
        ("hologram", "Evidence boundary", _hologram_section(doc, integrity, performance)),
        ("accounting", "Input accounting", _accounting_section(doc)),
        ("lattice", "Check lattice", _lattice_section(doc, lattice)),
        ("controls", "Checker controls", _controls_section(doc, invariants, ledger)),
    ]
    if _discriminations(doc):
        sections.append(("discrimination", "Discrimination", _discrimination_section(doc)))
    if _claim_join_results(doc) or _controls(doc).get("claim_join") is not None:
        sections.append(("claims", "Claim join", _claims_section(doc)))
    sections += [
        ("plan", "Plan closure", _plan_section(doc, invariants)),
        ("invariants", "Invariant ring", _invariant_section(invariants)),
        ("ledger", "Ledger chain", _ledger_section(doc, ledger)),
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
