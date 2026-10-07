"""Named invariants over the ledger, the results and the accounting (section 4),
and the numeric comparison rules (section 7).

Every invariant is a pure function of an :class:`InvariantContext` and returns
an :class:`~science_gate.models.InvariantResult`. The functions judge; they do
not decide. The verifier combines their results with the check verdicts, and
:data:`VIOLATION_OUTCOMES` records what a violation of each invariant implies,
so that the verifier, the reports and the mutation harness all agree.

Applicability is honest. An invariant with nothing to judge reports
``applicable=False, holds=None``. It never reports a vacuous ``holds=True``.
The ``pass_requires_*`` invariants apply only when something claims PASS:
either a check result has verdict PASS, or the caller states the run-level
status it intends to report (``claimed_status``). A verifier therefore
evaluates the invariants with its tentative status, and downgrades the status
if any applicable invariant is violated.

Numbers are compared only through :func:`parse_decimal` and
:func:`compare_decimal`, which use ``decimal.Decimal`` and never floats.

Section 17 adds six invariants that judge the checker rather than the data:
the run's pre-committed PLAN was executed in full and matches what the
manifest declares (``plan_closure``, ``plan_matches_manifest``), no pinned
file was written during the run (``harness_pins_intact``), the comparator and
the must-fail canary still reject what they must (``comparator_self_test``,
``canary_controls_hold``), and every PASS carries a recorded negative control
that its checker rejected (``pass_requires_falsifier_witness``). Every
control is judged from the sealed ledger, so a control narrated in a summary
but absent from the chain does not count.

Callers of the comparator look it up as the module attribute
``invariants.compare_decimal`` at call time, never through a bound import,
so a patched comparator is the one every caller and the self-test exercise.
"""

from __future__ import annotations

import re
from collections.abc import Sized
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Context, Decimal
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from ._canonical import CanonicalizationError, sha256_canonical
from .ledger import InvocationTrace, index_invocations, is_plan_entry, plan_of, verify_chain
from .models import (
    CheckResult,
    DenominatorSource,
    ExecutionState,
    FailureMode,
    FalsifierOutcome,
    InputAccounting,
    InvariantResult,
    Ratio,
    Reason,
    Status,
    WitnessState,
)

__all__ = [
    "INVARIANT_NAMES",
    "ViolationOutcome",
    "VIOLATION_OUTCOMES",
    "ClaimTally",
    "InvariantContext",
    "checked_claims_le_invocations",
    "every_verdict_has_invocation",
    "every_invocation_has_terminal_result",
    "every_required_check_has_terminal_state",
    "pass_requires_nonempty_evidence",
    "pass_requires_complete_required_inputs",
    "pass_requires_complete_required_checks",
    "pass_requires_examined_rows",
    "input_accounting_closure",
    "ledger_chain_intact",
    "plan_closure",
    "plan_matches_manifest",
    "harness_pins_intact",
    "comparator_self_test",
    "canary_controls_hold",
    "pass_requires_falsifier_witness",
    "INVARIANTS",
    "evaluate_invariants",
    "CONTROL_PREFIX",
    "FALSIFIER_PREFIX",
    "COMPARATOR_CONTROL",
    "CANARY_MUST_FAIL",
    "CANARY_MUST_PASS",
    "PLANNED_CONTROLS",
    "COMPARATOR_PAIRS",
    "DISCRIMINATION_STEPS",
    "falsifier_check_id",
    "is_control",
    "run_comparator_self_test",
    "comparison_discrimination",
    "NUMBER_PARSED",
    "AMBIGUOUS_SEPARATOR",
    "NOT_A_NUMBER",
    "EXACT",
    "AGREES_AT_STATED_PRECISION",
    "DISAGREES",
    "REQUIRES_HUMAN_REVIEW",
    "MAX_NUMBER_LENGTH",
    "ParsedDecimal",
    "NumericComparison",
    "parse_decimal",
    "compare_decimal",
]

INVARIANT_NAMES = (
    "checked_claims_le_invocations",
    "every_verdict_has_invocation",
    "every_invocation_has_terminal_result",
    "every_required_check_has_terminal_state",
    "pass_requires_nonempty_evidence",
    "pass_requires_complete_required_inputs",
    "pass_requires_complete_required_checks",
    "pass_requires_examined_rows",
    "input_accounting_closure",
    "ledger_chain_intact",
    "plan_closure",
    "plan_matches_manifest",
    "harness_pins_intact",
    "comparator_self_test",
    "canary_controls_hold",
    "pass_requires_falsifier_witness",
)

#: Every control invocation's ``check_id`` starts with this, so no declared
#: check can be mistaken for a control (manifest ids never contain ``:``).
CONTROL_PREFIX = "control:"
FALSIFIER_PREFIX = "control:falsifier:"
COMPARATOR_CONTROL = "control:comparator"
CANARY_MUST_FAIL = "control:canary:must_fail"
CANARY_MUST_PASS = "control:canary:must_pass"
#: The controls every PLAN commits to, sorted. Falsifiers are not planned:
#: which cases exist depends on what each check examined.
PLANNED_CONTROLS = (CANARY_MUST_FAIL, CANARY_MUST_PASS, COMPARATOR_CONTROL)


def falsifier_check_id(check_id: str, case_id: str) -> str:
    """The ledger ``check_id`` of one falsifier run: ``control:falsifier:<check_id>:<case_id>``."""
    return f"{FALSIFIER_PREFIX}{check_id}:{case_id}"


def is_control(check_id: object) -> bool:
    """True for a control invocation's check id (falsifier, canary or comparator)."""
    return isinstance(check_id, str) and check_id.startswith(CONTROL_PREFIX)


@dataclass(frozen=True)
class ViolationOutcome:
    """The status, reason and failure mode a violated invariant implies."""

    status: Status
    reason: Reason
    failure_mode: FailureMode


#: What each violation means for the run (section 6). Missing or unproven
#: evidence abstains; a definite contradiction of recorded facts fails.
#: A narrated verification abstains as UNVERIFIED (section 9), because the
#: claim may be true: it simply has not been shown.
VIOLATION_OUTCOMES: Mapping[str, ViolationOutcome] = MappingProxyType(
    {
        "checked_claims_le_invocations": ViolationOutcome(
            Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION
        ),
        "every_verdict_has_invocation": ViolationOutcome(
            Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION
        ),
        "every_invocation_has_terminal_result": ViolationOutcome(
            Status.ABSTAIN, Reason.PARTIAL_EXECUTION, FailureMode.PARTIAL_EXECUTION
        ),
        "every_required_check_has_terminal_state": ViolationOutcome(
            Status.ABSTAIN, Reason.PARTIAL_EXECUTION, FailureMode.PARTIAL_EXECUTION
        ),
        "pass_requires_nonempty_evidence": ViolationOutcome(
            Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, FailureMode.VACUOUS_PASS
        ),
        "pass_requires_complete_required_inputs": ViolationOutcome(
            Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, FailureMode.OMITTED_POPULATION
        ),
        "pass_requires_complete_required_checks": ViolationOutcome(
            Status.ABSTAIN, Reason.PARTIAL_EXECUTION, FailureMode.PARTIAL_EXECUTION
        ),
        "pass_requires_examined_rows": ViolationOutcome(
            Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, FailureMode.VACUOUS_PASS
        ),
        "input_accounting_closure": ViolationOutcome(
            Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH
        ),
        "ledger_chain_intact": ViolationOutcome(
            Status.FAIL, Reason.PROTOCOL_BROKEN, FailureMode.DEFECTIVE_VERIFICATION
        ),
        # An unexecuted planned item is a failure (D1), as a missing test is in TAP.
        "plan_closure": ViolationOutcome(Status.FAIL, Reason.PARTIAL_EXECUTION, FailureMode.PARTIAL_EXECUTION),
        "plan_matches_manifest": ViolationOutcome(Status.FAIL, Reason.PROTOCOL_DRIFT, FailureMode.PROTOCOL_DRIFT),
        "harness_pins_intact": ViolationOutcome(Status.FAIL, Reason.PROTOCOL_DRIFT, FailureMode.PROTOCOL_DRIFT),
        # A control that accepted what it must reject is a proven miss (D2).
        "comparator_self_test": ViolationOutcome(
            Status.FAIL, Reason.BLIND_SPOT, FailureMode.DEFECTIVE_VERIFICATION
        ),
        "canary_controls_hold": ViolationOutcome(
            Status.FAIL, Reason.BLIND_SPOT, FailureMode.DEFECTIVE_VERIFICATION
        ),
        # A PASS without a ledger-backed witness has unknown coverage, not a proven miss (D2).
        "pass_requires_falsifier_witness": ViolationOutcome(
            Status.ABSTAIN, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS
        ),
    }
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _optional_count(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name}: expected a non-negative int or None, got {value!r}")
    return value


@dataclass(frozen=True)
class ClaimTally:
    """A count of claimed verifications set against the invocations that back them.

    ``invocations=None`` means no invocation record exists at all, which for
    a positive claim is exactly a narrated verification.
    """

    subject: str
    claimed: int | None
    invocations: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject:
            raise ValueError("subject must be a non-empty string")
        _optional_count(self.claimed, "claimed")
        _optional_count(self.invocations, "invocations")


@dataclass(frozen=True)
class InvariantContext:
    """Everything the invariants may look at. All fields are optional facts.

    * ``entries``: ledger entries, as recorded or as read back from JSONL.
    * ``checks``: the check results to judge.
    * ``accounting``: input accounting from discovery (None if unavailable).
    * ``declared_checks``: ``{check_id: required}`` from the manifest; the
      source of truth for which checks were expected.
    * ``claimed_status``: the run-level status the caller intends to report.
    * ``evidence_manifest``: evidence-manifest entries, each a mapping with a
      ``sha256``; None when none was built.
    * ``ledger_head_sha256`` / ``ledger_length``: the seal to verify against;
      ``ledger_length=None`` means the ledger was never sealed.
    * ``run_id``: when given, invocation ids must derive from it.
    * ``claim_tallies``: further claimed-versus-invoked counts, for example a
      citation log's ``claimed_verified`` against its invocation records.
    * ``expected_plan``: the PLAN body the manifest implies; when set, the
      recorded PLAN must equal it.
    * ``pins``: ``{"pinned": [{role, path, sha256, sha256_after}], "writes":
      [{path, action, event}], "hook_errors": n}``; None when no pin was
      re-hashed after the checks.
    * ``controls``: the run's recorded controls summary
      (``RunResult.controls``). A control it names must also be in the ledger.
    * ``rows_examined``: the run's distinct admitted data rows of declared
      inputs that an executed check consumed (G1).
    """

    entries: tuple[Mapping[str, Any], ...] = ()
    checks: tuple[CheckResult, ...] = ()
    accounting: InputAccounting | None = None
    declared_checks: Mapping[str, bool] = field(default_factory=dict)
    claimed_status: Status | None = None
    evidence_manifest: Sequence[Mapping[str, Any]] | None = None
    ledger_head_sha256: str | None = None
    ledger_length: int | None = None
    run_id: str | None = None
    claim_tallies: tuple[ClaimTally, ...] = ()
    expected_plan: Mapping[str, Any] | None = None
    pins: Mapping[str, Any] | None = None
    controls: Mapping[str, Any] | None = None
    rows_examined: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))
        object.__setattr__(self, "rows_examined", _optional_count(self.rows_examined, "rows_examined"))
        object.__setattr__(self, "checks", tuple(sorted(self.checks, key=lambda check: check.check_id)))
        object.__setattr__(self, "declared_checks", MappingProxyType(dict(self.declared_checks)))
        object.__setattr__(self, "claim_tallies", tuple(self.claim_tallies))
        if self.claimed_status is not None:
            object.__setattr__(self, "claimed_status", Status(self.claimed_status))

    @property
    def run_claims_pass(self) -> bool:
        return self.claimed_status is Status.PASS

    @property
    def passing_checks(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if check.verdict is Status.PASS)

    def traces(self) -> dict[str, InvocationTrace]:
        return index_invocations(self.entries)

    def required_check_ids(self) -> tuple[str, ...]:
        """Checks the manifest requires, plus any result that calls itself required."""
        declared = {check_id for check_id, required in self.declared_checks.items() if required}
        return tuple(sorted(declared | {check.check_id for check in self.checks if check.required}))


def _not_applicable(name: str, detail: str) -> InvariantResult:
    return InvariantResult(name, False, None, detail)


def _judged(name: str, problems: Sequence[str], passed_detail: str) -> InvariantResult:
    """An applicable result: holds exactly when there are no problems."""
    if problems:
        return InvariantResult(name, True, False, "; ".join(problems))
    return InvariantResult(name, True, True, passed_detail)


def _nothing_claims_pass(name: str) -> InvariantResult:
    return _not_applicable(name, "no check result and no run-level status claims PASS")


def checked_claims_le_invocations(ctx: InvariantContext) -> InvariantResult:
    """Nothing may be claimed as checked more often than it was invoked.

    The run-level tally sets check results marked CHECKED against invocations
    with a terminal ledger result. Extra tallies (``claim_tallies``) apply the
    same rule to other claimed verifications.
    """
    name = "checked_claims_le_invocations"
    terminal = sum(1 for trace in ctx.traces().values() if trace.terminal)
    checked = sum(1 for check in ctx.checks if check.execution_state is ExecutionState.CHECKED)
    tallies = (ClaimTally("check results marked CHECKED", checked, terminal), *ctx.claim_tallies)
    judged: list[str] = []
    problems: list[str] = []
    for tally in tallies:
        if not tally.claimed:
            continue
        if tally.invocations is None:
            problems.append(f"{tally.subject}: {tally.claimed} claimed with no invocation record")
        elif tally.claimed > tally.invocations:
            problems.append(f"{tally.subject}: {tally.claimed} claimed but only {tally.invocations} invoked")
        judged.append(f"{tally.subject}: {tally.claimed} claimed <= {tally.invocations} invoked")
    if not judged:
        return _not_applicable(name, "nothing was claimed as checked or verified")
    return _judged(name, problems, "; ".join(judged))


def every_verdict_has_invocation(ctx: InvariantContext) -> InvariantResult:
    """Every check verdict must point to its own terminal ledger invocation.

    The invocation must belong to the same check and record the same verdict:
    a result that names someone else's invocation, or reports a verdict the
    ledger never recorded, is narrated rather than executed.
    """
    name = "every_verdict_has_invocation"
    if not ctx.checks:
        return _not_applicable(name, "there are no check results to trace")
    traces = ctx.traces()
    owners: dict[str, str] = {}
    problems: list[str] = []
    for check in ctx.checks:
        label = f"check {check.check_id!r} ({check.verdict.value})"
        invocation_id = check.invocation_id
        if invocation_id is None:
            problems.append(f"{label} has no invocation_id")
            continue
        if invocation_id in owners:
            problems.append(f"{label} shares invocation {invocation_id} with check {owners[invocation_id]!r}")
            continue
        owners[invocation_id] = check.check_id
        trace = traces.get(invocation_id)
        if trace is None:
            problems.append(f"{label} points to invocation {invocation_id}, which is not in the ledger")
        elif not trace.terminal:
            problems.append(f"{label} points to invocation {invocation_id}, which has no valid terminal result")
        elif trace.check_id != check.check_id:
            problems.append(f"{label} points to invocation {invocation_id} of check {trace.check_id!r}")
        elif trace.verdict is not check.verdict:
            problems.append(f"{label} disagrees with its ledger verdict {trace.verdict.value}")
    return _judged(name, problems, f"{len(ctx.checks)} verdict(s) each trace to a terminal invocation")


def every_invocation_has_terminal_result(ctx: InvariantContext) -> InvariantResult:
    """Every started invocation must be closed exactly once, consistently."""
    name = "every_invocation_has_terminal_result"
    traces = ctx.traces()
    if not traces:
        return _not_applicable(name, "the ledger records no invocations")
    problems: list[str] = []
    for trace in traces.values():
        problems.extend(trace.problems)
        if trace.terminal_seq is None:
            problems.append(f"{trace.invocation_id}: started but never reached a terminal result")
    return _judged(name, problems, f"{len(traces)} invocation(s) each reached exactly one terminal result")


def every_required_check_has_terminal_state(ctx: InvariantContext) -> InvariantResult:
    """Every required check must have a result backed by a terminal invocation.

    Unlike ``every_verdict_has_invocation``, which starts from the results,
    this starts from what was *expected*, so a required check that produced
    no result at all is caught here. A result that calls itself optional while
    the manifest requires it is also a violation: that is how a required check
    would be quietly demoted.
    """
    name = "every_required_check_has_terminal_state"
    required = ctx.required_check_ids()
    if not required:
        return _not_applicable(name, "no check is required")
    traces = ctx.traces()
    results = {check.check_id: check for check in ctx.checks}
    problems: list[str] = []
    for check_id in required:
        result = results.get(check_id)
        if result is None:
            problems.append(f"required check {check_id!r} has no result")
            continue
        if ctx.declared_checks.get(check_id) is True and not result.required:
            problems.append(f"check {check_id!r} is required by the manifest but its result says optional")
        trace = traces.get(result.invocation_id) if result.invocation_id is not None else None
        if trace is None or not trace.terminal:
            problems.append(f"required check {check_id!r} has no terminal invocation")
    return _judged(name, problems, f"{len(required)} required check(s) each reached a terminal state")


def pass_requires_nonempty_evidence(ctx: InvariantContext) -> InvariantResult:
    """A PASS must carry evidence: per check, and as a non-empty evidence manifest for the run."""
    name = "pass_requires_nonempty_evidence"
    passing = ctx.passing_checks
    if not passing and not ctx.run_claims_pass:
        return _nothing_claims_pass(name)
    problems = [f"check {check.check_id!r} passed with empty evidence" for check in passing if not check.evidence]
    if ctx.run_claims_pass:
        manifest = ctx.evidence_manifest
        if manifest is None:
            problems.append("the run claims PASS but no evidence manifest exists")
        elif not isinstance(manifest, Sized) or len(manifest) == 0:
            problems.append("the run claims PASS but its evidence manifest is empty")
        else:
            for index, entry in enumerate(manifest):
                digest = entry.get("sha256") if isinstance(entry, Mapping) else None
                if not (isinstance(digest, str) and _SHA256_HEX.fullmatch(digest)):
                    problems.append(f"evidence manifest entry {index} has no sha256")
    return _judged(name, problems, "every PASS carries non-empty, hashed evidence")


def pass_requires_complete_required_inputs(ctx: InvariantContext) -> InvariantResult:
    """A PASS may rest only on inputs that were found, opened, parsed and matched.

    Per check: every input a passing check used must be complete. For the
    run: every required input must be complete, and at least one input must
    have been declared and opened, so that a PASS is never about nothing.
    """
    name = "pass_requires_complete_required_inputs"
    passing = ctx.passing_checks
    if not passing and not ctx.run_claims_pass:
        return _nothing_claims_pass(name)
    accounting = ctx.accounting
    needs_accounting = ctx.run_claims_pass or any(check.inputs for check in passing)
    if accounting is None:
        if needs_accounting:
            return _judged(name, ["a PASS is claimed but there is no input accounting"], "")
        return _judged(name, [], "the passing checks consumed no declared inputs")
    records = {record.input_id: record for record in accounting.records}
    problems: list[str] = []
    for check in passing:
        for input_id in check.inputs:
            record = records.get(input_id)
            if record is None:
                problems.append(f"check {check.check_id!r} passed on undeclared input {input_id!r}")
            elif not record.complete:
                problems.append(f"check {check.check_id!r} passed on input {input_id!r} in state {record.state.value}")
    if ctx.run_claims_pass:
        if not accounting.value("expected"):
            problems.append("no input was declared")
        if not accounting.value("opened"):
            problems.append("no input was opened")
        for record in accounting.records:
            if record.required and not record.complete:
                problems.append(f"required input {record.input_id!r} is {record.state.value}")
    return _judged(name, problems, "every input behind a PASS is complete")


def pass_requires_complete_required_checks(ctx: InvariantContext) -> InvariantResult:
    """A run-level PASS needs every required check executed, terminal and passing.

    This is the ``checks_executed == checks_expected`` rule. A run with no
    required check at all cannot PASS: nothing was obliged to be able to fail.
    """
    name = "pass_requires_complete_required_checks"
    if not ctx.run_claims_pass:
        return _not_applicable(name, "the run does not claim PASS")
    required = ctx.required_check_ids()
    if not required:
        return _judged(name, ["no required check was declared, so a PASS would be vacuous"], "")
    traces = ctx.traces()
    results = {check.check_id: check for check in ctx.checks}
    problems: list[str] = []
    executed = 0
    for check_id in required:
        result = results.get(check_id)
        if result is None:
            problems.append(f"required check {check_id!r} did not run")
            continue
        if result.execution_state is not ExecutionState.CHECKED:
            problems.append(f"required check {check_id!r} was not executed: {result.execution_state.value}")
            continue
        trace = traces.get(result.invocation_id) if result.invocation_id is not None else None
        if trace is None or not trace.terminal:
            problems.append(f"required check {check_id!r} has no terminal invocation")
            continue
        executed += 1
        if result.verdict is not Status.PASS:
            problems.append(f"required check {check_id!r} ended {result.verdict.value}")
    counts = f"checks_expected={len(required)}, checks_executed={executed}"
    return _judged(name, [*problems, counts] if problems else [], counts)


def pass_requires_examined_rows(ctx: InvariantContext) -> InvariantResult:
    """A PASS needs examined rows: never None, never zero.

    Each passing check must report a positive count of its own subject
    records. The run is judged against ``ctx.rows_examined``: the distinct
    admitted data rows of declared inputs that an executed check consumed
    (G1). Comparisons, pins, verdicts and events are never rows, so a
    header-only input cannot be rescued by a check that compared a digest.
    """
    name = "pass_requires_examined_rows"
    passing = ctx.passing_checks
    if not passing and not ctx.run_claims_pass:
        return _nothing_claims_pass(name)
    problems: list[str] = []
    for check in passing:
        if check.rows_examined is None:
            problems.append(f"check {check.check_id!r} passed without reporting rows examined")
        elif check.rows_examined == 0:
            problems.append(f"check {check.check_id!r} passed after examining 0 rows")
    if ctx.run_claims_pass:
        if ctx.rows_examined is None:
            problems.append("the run claims PASS but its rows_examined is unknown")
        elif ctx.rows_examined < 1:
            problems.append("the run claims PASS but examined no rows")
    detail = f"rows_examined={ctx.rows_examined} (distinct data rows of declared inputs)"
    return _judged(name, [*problems, detail] if problems else [], detail)


def input_accounting_closure(ctx: InvariantContext) -> InvariantResult:
    """Every INDEPENDENT expectation must be exactly accounted for.

    Closures without an INDEPENDENT source are never judged, and neither are
    INDEPENDENT closures whose counts are unknown (for example an input that
    failed to parse). Those are listed in the detail so the gap stays visible;
    other invariants keep such a run from passing.
    """
    name = "input_accounting_closure"
    accounting = ctx.accounting
    if accounting is None:
        return _not_applicable(name, "there is no input accounting")
    closures = [("inputs", accounting.closure)]
    closures += [(f"rows of input {record.input_id!r}", record.closure) for record in accounting.records]
    judged = [(label, closure) for label, closure in closures if closure.holds is not None]
    unjudged = [
        label
        for label, closure in closures
        if closure.holds is None and closure.source is DenominatorSource.INDEPENDENT
    ]
    note = f"; not evaluable (counts unknown): {', '.join(unjudged)}" if unjudged else ""
    if not judged:
        return _not_applicable(name, "no closure has an INDEPENDENT expectation with known counts" + note)
    problems = [
        f"{label}: expected {closure.expected}, accounted {closure.accounted}"
        for label, closure in judged
        if closure.holds is False
    ]
    if problems:
        return InvariantResult(name, True, False, "; ".join(problems) + note)
    return InvariantResult(name, True, True, f"{len(judged)} INDEPENDENT closure(s) hold{note}")


def ledger_chain_intact(ctx: InvariantContext) -> InvariantResult:
    """The ledger must be exactly the sealed hash chain (see :func:`~science_gate.ledger.verify_chain`)."""
    name = "ledger_chain_intact"
    if not ctx.entries and not ctx.ledger_length and ctx.ledger_head_sha256 is None:
        return _not_applicable(name, "there is no ledger and no seal")
    verification = verify_chain(ctx.entries, ctx.ledger_head_sha256, ctx.ledger_length, run_id=ctx.run_id)
    return _judged(
        name,
        verification.problems,
        f"{verification.observed_length} entries chain to head {verification.observed_head}",
    )


def _traces_by_check(ctx: InvariantContext) -> dict[str, list[InvocationTrace]]:
    """Ledger invocations grouped by ``check_id``, in invocation-id order."""
    grouped: dict[str, list[InvocationTrace]] = {}
    for trace in ctx.traces().values():
        if trace.check_id is not None:
            grouped.setdefault(trace.check_id, []).append(trace)
    return grouped


def _terminal_evidence(ctx: InvariantContext) -> dict[str, Mapping[str, Any]]:
    """The evidence of each invocation's terminal ledger entry, keyed by invocation id."""
    found: dict[str, Mapping[str, Any]] = {}
    for entry in ctx.entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("invocation_id"), str):
            continue
        if entry.get("completed_at") is not None and isinstance(entry.get("evidence"), Mapping):
            found[entry["invocation_id"]] = entry["evidence"]
    return found


def _single_terminal(ctx: InvariantContext, check_id: str) -> InvocationTrace | None:
    """The invocation of ``check_id`` when there is exactly one and it is terminal, else None."""
    traces = _traces_by_check(ctx).get(check_id, [])
    return traces[0] if len(traces) == 1 and traces[0].terminal else None


def _planned_ids(body: Mapping[str, Any], problems: list[str]) -> list[str]:
    """Every check id and control id a PLAN body commits to."""
    checks, controls = body.get("checks"), body.get("controls")
    if not isinstance(checks, list) or not isinstance(controls, list):
        problems.append("the PLAN body has no list of checks and controls")
        return []
    planned = [item.get("check_id") if isinstance(item, Mapping) else None for item in checks] + list(controls)
    usable = [item for item in planned if isinstance(item, str) and item]
    if len(usable) != len(planned) or len(set(usable)) != len(usable):
        problems.append("the PLAN names a check or control that is not a unique non-empty id")
    return sorted(set(usable))


def plan_closure(ctx: InvariantContext) -> InvariantResult:
    """The ledger opens with the run's PLAN, and everything planned ran exactly once.

    Entry 1 must be the only PLAN entry. Every planned check and planned
    control must have exactly one invocation, and it must be terminal.
    Invocations nobody planned (other than falsifier controls, which no plan
    can list in advance) are listed in the detail, not judged: the plan binds
    what must run, and extra work cannot make up for a shortfall.
    """
    name = "plan_closure"
    if not ctx.entries:
        return _not_applicable(name, "the ledger has no entries")
    problems: list[str] = []
    if not is_plan_entry(ctx.entries[0]):
        problems.append("entry 1 is not a PLAN: the run committed to no plan before executing")
    later = [position for position, entry in enumerate(ctx.entries[1:], start=2) if is_plan_entry(entry)]
    if later:
        problems.append(f"PLAN entries also at position(s) {later}: exactly one PLAN may open the ledger")
    body = plan_of(ctx.entries)
    planned = _planned_ids(body, problems) if body is not None else []
    grouped = _traces_by_check(ctx)
    for check_id in planned:
        traces = grouped.get(check_id, [])
        terminal = sum(1 for trace in traces if trace.terminal)
        if len(traces) != 1 or terminal != 1:
            problems.append(
                f"planned {check_id!r} has {len(traces)} invocation(s) and {terminal} terminal result(s); "
                "exactly one of each is required"
            )
    unplanned = sorted(
        check_id for check_id in grouped if check_id not in planned and not check_id.startswith(FALSIFIER_PREFIX)
    )
    note = f"; unplanned invocation(s), listed not judged: {unplanned}" if unplanned else ""
    if problems:
        return InvariantResult(name, True, False, "; ".join(problems) + note)
    return InvariantResult(name, True, True, f"{len(planned)} planned item(s) each ran exactly once{note}")


def _plan_differences(recorded: Any, expected: Any, where: str = "plan") -> list[str]:
    """Where two plan bodies differ, named down to the first differing field."""
    if isinstance(recorded, Mapping) and isinstance(expected, Mapping):
        found: list[str] = []
        for key in sorted(set(recorded) | set(expected)):
            if key not in recorded or key not in expected:
                found.append(f"{where}.{key} is {'missing' if key not in recorded else 'not in the expected plan'}")
            else:
                found.extend(_plan_differences(recorded[key], expected[key], f"{where}.{key}"))
        return found
    if isinstance(recorded, list) and isinstance(expected, list) and len(recorded) == len(expected):
        found = []
        for index, (left, right) in enumerate(zip(recorded, expected)):
            label = (left.get("check_id") or left.get("input_id") or left.get("path")) if isinstance(left, Mapping) else None
            found.extend(_plan_differences(left, right, f"{where}[{label or index}]"))
        return found
    try:
        same = sha256_canonical(recorded) == sha256_canonical(expected)
    except CanonicalizationError:
        same = False
    return [] if same else [f"{where} differs"]


def plan_matches_manifest(ctx: InvariantContext) -> InvariantResult:
    """The recorded PLAN equals the plan the manifest implies, field for field.

    A re-sealed ledger whose PLAN was edited (a lowered ``expected_rows``,
    say) verifies as a chain. Only comparison with a plan rebuilt from the
    manifest exposes the edit, and that is a change of protocol after the
    fact: PROTOCOL_DRIFT.
    """
    name = "plan_matches_manifest"
    body = plan_of(ctx.entries)
    if body is None or ctx.expected_plan is None:
        return _not_applicable(name, "there is no recorded PLAN or no expected plan to compare it with")
    problems = _plan_differences(body, ctx.expected_plan)
    if not problems:
        return InvariantResult(name, True, True, "the recorded PLAN equals the plan the manifest implies")
    shown = problems[:MAX_LISTED_DIFFERENCES]
    more = f"; and {len(problems) - len(shown)} more" if len(problems) > len(shown) else ""
    return InvariantResult(name, True, False, "the recorded PLAN differs from the manifest: " + "; ".join(shown) + more)


#: How many PLAN differences a detail names before summarizing the rest.
MAX_LISTED_DIFFERENCES = 20


def harness_pins_intact(ctx: InvariantContext) -> InvariantResult:
    """No pinned file changed during the run, and nothing even wrote to one.

    A write that restored identical bytes leaves every digest equal, so the
    audited write itself is the violation. The re-hashed pins must also be
    the pins the PLAN committed to. Each offending path is named.
    """
    name = "harness_pins_intact"
    pins = ctx.pins
    if not isinstance(pins, Mapping) or not isinstance(pins.get("pinned"), list):
        return _not_applicable(name, "no pinned file was re-hashed after the checks")
    pinned = [item for item in pins["pinned"] if isinstance(item, Mapping)]
    problems: list[str] = []
    for item in pinned:
        if item.get("sha256") != item.get("sha256_after"):
            problems.append(f"{item.get('role')} {item.get('path')} changed during the run")
    for write in pins.get("writes") or ():
        if isinstance(write, Mapping):
            problems.append(
                f"{write.get('path')} was touched during the run ({write.get('action')} via {write.get('event')})"
            )
    errors = pins.get("hook_errors") or 0
    if errors:
        problems.append(f"the write-detection hook could not interpret {errors} event(s)")
    body = plan_of(ctx.entries)
    if body is not None:

        def triple(item: Mapping[str, Any]) -> tuple[str, str, str]:
            return (str(item.get("role")), str(item.get("path")), str(item.get("sha256")))

        committed = sorted(triple(item) for item in body.get("pins") or () if isinstance(item, Mapping))
        if committed != sorted(triple(item) for item in pinned):
            problems.append("the re-hashed pins are not the pins the PLAN committed to")
    return _judged(name, problems, f"{len(pinned)} pinned file(s) unchanged and never written during the run")


def comparator_self_test(ctx: InvariantContext) -> InvariantResult:
    """The comparator told the known pairs apart when this run used it.

    Judged from the sealed ledger: the control's single terminal invocation
    must be PASS, and every recorded pair must show its expected outcome.
    """
    name = "comparator_self_test"
    recorded = isinstance(ctx.controls, Mapping) and ctx.controls.get("comparator_self_test") is not None
    if COMPARATOR_CONTROL not in _traces_by_check(ctx) and not recorded:
        return _not_applicable(name, "the ledger records no comparator self-test")
    trace = _single_terminal(ctx, COMPARATOR_CONTROL)
    if trace is None:
        return _judged(name, [f"{COMPARATOR_CONTROL} has no single terminal invocation in the ledger"], "")
    problems: list[str] = []
    if trace.verdict is not Status.PASS:
        problems.append(f"{COMPARATOR_CONTROL} ended {trace.verdict.value if trace.verdict else None}")
    pairs = _terminal_evidence(ctx).get(trace.invocation_id, {}).get("pairs")
    if not isinstance(pairs, list) or len(pairs) != len(COMPARATOR_PAIRS):
        problems.append("the comparator self-test did not record its pairs")
    else:
        for pair in pairs:
            if not isinstance(pair, Mapping) or pair.get("actual") != pair.get("expected"):
                shown = dict(pair) if isinstance(pair, Mapping) else pair
                problems.append(f"comparator pair {shown} did not give its expected outcome")
    return _judged(name, problems, f"{len(COMPARATOR_PAIRS)} known pairs compared as expected")


def canary_controls_hold(ctx: InvariantContext) -> InvariantResult:
    """The must-fail canary FAILed and its known-good twin PASSed, through the same path as every check."""
    name = "canary_controls_hold"
    grouped = _traces_by_check(ctx)
    recorded = isinstance(ctx.controls, Mapping) and ctx.controls.get("canary") is not None
    if CANARY_MUST_FAIL not in grouped and CANARY_MUST_PASS not in grouped and not recorded:
        return _not_applicable(name, "the ledger records no canary controls")
    problems: list[str] = []
    for check_id, expected in ((CANARY_MUST_FAIL, Status.FAIL), (CANARY_MUST_PASS, Status.PASS)):
        trace = _single_terminal(ctx, check_id)
        if trace is None:
            problems.append(f"{check_id} has no single terminal invocation in the ledger")
        elif trace.verdict is not expected:
            actual = trace.verdict.value if trace.verdict else None
            problems.append(f"{check_id} ended {actual}, not {expected.value}")
    return _judged(name, problems, "the must-fail canary failed and its known-good twin passed")


def _stands(
    record: Any,
    check: CheckResult,
    grouped: Mapping[str, Sequence[InvocationTrace]],
    terminals: Mapping[str, Mapping[str, Any]],
) -> bool:
    """True when one recorded falsifier is a ledger-backed rejection by the same checker and params.

    The record names its control by ledger check id; the ledger binds that
    control to this subject, because the falsifier's terminal entry names
    the subject's own invocation. Exactly one such invocation must exist.
    """
    if not isinstance(record, Mapping) or record.get("outcome") != FalsifierOutcome.REJECTED.value:
        return False
    control_id = falsifier_check_id(check.check_id, str(record.get("case_id")))
    if record.get("control_id") != control_id or check.invocation_id is None:
        return False
    bound = [
        trace
        for trace in grouped.get(control_id, ())
        if terminals.get(trace.invocation_id, {}).get("subject_invocation_id") == check.invocation_id
    ]
    if len(bound) != 1:
        return False
    trace = bound[0]
    if not trace.terminal or trace.verdict is None or trace.reason is None:
        return False
    invocation_id = trace.invocation_id
    recorded = (trace.verdict.value, trace.reason.value)
    expected, actual = record.get("expected"), record.get("actual")
    if not isinstance(expected, Mapping) or not isinstance(actual, Mapping):
        return False
    if recorded != (expected.get("verdict"), expected.get("reason")) or recorded != (
        actual.get("verdict"),
        actual.get("reason"),
    ):
        return False
    digests = (check.evidence.get("checker_sha256"), check.evidence.get("params_sha256"))
    terminal = terminals.get(invocation_id, {})
    return (
        None not in digests
        and digests == (record.get("checker_sha256"), record.get("params_sha256"))
        and digests == (terminal.get("checker_sha256"), terminal.get("params_sha256"))
        and terminal.get("subject_check_id") == check.check_id
        and terminal.get("outcome") == FalsifierOutcome.REJECTED.value
    )


def pass_requires_falsifier_witness(ctx: InvariantContext) -> InvariantResult:
    """Every PASS carries proof, in the sealed ledger, that its checker rejected a known-bad case.

    The witness must be a falsifier invocation named for this check and
    case, terminal, with the expected rejection recorded, and run with the
    same checker and params digests as the PASS. A witness that exists only
    in a result's evidence is narrated, so the PASS has unknown coverage.
    """
    name = "pass_requires_falsifier_witness"
    passing = ctx.passing_checks
    if not passing:
        return _not_applicable(name, "no check result is PASS")
    grouped, terminals = _traces_by_check(ctx), _terminal_evidence(ctx)
    problems: list[str] = []
    for check in passing:
        state = check.evidence.get("falsification")
        if state != WitnessState.WITNESSED.value:
            problems.append(f"check {check.check_id!r} passed with falsification {state!r}, not WITNESSED")
        elif not any(_stands(record, check, grouped, terminals) for record in check.evidence.get("falsifiers") or ()):
            problems.append(
                f"check {check.check_id!r} passed but no REJECTED falsifier with its checker and params digests "
                "is terminal in the ledger"
            )
    return _judged(name, problems, f"{len(passing)} PASS result(s) each carry a ledger-backed falsifier witness")


#: The invariants in contract order.
INVARIANTS: Mapping[str, Callable[[InvariantContext], InvariantResult]] = MappingProxyType(
    {
        "checked_claims_le_invocations": checked_claims_le_invocations,
        "every_verdict_has_invocation": every_verdict_has_invocation,
        "every_invocation_has_terminal_result": every_invocation_has_terminal_result,
        "every_required_check_has_terminal_state": every_required_check_has_terminal_state,
        "pass_requires_nonempty_evidence": pass_requires_nonempty_evidence,
        "pass_requires_complete_required_inputs": pass_requires_complete_required_inputs,
        "pass_requires_complete_required_checks": pass_requires_complete_required_checks,
        "pass_requires_examined_rows": pass_requires_examined_rows,
        "input_accounting_closure": input_accounting_closure,
        "ledger_chain_intact": ledger_chain_intact,
        "plan_closure": plan_closure,
        "plan_matches_manifest": plan_matches_manifest,
        "harness_pins_intact": harness_pins_intact,
        "comparator_self_test": comparator_self_test,
        "canary_controls_hold": canary_controls_hold,
        "pass_requires_falsifier_witness": pass_requires_falsifier_witness,
    }
)


def evaluate_invariants(ctx: InvariantContext) -> tuple[InvariantResult, ...]:
    """Evaluate every named invariant, in contract order."""
    return tuple(INVARIANTS[name](ctx) for name in INVARIANT_NAMES)


# ---------------------------------------------------------------------------
# Numeric rules (section 7)
# ---------------------------------------------------------------------------

NUMBER_PARSED = "PARSED"
AMBIGUOUS_SEPARATOR = "AMBIGUOUS_SEPARATOR"
NOT_A_NUMBER = "NOT_A_NUMBER"

EXACT = "EXACT"
AGREES_AT_STATED_PRECISION = "AGREES_AT_STATED_PRECISION"
DISAGREES = "DISAGREES"
REQUIRES_HUMAN_REVIEW = Reason.REQUIRES_HUMAN_REVIEW.value

#: Printed numbers longer than this are refused rather than parsed: no
#: reported quantity needs more, and it bounds the cost of exact arithmetic.
MAX_NUMBER_LENGTH = 100

#: Characters that act as a grouping or decimal mark somewhere in the world.
#: One of these, undeclared, makes a string ambiguous rather than invalid:
#: "1,234" is 1234 in one convention and 1.234 in another.
_SEPARATOR_LIKE = frozenset(",. '_\u00a0\u2009\u202f\u2019")
_MINUS_SIGNS = frozenset("-\u2212")
_DIGITS = re.compile(r"[0-9]+")


@dataclass(frozen=True)
class ParsedDecimal:
    """A printed number and what it means, or why it has no single meaning.

    ``decimals`` counts the digits printed after the decimal mark, trailing
    zeros included: "12.40" states more precision than "12.4".
    """

    text: str
    state: str
    value: Decimal | None = None
    decimals: int | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state == NUMBER_PARSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "state": self.state,
            "value": None if self.value is None else format(self.value, "f"),
            "decimals": self.decimals,
            "detail": self.detail,
        }


def _check_marks(thousands: str | None, decimal_point: str) -> None:
    """Refuse separator declarations that could not be applied unambiguously."""
    for label, mark in (("thousands", thousands), ("decimal_point", decimal_point)):
        if mark is None:
            continue
        if not isinstance(mark, str) or len(mark) != 1 or mark.isdigit() or mark in "+-\u2212":
            raise ValueError(f"{label} must be a single non-digit, non-sign character, got {mark!r}")
    if thousands is not None and thousands == decimal_point:
        raise ValueError("thousands and decimal_point must differ")


def _fixed_point_length(value: Decimal) -> int:
    """How many characters ``format(value, "f")`` would produce, computed without producing them.

    A Decimal parsed from JSON such as ``1e999999999`` is tiny in memory but
    expands to a billion digits in fixed point, so the length must be known
    before the text is built.
    """
    sign, digits, raw_exponent = value.as_tuple()
    exponent = int(raw_exponent)  # an int for every finite value, the only kind callers pass
    if exponent >= 0:
        body = len(digits) + exponent
    else:
        body = max(len(digits), -exponent + 1) + 1  # leading "0" and the decimal point
    return body + sign


def _as_text(value: str | int | Decimal) -> str | None:
    """The printed form of ``value``, or None when it would exceed :data:`MAX_NUMBER_LENGTH`."""
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError(f"{type(value).__name__} is not accepted: pass the printed string")
    if isinstance(value, Decimal):
        if not value.is_finite():
            return str(value)
        if _fixed_point_length(value) > MAX_NUMBER_LENGTH:
            return None
        # Fixed-point rendering keeps the printed precision ("1.50" stays
        # "1.50") and never produces exponent notation.
        return format(value, "f")
    if isinstance(value, (str, int)):
        return str(value)
    raise TypeError(f"{type(value).__name__} is not a printed number")


def parse_decimal(
    text: str | int | Decimal,
    *,
    thousands: str | None = None,
    decimal_point: str = ".",
) -> ParsedDecimal:
    """Parse a printed number exactly.

    Grammar: optional sign (``+``, ``-`` or U+2212), ASCII digits, optionally
    a decimal mark followed by at least one digit. A declared ``thousands``
    separator is removed from the integer part, but only in well-formed groups
    of three: "1,234" parses to 1234 with ``thousands=","``, and it is
    AMBIGUOUS_SEPARATOR without the declaration. Exponents, spelled numbers
    and non-ASCII digits are NOT_A_NUMBER. Floats are refused with
    ``TypeError`` because their printed precision is already lost.
    """
    _check_marks(thousands, decimal_point)
    raw = _as_text(text)
    if raw is None:
        # Shown in exponent form, which is short and exact.
        return ParsedDecimal(str(text), NOT_A_NUMBER, detail=f"longer than {MAX_NUMBER_LENGTH} characters")
    stripped = raw.strip()
    if not stripped:
        return ParsedDecimal(raw, NOT_A_NUMBER, detail="empty")
    if len(stripped) > MAX_NUMBER_LENGTH:
        return ParsedDecimal(raw, NOT_A_NUMBER, detail=f"longer than {MAX_NUMBER_LENGTH} characters")
    sign, body = "", stripped
    if body[0] in _MINUS_SIGNS or body[0] == "+":
        sign, body = ("-" if body[0] in _MINUS_SIGNS else ""), body[1:]
    declared = {decimal_point} | ({thousands} if thousands is not None else set())
    for char in body:
        if char.isascii() and char.isdigit() or char in declared:
            continue
        if char in _SEPARATOR_LIKE:
            return ParsedDecimal(raw, AMBIGUOUS_SEPARATOR, detail=f"undeclared separator {char!r}")
        return ParsedDecimal(raw, NOT_A_NUMBER, detail=f"unexpected character {char!r}")
    if body.count(decimal_point) > 1:
        return ParsedDecimal(raw, AMBIGUOUS_SEPARATOR, detail=f"decimal mark {decimal_point!r} appears twice")
    integer, has_point, fraction = body.partition(decimal_point)
    if thousands is not None:
        if thousands in fraction:
            return ParsedDecimal(raw, AMBIGUOUS_SEPARATOR, detail="thousands separator after the decimal mark")
        if thousands in integer:
            groups = integer.split(thousands)
            if not (1 <= len(groups[0]) <= 3 and all(len(group) == 3 for group in groups[1:])):
                return ParsedDecimal(raw, AMBIGUOUS_SEPARATOR, detail=f"irregular digit grouping in {integer!r}")
            integer = "".join(groups)
    if not _DIGITS.fullmatch(integer) or (has_point and not _DIGITS.fullmatch(fraction)):
        return ParsedDecimal(raw, NOT_A_NUMBER, detail="expected digits on both sides of the decimal mark")
    value = Decimal(f"{sign}{integer}.{fraction}" if has_point else f"{sign}{integer}")
    return ParsedDecimal(raw, NUMBER_PARSED, value, len(fraction) if has_point else 0)


@dataclass(frozen=True)
class NumericComparison:
    """The outcome of comparing a claim string with a stored value.

    ``agrees`` is None when no comparison was possible; it is never False
    for a value that could not be read.
    """

    outcome: str
    claim: ParsedDecimal
    stored: ParsedDecimal
    precision: int | None = None
    rounded_stored: str | None = None
    detail: str = ""

    @property
    def agrees(self) -> bool | None:
        if self.outcome in (EXACT, AGREES_AT_STATED_PRECISION):
            return True
        return False if self.outcome == DISAGREES else None

    @property
    def verdict(self) -> Status:
        return {True: Status.PASS, False: Status.FAIL, None: Status.ABSTAIN}[self.agrees]

    @property
    def reason(self) -> Reason:
        return {True: Reason.VERIFIED, False: Reason.SOURCE_MISMATCH, None: Reason.REQUIRES_HUMAN_REVIEW}[self.agrees]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "agrees": self.agrees,
            "precision": self.precision,
            "rounding": "ROUND_HALF_EVEN" if self.rounded_stored is not None else None,
            "rounded_stored": self.rounded_stored,
            "claim": self.claim.to_dict(),
            "stored": self.stored.to_dict(),
            "verdict": self.verdict.value,
            "reason": self.reason.value,
            "detail": self.detail,
        }


def _round_half_even(value: Decimal, decimals: int) -> Decimal:
    """Round to ``decimals`` places, half-even, with enough precision never to trap."""
    quantum = Decimal((0, (1,), -decimals))
    context = Context(prec=max(28, value.adjusted() + decimals + 3), rounding=ROUND_HALF_EVEN)
    return value.quantize(quantum, context=context)


def compare_decimal(
    claim: str | int | Decimal,
    stored: str | int | Decimal,
    *,
    thousands: str | None = None,
    decimal_point: str = ".",
    precision_decimals: int | None = None,
) -> NumericComparison:
    """Compare a claimed value (as printed) with the stored value it cites.

    * **EXACT**: the two numbers are equal.
    * **AGREES_AT_STATED_PRECISION**: the stored value, rounded half-even to
      the number of decimals the claim *prints*, equals the claim.
    * **DISAGREES**: neither holds.
    * **REQUIRES_HUMAN_REVIEW**: either side is ambiguous or not a number, or
      a declared ``precision_decimals`` contradicts what the claim prints.

    Only the stored value is ever rounded, and only to the claim's printed
    precision. Rounding both sides to a coarser shared precision would let
    two different values "agree", which is exactly the false agreement this
    rule exists to prevent: claim "0.15" against stored "0.14" DISAGREES even
    though both round to 0.1.
    """
    claim_parsed = parse_decimal(claim, thousands=thousands, decimal_point=decimal_point)
    stored_parsed = parse_decimal(stored, thousands=thousands, decimal_point=decimal_point)
    if not claim_parsed.ok or not stored_parsed.ok:
        unreadable = [
            f"{label} {parsed.text!r}: {parsed.state} ({parsed.detail})"
            for label, parsed in (("claim", claim_parsed), ("stored", stored_parsed))
            if not parsed.ok
        ]
        return NumericComparison(REQUIRES_HUMAN_REVIEW, claim_parsed, stored_parsed, detail="; ".join(unreadable))
    printed = claim_parsed.decimals
    if precision_decimals is not None:
        if isinstance(precision_decimals, bool) or not isinstance(precision_decimals, int) or precision_decimals < 0:
            raise ValueError(f"precision_decimals must be a non-negative int, got {precision_decimals!r}")
        if precision_decimals != printed:
            detail = f"declared precision_decimals={precision_decimals} but the claim prints {printed}"
            return NumericComparison(REQUIRES_HUMAN_REVIEW, claim_parsed, stored_parsed, printed, detail=detail)
    if claim_parsed.value == stored_parsed.value:
        return NumericComparison(EXACT, claim_parsed, stored_parsed, printed, detail="numerically equal")
    rounded = _round_half_even(stored_parsed.value, printed)
    shown = format(rounded, "f")
    if rounded == claim_parsed.value:
        detail = f"stored value rounds half-even to {shown} at {printed} decimal(s)"
        return NumericComparison(AGREES_AT_STATED_PRECISION, claim_parsed, stored_parsed, printed, shown, detail)
    detail = f"stored value rounds half-even to {shown} at {printed} decimal(s), not {claim_parsed.text.strip()}"
    return NumericComparison(DISAGREES, claim_parsed, stored_parsed, printed, shown, detail)


#: The comparator self-test (17.6) as ``(claim, stored, expected outcome)``:
#: two values that differ but round alike, an exact match despite a trailing
#: zero, and a legitimate agreement at stated precision.
COMPARATOR_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("0.15", "0.14", DISAGREES),
    ("12.4", "12.40", EXACT),
    ("0.1", "0.14", AGREES_AT_STATED_PRECISION),
)


def run_comparator_self_test() -> tuple[dict[str, str], ...]:
    """Compare :data:`COMPARATOR_PAIRS` through the live comparator and record what it said.

    ``compare_decimal`` is looked up in this module's namespace at call time,
    so a patched comparator is the one tested. A comparator that raises is
    recorded as having raised, never as agreeing.
    """
    pairs = []
    for claim, stored, expected in COMPARATOR_PAIRS:
        try:
            actual = str(compare_decimal(claim, stored).outcome)
        except Exception as exc:  # a broken comparator is a finding, not a crash
            actual = f"RAISED: {type(exc).__name__}"
        pairs.append({"claim": claim, "stored": stored, "expected": expected, "actual": actual})
    return tuple(pairs)


#: Discrimination probes ``claim + k * 10**-d`` for ``k`` in ``-STEPS..STEPS``: 21 probes.
DISCRIMINATION_STEPS = 10


def comparison_discrimination(
    claim: str | int | Decimal,
    stored: str | int | Decimal,
    *,
    thousands: str | None = None,
    decimal_point: str = ".",
    precision_decimals: int | None = None,
) -> Ratio:
    """How many of the 21 nearest printable claims the live comparator would reject (17.8).

    The probes are ``c + k * 10**-d`` for ``k`` from -10 to 10, where ``c``
    is the claim and ``d`` its printed decimals, each printed with ``d``
    decimals and no grouping. A comparator that rejects none of them could
    not have failed this comparison, so its agreement proves nothing.
    Returns an UNAVAILABLE ratio when the claim cannot be read.
    """
    parsed = parse_decimal(claim, thousands=thousands, decimal_point=decimal_point)
    if not parsed.ok or parsed.value is None or parsed.decimals is None:
        return Ratio(None, None)
    step = Decimal((0, (1,), -parsed.decimals))
    rejected = 0
    for k in range(-DISCRIMINATION_STEPS, DISCRIMINATION_STEPS + 1):
        probe = format(_round_half_even(parsed.value + k * step, parsed.decimals), "f")
        if decimal_point != ".":
            probe = probe.replace(".", decimal_point)
        try:
            outcome = compare_decimal(
                probe, stored, thousands=thousands, decimal_point=decimal_point, precision_decimals=precision_decimals
            ).outcome
        except Exception:  # a comparator that cannot answer rejects nothing
            continue
        if outcome == DISAGREES:
            rejected += 1
    return Ratio(rejected, 2 * DISCRIMINATION_STEPS + 1)
