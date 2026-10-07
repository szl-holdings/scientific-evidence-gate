"""Exporter validators: reporters that can fail (ARCHITECTURE.md section 17.10, extension #12, D7).

A report writer that cannot reject its own output only narrates. Every export
of a run directory is therefore judged against ``run.json`` before anything
is written, and again whenever ``science-gate report RUN_DIR`` re-reads a
stored run. A validator returns problems; it never raises on a malformed
document, because the documents it reads back from disk may have been edited
by anyone.

Each problem is one line of text that starts with a stable code followed by
``": "``. The codes:

* ``RUN_JSON_MALFORMED`` / ``SARIF_MALFORMED`` / ``REPORT_MALFORMED``: the
  export does not have the shape the writer produces, so nothing else about
  it can be judged.
* ``RUN_CHECKS_EXECUTED_MISMATCH``: ``checks_executed`` differs from the
  number of required results that reached CHECKED with an invocation. When
  the declared checks are unknown (``checks_expected`` is null), the count
  must be null too: an unknown count is never a number.
* ``SARIF_LEVEL_WITHOUT_FAIL``: a result whose level is not ``none`` while
  its kind is not ``fail``. SARIF keeps outcome (kind) and severity (level)
  apart, and only a failure may carry a severity.
* ``SARIF_EXECUTION_SUCCESS_ON_ERROR`` and ``SARIF_ERROR_WITHOUT_NOTIFICATION``
  (D7): tool health belongs in the invocation, so an ERROR run must say
  ``executionSuccessful: false`` and carry an error-level
  toolExecutionNotification.
* ``SARIF_KIND_MISMATCH``: a check result whose kind is not the
  classification of the same check in ``run.json``.
* ``SARIF_CHECK_MISSING`` and ``SARIF_CHECK_UNEXPECTED``: every check id in
  ``declared.checks`` appears exactly once, and no other check id appears.
* ``REPORT_HEADING_MISSING`` and ``REPORT_HEADING_ORDER``: the nine contract
  headings are the first nine ``## `` headings of ``report.md``, in order.
* ``REPORT_ROWS_EXAMINED_MISMATCH`` (G5): ``report.md`` names the run's
  ``rows_examined`` on exactly one line, in the one wording of
  :func:`rows_examined_line`, with the figure ``run.json`` records.

``VALIDATORS`` maps each validated file name to a callable taking
``(export, run)``. Callers look it up through this module at call time, so a
test can replace one entry and prove that the tests built on it would then
fail.
"""

from __future__ import annotations

from collections import Counter
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from .models import Reason, Status

__all__ = [
    "RUN_JSON",
    "REPORT_MD",
    "RESULTS_SARIF",
    "REPORT_HEADINGS",
    "ROWS_EXAMINED_MEANING",
    "RUN_JSON_MALFORMED",
    "RUN_CHECKS_EXECUTED_MISMATCH",
    "SARIF_MALFORMED",
    "SARIF_LEVEL_WITHOUT_FAIL",
    "SARIF_EXECUTION_SUCCESS_ON_ERROR",
    "SARIF_ERROR_WITHOUT_NOTIFICATION",
    "SARIF_KIND_MISMATCH",
    "SARIF_CHECK_MISSING",
    "SARIF_CHECK_UNEXPECTED",
    "REPORT_MALFORMED",
    "REPORT_HEADING_MISSING",
    "REPORT_HEADING_ORDER",
    "REPORT_ROWS_EXAMINED_MISMATCH",
    "ExportValidationError",
    "Validator",
    "problem_code",
    "sarif_classification",
    "rows_examined_line",
    "validate_run_json",
    "validate_sarif",
    "validate_report_md",
    "VALIDATORS",
    "validate_exports",
]

RUN_JSON = "run.json"
REPORT_MD = "report.md"
RESULTS_SARIF = "results.sarif"

#: The first headings of ``report.md``, in this order (section 12).
REPORT_HEADINGS = (
    "STATUS",
    "WHAT WAS EXPECTED",
    "WHAT WAS EXAMINED",
    "WHAT ACTUALLY RAN",
    "WHAT PASSED",
    "WHAT FAILED",
    "WHAT ABSTAINED",
    "WHAT REMAINS UNRESOLVED",
    "WHAT THIS RESULT DOES NOT PROVE",
)

#: What the run-level ``rows_examined`` counts (G1), printed beside it (G5).
ROWS_EXAMINED_MEANING = "distinct data rows of declared inputs read by an executed check"

RUN_JSON_MALFORMED = "RUN_JSON_MALFORMED"
RUN_CHECKS_EXECUTED_MISMATCH = "RUN_CHECKS_EXECUTED_MISMATCH"
SARIF_MALFORMED = "SARIF_MALFORMED"
SARIF_LEVEL_WITHOUT_FAIL = "SARIF_LEVEL_WITHOUT_FAIL"
SARIF_EXECUTION_SUCCESS_ON_ERROR = "SARIF_EXECUTION_SUCCESS_ON_ERROR"
SARIF_ERROR_WITHOUT_NOTIFICATION = "SARIF_ERROR_WITHOUT_NOTIFICATION"
SARIF_KIND_MISMATCH = "SARIF_KIND_MISMATCH"
SARIF_CHECK_MISSING = "SARIF_CHECK_MISSING"
SARIF_CHECK_UNEXPECTED = "SARIF_CHECK_UNEXPECTED"
REPORT_MALFORMED = "REPORT_MALFORMED"
REPORT_HEADING_MISSING = "REPORT_HEADING_MISSING"
REPORT_HEADING_ORDER = "REPORT_HEADING_ORDER"
REPORT_ROWS_EXAMINED_MISMATCH = "REPORT_ROWS_EXAMINED_MISMATCH"

#: A validator judges one export against the run document it was built from.
Validator = Callable[[Any, Any], tuple[str, ...]]


class ExportValidationError(ValueError):
    """An export failed its validator, so nothing was written.

    ``problems`` holds every problem found, each starting with its code. The
    message is the first problem, which is what a one-line headline shows.
    """

    def __init__(self, problems: Sequence[str]) -> None:
        if not problems:
            raise ValueError("an ExportValidationError needs at least one problem")
        self.problems: tuple[str, ...] = tuple(problems)
        more = len(self.problems) - 1
        super().__init__(self.problems[0] + (f" (and {more} more)" if more else ""))


def problem_code(problem: str) -> str:
    """The stable code a problem line starts with."""
    return problem.split(":", 1)[0]


def _problem(code: str, message: str) -> str:
    return f"{code}: {message}"


def _is_count(value: Any) -> bool:
    """An int that is not a bool: JSON ``true`` must never pass for the count 1."""
    return isinstance(value, int) and not isinstance(value, bool)


def _mappings(value: Any) -> list[Mapping[str, Any]] | None:
    """``value`` as a list of objects, or None when it is anything else."""
    if isinstance(value, list) and all(isinstance(item, Mapping) for item in value):
        return value
    return None


# ---------------------------------------------------------------------------
# Shared definitions: the renderers use these, so the rule and the output
# cannot drift apart.
# ---------------------------------------------------------------------------


def sarif_classification(check: Mapping[str, Any]) -> tuple[str, str]:
    """SARIF ``(kind, level)`` for a ``run.json`` check result (section 1 and D7).

    ERROR -> fail/error; NOT_APPLICABLE -> notApplicable; SKIPPED -> open;
    CHECKED PASS -> pass; CHECKED FAIL -> fail/error; ABSTAIN with
    REQUIRES_HUMAN_REVIEW -> review; any other ABSTAIN -> open. Only ``fail``
    carries a level other than ``none``.
    """
    verdict, state = check.get("verdict"), check.get("execution_state")
    if verdict == Status.ERROR.value:
        return "fail", "error"
    if state == "NOT_APPLICABLE":
        return "notApplicable", "none"
    if state == "SKIPPED":
        return "open", "none"
    if verdict == Status.PASS.value:
        return "pass", "none"
    if verdict == Status.FAIL.value:
        return "fail", "error"
    if check.get("reason") == Reason.REQUIRES_HUMAN_REVIEW.value:
        return "review", "none"
    return "open", "none"


def _figure(value: Any) -> str:
    """A recorded count for people: unknown stays "unknown", never 0."""
    if value is None:
        return "unknown"
    return str(value) if _is_count(value) else repr(value)


def rows_examined_line(value: Any) -> str:
    """The one wording ``report.md`` uses for the run's ``rows_examined`` (G5).

    The run figure counts distinct data rows (G1); a check's own figure
    counts its subject records and is named differently, on its own line.
    """
    return f"rows_examined: {_figure(value)} ({ROWS_EXAMINED_MEANING})"


# ---------------------------------------------------------------------------
# run.json
# ---------------------------------------------------------------------------


def _executed_checks(checks: Sequence[Mapping[str, Any]]) -> int:
    """Required results that reached CHECKED and name the invocation that produced them."""
    return sum(
        1
        for check in checks
        if check.get("required") is True
        and check.get("execution_state") == "CHECKED"
        and check.get("invocation_id") is not None
    )


def validate_run_json(run: Any) -> tuple[str, ...]:
    """Problems with a ``run.json`` document, judged on its own."""
    if not isinstance(run, Mapping):
        return (_problem(RUN_JSON_MALFORMED, "run.json is not a JSON object"),)
    checks = _mappings(run.get("checks"))
    if checks is None:
        return (_problem(RUN_JSON_MALFORMED, "run.json checks is not a list of objects"),)
    recorded, expected = run.get("checks_executed"), run.get("checks_expected")
    if expected is None:
        if recorded is not None:
            return (
                _problem(
                    RUN_CHECKS_EXECUTED_MISMATCH,
                    f"checks_executed is {_figure(recorded)} although checks_expected is unknown",
                ),
            )
        return ()
    terminal = _executed_checks(checks)
    if not (_is_count(recorded) and recorded == terminal):
        return (
            _problem(
                RUN_CHECKS_EXECUTED_MISMATCH,
                f"checks_executed is {_figure(recorded)}, but {terminal} required result(s) reached CHECKED "
                "with an invocation",
            ),
        )
    return ()


# ---------------------------------------------------------------------------
# results.sarif
# ---------------------------------------------------------------------------


def _effective_kind_and_level(result: Mapping[str, Any]) -> tuple[Any, Any]:
    """A result's kind and level with SARIF's defaults applied.

    An absent kind means ``fail``. An absent level means ``warning`` for a
    failure and ``none`` for any other kind.
    """
    kind = result.get("kind", "fail")
    return kind, result.get("level", "warning" if kind == "fail" else "none")


def _result_label(index: int, result: Mapping[str, Any]) -> str:
    properties = result.get("properties")
    check_id = properties.get("check_id") if isinstance(properties, Mapping) else None
    return f"result {index}" + (f" (check {check_id!r})" if check_id is not None else "")


def _tool_health_problems(invocations: Sequence[Mapping[str, Any]], status: Any) -> list[str]:
    """D7: an ERROR run reports its tool failure in the invocation, not only in results."""
    if status != Status.ERROR.value:
        return []
    invocation = invocations[0] if invocations else {}
    problems: list[str] = []
    if invocation.get("executionSuccessful") is not False:
        shown = invocation.get("executionSuccessful", "absent")
        problems.append(
            _problem(
                SARIF_EXECUTION_SUCCESS_ON_ERROR,
                f"run.json status is ERROR but invocations[0].executionSuccessful is {shown!r}, not false",
            )
        )
    notifications = _mappings(invocation.get("toolExecutionNotifications")) or []
    if not any(item.get("level") == "error" for item in notifications):
        problems.append(
            _problem(
                SARIF_ERROR_WITHOUT_NOTIFICATION,
                "run.json status is ERROR but invocations[0] carries no error-level toolExecutionNotification",
            )
        )
    return problems


def _declared_check_ids(run: Mapping[str, Any]) -> list[str] | None:
    """The declared check ids, or None when ``declared.checks`` is not a list of objects with text ids."""
    declared = run.get("declared")
    checks = _mappings(declared.get("checks")) if isinstance(declared, Mapping) else None
    if checks is None or not all(isinstance(item.get("id"), str) for item in checks):
        return None
    return [item["id"] for item in checks]


def validate_sarif(sarif: Any, run: Any) -> tuple[str, ...]:
    """Problems with a SARIF log, judged against the ``run.json`` it was built from."""
    runs = sarif.get("runs") if isinstance(sarif, Mapping) else None
    if not (isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], Mapping)):
        return (_problem(SARIF_MALFORMED, "results.sarif does not hold exactly one run object"),)
    results = _mappings(runs[0].get("results"))
    invocations = _mappings(runs[0].get("invocations"))
    if results is None or invocations is None:
        return (_problem(SARIF_MALFORMED, "results.sarif results or invocations is not a list of objects"),)
    if not isinstance(run, Mapping):
        return (_problem(RUN_JSON_MALFORMED, "the run.json results.sarif is judged against is not a JSON object"),)
    declared = _declared_check_ids(run)
    recorded = _mappings(run.get("checks"))
    if declared is None or recorded is None:
        return (
            _problem(RUN_JSON_MALFORMED, "run.json declared.checks or checks is not a list of objects with text ids"),
        )

    problems: list[str] = []
    for index, result in enumerate(results):
        kind, level = _effective_kind_and_level(result)
        if kind != "fail" and level != "none":
            problems.append(
                _problem(
                    SARIF_LEVEL_WITHOUT_FAIL, f"{_result_label(index, result)} has level {level!r} but kind {kind!r}"
                )
            )
    problems += _tool_health_problems(invocations, run.get("status"))

    # A tampered run.json may hold any JSON value where an id belongs; only text ids can match.
    by_id = {check["check_id"]: check for check in recorded if isinstance(check.get("check_id"), str)}
    planned = set(declared)
    seen: Counter[str] = Counter()
    for index, result in enumerate(results):
        properties = result.get("properties")
        if not (isinstance(properties, Mapping) and "check_id" in properties):
            continue  # a run-level finding, not a check result
        check_id = properties["check_id"]
        if not isinstance(check_id, str) or check_id not in planned:
            problems.append(_problem(SARIF_CHECK_UNEXPECTED, f"{_result_label(index, result)} is not a declared check"))
            continue
        seen[check_id] += 1
        if seen[check_id] > 1:
            problems.append(
                _problem(SARIF_CHECK_UNEXPECTED, f"{_result_label(index, result)} repeats a check already reported")
            )
            continue
        check = by_id.get(check_id)
        expected_kind = sarif_classification(check)[0] if check is not None else None
        if result.get("kind", "fail") != expected_kind:
            recorded_as = (
                "no result in run.json"
                if check is None
                else f"{check.get('execution_state')} {check.get('verdict')} ({check.get('reason')}) in run.json"
            )
            problems.append(
                _problem(
                    SARIF_KIND_MISMATCH,
                    f"{_result_label(index, result)} has kind {result.get('kind', 'fail')!r}, but the check is "
                    f"{recorded_as}, which is kind {expected_kind!r}",
                )
            )
    problems += [
        _problem(SARIF_CHECK_MISSING, f"declared check {check_id!r} has no result")
        for check_id in sorted(planned)
        if not seen[check_id]
    ]
    return tuple(problems)


# ---------------------------------------------------------------------------
# report.md
# ---------------------------------------------------------------------------


def validate_report_md(text: Any, run: Any) -> tuple[str, ...]:
    """Problems with ``report.md`` text, judged against the run document it renders."""
    if not isinstance(text, str):
        return (_problem(REPORT_MALFORMED, "report.md is not text"),)
    lines = text.splitlines()
    headings = [line[3:].rstrip() for line in lines if line.startswith("## ")]
    present = [heading for heading in REPORT_HEADINGS if heading in headings]
    problems = [
        _problem(REPORT_HEADING_MISSING, f"heading {heading!r} is not in report.md")
        for heading in REPORT_HEADINGS
        if heading not in present
    ]
    if headings[: len(present)] != present:
        problems.append(
            _problem(
                REPORT_HEADING_ORDER,
                f"the first headings are {headings[: len(present)]!r}, not the contract order {present!r}",
            )
        )
    recorded = run.get("rows_examined") if isinstance(run, Mapping) else None
    wanted = "- " + rows_examined_line(recorded)
    named = [line for line in lines if line.startswith("- rows_examined: ")]
    if named != [wanted]:
        problems.append(
            _problem(
                REPORT_ROWS_EXAMINED_MISMATCH,
                f"report.md must name the run figure once, as {wanted!r}; it has {named!r}",
            )
        )
    return tuple(problems)


# ---------------------------------------------------------------------------
# The table, and the one entry point the writers use
# ---------------------------------------------------------------------------


def _validate_run_json_export(export: Any, run: Any) -> tuple[str, ...]:
    """``run.json`` is its own reference: the export judged is the run document itself."""
    del run  # the same document; judging it against itself adds nothing
    return validate_run_json(export)


#: The validator of each export, in the order problems are reported.
VALIDATORS: Mapping[str, Validator] = MappingProxyType(
    {
        RUN_JSON: _validate_run_json_export,
        RESULTS_SARIF: validate_sarif,
        REPORT_MD: validate_report_md,
    }
)


def validate_exports(exports: Mapping[str, Any], run: Any) -> tuple[str, ...]:
    """Every problem of every export in ``exports`` that has a validator.

    ``exports`` maps file names to parsed content (a JSON value, or text for
    ``report.md``). The table is read through this module at call time.
    """
    problems: list[str] = []
    for name, validator in VALIDATORS.items():
        if name in exports:
            problems.extend(validator(exports[name], run))
    return tuple(problems)
