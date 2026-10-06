"""The self-checking synthetic demonstration: ``science-gate demo [--output DIR]``.

The demo is the tool's acceptance run in a form anyone can repeat. It copies
the bundled synthetic fixtures into ``--output`` (a new temporary directory
by default), runs the real commands against the copies, in process, through
:func:`science_gate.cli.main`, and compares each outcome with an expectation
written down here in advance:

* a valid project PASSes, and its run directory re-verifies;
* an empty input ABSTAINs with exit 2;
* a narrated citation log is UNVERIFIED;
* mutation testing reports detections *and* blind spots, and never counts a
  skipped or non-applicable mutation as a detection;
* an upstream change marks descendants stale, and revalidation tells an
  unchanged artifact from a changed one;
* packaging a CONTROLLED_LOCAL corpus withholds every data file.

The demo checks itself: it exits 0 only if every expectation holds and 1 if
any does not. A demo that cannot run at all (an output directory that is not
empty, missing fixtures) exits 3. Nothing touches the network, because no
fixture asks for live lookups and no step passes ``--live``. Everything is
written inside the output directory, through safe writes or the commands'
own. The fixtures are synthetic, so a successful demo shows how the tool
behaves on known defects; it verifies nothing scientific.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, TextIO

from . import TOOL_NAME, __version__, cli
from ._canonical import StrictJSONError, pretty_json_bytes, strict_loads
from ._resources import bundled_dir
from ._safeio import SafeIOError, safe_read, safe_write
from .models import EXIT_CODE, Status

__all__ = [
    "DEMO_FIXTURES",
    "SUMMARY_SCHEMA",
    "SUMMARY_JSON",
    "SUMMARY_MD",
    "BLIND_SPOT_MANIFEST",
    "EXPECTED_BLIND_SPOTS",
    "DemoError",
    "CommandOutcome",
    "Expectation",
    "StepResult",
    "DemoResult",
    "run_demo",
    "render_table",
    "render_markdown",
    "cli_demo",
]

#: Fixture directories the demo copies, relative to the bundled ``fixtures/``.
DEMO_FIXTURES: tuple[str, ...] = (
    "core/valid",
    "core/empty",
    "citations/narrated-log",
    "mutations/rich",
    "dependencies/current",
    "packaging/controlled-local",
)

SUMMARY_SCHEMA = "science-gate-demo/v1"
SUMMARY_JSON = "demo-summary.json"
SUMMARY_MD = "demo-summary.md"

#: The rich mutation fixture without its reviewer_protocol check. The two
#: reviewer operators still change the evidence, so the pinned summary turns
#: the run FAIL, but the detector each operator expects never runs: a blind
#: spot that a bare "status is not PASS" rule would have hidden.
BLIND_SPOT_MANIFEST = "fixtures/mutations/rich/manifest-blind-spot.json"
EXPECTED_BLIND_SPOTS = ("M05_duplicate_reviewer_verdict", "M06_missing_required_reviewer")

_DEPENDENCIES = "fixtures/dependencies/current"
_DESIGN_NODE = "study-design"
_DESIGN_FILE = f"{_DEPENDENCIES}/design/protocol.md"
_PUBLICATION_NODE = "conclusion-1"
_DESIGN_AMENDMENT = b"\nSynthetic amendment made by science-gate demo: the invented design changed upstream.\n"

_CONTROLLED = "fixtures/packaging/controlled-local"

_ERROR = EXIT_CODE[Status.ERROR]

_NOT_PROVEN = (
    "Every fixture is synthetic: invented samples, sites, reviewers, citations and values. A demo that holds "
    "shows how the tool reacts to known defects on these fixtures. It establishes nothing about any real "
    "dataset, and nothing about scientific truth, accuracy, safety, or fitness for use."
)


class DemoError(Exception):
    """The demo cannot run at all. The command exits 3 and runs no step."""


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandOutcome:
    """One command the demo ran: its arguments as shown (output-relative), exit code and headline."""

    argv: tuple[str, ...]
    exit_code: int
    headline: str

    @property
    def command(self) -> str:
        return " ".join(("science-gate", *self.argv))


@dataclass(frozen=True)
class Expectation:
    """One row of the demo table: what was expected, what happened, and whether they agree."""

    expected: str
    actual: str
    holds: bool


@dataclass(frozen=True)
class StepResult:
    """One demo step: the commands it ran and the expectations it judged."""

    name: str
    commands: tuple[CommandOutcome, ...]
    expectations: tuple[Expectation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.name,
            "commands": [
                {"command": item.command, "exit_code": item.exit_code, "headline": item.headline}
                for item in self.commands
            ],
            "expectations": [
                {"expected": item.expected, "actual": item.actual, "holds": item.holds} for item in self.expectations
            ],
        }


@dataclass(frozen=True)
class DemoResult:
    """The whole demonstration. Exit 0 only when every expectation held."""

    output: Path
    steps: tuple[StepResult, ...]

    @property
    def expectations(self) -> tuple[Expectation, ...]:
        return tuple(item for step in self.steps for item in step.expectations)

    @property
    def failed_steps(self) -> tuple[str, ...]:
        return tuple(step.name for step in self.steps if not all(item.holds for item in step.expectations))

    @property
    def holds(self) -> bool:
        return bool(self.expectations) and not self.failed_steps

    @property
    def exit_code(self) -> int:
        return EXIT_CODE[Status.PASS] if self.holds else EXIT_CODE[Status.FAIL]

    @property
    def headline(self) -> str:
        total = len(self.expectations)
        if self.holds:
            return (
                f"OK demo: all {total} expectations held on synthetic fixtures in {self.output}; "
                "this shows tool behavior only and verifies nothing scientific"
            )
        missed = sum(not item.holds for item in self.expectations)
        return (
            f"FAIL demo: {missed} of {total} expectations did not hold (steps: {', '.join(self.failed_steps)}); "
            f"see {self.output / SUMMARY_MD}"
        )

    def to_dict(self) -> dict[str, Any]:
        expectations = self.expectations
        return {
            "schema": SUMMARY_SCHEMA,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "holds": self.holds,
            "exit_code": self.exit_code,
            "expectations_total": len(expectations),
            "expectations_held": sum(item.holds for item in expectations),
            "failed_steps": list(self.failed_steps),
            "steps": [step.to_dict() for step in self.steps],
            "fixtures": list(DEMO_FIXTURES),
            "network": "offline: no fixture requests live lookups and no step passes --live",
            "not_proven": _NOT_PROVEN,
        }


# ---------------------------------------------------------------------------
# The workspace: copied fixtures and in-process commands
# ---------------------------------------------------------------------------


class _Workspace:
    """The output directory. Paths given as :class:`PurePosixPath` are relative to it."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, *parts: str | PurePosixPath) -> CommandOutcome:
        """Run one ``science-gate`` command in process and capture its printed output.

        Output-relative paths are made absolute for the command, so the demo
        never depends on (or changes) the working directory, and shown
        relative, so the table reads the same wherever the output lives.
        """
        shown = tuple(part.as_posix() if isinstance(part, PurePosixPath) else part for part in parts)
        argv = [str(self.root / part) if isinstance(part, PurePosixPath) else part for part in parts]
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
            code = cli.main(argv)
        lines = printed.getvalue().splitlines()
        headline = lines[0].replace(str(self.root), "<output>") if lines else ""
        return CommandOutcome(shown, code, headline)

    def json(self, relpath: str) -> Any:
        """A JSON file a command wrote, or None when it is missing or unreadable."""
        try:
            return strict_loads(safe_read(self.root, relpath))
        except (OSError, SafeIOError, StrictJSONError):
            return None

    def read(self, relpath: str) -> bytes:
        return safe_read(self.root, relpath)

    def write(self, relpath: str, data: bytes) -> None:
        safe_write(self.root, relpath, data)

    def files(self, relpath: str) -> list[Path]:
        base = self.root / relpath
        return sorted(path for path in base.rglob("*") if path.is_file()) if base.is_dir() else []


def _prepare_output(output: str | None) -> Path:
    """The demo's output directory: new, or existing and empty. Never one holding other files."""
    if output is None:
        return Path(tempfile.mkdtemp(prefix="science-gate-demo-")).resolve()
    target = Path(output)
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise DemoError(f"{target} exists and is not an empty directory; refusing to overwrite")
    return target.resolve()


def _copy_fixtures(root: Path) -> None:
    """Copy the demo fixtures into ``root/fixtures``; the bundled originals are only read."""
    source = bundled_dir("fixtures")
    if source is None:
        raise DemoError("the bundled fixtures were not found in this installation")
    for fixture in DEMO_FIXTURES:
        base = source / fixture
        if not base.is_dir():
            raise DemoError(f"the bundled fixture {fixture} is missing from {source}")
        for path in sorted(base.rglob("*")):
            if path.is_file():
                safe_write(root, f"fixtures/{path.relative_to(source).as_posix()}", path.read_bytes())


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

#: What a step returns: the commands it ran and the expectations it judged.
_Outcome = tuple[tuple[CommandOutcome, ...], tuple[Expectation, ...]]


def _field(document: Any, *keys: str) -> Any:
    """``document[k1][k2]...``, or None as soon as a level is missing. Missing is shown, never assumed."""
    for key in keys:
        if not isinstance(document, Mapping):
            return None
        document = document.get(key)
    return document


def _status(document: Any, code: int) -> str:
    return f"{_field(document, 'status')} ({_field(document, 'reason')}), exit {code}"


def _verify(ws: _Workspace, fixture: str, run_dir: str) -> tuple[CommandOutcome, Any]:
    outcome = ws.run("verify", PurePosixPath(f"fixtures/{fixture}/manifest.json"), "--output", PurePosixPath(run_dir))
    return outcome, ws.json(f"{run_dir}/run.json")


def _step_valid(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "core/valid", "runs/valid")
    rows, executed, expected, passed = (
        _field(run, name) for name in ("rows_examined", "checks_executed", "checks_expected", "checks_passed")
    )
    complete = isinstance(expected, int) and expected >= 1 and executed == expected == passed
    return (command,), (
        Expectation(
            "PASS (VERIFIED), exit 0",
            _status(run, command.exit_code),
            _field(run, "status") == "PASS" and _field(run, "reason") == "VERIFIED" and command.exit_code == 0,
        ),
        Expectation(
            "at least one row examined; every required check executed and passed",
            f"{rows} row(s) examined; {executed}/{expected} required checks executed, {passed} passed",
            isinstance(rows, int) and rows >= 1 and complete,
        ),
    )


def _step_report(ws: _Workspace) -> _Outcome:
    command = ws.run("report", PurePosixPath("runs/valid"))
    return (command,), (
        Expectation(
            "receipt, ledger chain and recorded figures re-verify: PASS, exit 0",
            f"{command.headline.split(' ', 1)[0] or 'nothing printed'}, exit {command.exit_code}",
            command.exit_code == 0 and command.headline.startswith("PASS ") and "re-verified" in command.headline,
        ),
    )


def _step_empty(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "core/empty", "runs/empty")
    states = {item.get("id"): item.get("state") for item in _field(run, "accounting", "inputs") or ()}
    rows = _field(run, "rows_examined")
    return (command,), (
        Expectation(
            "ABSTAIN, exit 2: input measurements EMPTY, 0 rows examined, never PASS",
            f"{_status(run, command.exit_code)}; input measurements {states.get('measurements')}, "
            f"{rows} row(s) examined",
            _field(run, "status") == "ABSTAIN"
            and command.exit_code == 2
            and states.get("measurements") == "EMPTY"
            and rows == 0,
        ),
    )


def _step_narrated(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "citations/narrated-log", "runs/narrated")
    modes = _field(run, "failure_modes") or []
    held = {item.get("name"): item.get("holds") for item in _field(run, "invariants") or ()}
    tally = held.get("checked_claims_le_invocations")
    return (command,), (
        Expectation(
            "ABSTAIN (UNVERIFIED), exit 2",
            _status(run, command.exit_code),
            _field(run, "status") == "ABSTAIN" and _field(run, "reason") == "UNVERIFIED" and command.exit_code == 2,
        ),
        Expectation(
            "NARRATED_VERIFICATION; claimed verifications exceed invocation records; no live lookup",
            f"failure modes {', '.join(modes) or 'none'}; checked_claims_le_invocations holds={tally}; "
            f"live={_field(run, 'network', 'live')}",
            "NARRATED_VERIFICATION" in modes and tally is False and _field(run, "network", "live") is False,
        ),
    )


def _step_mutation(ws: _Workspace) -> _Outcome:
    command = ws.run("mutate", PurePosixPath(BLIND_SPOT_MANIFEST), "--output", PurePosixPath("mutation"))
    report = ws.json("mutation/mutation-report.json")
    records = [item for item in _field(report, "mutations") or () if isinstance(item, Mapping)]
    blind = tuple(item.get("mutation_id") for item in records if item.get("blind_spot") is True)
    executed = [item for item in records if item.get("execution_state") == "CHECKED"]
    others = [item for item in records if item.get("execution_state") != "CHECKED"]
    detected = _field(report, "detected_mutations")
    counted_apart = (
        bool(others)
        and all(item.get("detected") is None and item.get("blind_spot") is None for item in others)
        and detected == sum(item.get("detected") is True for item in executed)
    )
    return (command,), (
        Expectation(
            "FAIL (BLIND_SPOT), exit 1",
            _status(report, command.exit_code),
            _field(report, "status") == "FAIL" and _field(report, "reason") == "BLIND_SPOT"
            and command.exit_code == 1,
        ),
        Expectation(
            f"detections reported; blind spots exactly {', '.join(EXPECTED_BLIND_SPOTS)}",
            f"{detected} of {_field(report, 'executed_mutations')} executed mutations detected; "
            f"blind spots: {', '.join(str(item) for item in blind) or 'none'}",
            isinstance(detected, int) and detected >= 1 and blind == EXPECTED_BLIND_SPOTS,
        ),
        Expectation(
            "skipped and not-applicable mutations are counted apart, never as detections",
            f"{_field(report, 'skipped_mutations')} skipped, {_field(report, 'not_applicable_mutations')} not "
            f"applicable; {sum(item.get('detected') is not None for item in others)} of them marked detected "
            "or escaped",
            counted_apart,
        ),
    )


def _graph_report(ws: _Workspace, name: str) -> Any:
    return ws.json(f"{_DEPENDENCIES}/graph/{name}")


def _node(report: Any, node_id: str) -> Any:
    found = [item for item in _field(report, "nodes") or () if isinstance(item, Mapping) and item.get("id") == node_id]
    return found[0] if found else None


def _graph_command(ws: _Workspace, command: str) -> CommandOutcome:
    return ws.run(command, _DESIGN_NODE, "--manifest", PurePosixPath(f"{_DEPENDENCIES}/manifest.json"))


def _step_impact(ws: _Workspace) -> _Outcome:
    command = _graph_command(ws, "impact")
    report = _graph_report(ws, "impact-report.json")
    blocked = _field(report, "publication_block", "blocked")
    reached = [item.get("id") for item in _field(report, "impact", "descendants") or () if isinstance(item, Mapping)]
    publication = _field(_node(report, _PUBLICATION_NODE), "validity")
    return (command,), (
        Expectation(
            "FAIL, exit 1: publication blocked",
            f"{_status(report, command.exit_code)}; publication blocked={blocked}",
            _field(report, "status") == "FAIL" and command.exit_code == 1 and blocked is True,
        ),
        Expectation(
            f"descendants marked STALE_PENDING_REVALIDATION, {_PUBLICATION_NODE} among them",
            f"{len(reached)} descendant(s) reached; {_PUBLICATION_NODE} is {publication}",
            _PUBLICATION_NODE in reached and publication == "STALE_PENDING_REVALIDATION",
        ),
    )


def _revalidation(ws: _Workspace) -> tuple[Any, Any, list[Any], Any]:
    report = _graph_report(ws, "revalidation-report.json")
    action = _field(report, "revalidate")
    cleared = [item.get("id") for item in _field(action, "cleared") or () if isinstance(item, Mapping)]
    return report, _field(action, "outcome"), cleared, _field(_node(report, _PUBLICATION_NODE), "validity")


def _step_revalidate_unchanged(ws: _Workspace) -> _Outcome:
    command = _graph_command(ws, "revalidate")
    report, outcome, cleared, publication = _revalidation(ws)
    return (command,), (
        Expectation(
            f"REVALIDATED_UNCHANGED; early cutoff clears {_PUBLICATION_NODE}; PASS, exit 0",
            f"{outcome}; cleared {', '.join(cleared) or 'nothing'}; {_PUBLICATION_NODE} is {publication}; "
            f"{_status(report, command.exit_code)}",
            outcome == "REVALIDATED_UNCHANGED"
            and _PUBLICATION_NODE in cleared
            and publication == "CURRENT"
            and command.exit_code == 0,
        ),
    )


def _step_revalidate_changed(ws: _Workspace) -> _Outcome:
    ws.write(_DESIGN_FILE, ws.read(_DESIGN_FILE) + _DESIGN_AMENDMENT)
    command = _graph_command(ws, "revalidate")
    report, outcome, cleared, publication = _revalidation(ws)
    return (command,), (
        Expectation(
            f"REVALIDATED_CHANGED; {_PUBLICATION_NODE} stays STALE_PENDING_REVALIDATION; FAIL, exit 1",
            f"{outcome}; cleared {', '.join(cleared) or 'nothing'}; {_PUBLICATION_NODE} is {publication}; "
            f"{_status(report, command.exit_code)}",
            outcome == "REVALIDATED_CHANGED"
            and not cleared
            and publication == "STALE_PENDING_REVALIDATION"
            and command.exit_code == 1,
        ),
    )


def _leaked_rows(ws: _Workspace, entries: Iterable[Mapping[str, Any]]) -> int:
    """Data rows of withheld inputs that appear anywhere in the package (there must be none)."""
    packaged = [path.read_bytes() for path in ws.files("package")]
    leaked = 0
    for entry in entries:
        if entry.get("kind") != "input" or not isinstance(entry.get("path"), str):
            continue
        rows = ws.read(f"{_CONTROLLED}/{entry['path']}").splitlines()[1:]
        leaked += sum(1 for row in rows if row.strip() and any(row in data for data in packaged))
    return leaked


def _step_package(ws: _Workspace) -> _Outcome:
    command = ws.run(
        "package", PurePosixPath(f"{_CONTROLLED}/manifest.json"), "--output", PurePosixPath("package")
    )
    index = ws.json("package/package.json")
    files = [item for item in _field(index, "files") or () if isinstance(item, Mapping)]
    withheld = [
        item
        for item in files
        if item.get("disposition") == "WITHHELD" and item.get("basis") == "ACCESS_CLASS_CONTROLLED_LOCAL"
    ]
    leaked = _leaked_rows(ws, files)
    return (command,), (
        Expectation(
            "complete package, exit 0",
            f"{_field(index, 'package_state')}, exit {command.exit_code}",
            _field(index, "package_state") == "COMPLETE" and command.exit_code == 0,
        ),
        Expectation(
            "every evaluation file WITHHELD (CONTROLLED_LOCAL); no data row copied",
            f"{len(withheld)} of {len(files)} file(s) withheld; {leaked} data row(s) found in the package",
            bool(files) and len(withheld) == len(files) and leaked == 0,
        ),
    )


_STEPS: tuple[tuple[str, Callable[[_Workspace], _Outcome]], ...] = (
    ("valid project", _step_valid),
    ("re-verify the run directory", _step_report),
    ("empty input", _step_empty),
    ("narrated verification", _step_narrated),
    ("mutation testing", _step_mutation),
    ("upstream change", _step_impact),
    ("revalidate, file unchanged", _step_revalidate_unchanged),
    ("revalidate, file changed", _step_revalidate_changed),
    ("controlled-local packaging", _step_package),
)


def _guarded(name: str, step: Callable[[_Workspace], _Outcome], ws: _Workspace) -> StepResult:
    """Run one step; a step that breaks is a failed expectation in the table, never a traceback."""
    try:
        commands, expectations = step(ws)
    except Exception as exc:  # the demo reports on the tool; it must not die with it
        actual = f"the step raised {type(exc).__name__}: {exc}".replace(str(ws.root), "<output>")
        return StepResult(name, (), (Expectation("the step runs to completion", actual, False),))
    return StepResult(name, commands, expectations)


def run_demo(output: str | None = None) -> DemoResult:
    """Copy the fixtures into ``output`` (a new temporary directory when None) and run every step.

    Raises :class:`DemoError` when the demo cannot start. Writes
    ``demo-summary.json`` and ``demo-summary.md`` into the output directory.
    """
    root = _prepare_output(output)
    _copy_fixtures(root)
    ws = _Workspace(root)
    result = DemoResult(root, tuple(_guarded(name, step, ws) for name, step in _STEPS))
    safe_write(root, SUMMARY_JSON, pretty_json_bytes(result.to_dict()))
    safe_write(root, SUMMARY_MD, render_markdown(result).encode("utf-8"))
    return result


# ---------------------------------------------------------------------------
# Rendering and the command
# ---------------------------------------------------------------------------


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_table(result: DemoResult) -> list[str]:
    """The expected-versus-actual table, one row per expectation, as Markdown table lines."""
    lines = ["| # | step | expected | actual | holds |", "|---|---|---|---|---|"]
    number = 0
    for step in result.steps:
        for item in step.expectations:
            number += 1
            row = (str(number), step.name, item.expected, item.actual, "yes" if item.holds else "NO")
            lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return lines


def render_markdown(result: DemoResult) -> str:
    lines = ["# science-gate demo", "", result.headline.replace(str(result.output), "<output>"), ""]
    lines += ["## EXPECTED VERSUS ACTUAL", "", *render_table(result), "", "## COMMANDS RUN", ""]
    for step in result.steps:
        for command in step.commands:
            lines.append(f"- {step.name}: `{command.command}` -> exit {command.exit_code}")
            lines.append(f"  - {_cell(command.headline) or 'nothing printed'}")
    lines += ["", "## WHAT THIS DEMO DOES NOT PROVE", "", _NOT_PROVEN, ""]
    return "\n".join(lines)


def _written_paths(root: Path) -> list[Path]:
    """The summary files, then each step's output location, in step order."""
    places = [
        SUMMARY_JSON,
        SUMMARY_MD,
        "fixtures",
        "runs/valid",
        "runs/empty",
        "runs/narrated",
        "mutation",
        f"{_DEPENDENCIES}/graph",
        "package",
    ]
    return [root / place for place in places if (root / place).exists()]


def _emit(stream: TextIO, text: str) -> None:
    """Write one line, escaping what the stream's encoding cannot represent (a legacy console code page)."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")


def cli_demo(args: argparse.Namespace) -> int:
    """``science-gate demo [--output DIR]``; returns the exit code.

    Prints the headline, the paths written, a blank line and the
    expected-versus-actual table. Exit 0 means every expectation held, 1
    means at least one did not, and 3 means the demo could not run.
    """
    out = sys.stdout
    try:
        result = run_demo(args.output)
    except (DemoError, SafeIOError, OSError) as exc:
        _emit(out, f"ERROR demo: {exc}")
        return _ERROR
    _emit(out, result.headline)
    for path in _written_paths(result.output):
        _emit(out, str(path))
    _emit(out, "")
    for line in render_table(result):
        _emit(out, line)
    return result.exit_code
