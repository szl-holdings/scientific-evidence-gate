"""The self-checking synthetic demonstration: ``science-gate demo [--output DIR]``.

The demo is the tool's acceptance run in a form anyone can repeat. It copies
the bundled synthetic fixtures into ``--output`` (a new temporary directory
by default), runs the real commands against the copies, in process, through
:func:`science_gate.cli.main`, and compares each outcome with an expectation
written down here in advance:

* a valid project PASSes, every PASS carries a falsifier witness (a known-bad
  case its checker rejected), the must-fail canary fails and its must-pass
  twin passes, the ledger opens with the run's PLAN, and the run directory
  re-verifies;
* an empty input ABSTAINs with exit 2;
* a narrated citation log is UNVERIFIED;
* a mean that no integer total can produce fails the GRIM test, and a derived
  number that reproduces only the printed operands is a narrated number;
* a resolver whose canary (a DOI that cannot exist) resolves is a proven
  blind spot;
* agent assertions joined to a sealed ledger fall into BACKED, NARRATED,
  CONTRADICTED and ORPHANED;
* mutation testing reports detections *and* blind spots, detects its own
  forced defect (M00) first, keeps its bookkeeping conserved, and never
  counts a skipped or non-applicable mutation as a detection;
* an upstream change marks descendants stale, revalidation tells an
  unchanged artifact from a changed one, and a derived artifact is cleared
  only by a recompute witness, never by re-hashing its untouched file;
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
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, TextIO

from . import TOOL_NAME, __version__, cli
from ._canonical import StrictJSONError, pretty_json_bytes, sha256_bytes, strict_loads
from ._clock import format_utc, parse_utc
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
    "numeric/grim-inconsistent",
    "numeric/narrated",
    "citations/canary-resolved",
    "assertions/five-cases",
    "mutations/rich",
    "dependencies/current",
    "dependencies/witnessed",
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

#: The witnessed-revalidation project: analysis-run is derived from two root
#: nodes, and site-summary, figure-1 and conclusion-1 descend from it.
_WITNESSED = "fixtures/dependencies/witnessed"
_DERIVED_NODE = "analysis-run"
_BELOW_DERIVED = ("site-summary", "figure-1", "conclusion-1")
#: The committed witness whose parent and output digests bind the fixture; the
#: demo re-times copies of it around the change it records (see
#: :func:`_write_witness`).
_WITNESS_TEMPLATE = f"{_WITNESSED}/witnesses/analysis-run-recomputed.json"
_PREDATING_WITNESS = f"{_WITNESSED}/witnesses/demo-recompute-before-change.json"
_FRESH_WITNESS = f"{_WITNESSED}/witnesses/demo-recompute-after-change.json"

_CONTROLLED = "fixtures/packaging/controlled-local"

#: What the claim-join fixture is built to produce (fixtures/assertions/five-cases/expected.json).
_EXPECTED_CLAIM_JOIN = {"BACKED": 1, "NARRATED": 2, "CONTRADICTED": 1, "ORPHANED": 1}

_STALE = "STALE_PENDING_REVALIDATION"
_ERROR = EXIT_CODE[Status.ERROR]

_NOT_PROVEN = (
    "Every fixture is synthetic: invented samples, sites, reviewers, citations, assertions and values, and the "
    "demo writes its own synthetic recompute witnesses. A demo that holds shows how the tool reacts to known "
    "defects on these fixtures. A falsifier witness shows that a check rejected one known-bad case, not that it "
    "catches every defect. It establishes nothing about any real dataset, and nothing about scientific truth, "
    "accuracy, safety, or fitness for use."
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

    def json_lines(self, relpath: str) -> list[Any]:
        """The records of a JSON Lines file, or an empty list when it is missing or unreadable."""
        try:
            return [strict_loads(line) for line in safe_read(self.root, relpath).splitlines() if line.strip()]
        except (OSError, SafeIOError, StrictJSONError):
            return []

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
# Reading what the commands wrote
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


def _is_status(document: Any, code: int, status: str, reason: str) -> bool:
    """True when a written document records ``status (reason)`` and the command exited with status's code."""
    return (
        _field(document, "status") == status
        and _field(document, "reason") == reason
        and code == EXIT_CODE[Status(status)]
    )


def _mappings(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _check_of(run: Any, kind: str) -> Any:
    """The run's one result of ``kind``, or None when there is not exactly one."""
    found = [item for item in _mappings(_field(run, "checks")) if item.get("kind") == kind]
    return found[0] if len(found) == 1 else None


def _invariants(run: Any) -> dict[Any, Any]:
    """``{name: holds}`` for every invariant the run recorded."""
    return {item.get("name"): item.get("holds") for item in _mappings(_field(run, "invariants"))}


def _verify(ws: _Workspace, fixture: str, run_dir: str) -> tuple[CommandOutcome, Any]:
    outcome = ws.run("verify", PurePosixPath(f"fixtures/{fixture}/manifest.json"), "--output", PurePosixPath(run_dir))
    return outcome, ws.json(f"{run_dir}/run.json")


# ---------------------------------------------------------------------------
# Steps: the valid project and what its PASS carries
# ---------------------------------------------------------------------------


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
            _is_status(run, command.exit_code, "PASS", "VERIFIED"),
        ),
        Expectation(
            "at least one row examined; every required check executed and passed",
            f"{rows} row(s) examined; {executed}/{expected} required checks executed, {passed} passed",
            isinstance(rows, int) and rows >= 1 and complete,
        ),
    )


def _rejected_cases(check: Mapping[str, Any]) -> list[Any]:
    """The falsifier cases the check rejected, as its own evidence records them."""
    return [
        item.get("case_id")
        for item in _mappings(_field(check, "evidence", "falsifiers"))
        if item.get("outcome") == "REJECTED"
    ]


def _step_witnesses(ws: _Workspace) -> _Outcome:
    """Every PASS of the valid run carries a witness that it could have failed, and the canary pair held."""
    run = ws.json("runs/valid/run.json")
    passed = [item for item in _mappings(_field(run, "checks")) if item.get("verdict") == "PASS"]
    witnessed = [
        item.get("check_id")
        for item in passed
        if _field(item, "evidence", "falsification") == "WITNESSED" and _rejected_cases(item)
    ]
    held = _invariants(run)
    canary = _field(run, "controls", "canary")
    must_fail, must_pass = _field(canary, "must_fail", "verdict"), _field(canary, "must_pass", "verdict")
    return (), (
        Expectation(
            "every PASS check is WITNESSED: its checker rejected a known-bad case of its own input "
            "(pass_requires_falsifier_witness holds)",
            f"{len(witnessed)} of {len(passed)} PASS check(s) WITNESSED; pass_requires_falsifier_witness "
            f"holds={held.get('pass_requires_falsifier_witness')}",
            bool(passed) and len(witnessed) == len(passed) and held.get("pass_requires_falsifier_witness") is True,
        ),
        Expectation(
            "the must-fail canary (a planted duplicate row) FAILs and its must-pass twin PASSes "
            "(canary_controls_hold holds)",
            f"must_fail {must_fail}, must_pass {must_pass}; "
            f"canary_controls_hold holds={held.get('canary_controls_hold')}",
            must_fail == "FAIL"
            and must_pass == "PASS"
            and _field(canary, "holds") is True
            and held.get("canary_controls_hold") is True,
        ),
    )


def _step_plan(ws: _Workspace) -> _Outcome:
    """The ledger opens with the run's PLAN, committed before any check started, and the plan closed."""
    run = ws.json("runs/valid/run.json")
    entries = [entry for entry in ws.json_lines("runs/valid/ledger.jsonl") if isinstance(entry, Mapping)]
    first = entries[0] if entries else {}
    second = entries[1] if len(entries) > 1 else {}
    chained = (
        bool(first)
        and second.get("result") == "STARTED"
        and second.get("prev_entry_sha256") == first.get("entry_sha256")
        and _field(run, "controls", "plan", "entry_sha256") == first.get("entry_sha256")
    )
    held = _invariants(run)
    closure, matches = held.get("plan_closure"), held.get("plan_matches_manifest")
    return (), (
        Expectation(
            "the ledger's first entry (seq 1, the brief's entry 0) is the PLAN, hash-chained before the first "
            "check started; plan_closure and plan_matches_manifest hold",
            f"first entry seq {first.get('seq')}, result {first.get('result')}, "
            f"invocation {first.get('invocation_id')}; "
            f"next entry {second.get('result')} chained to it: {chained}; plan_closure holds={closure}, "
            f"plan_matches_manifest holds={matches}",
            first.get("seq") == 1
            and first.get("result") == "PLAN"
            and first.get("invocation_id") is None
            and chained
            and closure is True
            and matches is True,
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


# ---------------------------------------------------------------------------
# Steps: missing, narrated and contradicted evidence
# ---------------------------------------------------------------------------


def _step_empty(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "core/empty", "runs/empty")
    states = {item.get("id"): item.get("state") for item in _mappings(_field(run, "accounting", "inputs"))}
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
    tally = _invariants(run).get("checked_claims_le_invocations")
    return (command,), (
        Expectation(
            "ABSTAIN (UNVERIFIED), exit 2",
            _status(run, command.exit_code),
            _is_status(run, command.exit_code, "ABSTAIN", "UNVERIFIED"),
        ),
        Expectation(
            "NARRATED_VERIFICATION; claimed verifications exceed invocation records; no live lookup",
            f"failure modes {', '.join(modes) or 'none'}; checked_claims_le_invocations holds={tally}; "
            f"live={_field(run, 'network', 'live')}",
            "NARRATED_VERIFICATION" in modes and tally is False and _field(run, "network", "live") is False,
        ),
    )


def _step_grim(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "numeric/grim-inconsistent", "runs/grim")
    tests = _mappings(_field(_check_of(run, "claim_registry"), "evidence", "consistency", "tests"))
    grim = next((item for item in tests if item.get("test") == "grim"), {})
    nearest = _field(grim, "evidence", "nearest_consistent") or {}
    ratio = _field(grim, "discrimination_ratio") or {}
    return (command,), (
        Expectation(
            "FAIL (SOURCE_MISMATCH), exit 1",
            _status(run, command.exit_code),
            _is_status(run, command.exit_code, "FAIL", "SOURCE_MISMATCH"),
        ),
        Expectation(
            "GRIM: no integer total of 28 ratings has mean 5.19 (INCONSISTENT; nearest consistent 5.18 and 5.21), "
            "and the test could have failed (discrimination above 0)",
            f"mean {_field(grim, 'evidence', 'mean')} of n={_field(grim, 'evidence', 'n')}: {grim.get('outcome')}; "
            f"nearest {nearest.get('below')} and {nearest.get('above')}; discrimination {ratio.get('fraction')}",
            grim.get("outcome") == "INCONSISTENT"
            and (nearest.get("below"), nearest.get("above")) == ("5.18", "5.21")
            and ratio.get("state") == "DEFINED"
            and isinstance(ratio.get("numerator"), int)
            and ratio["numerator"] > 0,
        ),
    )


def _step_narrated_number(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "numeric/narrated", "runs/narrated-number")
    claims = _check_of(run, "claim_registry")
    modes = _field(claims, "failure_modes") or []
    derived = _mappings(_field(claims, "evidence", "narration", "claims"))
    claim = derived[0] if len(derived) == 1 else {}
    return (command,), (
        Expectation(
            "FAIL (SOURCE_MISMATCH), exit 1, with NARRATED_VERIFICATION",
            f"{_status(run, command.exit_code)}; failure modes {', '.join(modes) or 'none'}",
            _is_status(run, command.exit_code, "FAIL", "SOURCE_MISMATCH") and "NARRATED_VERIFICATION" in modes,
        ),
        Expectation(
            "the printed 2.10 reproduces the printed operands (12.35 - 10.25), not the stored ones "
            "(12.346 - 10.254 gives 2.09): NARRATED",
            f"{claim.get('claim_id')} {claim.get('value')}: {claim.get('outcome')}; from printed operands "
            f"{claim.get('from_printed')}, from stored operands {claim.get('from_stored')}",
            claim.get("outcome") == "NARRATED"
            and claim.get("from_printed") == ["2.10"]
            and claim.get("from_stored") == ["2.09"],
        ),
    )


def _step_canary(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "citations/canary-resolved", "runs/canary")
    resolver = _check_of(run, "citation_resolver")
    canary = _field(resolver, "evidence", "canaries", "10.5555") or {}
    totals = _field(resolver, "evidence", "state_totals") or {}
    return (command,), (
        Expectation(
            "FAIL (BLIND_SPOT), exit 1: the captured resolver vouches for a DOI that cannot exist",
            _status(run, command.exit_code),
            _is_status(run, command.exit_code, "FAIL", "BLIND_SPOT"),
        ),
        Expectation(
            "the 10.5555 canary resolved (holds=false), so no DOI under that prefix is reported DOI_RESOLVED",
            f"canary {canary.get('doi')} {canary.get('state')}, holds={canary.get('holds')}; "
            f"DOI_RESOLVED {totals.get('DOI_RESOLVED')}, SOURCE_UNAVAILABLE {totals.get('SOURCE_UNAVAILABLE')}",
            canary.get("holds") is False
            and canary.get("state") == "DOI_RESOLVED"
            and totals.get("DOI_RESOLVED") == 0
            and isinstance(totals.get("SOURCE_UNAVAILABLE"), int)
            and totals["SOURCE_UNAVAILABLE"] >= 1,
        ),
    )


def _step_claim_join(ws: _Workspace) -> _Outcome:
    command, run = _verify(ws, "assertions/five-cases", "runs/claim-join")
    counts = _field(_check_of(run, "claim_join"), "evidence", "counts")
    mirrored = _field(run, "controls", "claim_join")
    shown = ", ".join(f"{name} {_field(counts, name)}" for name in _EXPECTED_CLAIM_JOIN)
    return (command,), (
        Expectation(
            "FAIL (SOURCE_MISMATCH), exit 1: an assertion contradicts the sealed ledger",
            _status(run, command.exit_code),
            _is_status(run, command.exit_code, "FAIL", "SOURCE_MISMATCH"),
        ),
        Expectation(
            "assertions joined to the ledger: BACKED 1, NARRATED 2, CONTRADICTED 1, ORPHANED 1 "
            "(mirrored in run.json controls.claim_join)",
            f"{shown}; controls.claim_join {'matches' if mirrored == counts else 'differs'}",
            counts == _EXPECTED_CLAIM_JOIN and mirrored == _EXPECTED_CLAIM_JOIN,
        ),
    )


# ---------------------------------------------------------------------------
# Step: mutation testing
# ---------------------------------------------------------------------------


def _fired(record: Mapping[str, Any]) -> list[Any]:
    return [item.get("detector") for item in _mappings(record.get("detecting_invariants_fired"))]


def _step_mutation(ws: _Workspace) -> _Outcome:
    command = ws.run("mutate", PurePosixPath(BLIND_SPOT_MANIFEST), "--output", PurePosixPath("mutation"))
    report = ws.json("mutation/mutation-report.json")
    records = _mappings(_field(report, "mutations"))
    blind = tuple(item.get("mutation_id") for item in records if item.get("blind_spot") is True)
    executed = [item for item in records if item.get("execution_state") == "CHECKED"]
    others = [item for item in records if item.get("execution_state") != "CHECKED"]
    detected = _field(report, "detected_mutations")
    counted_apart = (
        bool(others)
        and all(item.get("detected") is None and item.get("blind_spot") is None for item in others)
        and detected == sum(item.get("detected") is True for item in executed)
    )
    forced = _field(report, "forced_detection") or {}
    conservation = _field(report, "conservation") or {}
    generated = conservation.get("generated")
    conserved = (
        all(conservation.get(key) is True for key in ("holds", "generated_holds", "executed_holds", "disjoint"))
        and isinstance(generated, list)
        and sorted(generated) == sorted(item.get("mutation_id") for item in records)
        and len(generated) == _field(report, "generated_mutations")
    )
    plan = next((item for item in records if item.get("mutation_id") == "M21_removed_plan"), {})
    return (command,), (
        Expectation(
            "FAIL (BLIND_SPOT), exit 1",
            _status(report, command.exit_code),
            _is_status(report, command.exit_code, "FAIL", "BLIND_SPOT"),
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
        Expectation(
            "the harness detects its own forced defect M00 (invariant:ledger_chain_intact) before counting; "
            "every generated mutant lands in exactly one bucket and the conservation identities hold",
            f"M00 detected={forced.get('detected')} by {forced.get('detector')}; {len(generated or [])} generated "
            f"(generated_mutations {_field(report, 'generated_mutations')}); conservation holds="
            f"{conservation.get('holds')}, disjoint={conservation.get('disjoint')}",
            forced.get("detected") is True and forced.get("detector") == "invariant:ledger_chain_intact" and conserved,
        ),
        Expectation(
            "M21_removed_plan (PLAN entry removed, ledger resealed) is DETECTED by invariant:plan_closure",
            f"M21_removed_plan {plan.get('status')}; fired {', '.join(str(item) for item in _fired(plan)) or 'none'}",
            plan.get("status") == "DETECTED" and "invariant:plan_closure" in _fired(plan),
        ),
    )


# ---------------------------------------------------------------------------
# Steps: dependency currency
# ---------------------------------------------------------------------------


def _graph_report(ws: _Workspace, graph_dir: str, name: str) -> Any:
    return ws.json(f"{graph_dir}/graph/{name}")


def _node(report: Any, node_id: str) -> Any:
    found = [item for item in _mappings(_field(report, "nodes")) if item.get("id") == node_id]
    return found[0] if found else None


def _graph_command(ws: _Workspace, command: str) -> CommandOutcome:
    return ws.run(command, _DESIGN_NODE, "--manifest", PurePosixPath(f"{_DEPENDENCIES}/manifest.json"))


def _step_impact(ws: _Workspace) -> _Outcome:
    command = _graph_command(ws, "impact")
    report = _graph_report(ws, _DEPENDENCIES, "impact-report.json")
    blocked = _field(report, "publication_block", "blocked")
    reached = [item.get("id") for item in _mappings(_field(report, "impact", "descendants"))]
    publication = _field(_node(report, _PUBLICATION_NODE), "validity")
    return (command,), (
        Expectation(
            "FAIL, exit 1: publication blocked",
            f"{_status(report, command.exit_code)}; publication blocked={blocked}",
            _field(report, "status") == "FAIL" and command.exit_code == 1 and blocked is True,
        ),
        Expectation(
            f"descendants marked {_STALE}, {_PUBLICATION_NODE} among them",
            f"{len(reached)} descendant(s) reached; {_PUBLICATION_NODE} is {publication}",
            _PUBLICATION_NODE in reached and publication == _STALE,
        ),
    )


def _revalidation(ws: _Workspace, graph_dir: str) -> tuple[Any, Any, list[Any]]:
    """The last revalidation report written under ``graph_dir``: the report, its outcome and what it cleared."""
    report = _graph_report(ws, graph_dir, "revalidation-report.json")
    action = _field(report, "revalidate")
    cleared = [item.get("id") for item in _mappings(_field(action, "cleared"))]
    return report, _field(action, "outcome"), cleared


def _step_revalidate_unchanged(ws: _Workspace) -> _Outcome:
    command = _graph_command(ws, "revalidate")
    report, outcome, cleared = _revalidation(ws, _DEPENDENCIES)
    publication = _field(_node(report, _PUBLICATION_NODE), "validity")
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
    report, outcome, cleared = _revalidation(ws, _DEPENDENCIES)
    publication = _field(_node(report, _PUBLICATION_NODE), "validity")
    return (command,), (
        Expectation(
            f"REVALIDATED_CHANGED; {_PUBLICATION_NODE} stays {_STALE}; FAIL, exit 1",
            f"{outcome}; cleared {', '.join(cleared) or 'nothing'}; {_PUBLICATION_NODE} is {publication}; "
            f"{_status(report, command.exit_code)}",
            outcome == "REVALIDATED_CHANGED" and not cleared and publication == _STALE and command.exit_code == 1,
        ),
    )


def _write_witness(ws: _Workspace, relpath: str, offset: timedelta) -> None:
    """Write a synthetic recompute witness for analysis-run, timed ``offset`` from its recorded change.

    The change is the last transition that made the node pending, as the
    ``impact`` command recorded it in graph-state.json; refused cutoffs are
    not changes. The parent and output digests come from the committed
    witness, which binds the fixture as recorded, so the only thing that
    differs between an accepted and a refused witness is whether the
    recompute started after the change. The invocation id is a content hash
    (D11). Raises ValueError when no change is recorded, which fails the step.
    """
    history = _mappings(_field(ws.json(f"{_WITNESSED}/graph/graph-state.json"), "nodes", _DERIVED_NODE, "history"))
    changes = [item for item in history if item.get("to") == _STALE and item.get("from") != item.get("to")]
    template = ws.json(_WITNESS_TEMPLATE)
    if not changes or not isinstance(template, Mapping):
        raise ValueError(f"no recorded change of {_DERIVED_NODE} or no witness template to time a recompute against")
    moment = format_utc(parse_utc(changes[-1]["at"]) + offset)
    label = f"synthetic recompute of {_DERIVED_NODE} by science-gate demo at {moment}"
    document = dict(
        template,
        invocation_id="inv-" + sha256_bytes(label.encode("utf-8"))[:12],
        started_at=moment,
        completed_at=moment,
    )
    ws.write(relpath, pretty_json_bytes(document))


def _step_witnessed(ws: _Workspace) -> _Outcome:
    """A derived artifact is cleared only by a recompute that followed its change (decision D6)."""
    manifest = PurePosixPath(f"{_WITNESSED}/manifest.json")
    impact = ws.run("impact", _DERIVED_NODE, "--manifest", manifest)
    bare = ws.run("revalidate", _DERIVED_NODE, "--manifest", manifest)
    report, outcome, _ = _revalidation(ws, _WITNESSED)
    modes = {mode for item in _mappings(_field(report, "findings")) for mode in item.get("failure_modes") or ()}
    pending = {node: _field(_node(report, node), "validity") for node in (_DERIVED_NODE, _PUBLICATION_NODE)}

    _write_witness(ws, _PREDATING_WITNESS, -timedelta(seconds=1))
    stale = ws.run("revalidate", _DERIVED_NODE, "--manifest", manifest, "--witness", PurePosixPath(_PREDATING_WITNESS))
    stale_report, stale_outcome, _ = _revalidation(ws, _WITNESSED)
    problems = _field(stale_report, "revalidate", "witness", "problems") or []

    _write_witness(ws, _FRESH_WITNESS, timedelta(seconds=1))
    fresh = ws.run("revalidate", _DERIVED_NODE, "--manifest", manifest, "--witness", PurePosixPath(_FRESH_WITNESS))
    fresh_report, fresh_outcome, cleared = _revalidation(ws, _WITNESSED)
    publication = _field(_node(fresh_report, _PUBLICATION_NODE), "validity")
    return (impact, bare, stale, fresh), (
        Expectation(
            f"after an upstream change, re-hashing the untouched derived node {_DERIVED_NODE} is refused: "
            f"REFUSED_VACUOUS_CUTOFF (VACUOUS_CUTOFF); it and {_PUBLICATION_NODE} stay {_STALE}; FAIL, exit 1",
            f"impact exit {impact.exit_code}; {outcome}; {_DERIVED_NODE} is {pending[_DERIVED_NODE]}, "
            f"{_PUBLICATION_NODE} is {pending[_PUBLICATION_NODE]}; {_status(report, bare.exit_code)}",
            impact.exit_code == 1
            and outcome == "REFUSED_VACUOUS_CUTOFF"
            and "VACUOUS_CUTOFF" in modes
            and pending == {_DERIVED_NODE: _STALE, _PUBLICATION_NODE: _STALE}
            and bare.exit_code == 1,
        ),
        Expectation(
            "a recompute witness that started before the change is refused: REFUSED_INVALID_WITNESS "
            "(WITNESS_PREDATES_CHANGE); FAIL, exit 1",
            f"{stale_outcome}; problems: {'; '.join(str(item).split(':', 1)[0] for item in problems) or 'none'}; "
            f"exit {stale.exit_code}",
            stale_outcome == "REFUSED_INVALID_WITNESS"
            and len(problems) == 1
            and str(problems[0]).startswith("WITNESS_PREDATES_CHANGE")
            and stale.exit_code == 1,
        ),
        Expectation(
            "a recompute witness that started after the change and binds both parents and the output: "
            f"REVALIDATED_UNCHANGED; early cutoff clears {', '.join(_BELOW_DERIVED)}; PASS, exit 0",
            f"{fresh_outcome}; cleared {', '.join(str(item) for item in cleared) or 'nothing'}; "
            f"{_PUBLICATION_NODE} is {publication}; {_status(fresh_report, fresh.exit_code)}",
            fresh_outcome == "REVALIDATED_UNCHANGED"
            and sorted(cleared) == sorted(_BELOW_DERIVED)
            and publication == "CURRENT"
            and fresh.exit_code == 0,
        ),
    )


# ---------------------------------------------------------------------------
# Step: packaging
# ---------------------------------------------------------------------------


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
    files = _mappings(_field(index, "files"))
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
    ("falsifier witnesses and canary", _step_witnesses),
    ("execution plan", _step_plan),
    ("re-verify the run directory", _step_report),
    ("empty input", _step_empty),
    ("narrated verification", _step_narrated),
    ("GRIM inconsistency", _step_grim),
    ("narrated number", _step_narrated_number),
    ("resolver canary", _step_canary),
    ("claim join", _step_claim_join),
    ("mutation testing", _step_mutation),
    ("upstream change", _step_impact),
    ("revalidate, file unchanged", _step_revalidate_unchanged),
    ("revalidate, file changed", _step_revalidate_changed),
    ("witnessed revalidation", _step_witnessed),
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
        "runs/grim",
        "runs/narrated-number",
        "runs/canary",
        "runs/claim-join",
        "mutation",
        f"{_DEPENDENCIES}/graph",
        f"{_WITNESSED}/graph",
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
