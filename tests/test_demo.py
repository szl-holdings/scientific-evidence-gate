"""The self-checking demo, the bundled resources it relies on, and their packaging.

The full demo runs once for the module (it executes every command against
copies of the fixtures, including a mutation suite). The rules that decide
its exit code are tested on hand-built results, so a failing expectation is
proven to fail the demo without running it twice. The steps that only read
what earlier commands wrote (falsifier witnesses, the canary pair, the PLAN)
are re-run on tampered copies of that output, so each of their expectations
is shown to be able to fail.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate import _resources, demo
from science_gate.demo import (
    DEMO_FIXTURES,
    EXPECTED_BLIND_SPOTS,
    SUMMARY_JSON,
    SUMMARY_MD,
    SUMMARY_SCHEMA,
    CommandOutcome,
    DemoResult,
    Expectation,
    StepResult,
    cli_demo,
    render_table,
)
from science_gate.packaging import SOURCE_SCHEMAS_DIR


def setUpModule() -> None:
    global DEMO_ROOT, DEMO_EXIT, DEMO_PRINTED
    DEMO_ROOT = Path(tempfile.mkdtemp(prefix="science-gate-test-demo-")).resolve()
    unittest.addModuleCleanup(shutil.rmtree, DEMO_ROOT, ignore_errors=True)
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        DEMO_EXIT = cli_demo(argparse.Namespace(output=str(DEMO_ROOT / "demo")))
    DEMO_PRINTED = printed.getvalue()


DEMO_ROOT: Path
DEMO_EXIT: int
DEMO_PRINTED: str

#: Every expectation the demo writes down in advance (ARCHITECTURE.md 18.11, extended by section 17).
EXPECTATIONS = 31
#: The steps that exercise section 17 (the frontier extensions), by name.
FRONTIER_STEPS = (
    "falsifier witnesses and canary",
    "execution plan",
    "GRIM inconsistency",
    "narrated number",
    "resolver canary",
    "claim join",
    "mutation testing",
    "witnessed revalidation",
)


class DemoRunTests(unittest.TestCase):
    """What the one module-level demo run printed and wrote."""

    def test_every_expectation_holds_and_the_demo_exits_0(self) -> None:
        self.assertEqual(DEMO_EXIT, 0, DEMO_PRINTED)
        self.assertTrue(DEMO_PRINTED.startswith(f"OK demo: all {EXPECTATIONS} expectations held"), DEMO_PRINTED)
        self.assertIn("verifies nothing scientific", DEMO_PRINTED.splitlines()[0])

    def test_the_headline_comes_first_then_paths_then_the_table(self) -> None:
        lines = DEMO_PRINTED.splitlines()
        blank = lines.index("")
        paths = [Path(line) for line in lines[1:blank]]
        self.assertEqual(paths[:2], [DEMO_ROOT / "demo" / SUMMARY_JSON, DEMO_ROOT / "demo" / SUMMARY_MD])
        self.assertTrue(all(path.exists() for path in paths))
        self.assertEqual(lines[blank + 1], "| # | step | expected | actual | holds |")
        rows = lines[blank + 3 :]
        self.assertEqual(len(rows), EXPECTATIONS)
        self.assertTrue(all(row.endswith("| yes |") for row in rows), rows)

    def test_the_summary_records_every_command_and_expectation(self) -> None:
        summary = json.loads((DEMO_ROOT / "demo" / SUMMARY_JSON).read_text(encoding="utf-8"))
        self.assertEqual((summary["schema"], summary["holds"], summary["exit_code"]), (SUMMARY_SCHEMA, True, 0))
        self.assertEqual((summary["expectations_total"], summary["expectations_held"]), (EXPECTATIONS, EXPECTATIONS))
        commands = [item["command"] for step in summary["steps"] for item in step["commands"]]
        for name in ("verify", "report", "mutate", "impact", "revalidate", "package"):
            with self.subTest(command=name):
                self.assertTrue(any(command.startswith(f"science-gate {name} ") for command in commands), commands)
        self.assertNotIn(str(DEMO_ROOT), json.dumps(summary), "commands are shown relative to the output")
        self.assertIn("science-gate revalidate analysis-run", " ".join(commands))
        self.assertTrue(any("--witness" in command for command in commands), "a recompute witness was offered")

    def test_every_frontier_step_ran_and_held(self) -> None:
        summary = json.loads((DEMO_ROOT / "demo" / SUMMARY_JSON).read_text(encoding="utf-8"))
        steps = {step["step"]: step for step in summary["steps"]}
        for name in FRONTIER_STEPS:
            with self.subTest(step=name):
                self.assertIn(name, steps)
                self.assertTrue(steps[name]["expectations"])
                self.assertTrue(all(item["holds"] for item in steps[name]["expectations"]))

    def test_every_step_wrote_its_evidence_inside_the_output(self) -> None:
        root = DEMO_ROOT / "demo"
        for relpath in (
            "runs/valid/receipt.json",
            "runs/valid/receipt.auth.json",
            "runs/empty/run.json",
            "runs/grim/run.json",
            "runs/narrated-number/run.json",
            "runs/canary/run.json",
            "runs/claim-join/run.json",
            "runs/narrated/report.md",
            "mutation/mutation-report.html",
            "fixtures/dependencies/current/graph/graph-state.json",
            "fixtures/dependencies/current/graph/revalidation-report.json",
            "fixtures/dependencies/witnessed/graph/graph-state.json",
            "fixtures/dependencies/witnessed/witnesses/demo-recompute-after-change.json",
            "package/package.json",
        ):
            with self.subTest(file=relpath):
                self.assertTrue((root / relpath).is_file())
        written = {path.relative_to(DEMO_ROOT).parts[0] for path in DEMO_ROOT.rglob("*")}
        self.assertEqual(written, {"demo"})

    def test_the_mutation_step_shows_detections_and_both_expected_blind_spots(self) -> None:
        report = json.loads((DEMO_ROOT / "demo" / "mutation" / "mutation-report.json").read_text(encoding="utf-8"))
        blind = tuple(item["mutation_id"] for item in report["mutations"] if item["blind_spot"] is True)
        self.assertEqual(blind, EXPECTED_BLIND_SPOTS)
        self.assertGreater(report["detected_mutations"], 0)

    def test_the_bundled_fixtures_were_only_read(self) -> None:
        source = _resources.bundled_dir("fixtures")
        protocol = (source / "dependencies" / "current" / "design" / "protocol.md").read_bytes()
        self.assertNotIn(b"Synthetic amendment made by science-gate demo", protocol)
        self.assertFalse((source / "dependencies" / "current" / "graph" / "graph-state.json").exists())
        witnessed = source / "dependencies" / "witnessed"
        self.assertFalse((witnessed / "graph" / "graph-state.json").exists())
        self.assertEqual(sorted(path.name for path in (witnessed / "witnesses").iterdir()),
                         ["analysis-run-before-change.json", "analysis-run-recomputed.json"])


class DemoReadingStepTests(TempDirTestCase):
    """The steps that judge the valid run's own evidence, re-run on tampered copies of what the demo wrote."""

    def setUp(self) -> None:
        super().setUp()
        shutil.copytree(DEMO_ROOT / "demo" / "runs" / "valid", self.tmp / "runs" / "valid")
        self.ws = demo._Workspace(self.tmp)

    def edit_run(self, change: Callable[[dict[str, Any]], None]) -> None:
        path = self.tmp / "runs" / "valid" / "run.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        change(document)
        path.write_text(json.dumps(document), encoding="utf-8")

    def holds(self, step: Callable[[Any], tuple[Any, tuple[Expectation, ...]]]) -> list[bool]:
        _, expectations = step(self.ws)
        return [item.holds for item in expectations]

    def test_the_untouched_output_holds(self) -> None:
        self.assertEqual(self.holds(demo._step_witnesses), [True, True])
        self.assertEqual(self.holds(demo._step_plan), [True])

    def test_one_unwitnessed_pass_fails_the_witness_expectation(self) -> None:
        def unwitness(document: dict[str, Any]) -> None:
            evidence = document["checks"][0]["evidence"]
            evidence["falsification"] = "UNWITNESSED"
        self.edit_run(unwitness)
        self.assertEqual(self.holds(demo._step_witnesses), [False, True])

    def test_a_rejection_that_is_only_narrated_fails_the_witness_expectation(self) -> None:
        def accept(document: dict[str, Any]) -> None:
            for item in document["checks"][-1]["evidence"]["falsifiers"]:
                item["outcome"] = "ACCEPTED"
        self.edit_run(accept)
        self.assertEqual(self.holds(demo._step_witnesses), [False, True])

    def test_a_canary_that_did_not_fail_fails_the_canary_expectation(self) -> None:
        def silence(document: dict[str, Any]) -> None:
            document["controls"]["canary"]["must_fail"]["verdict"] = "PASS"
        self.edit_run(silence)
        self.assertEqual(self.holds(demo._step_witnesses), [True, False])

    def test_a_ledger_that_does_not_open_with_the_plan_fails_the_plan_expectation(self) -> None:
        ledger = self.tmp / "runs" / "valid" / "ledger.jsonl"
        lines = ledger.read_bytes().splitlines(keepends=True)
        ledger.write_bytes(b"".join(lines[1:]))
        self.assertEqual(self.holds(demo._step_plan), [False])

    def test_a_violated_plan_closure_fails_the_plan_expectation(self) -> None:
        def violate(document: dict[str, Any]) -> None:
            for item in document["invariants"]:
                if item["name"] == "plan_closure":
                    item["holds"] = False
        self.edit_run(violate)
        self.assertEqual(self.holds(demo._step_plan), [False])

    def test_missing_output_never_holds(self) -> None:
        empty = demo._Workspace(self.tmp / "nothing-here")
        self.assertEqual([item.holds for item in demo._step_witnesses(empty)[1]], [False, False])
        self.assertEqual([item.holds for item in demo._step_plan(empty)[1]], [False])


class DemoRuleTests(TempDirTestCase):
    """The exit-code rules, on hand-built results."""

    def result(self, *holds: bool) -> DemoResult:
        command = CommandOutcome(("verify", "x"), 0, "PASS (VERIFIED) run-synthetic")
        steps = tuple(
            StepResult(f"step-{index}", (command,), (Expectation("expected", "actual", held),))
            for index, held in enumerate(holds)
        )
        return DemoResult(self.tmp, steps)

    def test_one_expectation_that_does_not_hold_fails_the_demo(self) -> None:
        result = self.result(True, False, True)
        self.assertEqual((result.holds, result.exit_code, result.failed_steps), (False, 1, ("step-1",)))
        self.assertTrue(result.headline.startswith("FAIL demo: 1 of 3 expectations did not hold (steps: step-1)"))
        self.assertTrue(render_table(result)[3].endswith("| NO |"))

    def test_a_demo_with_no_expectation_does_not_hold(self) -> None:
        self.assertEqual(DemoResult(self.tmp, ()).exit_code, 1)

    def test_a_step_that_raises_becomes_a_failed_expectation(self) -> None:
        def broken(ws: object) -> object:
            raise RuntimeError("synthetic step failure")

        step = demo._guarded("broken step", broken, demo._Workspace(self.tmp))
        (expectation,) = step.expectations
        self.assertFalse(expectation.holds)
        self.assertIn("RuntimeError: synthetic step failure", expectation.actual)

    def test_a_non_empty_output_is_refused_with_exit_3_and_left_untouched(self) -> None:
        keep = self.write("busy/keep.txt", "an unrelated file")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = cli_demo(argparse.Namespace(output=str(self.tmp / "busy")))
        self.assertEqual(code, 3)
        self.assertTrue(printed.getvalue().startswith("ERROR demo: "), printed.getvalue())
        self.assertEqual([path.name for path in (self.tmp / "busy").iterdir()], [keep.name])

    def test_missing_bundled_fixtures_are_an_error_not_an_empty_demo(self) -> None:
        printed = io.StringIO()
        with mock.patch.object(demo, "bundled_dir", return_value=None), contextlib.redirect_stdout(printed):
            code = cli_demo(argparse.Namespace(output=str(self.tmp / "out")))
        self.assertEqual(code, 3)
        self.assertIn("bundled fixtures were not found", printed.getvalue())


class BundledResourceTests(TempDirTestCase):
    def test_a_source_checkout_finds_the_repository_directories(self) -> None:
        self.assertEqual(_resources.bundled_dir("fixtures"), REPO_ROOT / "fixtures")
        self.assertEqual(_resources.bundled_dir("schemas"), REPO_ROOT / "schemas")
        self.assertEqual(SOURCE_SCHEMAS_DIR, REPO_ROOT / "schemas")

    def test_an_installed_layout_is_preferred(self) -> None:
        package = self.tmp / "site-packages" / "science_gate"
        (package / "_fixtures").mkdir(parents=True)
        with mock.patch.object(_resources, "_PACKAGE_DIR", package):
            self.assertEqual(_resources.bundled_dir("fixtures"), package / "_fixtures")
            self.assertIsNone(_resources.bundled_dir("schemas"), "no checkout above an installed package")

    def test_pyproject_ships_the_fixtures_and_schemas_as_package_data(self) -> None:
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
        for name, (subpackage, directory) in _resources.BUNDLED.items():
            with self.subTest(resource=name):
                dotted = f"science_gate.{subpackage}"
                self.assertIn(dotted, config["packages"])
                self.assertEqual(config["package-dir"][dotted], directory)
                self.assertIn(dotted, config["package-data"])
        self.assertEqual(config["package-data"]["science_gate._fixtures"], ["**/*"])
        self.assertIs(config["include-package-data"], False)

    def test_every_demo_fixture_exists(self) -> None:
        for fixture in DEMO_FIXTURES:
            with self.subTest(fixture=fixture):
                self.assertTrue((REPO_ROOT / "fixtures" / fixture / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
