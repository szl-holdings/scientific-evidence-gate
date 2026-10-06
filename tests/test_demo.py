"""The self-checking demo, the bundled resources it relies on, and their packaging.

The full demo runs once for the module (it executes every command against
copies of the fixtures, including a mutation suite). The rules that decide
its exit code are tested on hand-built results, so a failing expectation is
proven to fail the demo without running it twice.
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


class DemoRunTests(unittest.TestCase):
    """What the one module-level demo run printed and wrote."""

    def test_every_expectation_holds_and_the_demo_exits_0(self) -> None:
        self.assertEqual(DEMO_EXIT, 0, DEMO_PRINTED)
        self.assertTrue(DEMO_PRINTED.startswith("OK demo: all 15 expectations held"), DEMO_PRINTED)
        self.assertIn("verifies nothing scientific", DEMO_PRINTED.splitlines()[0])

    def test_the_headline_comes_first_then_paths_then_the_table(self) -> None:
        lines = DEMO_PRINTED.splitlines()
        blank = lines.index("")
        paths = [Path(line) for line in lines[1:blank]]
        self.assertEqual(paths[:2], [DEMO_ROOT / "demo" / SUMMARY_JSON, DEMO_ROOT / "demo" / SUMMARY_MD])
        self.assertTrue(all(path.exists() for path in paths))
        self.assertEqual(lines[blank + 1], "| # | step | expected | actual | holds |")
        rows = lines[blank + 3 :]
        self.assertEqual(len(rows), 15)
        self.assertTrue(all(row.endswith("| yes |") for row in rows), rows)

    def test_the_summary_records_every_command_and_expectation(self) -> None:
        summary = json.loads((DEMO_ROOT / "demo" / SUMMARY_JSON).read_text(encoding="utf-8"))
        self.assertEqual((summary["schema"], summary["holds"], summary["exit_code"]), (SUMMARY_SCHEMA, True, 0))
        self.assertEqual((summary["expectations_total"], summary["expectations_held"]), (15, 15))
        commands = [item["command"] for step in summary["steps"] for item in step["commands"]]
        for name in ("verify", "report", "mutate", "impact", "revalidate", "package"):
            with self.subTest(command=name):
                self.assertTrue(any(command.startswith(f"science-gate {name} ") for command in commands), commands)
        self.assertNotIn(str(DEMO_ROOT), json.dumps(summary), "commands are shown relative to the output")

    def test_every_step_wrote_its_evidence_inside_the_output(self) -> None:
        root = DEMO_ROOT / "demo"
        for relpath in (
            "runs/valid/receipt.json",
            "runs/empty/run.json",
            "runs/narrated/report.md",
            "mutation/mutation-report.html",
            "fixtures/dependencies/current/graph/graph-state.json",
            "fixtures/dependencies/current/graph/revalidation-report.json",
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
