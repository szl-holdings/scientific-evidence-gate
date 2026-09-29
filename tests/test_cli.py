"""The command line: exit codes, headlines, subcommands and determinism (section 14).

The CLI runs as a subprocess with a list of arguments, never through a shell,
exactly as a user or CI job would run it.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, SRC_DIR, TempDirTestCase
from _project import EMPTY_MANIFEST, REVIEWERS, TIME_EVENT, VALID_MANIFEST, check, reviews_document, time_document

from science_gate import cli
from science_gate.cli import LAZY_COMMANDS, scaffold_project
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.reports import LEDGER_JSONL, RUN_FILES, RUN_JSON
from science_gate.verifier import resolve_check

#: Arguments the stand-in lazy commands below received, for inspection.
RECEIVED: list[argparse.Namespace] = []


def returns_abstain(args: argparse.Namespace) -> int:
    RECEIVED.append(args)
    print("ABSTAIN stand-in: synthetic")
    return 2


def not_implemented(args: argparse.Namespace) -> int:
    raise NotImplementedError("synthetic stand-in")


def returns_bool(args: argparse.Namespace) -> Any:
    return True


def returns_seven(args: argparse.Namespace) -> int:
    return 7


class CliTestCase(TempDirTestCase):
    def run_cli(self, *args: str, cwd: Path | None = None, **env: str) -> subprocess.CompletedProcess[str]:
        """Run ``python -m science_gate.cli`` with a pinned clock and no signing key."""
        hidden = (HMAC_KEY_FILE_ENV, "PYTHONHASHSEED")
        environment = {key: value for key, value in os.environ.items() if key not in hidden}
        environment.update(
            {"PYTHONPATH": str(SRC_DIR), "PYTHONDONTWRITEBYTECODE": "1", "SCIENCE_GATE_FIXED_TIME": FIXED_TIME}
        )
        environment.update(env)
        return subprocess.run(
            [sys.executable, "-m", "science_gate.cli", *args],
            cwd=cwd or self.tmp,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def lines(self, completed: subprocess.CompletedProcess[str]) -> list[str]:
        return completed.stdout.splitlines()

    def assert_headline_then_paths(self, completed: subprocess.CompletedProcess[str], status: str) -> list[Path]:
        """Every command prints a one-line status headline first, then the paths it wrote."""
        headline, *paths = self.lines(completed)
        self.assertTrue(headline.startswith(status), headline)
        written = [Path(line) for line in paths]
        self.assertTrue(written)
        self.assertTrue(all(path.is_file() for path in written), paths)
        return written


class VerifyCommandTests(CliTestCase):
    def test_valid_fixture_exits_0_with_headline_and_paths(self) -> None:
        completed = self.run_cli("verify", str(VALID_MANIFEST), "--output", str(self.tmp / "run"))
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        written = self.assert_headline_then_paths(completed, "PASS (VERIFIED) run-")
        self.assertEqual([path.name for path in written][:6], list(RUN_FILES[:6]))

    def test_empty_fixture_exits_2(self) -> None:
        # Requirement 1.
        completed = self.run_cli("verify", str(EMPTY_MANIFEST), "--output", str(self.tmp / "run"))
        self.assertEqual(completed.returncode, 2)
        self.assert_headline_then_paths(completed, "ABSTAIN (INSUFFICIENT_EVIDENCE) run-")

    def test_default_output_is_under_the_working_directory(self) -> None:
        completed = self.run_cli("verify", str(VALID_MANIFEST))
        run_id = self.lines(completed)[0].split()[2].rstrip(":")
        self.assertTrue((self.tmp / "science-gate-runs" / run_id / RUN_JSON).is_file())

    def test_invalid_manifest_exits_3_and_still_records_the_run(self) -> None:
        manifest = self.write("manifest.json", "{not json")
        completed = self.run_cli("verify", str(manifest), "--output", str(self.tmp / "run"))
        self.assertEqual(completed.returncode, 3)
        self.assert_headline_then_paths(completed, "ERROR (PROTOCOL_BROKEN) run-")
        self.assertEqual(json.loads((self.tmp / "run" / RUN_JSON).read_text(encoding="utf-8"))["status"], "ERROR")

    def test_live_flag_is_recorded(self) -> None:
        completed = self.run_cli("verify", str(VALID_MANIFEST), "--output", str(self.tmp / "run"), "--live")
        self.assertEqual(completed.returncode, 0)
        document = json.loads((self.tmp / "run" / RUN_JSON).read_text(encoding="utf-8"))
        self.assertTrue(document["network"]["live"])

    def test_unwritable_output_is_an_error_not_a_traceback(self) -> None:
        blocker = self.write("occupied", "a file where the run directory should go")
        completed = self.run_cli("verify", str(VALID_MANIFEST), "--output", str(blocker))
        self.assertEqual(completed.returncode, 3)
        self.assertTrue(completed.stdout.startswith("ERROR verify: the PASS result could not be written"))
        self.assertNotIn("Traceback", completed.stderr)


class UsageTests(CliTestCase):
    def test_argument_errors_exit_3_never_2(self) -> None:
        cases = (
            (),
            ("frobnicate",),
            ("verify",),
            ("verify", "manifest.json", "--bogus"),
            ("impact", "artifact-1"),
            ("package", "manifest.json"),
            ("report",),
        )
        for args in cases:
            with self.subTest(args=args):
                completed = self.run_cli(*args)
                self.assertEqual(completed.returncode, 3, completed.stderr)
                self.assertTrue(completed.stderr.startswith("ERROR usage: "), completed.stderr)
                self.assertEqual(completed.stdout, "")

    def test_help_and_version_exit_0(self) -> None:
        self.assertEqual(self.run_cli("--help").returncode, 0)
        version = self.run_cli("--version")
        self.assertEqual(version.returncode, 0)
        self.assertTrue(version.stdout.startswith("science-gate "))


class ReportCommandTests(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.run_dir = self.tmp / "run"
        self.assertEqual(self.run_cli("verify", str(VALID_MANIFEST), "--output", str(self.run_dir)).returncode, 0)

    def test_intact_run_re_verifies_with_the_recorded_exit_code(self) -> None:
        completed = self.run_cli("report", str(self.run_dir))
        self.assertEqual(completed.returncode, 0)
        self.assert_headline_then_paths(completed, "PASS (VERIFIED) run-")
        self.assertIn("recorded run re-verified", self.lines(completed)[0])

    def test_tampered_ledger_exits_3(self) -> None:
        ledger = self.run_dir / LEDGER_JSONL
        ledger.write_bytes(b"".join(ledger.read_bytes().splitlines(keepends=True)[:-2]))
        completed = self.run_cli("report", str(self.run_dir))
        self.assertEqual(completed.returncode, 3)
        self.assert_headline_then_paths(completed, "ERROR (PROTOCOL_BROKEN) run-")

    def test_missing_run_directory_exits_3_without_creating_it(self) -> None:
        missing = self.tmp / "no-such-run"
        completed = self.run_cli("report", str(missing))
        self.assertEqual(completed.returncode, 3)
        self.assertFalse(missing.exists())


class InitCommandTests(CliTestCase):
    def test_init_writes_a_project_that_verifies(self) -> None:
        completed = self.run_cli("init", "starter")
        self.assertEqual(completed.returncode, 0)
        self.assert_headline_then_paths(completed, "OK init:")
        verified = self.run_cli("verify", str(self.tmp / "starter" / "manifest.json"), "--output", "run")
        self.assertEqual(verified.returncode, 0, verified.stdout)

    def test_valid_fixture_is_the_init_template(self) -> None:
        # The committed fixture and the scaffold must not drift apart: both are the reference PASS project.
        written = scaffold_project(self.tmp / "starter")
        fixture = VALID_MANIFEST.parent
        for path in written:
            relpath = path.relative_to(self.tmp / "starter")
            with self.subTest(file=relpath.as_posix()):
                self.assertEqual(path.read_bytes(), (fixture / relpath).read_bytes())
        self.assertEqual(
            sorted(item.relative_to(fixture) for item in fixture.rglob("*") if item.is_file()),
            sorted(path.relative_to(self.tmp / "starter") for path in written),
        )

    def test_init_refuses_to_overwrite(self) -> None:
        existing = self.write("starter/notes.txt", "keep me")
        completed = self.run_cli("init", "starter")
        self.assertEqual(completed.returncode, 3)
        self.assertTrue(completed.stdout.startswith("ERROR init:"))
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep me")
        self.assertFalse((self.tmp / "starter" / "manifest.json").exists())


class DeterminismTests(CliTestCase):
    def test_output_is_byte_identical_under_different_hash_seeds(self) -> None:
        # Requirement 13, over a run with findings, role documents and a missing input.
        project = self.tmp / "project"
        scaffold_project(project)
        (project / "reviews").mkdir()
        (project / "reviews" / "verdicts.json").write_text(json.dumps(reviews_document("reviewer-a")), encoding="utf-8")
        (project / "time").mkdir()
        (project / "time" / "events.json").write_text(json.dumps(time_document(TIME_EVENT)), encoding="utf-8")
        document = json.loads((project / "manifest.json").read_text(encoding="utf-8"))
        document["inputs"].append({"id": "protocol", "path": "data/protocol.csv", "format": "csv", "required": False})
        document["reviews"] = {"required_reviewers": REVIEWERS, "verdicts": "reviews/verdicts.json"}
        document["time_sources"] = "time/events.json"
        document["checks"].append(check("reviews", "reviewer_protocol", inputs=()))
        document["checks"].append(check("time", "time_source", inputs=()))
        manifest = project / "manifest.json"
        manifest.write_text(json.dumps(document), encoding="utf-8")

        outputs = {}
        for seed in ("0", "4242"):
            out = self.tmp / f"run-{seed}"
            completed = self.run_cli("verify", str(manifest), "--output", str(out), PYTHONHASHSEED=seed)
            self.assertEqual(completed.returncode, 2, completed.stdout)
            outputs[seed] = {path.name: path.read_bytes() for path in sorted(out.iterdir())}
        self.assertEqual(sorted(outputs["0"]), sorted(outputs["4242"]))
        for name in outputs["0"]:
            with self.subTest(file=name):
                self.assertEqual(outputs["0"][name], outputs["4242"][name])


class LazyCommandTests(unittest.TestCase):
    """Commands owned by other modules, dispatched in-process with stand-ins."""

    def invoke(self, targets: dict[str, str], *argv: str) -> tuple[int, str]:
        stdout = io.StringIO()
        with mock.patch.object(cli, "LAZY_COMMANDS", targets), contextlib.redirect_stdout(stdout):
            code = cli.main(list(argv))
        return code, stdout.getvalue()

    def test_every_lazy_command_resolves_to_a_function(self) -> None:
        self.assertEqual(set(LAZY_COMMANDS), {"mutate", "impact", "revalidate", "package", "demo"})
        for command, target in LAZY_COMMANDS.items():
            with self.subTest(command=command):
                self.assertTrue(callable(resolve_check(target)))

    def test_exit_code_and_arguments_pass_through(self) -> None:
        RECEIVED.clear()
        argv = ("package", "m.json", "--output", "out", "--force")
        code, output = self.invoke({"package": f"{__name__}:returns_abstain"}, *argv)
        self.assertEqual((code, output), (2, "ABSTAIN stand-in: synthetic\n"))
        (args,) = RECEIVED
        self.assertEqual((args.manifest, args.output, args.force), ("m.json", "out", True))

    def test_unavailable_or_misbehaving_commands_exit_3(self) -> None:
        cases = {
            "science_gate.no_such_module:cli_demo": "is not installed in this build",
            f"{__name__}:no_such_function": "does not provide no_such_function()",
            f"{__name__}:not_implemented": "not implemented yet (synthetic stand-in)",
            f"{__name__}:returns_bool": "returned True, not an exit code",
            f"{__name__}:returns_seven": "returned 7, not an exit code",
        }
        for target, message in cases.items():
            with self.subTest(target=target):
                code, output = self.invoke({"demo": target}, "demo")
                self.assertEqual(code, 3)
                self.assertTrue(output.startswith("ERROR demo: "), output)
                self.assertIn(message, output)

    def test_an_internal_error_is_exit_3_without_a_traceback(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(cli, "verify", side_effect=RuntimeError("synthetic engine defect")):
            with contextlib.redirect_stdout(stdout):
                code = cli.main(["verify", str(VALID_MANIFEST)])
        self.assertEqual(code, 3)
        self.assertEqual(stdout.getvalue(), "ERROR verify: internal error (RuntimeError: synthetic engine defect)\n")


if __name__ == "__main__":
    unittest.main()
