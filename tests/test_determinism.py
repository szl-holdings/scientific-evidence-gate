"""Determinism (ARCHITECTURE.md section 16).

Each command runs twice as a separate process, once with
``PYTHONHASHSEED=0`` and once with ``PYTHONHASHSEED=4242``, under the same
fixed clock and into different output directories. Every file written must
be byte-identical, and so must the printed output once the two output
directories are replaced by a placeholder. A hash seed changes the iteration
order of sets and dictionaries built from strings, so any output that
depends on that order shows up here as a difference.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR, TempDirTestCase

from science_gate.receipts import HMAC_KEY_FILE_ENV

SEEDS = ("0", "4242")
FIXTURES = REPO_ROOT / "fixtures"
RICH_MANIFEST = FIXTURES / "mutations" / "rich" / "manifest.json"
VALID_MANIFEST = FIXTURES / "core" / "valid" / "manifest.json"
EXAMPLE_MANIFEST = REPO_ROOT / "examples" / "field-survey" / "manifest.json"
DEPENDENCIES = FIXTURES / "dependencies" / "current"


def tree(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


class DeterminismTests(TempDirTestCase):
    def run_cli(self, seed: str, *argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        hidden = (HMAC_KEY_FILE_ENV, "PYTHONHASHSEED")
        environment = {key: value for key, value in os.environ.items() if key not in hidden}
        environment.update(
            {
                "PYTHONPATH": str(SRC_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": seed,
                "SCIENCE_GATE_FIXED_TIME": FIXED_TIME,
            }
        )
        return subprocess.run(
            [sys.executable, "-m", "science_gate.cli", *argv],
            cwd=cwd or self.tmp,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=900,
        )

    def assert_same_outputs(self, outputs: dict[str, Path], printed: dict[str, str]) -> None:
        """Byte-identical files, and identical printed text once each run's own directory is a placeholder."""
        first, second = (tree(outputs[seed]) for seed in SEEDS)
        self.assertTrue(first, "the command wrote nothing")
        self.assertEqual(sorted(first), sorted(second))
        for name in first:
            with self.subTest(file=name):
                self.assertEqual(first[name], second[name])
        normalized = [printed[seed].replace(str(outputs[seed]), "<output>") for seed in SEEDS]
        self.assertEqual(normalized[0], normalized[1])

    def run_twice(self, *argv: str, expected_exit: int) -> tuple[dict[str, Path], dict[str, str]]:
        """Run ``argv`` once per seed with ``--output`` set to a seed-specific directory."""
        outputs, printed = {}, {}
        for seed in SEEDS:
            outputs[seed] = self.tmp / f"seed-{seed}"
            completed = self.run_cli(seed, *argv, "--output", str(outputs[seed]))
            self.assertEqual(completed.returncode, expected_exit, completed.stdout + completed.stderr)
            printed[seed] = completed.stdout
        return outputs, printed

    def test_verify_and_report_are_byte_identical_across_hash_seeds(self) -> None:
        outputs, printed = self.run_twice("verify", str(RICH_MANIFEST), expected_exit=0)
        self.assertIn("report.html", tree(outputs[SEEDS[0]]))
        self.assert_same_outputs(outputs, printed)
        for seed in SEEDS:
            completed = self.run_cli(seed, "report", str(outputs[seed]))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            printed[seed] = completed.stdout
        self.assert_same_outputs(outputs, printed)

    def test_mutate_is_byte_identical_across_hash_seeds(self) -> None:
        outputs, printed = self.run_twice("mutate", str(VALID_MANIFEST), expected_exit=0)
        self.assertEqual(
            sorted(tree(outputs[SEEDS[0]])), ["mutation-report.html", "mutation-report.json", "mutation-report.md"]
        )
        self.assert_same_outputs(outputs, printed)

    def test_package_is_byte_identical_across_hash_seeds(self) -> None:
        outputs, printed = self.run_twice("package", str(EXAMPLE_MANIFEST), expected_exit=0)
        self.assertIn("package.json", tree(outputs[SEEDS[0]]))
        self.assert_same_outputs(outputs, printed)

    def test_impact_and_revalidate_are_byte_identical_across_hash_seeds(self) -> None:
        projects, printed = {}, {}
        for seed in SEEDS:
            project = self.tmp / f"project-{seed}"
            shutil.copytree(DEPENDENCIES, project)
            manifest = str(project / "manifest.json")
            impact = self.run_cli(seed, "impact", "study-design", "--manifest", manifest)
            revalidate = self.run_cli(seed, "revalidate", "study-design", "--manifest", manifest)
            self.assertEqual((impact.returncode, revalidate.returncode), (1, 0), impact.stdout + revalidate.stdout)
            projects[seed] = project
            printed[seed] = impact.stdout + revalidate.stdout
        self.assert_same_outputs(projects, printed)
