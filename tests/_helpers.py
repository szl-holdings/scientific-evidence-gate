"""Shared fixtures for the foundation tests.

Every fixture is synthetic: invented sample ids, invented values, and files
written only into OS temporary directories that are removed after each test.
The "good run" scenario is built through the real discovery and ledger code,
so tests that mutate it exercise the same shapes a verifier will produce.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

from science_gate._canonical import sha256_bytes
from science_gate.discovery import OpenedInput, discover
from science_gate.invariants import InvariantContext, evaluate_invariants
from science_gate.ledger import Ledger
from science_gate.manifests import MANIFEST_SCHEMA, Manifest, load_manifest
from science_gate.models import (
    CheckResult,
    ExecutionState,
    InputAccounting,
    Reason,
    RunResult,
    Status,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
FIXED_TIME = "2026-01-02T03:04:05Z"
RUN_ID = "run-synthetic-0001"

#: Three invented measurements. The values are chosen to exercise the numeric
#: rules (trailing zero, grouped thousands) and mean nothing.
MEASUREMENTS_CSV = "sample_id,value,count\nSYN-0001,12.40,\"1,234\"\nSYN-0002,0.14,7\nSYN-0003,3.5,12\n"


class TempDirTestCase(unittest.TestCase):
    """A test case with a private temporary directory, removed afterwards."""

    def setUp(self) -> None:
        super().setUp()
        # resolve() expands Windows 8.3 short names so path comparisons are exact.
        self.tmp = Path(tempfile.mkdtemp(prefix="science-gate-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, relpath: str, data: str | bytes) -> Path:
        """Create a fixture file under the temporary directory (test setup only)."""
        path = self.tmp / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path

    def write_manifest(self, document: dict[str, Any], relpath: str = "manifest.json") -> Path:
        return self.write(relpath, json.dumps(document, indent=2))

    def fixed_clock(self) -> None:
        """Pin ``_clock.now()`` for the rest of the test."""
        patcher = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
        patcher.start()
        self.addCleanup(patcher.stop)


def try_symlink(test: unittest.TestCase, target: Path, link: Path, *, directory: bool = False) -> None:
    """Create a symlink or skip the test with a visible reason.

    Windows only allows symlinks with Developer Mode or elevated rights, so
    symlink tests must degrade to an explicit skip rather than a false pass.
    """
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        test.skipTest(f"symbolic links cannot be created on this system ({type(exc).__name__})")


def manifest_document(**overrides: Any) -> dict[str, Any]:
    """A minimal valid manifest over the synthetic measurements file."""
    document: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "run_label": "synthetic-foundation",
        "inputs": [
            {
                "id": "measurements",
                "path": "data/measurements.csv",
                "format": "csv",
                "row_key": ["sample_id"],
                "expected_rows": 3,
                "denominator_source": "INDEPENDENT",
            }
        ],
        "checks": [
            {"id": "rows", "kind": "row_count", "version": "1", "required": True, "inputs": ["measurements"]}
        ],
    }
    document.update(overrides)
    return document


@dataclass
class Scenario:
    """A coherent, passing run assembled from real discovery and ledger output."""

    manifest: Manifest
    accounting: InputAccounting
    opened: dict[str, OpenedInput]
    ledger: Ledger
    checks: tuple[CheckResult, ...]
    evidence_manifest: list[dict[str, Any]]

    def context(self, **overrides: Any) -> InvariantContext:
        seal = self.ledger.seal()
        values: dict[str, Any] = {
            "entries": self.ledger.entries,
            "checks": self.checks,
            "accounting": self.accounting,
            "declared_checks": {spec.check_id: spec.required for spec in self.manifest.checks},
            "claimed_status": Status.PASS,
            "evidence_manifest": self.evidence_manifest,
            "ledger_head_sha256": seal["ledger_head_sha256"],
            "ledger_length": seal["ledger_length"],
            "run_id": self.ledger.run_id,
        }
        values.update(overrides)
        return InvariantContext(**values)

    def run_result(self, **overrides: Any) -> RunResult:
        values: dict[str, Any] = {
            "status": Status.PASS,
            "reason": Reason.VERIFIED,
            "reasons": (Reason.VERIFIED,),
            "failure_modes": (),
            "run_id": self.ledger.run_id,
            "accounting": self.accounting,
            "checks": self.checks,
            "invariants": evaluate_invariants(self.context()),
            "evidence_manifest_sha256": sha256_bytes(b"synthetic evidence manifest"),
            "started_at": FIXED_TIME,
            "completed_at": FIXED_TIME,
            "counters": {"checks_expected": 1, "checks_executed": 1, "rows_examined": 3},
        }
        values.update(overrides)
        return RunResult(**values)


def build_scenario(case: TempDirTestCase, csv_text: str = MEASUREMENTS_CSV, **manifest_overrides: Any) -> Scenario:
    """Write the synthetic tree, discover it and record one passing row_count check."""
    case.fixed_clock()
    case.write("data/measurements.csv", csv_text)
    manifest = load_manifest(case.write_manifest(manifest_document(**manifest_overrides)))
    accounting, opened = discover(manifest)
    ledger = Ledger(RUN_ID)
    checks = []
    for spec in manifest.checks:
        digests = {input_id: opened[input_id].sha256 for input_id in spec.inputs}
        rows = sum(len(opened[input_id].rows or ()) for input_id in spec.inputs)
        evidence = {"rows_examined": rows, "inputs": sorted(digests)}
        invocation_id = ledger.start(
            check_id=spec.check_id,
            check_kind=spec.kind,
            check_version=spec.version,
            input_ids=spec.inputs,
            input_sha256s=digests,
        )
        ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED, evidence=evidence)
        checks.append(
            CheckResult(
                check_id=spec.check_id,
                kind=spec.kind,
                version=spec.version,
                required=spec.required,
                execution_state=ExecutionState.CHECKED,
                verdict=Status.PASS,
                reason=Reason.VERIFIED,
                rows_examined=rows,
                inputs=spec.inputs,
                evidence=evidence,
                invocation_id=invocation_id,
            )
        )
    examined = sum(check.rows_examined or 0 for check in checks)
    evidence_manifest = [{"path": "ledger.jsonl", "sha256": sha256_bytes(ledger.to_jsonl())}]
    return Scenario(manifest, accounting.with_examined(examined), opened, ledger, tuple(checks), evidence_manifest)
