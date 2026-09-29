"""Shared fixtures for the engine-stage tests (verifier, reports, CLI).

Every test starts from the synthetic starter project that ``science-gate init``
writes, placed in a private temporary directory, and then edits it. The
starter project verifies as PASS, so each edit isolates exactly one defect.
All names, values and reviewers are invented.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate._canonical import sha256_bytes
from science_gate.cli import scaffold_project
from science_gate.models import CheckResult
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.verifier import (
    REVIEWS_SCHEMA,
    TIME_SOURCES_SCHEMA,
    VerificationRun,
    verify,
)

FIXTURES = REPO_ROOT / "fixtures" / "core"
VALID_MANIFEST = FIXTURES / "valid" / "manifest.json"
EMPTY_MANIFEST = FIXTURES / "empty" / "manifest.json"

#: Two invented reviewers, as the review protocol fixtures name them.
REVIEWERS = ["reviewer-a", "reviewer-b"]

#: One observation, 14:30 at UTC+02:00, which is 12:30Z, inside March 2026.
TIME_EVENT = {
    "id": "obs-0001",
    "local_time": "2026-03-10T14:30:00",
    "timezone": "+02:00",
    "utc": "2026-03-10T12:30:00Z",
}


def check(check_id: str, kind: str, *, inputs: tuple[str, ...] = ("measurements",), **extra: Any) -> dict[str, Any]:
    """A manifest check entry (required, version 1) with optional params."""
    entry: dict[str, Any] = {"id": check_id, "kind": kind, "version": "1", "required": True, "inputs": list(inputs)}
    entry.update(extra)
    return entry


def reviews_document(*reviewers: str) -> dict[str, Any]:
    return {"schema": REVIEWS_SCHEMA, "verdicts": [{"reviewer": name, "verdict": "ACCEPT"} for name in reviewers]}


def time_document(*events: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": TIME_SOURCES_SCHEMA,
        "window": {"start": "2026-03-01T00:00:00Z", "end": "2026-03-31T23:59:59Z"},
        "events": list(events),
    }


class ProjectTestCase(TempDirTestCase):
    """A test case holding a fresh synthetic starter project under ``self.project``.

    The clock is pinned, and any signing key in the caller's environment is
    hidden, so results do not depend on who runs the tests.
    """

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.project = self.tmp / "project"
        scaffold_project(self.project)

    @property
    def manifest_path(self) -> Path:
        return self.project / "manifest.json"

    def manifest(self) -> dict[str, Any]:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def save_manifest(self, document: dict[str, Any]) -> None:
        self.manifest_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def update_manifest(self, **fields: Any) -> None:
        document = self.manifest()
        document.update(fields)
        self.save_manifest(document)

    def add_checks(self, *checks: dict[str, Any]) -> None:
        document = self.manifest()
        document["checks"].extend(checks)
        self.save_manifest(document)

    def set_checks(self, *checks: dict[str, Any]) -> None:
        self.update_manifest(checks=list(checks))

    def write_file(self, relpath: str, data: str | bytes) -> Path:
        return self.write(f"project/{relpath}", data)

    def write_json(self, relpath: str, document: Any) -> Path:
        return self.write_file(relpath, json.dumps(document, indent=2))

    def write_data(self, text: str, *, declare_digest: bool = True) -> None:
        """Replace the measurements CSV; by default also re-declare its digest.

        Re-declaring isolates the defect under test from a digest mismatch,
        which would otherwise dominate the result.
        """
        data = self.write_file("data/measurements.csv", text)
        if declare_digest:
            document = self.manifest()
            document["inputs"][0]["sha256"] = sha256_bytes(data.read_bytes())
            self.save_manifest(document)

    def data_lines(self) -> list[str]:
        return (self.project / "data" / "measurements.csv").read_text(encoding="utf-8").splitlines(keepends=True)

    def file_digest(self, relpath: str) -> str:
        return sha256_bytes((self.project / relpath).read_bytes())

    def run_verify(self, **kwargs: Any) -> VerificationRun:
        return verify(self.manifest_path, **kwargs)

    def result_of(self, run: VerificationRun, check_id: str) -> CheckResult:
        (found,) = [item for item in run.result.checks if item.check_id == check_id]
        return found
