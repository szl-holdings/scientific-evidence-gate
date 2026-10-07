"""Harness pins, write-then-restore detection and the comparator self-test (section 17.6, #9, D10).

The test-only check kinds below tamper with the accepted snapshot from inside
a run, exactly as a misbehaving checker or agent could. Every write lands in
an OS temporary copy of the synthetic starter project.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import REPO_ROOT
from _project import VALID_MANIFEST, ProjectTestCase, check

from science_gate import _audit, invariants
from science_gate.invariants import EXACT, NumericComparison, parse_decimal
from science_gate.models import (
    SKIP_JUSTIFICATION_KEY,
    ExecutionState,
    FailureMode,
    Reason,
    SkipJustification,
    Status,
)
from science_gate.verifier import REGISTRY, CheckContext, CheckOutcome, verify

SNAPSHOT = "snapshots/accepted.json"

# --- test-only kinds: optional checks that touch the pinned snapshot ---------


def _not_applicable(note: str) -> CheckOutcome:
    evidence = {"note": note, SKIP_JUSTIFICATION_KEY: SkipJustification.NOT_DECLARED.value}
    return CheckOutcome(ExecutionState.NOT_APPLICABLE, Status.ABSTAIN, Reason.OUT_OF_SCOPE, rows_examined=0, evidence=evidence)


def rewrite_snapshot(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """Accept one row fewer in the snapshot, before snapshot_completeness runs."""
    path = ctx.root / SNAPSHOT
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("SYN-0006", "SYN-9999"), encoding="utf-8")
    return _not_applicable("rewrote the accepted snapshot")


def write_then_restore(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """Open the snapshot for writing and put identical bytes back: every digest stays equal."""
    path = ctx.root / SNAPSHOT
    original = path.read_bytes()
    with open(path, "wb") as handle:
        handle.write(original)
    return _not_applicable("restored the snapshot byte for byte")


def only_reads(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """Reading a pinned file is allowed."""
    (ctx.root / SNAPSHOT).read_bytes()
    return _not_applicable("read the snapshot")


TAMPER_REGISTRY = {
    **REGISTRY,
    "rewrite_snapshot": f"{__name__}:rewrite_snapshot",
    "write_then_restore": f"{__name__}:write_then_restore",
    "only_reads": f"{__name__}:only_reads",
}


def tamper(check_id: str, kind: str) -> dict[str, Any]:
    """An optional tampering check placed before every other check."""
    return {**check(check_id, kind, inputs=()), "required": False}


def always_equal(claim: Any, stored: Any, **_: Any) -> NumericComparison:
    """A broken comparator: every pair is "equal"."""
    return NumericComparison(EXACT, parse_decimal(claim), parse_decimal(stored))


class PinnedFileTests(ProjectTestCase):
    def run_with_first(self, *extra: dict[str, Any]) -> Any:
        self.set_checks(*extra, *self.manifest()["checks"])
        return self.run_verify(registry=TAMPER_REGISTRY)

    def test_a_rewritten_snapshot_is_protocol_drift_naming_the_path(self) -> None:
        # (a)
        run = self.run_with_first(tamper("tamper", "rewrite_snapshot"))
        self.assertEqual(self.result_of(run, "snapshot").verdict, Status.PASS, "the check saw the pinned bytes")
        (pins,) = [item for item in run.result.invariants if item.name == "harness_pins_intact"]
        self.assertIs(pins.holds, False)
        self.assertIn(f"document {SNAPSHOT} changed during the run", pins.detail)
        self.assertIn(f"{SNAPSHOT} was touched during the run (write via open)", pins.detail)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.FAIL, Reason.PROTOCOL_DRIFT, 1))
        self.assertIn(FailureMode.PROTOCOL_DRIFT, run.result.failure_modes)
        self.assertEqual(run.result.controls["pins"]["changed"], [SNAPSHOT])

    def test_write_then_restore_is_still_protocol_drift(self) -> None:
        # (b) The final digest is equal, but the write was seen as it happened.
        run = self.run_with_first(tamper("tamper", "write_then_restore"))
        (snapshot_pin,) = [item for item in run.pins["pinned"] if item["path"] == SNAPSHOT]
        self.assertEqual(snapshot_pin["sha256"], snapshot_pin["sha256_after"])
        self.assertIn({"path": SNAPSHOT, "action": "write", "event": "open"}, run.pins["writes"])
        (pins,) = [item for item in run.result.invariants if item.name == "harness_pins_intact"]
        self.assertIs(pins.holds, False)
        self.assertNotIn("changed during the run", pins.detail)
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.PROTOCOL_DRIFT))
        self.assertIs(run.result.controls["pins"]["holds"], False)

    def test_reading_a_pinned_file_is_not_a_write(self) -> None:
        run = self.run_with_first(tamper("peek", "only_reads"))
        self.assertEqual(run.pins["writes"], [])
        self.assertEqual(run.status, Status.PASS)

    def test_the_valid_demo_records_its_pins_and_stays_pass(self) -> None:
        # (d)
        run = verify(VALID_MANIFEST)
        self.assertEqual(run.status, Status.PASS)
        pinned = {(item["role"], item["path"]): item for item in run.pins["pinned"]}
        self.assertEqual(
            set(pinned),
            {
                ("manifest", "manifest.json"),
                ("input", "data/measurements.csv"),
                ("document", SNAPSHOT),
                ("check_module", "science_gate.verifier"),
            },
        )
        for key, item in pinned.items():
            with self.subTest(pin=key):
                self.assertRegex(item["sha256"], "^[0-9a-f]{64}$")
                self.assertEqual(item["sha256"], item["sha256_after"])
        self.assertEqual((run.pins["writes"], run.pins["hook_errors"]), ([], 0))
        self.assertEqual(run.result.controls["pins"], {"pinned": 4, "changed": [], "writes": [], "holds": True})
        (pins,) = [item for item in run.result.invariants if item.name == "harness_pins_intact"]
        self.assertEqual((pins.applicable, pins.holds), (True, True))

    def test_specialist_check_modules_are_pinned_when_their_kinds_are_declared(self) -> None:
        project = self.tmp / "dependencies"
        shutil.copytree(REPO_ROOT / "fixtures" / "dependencies" / "current", project)
        run = verify(project / "manifest.json")
        modules = {item["path"] for item in run.pins["pinned"] if item["role"] == "check_module"}
        self.assertEqual(modules, {"science_gate.dependencies", "science_gate.verifier"})


class ComparatorSelfTestTests(ProjectTestCase):
    def test_a_comparator_that_calls_everything_equal_fails_as_a_blind_spot(self) -> None:
        # (c)
        with mock.patch.object(invariants, "compare_decimal", always_equal):
            run = self.run_verify()
        self.assertIs(run.result.controls["comparator_self_test"]["holds"], False)
        (self_test,) = [item for item in run.result.invariants if item.name == "comparator_self_test"]
        self.assertIs(self_test.holds, False)
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.BLIND_SPOT))
        self.assertIn(FailureMode.DEFECTIVE_VERIFICATION, run.result.failure_modes)
        # numeric_agreement used the same patched comparator, so it could not discriminate either.
        values = self.result_of(run, "values")
        self.assertEqual((values.verdict, values.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(values.evidence["discrimination"], "0")

    def test_the_live_comparator_passes_its_self_test(self) -> None:
        run = self.run_verify()
        control = run.result.controls["comparator_self_test"]
        self.assertIs(control["holds"], True)
        self.assertEqual(
            [(pair["claim"], pair["stored"], pair["actual"]) for pair in control["pairs"]],
            [("0.15", "0.14", "DISAGREES"), ("12.4", "12.40", "EXACT"), ("0.1", "0.14", "AGREES_AT_STATED_PRECISION")],
        )


class AuditHookTests(unittest.TestCase):
    """D10: one process-wide hook, installed once, recording nothing outside a recording context."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="science-gate-audit-")).resolve()
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.path = self.directory / "pinned.txt"
        self.path.write_bytes(b"synthetic")

    def test_install_is_idempotent(self) -> None:
        for _ in range(3):
            _audit.install()
        self.assertTrue(_audit.installed())
        with _audit.recording(watch=[self.path]) as recorder:
            self.path.write_bytes(b"synthetic")
        self.assertEqual(len(recorder.writes), 1, "one hook, so one event per write")

    def test_nothing_is_recorded_outside_a_recording_context(self) -> None:
        with _audit.recording(watch=[self.path]) as recorder:
            pass
        self.path.write_bytes(b"after the block")
        self.assertEqual(recorder.events, ())
        self.assertFalse(_audit.values_requested())

    def test_recorders_nest_and_each_sees_its_own_block(self) -> None:
        with _audit.recording(watch=[self.path]) as outer:
            self.path.write_bytes(b"one")
            with _audit.recording(under=[self.directory]) as inner:
                self.path.read_bytes()
                (self.directory / "other.txt").write_bytes(b"two")
            self.path.write_bytes(b"three")
        self.assertEqual([event.action for event in outer.events], ["write", "read", "write"])
        self.assertEqual(len(inner.events), 2)
        self.assertTrue(inner.events[1].path.endswith("other.txt"))
        self.assertNotIn("other.txt", "".join(event.path for event in outer.events), "watch names files only")

    def test_every_mutating_operation_counts_as_a_write(self) -> None:
        copy = self.directory / "copy.txt"
        moved = self.directory / "moved.txt"
        with _audit.recording(under=[self.directory]) as recorder:
            with open(self.path, "ab"):
                pass
            with open(self.path, "r+b"):
                pass
            os.close(os.open(self.path, os.O_WRONLY))
            os.truncate(self.path, 0)
            shutil.copyfile(self.path, copy)
            os.replace(copy, moved)
            os.remove(moved)
        events = [(event.action, event.event, Path(event.path).name) for event in recorder.events]
        self.assertEqual(
            events,
            [
                ("write", "open", "pinned.txt"),  # append mode
                ("write", "open", "pinned.txt"),  # read-write mode
                ("write", "open", "pinned.txt"),  # os.open with O_WRONLY
                ("write", "os.truncate", "pinned.txt"),
                ("write", "shutil.copyfile", "copy.txt"),
                ("read", "open", "pinned.txt"),  # the copy's source is only read
                ("write", "open", "copy.txt"),
                ("rename", "os.rename", "copy.txt"),  # os.replace reports both ends
                ("rename", "os.rename", "moved.txt"),
                ("delete", "os.remove", "moved.txt"),
            ],
        )
        self.assertNotIn("read", {event.action for event in recorder.writes})

    def test_a_removed_tree_deletes_every_watched_file_inside_it(self) -> None:
        with _audit.recording(watch=[self.path]) as recorder:
            shutil.rmtree(self.directory)
        self.assertIn(("delete", "shutil.rmtree"), {(event.action, event.event) for event in recorder.events})

    def test_value_reads_are_attributed_to_the_current_check(self) -> None:
        row = _audit.RecordingMapping({"sample_id": "SYN-0001", "value": "12.40"}, "measurements", 1)
        with _audit.recording(record_values=True) as recorder:
            self.assertTrue(_audit.values_requested())
            row["value"]  # outside any check: not a check reading the cell
            with _audit.current_check("values"):
                self.assertEqual(row["value"], "12.40")
                self.assertIn("sample_id", row)  # membership is not a value read
                self.assertEqual(_audit.active_check(), "values")
        self.assertEqual([read.to_dict() for read in recorder.value_reads], [
            {"check_id": "values", "input_id": "measurements", "row_index": 1, "column": "value"}
        ])
        with _audit.recording() as plain, _audit.current_check("values"):
            row["value"]
        self.assertEqual(plain.value_reads, (), "only recorders that asked for values get them")

    def test_a_verify_inside_a_value_recording_reports_which_cells_each_check_read(self) -> None:
        project = Path(tempfile.mkdtemp(prefix="science-gate-audit-run-")).resolve()
        self.addCleanup(shutil.rmtree, project, ignore_errors=True)
        shutil.copytree(VALID_MANIFEST.parent, project / "valid")
        with _audit.recording(under=[project], record_values=True) as recorder:
            run = verify(project / "valid" / "manifest.json")
        self.assertEqual(run.status, Status.PASS)
        reads = {(read.check_id, read.column) for read in recorder.value_reads}
        self.assertIn(("values", "value"), reads)
        self.assertIn(("counts", "count"), reads)
        self.assertNotIn(("values", "count"), reads, "a check is credited only with the cells it read")
        opened = {Path(event.path).name for event in recorder.events if event.action == "read"}
        self.assertIn("measurements.csv", opened)


if __name__ == "__main__":
    unittest.main()
