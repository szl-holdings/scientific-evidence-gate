"""Harness self-mutation: extension #13 (ARCHITECTURE.md 17.12).

Seven known-wrong variants of the mutation harness (H01-H07) run over the same
PASS-baseline tree as the honest harness. Each is killed only if a status, a
reason, a record's status or a count differs from the honest harness on the
same probe. ``harness_sensitivity`` is killed/7, and the report is PASS only
at 7/7.

The tree is ``fixtures/mutations/activation``: its honest report holds a
blind spot that a non-PASS status would wrongly credit (M04, for H02),
operators with no target (for H04), file and replay mutants, and a required
input to empty (H05's probe). No correct engine raises, so H03 is judged on
the crash probe, where every mutant's verify raises. All data is synthetic
and every verify is offline.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, TempDirTestCase

from science_gate import mutations
from science_gate._canonical import pretty_json_bytes, sha256_bytes, strict_loads
from science_gate.models import RatioState, Reason, Status
from science_gate.mutations import (
    HARNESS_MUTANT_IDS,
    HARNESS_REPORT_HEADINGS,
    HarnessRecord,
    HarnessReport,
    cli_mutate,
    harness_headline,
    mutate_harness,
    render_harness_markdown,
)

ACTIVATION_MANIFEST = REPO_ROOT / "fixtures" / "mutations" / "activation" / "manifest.json"
EMPTY_MANIFEST = REPO_ROOT / "fixtures" / "core" / "empty" / "manifest.json"
GIVEN, EMPTIED, CRASHING = "given tree", "emptied first required input", "crashing verifier"


def fixed_clock(test_class: type[unittest.TestCase]) -> None:
    patcher = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
    patcher.start()
    test_class.addClassCleanup(patcher.stop)


class HarnessSensitivityTests(unittest.TestCase):
    report: HarnessReport
    records: dict[str, HarnessRecord]

    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)
        cls.report = mutate_harness(ACTIVATION_MANIFEST)
        cls.records = {record.harness_mutant_id: record for record in cls.report.records}

    def differences(self, mutant_id: str, probe: str) -> list[str]:
        return [text for text in self.records[mutant_id].differences if text.startswith(f"{probe}: ")]

    def test_harness_sensitivity_is_7_of_7_and_every_variant_is_killed(self) -> None:
        self.assertEqual(tuple(self.records), HARNESS_MUTANT_IDS)
        for mutant_id, record in self.records.items():
            with self.subTest(harness_mutant=mutant_id):
                self.assertIs(record.killed, True, record.differences)
                self.assertTrue(record.differences)
        ratio = self.report.harness_sensitivity
        self.assertEqual((ratio.numerator, ratio.denominator, ratio.fraction, ratio.decimal), (7, 7, "7/7", "1"))
        self.assertIs(ratio.state, RatioState.DEFINED)
        outcome = (self.report.status, self.report.reason, self.report.exit_code)
        self.assertEqual(outcome, (Status.PASS, Reason.VERIFIED, 0))

    def test_the_honest_harness_runs_every_probe_once(self) -> None:
        honest = {item["probe"]: item for item in self.report.honest}
        self.assertEqual(set(honest), {GIVEN, EMPTIED, CRASHING})
        self.assertEqual((honest[GIVEN]["status"], honest[GIVEN]["reason"]), ("FAIL", "BLIND_SPOT"))
        self.assertEqual(honest[EMPTIED]["reason"], "INVALID_BASELINE")
        self.assertIsNone(honest[EMPTIED]["counts"])
        self.assertEqual((honest[CRASHING]["status"], honest[CRASHING]["reason"]), ("FAIL", "PROTOCOL_BROKEN"))

    def test_h01_a_no_op_application_leaves_the_harness_blind(self) -> None:
        self.assertIn(f"{GIVEN}: reason BLIND_SPOT -> HARNESS_BLIND", self.records["H01_apply_noop"].differences)

    def test_h02_status_only_detection_credits_the_wrong_detector(self) -> None:
        found = self.differences("H02_status_only_detection", GIVEN)
        self.assertIn(f"{GIVEN}: M04_duplicate_row BLIND_SPOT -> DETECTED", found)
        self.assertNotIn(f"{GIVEN}: M18_changed_upstream_design BLIND_SPOT -> DETECTED", found, "M18's status is PASS")

    def test_h03_a_credited_crash_shows_only_on_the_crash_probe(self) -> None:
        self.assertEqual(self.differences("H03_crash_credited", GIVEN), [], "no correct engine raises by itself")
        found = self.differences("H03_crash_credited", CRASHING)
        self.assertIn(f"{CRASHING}: M01_empty_input VERIFIER_ERROR -> DETECTED", found)
        self.assertIn(f"{CRASHING}: reason PROTOCOL_BROKEN -> VERIFIED", found)

    def test_h04_counting_unexecuted_mutants_breaks_conservation(self) -> None:
        found = self.records["H04_unexecuted_counted"].differences
        self.assertIn(f"{GIVEN}: reason BLIND_SPOT -> UNMEASURED_MUTANTS", found)
        self.assertIn(f"{GIVEN}: executed_mutations 9 -> 21", found)

    def test_h05_an_unchecked_baseline_shows_only_on_the_emptied_input_probe(self) -> None:
        self.assertEqual(self.differences("H05_baseline_unchecked", GIVEN), [])
        found = self.differences("H05_baseline_unchecked", EMPTIED)
        self.assertTrue(any(text.startswith(f"{EMPTIED}: reason INVALID_BASELINE -> ") for text in found), found)

    def test_h06_resealing_a_tampered_ledger_hides_the_forced_defect(self) -> None:
        self.assertIn(f"{GIVEN}: reason BLIND_SPOT -> HARNESS_BLIND", self.records["H06_replay_reseals"].differences)

    def test_h07_reading_the_original_tree_activates_nothing(self) -> None:
        found = self.records["H07_reads_original_tree"].differences
        self.assertIn(f"{GIVEN}: reason BLIND_SPOT -> INSUFFICIENT_EVIDENCE", found)
        self.assertIn(f"{GIVEN}: M01_empty_input DETECTED -> NOT_ACTIVATED", found)

    def test_the_report_is_content_addressed_json_and_markdown(self) -> None:
        document = strict_loads(pretty_json_bytes(self.report.to_dict()), integers_only=True)
        self.assertRegex(document["report_id"], r"^har-[0-9a-f]{16}$")
        self.assertEqual(document["schema"], "science-gate-harness-report/v1")
        self.assertEqual(document["harness_sensitivity"]["fraction"], "7/7")
        for record in document["records"]:
            self.assertEqual(set(record), {"harness_mutant_id", "description", "killed", "differences"})
        markdown = render_harness_markdown(self.report)
        found = [line[3:] for line in markdown.splitlines() if line.startswith("## ")]
        self.assertEqual(found, list(HARNESS_REPORT_HEADINGS))
        self.assertIn("Harness sensitivity: 7/7 = 1.", markdown)
        self.assertTrue(harness_headline(self.report).startswith(f"PASS (VERIFIED) {self.report.report_id}: "))
        self.assertNotIn("science-gate-", json.dumps(document["diagnostics"]))


class HarnessCanFailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixed_clock(cls)

    def test_a_harness_mutant_that_changes_nothing_survives_and_the_report_fails(self) -> None:
        real = {item.harness_mutant_id: item for item in mutations._HARNESS_MUTANTS}
        honest_in_disguise = mutations._HarnessMutant(
            "H02_status_only_detection", "the honest harness", mutations._HONEST
        )
        with mock.patch.object(mutations, "_HARNESS_MUTANTS", (real["H01_apply_noop"], honest_in_disguise)):
            report = mutate_harness(ACTIVATION_MANIFEST)
        survivor = report.records[1]
        self.assertEqual((survivor.killed, survivor.differences), (False, ()))
        self.assertIs(report.records[0].killed, True)
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.HARNESS_BLIND, 1))
        self.assertEqual(report.harness_sensitivity.fraction, "1/7")
        self.assertIn("H02_status_only_detection left every result unchanged", report.message)

    def test_an_invalid_baseline_gives_no_harness_sensitivity(self) -> None:
        report = mutate_harness(EMPTY_MANIFEST)
        self.assertEqual((report.status, report.reason, report.exit_code), (Status.FAIL, Reason.INVALID_BASELINE, 1))
        self.assertEqual(report.records, ())
        ratio = report.harness_sensitivity
        self.assertIs(ratio.state, RatioState.UNAVAILABLE, "unknown, never 0/7")
        self.assertEqual((ratio.numerator, ratio.fraction, ratio.decimal), (None, None, None))

    def test_records_must_be_killed_exactly_when_something_differs(self) -> None:
        with self.assertRaises(ValueError):
            HarnessRecord("H01_apply_noop", "synthetic", True, ())
        with self.assertRaises(ValueError):
            HarnessRecord("H01_apply_noop", "synthetic", False, ("given tree: status PASS -> FAIL",))


class HarnessCommandTests(TempDirTestCase):
    def detecting_tree(self) -> Path:
        """A synthetic tree whose every applicable operator is caught, so its mutation report is PASS."""
        data = b"sample_id,value\nSYN-H-1,1\nSYN-H-2,2\nSYN-H-3,3\n"
        self.write("tree/data/samples.csv", data)
        spec = {"inputs": ["samples"], "required": True, "version": "1"}
        manifest = {
            "schema": "science-gate-manifest/v1",
            "run_label": "synthetic-harness-command",
            "inputs": [
                {
                    "id": "samples",
                    "path": "data/samples.csv",
                    "format": "csv",
                    "required": True,
                    "sha256": sha256_bytes(data),
                    "row_key": ["sample_id"],
                    "expected_rows": 3,
                    "denominator_source": "INDEPENDENT",
                }
            ],
            "checks": [{"id": "rows", "kind": "row_count", **spec}, {"id": "dupes", "kind": "duplicate_rows", **spec}],
            "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
        }
        return self.write_manifest(manifest, "tree/manifest.json")

    def test_mutate_harness_writes_both_reports_and_exits_with_the_worse_status(self) -> None:
        self.fixed_clock()
        output = self.tmp / "out"
        stdout = io.StringIO()
        arguments = argparse.Namespace(manifest=str(self.detecting_tree()), output=str(output), harness=True)
        # One variant keeps this test quick; an incomplete harness report can only FAIL.
        with mock.patch.object(mutations, "_HARNESS_MUTANTS", mutations._HARNESS_MUTANTS[:1]):
            with contextlib.redirect_stdout(stdout):
                code = cli_mutate(arguments)
        lines = stdout.getvalue().splitlines()
        self.assertTrue(lines[0].startswith("PASS (VERIFIED) mut-"), lines[0])
        self.assertTrue(lines[1].startswith("FAIL (HARNESS_BLIND) har-"), lines[1])
        names = [
            "mutation-report.json",
            "mutation-report.md",
            "mutation-report.html",
            "harness-report.json",
            "harness-report.md",
        ]
        self.assertEqual([Path(line).name for line in lines[2:]], names)
        self.assertEqual(code, 1, "the harness report FAILs, so the command does, though the mutation report passed")
        harness = json.loads((output / "harness-report.json").read_text(encoding="utf-8"))
        mutation = json.loads((output / "mutation-report.json").read_text(encoding="utf-8"))
        self.assertEqual(harness["honest"][0]["report_id"], mutation["report_id"])


if __name__ == "__main__":
    unittest.main()
