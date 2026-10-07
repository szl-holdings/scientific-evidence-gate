"""The runnable example in ``examples/field-survey`` and the walkthrough in ``examples/README.md``.

The walkthrough promises specific outcomes for specific edits. Each promise
is checked here on a private copy, so the documentation cannot drift from
what the tool does.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate._canonical import sha256_bytes
from science_gate.models import FailureMode, InputState, Reason, Status
from science_gate.mutations import mutate
from science_gate.packaging import Disposition, build_package
from science_gate.verifier import VerificationRun, verify

EXAMPLE = REPO_ROOT / "examples" / "field-survey"


class FieldSurveyExampleTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.project = self.tmp / "my-survey"
        shutil.copytree(EXAMPLE, self.project)

    def verify(self) -> VerificationRun:
        return verify(self.project / "manifest.json")

    def check(self, run: VerificationRun, check_id: str) -> Any:
        (found,) = [item for item in run.result.checks if item.check_id == check_id]
        return found

    def edit_plots(self, transform: Any, *, redeclare: bool) -> None:
        plots = self.project / "data" / "plots.csv"
        plots.write_bytes(transform(plots.read_bytes()))
        if redeclare:
            manifest = json.loads((self.project / "manifest.json").read_text(encoding="utf-8"))
            manifest["inputs"][0]["sha256"] = sha256_bytes(plots.read_bytes())
            (self.project / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def without_plot_4(self, data: bytes) -> bytes:
        return b"".join(line for line in data.splitlines(keepends=True) if not line.startswith(b"PLOT-SYN-04"))

    def test_the_example_verifies_as_pass(self) -> None:
        run = verify(EXAMPLE / "manifest.json")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.PASS, Reason.VERIFIED, 0))
        # rows_examined counts distinct data rows of declared inputs only (G1, ARCHITECTURE.md 17.7): the six
        # plot rows. Reviewer verdicts and time events are never rows.
        self.assertEqual((run.result.counters["checks_executed"], run.result.counters["rows_examined"]), (8, 6))
        canopy = self.check(run, "canopy").evidence
        self.assertIn("AGREES_AT_STATED_PRECISION", json.dumps(canopy), "41.2 against a stored 41.25")

    def test_deleting_a_row_breaks_the_declared_digest(self) -> None:
        self.edit_plots(self.without_plot_4, redeclare=False)
        run = self.verify()
        self.assertEqual(run.result.accounting.records[0].state, InputState.HASH_MISMATCH)
        self.assertEqual(run.status, Status.FAIL)

    def test_a_deleted_row_with_a_new_digest_is_caught_by_the_snapshot_and_the_closure(self) -> None:
        self.edit_plots(self.without_plot_4, redeclare=True)
        run = self.verify()
        snapshot = self.check(run, "snapshot")
        self.assertEqual(snapshot.verdict, Status.FAIL)
        self.assertIn(FailureMode.OMITTED_POPULATION, snapshot.failure_modes)
        self.assertIs(run.result.accounting.records[0].closure.holds, False)
        self.assertEqual(run.status, Status.FAIL)

    def test_a_missing_reviewer_abstains_as_protocol_broken(self) -> None:
        verdicts_path = self.project / "reviews" / "verdicts.json"
        verdicts = json.loads(verdicts_path.read_text(encoding="utf-8"))
        verdicts["verdicts"] = [item for item in verdicts["verdicts"] if item["reviewer"] != "reviewer-b"]
        verdicts_path.write_text(json.dumps(verdicts, indent=2), encoding="utf-8")
        run = self.verify()
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.PROTOCOL_BROKEN, 2))

    def test_a_wrong_utc_fails_as_source_mismatch(self) -> None:
        events_path = self.project / "time" / "events.json"
        events = json.loads(events_path.read_text(encoding="utf-8"))
        events["events"][1]["utc"] = "2026-03-19T11:40:00Z"
        events_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
        run = self.verify()
        self.assertEqual((self.check(run, "timing").verdict, run.result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))

    def test_an_emptied_input_examines_nothing_and_breaks_the_declared_closure(self) -> None:
        self.edit_plots(lambda data: data.splitlines(keepends=True)[0], redeclare=True)
        run = self.verify()
        record = run.result.accounting.records[0]
        self.assertEqual(record.state, InputState.EMPTY)
        readers = [check for check in run.result.checks if check.inputs == ("plots",)]
        self.assertEqual(len(readers), 6)
        for check in readers:
            with self.subTest(check=check.check_id):
                self.assertEqual((check.rows_examined, check.verdict), (0, Status.ABSTAIN))
        self.assertIs(record.closure.holds, False, "6 rows were declared, 0 were found")
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
        # The six readers are NOT_APPLICABLE labelled EMPTY_POPULATION: a justified shortfall, which is never
        # PARTIAL_EXECUTION (G2, ARCHITECTURE.md 17.7). The FAIL comes from the broken declared closure.
        self.assertNotIn(Reason.PARTIAL_EXECUTION, run.result.reasons)
        self.assertIn(Reason.INSUFFICIENT_EVIDENCE, run.result.reasons)
        self.assertEqual(run.result.counters["checks_justified"], 6)

    def test_an_emptied_input_without_a_declared_count_abstains(self) -> None:
        manifest = json.loads((self.project / "manifest.json").read_text(encoding="utf-8"))
        for key in ("expected_rows", "denominator_source"):
            del manifest["inputs"][0][key]
        (self.project / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        self.edit_plots(lambda data: data.splitlines(keepends=True)[0], redeclare=True)
        run = self.verify()
        self.assertEqual((run.status, run.exit_code), (Status.ABSTAIN, 2))

    def test_mutation_testing_marks_absent_targets_not_applicable(self) -> None:
        report = mutate(self.project / "manifest.json")
        self.assertTrue(report.baseline.valid)
        not_applicable = {record.mutation_id for record in report.mutations if not record.applicable}
        self.assertTrue(
            {"M08_changed_author", "M18_changed_upstream_design", "M19_replaced_stored_claim_output"} <= not_applicable
        )
        self.assertTrue(all(record.detected is None for record in report.mutations if not record.applicable))
        self.assertGreater(report.counts["executed_mutations"], 0)

    def test_the_synthetic_corpus_is_packaged_with_its_data(self) -> None:
        result = build_package(self.project / "manifest.json", self.tmp / "field-package", environ={})
        self.assertEqual(result.exit_code, 0)
        dispositions = {item["path"]: item["disposition"] for item in result.document["files"]}
        self.assertEqual(dispositions["data/plots.csv"], Disposition.INCLUDED.value)
        packaged = self.tmp / "field-package" / "evaluation" / "data" / "plots.csv"
        self.assertEqual(packaged.read_bytes(), (self.project / "data" / "plots.csv").read_bytes())

    def test_the_example_files_keep_their_exact_bytes(self) -> None:
        attributes = (EXAMPLE / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("* -text", attributes)
        self.assertNotIn(b"\r\n", (EXAMPLE / "data" / "plots.csv").read_bytes())


class WalkthroughTests(TempDirTestCase):
    def test_every_command_in_the_walkthrough_names_a_real_subcommand(self) -> None:
        text = (REPO_ROOT / "examples" / "README.md").read_text(encoding="utf-8")
        commands = {line.split()[3] for line in text.splitlines() if line.startswith("python -m science_gate.cli ")}
        self.assertEqual(commands, {"verify", "report", "mutate", "package", "demo"})

    def test_the_walkthrough_paths_exist(self) -> None:
        for relpath in ("examples/field-survey/manifest.json", "fixtures/packaging/controlled-local"):
            with self.subTest(path=relpath):
                self.assertTrue((REPO_ROOT / Path(relpath)).exists())
