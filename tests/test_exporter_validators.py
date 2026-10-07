"""Reporters that can fail: exporter validators and their negative fixtures (section 17.10, extension #12, D7).

Every committed fixture under ``fixtures/exporters/`` pairs a synthetic
``run.json`` with one export carrying exactly one defect, and the validator
for that export must reject it with exactly the expected code. A meta-test
then swaps each validator for one that accepts everything and shows that the
fixture test built on it fails: the fixture tests can fail, so their passing
means something. Finally, ``science-gate report RUN_DIR`` re-runs the
validators on stored exports, so a tampered ``results.sarif`` is ERROR, exit 3.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from typing import Any, Callable
from unittest import mock

from _helpers import REPO_ROOT, SRC_DIR
from _project import ProjectTestCase, check

from science_gate import _validators
from science_gate._canonical import pretty_json_bytes
from science_gate._validators import (
    REPORT_HEADING_MISSING,
    REPORT_HEADING_ORDER,
    REPORT_HEADINGS,
    REPORT_MALFORMED,
    REPORT_MD,
    REPORT_ROWS_EXAMINED_MISMATCH,
    RESULTS_SARIF,
    RUN_CHECKS_EXECUTED_MISMATCH,
    RUN_JSON,
    RUN_JSON_MALFORMED,
    SARIF_CHECK_MISSING,
    SARIF_CHECK_UNEXPECTED,
    SARIF_ERROR_WITHOUT_NOTIFICATION,
    SARIF_EXECUTION_SUCCESS_ON_ERROR,
    SARIF_KIND_MISMATCH,
    SARIF_LEVEL_WITHOUT_FAIL,
    SARIF_MALFORMED,
    VALIDATORS,
    ExportValidationError,
    problem_code,
    rows_examined_line,
    validate_exports,
    validate_report_md,
    validate_run_json,
    validate_sarif,
)
from science_gate.cli import main
from science_gate.models import Status
from science_gate.reports import SARIF_NOT_DERIVED, build_sarif, render_report, report_run_dir, write_run
from science_gate.verifier import REGISTRY, CheckContext, CheckOutcome

FIXTURES = REPO_ROOT / "fixtures" / "exporters"
CASES = {case["id"]: case for case in json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))["cases"]}
HTML_RENDERER = "science_gate._html"


def raising_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    raise RuntimeError("synthetic failure inside a check")


def codes(problems: tuple[str, ...]) -> list[str]:
    return [problem_code(problem) for problem in problems]


def load_case(case_id: str) -> tuple[Any, Any]:
    """The fixture's export (parsed JSON, or text for report.md) and the run.json it is judged against."""
    folder = FIXTURES / case_id
    run = json.loads((folder / RUN_JSON).read_text(encoding="utf-8"))
    export = CASES[case_id]["export"]
    if export == RUN_JSON:
        return run, run
    text = (folder / export).read_text(encoding="utf-8")
    return (text if export == REPORT_MD else json.loads(text)), run


def accept_all(export: Any, run: Any) -> tuple[str, ...]:
    return ()


def fresh_sarif(run: dict[str, Any]) -> dict[str, Any]:
    """The SARIF log ``run`` derives, as it reads back from disk."""
    return json.loads(pretty_json_bytes(build_sarif(run)))


# ---------------------------------------------------------------------------
# The committed negative fixtures
# ---------------------------------------------------------------------------


class NegativeFixtureTests(unittest.TestCase):
    """One test per committed fixture: its validator, looked up in VALIDATORS, rejects it."""

    def assert_rejected(self, case_id: str) -> None:
        export, run = load_case(case_id)
        problems = _validators.VALIDATORS[CASES[case_id]["export"]](export, run)
        self.assertEqual(codes(problems), [CASES[case_id]["problem"]], problems)

    def test_1_level_error_on_kind_pass(self) -> None:
        self.assert_rejected("sarif-level-error-on-pass")

    def test_2_error_run_with_execution_successful_true(self) -> None:
        self.assert_rejected("sarif-error-run-execution-successful")

    def test_3_one_planned_check_dropped(self) -> None:
        self.assert_rejected("sarif-planned-check-dropped")

    def test_4_kind_pass_for_a_failed_check(self) -> None:
        self.assert_rejected("sarif-pass-kind-for-failed-check")

    def test_5_report_missing_what_this_result_does_not_prove(self) -> None:
        self.assert_rejected("report-missing-not-prove")

    def test_6_report_headings_out_of_order(self) -> None:
        self.assert_rejected("report-headings-out-of-order")

    def test_run_json_overstating_checks_executed(self) -> None:
        self.assert_rejected("run-checks-executed-overstated")

    def test_report_renaming_the_run_rows_figure(self) -> None:
        self.assert_rejected("report-rows-examined-renamed")


#: Each fixture test method and the case it judges, so the meta-test can run it.
FIXTURE_TESTS = {
    "test_1_level_error_on_kind_pass": "sarif-level-error-on-pass",
    "test_2_error_run_with_execution_successful_true": "sarif-error-run-execution-successful",
    "test_3_one_planned_check_dropped": "sarif-planned-check-dropped",
    "test_4_kind_pass_for_a_failed_check": "sarif-pass-kind-for-failed-check",
    "test_5_report_missing_what_this_result_does_not_prove": "report-missing-not-prove",
    "test_6_report_headings_out_of_order": "report-headings-out-of-order",
    "test_run_json_overstating_checks_executed": "run-checks-executed-overstated",
    "test_report_renaming_the_run_rows_figure": "report-rows-examined-renamed",
}


class FixtureCatalogueTests(unittest.TestCase):
    def test_the_catalogue_names_every_fixture_directory_and_the_brief_six(self) -> None:
        folders = sorted(path.name for path in FIXTURES.iterdir() if path.is_dir())
        self.assertEqual(folders, sorted(CASES))
        self.assertEqual(sorted(FIXTURE_TESTS.values()), sorted(CASES))
        brief_cases = sorted(case["brief_case"] for case in CASES.values() if case["brief_case"])
        self.assertEqual(brief_cases, [1, 2, 3, 4, 5, 6])
        for case_id, case in CASES.items():
            with self.subTest(case=case_id):
                files = sorted(path.name for path in (FIXTURES / case_id).iterdir())
                self.assertEqual(files, sorted({RUN_JSON, case["export"]}))

    def test_every_validator_has_a_fixture(self) -> None:
        self.assertEqual({case["export"] for case in CASES.values()}, set(VALIDATORS))

    def test_each_fixture_differs_from_a_valid_export_only_by_its_defect(self) -> None:
        # The renderers' own output for each fixture's run.json passes every validator,
        # so each rejection above is caused by the one defect, not by the reference run.
        for case_id, case in CASES.items():
            if case["export"] == RUN_JSON:
                continue
            with self.subTest(case=case_id):
                _, run = load_case(case_id)
                exports = {
                    RUN_JSON: run,
                    RESULTS_SARIF: fresh_sarif(run),
                    REPORT_MD: render_report(run, files=(), html_note=None),
                }
                self.assertEqual(validate_exports(exports, run), ())

    def test_the_run_json_fixture_is_valid_once_its_count_is_corrected(self) -> None:
        run, _ = load_case("run-checks-executed-overstated")
        run["checks_executed"] = 2
        self.assertEqual(validate_run_json(run), ())


class MetaTests(unittest.TestCase):
    """Replace one validator with accept-all: the fixture test that relies on it must then fail."""

    def run_fixture_test(self, name: str, validators: Any) -> unittest.TestResult:
        result = unittest.TestResult()
        with mock.patch.object(_validators, "VALIDATORS", validators):
            NegativeFixtureTests(name).run(result)
        return result

    def test_every_fixture_test_fails_when_its_validator_accepts_everything(self) -> None:
        for name, case_id in FIXTURE_TESTS.items():
            export = CASES[case_id]["export"]
            with self.subTest(test=name):
                intact = self.run_fixture_test(name, VALIDATORS)
                self.assertTrue(intact.wasSuccessful(), intact.failures + intact.errors)
                swapped = self.run_fixture_test(name, {**VALIDATORS, export: accept_all})
                self.assertEqual((len(swapped.failures), len(swapped.errors), swapped.testsRun), (1, 0, 1))

    def test_an_accept_all_validator_lets_a_defective_export_be_written(self) -> None:
        # The same swap on the write path: the validators are what stop a bad export.
        _, run = load_case("sarif-pass-kind-for-failed-check")
        sarif = fresh_sarif(run)
        sarif["runs"][0]["results"][0]["kind"] = "pass"
        self.assertIn(SARIF_KIND_MISMATCH, codes(validate_exports({RESULTS_SARIF: sarif}, run)))
        with mock.patch.object(_validators, "VALIDATORS", {**VALIDATORS, RESULTS_SARIF: accept_all}):
            self.assertEqual(validate_exports({RESULTS_SARIF: sarif}, run), ())


# ---------------------------------------------------------------------------
# The rules, one by one, including the inputs each must not reject
# ---------------------------------------------------------------------------


class RunJsonRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        _, self.run = load_case("sarif-pass-kind-for-failed-check")

    def test_the_count_must_equal_required_results_checked_with_an_invocation(self) -> None:
        self.assertEqual(validate_run_json(self.run), ())
        for value in (2, 4, None, True, "3"):
            with self.subTest(checks_executed=value):
                self.run["checks_executed"] = value
                self.assertEqual(codes(validate_run_json(self.run)), [RUN_CHECKS_EXECUTED_MISMATCH])

    def test_optional_and_uninvoked_results_are_not_executed_checks(self) -> None:
        self.run["checks"][0]["required"] = False
        self.run["checks"][1]["invocation_id"] = None
        self.run["checks_executed"] = 1
        self.assertEqual(validate_run_json(self.run), ())

    def test_an_unknown_declaration_needs_an_unknown_count(self) -> None:
        # An invalid manifest leaves checks_expected null: the count is unknown, never 0.
        self.run.update(checks=[], checks_expected=None, checks_executed=None)
        self.assertEqual(validate_run_json(self.run), ())
        self.run["checks_executed"] = 0
        self.assertEqual(codes(validate_run_json(self.run)), [RUN_CHECKS_EXECUTED_MISMATCH])

    def test_malformed_documents_are_problems_not_crashes(self) -> None:
        for document in ([], "run", {"checks": "none"}, {"checks": [1, 2]}):
            with self.subTest(document=document):
                self.assertEqual(codes(validate_run_json(document)), [RUN_JSON_MALFORMED])


class SarifRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        _, self.run = load_case("sarif-pass-kind-for-failed-check")
        self.sarif = fresh_sarif(self.run)
        self.results = self.sarif["runs"][0]["results"]
        self.invocation = self.sarif["runs"][0]["invocations"][0]

    def judge(self) -> list[str]:
        return codes(validate_sarif(self.sarif, self.run))

    def result(self, check_id: str) -> dict[str, Any]:
        (found,) = [item for item in self.results if item["properties"].get("check_id") == check_id]
        return found

    def test_the_derived_log_is_valid(self) -> None:
        self.assertEqual(self.judge(), [])

    def test_only_a_failure_may_carry_a_level(self) -> None:
        # Check 'reviews' ABSTAINed with PROTOCOL_BROKEN, so its kind must be 'open'.
        cases = (
            ("open", "warning", [SARIF_LEVEL_WITHOUT_FAIL]),
            ("pass", "note", [SARIF_KIND_MISMATCH, SARIF_LEVEL_WITHOUT_FAIL]),
            ("fail", "warning", [SARIF_KIND_MISMATCH]),
        )
        for kind, level, expected in cases:
            with self.subTest(kind=kind, level=level):
                self.setUp()
                self.result("reviews").update(kind=kind, level=level)
                self.assertEqual(sorted(self.judge()), expected)

    def test_sarif_defaults_apply_when_kind_or_level_is_absent(self) -> None:
        # An absent level defaults to none for a non-failure, and an absent kind means fail.
        del self.result("rows")["level"]
        del self.result("duplicates")["kind"]
        self.assertEqual(self.judge(), [])

    def test_a_finding_result_is_judged_by_level_but_not_as_a_check(self) -> None:
        self.results.append({"ruleId": "contract", "kind": "open", "level": "error", "properties": {"source": "x"}})
        self.assertEqual(self.judge(), [SARIF_LEVEL_WITHOUT_FAIL])

    def test_every_declared_check_appears_exactly_once_and_nothing_else(self) -> None:
        self.results.append(json.loads(json.dumps(self.result("rows"))))
        self.assertEqual(self.judge(), [SARIF_CHECK_UNEXPECTED])
        self.setUp()
        self.result("rows")["properties"]["check_id"] = "invented"
        self.assertEqual(sorted(self.judge()), sorted([SARIF_CHECK_UNEXPECTED, SARIF_CHECK_MISSING]))

    def test_each_kind_must_follow_the_run_json_classification(self) -> None:
        cases = {
            "notApplicable": ("NOT_APPLICABLE", "ABSTAIN", "OUT_OF_SCOPE"),
            "review": ("CHECKED", "ABSTAIN", "REQUIRES_HUMAN_REVIEW"),
            "open": ("SKIPPED", "ABSTAIN", "INSUFFICIENT_EVIDENCE"),
        }
        for kind, (state, verdict, reason) in cases.items():
            with self.subTest(kind=kind):
                self.setUp()
                # Check 'rows' PASSed, so its derived result says 'pass' until run.json says otherwise.
                recorded = next(item for item in self.run["checks"] if item["check_id"] == "rows")
                recorded.update(execution_state=state, verdict=verdict, reason=reason)
                self.assertEqual(self.judge(), [SARIF_KIND_MISMATCH])
                self.result("rows")["kind"] = kind
                self.assertEqual(self.judge(), [])

    def test_d7_an_error_run_reports_tool_failure_in_the_invocation(self) -> None:
        self.run["status"] = Status.ERROR.value
        self.assertEqual(sorted(self.judge()), sorted([SARIF_EXECUTION_SUCCESS_ON_ERROR,
                                                       SARIF_ERROR_WITHOUT_NOTIFICATION]))
        self.invocation["executionSuccessful"] = False
        self.invocation["toolExecutionNotifications"] = [{"level": "warning", "message": {"text": "synthetic"}}]
        self.assertEqual(self.judge(), [SARIF_ERROR_WITHOUT_NOTIFICATION])
        self.invocation["toolExecutionNotifications"].append({"level": "error", "message": {"text": "synthetic"}})
        self.assertEqual(self.judge(), [])
        del self.invocation["executionSuccessful"]
        self.assertEqual(self.judge(), [SARIF_EXECUTION_SUCCESS_ON_ERROR])

    def test_a_run_that_is_not_error_is_not_judged_on_tool_health(self) -> None:
        self.invocation["executionSuccessful"] = False
        self.assertEqual(self.judge(), [])

    def test_malformed_logs_are_problems_not_crashes(self) -> None:
        for sarif in ([], {"runs": []}, {"runs": [{}, {}]}, {"runs": [{"results": {}, "invocations": []}]},
                      {"runs": [{"results": [1], "invocations": []}]}):
            with self.subTest(sarif=sarif):
                self.assertEqual(codes(validate_sarif(sarif, self.run)), [SARIF_MALFORMED])
        self.assertEqual(codes(validate_sarif(self.sarif, [])), [RUN_JSON_MALFORMED])
        self.assertEqual(codes(validate_sarif(self.sarif, {"declared": {}, "checks": []})), [RUN_JSON_MALFORMED])
        unhashable = {**self.run, "declared": {"checks": [{"id": ["rows"]}]}}
        self.assertEqual(codes(validate_sarif(self.sarif, unhashable)), [RUN_JSON_MALFORMED])

    def test_unusable_ids_in_a_tampered_run_json_are_judged_not_crashed(self) -> None:
        self.run["checks"][0]["check_id"] = {"tampered": True}
        self.result("rows")["properties"]["check_id"] = ["rows"]
        problems = self.judge()
        self.assertIn(SARIF_CHECK_UNEXPECTED, problems)
        self.assertIn(SARIF_CHECK_MISSING, problems)


class ReportRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        _, self.run = load_case("report-missing-not-prove")
        self.text = render_report(self.run, files=(), html_note=None)

    def judge(self, text: str) -> list[str]:
        return codes(validate_report_md(text, self.run))

    def test_the_rendered_report_is_valid(self) -> None:
        self.assertEqual(self.judge(self.text), [])

    def test_a_heading_before_the_nine_breaks_the_order(self) -> None:
        self.assertEqual(self.judge("## PREFACE\n\n" + self.text), [REPORT_HEADING_ORDER])

    def test_deeper_headings_and_later_sections_do_not_count(self) -> None:
        self.assertEqual(self.judge("### NOTE\n\n" + self.text + "\n## STATUS\n"), [])

    def test_every_missing_heading_is_named(self) -> None:
        text = self.text.replace("## STATUS\n", "").replace("## WHAT PASSED\n", "")
        problems = validate_report_md(text, self.run)
        self.assertEqual(codes(problems), [REPORT_HEADING_MISSING, REPORT_HEADING_MISSING])
        self.assertIn("'STATUS'", problems[0])
        self.assertIn("'WHAT PASSED'", problems[1])

    def test_g5_the_run_rows_figure_is_named_once_with_run_json_value(self) -> None:
        line = "- " + rows_examined_line(6)
        self.assertEqual(line, "- rows_examined: 6 (distinct data rows of declared inputs read by an executed check)")
        self.assertEqual(self.text.count(line), 1)
        variants = {
            "absent": self.text.replace(line, ""),
            "repeated": self.text.replace(line, line + "\n" + line),
            "per-check sum": self.text.replace(line, "- " + rows_examined_line(29)),
        }
        for name, text in variants.items():
            with self.subTest(variant=name):
                self.assertEqual(self.judge(text), [REPORT_ROWS_EXAMINED_MISMATCH])

    def test_an_unknown_figure_reads_unknown_never_zero(self) -> None:
        self.run["rows_examined"] = None
        self.assertEqual(rows_examined_line(None), f"rows_examined: unknown ({_validators.ROWS_EXAMINED_MEANING})")
        self.assertEqual(self.judge(render_report(self.run, files=(), html_note=None)), [])
        self.assertEqual(self.judge(self.text), [REPORT_ROWS_EXAMINED_MISMATCH])

    def test_report_text_must_be_text(self) -> None:
        self.assertEqual(self.judge(b"## STATUS"), [REPORT_MALFORMED])  # type: ignore[arg-type]

    def test_the_headings_are_the_contract_nine(self) -> None:
        self.assertEqual(len(REPORT_HEADINGS), 9)
        self.assertEqual(REPORT_HEADINGS[-1], "WHAT THIS RESULT DOES NOT PROVE")


class ExportValidationErrorTests(unittest.TestCase):
    def test_the_message_is_the_first_problem_and_every_problem_is_kept(self) -> None:
        error = ExportValidationError(["A: first", "B: second", "C: third"])
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(error), "A: first (and 2 more)")
        self.assertEqual(error.problems, ("A: first", "B: second", "C: third"))
        self.assertEqual(str(ExportValidationError(["A: only"])), "A: only")

    def test_an_error_without_problems_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            ExportValidationError([])


# ---------------------------------------------------------------------------
# The validators on the write path and on re-verification
# ---------------------------------------------------------------------------


def no_html_renderer() -> Any:
    return mock.patch.dict(sys.modules, {HTML_RENDERER: None})


class WritePathTests(ProjectTestCase):
    def write_dir(self, run: Any, name: str = "run") -> Any:
        with no_html_renderer():
            return write_run(run, self.tmp / name, environ={})

    def sarif(self, name: str = "run") -> dict[str, Any]:
        return json.loads((self.tmp / name / RESULTS_SARIF).read_text(encoding="utf-8"))

    def test_a_defective_export_raises_and_nothing_is_written(self) -> None:
        run = self.run_verify()
        with mock.patch("science_gate.reports.sarif_classification", lambda check: ("pass", "error")):
            with self.assertRaises(ExportValidationError) as raised:
                self.write_dir(run)
        self.assertIn(SARIF_LEVEL_WITHOUT_FAIL, codes(raised.exception.problems))
        self.assertFalse((self.tmp / "run").exists())
        self.assertEqual(sorted(path.name for path in self.tmp.iterdir()), ["project"])

    def test_a_report_missing_a_heading_is_never_written(self) -> None:
        run = self.run_verify()
        broken = ("STATUS",) * 9
        with mock.patch("science_gate.reports.REPORT_HEADINGS", broken), self.assertRaises(ExportValidationError):
            self.write_dir(run)
        self.assertFalse((self.tmp / "run").exists())

    def test_d7_an_errored_check_makes_an_unsuccessful_invocation_with_a_notification(self) -> None:
        self.add_checks(check("boom", "raises"))
        run = self.run_verify(registry={**REGISTRY, "raises": f"{__name__}:raising_check"})
        self.assertEqual(run.status, Status.ERROR)
        self.write_dir(run)
        invocation = self.sarif()["runs"][0]["invocations"][0]
        self.assertIs(invocation["executionSuccessful"], False)
        errors = [item for item in invocation["toolExecutionNotifications"] if item["level"] == "error"]
        self.assertIn("boom", errors[0]["message"]["text"])

    def test_d7_an_error_from_a_refused_input_also_notifies(self) -> None:
        # Before D7 only manifest findings were notified, so this ERROR run had no notification.
        document = self.manifest()
        document["inputs"][0].update(path="../outside.csv", sha256=None)
        self.save_manifest(document)
        run = self.run_verify()
        self.assertEqual(run.status, Status.ERROR)
        self.write_dir(run)
        invocation = self.sarif()["runs"][0]["invocations"][0]
        self.assertIs(invocation["executionSuccessful"], False)
        sources = [item["properties"].get("source") for item in invocation["toolExecutionNotifications"]]
        self.assertIn("input:measurements", sources)

    def test_d7_an_invalid_manifest_run_is_written_and_valid(self) -> None:
        self.manifest_path.write_text("{not json", encoding="utf-8")
        run = self.run_verify()
        self.write_dir(run)
        run_json = json.loads((self.tmp / "run" / RUN_JSON).read_text(encoding="utf-8"))
        self.assertEqual((run_json["checks_expected"], run_json["checks_executed"]), (None, None))
        self.assertEqual(validate_sarif(self.sarif(), run_json), ())
        self.assertIs(self.sarif()["runs"][0]["invocations"][0]["executionSuccessful"], False)

    def test_sarif_properties_carry_the_controls_and_each_witness_state(self) -> None:
        run = self.run_verify()
        self.write_dir(run)
        run_json = json.loads((self.tmp / "run" / RUN_JSON).read_text(encoding="utf-8"))
        sarif = self.sarif()["runs"][0]
        self.assertEqual(sarif["properties"]["controls"], run_json["controls"])
        recorded = {item["check_id"]: item["evidence"].get("falsification") for item in run_json["checks"]}
        shown = {item["properties"]["check_id"]: item["properties"]["falsification"] for item in sarif["results"]
                 if "check_id" in item["properties"]}
        self.assertEqual(shown, recorded)


class StoredExportTests(ProjectTestCase):
    """``report RUN_DIR`` re-validates the stored exports: a tampered results.sarif is ERROR, exit 3."""

    def setUp(self) -> None:
        super().setUp()
        self.out = self.tmp / "run"
        with no_html_renderer():
            self.written = write_run(self.run_verify(), self.out, environ={})
        self.recorded_exit = self.written.exit_code

    def sarif(self) -> dict[str, Any]:
        return json.loads((self.out / RESULTS_SARIF).read_text(encoding="utf-8"))

    def save_sarif(self, sarif: Any) -> None:
        (self.out / RESULTS_SARIF).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    def cli_report(self) -> tuple[int, str]:
        stdout = io.StringIO()
        with no_html_renderer(), contextlib.redirect_stdout(stdout):
            code = main(["report", str(self.out)])
        return code, stdout.getvalue()

    def assert_tamper_rejected(self, tamper: Callable[[dict[str, Any]], None], code_expected: str) -> None:
        sarif = self.sarif()
        tamper(sarif)
        self.save_sarif(sarif)
        code, printed = self.cli_report()
        self.assertEqual(code, 3, printed)
        self.assertTrue(printed.startswith("ERROR (PROTOCOL_BROKEN)"), printed)
        report = (self.out / REPORT_MD).read_text(encoding="utf-8")
        self.assertIn("Re-verification of this run directory FAILED", report)
        self.assertIn(code_expected, report)

    def test_an_intact_run_keeps_its_recorded_exit_code(self) -> None:
        code, printed = self.cli_report()
        self.assertEqual(code, self.recorded_exit, printed)

    def test_a_flipped_result_kind_is_rejected_by_the_validator(self) -> None:
        def flip(sarif: dict[str, Any]) -> None:
            result = next(item for item in sarif["runs"][0]["results"] if "check_id" in item["properties"])
            result["kind"] = "notApplicable" if result["kind"] != "notApplicable" else "pass"
            result["level"] = "none"

        self.assert_tamper_rejected(flip, SARIF_KIND_MISMATCH)

    def test_a_dropped_check_result_is_rejected_by_the_validator(self) -> None:
        def drop(sarif: dict[str, Any]) -> None:
            results = sarif["runs"][0]["results"]
            results.remove(next(item for item in results if "check_id" in item["properties"]))

        self.assert_tamper_rejected(drop, SARIF_CHECK_MISSING)

    def test_an_edited_message_is_rejected_as_not_derived(self) -> None:
        def reword(sarif: dict[str, Any]) -> None:
            sarif["runs"][0]["results"][0]["message"]["text"] = "synthetic reassurance"

        self.assert_tamper_rejected(reword, SARIF_NOT_DERIVED)

    def test_an_unparseable_or_missing_log_is_rejected(self) -> None:
        (self.out / RESULTS_SARIF).write_text("{", encoding="utf-8")
        self.assertEqual(self.cli_report()[0], 3)
        (self.out / RESULTS_SARIF).unlink()
        code, _ = self.cli_report()
        self.assertEqual(code, 3)
        self.assertIn("FILE_MISSING: results.sarif", (self.out / REPORT_MD).read_text(encoding="utf-8"))

    def test_a_stored_run_json_that_breaks_its_validator_is_rejected(self) -> None:
        document = json.loads((self.out / RUN_JSON).read_text(encoding="utf-8"))
        document["checks"][0]["required"] = not document["checks"][0]["required"]
        (self.out / RUN_JSON).write_text(json.dumps(document), encoding="utf-8")
        with no_html_renderer():
            written = report_run_dir(self.out, environ={})
        self.assertEqual(written.exit_code, 3)
        self.assertIn(RUN_CHECKS_EXECUTED_MISMATCH, (self.out / REPORT_MD).read_text(encoding="utf-8"))

    def test_a_re_rendered_report_that_breaks_its_validator_fails_re_verification(self) -> None:
        calls: list[int] = []

        def reject_once(text: Any, run: Any) -> tuple[str, ...]:
            calls.append(1)
            return ("REPORT_HEADING_ORDER: synthetic rejection",) if len(calls) == 1 else ()

        with mock.patch.object(_validators, "VALIDATORS", {**VALIDATORS, REPORT_MD: reject_once}):
            with no_html_renderer():
                written = report_run_dir(self.out, environ={})
        self.assertEqual((written.status, written.exit_code), (Status.ERROR, 3))
        self.assertIn("synthetic rejection", (self.out / REPORT_MD).read_text(encoding="utf-8"))

    def test_a_report_that_can_never_be_valid_is_not_written(self) -> None:
        before = (self.out / REPORT_MD).read_bytes()
        always = {**VALIDATORS, REPORT_MD: lambda text, run: ("REPORT_HEADING_ORDER: synthetic rejection",)}
        with mock.patch.object(_validators, "VALIDATORS", always), no_html_renderer():
            with self.assertRaises(ExportValidationError):
                report_run_dir(self.out, environ={})
        self.assertEqual((self.out / REPORT_MD).read_bytes(), before)
        self.assertEqual(sorted(path.name for path in self.out.iterdir() if path.name.endswith(".incomplete")), [])

    def test_the_cli_command_exits_3_on_a_tampered_log(self) -> None:
        # The acceptance test of extension #12, through the real console entry point.
        sarif = self.sarif()
        result = next(item for item in sarif["runs"][0]["results"] if "check_id" in item["properties"])
        result.update(kind="review" if result["kind"] != "review" else "pass", level="none")
        self.save_sarif(sarif)
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONHASHSEED"}
        environment.update(PYTHONPATH=str(SRC_DIR), PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run(
            [sys.executable, "-m", "science_gate.cli", "report", str(self.out)],
            cwd=self.tmp,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(completed.returncode, 3, completed.stdout + completed.stderr)
        self.assertTrue(completed.stdout.startswith("ERROR (PROTOCOL_BROKEN)"), completed.stdout)


if __name__ == "__main__":
    unittest.main()
