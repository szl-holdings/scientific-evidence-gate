"""Run directories: files, report headings, SARIF, receipts, re-verification (sections 12, 17.9, 17.10).

Also the reports builder's tool gaps: G4 (an interrupted run never leaves a
verdict-bearing report.md without run.json) and G5 (one name per quantity).
Both were written to fail against the 0.1.0 writer first: it wrote files
straight into the output directory, so a full disk left ledger.jsonl and
report.md behind, and its report printed "Rows examined in scope" beside a
contract field with another meaning.
"""

from __future__ import annotations

import contextlib
import errno
import importlib.machinery
import io
import json
import re
import shutil
import sys
import types
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from _helpers import REPO_ROOT, try_symlink
from _project import REVIEWERS, ProjectTestCase, check, reviews_document

from science_gate import reports
from science_gate._canonical import canonical_bytes, sha256_bytes, sha256_canonical, strict_loads
from science_gate._safeio import SafeIOError, UnsafePathError
from science_gate._validators import ROWS_EXAMINED_MEANING, validate_report_md
from science_gate.cli import main
from science_gate.ledger import index_invocations, parse_jsonl, verify_chain
from science_gate.models import Ratio, Status
from science_gate.receipts import HMAC_KEY_FILE_ENV, verify_receipt
from science_gate.reports import (
    EVIDENCE_MANIFEST_JSON,
    HTML_RENDERER,
    INCOMPLETE_SUFFIX,
    LEDGER_JSONL,
    OUTPUT_EXISTS,
    PASS_CONTRACT_FIELDS,
    RECEIPT_AUTH_JSON,
    RECEIPT_JSON,
    REPORT_HEADINGS,
    REPORT_HTML,
    REPORT_MD,
    RESULTS_SARIF,
    RUN_FILES,
    RUN_INCOMPLETE,
    RUN_JSON,
    SARIF_SCHEMA,
    SARIF_VERSION,
    build_sarif,
    implied_predicate,
    render_report,
    report_run_dir,
    reverify_run_dir,
    sarif_classification,
    write_run,
)
from science_gate.verifier import REGISTRY, SUMMARY_SCHEMA, CheckContext, CheckOutcome

_HEADING = re.compile(r"^#{1,6} (.+)$", re.MULTILINE)
SYNTHETIC_HTML = "<!doctype html><title>synthetic</title>"
#: A synthetic run document with every section 17.8 control recorded (see fixtures/exporters).
CONTROLS_RUN = REPO_ROOT / "fixtures" / "exporters" / "report-missing-not-prove" / RUN_JSON


def raising_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    raise RuntimeError("synthetic failure inside a check")


def headings(text: str) -> list[str]:
    return _HEADING.findall(text)


def section(text: str, heading: str) -> str:
    """The body of one ``## heading`` section of a report."""
    return text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]


def html_renderer(render: Callable[[Any], Any]) -> Any:
    """Install a stand-in ``science_gate._html`` module for one test."""
    module = types.ModuleType(HTML_RENDERER)
    module.__spec__ = importlib.machinery.ModuleSpec(HTML_RENDERER, loader=None)
    module.render = render  # type: ignore[attr-defined]
    return mock.patch.dict(sys.modules, {HTML_RENDERER: module})


def no_html_renderer() -> Any:
    """Hide any installed renderer, so these tests do not depend on a later stage."""
    return mock.patch.dict(sys.modules, {HTML_RENDERER: None})


def failing_on_call(number: int) -> tuple[Callable[..., Path], list[str]]:
    """A ``safe_write`` stand-in that runs out of disk space on its ``number``-th call."""
    real = reports.safe_write
    calls: list[str] = []

    def write(root: Any, relpath: str, data: bytes) -> Path:
        calls.append(relpath)
        if len(calls) == number:
            raise OSError(errno.ENOSPC, "No space left on device (simulated)")
        return real(root, relpath, data)

    return write, calls


class RunDirectoryTestCase(ProjectTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.out = self.tmp / "run"

    def write_run_dir(self, *, environ: dict[str, str] | None = None, out: Path | None = None, **kwargs: Any) -> Any:
        run = self.run_verify(**kwargs)
        with no_html_renderer():
            return write_run(run, out or self.out, environ={} if environ is None else environ)

    def read_json(self, name: str, out: Path | None = None) -> Any:
        return json.loads(((out or self.out) / name).read_text(encoding="utf-8"))

    def report_text(self, out: Path | None = None) -> str:
        return ((out or self.out) / REPORT_MD).read_text(encoding="utf-8")

    def rerender(self, out: Path | None = None, **kwargs: Any) -> Any:
        with no_html_renderer():
            return report_run_dir(out or self.out, environ=kwargs.get("environ", {}))


class WrittenFilesTests(RunDirectoryTestCase):
    def test_every_file_is_written_in_contract_order(self) -> None:
        written = self.write_run_dir()
        self.assertEqual([path.name for path in written.paths], [name for name in RUN_FILES if name != REPORT_HTML])
        self.assertTrue(all(path.is_file() and path.parent == self.out for path in written.paths))
        self.assertEqual((written.status, written.exit_code), (Status.PASS, 0))
        self.assertTrue(written.headline.startswith("PASS (VERIFIED) run-"))

    def test_report_opens_with_the_nine_headings_in_order(self) -> None:
        self.write_run_dir()
        text = self.report_text()
        self.assertTrue(text.startswith("## STATUS\n"))
        self.assertEqual(headings(text)[: len(REPORT_HEADINGS)], list(REPORT_HEADINGS))
        self.assertEqual(headings(text)[len(REPORT_HEADINGS)], "FILES")
        self.assertIn(f"`{RECEIPT_AUTH_JSON}`", section(text, "FILES"))

    def test_run_json_carries_the_pass_contract_at_top_level(self) -> None:
        self.write_run_dir()
        document = self.read_json(RUN_JSON)
        for name in PASS_CONTRACT_FIELDS:
            with self.subTest(field=name):
                self.assertIn(name, document)
                self.assertIsNotNone(document[name])
        self.assertEqual(
            {name: document[name] for name in ("expected_inputs", "inputs_opened", "rows_examined")},
            {"expected_inputs": 1, "inputs_opened": 1, "rows_examined": 6},
        )
        self.assertEqual(document["checks_executed"], document["checks_expected"])
        self.assertEqual(document["counters"]["checks_passed"], document["checks_passed"])
        self.assertEqual(document["evidence_boundary"]["scientific_validity"], "NOT ESTABLISHED")
        self.assertIn("controls", document)

    def test_evidence_manifest_file_is_the_hashed_bytes(self) -> None:
        self.write_run_dir()
        data = (self.out / EVIDENCE_MANIFEST_JSON).read_bytes()
        recorded = self.read_json(RUN_JSON)["evidence_manifest_sha256"]
        self.assertEqual(sha256_bytes(data.rstrip(b"\n")), recorded)
        self.assertEqual(sha256_canonical(strict_loads(data)), recorded)

    def test_ledger_file_verifies_against_its_seal(self) -> None:
        self.write_run_dir()
        document = self.read_json(RUN_JSON)
        entries = parse_jsonl((self.out / LEDGER_JSONL).read_bytes())
        seal = (document["ledger_head_sha256"], document["ledger_length"])
        chain = verify_chain(entries, *seal, run_id=document["run_id"])
        self.assertTrue(chain.intact, chain.problems)
        traces = index_invocations(entries)
        for item in document["checks"]:
            self.assertTrue(traces[item["invocation_id"]].terminal)

    def test_missing_required_file_is_visible_in_every_output(self) -> None:
        # Requirement 6.
        document = self.manifest()
        document["inputs"].append({"id": "protocol", "path": "data/protocol.csv", "format": "csv"})
        self.save_manifest(document)
        written = self.write_run_dir()
        self.assertEqual(written.exit_code, 2)
        states = {item["id"]: item["state"] for item in self.read_json(RUN_JSON)["accounting"]["inputs"]}
        self.assertEqual(states["protocol"], "MISSING")
        absent = strict_loads((self.out / EVIDENCE_MANIFEST_JSON).read_bytes())["absent"]
        self.assertIn("protocol", [item["name"] for item in absent])
        predicate = self.read_json(RECEIPT_JSON)["predicate"]
        self.assertIn(("protocol", "MISSING"), [(item["id"], item["state"]) for item in predicate["inputs"]])
        self.assertIn("required input `protocol` is MISSING", self.report_text())

    def test_an_unsaved_graph_state_is_named_plainly_and_other_missing_documents_stay_missing(self) -> None:
        document = {
            "documents": [
                {"path": "graph/graph-state.json", "roles": ["dependencies.state"], "state": "MISSING"},
                {"path": "claims/registry.json", "roles": ["claims"], "state": "MISSING", "diagnostic": "MISSING: x"},
            ]
        }
        unresolved = section(render_report(document, files=(), html_note=None), "WHAT REMAINS UNRESOLVED")
        self.assertIn(
            "no saved graph state at `graph/graph-state.json`: the graph's declared node states were used", unresolved
        )
        self.assertIn("document `claims/registry.json` is MISSING", unresolved)

    def test_crafted_text_cannot_forge_a_heading(self) -> None:
        forged = {"status": "FAIL", "source": "input:x", "detail": "a\n## STATUS\nb"}
        document = {"status": "FAIL", "findings": [forged]}
        text = render_report(document, files=(), html_note="none")
        self.assertEqual(headings(text)[: len(REPORT_HEADINGS)], list(REPORT_HEADINGS))
        self.assertEqual(headings(text).count("STATUS"), 1)


class ReceiptTests(RunDirectoryTestCase):
    def test_missing_key_gives_an_unsigned_receipt(self) -> None:
        # Requirement 24, with the D9 layout: a bare statement plus a sidecar that says UNSIGNED.
        self.write_run_dir()
        statement, auth = self.read_json(RECEIPT_JSON), self.read_json(RECEIPT_AUTH_JSON)
        self.assertNotIn("body", statement)
        self.assertEqual(auth["signature_state"], "UNSIGNED")
        self.assertFalse({"signature", "key_id"} & set(auth), "an unsigned sidecar has no signature fields at all")
        self.assertEqual(auth["content_sha256"], sha256_canonical(statement))
        self.assertEqual(self.read_json(RUN_JSON)["receipt"]["content_sha256"], auth["content_sha256"])
        self.assertTrue(verify_receipt(self.out / RECEIPT_JSON, environ={}).ok)
        self.assertIn("the receipt is UNSIGNED", self.report_text())

    def test_a_configured_key_signs_and_re_verifies(self) -> None:
        key = self.write("keys/synthetic.key", b"synthetic-test-hmac-key-0123456789")
        environ = {HMAC_KEY_FILE_ENV: str(key)}
        self.write_run_dir(environ=environ)
        self.assertEqual(self.read_json(RUN_JSON)["receipt"]["signature_state"], "SIGNED_HMAC_SHA256")
        self.assertEqual(self.read_json(RECEIPT_AUTH_JSON)["signature_state"], "SIGNED_HMAC_SHA256")
        written = self.rerender(environ=environ)
        self.assertEqual(written.exit_code, self.read_json(RUN_JSON)["exit_code"])
        text = self.report_text()
        self.assertIn("signature SIGNED_HMAC_SHA256, signature verified true", text)
        self.assertNotIn("receipt: signature verified", text)  # a verified signature is not an open item

    def test_protected_content_change_alters_the_receipt_hash(self) -> None:
        # Requirement 23: an unchecked document changes, the PASS stays, the hash moves.
        self.write_file("claims/manuscript.md", "Synthetic manuscript, first draft.\n")
        self.update_manifest(manuscript="claims/manuscript.md")
        first_dir, second_dir = self.tmp / "first", self.tmp / "second"
        self.write_run_dir(out=first_dir)
        self.write_file("claims/manuscript.md", "Synthetic manuscript, second draft.\n")
        self.write_run_dir(out=second_dir)
        statements = (self.read_json(RECEIPT_JSON, first_dir), self.read_json(RECEIPT_JSON, second_dir))
        self.assertEqual([item["predicate"]["status"] for item in statements], ["PASS", "PASS"])
        hashes = [self.read_json(RECEIPT_AUTH_JSON, out)["content_sha256"] for out in (first_dir, second_dir)]
        self.assertNotEqual(hashes[0], hashes[1])


class SarifTests(RunDirectoryTestCase):
    def test_check_classification_follows_the_contract(self) -> None:
        cases = [
            (("CHECKED", "PASS", "VERIFIED"), ("pass", "none")),
            (("CHECKED", "FAIL", "SOURCE_MISMATCH"), ("fail", "error")),
            (("NOT_APPLICABLE", "ABSTAIN", "OUT_OF_SCOPE"), ("notApplicable", "none")),
            (("CHECKED", "ABSTAIN", "REQUIRES_HUMAN_REVIEW"), ("review", "none")),
            (("SKIPPED", "ABSTAIN", "INSUFFICIENT_EVIDENCE"), ("open", "none")),
            (("CHECKED", "ABSTAIN", "PROTOCOL_BROKEN"), ("open", "none")),
            (("SKIPPED", "ERROR", "PROTOCOL_BROKEN"), ("fail", "error")),
        ]
        for (state, verdict, reason), expected in cases:
            with self.subTest(state=state, verdict=verdict, reason=reason):
                item = {"execution_state": state, "verdict": verdict, "reason": reason}
                self.assertEqual(sarif_classification(item), expected)

    def test_sarif_file_is_2_1_0_with_consistent_rules(self) -> None:
        self.write_run_dir()
        sarif = self.read_json(RESULTS_SARIF)
        self.assertEqual((sarif["version"], sarif["$schema"]), (SARIF_VERSION, SARIF_SCHEMA))
        (run,) = sarif["runs"]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual(len(run["results"]), 6)
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
            self.assertEqual((result["kind"], result["level"]), ("pass", "none"))
            self.assertEqual(result["properties"]["falsification"], "WITNESSED")
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(run["artifacts"][0]["hashes"]["sha-256"], self.file_digest("data/measurements.csv"))

    def test_an_errored_check_is_a_failure_with_a_notification(self) -> None:
        self.add_checks(check("boom", "raises"))
        self.write_run_dir(registry={**REGISTRY, "raises": f"{__name__}:raising_check"})
        (run,) = self.read_json(RESULTS_SARIF)["runs"]
        (boom,) = [item for item in run["results"] if item["properties"].get("check_id") == "boom"]
        self.assertEqual((boom["kind"], boom["level"]), ("fail", "error"))
        invocation = run["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertIn("boom", invocation["toolExecutionNotifications"][0]["message"]["text"])

    def test_findings_outside_checks_become_results(self) -> None:
        self.write_json("reviews/verdicts.json", reviews_document("reviewer-a"))
        document = self.manifest()
        document["inputs"].append({"id": "protocol", "path": "data/protocol.csv", "format": "csv"})
        document["reviews"] = {"required_reviewers": REVIEWERS, "verdicts": "reviews/verdicts.json"}
        document["checks"].append(check("reviews", "reviewer_protocol", inputs=()))
        self.save_manifest(document)
        self.write_run_dir()
        results = {item["ruleId"]: item for item in build_sarif(self.read_json(RUN_JSON))["runs"][0]["results"]}
        missing = results["input"]
        self.assertEqual((missing["kind"], missing["level"]), ("open", "none"))
        location = missing["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertEqual(location["uri"], "data/protocol.csv")
        reviews = results["reviewer_protocol"]
        self.assertEqual((reviews["kind"], reviews["level"]), ("open", "none"))


class ReverificationTests(RunDirectoryTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_run_dir()

    def assert_rejected(self, problem: str) -> None:
        written = self.rerender()
        self.assertEqual((written.status, written.exit_code), (Status.ERROR, 3))
        text = self.report_text()
        self.assertEqual(headings(text)[: len(REPORT_HEADINGS)], list(REPORT_HEADINGS))
        self.assertIn("Re-verification of this run directory FAILED", text)
        self.assertIn(problem, text)

    def test_an_intact_run_re_verifies_with_its_recorded_status(self) -> None:
        written = self.rerender()
        self.assertEqual((written.status, written.exit_code), (Status.PASS, 0))
        self.assertEqual([path.name for path in written.paths], [REPORT_MD])
        text = self.report_text()
        self.assertEqual(headings(text)[: len(REPORT_HEADINGS)], list(REPORT_HEADINGS))
        self.assertIn("## RE-VERIFICATION", text)
        self.assertIn("Result: PASSED", text)
        self.assertEqual(validate_report_md(text, self.read_json(RUN_JSON)), ())

    def test_an_abstaining_run_keeps_exit_2(self) -> None:
        self.write_data("sample_id,site,value,count\n")
        self.update_manifest(inputs=[{**self.manifest()["inputs"][0], "expected_rows": 0}])
        abstained = self.tmp / "abstained"
        self.write_run_dir(out=abstained)
        self.assertEqual(self.rerender(abstained).exit_code, 2)

    def test_truncated_ledger_is_rejected(self) -> None:
        path = self.out / LEDGER_JSONL
        lines = path.read_bytes().splitlines(keepends=True)
        path.write_bytes(b"".join(lines[:-1]))
        self.assert_rejected("LENGTH_MISMATCH")

    def test_reordered_ledger_is_rejected(self) -> None:
        path = self.out / LEDGER_JSONL
        lines = path.read_bytes().splitlines(keepends=True)
        path.write_bytes(b"".join([lines[1], lines[0], *lines[2:]]))
        self.assert_rejected("CHAIN_BREAK")

    def edit_run_json(self, edit: Callable[[dict[str, Any]], None]) -> None:
        document = self.read_json(RUN_JSON)
        edit(document)
        (self.out / RUN_JSON).write_text(json.dumps(document), encoding="utf-8")

    def test_edited_run_status_is_rejected(self) -> None:
        self.edit_run_json(lambda document: document.update(status="FAIL"))
        self.assert_rejected("RUN_RECEIPT_MISMATCH")

    def test_run_json_implies_exactly_the_receipt_predicate(self) -> None:
        # Every predicate field is projected, so a new receipt field cannot go unchecked.
        predicate = self.read_json(RECEIPT_JSON)["predicate"]
        self.assertEqual(implied_predicate(self.read_json(RUN_JSON)), predicate)
        self.assertEqual(predicate["controls_sha256"], sha256_canonical(self.read_json(RUN_JSON)["controls"]))

    def test_every_attested_figure_is_cross_checked(self) -> None:
        def top_level_rows(document: dict[str, Any]) -> None:
            document["rows_examined"] = 600

        def counters(document: dict[str, Any]) -> None:
            document["counters"]["checks_failed"] = 0 if document["counters"]["checks_failed"] else 1

        def input_state(document: dict[str, Any]) -> None:
            document["accounting"]["inputs"][0]["state"] = "MISSING"

        def check_evidence(document: dict[str, Any]) -> None:
            document["checks"][0]["evidence"] = {"synthetic": "replaced"}

        def invariant(document: dict[str, Any]) -> None:
            document["invariants"][0]["holds"] = not document["invariants"][0]["holds"]

        def exit_code(document: dict[str, Any]) -> None:
            document["exit_code"] = 1

        def controls(document: dict[str, Any]) -> None:
            document["controls"]["canary"] = {"holds": True, "synthetic": "narrated canary"}

        def dropped_controls(document: dict[str, Any]) -> None:
            del document["controls"]

        pristine = (self.out / RUN_JSON).read_bytes()
        edits = (top_level_rows, counters, input_state, check_evidence, invariant, exit_code, controls)
        for edit in edits:
            with self.subTest(edit=edit.__name__):
                (self.out / RUN_JSON).write_bytes(pristine)
                self.edit_run_json(edit)
                self.assert_rejected("RUN_RECEIPT_MISMATCH")
        (self.out / RUN_JSON).write_bytes(pristine)
        self.edit_run_json(dropped_controls)
        self.assert_rejected("MALFORMED_RUN")

    def test_check_fields_outside_the_receipt_are_checked_against_the_ledger(self) -> None:
        self.edit_run_json(lambda document: document["checks"][0].update(diagnostics=["synthetic inserted note"]))
        self.assert_rejected("RUN_LEDGER_MISMATCH")

    def test_unknown_recorded_status_is_rejected(self) -> None:
        self.edit_run_json(lambda document: document.update(status=["PASS"]))
        self.assert_rejected("is not a known status")

    def test_unattested_content_is_labelled_as_recorded(self) -> None:
        self.rerender()
        self.assertIn("findings, declared manifest content and document list are shown as recorded", self.report_text())

    def test_edited_receipt_is_rejected(self) -> None:
        statement = self.read_json(RECEIPT_JSON)
        statement["predicate"]["rows_examined"] = 600
        (self.out / RECEIPT_JSON).write_bytes(canonical_bytes(statement) + b"\n")
        self.assert_rejected("CONTENT_HASH_MISMATCH")

    def test_edited_evidence_manifest_is_rejected(self) -> None:
        evidence = strict_loads((self.out / EVIDENCE_MANIFEST_JSON).read_bytes())
        evidence["absent"].append({"kind": "input", "name": "invented"})
        (self.out / EVIDENCE_MANIFEST_JSON).write_bytes(canonical_bytes(evidence))
        self.assert_rejected("EVIDENCE_MANIFEST_MISMATCH")

    def test_missing_receipt_is_rejected(self) -> None:
        (self.out / RECEIPT_JSON).unlink()
        self.assert_rejected("RECEIPT_MISSING")

    def test_missing_receipt_sidecar_is_rejected(self) -> None:
        (self.out / RECEIPT_AUTH_JSON).unlink()
        self.assert_rejected("AUTH_SIDECAR_MISSING")

    def test_unreadable_run_json_still_yields_the_nine_headings(self) -> None:
        (self.out / RUN_JSON).write_text("[1, 2", encoding="utf-8")
        self.assert_rejected("MALFORMED_FILE")

    def test_run_json_with_wrong_shapes_is_rejected_not_crashed(self) -> None:
        document = self.read_json(RUN_JSON)
        document["checks"] = ["not", "objects"]
        (self.out / RUN_JSON).write_text(json.dumps(document), encoding="utf-8")
        self.assert_rejected("MALFORMED_RUN")

    def test_a_missing_run_directory_is_never_created(self) -> None:
        missing = self.tmp / "no-such-run"
        with self.assertRaises(NotADirectoryError):
            report_run_dir(missing)
        self.assertFalse(missing.exists())


class HtmlRendererTests(RunDirectoryTestCase):
    def write_with(self, render: Callable[[Any], Any]) -> Any:
        run = self.run_verify()
        with html_renderer(render):
            return write_run(run, self.out, environ={})

    def test_absent_renderer_is_reported_not_hidden(self) -> None:
        written = self.write_run_dir()
        self.assertNotIn(REPORT_HTML, [path.name for path in written.paths])
        self.assertFalse((self.out / REPORT_HTML).exists())
        self.assertIn("report.html was not written: the HTML renderer (science_gate._html) is not installed",
                      self.report_text())

    def test_installed_renderer_receives_the_run_document(self) -> None:
        seen: list[Any] = []

        def render(document: Any) -> str:
            seen.append(document)
            return SYNTHETIC_HTML

        written = self.write_with(render)
        self.assertEqual(written.paths[-1].name, REPORT_HTML)
        self.assertEqual((self.out / REPORT_HTML).read_text(encoding="utf-8"), SYNTHETIC_HTML)
        self.assertEqual(seen[0]["run_id"], self.read_json(RUN_JSON)["run_id"])
        self.assertIn("`report.html`", self.report_text())

    def test_failing_renderer_is_recorded_and_does_not_change_the_status(self) -> None:
        def render(document: Any) -> str:
            raise ValueError("synthetic renderer failure")

        written = self.write_with(render)
        self.assertEqual(written.status.value, self.read_json(RUN_JSON)["status"])
        self.assertFalse((self.out / REPORT_HTML).exists())
        self.assertIn("the HTML renderer failed (ValueError: synthetic renderer failure)", self.report_text())

    def test_a_rendered_page_is_not_an_open_item(self) -> None:
        self.write_with(lambda document: SYNTHETIC_HTML)
        self.assertNotIn("report.html", section(self.report_text(), "WHAT REMAINS UNRESOLVED"))

    def test_a_page_the_renderer_cannot_refresh_is_flagged_as_stale(self) -> None:
        # A new run directory never holds an older page (G4), but a re-rendered one can.
        self.write_with(lambda document: SYNTHETIC_HTML)
        self.rerender()
        self.assertEqual((self.out / REPORT_HTML).read_text(encoding="utf-8"), SYNTHETIC_HTML)
        self.assertIn("the report.html already in this directory was left unchanged", self.report_text())

    def test_a_rejected_run_is_never_shown_to_the_renderer_as_trusted(self) -> None:
        seen: list[Any] = []

        def render(document: Any) -> str:
            seen.append(document)
            return SYNTHETIC_HTML

        self.write_with(render)
        recorded = self.read_json(RUN_JSON)
        with html_renderer(render):
            self.assertEqual(report_run_dir(self.out, environ={}).exit_code, recorded["exit_code"])
        self.assertEqual((seen[-1]["status"], seen[-1]["reverification"]["ok"]), (recorded["status"], True))
        (self.out / LEDGER_JSONL).write_bytes(b"".join((self.out / LEDGER_JSONL).read_bytes().splitlines(True)[:-1]))
        with html_renderer(render):
            self.assertEqual(report_run_dir(self.out, environ={}).exit_code, 3)
        rejected = seen[-1]
        self.assertEqual((rejected["status"], rejected["recorded_status"]), ("ERROR", recorded["status"]))
        self.assertFalse(rejected["reverification"]["ok"])


# ---------------------------------------------------------------------------
# G4: atomic run directories
# ---------------------------------------------------------------------------


class AtomicRunDirectoryTests(RunDirectoryTestCase):
    """An interrupted run never leaves a verdict-bearing report.md without run.json (G4)."""

    def staging(self, out: Path | None = None) -> Path:
        target = out or self.out
        return target.with_name(f".{target.name}{INCOMPLETE_SUFFIX}")

    def leftovers(self) -> list[str]:
        """Every file under the temporary directory that is not part of the project."""
        return sorted(
            path.relative_to(self.tmp).as_posix()
            for path in self.tmp.rglob("*")
            if path.is_file() and not path.is_relative_to(self.project)
        )

    def test_running_out_of_space_on_any_write_leaves_nothing_behind(self) -> None:
        run = self.run_verify()
        files = len([name for name in RUN_FILES if name != REPORT_HTML])
        for number in range(1, files + 1):
            with self.subTest(failing_write=number):
                failing, calls = failing_on_call(number)
                with no_html_renderer(), mock.patch.object(reports, "safe_write", failing):
                    with self.assertRaises(OSError) as raised:
                        write_run(run, self.out, environ={})
                self.assertEqual(raised.exception.errno, errno.ENOSPC)
                self.assertEqual(len(calls), number)
                self.assertFalse(self.out.exists(), "the output path never appears")
                self.assertFalse(self.staging().exists(), "the staging directory is removed")
                self.assertEqual(self.leftovers(), [], "no report.md, or any other file, survives")

    def test_run_json_is_written_last_even_into_the_staging_directory(self) -> None:
        run = self.run_verify()
        failing, calls = failing_on_call(1000)
        with no_html_renderer(), mock.patch.object(reports, "safe_write", failing):
            write_run(run, self.out, environ={})
        self.assertEqual(calls[-1], RUN_JSON)
        self.assertEqual(sorted(calls), sorted(name for name in RUN_FILES if name != REPORT_HTML))

    def test_a_failed_rename_leaves_nothing_behind(self) -> None:
        run = self.run_verify()
        real = reports.os.replace

        def refuse_directories(source: Any, target: Any) -> None:
            if Path(source).is_dir():
                raise OSError(errno.EXDEV, "synthetic rename failure")
            real(source, target)

        with no_html_renderer(), mock.patch.object(reports.os, "replace", refuse_directories):
            with self.assertRaises(OSError):
                write_run(run, self.out, environ={})
        self.assertFalse(self.out.exists())
        self.assertEqual(self.leftovers(), [])

    def test_a_transient_lock_on_the_rename_is_retried(self) -> None:
        run = self.run_verify()
        real = reports.os.replace
        refusals: list[Any] = []

        def locked_twice(source: Any, target: Any) -> None:
            if Path(source).is_dir() and len(refusals) < 2:
                refusals.append(source)
                raise PermissionError(errno.EACCES, "synthetic lock held by another process")
            real(source, target)

        with no_html_renderer(), mock.patch.object(reports.os, "replace", locked_twice):
            with mock.patch.object(reports, "_RENAME_RETRY_DELAYS", (0, 0, 0, 0)):
                write_run(run, self.out, environ={})
        self.assertEqual(len(refusals), 2)
        self.assertTrue((self.out / RUN_JSON).is_file())
        self.assertFalse(self.staging().exists())

    def test_a_non_empty_output_directory_is_refused_and_left_alone(self) -> None:
        run = self.run_verify()
        self.write("run/notes.txt", "synthetic earlier content")
        with no_html_renderer(), self.assertRaises(SafeIOError) as raised:
            write_run(run, self.out, environ={})
        self.assertEqual(raised.exception.code, OUTPUT_EXISTS)
        self.assertEqual(sorted(path.name for path in self.out.iterdir()), ["notes.txt"])
        self.assertFalse(self.staging().exists())

    def test_a_file_at_the_output_path_is_refused(self) -> None:
        run = self.run_verify()
        self.write("run", "synthetic file where a directory belongs")
        with no_html_renderer(), self.assertRaises(SafeIOError) as raised:
            write_run(run, self.out, environ={})
        self.assertEqual(raised.exception.code, OUTPUT_EXISTS)

    def test_an_empty_output_directory_is_replaced(self) -> None:
        self.out.mkdir()
        written = self.write_run_dir()
        self.assertTrue(all(path.is_file() for path in written.paths))

    def test_a_stale_staging_directory_cannot_leak_into_a_new_run(self) -> None:
        self.write(f".run{INCOMPLETE_SUFFIX}/{REPORT_HTML}", "<!doctype html><title>an interrupted run</title>")
        self.write(f".run{INCOMPLETE_SUFFIX}/{REPORT_MD}", "## STATUS\n\n**PASS**\n")
        self.write_run_dir()
        self.assertFalse((self.out / REPORT_HTML).exists())
        self.assertNotIn("an interrupted run", self.report_text())
        self.assertFalse(self.staging().exists())

    def test_the_output_path_is_never_a_link(self) -> None:
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        try_symlink(self, elsewhere, self.out, directory=True)
        run = self.run_verify()
        with no_html_renderer(), self.assertRaises(UnsafePathError):
            write_run(run, self.out, environ={})
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_directory_without_run_json_is_incomplete_and_never_rendered(self) -> None:
        self.write_run_dir()
        (self.out / RUN_JSON).unlink()
        before = {path.name: path.read_bytes() for path in self.out.iterdir()}
        written = self.rerender()
        self.assertEqual((written.status, written.exit_code, written.paths), (Status.ERROR, 3, ()))
        self.assertIn(RUN_INCOMPLETE, written.headline)
        self.assertEqual({path.name: path.read_bytes() for path in self.out.iterdir()}, before)
        verification, document = reverify_run_dir(self.out)
        self.assertEqual((verification.ok, document), (False, None))
        self.assertTrue(verification.problems[0].startswith(f"{RUN_INCOMPLETE}:"))

    def test_a_staging_directory_is_incomplete_even_with_every_file(self) -> None:
        self.write_run_dir()
        staged = self.staging()
        shutil.copytree(self.out, staged)
        written = self.rerender(staged)
        self.assertEqual((written.exit_code, written.paths), (3, ()))
        self.assertIn("did not finish", written.headline)

    def test_the_report_command_exits_3_on_an_incomplete_directory(self) -> None:
        self.out.mkdir()
        self.write("run/report.md", "## STATUS\n\n**PASS** (VERIFIED), exit code 0.\n")
        stdout = io.StringIO()
        with no_html_renderer(), contextlib.redirect_stdout(stdout):
            code = main(["report", str(self.out)])
        self.assertEqual(code, 3)
        self.assertTrue(stdout.getvalue().startswith(f"ERROR (PROTOCOL_BROKEN) {RUN_INCOMPLETE}:"), stdout.getvalue())

    def test_a_failed_re_render_keeps_both_previous_views(self) -> None:
        run = self.run_verify()
        with html_renderer(lambda document: SYNTHETIC_HTML):
            write_run(run, self.out, environ={})
        before = {name: (self.out / name).read_bytes() for name in (REPORT_MD, REPORT_HTML)}
        failing, _ = failing_on_call(2)
        with html_renderer(lambda document: "<!doctype html><title>re-rendered</title>"):
            with mock.patch.object(reports, "safe_write", failing), self.assertRaises(OSError):
                report_run_dir(self.out, environ={})
        self.assertEqual({name: (self.out / name).read_bytes() for name in before}, before)
        self.assertEqual([path.name for path in self.out.iterdir() if path.name.endswith(INCOMPLETE_SUFFIX)], [])


# ---------------------------------------------------------------------------
# G5: one name per quantity
# ---------------------------------------------------------------------------


class OneNamePerQuantityTests(RunDirectoryTestCase):
    """report.md names the run's rows_examined once; a check's own figure has its own name (G5)."""

    RUN_FIGURE = re.compile(r"rows_examined\s*[=:]\s*(\w+)")

    def test_the_run_figure_has_one_name_and_one_value(self) -> None:
        self.write_run_dir()
        text, document = self.report_text(), self.read_json(RUN_JSON)
        figure = document["rows_examined"]
        line = f"- rows_examined: {figure} ({ROWS_EXAMINED_MEANING})"
        self.assertEqual([item for item in text.splitlines() if item.startswith("- rows_examined")], [line])
        self.assertNotIn("Rows examined in scope", text)
        self.assertIsNone(re.search(r"rows examined", text, re.IGNORECASE), "the run figure is never renamed")
        self.assertEqual(set(self.RUN_FIGURE.findall(text)), {str(figure)}, "every rows_examined is the run figure")

    def test_each_check_figure_appears_only_on_its_own_line(self) -> None:
        self.write_run_dir()
        text, document = self.report_text(), self.read_json(RUN_JSON)
        named = re.findall(r"^- `([^`]+)`.*subject records examined (\w+)", text, re.MULTILINE)
        self.assertEqual(
            sorted(named), sorted((item["check_id"], str(item["rows_examined"])) for item in document["checks"])
        )
        self.assertNotIn("subject records examined", section(text, "WHAT ACTUALLY RAN"))

    def test_the_per_check_sum_is_never_printed(self) -> None:
        # The starter project's checks examine 6 + 6 + 6 + 6 + 3 + 2 = 29 subject records over 6 data rows.
        self.write_run_dir()
        document = self.read_json(RUN_JSON)
        total = sum(item["rows_examined"] for item in document["checks"])
        self.assertEqual((total, document["rows_examined"]), (29, 6))
        counted = [line for line in self.report_text().splitlines() if re.search(r"rows|records", line, re.I)]
        self.assertTrue(counted)
        for line in counted:
            self.assertNotIn(str(total), re.findall(r"\b\d+\b", line), line)

    def test_a_header_only_input_with_a_pinned_summary_reads_zero_data_rows(self) -> None:
        # G1 seen through G5: a summary pin is a comparison, never a data row.
        self.write_data("sample_id,site,value,count\n")
        data = (self.project / "data" / "measurements.csv").read_bytes()
        document = self.manifest()
        document["inputs"][0]["expected_rows"] = 0
        document["summary_claim"] = "claims/summary.json"
        document["checks"].append(check("summary", "summary_consistency", inputs=()))
        self.save_manifest(document)
        pinned = {"inputs": {"measurements": {"sha256": sha256_bytes(data)}}, "documents": {}}
        self.write_json("claims/summary.json", {"schema": SUMMARY_SCHEMA, "status": "PASS", "pinned": pinned})
        self.write_run_dir()
        text, run = self.report_text(), self.read_json(RUN_JSON)
        self.assertEqual(run["rows_examined"], 0)
        self.assertNotEqual(run["status"], "PASS")
        self.assertIn(f"- rows_examined: 0 ({ROWS_EXAMINED_MEANING})", text)
        self.assertEqual(set(self.RUN_FIGURE.findall(text)), {"0"})


# ---------------------------------------------------------------------------
# Section 17 controls in report.md
# ---------------------------------------------------------------------------


class ControlsRenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run = json.loads(CONTROLS_RUN.read_text(encoding="utf-8"))
        self.controls = self.run["controls"]

    def render(self) -> str:
        return render_report(self.run, files=(), html_note=None)

    def ran(self) -> str:
        return section(self.render(), "WHAT ACTUALLY RAN")

    def test_what_actually_ran_lists_the_plan_controls_and_witness_states(self) -> None:
        ran = self.ran()
        plan = self.controls["plan"]
        self.assertIn(
            f"- PLAN: ledger entry 1, entry sha256 `{plan['entry_sha256']}`, written before any check ran: 1 input(s), "
            f"3 check(s) and 4 pin(s) planned, manifest sha256 `{plan['manifest_sha256']}`",
            ran,
        )
        self.assertIn("CHECKED, PASS; falsifier witness WITNESSED (1 of 1 case(s) rejected as expected)", ran)
        self.assertIn("CHECKED, FAIL; no falsifier ran (only a would-be PASS is falsified)", ran)
        self.assertIn("3 of 3 known pair(s) compared as expected; holds", ran)
        canary = self.controls["canary"]
        self.assertIn(
            f"- canary: must_fail invocation `{canary['must_fail']['invocation_id']}` gave FAIL (SOURCE_MISMATCH), "
            f"expected FAIL; must_pass invocation `{canary['must_pass']['invocation_id']}` gave PASS (VERIFIED), "
            "expected PASS; holds",
            ran,
        )
        self.assertIn("- harness pins: 4 file(s) pinned; changed: none; writes to pinned paths: none; holds", ran)
        self.assertIn(
            "- falsifier witnesses: WITNESSED 1 (`rows`), REFUTED 0, UNWITNESSED 0, NO_CASE 0, NO_GENERATOR 0; "
            "1 falsifier invocation(s)",
            ran,
        )
        self.assertIn("- claim-to-invocation join: no claim_join check ran", ran)

    def test_failed_controls_are_said_plainly(self) -> None:
        self.controls["canary"]["holds"] = False
        self.controls["comparator_self_test"]["pairs"][0]["actual"] = "AGREES_AT_STATED_PRECISION"
        self.controls["comparator_self_test"]["holds"] = False
        self.controls["pins"].update(
            changed=["data/measurements.csv"], writes=[{"path": "data/measurements.csv", "action": "write",
                                                         "event": "open"}], holds=False
        )
        self.controls["falsifiers"].update(WITNESSED=[], REFUTED=["rows"])
        rows = next(item for item in self.run["checks"] if item["check_id"] == "rows")
        rows["evidence"]["falsification"] = "REFUTED"
        rows["evidence"]["falsifiers"][0]["outcome"] = "ACCEPTED"
        ran = self.ran()
        self.assertIn("2 of 3 known pair(s) compared as expected; DOES NOT HOLD", ran)
        self.assertIn("expected PASS; DOES NOT HOLD", ran)
        self.assertIn(
            "changed: data/measurements.csv; writes to pinned paths: write `data/measurements.csv`; DOES NOT HOLD", ran
        )
        self.assertIn("WITNESSED 0, REFUTED 1 (`rows`)", ran)
        self.assertIn("falsifier witness REFUTED (0 of 1 case(s) rejected as expected)", ran)

    def test_missing_controls_read_not_recorded_never_held(self) -> None:
        self.run["controls"] = {key: None for key in self.controls} | {"verdict_transitions": []}
        text = self.render()
        ran = section(text, "WHAT ACTUALLY RAN")
        for line in (
            "PLAN: not recorded",
            "comparator self-test: not recorded",
            "canary: not recorded",
            "harness pins: not recorded",
            "falsifier witnesses: not recorded",
        ):
            self.assertIn(line, ran)
        self.assertNotIn("holds", ran)
        self.assertIn("Verdict rises: no contribution was recorded", section(text, "STATUS"))
        del self.run["controls"]
        self.assertIn("Verdict rises: not recorded", section(self.render(), "STATUS"))
        rows = next(item for item in self.run["checks"] if item["check_id"] == "rows")
        del rows["evidence"]["falsification"]
        self.assertIn("CHECKED, PASS; falsifier witness not recorded", section(self.render(), "WHAT ACTUALLY RAN"))

    def test_the_claim_join_counts_are_listed(self) -> None:
        # The five-assertion case of extension #6: one BACKED, two NARRATED, one CONTRADICTED, one ORPHANED.
        self.controls["claim_join"] = {"BACKED": 1, "NARRATED": 2, "CONTRADICTED": 1, "ORPHANED": 1}
        self.assertIn("- claim-to-invocation join: BACKED 1, NARRATED 2, CONTRADICTED 1, ORPHANED 1", self.ran())

    def test_the_weakest_discrimination_qualifies_what_passed(self) -> None:
        passed = section(self.render(), "WHAT PASSED")
        self.assertIn("Weakest discrimination: no PASS result records a discrimination ratio", passed)
        self.controls["min_discrimination"] = {
            "check_id": "values",
            "discrimination": "0.9524",
            "ratio": Ratio(20, 21).to_dict(),
        }
        passed = section(self.render(), "WHAT PASSED")
        self.assertIn(
            "Weakest discrimination among PASS results: `values` rejected 20/21 nearby claims (decimal 0.9524, "
            "DEFINED)",
            passed,
        )

    def test_a_zero_denominator_never_renders_as_a_percentage(self) -> None:
        ratio = Ratio(0, 0).to_dict()
        self.controls["min_discrimination"] = {"check_id": "values", "discrimination": None, "ratio": ratio}
        passed = section(self.render(), "WHAT PASSED")
        self.assertIn("rejected 0/0 nearby claims (decimal unknown, ZERO_DENOMINATOR)", passed)

    def test_verdict_rises_explain_the_status(self) -> None:
        self.assertIn(
            "- Verdict rises: NONE -> PASS at step 1 (`check:rows`, VERIFIED); PASS -> FAIL at step 2 "
            "(`check:duplicates`, SOURCE_MISMATCH)",
            section(self.render(), "STATUS"),
        )

    def test_the_limits_of_a_witness_and_of_the_write_hook_are_stated(self) -> None:
        not_proven = section(self.render(), "WHAT THIS RESULT DOES NOT PROVE")
        hook = "File reads and writes made by a subprocess or by C-extension code are invisible to it"
        self.assertIn(hook, not_proven)
        self.assertIn("it does not show that the checker rejects every defect", not_proven)

    def test_the_rendered_report_passes_its_validator(self) -> None:
        self.assertEqual(validate_report_md(self.render(), self.run), ())


if __name__ == "__main__":
    unittest.main()
