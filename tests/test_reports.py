"""Run directories: files, report headings, SARIF, receipts and re-verification (section 12)."""

from __future__ import annotations

import importlib.machinery
import json
import re
import sys
import types
import unittest
from typing import Any, Callable
from unittest import mock

from _project import REVIEWERS, ProjectTestCase, check, reviews_document

from science_gate._canonical import canonical_bytes, sha256_bytes, sha256_canonical, strict_loads
from science_gate.ledger import index_invocations, parse_jsonl, verify_chain
from science_gate.models import Status
from science_gate.receipts import HMAC_KEY_FILE_ENV, verify_receipt
from science_gate.reports import (
    EVIDENCE_MANIFEST_JSON,
    HTML_RENDERER,
    LEDGER_JSONL,
    PASS_CONTRACT_FIELDS,
    RECEIPT_JSON,
    REPORT_HEADINGS,
    REPORT_HTML,
    REPORT_MD,
    RESULTS_SARIF,
    RUN_FILES,
    RUN_JSON,
    SARIF_VERSION,
    build_sarif,
    render_report,
    report_run_dir,
    sarif_classification,
    write_run,
)
from science_gate.verifier import REGISTRY, CheckContext, CheckOutcome

_HEADING = re.compile(r"^#{1,6} (.+)$", re.MULTILINE)
SYNTHETIC_HTML = "<!doctype html><title>synthetic</title>"


def raising_check(ctx: CheckContext, spec: Any) -> CheckOutcome:
    raise RuntimeError("synthetic failure inside a check")


def headings(text: str) -> list[str]:
    return _HEADING.findall(text)


def html_renderer(render: Callable[[Any], Any]) -> Any:
    """Install a stand-in ``science_gate._html`` module for one test."""
    module = types.ModuleType(HTML_RENDERER)
    module.__spec__ = importlib.machinery.ModuleSpec(HTML_RENDERER, loader=None)
    module.render = render  # type: ignore[attr-defined]
    return mock.patch.dict(sys.modules, {HTML_RENDERER: module})


def no_html_renderer() -> Any:
    """Hide any installed renderer, so these tests do not depend on a later stage."""
    return mock.patch.dict(sys.modules, {HTML_RENDERER: None})


class RunDirectoryTestCase(ProjectTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.out = self.tmp / "run"

    def write_run_dir(self, *, environ: dict[str, str] | None = None, **verify_kwargs: Any) -> Any:
        run = self.run_verify(**verify_kwargs)
        with no_html_renderer():
            return write_run(run, self.out, environ={} if environ is None else environ)

    def read_json(self, name: str) -> Any:
        return json.loads((self.out / name).read_text(encoding="utf-8"))

    def report_text(self) -> str:
        return (self.out / REPORT_MD).read_text(encoding="utf-8")

    def rerender(self, **kwargs: Any) -> Any:
        with no_html_renderer():
            return report_run_dir(self.out, environ=kwargs.get("environ", {}))


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
        predicate = self.read_json(RECEIPT_JSON)["body"]["predicate"]
        self.assertIn(("protocol", "MISSING"), [(item["id"], item["state"]) for item in predicate["inputs"]])
        self.assertIn("required input `protocol` is MISSING", self.report_text())

    def test_crafted_text_cannot_forge_a_heading(self) -> None:
        forged = {"status": "FAIL", "source": "input:x", "detail": "a\n## STATUS\nb"}
        document = {"status": "FAIL", "findings": [forged]}
        text = render_report(document, files=(), html_note="none")
        self.assertEqual(headings(text)[: len(REPORT_HEADINGS)], list(REPORT_HEADINGS))
        self.assertEqual(headings(text).count("STATUS"), 1)


class ReceiptTests(RunDirectoryTestCase):
    def test_missing_key_gives_an_unsigned_receipt(self) -> None:
        # Requirement 24.
        self.write_run_dir()
        receipt = self.read_json(RECEIPT_JSON)
        signature = (receipt["signature_state"], receipt["signature"], receipt["key_id"])
        self.assertEqual(signature, ("UNSIGNED", None, None))
        self.assertTrue(verify_receipt(self.out / RECEIPT_JSON, environ={}).ok)
        self.assertIn("the receipt is UNSIGNED", self.report_text())

    def test_a_configured_key_signs_and_re_verifies(self) -> None:
        key = self.write("keys/synthetic.key", b"synthetic-test-hmac-key-0123456789")
        environ = {HMAC_KEY_FILE_ENV: str(key)}
        self.write_run_dir(environ=environ)
        self.assertEqual(self.read_json(RUN_JSON)["receipt"]["signature_state"], "SIGNED_HMAC_SHA256")
        written = self.rerender(environ=environ)
        self.assertEqual(written.exit_code, 0)
        text = self.report_text()
        self.assertIn("signature SIGNED_HMAC_SHA256, signature verified true", text)
        self.assertNotIn("receipt: signature verified", text)  # a verified signature is not an open item

    def test_protected_content_change_alters_the_receipt_hash(self) -> None:
        # Requirement 23: an unchecked document changes, the PASS stays, the hash moves.
        self.write_file("claims/manuscript.md", "Synthetic manuscript, first draft.\n")
        self.update_manifest(manuscript="claims/manuscript.md")
        self.write_run_dir()
        first = self.read_json(RECEIPT_JSON)
        self.write_file("claims/manuscript.md", "Synthetic manuscript, second draft.\n")
        self.write_run_dir()
        second = self.read_json(RECEIPT_JSON)
        statuses = (first["body"]["predicate"]["status"], second["body"]["predicate"]["status"])
        self.assertEqual(statuses, ("PASS", "PASS"))
        self.assertNotEqual(first["content_sha256"], second["content_sha256"])


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
        self.assertEqual(sarif["version"], SARIF_VERSION)
        (run,) = sarif["runs"]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual(len(run["results"]), 6)
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
            self.assertEqual((result["kind"], result["level"]), ("pass", "none"))
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

    def test_an_abstaining_run_keeps_exit_2(self) -> None:
        self.write_data("sample_id,site,value,count\n")
        self.update_manifest(inputs=[{**self.manifest()["inputs"][0], "expected_rows": 0}])
        self.write_run_dir()
        self.assertEqual(self.rerender().exit_code, 2)

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

    def test_edited_run_status_is_rejected(self) -> None:
        document = self.read_json(RUN_JSON)
        document["status"] = "FAIL"
        (self.out / RUN_JSON).write_text(json.dumps(document), encoding="utf-8")
        self.assert_rejected("RUN_RECEIPT_MISMATCH")

    def test_edited_receipt_is_rejected(self) -> None:
        receipt = self.read_json(RECEIPT_JSON)
        receipt["body"]["predicate"]["rows_examined"] = 600
        (self.out / RECEIPT_JSON).write_bytes(canonical_bytes(receipt))
        self.assert_rejected("CONTENT_HASH_MISMATCH")

    def test_edited_evidence_manifest_is_rejected(self) -> None:
        evidence = strict_loads((self.out / EVIDENCE_MANIFEST_JSON).read_bytes())
        evidence["absent"].append({"kind": "input", "name": "invented"})
        (self.out / EVIDENCE_MANIFEST_JSON).write_bytes(canonical_bytes(evidence))
        self.assert_rejected("EVIDENCE_MANIFEST_MISMATCH")

    def test_missing_receipt_is_rejected(self) -> None:
        (self.out / RECEIPT_JSON).unlink()
        self.assert_rejected("RECEIPT_MISSING")

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
        self.assertEqual(written.status, Status.PASS)
        self.assertFalse((self.out / REPORT_HTML).exists())
        self.assertIn("the HTML renderer failed (ValueError: synthetic renderer failure)", self.report_text())


if __name__ == "__main__":
    unittest.main()
