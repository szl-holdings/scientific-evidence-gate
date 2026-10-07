"""Run receipts: the statement, its authentication sidecar, content hash, HMAC and verification (sections 11, 17.9)."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from _helpers import TempDirTestCase, build_scenario

from science_gate import TOOL_NAME, __version__
from science_gate._canonical import canonical_bytes, sha256_bytes, sha256_canonical, strict_loads
from science_gate._safeio import UnsafePathError
from science_gate.invariants import INVARIANT_NAMES
from science_gate.models import AuthStatus, InputState, SignatureState, WitnessState, empty_controls
from science_gate.receipts import (
    AUTH_ALGORITHM,
    AUTH_FILE,
    AUTH_SCHEMA,
    BODY_KEYS,
    DISCLAIMER,
    HMAC_KEY_FILE_ENV,
    MAX_KEY_BYTES,
    PREDICATE_TYPE,
    RECEIPT_SCHEMA,
    RECORD_KEYS,
    SIGNED_AUTH_KEYS,
    STATEMENT_FILE,
    UNSIGNED_AUTH_KEYS,
    KeyResolution,
    ReceiptError,
    SigningKey,
    auth_file_name,
    build_body,
    build_run_receipt,
    receipt_bytes,
    receipt_files,
    resolve_signing_key,
    run_predicate,
    seal_body,
    verify_receipt,
    verify_receipt_documents,
    write_receipt,
)

#: A synthetic key used only by these tests.
KEY_BYTES = b"synthetic-test-hmac-key-0123456789"


class ReceiptTestCase(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.scenario = build_scenario(self)
        self.seal = self.scenario.ledger.seal()
        self.key_file = self.write("keys/hmac.key", KEY_BYTES)

    def receipt(self, run: Any = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
        return build_run_receipt(
            run or self.scenario.run_result(),
            ledger_head_sha256=self.seal["ledger_head_sha256"],
            ledger_length=self.seal["ledger_length"],
            environ={} if environ is None else environ,
        )

    def signed_environ(self) -> dict[str, str]:
        return {HMAC_KEY_FILE_ENV: str(self.key_file)}

    def files(self, record: dict[str, Any], name: str = STATEMENT_FILE) -> tuple[dict[str, Any], dict[str, Any]]:
        """The parsed statement and sidecar that ``record`` becomes."""
        written = receipt_files(record, statement_name=name)
        return strict_loads(written[name], integers_only=True), strict_loads(written[auth_file_name(name)])


class ReceiptBodyTests(ReceiptTestCase):
    def test_body_follows_the_contract_shape(self) -> None:
        body = self.receipt()["body"]
        self.assertEqual(set(body), BODY_KEYS)
        self.assertEqual((body["schema"], body["predicate_type"]), (RECEIPT_SCHEMA, PREDICATE_TYPE))
        self.assertEqual(body["disclaimer"], DISCLAIMER)
        self.assertEqual(
            DISCLAIMER,
            "A receipt supports integrity, provenance, and replayability. It does not establish scientific truth, "
            "accuracy, safety, or fitness for use.",
        )
        self.assertEqual(body["evidence_boundary"]["scientific_validity"], "NOT ESTABLISHED")
        self.assertEqual(set(body["evidence_boundary"]), {"integrity", "performance", "scientific_validity"})
        digest = self.scenario.opened["measurements"].sha256
        self.assertEqual(body["subject"], [{"name": "measurements", "digest": {"sha256": digest}}])

    def test_predicate_carries_the_run_summary(self) -> None:
        predicate = self.receipt()["body"]["predicate"]
        run = self.scenario.run_result()
        self.assertEqual((predicate["status"], predicate["reason"], predicate["run_id"]), ("PASS", "VERIFIED", run.run_id))
        self.assertEqual(predicate["ledger_head_sha256"], self.seal["ledger_head_sha256"])
        self.assertEqual(predicate["ledger_length"], self.seal["ledger_length"])
        self.assertEqual(predicate["evidence_manifest_sha256"], run.evidence_manifest_sha256)
        self.assertEqual(predicate["tool"], {"name": TOOL_NAME, "version": __version__})
        self.assertEqual(predicate["counters"], dict(run.counters))
        (check,) = predicate["checks"]
        self.assertEqual(check["invocation_id"], self.scenario.checks[0].invocation_id)
        self.assertEqual(check["evidence_sha256"], sha256_canonical(self.scenario.checks[0].evidence))
        self.assertEqual([item["name"] for item in predicate["invariants"]], sorted(INVARIANT_NAMES))

    def test_predicate_attests_the_checker_controls(self) -> None:
        # 17.8: controls_sha256 = sha256_canonical(run.controls), so a changed witness moves the hash.
        baseline = self.receipt()
        self.assertEqual(baseline["body"]["predicate"]["controls_sha256"], sha256_canonical(empty_controls()))
        controls = dict(empty_controls(), canary={"holds": True})
        altered = self.receipt(self.scenario.run_result(controls=controls))
        self.assertEqual(altered["body"]["predicate"]["controls_sha256"], sha256_canonical(controls))
        self.assertEqual(altered["body"]["predicate"]["status"], baseline["body"]["predicate"]["status"])
        self.assertNotEqual(altered["content_sha256"], baseline["content_sha256"])

    def test_statements_describe_evidence_without_claiming_validity(self) -> None:
        boundary = self.receipt()["body"]["evidence_boundary"]
        self.assertIn("SHA-256 recorded for 1 of 1 declared input(s)", boundary["integrity"])
        self.assertIn(f"ledger head {self.seal['ledger_head_sha256']}", boundary["integrity"])
        self.assertIn("Run status PASS (VERIFIED)", boundary["performance"])
        for text in boundary["integrity"], boundary["performance"]:
            self.assertNotIn("scientifically", text.lower())

    def test_missing_inputs_remain_visible_in_the_receipt(self) -> None:
        # Requirement 6: no digest means no subject, but the input is still listed with its state.
        accounting = self.scenario.accounting
        record = accounting.record("measurements")
        missing = dataclasses.replace(
            record,
            input_id="protocol",
            path="data/protocol.csv",
            state=InputState.MISSING,
            sha256=None,
            discovered=False,
            opened=False,
            parsed=False,
        )
        both = dataclasses.replace(accounting, records=(record, missing))
        run = self.scenario.run_result(status="ABSTAIN", reason="INSUFFICIENT_EVIDENCE", accounting=both)
        body = self.receipt(run)["body"]
        self.assertEqual([item["name"] for item in body["subject"]], ["measurements"])
        listed = {item["id"]: item for item in body["predicate"]["inputs"]}
        self.assertEqual((listed["protocol"]["state"], listed["protocol"]["sha256"]), ("MISSING", None))
        self.assertIn("no digest for protocol (MISSING)", body["evidence_boundary"]["integrity"])

    def test_body_is_independent_of_declaration_order(self) -> None:
        first = build_body(subjects={"b": "1" * 64, "a": "2" * 64}, predicate={}, integrity="i", performance="p")
        second = build_body(subjects={"a": "2" * 64, "b": "1" * 64}, predicate={}, integrity="i", performance="p")
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual([item["name"] for item in first["subject"]], ["a", "b"])

    def test_invalid_body_inputs_are_refused(self) -> None:
        with self.assertRaises(ReceiptError):
            build_body(subjects={"a": "XYZ"}, predicate={}, integrity="i", performance="p")
        with self.assertRaises(ReceiptError):
            build_body(subjects={}, predicate={}, integrity="  ", performance="p")
        run = self.scenario.run_result()
        for head, length in ((None, 3), ("a" * 64, 0), ("A" * 64, 3), (None, -1)):
            with self.subTest(head=head, length=length), self.assertRaises(ReceiptError):
                run_predicate(run, ledger_head_sha256=head, ledger_length=length)


class PerformanceStatementTests(ReceiptTestCase):
    """D4: the performance plane is two labelled parts, CHECKER then RUN."""

    def performance(self, **controls: Any) -> str:
        run = self.scenario.run_result(controls=dict(empty_controls(), **controls))
        return str(self.receipt(run)["body"]["evidence_boundary"]["performance"])

    def test_checker_part_comes_first_then_the_run_tally(self) -> None:
        text = self.performance()
        self.assertTrue(text.startswith("CHECKER: "), text)
        tally = "1 PASS, 0 FAIL, 0 ABSTAIN, 0 ERROR"
        self.assertIn(f". RUN: Run status PASS (VERIFIED) from 1 check result(s): {tally}", text)
        self.assertLess(text.index("CHECKER:"), text.index("RUN:"))

    def test_unrecorded_controls_are_said_to_be_missing_never_held(self) -> None:
        text = self.performance()
        self.assertIn(
            "CHECKER: falsifier witnesses not recorded; must-fail/must-pass canary not recorded; "
            "comparator self-test not recorded. RUN:",
            text,
        )
        self.assertNotIn("held", text)

    def test_recorded_controls_are_counted(self) -> None:
        falsifiers = {state.value: [] for state in WitnessState}
        falsifiers.update(WITNESSED=["columns", "rows"], NO_GENERATOR=["custom"], invocations=2)
        text = self.performance(
            falsifiers=falsifiers, canary={"holds": True}, comparator_self_test={"holds": False}
        )
        self.assertIn(
            "CHECKER: falsifier witnesses 2 WITNESSED, 0 REFUTED, 0 UNWITNESSED, 0 NO_CASE, 1 NO_GENERATOR "
            "(2 falsifier invocation(s)); must-fail/must-pass canary held; comparator self-test did NOT hold.",
            text,
        )

    def test_an_absent_count_is_unknown_not_zero(self) -> None:
        text = self.performance(falsifiers={"WITNESSED": ["rows"]}, canary={"holds": None})
        self.assertIn("1 WITNESSED, unknown REFUTED, unknown UNWITNESSED", text)
        self.assertIn("(unknown falsifier invocation(s))", text)
        self.assertIn("canary outcome unknown", text)


class SigningTests(ReceiptTestCase):
    def test_missing_keys_produce_unsigned_receipts(self) -> None:
        # Requirement 24.
        environments = [
            {},
            {HMAC_KEY_FILE_ENV: ""},
            {HMAC_KEY_FILE_ENV: str(self.tmp / "keys" / "absent.key")},
            {HMAC_KEY_FILE_ENV: str(self.write("keys/empty.key", b""))},
            {HMAC_KEY_FILE_ENV: str(self.write("keys/huge.key", b"k" * (MAX_KEY_BYTES + 1)))},
            {HMAC_KEY_FILE_ENV: str(self.tmp / "keys")},
        ]
        for environ in environments:
            with self.subTest(environ=environ):
                receipt = self.receipt(environ=environ)
                self.assertEqual(receipt["signature_state"], SignatureState.UNSIGNED.value)
                self.assertIsNone(receipt["signature"])
                self.assertIsNone(receipt["key_id"])
                resolution = resolve_signing_key(environ)
                self.assertIsNone(resolution.key)
                self.assertIn(HMAC_KEY_FILE_ENV, resolution.detail)
                self.assertEqual(receipt["detail"], resolution.detail)
                self.assertNotIn(str(self.tmp), resolution.detail)

    def test_a_readable_key_authenticates_the_canonical_body(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        self.assertEqual(set(receipt), RECORD_KEYS)
        self.assertEqual(receipt["signature_state"], "SIGNED_HMAC_SHA256")
        expected = hmac.new(KEY_BYTES, canonical_bytes(receipt["body"]), hashlib.sha256).hexdigest()
        self.assertEqual(receipt["signature"], expected)
        self.assertEqual(receipt["key_id"], hashlib.sha256(KEY_BYTES).hexdigest())
        # D9: HMAC is a shared-key authenticator, never described as a public signature.
        self.assertIn("shared key", receipt["detail"])

    def test_the_key_never_appears_in_any_output(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        for name, data in receipt_files(receipt).items():
            with self.subTest(file=name):
                self.assertNotIn(KEY_BYTES, data)
                self.assertNotIn(str(self.key_file).encode("utf-8"), data)
        resolution = resolve_signing_key(self.signed_environ())
        self.assertNotIn(KEY_BYTES.decode(), repr(resolution))
        self.assertNotIn(KEY_BYTES.decode(), resolution.detail)
        self.assertNotIn(KEY_BYTES.decode(), repr(SigningKey(KEY_BYTES)))

    def test_signing_key_must_be_bytes(self) -> None:
        for bad in (b"", "text"):
            with self.subTest(bad=bad), self.assertRaises(ReceiptError):
                SigningKey(bad)  # type: ignore[arg-type]


class ContentHashTests(ReceiptTestCase):
    def test_content_hash_is_the_sha256_of_the_canonical_body(self) -> None:
        receipt = self.receipt()
        self.assertEqual(receipt["content_sha256"], sha256_bytes(canonical_bytes(receipt["body"])))

    def test_receipts_are_deterministic(self) -> None:
        for environ in ({}, self.signed_environ()):
            with self.subTest(signed=bool(environ)):
                first, second = (receipt_files(self.receipt(environ=environ)) for _ in range(2))
                self.assertEqual(first, second)

    def test_protected_content_changes_alter_the_receipt_hash(self) -> None:
        # Requirement 23: different input bytes give a different subject digest and content hash.
        baseline = self.receipt()["content_sha256"]
        edited_csv = "sample_id,value,count\nSYN-0001,12.41,1\nSYN-0002,0.14,7\nSYN-0003,3.5,12\n"
        changed_rows = build_scenario(self, csv_text=edited_csv)
        changed = build_run_receipt(changed_rows.run_result(), **changed_rows.ledger.seal(), environ={})
        self.assertNotEqual(changed["content_sha256"], baseline)
        self.assertNotEqual(changed["body"]["subject"], self.receipt()["body"]["subject"])

    def test_evidence_changes_beneath_an_unchanged_pass_alter_the_hash(self) -> None:
        # Requirement 28 at the receipt layer: same verdicts, different recorded evidence.
        baseline = self.receipt()
        check = dataclasses.replace(self.scenario.checks[0], evidence={"rows_examined": 3, "inputs": ["other"]})
        altered = self.receipt(self.scenario.run_result(checks=(check,)))
        self.assertEqual(altered["body"]["predicate"]["status"], baseline["body"]["predicate"]["status"])
        self.assertNotEqual(altered["content_sha256"], baseline["content_sha256"])

    def test_each_predicate_field_is_protected(self) -> None:
        receipt = self.receipt()
        for field in ("status", "ledger_length", "ledger_head_sha256", "evidence_manifest_sha256", "controls_sha256"):
            with self.subTest(field=field):
                body = copy.deepcopy(receipt["body"])
                body["predicate"][field] = "tampered"
                self.assertNotEqual(sha256_canonical(body), receipt["content_sha256"])


class ReceiptFileTests(ReceiptTestCase):
    """17.9: a record becomes a bare statement plus its sidecar, and is never written as such."""

    def test_the_statement_is_the_canonical_body_and_nothing_else(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        files = receipt_files(receipt)
        self.assertEqual(list(files), [STATEMENT_FILE, AUTH_FILE])
        self.assertEqual(files[STATEMENT_FILE], canonical_bytes(receipt["body"]) + b"\n")
        self.assertEqual(receipt_bytes(receipt), files[STATEMENT_FILE])
        self.assertEqual(sha256_bytes(files[STATEMENT_FILE].rstrip(b"\n")), receipt["content_sha256"])

    def test_an_unsigned_sidecar_says_why_and_has_no_signature_key(self) -> None:
        receipt = self.receipt()
        _, sidecar = self.files(receipt)
        self.assertEqual(set(sidecar), UNSIGNED_AUTH_KEYS)
        self.assertEqual(
            sidecar,
            {
                "schema": AUTH_SCHEMA,
                "statement": STATEMENT_FILE,
                "content_sha256": receipt["content_sha256"],
                "signature_state": "UNSIGNED",
                "detail": f"{HMAC_KEY_FILE_ENV} is not set",
            },
        )

    def test_a_signed_sidecar_carries_the_authenticator_and_key_id(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        _, sidecar = self.files(receipt)
        self.assertEqual(set(sidecar), SIGNED_AUTH_KEYS)
        self.assertEqual(sidecar["algorithm"], AUTH_ALGORITHM)
        self.assertEqual(sidecar["algorithm"], "HMAC-SHA256")
        self.assertEqual((sidecar["signature"], sidecar["key_id"]), (receipt["signature"], receipt["key_id"]))

    def test_the_sidecar_is_named_after_its_statement(self) -> None:
        self.assertEqual(auth_file_name("receipt.json"), "receipt.auth.json")
        self.assertEqual(AUTH_FILE, auth_file_name(STATEMENT_FILE))
        files = receipt_files(self.receipt(), statement_name="expected.json")
        self.assertEqual(list(files), ["expected.json", "expected.auth.json"])
        self.assertEqual(strict_loads(files["expected.auth.json"])["statement"], "expected.json")
        for bad in ("receipt", "", ".json", "dir/receipt.json", "dir\\receipt.json", "receipt.auth.json"):
            with self.subTest(name=bad), self.assertRaises(ReceiptError):
                auth_file_name(bad)

    def test_inconsistent_records_are_never_written(self) -> None:
        unsigned = self.receipt()
        signed = self.receipt(environ=self.signed_environ())
        cases = {
            "content hash not of the body": dict(unsigned, content_sha256="0" * 64),
            "unsigned with an authenticator": dict(unsigned, signature="0" * 64),
            "unsigned without its reason": dict(unsigned, detail=" "),
            "signed with an empty authenticator": dict(signed, signature=""),
            "signed with no authenticator": dict(signed, signature=None),
            "signed with no key id": dict(signed, key_id=None),
            "unknown state": dict(unsigned, signature_state="SIGNED_SOMEHOW"),
            "an extra key": dict(unsigned, extra=1),
        }
        for label, record in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ReceiptError):
                    receipt_files(record)
                with self.assertRaises(ReceiptError):
                    write_receipt(self.tmp / "run", STATEMENT_FILE, record)
                self.assertFalse((self.tmp / "run").exists())

    def test_seal_body_records_the_key_resolution(self) -> None:
        record = seal_body({"any": "body"}, KeyResolution(None, "synthetic: no key configured"))
        self.assertEqual(set(record), RECORD_KEYS)
        self.assertEqual((record["signature_state"], record["detail"]), ("UNSIGNED", "synthetic: no key configured"))
        signed = seal_body({"any": "body"}, KeyResolution(SigningKey(KEY_BYTES), "synthetic"))
        self.assertEqual(signed["signature"], SigningKey(KEY_BYTES).sign({"any": "body"}))

    def test_write_receipt_writes_both_files_beside_each_other(self) -> None:
        statement, sidecar = write_receipt(self.tmp / "package", "expected/receipt.json", self.receipt())
        self.assertEqual(statement, self.tmp / "package" / "expected" / "receipt.json")
        self.assertEqual(sidecar, self.tmp / "package" / "expected" / "receipt.auth.json")
        self.assertTrue(verify_receipt(statement, environ={}).ok)

    def test_writes_stay_inside_the_root(self) -> None:
        with self.assertRaises(UnsafePathError):
            write_receipt(self.tmp / "run", "../receipt.json", self.receipt())
        self.assertFalse((self.tmp / "receipt.json").exists())
        self.assertFalse((self.tmp / "receipt.auth.json").exists())


class VerificationTests(ReceiptTestCase):
    def written(self, receipt: dict[str, Any], name: str = STATEMENT_FILE) -> Path:
        return write_receipt(self.tmp / "run", name, receipt)[0]

    def sidecar_path(self) -> Path:
        return self.tmp / "run" / AUTH_FILE

    def rewrite_sidecar(self, **changes: Any) -> None:
        sidecar = strict_loads(self.sidecar_path().read_bytes())
        self.sidecar_path().write_bytes(canonical_bytes(dict(sidecar, **changes)) + b"\n")

    def test_unsigned_round_trip(self) -> None:
        result = verify_receipt(self.written(self.receipt()), environ={})
        self.assertTrue(result.ok, result.problems)
        self.assertTrue(result.content_intact)
        self.assertIs(result.signature_state, SignatureState.UNSIGNED)
        self.assertIs(result.auth_status, AuthStatus.UNSIGNED)
        self.assertIsNone(result.signature_verified)
        expected = f"no key when written: {HMAC_KEY_FILE_ENV} is not set; only the content hash was checked"
        self.assertEqual(result.detail, expected)
        self.assertEqual(result.run_id, self.scenario.run_result().run_id)

    def test_signed_round_trip_and_unchecked_authenticators(self) -> None:
        path = self.written(self.receipt(environ=self.signed_environ()))
        verified = verify_receipt(path, environ=self.signed_environ())
        self.assertTrue(verified.ok, verified.problems)
        self.assertIs(verified.auth_status, AuthStatus.SIGNED_VERIFIED)
        self.assertIs(verified.signature_verified, True)
        # Without the key the authenticator is "not checked", never "good" and never a problem.
        unchecked = verify_receipt(path, environ={})
        self.assertTrue(unchecked.ok, unchecked.problems)
        self.assertIs(unchecked.auth_status, AuthStatus.SIGNED_UNCHECKED)
        self.assertIsNone(unchecked.signature_verified)
        self.assertIn("no key is available", unchecked.detail)
        other_key = self.write("keys/other.key", b"a-different-synthetic-key")
        mismatched = verify_receipt(path, environ={HMAC_KEY_FILE_ENV: str(other_key)})
        self.assertIs(mismatched.auth_status, AuthStatus.SIGNED_UNCHECKED)
        self.assertIn("not checked", mismatched.detail)

    def test_forged_authenticator_is_signed_failed(self) -> None:
        path = self.written(self.receipt(environ=self.signed_environ()))
        self.rewrite_sidecar(signature="0" * 64)
        result = verify_receipt(path, environ=self.signed_environ())
        self.assertIs(result.auth_status, AuthStatus.SIGNED_FAILED)
        self.assertIs(result.signature_verified, False)
        self.assertTrue(result.content_intact)
        self.assertFalse(result.ok)
        self.assertTrue(any(problem.startswith("SIGNATURE_MISMATCH") for problem in result.problems))

    def test_edited_statement_breaks_the_content_hash_and_the_authenticator(self) -> None:
        path = self.written(self.receipt(environ=self.signed_environ()))
        statement = strict_loads(path.read_bytes())
        statement["predicate"]["status"] = "FAIL"
        path.write_bytes(canonical_bytes(statement) + b"\n")
        result = verify_receipt(path, environ=self.signed_environ())
        self.assertFalse(result.content_intact)
        self.assertIs(result.auth_status, AuthStatus.SIGNED_FAILED)
        codes = [problem.split(":")[0] for problem in result.problems]
        self.assertEqual(codes, ["CONTENT_HASH_MISMATCH", "SIGNATURE_MISMATCH"])

    def test_rehashed_statement_cannot_claim_scientific_validity(self) -> None:
        # A forger who recomputes content_sha256 still cannot weaken the evidence boundary.
        statement, sidecar = self.files(self.receipt())
        claimed = copy.deepcopy(statement)
        claimed["evidence_boundary"]["scientific_validity"] = "ESTABLISHED"
        dropped = copy.deepcopy(statement)
        dropped["disclaimer"] = "Verified."
        for forged in (claimed, dropped):
            result = verify_receipt_documents(forged, dict(sidecar, content_sha256=sha256_canonical(forged)))
            self.assertTrue(result.content_intact)
            self.assertFalse(result.ok)
            self.assertTrue(any(problem.startswith("BOUNDARY_VIOLATION") for problem in result.problems))

    def test_structural_defects_are_reported(self) -> None:
        statement, unsigned = self.files(self.receipt())
        _, signed = self.files(self.receipt(environ=self.signed_environ()))
        unsigned_keys = "a sidecar in state UNSIGNED has exactly the keys"
        cases: list[tuple[Any, Any, str]] = [
            ("not a statement", unsigned, "the statement is not a JSON object"),
            (dict(statement, extra=1), unsigned, "MALFORMED_RECEIPT: statement keys"),
            (statement, "not a sidecar", "AUTH_SIDECAR_MALFORMED: the sidecar is not a JSON object"),
            (statement, dict(unsigned, signature=None), f"AUTH_SIDECAR_MALFORMED: {unsigned_keys}"),
            (statement, dict(unsigned, signature=""), f"AUTH_SIDECAR_MALFORMED: {unsigned_keys}"),
            (statement, dict(unsigned, signature_state="SIGNED_SOMEHOW"), "signature_state is not"),
            (statement, dict(unsigned, schema="other/v1"), "schema must be"),
            (statement, dict(unsigned, statement="other.json"), "does not name the statement"),
            (statement, dict(unsigned, content_sha256="xyz"), "content_sha256 must be"),
            (statement, dict(unsigned, detail=""), "must say why it is unsigned"),
            (statement, dict(signed, algorithm="HMAC-SHA1"), "algorithm must be"),
            (statement, dict(signed, signature=""), "signature must be 64"),
            (statement, dict(signed, key_id=None), "key_id must be 64"),
        ]
        body = copy.deepcopy(statement)
        body["subject"] = [{"name": "x", "digest": {"md5": "0"}}]
        cases.append((body, dict(unsigned, content_sha256=sha256_canonical(body)), "every subject needs"))
        for document, sidecar, fragment in cases:
            with self.subTest(fragment=fragment):
                result = verify_receipt_documents(document, sidecar)
                self.assertFalse(result.ok)
                self.assertTrue(any(fragment in problem for problem in result.problems), result.problems)

    def test_a_malformed_sidecar_is_unknown_never_unsigned(self) -> None:
        statement, signed = self.files(self.receipt(environ=self.signed_environ()))
        stripped = {key: value for key, value in signed.items() if key not in ("signature", "key_id", "algorithm")}
        result = verify_receipt_documents(statement, stripped, key=SigningKey(KEY_BYTES))
        self.assertIsNone(result.auth_status)
        self.assertIsNone(result.signature_state)
        self.assertFalse(result.content_intact)

    def test_a_legacy_envelope_is_refused(self) -> None:
        receipt = self.receipt()
        envelope = {key: receipt[key] for key in ("body", "content_sha256", "signature_state", "signature", "key_id")}
        path = self.write("run/receipt.json", canonical_bytes(envelope) + b"\n")
        self.written(receipt, "other.json")  # a valid sidecar elsewhere must not rescue it
        result = verify_receipt(path, environ={})
        self.assertFalse(result.ok)
        self.assertIsNone(result.auth_status)
        self.assertTrue(result.problems[0].startswith("LEGACY_ENVELOPE"), result.problems)

    def test_unreadable_files_are_problems_not_tracebacks(self) -> None:
        missing = verify_receipt(self.tmp / "run" / STATEMENT_FILE, environ={})
        self.assertEqual(missing.problems, ("RECEIPT_MISSING: no receipt at 'receipt.json'",))
        malformed = self.write("run/bad.json", b'{"schema": ')
        self.assertIn("MALFORMED_RECEIPT", verify_receipt(malformed, environ={}).problems[0])
        floated = self.write("run/float.json", json.dumps({"schema": 1.5}))
        self.assertIn("NON_INTEGER_NUMBER", verify_receipt(floated, environ={}).problems[0])
        (self.tmp / "run" / "dir.json").mkdir()
        self.assertIn("RECEIPT_UNREADABLE", verify_receipt(self.tmp / "run" / "dir.json", environ={}).problems[0])
        for result in (missing, verify_receipt(malformed, environ={})):
            self.assertNotIn(str(self.tmp), " ".join(result.problems))

    def test_a_missing_or_unreadable_sidecar_leaves_authentication_unknown(self) -> None:
        path = self.written(self.receipt(environ=self.signed_environ()))
        self.sidecar_path().unlink()
        missing = verify_receipt(path, environ=self.signed_environ())
        self.assertEqual((missing.ok, missing.content_intact, missing.auth_status), (False, False, None))
        self.assertTrue(missing.problems[0].startswith("AUTH_SIDECAR_MISSING"), missing.problems)
        self.sidecar_path().write_bytes(b'{"schema": "science-gate-receipt-auth/v1",')
        broken = verify_receipt(path, environ=self.signed_environ())
        self.assertIsNone(broken.auth_status)
        self.assertTrue(broken.problems[0].startswith("AUTH_SIDECAR_MALFORMED"), broken.problems)
        self.assertNotIn(str(self.tmp), " ".join(missing.problems + broken.problems))

    def test_require_signature_accepts_only_signed_verified(self) -> None:
        unsigned = verify_receipt(self.written(self.receipt()), environ={}, require_signature=True)
        self.assertFalse(unsigned.ok)
        self.assertIs(unsigned.auth_status, AuthStatus.UNSIGNED)
        self.assertEqual(
            unsigned.problems[-1],
            "SIGNATURE_REQUIRED: a verified HMAC-SHA256 authenticator was required, but the receipt is UNSIGNED",
        )
        path = self.written(self.receipt(environ=self.signed_environ()))
        self.assertTrue(verify_receipt(path, environ=self.signed_environ(), require_signature=True).ok)
        unchecked = verify_receipt(path, environ={}, require_signature=True)
        required = "SIGNATURE_REQUIRED: a verified HMAC-SHA256 authenticator was required, but the receipt is"
        self.assertEqual(unchecked.problems, (f"{required} SIGNED_UNCHECKED",))
        absent = verify_receipt(self.tmp / "run" / "absent.json", environ={}, require_signature=True)
        self.assertTrue(absent.problems[-1].endswith("but the receipt could not be determined"))

    def test_verification_serializes(self) -> None:
        result = verify_receipt(self.written(self.receipt()), environ={})
        data = result.to_dict()
        self.assertEqual(
            (data["ok"], data["signature_state"], data["signature_verified"], data["auth_status"]),
            (True, "UNSIGNED", None, "UNSIGNED"),
        )
        self.assertEqual(data["run_id"], self.scenario.run_result().run_id)
        strict_loads(canonical_bytes(data))
