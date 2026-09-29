"""Run receipts: canonical body, content hash, optional HMAC and verification (section 11)."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import hmac
import json
from typing import Any

from _helpers import TempDirTestCase, build_scenario

from science_gate import TOOL_NAME, __version__
from science_gate._canonical import canonical_bytes, sha256_bytes, sha256_canonical, strict_loads
from science_gate._safeio import UnsafePathError
from science_gate.models import InputState, SignatureState
from science_gate.receipts import (
    BODY_KEYS,
    DISCLAIMER,
    HMAC_KEY_FILE_ENV,
    MAX_KEY_BYTES,
    PREDICATE_TYPE,
    RECEIPT_KEYS,
    RECEIPT_SCHEMA,
    ReceiptError,
    SigningKey,
    build_body,
    build_run_receipt,
    receipt_bytes,
    resolve_signing_key,
    run_predicate,
    seal_body,
    verify_receipt,
    verify_receipt_document,
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
        self.assertEqual(len(predicate["invariants"]), 10)

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

    def test_a_readable_key_signs_the_canonical_body(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        self.assertEqual(set(receipt), RECEIPT_KEYS)
        self.assertEqual(receipt["signature_state"], "SIGNED_HMAC_SHA256")
        expected = hmac.new(KEY_BYTES, canonical_bytes(receipt["body"]), hashlib.sha256).hexdigest()
        self.assertEqual(receipt["signature"], expected)
        self.assertEqual(receipt["key_id"], hashlib.sha256(KEY_BYTES).hexdigest())

    def test_the_key_never_appears_in_any_output(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        self.assertNotIn(KEY_BYTES, receipt_bytes(receipt))
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
        self.assertEqual(receipt_bytes(self.receipt()), receipt_bytes(self.receipt()))
        self.assertEqual(
            receipt_bytes(self.receipt(environ=self.signed_environ())),
            receipt_bytes(self.receipt(environ=self.signed_environ())),
        )

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
        for field in ("status", "ledger_length", "ledger_head_sha256", "evidence_manifest_sha256"):
            with self.subTest(field=field):
                body = copy.deepcopy(receipt["body"])
                body["predicate"][field] = "tampered"
                self.assertNotEqual(sha256_canonical(body), receipt["content_sha256"])


class VerificationTests(ReceiptTestCase):
    def written(self, receipt: dict[str, Any], name: str = "receipt.json") -> Any:
        return write_receipt(self.tmp / "run", name, receipt)

    def test_file_is_canonical_json_containing_the_hashed_bytes(self) -> None:
        receipt = self.receipt()
        data = self.written(receipt).read_bytes()
        self.assertEqual(data, canonical_bytes(receipt) + b"\n")
        self.assertIn(canonical_bytes(receipt["body"]), data)

    def test_unsigned_round_trip(self) -> None:
        result = verify_receipt(self.written(self.receipt()), environ={})
        self.assertTrue(result.ok, result.problems)
        self.assertTrue(result.content_intact)
        self.assertIs(result.signature_state, SignatureState.UNSIGNED)
        self.assertIsNone(result.signature_verified)
        self.assertIn("unsigned", result.detail)

    def test_signed_round_trip_and_unchecked_signatures(self) -> None:
        path = self.written(self.receipt(environ=self.signed_environ()))
        verified = verify_receipt(path, environ=self.signed_environ())
        self.assertTrue(verified.ok, verified.problems)
        self.assertIs(verified.signature_verified, True)
        # Without the key the signature is "not checked", never "good".
        unchecked = verify_receipt(path, environ={})
        self.assertIsNone(unchecked.signature_verified)
        self.assertIn("no key is available", unchecked.detail)
        other_key = self.write("keys/other.key", b"a-different-synthetic-key")
        mismatched = verify_receipt(path, environ={HMAC_KEY_FILE_ENV: str(other_key)})
        self.assertIsNone(mismatched.signature_verified)
        self.assertIn("signature not checked", mismatched.detail)

    def test_forged_signature_is_detected(self) -> None:
        receipt = self.receipt(environ=self.signed_environ())
        receipt["signature"] = "0" * 64
        result = verify_receipt_document(receipt, key=SigningKey(KEY_BYTES))
        self.assertIs(result.signature_verified, False)
        self.assertFalse(result.ok)
        self.assertTrue(any(problem.startswith("SIGNATURE_MISMATCH") for problem in result.problems))

    def test_edited_body_breaks_the_content_hash(self) -> None:
        receipt = self.receipt()
        receipt["body"]["predicate"]["status"] = "FAIL"
        result = verify_receipt(self.written(receipt), environ={})
        self.assertFalse(result.content_intact)
        self.assertIn("CONTENT_HASH_MISMATCH", result.problems[0])

    def test_rehashed_body_cannot_claim_scientific_validity(self) -> None:
        # A forger who recomputes content_sha256 still cannot weaken the evidence boundary.
        claimed = copy.deepcopy(self.receipt()["body"])
        claimed["evidence_boundary"]["scientific_validity"] = "ESTABLISHED"
        dropped = copy.deepcopy(self.receipt()["body"])
        dropped["disclaimer"] = "Verified."
        for body in (claimed, dropped):
            result = verify_receipt_document(seal_body(body, None))
            self.assertTrue(result.content_intact)
            self.assertFalse(result.ok)
            self.assertTrue(any(problem.startswith("BOUNDARY_VIOLATION") for problem in result.problems))

    def test_structural_defects_are_reported(self) -> None:
        receipt = self.receipt()
        cases: list[tuple[Any, str]] = [
            ("not a receipt", "not a JSON object"),
            (dict(receipt, extra=1), "MALFORMED_RECEIPT: keys"),
            (dict(receipt, signature="0" * 64), "UNSIGNED receipt must have null"),
            (dict(receipt, signature_state="SIGNED_SOMEHOW"), "unknown signature_state"),
            (dict(receipt, body=[]), "body is not an object"),
        ]
        body = copy.deepcopy(receipt["body"])
        body["subject"] = [{"name": "x", "digest": {"md5": "0"}}]
        cases.append((seal_body(body, None), "every subject needs"))
        signed = self.receipt(environ=self.signed_environ())
        cases.append((dict(signed, key_id=None), "key_id must be"))
        for document, fragment in cases:
            with self.subTest(fragment=fragment):
                result = verify_receipt_document(document)
                self.assertFalse(result.ok)
                self.assertTrue(any(fragment in problem for problem in result.problems), result.problems)

    def test_unreadable_files_are_problems_not_tracebacks(self) -> None:
        missing = verify_receipt(self.tmp / "run" / "receipt.json", environ={})
        self.assertEqual(missing.problems, ("RECEIPT_MISSING: no receipt at 'receipt.json'",))
        malformed = self.write("run/bad.json", b'{"body": ')
        self.assertIn("MALFORMED_RECEIPT", verify_receipt(malformed, environ={}).problems[0])
        floated = self.write("run/float.json", json.dumps(dict(self.receipt(), content_sha256=1.5)))
        self.assertIn("NON_INTEGER_NUMBER", verify_receipt(floated, environ={}).problems[0])
        (self.tmp / "run" / "dir.json").mkdir()
        self.assertIn("RECEIPT_UNREADABLE", verify_receipt(self.tmp / "run" / "dir.json", environ={}).problems[0])
        for result in (missing, verify_receipt(malformed, environ={})):
            self.assertNotIn(str(self.tmp), " ".join(result.problems))

    def test_verification_serializes(self) -> None:
        result = verify_receipt(self.written(self.receipt()), environ={})
        data = result.to_dict()
        self.assertEqual((data["ok"], data["signature_state"], data["signature_verified"]), (True, "UNSIGNED", None))
        strict_loads(canonical_bytes(data))

    def test_writes_stay_inside_the_run_directory(self) -> None:
        with self.assertRaises(UnsafePathError):
            write_receipt(self.tmp / "run", "../receipt.json", self.receipt())
        self.assertFalse((self.tmp / "receipt.json").exists())
