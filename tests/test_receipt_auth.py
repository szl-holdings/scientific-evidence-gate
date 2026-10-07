"""Authentication outside the payload (extension #15, decisions D3 and D9).

Acceptance, from the research brief: unsigned plus ``--require-signature``
gives a distinct nonzero exit; a corrupted HMAC gives SIGNED_FAILED; no file
is ever written as an envelope with an empty signature. Around those: the
statement never carries its own authentication; unsigned, unchecked, failed
and verified are four different outcomes; and each check here is shown able
to fail as well as to pass.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

from _helpers import FIXED_TIME, TempDirTestCase, build_scenario
from _project import VALID_MANIFEST
from test_cli import CliTestCase

from science_gate import cli
from science_gate._canonical import canonical_bytes, strict_loads
from science_gate.models import EXIT_CODE, AuthStatus, Status
from science_gate.receipts import (
    AUTH_FILE,
    HMAC_KEY_FILE_ENV,
    STATEMENT_FILE,
    ReceiptError,
    SigningKey,
    build_run_receipt,
    receipt_files,
    verify_receipt,
    verify_receipt_documents,
    write_receipt,
)

#: A synthetic key used only by these tests.
KEY_BYTES = b"synthetic-receipt-auth-key-0123456789"
#: Keys that state authentication. None of them may appear anywhere in a statement.
AUTH_KEYS = frozenset({"signature", "signature_state", "key_id", "auth_status", "algorithm"})
_HEX64 = re.compile(r"[0-9a-f]{64}")


def walk(value: Any) -> Iterator[dict[str, Any]]:
    """Every JSON object nested anywhere in ``value``."""
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def json_documents(root: Path) -> Iterator[tuple[str, Any]]:
    """Every JSON document written under ``root``: .json and .sarif files, and each line of .jsonl files."""
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.suffix in (".json", ".sarif"):
            yield name, strict_loads(path.read_bytes())
        elif path.suffix == ".jsonl":
            for number, line in enumerate(path.read_bytes().splitlines(), start=1):
                yield f"{name}:{number}", strict_loads(line)


def flip_last_hex_digit(text: str) -> str:
    return text[:-1] + ("0" if text[-1] != "0" else "1")


class AuthTestCase(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.scenario = build_scenario(self)
        self.key_file = self.write("keys/hmac.key", KEY_BYTES)

    def signed_environ(self) -> dict[str, str]:
        return {HMAC_KEY_FILE_ENV: str(self.key_file)}

    def record(self, environ: dict[str, str] | None = None) -> dict[str, Any]:
        return build_run_receipt(self.scenario.run_result(), **self.scenario.ledger.seal(), environ=environ or {})

    def write_receipt(self, environ: dict[str, str] | None = None) -> Path:
        return write_receipt(self.tmp / "run", STATEMENT_FILE, self.record(environ))[0]

    def edit_sidecar(self, **changes: Any) -> None:
        path = self.tmp / "run" / AUTH_FILE
        path.write_bytes(canonical_bytes(dict(strict_loads(path.read_bytes()), **changes)) + b"\n")


class AuthenticationOutsideThePayloadTests(AuthTestCase):
    def test_the_statement_never_states_its_own_authentication(self) -> None:
        unsigned = receipt_files(self.record())
        signed = receipt_files(self.record(self.signed_environ()))
        # Authenticating adds a sidecar; it never changes one byte of the statement.
        self.assertEqual(unsigned[STATEMENT_FILE], signed[STATEMENT_FILE])
        statement = strict_loads(signed[STATEMENT_FILE])
        for item in walk(statement):
            self.assertFalse(AUTH_KEYS & set(item), sorted(AUTH_KEYS & set(item)))

    def test_what_checking_established_is_never_written(self) -> None:
        for environ in ({}, self.signed_environ()):
            for name, data in receipt_files(self.record(environ)).items():
                for status in (AuthStatus.SIGNED_VERIFIED, AuthStatus.SIGNED_FAILED, AuthStatus.SIGNED_UNCHECKED):
                    with self.subTest(file=name, signed=bool(environ), status=status.value):
                        self.assertNotIn(status.value.encode("ascii"), data)
                self.assertNotIn(b"auth_status", data)

    def test_unsigned_unchecked_failed_and_verified_are_four_outcomes(self) -> None:
        unsigned = verify_receipt(self.write_receipt(), environ={})
        path = self.write_receipt(self.signed_environ())
        verified = verify_receipt(path, environ=self.signed_environ())
        unchecked = verify_receipt(path, environ={})
        self.edit_sidecar(signature=flip_last_hex_digit(self.record(self.signed_environ())["signature"]))
        failed = verify_receipt(path, environ=self.signed_environ())
        outcomes = [unsigned.auth_status, unchecked.auth_status, failed.auth_status, verified.auth_status]
        self.assertEqual(outcomes, [AuthStatus.UNSIGNED, AuthStatus.SIGNED_UNCHECKED, AuthStatus.SIGNED_FAILED,
                                    AuthStatus.SIGNED_VERIFIED])
        self.assertEqual([unsigned.ok, unchecked.ok, failed.ok, verified.ok], [True, True, False, True])


class CorruptedHmacTests(AuthTestCase):
    def test_a_corrupted_hmac_is_signed_failed(self) -> None:
        path = self.write_receipt(self.signed_environ())
        before = verify_receipt(path, environ=self.signed_environ())
        self.assertIs(before.auth_status, AuthStatus.SIGNED_VERIFIED)  # the check can pass ...
        signature = self.record(self.signed_environ())["signature"]
        for corrupted in (flip_last_hex_digit(signature), ("1" if signature[0] == "0" else "0") + signature[1:]):
            with self.subTest(corrupted=corrupted):
                self.edit_sidecar(signature=corrupted)
                after = verify_receipt(path, environ=self.signed_environ())  # ... and it can fail
                self.assertIs(after.auth_status, AuthStatus.SIGNED_FAILED)
                self.assertIs(after.signature_verified, False)
                self.assertFalse(after.ok)
                self.assertIn(
                    "SIGNATURE_MISMATCH: the HMAC-SHA256 authenticator does not match the statement", after.problems
                )

    def test_a_forger_who_rehashes_the_statement_still_fails_the_hmac(self) -> None:
        path = self.write_receipt(self.signed_environ())
        statement = strict_loads(path.read_bytes())
        statement["predicate"]["status"] = "FAIL"
        path.write_bytes(canonical_bytes(statement) + b"\n")
        sidecar = strict_loads((self.tmp / "run" / AUTH_FILE).read_bytes())
        result = verify_receipt_documents(
            statement,
            dict(sidecar, content_sha256=verify_receipt(path, environ={}).recomputed_sha256),
            key=SigningKey(KEY_BYTES),
        )
        self.assertTrue(result.content_intact)
        self.assertIs(result.auth_status, AuthStatus.SIGNED_FAILED)


class NoEmptySignatureTests(AuthTestCase):
    def test_no_receipt_file_holds_an_empty_signature(self) -> None:
        for environ in ({}, self.signed_environ()):
            for name, data in receipt_files(self.record(environ)).items():
                for item in walk(strict_loads(data)):
                    with self.subTest(file=name, signed=bool(environ)):
                        if "signature" in item:
                            self.assertRegex(item["signature"], _HEX64)
                        if item.get("signature_state") == "UNSIGNED":
                            self.assertNotIn("signature", item)
                            self.assertNotIn("key_id", item)

    def test_a_record_with_an_empty_signature_is_never_written(self) -> None:
        signed = self.record(self.signed_environ())
        for empty in ("", None):
            with self.subTest(signature=empty):
                with self.assertRaises(ReceiptError):
                    write_receipt(self.tmp / "run", STATEMENT_FILE, dict(signed, signature=empty))
                self.assertFalse((self.tmp / "run").exists())

    def test_an_empty_signature_envelope_is_never_accepted(self) -> None:
        statement = strict_loads(receipt_files(self.record())[STATEMENT_FILE])
        sidecar = strict_loads(receipt_files(self.record(self.signed_environ()))[AUTH_FILE])
        unsigned = strict_loads(receipt_files(self.record())[AUTH_FILE])
        for label, document in {
            "signed, empty signature": dict(sidecar, signature=""),
            "unsigned, null signature": dict(unsigned, signature=None, key_id=None),
            "unsigned, empty signature": dict(unsigned, signature=""),
        }.items():
            with self.subTest(case=label):
                result = verify_receipt_documents(statement, document, key=SigningKey(KEY_BYTES))
                self.assertIsNone(result.auth_status)
                self.assertTrue(result.problems[0].startswith("AUTH_SIDECAR_MALFORMED"), result.problems)


class RequireSignatureCommandTests(CliTestCase):
    """The CLI outcome of ``--require-signature`` (17.9, D3), on real run directories."""

    HEADLINE = re.compile(
        r"ERROR \(PROTOCOL_BROKEN\) (run-[0-9a-f]+): --require-signature: the receipt is (\w+) \((.+)\); "
        r"the (run|report)'s own status (\w+) is recorded in (run\.json|report\.md)"
    )

    def setUp(self) -> None:
        super().setUp()
        self.key_file = self.write("keys/hmac.key", KEY_BYTES)
        environment = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)

    def main(self, *argv: str, key: bool = False) -> tuple[int, list[str]]:
        """Run the CLI in process, with or without the synthetic key in the environment."""
        stdout = io.StringIO()
        extra = {HMAC_KEY_FILE_ENV: str(self.key_file)} if key else {}
        with mock.patch.dict(os.environ, extra), contextlib.redirect_stdout(stdout):
            code = cli.main(list(argv))
        return code, stdout.getvalue().splitlines()

    def run_json(self, run_dir: Path) -> dict[str, Any]:
        return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))

    def test_unsigned_with_require_signature_exits_3(self) -> None:
        # The acceptance case end to end, as a user runs it: a separate process and its exit code.
        plain = self.run_cli("verify", str(VALID_MANIFEST), "--output", str(self.tmp / "plain"))
        required = self.run_cli("verify", str(VALID_MANIFEST), "--output", str(self.tmp / "run"), "--require-signature")
        own_status = self.run_json(self.tmp / "run")["status"]
        self.assertEqual(own_status, Status.PASS.value, "the acceptance case is an unsigned run that passes")
        self.assertEqual(plain.returncode, EXIT_CODE[Status.PASS])
        self.assertEqual(required.returncode, EXIT_CODE[Status.ERROR])
        self.assertNotIn(required.returncode, (EXIT_CODE[Status.FAIL], EXIT_CODE[Status.ABSTAIN]))
        headline, *paths = self.lines(required)
        match = self.HEADLINE.fullmatch(headline)
        self.assertIsNotNone(match, headline)
        assert match is not None
        self.assertEqual(match.group(2, 3), (
            "UNSIGNED", f"no key when written: {HMAC_KEY_FILE_ENV} is not set; only the content hash was checked"
        ))
        self.assertEqual(match.group(4, 5, 6), ("run", "PASS", "run.json"))
        # The run directory is written as usual: the run's own verdict is kept, not rewritten as ERROR.
        self.assertIn(STATEMENT_FILE, [Path(path).name for path in paths])
        self.assertIn(AUTH_FILE, [Path(path).name for path in paths])
        self.assertTrue(all(Path(path).is_file() for path in paths))
        self.assertEqual(self.run_json(self.tmp / "run")["exit_code"], EXIT_CODE[Status.PASS])

    def test_a_verified_authenticator_keeps_the_run_exit_code(self) -> None:
        code, lines = self.main("verify", str(VALID_MANIFEST), "--output", str(self.tmp / "run"),
                                "--require-signature", key=True)
        own = self.run_json(self.tmp / "run")
        self.assertEqual(code, own["exit_code"])
        self.assertTrue(lines[0].startswith(f"{own['status']} ({own['reason']}) {own['run_id']}"), lines[0])
        environ = {HMAC_KEY_FILE_ENV: str(self.key_file)}
        self.assertIs(verify_receipt(self.tmp / "run" / STATEMENT_FILE, environ=environ).auth_status,
                      AuthStatus.SIGNED_VERIFIED)

    def test_report_with_require_signature_on_a_corrupted_hmac(self) -> None:
        run_dir = self.tmp / "run"
        self.main("verify", str(VALID_MANIFEST), "--output", str(run_dir), key=True)
        sidecar = strict_loads((run_dir / AUTH_FILE).read_bytes())
        corrupted = dict(sidecar, signature=flip_last_hex_digit(sidecar["signature"]))
        (run_dir / AUTH_FILE).write_bytes(canonical_bytes(corrupted) + b"\n")
        plain_code, _ = self.main("report", str(run_dir), key=True)
        self.assertEqual(plain_code, EXIT_CODE[Status.ERROR], "a failed authenticator fails re-verification")
        code, lines = self.main("report", str(run_dir), "--require-signature", key=True)
        self.assertEqual(code, EXIT_CODE[Status.ERROR])
        match = self.HEADLINE.fullmatch(lines[0])
        self.assertIsNotNone(match, lines[0])
        assert match is not None
        mismatch = "the HMAC-SHA256 authenticator does not match the statement"
        self.assertEqual(match.group(2, 3), ("SIGNED_FAILED", mismatch))
        self.assertEqual(match.group(4, 5, 6), ("report", "ERROR", "report.md"))
        self.assertTrue(all(Path(path).is_file() for path in lines[1:]))

    def test_report_with_require_signature_and_no_key_is_signed_unchecked(self) -> None:
        run_dir = self.tmp / "run"
        self.main("verify", str(VALID_MANIFEST), "--output", str(run_dir), key=True)
        own = self.run_json(run_dir)
        plain_code, plain = self.main("report", str(run_dir))
        self.assertEqual(plain_code, own["exit_code"], "an unchecked authenticator is not a problem by itself")
        code, lines = self.main("report", str(run_dir), "--require-signature")
        self.assertEqual(code, EXIT_CODE[Status.ERROR])
        match = self.HEADLINE.fullmatch(lines[0])
        self.assertIsNotNone(match, lines[0])
        assert match is not None
        self.assertEqual(match.group(1), own["run_id"])
        self.assertEqual(match.group(2), "SIGNED_UNCHECKED")
        self.assertIn("no key is available to check it", match.group(3))
        self.assertEqual(match.group(4, 5), ("report", own["status"]))
        with_key, _ = self.main("report", str(run_dir), "--require-signature", key=True)
        self.assertEqual(with_key, own["exit_code"])

    def test_no_written_file_holds_an_empty_signature(self) -> None:
        for key in (False, True):
            run_dir = self.tmp / f"run-{'signed' if key else 'unsigned'}"
            self.main("verify", str(VALID_MANIFEST), "--output", str(run_dir), key=key)
            self.main("report", str(run_dir), key=key)
            self.assertTrue((run_dir / AUTH_FILE).is_file())
            signatures = 0
            for name, document in json_documents(run_dir):
                for item in walk(document):
                    with self.subTest(signed=key, file=name):
                        if "signature" in item:
                            signatures += 1
                            self.assertRegex(item["signature"], _HEX64)
                        if item.get("signature_state") == "UNSIGNED":
                            self.assertNotIn("signature", item)
            if key:
                self.assertGreaterEqual(signatures, 1, "the signed run must carry its authenticator somewhere")
            else:
                self.assertEqual(signatures, 0, "an unsigned run has no signature key in any file")
