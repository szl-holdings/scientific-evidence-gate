"""The hash-chained execution ledger (section 4)."""

from __future__ import annotations

import copy
import hashlib
import os
import unittest
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, RUN_ID, TempDirTestCase

from science_gate._canonical import CanonicalizationError, canonical_bytes
from science_gate._redact import REDACTED
from science_gate.ledger import (
    ENTRY_FIELDS,
    GENESIS_SHA256,
    Ledger,
    LedgerError,
    LedgerFormatError,
    entry_digest,
    index_invocations,
    invocation_id_for,
    parse_jsonl,
    verify_chain,
)
from science_gate.models import InvocationResult, Reason, Status

DIGEST = "b" * 64


def recorded_ledger(checks: int = 3) -> Ledger:
    """A ledger with ``checks`` invocations, each started and finished."""
    ledger = Ledger(RUN_ID)
    for index in range(checks):
        invocation_id = ledger.start(
            check_id=f"check-{index}",
            check_kind="row_count",
            check_version="1",
            input_ids=["measurements"],
            input_sha256s={"measurements": DIGEST},
        )
        ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED, evidence={"rows_examined": 3})
    return ledger


def rehash_chain(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What a careful forger would do: renumber and re-link every entry."""
    previous = GENESIS_SHA256
    for position, entry in enumerate(entries, start=1):
        entry["seq"] = position
        entry["prev_entry_sha256"] = previous
        entry["entry_sha256"] = entry_digest(entry)
        previous = entry["entry_sha256"]
    return entries


class LedgerRecordingTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def test_invocation_id_is_derived_from_run_and_sequence(self) -> None:
        expected = "inv-" + hashlib.sha256(f"{RUN_ID}:1".encode()).hexdigest()[:12]
        self.assertEqual(invocation_id_for(RUN_ID, 1), expected)
        self.assertNotEqual(invocation_id_for(RUN_ID, 1), invocation_id_for(RUN_ID, 2))
        self.assertNotEqual(invocation_id_for(RUN_ID, 1), invocation_id_for("run-synthetic-0002", 1))

    def test_start_records_before_the_check_runs(self) -> None:
        ledger = Ledger(RUN_ID)
        invocation_id = ledger.start(
            check_id="rows", check_kind="row_count", check_version="1", input_ids=["b", "a"], input_sha256s={"a": DIGEST}
        )
        (entry,) = ledger.entries
        self.assertEqual(tuple(sorted(entry)), tuple(sorted(ENTRY_FIELDS)))
        self.assertEqual(entry["seq"], 1)
        self.assertEqual(entry["invocation_id"], invocation_id)
        self.assertEqual(entry["input_ids"], ["a", "b"])
        # A digest the caller did not supply is recorded as unknown, never guessed.
        self.assertEqual(entry["input_sha256s"], {"a": DIGEST, "b": None})
        self.assertEqual((entry["started_at"], entry["completed_at"]), (FIXED_TIME, None))
        self.assertEqual((entry["result"], entry["verdict"], entry["reason"]), ("STARTED", None, None))
        self.assertEqual(entry["prev_entry_sha256"], GENESIS_SHA256)
        self.assertEqual(entry["entry_sha256"], entry_digest(entry))
        self.assertEqual(ledger.open_invocations(), (invocation_id,))

    def test_finish_appends_a_linked_terminal_entry(self) -> None:
        ledger = Ledger(RUN_ID)
        invocation_id = ledger.start(check_id="rows", check_kind="row_count", check_version="1")
        terminal = ledger.finish(invocation_id, verdict="ABSTAIN", reason="INSUFFICIENT_EVIDENCE", evidence={"n": 0})
        start, stored = ledger.entries
        self.assertEqual(stored, terminal)
        self.assertEqual((terminal["seq"], terminal["invocation_id"]), (2, invocation_id))
        self.assertEqual(terminal["result"], InvocationResult.ABSTAINED.value)
        self.assertEqual((terminal["verdict"], terminal["reason"]), ("ABSTAIN", "INSUFFICIENT_EVIDENCE"))
        self.assertEqual(terminal["completed_at"], FIXED_TIME)
        self.assertEqual(terminal["started_at"], start["started_at"])
        self.assertEqual(terminal["prev_entry_sha256"], start["entry_sha256"])
        self.assertEqual(ledger.open_invocations(), ())
        self.assertEqual(ledger.seal(), {"ledger_head_sha256": terminal["entry_sha256"], "ledger_length": 2})

    def test_result_is_derived_from_the_verdict(self) -> None:
        ledger = Ledger(RUN_ID)
        cases = [
            (Status.PASS, Reason.VERIFIED, "COMPLETED"),
            (Status.FAIL, Reason.SOURCE_MISMATCH, "COMPLETED"),
            (Status.ERROR, Reason.PROTOCOL_BROKEN, "ERRORED"),
        ]
        for verdict, reason, result in cases:
            invocation_id = ledger.start(check_id=f"c-{verdict.value}", check_kind="row_count", check_version="1")
            self.assertEqual(ledger.finish(invocation_id, verdict=verdict, reason=reason)["result"], result)

    def test_misuse_is_refused(self) -> None:
        ledger = Ledger(RUN_ID)
        invocation_id = ledger.start(check_id="rows", check_kind="row_count", check_version="1")
        with self.assertRaises(ValueError):
            ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.UNVERIFIED)
        with self.assertRaises(ValueError):
            ledger.finish(invocation_id, verdict=Status.ABSTAIN, reason=Reason.VERIFIED)
        ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED)
        with self.assertRaisesRegex(LedgerError, "already finished"):
            ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED)
        with self.assertRaisesRegex(LedgerError, "unknown"):
            ledger.finish("inv-000000000000", verdict=Status.PASS, reason=Reason.VERIFIED)
        with self.assertRaises(ValueError):
            Ledger("")
        with self.assertRaises(ValueError):
            ledger.start(check_id="", check_kind="row_count", check_version="1")
        identity = {"check_id": "x", "check_kind": "row_count", "check_version": "1"}
        for bad in (
            {"input_ids": ["a", "a"]},
            {"input_ids": ["a"], "input_sha256s": {"b": DIGEST}},
            {"input_ids": ["a"], "input_sha256s": {"a": "XYZ"}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ledger.start(**identity, **bad)

    def test_evidence_is_canonical_and_redacted_before_hashing(self) -> None:
        ledger = Ledger(RUN_ID)
        invocation_id = ledger.start(check_id="rows", check_kind="row_count", check_version="1")
        with self.assertRaises(CanonicalizationError):
            ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED, evidence={"ratio": 0.5})
        fake = "synthetic-ledger-secret-value"
        with mock.patch.dict(os.environ, {"SYNTHETIC_LEDGER_TOKEN": fake}):
            entry = ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED, evidence={"cell": fake})
        self.assertEqual(entry["evidence"], {"cell": REDACTED})
        self.assertNotIn(fake.encode(), ledger.to_jsonl())

    def test_handed_out_entries_cannot_edit_the_ledger(self) -> None:
        ledger = recorded_ledger(1)
        entries = ledger.entries
        entries[0]["verdict"] = "PASS"
        entries[1]["evidence"]["rows_examined"] = 999
        self.assertTrue(ledger.verify().intact)
        self.assertEqual(ledger.entries[1]["evidence"], {"rows_examined": 3})

    def test_serialization_round_trips_and_is_deterministic(self) -> None:
        data = recorded_ledger().to_jsonl()
        self.assertEqual(data, recorded_ledger().to_jsonl())
        self.assertTrue(data.endswith(b"\n"))
        entries = parse_jsonl(data)
        self.assertEqual(len(entries), 6)
        self.assertEqual(data.split(b"\n")[0], canonical_bytes(entries[0]))
        seal = recorded_ledger().seal()
        self.assertTrue(verify_chain(entries, seal["ledger_head_sha256"], seal["ledger_length"], run_id=RUN_ID).intact)

    def test_static_verify_chain_is_the_module_function(self) -> None:
        self.assertIs(Ledger.verify_chain, verify_chain)


class ChainVerificationTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.ledger = recorded_ledger()
        self.seal = self.ledger.seal()
        self.entries = [dict(entry) for entry in self.ledger.entries]

    def verify(self, entries: list[Any], **overrides: Any) -> tuple[str, ...]:
        head = overrides.get("head", self.seal["ledger_head_sha256"])
        length = overrides.get("length", self.seal["ledger_length"])
        result = verify_chain(entries, head, length, run_id=overrides.get("run_id", RUN_ID))
        self.assertEqual(result.intact, not result.problems)
        return result.problems

    def codes(self, problems: tuple[str, ...]) -> set[str]:
        return {problem.split(":", 1)[0] for problem in problems}

    def test_intact_chain_and_empty_ledger(self) -> None:
        self.assertEqual(self.verify(self.entries), ())
        self.assertEqual(verify_chain([], None, 0).problems, ())
        self.assertEqual(Ledger(RUN_ID).verify().problems, ())

    def test_edited_entry_is_detected(self) -> None:
        edited = copy.deepcopy(self.entries)
        edited[1]["verdict"] = "FAIL"
        self.assertIn("ENTRY_EDITED", self.codes(self.verify(edited)))

    def test_edited_and_rehashed_entry_breaks_the_next_link_or_the_head(self) -> None:
        edited = copy.deepcopy(self.entries)
        edited[1]["evidence"] = {"rows_examined": 999}
        edited[1]["entry_sha256"] = entry_digest(edited[1])
        self.assertIn("CHAIN_BREAK", self.codes(self.verify(edited)))
        last = copy.deepcopy(self.entries)
        last[-1]["evidence"] = {"rows_examined": 999}
        last[-1]["entry_sha256"] = entry_digest(last[-1])
        self.assertEqual(self.codes(self.verify(last)), {"HEAD_MISMATCH"})

    def test_reordering_is_detected(self) -> None:
        reordered = copy.deepcopy(self.entries)
        reordered[1], reordered[2] = reordered[2], reordered[1]
        self.assertTrue({"SEQUENCE_BREAK", "CHAIN_BREAK"} <= self.codes(self.verify(reordered)))
        # Even a fully re-linked reordering cannot reproduce the sealed head.
        self.assertIn("HEAD_MISMATCH", self.codes(self.verify(rehash_chain(reordered))))

    def test_truncation_is_detected(self) -> None:
        truncated = copy.deepcopy(self.entries[:-2])
        self.assertEqual(self.codes(self.verify(truncated)), {"LENGTH_MISMATCH", "HEAD_MISMATCH"})
        self.assertEqual(self.codes(self.verify([])), {"LENGTH_MISMATCH", "HEAD_MISMATCH"})

    def test_insertion_and_deletion_are_detected(self) -> None:
        inserted = copy.deepcopy(self.entries)
        inserted.insert(2, copy.deepcopy(self.entries[0]))
        self.assertTrue({"SEQUENCE_BREAK", "CHAIN_BREAK", "LENGTH_MISMATCH"} <= self.codes(self.verify(inserted)))
        deleted = copy.deepcopy(self.entries)
        del deleted[2]
        self.assertTrue({"SEQUENCE_BREAK", "CHAIN_BREAK", "LENGTH_MISMATCH"} <= self.codes(self.verify(deleted)))

    def test_unsealed_ledger_is_never_intact(self) -> None:
        self.assertIn("UNSEALED", self.codes(self.verify(self.entries, length=None)))

    def test_entries_from_another_run_are_detected(self) -> None:
        self.assertIn("FOREIGN_INVOCATION", self.codes(self.verify(self.entries, run_id="run-synthetic-other")))

    def test_malformed_entries_are_reported_not_raised(self) -> None:
        extra = copy.deepcopy(self.entries)
        extra[0]["note"] = "added"
        self.assertIn("MALFORMED_ENTRY", self.codes(self.verify(extra)))
        self.assertIn("MALFORMED_ENTRY", self.codes(self.verify(["not an entry", *self.entries[1:]])))
        floated = copy.deepcopy(self.entries)
        floated[0]["evidence"] = {"x": 0.5}
        self.assertIn("MALFORMED_ENTRY", self.codes(self.verify(floated)))


class ParseJsonlTests(unittest.TestCase):
    def test_refuses_what_this_tool_never_writes(self) -> None:
        cases = {
            b'{"a":1}\n\n{"b":2}\n': "blank line",
            b'{"a":1.5}\n': "NON_INTEGER_NUMBER",
            b"[1]\n": "must be a JSON object",
            b'{"a":1,"a":2}\n': "DUPLICATE_KEY",
            b'{"a":"\xff"}\n': "UTF-8",
        }
        for data, fragment in cases.items():
            with self.subTest(data=data):
                with self.assertRaises(LedgerFormatError) as caught:
                    parse_jsonl(data)
                self.assertIn(fragment, str(caught.exception))
                self.assertIn("MALFORMED_LEDGER", str(caught.exception))

    def test_empty_ledger(self) -> None:
        self.assertEqual(parse_jsonl(b""), ())


class InvocationIndexTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def test_complete_invocations_are_terminal(self) -> None:
        traces = index_invocations(recorded_ledger(2).entries)
        self.assertEqual(len(traces), 2)
        for trace in traces.values():
            self.assertTrue(trace.terminal)
            self.assertIs(trace.verdict, Status.PASS)
            self.assertEqual(trace.problems, ())

    def test_an_invocation_left_open_is_not_terminal(self) -> None:
        ledger = recorded_ledger(1)
        open_id = ledger.start(check_id="hung", check_kind="row_count", check_version="1")
        trace = index_invocations(ledger.entries)[open_id]
        self.assertFalse(trace.terminal)
        self.assertIsNone(trace.terminal_seq)
        self.assertEqual(trace.check_id, "hung")

    def test_structural_defects_are_listed(self) -> None:
        entries = [dict(entry) for entry in recorded_ledger(1).entries]
        start, terminal = entries
        cases = {
            "terminal results": [start, terminal, dict(terminal, seq=3)],
            "changes check_id": [start, dict(terminal, check_id="other")],
            "contradicts verdict": [start, dict(terminal, result="ERRORED")],
            "no completed_at": [start, dict(terminal, completed_at=None)],
            "valid verdict": [start, dict(terminal, verdict="MAYBE")],
            "not STARTED": [terminal],
        }
        for fragment, group in cases.items():
            with self.subTest(fragment=fragment):
                (trace,) = index_invocations(group).values()
                self.assertFalse(trace.terminal)
                self.assertTrue(any(fragment in problem for problem in trace.problems), trace.problems)


if __name__ == "__main__":
    unittest.main()
