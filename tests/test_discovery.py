"""Input discovery and accounting (section 3)."""

from __future__ import annotations

import hashlib
import unittest
from decimal import Decimal
from typing import Any

from _helpers import MEASUREMENTS_CSV, TempDirTestCase, manifest_document, try_symlink

from science_gate._canonical import canonical_dumps
from science_gate.discovery import MAX_LISTED_POSITIONS, OpenedInput, discover, row_key_of
from science_gate.manifests import load_manifest
from science_gate.models import DenominatorSource, InputAccounting, InputState


def spec(input_id: str, path: str, fmt: str = "csv", **extra: Any) -> dict[str, Any]:
    return {"id": input_id, "path": path, "format": fmt, **extra}


class DiscoveryTestCase(TempDirTestCase):
    def discover(self, inputs: list[dict[str, Any]], **overrides: Any) -> tuple[InputAccounting, dict[str, OpenedInput]]:
        document = manifest_document(inputs=inputs, checks=[], **overrides)
        return discover(load_manifest(self.write_manifest(document)))

    def one(self, content: str | bytes | None, fmt: str = "csv", **extra: Any) -> OpenedInput:
        name = f"data/input.{fmt}"
        if content is not None:
            self.write(name, content)
        _, opened = self.discover([spec("input", name, fmt, **extra)])
        return opened["input"]


class CsvDiscoveryTests(DiscoveryTestCase):
    def test_valid_csv_is_parsed_hashed_and_kept_as_strings(self) -> None:
        item = self.one(MEASUREMENTS_CSV, row_key=["sample_id"], expected_rows=3, denominator_source="INDEPENDENT")
        record = item.record
        data = MEASUREMENTS_CSV.encode("utf-8")
        self.assertIs(record.state, InputState.PARSED)
        self.assertEqual((record.sha256, record.size_bytes, record.rows), (hashlib.sha256(data).hexdigest(), len(data), 3))
        self.assertEqual((record.discovered, record.opened, record.parsed), (True, True, True))
        self.assertEqual(item.columns, ("sample_id", "value", "count"))
        first = item.rows[0]
        self.assertEqual((first.index, first.line), (1, 2))
        # Values are never converted: grouping and trailing zeros survive for parse_decimal.
        self.assertEqual(dict(first.values), {"sample_id": "SYN-0001", "value": "12.40", "count": "1,234"})
        self.assertEqual(record.closure.to_dict(), {"source": "INDEPENDENT", "holds": True, "expected": 3, "accounted": 3})
        self.assertEqual(record.diagnostics, ())

    def test_closure_breaks_against_an_independent_count(self) -> None:
        item = self.one(MEASUREMENTS_CSV, expected_rows=12, denominator_source="INDEPENDENT")
        self.assertIs(item.record.closure.holds, False)
        self.assertEqual((item.record.closure.expected, item.record.closure.accounted), (12, 3))

    def test_closure_is_never_true_without_an_independent_count(self) -> None:
        declarations = (
            {"expected_rows": 3, "denominator_source": "OBSERVED"},
            {"expected_rows": 3, "denominator_source": "ESTIMATED"},
            {},
        )
        for extra in declarations:
            with self.subTest(extra=extra):
                closure = self.one(MEASUREMENTS_CSV, **extra).record.closure
                self.assertIsNone(closure.holds)

    def test_crlf_and_byte_order_mark_are_handled(self) -> None:
        item = self.one(b"\xef\xbb\xbfsample_id,value\r\nSYN-1,1\r\nSYN-2,2\r\n")
        self.assertIs(item.state, InputState.PARSED)
        self.assertEqual(item.columns, ("sample_id", "value"))
        self.assertEqual(item.record.rows, 2)

    def test_empty_file_and_header_only_file_are_empty_not_passed(self) -> None:
        for content in ("", "sample_id,value\n"):
            with self.subTest(content=content):
                item = self.one(content, expected_rows=3, denominator_source="INDEPENDENT")
                self.assertIs(item.state, InputState.EMPTY)
                self.assertEqual(item.rows, ())
                self.assertEqual(item.record.rows, 0)
                self.assertTrue(item.record.diagnostics[0].startswith("EMPTY"))
                self.assertIs(item.record.closure.holds, False)

    def test_malformed_records_make_the_input_partial(self) -> None:
        item = self.one("sample_id,value\nSYN-1,1\nSYN-2,2,extra\nSYN-3\nSYN-4,4\n")
        self.assertIs(item.state, InputState.PARTIAL)
        self.assertEqual(
            item.record.counts.to_dict(), {"admitted": 2, "excluded": 0, "deferred": 0, "unresolved": 0, "failed": 2}
        )
        self.assertEqual([row.values["sample_id"] for row in item.rows], ["SYN-1", "SYN-4"])
        self.assertIn("MALFORMED_RECORDS: 2 record(s) could not be parsed (lines 3, 4)", item.record.diagnostics)

    def test_blank_or_missing_row_keys_are_unresolved(self) -> None:
        item = self.one("sample_id,value\nSYN-1,1\n  ,2\n,3\n", row_key=["sample_id"])
        self.assertEqual(item.record.counts.unresolved, 2)
        self.assertIs(item.state, InputState.PARTIAL)
        item = self.one("id,value\nSYN-1,1\n", row_key=["sample_id"])
        self.assertTrue(any(text.startswith("ROW_KEY_COLUMN_MISSING") for text in item.record.diagnostics))
        self.assertEqual(item.record.counts.unresolved, 1)

    def test_rows_beyond_max_rows_are_deferred_not_dropped(self) -> None:
        body = "sample_id\n" + "".join(f"SYN-{index}\n" for index in range(5))
        self.write("data/input.csv", body)
        declared = spec("input", "data/input.csv", expected_rows=5, denominator_source="INDEPENDENT")
        item = self.discover([declared], limits={"max_rows": 2})[1]["input"]
        self.assertIs(item.state, InputState.PARTIAL)
        self.assertEqual((item.record.counts.admitted, item.record.counts.deferred), (2, 3))
        self.assertIs(item.record.closure.holds, True)
        self.assertTrue(any(text.startswith("ROWS_DEFERRED: 3") for text in item.record.diagnostics))

    def test_unparseable_csv_is_a_parse_error_with_unknown_counts(self) -> None:
        content = b'sample_id,value\nSYN-1,"unterminated\nSYN-2,"x"y\n'
        item = self.one(content)
        self.assertIs(item.state, InputState.PARSE_ERROR)
        self.assertIsNone(item.rows)
        self.assertIsNone(item.record.rows)
        self.assertFalse(item.record.parsed)
        # The digest still covers every byte of the file, not just what was parsed.
        self.assertEqual(item.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(item.record.size_bytes, len(content))

    def test_ambiguous_headers_are_parse_errors(self) -> None:
        self.assertIn("DUPLICATE_COLUMN", self.one("a,b,a\n1,2,3\n").record.diagnostics[0])
        self.assertIn("INVALID_HEADER", self.one("a, ,c\n1,2,3\n").record.diagnostics[0])

    def test_non_utf8_input_is_a_parse_error_hashed_in_full(self) -> None:
        content = b"sample_id,value\nSYN-1,\xff\xfe\n" + b"SYN-2,2\n" * 5000
        item = self.one(content)
        self.assertIs(item.state, InputState.PARSE_ERROR)
        self.assertIn("NOT_UTF8", item.record.diagnostics[0])
        self.assertEqual(item.sha256, hashlib.sha256(content).hexdigest())

    def test_positions_listed_in_diagnostics_are_bounded(self) -> None:
        body = "a,b\n" + "x\n" * (MAX_LISTED_POSITIONS + 5)
        diagnostic = self.one(body).record.diagnostics[0]
        self.assertIn(f"{MAX_LISTED_POSITIONS + 5} record(s)", diagnostic)
        self.assertIn("and 5 more", diagnostic)


class DigestAndSafetyTests(DiscoveryTestCase):
    def test_matching_declared_digest_is_accepted(self) -> None:
        digest = hashlib.sha256(MEASUREMENTS_CSV.encode("utf-8")).hexdigest()
        item = self.one(MEASUREMENTS_CSV, sha256=digest)
        self.assertIs(item.state, InputState.PARSED)
        self.assertEqual(item.record.declared_sha256, digest)

    def test_hash_mismatch_is_recorded_and_content_is_never_admitted(self) -> None:
        item = self.one(MEASUREMENTS_CSV, sha256="0" * 64)
        self.assertIs(item.state, InputState.HASH_MISMATCH)
        self.assertIsNone(item.rows)
        self.assertEqual(
            item.record.counts.to_dict(), {"admitted": 0, "excluded": 0, "deferred": 0, "unresolved": 0, "failed": 3}
        )
        self.assertTrue(item.record.diagnostics[0].startswith("HASH_MISMATCH: declared " + "0" * 64))
        self.assertFalse(item.record.complete)

    def test_missing_required_input_stays_visible(self) -> None:
        accounting, opened = self.discover([spec("gone", "data/gone.csv")])
        record = accounting.record("gone")
        self.assertIs(record.state, InputState.MISSING)
        self.assertEqual((record.discovered, record.opened, record.parsed), (False, False, False))
        self.assertEqual((record.sha256, record.rows, record.size_bytes), (None, None, None))
        self.assertIsNone(record.counts.accounted)
        self.assertIn("MISSING: required input not found at data/gone.csv", record.diagnostics)
        self.assertIsNone(opened["gone"].rows)
        self.assertEqual(accounting.value("unresolved"), 1)

    def test_missing_optional_input_is_excluded(self) -> None:
        accounting, _ = self.discover([spec("gone", "data/gone.csv", required=False)])
        self.assertEqual((accounting.value("excluded"), accounting.value("unresolved")), (1, 0))

    def test_traversal_is_refused_even_if_the_target_exists(self) -> None:
        self.write("outside.csv", MEASUREMENTS_CSV)
        document = manifest_document(inputs=[spec("escape", "../outside.csv")], checks=[])
        accounting, _ = discover(load_manifest(self.write_manifest(document, "inner/manifest.json")))
        record = accounting.record("escape")
        self.assertIs(record.state, InputState.REFUSED)
        self.assertFalse(record.opened)
        self.assertIsNone(record.sha256)
        self.assertIn("PATH_TRAVERSAL", record.diagnostics[0])
        self.assertEqual(record.path, "../outside.csv")

    def test_symlink_escape_is_refused(self) -> None:
        self.write("outside/secret.csv", MEASUREMENTS_CSV)
        (self.tmp / "project" / "data").mkdir(parents=True)
        try_symlink(self, self.tmp / "outside" / "secret.csv", self.tmp / "project" / "data" / "link.csv")
        document = manifest_document(inputs=[spec("link", "data/link.csv")], checks=[])
        manifest = load_manifest(self.write_manifest(document, "project/manifest.json"))
        self.assertFalse((self.tmp / "outside" / "secret.csv").is_relative_to(manifest.root))
        _, opened = discover(manifest)
        self.assertIs(opened["link"].state, InputState.REFUSED)
        self.assertIn("SYMLINK_ESCAPE", opened["link"].record.diagnostics[0])
        self.assertFalse(opened["link"].record.opened)
        self.assertIsNone(opened["link"].sha256)
        self.assertIsNone(opened["link"].rows)

    def test_symlink_inside_manifest_root_is_allowed(self) -> None:
        target = self.write("data/source.csv", MEASUREMENTS_CSV)
        try_symlink(self, target, self.tmp / "data" / "link.csv")
        _, opened = self.discover([spec("link", "data/link.csv")])
        self.assertIs(opened["link"].state, InputState.PARSED)
        self.assertEqual(opened["link"].absolute_path, target.resolve())
        self.assertEqual(opened["link"].sha256, hashlib.sha256(MEASUREMENTS_CSV.encode("utf-8")).hexdigest())

    def test_oversized_input_is_refused_before_opening(self) -> None:
        self.write("data/big.csv", "a\n" + "1\n" * 100)
        _, opened = self.discover([spec("big", "data/big.csv")], limits={"max_file_bytes": 50})
        record = opened["big"].record
        self.assertIs(record.state, InputState.REFUSED)
        self.assertEqual((record.discovered, record.opened, record.size_bytes), (True, False, 202))
        self.assertIn("FILE_TOO_LARGE", record.diagnostics[0])

    def test_inputs_beyond_max_files_are_refused(self) -> None:
        for name in ("a", "b", "c"):
            self.write(f"data/{name}.csv", "x\n1\n")
        names = ("a", "b", "c")
        accounting, opened = self.discover([spec(name, f"data/{name}.csv") for name in names], limits={"max_files": 2})
        states = [opened[name].state for name in names]
        self.assertEqual(states, [InputState.PARSED, InputState.PARSED, InputState.REFUSED])
        self.assertIn("FILE_COUNT_LIMIT", opened["c"].record.diagnostics[0])
        self.assertEqual(accounting.value("failed"), 1)

    def test_a_directory_is_not_an_input(self) -> None:
        (self.tmp / "data" / "folder.csv").mkdir(parents=True)
        _, opened = self.discover([spec("folder", "data/folder.csv")])
        self.assertIs(opened["folder"].state, InputState.REFUSED)
        self.assertIn("NOT_A_REGULAR_FILE", opened["folder"].record.diagnostics[0])


class JsonDiscoveryTests(DiscoveryTestCase):
    def test_json_array_records_and_decimals(self) -> None:
        content = '[{"sample_id": "SYN-1", "value": 0.10}, {"sample_id": "SYN-2", "value": 7}]'
        item = self.one(content, "json", row_key=["sample_id"])
        self.assertIs(item.state, InputState.PARSED)
        self.assertEqual(item.rows[0].values["value"], Decimal("0.10"))
        self.assertIsNone(item.rows[0].line)
        self.assertEqual(item.document[1]["value"], 7)

    def test_json_object_is_one_record_and_empty_documents_are_empty(self) -> None:
        self.assertEqual(self.one('{"registry": []}', "json").record.rows, 1)
        for content in ("{}", "[]", "null", "   "):
            with self.subTest(content=content):
                self.assertIs(self.one(content, "json").state, InputState.EMPTY)

    def test_strict_json_rules_apply_to_inputs(self) -> None:
        cases = {
            '{"a": 1, "a": 2}': "DUPLICATE_KEY",
            "[NaN]": "NON_FINITE_NUMBER",
            '{"a": Infinity}': "NON_FINITE_NUMBER",
            "[1,": "MALFORMED_JSON",
        }
        for content, code in cases.items():
            with self.subTest(content=content):
                item = self.one(content, "json")
                self.assertIs(item.state, InputState.PARSE_ERROR)
                self.assertIn(code, item.record.diagnostics[0])

    def test_jsonl_fails_only_the_malformed_line(self) -> None:
        item = self.one('{"sample_id": "SYN-1"}\n\n{"sample_id": \n{"sample_id": "SYN-3"}\n', "jsonl")
        self.assertIs(item.state, InputState.PARTIAL)
        self.assertEqual((item.record.counts.admitted, item.record.counts.failed), (2, 1))
        self.assertEqual([row.line for row in item.rows], [1, 4])
        self.assertTrue(any(text.startswith("BLANK_LINES_IGNORED: 1") for text in item.record.diagnostics))


class AccountingTests(DiscoveryTestCase):
    def build(self) -> tuple[InputAccounting, dict[str, OpenedInput]]:
        self.write("data/good.csv", MEASUREMENTS_CSV)
        self.write("data/empty.csv", "")
        self.write("data/bad.csv", MEASUREMENTS_CSV)
        return self.discover(
            [
                spec("good", "data/good.csv"),
                spec("empty", "data/empty.csv"),
                spec("bad", "data/bad.csv", sha256="1" * 64),
                spec("gone", "data/gone.csv"),
                spec("optional", "data/optional.csv", required=False),
            ]
        )

    def test_every_declared_input_is_accounted_for(self) -> None:
        accounting, opened = self.build()
        self.assertEqual(list(opened), ["bad", "empty", "gone", "good", "optional"])
        expected = {
            "expected": 5, "discovered": 3, "opened": 3, "parsed": 3,
            "admitted": 1, "excluded": 1, "unresolved": 2, "failed": 1,
        }
        self.assertEqual({name: accounting.value(name) for name in expected}, expected)
        self.assertIs(accounting.counters["expected"].source, DenominatorSource.INDEPENDENT)
        self.assertIs(accounting.counters["opened"].source, DenominatorSource.OBSERVED)
        self.assertEqual(
            accounting.closure.to_dict(), {"source": "INDEPENDENT", "holds": True, "expected": 5, "accounted": 5}
        )

    def test_examined_is_unknown_until_checks_run(self) -> None:
        accounting, _ = self.build()
        self.assertEqual(accounting.counters["examined"].to_dict(), {"value": None, "denominator_source": "UNAVAILABLE"})

    def test_no_inputs_means_nothing_opened_not_everything_passed(self) -> None:
        accounting, opened = self.discover([])
        self.assertEqual(opened, {})
        self.assertEqual((accounting.value("expected"), accounting.value("opened")), (0, 0))

    def test_discovery_is_deterministic(self) -> None:
        first, _ = self.build()
        second, _ = self.build()
        self.assertEqual(canonical_dumps(first), canonical_dumps(second))


class RowKeyTests(unittest.TestCase):
    def test_usable_and_unusable_keys(self) -> None:
        self.assertEqual(row_key_of({"a": "x", "b": 7, "c": Decimal("1.5")}, ["a", "b", "c"]), ("x", "7", "1.5"))
        for values in ({"a": ""}, {"a": "  "}, {"a": None}, {"a": True}, {"a": [1]}, {}, ["x"]):
            with self.subTest(values=values):
                self.assertIsNone(row_key_of(values, ["a"]))


if __name__ == "__main__":
    unittest.main()
