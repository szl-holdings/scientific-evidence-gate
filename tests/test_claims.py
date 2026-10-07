"""Claim registry and manuscript scan (ARCHITECTURE.md sections 7 and 17.11).

The pure parts (registry parsing, JSON Pointers, the manuscript scanner,
token classification) are tested directly. The check itself is tested through
``verify`` on a private copy of the synthetic ``fixtures/claims/valid``
project, which verifies as PASS, so each test's edit isolates exactly one
defect. Section 17 adds the skip labels, the falsifier generator and the
comparator lookup tested at the end; the numeric forensics have their own
files (test_numeric_forensics, test_narrated_numbers, test_numeric_coverage).
Every claim, value, site and reviewer here is invented.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import unittest
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import REPO_ROOT, TempDirTestCase

from science_gate import invariants
from science_gate._canonical import sha256_bytes, sha256_canonical
from science_gate.claims import (
    CHAIN,
    CLAIM_KEYS,
    CLAIMS_SCHEMA,
    CONSISTENCY_KEYS,
    CSV_SELECTOR_KEYS,
    DECLARED,
    DECLARED_NOT_A_CLAIM,
    DERIVATION_KEYS,
    DERIVATION_LINKS,
    DIGEST_MATCHES,
    DIGEST_MISMATCH,
    DIGEST_NOT_RECORDED,
    DISPOSITION_OUTCOMES,
    EPHEMERAL_CLAIM,
    EXEMPTIONS_APPLIED,
    EXEMPTIONS_STALE,
    HUMAN_REVIEW,
    INCOMPLETE_CHAIN,
    LINK_FIELDS,
    MATCHED,
    MISSING,
    NOT_CLAIM_TOKEN_KEYS,
    NOT_CLAIMS_KEYS,
    REGISTRY_KEYS,
    RESOLVED,
    STORED_OUTPUT_CHANGED,
    STORED_OUTPUT_KEYS,
    STORED_OUTPUT_ROLE,
    STORED_OUTPUT_UNAVAILABLE,
    UNAVAILABLE,
    UNREGISTERED,
    VALUE_DISAGREES,
    VALUE_NOT_LOCATED,
    CsvSelector,
    ManuscriptToken,
    NotClaim,
    RegisteredClaim,
    RegistryFormatError,
    check_claim_registry,
    classify_tokens,
    falsify_claim_registry,
    parse_registry,
    resolve_json_pointer,
    scan_manuscript,
)
from science_gate.invariants import AGREES_AT_STATED_PRECISION, DISAGREES, EXACT, parse_decimal
from science_gate.discovery import discover
from science_gate.manifests import IDENTIFIER_PATTERN, CheckSpec, load_manifest
from science_gate.models import (
    SKIP_JUSTIFICATION_KEY,
    CheckResult,
    ExecutionState,
    FailureMode,
    FalsifierCase,
    Reason,
    SkipJustification,
    Status,
)
from science_gate.verifier import MAX_LISTED, CheckContext, VerificationRun, verify

CLAIMS_FIXTURES = REPO_ROOT / "fixtures" / "claims"
VALID_PROJECT = CLAIMS_FIXTURES / "valid"
SUMMARY_OUTPUT = "outputs/site-summary.json"
COUNTS_OUTPUT = "outputs/site-counts.csv"
DIGEST = "ab" * 32


def minimal_registry(*claims: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"schema": CLAIMS_SCHEMA, "claims": list(claims), **extra}


def token(text: str, line: int = 1, column: int = 1, **marks: Any) -> ManuscriptToken:
    return ManuscriptToken(line, column, text, parse_decimal(text, **marks))


# ---------------------------------------------------------------------------
# The registry document
# ---------------------------------------------------------------------------


class ParseRegistryTest(unittest.TestCase):
    def assertRefused(self, document: Any, fragment: str) -> None:
        with self.assertRaises(RegistryFormatError) as caught:
            parse_registry(document)
        self.assertIn(fragment, str(caught.exception))

    def test_a_bare_claim_parses_with_every_link_missing(self) -> None:
        registry = parse_registry(minimal_registry({"claim_id": "C-001"}))
        (claim,) = registry.claims
        self.assertEqual(claim, RegisteredClaim("C-001"))
        for link in CHAIN:
            with self.subTest(link=link):
                self.assertEqual(claim.missing_fields(link), LINK_FIELDS[link])

    def test_the_valid_fixture_registry_parses_completely(self) -> None:
        document = json.loads((VALID_PROJECT / "claims" / "registry.json").read_text(encoding="utf-8"))
        registry = parse_registry(document)
        self.assertEqual([claim.claim_id for claim in registry.claims], ["C-001", "C-002", "C-003", "C-004"])
        for claim in registry.claims:
            for link in CHAIN:
                self.assertEqual(claim.missing_fields(link), (), f"{claim.claim_id} {link}")
        selector = CsvSelector((("site", "site-gamma"),), "total_count")
        self.assertEqual(registry.claims[2].stored_output.selector, selector)
        self.assertEqual(registry.not_claims, (NotClaim(1, "3", "draft number of this synthetic note, not a result"),))

    def test_null_absent_and_blank_fields_all_mean_missing(self) -> None:
        claim = {
            "claim_id": "C-001",
            "statement": "   ",
            "value": "",
            "derivation": None,
            "stored_output": {"path": None, "sha256": "", "selector": None},
            "review_state": None,
        }
        (parsed,) = parse_registry(minimal_registry(claim)).claims
        self.assertEqual(parsed, RegisteredClaim("C-001"))

    def test_structural_problems_are_refused(self) -> None:
        cases = {
            "schema must be": {"schema": "science-gate-claims/v0", "claims": []},
            "registry must be a JSON object": ["not", "an", "object"],
            "is missing ['claims']": {"schema": CLAIMS_SCHEMA},
            "unknown key(s) ['extra']": minimal_registry(extra=1),
            "claims must be a list": {"schema": CLAIMS_SCHEMA, "claims": {}},
            "must be a JSON object": minimal_registry("C-001"),
            "is missing ['claim_id']": minimal_registry({"value": "1"}),
        }
        for fragment, document in cases.items():
            with self.subTest(fragment=fragment):
                self.assertRefused(document, fragment)

    def test_a_typo_in_a_nested_key_is_refused_rather_than_dropping_a_pin(self) -> None:
        claim = {"claim_id": "C-001", "stored_output": {"path": "out.json", "sha265": DIGEST, "selector": "/v"}}
        self.assertRefused(minimal_registry(claim), "unknown key(s) ['sha265']")
        self.assertRefused(minimal_registry({"claim_id": "C-001", "derivation": {"recipe": "x"}}), "['recipe']")

    def test_claim_ids_must_be_identifiers_and_unique(self) -> None:
        self.assertRefused(minimal_registry({"claim_id": "C 001"}), "claim_id must match")
        self.assertRefused(minimal_registry({"claim_id": 7}), "claim_id must match")
        self.assertRefused(minimal_registry({"claim_id": "C-001"}, {"claim_id": "C-001"}), "registered twice")

    def test_recorded_digests_must_be_well_formed(self) -> None:
        bad = {"claim_id": "C-001", "stored_output": {"sha256": "ABC"}}
        self.assertRefused(minimal_registry(bad), "stored_output.sha256 must be 64 lowercase hex")
        bad = {"claim_id": "C-001", "derivation": {"input_manifest_sha256": "A" * 64}}
        self.assertRefused(minimal_registry(bad), "input_manifest_sha256 must be 64 lowercase hex")

    def test_values_keep_their_printed_form(self) -> None:
        cases = {"12.40": "12.40", 12: "12", Decimal("12.40"): "12.40", Decimal("1E+3"): "1000"}
        for value, printed in cases.items():
            with self.subTest(value=value):
                (claim,) = parse_registry(minimal_registry({"claim_id": "C-001", "value": value})).claims
                self.assertEqual(claim.value, printed)

    def test_values_that_are_not_printed_numbers_are_refused(self) -> None:
        for value in (True, ["1"], {"v": "1"}, Decimal("1E+999999")):
            with self.subTest(value=value):
                self.assertRefused(minimal_registry({"claim_id": "C-001", "value": value}), "value")

    def test_precision_must_be_a_non_negative_integer(self) -> None:
        for precision in (-1, True, "2", Decimal("1.5")):
            with self.subTest(precision=precision):
                claim = {"claim_id": "C-001", "precision_decimals": precision}
                self.assertRefused(minimal_registry(claim), "precision_decimals")

    def test_stored_output_paths_must_stay_inside_the_manifest_directory(self) -> None:
        for path in ("../outside.json", "/abs/out.json", "C:\\out.json", "outputs/../../x.json"):
            with self.subTest(path=path):
                claim = {"claim_id": "C-001", "stored_output": {"path": path}}
                self.assertRefused(minimal_registry(claim), "stored_output.path is refused")

    def test_stored_output_paths_are_normalized(self) -> None:
        claim = {"claim_id": "C-001", "stored_output": {"path": "outputs/./a\\b.json"}}
        (parsed,) = parse_registry(minimal_registry(claim)).claims
        self.assertEqual(parsed.stored_output.path, "outputs/a/b.json")

    def test_selectors(self) -> None:
        accepted = {"": "", "/a/0": "/a/0", "/a~1b/~0c": "/a~1b/~0c"}
        for selector, expected in accepted.items():
            with self.subTest(selector=selector):
                claim = {"claim_id": "C-001", "stored_output": {"selector": selector}}
                (parsed,) = parse_registry(minimal_registry(claim)).claims
                self.assertEqual(parsed.stored_output.selector, expected)
        refused = (
            ("a/b", "JSON Pointer"),
            ("/a~2", "'~' not followed by 0 or 1"),
            ({"row": {}, "column": "c"}, "row must map"),
            ({"row": {"site": 1}, "column": "c"}, "row must map"),
            ({"row": {"site": "a"}, "column": ""}, "column must be a non-empty string"),
            ({"row": {"site": "a"}}, "is missing ['column']"),
            (3, "must be a JSON object"),
        )
        for selector, fragment in refused:
            with self.subTest(selector=selector):
                claim = {"claim_id": "C-001", "stored_output": {"selector": selector}}
                self.assertRefused(minimal_registry(claim), fragment)

    def test_not_claims_must_pin_the_manuscript_and_be_well_formed(self) -> None:
        good = {"manuscript_sha256": DIGEST, "tokens": [{"line": 2, "text": "2026", "reason": "year"}]}
        registry = parse_registry(minimal_registry(not_claims=good))
        self.assertEqual(registry.not_claims, (NotClaim(2, "2026", "year"),))
        self.assertEqual(registry.not_claims_manuscript_sha256, DIGEST)
        entry = {"line": 2, "text": "2026", "reason": "year"}
        cases = {
            "must pin the manuscript": {"manuscript_sha256": "", "tokens": []},
            "is missing ['manuscript_sha256']": {"tokens": []},
            "tokens must be a list": {"manuscript_sha256": DIGEST, "tokens": {}},
            "line must be a positive integer": {"manuscript_sha256": DIGEST, "tokens": [{**entry, "line": 0}]},
            "needs a non-blank text and reason": {"manuscript_sha256": DIGEST, "tokens": [{**entry, "reason": " "}]},
            "repeats line 2": {"manuscript_sha256": DIGEST, "tokens": [entry, dict(entry)]},
        }
        for fragment, block in cases.items():
            with self.subTest(fragment=fragment):
                self.assertRefused(minimal_registry(not_claims=block), fragment)

    def test_the_schema_documents_exactly_what_the_code_accepts(self) -> None:
        schema = json.loads((REPO_ROOT / "schemas" / "claims.schema.json").read_text(encoding="utf-8"))
        definitions = schema["$defs"]
        self.assertEqual(schema["$id"], CLAIMS_SCHEMA)
        self.assertEqual(schema["properties"]["schema"]["const"], CLAIMS_SCHEMA)
        pairs = {
            "registry": (REGISTRY_KEYS, schema),
            "claim": (CLAIM_KEYS, definitions.get("claim")),
            "derivation": (DERIVATION_KEYS, definitions.get("derivation")),
            "consistency": (CONSISTENCY_KEYS, definitions.get("consistency")),
            "stored_output": (STORED_OUTPUT_KEYS, definitions.get("stored_output")),
            "csv_selector": (CSV_SELECTOR_KEYS, definitions.get("csv_selector")),
            "not_claims": (NOT_CLAIMS_KEYS, definitions.get("not_claims")),
            "not_claims token": (
                NOT_CLAIM_TOKEN_KEYS,
                definitions.get("not_claims", {}).get("properties", {}).get("tokens", {}).get("items"),
            ),
        }
        for name, (keys, node) in pairs.items():
            with self.subTest(definition=name):
                self.assertIsNotNone(node, f"the schema has no definition for {name}")
                self.assertEqual(set(node["properties"]), set(keys))
                self.assertFalse(node["additionalProperties"])
        self.assertEqual(definitions["claim"]["required"], ["claim_id"])
        self.assertEqual(definitions["claim"]["properties"]["claim_id"]["pattern"], f"^{IDENTIFIER_PATTERN.pattern}$")
        self.assertEqual(definitions.get("consistency", {}).get("required"), ["test", "n"])


class JsonPointerTest(unittest.TestCase):
    DOCUMENT = {"a": {"b/c": [10, {"d~e": "x"}]}, "": "empty key", "n": None}

    def test_resolution(self) -> None:
        cases = {
            "": (True, self.DOCUMENT),
            "/a/b~1c/0": (True, 10),
            "/a/b~1c/1/d~0e": (True, "x"),
            "/": (True, "empty key"),
            "/n": (True, None),
        }
        for pointer, expected in cases.items():
            with self.subTest(pointer=pointer):
                self.assertEqual(resolve_json_pointer(self.DOCUMENT, pointer), expected)

    def test_missing_paths_are_not_found_and_never_raise(self) -> None:
        for pointer in ("/missing", "/a/b~1c/2", "/a/b~1c/01", "/a/b~1c/-", "/a/b~1c/0/deeper", "/a/b~1c/99999999999"):
            with self.subTest(pointer=pointer):
                self.assertEqual(resolve_json_pointer(self.DOCUMENT, pointer), (False, None))


# ---------------------------------------------------------------------------
# The manuscript scan
# ---------------------------------------------------------------------------


class ScanManuscriptTest(unittest.TestCase):
    def texts(self, text: str, **marks: Any) -> list[str]:
        return [item.text for item in scan_manuscript(text, **marks).tokens]

    def test_line_numbers_and_columns_follow_every_line_ending(self) -> None:
        scan = scan_manuscript("first 1\r\nsecond 22\rthird 333\nfourth\n")
        self.assertEqual(scan.lines, 4)
        self.assertEqual([(item.line, item.column, item.text) for item in scan.tokens], [
            (1, 7, "1"), (2, 8, "22"), (3, 7, "333"),
        ])

    def test_an_empty_manuscript_has_no_lines_and_no_tokens(self) -> None:
        scan = scan_manuscript("")
        self.assertEqual((scan.lines, scan.tokens), (0, ()))

    def test_identifiers_are_not_numbers(self) -> None:
        text = "SYN-0001 C-001 H2O v1.2.3 Fig.2 sha256 run_2 issue#4 path/to/file7"
        scan = scan_manuscript(text)
        self.assertEqual(scan.tokens, ())
        self.assertEqual(scan.identifier_digits_skipped, 9)

    def test_urls_and_dois_are_masked(self) -> None:
        scan = scan_manuscript("See https://doi.org/10.5555/syn-001 and doi:10.5555/abc.7 then 4.")
        self.assertEqual([item.text for item in scan.tokens], ["4"])
        self.assertEqual(scan.tokens[0].column, 64)
        self.assertEqual(scan.urls_and_dois_masked, 2)

    def test_signs_are_kept_only_when_they_join_nothing(self) -> None:
        scan = scan_manuscript("change \u22120.5 and -3 over 3-5 days (+2)")
        self.assertEqual([item.text for item in scan.tokens], ["\u22120.5", "-3", "3", "5", "+2"])
        self.assertEqual([item.number.value for item in scan.tokens], [
            Decimal("-0.5"), Decimal("-3"), Decimal("3"), Decimal("5"), Decimal("2"),
        ])

    def test_trailing_punctuation_is_not_part_of_a_number(self) -> None:
        (item,) = scan_manuscript("The mean was 12.4.").tokens
        self.assertEqual((item.text, item.number.decimals), ("12.4", 1))
        self.assertEqual(self.texts("values 1, 2, and 3"), ["1", "2", "3"])

    def test_numbers_glued_to_units_are_still_numbers(self) -> None:
        self.assertEqual(self.texts("12.4mg 95% 5-fold"), ["12.4", "95", "5"])

    def test_undeclared_separators_are_ambiguous_never_guessed(self) -> None:
        (item,) = scan_manuscript("count 1,234").tokens
        self.assertEqual(item.number.state, "AMBIGUOUS_SEPARATOR")
        (item,) = scan_manuscript("count 1,234", thousands=",").tokens
        self.assertEqual((item.number.state, item.number.value), ("PARSED", Decimal("1234")))
        (item,) = scan_manuscript("value 12,5", decimal_point=",").tokens
        self.assertEqual(item.number.value, Decimal("12.5"))
        (item,) = scan_manuscript("list 1,2,3", thousands=",").tokens
        self.assertEqual(item.number.state, "AMBIGUOUS_SEPARATOR")

    def test_exponents_are_scanned_but_not_read(self) -> None:
        (item,) = scan_manuscript("rate 1.2e3 per unit").tokens
        self.assertEqual((item.text, item.number.state), ("1.2e3", "NOT_A_NUMBER"))


class ClassifyTokensTest(unittest.TestCase):
    CLAIMS = (RegisteredClaim("C-001", value="12.4"), RegisteredClaim("C-002", value="10801"))

    def classify(self, *texts: str, exemptions: Any = None, **marks: Any) -> list[Any]:
        tokens = [token(text, line=index + 1, **marks) for index, text in enumerate(texts)]
        return list(classify_tokens(tokens, self.CLAIMS, exemptions or {}, **marks))

    def test_a_match_needs_the_same_value_and_printed_decimals(self) -> None:
        exact, wider, shorter = self.classify("12.4", "12.40", "12")
        self.assertEqual((exact.classification, exact.claim_ids), (MATCHED, ("C-001",)))
        self.assertEqual(wider.classification, UNREGISTERED)
        self.assertIn("equals C-001 (1 decimal(s)) but prints 2 decimal(s)", wider.detail)
        self.assertEqual((shorter.classification, shorter.detail), (UNREGISTERED, ""))

    def test_rounding_never_creates_a_match(self) -> None:
        (item,) = list(classify_tokens([token("0.14")], [RegisteredClaim("C-009", value="0.1")], {}))
        self.assertEqual(item.classification, UNREGISTERED)

    def test_thousands_separators_cannot_evade_comparison(self) -> None:
        (declared,) = self.classify("10,801", thousands=",")
        self.assertEqual((declared.classification, declared.claim_ids), (MATCHED, ("C-002",)))
        (undeclared,) = self.classify("10,801")
        self.assertEqual((undeclared.classification, undeclared.readable), (UNREGISTERED, False))
        self.assertIn("AMBIGUOUS_SEPARATOR", undeclared.detail)
        # Identical raw text is still not a match when neither side can be read unambiguously.
        (same_text,) = list(classify_tokens([token("10,801")], [RegisteredClaim("C-003", value="10,801")], {}))
        self.assertEqual((same_text.classification, same_text.claim_ids), (UNREGISTERED, ()))

    def test_every_claim_printing_the_value_is_named(self) -> None:
        claims = (RegisteredClaim("C-001", value="6"), RegisteredClaim("C-002", value="6"))
        (item,) = list(classify_tokens([token("6")], claims, {}))
        self.assertEqual(item.claim_ids, ("C-001", "C-002"))

    def test_exemptions_are_listed_as_declared_not_claims(self) -> None:
        exemption = NotClaim(1, "2026", "calendar year of the synthetic note")
        (item,) = self.classify("2026", exemptions={(1, "2026"): exemption})
        self.assertEqual((item.classification, item.detail), (DECLARED_NOT_A_CLAIM, exemption.reason))
        self.assertEqual(item.to_dict()["line"], 1)


# ---------------------------------------------------------------------------
# The check, through verify(), on a private copy of the valid fixture
# ---------------------------------------------------------------------------


class ClaimsProjectCase(TempDirTestCase):
    """A private copy of ``fixtures/claims/valid`` under ``self.project``, with the clock pinned."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.project = self.tmp / "project"
        shutil.copytree(VALID_PROJECT, self.project)

    def path(self, relpath: str) -> Path:
        return self.project / relpath

    def read_json(self, relpath: str) -> Any:
        return json.loads(self.path(relpath).read_text(encoding="utf-8"))

    def write_file(self, relpath: str, data: str) -> Path:
        path = self.path(relpath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8"))
        return path

    def write_json(self, relpath: str, document: Any) -> None:
        self.write_file(relpath, json.dumps(document, indent=2))

    def digest(self, relpath: str) -> str:
        return sha256_bytes(self.path(relpath).read_bytes())

    def registry(self) -> dict[str, Any]:
        return self.read_json("claims/registry.json")

    def save_registry(self, document: dict[str, Any]) -> None:
        self.write_json("claims/registry.json", document)

    def edit_claim(self, claim_id: str, **fields: Any) -> None:
        """Replace fields of one claim; a value of ``...`` deletes the field."""
        document = self.registry()
        (claim,) = [item for item in document["claims"] if item["claim_id"] == claim_id]
        for name, value in fields.items():
            if value is ...:
                claim.pop(name, None)
            else:
                claim[name] = value
        self.save_registry(document)

    def edit_stored_output(self, claim_id: str, **fields: Any) -> None:
        document = self.registry()
        (claim,) = [item for item in document["claims"] if item["claim_id"] == claim_id]
        for name, value in fields.items():
            if value is ...:
                claim["stored_output"].pop(name, None)
            else:
                claim["stored_output"][name] = value
        self.save_registry(document)

    def manuscript(self) -> str:
        return self.path("claims/manuscript.md").read_text(encoding="utf-8")

    def write_manuscript(self, text: str, *, repin: bool = True) -> None:
        """Replace the manuscript; by default re-pin the exemptions to it, isolating the edit under test."""
        self.write_file("claims/manuscript.md", text)
        if repin:
            document = self.registry()
            document["not_claims"]["manuscript_sha256"] = self.digest("claims/manuscript.md")
            self.save_registry(document)

    def write_output(self, relpath: str, data: str, *, repin: bool = True) -> None:
        """Replace a stored output; by default re-pin every claim citing it, isolating the edit under test."""
        self.write_file(relpath, data)
        if repin:
            document = self.registry()
            for claim in document["claims"]:
                if claim.get("stored_output", {}).get("path") == relpath:
                    claim["stored_output"]["sha256"] = self.digest(relpath)
            self.save_registry(document)

    def update_manifest(self, **fields: Any) -> None:
        document = self.read_json("manifest.json")
        for name, value in fields.items():
            if value is ...:
                document.pop(name, None)
            else:
                document[name] = value
        self.write_json("manifest.json", document)

    def set_claims_check(self, **fields: Any) -> None:
        document = self.read_json("manifest.json")
        (entry,) = [item for item in document["checks"] if item["id"] == "claims"]
        entry.update(fields)
        self.write_json("manifest.json", document)

    def verify(self) -> VerificationRun:
        return verify(self.path("manifest.json"))

    def claims_result(self, run: VerificationRun | None = None) -> CheckResult:
        run = run or self.verify()
        (result,) = [item for item in run.result.checks if item.check_id == "claims"]
        return result

    def claim_record(self, result: CheckResult, claim_id: str) -> dict[str, Any]:
        records = [*result.evidence["problem_claims"], *result.evidence["resolved_claims"]]
        (record,) = [item for item in records if item["claim_id"] == claim_id]
        return record

    @staticmethod
    def link(record: dict[str, Any], name: str) -> dict[str, Any]:
        (found,) = [item for item in record["links"] if item["link"] == name]
        return found

    def assertOutcome(
        self, result: CheckResult, verdict: Status, reason: Reason, *modes: FailureMode
    ) -> None:
        self.assertEqual((result.verdict, result.reason), (verdict, reason), result.diagnostics)
        self.assertEqual(set(result.failure_modes), set(modes), result.diagnostics)


class FixtureOutcomesTest(unittest.TestCase):
    """Each committed fixture verifies to the outcome ``fixtures/claims/expected.json`` records."""

    def test_every_fixture_matches_its_expected_outcome(self) -> None:
        expected = json.loads((CLAIMS_FIXTURES / "expected.json").read_text(encoding="utf-8"))["fixtures"]
        directories = sorted(path.name for path in CLAIMS_FIXTURES.iterdir() if path.is_dir())
        self.assertEqual(sorted(expected), directories)
        for name, want in expected.items():
            with self.subTest(fixture=name):
                run = verify(CLAIMS_FIXTURES / name / "manifest.json")
                (result,) = [item for item in run.result.checks if item.check_id == "claims"]
                self.assertEqual(
                    (run.status.value, run.result.reason.value, run.exit_code),
                    (want["status"], want["reason"], want["exit_code"]),
                )
                self.assertEqual(
                    (result.verdict.value, result.reason.value, sorted(mode.value for mode in result.failure_modes)),
                    (
                        want["claims_check"]["verdict"],
                        want["claims_check"]["reason"],
                        want["claims_check"]["failure_modes"],
                    ),
                )


class ResolvedClaimsTest(ClaimsProjectCase):
    def test_the_valid_project_passes_with_evidence_of_every_comparison(self) -> None:
        run = self.verify()
        self.assertEqual((run.status, run.exit_code), (Status.PASS, 0))
        result = self.claims_result(run)
        self.assertEqual((result.execution_state, result.verdict), (ExecutionState.CHECKED, Status.PASS))
        self.assertEqual(result.rows_examined, 9)
        evidence = result.evidence
        self.assertEqual(evidence["records_examined"], {"claims": 4, "manuscript_tokens": 5})
        self.assertEqual(evidence["dispositions"], {RESOLVED: 4})
        self.assertEqual(evidence["problem_claims"], [])
        outcomes = {}
        for record in evidence["resolved_claims"]:
            outcomes[record["claim_id"]] = record["value_comparison"]["outcome"]
            self.assertEqual([link["link"] for link in record["links"]], list(CHAIN))
            self.assertEqual(self.link(record, "STORED_OUTPUT")["state"], DIGEST_MATCHES)
            for name in sorted(DERIVATION_LINKS - {"STORED_OUTPUT"}):
                self.assertEqual(self.link(record, name)["state"], DECLARED)
        self.assertEqual(
            outcomes, {"C-001": EXACT, "C-002": AGREES_AT_STATED_PRECISION, "C-003": EXACT, "C-004": EXACT}
        )
        self.assertEqual(self.claim_record(result, "C-003")["manuscript_lines"], [6])
        scan = evidence["manuscript_scan"]
        self.assertEqual(scan["classifications"], {MATCHED: 4, UNREGISTERED: 0, DECLARED_NOT_A_CLAIM: 1})
        self.assertEqual(scan["exemptions"]["state"], EXEMPTIONS_APPLIED)
        self.assertIn("not established", evidence["scope"])

    def test_stored_outputs_enter_the_evidence_manifest(self) -> None:
        run = self.verify()
        documents = {entry["path"]: entry for entry in run.evidence_manifest["entries"] if entry["kind"] == "document"}
        for relpath in (SUMMARY_OUTPUT, COUNTS_OUTPUT):
            with self.subTest(path=relpath):
                self.assertEqual(documents[relpath]["name"], STORED_OUTPUT_ROLE)
                self.assertEqual(documents[relpath]["sha256"], self.digest(relpath))

    def test_the_outcome_is_deterministic(self) -> None:
        first, second = self.claims_result(), self.claims_result()
        self.assertEqual(sha256_canonical(first.evidence), sha256_canonical(second.evidence))
        self.assertEqual(first.diagnostics, second.diagnostics)


class UnregisteredNumbersTest(ClaimsProjectCase):
    def test_an_unregistered_number_is_listed_with_its_line_and_the_run_abstains(self) -> None:
        self.write_manuscript(self.manuscript() + "An unregistered synthetic figure of 42.5 appears here.\n")
        run = self.verify()
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.UNVERIFIED, 2))
        result = self.claims_result(run)
        # Section 17.11: the unchecked number also puts coverage below the floor, recorded after
        # the 0.1.0 finding, so the primary reason stays UNVERIFIED.
        self.assertOutcome(
            result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM, FailureMode.OMITTED_POPULATION
        )
        (listed,) = result.evidence["manuscript_scan"]["unregistered_tokens"]
        self.assertEqual(
            {key: listed[key] for key in ("line", "column", "text", "classification")},
            {"line": 7, "column": 37, "text": "42.5", "classification": UNREGISTERED},
        )
        self.assertEqual(result.evidence["numeric_coverage"]["buckets"][UNREGISTERED], [{"line": 7, "text": "42.5"}])
        self.assertIn("line 7 '42.5'", " ".join(result.diagnostics))

    def test_a_number_printed_at_a_different_precision_is_unregistered(self) -> None:
        self.write_manuscript(self.manuscript().replace("was 6.27 and", "was 6.270 and"))
        result = self.claims_result()
        self.assertOutcome(
            result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM, FailureMode.OMITTED_POPULATION
        )
        (listed,) = result.evidence["manuscript_scan"]["unregistered_tokens"]
        self.assertIn("equals C-001 (2 decimal(s)) but prints 3 decimal(s)", listed["detail"])

    def test_an_undeclared_thousands_separator_requires_review(self) -> None:
        self.set_claims_check(params={})
        result = self.claims_result()
        self.assertOutcome(result, Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW, FailureMode.OMITTED_POPULATION)
        buckets = result.evidence["numeric_coverage"]["buckets"]
        self.assertEqual(buckets["AMBIGUOUS_SEPARATOR"], [{"line": 6, "text": "10,801"}])
        (listed,) = result.evidence["manuscript_scan"]["unregistered_tokens"]
        self.assertEqual((listed["text"], listed["number_state"]), ("10,801", "AMBIGUOUS_SEPARATOR"))
        self.assertEqual(result.evidence["manuscript_scan"]["unreadable"], 1)

    def test_many_unregistered_numbers_are_all_counted_but_quoted_briefly(self) -> None:
        extra = "".join(f"Invented figure {index}.5 here.\n" for index in range(100, 100 + MAX_LISTED + 5))
        self.write_manuscript(self.manuscript() + extra)
        result = self.claims_result()
        scan = result.evidence["manuscript_scan"]
        self.assertEqual(scan["classifications"][UNREGISTERED], MAX_LISTED + 5)
        self.assertEqual(len(scan["unregistered_tokens"]), MAX_LISTED)
        diagnostic, coverage = result.diagnostics
        self.assertTrue(diagnostic.startswith(f"UNREGISTERED: {MAX_LISTED + 5} manuscript number(s)"))
        self.assertTrue(diagnostic.endswith(", ..."))
        self.assertTrue(coverage.startswith("NUMERIC_COVERAGE: 4 of 29 undeclared manuscript number(s) checked"))
        self.assertEqual(result.evidence["numeric_coverage"]["bucket_counts"][UNREGISTERED], MAX_LISTED + 5)


class ExemptionsTest(ClaimsProjectCase):
    def test_an_edited_manuscript_voids_the_exemptions(self) -> None:
        self.write_manuscript(self.manuscript() + "A sentence without numbers.\n", repin=False)
        result = self.claims_result()
        # The draft number is no longer exempt, so it is unregistered: UNVERIFIED comes first.
        self.assertOutcome(
            result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM, FailureMode.OMITTED_POPULATION
        )
        self.assertEqual(result.evidence["numeric_coverage"]["declared"], 0)
        scan = result.evidence["manuscript_scan"]
        self.assertEqual(scan["exemptions"]["state"], EXEMPTIONS_STALE)
        self.assertEqual(scan["unregistered_tokens"][0]["text"], "3")
        self.assertTrue(any("none of its 1 exemption(s) were applied" in text for text in result.diagnostics))

    def test_an_exemption_matching_no_number_requires_review(self) -> None:
        document = self.registry()
        document["not_claims"]["tokens"].append({"line": 3, "text": "99", "reason": "stale synthetic entry"})
        self.save_registry(document)
        result = self.claims_result()
        self.assertOutcome(result, Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW)
        unused = result.evidence["manuscript_scan"]["exemptions"]["unused"]
        self.assertEqual(unused, [{"line": 3, "text": "99", "reason": "stale synthetic entry"}])


class EphemeralClaimsTest(ClaimsProjectCase):
    def test_a_claim_without_a_derivation_is_unverified_and_never_false(self) -> None:
        self.edit_claim("C-004", derivation=...)
        run = self.verify()
        self.assertEqual((run.status, run.exit_code), (Status.ABSTAIN, 2))
        result = self.claims_result(run)
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM)
        record = self.claim_record(result, "C-004")
        self.assertEqual(record["disposition"], EPHEMERAL_CLAIM)
        self.assertEqual(record["missing_links"], ["ANALYSIS_RECIPE", "CODE_VERSION", "ENVIRONMENT", "INPUT_MANIFEST"])
        # The stored output is still compared, and it agrees: ephemeral is about provenance, not truth.
        self.assertEqual(record["value_comparison"]["outcome"], EXACT)
        self.assertNotIn(FailureMode.SOURCE_MISMATCH, result.failure_modes)

    def test_each_missing_derivation_link_is_listed(self) -> None:
        for name, link in zip(DERIVATION_KEYS, ("ANALYSIS_RECIPE", "CODE_VERSION", "ENVIRONMENT", "INPUT_MANIFEST")):
            with self.subTest(field=name):
                document = json.loads((VALID_PROJECT / "claims" / "registry.json").read_text(encoding="utf-8"))
                document["claims"][0]["derivation"][name] = None
                self.save_registry(document)
                result = self.claims_result()
                self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM)
                record = self.claim_record(result, "C-001")
                self.assertEqual(record["missing_links"], [link])
                self.assertEqual(self.link(record, link)["missing_fields"], [f"derivation.{name}"])

    def test_a_claim_with_no_stored_output_is_ephemeral_and_not_compared(self) -> None:
        self.edit_claim("C-004", stored_output=..., derivation=...)
        result = self.claims_result()
        record = self.claim_record(result, "C-004")
        self.assertEqual(record["disposition"], EPHEMERAL_CLAIM)
        self.assertIn("STORED_OUTPUT", record["missing_links"])
        comparison = record["value_comparison"]
        self.assertEqual((comparison["outcome"], comparison["agrees"]), ("NOT_COMPARED", None))
        self.assertNotIn('"agrees":false', json.dumps(result.evidence, separators=(",", ":")))

    def test_an_unpinned_stored_output_is_ephemeral_but_still_read(self) -> None:
        self.edit_stored_output("C-003", sha256=...)
        result = self.claims_result()
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM)
        link = self.link(self.claim_record(result, "C-003"), "STORED_OUTPUT")
        self.assertEqual((link["state"], link["digest"]), (MISSING, DIGEST_NOT_RECORDED))
        self.assertEqual(link["missing_fields"], ["stored_output.sha256"])
        self.assertEqual(link["current_sha256"], self.digest(COUNTS_OUTPUT))

    def test_missing_review_or_publication_links_leave_the_chain_incomplete(self) -> None:
        for name, link in (("review_state", "REVIEW_STATE"), ("publication_location", "PUBLICATION_LOCATION")):
            with self.subTest(field=name):
                document = json.loads((VALID_PROJECT / "claims" / "registry.json").read_text(encoding="utf-8"))
                document["claims"][1][name] = ""
                self.save_registry(document)
                result = self.claims_result()
                self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED)
                record = self.claim_record(result, "C-002")
                self.assertEqual((record["disposition"], record["missing_links"]), (INCOMPLETE_CHAIN, [link]))

    def test_a_claim_without_a_value_is_incomplete_and_not_compared(self) -> None:
        self.edit_claim("C-001", value=None)
        record = self.claim_record(self.claims_result(), "C-001")
        self.assertEqual((record["disposition"], record["missing_links"]), (INCOMPLETE_CHAIN, ["CLAIM"]))
        self.assertEqual(record["value_comparison"]["outcome"], "NOT_COMPARED")

    def test_missing_evidence_never_maps_to_fail(self) -> None:
        for kind in (EPHEMERAL_CLAIM, INCOMPLETE_CHAIN, STORED_OUTPUT_UNAVAILABLE, VALUE_NOT_LOCATED, HUMAN_REVIEW):
            with self.subTest(disposition=kind):
                self.assertEqual(DISPOSITION_OUTCOMES[kind][0], Status.ABSTAIN)
        self.assertEqual(list(DISPOSITION_OUTCOMES)[:2], [STORED_OUTPUT_CHANGED, VALUE_DISAGREES])

    def test_problem_claims_beyond_the_listing_limit_are_still_counted(self) -> None:
        document = self.registry()
        document["claims"].extend({"claim_id": f"X-{index:03d}", "value": "1"} for index in range(MAX_LISTED + 3))
        self.save_registry(document)
        result = self.claims_result()
        evidence = result.evidence
        self.assertEqual(evidence["claims_examined"], 4 + MAX_LISTED + 3)
        self.assertEqual(evidence["dispositions"][EPHEMERAL_CLAIM], MAX_LISTED + 3)
        self.assertEqual(len(evidence["problem_claims"]), MAX_LISTED)
        self.assertEqual(len(result.diagnostics), MAX_LISTED + 1)
        self.assertIn("3 more claim(s) with problems", result.diagnostics[-1])


class StoredOutputTest(ClaimsProjectCase):
    def test_a_replaced_stored_output_fails_even_when_the_value_still_agrees(self) -> None:
        original = self.path(SUMMARY_OUTPUT).read_text(encoding="utf-8")
        self.write_output(SUMMARY_OUTPUT, original.replace("Invented values", "Invented numbers"), repin=False)
        run = self.verify()
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))
        result = self.claims_result(run)
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        record = self.claim_record(result, "C-001")
        self.assertEqual(record["disposition"], STORED_OUTPUT_CHANGED)
        self.assertEqual(self.link(record, "STORED_OUTPUT")["state"], DIGEST_MISMATCH)
        self.assertEqual(record["value_comparison"]["outcome"], EXACT)
        self.assertEqual(self.claim_record(result, "C-003")["disposition"], RESOLVED)

    def test_a_replaced_output_changes_the_evidence_manifest(self) -> None:
        before = self.verify()
        self.write_output(COUNTS_OUTPUT, "site,samples,total_count\nsite-gamma,2,10801\n", repin=False)
        after = self.verify()
        self.assertNotEqual(before.result.evidence_manifest_sha256, after.result.evidence_manifest_sha256)
        documents = {entry["path"]: entry["sha256"] for entry in after.evidence_manifest["entries"] if "path" in entry}
        self.assertEqual(documents[COUNTS_OUTPUT], self.digest(COUNTS_OUTPUT))
        self.assertEqual(self.claim_record(self.claims_result(after), "C-003")["disposition"], STORED_OUTPUT_CHANGED)

    def test_a_missing_stored_output_abstains(self) -> None:
        self.path(COUNTS_OUTPUT).unlink()
        result = self.claims_result()
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, FailureMode.OMITTED_POPULATION)
        buckets = result.evidence["numeric_coverage"]["buckets"]
        self.assertEqual(buckets["NOT_COMPARED"], [{"line": 6, "text": "10,801"}])
        record = self.claim_record(result, "C-003")
        self.assertEqual(record["disposition"], STORED_OUTPUT_UNAVAILABLE)
        link = self.link(record, "STORED_OUTPUT")
        observed = (link["state"], link["document_state"], link["current_sha256"])
        self.assertEqual(observed, (UNAVAILABLE, "MISSING", None))

    def test_an_unparseable_stored_output_abstains(self) -> None:
        self.write_output(SUMMARY_OUTPUT, "{not json")
        result = self.claims_result()
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, FailureMode.OMITTED_POPULATION)
        self.assertEqual(self.claim_record(result, "C-001")["disposition"], STORED_OUTPUT_UNAVAILABLE)

    def test_values_that_cannot_be_located_abstain(self) -> None:
        cases = (
            ({"selector": "/sites/site-delta/mean_value"}, "SELECTOR_NOT_FOUND", VALUE_NOT_LOCATED),
            ({"selector": "/sites"}, "NOT_A_PRINTED_NUMBER", HUMAN_REVIEW),
            ({"selector": "/note"}, None, HUMAN_REVIEW),
        )
        for fields, code, disposition in cases:
            with self.subTest(fields=fields):
                shutil.copy(VALID_PROJECT / "claims" / "registry.json", self.path("claims/registry.json"))
                self.edit_stored_output("C-001", **fields)
                result = self.claims_result()
                self.assertEqual(result.verdict, Status.ABSTAIN)
                record = self.claim_record(result, "C-001")
                self.assertEqual(record["disposition"], disposition)
                if code is not None:
                    self.assertEqual(record["value_comparison"]["locate"], code)

    def test_csv_selectors(self) -> None:
        header = "site,samples,total_count\n"
        cases = (
            (header + "site-gamma,2,10801\nsite-gamma,3,10801\n", "AMBIGUOUS_ROW", HUMAN_REVIEW),
            (header + "site-alpha,2,1241\n", "ROW_NOT_FOUND", VALUE_NOT_LOCATED),
            ("site,samples\nsite-gamma,2\n", "COLUMN_ABSENT", VALUE_NOT_LOCATED),
            (header + "site-gamma,2\n", "OUTPUT_UNPARSEABLE", VALUE_NOT_LOCATED),
            ("site,site,total_count\nsite-gamma,2,10801\n", "OUTPUT_UNPARSEABLE", VALUE_NOT_LOCATED),
            (header + "site-gamma,2,\n", "VALUE_EMPTY", VALUE_NOT_LOCATED),
        )
        for text, code, disposition in cases:
            with self.subTest(code=code, text=text):
                self.write_output(COUNTS_OUTPUT, text)
                record = self.claim_record(self.claims_result(), "C-003")
                self.assertEqual(
                    (record["disposition"], record["value_comparison"]["locate"]), (disposition, code)
                )

    def test_a_value_that_disagrees_with_its_stored_output_fails(self) -> None:
        self.write_output(COUNTS_OUTPUT, "site,samples,total_count\nsite-gamma,2,10810\n")
        result = self.claims_result()
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        record = self.claim_record(result, "C-003")
        self.assertEqual((record["disposition"], record["value_comparison"]["outcome"]), (VALUE_DISAGREES, DISAGREES))

    def test_a_json_decimal_keeps_its_printed_precision(self) -> None:
        record = self.claim_record(self.claims_result(), "C-002")
        comparison = record["value_comparison"]
        self.assertEqual(comparison["stored"]["text"], "15.3125")
        self.assertEqual((comparison["outcome"], comparison["rounded_stored"]), (AGREES_AT_STATED_PRECISION, "15.31"))


class NumericRulesTest(ClaimsProjectCase):
    """Rounding cannot create agreement and separators cannot evade comparison (section 7 numeric rules)."""

    def compare(self, claim_value: str, stored: str, precision: int | None, **params: Any) -> dict[str, Any]:
        self.write_output(COUNTS_OUTPUT, f'site,samples,total_count\nsite-gamma,2,"{stored}"\n')
        self.edit_claim("C-003", value=claim_value, precision_decimals=precision)
        self.set_claims_check(params=params)
        return self.claim_record(self.claims_result(), "C-003")["value_comparison"]

    def test_coarser_rounding_of_both_sides_never_creates_agreement(self) -> None:
        # 6.2 and 6.27 both round to 6, but the stored value rounds to 6.3 at the claim's precision.
        comparison = self.compare("6.2", "6.27", 1)
        self.assertEqual((comparison["outcome"], comparison["rounded_stored"]), (DISAGREES, "6.3"))

    def test_half_even_ties_do_not_round_up_into_agreement(self) -> None:
        self.assertEqual(self.compare("0.3", "0.25", 1)["outcome"], DISAGREES)
        self.assertEqual(self.compare("0.2", "0.25", 1)["outcome"], AGREES_AT_STATED_PRECISION)

    def test_a_declared_precision_that_contradicts_the_printed_value_requires_review(self) -> None:
        comparison = self.compare("6.3", "6.27", 2)
        self.assertEqual((comparison["outcome"], comparison["agrees"]), ("REQUIRES_HUMAN_REVIEW", None))

    def test_thousands_separators_in_a_stored_output_are_compared_only_when_declared(self) -> None:
        self.assertEqual(self.compare("10801", "10,801", 0, thousands=",")["outcome"], EXACT)
        undeclared = self.compare("10801", "10,801", 0)
        self.assertEqual((undeclared["outcome"], undeclared["agrees"]), ("REQUIRES_HUMAN_REVIEW", None))
        self.assertEqual(self.compare("10801", "10,810", 0, thousands=",")["outcome"], DISAGREES)


class DocumentAvailabilityTest(ClaimsProjectCase):
    def test_no_manuscript_is_a_blind_spot(self) -> None:
        self.update_manifest(manuscript=...)
        result = self.claims_result()
        self.assertOutcome(result, Status.ABSTAIN, Reason.BLIND_SPOT)
        self.assertEqual(result.evidence["manuscript_scan"], {"state": "NOT_DECLARED"})
        self.assertIsNone(self.claim_record(result, "C-001")["manuscript_lines"])
        self.assertEqual(result.rows_examined, 4)

    def test_a_missing_or_empty_manuscript_is_never_read_as_number_free(self) -> None:
        for state, prepare in (("MISSING", lambda path: path.unlink()), ("EMPTY", lambda path: path.write_bytes(b""))):
            with self.subTest(state=state):
                shutil.copy(VALID_PROJECT / "claims" / "manuscript.md", self.path("claims/manuscript.md"))
                prepare(self.path("claims/manuscript.md"))
                result = self.claims_result()
                self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)
                self.assertEqual(result.evidence["manuscript"]["state"], state)
                self.assertEqual(result.evidence["manuscript_scan"], {"state": "UNAVAILABLE"})

    def test_a_manuscript_that_is_not_utf8_is_protocol_broken(self) -> None:
        self.path("claims/manuscript.md").write_bytes(b"value \xff 12.4\n")
        self.assertOutcome(self.claims_result(), Status.ABSTAIN, Reason.PROTOCOL_BROKEN)

    def test_a_manuscript_without_a_registry_is_all_unregistered(self) -> None:
        self.update_manifest(claims=...)
        result = self.claims_result()
        self.assertOutcome(
            result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.EPHEMERAL_CLAIM, FailureMode.OMITTED_POPULATION
        )
        self.assertEqual(result.evidence["manuscript_scan"]["classifications"][UNREGISTERED], 5)
        self.assertIn("no claim registry", result.diagnostics[0])

    def test_neither_document_is_not_applicable(self) -> None:
        self.update_manifest(claims=..., manuscript=...)
        result = self.claims_result()
        self.assertEqual(
            (result.execution_state, result.verdict, result.reason, result.rows_examined),
            (ExecutionState.NOT_APPLICABLE, Status.ABSTAIN, Reason.OUT_OF_SCOPE, 0),
        )

    def test_an_empty_registry_and_a_number_free_manuscript_never_pass(self) -> None:
        self.save_registry(minimal_registry())
        self.write_manuscript("A synthetic note with no numbers at all.\n", repin=False)
        run = self.verify()
        result = self.claims_result(run)
        self.assertEqual((result.execution_state, result.verdict), (ExecutionState.NOT_APPLICABLE, Status.ABSTAIN))
        self.assertEqual(result.reason, Reason.INSUFFICIENT_EVIDENCE)
        self.assertEqual(run.status, Status.ABSTAIN)

    def test_an_unusable_registry_skips_the_check(self) -> None:
        cases = (
            ("missing", None, Reason.INSUFFICIENT_EVIDENCE, "MISSING"),
            ("malformed JSON", '{"schema": ', Reason.PROTOCOL_BROKEN, "PARSE_ERROR"),
            ("duplicate keys", '{"schema": "a", "schema": "b"}', Reason.PROTOCOL_BROKEN, "PARSE_ERROR"),
            ("wrong schema", json.dumps({"schema": "x", "claims": []}), Reason.PROTOCOL_BROKEN, "MALFORMED_DOCUMENT"),
            (
                "unsafe stored output",
                json.dumps(minimal_registry({"claim_id": "C-001", "stored_output": {"path": "../secret.json"}})),
                Reason.PROTOCOL_BROKEN,
                "stored_output.path is refused",
            ),
        )
        for label, text, reason, fragment in cases:
            with self.subTest(case=label):
                path = self.path("claims/registry.json")
                if text is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(text, encoding="utf-8")
                result = self.claims_result()
                self.assertEqual(
                    (result.execution_state, result.verdict, result.reason, result.rows_examined),
                    (ExecutionState.SKIPPED, Status.ABSTAIN, reason, 0),
                )
                self.assertIn(fragment, result.diagnostics[0])


class ParamsTest(ClaimsProjectCase):
    def test_unusable_params_or_inputs_are_errors_never_a_weaker_check(self) -> None:
        cases = (
            ({"params": {"thousand": ","}}, "UNKNOWN_PARAM"),
            ({"params": {"thousands": ",,"}}, "INVALID_PARAM"),
            ({"params": {"thousands": ".", "decimal_point": "."}}, "INVALID_PARAM"),
            ({"params": {"decimal_point": None}}, "INVALID_PARAM"),
            ({"inputs": ["measurements"]}, "UNEXPECTED_INPUTS"),
        )
        for fields, code in cases:
            with self.subTest(fields=fields):
                shutil.copy(VALID_PROJECT / "manifest.json", self.path("manifest.json"))
                self.set_claims_check(**fields)
                run = self.verify()
                result = self.claims_result(run)
                self.assertEqual((result.verdict, run.status), (Status.ERROR, Status.ERROR))
                self.assertIn(code, result.diagnostics[0])


# ---------------------------------------------------------------------------
# Section 17: skip labels, the falsifier generator, the comparator lookup
# ---------------------------------------------------------------------------


class SkipJustificationTest(ClaimsProjectCase):
    """Every SKIPPED or NOT_APPLICABLE claims result carries a closed-vocabulary label (17.7)."""

    def fresh(self, name: str) -> None:
        self.project = self.tmp / name
        shutil.copytree(VALID_PROJECT, self.project)

    def empty_registry(self, manuscript: str | None) -> None:
        self.save_registry(minimal_registry())
        if manuscript is None:
            self.path("claims/manuscript.md").unlink()
        else:
            self.write_file("claims/manuscript.md", manuscript)

    def test_each_way_of_not_executing_is_labelled(self) -> None:
        registry = "claims/registry.json"
        cases = (
            ("neither", lambda: self.update_manifest(claims=..., manuscript=...), "NOT_APPLICABLE", "NOT_DECLARED"),
            ("missing", lambda: self.path(registry).unlink(), "SKIPPED", "INPUT_UNAVAILABLE"),
            ("broken", lambda: self.write_file(registry, '{"schema": '), "SKIPPED", "EVIDENCE_MALFORMED"),
            (
                "malformed",
                lambda: self.write_json(registry, {"schema": "x", "claims": []}),
                "SKIPPED",
                "EVIDENCE_MALFORMED",
            ),
            ("empty", lambda: self.empty_registry("No numbers here.\n"), "NOT_APPLICABLE", "EMPTY_POPULATION"),
            ("unread", lambda: self.empty_registry(None), "NOT_APPLICABLE", "INPUT_UNAVAILABLE"),
        )
        for name, prepare, state, label in cases:
            with self.subTest(case=name):
                self.fresh(name)
                prepare()
                result = self.claims_result()
                self.assertEqual((result.execution_state.value, result.verdict), (state, Status.ABSTAIN))
                self.assertEqual(SkipJustification(result.evidence[SKIP_JUSTIFICATION_KEY]).value, label)

    def test_an_executed_check_carries_no_label(self) -> None:
        result = self.claims_result()
        self.assertEqual(result.verdict, Status.PASS)
        self.assertNotIn(SKIP_JUSTIFICATION_KEY, result.evidence)


class FalsifierTest(ClaimsProjectCase):
    """``falsify_claim_registry`` builds a known-bad twin the checker must reject (17.5)."""

    def generate(self) -> tuple[tuple[FalsifierCase, ...], CheckContext, CheckSpec]:
        manifest = load_manifest(self.path("manifest.json"))
        _, inputs = discover(manifest)
        (spec,) = [item for item in manifest.checks if item.check_id == "claims"]
        ctx = CheckContext(manifest, inputs)
        ctx.preload([spec.kind])
        return falsify_claim_registry(ctx, spec, self.claims_result()), ctx, spec

    def test_the_case_shifts_the_first_resolved_value_and_repins_only_its_output(self) -> None:
        before = self.digest(SUMMARY_OUTPUT)
        (case,), _, _ = self.generate()
        self.assertEqual(
            (case.case_id, case.expected_verdict, case.expected_reason),
            ("shift-stored-value", Status.FAIL, Reason.SOURCE_MISMATCH),
        )
        self.assertEqual(sorted(case.documents), ["claims/registry.json", SUMMARY_OUTPUT])
        changed = json.loads(case.documents[SUMMARY_OUTPUT])
        self.assertEqual(changed["sites"]["site-alpha"]["mean_value"], "6.28")
        self.assertEqual(changed["sites"]["site-beta"]["mean_value"], "15.3125")
        pins = {
            claim["claim_id"]: claim["stored_output"]["sha256"]
            for claim in json.loads(case.documents["claims/registry.json"])["claims"]
        }
        digest = sha256_bytes(case.documents[SUMMARY_OUTPUT])
        self.assertEqual({claim_id for claim_id, pin in pins.items() if pin == digest}, {"C-001", "C-002", "C-004"})
        self.assertEqual(pins["C-003"], self.digest(COUNTS_OUTPUT))
        self.assertEqual(self.digest(SUMMARY_OUTPUT), before, "a generator never writes")
        self.assertEqual(self.generate()[0], (case,), "the case is deterministic")

    def test_the_checker_rejects_the_case_on_the_value_not_the_digest(self) -> None:
        (case,), _, _ = self.generate()
        for relpath, data in case.documents.items():
            self.path(relpath).write_bytes(data)
        result = self.claims_result()
        self.assertEqual((result.verdict, result.reason), (case.expected_verdict, case.expected_reason))
        record = self.claim_record(result, "C-001")
        self.assertEqual(record["disposition"], VALUE_DISAGREES)
        self.assertEqual(self.link(record, "STORED_OUTPUT")["state"], DIGEST_MATCHES)

    def test_the_checker_rejects_the_case_in_the_engine_overlay(self) -> None:
        (case,), ctx, spec = self.generate()
        outcome = check_claim_registry(ctx.overlay(case), spec)
        self.assertEqual((outcome.verdict, outcome.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertEqual(check_claim_registry(ctx, spec).verdict, Status.PASS)

    def test_a_passing_claims_check_carries_its_rejected_twin_as_a_witness(self) -> None:
        result = self.claims_result()
        self.assertEqual((result.verdict, result.evidence["falsification"]), (Status.PASS, "WITNESSED"))
        (falsifier,) = result.evidence["falsifiers"]
        self.assertEqual(
            (falsifier["case_id"], falsifier["outcome"], falsifier["actual"]["verdict"]),
            ("shift-stored-value", "REJECTED", "FAIL"),
        )

    def test_a_csv_value_is_shifted_in_its_cell(self) -> None:
        document = self.registry()
        document["claims"] = [document["claims"][2], *document["claims"][:2], document["claims"][3]]
        self.save_registry(document)
        (case,), _, _ = self.generate()
        self.assertEqual(
            case.documents[COUNTS_OUTPUT].decode("utf-8"),
            "site,samples,total_count\nsite-alpha,2,1241\nsite-beta,2,2060\nsite-gamma,2,10802\n",
        )
        for relpath, data in case.documents.items():
            self.path(relpath).write_bytes(data)
        self.assertEqual(self.claim_record(self.claims_result(), "C-003")["disposition"], VALUE_DISAGREES)

    def test_no_resolved_claim_means_no_case(self) -> None:
        document = self.registry()
        for claim in document["claims"]:
            claim["derivation"] = None
        self.save_registry(document)
        self.assertEqual(self.generate()[0], ())


class ComparatorLookupTest(ClaimsProjectCase):
    """The check calls ``invariants.compare_decimal`` as found at call time, so the run's self-test judges it (17.6)."""

    def test_a_patched_comparator_is_the_one_the_check_uses(self) -> None:
        self.write_output(COUNTS_OUTPUT, "site,samples,total_count\nsite-gamma,2,10810\n")
        self.assertEqual(self.claim_record(self.claims_result(), "C-003")["value_comparison"]["outcome"], DISAGREES)
        real = invariants.compare_decimal

        def always_exact(claim: Any, stored: Any, **kwargs: Any) -> Any:
            return dataclasses.replace(real(claim, stored, **kwargs), outcome=EXACT)

        with mock.patch.object(invariants, "compare_decimal", always_exact):
            record = self.claim_record(self.claims_result(), "C-003")
        self.assertEqual(record["value_comparison"]["outcome"], EXACT)


if __name__ == "__main__":
    unittest.main()
