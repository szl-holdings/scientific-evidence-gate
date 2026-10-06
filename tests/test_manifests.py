"""Manifest loading and validation (section 2) and the documentation schema."""

from __future__ import annotations

import json
import os
import re
import unittest
from decimal import Decimal
from typing import Any
from unittest import mock

from _helpers import REPO_ROOT, TempDirTestCase, manifest_document

from science_gate import manifests
from science_gate._canonical import sha256_bytes, strict_loads
from science_gate.manifests import (
    CHECK_KEYS,
    CITATIONS_KEYS,
    CORPUS_KEYS,
    DEFAULT_LIMITS,
    IDENTIFIER_PATTERN,
    INPUT_FORMATS,
    INPUT_KEYS,
    MANIFEST_SCHEMA,
    REQUIRED_CHECK_KEYS,
    REQUIRED_INPUT_KEYS,
    REQUIRED_TOP_LEVEL_KEYS,
    REVIEWS_KEYS,
    TOP_LEVEL_KEYS,
    UNSAFE_KEYS,
    ManifestError,
    ManifestIssue,
    load_manifest,
    parse_manifest,
)
from science_gate.models import (
    BUILTIN_CHECK_KINDS,
    AccessClass,
    DenominatorSource,
    Permissions,
    Reason,
    Status,
)

#: The section 2 example, verbatim in structure, with synthetic names only.
CONTRACT_EXAMPLE: dict[str, Any] = {
    "schema": "science-gate-manifest/v1",
    "run_label": "demo-valid",
    "inputs": [
        {
            "id": "measurements",
            "path": "data/measurements.csv",
            "required": True,
            "format": "csv",
            "sha256": "0" * 64,
            "row_key": ["sample_id"],
            "expected_rows": 12,
            "denominator_source": "INDEPENDENT",
        }
    ],
    "accepted_snapshot": "snapshots/accepted.json",
    "checks": [
        {"id": "rows", "kind": "row_count", "version": "1", "required": True, "inputs": ["measurements"], "params": {}}
    ],
    "claims": "claims/registry.json",
    "manuscript": "claims/manuscript.md",
    "dependencies": "graph/graph.json",
    "citations": {
        "entries": "citations/entries.json",
        "log": "citations/verification-log.json",
        "frozen": "citations/frozen.json",
        "live": False,
    },
    "reviews": {"required_reviewers": ["reviewer-a", "reviewer-b"], "verdicts": "reviews/verdicts.json"},
    "time_sources": "time/events.json",
    "limits": {"max_file_bytes": 52428800, "max_files": 10000, "max_rows": 1000000},
    "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
    "summary_claim": "claims/summary.json",
}


def parse(document: Any, **kwargs: Any) -> manifests.Manifest:
    data = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
    return parse_manifest(data, manifest_path="synthetic/manifest.json", **kwargs)


class ValidManifestTests(TempDirTestCase):
    def test_contract_example_loads_with_every_field(self) -> None:
        path = self.write_manifest(CONTRACT_EXAMPLE)
        manifest = load_manifest(path)
        self.assertEqual(manifest.root, path.parent)
        self.assertEqual(manifest.sha256, sha256_bytes(path.read_bytes()))
        self.assertEqual(manifest.run_label, "demo-valid")
        (spec,) = manifest.inputs
        self.assertEqual(
            (spec.input_id, spec.path, spec.format, spec.required), ("measurements", "data/measurements.csv", "csv", True)
        )
        self.assertEqual((spec.row_key, spec.expected_rows), (("sample_id",), 12))
        self.assertIs(spec.denominator_source, DenominatorSource.INDEPENDENT)
        (check,) = manifest.checks
        self.assertEqual(
            (check.check_id, check.kind, check.version, check.inputs), ("rows", "row_count", "1", ("measurements",))
        )
        self.assertEqual(manifest.limits.max_rows, 1_000_000)
        self.assertIs(manifest.corpus.access_class, AccessClass.SYNTHETIC)
        self.assertEqual(manifest.corpus.permissions, Permissions())
        self.assertEqual(manifest.reviews.required_reviewers, ("reviewer-a", "reviewer-b"))
        self.assertFalse(manifest.citations.live)
        self.assertEqual(manifest.summary_claim, "claims/summary.json")

    def test_defaults(self) -> None:
        manifest = parse(
            {
                "schema": MANIFEST_SCHEMA,
                "inputs": [{"id": "a", "path": "a.csv", "format": "csv"}],
                "checks": [{"id": "c", "kind": "row_count", "version": "1"}],
            }
        )
        self.assertTrue(manifest.inputs[0].required)
        self.assertTrue(manifest.checks[0].required)
        self.assertIs(manifest.inputs[0].denominator_source, DenominatorSource.UNAVAILABLE)
        self.assertIsNone(manifest.inputs[0].expected_rows)
        self.assertEqual((manifest.limits.max_file_bytes, manifest.limits.max_files), (52_428_800, 10_000))
        self.assertIsNone(manifest.corpus.source_licenses, "nothing declared is not an empty declaration")
        self.assertIsNone(manifest.corpus.approved_redactions)
        # An undeclared corpus is treated as the most restrictive class.
        self.assertIs(manifest.corpus.access_class, AccessClass.CONTROLLED_LOCAL)
        self.assertIsNone(manifest.reviews)

    def test_empty_inputs_and_checks_are_valid_so_the_run_can_abstain(self) -> None:
        manifest = parse({"schema": MANIFEST_SCHEMA, "inputs": [], "checks": []})
        self.assertEqual((manifest.inputs, manifest.checks), ((), ()))

    def test_params_numbers_arrive_as_decimals(self) -> None:
        document = manifest_document()
        document["checks"][0]["params"] = {"tolerance": 0.05, "nested": {"n": 2}}
        params = parse(document).checks[0].params
        self.assertEqual(params["tolerance"], Decimal("0.05"))
        self.assertIsInstance(params["tolerance"], Decimal)

    def test_referenced_paths_cover_inputs_and_roles(self) -> None:
        pointers = [pointer for pointer, _ in parse(CONTRACT_EXAMPLE).referenced_paths()]
        self.assertEqual(pointers[0], "/inputs/0/path")
        for expected in ("/accepted_snapshot", "/citations/log", "/reviews/verdicts", "/summary_claim"):
            self.assertIn(expected, pointers)

    def test_unsafe_input_paths_are_left_for_discovery_to_refuse_visibly(self) -> None:
        document = manifest_document()
        document["inputs"][0]["path"] = "../outside.csv"
        self.assertEqual(parse(document).inputs[0].path, "../outside.csv")


class CorpusDeclarationTests(unittest.TestCase):
    def test_source_licenses_and_approved_redactions_are_kept_as_declared(self) -> None:
        corpus = {
            "access_class": "SYNTHETIC",
            "source_licenses": [{"source": "measurements", "license": "CC0-1.0"}],
            "approved_redactions": [
                {"target": "data/measurements.csv", "description": "synthetic notes column removed"}
            ],
        }
        manifest = parse(manifest_document(corpus=corpus))
        self.assertEqual([item.to_dict() for item in manifest.corpus.source_licenses], corpus["source_licenses"])
        self.assertEqual([item.to_dict() for item in manifest.corpus.approved_redactions], corpus["approved_redactions"])

    def test_an_empty_list_is_a_declaration_of_none(self) -> None:
        manifest = parse(manifest_document(corpus={"access_class": "SYNTHETIC", "source_licenses": []}))
        self.assertEqual(manifest.corpus.source_licenses, ())
        self.assertIsNone(manifest.corpus.approved_redactions)


class InvalidManifestTests(TempDirTestCase):
    def assertCodes(self, document: Any, *codes: str, **kwargs: Any) -> ManifestError:
        with self.assertRaises(ManifestError) as caught:
            parse(document, **kwargs)
        error = caught.exception
        for code in codes:
            self.assertIn(code, error.codes, str(error))
        self.assertIs(error.status, Status.ERROR)
        self.assertIs(error.reason, Reason.PROTOCOL_BROKEN)
        return error

    def test_wrong_or_missing_schema(self) -> None:
        self.assertCodes(manifest_document(schema="science-gate-manifest/v2"), "SCHEMA_MISMATCH")
        document = manifest_document()
        del document["schema"]
        self.assertCodes(document, "SCHEMA_MISMATCH")

    def test_unknown_keys_are_refused_at_every_level(self) -> None:
        self.assertCodes(manifest_document(extra=True), "UNKNOWN_KEY")
        document = manifest_document()
        document["inputs"][0]["sha265"] = "0" * 64
        error = self.assertCodes(document, "UNKNOWN_KEY")
        self.assertIn("/inputs/0/sha265", [issue.pointer for issue in error.issues])

    def test_subprocess_keys_are_refused_at_any_depth_and_any_case(self) -> None:
        document = manifest_document(command="rm -rf /")
        document["checks"][0]["params"] = {"outer": [{"Shell": True}], "ENTRYPOINT": "x"}
        error = self.assertCodes(document, "UNSAFE_SUBPROCESS_REQUEST")
        pointers = {issue.pointer for issue in error.issues if issue.code == "UNSAFE_SUBPROCESS_REQUEST"}
        self.assertEqual(pointers, {"/command", "/checks/0/params/outer/0/Shell", "/checks/0/params/ENTRYPOINT"})
        self.assertNotIn("UNKNOWN_KEY", error.codes)

    def test_every_unsafe_key_name_is_refused(self) -> None:
        for key in sorted(UNSAFE_KEYS):
            with self.subTest(key=key):
                document = manifest_document()
                document["checks"][0]["params"] = {key: "x"}
                self.assertCodes(document, "UNSAFE_SUBPROCESS_REQUEST")

    def test_duplicate_paths_are_refused(self) -> None:
        document = manifest_document()
        document["inputs"].append({"id": "again", "path": "data/./measurements.csv", "format": "csv"})
        self.assertCodes(document, "DUPLICATE_PATH")
        self.assertCodes(manifest_document(claims="data\\measurements.csv"), "DUPLICATE_PATH")

    def test_duplicate_paths_compare_case_insensitively_on_windows(self) -> None:
        document = manifest_document()
        document["inputs"].append({"id": "upper", "path": "DATA/Measurements.CSV", "format": "csv"})
        if os.name == "nt":
            self.assertCodes(document, "DUPLICATE_PATH")
        else:
            self.assertEqual(len(parse(document).inputs), 2)

    def test_malformed_json_is_a_named_error_never_a_traceback(self) -> None:
        for data in (b'{"schema": ', b"\xff\xfe", b'{"schema": "a", "schema": "b"}', b'{"x": NaN}', b"[]", b"42"):
            with self.subTest(data=data):
                error = self.assertCodes(data, "MALFORMED_JSON")
                self.assertEqual(len(error.issues), 1)

    def test_missing_and_oversized_manifest_files(self) -> None:
        with self.assertRaises(ManifestError) as caught:
            load_manifest(self.tmp / "absent.json")
        self.assertEqual(caught.exception.codes, ("MANIFEST_NOT_FOUND",))
        self.assertNotIn(str(self.tmp), str(caught.exception))
        path = self.write_manifest(manifest_document())
        with mock.patch.object(manifests, "MAX_MANIFEST_BYTES", 16):
            with self.assertRaises(ManifestError) as caught:
                load_manifest(path)
        self.assertEqual(caught.exception.codes, ("MANIFEST_TOO_LARGE",))

    def test_check_kinds_must_be_registered(self) -> None:
        document = manifest_document()
        document["checks"][0]["kind"] = "made_up_kind"
        self.assertCodes(document, "UNREGISTERED_CHECK_KIND")
        self.assertCodes(manifest_document(), "UNREGISTERED_CHECK_KIND", registered_kinds={"other"})

    def test_references_and_identifiers(self) -> None:
        document = manifest_document()
        document["checks"][0]["inputs"] = ["measurements", "ghost"]
        self.assertCodes(document, "UNKNOWN_INPUT_REFERENCE")
        document = manifest_document()
        document["inputs"].append(dict(document["inputs"][0], path="data/other.csv"))
        document["checks"].append(dict(document["checks"][0]))
        error = self.assertCodes(document, "DUPLICATE_ID")
        self.assertEqual(sum(issue.code == "DUPLICATE_ID" for issue in error.issues), 2)
        document = manifest_document()
        document["inputs"][0]["id"] = "has space"
        self.assertCodes(document, "INVALID_VALUE")

    def test_denominator_provenance_rules(self) -> None:
        cases = [
            ({"expected_rows": 3, "denominator_source": None}, "MISSING_FIELD"),
            ({"expected_rows": 3, "denominator_source": "UNAVAILABLE"}, "INVALID_VALUE"),
            ({"expected_rows": None, "denominator_source": "INDEPENDENT"}, "MISSING_FIELD"),
            ({"denominator_source": "GUESSED"}, "INVALID_VALUE"),
            ({"expected_rows": 3.0}, "INVALID_TYPE"),
            ({"expected_rows": -1}, "INVALID_VALUE"),
        ]
        for change, code in cases:
            with self.subTest(change=change):
                document = manifest_document()
                document["inputs"][0].update(change)
                self.assertCodes(document, code)

    def test_field_types_and_values(self) -> None:
        cases = [
            ({"sha256": "ABC"}, "INVALID_VALUE"),
            ({"format": "xlsx"}, "INVALID_VALUE"),
            ({"required": "yes"}, "INVALID_TYPE"),
            ({"row_key": "sample_id"}, "INVALID_TYPE"),
            ({"row_key": ["a", "a"]}, "DUPLICATE_ID"),
            ({"path": ""}, "INVALID_TYPE"),
        ]
        for change, code in cases:
            with self.subTest(change=change):
                document = manifest_document()
                document["inputs"][0].update(change)
                self.assertCodes(document, code)
        document = manifest_document()
        del document["inputs"][0]["format"]
        self.assertCodes(document, "MISSING_FIELD")
        self.assertCodes(manifest_document(inputs={}), "INVALID_TYPE")
        document = manifest_document()
        del document["checks"]
        self.assertCodes(document, "MISSING_FIELD")

    def test_unsafe_role_paths_are_refused(self) -> None:
        for path in ("../claims.json", "/abs/claims.json", "C:\\claims.json", "a/CON"):
            with self.subTest(path=path):
                self.assertCodes(manifest_document(claims=path), "UNSAFE_PATH")
        self.assertCodes(manifest_document(reviews={"required_reviewers": ["r"], "verdicts": "../v.json"}), "UNSAFE_PATH")

    def test_section_rules(self) -> None:
        self.assertCodes(manifest_document(reviews={"required_reviewers": [], "verdicts": "v.json"}), "INVALID_VALUE")
        self.assertCodes(manifest_document(reviews={"required_reviewers": ["r"]}), "MISSING_FIELD")
        self.assertCodes(manifest_document(limits={"max_rows": 0}), "INVALID_VALUE")
        self.assertCodes(manifest_document(limits={"max_bytes": 1}), "UNKNOWN_KEY")
        self.assertCodes(manifest_document(corpus={"access_class": "OPEN"}), "INVALID_VALUE")
        corpus = {"access_class": "PUBLIC", "permissions": {"training_allowed": 1}}
        self.assertCodes(manifest_document(corpus=corpus), "INVALID_TYPE")
        self.assertCodes(manifest_document(citations={"live": "true"}), "INVALID_TYPE")

    def test_declared_source_licenses_and_redactions_must_be_well_formed(self) -> None:
        def corpus(**fields: Any) -> dict[str, Any]:
            return manifest_document(corpus={"access_class": "SYNTHETIC", **fields})

        self.assertCodes(corpus(source_licenses={"measurements": "CC0-1.0"}), "INVALID_TYPE")
        self.assertCodes(corpus(source_licenses=[{"source": "measurements"}]), "MISSING_FIELD")
        self.assertCodes(corpus(source_licenses=[{"source": "measurements", "license": " "}]), "INVALID_TYPE")
        self.assertCodes(corpus(source_licenses=[{"source": "m", "license": "x", "url": "u"}]), "UNKNOWN_KEY")
        twice = [{"source": "measurements", "license": "A"}, {"source": "measurements", "license": "B"}]
        self.assertCodes(corpus(source_licenses=twice), "DUPLICATE_ID")
        self.assertCodes(corpus(approved_redactions=[{"target": "data/x.csv"}]), "MISSING_FIELD")
        self.assertCodes(corpus(approved_redactions=["column notes"]), "INVALID_TYPE")

    def test_all_problems_are_reported_together(self) -> None:
        document = manifest_document(extra=1, claims="../x.json")
        document["inputs"][0]["format"] = "xlsx"
        error = self.assertCodes(document, "UNKNOWN_KEY", "UNSAFE_PATH", "INVALID_VALUE")
        self.assertGreaterEqual(len(error.issues), 3)
        self.assertTrue(all(isinstance(issue, ManifestIssue) for issue in error.issues))

    def test_an_error_needs_at_least_one_issue(self) -> None:
        with self.assertRaises(ValueError):
            ManifestError([])


class ManifestSchemaDocumentTests(unittest.TestCase):
    """The JSON Schema is documentation; these tests keep it in step with the code."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = strict_loads((REPO_ROOT / "schemas" / "manifest.schema.json").read_bytes())
        cls.defs = cls.schema["$defs"]

    def test_draft_and_version(self) -> None:
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema["properties"]["schema"], {"const": MANIFEST_SCHEMA})

    def test_key_sets_match_the_validator(self) -> None:
        self.assertEqual(set(self.schema["properties"]), TOP_LEVEL_KEYS)
        self.assertEqual(set(self.schema["required"]), REQUIRED_TOP_LEVEL_KEYS)
        self.assertEqual(set(self.defs["input"]["properties"]), INPUT_KEYS)
        self.assertEqual(set(self.defs["input"]["required"]), REQUIRED_INPUT_KEYS)
        self.assertEqual(set(self.defs["check"]["properties"]), CHECK_KEYS)
        self.assertEqual(set(self.defs["check"]["required"]), REQUIRED_CHECK_KEYS)
        self.assertEqual(set(self.defs["citations"]["properties"]), CITATIONS_KEYS)
        self.assertEqual(set(self.defs["reviews"]["properties"]), REVIEWS_KEYS)
        self.assertEqual(set(self.defs["corpus"]["properties"]), CORPUS_KEYS)
        self.assertEqual(set(self.defs["corpus"]["properties"]["permissions"]["properties"]), set(Permissions().to_dict()))
        for name in ("input", "check", "citations", "reviews", "limits", "corpus"):
            self.assertIs(self.defs[name]["additionalProperties"], False, name)

    def test_enumerations_and_defaults_match_the_code(self) -> None:
        self.assertEqual(set(self.defs["check"]["properties"]["kind"]["enum"]), BUILTIN_CHECK_KINDS)
        self.assertEqual(tuple(self.defs["input"]["properties"]["format"]["enum"]), INPUT_FORMATS)
        self.assertEqual(
            self.defs["input"]["properties"]["denominator_source"]["anyOf"][0]["enum"],
            [source.value for source in DenominatorSource],
        )
        self.assertEqual(
            self.defs["corpus"]["properties"]["access_class"]["enum"], [member.value for member in AccessClass]
        )
        limits = self.defs["limits"]["properties"]
        self.assertEqual({name: limits[name]["default"] for name in limits}, dict(DEFAULT_LIMITS))
        self.assertEqual(self.defs["identifier"]["pattern"], "^" + IDENTIFIER_PATTERN.pattern + "$")

    def test_unsafe_key_pattern_matches_the_refused_names_in_any_case(self) -> None:
        pattern = re.compile(self.defs["unsafe_key"]["pattern"])
        for key in UNSAFE_KEYS:
            for variant in (key, key.upper(), key.capitalize()):
                self.assertTrue(pattern.search(variant), variant)
        for safe in ("commands", "runner", "rows", "description"):
            self.assertIsNone(pattern.search(safe), safe)


if __name__ == "__main__":
    unittest.main()
