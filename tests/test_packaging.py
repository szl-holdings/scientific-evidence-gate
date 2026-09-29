"""Evaluation packaging (section 13): access classes, permissions, confinement, completeness and replay.

Every project here is synthetic. It is either the ``init`` starter project
(SYNTHETIC) or the committed ``fixtures/packaging/controlled-local`` project,
whose invented sample ids all start with ``CTLSYN-`` so that any leak into a
package is easy to find. Both live in private temporary directories that are
removed after each test.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR, TempDirTestCase, try_symlink
from _project import VALID_MANIFEST, ProjectTestCase, check

from science_gate import cli, packaging
from science_gate._canonical import sha256_bytes, strict_loads
from science_gate.models import AccessClass, InputState, Permissions
from science_gate.packaging import (
    BASES_FOR,
    DISCLAIMER,
    EVALUATION_NOT_TRAINING,
    NOT_REPRODUCIBLE_FIELDS,
    PACKAGE_JSON,
    PACKAGE_SCHEMA,
    REPRODUCIBLE_FIELDS,
    Basis,
    Disposition,
    PackageFile,
    PackageResult,
    PackageState,
    PackagingError,
    build_package,
    data_inclusion,
    expected_results_from_predicate,
    permission_statement,
)
from science_gate.receipts import HMAC_KEY_FILE_ENV, run_predicate, verify_receipt
from science_gate.verifier import SUMMARY_SCHEMA, verify

CONTROLLED_FIXTURE = REPO_ROOT / "fixtures" / "packaging" / "controlled-local"
#: Every sample id in the controlled-local fixture starts with this marker.
CONTROLLED_MARKER = b"CTLSYN-"
#: Shaped like a GitHub token so the redaction patterns recognize it; entirely invented.
FAKE_TOKEN = "ghp_SyntheticPackagingFakeToken0000000000"

_real_verify = packaging.verify


def package_files(root: Path) -> dict[str, bytes]:
    """Every file under ``root`` as ``{posix relpath: bytes}``."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()
    }


def tree_digests(root: Path) -> dict[str, str]:
    """``{posix relpath: sha256}`` for every file under ``root``: a before/after picture of a tree."""
    return {relpath: sha256_bytes(data) for relpath, data in package_files(root).items()}


def reproduced(manifest: Path) -> dict[str, Any]:
    """Verify ``manifest`` afresh and reduce its receipt predicate as a recipient would."""
    run = verify(manifest)
    seal = run.ledger.seal()
    predicate = run_predicate(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"]
    )
    return expected_results_from_predicate(predicate)


class PackageTestCase(ProjectTestCase):
    """A synthetic starter project plus an output location outside it."""

    def setUp(self) -> None:
        super().setUp()
        self.out = self.tmp / "package"

    def package(self, **kwargs: Any) -> PackageResult:
        output = kwargs.pop("output", self.out)
        return build_package(self.manifest_path, output, **kwargs)

    def refused(self, code: str, **kwargs: Any) -> PackagingError:
        with self.assertRaises(PackagingError) as caught:
            self.package(**kwargs)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception

    def index(self, output: Path | None = None) -> dict[str, Any]:
        return strict_loads(((output or self.out) / PACKAGE_JSON).read_bytes())

    @staticmethod
    def entry(document: dict[str, Any], kind: str, name: str) -> dict[str, Any]:
        (found,) = [item for item in document["files"] if item["kind"] == kind and item["name"] == name]
        return found

    def assert_nothing_contains(self, output: Path, needle: bytes) -> None:
        for relpath, data in package_files(output).items():
            with self.subTest(file=relpath):
                self.assertNotIn(needle, data)


class ControlledProjectTestCase(PackageTestCase):
    """The committed CONTROLLED_LOCAL fixture, copied so tests may edit it."""

    def setUp(self) -> None:
        super().setUp()
        self.project = self.tmp / "controlled"
        shutil.copytree(CONTROLLED_FIXTURE, self.project)

    def set_corpus(self, corpus: dict[str, Any] | None) -> None:
        document = self.manifest()
        if corpus is None:
            document.pop("corpus", None)
        else:
            document["corpus"] = corpus
        self.save_manifest(document)


# ---------------------------------------------------------------------------
# Rules in isolation
# ---------------------------------------------------------------------------


class DataInclusionTests(unittest.TestCase):
    GENEROUS = Permissions(
        training_allowed=True,
        redistribution_allowed=True,
        derivatives_allowed=True,
        public_display_allowed=True,
        commercial_use_allowed=True,
    )

    def test_protected_classes_are_never_copied_whatever_the_permissions(self) -> None:
        expected = {
            AccessClass.CONTROLLED_LOCAL: Basis.ACCESS_CLASS_CONTROLLED_LOCAL,
            AccessClass.REFERENCE_ONLY: Basis.ACCESS_CLASS_REFERENCE_ONLY,
        }
        for access_class, basis in expected.items():
            for permissions in (Permissions(), self.GENEROUS):
                for declared in (False, True):
                    with self.subTest(access_class=access_class, permissions=permissions, declared=declared):
                        decision = data_inclusion(access_class, permissions, permissions_declared=declared)
                        self.assertFalse(decision.included)
                        self.assertIs(decision.basis, basis)

    def test_public_data_needs_redistribution_permission(self) -> None:
        for declared in (False, True):
            refused = data_inclusion(AccessClass.PUBLIC, Permissions(), permissions_declared=declared)
            self.assertEqual((refused.included, refused.basis), (False, Basis.REDISTRIBUTION_NOT_ALLOWED))
        allowed = data_inclusion(
            AccessClass.PUBLIC, Permissions(redistribution_allowed=True), permissions_declared=True
        )
        self.assertEqual((allowed.included, allowed.basis), (True, Basis.REDISTRIBUTION_ALLOWED))

    def test_synthetic_defaults_are_shared_but_declared_permissions_are_taken_at_their_word(self) -> None:
        default = data_inclusion(AccessClass.SYNTHETIC, Permissions(), permissions_declared=False)
        self.assertEqual((default.included, default.basis), (True, Basis.SYNTHETIC_DEFAULT_PERMISSIONS))
        # The same values written explicitly are a decision, not a default.
        declared = data_inclusion(AccessClass.SYNTHETIC, Permissions(), permissions_declared=True)
        self.assertEqual((declared.included, declared.basis), (False, Basis.REDISTRIBUTION_NOT_ALLOWED))
        allowed = data_inclusion(
            AccessClass.SYNTHETIC, Permissions(redistribution_allowed=True), permissions_declared=True
        )
        self.assertEqual((allowed.included, allowed.basis), (True, Basis.REDISTRIBUTION_ALLOWED))

    def test_access_class_strings_are_accepted_and_unknown_ones_refused(self) -> None:
        self.assertFalse(data_inclusion("CONTROLLED_LOCAL", self.GENEROUS, permissions_declared=True).included)
        with self.assertRaises(ValueError):
            data_inclusion("SECRET", Permissions(), permissions_declared=False)


class PermissionStatementTests(unittest.TestCase):
    def test_evaluation_permission_never_implies_training_permission(self) -> None:
        cases = {
            "default": (Permissions(), False, "training_allowed is false (the default)"),
            "declared": (Permissions(), True, "training_allowed is false (declared)"),
            "granted": (Permissions(training_allowed=True), True, "separate from evaluation_allowed"),
        }
        for label, (permissions, declared, phrase) in cases.items():
            with self.subTest(case=label):
                statement = permission_statement(permissions, training_declared=declared)
                self.assertTrue(statement.startswith(EVALUATION_NOT_TRAINING), statement)
                self.assertIn(phrase, statement)


class ExpectedResultsProjectionTests(unittest.TestCase):
    PREDICATE: dict[str, Any] = {
        "run_id": "run-synthetic",
        "status": "ABSTAIN",
        "reason": "INSUFFICIENT_EVIDENCE",
        "reasons": ["INSUFFICIENT_EVIDENCE"],
        "failure_modes": ["VACUOUS_PASS"],
        "started_at": FIXED_TIME,
        "completed_at": FIXED_TIME,
        "counters": {"rows_examined": None},
        "input_accounting": {"closure": {}},
        "inputs": [{"id": "measurements", "sha256": None, "state": "EMPTY"}],
        "checks": [{"check_id": "rows", "invocation_id": "inv-000000000000", "evidence_sha256": "0" * 64}],
        "invariants": [{"name": "ledger_chain_intact", "applicable": True, "holds": True}],
        "ledger_head_sha256": "1" * 64,
        "ledger_length": 2,
        "evidence_manifest_sha256": "2" * 64,
        "tool": {"name": "scientific-evidence-gate", "version": "0"},
    }

    def test_run_bound_fields_are_dropped_and_the_exit_code_added(self) -> None:
        results = expected_results_from_predicate(self.PREDICATE)
        self.assertEqual(set(results), {*REPRODUCIBLE_FIELDS, "exit_code"})
        self.assertEqual(results["exit_code"], 2)
        self.assertEqual(results["checks"], [{"check_id": "rows", "evidence_sha256": "0" * 64}])
        self.assertEqual(results["counters"], {"rows_examined": None})
        for field in ("run_id", "started_at", "completed_at", "ledger_head_sha256", "evidence_manifest_sha256"):
            self.assertIn(field, NOT_REPRODUCIBLE_FIELDS)
            self.assertNotIn(field, results)

    def test_a_predicate_missing_a_reproducible_field_is_an_error_not_a_blank(self) -> None:
        predicate = dict(self.PREDICATE)
        del predicate["counters"]
        with self.assertRaises(KeyError):
            expected_results_from_predicate(predicate)


class PackageFileTests(unittest.TestCase):
    def make(self, **overrides: Any) -> PackageFile:
        values: dict[str, Any] = {
            "kind": "input",
            "name": "measurements",
            "path": "data/measurements.csv",
            "package_path": "evaluation/data/measurements.csv",
            "state": "PARSED",
            "sha256": "a" * 64,
            "size_bytes": 10,
            "required": True,
            "declared_sha256": None,
            "disposition": Disposition.WITHHELD,
            "basis": Basis.ACCESS_CLASS_CONTROLLED_LOCAL,
        }
        values.update(overrides)
        return PackageFile(**values)

    def test_inconsistent_entries_cannot_be_constructed(self) -> None:
        bad = {
            "included without permission": {"disposition": Disposition.INCLUDED, "basis": Basis.NO_RECORDED_DIGEST},
            "withheld without digest": {"sha256": None},
            "withheld without a place": {"package_path": None},
            "unknown kind": {"kind": "log"},
        }
        for label, overrides in bad.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                self.make(**overrides)

    def test_retrieval_names_the_place_and_the_digest(self) -> None:
        text = self.make().retrieval()
        self.assertIn("CONTROLLED_LOCAL", text)
        self.assertIn("evaluation/data/measurements.csv", text)
        self.assertIn("a" * 64, text)
        self.assertIsNone(self.make(disposition=Disposition.INCLUDED, basis=Basis.REDISTRIBUTION_ALLOWED).retrieval())

    def test_an_unplaceable_file_says_so_instead_of_inventing_a_place(self) -> None:
        item = self.make(
            kind="document",
            path="../elsewhere.json",
            package_path=None,
            state="REFUSED",
            sha256=None,
            size_bytes=None,
            required=None,
            disposition=Disposition.UNAVAILABLE,
            basis=Basis.NO_RECORDED_DIGEST,
        )
        self.assertIn("not a safe relative path", item.retrieval())
        self.assertIsNone(item.to_dict()["package_path"])


# ---------------------------------------------------------------------------
# A shareable (SYNTHETIC) evaluation
# ---------------------------------------------------------------------------


class SyntheticPackageTests(PackageTestCase):
    def test_a_complete_package_exits_0_and_reports_every_path_it_wrote(self) -> None:
        result = self.package()
        self.assertIs(result.state, PackageState.COMPLETE)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.headline.startswith("OK package: wrote a complete evaluation package to "))
        self.assertIn("expected verify result PASS (VERIFIED), exit 0", result.headline)
        written = [path.relative_to(self.out).as_posix() for path in result.paths]
        self.assertEqual(sorted(written), sorted(package_files(self.out)))
        self.assertEqual(written[-1], PACKAGE_JSON, "the index is written last")
        self.assertEqual(result.document, self.index())

    def test_manifest_data_and_documents_are_copied_byte_for_byte(self) -> None:
        self.package()
        document = self.index()
        for kind, name, relpath in (
            ("manifest", "manifest", "manifest.json"),
            ("input", "measurements", "data/measurements.csv"),
            ("document", "accepted_snapshot", "snapshots/accepted.json"),
        ):
            with self.subTest(file=relpath):
                original = (self.project / relpath).read_bytes()
                self.assertEqual((self.out / "evaluation" / relpath).read_bytes(), original)
                item = self.entry(document, kind, name)
                self.assertEqual(item["disposition"], "INCLUDED")
                self.assertEqual(item["basis"], "SYNTHETIC_DEFAULT_PERMISSIONS")
                self.assertEqual((item["sha256"], item["bytes"]), (sha256_bytes(original), len(original)))
                self.assertEqual(item["package_path"], f"evaluation/{relpath}")
                self.assertIsNone(item["retrieval"])

    def test_contents_lists_every_file_but_the_index_with_its_digest(self) -> None:
        self.package()
        document = self.index()
        on_disk = package_files(self.out)
        del on_disk[PACKAGE_JSON]
        listed = {item["path"]: (item["sha256"], item["bytes"]) for item in document["contents"]}
        self.assertEqual(listed, {path: (sha256_bytes(data), len(data)) for path, data in on_disk.items()})
        self.assertEqual([item["path"] for item in document["contents"]], sorted(listed))

    def test_the_schemas_are_included(self) -> None:
        self.package()
        document = self.index()
        self.assertEqual(document["schemas"]["state"], "INCLUDED")
        self.assertIsNone(document["schemas"]["problem"])
        for name in ("manifest.schema.json", "package.schema.json"):
            with self.subTest(schema=name):
                source = (REPO_ROOT / "schemas" / name).read_bytes()
                self.assertEqual((self.out / "schemas" / name).read_bytes(), source)
                self.assertIn(
                    {"path": f"schemas/{name}", "sha256": sha256_bytes(source), "bytes": len(source)},
                    document["schemas"]["files"],
                )

    def test_expected_results_are_the_reproducible_part_of_an_intact_receipt(self) -> None:
        self.package()
        document = self.index()
        receipt_path = self.out / "expected" / "receipt.json"
        self.assertTrue(verify_receipt(receipt_path).ok)
        receipt = strict_loads(receipt_path.read_bytes())
        expected = document["expected_results"]
        self.assertEqual(expected["reproducible"], expected_results_from_predicate(receipt["body"]["predicate"]))
        self.assertEqual(expected["recorded_run"]["receipt"]["content_sha256"], receipt["content_sha256"])
        self.assertEqual(expected["recorded_run"]["run_id"], receipt["body"]["predicate"]["run_id"])
        self.assertEqual((expected["reproducible"]["status"], expected["reproducible"]["exit_code"]), ("PASS", 0))
        self.assertEqual(expected["network"]["network_used"], False)

    def test_the_index_and_receipt_never_quote_input_content(self) -> None:
        self.package()
        for relpath in (PACKAGE_JSON, "expected/receipt.json"):
            with self.subTest(file=relpath):
                data = (self.out / relpath).read_bytes()
                self.assertNotIn(b"SYN-0001", data)
                self.assertNotIn(b"site-alpha", data)

    def test_the_packaged_evaluation_reproduces_the_expected_results_on_another_day(self) -> None:
        self.package()
        expected = self.index()["expected_results"]["reproducible"]
        with mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": "2031-07-08T09:10:11Z"}):
            self.assertEqual(reproduced(self.out / "evaluation" / "manifest.json"), expected)

    def test_local_execution_is_an_argument_list_with_its_expected_exit_code(self) -> None:
        self.package()
        local = self.index()["local_execution"]
        command = ["science-gate", "verify", "evaluation/manifest.json", "--output", "local-run"]
        self.assertEqual(local["command"], command)
        self.assertEqual(local["expected_exit_code"], 0)
        self.assertEqual(local["requires"]["network"], "none")
        self.assertIn("No file is withheld; nothing needs to be retrieved.", local["steps"])

    def test_permission_defaults_and_their_sources_are_recorded(self) -> None:
        self.package()
        document = self.index()
        corpus = document["corpus"]
        self.assertEqual(corpus["access_class"], "SYNTHETIC")
        self.assertEqual(corpus["access_class_source"], "DECLARED")
        self.assertEqual(corpus["permissions"], Permissions().to_dict())
        self.assertEqual(set(corpus["permission_sources"].values()), {"DEFAULT"})
        self.assertEqual(corpus["data_inclusion"]["basis"], "SYNTHETIC_DEFAULT_PERMISSIONS")
        self.assertTrue(document["permission_statement"].startswith(EVALUATION_NOT_TRAINING))
        self.assertIn("(the default)", document["permission_statement"])

    def test_licenses_and_redactions_are_not_invented(self) -> None:
        self.package()
        document = self.index()
        licenses = document["source_licenses"]
        self.assertEqual(
            (licenses["state"], licenses["declared"], licenses["assertion"]), ("NOT_DECLARED", None, "NOASSERTION")
        )
        redactions = document["approved_redactions"]
        self.assertEqual((redactions["state"], redactions["declared"]), ("NOT_DECLARED", None))

    def test_scientific_validity_is_never_established(self) -> None:
        self.package()
        document = self.index()
        self.assertEqual(document["evidence_boundary"]["scientific_validity"], "NOT ESTABLISHED")
        self.assertEqual(document["disclaimer"], DISCLAIMER)
        self.assertEqual(document["schema"], PACKAGE_SCHEMA)


# ---------------------------------------------------------------------------
# Protected and non-redistributable corpora
# ---------------------------------------------------------------------------


class ProtectedCorpusTests(ControlledProjectTestCase):
    def assert_withheld(self, document: dict[str, Any], basis: str) -> None:
        self.assertFalse(document["corpus"]["data_inclusion"]["included"])
        self.assertEqual(len(document["files"]), 3)
        for item in document["files"]:
            with self.subTest(file=item["path"]):
                original = (self.project / item["path"]).read_bytes()
                self.assertEqual(item["disposition"], "WITHHELD")
                self.assertEqual(item["basis"], basis)
                self.assertEqual(item["sha256"], sha256_bytes(original))
                self.assertEqual(item["bytes"], len(original))
                self.assertIn(item["package_path"], item["retrieval"])
                self.assertIn(item["sha256"], item["retrieval"])
        self.assertFalse((self.out / "evaluation").exists())
        self.assert_nothing_contains(self.out, CONTROLLED_MARKER)

    def test_the_fixture_is_a_passing_evaluation(self) -> None:
        self.assertEqual(verify(self.manifest_path).status.value, "PASS")

    def test_controlled_local_inputs_are_never_copied(self) -> None:
        # Requirement 25: only digests and retrieval instructions leave the machine.
        result = self.package()
        self.assertEqual(result.exit_code, 0)
        document = self.index()
        self.assertEqual(document["package_state"], "COMPLETE")
        self.assert_withheld(document, "ACCESS_CLASS_CONTROLLED_LOCAL")
        data = (self.project / "data" / "measurements.csv").read_bytes()
        self.assert_nothing_contains(self.out, data)
        self.assertEqual(document["expected_results"]["reproducible"]["status"], "PASS")
        self.assertIn("0 of 3 evaluation file(s) included, 3 withheld", result.headline)

    def test_controlled_local_is_withheld_even_when_redistribution_is_allowed(self) -> None:
        self.set_corpus({"access_class": "CONTROLLED_LOCAL", "permissions": {"redistribution_allowed": True}})
        self.package()
        self.assert_withheld(self.index(), "ACCESS_CLASS_CONTROLLED_LOCAL")

    def test_reference_only_is_never_copied(self) -> None:
        self.set_corpus({"access_class": "REFERENCE_ONLY", "permissions": {"redistribution_allowed": True}})
        self.package()
        self.assert_withheld(self.index(), "ACCESS_CLASS_REFERENCE_ONLY")

    def test_an_undeclared_corpus_is_treated_as_controlled_local(self) -> None:
        self.set_corpus(None)
        self.package()
        document = self.index()
        self.assertEqual(document["corpus"]["access_class"], "CONTROLLED_LOCAL")
        self.assertEqual(document["corpus"]["access_class_source"], "DEFAULT")
        self.assertIn("declares no corpus", document["corpus"]["data_inclusion"]["statement"])
        self.assert_withheld(document, "ACCESS_CLASS_CONTROLLED_LOCAL")

    def test_public_data_is_copied_only_with_redistribution_permission(self) -> None:
        self.set_corpus({"access_class": "PUBLIC"})
        self.package()
        self.assert_withheld(self.index(), "REDISTRIBUTION_NOT_ALLOWED")
        self.set_corpus({"access_class": "PUBLIC", "permissions": {"redistribution_allowed": True}})
        allowed = self.tmp / "public-allowed"
        self.package(output=allowed)
        document = self.index(allowed)
        self.assertEqual({item["disposition"] for item in document["files"]}, {"INCLUDED"})
        self.assertEqual(document["corpus"]["data_inclusion"]["basis"], "REDISTRIBUTION_ALLOWED")

    def test_synthetic_data_with_declared_permissions_follows_them(self) -> None:
        self.set_corpus({"access_class": "SYNTHETIC", "permissions": {"redistribution_allowed": False}})
        self.package()
        document = self.index()
        self.assert_withheld(document, "REDISTRIBUTION_NOT_ALLOWED")
        self.assertEqual(document["corpus"]["permission_sources"]["redistribution_allowed"], "DECLARED")

    def test_training_permission_is_reported_separately_from_evaluation(self) -> None:
        self.package()
        statement = self.index()["permission_statement"]
        self.assertTrue(statement.startswith(EVALUATION_NOT_TRAINING))
        self.assertIn("training_allowed is false (declared)", statement)

    def test_withheld_files_placed_as_instructed_reproduce_the_expected_results(self) -> None:
        self.package()
        document = self.index()
        for item in document["files"]:
            destination = self.out / item["package_path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.project / item["path"], destination)
            self.assertEqual(sha256_bytes(destination.read_bytes()), item["sha256"])
        manifest = self.out / document["local_execution"]["command"][2]
        self.assertEqual(reproduced(manifest), document["expected_results"]["reproducible"])

    def test_repackaging_with_force_after_reclassification_removes_copied_data(self) -> None:
        self.set_corpus({"access_class": "SYNTHETIC"})
        self.package()
        self.assertTrue((self.out / "evaluation" / "data" / "measurements.csv").is_file())
        self.set_corpus({"access_class": "CONTROLLED_LOCAL"})
        result = self.package(force=True)
        self.assertTrue(result.replaced)
        self.assertIn("replaced a previous package", result.headline)
        self.assert_withheld(self.index(), "ACCESS_CLASS_CONTROLLED_LOCAL")


# ---------------------------------------------------------------------------
# Completeness: nothing the evaluation needs is dropped silently
# ---------------------------------------------------------------------------


class CompletenessTests(PackageTestCase):
    def test_a_missing_required_input_makes_the_package_incomplete(self) -> None:
        (self.project / "data" / "measurements.csv").unlink()
        result = self.package()
        self.assertIs(result.state, PackageState.INCOMPLETE)
        self.assertEqual(result.exit_code, 2)
        self.assertTrue(result.headline.startswith("ABSTAIN package: wrote an INCOMPLETE evaluation package to "))
        document = self.index()
        item = self.entry(document, "input", "measurements")
        self.assertEqual(
            (item["disposition"], item["basis"], item["sha256"]), ("UNAVAILABLE", "NO_RECORDED_DIGEST", None)
        )
        self.assertIn("state MISSING", item["retrieval"])
        self.assertIn("input measurements: MISSING, no digest recorded", document["incomplete_because"])
        self.assertEqual(document["expected_results"]["reproducible"]["status"], "ABSTAIN")
        self.assertIn("INCOMPLETE", " ".join(document["local_execution"]["steps"]))

    def test_an_absent_optional_input_is_listed_but_does_not_block_completeness(self) -> None:
        document = self.manifest()
        document["inputs"].append({"id": "protocol", "path": "data/protocol.csv", "format": "csv", "required": False})
        self.save_manifest(document)
        result = self.package()
        self.assertIs(result.state, PackageState.COMPLETE)
        item = self.entry(self.index(), "input", "protocol")
        self.assertEqual((item["disposition"], item["state"], item["required"]), ("UNAVAILABLE", "MISSING", False))
        self.assertIn("Leave evaluation/data/protocol.csv absent", item["retrieval"])

    def test_a_file_that_fails_its_declared_digest_is_neither_copied_nor_complete(self) -> None:
        declared = self.manifest()["inputs"][0]["sha256"]
        self.write_data("".join(self.data_lines()[:-1]), declare_digest=False)
        result = self.package()
        self.assertEqual(result.exit_code, 2)
        document = self.index()
        item = self.entry(document, "input", "measurements")
        self.assertEqual(
            (item["disposition"], item["basis"], item["state"]),
            ("UNAVAILABLE", "DECLARED_DIGEST_MISMATCH", "HASH_MISMATCH"),
        )
        self.assertEqual(item["declared_sha256"], declared)
        self.assertIn(declared, item["retrieval"])
        self.assertFalse((self.out / "evaluation" / "data" / "measurements.csv").exists())
        reason = "input measurements: the file on disk does not match its declared sha256"
        self.assertIn(reason, document["incomplete_because"])

    def test_a_path_shared_with_a_mismatching_input_is_never_shipped(self) -> None:
        # A summary that pins the input file as a document makes a check read the same bytes twice.
        pins = {"documents": {"data/measurements.csv": "0" * 64}}
        self.write_json("claims/summary.json", {"schema": SUMMARY_SCHEMA, "status": "PASS", "pinned": pins})
        self.update_manifest(summary_claim="claims/summary.json")
        self.add_checks(check("summary", "summary_consistency", inputs=()))
        self.write_data("".join(self.data_lines()[:-1]), declare_digest=False)
        self.package()
        shared = {item["kind"]: item for item in self.index()["files"] if item["path"] == "data/measurements.csv"}
        self.assertEqual(set(shared), {"input", "document"})
        self.assertEqual(
            (shared["input"]["disposition"], shared["input"]["basis"]), ("UNAVAILABLE", "DECLARED_DIGEST_MISMATCH")
        )
        self.assertEqual(
            (shared["document"]["disposition"], shared["document"]["basis"]), ("WITHHELD", "DECLARED_DIGEST_MISMATCH")
        )
        self.assertFalse((self.out / "evaluation" / "data" / "measurements.csv").exists())

    def test_a_missing_role_document_makes_the_package_incomplete(self) -> None:
        (self.project / "snapshots" / "accepted.json").unlink()
        result = self.package()
        self.assertEqual(result.exit_code, 2)
        item = self.entry(self.index(), "document", "accepted_snapshot")
        self.assertEqual((item["disposition"], item["state"]), ("UNAVAILABLE", "MISSING"))

    def test_missing_schemas_make_the_package_incomplete(self) -> None:
        partial = self.tmp / "partial-schemas"
        partial.mkdir()
        shutil.copyfile(REPO_ROOT / "schemas" / "manifest.schema.json", partial / "manifest.schema.json")
        cases = {
            self.tmp / "no-schemas": "the schema directory could not be read",
            partial: "missing package.schema.json",
            None: "no schema directory is configured",
        }
        for index, (directory, problem) in enumerate(cases.items()):
            with self.subTest(problem=problem):
                output = self.tmp / f"package-{index}"
                result = self.package(output=output, schemas_dir=directory)
                self.assertEqual(result.exit_code, 2)
                document = self.index(output)
                schemas = document["schemas"]
                self.assertEqual((schemas["state"], schemas["problem"]), ("INCOMPLETE", problem))
                self.assertIn(f"schemas: {problem}", document["incomplete_because"])


class SecretScreeningTests(PackageTestCase):
    def test_a_secret_in_the_manifest_is_redacted_from_the_index_and_the_manifest_withheld(self) -> None:
        self.update_manifest(run_label=f"synthetic {FAKE_TOKEN}")
        result = self.package()
        self.assertIs(result.state, PackageState.COMPLETE)
        document = self.index()
        self.assertEqual(document["run_label"], "synthetic [REDACTED]")
        item = self.entry(document, "manifest", "manifest")
        self.assertEqual((item["disposition"], item["basis"]), ("WITHHELD", "SECRET_PATTERN_IN_CONTENT"))
        self.assertFalse((self.out / "evaluation" / "manifest.json").exists())
        self.assert_nothing_contains(self.out, FAKE_TOKEN.encode())

    def test_content_matching_a_secret_pattern_is_withheld_whole(self) -> None:
        env_secret = "synthetic-environment-secret-0042"
        self.write_file("data/notes.json", json.dumps({"note": FAKE_TOKEN}))
        self.write_file("data/env-notes.json", json.dumps({"note": env_secret}))
        document = self.manifest()
        for input_id in ("notes", "env-notes"):
            document["inputs"].append(
                {"id": input_id, "path": f"data/{input_id}.json", "format": "json", "required": False}
            )
        self.save_manifest(document)
        with mock.patch.dict(os.environ, {"SCIENCE_GATE_SYNTHETIC_API_TOKEN": env_secret}):
            result = self.package()
        self.assertIs(result.state, PackageState.COMPLETE)
        index = self.index()
        for name in ("notes", "env-notes"):
            with self.subTest(input=name):
                item = self.entry(index, "input", name)
                self.assertEqual((item["disposition"], item["basis"]), ("WITHHELD", "SECRET_PATTERN_IN_CONTENT"))
                self.assertIn(item["sha256"], item["retrieval"])
        self.assertEqual(self.entry(index, "input", "measurements")["disposition"], "INCLUDED")
        self.assert_nothing_contains(self.out, FAKE_TOKEN.encode())
        self.assert_nothing_contains(self.out, env_secret.encode())


# ---------------------------------------------------------------------------
# Output confinement and replacement
# ---------------------------------------------------------------------------


class OutputConfinementTests(PackageTestCase):
    def test_output_inside_an_input_directory_is_refused(self) -> None:
        for output in (self.project / "data" / "package", self.project / "package", self.project):
            with self.subTest(output=output.relative_to(self.tmp).as_posix()):
                before = tree_digests(self.tmp)
                self.refused("OUTPUT_INSIDE_INPUT_DIRECTORY", output=output)
                self.assertEqual(tree_digests(self.tmp), before)
        self.assertFalse((self.project / "data" / "package").exists())

    def test_output_containing_the_inputs_is_refused(self) -> None:
        before = tree_digests(self.tmp)
        self.refused("OUTPUT_CONTAINS_INPUTS", output=self.tmp, force=True)
        self.assertEqual(tree_digests(self.tmp), before)

    def test_every_write_stays_inside_the_output_directory(self) -> None:
        before = tree_digests(self.tmp)
        self.package()
        after = tree_digests(self.tmp)
        changed = {path for path in set(before) | set(after) if before.get(path) != after.get(path)}
        self.assertTrue(changed)
        self.assertTrue(all(path.startswith("package/") for path in changed), sorted(changed))

    def test_existing_output_is_refused_without_force(self) -> None:
        notes = self.write("package/notes.txt", "keep me")
        self.refused("OUTPUT_EXISTS")
        self.assertEqual(package_files(self.out), {"notes.txt": b"keep me"})
        self.assertEqual(notes.read_text(encoding="utf-8"), "keep me")

    def test_an_existing_empty_directory_is_not_existing_output(self) -> None:
        self.out.mkdir()
        self.assertEqual(self.package().exit_code, 0)

    def test_an_output_that_is_a_file_is_refused(self) -> None:
        self.write("package", "a file where the package should go")
        self.refused("OUTPUT_NOT_A_DIRECTORY", force=True)

    def test_force_replaces_a_previous_package(self) -> None:
        self.package()
        first = package_files(self.out)
        result = self.package(force=True)
        self.assertTrue(result.replaced)
        self.assertEqual(package_files(self.out), first, "a pinned clock makes the replacement identical")

    def test_force_never_deletes_a_file_the_package_did_not_list(self) -> None:
        self.package()
        self.write("package/evaluation/data/notes.txt", "added by hand")
        before = package_files(self.out)
        error = self.refused("OUTPUT_NOT_A_PACKAGE", force=True)
        self.assertIn("evaluation/data/notes.txt", str(error))
        self.assertEqual(package_files(self.out), before)

    def test_force_refuses_a_directory_that_is_not_a_package(self) -> None:
        cases = {
            "no index": {"notes.txt": "keep me"},
            "not an index": {PACKAGE_JSON: json.dumps({"schema": "something-else/v1", "contents": []})},
            "malformed index": {PACKAGE_JSON: "{not json"},
        }
        for index, (label, files) in enumerate(cases.items()):
            with self.subTest(case=label):
                output = self.tmp / f"occupied-{index}"
                for relpath, text in files.items():
                    self.write(f"occupied-{index}/{relpath}", text)
                before = package_files(output)
                self.refused("OUTPUT_NOT_A_PACKAGE", output=output, force=True)
                self.assertEqual(package_files(output), before)

    def test_force_refuses_a_previous_package_holding_a_link(self) -> None:
        self.package()
        outside = self.write("outside.txt", "not part of any package")
        try_symlink(self, outside, self.out / "link.txt")
        self.refused("OUTPUT_NOT_A_PACKAGE", force=True)
        self.assertEqual(outside.read_text(encoding="utf-8"), "not part of any package")

    def test_a_file_changing_during_packaging_leaves_nothing_behind(self) -> None:
        snapshot = self.project / "snapshots" / "accepted.json"

        def verify_then_edit(*args: Any, **kwargs: Any) -> Any:
            run = _real_verify(*args, **kwargs)
            snapshot.write_bytes(snapshot.read_bytes() + b"\n")
            return run

        output = self.tmp / "nested" / "deeper" / "package"
        with mock.patch.object(packaging, "verify", side_effect=verify_then_edit):
            error = self.refused("INPUT_CHANGED_DURING_PACKAGING", output=output)
        self.assertIn("snapshots/accepted.json", str(error))
        # The manifest and data were already copied when the edit was found; all of it is gone.
        self.assertFalse((self.tmp / "nested").exists())


# ---------------------------------------------------------------------------
# Refusals before anything is written
# ---------------------------------------------------------------------------


class RefusalTests(PackageTestCase):
    def test_an_invalid_manifest_is_refused(self) -> None:
        self.manifest_path.write_text("{not json", encoding="utf-8")
        error = self.refused("INVALID_MANIFEST")
        self.assertIn("MALFORMED_JSON", str(error))
        self.assertFalse(self.out.exists())

    def test_a_declared_path_outside_the_manifest_directory_is_refused(self) -> None:
        self.write("outside.csv", "sample_id\nSYN-9999\n")
        document = self.manifest()
        document["inputs"].append({"id": "outside", "path": "../outside.csv", "format": "csv"})
        self.save_manifest(document)
        error = self.refused("UNSAFE_DECLARED_PATH")
        self.assertIn("/inputs/1/path", str(error))
        self.assertFalse(self.out.exists())

    def test_a_corpus_that_forbids_evaluation_is_refused(self) -> None:
        self.update_manifest(corpus={"access_class": "SYNTHETIC", "permissions": {"evaluation_allowed": False}})
        self.refused("EVALUATION_NOT_ALLOWED")
        self.assertFalse(self.out.exists())

    def test_packaging_never_uses_the_network(self) -> None:
        self.update_manifest(citations={"live": True})
        policies = []

        def capture(*args: Any, **kwargs: Any) -> Any:
            policies.append(kwargs["network"])
            return _real_verify(*args, **kwargs)

        with (
            mock.patch.object(packaging, "verify", side_effect=capture),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("network used")),
        ):
            self.package()
        (policy,) = policies
        with self.assertRaises(urllib.error.URLError):
            policy.opener("https://doi.example.invalid/10.5555/synthetic")
        network = self.index()["expected_results"]["network"]
        self.assertEqual((network["live_requested"], network["network_used"]), (True, False))
        self.assertIn("refused", network["statement"])


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


class CommandLineTests(TempDirTestCase):
    def run_cli(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        """Run ``python -m science_gate.cli`` with a pinned clock and no signing key."""
        hidden = (HMAC_KEY_FILE_ENV, "PYTHONHASHSEED")
        environment = {key: value for key, value in os.environ.items() if key not in hidden}
        environment.update(
            {"PYTHONPATH": str(SRC_DIR), "PYTHONDONTWRITEBYTECODE": "1", "SCIENCE_GATE_FIXED_TIME": FIXED_TIME, **env}
        )
        return subprocess.run(
            [sys.executable, "-m", "science_gate.cli", *args],
            cwd=self.tmp,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_package_prints_a_headline_then_the_paths_and_exits_0(self) -> None:
        completed = self.run_cli("package", str(VALID_MANIFEST), "--output", "package")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        headline, *paths = completed.stdout.splitlines()
        self.assertTrue(headline.startswith("OK package: wrote a complete evaluation package to "), headline)
        self.assertTrue(paths and all(Path(path).is_file() for path in paths), paths)
        self.assertEqual(Path(paths[-1]).name, PACKAGE_JSON)

    def test_refusals_exit_3_with_their_code(self) -> None:
        self.write("package/notes.txt", "keep me")
        completed = self.run_cli("package", str(VALID_MANIFEST), "--output", "package")
        self.assertEqual(completed.returncode, 3)
        self.assertTrue(completed.stdout.startswith("ERROR package: OUTPUT_EXISTS: "), completed.stdout)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertNotIn("Traceback", completed.stderr)

    def test_packages_are_byte_identical_under_different_hash_seeds(self) -> None:
        outputs = {}
        for seed in ("0", "4242"):
            completed = self.run_cli(
                "package", str(CONTROLLED_FIXTURE / "manifest.json"), "--output", f"package-{seed}", PYTHONHASHSEED=seed
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            outputs[seed] = package_files(self.tmp / f"package-{seed}")
        self.assertEqual(sorted(outputs["0"]), sorted(outputs["4242"]))
        for relpath in outputs["0"]:
            with self.subTest(file=relpath):
                self.assertEqual(outputs["0"][relpath], outputs["4242"][relpath])

    def test_the_cli_dispatches_to_this_module(self) -> None:
        # A copy, so that even a regression could never write into the committed fixture.
        project = self.tmp / "controlled"
        shutil.copytree(CONTROLLED_FIXTURE, project)
        stdout = io.StringIO()
        inside = project / "data" / "package"
        with contextlib.redirect_stdout(stdout):
            code = cli.main(["package", str(project / "manifest.json"), "--output", str(inside)])
        self.assertEqual(code, 3)
        self.assertTrue(stdout.getvalue().startswith("ERROR package: OUTPUT_INSIDE_INPUT_DIRECTORY: "))
        self.assertFalse(inside.exists())


# ---------------------------------------------------------------------------
# The documentation schema agrees with the code
# ---------------------------------------------------------------------------


class PackageSchemaTests(PackageTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.schema = strict_loads((REPO_ROOT / "schemas" / "package.schema.json").read_bytes())
        cls.defs = cls.schema["$defs"]

    def test_identity(self) -> None:
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema["$id"], PACKAGE_SCHEMA)
        self.assertEqual(self.schema["properties"]["schema"], {"const": PACKAGE_SCHEMA})

    def test_documented_keys_are_exactly_the_keys_written(self) -> None:
        self.package()
        document = self.index()
        self.assertEqual(set(self.schema["required"]), set(document))
        self.assertEqual(set(self.schema["properties"]), set(document))
        file_schema = self.defs["evaluation_file"]
        for item in document["files"]:
            self.assertEqual(set(file_schema["required"]), set(item))
        properties = self.schema["properties"]
        for key in ("corpus", "schemas", "expected_results", "local_execution", "evidence_boundary"):
            with self.subTest(section=key):
                self.assertEqual(set(properties[key]["required"]), set(document[key]))
        reproducible = properties["expected_results"]["properties"]["reproducible"]
        self.assertEqual(set(reproducible["required"]), {*REPRODUCIBLE_FIELDS, "exit_code"})

    def test_enumerations_match_the_code(self) -> None:
        file_properties = self.defs["evaluation_file"]["properties"]
        self.assertEqual(set(file_properties["disposition"]["enum"]), {item.value for item in Disposition})
        self.assertEqual(set(file_properties["basis"]["enum"]), {item.value for item in Basis})
        self.assertEqual(set(file_properties["state"]["enum"]), {item.value for item in InputState})
        self.assertEqual(set(self.defs["access_class"]["enum"]), {item.value for item in AccessClass})
        self.assertEqual(set(self.schema["properties"]["package_state"]["enum"]), {item.value for item in PackageState})
        permissions = self.defs["permissions"]["properties"]
        self.assertEqual({name: spec["default"] for name, spec in permissions.items()}, Permissions().to_dict())
        for rule in self.defs["evaluation_file"]["allOf"]:
            disposition = Disposition(rule["if"]["properties"]["disposition"]["const"])
            with self.subTest(disposition=disposition):
                allowed = set(rule["then"]["properties"]["basis"]["enum"])
                self.assertEqual(allowed, {basis.value for basis in BASES_FOR[disposition]})


if __name__ == "__main__":
    unittest.main()
