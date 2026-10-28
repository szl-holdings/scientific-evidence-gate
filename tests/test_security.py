"""Security properties (ARCHITECTURE.md section 15).

One test class per listed threat. Every test builds a synthetic project in an
OS temporary directory, attacks it in one way, and asserts both the refusal
and that nothing escaped: no file read or written outside the project, no
secret copied into any output. Symlink tests skip with a visible reason where
the account cannot create symbolic links.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import unicodedata
import unittest
from decimal import Decimal
from pathlib import Path

from _helpers import REPO_ROOT, try_symlink
from _project import ProjectTestCase

from science_gate import cli
from science_gate._canonical import sha256_bytes
from science_gate._redact import REDACTED
from science_gate._safeio import UnsafePathError, safe_write
from science_gate.invariants import MAX_NUMBER_LENGTH, NOT_A_NUMBER, compare_decimal, parse_decimal
from science_gate.manifests import (
    DUPLICATE_PATH,
    MALFORMED_JSON,
    UNSAFE_PATH,
    UNSAFE_SUBPROCESS_REQUEST,
    ManifestError,
    load_manifest,
)
from science_gate.models import InputState, Reason, Status
from science_gate.packaging import OUTPUT_INSIDE_INPUT_DIRECTORY, PackagingError, build_package
from science_gate.reports import report_run_dir, write_run
from science_gate.verifier import verify

#: A fake credential in a well-known token shape (never a real token).
FAKE_SHAPED_TOKEN = "ghp_" + "SyntheticFakeTokenForTests0123456789"
#: A fake credential with no recognizable shape; only its environment variable name marks it as secret.
FAKE_ENV_SECRET = "synthetic-env-secret-value-4f2a9c"


def make_junction(test: unittest.TestCase, target: Path, link: Path) -> None:
    """A Windows directory junction, which needs no symlink privilege, or a visible skip elsewhere.

    The junction is removed before the temporary tree, so cleanup never
    reaches through it into the directory it points at.
    """
    try:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    except (ImportError, AttributeError, OSError) as exc:
        test.skipTest(f"directory junctions cannot be created on this system ({type(exc).__name__})")
    test.addCleanup(os.rmdir, link)


def tree_snapshot(root: Path) -> dict[str, bytes]:
    """Every file under ``root`` with its bytes: what "nothing changed here" means."""
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


class SecurityTestCase(ProjectTestCase):
    """The synthetic starter project plus a sentinel file just outside it."""

    def setUp(self) -> None:
        super().setUp()
        self.outside = self.write("outside/secret-data.csv", "sample_id,value\nOUTSIDE-0001,999\n")

    def first_input(self, **changes: object) -> None:
        document = self.manifest()
        document["inputs"][0].update(changes)
        self.save_manifest(document)

    def cli(self, *argv: str) -> tuple[int, str]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            code = cli.main(list(argv))
        return code, stdout.getvalue()

    def assert_outside_untouched(self, run_dir: Path | None = None) -> None:
        self.assertEqual(self.outside.read_bytes(), b"sample_id,value\nOUTSIDE-0001,999\n")
        if run_dir is not None:
            for name, data in tree_snapshot(run_dir).items():
                with self.subTest(output=name):
                    self.assertNotIn(b"OUTSIDE-0001", data, "content from outside the project was read")


class PathTraversalTests(SecurityTestCase):
    def test_an_input_path_leaving_the_project_is_refused_and_the_run_is_error(self) -> None:
        self.first_input(path="../outside/secret-data.csv", sha256=None)
        run = self.run_verify()
        record = run.result.accounting.records[0]
        self.assertEqual(record.state, InputState.REFUSED)
        self.assertIn("PATH_TRAVERSAL", " ".join(record.diagnostics))
        self.assertIsNone(record.sha256, "a refused file is never hashed, so it was never read")
        self.assertEqual((run.status, run.exit_code), (Status.ERROR, 3))
        self.assert_outside_untouched(write_run(run, self.tmp / "run", environ={}).run_dir)

    def test_absolute_paths_are_refused(self) -> None:
        self.first_input(path=str(self.outside), sha256=None)
        run = self.run_verify()
        self.assertEqual(run.result.accounting.records[0].state, InputState.REFUSED)
        self.assertEqual(run.status, Status.ERROR)

    def test_role_document_paths_are_refused_when_the_manifest_is_loaded(self) -> None:
        self.update_manifest(accepted_snapshot="../outside/secret-data.csv")
        with self.assertRaises(ManifestError) as raised:
            load_manifest(self.manifest_path)
        self.assertIn(UNSAFE_PATH, raised.exception.codes)


class SymlinkEscapeTests(SecurityTestCase):
    def test_a_symlink_leading_outside_the_project_is_refused(self) -> None:
        link = self.project / "data" / "linked.csv"
        try_symlink(self, self.outside, link)
        self.first_input(path="data/linked.csv", sha256=None)
        run = self.run_verify()
        record = run.result.accounting.records[0]
        self.assertEqual(record.state, InputState.REFUSED)
        self.assertIn("SYMLINK_ESCAPE", " ".join(record.diagnostics))
        self.assertEqual(run.status, Status.ERROR)
        self.assert_outside_untouched(write_run(run, self.tmp / "run", environ={}).run_dir)

    def test_safe_write_refuses_to_follow_a_symlinked_directory_out_of_its_root(self) -> None:
        link = self.tmp / "out" / "escape"
        link.parent.mkdir()
        try_symlink(self, self.outside.parent, link, directory=True)
        with self.assertRaises(UnsafePathError):
            safe_write(self.tmp / "out", "escape/planted.txt", b"never written")
        self.assertFalse((self.outside.parent / "planted.txt").exists())


class JunctionEscapeTests(SecurityTestCase):
    """The same escape through a directory junction, which Windows accounts can create without privilege."""

    def test_an_input_reached_through_a_junction_outside_the_project_is_refused(self) -> None:
        make_junction(self, self.outside.parent, self.project / "data" / "elsewhere")
        self.first_input(path="data/elsewhere/secret-data.csv", sha256=None)
        run = self.run_verify()
        record = run.result.accounting.records[0]
        self.assertEqual(record.state, InputState.REFUSED)
        self.assertIn("SYMLINK_ESCAPE", " ".join(record.diagnostics))
        self.assertEqual(run.status, Status.ERROR)
        self.assert_outside_untouched(write_run(run, self.tmp / "run", environ={}).run_dir)

    def test_safe_write_refuses_to_write_through_a_junction(self) -> None:
        (self.tmp / "out").mkdir()
        make_junction(self, self.outside.parent, self.tmp / "out" / "escape")
        with self.assertRaises(UnsafePathError):
            safe_write(self.tmp / "out", "escape/planted.txt", b"never written")
        self.assertFalse((self.outside.parent / "planted.txt").exists())


class DuplicatePathTests(SecurityTestCase):
    def test_two_entries_naming_the_same_file_are_refused(self) -> None:
        document = self.manifest()
        twin = dict(document["inputs"][0], id="measurements-again", path="data/./measurements.csv")
        document["inputs"].append(twin)
        self.save_manifest(document)
        with self.assertRaises(ManifestError) as raised:
            load_manifest(self.manifest_path)
        self.assertIn(DUPLICATE_PATH, raised.exception.codes)
        run = self.run_verify()
        self.assertEqual((run.status, run.exit_code), (Status.ERROR, 3))

    def test_paths_differing_only_in_case_are_the_same_file_on_windows(self) -> None:
        if os.name != "nt":
            self.skipTest("path comparison is case-sensitive on this operating system")
        document = self.manifest()
        document["inputs"].append(dict(document["inputs"][0], id="shouting", path="DATA/MEASUREMENTS.CSV"))
        self.save_manifest(document)
        with self.assertRaises(ManifestError) as raised:
            load_manifest(self.manifest_path)
        self.assertIn(DUPLICATE_PATH, raised.exception.codes)


class OversizedInputTests(SecurityTestCase):
    def test_an_input_over_max_file_bytes_is_refused_without_being_parsed(self) -> None:
        self.update_manifest(limits={"max_file_bytes": 64})
        run = self.run_verify()
        record = run.result.accounting.records[0]
        self.assertEqual(record.state, InputState.REFUSED)
        self.assertIn("FILE_TOO_LARGE", " ".join(record.diagnostics))
        self.assertIsNone(record.rows)
        self.assertNotEqual(run.status, Status.PASS)

    def test_a_number_with_a_huge_exponent_is_refused_without_being_expanded(self) -> None:
        # Expanding 1E+999999999 to fixed point would need about a gigabyte.
        for value in (Decimal("1E+999999999"), Decimal("-7.5E+200000"), Decimal("3E-999999")):
            with self.subTest(value=str(value)):
                parsed = parse_decimal(value)
                self.assertEqual(parsed.state, NOT_A_NUMBER)
                self.assertIn(str(MAX_NUMBER_LENGTH), parsed.detail)
        self.assertIsNone(compare_decimal(Decimal("1E+999999999"), "1").agrees)

    def test_a_json_input_holding_a_huge_exponent_cannot_exhaust_memory(self) -> None:
        self.write_file("data/sites.json", '[{"site_id": "SYN-SITE-1", "elevation": 1E+999999999}]')
        document = self.manifest()
        document["inputs"].append({"id": "sites", "path": "data/sites.json", "format": "json", "row_key": ["site_id"]})
        params = {"column": "elevation", "expected": [{"key": "SYN-SITE-1", "value": "1"}]}
        document["checks"].append(
            {"id": "elevation", "kind": "numeric_agreement", "version": "1", "inputs": ["sites"], "params": params}
        )
        self.save_manifest(document)
        run = self.run_verify()
        check = self.result_of(run, "elevation")
        self.assertEqual((check.verdict, check.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))


class FileCountTests(SecurityTestCase):
    def test_inputs_beyond_max_files_are_refused_and_counted(self) -> None:
        document = self.manifest()
        document["limits"] = {"max_files": 1}
        document["inputs"].append(
            {"id": "extra", "path": "data/extra.csv", "format": "csv", "required": True, "row_key": ["sample_id"]}
        )
        self.save_manifest(document)
        self.write_file("data/extra.csv", "sample_id,value\nSYN-X-0001,1\n")
        run = self.run_verify()
        (extra,) = [item for item in run.result.accounting.records if item.input_id == "extra"]
        self.assertEqual(extra.state, InputState.REFUSED)
        self.assertIn("FILE_COUNT_LIMIT", " ".join(extra.diagnostics))
        self.assertIsNone(extra.sha256, "the file beyond the limit was never opened")
        self.assertNotEqual(run.status, Status.PASS)


class MalformedJsonTests(SecurityTestCase):
    def test_a_malformed_manifest_is_an_error_with_a_named_diagnostic_not_a_traceback(self) -> None:
        self.manifest_path.write_text('{"schema": "science-gate-manifest/v1", "inputs": [', encoding="utf-8")
        code, output = self.cli("verify", str(self.manifest_path), "--output", str(self.tmp / "run"))
        self.assertEqual(code, 3)
        self.assertTrue(output.startswith("ERROR"), output)
        self.assertNotIn("Traceback", output)
        document = json.loads((self.tmp / "run" / "run.json").read_text(encoding="utf-8"))
        self.assertIn(MALFORMED_JSON, {issue["code"] for issue in document["manifest"]["issues"]})

    def test_json_inputs_reject_duplicate_keys_and_non_finite_numbers(self) -> None:
        document = self.manifest()
        document["inputs"].append({"id": "sites", "path": "data/sites.json", "format": "json", "required": False})
        self.save_manifest(document)
        for text in ('[{"site_id": "A", "site_id": "B"}]', '[{"site_id": "A", "value": NaN}]', "[Infinity]"):
            with self.subTest(text=text):
                self.write_file("data/sites.json", text)
                run = self.run_verify()
                (sites,) = [item for item in run.result.accounting.records if item.input_id == "sites"]
                self.assertEqual(sites.state, InputState.PARSE_ERROR)


class HashMismatchTests(SecurityTestCase):
    def test_a_declared_digest_that_does_not_match_fails_the_run(self) -> None:
        self.first_input(sha256=sha256_bytes(b"some other synthetic bytes"))
        run = self.run_verify()
        record = run.result.accounting.records[0]
        self.assertEqual(record.state, InputState.HASH_MISMATCH)
        self.assertEqual(record.counts.admitted, 0, "bytes that are not the declared artifact are never admitted")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.FAIL, Reason.SOURCE_MISMATCH, 1))


class SubprocessRequestTests(SecurityTestCase):
    def test_process_keys_are_refused_at_any_depth_and_in_any_case(self) -> None:
        cases = {
            "top level": lambda document: document.update(command="echo synthetic"),
            "inside params": lambda document: document["checks"][0].setdefault("params", {}).update(shell="sh"),
            "mixed case": lambda document: document["inputs"][0].update(Exec="run-me"),
            "nested object": lambda document: document.update(corpus={"access_class": "SYNTHETIC", "entrypoint": {}}),
        }
        for label, edit in cases.items():
            with self.subTest(case=label):
                document = self.manifest()
                edit(document)
                self.save_manifest(document)
                with self.assertRaises(ManifestError) as raised:
                    load_manifest(self.manifest_path)
                self.assertIn(UNSAFE_SUBPROCESS_REQUEST, raised.exception.codes)
                run = self.run_verify()
                self.assertEqual((run.status, run.exit_code), (Status.ERROR, 3))
                self.assertEqual(run.result.checks, (), "no check runs for an unsafe manifest")

    def test_the_package_never_starts_a_process(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src" / "science_gate"
        for path in sorted(source.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(module=path.name):
                self.assertNotIn("import subprocess", text)
                self.assertNotIn("shell=True", text)
                self.assertNotIn("os.system(", text)
                self.assertNotIn("os.popen(", text)


class SecretLeakageTests(SecurityTestCase):
    def setUp(self) -> None:
        super().setUp()
        os.environ["SCIENCE_GATE_SYNTHETIC_API_TOKEN"] = FAKE_ENV_SECRET

    def plant_secrets(self) -> None:
        """Put both fake secrets where evidence quotes them: duplicated row keys and a malformed value."""
        lines = self.data_lines()
        planted = [
            f"{FAKE_SHAPED_TOKEN},site-alpha,1.0,1\n",
            f"{FAKE_SHAPED_TOKEN},site-alpha,1.0,1\n",
            f"{FAKE_ENV_SECRET},site-beta,{FAKE_ENV_SECRET},2\n",
            f"{FAKE_ENV_SECRET},site-beta,2.0,2\n",
        ]
        self.write_data("".join(lines + planted))
        document = self.manifest()
        document["inputs"][0]["expected_rows"] = 10
        values = document["checks"][4]["params"]
        values["expected"].append({"key": FAKE_ENV_SECRET, "value": "1"})
        self.save_manifest(document)

    def assert_no_secret(self, root: Path) -> None:
        files = tree_snapshot(root)
        self.assertTrue(files)
        for name, data in files.items():
            with self.subTest(file=name):
                self.assertNotIn(FAKE_SHAPED_TOKEN.encode(), data)
                self.assertNotIn(FAKE_ENV_SECRET.encode(), data)

    def test_planted_secrets_never_reach_any_output_file(self) -> None:
        self.plant_secrets()
        run_dir = self.tmp / "run"
        code, output = self.cli("verify", str(self.manifest_path), "--output", str(run_dir))
        self.assertIn(code, (1, 2))
        self.assertNotIn(FAKE_SHAPED_TOKEN, output)
        self.assertNotIn(FAKE_ENV_SECRET, output)
        self.assert_no_secret(run_dir)
        # The redaction is visible, so a reader knows something was withheld.
        self.assertIn(REDACTED, (run_dir / "run.json").read_text(encoding="utf-8"))
        written = report_run_dir(run_dir)
        self.assertEqual(written.exit_code, code, "re-verification succeeds on the redacted run")
        self.assert_no_secret(run_dir)

    def test_planted_secrets_never_reach_a_package(self) -> None:
        self.plant_secrets()
        output = self.tmp / "package"
        build_package(self.manifest_path, output, environ={})
        self.assert_no_secret(output)


class OutputConfinementTests(SecurityTestCase):
    def test_safe_write_refuses_paths_outside_its_root(self) -> None:
        root = self.tmp / "out"
        for relpath in ("../escaped.txt", str(self.tmp / "absolute.txt"), "a/../../escaped.txt", "C:/escaped.txt"):
            with self.subTest(relpath=relpath):
                with self.assertRaises(UnsafePathError):
                    safe_write(root, relpath, b"never written")
        self.assertFalse((self.tmp / "escaped.txt").exists())
        self.assertFalse((self.tmp / "absolute.txt").exists())

    def test_verify_writes_only_inside_its_output_directory(self) -> None:
        before = tree_snapshot(self.tmp)
        run_dir = self.tmp / "nested" / "run"
        code, output = self.cli("verify", str(self.manifest_path), "--output", str(run_dir))
        self.assertEqual(code, 0, output)
        after = tree_snapshot(self.tmp)
        added = sorted(set(after) - set(before))
        self.assertTrue(added)
        self.assertTrue(all(name.startswith("nested/run/") for name in added), added)
        self.assertEqual({name: after[name] for name in before}, before, "no existing file was modified")

    def test_package_refuses_an_output_inside_the_evaluated_project(self) -> None:
        before = tree_snapshot(self.project)
        with self.assertRaises(PackagingError) as raised:
            build_package(self.manifest_path, self.project / "package", environ={})
        self.assertEqual(raised.exception.code, OUTPUT_INSIDE_INPUT_DIRECTORY)
        self.assertEqual(tree_snapshot(self.project), before)


class SourceTextTests(unittest.TestCase):
    """No invisible character hides in the package or test source (the "Trojan Source" class of attack).

    A bidirectional control, a zero-width character or a look-alike space
    can make code read differently from how it runs. Where a literal needs
    one (a byte-order mark, a no-break space used as a thousands separator),
    the source writes it as an escape, so a reviewer sees it.
    """

    @staticmethod
    def hidden(text: str) -> list[str]:
        """``U+XXXX NAME`` for every character a reader could not see or would mistake for another."""
        return [
            f"U+{ord(char):04X} {unicodedata.name(char, '?')}"
            for char in text
            if char not in "\t\n "
            and unicodedata.category(char) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp", "Zs"}
        ]

    def test_python_sources_are_lf_only_and_free_of_invisible_characters(self) -> None:
        sources = sorted(path for base in ("src", "tests") for path in (REPO_ROOT / base).rglob("*.py"))
        self.assertGreater(len(sources), 40)
        for path in sources:
            with self.subTest(path=path.relative_to(REPO_ROOT).as_posix()):
                self.assertEqual(self.hidden(path.read_bytes().decode("utf-8")), [])

    def test_the_scan_sees_what_it_is_meant_to_refuse(self) -> None:
        """The guard could fail: each class of hidden character, a carriage return included, is reported."""
        for code in (0x202E, 0x200B, 0xFEFF, 0x00A0, 0x2009, 0x2028, 0x0007, 0x000D):
            with self.subTest(code=f"U+{code:04X}"):
                self.assertEqual(len(self.hidden(f"x = 'a{chr(code)}b'")), 1)
        self.assertEqual(self.hidden("plain\ttext\n with spaces and a visible \u00b7 dot"), [])
