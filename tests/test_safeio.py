"""Path containment and the only sanctioned write path (sections 0 and 15)."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from _helpers import TempDirTestCase, try_symlink

from science_gate._safeio import (
    ABSOLUTE_PATH,
    DRIVE_PATH,
    EMPTY_PATH,
    FILE_TOO_LARGE,
    INVALID_PATH,
    NOT_A_REGULAR_FILE,
    PATH_TRAVERSAL,
    RESERVED_NAME,
    SYMLINK_ESCAPE,
    SYMLINK_LOOP,
    SYMLINK_TARGET,
    SafeIOError,
    UnsafePathError,
    comparison_key,
    is_within,
    normalize_relpath,
    resolve_under_root,
    safe_read,
    safe_write,
)


class NormalizeRelpathTests(unittest.TestCase):
    def test_accepts_and_normalizes_safe_paths(self) -> None:
        cases = {
            "a/b.csv": "a/b.csv",
            "a\\b.csv": "a/b.csv",
            "./a//b/": "a/b",
            "a/../b.csv": "b.csv",
            "data/./x/../m.csv": "data/m.csv",
        }
        for given, expected in cases.items():
            with self.subTest(given=given):
                self.assertEqual(normalize_relpath(given), expected)

    def test_refuses_unsafe_paths_with_named_codes(self) -> None:
        cases = {
            "": EMPTY_PATH,
            "   ": EMPTY_PATH,
            ".": EMPTY_PATH,
            "a/..": EMPTY_PATH,
            "..": PATH_TRAVERSAL,
            "../secret.csv": PATH_TRAVERSAL,
            "a/../../b.csv": PATH_TRAVERSAL,
            "/etc/passwd": ABSOLUTE_PATH,
            "\\\\server\\share\\x.csv": ABSOLUTE_PATH,
            "C:\\x.csv": DRIVE_PATH,
            "C:x.csv": DRIVE_PATH,
            "a\x00b": INVALID_PATH,
            "a/\x07b": INVALID_PATH,
            "file.csv:stream": INVALID_PATH,
            "a/b?.csv": INVALID_PATH,
            "a/b*.csv": INVALID_PATH,
            "trailing./x": INVALID_PATH,
            "trailing /x": INVALID_PATH,
            "CON": RESERVED_NAME,
            "nul.txt": RESERVED_NAME,
            "data/COM1.csv": RESERVED_NAME,
        }
        for given, code in cases.items():
            with self.subTest(given=given):
                with self.assertRaises(UnsafePathError) as caught:
                    normalize_relpath(given)
                self.assertEqual(caught.exception.code, code)

    def test_refuses_non_strings(self) -> None:
        with self.assertRaises(UnsafePathError):
            normalize_relpath(b"a/b")  # type: ignore[arg-type]

    def test_device_names_are_whole_segments_only(self) -> None:
        self.assertEqual(normalize_relpath("console/auxiliary.csv"), "console/auxiliary.csv")


class ComparisonKeyTests(unittest.TestCase):
    def test_equivalent_spellings_share_a_key(self) -> None:
        self.assertEqual(comparison_key("data/./a.csv"), comparison_key("data\\a.csv"))

    def test_case_folding_follows_the_request_or_the_host(self) -> None:
        self.assertEqual(comparison_key("A.csv", case_insensitive=True), comparison_key("a.csv", case_insensitive=True))
        self.assertNotEqual(
            comparison_key("A.csv", case_insensitive=False), comparison_key("a.csv", case_insensitive=False)
        )
        self.assertEqual(comparison_key("A.csv") == comparison_key("a.csv"), os.name == "nt")

    def test_unsafe_paths_still_get_a_key(self) -> None:
        self.assertEqual(comparison_key("../x.csv", case_insensitive=False), "../x.csv")


class IsWithinTests(TempDirTestCase):
    def test_containment(self) -> None:
        root = self.tmp / "root"
        self.assertTrue(is_within(root, root))
        self.assertTrue(is_within(root, root / "a" / "b"))
        self.assertFalse(is_within(root, self.tmp / "root2" / "a"))
        self.assertFalse(is_within(root, self.tmp))

    @unittest.skipUnless(os.name == "nt", "drive letters exist only on Windows")
    def test_other_drive_is_never_within(self) -> None:
        other = "Z:\\x" if not str(self.tmp).upper().startswith("Z:") else "Y:\\x"
        self.assertFalse(is_within(self.tmp, other))


class ResolveUnderRootTests(TempDirTestCase):
    def test_resolves_inside_the_root(self) -> None:
        self.write("root/data/a.csv", "x\n")
        self.assertEqual(resolve_under_root(self.tmp / "root", "data/a.csv"), self.tmp / "root" / "data" / "a.csv")

    def test_traversal_is_refused_even_when_the_target_exists(self) -> None:
        self.write("outside.csv", "x\n")
        (self.tmp / "root").mkdir()
        with self.assertRaises(UnsafePathError) as caught:
            resolve_under_root(self.tmp / "root", "../outside.csv")
        self.assertEqual(caught.exception.code, PATH_TRAVERSAL)

    def test_symlink_escape_is_refused(self) -> None:
        self.write("outside/secret.csv", "x\n")
        (self.tmp / "root").mkdir()
        try_symlink(self, self.tmp / "outside", self.tmp / "root" / "link", directory=True)
        with self.assertRaises(UnsafePathError) as caught:
            resolve_under_root(self.tmp / "root", "link/secret.csv")
        self.assertEqual(caught.exception.code, SYMLINK_ESCAPE)

    def test_symlink_inside_the_root_is_allowed(self) -> None:
        target = self.write("root/real.csv", "x\n")
        try_symlink(self, target, self.tmp / "root" / "alias.csv")
        self.assertEqual(resolve_under_root(self.tmp / "root", "alias.csv"), target)

    def test_symlink_loop_is_a_named_refusal(self) -> None:
        (self.tmp / "root").mkdir()
        try_symlink(self, self.tmp / "root" / "b", self.tmp / "root" / "a")
        try_symlink(self, self.tmp / "root" / "a", self.tmp / "root" / "b")
        with self.assertRaises(UnsafePathError) as caught:
            resolve_under_root(self.tmp / "root", "a")
        self.assertEqual(caught.exception.code, SYMLINK_LOOP)

    def test_loop_signal_from_pathlib_becomes_a_named_refusal(self) -> None:
        # Runs everywhere, including where symlinks cannot be created: Python
        # 3.11 reports a loop as RuntimeError, which must never escape as a traceback.
        with mock.patch.object(Path, "resolve", side_effect=RuntimeError("Symlink loop from 'x'")):
            with self.assertRaises(UnsafePathError) as caught:
                resolve_under_root(self.tmp, "a")
        self.assertEqual(caught.exception.code, SYMLINK_LOOP)
        self.assertNotIn(str(self.tmp), str(caught.exception))


class SafeWriteTests(TempDirTestCase):
    def listing(self) -> list[str]:
        return sorted(str(path.relative_to(self.tmp)) for path in self.tmp.rglob("*"))

    def test_writes_bytes_verbatim_and_text_as_utf8(self) -> None:
        root = self.tmp / "out"
        written = safe_write(root, "a/b/data.bin", b"one\r\ntwo\n")
        self.assertEqual(written, root / "a" / "b" / "data.bin")
        self.assertEqual(written.read_bytes(), b"one\r\ntwo\n")
        safe_write(root, "text.md", "caf\u00e9\n")
        self.assertEqual((root / "text.md").read_bytes(), "caf\u00e9\n".encode("utf-8"))

    def test_overwrites_atomically_and_leaves_no_temporary_files(self) -> None:
        root = self.tmp / "out"
        safe_write(root, "x.json", "first")
        safe_write(root, "x.json", "second")
        self.assertEqual((root / "x.json").read_text(encoding="utf-8"), "second")
        self.assertEqual(sorted(path.name for path in root.iterdir()), ["x.json"])

    def test_refuses_every_escape_and_writes_nothing(self) -> None:
        root = self.tmp / "out"
        root.mkdir()
        before = self.listing()
        for relpath in ("../escape.txt", "a/../../escape.txt", "/abs.txt", "C:\\abs.txt", "C:rel.txt", ""):
            with self.subTest(relpath=relpath), self.assertRaises(UnsafePathError):
                safe_write(root, relpath, "x")
        self.assertEqual(self.listing(), before)

    def test_refuses_to_write_through_a_symlinked_file(self) -> None:
        outside = self.write("outside.txt", "original")
        (self.tmp / "out").mkdir()
        try_symlink(self, outside, self.tmp / "out" / "link.txt")
        with self.assertRaises(UnsafePathError) as caught:
            safe_write(self.tmp / "out", "link.txt", "overwritten")
        self.assertIn(caught.exception.code, (SYMLINK_TARGET, SYMLINK_ESCAPE))
        self.assertEqual(outside.read_text(encoding="utf-8"), "original")

    def test_refuses_to_write_through_a_symlinked_directory(self) -> None:
        (self.tmp / "outside").mkdir()
        (self.tmp / "out").mkdir()
        try_symlink(self, self.tmp / "outside", self.tmp / "out" / "sub", directory=True)
        with self.assertRaises(UnsafePathError) as caught:
            safe_write(self.tmp / "out", "sub/x.txt", "data")
        self.assertEqual(caught.exception.code, SYMLINK_ESCAPE)
        self.assertEqual(list((self.tmp / "outside").iterdir()), [])

    def test_refuses_to_replace_a_directory(self) -> None:
        (self.tmp / "out" / "dir").mkdir(parents=True)
        with self.assertRaises(UnsafePathError) as caught:
            safe_write(self.tmp / "out", "dir", "data")
        self.assertEqual(caught.exception.code, NOT_A_REGULAR_FILE)


class SafeReadTests(TempDirTestCase):
    def test_reads_a_file_under_the_root(self) -> None:
        self.write("root/a.txt", b"payload")
        self.assertEqual(safe_read(self.tmp / "root", "a.txt"), b"payload")

    def test_missing_file_is_not_a_safety_error(self) -> None:
        (self.tmp / "root").mkdir()
        with self.assertRaises(FileNotFoundError) as caught:
            safe_read(self.tmp / "root", "absent.txt")
        self.assertNotIsInstance(caught.exception, SafeIOError)

    def test_size_limit_and_non_regular_files(self) -> None:
        self.write("root/big.txt", b"12345678")
        (self.tmp / "root" / "dir").mkdir()
        with self.assertRaises(SafeIOError) as caught:
            safe_read(self.tmp / "root", "big.txt", max_bytes=4)
        self.assertEqual(caught.exception.code, FILE_TOO_LARGE)
        self.assertEqual(safe_read(self.tmp / "root", "big.txt", max_bytes=8), b"12345678")
        with self.assertRaises(UnsafePathError) as caught:
            safe_read(self.tmp / "root", "dir")
        self.assertEqual(caught.exception.code, NOT_A_REGULAR_FILE)

    def test_traversal_is_refused(self) -> None:
        self.write("secret.txt", b"s")
        (self.tmp / "root").mkdir()
        with self.assertRaises(UnsafePathError):
            safe_read(self.tmp / "root", "../secret.txt")


if __name__ == "__main__":
    unittest.main()
