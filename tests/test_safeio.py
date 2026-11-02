"""Path containment and the only sanctioned write path (sections 0 and 15)."""

from __future__ import annotations

import errno
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

    def test_superscript_device_names_are_refused_on_every_platform(self) -> None:
        # Windows reserves these six aliases, including mixed case, extensions
        # and intermediate directories. They must also be refused on Linux.
        for name in ("COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"):
            for relpath in (
                name,
                name.lower() + ".csv",
                name + ".tar.gz",
                "data/" + name + ".json",
                name + "/measurements.csv",
                "data\\" + name.lower() + "\\measurements.csv",
            ):
                with self.subTest(relpath=relpath):
                    with self.assertRaises(UnsafePathError) as caught:
                        normalize_relpath(relpath)
                    self.assertEqual(caught.exception.code, RESERVED_NAME)

    def test_similar_unreserved_names_remain_valid(self) -> None:
        for relpath in (
            "COM0", "LPT0", "COM10", "LPT10", "COM⁴", "LPT⁴",
            "COM¹data.csv", "xLPT².txt", "data.LPT³", "measurements³.csv",
        ):
            with self.subTest(relpath=relpath):
                self.assertEqual(normalize_relpath(relpath), relpath)


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

    def test_os_loop_signal_becomes_a_named_refusal(self) -> None:
        with mock.patch.object(Path, "resolve", side_effect=OSError(errno.ELOOP, "Too many links")):
            with self.assertRaises(UnsafePathError) as caught:
                resolve_under_root(self.tmp, "a")
        self.assertEqual(caught.exception.code, SYMLINK_LOOP)
        self.assertNotIn(str(self.tmp), str(caught.exception))

    def test_missing_path_still_resolves_for_input_accounting_and_writes(self) -> None:
        root = self.tmp / "root"
        root.mkdir()
        self.assertEqual(resolve_under_root(root, "missing/child.csv"), root / "missing" / "child.csv")

    def test_dangling_symlink_outside_root_is_still_refused(self) -> None:
        root = self.tmp / "root"
        root.mkdir()
        try_symlink(self, self.tmp / "outside" / "missing.csv", root / "link.csv")
        with self.assertRaises(UnsafePathError) as caught:
            resolve_under_root(root, "link.csv")
        self.assertEqual(caught.exception.code, SYMLINK_ESCAPE)

    def test_non_loop_os_errors_are_not_relabelled(self) -> None:
        with mock.patch.object(Path, "resolve", side_effect=PermissionError(errno.EACCES, "Denied")):
            with self.assertRaises(PermissionError):
                resolve_under_root(self.tmp, "a")


    def test_loop_is_refused_when_nonstrict_pathlib_suppresses_errors(self) -> None:
        root = self.tmp / "root"
        root.mkdir()
        try_symlink(self, root / "b", root / "a")
        try_symlink(self, root / "a", root / "b")

        def resolve_like_python313(path: Path, strict: bool = False) -> Path:
            # Python 3.13 no longer raises for loops in non-strict mode.
            # os.path.realpath exposes those semantics on earlier Pythons too.
            return Path(os.path.realpath(path, strict=strict))

        with mock.patch.object(Path, "resolve", resolve_like_python313):
            for base, relative in (
                (root, "a"),
                (root / "missing" / "..", "a"),
                (root / "missing" / ".." / "a", "child.csv"),
            ):
                with self.subTest(base=base, relative=relative):
                    with self.assertRaises(UnsafePathError) as caught:
                        resolve_under_root(base, relative)
                    self.assertEqual(caught.exception.code, SYMLINK_LOOP)
                    self.assertNotIn(str(self.tmp), str(caught.exception))

    def test_windows_loop_signal_becomes_a_named_refusal(self) -> None:
        error = OSError(errno.EINVAL, "synthetic unresolvable filename")
        error.winerror = 1921  # ERROR_CANT_RESOLVE_FILENAME, the Windows loop signal.
        with mock.patch.object(Path, "resolve", side_effect=error):
            with self.assertRaises(UnsafePathError) as caught:
                resolve_under_root(self.tmp, "a")
        self.assertEqual(caught.exception.code, SYMLINK_LOOP)

    def test_unrelated_resolution_errors_propagate_unchanged(self) -> None:
        for code in (errno.EACCES, errno.EIO, errno.ENOTDIR):
            error = OSError(code, "synthetic filesystem error")
            with self.subTest(errno=code), mock.patch.object(Path, "resolve", side_effect=error):
                with self.assertRaises(OSError) as caught:
                    resolve_under_root(self.tmp, "a")
                self.assertIs(caught.exception, error)

    def test_missing_children_are_resolved_without_becoming_safety_errors(self) -> None:
        for relative in ("missing.csv", "missing/child.csv"):
            with self.subTest(relative=relative):
                self.assertEqual(resolve_under_root(self.tmp, relative), self.tmp / relative)

    def test_dangling_symlink_inside_root_is_still_a_missing_path(self) -> None:
        target = self.tmp / "missing" / "child.csv"
        try_symlink(self, target, self.tmp / "alias.csv")
        self.assertEqual(resolve_under_root(self.tmp, "alias.csv"), target)
        with self.assertRaises(FileNotFoundError):
            safe_read(self.tmp, "alias.csv")

    def test_dangling_symlink_outside_root_is_refused(self) -> None:
        root = self.tmp / "root"
        root.mkdir()
        try_symlink(self, self.tmp / "missing.csv", root / "alias.csv")
        with self.assertRaises(UnsafePathError) as caught:
            resolve_under_root(root, "alias.csv")
        self.assertEqual(caught.exception.code, SYMLINK_ESCAPE)


class SafeWriteTests(TempDirTestCase):
    def listing(self) -> list[str]:
        return sorted(str(path.relative_to(self.tmp)) for path in self.tmp.rglob("*"))

    def test_superscript_device_names_are_refused_before_creating_directories(self) -> None:
        root = self.tmp / "out"
        for name in ("COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"):
            with self.subTest(name=name), mock.patch.object(
                Path, "mkdir", side_effect=AssertionError("reserved path reached directory creation")
            ) as mkdir:
                with self.assertRaises(UnsafePathError) as caught:
                    safe_write(root, "data/" + name + ".csv", "synthetic")
                self.assertEqual(caught.exception.code, RESERVED_NAME)
                mkdir.assert_not_called()
        self.assertFalse(root.exists())

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
    def test_superscript_device_names_are_refused_before_resolving_paths(self) -> None:
        for name in ("COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"):
            with self.subTest(name=name), mock.patch.object(
                Path, "resolve", side_effect=AssertionError("reserved path reached filesystem resolution")
            ) as resolve:
                with self.assertRaises(UnsafePathError) as caught:
                    safe_read(self.tmp, "data/" + name + ".csv")
                self.assertEqual(caught.exception.code, RESERVED_NAME)
                resolve.assert_not_called()

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

