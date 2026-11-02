"""Path containment and the only sanctioned way to write files.

Manifests and inputs are untrusted text, and a path taken from them must never
reach outside the directory it is relative to. Every write in the package goes
through :func:`safe_write`, and every manifest-relative read resolves through
:func:`resolve_under_root`. Both apply two independent defences:

1. **Lexical validation** (:func:`normalize_relpath`). Absolute paths, drive
   letters, UNC shares, ``..`` segments that climb above the root, NUL and
   control characters, Windows device names and alternate-data-stream colons
   are refused before the filesystem is touched. Windows path rules are
   applied on every platform, so a manifest that is safe on Linux is also safe
   when it is replayed on Windows.
2. **Filesystem resolution.** The lexically clean path is resolved with
   symlinks followed and must still lie inside the resolved root. This catches
   symlinks and junctions that point outside.

Both defences check the path at the moment of use. A concurrent attacker who
swaps a directory for a symlink between the check and the open is outside
this tool's threat model: it runs locally on the operator's own files.
"""

from __future__ import annotations

import contextlib
import errno
import os
import posixpath
import re
import stat
import tempfile
from pathlib import Path, PureWindowsPath

__all__ = [
    "SafeIOError",
    "UnsafePathError",
    "normalize_relpath",
    "comparison_key",
    "is_within",
    "resolve_under_root",
    "safe_write",
    "safe_read",
    "EMPTY_PATH",
    "INVALID_PATH",
    "ABSOLUTE_PATH",
    "DRIVE_PATH",
    "PATH_TRAVERSAL",
    "RESERVED_NAME",
    "SYMLINK_ESCAPE",
    "SYMLINK_TARGET",
    "SYMLINK_LOOP",
    "NOT_A_REGULAR_FILE",
    "FILE_TOO_LARGE",
]

EMPTY_PATH = "EMPTY_PATH"
INVALID_PATH = "INVALID_PATH"
ABSOLUTE_PATH = "ABSOLUTE_PATH"
DRIVE_PATH = "DRIVE_PATH"
PATH_TRAVERSAL = "PATH_TRAVERSAL"
RESERVED_NAME = "RESERVED_NAME"
SYMLINK_ESCAPE = "SYMLINK_ESCAPE"
SYMLINK_TARGET = "SYMLINK_TARGET"
SYMLINK_LOOP = "SYMLINK_LOOP"
NOT_A_REGULAR_FILE = "NOT_A_REGULAR_FILE"
FILE_TOO_LARGE = "FILE_TOO_LARGE"

_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)
_WINDOWS_FORBIDDEN_CHARS = frozenset('<>"|?*')
_SEPARATORS = re.compile(r"[\\/]+")


class SafeIOError(Exception):
    """A refused file operation, with a stable machine-readable ``code``."""

    def __init__(self, code: str, message: str, *, path: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.detail = message
        self.path = path


class UnsafePathError(SafeIOError, ValueError):
    """A path refused because it could reach outside its root."""


def _check_component(part: str, relpath: str) -> None:
    """Refuse a single path segment that is unsafe or non-portable."""
    if any(ord(char) < 32 for char in part):
        raise UnsafePathError(INVALID_PATH, "control characters are not allowed in paths", path=relpath)
    if ":" in part:
        raise UnsafePathError(
            INVALID_PATH, "':' marks a drive or an alternate data stream on Windows", path=relpath
        )
    if _WINDOWS_FORBIDDEN_CHARS.intersection(part):
        raise UnsafePathError(INVALID_PATH, f"segment {part!r} contains a character Windows forbids", path=relpath)
    if part.endswith((".", " ")):
        # Windows silently strips trailing dots and spaces, so "a." and "a"
        # would name the same file under two spellings.
        raise UnsafePathError(INVALID_PATH, f"segment {part!r} ends with a dot or space", path=relpath)
    if part.split(".", 1)[0].upper() in _WINDOWS_DEVICE_NAMES:
        raise UnsafePathError(RESERVED_NAME, f"segment {part!r} is a Windows device name", path=relpath)


def normalize_relpath(relpath: str) -> str:
    """Validate a root-relative path and return it as ``a/b/c``.

    ``.`` segments are dropped and ``..`` segments are folded lexically; a
    ``..`` that would climb above the root is refused. Both ``/`` and ``\\``
    are separators on every platform.
    """
    if not isinstance(relpath, str):
        raise UnsafePathError(INVALID_PATH, f"path must be a string, got {type(relpath).__name__}")
    if not relpath.strip():
        raise UnsafePathError(EMPTY_PATH, "path is empty", path=relpath)
    if "\x00" in relpath:
        raise UnsafePathError(INVALID_PATH, "NUL byte in path", path=relpath)
    if relpath[0] in "/\\":
        raise UnsafePathError(ABSOLUTE_PATH, "absolute and UNC paths are not allowed", path=relpath)
    if PureWindowsPath(relpath).drive:
        raise UnsafePathError(DRIVE_PATH, "drive-qualified paths are not allowed", path=relpath)
    stack: list[str] = []
    for part in _SEPARATORS.split(relpath):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise UnsafePathError(PATH_TRAVERSAL, "'..' climbs above the root", path=relpath)
            stack.pop()
            continue
        _check_component(part, relpath)
        stack.append(part)
    if not stack:
        raise UnsafePathError(EMPTY_PATH, "path names the root itself", path=relpath)
    return "/".join(stack)


def comparison_key(relpath: str, *, case_insensitive: bool | None = None) -> str:
    """Return the key under which two declared paths name the same file.

    Used to refuse duplicate declarations. Paths are compared
    case-insensitively on Windows (``case_insensitive=None`` means "whatever
    the host does"). An unsafe path still gets a best-effort lexical key, so
    duplicate detection never depends on the path also being safe.
    """
    if case_insensitive is None:
        case_insensitive = os.name == "nt"
    try:
        key = normalize_relpath(relpath)
    except UnsafePathError:
        key = posixpath.normpath(_SEPARATORS.sub("/", str(relpath)))
    return key.casefold() if case_insensitive else key


def is_within(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> bool:
    """Return True when ``candidate`` is ``root`` or lies beneath it.

    Both arguments should already be resolved. Comparison honours the host's
    case rules, and paths on different drives are never within each other.
    """
    root_text = os.path.normcase(os.path.abspath(root))
    candidate_text = os.path.normcase(os.path.abspath(candidate))
    try:
        return os.path.commonpath([root_text, candidate_text]) == root_text
    except ValueError:
        return False


def _resolve(path: Path, relpath: str) -> Path:
    """Resolve missing paths, but report symlink loops as unsafe paths.

    Python 3.13 suppresses loop errors in non-strict mode, so strictly check
    the resolved spelling too. Checking that spelling also catches a cycle
    after a missing/.. prefix, which a strict-first check would stop before.
    Missing children remain valid paths for later creation or MISSING reports.
    The refusal names only the relative path, never a machine-specific root.
    """
    try:
        resolved = path.resolve(strict=False)
        try:
            return resolved.resolve(strict=True)
        except FileNotFoundError:
            return resolved
    except (RuntimeError, OSError) as exc:
        # Older pathlib uses RuntimeError; newer versions use platform errors.
        if isinstance(exc, OSError) and exc.errno != errno.ELOOP and getattr(exc, "winerror", None) != 1921:
            raise
        raise UnsafePathError(SYMLINK_LOOP, f"{relpath!r} runs into a symbolic link loop", path=relpath) from None


def resolve_under_root(root: str | os.PathLike[str], relpath: str) -> Path:
    """Resolve ``relpath`` against ``root`` and prove it stays inside.

    Returns the fully resolved path (symlinks followed), which is the path
    callers should open: re-resolving the original spelling later could
    follow a link that has since changed.
    """
    clean = normalize_relpath(relpath)
    root_real = _resolve(Path(root), clean)
    resolved = _resolve(root_real.joinpath(*clean.split("/")), clean)
    if not is_within(root_real, resolved):
        raise UnsafePathError(SYMLINK_ESCAPE, f"{clean!r} resolves outside the root", path=clean)
    return resolved


def safe_write(root: str | os.PathLike[str], relpath: str, data: bytes | str) -> Path:
    """Write ``data`` to ``root/relpath`` atomically and return the path written.

    Strings are encoded as UTF-8 and bytes are written verbatim, with no
    newline translation, so output is byte-identical on every platform.
    ``root`` is created if missing. Each intermediate directory is resolved and
    checked before it is created, so a symlinked directory cannot redirect the
    write. Writing through a symlink, or over a directory, is refused. The data
    lands in a temporary file in the destination directory and is then renamed
    into place, so readers never observe a half-written file.
    """
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    clean = normalize_relpath(relpath)
    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)
    root_real = root_path.resolve(strict=True)
    parts = clean.split("/")
    parent = root_real
    for part in parts[:-1]:
        step = _resolve(parent / part, clean)
        if not is_within(root_real, step):
            raise UnsafePathError(SYMLINK_ESCAPE, f"directory {part!r} resolves outside the root", path=clean)
        step.mkdir(exist_ok=True)
        parent = step
    target = parent / parts[-1]
    if target.is_symlink():
        raise UnsafePathError(SYMLINK_TARGET, "refusing to write through a symbolic link", path=clean)
    if target.exists() and not target.is_file():
        raise UnsafePathError(NOT_A_REGULAR_FILE, "destination exists and is not a regular file", path=clean)
    if not is_within(root_real, target):
        raise UnsafePathError(SYMLINK_ESCAPE, f"{clean!r} resolves outside the root", path=clean)
    descriptor, temp_name = tempfile.mkstemp(prefix=".science-gate-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        os.replace(temp_name, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
        raise
    return target


def safe_read(root: str | os.PathLike[str], relpath: str, *, max_bytes: int | None = None) -> bytes:
    """Read a regular file under ``root``, refusing escapes and oversize files.

    A missing file raises :class:`FileNotFoundError`, which is deliberately not
    a :class:`SafeIOError`: absence is a fact about the evidence, not a safety
    violation, and callers must be able to report it as MISSING.
    """
    path = resolve_under_root(root, relpath)
    info = path.stat()
    clean = normalize_relpath(relpath)
    if not stat.S_ISREG(info.st_mode):
        raise UnsafePathError(NOT_A_REGULAR_FILE, "not a regular file", path=clean)
    if max_bytes is not None and info.st_size > max_bytes:
        raise SafeIOError(FILE_TOO_LARGE, f"{info.st_size} bytes exceeds the {max_bytes}-byte limit", path=clean)
    with open(path, "rb") as handle:
        data = handle.read() if max_bytes is None else handle.read(max_bytes + 1)
    if max_bytes is not None and len(data) > max_bytes:
        raise SafeIOError(FILE_TOO_LARGE, f"file grew beyond the {max_bytes}-byte limit while reading", path=clean)
    return data

