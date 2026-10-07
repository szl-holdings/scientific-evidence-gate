"""The one process-wide audit hook, gated by recording contexts (ARCHITECTURE.md 17.6, decision D10).

Why a hook at all: a checker that edits a pinned file and then restores its
bytes leaves every digest unchanged, so re-hashing after the run cannot see
the edit. CPython's audit events report each ``open`` with its mode, and each
rename, delete and truncation, at the moment it happens. Recording them is
what turns "the bytes are the same" into "nobody wrote to the file".

Why exactly one hook, installed once: ``sys.addaudithook`` hooks can never be
removed, and every installed hook runs for every audited event in the
process. So :func:`install` adds a single hook, idempotently, and that hook
returns at once unless a :func:`recording` context is active in the current
context. Code that never asks to be watched pays one ``ContextVar`` lookup per
audited event and nothing else.

Recorders nest. Each :func:`recording` adds a recorder to a ``ContextVar``
tuple for the duration of its ``with`` block, and every active recorder sees
the events that match its own filters. The verifier watches its pinned files,
while the mutation harness watches a whole mutant tree and also asks for value
reads, which :class:`RecordingMapping` reports per check.

Known blind spot, stated in every report: I/O done by a subprocess, or by a C
extension that bypasses the audited Python APIs, is invisible here.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterable

__all__ = [
    "READ",
    "WRITE",
    "DELETE",
    "RENAME",
    "FileEvent",
    "ValueRead",
    "AuditRecorder",
    "install",
    "installed",
    "recording",
    "current_check",
    "active_check",
    "values_requested",
    "RecordingMapping",
    "normalize_path",
]

READ = "read"
WRITE = "write"
DELETE = "delete"
RENAME = "rename"

#: ``os.open`` flags that make an open a write. The mode string covers
#: ``builtins.open``; the flags cover ``os.open``, whose audit event has no mode.
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
_WRITE_MODE_CHARACTERS = frozenset("wax+")


@dataclass(frozen=True)
class FileEvent:
    """One audited file operation: the absolute, case-normalized path, what was done, and the audit event."""

    path: str
    action: str
    event: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "action": self.action, "event": self.event}


@dataclass(frozen=True)
class ValueRead:
    """One cell a check read: which check, which input, which row (1-based record index), which column."""

    check_id: str
    input_id: str
    row_index: int
    column: str

    def to_dict(self) -> dict[str, Any]:
        return {"check_id": self.check_id, "input_id": self.input_id, "row_index": self.row_index, "column": self.column}


def normalize_path(path: str | os.PathLike[str], *, resolve: bool = False) -> str:
    """The form every path is compared in: absolute and ``os.path.normcase``d.

    ``resolve`` follows symlinks too. It is used for the paths a recorder
    watches, never inside the hook, where resolving could itself trigger
    audited operations.
    """
    text = os.fsdecode(os.fspath(path))
    text = os.path.realpath(text) if resolve else os.path.abspath(text)
    return os.path.normcase(text)


class AuditRecorder:
    """Collects the file events and value reads that match its filters while its context is active.

    ``watch`` names files and ``under`` names directory prefixes. A recorder
    with neither filter records every file event, which is useful only in
    tests. Value reads are recorded only when ``record_values`` is set.
    ``errors`` counts events the hook could not interpret; a non-zero value
    means some operation may have gone unrecorded.
    """

    def __init__(
        self,
        watch: Iterable[str | os.PathLike[str]] = (),
        under: Iterable[str | os.PathLike[str]] = (),
        record_values: bool = False,
    ) -> None:
        watched: set[str] = set()
        for item in watch:
            # Both spellings: the hook sees paths as callers wrote them, unresolved.
            watched.add(normalize_path(item))
            watched.add(normalize_path(item, resolve=True))
        prefixes: set[str] = set()
        for item in under:
            prefixes.add(normalize_path(item))
            prefixes.add(normalize_path(item, resolve=True))
        self.watch = frozenset(watched)
        self.under = tuple(sorted(prefixes))
        self.record_values = record_values
        self.errors = 0
        self._events: list[FileEvent] = []
        self._value_reads: list[ValueRead] = []
        self._lock = threading.Lock()

    @property
    def events(self) -> tuple[FileEvent, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def writes(self) -> tuple[FileEvent, ...]:
        """Every event that is not a read: writes, deletes and renames."""
        return tuple(event for event in self.events if event.action != READ)

    @property
    def value_reads(self) -> tuple[ValueRead, ...]:
        with self._lock:
            return tuple(self._value_reads)

    def _unfiltered(self) -> bool:
        return not self.watch and not self.under

    def _is_under(self, path: str) -> bool:
        return any(path == prefix or path.startswith(prefix.rstrip(os.sep) + os.sep) for prefix in self.under)

    def _offer(self, path: str, action: str, event: str) -> None:
        if self._unfiltered() or path in self.watch or self._is_under(path):
            with self._lock:
                self._events.append(FileEvent(path, action, event))

    def _offer_tree(self, directory: str, event: str) -> None:
        """A directory tree removal: every watched file inside it counts as deleted."""
        prefix = directory.rstrip(os.sep) + os.sep
        affected = sorted(path for path in self.watch if path == directory or path.startswith(prefix))
        with self._lock:
            self._events.extend(FileEvent(path, DELETE, event) for path in affected)
        if not affected and (self._unfiltered() or self._is_under(directory)):
            with self._lock:
                self._events.append(FileEvent(directory, DELETE, event))

    def _offer_value(self, read: ValueRead) -> None:
        if self.record_values:
            with self._lock:
                self._value_reads.append(read)


_RECORDERS: ContextVar[tuple[AuditRecorder, ...]] = ContextVar("science_gate_audit_recorders", default=())
_CURRENT_CHECK: ContextVar[str | None] = ContextVar("science_gate_current_check", default=None)
_INSTALL_LOCK = threading.Lock()
_INSTALLED = False
_REENTRY = threading.local()


def _path_of(value: Any) -> str | None:
    """An audited path argument as a comparable string, or None for a file descriptor or junk."""
    if isinstance(value, bool) or isinstance(value, int) or value is None:
        return None
    if not isinstance(value, (str, bytes, os.PathLike)):
        return None
    return normalize_path(value)


def _open_action(args: tuple[Any, ...]) -> list[tuple[str, str]]:
    path = _path_of(args[0]) if args else None
    if path is None:
        return []
    mode = args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 else None
    writes = (isinstance(mode, str) and bool(_WRITE_MODE_CHARACTERS & set(mode))) or (
        isinstance(flags, int) and not isinstance(flags, bool) and bool(flags & _WRITE_FLAGS)
    )
    return [(path, WRITE if writes else READ)]


def _remove(args: tuple[Any, ...]) -> list[tuple[str, str]]:
    # ``os.remove(path, dir_fd)``: a name relative to a directory descriptor
    # cannot be placed, so it is skipped; the enclosing operation (for
    # example ``shutil.rmtree``) is recorded instead. CPython reports an
    # absent descriptor as -1.
    dir_fd = args[1] if len(args) > 1 else None
    path = _path_of(args[0]) if args and dir_fd in (None, -1) else None
    return [] if path is None else [(path, DELETE)]


def _truncate(args: tuple[Any, ...]) -> list[tuple[str, str]]:
    # ``os.truncate(path_or_fd, length)``: only a path can be placed.
    path = _path_of(args[0]) if args else None
    return [] if path is None else [(path, WRITE)]


def _rename(args: tuple[Any, ...]) -> list[tuple[str, str]]:
    # ``os.rename`` and ``os.replace`` share this event: both ends changed.
    found = []
    for value in args[:2]:
        path = _path_of(value)
        if path is not None:
            found.append((path, RENAME))
    return found


def _copy_destination(args: tuple[Any, ...]) -> list[tuple[str, str]]:
    path = _path_of(args[1]) if len(args) > 1 else None
    return [] if path is None else [(path, WRITE)]


#: Audited events that touch files, mapped to how their arguments name paths.
_HANDLERS: Mapping[str, Callable[[tuple[Any, ...]], list[tuple[str, str]]]] = {
    "open": _open_action,
    "os.remove": _remove,
    "os.rename": _rename,
    "os.truncate": _truncate,
    "shutil.copyfile": _copy_destination,
}


def _hook(event: str, args: tuple[Any, ...]) -> None:
    """The installed hook. It must never raise: an exception here would abort the audited operation."""
    recorders = _RECORDERS.get()
    if not recorders:
        return
    if event != "shutil.rmtree" and event not in _HANDLERS:
        return
    if getattr(_REENTRY, "active", False):
        return
    _REENTRY.active = True
    try:
        if event == "shutil.rmtree":
            directory = _path_of(args[0]) if args else None
            if directory is not None:
                for recorder in recorders:
                    recorder._offer_tree(directory, event)
            return
        for path, action in _HANDLERS[event](args):
            for recorder in recorders:
                recorder._offer(path, action, event)
    except Exception:  # never propagate into the caller's open() or rename()
        for recorder in recorders:
            recorder.errors += 1
    finally:
        _REENTRY.active = False


def install() -> None:
    """Add the one process hook. Safe to call any number of times, from any thread."""
    global _INSTALLED
    with _INSTALL_LOCK:
        if not _INSTALLED:
            sys.addaudithook(_hook)
            _INSTALLED = True


def installed() -> bool:
    return _INSTALLED


@contextmanager
def recording(
    *,
    watch: Iterable[str | os.PathLike[str]] = (),
    under: Iterable[str | os.PathLike[str]] = (),
    record_values: bool = False,
) -> Iterator[AuditRecorder]:
    """Record matching file events (and optionally value reads) for the duration of the block.

    Installs the hook on first use. Nested blocks each get their own
    recorder; leaving a block removes only its recorder.
    """
    install()
    recorder = AuditRecorder(watch, under, record_values)
    token = _RECORDERS.set((*_RECORDERS.get(), recorder))
    try:
        yield recorder
    finally:
        _RECORDERS.reset(token)


@contextmanager
def current_check(check_id: str | None) -> Iterator[None]:
    """Attribute value reads inside the block to ``check_id`` (None: attribute them to nobody)."""
    token = _CURRENT_CHECK.set(check_id)
    try:
        yield
    finally:
        _CURRENT_CHECK.reset(token)


def active_check() -> str | None:
    """The check id value reads are currently attributed to."""
    return _CURRENT_CHECK.get()


def values_requested() -> bool:
    """True when some active recorder asked for value reads, so rows should be wrapped."""
    return any(recorder.record_values for recorder in _RECORDERS.get())


class RecordingMapping(Mapping[str, Any]):
    """A read-only row whose every value read is reported to recorders that asked for value reads.

    Reads are attributed to the check named by :func:`current_check`; reads
    outside any check (the engine preparing a falsifier, say) are not
    recorded, because they are not a check examining the cell. Membership
    tests and iteration over keys are not value reads.
    """

    __slots__ = ("_values", "_input_id", "_row_index")

    def __init__(self, values: Mapping[str, Any], input_id: str, row_index: int) -> None:
        self._values = values
        self._input_id = input_id
        self._row_index = row_index

    def __getitem__(self, key: str) -> Any:
        value = self._values[key]
        check_id = _CURRENT_CHECK.get()
        if check_id is not None:
            read = ValueRead(check_id, self._input_id, self._row_index, key)
            for recorder in _RECORDERS.get():
                recorder._offer_value(read)
        return value

    def __contains__(self, key: object) -> bool:
        return key in self._values

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"RecordingMapping(input_id={self._input_id!r}, row_index={self._row_index}, keys={list(self._values)!r})"
