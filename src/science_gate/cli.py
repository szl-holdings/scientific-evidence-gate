"""The ``science-gate`` command line (ARCHITECTURE.md section 14).

Exit codes follow :data:`~science_gate.models.EXIT_CODE`: 0 PASS, 1 FAIL,
2 ABSTAIN, 3 ERROR. Argument errors exit 3, not argparse's usual 2, so that 2
always means ABSTAIN and a script can never mistake a typo for a verdict.
Every command prints a one-line status headline first and then the paths it
wrote, one per line.

``verify``, ``report`` and ``init`` are implemented here. ``mutate``,
``impact``, ``revalidate``, ``package`` and ``demo`` belong to their own
modules. They are imported only when invoked, and each is called as
``function(args) -> int``. If a module is missing, the command says so and
exits 3.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence, TextIO

from . import __version__
from ._canonical import pretty_json_bytes, sha256_bytes
from ._redact import redaction_scope
from ._safeio import SafeIOError, safe_write
from .discovery import discover
from .manifests import MANIFEST_SCHEMA, load_manifest
from .models import EXIT_CODE, Status
from .reports import report_run_dir, write_run
from .verifier import build_snapshot, verify

__all__ = [
    "PROG",
    "DEFAULT_RUNS_DIR",
    "LAZY_COMMANDS",
    "TEMPLATE_CSV",
    "UsageError",
    "build_parser",
    "template_manifest",
    "scaffold_project",
    "main",
]

PROG = "science-gate"

#: ``verify`` writes to ``./science-gate-runs/<run_id>/`` unless ``--output`` is given.
DEFAULT_RUNS_DIR = "science-gate-runs"

#: Commands implemented elsewhere, as ``"module:function"`` taking ``(args) -> int``.
LAZY_COMMANDS: Mapping[str, str] = MappingProxyType(
    {
        "mutate": "science_gate.mutations:cli_mutate",
        "impact": "science_gate.dependencies:cli_impact",
        "revalidate": "science_gate.dependencies:cli_revalidate",
        "package": "science_gate.packaging:cli_package",
        "demo": "science_gate.demo:cli_demo",
    }
)

_ERROR = EXIT_CODE[Status.ERROR]

#: The starter project's data: six invented samples at three invented sites.
#: The values exercise the numeric rules (a trailing zero, a half-even tie,
#: grouped thousands) and mean nothing.
TEMPLATE_CSV = (
    "sample_id,site,value,count\n"
    'SYN-0001,site-alpha,12.40,"1,234"\n'
    "SYN-0002,site-alpha,0.14,7\n"
    "SYN-0003,site-beta,3.5,12\n"
    'SYN-0004,site-beta,27.125,"2,048"\n'
    "SYN-0005,site-gamma,8.00,301\n"
    'SYN-0006,site-gamma,15.55,"10,500"\n'
)


class UsageError(Exception):
    """A command-line argument error. It exits 3 because 2 means ABSTAIN."""


class _Parser(argparse.ArgumentParser):
    """An ``ArgumentParser`` that raises :class:`UsageError` instead of exiting 2."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(f"{self.prog}: {message}")


def build_parser() -> argparse.ArgumentParser:
    """The argument parser for all eight subcommands."""
    parser = _Parser(
        prog=PROG,
        description=(
            "Local evidence gate: a passing check must emit enough evidence to prove it had the opportunity "
            "to fail. Exit codes: 0 PASS, 1 FAIL, 2 ABSTAIN, 3 ERROR."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    init = commands.add_parser("init", help="create a synthetic starter project in PATH (never overwrites)")
    init.add_argument("path", metavar="PATH")

    run = commands.add_parser("verify", help="verify a manifest and write a run directory")
    run.add_argument("manifest", metavar="MANIFEST")
    run.add_argument("--output", metavar="DIR", help=f"run directory (default ./{DEFAULT_RUNS_DIR}/<run_id>/)")
    run.add_argument("--live", action="store_true", help="allow live network lookups (off by default)")

    report = commands.add_parser("report", help="re-verify a run directory and re-render its reports")
    report.add_argument("run_dir", metavar="RUN_DIR")

    mutate = commands.add_parser("mutate", help="mutation-test the verifier against a manifest")
    mutate.add_argument("manifest", metavar="MANIFEST")
    mutate.add_argument("--output", metavar="DIR")

    graph_commands = (("impact", "mark the descendants of an artifact stale"), ("revalidate", "revalidate an artifact"))
    for name, text in graph_commands:
        command = commands.add_parser(name, help=text)
        command.add_argument("artifact_id", metavar="ARTIFACT_ID")
        command.add_argument("--manifest", metavar="MANIFEST", required=True)

    package = commands.add_parser("package", help="package an evaluation for local execution")
    package.add_argument("manifest", metavar="MANIFEST")
    package.add_argument("--output", metavar="PATH", required=True)
    package.add_argument("--force", action="store_true", help="replace existing output")

    demo = commands.add_parser("demo", help="run the synthetic demonstration")
    demo.add_argument("--output", metavar="DIR")
    return parser


def _emit(stream: TextIO, text: str) -> None:
    """Write one line, escaping what the stream's encoding cannot represent.

    A Windows console or pipe may use a legacy code page. A path with an
    unencodable character must not turn a verdict into a traceback.
    """
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")


def template_manifest(csv_sha256: str) -> dict[str, Any]:
    """The starter manifest: the five built-in input checks over :data:`TEMPLATE_CSV`."""
    measurements = ["measurements"]
    return {
        "schema": MANIFEST_SCHEMA,
        "run_label": "synthetic-starter",
        "inputs": [
            {
                "id": "measurements",
                "path": "data/measurements.csv",
                "format": "csv",
                "required": True,
                "sha256": csv_sha256,
                "row_key": ["sample_id"],
                "expected_rows": 6,
                "denominator_source": "INDEPENDENT",
            }
        ],
        "accepted_snapshot": "snapshots/accepted.json",
        "checks": [
            {"id": "rows", "kind": "row_count", "version": "1", "required": True, "inputs": measurements},
            {
                "id": "columns",
                "kind": "required_columns",
                "version": "1",
                "required": True,
                "inputs": measurements,
                "params": {"columns": ["sample_id", "site", "value", "count"]},
            },
            {"id": "duplicates", "kind": "duplicate_rows", "version": "1", "required": True, "inputs": measurements},
            {
                "id": "snapshot",
                "kind": "snapshot_completeness",
                "version": "1",
                "required": True,
                "inputs": measurements,
            },
            {
                "id": "values",
                "kind": "numeric_agreement",
                "version": "1",
                "required": True,
                "inputs": measurements,
                "params": {
                    "column": "value",
                    "expected": [
                        {"key": "SYN-0001", "value": "12.4"},
                        {"key": "SYN-0002", "value": "0.1"},
                        {"key": "SYN-0004", "value": "27.12"},
                    ],
                },
            },
            {
                "id": "counts",
                "kind": "numeric_agreement",
                "version": "1",
                "required": True,
                "inputs": measurements,
                "params": {
                    "column": "count",
                    "thousands": ",",
                    "expected": [{"key": "SYN-0001", "value": "1234"}, {"key": "SYN-0006", "value": "10,500"}],
                },
            },
        ],
        "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
    }


def scaffold_project(target: str | Path) -> tuple[Path, ...]:
    """Write the synthetic starter project into ``target`` and return the paths written.

    The accepted snapshot is computed from the data by the same code that
    checks it (:func:`~science_gate.verifier.build_snapshot`), so a fresh
    project verifies as PASS. Callers must refuse a non-empty ``target``
    first: this function writes, it does not decide.
    """
    root = Path(target)
    data = TEMPLATE_CSV.encode("utf-8")
    paths = [
        safe_write(root, "data/measurements.csv", data),
        safe_write(root, "manifest.json", pretty_json_bytes(template_manifest(sha256_bytes(data)))),
    ]
    _, opened = discover(load_manifest(root / "manifest.json"))
    paths.append(safe_write(root, "snapshots/accepted.json", pretty_json_bytes(build_snapshot(opened.values()))))
    return tuple(paths)


def _cmd_init(args: argparse.Namespace, out: TextIO) -> int:
    target = Path(args.path)
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        _emit(out, f"ERROR init: {target} exists and is not an empty directory; refusing to overwrite")
        return _ERROR
    paths = scaffold_project(target)
    manifest = target / "manifest.json"
    _emit(out, f"OK init: wrote a synthetic starter project; next: {PROG} verify {manifest}")
    for path in paths:
        _emit(out, str(path))
    return 0


def _cmd_verify(args: argparse.Namespace, out: TextIO) -> int:
    run = verify(args.manifest, live=args.live)
    output = Path(args.output) if args.output else Path(DEFAULT_RUNS_DIR) / run.result.run_id
    try:
        written = write_run(run, output)
    except (SafeIOError, OSError) as exc:
        _emit(out, f"ERROR verify: the {run.status.value} result could not be written to {output}: {exc}")
        return _ERROR
    _emit(out, written.headline)
    for path in written.paths:
        _emit(out, str(path))
    return written.exit_code


def _cmd_report(args: argparse.Namespace, out: TextIO) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        _emit(out, f"ERROR report: {run_dir} is not a run directory")
        return _ERROR
    try:
        written = report_run_dir(run_dir)
    except (SafeIOError, OSError) as exc:
        _emit(out, f"ERROR report: cannot write the re-rendered report into {run_dir}: {exc}")
        return _ERROR
    _emit(out, written.headline)
    for path in written.paths:
        _emit(out, str(path))
    return written.exit_code


def _cmd_lazy(args: argparse.Namespace, out: TextIO) -> int:
    """Import the owning module now and call ``function(args) -> int``."""
    module_name, _, function_name = LAZY_COMMANDS[args.command].partition(":")
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        missing = module_name if exc.name == module_name else f"{exc.name} (needed by {module_name})"
        _emit(out, f"ERROR {args.command}: module {missing} is not installed in this build")
        return _ERROR
    function = getattr(module, function_name, None)
    if not callable(function):
        _emit(out, f"ERROR {args.command}: {module_name} does not provide {function_name}()")
        return _ERROR
    try:
        code = function(args)
    except NotImplementedError as exc:
        _emit(out, f"ERROR {args.command}: not implemented yet ({exc})")
        return _ERROR
    if isinstance(code, bool) or code not in set(EXIT_CODE.values()):
        _emit(out, f"ERROR {args.command}: {module_name}.{function_name}() returned {code!r}, not an exit code")
        return _ERROR
    return code


_HANDLERS: Mapping[str, Callable[[argparse.Namespace, TextIO], int]] = MappingProxyType(
    {"init": _cmd_init, "verify": _cmd_verify, "report": _cmd_report, **{name: _cmd_lazy for name in LAZY_COMMANDS}}
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its exit code. ``--help`` and ``--version`` exit 0 via SystemExit."""
    out, err = sys.stdout, sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        _emit(err, f"ERROR usage: {exc}")
        _emit(err, f"run '{PROG} --help' for the commands; argument errors exit {_ERROR}, never 2 (2 means ABSTAIN)")
        return _ERROR
    try:
        # Every command redacts what it prints and writes; read the environment's secrets once for all of it.
        with redaction_scope():
            return _HANDLERS[args.command](args, out)
    except Exception as exc:  # the last line of defence: an exit code and a message, never a traceback
        _emit(out, f"ERROR {args.command}: internal error ({type(exc).__name__}: {exc})")
        return _ERROR


if __name__ == "__main__":
    raise SystemExit(main())
