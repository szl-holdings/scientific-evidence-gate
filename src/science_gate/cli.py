"""The ``science-gate`` command line (ARCHITECTURE.md sections 14 and 17.9).

Exit codes follow :data:`~science_gate.models.EXIT_CODE`: 0 PASS, 1 FAIL,
2 ABSTAIN, 3 ERROR. Argument errors exit 3, not argparse's usual 2, so that 2
always means ABSTAIN and a script can never mistake a typo for a verdict
(decision D3 keeps this scheme). Every command prints a one-line status
headline first and then the paths it wrote, one per line.

``--require-signature`` (on ``verify`` and ``report``) asks for more than a
verdict: the receipt's HMAC-SHA256 shared-key authenticator must verify with
the configured key. The run directory is still written or re-rendered as
usual, so nothing is lost, but unless re-checking the files on disk gives
``SIGNED_VERIFIED`` the headline is ``ERROR (PROTOCOL_BROKEN) <run_id>:
--require-signature: ...`` and the exit code is 3. That outcome stays inside
the 0-3 scheme and never borrows another status's code, while its headline
names the receipt's authentication status and the run's own status, so the
two are never confused.

``verify``, ``report`` and ``init`` are implemented here. ``mutate``,
``impact``, ``revalidate``, ``what-if``, ``package`` and ``demo`` belong to
their own modules. They are imported only when invoked, and each is called as
``function(args) -> int``; flags such as ``mutate --harness`` and
``revalidate --witness`` are parsed here and read by those functions. If a
module is missing, the command says so and exits 3.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence, TextIO

from . import __version__
from ._canonical import pretty_json_bytes, sha256_bytes
from ._redact import redaction_scope
from ._safeio import SafeIOError, safe_write
from ._validators import ExportValidationError
from .discovery import discover
from .manifests import MANIFEST_SCHEMA, load_manifest
from .models import EXIT_CODE, AuthStatus, Reason, Status
from .receipts import STATEMENT_FILE, ReceiptVerification, verify_receipt
from .reports import report_run_dir, write_run
from .verifier import build_snapshot, verify

__all__ = [
    "PROG",
    "DEFAULT_RUNS_DIR",
    "LAZY_COMMANDS",
    "TEMPLATE_CSV",
    "UsageError",
    "build_parser",
    "require_signature_headline",
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
        "what-if": "science_gate.dependencies:cli_what_if",
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


_REQUIRE_SIGNATURE_HELP = (
    "exit 3 with an ERROR (PROTOCOL_BROKEN) headline unless the receipt's HMAC-SHA256 shared-key authenticator "
    f"verifies with the key named by the environment (auth status {AuthStatus.SIGNED_VERIFIED.value}); "
    "the run's own status stays recorded"
)


def build_parser() -> argparse.ArgumentParser:
    """The argument parser for all nine subcommands."""
    parser = _Parser(
        prog=PROG,
        description=(
            "Local evidence gate: a passing check must emit enough evidence to prove it had the opportunity "
            "to fail. Exit codes: 0 PASS, 1 FAIL, 2 ABSTAIN, 3 ERROR (also usage errors and an unmet "
            "--require-signature)."
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
    run.add_argument("--require-signature", action="store_true", help=_REQUIRE_SIGNATURE_HELP)

    report = commands.add_parser("report", help="re-verify a run directory and re-render its reports")
    report.add_argument("run_dir", metavar="RUN_DIR")
    report.add_argument("--require-signature", action="store_true", help=_REQUIRE_SIGNATURE_HELP)

    mutate = commands.add_parser("mutate", help="mutation-test the verifier against a manifest")
    mutate.add_argument("manifest", metavar="MANIFEST")
    mutate.add_argument("--output", metavar="DIR")
    mutate.add_argument(
        "--harness", action="store_true", help="also mutate the mutation harness itself and report its sensitivity"
    )

    graph_commands = {
        "impact": "mark the descendants of an artifact stale",
        "revalidate": "revalidate an artifact",
        "what-if": "inject a synthetic change into an artifact and check that staleness detection reacts",
    }
    graph_parsers: dict[str, argparse.ArgumentParser] = {}
    for name, text in graph_commands.items():
        command = graph_parsers[name] = commands.add_parser(name, help=text)
        command.add_argument("artifact_id", metavar="ARTIFACT_ID")
        command.add_argument("--manifest", metavar="MANIFEST", required=True)
    graph_parsers["revalidate"].add_argument(
        "--witness", metavar="PATH", help="recompute witness that a derived artifact was re-executed, not re-hashed"
    )

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


def _emit_written(out: TextIO, headline: str, paths: Sequence[Path]) -> None:
    """The output every command shares: its headline, then each path it wrote."""
    _emit(out, headline)
    for path in paths:
        _emit(out, str(path))


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
    _emit_written(out, f"OK init: wrote a synthetic starter project; next: {PROG} verify {manifest}", paths)
    return 0


def require_signature_headline(verification: ReceiptVerification, *, run_id: str | None, recorded: str) -> str | None:
    """The headline for an unmet ``--require-signature``, or None when the receipt is SIGNED_VERIFIED.

    ``recorded`` finishes the line by saying where the command's own status
    is kept (for ``verify``, the run's status in run.json), so the reader
    sees that the run itself was not rewritten as ERROR. A missing or
    malformed sidecar has no auth status at all; the line then quotes the
    problem instead of inventing one. The result is always one line.
    """
    status = verification.auth_status
    if status is AuthStatus.SIGNED_VERIFIED:
        return None
    if status is None:
        cause = next(
            (problem for problem in verification.problems if not problem.startswith("SIGNATURE_REQUIRED")),
            "no usable authentication sidecar",
        )
        subject = f"the receipt's authentication could not be determined ({cause})"
    else:
        subject = f"the receipt is {status.value} ({verification.detail})"
    line = f"{Status.ERROR.value} ({Reason.PROTOCOL_BROKEN.value}) {run_id or 'unknown'}: --require-signature: "
    return " ".join(f"{line}{subject}; {recorded}".split())


def _cmd_verify(args: argparse.Namespace, out: TextIO) -> int:
    run = verify(args.manifest, live=args.live)
    output = Path(args.output) if args.output else Path(DEFAULT_RUNS_DIR) / run.result.run_id
    try:
        written = write_run(run, output)
    except ExportValidationError as exc:
        _emit(out, f"ERROR verify: export validation failed: {exc.problems[0]}")
        return _ERROR
    except (SafeIOError, OSError) as exc:
        _emit(out, f"ERROR verify: the {run.status.value} result could not be written to {output}: {exc}")
        return _ERROR
    if args.require_signature:
        # Judge the files as written, not the record in memory: that is what a later reader will have.
        headline = require_signature_headline(
            verify_receipt(written.run_dir / STATEMENT_FILE, require_signature=True),
            run_id=run.result.run_id,
            recorded=f"the run's own status {written.status.value} is recorded in run.json",
        )
        if headline is not None:
            _emit_written(out, headline, written.paths)
            return _ERROR
    _emit_written(out, written.headline, written.paths)
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
    if args.require_signature:
        verification = verify_receipt(run_dir / STATEMENT_FILE, require_signature=True)
        headline = require_signature_headline(
            verification,
            run_id=verification.run_id,
            recorded=f"the report's own status {written.status.value} is recorded in report.md",
        )
        if headline is not None:
            _emit_written(out, headline, written.paths)
            return _ERROR
    _emit_written(out, written.headline, written.paths)
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


def _discard(stream: TextIO) -> None:
    """Point a stream that can no longer be written at ``os.devnull``.

    The interpreter flushes the standard streams once more when it exits;
    without this, that flush meets the closed pipe again, prints "Exception
    ignored" and exits 120. A stream without a file descriptor (a test's
    stand-in) has nothing to redirect.
    """
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, descriptor)
    finally:
        os.close(devnull)


def _output_failed(command: str, failure: Exception, out: TextIO, err: TextIO) -> int:
    """Exit 3 when standard output stopped accepting lines, as in ``science-gate demo | head -1``.

    The command may have reached its verdict and written its files, but its
    headline and paths were not all delivered, so the outcome is ERROR. Left
    alone, a BrokenPipeError would end the process with Python's own exit 1,
    which here means FAIL. One line on standard error names the cause.
    """
    _discard(out)
    reason = getattr(failure, "strerror", None) or str(failure) or type(failure).__name__
    try:
        _emit(err, f"ERROR {command}: standard output stopped accepting lines ({reason}); exit {_ERROR}")
        err.flush()
    except (OSError, ValueError):
        _discard(err)  # standard error went too; the exit code is the only report left
    return _ERROR


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
            code = _HANDLERS[args.command](args, out)
        # Deliver buffered lines now, so a reader that has gone is met here, not at interpreter exit.
        out.flush()
        return code
    except Exception as exc:  # the last line of defence: an exit code and a message, never a traceback
        try:
            _emit(out, f"ERROR {args.command}: internal error ({type(exc).__name__}: {exc})")
            out.flush()
        except (OSError, ValueError) as failure:
            # Standard output itself cannot be written: its reader left (EPIPE, or EINVAL on Windows),
            # its file is full, or it was closed.
            return _output_failed(args.command, failure, out, err)
        return _ERROR


if __name__ == "__main__":
    raise SystemExit(main())
