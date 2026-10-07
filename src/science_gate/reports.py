"""Run directories: writing them, re-verifying them and rendering them (sections 12, 17.9 and 17.10).

``verify`` writes one directory per run. Every file is written through
:func:`~science_gate._safeio.safe_write`:

* ``run.json``: the machine-readable run, with the PASS-contract fields at
  top level and the checker ``controls`` (PLAN, falsifier witnesses, canary,
  comparator self-test, pins) beside them;
* ``report.md``: the human report, opening with the nine contract headings;
* ``ledger.jsonl``: the execution ledger, canonical JSON Lines;
* ``evidence-manifest.json``: one entry per piece of evidence, with its
  SHA-256, in canonical JSON (the bytes that were hashed appear verbatim);
* ``receipt.json`` and ``receipt.auth.json``: the receipt statement and its
  authentication sidecar (:mod:`science_gate.receipts`);
* ``results.sarif``: SARIF 2.1.0;
* ``report.html``: written only when ``science_gate._html`` is installed.
  Otherwise the report says it was not written.

Three rules shape the writer.

**Reporters that can fail** (extension #12, D7). Every export is built in
memory and judged by :mod:`science_gate._validators` against ``run.json``
before anything touches the disk. A problem raises
:class:`ExportValidationError` and nothing is written: a report that
contradicts its own run is never published.

**Atomic finalization** (G4). The files are written into a staging sibling,
``<parent>/.<name>.incomplete``, which is then renamed onto the output path.
An interrupted run (a full disk, say) therefore never leaves a
verdict-bearing ``report.md`` without its ``run.json``: the output path
either holds the whole run or does not exist. An existing non-empty output
directory is refused (``OUTPUT_EXISTS``), so one run never overwrites part
of another. Readers refuse a directory without ``run.json``, or one named
``*.incomplete``, as ``RUN_INCOMPLETE`` and never render its verdict.

**One name per quantity** (G5). ``report.md`` names the run's
``rows_examined`` (distinct data rows of declared inputs) once, in the one
wording :func:`~science_gate._validators.rows_examined_line` defines. A
check's own figure counts its subject records and is called that, on that
check's line only. No per-check sum is computed.

Reports are rendered from the ``run.json`` document alone, never from live
objects. ``science-gate report RUN_DIR`` can therefore re-render a recorded
run exactly as ``verify`` rendered it. First it re-verifies the receipt, the
ledger chain and the stored exports. Then it checks that every figure in
``run.json`` is one the receipt attests (see :func:`implied_predicate`), that
every check result matches its terminal ledger entry, and that
``results.sarif`` is exactly the log ``run.json`` derives. If any of that
fails, the recorded status is not trusted: the report says so, with status
ERROR.

The HTML renderer contract is ``science_gate._html.render(document) -> str``,
and ``render(document, mutation)`` for the page ``mutate`` writes.
``document`` is the ``run.json`` content as a dict, not a live object, so that
``verify`` and ``report RUN_DIR`` render from the same input. For a
re-rendered run it also carries ``reverification``. A run that failed
re-verification is passed with status ERROR, and its recorded status is kept
as ``recorded_status``.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import re
import shutil
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote

from . import TOOL_NAME, __version__
from ._canonical import (
    CanonicalizationError,
    StrictJSONError,
    canonical_bytes,
    pretty_json_bytes,
    sha256_canonical,
    strict_loads,
)
from ._redact import redact, redact_text
from ._safeio import SYMLINK_TARGET, SafeIOError, UnsafePathError, resolve_under_root, safe_read, safe_write
from ._validators import (
    REPORT_HEADINGS,
    REPORT_MD,
    RESULTS_SARIF,
    RUN_JSON,
    ExportValidationError,
    rows_examined_line,
    sarif_classification,
    validate_exports,
)
from .dependencies import STATE_ROLE as GRAPH_STATE_ROLE
from .invariants import (
    InvariantContext,
    every_invocation_has_terminal_result,
    every_verdict_has_invocation,
    ledger_chain_intact,
)
from .ledger import LedgerFormatError, parse_jsonl
from .models import EXIT_CODE, TERMINAL_INVOCATION_RESULTS, CheckResult, InvariantResult, Reason, Status
from .receipts import AUTH_FILE, STATEMENT_FILE, build_run_receipt, receipt_files, verify_receipt
from .verifier import VerificationRun, ledger_evidence

__all__ = [
    "RUN_SCHEMA",
    "RUN_JSON",
    "REPORT_MD",
    "LEDGER_JSONL",
    "EVIDENCE_MANIFEST_JSON",
    "RECEIPT_JSON",
    "RECEIPT_AUTH_JSON",
    "RESULTS_SARIF",
    "REPORT_HTML",
    "RUN_FILES",
    "REPORT_HEADINGS",
    "PASS_CONTRACT_FIELDS",
    "SARIF_VERSION",
    "SARIF_SCHEMA",
    "HTML_RENDERER",
    "INCOMPLETE_SUFFIX",
    "OUTPUT_EXISTS",
    "RUN_INCOMPLETE",
    "SARIF_NOT_DERIVED",
    "ExportValidationError",
    "WrittenRun",
    "Reverification",
    "run_document",
    "implied_predicate",
    "headline",
    "render_report",
    "sarif_classification",
    "build_sarif",
    "render_html",
    "write_run",
    "reverify_run_dir",
    "report_run_dir",
]

RUN_SCHEMA = "science-gate-run/v1"
LEDGER_JSONL = "ledger.jsonl"
EVIDENCE_MANIFEST_JSON = "evidence-manifest.json"
RECEIPT_JSON = STATEMENT_FILE
RECEIPT_AUTH_JSON = AUTH_FILE
REPORT_HTML = "report.html"
#: Every file a run directory can hold, in the contract's table order.
RUN_FILES = (
    RUN_JSON,
    REPORT_MD,
    LEDGER_JSONL,
    EVIDENCE_MANIFEST_JSON,
    RECEIPT_JSON,
    RECEIPT_AUTH_JSON,
    RESULTS_SARIF,
    REPORT_HTML,
)

#: Fields ``run.json`` carries at top level (section 6).
PASS_CONTRACT_FIELDS = (
    "status",
    "run_id",
    "expected_inputs",
    "inputs_discovered",
    "inputs_opened",
    "rows_examined",
    "checks_expected",
    "checks_executed",
    "checks_passed",
    "checks_failed",
    "checks_abstained",
    "evidence_manifest_sha256",
    "started_at",
    "completed_at",
)

SARIF_VERSION = "2.1.0"
#: A schema identifier for SARIF consumers. It is a name only: nothing is ever fetched from it.
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
HTML_RENDERER = "science_gate._html"

#: Marks a staging directory or a staged file that is not (yet) a finished run (G4).
INCOMPLETE_SUFFIX = ".incomplete"
#: ``write_run`` never writes over an existing non-empty directory.
OUTPUT_EXISTS = "OUTPUT_EXISTS"
#: A directory without ``run.json``, or a staging directory: never rendered as a run.
RUN_INCOMPLETE = "RUN_INCOMPLETE"
#: ``results.sarif`` is not the SARIF log its ``run.json`` derives.
SARIF_NOT_DERIVED = "SARIF_NOT_DERIVED"

#: ``run.json`` fields that must equal the receipt predicate's fields of the
#: same name. The nested ones are projected by :func:`implied_predicate`.
_ATTESTED_FIELDS = (
    "run_id",
    "status",
    "reason",
    "reasons",
    "failure_modes",
    "started_at",
    "completed_at",
    "counters",
    "ledger_head_sha256",
    "ledger_length",
    "evidence_manifest_sha256",
    "tool",
)
_ATTESTED_INPUT_FIELDS = ("id", "path", "required", "state", "sha256", "bytes", "rows")
_ATTESTED_CHECK_FIELDS = (
    "check_id",
    "kind",
    "version",
    "required",
    "execution_state",
    "verdict",
    "reason",
    "rows_examined",
    "invocation_id",
)
_ATTESTED_INVARIANT_FIELDS = ("name", "applicable", "holds")
_TERMINAL_RESULTS = frozenset(result.value for result in TERMINAL_INVOCATION_RESULTS)
#: A tuple, not a set: a tampered run.json may hold an unhashable value where
#: a status belongs, and a membership test must not raise on it.
_STATUS_VALUES = tuple(status.value for status in Status)

#: Run files are summaries; this bounds what re-verification will read.
MAX_RUN_FILE_BYTES = 256 * 1024 * 1024

#: Pauses between attempts to rename a finished staging directory into place.
#: On Windows another process (a virus scanner, a search indexer) may briefly
#: hold a file that was just written, and a directory holding an open file
#: cannot be renamed. The rename is retried a few times before it is reported.
_RENAME_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4)

_CHECK_PURPOSES: Mapping[str, str] = {
    "row_count": "Rows examined > 0, with closure against an INDEPENDENT expected_rows.",
    "required_columns": "Declared columns are present.",
    "duplicate_rows": "No exact duplicates and no duplicate row_key.",
    "snapshot_completeness": "Rows accepted in the snapshot are still present and unchanged.",
    "numeric_agreement": "Declared values agree with stored values, rounding- and separator-aware.",
    "reviewer_protocol": "All required reviewers present, no duplicate verdicts.",
    "time_source": "Declared timezone and normalized UTC exist, agree, and fall inside the window.",
    "verification_log": "Claimed verifications are backed by invocation records.",
    "citation_resolver": "DOIs resolve in the frozen record set; live lookups, when enabled, only fill its gaps.",
    "citation_metadata": "Citation metadata matches the resolved records.",
    "claim_registry": "Manuscript numbers are registered claims with a derivation.",
    "dependency_currency": "No stale dependency blocks publication.",
    "summary_consistency": "A stored PASS summary matches what was recomputed.",
    "claim_join": "Each asserted action cites a terminal invocation of a sealed run that backs it.",
    "editorial_status": "Cited works carry no retraction or other editorial notice within the consulted channels.",
    "mutation_accounting": "A mutation report's buckets account for every generated mutant.",
}

_FINDING_RULES: Mapping[str, str] = {
    "manifest": "The manifest must be valid and safe.",
    "input": "Every required input must be present, readable, parsed and match any declared digest.",
    "contract": "The PASS contract's counting rules (section 6).",
    "invariant": "A named invariant over the ledger, results and accounting (section 4).",
}

#: Witness states in the order report.md lists them (section 17.5).
_WITNESS_STATES = ("WITNESSED", "REFUTED", "UNWITNESSED", "NO_CASE", "NO_GENERATOR")
#: The claim-join outcomes in the order report.md lists them (section 17.15).
_JOIN_OUTCOMES = ("BACKED", "NARRATED", "CONTRADICTED", "ORPHANED")


# ---------------------------------------------------------------------------
# The run document
# ---------------------------------------------------------------------------


def run_document(run: VerificationRun, receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The ``run.json`` document: the full RunResult plus everything the reports need.

    The PASS-contract fields sit at top level, beside the nested result.
    The evidence boundary is copied from the receipt body, so the run file
    and the receipt can never describe it differently.
    """
    result = run.result
    seal = run.ledger.seal()
    body = receipt["body"]
    manifest = run.manifest
    declared: dict[str, Any] = {"inputs": [], "checks": []}
    if manifest is not None:
        declared = {
            "inputs": [
                {
                    "id": spec.input_id,
                    "path": spec.path,
                    "format": spec.format,
                    "required": spec.required,
                    "sha256": spec.sha256,
                    "row_key": list(spec.row_key),
                    "expected_rows": spec.expected_rows,
                    "denominator_source": spec.denominator_source,
                }
                for spec in manifest.inputs
            ],
            "checks": [
                {
                    "id": spec.check_id,
                    "kind": spec.kind,
                    "version": spec.version,
                    "required": spec.required,
                    "inputs": list(spec.inputs),
                    "params": spec.params,
                }
                for spec in manifest.checks
            ],
        }
    document = {
        **result.to_dict(),
        **{name: result.counters.get(name) for name in PASS_CONTRACT_FIELDS if name in result.counters},
        "schema": RUN_SCHEMA,
        "exit_code": result.exit_code,
        "findings": [finding.to_dict() for finding in run.findings],
        "ledger_head_sha256": seal["ledger_head_sha256"],
        "ledger_length": seal["ledger_length"],
        "manifest": {
            "file": run.manifest_name,
            "sha256": run.manifest_sha256,
            "run_label": manifest.run_label if manifest is not None else None,
            "issues": redact([issue.to_dict() for issue in run.manifest_issues]),
        },
        # Declared params and document diagnostics quote manifest text verbatim;
        # everything else here was redacted when it was recorded.
        "declared": redact(declared),
        "documents": redact(list(run.documents)),
        "claim_tallies": [
            {"check_id": check_id, "subject": tally.subject, "claimed": tally.claimed, "invocations": tally.invocations}
            for check_id, tally in run.claim_tallies
        ],
        "network": run.network.to_dict(),
        "receipt": {
            "content_sha256": receipt["content_sha256"],
            "signature_state": receipt["signature_state"],
            "key_id": receipt["key_id"],
        },
        "evidence_boundary": body["evidence_boundary"],
        "disclaimer": body["disclaimer"],
        "tool": {"name": TOOL_NAME, "version": __version__},
    }
    # Normalizing turns enums, Decimals and mapping proxies into JSON values,
    # exactly as they will read back from run.json.
    return strict_loads(canonical_bytes(document), integers_only=True)


def implied_predicate(document: Mapping[str, Any]) -> dict[str, Any]:
    """The receipt predicate that a ``run.json`` document implies.

    This mirrors :func:`science_gate.receipts.run_predicate`, but it reads the
    serialized run instead of a live result. When the projection equals the
    predicate in ``receipt.json``, every status, counter, input state, check
    verdict, evidence digest, invariant outcome and checker control that a
    re-rendered report shows is one the receipt attests. It works from the
    raw document rather than rebuilding model objects, because rebuilding
    would redact again under the current environment and could alter what
    was recorded.

    Raises KeyError, TypeError, AttributeError or ValueError when the
    document does not have the shape ``verify`` writes.
    """
    accounting = document["accounting"]
    return {
        **{name: document.get(name) for name in _ATTESTED_FIELDS},
        "controls_sha256": sha256_canonical(document["controls"]),
        "input_accounting": {"counters": accounting["counters"], "closure": accounting["closure"]},
        "inputs": [{name: item[name] for name in _ATTESTED_INPUT_FIELDS} for item in accounting["inputs"]],
        "checks": [
            {
                **{name: check[name] for name in _ATTESTED_CHECK_FIELDS},
                "evidence_sha256": sha256_canonical(check["evidence"]),
            }
            for check in document["checks"]
        ],
        "invariants": [{name: item[name] for name in _ATTESTED_INVARIANT_FIELDS} for item in document["invariants"]],
    }


def _known(value: Any) -> str:
    """Render a value for people. An unknown count reads "unknown", never 0."""
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def headline(document: Mapping[str, Any]) -> str:
    """The one-line status headline every command prints first."""
    return (
        f"{document.get('status')} ({document.get('reason')}) {document.get('run_id')}: "
        f"{_known(document.get('checks_executed'))}/{_known(document.get('checks_expected'))} required checks "
        f"executed, {_known(document.get('rows_examined'))} rows examined, "
        f"{_known(document.get('inputs_opened'))}/{_known(document.get('expected_inputs'))} inputs opened"
    )


# ---------------------------------------------------------------------------
# report.md
# ---------------------------------------------------------------------------

_WHITESPACE = re.compile(r"\s+")


def _md(value: Any) -> str:
    """One line of text: whitespace (newlines included) collapsed.

    Diagnostics can quote input content. Collapsing newlines keeps a crafted
    value from starting a line of its own, so it can never forge a heading.
    """
    return _WHITESPACE.sub(" ", _known(value)).strip()


def _code(value: Any) -> str:
    return "`" + _md(value).replace("`", "'") + "`"


def _bullets(items: Sequence[str], empty: str) -> list[str]:
    return [f"- {item}" for item in items] if items else [empty]


def _mapping(value: Any) -> Mapping[str, Any]:
    """``value`` when it is an object; otherwise an empty one, so absent reads as "not recorded"."""
    return value if isinstance(value, Mapping) else {}


def _ids(value: Any) -> list[str]:
    """A recorded id list as text items; anything that is not a list holds none."""
    return [_md(item) for item in value] if isinstance(value, list) else []


@dataclass(frozen=True)
class Reverification:
    """The result of re-checking a recorded run directory.

    ``ok`` is True only when every problem list is empty. ``notes`` records
    what could not be checked, such as an unsigned receipt or a signature
    without its key, so "not checked" is never mistaken for "good".
    """

    ok: bool
    problems: tuple[str, ...]
    notes: tuple[str, ...]
    receipt: Mapping[str, Any] | None
    ledger: Mapping[str, Any] | None
    invariants: tuple[InvariantResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "problems": list(self.problems),
            "notes": list(self.notes),
            "receipt": self.receipt,
            "ledger": self.ledger,
            "invariants": [item.to_dict() for item in self.invariants],
        }


def _transitions_text(value: Any) -> str:
    """The verdict lattice's log (#23): each rise, where it happened and what caused it."""
    if not isinstance(value, list):
        return "not recorded"
    if not value:
        return "no contribution was recorded, so the empty aggregate decided"
    steps = [
        f"{_md(item.get('before'))} -> {_md(item.get('after'))} at step {_known(item.get('step'))} "
        f"({_code(item.get('source'))}, {_md(item.get('reason'))})"
        for item in (_mapping(entry) for entry in value)
    ]
    return "; ".join(steps)


def _status_section(doc: Mapping[str, Any], reverification: Reverification | None) -> list[str]:
    status, reason = doc.get("status"), doc.get("reason")
    lines: list[str] = []
    if reverification is not None and not reverification.ok:
        lines += [
            f"**ERROR** ({Reason.PROTOCOL_BROKEN.value}), exit code {EXIT_CODE[Status.ERROR]}.",
            "",
            f"Re-verification of this run directory FAILED, so its recorded status ({_md(status)}) cannot be "
            "trusted. The recorded content below is shown only for inspection.",
            "",
        ]
    else:
        lines += [f"**{_md(status)}** ({_md(reason)}), exit code {_known(doc.get('exit_code'))}.", ""]
    receipt = _mapping(doc.get("receipt"))
    lines += _bullets(
        [
            f"Run: {_code(doc.get('run_id'))}",
            f"Started {_md(doc.get('started_at'))}; completed {_md(doc.get('completed_at'))}",
            f"Reasons: {', '.join(doc.get('reasons') or []) or 'none'}",
            f"Failure modes: {', '.join(doc.get('failure_modes') or []) or 'none'}",
            f"Verdict rises: {_transitions_text(_mapping(doc.get('controls')).get('verdict_transitions'))}",
            f"Evidence manifest sha256: {_code(doc.get('evidence_manifest_sha256'))}",
            f"Ledger: {_known(doc.get('ledger_length'))} entries, head {_ledger_head(doc)}",
            f"Receipt: content sha256 {_code(receipt.get('content_sha256'))}, {_md(receipt.get('signature_state'))}",
            "Scope: integrity and the declared evaluation only. Scientific validity is not established by this tool.",
        ],
        "",
    )
    return lines


def _expected_section(doc: Mapping[str, Any]) -> list[str]:
    manifest = _mapping(doc.get("manifest"))
    declared = _mapping(doc.get("declared"))
    lines = _bullets(
        [
            f"Manifest {_code(manifest.get('file'))}, sha256 {_code(manifest.get('sha256'))}, "
            f"run label {_code(manifest.get('run_label'))}"
        ],
        "",
    )
    if manifest.get("issues"):
        issues = [
            f"{_md(item.get('code'))} at {_code(item.get('pointer') or '/')}: {_md(item.get('message'))}"
            for item in manifest["issues"]
        ]
        lines += ["", "The manifest could not be used, so nothing further was expected:", ""]
        return lines + _bullets(issues, "")
    inputs = declared.get("inputs") or []
    lines += ["", f"Inputs declared: {len(inputs)} (expected_inputs {_known(doc.get('expected_inputs'))})", ""]
    lines += _bullets(
        [
            f"{_code(item.get('id'))}: {_code(item.get('path'))}, {_md(item.get('format'))}, "
            f"{'required' if item.get('required') else 'optional'}, expected_rows "
            f"{_known(item.get('expected_rows'))} ({_md(item.get('denominator_source'))}), declared sha256 "
            f"{_code(item.get('sha256'))}"
            for item in inputs
        ],
        "- none",
    )
    checks = declared.get("checks") or []
    required = sum(1 for item in checks if item.get("required"))
    summary = f"Checks declared: {len(checks)}, of which {required} required"
    lines += ["", f"{summary} (checks_expected {_known(doc.get('checks_expected'))})", ""]
    lines += _bullets(
        [
            f"{_code(item.get('id'))}: {_md(item.get('kind'))} v{_md(item.get('version'))}, "
            f"{'required' if item.get('required') else 'optional'}, inputs {_md(', '.join(item.get('inputs') or []))}"
            for item in checks
        ],
        "- none",
    )
    lines += [
        "",
        "PASS requires: every required input found, opened, parsed and matching any declared digest; at least one "
        "input opened; at least one data row examined; checks_executed == checks_expected; every required check "
        "PASS with a falsifier witness showing it could have failed; every applicable invariant holding; a "
        "non-empty evidence manifest.",
    ]
    return lines


def _closure_text(closure: Mapping[str, Any] | None) -> str:
    if not closure:
        return "closure unknown"
    holds = closure.get("holds")
    if holds is None:
        return f"closure not evaluable ({_md(closure.get('source'))} expectation)"
    verdict = "holds" if holds else "BROKEN"
    counts = f"{_known(closure.get('accounted'))} of {_known(closure.get('expected'))}"
    return f"closure {verdict} ({counts}, {_md(closure.get('source'))})"


def _examined_section(doc: Mapping[str, Any]) -> list[str]:
    accounting = _mapping(doc.get("accounting"))
    counters = _mapping(accounting.get("counters"))
    funnel = " -> ".join(
        f"{name} {_known(_mapping(counters.get(name)).get('value'))}"
        for name in ("expected", "discovered", "opened", "parsed", "examined")
    )
    lines = _bullets(
        [
            f"Input funnel: {funnel}; input {_closure_text(accounting.get('closure'))}",
            # G5: the run figure has one name, defined in one place.
            rows_examined_line(doc.get("rows_examined")),
            "Each check line under WHAT PASSED, WHAT FAILED and WHAT ABSTAINED gives that check's own subject "
            "records examined (its run.json checks[].rows_examined); those figures are not summed.",
        ],
        "",
    )
    lines += ["", "Inputs:", ""]
    records = []
    for item in accounting.get("inputs") or []:
        counts = item.get("row_counts") or {}
        dispositions = ("admitted", "excluded", "deferred", "unresolved", "failed")
        split = ", ".join(f"{name} {_known(counts.get(name))}" for name in dispositions)
        records.append(
            f"{_code(item.get('id'))} {_md(item.get('state'))}: {_code(item.get('path'))}, sha256 "
            f"{_code(item.get('sha256'))}, {_known(item.get('bytes'))} bytes, {_known(item.get('rows'))} records "
            f"({split}); row {_closure_text(item.get('closure'))}"
        )
    lines += _bullets(records, "- none")
    documents = [
        f"{_code(item.get('path'))} ({_md(', '.join(item.get('roles') or []))}): {_md(item.get('state'))}, "
        f"sha256 {_code(item.get('sha256'))}"
        for item in doc.get("documents") or []
    ]
    lines += ["", "Other documents read:", ""] + _bullets(documents, "- none")
    return lines


def _witness_text(check: Mapping[str, Any]) -> str:
    """A check's falsifier witness (#1): whether its PASS was shown able to fail."""
    evidence = _mapping(check.get("evidence"))
    state = evidence.get("falsification")
    if state is None:
        if check.get("verdict") == Status.PASS.value:
            return "falsifier witness not recorded"
        return "no falsifier ran (only a would-be PASS is falsified)"
    cases = [_mapping(case) for case in evidence.get("falsifiers") or []]
    rejected = sum(1 for case in cases if case.get("outcome") == "REJECTED")
    return f"falsifier witness {_md(state)} ({rejected} of {len(cases)} case(s) rejected as expected)"


def _plan_line(plan: Any) -> str:
    """The PLAN entry (#2): what was committed to before any check ran."""
    if not isinstance(plan, Mapping):
        return "PLAN: not recorded, so nothing shows what this run committed to before its checks ran"
    return (
        f"PLAN: ledger entry 1, entry sha256 {_code(plan.get('entry_sha256'))}, written before any check ran: "
        f"{_known(plan.get('inputs_planned'))} input(s), {_known(plan.get('checks_planned'))} check(s) and "
        f"{_known(plan.get('pins'))} pin(s) planned, manifest sha256 {_code(plan.get('manifest_sha256'))}"
    )


def _holds_text(control: Mapping[str, Any]) -> str:
    """Only a recorded ``holds: true`` reads as holding; anything else is said plainly."""
    holds = control.get("holds")
    if holds is True:
        return "holds"
    return "DOES NOT HOLD" if holds is False else "outcome not recorded"


def _comparator_line(control: Any) -> str:
    if not isinstance(control, Mapping):
        return "comparator self-test: not recorded"
    pairs = [_mapping(pair) for pair in control.get("pairs") or []]
    as_expected = sum(1 for pair in pairs if pair.get("actual") == pair.get("expected"))
    return (
        f"comparator self-test: invocation {_code(control.get('invocation_id'))}, {as_expected} of {len(pairs)} "
        f"known pair(s) compared as expected; {_holds_text(control)}"
    )


def _canary_line(control: Any) -> str:
    if not isinstance(control, Mapping):
        return "canary: not recorded"
    parts = []
    for name, expected in (("must_fail", Status.FAIL.value), ("must_pass", Status.PASS.value)):
        run = _mapping(control.get(name))
        parts.append(
            f"{name} invocation {_code(run.get('invocation_id'))} gave {_md(run.get('verdict'))} "
            f"({_md(run.get('reason'))}), expected {expected}"
        )
    return f"canary: {'; '.join(parts)}; {_holds_text(control)}"


def _pins_line(control: Any) -> str:
    if not isinstance(control, Mapping):
        return "harness pins: not recorded"
    changed = _ids(control.get("changed"))
    writes = [
        f"{_md(_mapping(item).get('action'))} {_code(_mapping(item).get('path'))}"
        for item in control.get("writes") or []
    ]
    return (
        f"harness pins: {_known(control.get('pinned'))} file(s) pinned; changed: {', '.join(changed) or 'none'}; "
        f"writes to pinned paths: {', '.join(writes) or 'none'}; {_holds_text(control)}"
    )


def _falsifiers_line(control: Any) -> str:
    if not isinstance(control, Mapping):
        return "falsifier witnesses: not recorded"
    states = []
    for state in _WITNESS_STATES:
        ids = control.get(state)
        if not isinstance(ids, list):
            states.append(f"{state} not recorded")
            continue
        states.append(f"{state} {len(ids)}" + (f" ({', '.join(_code(item) for item in ids)})" if ids else ""))
    return f"falsifier witnesses: {', '.join(states)}; {_known(control.get('invocations'))} falsifier invocation(s)"


def _claim_join_line(control: Any) -> str:
    if not isinstance(control, Mapping):
        return "claim-to-invocation join: no claim_join check ran"
    counts = ", ".join(f"{outcome} {_known(control.get(outcome))}" for outcome in _JOIN_OUTCOMES)
    return f"claim-to-invocation join: {counts}"


def _ran_section(doc: Mapping[str, Any]) -> list[str]:
    controls = _mapping(doc.get("controls"))
    lines = _bullets(
        [
            f"checks_executed {_known(doc.get('checks_executed'))} of checks_expected "
            f"{_known(doc.get('checks_expected'))} (required checks that reached CHECKED with a terminal invocation)",
            f"Ledger sealed at {_known(doc.get('ledger_length'))} entries, head {_ledger_head(doc)}",
            _plan_line(controls.get("plan")),
        ],
        "",
    )
    invocations = [
        f"{_code(check.get('check_id'))} ({_md(check.get('kind'))} v{_md(check.get('version'))}"
        f"{'' if check.get('required') else ', optional'}): invocation {_code(check.get('invocation_id'))}, "
        f"{_md(check.get('execution_state'))}, {_md(check.get('verdict'))}; {_witness_text(check)}"
        for check in doc.get("checks") or []
    ]
    lines += ["", "Invocations:", ""] + _bullets(invocations, "- none: no check was invoked")
    control_lines = [
        _comparator_line(controls.get("comparator_self_test")),
        _canary_line(controls.get("canary")),
        _pins_line(controls.get("pins")),
        _falsifiers_line(controls.get("falsifiers")),
        _claim_join_line(controls.get("claim_join")),
    ]
    lines += ["", "Controls (each its own invocation, never counted as a check):", ""]
    return lines + _bullets(control_lines, "")


def _check_line(check: Mapping[str, Any]) -> str:
    optional = "" if check.get("required") else " (optional)"
    diagnostics = "; ".join(_md(item) for item in check.get("diagnostics") or [])
    return (
        f"{_code(check.get('check_id'))}{optional}: {_md(check.get('kind'))} {_md(check.get('verdict'))} "
        f"({_md(check.get('reason'))}), subject records examined {_known(check.get('rows_examined'))}"
        + (f"; {diagnostics}" if diagnostics else "")
    )


def _finding_line(finding: Mapping[str, Any]) -> str:
    modes = ", ".join(finding.get("failure_modes") or [])
    return (
        f"[{_md(finding.get('source'))}] {_md(finding.get('status'))} {_md(finding.get('reason'))}"
        + (f" ({modes})" if modes else "")
        + f": {_md(finding.get('detail'))}"
    )


def _findings(doc: Mapping[str, Any], statuses: Sequence[str]) -> list[str]:
    """Run-level findings other than check results, which are listed per check beside them."""
    return [
        _finding_line(item)
        for item in doc.get("findings") or []
        if item.get("status") in statuses and not str(item.get("source", "")).startswith("check:")
    ]


def _ledger_head(doc: Mapping[str, Any]) -> str:
    """An empty ledger has no head. Say "none" rather than "unknown", because nothing is missing."""
    return "none (empty ledger)" if doc.get("ledger_length") == 0 else _code(doc.get("ledger_head_sha256"))


def _discrimination_line(value: Any) -> str:
    """The weakest numeric discrimination among PASS results (#3): how sharp the bluntest PASS was."""
    if not isinstance(value, Mapping):
        return "Weakest discrimination: no PASS result records a discrimination ratio"
    ratio = _mapping(value.get("ratio"))
    return (
        f"Weakest discrimination among PASS results: {_code(value.get('check_id'))} rejected "
        f"{_md(ratio.get('fraction'))} nearby claims (decimal {_md(ratio.get('decimal'))}, {_md(ratio.get('state'))})"
    )


def _passed_section(doc: Mapping[str, Any]) -> list[str]:
    checks = [_check_line(check) for check in doc.get("checks") or [] if check.get("verdict") == Status.PASS.value]
    holding = [
        f"{_code(item.get('name'))}: {_md(item.get('detail'))}"
        for item in doc.get("invariants") or []
        if item.get("applicable") and item.get("holds") is True
    ]
    discrimination = _discrimination_line(_mapping(doc.get("controls")).get("min_discrimination"))
    lines = ["Checks:", ""] + _bullets(checks, "- none") + ["", discrimination]
    return lines + ["", "Invariants that hold:", ""] + _bullets(holding, "- none")


def _failed_section(doc: Mapping[str, Any]) -> list[str]:
    checks = [
        _check_line(check)
        for check in doc.get("checks") or []
        if check.get("verdict") in (Status.FAIL.value, Status.ERROR.value)
    ]
    findings = _findings(doc, (Status.ERROR.value, Status.FAIL.value))
    return ["Findings:", ""] + _bullets(findings, "- none") + ["", "Checks:", ""] + _bullets(checks, "- none")


def _abstained_section(doc: Mapping[str, Any]) -> list[str]:
    checks = [_check_line(check) for check in doc.get("checks") or [] if check.get("verdict") == Status.ABSTAIN.value]
    findings = _findings(doc, (Status.ABSTAIN.value,))
    return ["Findings:", ""] + _bullets(findings, "- none") + ["", "Checks:", ""] + _bullets(checks, "- none")


def _unresolved_section(
    doc: Mapping[str, Any], html_note: str | None, reverification: Reverification | None
) -> list[str]:
    items: list[str] = []
    for record in _mapping(doc.get("accounting")).get("inputs") or []:
        if record.get("state") != "PARSED":
            required = "required" if record.get("required") else "optional"
            diagnostics = "; ".join(_md(text) for text in record.get("diagnostics") or [])
            items.append(f"{required} input {_code(record.get('id'))} is {_md(record.get('state'))}: {diagnostics}")
        closure = record.get("closure") or {}
        if closure.get("holds") is None:
            items.append(f"row closure of input {_code(record.get('id'))} not evaluated ({_md(closure.get('source'))})")
    for document in doc.get("documents") or []:
        if document.get("state") == "MISSING" and GRAPH_STATE_ROLE in (document.get("roles") or ()):
            # Normal for a graph no impact or revalidate command has touched yet.
            items.append(
                f"no saved graph state at {_code(document.get('path'))}: the graph's declared node states were used"
            )
        elif document.get("state") != "PARSED":
            state = f"{_md(document.get('state'))}: {_md(document.get('diagnostic'))}"
            items.append(f"document {_code(document.get('path'))} is {state}")
    for check in doc.get("checks") or []:
        if check.get("execution_state") != "CHECKED":
            items.append(f"check {_code(check.get('check_id'))} was {_md(check.get('execution_state'))}")
    for invariant in doc.get("invariants") or []:
        if not invariant.get("applicable"):
            items.append(f"invariant {_code(invariant.get('name'))} not applicable: {_md(invariant.get('detail'))}")
    receipt = _mapping(doc.get("receipt"))
    if receipt.get("signature_state") != "SIGNED_HMAC_SHA256":
        items.append(
            f"the receipt is UNSIGNED ({RECEIPT_AUTH_JSON} says so): its content hash detects accidental change, "
            "but anyone able to edit the run directory can rewrite and rehash it"
        )
    if reverification is not None:
        items += [_md(note) for note in reverification.notes]
    if html_note:
        items.append(_md(html_note))
    return _bullets(items, "- nothing")


def _not_proven_section(doc: Mapping[str, Any]) -> list[str]:
    boundary = _mapping(doc.get("evidence_boundary"))
    network = _mapping(doc.get("network"))
    live = network.get("live")
    return _bullets(
        [
            "Scientific validity: NOT ESTABLISHED. Whether any conclusion holds in its intended domain is outside "
            "what this tool can show.",
            f"Integrity (what was established): {_md(boundary.get('integrity'))}",
            f"Performance (how the checkers and the declared checks behaved): {_md(boundary.get('performance'))}",
            "A PASS shows only that the declared checks had the opportunity to fail on the declared inputs and did "
            "not. It says nothing about inputs, checks or questions that were not declared, and nothing about "
            "whether the declared expectations were the right ones.",
            "A falsifier witness shows that a checker rejected the known-bad cases constructed for it; it does not "
            "show that the checker rejects every defect.",
            "Write detection: the harness pins are watched by an in-process audit hook. File reads and writes made "
            "by a subprocess or by C-extension code are invisible to it, so pins that hold do not exclude changes "
            "made that way.",
            "Network: live lookups were enabled for this run." if live
            else "Network: no live lookup was performed; nothing was confirmed against an external source.",
            _md(doc.get("disclaimer")),
        ],
        "",
    )


def _files_section(files: Sequence[str]) -> list[str]:
    return _bullets([_code(name) for name in files], "- none")


def _reverification_section(reverification: Reverification) -> list[str]:
    receipt = reverification.receipt or {}
    ledger = reverification.ledger or {}
    lines = _bullets(
        [
            f"Result: {'PASSED' if reverification.ok else 'FAILED'}",
            f"Receipt: content intact {_known(receipt.get('content_intact'))}, signature "
            f"{_md(receipt.get('signature_state'))}, signature verified {_known(receipt.get('signature_verified'))}",
            f"Ledger chain: intact {_known(ledger.get('intact'))}, {_known(ledger.get('observed_length'))} entries, "
            f"head {_code(ledger.get('observed_head'))}",
            f"Stored exports: {RUN_JSON} and {RESULTS_SARIF} judged by their validators, and {RESULTS_SARIF} "
            f"compared with the log {RUN_JSON} derives; this {REPORT_MD} judged by its validator before it was "
            "written",
        ]
        + [
            f"invariant {_code(item.name)}: {'holds' if item.holds else 'VIOLATED'} ({_md(item.detail)})"
            for item in reverification.invariants
            if item.applicable
        ],
        "",
    )
    return lines + ["", "Problems:", ""] + _bullets([_md(problem) for problem in reverification.problems], "- none")


def render_report(
    document: Mapping[str, Any],
    *,
    files: Sequence[str],
    html_note: str | None,
    reverification: Reverification | None = None,
) -> str:
    """Render ``report.md`` from a run document.

    The nine contract headings come first, in order, and nothing precedes
    them. The file list, and for a re-rendered run the re-verification
    result, follow them. ``html_note`` says why ``report.html`` was not
    written. It is None when the page was rendered, which is not an open item.
    """
    bodies: tuple[Callable[[], list[str]], ...] = (
        lambda: _status_section(document, reverification),
        lambda: _expected_section(document),
        lambda: _examined_section(document),
        lambda: _ran_section(document),
        lambda: _passed_section(document),
        lambda: _failed_section(document),
        lambda: _abstained_section(document),
        lambda: _unresolved_section(document, html_note, reverification),
        lambda: _not_proven_section(document),
    )
    lines: list[str] = []
    for heading, body in zip(REPORT_HEADINGS, bodies):
        lines += [f"## {heading}", "", *body(), ""]
    lines += ["## FILES", "", *_files_section(files), ""]
    if reverification is not None:
        lines += ["## RE-VERIFICATION", "", *_reverification_section(reverification), ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# results.sarif
# ---------------------------------------------------------------------------


def _finding_classification(finding: Mapping[str, Any]) -> tuple[str, str]:
    if finding.get("status") in (Status.ERROR.value, Status.FAIL.value):
        return "fail", "error"
    if finding.get("reason") == Reason.REQUIRES_HUMAN_REVIEW.value:
        return "review", "none"
    return "open", "none"


def _location(path: str) -> dict[str, Any]:
    return {"physicalLocation": {"artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "MANIFEST_DIR"}}}


def build_sarif(document: Mapping[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0 for a run document: one result per check and per non-check finding.

    Tool health lives in the invocation (D7): every ERROR check and every
    ERROR finding adds an error-level toolExecutionNotification, and an
    ERROR run reports ``executionSuccessful: false``.
    """
    paths = {item.get("id"): item.get("path") for item in (document.get("accounting") or {}).get("inputs") or []}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []

    def rule(rule_id: str, text: str) -> None:
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": text}})

    for check in document.get("checks") or []:
        kind, level = sarif_classification(check)
        rule(check["kind"], _CHECK_PURPOSES.get(check["kind"], "Registered check kind."))
        text = (
            f"{check['check_id']}: {check['verdict']} ({check['reason']}), {check['execution_state']}, "
            f"subject records examined {_known(check.get('rows_examined'))}"
        )
        if check.get("diagnostics"):
            text += ". " + "; ".join(check["diagnostics"])
        results.append(
            {
                "ruleId": check["kind"],
                "kind": kind,
                "level": level,
                "message": {"text": text},
                "locations": [
                    _location(paths[input_id]) for input_id in check.get("inputs") or [] if paths.get(input_id)
                ],
                "properties": {
                    **{
                        name: check.get(name)
                        for name in ("check_id", "required", "execution_state", "verdict", "reason", "failure_modes",
                                     "rows_examined", "invocation_id")
                    },
                    "falsification": (check.get("evidence") or {}).get("falsification"),
                },
            }
        )
        if check["verdict"] == Status.ERROR.value:
            notifications.append(
                {
                    "level": "error",
                    "message": {
                        "text": f"check {check['check_id']} errored: " + "; ".join(check.get("diagnostics") or [])
                    },
                    "properties": {"check_id": check["check_id"], "invocation_id": check.get("invocation_id")},
                }
            )
    for finding in document.get("findings") or []:
        source = finding.get("source", "")
        family, _, name = source.partition(":")
        if family == "check":
            continue
        rule_id = f"{family}/{name}" if family == "invariant" else family
        rule(rule_id, _FINDING_RULES.get(family, "Run finding."))
        kind, level = _finding_classification(finding)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "kind": kind,
            "level": level,
            "message": {"text": f"{finding['status']} {finding['reason']}: {finding['detail']}"},
            "properties": finding,
        }
        if family == "input" and paths.get(name):
            result["locations"] = [_location(paths[name])]
        results.append(result)
        if finding.get("status") == Status.ERROR.value:
            notifications.append(
                {
                    "level": "error",
                    "message": {"text": f"{source}: {finding['detail']}"},
                    "properties": {"source": source},
                }
            )
    ordered = sorted(rules)
    index = {rule_id: position for position, rule_id in enumerate(ordered)}
    for result in results:
        result["ruleIndex"] = index[result["ruleId"]]
    artifacts = [
        {
            "location": {"uri": quote(item["path"], safe="/"), "uriBaseId": "MANIFEST_DIR"},
            "hashes": {"sha-256": item["sha256"]},
        }
        for item in (document.get("accounting") or {}).get("inputs") or []
        if item.get("sha256")
    ]
    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "semanticVersion": __version__,
                "rules": [rules[rule_id] for rule_id in ordered],
            }
        },
        "invocations": [
            {
                "executionSuccessful": document.get("status") != Status.ERROR.value,
                "exitCode": document.get("exit_code"),
                "startTimeUtc": document.get("started_at"),
                "endTimeUtc": document.get("completed_at"),
                "toolExecutionNotifications": notifications,
            }
        ],
        "originalUriBaseIds": {
            "MANIFEST_DIR": {"description": {"text": "The directory containing the manifest; URIs are relative to it."}}
        },
        "artifacts": artifacts,
        "results": results,
        "properties": {
            name: document.get(name)
            for name in ("status", "reason", "reasons", "failure_modes", "run_id", "counters",
                         "evidence_manifest_sha256", "controls", "evidence_boundary", "disclaimer")
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def _sarif_bytes(document: Mapping[str, Any]) -> bytes:
    return pretty_json_bytes(build_sarif(document))


# ---------------------------------------------------------------------------
# Writing a run directory
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WrittenRun:
    """What a command wrote: its headline, its exit code and the paths, in order."""

    headline: str
    status: Status
    exit_code: int
    run_dir: Path
    paths: tuple[Path, ...]


def render_html(
    document: Mapping[str, Any], root: Path, *, mutation: Mapping[str, Any] | None = None, name: str = REPORT_HTML
) -> tuple[str | None, str | None]:
    """Render a page with ``science_gate._html.render(document, mutation)`` if installed.

    Returns ``(html, note)``. ``note`` is None when the page was rendered,
    and otherwise says why it was not. The page is a view of the run (and,
    for ``mutate``, of its mutation report), not evidence, so a missing or
    failing renderer is reported rather than changing any status. An older
    page called ``name`` already in ``root`` is left alone, and the note
    says so, so a stale page is never mistaken for a view of this run.
    """
    try:
        spec = importlib.util.find_spec(HTML_RENDERER)
    except (ImportError, ValueError):  # a half-registered module: treat it as absent
        spec = None
    if spec is None:
        note = f"{name} was not written: the HTML renderer ({HTML_RENDERER}) is not installed"
    else:
        try:
            renderer = importlib.import_module(HTML_RENDERER).render
            # A run page keeps the one-argument contract; only a mutation page passes the report too.
            html = renderer(document) if mutation is None else renderer(document, mutation)
        except Exception as exc:  # a view must never take the run's evidence down with it
            note = redact_text(f"{name} was not written: the HTML renderer failed ({type(exc).__name__}: {exc})")
        else:
            if isinstance(html, str):
                return html, None
            note = f"{name} was not written: the HTML renderer returned {type(html).__name__}, not text"
    if (root / name).is_file():
        note += f"; the {name} already in this directory was left unchanged and does not reflect this rendering"
    return None, note


def _parsed_exports(payloads: Mapping[str, bytes]) -> dict[str, Any]:
    """The validated exports read back from the exact bytes that would be written."""
    return {
        RUN_JSON: strict_loads(payloads[RUN_JSON], integers_only=True),
        RESULTS_SARIF: strict_loads(payloads[RESULTS_SARIF], integers_only=True),
        REPORT_MD: payloads[REPORT_MD].decode("utf-8"),
    }


def _confined(parent: Path, name: str) -> Path:
    """``parent/name`` resolved and proven to stay in ``parent``, and not itself a link.

    A link at the output or staging path could redirect the rename, or make
    the clean-up of a stale staging directory delete somebody else's tree.
    """
    resolved = resolve_under_root(parent, name)
    lexical = Path(os.path.realpath(parent)) / name
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        raise UnsafePathError(SYMLINK_TARGET, f"{name!r} is a link; a run directory is never written through one")
    return resolved


def _run_dir_paths(output_dir: str | Path) -> tuple[Path, Path]:
    """The confined output path and its staging sibling ``.<name>.incomplete`` (G4)."""
    absolute = Path(os.path.abspath(output_dir))
    target = _confined(absolute.parent, absolute.name)
    staging = _confined(absolute.parent, f".{absolute.name}{INCOMPLETE_SUFFIX}")
    return target, staging


def _refuse_existing_output(target: Path) -> None:
    """One run never overwrites part of another (G4): only an absent or empty directory is used."""
    if target.is_dir():
        if any(target.iterdir()):
            raise SafeIOError(
                OUTPUT_EXISTS, f"{target.name!r} already exists and is not empty; choose a new output directory"
            )
    elif os.path.lexists(target):
        raise SafeIOError(OUTPUT_EXISTS, f"{target.name!r} already exists and is not a directory")


def _rename_into_place(source: Path, target: Path) -> None:
    """``os.replace`` a finished directory onto ``target``, retrying a transient Windows lock."""
    for delay in _RENAME_RETRY_DELAYS:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            time.sleep(delay)
    os.replace(source, target)


def _finalize(target: Path, staging: Path, order: Sequence[str], payloads: Mapping[str, bytes]) -> None:
    """Write every file into the staging directory, then rename it onto the output path.

    A stale staging directory from an interrupted run is removed first, so
    none of its files can slip into this run. On any failure the staging
    directory is removed (best effort) and the output path never appears.
    """
    if staging.is_dir():
        shutil.rmtree(staging)
    elif os.path.lexists(staging):
        staging.unlink()
    try:
        for name in order:
            safe_write(staging, name, payloads[name])
        if target.is_dir():
            target.rmdir()  # empty, as _refuse_existing_output found it; anything newer makes this fail loudly
        _rename_into_place(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def write_run(run: VerificationRun, output_dir: str | Path, *, environ: Mapping[str, str] | None = None) -> WrittenRun:
    """Write the run directory for ``run`` at ``output_dir``, all or nothing.

    ``environ`` decides receipt authentication (see
    :mod:`science_gate.receipts`) and defaults to the process environment.
    Raises :class:`~science_gate._safeio.SafeIOError` with code
    ``OUTPUT_EXISTS`` for an existing non-empty ``output_dir``,
    :class:`ExportValidationError` when an export contradicts ``run.json``,
    and the OS error of a failed write. In each case nothing is left at
    ``output_dir``.
    """
    root = Path(output_dir)
    target, staging = _run_dir_paths(root)
    _refuse_existing_output(target)
    seal = run.ledger.seal()
    receipt = build_run_receipt(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"], environ=environ
    )
    document = run_document(run, receipt)
    html, html_note = render_html(document, target)
    names = [name for name in RUN_FILES if name != REPORT_HTML or html is not None]
    payloads = {
        RUN_JSON: pretty_json_bytes(document),
        LEDGER_JSONL: run.ledger.to_jsonl(),
        EVIDENCE_MANIFEST_JSON: canonical_bytes(run.evidence_manifest) + b"\n",
        **receipt_files(receipt),
        RESULTS_SARIF: _sarif_bytes(document),
        REPORT_MD: render_report(document, files=names, html_note=html_note).encode("utf-8"),
    }
    if html is not None:
        payloads[REPORT_HTML] = html.encode("utf-8")
    exports = _parsed_exports(payloads)
    problems = validate_exports(exports, exports[RUN_JSON])
    if problems:
        raise ExportValidationError(problems)
    # run.json still goes last, so even the staging directory holds it only when complete.
    _finalize(target, staging, sorted(names, key=lambda name: name == RUN_JSON), payloads)
    return WrittenRun(headline(document), run.result.status, run.result.exit_code, root, tuple(root / n for n in names))


# ---------------------------------------------------------------------------
# Re-verifying and re-rendering a recorded run
# ---------------------------------------------------------------------------


def _read_json(run_dir: Path, name: str, problems: list[str]) -> Any:
    """Read one canonical-or-pretty JSON run file; record a problem instead of raising."""
    try:
        return strict_loads(safe_read(run_dir, name, max_bytes=MAX_RUN_FILE_BYTES), integers_only=True)
    except FileNotFoundError:
        problems.append(f"FILE_MISSING: {name} is not in the run directory")
    except (SafeIOError, OSError) as exc:
        problems.append(f"FILE_UNREADABLE: {name}: {getattr(exc, 'strerror', None) or exc}")
    except StrictJSONError as exc:
        problems.append(f"MALFORMED_FILE: {name}: {exc}")
    return None


def _incompleteness(run_dir: Path) -> str | None:
    """Why ``run_dir`` is not a finished run directory (G4), or None when it may be one."""
    if run_dir.name.endswith(INCOMPLETE_SUFFIX):
        return f"{RUN_INCOMPLETE}: {run_dir.name!r} is the staging directory of a run that did not finish"
    if not (run_dir / RUN_JSON).is_file():
        return f"{RUN_INCOMPLETE}: {run_dir.name!r} has no {RUN_JSON}, so it does not hold a finished run"
    return None


def _recorded_checks(document: Mapping[str, Any], problems: list[str]) -> tuple[CheckResult, ...]:
    try:
        return tuple(CheckResult(**item) for item in document.get("checks") or [])
    except (TypeError, ValueError) as exc:
        problems.append(f"MALFORMED_RUN: run.json checks cannot be read back: {exc}")
        return ()


def _cross_check(document: Mapping[str, Any], predicate: Mapping[str, Any], content_sha256: str | None) -> list[str]:
    """run.json must agree, field by field, with the receipt it was issued with.

    That covers the attested predicate (see :func:`implied_predicate`) in
    both directions, so a predicate field that run.json does not reproduce is
    a mismatch too; the top-level copies of the PASS-contract counters; the
    exit code implied by the status; and the content hash of the statement.
    Without this, an edited ``run.json`` would be re-rendered as a
    re-verified run.
    """
    try:
        implied = implied_predicate(document)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        return [f"MALFORMED_RUN: run.json cannot be compared with its receipt ({type(exc).__name__})"]
    problems: list[str] = []
    for name in sorted(set(implied) | set(predicate)):
        if implied.get(name) == predicate.get(name):
            continue
        shown = ""
        if isinstance(implied.get(name), (str, int, type(None))):
            shown = f" ({implied.get(name)!r}, but the receipt attests {predicate.get(name)!r})"
        problems.append(f"RUN_RECEIPT_MISMATCH: run.json {name} differs from the receipt{shown}")
    counters = predicate.get("counters") if isinstance(predicate.get("counters"), dict) else {}
    problems += [
        f"RUN_RECEIPT_MISMATCH: run.json top-level {name} differs from the attested counter"
        for name in PASS_CONTRACT_FIELDS
        if name in counters and document.get(name) != counters[name]
    ]
    status = document.get("status")
    if status in _STATUS_VALUES and document.get("exit_code") != EXIT_CODE[Status(status)]:
        problems.append(f"RUN_RECEIPT_MISMATCH: run.json exit_code does not follow its status {status}")
    named = document.get("receipt")
    if not isinstance(named, dict) or content_sha256 is None or named.get("content_sha256") != content_sha256:
        problems.append("RUN_RECEIPT_MISMATCH: run.json names a different receipt content_sha256")
    return problems


def _ledger_cross_check(checks: Any, entries: Sequence[Mapping[str, Any]]) -> list[str]:
    """Each run.json check must match what its terminal ledger entry recorded.

    The receipt attests verdicts and evidence digests. The sealed ledger also
    records execution state, failure modes and diagnostics, so together they
    cover every field of a check result. A check whose invocation has no
    terminal entry is reported by the ``every_verdict_has_invocation``
    invariant instead.
    """
    # A tampered file can hold any JSON value where a string belongs, so only
    # string ids and results are used as keys.
    recorded = {
        entry["invocation_id"]: entry.get("evidence")
        for entry in entries
        if isinstance(entry.get("invocation_id"), str)
        and isinstance(entry.get("result"), str)
        and entry["result"] in _TERMINAL_RESULTS
    }
    problems: list[str] = []
    for check in checks if isinstance(checks, list) else []:
        if not isinstance(check, dict) or not isinstance(check.get("invocation_id"), str):
            continue
        invocation_id = check["invocation_id"]
        if invocation_id in recorded and ledger_evidence(check) != recorded[invocation_id]:
            problems.append(
                f"RUN_LEDGER_MISMATCH: run.json check {check.get('check_id')!r} differs from its terminal ledger entry"
            )
    return problems


def _stored_export_problems(document: Mapping[str, Any], sarif: Any) -> list[str]:
    """Re-run the exporter validators on the stored files (#12), then demand the derived SARIF.

    ``results.sarif`` is neither hashed into the receipt nor into the
    evidence manifest, yet code-scanning tools read it directly. It is a pure
    function of ``run.json``, so any byte of it that ``run.json`` does not
    derive is an edit.
    """
    problems = list(validate_exports({RUN_JSON: document, RESULTS_SARIF: sarif}, document))
    try:
        derived = strict_loads(_sarif_bytes(document), integers_only=True)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        return problems + [f"MALFORMED_RUN: {RESULTS_SARIF} cannot be re-derived from run.json ({type(exc).__name__})"]
    if derived != sarif:
        problems.append(f"{SARIF_NOT_DERIVED}: {RESULTS_SARIF} differs from the SARIF log run.json derives")
    return problems


def reverify_run_dir(run_dir: str | Path, *, environ: Mapping[str, str] | None = None) -> tuple[Reverification, Any]:
    """Re-check a recorded run directory without trusting any single file.

    Checks: that the directory holds a finished run (G4); the receipt
    statement and its sidecar (structure, content hash, and authenticator
    when the key is available); the ledger chain against the seal in the
    receipt; the ledger invariants over the recorded results; run.json
    against the receipt and against the terminal ledger entries; the stored
    exports against their validators; and the evidence manifest against its
    recorded hash. Returns the verification and the parsed ``run.json``
    (None when unreadable, or when the directory is not a finished run).
    """
    root = Path(run_dir)
    incomplete = _incompleteness(root)
    if incomplete is not None:
        return Reverification(False, (incomplete,), (), None, None, ()), None
    problems: list[str] = []
    notes: list[str] = []
    document = _read_json(root, RUN_JSON, problems)
    if document is not None and not isinstance(document, dict):
        problems.append("MALFORMED_RUN: run.json is not a JSON object")
        document = None
    if document is not None and document.get("status") not in _STATUS_VALUES:
        problems.append(f"MALFORMED_RUN: run.json status {_md(document.get('status'))} is not a known status")
    verification = verify_receipt(root / RECEIPT_JSON, environ=environ)
    problems.extend(f"RECEIPT: {problem}" for problem in verification.problems)
    if verification.detail and verification.signature_verified is not True:
        # Only what could not be checked is a note; a verified signature is not an open item.
        notes.append(f"receipt: {verification.detail}")
    statement = _read_json(root, RECEIPT_JSON, [])
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    predicate = predicate if isinstance(predicate, dict) else {}

    seal_source = predicate or (document or {})
    ledger_summary: dict[str, Any] | None = None
    invariants: tuple[InvariantResult, ...] = ()
    try:
        entries = parse_jsonl(safe_read(root, LEDGER_JSONL, max_bytes=MAX_RUN_FILE_BYTES))
    except FileNotFoundError:
        problems.append(f"FILE_MISSING: {LEDGER_JSONL} is not in the run directory")
    except (SafeIOError, OSError, LedgerFormatError) as exc:
        problems.append(f"LEDGER_UNREADABLE: {exc}")
    else:
        checks = _recorded_checks(document or {}, problems)
        ctx = InvariantContext(
            entries=entries,
            checks=checks,
            ledger_head_sha256=seal_source.get("ledger_head_sha256"),
            ledger_length=seal_source.get("ledger_length"),
            run_id=seal_source.get("run_id"),
        )
        chain = ledger_chain_intact(ctx)
        invariants = (chain, every_invocation_has_terminal_result(ctx), every_verdict_has_invocation(ctx))
        problems.extend(f"INVARIANT {item.name}: {item.detail}" for item in invariants if item.violated)
        problems.extend(_ledger_cross_check((document or {}).get("checks"), entries))
        ledger_summary = {
            "intact": not chain.violated,
            "observed_length": len(entries),
            "observed_head": entries[-1].get("entry_sha256") if entries else None,
        }
    if document is not None and predicate:
        problems.extend(_cross_check(document, predicate, verification.recomputed_sha256))
    elif document is not None:
        problems.append("RECEIPT: no readable predicate to cross-check run.json against")
    if document is not None:
        notes.append(
            "run.json findings, declared manifest content and document list are shown as recorded: the receipt and "
            "the ledger do not attest them directly (the manifest and document digests are in evidence-manifest.json)"
        )
        sarif = _read_json(root, RESULTS_SARIF, problems)
        if sarif is not None:
            problems.extend(_stored_export_problems(document, sarif))
    evidence = _read_json(root, EVIDENCE_MANIFEST_JSON, problems)
    if evidence is not None:
        try:
            digest = sha256_canonical(evidence)
        except CanonicalizationError as exc:
            problems.append(f"MALFORMED_FILE: {EVIDENCE_MANIFEST_JSON}: {exc}")
        else:
            expected = predicate.get("evidence_manifest_sha256") or (document or {}).get("evidence_manifest_sha256")
            if digest != expected:
                problems.append(
                    f"EVIDENCE_MANIFEST_MISMATCH: {EVIDENCE_MANIFEST_JSON} hashes to {digest}, "
                    f"not the recorded {expected}"
                )
    result = Reverification(
        ok=not problems,
        problems=tuple(problems),
        notes=tuple(notes),
        receipt=verification.to_dict(),
        ledger=ledger_summary,
        invariants=invariants,
    )
    return result, document


def _placeholder_document(run_dir: Path) -> dict[str, Any]:
    """What the report renders when run.json itself cannot be used."""
    return {
        "status": Status.ERROR.value,
        "reason": Reason.PROTOCOL_BROKEN.value,
        "run_id": None,
        "exit_code": EXIT_CODE[Status.ERROR],
        "reasons": [Reason.PROTOCOL_BROKEN.value],
        "manifest": {
            "file": None,
            "issues": [
                {"code": "RUN_UNREADABLE", "pointer": "", "message": f"run.json in {run_dir.name!r} is unusable"}
            ],
        },
    }


def _html_view(document: Mapping[str, Any], reverification: Reverification) -> dict[str, Any]:
    """The document the HTML renderer sees for a re-rendered run.

    It is the run document plus the re-verification result. A run that failed
    re-verification is shown as ERROR, with its recorded status kept beside it
    as ``recorded_status``. The dashboard therefore can never display a
    status that re-verification rejected, just as ``report.md`` does not.
    """
    view = {**document, "reverification": reverification.to_dict()}
    if not reverification.ok:
        view.update(
            status=Status.ERROR.value,
            reason=Reason.PROTOCOL_BROKEN.value,
            exit_code=EXIT_CODE[Status.ERROR],
            recorded_status=document.get("status"),
        )
    return view


def _rejected(reverification: Reverification, problems: Sequence[str]) -> Reverification:
    return replace(reverification, ok=False, problems=(*reverification.problems, *problems))


def _render_views(
    document: Mapping[str, Any], reverification: Reverification, root: Path
) -> tuple[str, str | None]:
    """``report.md`` text and, when the renderer is installed, ``report.html``, for one re-verification."""
    html, html_note = render_html(_html_view(document, reverification), root)
    written = [REPORT_MD] + ([REPORT_HTML] if html is not None else [])
    present = [name for name in RUN_FILES if name in written or (root / name).is_file()]
    return render_report(document, files=present, html_note=html_note, reverification=reverification), html


def _replace_in_place(root: Path, payloads: Mapping[str, bytes]) -> list[Path]:
    """Write each file as ``<name>.incomplete`` and only then rename every one into place (G4).

    A failed write leaves every existing view untouched, so ``report.md`` and
    ``report.html`` never describe two different re-verifications.
    """
    staged: list[Path] = []
    try:
        for name, data in payloads.items():
            staged.append(safe_write(root, name + INCOMPLETE_SUFFIX, data))
        placed = []
        for path in staged:
            final = path.with_name(path.name[: -len(INCOMPLETE_SUFFIX)])
            os.replace(path, final)
            placed.append(final)
        return placed
    except BaseException:
        for path in staged:
            path.unlink(missing_ok=True)
        raise


def report_run_dir(run_dir: str | Path, *, environ: Mapping[str, str] | None = None) -> WrittenRun:
    """``science-gate report RUN_DIR``: re-verify, then re-render report.md and report.html.

    The exit code is the recorded status's when re-verification succeeds, and
    3 (ERROR) when it does not. A directory that does not hold a finished run
    (``RUN_INCOMPLETE``) is ERROR too, and nothing is written into it: its
    verdict is never rendered. Raises :class:`ExportValidationError`, writing
    nothing, if even the report of a failed re-verification would contradict
    its validator.
    """
    root = Path(run_dir)
    if not root.is_dir():
        # Writing report.md would otherwise create the directory it was asked to check.
        raise NotADirectoryError(f"{root.name!r} is not a run directory")
    incomplete = _incompleteness(root)
    if incomplete is not None:
        line = f"{Status.ERROR.value} ({Reason.PROTOCOL_BROKEN.value}) {incomplete}; nothing was rendered"
        return WrittenRun(_md(line), Status.ERROR, EXIT_CODE[Status.ERROR], root, ())
    reverification, document = reverify_run_dir(root, environ=environ)
    if document is None:
        document = _placeholder_document(root)
    try:
        text, html = _render_views(document, reverification, root)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        # A tampered run.json may have the right keys holding the wrong
        # shapes. Say so and render what is certain rather than crash.
        problem = f"MALFORMED_RUN: run.json could not be rendered ({type(exc).__name__})"
        reverification = _rejected(reverification, (problem,))
        document = _placeholder_document(root)
        text, html = _render_views(document, reverification, root)
    problems = validate_exports({REPORT_MD: text}, document)
    if problems:
        reverification = _rejected(reverification, problems)
        text, html = _render_views(document, reverification, root)
        remaining = validate_exports({REPORT_MD: text}, document)
        if remaining:
            raise ExportValidationError(remaining)
    payloads = {REPORT_MD: text.encode("utf-8")}
    if html is not None:
        payloads[REPORT_HTML] = html.encode("utf-8")
    paths = _replace_in_place(root, payloads)
    if reverification.ok:
        # A run that re-verified has a known status: reverify_run_dir checks it.
        status = Status(document["status"])
        line = f"{status.value} ({document.get('reason')}) {document.get('run_id')}: recorded run re-verified"
    else:
        status = Status.ERROR
        line = (
            f"{Status.ERROR.value} ({Reason.PROTOCOL_BROKEN.value}) {document.get('run_id')}: re-verification "
            f"failed: {reverification.problems[0]}"
        )
    # Recorded values can hold newlines; the headline must stay one line.
    return WrittenRun(_md(line), status, EXIT_CODE[status], root, tuple(paths))
