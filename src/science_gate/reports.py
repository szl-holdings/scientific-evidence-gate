"""Run directories: writing them, re-verifying them and rendering them (ARCHITECTURE.md section 12).

``verify`` writes one directory per run. Every file is written through
:func:`~science_gate._safeio.safe_write`:

* ``run.json``: the machine-readable run, with the PASS-contract fields at
  top level;
* ``report.md``: the human report, opening with the nine contract headings;
* ``ledger.jsonl``: the execution ledger, canonical JSON Lines;
* ``evidence-manifest.json``: one entry per piece of evidence, with its
  SHA-256, in canonical JSON (the bytes that were hashed appear verbatim);
* ``receipt.json``: the run receipt (:mod:`science_gate.receipts`);
* ``results.sarif``: SARIF 2.1.0;
* ``report.html``: written only when ``science_gate._html`` is installed.
  Otherwise the report says it was not written.

Reports are rendered from the ``run.json`` document alone, never from live
objects. ``science-gate report RUN_DIR`` can therefore re-render a recorded
run exactly as ``verify`` rendered it. First it re-verifies the receipt and
the ledger chain. Then it checks that every figure in ``run.json`` is one the
receipt attests (see :func:`implied_predicate`), and that every check result
matches its terminal ledger entry. If any of that fails, the recorded status
is not trusted: the report says so, with status ERROR.

The HTML renderer contract is ``science_gate._html.render(document) -> str``.
``document`` is the ``run.json`` content as a dict, not a live object, so that
``verify`` and ``report RUN_DIR`` render from the same input. For a
re-rendered run it also carries ``reverification``. A run that failed
re-verification is passed with status ERROR, and its recorded status is kept
as ``recorded_status``.
"""

from __future__ import annotations

import importlib
import importlib.util
import re
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
from ._safeio import SafeIOError, safe_read, safe_write
from .invariants import (
    InvariantContext,
    every_invocation_has_terminal_result,
    every_verdict_has_invocation,
    ledger_chain_intact,
)
from .ledger import LedgerFormatError, parse_jsonl
from .models import EXIT_CODE, TERMINAL_INVOCATION_RESULTS, CheckResult, InvariantResult, Reason, Status
from .receipts import build_run_receipt, receipt_bytes, verify_receipt
from .verifier import VerificationRun, ledger_evidence

__all__ = [
    "RUN_SCHEMA",
    "RUN_JSON",
    "REPORT_MD",
    "LEDGER_JSONL",
    "EVIDENCE_MANIFEST_JSON",
    "RECEIPT_JSON",
    "RESULTS_SARIF",
    "REPORT_HTML",
    "RUN_FILES",
    "REPORT_HEADINGS",
    "PASS_CONTRACT_FIELDS",
    "SARIF_VERSION",
    "SARIF_SCHEMA",
    "HTML_RENDERER",
    "WrittenRun",
    "Reverification",
    "run_document",
    "implied_predicate",
    "headline",
    "render_report",
    "sarif_classification",
    "build_sarif",
    "write_run",
    "reverify_run_dir",
    "report_run_dir",
]

RUN_SCHEMA = "science-gate-run/v1"
RUN_JSON = "run.json"
REPORT_MD = "report.md"
LEDGER_JSONL = "ledger.jsonl"
EVIDENCE_MANIFEST_JSON = "evidence-manifest.json"
RECEIPT_JSON = "receipt.json"
RESULTS_SARIF = "results.sarif"
REPORT_HTML = "report.html"
#: Every file a run directory can hold, in the contract's table order.
RUN_FILES = (RUN_JSON, REPORT_MD, LEDGER_JSONL, EVIDENCE_MANIFEST_JSON, RECEIPT_JSON, RESULTS_SARIF, REPORT_HTML)

#: The first headings of ``report.md``, in this order (section 12).
REPORT_HEADINGS = (
    "STATUS",
    "WHAT WAS EXPECTED",
    "WHAT WAS EXAMINED",
    "WHAT ACTUALLY RAN",
    "WHAT PASSED",
    "WHAT FAILED",
    "WHAT ABSTAINED",
    "WHAT REMAINS UNRESOLVED",
    "WHAT THIS RESULT DOES NOT PROVE",
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

_CHECK_PURPOSES: Mapping[str, str] = {
    "row_count": "Rows examined > 0, with closure against an INDEPENDENT expected_rows.",
    "required_columns": "Declared columns are present.",
    "duplicate_rows": "No exact duplicates and no duplicate row_key.",
    "snapshot_completeness": "Rows accepted in the snapshot are still present and unchanged.",
    "numeric_agreement": "Declared values agree with stored values, rounding- and separator-aware.",
    "reviewer_protocol": "All required reviewers present, no duplicate verdicts.",
    "time_source": "Declared timezone and normalized UTC exist, agree, and fall inside the window.",
    "verification_log": "Claimed verifications are backed by invocation records.",
    "citation_resolver": "DOIs resolve in the frozen record set.",
    "citation_metadata": "Citation metadata matches the resolved records.",
    "claim_registry": "Manuscript numbers are registered claims with a derivation.",
    "dependency_currency": "No stale dependency blocks publication.",
    "summary_consistency": "A stored PASS summary matches what was recomputed.",
}

_FINDING_RULES: Mapping[str, str] = {
    "manifest": "The manifest must be valid and safe.",
    "input": "Every required input must be present, readable, parsed and match any declared digest.",
    "contract": "The PASS contract's counting rules (section 6).",
    "invariant": "A named invariant over the ledger, results and accounting (section 4).",
}


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
    verdict, evidence digest and invariant outcome that a re-rendered report
    shows is one the receipt attests. It works from the raw document rather
    than rebuilding model objects, because rebuilding would redact again under
    the current environment and could alter what was recorded.

    Raises KeyError, TypeError, AttributeError or ValueError when the
    document does not have the shape ``verify`` writes.
    """
    accounting = document["accounting"]
    return {
        **{name: document.get(name) for name in _ATTESTED_FIELDS},
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
    receipt = doc.get("receipt") or {}
    lines += _bullets(
        [
            f"Run: {_code(doc.get('run_id'))}",
            f"Started {_md(doc.get('started_at'))}; completed {_md(doc.get('completed_at'))}",
            f"Reasons: {', '.join(doc.get('reasons') or []) or 'none'}",
            f"Failure modes: {', '.join(doc.get('failure_modes') or []) or 'none'}",
            f"Evidence manifest sha256: {_code(doc.get('evidence_manifest_sha256'))}",
            f"Ledger: {_known(doc.get('ledger_length'))} entries, head {_ledger_head(doc)}",
            f"Receipt: content sha256 {_code(receipt.get('content_sha256'))}, {_md(receipt.get('signature_state'))}",
            "Scope: integrity and the declared evaluation only. Scientific validity is not established by this tool.",
        ],
        "",
    )
    return lines


def _expected_section(doc: Mapping[str, Any]) -> list[str]:
    manifest = doc.get("manifest") or {}
    declared = doc.get("declared") or {}
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
        "input opened; at least one row examined; checks_executed == checks_expected; every required check PASS; "
        "every applicable invariant holding; a non-empty evidence manifest.",
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
    accounting = doc.get("accounting") or {}
    counters = accounting.get("counters") or {}
    funnel = " -> ".join(
        f"{name} {_known((counters.get(name) or {}).get('value'))}"
        for name in ("expected", "discovered", "opened", "parsed", "examined")
    )
    lines = _bullets(
        [
            f"Input funnel: {funnel}; input {_closure_text(accounting.get('closure'))}",
            f"Rows examined in scope: {_known(doc.get('rows_examined'))}",
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


def _ran_section(doc: Mapping[str, Any]) -> list[str]:
    lines = _bullets(
        [
            f"checks_executed {_known(doc.get('checks_executed'))} of checks_expected "
            f"{_known(doc.get('checks_expected'))} (required checks that reached CHECKED with a terminal invocation)",
            f"Ledger sealed at {_known(doc.get('ledger_length'))} entries, head {_ledger_head(doc)}",
        ],
        "",
    )
    invocations = [
        f"{_code(check.get('check_id'))} ({_md(check.get('kind'))} v{_md(check.get('version'))}"
        f"{'' if check.get('required') else ', optional'}): invocation {_code(check.get('invocation_id'))}, "
        f"{_md(check.get('execution_state'))}, {_md(check.get('verdict'))}, rows examined "
        f"{_known(check.get('rows_examined'))}"
        for check in doc.get("checks") or []
    ]
    return lines + ["", "Invocations:", ""] + _bullets(invocations, "- none: no check was invoked")


def _check_line(check: Mapping[str, Any]) -> str:
    optional = "" if check.get("required") else " (optional)"
    diagnostics = "; ".join(_md(item) for item in check.get("diagnostics") or [])
    return (
        f"{_code(check.get('check_id'))}{optional}: {_md(check.get('kind'))} {_md(check.get('verdict'))} "
        f"({_md(check.get('reason'))}), rows examined {_known(check.get('rows_examined'))}"
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


def _passed_section(doc: Mapping[str, Any]) -> list[str]:
    checks = [_check_line(check) for check in doc.get("checks") or [] if check.get("verdict") == Status.PASS.value]
    holding = [
        f"{_code(item.get('name'))}: {_md(item.get('detail'))}"
        for item in doc.get("invariants") or []
        if item.get("applicable") and item.get("holds") is True
    ]
    lines = ["Checks:", ""] + _bullets(checks, "- none")
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
    for record in (doc.get("accounting") or {}).get("inputs") or []:
        if record.get("state") != "PARSED":
            required = "required" if record.get("required") else "optional"
            diagnostics = "; ".join(_md(text) for text in record.get("diagnostics") or [])
            items.append(f"{required} input {_code(record.get('id'))} is {_md(record.get('state'))}: {diagnostics}")
        closure = record.get("closure") or {}
        if closure.get("holds") is None:
            items.append(f"row closure of input {_code(record.get('id'))} not evaluated ({_md(closure.get('source'))})")
    for document in doc.get("documents") or []:
        if document.get("state") != "PARSED":
            state = f"{_md(document.get('state'))}: {_md(document.get('diagnostic'))}"
            items.append(f"document {_code(document.get('path'))} is {state}")
    for check in doc.get("checks") or []:
        if check.get("execution_state") != "CHECKED":
            items.append(f"check {_code(check.get('check_id'))} was {_md(check.get('execution_state'))}")
    for invariant in doc.get("invariants") or []:
        if not invariant.get("applicable"):
            items.append(f"invariant {_code(invariant.get('name'))} not applicable: {_md(invariant.get('detail'))}")
    receipt = doc.get("receipt") or {}
    if receipt.get("signature_state") != "SIGNED_HMAC_SHA256":
        items.append(
            "the receipt is UNSIGNED: its content hash detects accidental change, but anyone able to edit "
            "the run directory can rewrite and rehash it"
        )
    if reverification is not None:
        items += [_md(note) for note in reverification.notes]
    if html_note:
        items.append(_md(html_note))
    return _bullets(items, "- nothing")


def _not_proven_section(doc: Mapping[str, Any]) -> list[str]:
    boundary = doc.get("evidence_boundary") or {}
    network = doc.get("network") or {}
    live = network.get("live")
    return _bullets(
        [
            "Scientific validity: NOT ESTABLISHED. Whether any conclusion holds in its intended domain is outside "
            "what this tool can show.",
            f"Integrity (what was established): {_md(boundary.get('integrity'))}",
            f"Performance (how the declared checks behaved): {_md(boundary.get('performance'))}",
            "A PASS shows only that the declared checks had the opportunity to fail on the declared inputs and did "
            "not. It says nothing about inputs, checks or questions that were not declared, and nothing about "
            "whether the declared expectations were the right ones.",
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


def sarif_classification(check: Mapping[str, Any]) -> tuple[str, str]:
    """SARIF ``(kind, level)`` for a check result (section 1).

    ERROR -> fail/error; NOT_APPLICABLE -> notApplicable; SKIPPED -> open;
    CHECKED PASS -> pass; CHECKED FAIL -> fail/error; ABSTAIN with
    REQUIRES_HUMAN_REVIEW -> review; any other ABSTAIN -> open. SARIF
    requires level ``none`` for every kind except ``fail``.
    """
    verdict, state = check.get("verdict"), check.get("execution_state")
    if verdict == Status.ERROR.value:
        return "fail", "error"
    if state == "NOT_APPLICABLE":
        return "notApplicable", "none"
    if state == "SKIPPED":
        return "open", "none"
    if verdict == Status.PASS.value:
        return "pass", "none"
    if verdict == Status.FAIL.value:
        return "fail", "error"
    if check.get("reason") == Reason.REQUIRES_HUMAN_REVIEW.value:
        return "review", "none"
    return "open", "none"


def _finding_classification(finding: Mapping[str, Any]) -> tuple[str, str]:
    if finding.get("status") in (Status.ERROR.value, Status.FAIL.value):
        return "fail", "error"
    if finding.get("reason") == Reason.REQUIRES_HUMAN_REVIEW.value:
        return "review", "none"
    return "open", "none"


def _location(path: str) -> dict[str, Any]:
    return {"physicalLocation": {"artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "MANIFEST_DIR"}}}


def build_sarif(document: Mapping[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0 for a run document: one result per check and per non-check finding."""
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
            f"rows examined {_known(check.get('rows_examined'))}"
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
                    name: check.get(name)
                    for name in ("check_id", "required", "execution_state", "verdict", "reason", "failure_modes",
                                 "rows_examined", "invocation_id")
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
        if family == "manifest":
            notifications.append({"level": "error", "message": {"text": finding["detail"]}})
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
                         "evidence_manifest_sha256", "evidence_boundary", "disclaimer")
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


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


def _render_html(document: Mapping[str, Any], root: Path) -> tuple[str | None, str | None]:
    """Render ``report.html`` with ``science_gate._html.render(document)`` if installed.

    Returns ``(html, note)``. ``note`` is None when the page was rendered,
    and otherwise says why it was not. The dashboard is a view of the run,
    not evidence, so a missing or failing renderer is reported in
    ``report.md`` rather than changing the decided status. An older
    ``report.html`` already in ``root`` is left alone, and the note says so,
    so a stale page is never mistaken for a view of this run.
    """
    try:
        spec = importlib.util.find_spec(HTML_RENDERER)
    except (ImportError, ValueError):  # a half-registered module: treat it as absent
        spec = None
    if spec is None:
        note = f"report.html was not written: the HTML renderer ({HTML_RENDERER}) is not installed"
    else:
        try:
            html = importlib.import_module(HTML_RENDERER).render(document)
        except Exception as exc:  # a view must never take the run's evidence down with it
            note = redact_text(f"report.html was not written: the HTML renderer failed ({type(exc).__name__}: {exc})")
        else:
            if isinstance(html, str):
                return html, None
            note = f"report.html was not written: the HTML renderer returned {type(html).__name__}, not text"
    if (root / REPORT_HTML).is_file():
        note += "; the report.html already in this directory was left unchanged and does not reflect this rendering"
    return None, note


def write_run(run: VerificationRun, output_dir: str | Path, *, environ: Mapping[str, str] | None = None) -> WrittenRun:
    """Write the run directory for ``run`` into ``output_dir``.

    ``environ`` decides receipt signing (see :mod:`science_gate.receipts`)
    and defaults to the process environment.
    """
    root = Path(output_dir)
    seal = run.ledger.seal()
    receipt = build_run_receipt(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"], environ=environ
    )
    document = run_document(run, receipt)
    html, html_note = _render_html(document, root)
    names = [name for name in RUN_FILES if name != REPORT_HTML or html is not None]
    payloads = {
        RUN_JSON: pretty_json_bytes(document),
        LEDGER_JSONL: run.ledger.to_jsonl(),
        EVIDENCE_MANIFEST_JSON: canonical_bytes(run.evidence_manifest) + b"\n",
        RECEIPT_JSON: receipt_bytes(receipt),
        RESULTS_SARIF: pretty_json_bytes(build_sarif(document)),
        REPORT_MD: render_report(document, files=names, html_note=html_note).encode("utf-8"),
    }
    if html is not None:
        payloads[REPORT_HTML] = html.encode("utf-8")
    # run.json goes last, so a directory holding it holds a complete run.
    order = sorted(names, key=lambda name: name == RUN_JSON)
    written = {name: safe_write(root, name, payloads[name]) for name in order}
    paths = tuple(written[name] for name in names)
    return WrittenRun(headline(document), run.result.status, run.result.exit_code, root, paths)


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


def _recorded_checks(document: Mapping[str, Any], problems: list[str]) -> tuple[CheckResult, ...]:
    try:
        return tuple(CheckResult(**item) for item in document.get("checks") or [])
    except (TypeError, ValueError) as exc:
        problems.append(f"MALFORMED_RUN: run.json checks cannot be read back: {exc}")
        return ()


def _cross_check(document: Mapping[str, Any], predicate: Mapping[str, Any], receipt: Mapping[str, Any]) -> list[str]:
    """run.json must agree, field by field, with the receipt it was issued with.

    That covers the attested predicate (see :func:`implied_predicate`), the
    top-level copies of the PASS-contract counters, the exit code implied by
    the status, and the receipt's own content hash. Without this, an edited
    ``run.json`` would be re-rendered as a re-verified run.
    """
    try:
        implied = implied_predicate(document)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        return [f"MALFORMED_RUN: run.json cannot be compared with its receipt ({type(exc).__name__})"]
    problems: list[str] = []
    for name in sorted(implied):
        if implied[name] == predicate.get(name):
            continue
        shown = ""
        if isinstance(implied[name], (str, int, type(None))):
            shown = f" ({implied[name]!r}, but the receipt attests {predicate.get(name)!r})"
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
    if not isinstance(named, dict) or named.get("content_sha256") != receipt.get("content_sha256"):
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


def reverify_run_dir(run_dir: str | Path, *, environ: Mapping[str, str] | None = None) -> tuple[Reverification, Any]:
    """Re-check a recorded run directory without trusting any single file.

    Checks: the receipt (structure, content hash, and signature when the key
    is available); the ledger chain against the seal in the receipt; the
    ledger invariants over the recorded results; run.json against the
    receipt and against the terminal ledger entries; and the evidence
    manifest against its recorded hash. Returns the verification and the
    parsed ``run.json`` (None when unreadable).
    """
    root = Path(run_dir)
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
    receipt = _read_json(root, RECEIPT_JSON, []) or {}
    body = receipt.get("body") if isinstance(receipt, dict) else None
    predicate = body.get("predicate") if isinstance(body, dict) else None
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
        problems.extend(_cross_check(document, predicate, receipt))
    elif document is not None:
        problems.append("RECEIPT: no readable predicate to cross-check run.json against")
    if document is not None:
        notes.append(
            "run.json findings, declared manifest content and document list are shown as recorded: the receipt and "
            "the ledger do not attest them directly (the manifest and document digests are in evidence-manifest.json)"
        )
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


def report_run_dir(run_dir: str | Path, *, environ: Mapping[str, str] | None = None) -> WrittenRun:
    """``science-gate report RUN_DIR``: re-verify, then re-render report.md and report.html.

    The exit code is the recorded status's when re-verification succeeds, and
    3 (ERROR) when it does not.
    """
    root = Path(run_dir)
    if not root.is_dir():
        # Writing report.md would otherwise create the directory it was asked to check.
        raise NotADirectoryError(f"{root.name!r} is not a run directory")
    reverification, document = reverify_run_dir(root, environ=environ)
    if document is None:
        document = _placeholder_document(root)
    try:
        # A dry run: a tampered run.json may have the right keys holding the
        # wrong shapes. Say so and render what is certain rather than crash.
        render_report(document, files=(), html_note=None, reverification=reverification)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        problem = f"MALFORMED_RUN: run.json could not be rendered ({type(exc).__name__})"
        reverification = replace(reverification, ok=False, problems=(*reverification.problems, problem))
        document = _placeholder_document(root)
    html, html_note = _render_html(_html_view(document, reverification), root)
    written = [REPORT_MD] + ([REPORT_HTML] if html is not None else [])
    present = [name for name in RUN_FILES if name in written or (root / name).is_file()]
    text = render_report(document, files=present, html_note=html_note, reverification=reverification)
    paths = [safe_write(root, REPORT_MD, text.encode("utf-8"))]
    if html is not None:
        paths.append(safe_write(root, REPORT_HTML, html.encode("utf-8")))
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
