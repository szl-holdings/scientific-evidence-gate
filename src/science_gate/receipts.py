"""Run receipts: a hashed statement about a run plus a separate authentication sidecar (sections 11 and 17.9).

A receipt lets someone who was not present check three things later: which
input bytes a run saw (``subject`` digests), what the run concluded and on
what execution record (``predicate``, including the sealed ledger head and the
digest of the run's checker controls), and that none of it was edited
afterwards (``content_sha256`` and, when a key is configured, an HMAC-SHA256
authenticator).

What a receipt does *not* do is written into it. ``evidence_boundary`` keeps
integrity, performance and scientific validity apart, and scientific validity
is always ``"NOT ESTABLISHED"``: callers cannot set it, and a receipt that
claims otherwise fails verification even when its hash was recomputed.

On disk a receipt is two files (decision D9):

* ``receipt.json``, the **statement**: the canonical body and nothing else.
  It never says whether it is authenticated, because a statement cannot
  vouch for itself.
* ``receipt.auth.json``, the **sidecar**: the statement's content hash and
  either the HMAC-SHA256 authenticator with its key id, or ``UNSIGNED`` with
  the reason no key was used. An unsigned sidecar has no ``signature`` key at
  all, so no file is ever an envelope with an empty signature.

HMAC-SHA256 is a *shared-key authenticator*: anyone holding the key can
produce it, so it shows that a key holder issued the statement. It is not a
public signature, and nothing here calls it one. The key never appears in
any output, only its SHA-256 (``key_id``).

What re-checking established is reported apart from what the files declare:
:class:`ReceiptVerification` carries ``auth_status``, an
:class:`~science_gate.models.AuthStatus`, which is never written into either
file. Unsigned, failed and unchecked authentication are different outcomes,
and ``require_signature`` turns everything but ``SIGNED_VERIFIED`` into a
problem.

The in-memory *record* that :func:`build_run_receipt` returns keeps the 0.1.0
shape ``{body, content_sha256, signature_state, signature, key_id}`` plus the
key resolution's ``detail``. It is never written as such: :func:`receipt_files`
turns it into the two files.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from ._canonical import (
    CanonicalizationError,
    StrictJSONError,
    canonical_bytes,
    sha256_bytes,
    sha256_canonical,
    strict_loads,
)
from ._safeio import SafeIOError, safe_read, safe_write
from .models import AuthStatus, InputAccounting, RunResult, SignatureState, Status, WitnessState

__all__ = [
    "RECEIPT_SCHEMA",
    "PREDICATE_TYPE",
    "DISCLAIMER",
    "SCIENTIFIC_VALIDITY",
    "HMAC_KEY_FILE_ENV",
    "MAX_KEY_BYTES",
    "MAX_RECEIPT_BYTES",
    "MAX_AUTH_BYTES",
    "STATEMENT_FILE",
    "AUTH_FILE",
    "AUTH_SCHEMA",
    "AUTH_ALGORITHM",
    "BODY_KEYS",
    "RECORD_KEYS",
    "UNSIGNED_AUTH_KEYS",
    "SIGNED_AUTH_KEYS",
    "ReceiptError",
    "SigningKey",
    "KeyResolution",
    "ReceiptVerification",
    "resolve_signing_key",
    "build_body",
    "run_subjects",
    "run_predicate",
    "build_run_body",
    "seal_body",
    "build_run_receipt",
    "auth_file_name",
    "receipt_files",
    "receipt_bytes",
    "write_receipt",
    "verify_receipt_documents",
    "verify_receipt",
]

RECEIPT_SCHEMA = "science-gate-receipt/v1"
PREDICATE_TYPE = "science-gate/run/v1"
DISCLAIMER = (
    "A receipt supports integrity, provenance, and replayability. It does not establish "
    "scientific truth, accuracy, safety, or fitness for use."
)
#: The only value ``evidence_boundary.scientific_validity`` may ever take.
SCIENTIFIC_VALIDITY = "NOT ESTABLISHED"
HMAC_KEY_FILE_ENV = "SCIENCE_GATE_HMAC_KEY_FILE"

#: A key file larger than this is not a key; refusing it avoids reading an
#: arbitrary large file that an environment variable happens to point at.
MAX_KEY_BYTES = 64 * 1024
#: Receipts are summaries; this bounds what :func:`verify_receipt` will read.
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
#: A sidecar holds a hash, a state and at most an authenticator and a key id.
MAX_AUTH_BYTES = 64 * 1024

#: The statement's file name in a run directory.
STATEMENT_FILE = "receipt.json"
#: The authentication sidecar's file name beside :data:`STATEMENT_FILE`.
AUTH_FILE = "receipt.auth.json"
AUTH_SCHEMA = "science-gate-receipt-auth/v1"
#: The one authenticator this tool produces: a shared-key MAC, not a public signature.
AUTH_ALGORITHM = "HMAC-SHA256"

_STATEMENT_SUFFIX = ".json"
_AUTH_SUFFIX = ".auth.json"

BODY_KEYS = frozenset({"schema", "subject", "predicate_type", "predicate", "evidence_boundary", "disclaimer"})
#: Keys of the in-memory record returned by :func:`build_run_receipt`.
RECORD_KEYS = frozenset({"body", "content_sha256", "signature_state", "signature", "key_id", "detail"})
#: An unsigned sidecar says why it is unsigned and has no ``signature`` or ``key_id`` key.
UNSIGNED_AUTH_KEYS = frozenset({"schema", "statement", "content_sha256", "signature_state", "detail"})
SIGNED_AUTH_KEYS = frozenset(
    {"schema", "statement", "content_sha256", "signature_state", "algorithm", "signature", "key_id"}
)
_BOUNDARY_KEYS = frozenset({"integrity", "performance", "scientific_validity"})
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class ReceiptError(ValueError):
    """A receipt that cannot be built or written from the values given."""


@dataclass(frozen=True)
class SigningKey:
    """A shared HMAC key. ``material`` is excluded from ``repr`` so it cannot leak into logs."""

    material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.material, bytes) or not self.material:
            raise ReceiptError("a signing key must be non-empty bytes")

    @property
    def key_id(self) -> str:
        """SHA-256 of the key: identifies the key without revealing it."""
        return sha256_bytes(self.material)

    def sign(self, body: Mapping[str, Any]) -> str:
        """The HMAC-SHA256 authenticator over the canonical body, as lowercase hex.

        Anyone holding the key can compute this value, so it authenticates
        the statement between key holders. It is not a public signature.
        """
        return hmac.new(self.material, canonical_bytes(body), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class KeyResolution:
    """The key to authenticate with, or None, and a one-line reason that never quotes the key."""

    key: SigningKey | None
    detail: str


def resolve_signing_key(environ: Mapping[str, str] | None = None) -> KeyResolution:
    """Find the shared key named by ``SCIENCE_GATE_HMAC_KEY_FILE``.

    The key is the key file's exact bytes: no trimming, so the same file
    always yields the same key on every platform. Every way of not having a
    usable key (variable unset, file missing, unreadable, empty or oversized)
    yields ``key=None`` and an explanation, and the receipt is then UNSIGNED.
    Nothing here raises: a missing key is a fact to report, not a crash. The
    explanation names the variable, never its value, so neither the key nor
    the key file's location reaches any output.
    """
    source = os.environ if environ is None else environ
    location = source.get(HMAC_KEY_FILE_ENV, "")
    if not location:
        return KeyResolution(None, f"{HMAC_KEY_FILE_ENV} is not set")
    try:
        with open(location, "rb") as handle:
            material = handle.read(MAX_KEY_BYTES + 1)
    except OSError as exc:
        reason = exc.strerror or "error"
        return KeyResolution(None, f"{HMAC_KEY_FILE_ENV} names a key file that cannot be read ({reason})")
    if not material:
        return KeyResolution(None, f"{HMAC_KEY_FILE_ENV} names an empty key file")
    if len(material) > MAX_KEY_BYTES:
        return KeyResolution(None, f"{HMAC_KEY_FILE_ENV} names a file larger than {MAX_KEY_BYTES} bytes")
    key = SigningKey(material)
    return KeyResolution(key, f"authenticating with the {AUTH_ALGORITHM} shared key {key.key_id}")


# ---------------------------------------------------------------------------
# The statement
# ---------------------------------------------------------------------------


def _subject(name: str, sha256: str) -> dict[str, Any]:
    """One receipt subject: a named artifact and its SHA-256 digest."""
    if not isinstance(name, str) or not name:
        raise ReceiptError("a subject name must be a non-empty string")
    if not isinstance(sha256, str) or not _SHA256_HEX.fullmatch(sha256):
        raise ReceiptError(f"subject {name!r} needs a lowercase hex SHA-256 digest")
    return {"name": name, "digest": {"sha256": sha256}}


def build_body(
    *,
    subjects: Mapping[str, str],
    predicate: Mapping[str, Any],
    integrity: str,
    performance: str,
) -> dict[str, Any]:
    """Assemble a receipt body. Scientific validity is fixed, not a parameter.

    ``subjects`` maps each artifact name to its SHA-256. They are emitted
    sorted by name, so the body (and so its hash) does not depend on the
    order in which inputs were declared.
    """
    for label, text in (("integrity", integrity), ("performance", performance)):
        if not isinstance(text, str) or not text.strip():
            raise ReceiptError(f"the {label} statement must be non-empty text")
    return {
        "schema": RECEIPT_SCHEMA,
        "subject": [_subject(name, subjects[name]) for name in sorted(subjects)],
        "predicate_type": PREDICATE_TYPE,
        "predicate": dict(predicate),
        "evidence_boundary": {
            "integrity": integrity,
            "performance": performance,
            "scientific_validity": SCIENTIFIC_VALIDITY,
        },
        "disclaimer": DISCLAIMER,
    }


def run_subjects(accounting: InputAccounting) -> dict[str, str]:
    """``{input_id: sha256}`` for every input that has a digest.

    Inputs without a digest (missing, refused) cannot be subjects, but they
    are not dropped from the receipt: :func:`run_predicate` lists every input
    with its state.
    """
    return {record.input_id: record.sha256 for record in accounting.records if record.sha256 is not None}


def run_predicate(run: RunResult, *, ledger_head_sha256: str | None, ledger_length: int) -> dict[str, Any]:
    """The run summary that a receipt attests to.

    Each check contributes the hash of its evidence rather than the evidence
    itself, and the run's checker controls (PLAN, falsifier witnesses, canary,
    comparator self-test, pins) contribute ``controls_sha256``: the receipt
    stays small, yet any change to recorded evidence or to the proof that the
    checkers could fail, beneath an unchanged verdict, still changes the
    receipt's content hash.
    """
    if isinstance(ledger_length, bool) or not isinstance(ledger_length, int) or ledger_length < 0:
        raise ReceiptError("ledger_length must be a non-negative int")
    if ledger_head_sha256 is not None and not _SHA256_HEX.fullmatch(str(ledger_head_sha256)):
        raise ReceiptError("ledger_head_sha256 must be a lowercase hex SHA-256 digest or None")
    if (ledger_head_sha256 is None) != (ledger_length == 0):
        raise ReceiptError("an empty ledger has no head, and a non-empty ledger must have one")
    accounting = run.accounting
    return {
        "run_id": run.run_id,
        "status": run.status.value,
        "reason": run.reason.value,
        "reasons": [reason.value for reason in run.reasons],
        "failure_modes": [mode.value for mode in run.failure_modes],
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "counters": dict(run.counters),
        "input_accounting": {
            "counters": {name: count.to_dict() for name, count in accounting.counters.items()},
            "closure": accounting.closure.to_dict(),
        },
        "inputs": [
            {
                "id": record.input_id,
                "path": record.path,
                "required": record.required,
                "state": record.state.value,
                "sha256": record.sha256,
                "bytes": record.size_bytes,
                "rows": record.rows,
            }
            for record in accounting.records
        ],
        "checks": [
            {
                "check_id": check.check_id,
                "kind": check.kind,
                "version": check.version,
                "required": check.required,
                "execution_state": check.execution_state.value,
                "verdict": check.verdict.value,
                "reason": check.reason.value,
                "rows_examined": check.rows_examined,
                "invocation_id": check.invocation_id,
                "evidence_sha256": sha256_canonical(check.evidence),
            }
            for check in run.checks
        ],
        "invariants": [
            {"name": item.name, "applicable": item.applicable, "holds": item.holds} for item in run.invariants
        ],
        "ledger_head_sha256": ledger_head_sha256,
        "ledger_length": ledger_length,
        "evidence_manifest_sha256": run.evidence_manifest_sha256,
        "controls_sha256": sha256_canonical(run.controls),
        "tool": {"name": TOOL_NAME, "version": __version__},
    }


def _integrity_statement(run: RunResult, ledger_head_sha256: str | None, ledger_length: int) -> str:
    """What the receipt can say about integrity, including what it cannot."""
    records = run.accounting.records
    hashed = [record for record in records if record.sha256 is not None]
    unhashed = [f"{record.input_id} ({record.state.value})" for record in records if record.sha256 is None]
    parts = [f"SHA-256 recorded for {len(hashed)} of {len(records)} declared input(s)"]
    if unhashed:
        parts.append(f"no digest for {', '.join(unhashed)}")
    parts.append(f"execution ledger sealed at {ledger_length} entr{'y' if ledger_length == 1 else 'ies'}")
    if ledger_head_sha256 is not None:
        parts.append(f"ledger head {ledger_head_sha256}")
    manifest = run.evidence_manifest_sha256
    parts.append(f"evidence manifest {manifest}" if manifest else "no evidence manifest recorded")
    return "; ".join(parts) + "."


def _count(value: Any) -> str:
    """The size of a recorded id list, or "unknown": an absent list is never a zero."""
    return str(len(value)) if isinstance(value, (list, tuple)) else "unknown"


def _control_outcome(name: str, control: Any) -> str:
    """One control's outcome in words. Only a recorded ``holds: true`` reads as held."""
    if not isinstance(control, Mapping):
        return f"{name} not recorded"
    holds = control.get("holds")
    if holds is True:
        return f"{name} held"
    if holds is False:
        return f"{name} did NOT hold"
    return f"{name} outcome unknown"


def _checker_statement(controls: Mapping[str, Any]) -> str:
    """What the run's controls show about whether its checkers could fail (D4, ``CHECKER:``).

    Falsifier witnesses are counted per :class:`~science_gate.models.WitnessState`;
    the canary and the comparator self-test are stated as held, not held, or
    not recorded. A control the run did not record is said to be missing,
    never assumed to have held.
    """
    falsifiers = controls.get("falsifiers")
    if isinstance(falsifiers, Mapping):
        counts = ", ".join(f"{_count(falsifiers.get(state.value))} {state.value}" for state in WitnessState)
        invocations = falsifiers.get("invocations")
        shown = invocations if isinstance(invocations, int) and not isinstance(invocations, bool) else "unknown"
        witnesses = f"falsifier witnesses {counts} ({shown} falsifier invocation(s))"
    else:
        witnesses = "falsifier witnesses not recorded"
    canary = _control_outcome("must-fail/must-pass canary", controls.get("canary"))
    comparator = _control_outcome("comparator self-test", controls.get("comparator_self_test"))
    return f"{witnesses}; {canary}; {comparator}"


def _performance_statement(run: RunResult) -> str:
    """How the checkers and the declared checks behaved, stated as counts and never as validity.

    Two labelled parts (D4): ``CHECKER:`` says whether the checkers were shown
    able to fail, ``RUN:`` tallies what the declared checks concluded. Keeping
    them apart stops a clean tally from implying that the checkers worked.
    """
    verdicts = {status: 0 for status in Status}
    for check in run.checks:
        verdicts[check.verdict] += 1
    tally = ", ".join(f"{count} {status.value}" for status, count in verdicts.items())
    applicable = [item for item in run.invariants if item.applicable]
    violated = sum(1 for item in applicable if item.violated)
    return (
        f"CHECKER: {_checker_statement(run.controls)}. "
        f"RUN: Run status {run.status.value} ({run.reason.value}) from {len(run.checks)} check result(s): {tally}; "
        f"{len(applicable)} applicable invariant(s), {violated} violated. "
        "This describes how the declared checks behaved on the declared inputs only."
    )


def build_run_body(run: RunResult, *, ledger_head_sha256: str | None, ledger_length: int) -> dict[str, Any]:
    """The receipt body (the statement) for a finished run."""
    return build_body(
        subjects=run_subjects(run.accounting),
        predicate=run_predicate(run, ledger_head_sha256=ledger_head_sha256, ledger_length=ledger_length),
        integrity=_integrity_statement(run, ledger_head_sha256, ledger_length),
        performance=_performance_statement(run),
    )


def seal_body(body: Mapping[str, Any], resolution: KeyResolution) -> dict[str, Any]:
    """The in-memory record of ``body``: its content hash and, when a key resolved, its authenticator.

    ``detail`` keeps the key resolution's explanation, which an unsigned
    sidecar must carry so that "unsigned" always comes with its reason.
    """
    key = resolution.key
    state = SignatureState.UNSIGNED if key is None else SignatureState.SIGNED_HMAC_SHA256
    return {
        "body": dict(body),
        "content_sha256": sha256_canonical(body),
        "signature_state": state.value,
        "signature": None if key is None else key.sign(body),
        "key_id": None if key is None else key.key_id,
        "detail": resolution.detail,
    }


def build_run_receipt(
    run: RunResult,
    *,
    ledger_head_sha256: str | None,
    ledger_length: int,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build and seal the receipt record for ``run``, authenticating it when a key is configured.

    ``environ`` defaults to the process environment; tests pass their own
    mapping so that they never depend on, or disturb, the caller's.
    """
    body = build_run_body(run, ledger_head_sha256=ledger_head_sha256, ledger_length=ledger_length)
    return seal_body(body, resolve_signing_key(environ))


# ---------------------------------------------------------------------------
# Writing: a bare statement plus its sidecar
# ---------------------------------------------------------------------------


def auth_file_name(statement_name: str) -> str:
    """The sidecar's file name for a statement file name: ``receipt.json`` gives ``receipt.auth.json``.

    The statement name must be a bare ``*.json`` file name, because the
    sidecar records it and is looked up beside it. A name that already ends
    in ``.auth.json`` is refused, so a statement can never be mistaken for a
    sidecar.
    """
    if (
        not isinstance(statement_name, str)
        or "/" in statement_name
        or "\\" in statement_name
        or not statement_name.endswith(_STATEMENT_SUFFIX)
        or statement_name.endswith(_AUTH_SUFFIX)
        or statement_name in (_STATEMENT_SUFFIX, "")
    ):
        raise ReceiptError(f"a receipt statement needs a bare '*{_STATEMENT_SUFFIX}' file name, not {statement_name!r}")
    return statement_name[: -len(_STATEMENT_SUFFIX)] + _AUTH_SUFFIX


def _checked_record(record: Mapping[str, Any]) -> tuple[Mapping[str, Any], SignatureState]:
    """Refuse to write a record whose parts disagree.

    The content hash must be the hash of the body, an UNSIGNED record must
    have neither authenticator nor key id but must have its reason, and a
    signed record must carry both as 64 hex characters. An empty or absent
    authenticator on a record that claims one is refused (D9).
    """
    if not isinstance(record, Mapping) or set(record) != RECORD_KEYS:
        raise ReceiptError(f"a receipt record has exactly the keys {sorted(RECORD_KEYS)}")
    body = record["body"]
    if not isinstance(body, Mapping):
        raise ReceiptError("a receipt record's body must be a mapping")
    if record["content_sha256"] != sha256_canonical(body):
        raise ReceiptError("the record's content_sha256 is not the hash of its body; refusing to write it")
    try:
        state = SignatureState(record["signature_state"])
    except ValueError:
        raise ReceiptError(f"unknown signature_state {record['signature_state']!r}") from None
    signature, key_id = record["signature"], record["key_id"]
    if state is SignatureState.UNSIGNED:
        if signature is not None or key_id is not None:
            raise ReceiptError("an UNSIGNED record must have no signature and no key_id")
        if not isinstance(record["detail"], str) or not record["detail"].strip():
            raise ReceiptError("an UNSIGNED record must say why it is unsigned")
    elif not all(isinstance(value, str) and _SHA256_HEX.fullmatch(value) for value in (signature, key_id)):
        raise ReceiptError("a signed record needs a 64-hex authenticator and key_id; an empty one is never written")
    return body, state


def receipt_files(record: Mapping[str, Any], *, statement_name: str = STATEMENT_FILE) -> dict[str, bytes]:
    """The two files a receipt record becomes: ``{statement_name: statement, sidecar_name: sidecar}``.

    The statement is the canonical body plus a newline, so the bytes that
    were hashed and authenticated appear verbatim and anyone can re-check
    them with a standard SHA-256 tool. The sidecar names the statement, repeats
    its content hash, and holds either the authenticator or UNSIGNED with its
    reason, with no ``signature`` key at all.
    """
    body, state = _checked_record(record)
    sidecar: dict[str, Any] = {
        "schema": AUTH_SCHEMA,
        "statement": statement_name,
        "content_sha256": record["content_sha256"],
        "signature_state": state.value,
    }
    if state is SignatureState.UNSIGNED:
        sidecar["detail"] = record["detail"]
    else:
        sidecar.update(algorithm=AUTH_ALGORITHM, signature=record["signature"], key_id=record["key_id"])
    return {
        statement_name: canonical_bytes(body) + b"\n",
        auth_file_name(statement_name): canonical_bytes(sidecar) + b"\n",
    }


def receipt_bytes(record: Mapping[str, Any]) -> bytes:
    """The statement file's bytes for ``record``: canonical JSON and a final newline."""
    return receipt_files(record)[STATEMENT_FILE]


def write_receipt(root: str | os.PathLike[str], relpath: str, record: Mapping[str, Any]) -> tuple[Path, Path]:
    """Write the statement at ``relpath`` and its sidecar beside it, both through ``safe_write``.

    Returns ``(statement_path, sidecar_path)``. The statement is written
    first: if the sidecar cannot be written, what remains is a statement
    without authentication, which :func:`verify_receipt` reports as
    ``AUTH_SIDECAR_MISSING``, never as unsigned.
    """
    directory, _, name = relpath.replace("\\", "/").rpartition("/")
    prefix = f"{directory}/" if directory else ""
    files = receipt_files(record, statement_name=name)
    statement, sidecar = (safe_write(root, prefix + file, data) for file, data in files.items())
    return statement, sidecar


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReceiptVerification:
    """The outcome of re-checking a statement and its sidecar.

    ``content_intact`` is True only when the sidecar's ``content_sha256``
    equals the hash recomputed from the statement. ``signature_state`` is
    what the sidecar *declares*; ``auth_status`` is what checking
    *established*, and is None when the sidecar is missing or unusable, so
    a stripped sidecar never reads as UNSIGNED. ``problems`` lists every
    defect found; ``ok`` requires none. ``run_id`` is the run the statement
    attests, when it is a run receipt.
    """

    content_intact: bool
    recomputed_sha256: str | None
    signature_state: SignatureState | None
    auth_status: AuthStatus | None
    problems: tuple[str, ...]
    detail: str
    run_id: str | None

    @property
    def ok(self) -> bool:
        return self.content_intact and not self.problems

    @property
    def signature_verified(self) -> bool | None:
        """True only for SIGNED_VERIFIED and False only for SIGNED_FAILED; None means "not checked"."""
        if self.auth_status is AuthStatus.SIGNED_VERIFIED:
            return True
        if self.auth_status is AuthStatus.SIGNED_FAILED:
            return False
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "content_intact": self.content_intact,
            "recomputed_sha256": self.recomputed_sha256,
            "signature_state": None if self.signature_state is None else self.signature_state.value,
            "signature_verified": self.signature_verified,
            "auth_status": None if self.auth_status is None else self.auth_status.value,
            "run_id": self.run_id,
            "problems": list(self.problems),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class _Sidecar:
    """A sidecar that passed structural validation."""

    signature_state: SignatureState
    content_sha256: str
    detail: str | None
    signature: str | None
    key_id: str | None


def _required_problem(auth_status: AuthStatus | None) -> str:
    """The SIGNATURE_REQUIRED problem for any outcome short of SIGNED_VERIFIED."""
    shown = "could not be determined" if auth_status is None else f"is {auth_status.value}"
    return f"SIGNATURE_REQUIRED: a verified {AUTH_ALGORITHM} authenticator was required, but the receipt {shown}"


def _unverifiable(problem: str, *, require_signature: bool) -> ReceiptVerification:
    """A verification that could not get as far as the statement's content."""
    problems = (problem, _required_problem(None)) if require_signature else (problem,)
    return ReceiptVerification(False, None, None, None, problems, "", None)


def _is_subject(item: Any) -> bool:
    """True for ``{"name": <non-empty str>, "digest": {"sha256": <hex>}}`` exactly."""
    try:
        _subject(item["name"], item["digest"]["sha256"])
    except (ReceiptError, KeyError, TypeError):
        return False
    return set(item) == {"name", "digest"} and set(item["digest"]) == {"sha256"}


def _statement_problems(statement: Any) -> list[str]:
    """Structural defects of a statement, including a weakened evidence boundary."""
    if not isinstance(statement, dict):
        return ["MALFORMED_RECEIPT: the statement is not a JSON object"]
    problems: list[str] = []
    if set(statement) != BODY_KEYS:
        problems.append(f"MALFORMED_RECEIPT: statement keys {sorted(statement)} are not {sorted(BODY_KEYS)}")
    if statement.get("schema") != RECEIPT_SCHEMA:
        problems.append(f"SCHEMA_MISMATCH: statement schema is {statement.get('schema')!r}")
    if statement.get("predicate_type") != PREDICATE_TYPE:
        problems.append(f"SCHEMA_MISMATCH: predicate_type is {statement.get('predicate_type')!r}")
    boundary = statement.get("evidence_boundary")
    if not isinstance(boundary, dict) or set(boundary) != _BOUNDARY_KEYS:
        problems.append("MALFORMED_RECEIPT: evidence_boundary must have integrity, performance, scientific_validity")
    elif boundary["scientific_validity"] != SCIENTIFIC_VALIDITY:
        problems.append(f"BOUNDARY_VIOLATION: scientific_validity must be {SCIENTIFIC_VALIDITY!r}")
    if statement.get("disclaimer") != DISCLAIMER:
        problems.append("BOUNDARY_VIOLATION: the disclaimer was altered or removed")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not all(_is_subject(item) for item in subjects):
        problems.append("MALFORMED_RECEIPT: every subject needs a name and a sha256 digest")
    return problems


def _parse_sidecar(document: Any, statement_name: str) -> tuple[_Sidecar | None, list[str]]:
    """Validate a parsed sidecar against its schema; malformed means unusable, never unsigned.

    The key set is exact per state, so an UNSIGNED sidecar that carries a
    ``signature`` key (even null or empty) is refused: no file may be an
    envelope with an empty signature (D9).
    """

    def malformed(why: str) -> tuple[None, list[str]]:
        return None, [f"AUTH_SIDECAR_MALFORMED: {why}"]

    if not isinstance(document, dict):
        return malformed("the sidecar is not a JSON object")
    try:
        state = SignatureState(document.get("signature_state"))
    except ValueError:
        return malformed("signature_state is not UNSIGNED or SIGNED_HMAC_SHA256")
    expected = UNSIGNED_AUTH_KEYS if state is SignatureState.UNSIGNED else SIGNED_AUTH_KEYS
    if set(document) != expected:
        keys = f"exactly the keys {sorted(expected)}, not {sorted(document)}"
        return malformed(f"a sidecar in state {state.value} has {keys}")
    if document["schema"] != AUTH_SCHEMA:
        return malformed(f"schema must be {AUTH_SCHEMA!r}")
    if document["statement"] != statement_name:
        return malformed(f"the sidecar does not name the statement {statement_name!r}")
    if not (isinstance(document["content_sha256"], str) and _SHA256_HEX.fullmatch(document["content_sha256"])):
        return malformed("content_sha256 must be 64 lowercase hex characters")
    if state is SignatureState.UNSIGNED:
        detail = document["detail"]
        if not isinstance(detail, str) or not detail.strip():
            return malformed("an UNSIGNED sidecar must say why it is unsigned")
        return _Sidecar(state, document["content_sha256"], detail, None, None), []
    if document["algorithm"] != AUTH_ALGORITHM:
        return malformed(f"algorithm must be {AUTH_ALGORITHM!r}")
    for name in ("signature", "key_id"):
        if not (isinstance(document[name], str) and _SHA256_HEX.fullmatch(document[name])):
            return malformed(f"{name} must be 64 lowercase hex characters")
    return _Sidecar(state, document["content_sha256"], None, document["signature"], document["key_id"]), []


def _authenticate(
    statement: Any, recomputed: str | None, sidecar: _Sidecar | None, key: SigningKey | None
) -> tuple[AuthStatus | None, str, list[str]]:
    """Judge the authenticator: ``(auth_status, detail, problems)``.

    Only a recomputed HMAC can give SIGNED_VERIFIED or SIGNED_FAILED. A
    signed sidecar with no matching key, or over a statement that is not
    canonical JSON, is SIGNED_UNCHECKED: nothing about the authenticator is
    known, so it is neither good nor bad.
    """
    if sidecar is None:
        return None, "", []
    if sidecar.signature_state is SignatureState.UNSIGNED:
        return AuthStatus.UNSIGNED, f"no key when written: {sidecar.detail}; only the content hash was checked", []
    key_id = sidecar.key_id
    unchecked = AuthStatus.SIGNED_UNCHECKED
    if recomputed is None:
        return unchecked, "the statement is not canonical JSON, so the authenticator was not checked", []
    if key is None:
        return unchecked, f"authenticated with shared key {key_id}, but no key is available to check it", []
    if key.key_id != key_id:
        other = f"the available key is {key.key_id}"
        return unchecked, f"authenticated with shared key {key_id}, but {other}; not checked", []
    if hmac.compare_digest(key.sign(statement), sidecar.signature or ""):
        return AuthStatus.SIGNED_VERIFIED, f"{AUTH_ALGORITHM} shared-key authenticator verified with key {key_id}", []
    mismatch = f"the {AUTH_ALGORITHM} authenticator does not match the statement"
    return AuthStatus.SIGNED_FAILED, mismatch, [f"SIGNATURE_MISMATCH: {mismatch}"]


def _attested_run_id(statement: Any) -> str | None:
    """The run id a run receipt's predicate names, if it names one."""
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    run_id = predicate.get("run_id") if isinstance(predicate, dict) else None
    return run_id if isinstance(run_id, str) else None


def _judge(
    statement: Any,
    sidecar: _Sidecar | None,
    sidecar_problems: list[str],
    *,
    key: SigningKey | None,
    require_signature: bool,
) -> ReceiptVerification:
    """Combine the statement's own checks with what its sidecar establishes."""
    if isinstance(statement, dict) and "body" in statement:
        legacy = (
            "LEGACY_ENVELOPE: the statement file holds a 'body' envelope; a receipt is a bare statement "
            f"with its authentication in {AUTH_FILE}"
        )
        return _unverifiable(legacy, require_signature=require_signature)
    problems = _statement_problems(statement)
    recomputed: str | None = None
    if isinstance(statement, dict):
        try:
            recomputed = sha256_canonical(statement)
        except CanonicalizationError as exc:
            problems.append(f"MALFORMED_RECEIPT: the statement is not canonical JSON: {exc}")
    problems.extend(sidecar_problems)
    content_intact = recomputed is not None and sidecar is not None and sidecar.content_sha256 == recomputed
    if recomputed is not None and sidecar is not None and not content_intact:
        problems.append("CONTENT_HASH_MISMATCH: the sidecar's content_sha256 does not match the statement")
    auth_status, detail, auth_problems = _authenticate(statement, recomputed, sidecar, key)
    problems.extend(auth_problems)
    if require_signature and auth_status is not AuthStatus.SIGNED_VERIFIED:
        problems.append(_required_problem(auth_status))
    return ReceiptVerification(
        content_intact=content_intact,
        recomputed_sha256=recomputed,
        signature_state=None if sidecar is None else sidecar.signature_state,
        auth_status=auth_status,
        problems=tuple(problems),
        detail=detail,
        run_id=_attested_run_id(statement),
    )


def verify_receipt_documents(
    statement: Any,
    auth: Any,
    *,
    statement_name: str = STATEMENT_FILE,
    key: SigningKey | None = None,
    require_signature: bool = False,
) -> ReceiptVerification:
    """Re-check a parsed statement against its parsed sidecar: structure, content hash and authenticator."""
    sidecar, problems = _parse_sidecar(auth, statement_name)
    return _judge(statement, sidecar, problems, key=key, require_signature=require_signature)


def _read_json(directory: Path, name: str, max_bytes: int) -> Any:
    """Read one strict, integers-only JSON file; raises the I/O or parse error for the caller to name."""
    return strict_loads(safe_read(directory, name, max_bytes=max_bytes), integers_only=True)


def verify_receipt(
    path: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    require_signature: bool = False,
) -> ReceiptVerification:
    """Read the statement at ``path`` and its sidecar beside it, and re-check both.

    The key, when one is configured, is taken from ``environ`` (the process
    environment by default) exactly as when the receipt was written. An
    unreadable or malformed file is reported as a problem, never raised, and
    no message carries an absolute path. A missing or malformed sidecar
    leaves ``auth_status`` None: the authentication is unknown, which is
    neither unsigned nor failed.
    """
    location = Path(path)
    try:
        statement = _read_json(location.parent, location.name, MAX_RECEIPT_BYTES)
    except FileNotFoundError:
        return _unverifiable(f"RECEIPT_MISSING: no receipt at {location.name!r}", require_signature=require_signature)
    except SafeIOError as exc:
        return _unverifiable(f"RECEIPT_UNREADABLE: {exc}", require_signature=require_signature)
    except OSError as exc:  # str(exc) would carry an absolute, machine-specific path
        return _unverifiable(f"RECEIPT_UNREADABLE: {exc.strerror or 'error'}", require_signature=require_signature)
    except StrictJSONError as exc:
        return _unverifiable(f"MALFORMED_RECEIPT: {exc}", require_signature=require_signature)
    key = resolve_signing_key(environ).key
    try:
        auth_name = auth_file_name(location.name)
    except ReceiptError as exc:
        return _judge(statement, None, [f"AUTH_SIDECAR_MISSING: {exc}"], key=key, require_signature=require_signature)
    try:
        auth = _read_json(location.parent, auth_name, MAX_AUTH_BYTES)
    except FileNotFoundError:
        problem = f"AUTH_SIDECAR_MISSING: no {auth_name!r} beside the statement; its authentication is unknown"
        return _judge(statement, None, [problem], key=key, require_signature=require_signature)
    except SafeIOError as exc:
        problem = f"AUTH_SIDECAR_MALFORMED: {auth_name!r} cannot be read ({exc})"
        return _judge(statement, None, [problem], key=key, require_signature=require_signature)
    except OSError as exc:
        problem = f"AUTH_SIDECAR_MALFORMED: {auth_name!r} cannot be read ({exc.strerror or 'error'})"
        return _judge(statement, None, [problem], key=key, require_signature=require_signature)
    except StrictJSONError as exc:
        problem = f"AUTH_SIDECAR_MALFORMED: {auth_name!r} is not strict JSON ({exc})"
        return _judge(statement, None, [problem], key=key, require_signature=require_signature)
    return verify_receipt_documents(
        statement, auth, statement_name=location.name, key=key, require_signature=require_signature
    )
