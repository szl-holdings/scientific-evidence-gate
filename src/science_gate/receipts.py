"""Run receipts: a hashed, optionally HMAC-signed summary of a run (section 11).

A receipt lets someone who was not present check three things later: which
input bytes a run saw (``subject`` digests), what the run concluded and on
what execution record (``predicate``, including the sealed ledger head), and
that none of it was edited afterwards (``content_sha256`` and, when a key is
configured, an HMAC-SHA256 ``signature``).

What a receipt does *not* do is written into it. ``evidence_boundary`` keeps
integrity, performance and scientific validity apart, and scientific validity
is always ``"NOT ESTABLISHED"``: callers cannot set it, and a receipt that
claims otherwise fails verification even when its hash was recomputed.

Signing is opt-in and never silent about its absence. When
``SCIENCE_GATE_HMAC_KEY_FILE`` names a readable, non-empty key file the body is
signed; in every other case the receipt says ``UNSIGNED`` with a null
signature. The key never appears in any output, only its SHA-256 (``key_id``),
so a verifier can tell which key to use without learning it.

The receipt file is written in canonical JSON, so the bytes that were hashed
appear verbatim in the file and anyone can re-check them with a standard
SHA-256 tool.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

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
from .models import InputAccounting, RunResult, SignatureState, Status

__all__ = [
    "RECEIPT_SCHEMA",
    "PREDICATE_TYPE",
    "DISCLAIMER",
    "SCIENTIFIC_VALIDITY",
    "HMAC_KEY_FILE_ENV",
    "MAX_KEY_BYTES",
    "MAX_RECEIPT_BYTES",
    "BODY_KEYS",
    "RECEIPT_KEYS",
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
    "receipt_bytes",
    "write_receipt",
    "verify_receipt_document",
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

BODY_KEYS = frozenset({"schema", "subject", "predicate_type", "predicate", "evidence_boundary", "disclaimer"})
RECEIPT_KEYS = frozenset({"body", "content_sha256", "signature_state", "signature", "key_id"})
_BOUNDARY_KEYS = frozenset({"integrity", "performance", "scientific_validity"})
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class ReceiptError(ValueError):
    """A receipt that cannot be built from the values given."""


@dataclass(frozen=True)
class SigningKey:
    """An HMAC key. ``material`` is excluded from ``repr`` so it cannot leak into logs."""

    material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.material, bytes) or not self.material:
            raise ReceiptError("a signing key must be non-empty bytes")

    @property
    def key_id(self) -> str:
        """SHA-256 of the key: identifies the key without revealing it."""
        return sha256_bytes(self.material)

    def sign(self, body: Mapping[str, Any]) -> str:
        """HMAC-SHA256 over the canonical body, as lowercase hex."""
        return hmac.new(self.material, canonical_bytes(body), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class KeyResolution:
    """The key to sign with, or None, and a one-line reason that never quotes the key."""

    key: SigningKey | None
    detail: str


def resolve_signing_key(environ: Mapping[str, str] | None = None) -> KeyResolution:
    """Find the signing key named by ``SCIENCE_GATE_HMAC_KEY_FILE``.

    The key is the key file's exact bytes: no trimming, so the same file
    always yields the same key on every platform. Every way of not having a
    usable key (variable unset, file missing, unreadable, empty or oversized)
    yields ``key=None`` and an explanation, and the receipt is then UNSIGNED.
    Nothing here raises: a missing key is a fact to report, not a crash.
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
    return KeyResolution(key, f"signing with HMAC-SHA256 key {key.key_id}")


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
    itself: the receipt stays small, yet any change to recorded evidence
    beneath an unchanged verdict still changes the receipt's content hash.
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


def _performance_statement(run: RunResult) -> str:
    """How the declared checks behaved, stated as counts and never as validity."""
    verdicts = {status: 0 for status in Status}
    for check in run.checks:
        verdicts[check.verdict] += 1
    tally = ", ".join(f"{count} {status.value}" for status, count in verdicts.items())
    applicable = [item for item in run.invariants if item.applicable]
    violated = sum(1 for item in applicable if item.violated)
    return (
        f"Run status {run.status.value} ({run.reason.value}) from {len(run.checks)} check result(s): {tally}; "
        f"{len(applicable)} applicable invariant(s), {violated} violated. "
        "This describes how the declared checks behaved on the declared inputs only."
    )


def build_run_body(run: RunResult, *, ledger_head_sha256: str | None, ledger_length: int) -> dict[str, Any]:
    """The receipt body for a finished run."""
    return build_body(
        subjects=run_subjects(run.accounting),
        predicate=run_predicate(run, ledger_head_sha256=ledger_head_sha256, ledger_length=ledger_length),
        integrity=_integrity_statement(run, ledger_head_sha256, ledger_length),
        performance=_performance_statement(run),
    )


def seal_body(body: Mapping[str, Any], key: SigningKey | None) -> dict[str, Any]:
    """Wrap a body with its content hash and, when a key is given, its signature."""
    state = SignatureState.UNSIGNED if key is None else SignatureState.SIGNED_HMAC_SHA256
    return {
        "body": dict(body),
        "content_sha256": sha256_canonical(body),
        "signature_state": state.value,
        "signature": None if key is None else key.sign(body),
        "key_id": None if key is None else key.key_id,
    }


def build_run_receipt(
    run: RunResult,
    *,
    ledger_head_sha256: str | None,
    ledger_length: int,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build and seal the receipt for ``run``, signing it when a key is configured.

    ``environ`` defaults to the process environment; tests pass their own
    mapping so that they never depend on, or disturb, the caller's.
    """
    body = build_run_body(run, ledger_head_sha256=ledger_head_sha256, ledger_length=ledger_length)
    return seal_body(body, resolve_signing_key(environ).key)


def receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    """The receipt file's bytes: canonical JSON and a final newline."""
    return canonical_bytes(receipt) + b"\n"


def write_receipt(root: str | os.PathLike[str], relpath: str, receipt: Mapping[str, Any]) -> Path:
    """Write a receipt under ``root`` through :func:`~science_gate._safeio.safe_write`."""
    return safe_write(root, relpath, receipt_bytes(receipt))


@dataclass(frozen=True)
class ReceiptVerification:
    """The outcome of re-checking a receipt.

    ``content_intact`` is True only when the stored ``content_sha256`` equals
    the recomputed hash. ``signature_verified`` is None whenever the signature
    could not be checked (unsigned, or no matching key available), so an
    unchecked signature is never reported as a good one. ``problems`` lists
    every defect found, a bad signature included; ``ok`` requires none.
    """

    content_intact: bool
    recomputed_sha256: str | None
    signature_state: SignatureState | None
    signature_verified: bool | None
    problems: tuple[str, ...]
    detail: str

    @property
    def ok(self) -> bool:
        return self.content_intact and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "content_intact": self.content_intact,
            "recomputed_sha256": self.recomputed_sha256,
            "signature_state": None if self.signature_state is None else self.signature_state.value,
            "signature_verified": self.signature_verified,
            "problems": list(self.problems),
            "detail": self.detail,
        }


def _failed(problem: str) -> ReceiptVerification:
    """A verification that could not get as far as the receipt's content."""
    return ReceiptVerification(False, None, None, None, (problem,), "")


def _is_subject(item: Any) -> bool:
    """True for ``{"name": <non-empty str>, "digest": {"sha256": <hex>}}`` exactly."""
    try:
        _subject(item["name"], item["digest"]["sha256"])
    except (ReceiptError, KeyError, TypeError):
        return False
    return set(item) == {"name", "digest"} and set(item["digest"]) == {"sha256"}


def _body_problems(body: Any) -> list[str]:
    """Structural defects of a body, including a weakened evidence boundary."""
    if not isinstance(body, dict):
        return ["MALFORMED_RECEIPT: body is not an object"]
    problems: list[str] = []
    if set(body) != BODY_KEYS:
        problems.append(f"MALFORMED_RECEIPT: body keys {sorted(body)} are not {sorted(BODY_KEYS)}")
    if body.get("schema") != RECEIPT_SCHEMA:
        problems.append(f"SCHEMA_MISMATCH: body schema is {body.get('schema')!r}")
    if body.get("predicate_type") != PREDICATE_TYPE:
        problems.append(f"SCHEMA_MISMATCH: predicate_type is {body.get('predicate_type')!r}")
    boundary = body.get("evidence_boundary")
    if not isinstance(boundary, dict) or set(boundary) != _BOUNDARY_KEYS:
        problems.append("MALFORMED_RECEIPT: evidence_boundary must have integrity, performance, scientific_validity")
    elif boundary["scientific_validity"] != SCIENTIFIC_VALIDITY:
        problems.append(f"BOUNDARY_VIOLATION: scientific_validity must be {SCIENTIFIC_VALIDITY!r}")
    if body.get("disclaimer") != DISCLAIMER:
        problems.append("BOUNDARY_VIOLATION: the disclaimer was altered or removed")
    subjects = body.get("subject")
    if not isinstance(subjects, list) or not all(_is_subject(item) for item in subjects):
        problems.append("MALFORMED_RECEIPT: every subject needs a name and a sha256 digest")
    return problems


def _signature_findings(
    document: Mapping[str, Any], state: SignatureState, body: Any, key: SigningKey | None
) -> tuple[bool | None, list[str], str]:
    """Judge the signature fields: ``(verified, problems, detail)``.

    ``verified`` stays None unless an HMAC was actually recomputed, so a
    receipt signed with an unknown key reads as "not checked", never "good".
    """
    signature, key_id = document.get("signature"), document.get("key_id")
    if state is SignatureState.UNSIGNED:
        if signature is not None or key_id is not None:
            return None, ["MALFORMED_RECEIPT: an UNSIGNED receipt must have null signature and key_id"], ""
        return None, [], "the receipt is unsigned; only its content hash was checked"
    if not (isinstance(signature, str) and _SHA256_HEX.fullmatch(signature)):
        return None, ["MALFORMED_RECEIPT: signature must be 64 lowercase hex characters"], ""
    if not (isinstance(key_id, str) and _SHA256_HEX.fullmatch(key_id)):
        return None, ["MALFORMED_RECEIPT: key_id must be 64 lowercase hex characters"], ""
    if key is None:
        return None, [], f"signed with key {key_id}, but no key is available to check the signature"
    if key.key_id != key_id:
        return None, [], f"signed with key {key_id}, but the available key is {key.key_id}; signature not checked"
    if hmac.compare_digest(key.sign(body), signature):
        return True, [], "signature verified"
    return False, ["SIGNATURE_MISMATCH: the HMAC-SHA256 signature does not match the body"], ""


def verify_receipt_document(document: Any, *, key: SigningKey | None = None) -> ReceiptVerification:
    """Re-check a parsed receipt: structure, content hash and, if possible, signature."""
    if not isinstance(document, dict):
        return _failed("MALFORMED_RECEIPT: not a JSON object")
    problems: list[str] = []
    if set(document) != RECEIPT_KEYS:
        problems.append(f"MALFORMED_RECEIPT: keys {sorted(document)} are not {sorted(RECEIPT_KEYS)}")
    body = document.get("body")
    problems.extend(_body_problems(body))
    recomputed: str | None = None
    if isinstance(body, dict):
        try:
            recomputed = sha256_canonical(body)
        except CanonicalizationError as exc:
            problems.append(f"MALFORMED_RECEIPT: body is not canonical JSON: {exc}")
    content_intact = recomputed is not None and document.get("content_sha256") == recomputed
    if recomputed is not None and not content_intact:
        problems.append("CONTENT_HASH_MISMATCH: content_sha256 does not match the body")

    try:
        state = SignatureState(document.get("signature_state"))
    except ValueError:
        problems.append(f"MALFORMED_RECEIPT: unknown signature_state {document.get('signature_state')!r}")
        return ReceiptVerification(content_intact, recomputed, None, None, tuple(problems), "")
    if recomputed is None:
        # Without a hashable body there is nothing a signature could be checked against.
        return ReceiptVerification(content_intact, recomputed, state, None, tuple(problems), "")
    verified, signature_problems, detail = _signature_findings(document, state, body, key)
    problems.extend(signature_problems)
    return ReceiptVerification(content_intact, recomputed, state, verified, tuple(problems), detail)


def verify_receipt(path: str | os.PathLike[str], *, environ: Mapping[str, str] | None = None) -> ReceiptVerification:
    """Read the receipt at ``path`` and re-check it.

    The signing key, when one is configured, is taken from ``environ`` (the
    process environment by default) exactly as when signing. An unreadable or
    malformed file is reported as a problem, never raised.
    """
    location = Path(path)
    try:
        data = safe_read(location.parent, location.name, max_bytes=MAX_RECEIPT_BYTES)
    except FileNotFoundError:
        return _failed(f"RECEIPT_MISSING: no receipt at {location.name!r}")
    except SafeIOError as exc:
        return _failed(f"RECEIPT_UNREADABLE: {exc}")
    except OSError as exc:  # str(exc) would carry an absolute, machine-specific path
        return _failed(f"RECEIPT_UNREADABLE: {exc.strerror or 'error'}")
    try:
        document = strict_loads(data, integers_only=True)
    except StrictJSONError as exc:
        return _failed(f"MALFORMED_RECEIPT: {exc}")
    return verify_receipt_document(document, key=resolve_signing_key(environ).key)
