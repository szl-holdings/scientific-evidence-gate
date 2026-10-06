"""Evaluation packaging (ARCHITECTURE.md section 13).

``science-gate package MANIFEST --output PATH [--force]`` turns a verification
project into a package that someone else can execute locally and compare with
the results recorded here. Copying files is the easy part. The hard part is
deciding which files may leave the operator's machine, and making sure every
file that stays behind is still accounted for. The rules, in order of
precedence:

* **The access class decides first.** CONTROLLED_LOCAL and REFERENCE_ONLY data
  is never copied, whatever its permissions say. Only its SHA-256, its size
  and retrieval instructions go into the package. A manifest that declares no
  corpus is CONTROLLED_LOCAL (see :class:`~science_gate.manifests.CorpusSpec`),
  so data can never be shared by omission.
* **Permissions decide next.** PUBLIC and SYNTHETIC data is copied only when
  ``redistribution_allowed`` is true. The one exception is a SYNTHETIC corpus
  that declares no permissions at all, which keeps its default synthetic
  permissions. Declared permissions are taken at their word, so a SYNTHETIC
  corpus that declares permissions without allowing redistribution is not
  copied.
* **The manifest follows the data rule.** Check parameters can quote data
  values, such as expected keys and expected numbers, so the manifest is
  copied only when the data is.
* **Nothing is altered.** A file is either copied byte for byte or withheld
  whole, because any edit would break the digest that ties it to the expected
  results. This is why a file whose content matches a secret pattern is
  withheld rather than redacted.
* **Nothing is dropped.** ``package.json`` lists every evaluation file: the
  manifest, the inputs, and every document a check read. Each gets a
  disposition. INCLUDED means copied. WITHHELD means only its digest and
  retrieval instructions are in the package. UNAVAILABLE means no digest could
  be pinned. If a needed file is UNAVAILABLE, the package is INCOMPLETE and
  the command exits 2, never 0.

The expected results come from running :func:`~science_gate.verifier.verify`
on the project at packaging time, offline. They are the reproducible part of
that run's receipt predicate. Run ids, timestamps, invocation ids and the
ledger head come from the clock, so they differ on every faithful
re-execution. They are recorded as provenance, not as expectations. Nothing
that quotes input content (check evidence, diagnostics) is packaged. Evidence
appears only as its SHA-256, which a re-execution can match exactly.

Layout of a package::

    package.json            the index (science-gate-package/v1), written last
    schemas/*.schema.json   the schemas, from the source tree
    expected/receipt.json   receipt of the packaging-time run
    evaluation/...          manifest and data, at their manifest-relative paths

The evaluation tree is kept under its own directory. Manifest-relative paths
therefore can never collide with files the tool writes, and
``science-gate verify evaluation/<manifest>`` works unchanged.

Output is confined in four ways:

* Every write goes through :func:`~science_gate._safeio.safe_write` under
  ``--output``.
* An output inside the manifest directory is refused. That directory is the
  root of every declared input, so an output inside it is inside an input
  directory.
* An output that contains the manifest directory is refused.
* Existing output is refused unless ``--force`` is given. Even then, only a
  previous package whose every file is listed in its own ``package.json`` is
  replaced, so ``--force`` can never delete a file this command did not write.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import sys
import urllib.error
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterator, Mapping, Sequence, TextIO

from . import TOOL_NAME, __version__
from ._canonical import StrictJSONError, normalize, pretty_json_bytes, sha256_bytes, strict_loads
from ._clock import now
from ._redact import redact, redact_text
from ._resources import bundled_dir
from ._safeio import (
    SafeIOError,
    UnsafePathError,
    is_within,
    normalize_relpath,
    resolve_under_root,
    safe_read,
    safe_write,
)
from .manifests import MAX_MANIFEST_BYTES, ApprovedRedaction, Manifest, ManifestError, SourceLicense, load_manifest
from .models import EXIT_CODE, AccessClass, InputState, Permissions, Status
from .receipts import SCIENTIFIC_VALIDITY, build_run_receipt, receipt_bytes
from .verifier import NetworkPolicy, VerificationRun, verify

__all__ = [
    "PACKAGE_SCHEMA",
    "PACKAGE_JSON",
    "EVALUATION_DIR",
    "SCHEMAS_DIR",
    "EXPECTED_RECEIPT",
    "SOURCE_SCHEMAS_DIR",
    "REQUIRED_SCHEMAS",
    "EVALUATION_NOT_TRAINING",
    "DISCLAIMER",
    "NOT_REPRODUCIBLE_FIELDS",
    "REPRODUCIBLE_FIELDS",
    "FILE_KINDS",
    "Disposition",
    "Basis",
    "BASES_FOR",
    "PackageState",
    "PackagingError",
    "DataInclusion",
    "data_inclusion",
    "permission_statement",
    "expected_results_from_predicate",
    "PackageFile",
    "PackageResult",
    "build_package",
    "cli_package",
]

PACKAGE_SCHEMA = "science-gate-package/v1"
PACKAGE_JSON = "package.json"
EVALUATION_DIR = "evaluation"
SCHEMAS_DIR = "schemas"
EXPECTED_RECEIPT = "expected/receipt.json"

#: The bundled schemas: ``science_gate/_schemas`` in an installed wheel,
#: ``<repo>/schemas`` in a source checkout (see :mod:`science_gate._resources`).
#: None when neither exists; the package then records its schemas as
#: INCOMPLETE rather than silently omitting them.
SOURCE_SCHEMAS_DIR = bundled_dir("schemas")

#: The schemas that describe the package's own documents. Without both, a
#: recipient cannot interpret what they were given.
REQUIRED_SCHEMAS = ("manifest.schema.json", "package.schema.json")

#: Schemas are small documentation files; anything larger is not one of them.
_MAX_SCHEMA_BYTES = 1024 * 1024
#: Bound on reading a previous package's index when ``--force`` replaces it.
_MAX_INDEX_BYTES = 64 * 1024 * 1024

#: Section 13 requires this to be stated explicitly; every permission statement opens with it.
EVALUATION_NOT_TRAINING = "Evaluation permission does not imply training permission."

DISCLAIMER = (
    "A package supports local re-execution and integrity comparison. It does not establish scientific truth, "
    "accuracy, safety, or fitness for use, and it grants no permission beyond those it records."
)

#: Receipt-predicate fields a faithful re-execution reproduces exactly.
REPRODUCIBLE_FIELDS = (
    "status",
    "reason",
    "reasons",
    "failure_modes",
    "counters",
    "input_accounting",
    "inputs",
    "checks",
    "invariants",
    "ledger_length",
    "tool",
)

#: Fields that are derived from the run's clock and run id and so change on
#: every run. They are recorded as provenance, never as expectations.
NOT_REPRODUCIBLE_FIELDS = (
    "run_id",
    "started_at",
    "completed_at",
    "ledger_head_sha256",
    "evidence_manifest_sha256",
    "checks[].invocation_id",
)

#: Kinds of evaluation file, in the order ``package.json`` lists them.
FILE_KINDS = ("manifest", "input", "document")

INVALID_MANIFEST = "INVALID_MANIFEST"
EVALUATION_NOT_ALLOWED = "EVALUATION_NOT_ALLOWED"
UNSAFE_DECLARED_PATH = "UNSAFE_DECLARED_PATH"
OUTPUT_INSIDE_INPUT_DIRECTORY = "OUTPUT_INSIDE_INPUT_DIRECTORY"
OUTPUT_CONTAINS_INPUTS = "OUTPUT_CONTAINS_INPUTS"
OUTPUT_NOT_A_DIRECTORY = "OUTPUT_NOT_A_DIRECTORY"
OUTPUT_EXISTS = "OUTPUT_EXISTS"
OUTPUT_NOT_A_PACKAGE = "OUTPUT_NOT_A_PACKAGE"
INPUT_CHANGED_DURING_PACKAGING = "INPUT_CHANGED_DURING_PACKAGING"
WRITE_FAILED = "WRITE_FAILED"


class Disposition(str, Enum):
    """What the package does with one evaluation file."""

    INCLUDED = "INCLUDED"
    WITHHELD = "WITHHELD"
    UNAVAILABLE = "UNAVAILABLE"


class Basis(str, Enum):
    """Why a file has its disposition. Stable spellings: they are persisted."""

    REDISTRIBUTION_ALLOWED = "REDISTRIBUTION_ALLOWED"
    SYNTHETIC_DEFAULT_PERMISSIONS = "SYNTHETIC_DEFAULT_PERMISSIONS"
    ACCESS_CLASS_CONTROLLED_LOCAL = "ACCESS_CLASS_CONTROLLED_LOCAL"
    ACCESS_CLASS_REFERENCE_ONLY = "ACCESS_CLASS_REFERENCE_ONLY"
    REDISTRIBUTION_NOT_ALLOWED = "REDISTRIBUTION_NOT_ALLOWED"
    SECRET_PATTERN_IN_CONTENT = "SECRET_PATTERN_IN_CONTENT"
    DECLARED_DIGEST_MISMATCH = "DECLARED_DIGEST_MISMATCH"
    NO_RECORDED_DIGEST = "NO_RECORDED_DIGEST"


#: The bases each disposition admits; any other pairing is a construction error.
BASES_FOR: Mapping[Disposition, frozenset[Basis]] = MappingProxyType(
    {
        Disposition.INCLUDED: frozenset({Basis.REDISTRIBUTION_ALLOWED, Basis.SYNTHETIC_DEFAULT_PERMISSIONS}),
        Disposition.WITHHELD: frozenset(
            {
                Basis.ACCESS_CLASS_CONTROLLED_LOCAL,
                Basis.ACCESS_CLASS_REFERENCE_ONLY,
                Basis.REDISTRIBUTION_NOT_ALLOWED,
                Basis.SECRET_PATTERN_IN_CONTENT,
                Basis.DECLARED_DIGEST_MISMATCH,
            }
        ),
        Disposition.UNAVAILABLE: frozenset({Basis.NO_RECORDED_DIGEST, Basis.DECLARED_DIGEST_MISMATCH}),
    }
)

#: Completes "Not included because ..." in a WITHHELD file's retrieval text.
_WITHHELD_BECAUSE: Mapping[Basis, str] = MappingProxyType(
    {
        Basis.ACCESS_CLASS_CONTROLLED_LOCAL: (
            "the corpus is CONTROLLED_LOCAL, and such data is never copied into a package"
        ),
        Basis.ACCESS_CLASS_REFERENCE_ONLY: "the corpus is REFERENCE_ONLY, and such data is never copied into a package",
        Basis.REDISTRIBUTION_NOT_ALLOWED: "the corpus permissions do not allow redistribution",
        Basis.SECRET_PATTERN_IN_CONTENT: (
            "its content matches a secret pattern, and packaging never alters a file to redact it"
        ),
        Basis.DECLARED_DIGEST_MISMATCH: (
            "the same path holds an input whose content does not match its declared sha256"
        ),
    }
)


class PackageState(str, Enum):
    """Whether every file the evaluation needs is pinned by a digest."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


class PackagingError(Exception):
    """A refused or failed packaging request. The command exits 3 (ERROR).

    ``code`` is a stable name for the refusal. By the time this is raised,
    nothing this attempt wrote is left in the output directory. A ``--force``
    replacement that had already removed the previous package does not
    restore it.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.detail = message


# ---------------------------------------------------------------------------
# Access rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataInclusion:
    """Whether a corpus's data files may be copied into a package, and why."""

    included: bool
    basis: Basis

    def statement(self, access_class: AccessClass, *, class_declared: bool) -> str:
        """One sentence a recipient can read without knowing this module."""
        if self.basis is Basis.REDISTRIBUTION_ALLOWED:
            return (
                f"Data files are included: the access class is {access_class.value} and "
                "redistribution_allowed is true."
            )
        if self.basis is Basis.SYNTHETIC_DEFAULT_PERMISSIONS:
            return (
                "Data files are included: the corpus is SYNTHETIC and declares no permissions, so its default "
                "synthetic permissions apply. This grants no right beyond the permissions recorded here."
            )
        if self.basis is Basis.REDISTRIBUTION_NOT_ALLOWED:
            return (
                f"Data files are not included: the access class is {access_class.value} and "
                "redistribution_allowed is false. Only their digests and retrieval instructions are included."
            )
        origin = "" if class_declared else " The manifest declares no corpus, so it is treated as CONTROLLED_LOCAL."
        return (
            f"Data files are not included: {access_class.value} data is never copied into a package, whatever its "
            f"permissions. Only digests and retrieval instructions are included.{origin}"
        )


def data_inclusion(
    access_class: AccessClass | str, permissions: Permissions, *, permissions_declared: bool
) -> DataInclusion:
    """Apply the section 13 rule to one corpus.

    ``permissions_declared`` says whether the manifest wrote any permission
    explicitly. Only an undeclared permission set counts as the "default
    synthetic permissions". An author who writes permissions gets exactly what
    they wrote.
    """
    access_class = AccessClass(access_class)
    if access_class is AccessClass.CONTROLLED_LOCAL:
        return DataInclusion(False, Basis.ACCESS_CLASS_CONTROLLED_LOCAL)
    if access_class is AccessClass.REFERENCE_ONLY:
        return DataInclusion(False, Basis.ACCESS_CLASS_REFERENCE_ONLY)
    if permissions.redistribution_allowed:
        return DataInclusion(True, Basis.REDISTRIBUTION_ALLOWED)
    if access_class is AccessClass.SYNTHETIC and not permissions_declared:
        return DataInclusion(True, Basis.SYNTHETIC_DEFAULT_PERMISSIONS)
    return DataInclusion(False, Basis.REDISTRIBUTION_NOT_ALLOWED)


def permission_statement(permissions: Permissions, *, training_declared: bool) -> str:
    """State explicitly that evaluation permission does not imply training permission."""
    if permissions.training_allowed:
        return (
            f"{EVALUATION_NOT_TRAINING} Training is permitted here only because training_allowed is declared true, "
            "a permission separate from evaluation_allowed."
        )
    origin = "declared" if training_declared else "the default"
    return (
        f"{EVALUATION_NOT_TRAINING} training_allowed is false ({origin}): neither this package nor the data it "
        "describes may be used to train, fine-tune or otherwise fit a model."
    )


def _declared_corpus(manifest: Manifest) -> tuple[bool, frozenset[str]]:
    """Whether the manifest declared a corpus, and which permissions it wrote.

    The validated :class:`~science_gate.manifests.CorpusSpec` has already
    filled in defaults, so the raw document is the only place where
    "declared false" and "defaulted to false" can be told apart.
    """
    corpus = manifest.raw.get("corpus")
    if not isinstance(corpus, Mapping):
        return False, frozenset()
    permissions = corpus.get("permissions")
    return True, frozenset(permissions) if isinstance(permissions, Mapping) else frozenset()


# ---------------------------------------------------------------------------
# Expected results
# ---------------------------------------------------------------------------


def expected_results_from_predicate(predicate: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a run receipt's predicate to what a faithful re-execution reproduces.

    This single definition serves two purposes. It builds a package's
    expected results, and it lets a recipient reduce their own run's
    ``receipt.json`` predicate for an equality comparison. Check evidence
    appears only as ``evidence_sha256``, so the result never quotes input
    content. Raises ``KeyError`` if a reproducible field is missing.
    """
    results = {name: predicate[name] for name in REPRODUCIBLE_FIELDS}
    results["checks"] = [
        {key: value for key, value in check.items() if key != "invocation_id"} for check in predicate["checks"]
    ]
    results["exit_code"] = EXIT_CODE[Status(predicate["status"])]
    return normalize(results)


def _expected_results(run: VerificationRun, receipt: Mapping[str, Any]) -> dict[str, Any]:
    predicate = receipt["body"]["predicate"]
    if run.network.live:
        network = (
            "The manifest requests live lookups. The network was refused while the package was made, so any "
            "live-dependent check here reflects SOURCE_UNAVAILABLE."
        )
    else:
        network = "No live lookup was requested; the expected results were computed offline."
    return {
        "reproducible": expected_results_from_predicate(predicate),
        "not_reproducible": {
            "fields": list(NOT_REPRODUCIBLE_FIELDS),
            "why": "They derive from the run's clock and run id, so every faithful re-execution produces new values.",
        },
        "recorded_run": {
            "run_id": predicate["run_id"],
            "started_at": predicate["started_at"],
            "completed_at": predicate["completed_at"],
            "ledger_head_sha256": predicate["ledger_head_sha256"],
            "evidence_manifest_sha256": predicate["evidence_manifest_sha256"],
            "receipt": {
                "path": EXPECTED_RECEIPT,
                "content_sha256": receipt["content_sha256"],
                "signature_state": receipt["signature_state"],
                "key_id": receipt["key_id"],
            },
        },
        "network": {"live_requested": run.network.live, "network_used": False, "statement": network},
        "content_policy": (
            "Expected results never quote input content: check evidence appears only as evidence_sha256, and "
            "diagnostics are omitted."
        ),
    }


def _refuse_network(*_args: Any, **_kwargs: Any) -> Any:
    """Stand-in for ``urlopen`` while packaging.

    Expected results must not depend on what a remote service said on the day
    the package was made. A live lookup therefore fails as a network error,
    which the adapters record as SOURCE_UNAVAILABLE.
    """
    raise urllib.error.URLError("packaging never uses the network")


# ---------------------------------------------------------------------------
# Evaluation files
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageFile:
    """One evaluation file and what the package does with it.

    ``path`` is relative to the manifest directory, as the run recorded it.
    ``package_path`` is where the file is in the package (INCLUDED), or where
    a recipient must place it (otherwise). It is None only when the recorded
    path is not a safe relative path. A file that is INCLUDED or WITHHELD
    always has a digest: a withheld file without one could not be retrieved
    and checked.
    """

    kind: str
    name: str
    path: str
    package_path: str | None
    state: str
    sha256: str | None
    size_bytes: int | None
    required: bool | None
    declared_sha256: str | None
    disposition: Disposition
    basis: Basis

    def __post_init__(self) -> None:
        if self.kind not in FILE_KINDS:
            raise ValueError(f"unknown file kind {self.kind!r}")
        if self.basis not in BASES_FOR[self.disposition]:
            raise ValueError(f"{self.disposition.value} cannot have basis {self.basis.value}")
        if self.disposition is not Disposition.UNAVAILABLE and (self.sha256 is None or self.package_path is None):
            raise ValueError(f"a {self.disposition.value} file needs a digest and a package path")

    @property
    def optional_absence(self) -> bool:
        """An optional input that is absent was declared out of scope; it does not make a package incomplete."""
        return self.kind == "input" and self.required is False and self.state == InputState.MISSING.value

    def retrieval(self) -> str | None:
        """How a recipient obtains this file, or None when it is in the package."""
        if self.disposition is Disposition.INCLUDED:
            return None
        if self.disposition is Disposition.WITHHELD:
            return (
                f"Not included because {_WITHHELD_BECAUSE[self.basis]}. Obtain it through the arrangement under "
                f"which you may use this corpus, place it at {self.package_path}, and confirm its SHA-256 is "
                f"{self.sha256} ({self.size_bytes} bytes) before running."
            )
        if self.basis is Basis.DECLARED_DIGEST_MISMATCH:
            return (
                f"The file present when the package was made (SHA-256 {self.sha256}) is not the declared artifact. "
                f"Obtain the declared artifact, place it at {self.package_path}, and confirm its SHA-256 is "
                f"{self.declared_sha256}. The expected results were computed on the mismatching file, so they will "
                "not reproduce with the declared one."
            )
        if self.optional_absence:
            return (
                "This optional input was absent when the package was made, and the expected results treat it as "
                f"excluded. Leave {self.package_path} absent to reproduce them."
            )
        if self.package_path is None:
            return (
                f"No digest could be recorded (state {self.state}), and the recorded path is not a safe relative "
                "path, so this package cannot say what belongs where."
            )
        return (
            f"No digest could be recorded when the package was made (state {self.state}), so this package cannot "
            f"say which bytes belong at {self.package_path}. The expected results reflect that state."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "path": self.path,
            "package_path": self.package_path,
            "state": self.state,
            "sha256": self.sha256,
            "bytes": self.size_bytes,
            "required": self.required,
            "declared_sha256": self.declared_sha256,
            "disposition": self.disposition.value,
            "basis": self.basis.value,
            "retrieval": self.retrieval(),
        }


def _package_path(relpath: str) -> str | None:
    """Where a manifest-relative path lives in the package, or None if it is unsafe."""
    try:
        return f"{EVALUATION_DIR}/{normalize_relpath(relpath)}"
    except UnsafePathError:
        return None


def _evaluation_file(
    kind: str,
    name: str,
    path: str,
    state: str,
    sha256: str | None,
    size_bytes: int | None,
    inclusion: DataInclusion,
    *,
    required: bool | None = None,
    declared_sha256: str | None = None,
) -> PackageFile:
    """An evaluation file with its disposition as decided before any content is read.

    INCLUDED is provisional here: the content screen at write time can still
    withhold the file. A file whose content failed its declared digest is
    never shipped, because it is not the artifact the evaluation declares.
    """
    package_path = _package_path(path)
    if sha256 is None or package_path is None:
        disposition, basis = Disposition.UNAVAILABLE, Basis.NO_RECORDED_DIGEST
    elif state == InputState.HASH_MISMATCH.value:
        disposition, basis = Disposition.UNAVAILABLE, Basis.DECLARED_DIGEST_MISMATCH
    else:
        disposition = Disposition.INCLUDED if inclusion.included else Disposition.WITHHELD
        basis = inclusion.basis
    return PackageFile(
        kind=kind,
        name=name,
        path=path,
        package_path=package_path,
        state=state,
        sha256=sha256,
        size_bytes=size_bytes,
        required=required,
        declared_sha256=declared_sha256,
        disposition=disposition,
        basis=basis,
    )


def _plan_files(
    manifest: Manifest, manifest_size: int, run: VerificationRun, inclusion: DataInclusion
) -> list[PackageFile]:
    """List every evaluation file the run relied on, with its provisional disposition.

    Digests are the ones the verification run recorded, so the package pins
    exactly the bytes the expected results were computed from.
    """
    files = [
        _evaluation_file(
            "manifest",
            "manifest",
            manifest.path.name,
            InputState.PARSED.value,
            manifest.sha256,
            manifest_size,
            inclusion,
            required=True,
        )
    ]
    for record in run.result.accounting.records:
        files.append(
            _evaluation_file(
                "input",
                record.input_id,
                record.path,
                record.state.value,
                record.sha256,
                record.size_bytes,
                inclusion,
                required=record.required,
                declared_sha256=record.declared_sha256,
            )
        )
    for document in run.documents:
        files.append(
            _evaluation_file(
                "document",
                ",".join(document["roles"]) or document["path"],
                document["path"],
                document["state"],
                document["sha256"],
                document["bytes"],
                inclusion,
            )
        )
    return _withhold_shared_mismatches(files)


def _withhold_shared_mismatches(files: list[PackageFile]) -> list[PackageFile]:
    """Never ship a path that is also an input whose content failed its declared digest.

    This happens only when a check reads a declared input as a document too.
    Shipping it under the document's name would contradict the input's entry.
    """
    blocked = {
        item.package_path
        for item in files
        if item.basis is Basis.DECLARED_DIGEST_MISMATCH and item.package_path is not None
    }
    return [
        dataclasses.replace(item, disposition=Disposition.WITHHELD, basis=Basis.DECLARED_DIGEST_MISMATCH)
        if item.disposition is Disposition.INCLUDED and item.package_path in blocked
        else item
        for item in files
    ]


def _sort_key(item: PackageFile) -> tuple[int, str, str]:
    return FILE_KINDS.index(item.kind), item.name, item.path


def _matches_secret_pattern(data: bytes) -> bool:
    """True when redaction would change the content, i.e. it holds a secret-shaped value.

    Undecodable bytes are replaced rather than rejected. A credential is
    ASCII and stays findable, while a stray invalid byte must not make a file
    look clean.
    """
    text = data.decode("utf-8", errors="replace")
    return redact_text(text) != text


def _strings(value: Any) -> Iterator[str]:
    """Every string in a JSON-like value, mapping keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _redacted(document: dict[str, Any]) -> dict[str, Any]:
    """The document with secret-shaped values redacted, as :func:`~science_gate._redact.redact` would.

    ``redact`` re-reads the environment for every string, which dominates
    packaging time on an index of several hundred strings. A secret in any
    one string is still found in all of them joined by newlines, because the
    patterns treat a newline as a boundary. So one scan decides whether
    anything needs redacting, and the full walk runs only when it does.
    """
    joined = "\n".join(_strings(document))
    return redact(document) if redact_text(joined) != joined else document


def _incomplete_because(files: Sequence[PackageFile], schema_problem: str | None) -> list[str]:
    """Why the package cannot pin everything the evaluation needs (empty when complete)."""
    reasons = []
    for item in sorted(files, key=_sort_key):
        if item.disposition is not Disposition.UNAVAILABLE or item.optional_absence:
            continue
        if item.basis is Basis.DECLARED_DIGEST_MISMATCH:
            reasons.append(f"input {item.name}: the file on disk does not match its declared sha256")
        else:
            reasons.append(f"{item.kind} {item.name}: {item.state}, no digest recorded")
    if schema_problem is not None:
        reasons.append(f"schemas: {schema_problem}")
    return reasons


def _load_schemas(directory: Path | None) -> tuple[tuple[tuple[str, bytes], ...], str | None]:
    """Read every ``*.schema.json`` in ``directory``; return them and any problem.

    Error text never contains an absolute path, because the problem is
    recorded in ``package.json`` and would otherwise differ between machines.
    """
    if directory is None:
        return (), "no schema directory is configured"
    try:
        names = sorted(entry.name for entry in directory.iterdir() if entry.name.endswith(".schema.json"))
    except OSError:
        return (), "the schema directory could not be read"
    loaded: list[tuple[str, bytes]] = []
    problems: list[str] = []
    for name in names:
        try:
            loaded.append((name, safe_read(directory, name, max_bytes=_MAX_SCHEMA_BYTES)))
        except SafeIOError as exc:
            problems.append(f"{name} was refused ({exc.code})")
        except OSError as exc:
            problems.append(f"{name} could not be read ({exc.strerror or type(exc).__name__})")
    present = {name for name, _ in loaded}
    missing = [name for name in REQUIRED_SCHEMAS if name not in present]
    if missing:
        problems.append(f"missing {', '.join(missing)}")
    return tuple(loaded), "; ".join(problems) or None


# ---------------------------------------------------------------------------
# Output confinement
# ---------------------------------------------------------------------------


def _output_location(output: Path, manifest_root: Path) -> Path:
    """Resolve ``--output`` and refuse locations that would mix output with inputs.

    Every declared path resolves under the manifest directory (enforced
    before this is called), so the manifest directory contains every input
    directory. An output inside it would sit among the evidence. An output
    containing it would put the evidence inside what ``--force`` may replace.
    """
    target = output.resolve()
    if is_within(manifest_root, target):
        raise PackagingError(
            OUTPUT_INSIDE_INPUT_DIRECTORY,
            f"{output} is inside the manifest directory {manifest_root}, which holds the inputs; "
            "choose an output outside it",
        )
    if is_within(target, manifest_root):
        raise PackagingError(
            OUTPUT_CONTAINS_INPUTS,
            f"{output} contains the manifest directory {manifest_root}; choose an output outside it",
        )
    return target


def _existing_package_files(target: Path, force: bool) -> tuple[Path, ...]:
    """Files of a previous package that ``--force`` will replace (empty for fresh output).

    Refuses non-empty output without ``--force``. With ``--force``, it still
    refuses anything that is not provably a previous package: the directory
    must hold a ``science-gate-package/v1`` index, and every file under it must
    be that index or be listed in the index's ``contents``. It must also
    contain no link, so that deletion can never reach beyond this directory.
    """
    if not target.exists():
        return ()
    if not target.is_dir():
        raise PackagingError(OUTPUT_NOT_A_DIRECTORY, f"{target} exists and is not a directory")
    if not any(target.iterdir()):
        return ()
    if not force:
        raise PackagingError(
            OUTPUT_EXISTS, f"{target} already exists and is not empty; pass --force to replace a previous package"
        )
    listed = _listed_contents(target) | {PACKAGE_JSON}
    found: list[Path] = []
    unlisted: list[str] = []
    for directory, subdirectories, filenames in os.walk(target):
        for name in (*subdirectories, *filenames):
            entry = Path(directory, name)
            if entry.is_symlink() or not is_within(target, entry.resolve()):
                raise PackagingError(OUTPUT_NOT_A_PACKAGE, f"{target} holds a link ({name}); refusing to replace it")
        for name in filenames:
            entry = Path(directory, name)
            relpath = entry.relative_to(target).as_posix()
            if relpath in listed:
                found.append(entry)
            else:
                unlisted.append(relpath)
    if unlisted:
        shown = ", ".join(sorted(unlisted)[:5])
        raise PackagingError(
            OUTPUT_NOT_A_PACKAGE,
            f"{target} holds {len(unlisted)} file(s) no previous package listed ({shown}); refusing to delete them",
        )
    # The index goes last, so an interrupted removal still looks like a package.
    return tuple(sorted(found, key=lambda path: (path == target / PACKAGE_JSON, str(path))))


def _listed_contents(target: Path) -> set[str]:
    """The ``contents`` paths of the package index in ``target``, or refuse."""
    try:
        document = strict_loads(safe_read(target, PACKAGE_JSON, max_bytes=_MAX_INDEX_BYTES))
    except FileNotFoundError:
        raise PackagingError(
            OUTPUT_NOT_A_PACKAGE, f"{target} is not empty and holds no {PACKAGE_JSON}; refusing to replace it"
        ) from None
    except (SafeIOError, OSError, StrictJSONError) as exc:
        raise PackagingError(OUTPUT_NOT_A_PACKAGE, f"{target}/{PACKAGE_JSON} cannot be read ({exc})") from None
    contents = document.get("contents") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("schema") != PACKAGE_SCHEMA
        or not isinstance(contents, list)
        or not all(isinstance(item, dict) and isinstance(item.get("path"), str) for item in contents)
    ):
        raise PackagingError(OUTPUT_NOT_A_PACKAGE, f"{target}/{PACKAGE_JSON} is not a {PACKAGE_SCHEMA} index")
    return {item["path"] for item in contents}


def _remove_empty_directories(root: Path) -> None:
    """Remove every empty directory strictly below ``root``, deepest first."""
    for directory, _, _ in os.walk(root, topdown=False):
        if Path(directory) != root:
            with contextlib.suppress(OSError):  # not empty: something else lives there
                os.rmdir(directory)


def _first_missing_ancestor(path: Path) -> Path | None:
    """The highest directory on the way to ``path`` (inclusive) that does not exist yet."""
    missing = None
    for candidate in (path, *path.parents):
        if candidate.exists():
            break
        missing = candidate
    return missing


class _Writer:
    """Writes package files under one root and can undo exactly those writes.

    A packaging failure after some files were written must not leave
    something behind that looks like a package, or that blocks the next
    attempt.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.first_created = _first_missing_ancestor(root)
        self.paths: list[Path] = []
        self.contents: dict[str, dict[str, Any]] = {}

    def write(self, relpath: str, data: bytes) -> Path:
        path = safe_write(self.root, relpath, data)
        self.paths.append(path)
        if relpath != PACKAGE_JSON:
            self.contents[relpath] = {"path": relpath, "sha256": sha256_bytes(data), "bytes": len(data)}
        return path

    def rollback(self) -> None:
        for path in reversed(self.paths):
            with contextlib.suppress(OSError):
                path.unlink()
        if not self.root.is_dir():
            return
        _remove_empty_directories(self.root)
        if self.first_created is None:
            return
        for directory in (self.root, *self.root.parents):
            with contextlib.suppress(OSError):
                directory.rmdir()
            if directory == self.first_created:
                break


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageResult:
    """A written package: where it is, its index, and the files written in order."""

    output: Path
    document: Mapping[str, Any]
    paths: tuple[Path, ...]
    replaced: bool = False

    @property
    def state(self) -> PackageState:
        return PackageState(self.document["package_state"])

    @property
    def exit_code(self) -> int:
        """0 for a complete package; 2 (ABSTAIN) when something it needed could not be pinned."""
        return EXIT_CODE[Status.PASS] if self.state is PackageState.COMPLETE else EXIT_CODE[Status.ABSTAIN]

    @property
    def headline(self) -> str:
        document = self.document
        counts = Counter(item["disposition"] for item in document["files"])
        expected = document["expected_results"]["reproducible"]
        replaced = "; replaced a previous package" if self.replaced else ""
        tail = (
            f"{counts[Disposition.INCLUDED.value]} of {len(document['files'])} evaluation file(s) included, "
            f"{counts[Disposition.WITHHELD.value]} withheld with digests, "
            f"{counts[Disposition.UNAVAILABLE.value]} unavailable; corpus {document['corpus']['access_class']}; "
            f"expected verify result {expected['status']} ({expected['reason']}), exit {expected['exit_code']}"
            f"{replaced}"
        )
        if self.state is PackageState.COMPLETE:
            return f"OK package: wrote a complete evaluation package to {self.output} ({tail})"
        because = "; ".join(document["incomplete_because"])
        return f"ABSTAIN package: wrote an INCOMPLETE evaluation package to {self.output}: {because} ({tail})"


def _local_execution(manifest_name: str, files: Sequence[PackageFile], expected_exit: int) -> dict[str, Any]:
    """Instructions for re-running the evaluation from the package, offline."""
    withheld = [item for item in files if item.disposition is Disposition.WITHHELD]
    unavailable = [
        item for item in files if item.disposition is Disposition.UNAVAILABLE and not item.optional_absence
    ]
    steps = [f"Work in the directory that holds {PACKAGE_JSON}. Nothing here needs network access."]
    if withheld:
        steps.append(
            f"Obtain the {len(withheld)} file(s) under 'files' with disposition WITHHELD as each entry's "
            "'retrieval' text says, place each at its 'package_path', and confirm its SHA-256 before going on."
        )
    else:
        steps.append("No file is withheld; nothing needs to be retrieved.")
    if unavailable:
        steps.append(
            f"This package is INCOMPLETE: {len(unavailable)} file(s) are UNAVAILABLE (see incomplete_because). "
            "A local run reproduces the expected results only if they are in the same state as when it was made."
        )
    command = ["science-gate", "verify", f"{EVALUATION_DIR}/{manifest_name}", "--output", "local-run"]
    steps.append(f"Run: {' '.join(command)}")
    steps.append(
        f"Expect exit code {expected_exit}. Reduce the body.predicate of local-run/receipt.json to the fields in "
        "expected_results.reproducible and compare them; the fields under expected_results.not_reproducible "
        "change on every run."
    )
    return {
        "requires": {"tool": TOOL_NAME, "version": __version__, "python": ">=3.11", "network": "none"},
        "steps": steps,
        "command": command,
        "expected_exit_code": expected_exit,
    }


def _package_document(
    *,
    manifest: Manifest,
    run: VerificationRun,
    receipt: Mapping[str, Any],
    inclusion: DataInclusion,
    class_declared: bool,
    declared_permissions: frozenset[str],
    files: Sequence[PackageFile],
    schema_entries: Sequence[Mapping[str, Any]],
    schema_problem: str | None,
    contents: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """The ``package.json`` index (``science-gate-package/v1``)."""
    permissions = manifest.corpus.permissions
    expected = _expected_results(run, receipt)
    incomplete = _incomplete_because(files, schema_problem)
    ordered = sorted(files, key=_sort_key)
    unpinned = sum(1 for item in files if item.sha256 is None)
    reproducible = expected["reproducible"]
    return {
        "schema": PACKAGE_SCHEMA,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "created_at": now(),
        "run_label": manifest.run_label,
        "package_state": (PackageState.INCOMPLETE if incomplete else PackageState.COMPLETE).value,
        "incomplete_because": incomplete,
        "corpus": {
            "access_class": manifest.corpus.access_class.value,
            "access_class_source": "DECLARED" if class_declared else "DEFAULT",
            "permissions": permissions.to_dict(),
            "permission_sources": {
                name: "DECLARED" if name in declared_permissions else "DEFAULT" for name in permissions.to_dict()
            },
            "data_inclusion": {
                "included": inclusion.included,
                "basis": inclusion.basis.value,
                "statement": inclusion.statement(manifest.corpus.access_class, class_declared=class_declared),
            },
        },
        "permission_statement": permission_statement(
            permissions, training_declared="training_allowed" in declared_permissions
        ),
        "source_licenses": _source_licenses(manifest.corpus.source_licenses),
        "approved_redactions": _approved_redactions(manifest.corpus.approved_redactions),
        "files": [item.to_dict() for item in ordered],
        "schemas": {
            "state": "INCOMPLETE" if schema_problem else "INCLUDED",
            "problem": schema_problem,
            "files": list(schema_entries),
        },
        "expected_results": expected,
        "local_execution": _local_execution(manifest.path.name, ordered, reproducible["exit_code"]),
        "contents": [contents[path] for path in sorted(contents)],
        "evidence_boundary": {
            "integrity": (
                f"Each file in this package except {PACKAGE_JSON} is listed under 'contents' with its SHA-256. "
                f"Each of the {len(files)} evaluation file(s) is listed under 'files' with the digest recorded when "
                f"the package was made, whether or not it is included; {unpinned} had no digest."
            ),
            "performance": (
                f"The expected results record how the declared checks behaved on the declared inputs when this "
                f"package was made: status {reproducible['status']} ({reproducible['reason']}). They describe that "
                "one evaluation only."
            ),
            "scientific_validity": SCIENTIFIC_VALIDITY,
        },
        "disclaimer": DISCLAIMER,
    }


#: Why packaging never applies a redaction itself, whatever the manifest declares.
_NEVER_ALTERED = (
    "Packaging never alters a data file, because any change would break its recorded digest: a file is either "
    "copied byte for byte or withheld whole with its digest (basis SECRET_PATTERN_IN_CONTENT when its content "
    "matches a secret pattern)."
)


def _source_licenses(declared: Sequence[SourceLicense] | None) -> dict[str, Any]:
    """The ``source_licenses`` block: what the manifest declared, and that this tool asserts none of it."""
    if declared is None:
        return {
            "state": "NOT_DECLARED",
            "declared": None,
            "assertion": "NOASSERTION",
            "statement": (
                "The manifest declares no source licenses (corpus.source_licenses), so none are recorded and none "
                "are asserted here. Check each source's own terms before any use beyond local evaluation."
            ),
        }
    return {
        "state": "DECLARED",
        "declared": [item.to_dict() for item in declared],
        "assertion": "NOASSERTION",
        "statement": (
            "Recorded exactly as the manifest declares them (corpus.source_licenses). This tool neither verifies "
            "nor asserts any license; check each source's own terms before any use beyond local evaluation."
        ),
    }


def _approved_redactions(declared: Sequence[ApprovedRedaction] | None) -> dict[str, Any]:
    """The ``approved_redactions`` block: what the manifest declared as approved, recorded as declared."""
    if declared is None:
        return {
            "state": "NOT_DECLARED",
            "declared": None,
            "statement": f"No redaction was declared or approved (corpus.approved_redactions). {_NEVER_ALTERED}",
        }
    return {
        "state": "DECLARED",
        "declared": [item.to_dict() for item in declared],
        "statement": (
            "Recorded exactly as the manifest declares them (corpus.approved_redactions): redactions the data "
            f"owner made before the files were digested. {_NEVER_ALTERED}"
        ),
    }


def _load_manifest(manifest_path: str | os.PathLike[str]) -> Manifest:
    """Load the manifest; an invalid one is a packaging refusal with its issue codes, never a traceback."""
    try:
        return load_manifest(manifest_path)
    except ManifestError as exc:
        raise PackagingError(INVALID_MANIFEST, str(exc)) from None


def _require_safe_paths(manifest: Manifest) -> None:
    """Refuse a manifest whose declared paths leave its directory.

    Such a manifest is unsafe (the run would be ERROR). A package built from
    it would carry retrieval instructions pointing outside the evaluation.
    """
    for pointer, relpath in manifest.referenced_paths():
        try:
            resolve_under_root(manifest.root, relpath)
        except UnsafePathError as exc:
            raise PackagingError(UNSAFE_DECLARED_PATH, f"{pointer}: {exc}") from None


def _read_verified(manifest: Manifest, relpath: str, sha256: str, *, max_bytes: int) -> bytes:
    """Read a file under the manifest directory and prove it has the digest the run recorded.

    Copying goes through this check, so a package can never pair expected
    results with bytes other than the ones they were computed from.
    """
    try:
        data = safe_read(manifest.root, relpath, max_bytes=max_bytes)
    except (SafeIOError, OSError) as exc:
        detail = exc.code if isinstance(exc, SafeIOError) else (exc.strerror or type(exc).__name__)
        raise PackagingError(INPUT_CHANGED_DURING_PACKAGING, f"{relpath} can no longer be read: {detail}") from None
    if sha256_bytes(data) != sha256:
        raise PackagingError(INPUT_CHANGED_DURING_PACKAGING, f"{relpath} changed after it was verified; package again")
    return data


def _write_evaluation_files(writer: _Writer, manifest: Manifest, files: Sequence[PackageFile]) -> list[PackageFile]:
    """Copy every INCLUDED file, screening content first; return the final dispositions.

    A package path shared by two entries is read once. Both entries then get
    the same outcome, because they describe the same bytes.
    """
    screened: dict[str, bool] = {}
    final: list[PackageFile] = []
    for item in sorted(files, key=lambda entry: (entry.package_path or "", _sort_key(entry))):
        if item.disposition is not Disposition.INCLUDED:
            final.append(item)
            continue
        if item.package_path not in screened:
            limit = MAX_MANIFEST_BYTES if item.kind == "manifest" else manifest.limits.max_file_bytes
            data = _read_verified(manifest, item.path, item.sha256, max_bytes=limit)
            screened[item.package_path] = _matches_secret_pattern(data)
            if not screened[item.package_path]:
                writer.write(item.package_path, data)
        if screened[item.package_path]:
            item = dataclasses.replace(item, disposition=Disposition.WITHHELD, basis=Basis.SECRET_PATTERN_IN_CONTENT)
        final.append(item)
    return final


def build_package(
    manifest_path: str | os.PathLike[str],
    output: str | os.PathLike[str],
    *,
    force: bool = False,
    schemas_dir: Path | None = SOURCE_SCHEMAS_DIR,
    environ: Mapping[str, str] | None = None,
) -> PackageResult:
    """Build an evaluation package for ``manifest_path`` inside ``output``.

    Every refusal that depends only on the request runs before anything is
    written or removed. That covers the manifest, the evaluation permission,
    path safety, the output location and existing output. A file that
    changes after it was verified is caught while it is copied, and
    everything written so far is then rolled back. ``environ`` is passed to
    receipt signing, as in :func:`~science_gate.receipts.build_run_receipt`.
    Raises :class:`PackagingError` for every refusal or failure.
    """
    manifest = _load_manifest(manifest_path)
    if not manifest.corpus.permissions.evaluation_allowed:
        raise PackagingError(
            EVALUATION_NOT_ALLOWED,
            "the corpus permissions do not allow evaluation, so an evaluation package would invite a forbidden use",
        )
    _require_safe_paths(manifest)
    target = _output_location(Path(output), manifest.root)
    previous = _existing_package_files(target, force)

    manifest_bytes = _read_verified(manifest, manifest.path.name, manifest.sha256, max_bytes=MAX_MANIFEST_BYTES)
    run = verify(manifest.path, network=NetworkPolicy(opener=_refuse_network))
    if run.manifest_sha256 != manifest.sha256:
        raise PackagingError(INPUT_CHANGED_DURING_PACKAGING, "the manifest changed while the package was being made")
    seal = run.ledger.seal()
    receipt = build_run_receipt(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"], environ=environ
    )
    class_declared, declared_permissions = _declared_corpus(manifest)
    inclusion = data_inclusion(
        manifest.corpus.access_class, manifest.corpus.permissions, permissions_declared=bool(declared_permissions)
    )
    files = _plan_files(manifest, len(manifest_bytes), run, inclusion)
    schemas, schema_problem = _load_schemas(schemas_dir)

    try:
        for path in previous:
            path.unlink()
        _remove_empty_directories(target)
    except OSError as exc:
        raise PackagingError(WRITE_FAILED, f"could not remove the previous package: {exc}") from None
    writer = _Writer(target)
    try:
        files = _write_evaluation_files(writer, manifest, files)
        schema_entries = []
        for name, data in schemas:
            relpath = f"{SCHEMAS_DIR}/{name}"
            writer.write(relpath, data)
            schema_entries.append(writer.contents[relpath])
        writer.write(EXPECTED_RECEIPT, receipt_bytes(receipt))
        document = normalize(
            _redacted(
                _package_document(
                    manifest=manifest,
                    run=run,
                    receipt=receipt,
                    inclusion=inclusion,
                    class_declared=class_declared,
                    declared_permissions=declared_permissions,
                    files=files,
                    schema_entries=schema_entries,
                    schema_problem=schema_problem,
                    contents=writer.contents,
                )
            )
        )
        writer.write(PACKAGE_JSON, pretty_json_bytes(document))
    except (SafeIOError, OSError) as exc:
        writer.rollback()
        raise PackagingError(WRITE_FAILED, f"could not write the package into {target}: {exc}") from None
    except BaseException:
        # Whatever went wrong, a half-written package must not survive it.
        writer.rollback()
        raise
    return PackageResult(target, document, tuple(writer.paths), replaced=bool(previous))


def _emit(stream: TextIO, text: str) -> None:
    """Write one line, escaping what the stream's encoding cannot represent.

    A Windows console may use a legacy code page. A path with an unencodable
    character must not turn a packaging outcome into a traceback.
    """
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")


def cli_package(args: argparse.Namespace) -> int:
    """``science-gate package MANIFEST --output PATH [--force]``; returns the exit code.

    Prints a one-line headline first, then every path written, in write
    order (``package.json`` last). The exit code is 0 for a complete package,
    2 for an incomplete one, and 3 for any refusal or failure.
    """
    out = sys.stdout
    try:
        result = build_package(args.manifest, args.output, force=args.force)
    except PackagingError as exc:
        _emit(out, f"ERROR package: {exc}")
        return EXIT_CODE[Status.ERROR]
    _emit(out, result.headline)
    for path in result.paths:
        _emit(out, str(path))
    return result.exit_code
