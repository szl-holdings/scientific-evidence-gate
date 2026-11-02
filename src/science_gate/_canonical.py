"""Canonical JSON, strict JSON parsing and SHA-256 helpers.

Every hash this tool emits (ledger entries, receipts, evidence manifests) is a
hash of *canonical* JSON: UTF-8, sorted keys, compact separators,
``ensure_ascii=False``, integers only. Two semantically equal documents must
hash identically on every machine and under every ``PYTHONHASHSEED``, so this
module is deliberately strict:

* Floats are refused outright. Their text form is platform- and
  history-dependent (``0.1 + 0.2``), so a float in hashed content would make a
  hash depend on arithmetic accidents. Non-integer quantities travel as
  ``decimal.Decimal`` and are serialized as decimal strings such as ``"0.125"``.
* Integers must lie within ``±(2**53 - 1)`` (:data:`MAX_SAFE_INTEGER`). A
  consumer that reads JSON numbers as IEEE doubles silently rounds anything
  larger, so a digest computed there would differ from ours while both sides
  believe they hashed the same document. Larger quantities travel as decimal
  strings.
* NaN and infinities are refused in every form, because they have no stable
  JSON representation and usually signal a failed computation.
* Mapping keys must be strings. ``json`` would silently coerce ``1`` and
  ``"1"`` to the same key, which could merge two distinct facts.
* Sets are emitted as lists sorted by their canonical encoding, so iteration
  order never leaks into output.

This encoding is **not** RFC 8785 (the JSON Canonicalization Scheme) and must
never be described as such (decision D8). Keys sort by Unicode code point,
whereas JCS sorts by UTF-16 code unit, so the two disagree whenever a key holds
a character above U+FFFF: here a key U+E000 sorts before a key U+1F600, under
JCS after it. The golden vectors in ``tests/test_canonical_vectors.py`` pin
that divergence and the exact output bytes, so a change to the digest
function is itself a test that fails.

The strict loader mirrors these rules on the way in: duplicate keys, NaN and
Infinity are errors, and JSON numbers with a fraction or exponent are parsed as
``Decimal`` so a float can never enter the process from input data either.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation, localcontext
from enum import Enum
from pathlib import PurePath
from typing import Any, BinaryIO, Mapping

__all__ = [
    "CanonicalizationError",
    "SizeLimitExceeded",
    "StrictJSONError",
    "normalize",
    "canonical_dumps",
    "canonical_bytes",
    "pretty_json_bytes",
    "sha256_bytes",
    "sha256_canonical",
    "sha256_stream",
    "sha256_file",
    "strict_loads",
    "HASH_CHUNK_BYTES",
    "MAX_SAFE_INTEGER",
]

#: Read size for streaming hashes. Large enough to be efficient, small enough
#: that a multi-gigabyte input never has to fit in memory.
HASH_CHUNK_BYTES = 1 << 16

#: The largest magnitude an integer in canonical JSON may have (D8): every
#: integer up to it is exact in an IEEE 754 double, so every JSON reader agrees
#: on its value.
MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented in canonical JSON.

    The message names the JSON path of the offending value so the producer of
    bad evidence can be found without a debugger.
    """


class SizeLimitExceeded(ValueError):
    """Raised when a stream proves larger than its declared byte budget."""


class StrictJSONError(ValueError):
    """Raised by :func:`strict_loads` for any input that is not strict JSON.

    ``kind`` is one of ``MALFORMED_JSON``, ``DUPLICATE_KEY``,
    ``NON_FINITE_NUMBER``, ``NON_INTEGER_NUMBER`` or ``INTEGER_OUT_OF_RANGE``
    so callers can report a named diagnostic instead of a traceback.
    """

    def __init__(self, kind: str, message: str, *, line: int | None = None, column: int | None = None) -> None:
        location = f" (line {line}, column {column})" if line is not None else ""
        super().__init__(f"{kind}: {message}{location}")
        self.kind = kind
        self.detail = message
        self.line = line
        self.column = column


def normalize(value: Any, _path: str = "$") -> Any:
    """Return a JSON-safe copy of ``value`` that obeys the canonical rules.

    Accepted: ``None``, ``bool``, ``int`` within ``±MAX_SAFE_INTEGER``,
    ``str``, finite ``Decimal`` (emitted as its string form), ``Enum``
    (emitted as its value), mappings with string keys, lists, tuples, sets,
    and objects exposing ``to_dict()``.

    Refused: floats, integers beyond ``±MAX_SAFE_INTEGER``, non-finite
    decimals, bytes and filesystem paths. Paths are refused because an
    absolute path would make output differ between machines; callers must
    pass an explicit relative path string instead.

    A ``Decimal`` keeps its own ``str`` form, so ``Decimal("1.50")`` stays
    ``"1.50"`` (printed precision is evidence) and an input such as ``1e999999``
    stays compact instead of expanding into a million digits.
    """
    if isinstance(value, Enum):
        return normalize(value.value, _path)
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer at {_path} is outside +/-(2**53 - 1); carry it as a decimal string"
            )
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            f"float at {_path}: floats never enter hashed content; use an int or a decimal string"
        )
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalizationError(f"non-finite decimal at {_path}")
        return str(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, Enum):
                key = key.value
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string key {key!r} at {_path}")
            if key in result:
                raise CanonicalizationError(f"duplicate key {key!r} at {_path} after normalization")
            result[key] = normalize(item, f"{_path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [normalize(item, f"{_path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, (set, frozenset)):
        items = [normalize(item, f"{_path}{{}}") for item in value]
        return sorted(items, key=_encode)
    if isinstance(value, (bytes, bytearray, PurePath)):
        raise CanonicalizationError(
            f"{type(value).__name__} at {_path}: pass an explicit string (relative path or hex digest)"
        )
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return normalize(to_dict(), _path)
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {_path}")


def _encode(normalized: Any) -> str:
    """Serialize an already-normalized value with the canonical settings."""
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_dumps(value: Any) -> str:
    """Return the canonical JSON text of ``value``."""
    return _encode(normalize(value))


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes of ``value`` (the bytes that get hashed)."""
    text = canonical_dumps(value)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates cannot be encoded
        raise CanonicalizationError(f"string is not valid Unicode text: {exc.reason}") from exc


def pretty_json_bytes(value: Any) -> bytes:
    """Return deterministic, human-readable JSON bytes ending in a newline.

    Output files are read by people as well as machines. This uses the same
    normalization as the canonical form (so it can never contain floats and
    keys are always sorted) but indents it. Hashes are always taken over
    :func:`canonical_bytes`, never over this rendering.
    """
    text = json.dumps(normalize(value), sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    try:
        return (text + "\n").encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"string is not valid Unicode text: {exc.reason}") from exc


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_canonical(value: Any) -> str:
    """Return the SHA-256 of the canonical encoding of ``value``."""
    return sha256_bytes(canonical_bytes(value))


def sha256_stream(stream: BinaryIO, *, max_bytes: int | None = None) -> tuple[str, int]:
    """Hash a binary stream in chunks and return ``(hexdigest, byte_count)``.

    Streaming keeps memory flat for large inputs. When ``max_bytes`` is given
    the read stops with :class:`SizeLimitExceeded` as soon as the stream proves
    larger than the limit, so a file that grows after it was measured can
    never be hashed past its declared budget.
    """
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(HASH_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise SizeLimitExceeded(f"stream exceeds {max_bytes} bytes")
        digest.update(chunk)
    return digest.hexdigest(), total


def sha256_file(path: str | PurePath, *, max_bytes: int | None = None) -> tuple[str, int]:
    """Stream-hash the file at ``path`` and return ``(hexdigest, byte_count)``."""
    with open(path, "rb") as stream:
        return sha256_stream(stream, max_bytes=max_bytes)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that refuses duplicate keys.

    Python's ``json`` keeps the *last* duplicate silently, which lets a file
    say two different things to two different readers. Refusing is the only
    unambiguous option.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("DUPLICATE_KEY", f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    """``parse_constant`` hook that refuses NaN, Infinity and -Infinity."""
    raise StrictJSONError("NON_FINITE_NUMBER", f"{name} is not a finite JSON number")


def _reject_non_integer(text: str) -> Any:
    """``parse_float`` hook for documents that must be canonical.

    Canonical output never contains a fraction or an exponent. Accepting one
    on the way back in would let ``1.5`` and ``"1.5"`` normalize to the same
    string and therefore hash identically, hiding a type change.
    """
    raise StrictJSONError("NON_INTEGER_NUMBER", f"{text} is not an integer; canonical documents carry integers only")


def _canonical_integer(text: str) -> int:
    """``parse_int`` hook for canonical documents: integers within ``±MAX_SAFE_INTEGER`` only.

    :func:`normalize` never writes a larger integer, so one found on the way
    back in was not written by this tool and is refused rather than trusted.
    """
    value = int(text)
    if abs(value) > MAX_SAFE_INTEGER:
        raise StrictJSONError("INTEGER_OUT_OF_RANGE", f"{text} is outside +/-(2**53 - 1)")
    return value


def _data_integer(text: str) -> int | Decimal:
    """``parse_int`` hook for input data: an unsafe integer is carried as a ``Decimal``.

    Input data are not ours to refuse, but an integer beyond
    ``±MAX_SAFE_INTEGER`` must never reach hashed content as a JSON number
    (D8). As a ``Decimal`` it keeps every digit and is serialized as a decimal
    string, exactly like a number with a fraction.
    """
    value = int(text)
    return Decimal(text) if abs(value) > MAX_SAFE_INTEGER else value


def _data_decimal(text: str) -> Decimal:
    """Parse a finite decimal without inheriting an invalid-operation policy.

    Even a short JSON exponent can exceed Decimal's implementation range.
    Depending on the caller's context that otherwise raises InvalidOperation
    or produces NaN. Refuse both as a named input error, without changing the
    caller's traps or flags. Decimal construction preserves printed precision
    and does not expand a representable exponent into its digits.
    """
    try:
        with localcontext() as context:
            context.traps[InvalidOperation] = True
            value = Decimal(text)
    except InvalidOperation:
        raise StrictJSONError("MALFORMED_JSON", "number is outside the finite decimal representation") from None
    if not value.is_finite():
        raise StrictJSONError("NON_FINITE_NUMBER", "number is not a finite decimal")
    return value


def strict_loads(data: str | bytes, *, integers_only: bool = False) -> Any:
    """Parse strict JSON from text or UTF-8 bytes (a leading BOM is accepted).

    Non-integer numbers, and integers beyond ``±MAX_SAFE_INTEGER``, are
    returned as ``Decimal``. With ``integers_only`` (use it to re-read
    documents this tool wrote in canonical form, such as ledgers and
    receipts) both are refused instead. Every failure is raised as
    :class:`StrictJSONError`, never as a bare ``json``, ``Unicode`` or
    recursion error, so callers can always produce a named diagnostic.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("MALFORMED_JSON", f"not valid UTF-8 at byte {exc.start}") from exc
    else:
        text = data[1:] if data.startswith("\ufeff") else data
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_reject_non_integer if integers_only else _data_decimal,
            parse_int=_canonical_integer if integers_only else _data_integer,
        )
    except StrictJSONError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJSONError("MALFORMED_JSON", exc.msg, line=exc.lineno, column=exc.colno) from exc
    except RecursionError as exc:
        raise StrictJSONError("MALFORMED_JSON", "nesting is too deep") from exc
    except ValueError as exc:  # e.g. integers beyond the interpreter's digit limit
        raise StrictJSONError("MALFORMED_JSON", str(exc)) from exc
