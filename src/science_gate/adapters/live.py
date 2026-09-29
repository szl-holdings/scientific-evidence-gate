"""Live resolver adapter: the only network access in the package.

It runs only when the run's :class:`~science_gate.verifier.NetworkPolicy` is
live (``--live`` or the manifest's ``citations.live``). Otherwise
:func:`resolve` raises before it builds a request, so a caller's mistake
becomes a loud ERROR result rather than a quiet network call.

A lookup asks the DOI resolver for CSL JSON through content negotiation, with
the policy's ``User-Agent`` and timeout. The request goes through
``network.opener`` (``urllib.request.urlopen`` when none is injected), which is
how tests replace the network with a failing or scripted opener.

Every failure is SOURCE_UNAVAILABLE, never "not found": a network error, a
non-2xx status (a live 404 included, as the contract requires), an oversized
body, or a body that is not usable CSL JSON. A live answer cannot be
replayed, so only a frozen capture of a NOT_FOUND answer may ever yield
DOI_NOT_RESOLVED_AT_CAPTURE.

The response is hashed, and only the minimum metadata (:class:`Work`) is
kept. The body itself is returned only when the caller says redistribution
is allowed.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .._canonical import StrictJSONError, sha256_bytes, strict_loads
from .._clock import now
from ..models import ResolverState
from .records import SOURCE_LIVE, RecordFormatError, Resolution, Work, parse_work

if TYPE_CHECKING:
    from ..verifier import NetworkPolicy

__all__ = [
    "RESOLVER_BASE_URL",
    "ACCEPT",
    "RESOLVER_IDENTITY",
    "RESOLVER_SCHEMA_VERSION",
    "MAX_RESPONSE_BYTES",
    "LiveAccessRefused",
    "request_url",
    "resolve",
]

RESOLVER_BASE_URL = "https://doi.org/"
ACCEPT = "application/vnd.citationstyles.csl+json"
RESOLVER_IDENTITY = "doi.org content negotiation"
RESOLVER_SCHEMA_VERSION = "csl-json"

#: Bibliographic metadata is small. A larger body is refused unread rather
#: than buffered, so a misbehaving endpoint cannot exhaust memory.
MAX_RESPONSE_BYTES = 1 << 20

#: Exception messages can be long (and quote URLs); diagnostics keep a prefix.
_MAX_DETAIL = 200


class LiveAccessRefused(RuntimeError):
    """A live lookup was requested while the network policy is not live."""


def request_url(doi: str) -> str:
    """The resolver URL for ``doi``, with everything but ``/`` percent-encoded."""
    return RESOLVER_BASE_URL + urllib.parse.quote(doi, safe="/")


def _describe(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return text[:_MAX_DETAIL]


def _close(response: Any) -> None:
    """Release a response whether or not the (possibly injected) object can be closed."""
    close = getattr(response, "close", None)
    if callable(close):
        close()


def _status_of(response: Any) -> int | None:
    status = getattr(response, "status", None)
    if status is None and callable(getattr(response, "getcode", None)):
        status = response.getcode()
    return status if isinstance(status, int) and not isinstance(status, bool) else None


def _fetch(opener: Callable[..., Any], request: urllib.request.Request, timeout: int) -> tuple[int | None, bytes]:
    """Open ``request`` and read at most one byte beyond the size limit."""
    response = opener(request, timeout=timeout)
    try:
        return _status_of(response), response.read(MAX_RESPONSE_BYTES + 1)
    finally:
        _close(response)


def _first_text(value: Any) -> Any:
    """CSL fields such as ``title`` may be a string or a list of strings."""
    if isinstance(value, list):
        return next((item for item in value if isinstance(item, str) and item.strip()), None)
    return value


def _year(issued: Any) -> Any:
    """The year from CSL ``issued.date-parts[0][0]``, or None if absent."""
    if not isinstance(issued, Mapping):
        return None
    parts = issued.get("date-parts")
    if isinstance(parts, list) and parts and isinstance(parts[0], list) and parts[0]:
        return parts[0][0]
    return None


def _author(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        return {"family": None}
    family = item.get("family") or item.get("literal")
    return {"family": family, "given": item.get("given")}


def _work_from_csl(data: Any) -> Work:
    """Keep only the minimum metadata from a CSL JSON record, validated like any other work."""
    if not isinstance(data, Mapping):
        raise RecordFormatError("the response is not a JSON object")
    authors = data.get("author")
    shape = {
        "doi": data.get("DOI"),
        "title": _first_text(data.get("title")),
        "authors": [_author(item) for item in authors] if isinstance(authors, list) else authors,
        "year": _year(data.get("issued")),
        "journal": _first_text(data.get("container-title")),
        "volume": data.get("volume"),
        "issue": data.get("issue"),
    }
    return parse_work(shape, "response")


def _unavailable(
    doi: str, provenance: Mapping[str, Any], diagnostic: str, status: int | None = None
) -> Resolution:
    return Resolution(
        doi=doi,
        state=ResolverState.SOURCE_UNAVAILABLE,
        source=SOURCE_LIVE,
        provenance=provenance,
        http_status=status,
        diagnostics=(diagnostic,),
    )


def resolve(doi: str, network: NetworkPolicy, *, keep_body: bool = False) -> Resolution:
    """Ask the live resolver about ``doi`` (in comparison form) under ``network``'s policy.

    Raises :class:`LiveAccessRefused` when the policy is not live. Otherwise
    always returns a :class:`Resolution`: network trouble is an answer
    (SOURCE_UNAVAILABLE), not an exception. ``keep_body`` is for callers
    whose corpus permissions allow redistribution.
    """
    if not network.live:
        raise LiveAccessRefused(f"live lookup of {doi} refused: the network policy is not live")
    url = request_url(doi)
    provenance: dict[str, Any] = {
        "retrieved_at": now(),
        "request_url_or_query": url,
        "response_sha256": None,
        "resolver_identity": RESOLVER_IDENTITY,
        "resolver_schema_version": RESOLVER_SCHEMA_VERSION,
        "live_refresh_performed": True,
    }
    request = urllib.request.Request(url, headers={"User-Agent": network.user_agent, "Accept": ACCEPT})
    try:
        status, body = _fetch(network.opener or urllib.request.urlopen, request, network.timeout_seconds)
    except urllib.error.HTTPError as exc:  # before OSError: it is one, but it carries a status
        _close(exc)
        return _unavailable(doi, provenance, f"HTTP_STATUS: {exc.code}", exc.code)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return _unavailable(doi, provenance, f"NETWORK_ERROR: {_describe(exc)}")
    if status is None or not 200 <= status <= 299:
        return _unavailable(doi, provenance, f"HTTP_STATUS: {status}", status)
    if len(body) > MAX_RESPONSE_BYTES:
        return _unavailable(doi, provenance, f"RESPONSE_TOO_LARGE: more than {MAX_RESPONSE_BYTES} bytes", status)
    provenance["response_sha256"] = sha256_bytes(body)
    try:
        work = _work_from_csl(strict_loads(body))
    except (StrictJSONError, RecordFormatError) as exc:
        return _unavailable(doi, provenance, f"RESPONSE_UNUSABLE: {_describe(exc)}", status)
    resolved = work.doi == doi
    return Resolution(
        doi=doi,
        state=ResolverState.DOI_RESOLVED if resolved else ResolverState.DOI_TARGET_MISMATCH,
        source=SOURCE_LIVE,
        work=work,
        provenance=provenance,
        http_status=status,
        diagnostics=() if resolved else (f"TARGET_MISMATCH: the resolver returned the work {work.doi}",),
        # strict_loads accepted these bytes, so they decode.
        body=body.decode("utf-8-sig") if keep_body else None,
    )
