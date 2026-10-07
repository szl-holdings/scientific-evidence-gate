"""Live resolver adapter: metadata lookups and the live negative control.

With :mod:`.doi_handle`, this is the only network access in the package. It
runs only when the run's :class:`~science_gate.verifier.NetworkPolicy` is
live (``--live`` or the manifest's ``citations.live``). Otherwise
:func:`resolve` raises before it builds a request, so a caller's mistake
becomes a loud ERROR result rather than a quiet network call.

A lookup asks the DOI resolver for CSL JSON through content negotiation, with
the policy's ``User-Agent`` and timeout. The request goes through
``network.opener`` (``urllib.request.urlopen`` when none is injected), which is
how tests replace the network with a failing or scripted opener.

A positive answer here is only worth something if the same resolver can say
"no". :func:`canary_check` is that negative control (extension #8): a canary
DOI that must not exist, asked of the Handle API (:mod:`.doi_handle`, whose
body code is definitive) and then of this resolver, which must answer "not
found" rather than invent a record.

Every failure is SOURCE_UNAVAILABLE, never "not found": a network error, a
non-2xx status (a live 404 included, as the contract requires), an oversized
body, or a body that is not usable CSL JSON. A content-negotiation 404 is
ambiguous (an HTML error page looks the same), so this adapter never yields
DOI_NOT_RESOLVED_AT_CAPTURE; only a captured NOT_FOUND or a Handle body code
can.

The response is hashed, and only the minimum metadata (:class:`Work`) is
kept. The body itself is returned only when the caller says redistribution
is allowed.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any, Mapping

from .._canonical import StrictJSONError, sha256_bytes, strict_loads
from .._clock import now
from ..models import ResolverState
from . import doi_handle
from ._http import LiveAccessRefused, close, describe, fetch, opener_of, require_live
from .records import (
    HANDLE_NOT_FOUND,
    SOURCE_LIVE,
    SOURCE_NONE,
    CanaryCheck,
    RecordFormatError,
    Resolution,
    Work,
    canary_doi,
    canary_nonce,
    parse_work,
)

if TYPE_CHECKING:
    from ..verifier import NetworkPolicy

__all__ = [
    "RESOLVER_BASE_URL",
    "ACCEPT",
    "RESOLVER_IDENTITY",
    "RESOLVER_SCHEMA_VERSION",
    "MAX_RESPONSE_BYTES",
    "NOT_FOUND_STATUSES",
    "LiveAccessRefused",
    "request_url",
    "resolve",
    "canary_check",
]

RESOLVER_BASE_URL = "https://doi.org/"
ACCEPT = "application/vnd.citationstyles.csl+json"
RESOLVER_IDENTITY = "doi.org content negotiation"
RESOLVER_SCHEMA_VERSION = "csl-json"

#: Bibliographic metadata is small. A larger body is refused unread rather
#: than buffered, so a misbehaving endpoint cannot exhaust memory.
MAX_RESPONSE_BYTES = 1 << 20

#: The statuses with which this resolver says a DOI does not exist. They are
#: never "not found" for a cited DOI (an error page looks the same), but a
#: canary needs exactly this answer: anything else leaves the control unconfirmed.
NOT_FOUND_STATUSES = (404, 410)


def request_url(doi: str) -> str:
    """The resolver URL for ``doi``, with everything but ``/`` percent-encoded."""
    return RESOLVER_BASE_URL + urllib.parse.quote(doi, safe="/")


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
    require_live(network, doi)
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
        status, body = fetch(opener_of(network), request, network.timeout_seconds, MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:  # before OSError: it is one, but it carries a status
        close(exc)
        return _unavailable(doi, provenance, f"HTTP_STATUS: {exc.code}", exc.code)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return _unavailable(doi, provenance, f"NETWORK_ERROR: {describe(exc)}")
    if status is None or not 200 <= status <= 299:
        return _unavailable(doi, provenance, f"HTTP_STATUS: {status}", status)
    if len(body) > MAX_RESPONSE_BYTES:
        return _unavailable(doi, provenance, f"RESPONSE_TOO_LARGE: more than {MAX_RESPONSE_BYTES} bytes", status)
    provenance["response_sha256"] = sha256_bytes(body)
    try:
        work = _work_from_csl(strict_loads(body))
    except (StrictJSONError, RecordFormatError) as exc:
        return _unavailable(doi, provenance, f"RESPONSE_UNUSABLE: {describe(exc)}", status)
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


def canary_check(prefix: str, run_id: str | None, network: NetworkPolicy) -> CanaryCheck:
    """The live negative control for ``prefix``: ``<prefix>/science-gate-canary-<sha256(run_id)[:12]>``.

    Both halves must say the DOI does not exist: the Handle API with body
    code 100, then this resolver with HTTP 404 or 410. Body code 1, or a work
    returned by this resolver, is a proven miss. The resolver is asked only
    once the Handle API has said 100, so a run makes at most two calls per
    prefix. Without a run id there is no nonce, so nothing is asked and the
    control is missing.
    """
    if run_id is None:
        return CanaryCheck(
            prefix=prefix,
            source=SOURCE_NONE,
            doi=None,
            state=ResolverState.SOURCE_UNAVAILABLE,
            handle_response_code=None,
            holds=False,
            detail="NO_RUN_ID: a live canary DOI is derived from the run id, and this context has none",
        )
    doi = canary_doi(prefix, canary_nonce(run_id))
    handle = doi_handle.lookup(doi, network)
    code = handle.handle_response_code
    if code != HANDLE_NOT_FOUND:
        if handle.state is ResolverState.DOI_RESOLVED:
            detail = f"CANARY_RESOLVED: body responseCode {code} for a DOI that cannot exist"
        else:
            detail = "CANARY_NOT_CONFIRMED: a canary needs body responseCode 100; " + "; ".join(handle.diagnostics)
        return CanaryCheck(prefix, SOURCE_LIVE, doi, handle.state, code, False, detail, handle.provenance)
    answer = resolve(doi, network)
    if answer.work is not None:
        state = answer.state
        detail = f"CANARY_RESOLVED: the resolver returned the work {answer.work.doi} for a DOI that cannot exist"
    elif answer.http_status in NOT_FOUND_STATUSES:
        state = handle.state
        detail = f"CANARY_HOLDS: body responseCode 100, and the resolver answered HTTP {answer.http_status}"
    else:
        state = ResolverState.SOURCE_UNAVAILABLE
        detail = (
            "CANARY_NOT_CONFIRMED: body responseCode 100, but the resolver did not say the DOI does not exist: "
            + "; ".join(answer.diagnostics)
        )
    holds = state is ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE
    return CanaryCheck(prefix, SOURCE_LIVE, doi, state, code, holds, detail, answer.provenance)
