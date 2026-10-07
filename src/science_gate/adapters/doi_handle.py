"""Live Handle lookups through the DOI proxy's Handle API (extension #8).

This adapter answers one question: does a DOI exist as a handle? The live
resolver's negative control (:func:`.live.canary_check`) asks it first about
a canary DOI that must not exist, because only the Handle API answers "no"
definitively. A content-negotiation 404 is ambiguous: an HTML error page
looks the same.

**Body codes decide, never the HTTP status.** The JSON body's
``responseCode`` is the answer (:func:`~.records.state_for_handle_code`): 1
resolves, 100 (handle not found) and 200 (values not found) do not, anything
else is no answer. The proxy sends 100 behind HTTP 404 and 200 behind HTTP
200, so the body of an error response is read too, and a "values not found"
behind HTTP 200 can never read as resolved.

Like :mod:`.live`, it runs only under a live :class:`NetworkPolicy`, goes
through ``network.opener`` only, bounds what it reads, and turns every
transport failure into SOURCE_UNAVAILABLE. The body is hashed and dropped; a
Handle answer carries no bibliographic metadata worth keeping.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping

from .._canonical import StrictJSONError, sha256_bytes, strict_loads
from .._clock import now
from ..models import ResolverState
from ._http import close, describe, fetch, opener_of, read_bounded, require_live
from .records import PROVENANCE_FIELDS, state_for_handle_code

if TYPE_CHECKING:
    from ..verifier import NetworkPolicy

__all__ = [
    "HANDLE_API_URL",
    "ACCEPT",
    "RESOLVER_IDENTITY",
    "RESOLVER_SCHEMA_VERSION",
    "MAX_RESPONSE_BYTES",
    "HandleAnswer",
    "request_url",
    "lookup",
]

HANDLE_API_URL = "https://doi.org/api/handles/"
ACCEPT = "application/json"
RESOLVER_IDENTITY = "doi.org handle API"
RESOLVER_SCHEMA_VERSION = "handle-api-json"

#: A Handle answer is a short JSON object; anything larger is refused unread.
MAX_RESPONSE_BYTES = 1 << 16


@dataclass(frozen=True)
class HandleAnswer:
    """One Handle lookup: the body code (when one could be read) and the state it decides."""

    doi: str
    state: ResolverState
    handle_response_code: int | None
    http_status: int | None
    provenance: Mapping[str, Any] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "doi": self.doi,
            "state": self.state.value,
            "handle_response_code": self.handle_response_code,
            "http_status": self.http_status,
            "provenance": {name: self.provenance.get(name) for name in PROVENANCE_FIELDS},
            "diagnostics": list(self.diagnostics),
        }


def request_url(doi: str) -> str:
    """The Handle API URL for ``doi``, with everything but ``/`` percent-encoded."""
    return HANDLE_API_URL + urllib.parse.quote(doi, safe="/")


def _response_code(body: bytes) -> int:
    """The integer ``responseCode`` of a Handle body; ValueError when there is none."""
    try:
        document = strict_loads(body)
    except StrictJSONError as exc:
        raise ValueError(f"not JSON: {exc}") from None
    code = document.get("responseCode") if isinstance(document, Mapping) else None
    if isinstance(code, bool) or not isinstance(code, int):
        raise ValueError("the body has no integer responseCode")
    return code


def lookup(doi: str, network: NetworkPolicy) -> HandleAnswer:
    """Ask the Handle API about ``doi`` (in comparison form) under ``network``'s policy.

    Raises :class:`~._http.LiveAccessRefused` when the policy is not live.
    Otherwise always returns an answer: network trouble, an oversized body or
    a body without a ``responseCode`` is SOURCE_UNAVAILABLE.
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

    def unavailable(diagnostic: str, status: int | None = None) -> HandleAnswer:
        return HandleAnswer(doi, ResolverState.SOURCE_UNAVAILABLE, None, status, provenance, (diagnostic,))

    request = urllib.request.Request(url, headers={"User-Agent": network.user_agent, "Accept": ACCEPT})
    try:
        status, body = fetch(opener_of(network), request, network.timeout_seconds, MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:  # the proxy answers "not found" with a 404 *and* a body code
        status = exc.code
        try:
            body = read_bounded(exc, MAX_RESPONSE_BYTES)
        except (OSError, http.client.HTTPException, ValueError) as read_error:
            return unavailable(f"NETWORK_ERROR: {describe(read_error)}", status)
        finally:
            close(exc)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return unavailable(f"NETWORK_ERROR: {describe(exc)}")
    if len(body) > MAX_RESPONSE_BYTES:
        return unavailable(f"RESPONSE_TOO_LARGE: more than {MAX_RESPONSE_BYTES} bytes", status)
    if body:
        provenance["response_sha256"] = sha256_bytes(body)
    try:
        code = _response_code(body)
    except ValueError as exc:
        return unavailable(f"RESPONSE_UNUSABLE: HTTP status {status}, {exc}", status)
    state = state_for_handle_code(code)
    detail = f"HANDLE_RESPONSE: body responseCode {code} (HTTP status {status} not used)"
    return HandleAnswer(doi, state, code, status, provenance, (detail,))

