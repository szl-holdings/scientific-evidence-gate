"""HTTP plumbing shared by the live adapters (``live`` and ``doi_handle``).

Both adapters go through ``NetworkPolicy.opener`` only, read a bounded body,
and turn every transport failure into an answer rather than an exception.
Keeping that plumbing in one place means the two adapters cannot drift apart
on the rules that keep a live run honest: the size bound, closing what was
opened, and short, path-free diagnostics.
"""

from __future__ import annotations

import urllib.request
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ..verifier import NetworkPolicy

__all__ = ["LiveAccessRefused", "require_live", "opener_of", "close", "status_of", "fetch", "read_bounded", "describe"]

#: Exception messages can be long (and quote URLs); diagnostics keep a prefix.
_MAX_DETAIL = 200


class LiveAccessRefused(RuntimeError):
    """A live lookup was requested while the network policy is not live."""


def require_live(network: NetworkPolicy, what: str) -> None:
    """Refuse before any request is built: a caller's mistake must be a loud ERROR, not a quiet call."""
    if not network.live:
        raise LiveAccessRefused(f"live lookup of {what} refused: the network policy is not live")


def opener_of(network: NetworkPolicy) -> Callable[..., Any]:
    """The injected opener, else ``urllib.request.urlopen``. Nothing else ever opens a connection."""
    return network.opener or urllib.request.urlopen


def close(response: Any) -> None:
    """Release a response whether or not the (possibly injected) object can be closed."""
    closer = getattr(response, "close", None)
    if callable(closer):
        closer()


def status_of(response: Any) -> int | None:
    """The HTTP status of a response object, from ``status`` or ``getcode()``; None if neither is an int."""
    status = getattr(response, "status", None)
    if status is None and callable(getattr(response, "getcode", None)):
        status = response.getcode()
    return status if isinstance(status, int) and not isinstance(status, bool) else None


def read_bounded(response: Any, max_bytes: int) -> bytes:
    """Read at most one byte beyond ``max_bytes``, so an oversized body is detected without buffering it."""
    data = response.read(max_bytes + 1)
    return data if isinstance(data, bytes) else b""


def fetch(
    opener: Callable[..., Any], request: urllib.request.Request, timeout: int, max_bytes: int
) -> tuple[int | None, bytes]:
    """Open ``request`` and return ``(status, body)``, closing the response either way."""
    response = opener(request, timeout=timeout)
    try:
        return status_of(response), read_bounded(response, max_bytes)
    finally:
        close(response)


def describe(exc: BaseException) -> str:
    """``Type: message``, cut to a short prefix so a diagnostic never carries a long URL or path."""
    text = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return text[:_MAX_DETAIL]
