"""Live resolver adapter: the only network access in the package.

STUB: a later stage replaces this module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from ..verifier import NetworkPolicy

__all__ = ["resolve"]


def resolve(doi: str, network: NetworkPolicy) -> Mapping[str, Any]:
    """Resolve ``doi`` over the network, under ``network``'s policy.

    Contract (section 9): refuse unless ``network.live``. Use
    ``network.opener`` (``urllib.request.urlopen`` when None) with
    ``network.timeout_seconds`` and a ``User-Agent`` of ``network.user_agent``.
    Any network error or non-2xx response becomes SOURCE_UNAVAILABLE.
    Responses are hashed, only minimum metadata is kept, and bodies are
    persisted only when redistribution is allowed.
    """
    raise NotImplementedError("the live resolver adapter is not implemented yet")
