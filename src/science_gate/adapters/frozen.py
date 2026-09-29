"""Frozen resolver adapter: answers from a recorded response set, offline.

STUB: a later stage replaces this module.
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = ["resolve"]


def resolve(doi: str, frozen: Mapping[str, Any]) -> Mapping[str, Any]:
    """Look ``doi`` up in the frozen record set.

    Contract (section 9): a record needs ``retrieved_at``,
    ``request_url_or_query``, ``response_sha256``, ``resolver_identity``,
    ``resolver_schema_version`` and ``live_refresh_performed``. A record
    missing any of them, or a DOI absent from the frozen set, is
    SOURCE_UNAVAILABLE, never "not found".
    """
    raise NotImplementedError("the frozen resolver adapter is not implemented yet")
