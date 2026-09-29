"""Dependency graph, impact walks and revalidation (ARCHITECTURE.md section 8).

STUB: a later stage replaces this module. It exists now so that the
``dependency_currency`` kind and the ``impact`` and ``revalidate`` commands
resolve to real functions. Until they are implemented, the check is recorded
as an ERROR result, and the commands exit 3 with a clear message.
"""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manifests import CheckSpec
    from .verifier import CheckContext, CheckOutcome

__all__ = ["check_dependency_currency", "cli_impact", "cli_revalidate"]


def check_dependency_currency(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Publication is blocked by stale dependencies (kind ``dependency_currency``).

    Contract: read the ``dependencies`` graph (and ``graph-state.json`` next to
    it). A cycle is an ERROR. While any CONCLUSION or FIGURE_OR_TABLE node is
    STALE_PENDING_REVALIDATION, the verdict is FAIL with STALE_DEPENDENCY.
    """
    raise NotImplementedError("dependency_currency is not implemented yet (science_gate.dependencies)")


def cli_impact(args: argparse.Namespace) -> int:
    """``science-gate impact ARTIFACT_ID --manifest MANIFEST``; returns the exit code.

    Contract: walk the descendants of ``args.artifact_id`` breadth-first in
    sorted order and mark them STALE_PENDING_REVALIDATION. Record each
    transition in ``history`` as ``{at, from, to, reason}``, persist the
    result to ``graph-state.json`` with a safe write, and print a one-line
    status headline followed by the paths written. Nothing is called false or
    INVALIDATED.
    """
    raise NotImplementedError("impact is not implemented yet (science_gate.dependencies)")


def cli_revalidate(args: argparse.Namespace) -> int:
    """``science-gate revalidate ARTIFACT_ID --manifest MANIFEST``; returns the exit code.

    Contract: recompute the node's hash. If it equals the recorded hash, the
    node becomes REVALIDATED_UNCHANGED, and descendants stale only because of
    it may be cleared. Otherwise it becomes REVALIDATED_CHANGED, the new hash
    is recorded, and its children stay stale. Both states are kept in
    ``history``.
    """
    raise NotImplementedError("revalidate is not implemented yet (science_gate.dependencies)")
