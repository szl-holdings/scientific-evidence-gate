"""Mutation testing of the verifier itself (ARCHITECTURE.md section 10).

STUB: a later stage replaces this module. It exists now so that the ``mutate``
command resolves to a real function. Until it is implemented, the command
exits 3 with a clear message.
"""

from __future__ import annotations

import argparse

__all__ = ["cli_mutate"]


def cli_mutate(args: argparse.Namespace) -> int:
    """``science-gate mutate MANIFEST [--output DIR]``; returns the exit code.

    Contract: first verify an untouched copy of the tree. If that baseline is
    not PASS, the report is INVALID_BASELINE, carries no sensitivity figure and
    no count keys, prints "No sensitivity figure was produced because the
    verifier failed its accepting baseline.", and exits 1. Otherwise apply each
    operator M01..M20 to a fresh copy. A mutation counts as detected only if
    the status is not PASS *and* its expected detector fired. Skipped and
    not-applicable mutations are never counted as detections.
    """
    raise NotImplementedError("mutate is not implemented yet (science_gate.mutations)")
