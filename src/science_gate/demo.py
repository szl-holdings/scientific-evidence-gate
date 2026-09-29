"""The synthetic end-to-end demonstration (ARCHITECTURE.md section 14).

STUB: a later stage replaces this module. It exists now so that the ``demo``
command resolves to a real function. Until it is implemented, the command
exits 3 with a clear message.
"""

from __future__ import annotations

import argparse

__all__ = ["cli_demo"]


def cli_demo(args: argparse.Namespace) -> int:
    """``science-gate demo [--output DIR]``; returns the exit code.

    Contract: run the synthetic fixtures end to end, offline, writing only
    inside ``--output``. Print a one-line status headline followed by the
    paths written, and claim no scientific verification.
    """
    raise NotImplementedError("demo is not implemented yet (science_gate.demo)")
