"""Evaluation packaging (ARCHITECTURE.md section 13).

STUB: a later stage replaces this module. It exists now so that the
``package`` command resolves to a real function. Until it is implemented, the
command exits 3 with a clear message.
"""

from __future__ import annotations

import argparse

__all__ = ["cli_package"]


def cli_package(args: argparse.Namespace) -> int:
    """``science-gate package MANIFEST --output PATH [--force]``; returns the exit code.

    Contract: write ``package.json`` (access class, permissions, declared
    source licenses, input hashes, expected results, approved redactions,
    local execution instructions), the schemas and the expected results. Data
    files are copied only for PUBLIC or SYNTHETIC corpora that may be
    redistributed. CONTROLLED_LOCAL and REFERENCE_ONLY inputs are never copied.
    Output goes only inside ``--output``, never inside an input directory, and
    existing output is refused unless ``--force``.
    """
    raise NotImplementedError("package is not implemented yet (science_gate.packaging)")
