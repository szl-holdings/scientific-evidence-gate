"""Claim registry and manuscript scan (ARCHITECTURE.md section 7).

STUB: a later stage replaces this module. It exists now so that the
``claim_registry`` kind resolves to a real function. Until it is implemented,
the engine records a manifest that uses the kind as an ERROR result for that
check, with a NotImplementedError diagnostic, and never as a PASS.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manifests import CheckSpec
    from .verifier import CheckContext, CheckOutcome

__all__ = ["check_claim_registry"]


def check_claim_registry(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Check the claim registry and scan the manuscript (kind ``claim_registry``).

    Contract (section 7): read the ``claims`` registry and the ``manuscript``
    through ``ctx.role_document``. Resolve each claim along CLAIM -> ANALYSIS
    RECIPE -> CODE VERSION -> ENVIRONMENT -> INPUT MANIFEST -> STORED OUTPUT ->
    REVIEW STATE -> PUBLICATION LOCATION, and list every missing link. A claim
    with no reproducible derivation is UNVERIFIED with EPHEMERAL_CLAIM, and is
    never called false. Every numeric token in the manuscript either matches a
    registered claim value or is listed as UNREGISTERED with its line number,
    and the check then ABSTAINs with UNVERIFIED. Registered values are compared
    with their stored outputs only through ``invariants.compare_decimal``.
    """
    raise NotImplementedError("claim_registry is not implemented yet (science_gate.claims)")
