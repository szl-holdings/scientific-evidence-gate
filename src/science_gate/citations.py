"""Citation checks in three layers (ARCHITECTURE.md section 9).

STUB: a later stage replaces this module. It exists now so that the
``verification_log``, ``citation_resolver`` and ``citation_metadata`` kinds
resolve to real functions. Until they are implemented, the engine records any
manifest check of these kinds as an ERROR result with a NotImplementedError
diagnostic, and never as a PASS.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manifests import CheckSpec
    from .verifier import CheckContext, CheckOutcome

__all__ = ["check_verification_log", "check_resolver", "check_metadata"]


def check_verification_log(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 1, structural and fully offline (kind ``verification_log``).

    Contract: read ``citations.log`` (``{claimed_verified, verifier, entries,
    invocations}``). An entry claimed as verified with no matching invocation
    is UNVERIFIED with NARRATED_VERIFICATION. The claimed count is reported
    as a ``ClaimTally`` in ``CheckOutcome.claim_tallies``, so that
    ``checked_claims_le_invocations`` breaks when ``claimed_verified``
    exceeds the invocations. Claimed verifications with zero invocations
    give ABSTAIN with UNVERIFIED.
    """
    raise NotImplementedError("verification_log is not implemented yet (science_gate.citations)")


def check_resolver(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 2, DOI resolution from the frozen record set (kind ``citation_resolver``).

    Contract: every frozen record carries ``retrieved_at``,
    ``request_url_or_query``, ``response_sha256``, ``resolver_identity``,
    ``resolver_schema_version`` and ``live_refresh_performed``. A missing
    provenance field makes that record SOURCE_UNAVAILABLE. Per-DOI states come
    from ``ResolverState``. With ``ctx.network.live`` off, anything absent from
    the frozen set is SOURCE_UNAVAILABLE, never "not found". Live lookups go
    only through ``science_gate.adapters.live`` with ``ctx.network``.
    """
    raise NotImplementedError("citation_resolver is not implemented yet (science_gate.citations)")


def check_metadata(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome:
    """Layer 3, metadata comparison (kind ``citation_metadata``).

    Contract: compare title (casefolded, whitespace and punctuation
    normalized), authors and their order, year, journal, volume, issue, and
    DOI-to-work consistency. CONFLATED_ENTRY applies when the fields match two
    different frozen records. Each citation gets exactly one
    ``primary_disposition`` plus a list of ``defects``, which may overlap.
    Totals are per defect type. An unresolved replacement candidate is never
    chosen as ground truth.
    """
    raise NotImplementedError("citation_metadata is not implemented yet (science_gate.citations)")
