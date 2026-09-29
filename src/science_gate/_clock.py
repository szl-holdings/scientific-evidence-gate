"""The single source of time for scientific-evidence-gate.

Every timestamp the tool writes comes from :func:`now`. Keeping one entry point
is what makes byte-for-byte reproducible runs possible: setting
``SCIENCE_GATE_FIXED_TIME`` (ISO-8601 UTC with a ``Z`` suffix) pins every
timestamp, so two runs of the same inputs produce identical files.

A malformed fixed time is an error rather than a silent fallback to the wall
clock. Falling back would quietly break reproducibility while the operator
believes the clock is pinned.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

__all__ = ["FIXED_TIME_ENV", "ClockError", "now", "parse_utc", "format_utc"]

#: Environment variable that pins :func:`now` to a fixed instant.
FIXED_TIME_ENV = "SCIENCE_GATE_FIXED_TIME"

_UTC_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


class ClockError(ValueError):
    """Raised for a timestamp that is not ISO-8601 UTC with a ``Z`` suffix."""


def parse_utc(text: str) -> datetime:
    """Parse ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z`` into an aware UTC datetime.

    Only the ``Z`` form is accepted. Offsets such as ``+02:00`` are refused so
    that one instant has exactly one spelling in every output file.
    """
    if not isinstance(text, str) or not _UTC_PATTERN.fullmatch(text):
        raise ClockError(f"expected ISO-8601 UTC with a Z suffix, got {text!r}")
    try:
        parsed = datetime.fromisoformat(text[:-1])
    except ValueError as exc:  # e.g. month 13 passes the pattern but not the calendar
        raise ClockError(f"not a real UTC instant: {text!r}") from exc
    return parsed.replace(tzinfo=timezone.utc)


def format_utc(moment: datetime) -> str:
    """Format an aware datetime as ISO-8601 UTC with a ``Z`` suffix.

    Microseconds are written only when non-zero, which keeps the common case
    (whole seconds) short and gives every instant a single canonical spelling.
    """
    if moment.tzinfo is None:
        raise ClockError("refusing a naive datetime: its time zone is unknown")
    utc = moment.astimezone(timezone.utc).replace(tzinfo=None)
    spec = "microseconds" if utc.microsecond else "seconds"
    return utc.isoformat(timespec=spec) + "Z"


def now() -> str:
    """Return the current instant, or the pinned instant, as ISO-8601 UTC.

    An empty ``SCIENCE_GATE_FIXED_TIME`` is treated as unset, matching the
    usual shell idiom for clearing a variable. The wall clock is truncated to
    whole seconds because sub-second precision adds noise without adding
    ordering information: the ledger's sequence numbers already order events.
    """
    fixed = os.environ.get(FIXED_TIME_ENV, "")
    if fixed:
        return format_utc(parse_utc(fixed))
    return format_utc(datetime.now(timezone.utc).replace(microsecond=0))
