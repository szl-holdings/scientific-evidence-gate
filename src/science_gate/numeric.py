"""Exact numeric forensics (ARCHITECTURE.md section 17.11: extensions #3, #7, #17 and decision D5).

A printed number is not a point. "5.18" stands for every value that some
rounding rule would print as 5.18, and toolchains disagree about ties, so the
set of values behind a printed number depends on a *convention set*. This
module turns printed strings into those sets and asks exact questions of them:

* :func:`preimage`: the interval of values a printed number can stand for.
* :func:`grim`, :func:`grimmer`, :func:`debit`: can a reported mean, standard
  deviation or proportion come from integer data of the stated size at all?
* :func:`metric_feasibility`: can reported classifier metrics come from any
  confusion matrix with the stated class sizes?
* :func:`derived_interval`: the guaranteed range of a quantity computed from
  rounded inputs.
* :func:`compare_with_tolerance`: a tolerance comparison that reports when its
  band is so wide that it could not have failed.
* :func:`rounding_fingerprint`: which rounding rules turn a stored value into
  the printed digits (a number rounded outside the declared toolchain shows up
  here, extension #7).
* :func:`candidate_readings`: every way a manuscript token can be read, so a
  locale or separator problem is named instead of silently guessed (#17).

The governing rule applies to numbers too: a test may pass only if it could
have failed. Every test therefore returns a :class:`NumericTest` that carries
its *discrimination*, the share of a stated finite grid of admissible values
the test would reject, as an exact :class:`~science_gate.models.Ratio`. A test
with zero discrimination is NOT_TESTABLE and never PASS; a test that holds
only because it could not have failed is VACUOUSLY_CONSISTENT.

Everything is exact: ``Decimal`` and ``Fraction`` only, and inputs are printed
strings, never floats. The one exception is FLOAT_FIRST, which models a
toolchain that converts to binary floating point before rounding; that float
exists only for the duration of one rounding call and is never returned,
stored or hashed. Work is bounded by :data:`MAX_ENUMERATION`, and a grid too
large to count exactly gives an UNAVAILABLE discrimination (so NOT_TESTABLE),
never a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from .invariants import MAX_NUMBER_LENGTH, parse_decimal
from .models import (
    EITHER_HALF,
    NUMERIC_OUTCOME_VERDICTS,
    ExecutionState,
    FailureMode,
    NumericOutcome,
    Ratio,
    RatioState,
    Reason,
    RoundingConvention,
    Status,
)

__all__ = [
    "MAX_ENUMERATION",
    "MAX_GRID_POINTS",
    "TOLERANCE_GRID_STEPS",
    "MAX_LISTED_WITNESSES",
    "FORMULAS",
    "METRICS",
    "GROUPING_MARKS",
    "DECIMAL_MARKS",
    "PrintedNumber",
    "printed_number",
    "round_fraction",
    "round_with",
    "RoundingInterval",
    "preimage",
    "NumericTest",
    "grim",
    "grimmer",
    "debit",
    "metric_feasibility",
    "apply_formula",
    "derived_interval",
    "compare_with_tolerance",
    "rounding_fingerprint",
    "Reading",
    "candidate_readings",
]

#: The most candidates any single test enumerates (sums, confusion matrices,
#: grid points times candidates). Past it the test reports an UNAVAILABLE
#: discrimination instead of running for an unbounded time.
MAX_ENUMERATION = 1_000_000

#: The largest grid whose size is reported. Discrimination counts travel in
#: canonical JSON, whose integers are bounded by 2**53 - 1 (decision D8).
MAX_GRID_POINTS = 2**53 - 1

#: :func:`compare_with_tolerance` probes the observed value moved by
#: k units of its last printed digit, for k = -10..10 (21 points).
TOLERANCE_GRID_STEPS = 10

#: Evidence lists at most this many witnesses (valid confusion matrices);
#: the full count is always recorded beside them.
MAX_LISTED_WITNESSES = 20

#: Derivations a registered claim may declare, each over two ordered operands.
FORMULAS: tuple[str, ...] = ("difference", "ratio", "percent", "f1")

#: Classifier metrics :func:`metric_feasibility` understands, as proportions in [0, 1].
METRICS: tuple[str, ...] = (
    "sensitivity",
    "specificity",
    "precision",
    "npv",
    "accuracy",
    "balanced_accuracy",
    "f1",
)

#: Marks that group digits somewhere in the world, and the two decimal marks.
#: :func:`candidate_readings` tries each pairing when the declared one fails.
GROUPING_MARKS: tuple[str, ...] = (",", ".", "'", "_", "\u00a0", "\u2009", "\u202f", "’")
DECIMAL_MARKS: tuple[str, ...] = (".", ",")

_PLAIN = re.compile(r"(-?)([0-9]+)(?:\.([0-9]+))?")


# ---------------------------------------------------------------------------
# Printed numbers and exact rounding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrintedNumber:
    """A plain printed number: its exact value, its printed decimals, and ``scaled = value * 10**decimals``.

    ``scaled`` is an integer, so rounding questions about the number become
    integer arithmetic, which is both exact and fast.
    """

    text: str
    value: Decimal
    decimals: int
    scaled: int

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.scaled, 10**self.decimals)


def printed_number(text: str, name: str = "value") -> PrintedNumber:
    """Parse a plain printed number: optional ``-``, ASCII digits, optional ``.`` and digits.

    No grouping marks, exponents or locale decimal commas: a caller that reads
    manuscripts normalizes first (see :func:`candidate_readings`), so that a
    test never guesses which number a string meant. Floats are refused,
    because their printed precision is already lost.
    """
    if isinstance(text, float) or not isinstance(text, str):
        raise TypeError(f"{name} must be the printed string, not {type(text).__name__}")
    if len(text) > MAX_NUMBER_LENGTH:
        raise ValueError(f"{name} is longer than {MAX_NUMBER_LENGTH} characters")
    match = _PLAIN.fullmatch(text)
    if match is None:
        raise ValueError(f"{name} {text!r} is not a plain printed number such as '5.18'")
    sign, integer, fraction = match.group(1), match.group(2), match.group(3) or ""
    scaled = int(integer + fraction) * (-1 if sign else 1)
    return PrintedNumber(text, Decimal(text), len(fraction), scaled)


def _scaled_text(scaled: int, decimals: int) -> str:
    """The plain text of ``scaled / 10**decimals`` with exactly ``decimals`` places (never ``-0``)."""
    digits = str(abs(scaled)).rjust(decimals + 1, "0")
    body = f"{digits[:-decimals]}.{digits[-decimals:]}" if decimals else digits
    return f"-{body}" if scaled < 0 else body


def _scaled_decimal(scaled: int, decimals: int) -> Decimal:
    return Decimal(_scaled_text(scaled, decimals))


def _scaled_round(numerator: int, denominator: int, decimals: int, convention: RoundingConvention) -> int:
    """``numerator / denominator`` rounded to ``decimals`` places, as an integer count of the last place.

    Pure integer arithmetic for every exact rule. HALF_UP rounds ties away
    from zero (as ``decimal.ROUND_HALF_UP`` and spreadsheet ROUND do), and
    TRUNCATE rounds toward zero. FLOAT_FIRST converts to the nearest binary
    float, rounds that with Python's correctly rounded ``round`` and reads
    back its shortest ``repr``: the float lives only inside this call.
    """
    if convention is RoundingConvention.FLOAT_FIRST:
        shown = Decimal(repr(round(numerator / denominator, decimals)))
        return int(shown.scaleb(decimals).to_integral_value())
    scaled = numerator * 10**decimals
    quotient, remainder = divmod(scaled, denominator)
    if remainder == 0 or convention is RoundingConvention.FLOOR:
        return quotient
    if convention is RoundingConvention.CEILING:
        return quotient + 1
    if convention is RoundingConvention.TRUNCATE:
        return quotient if scaled >= 0 else quotient + 1
    twice = 2 * remainder
    if twice != denominator:
        return quotient + (twice > denominator)
    if convention is RoundingConvention.HALF_EVEN:
        return quotient + (quotient % 2)
    return quotient + 1 if scaled >= 0 else quotient  # HALF_UP: a tie goes away from zero


def _decimals(decimals: int) -> int:
    if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
        raise ValueError(f"decimals must be a non-negative int, got {decimals!r}")
    if decimals > MAX_NUMBER_LENGTH:
        raise ValueError(f"decimals above {MAX_NUMBER_LENGTH} are refused")
    return decimals


def round_fraction(value: Fraction, decimals: int, convention: RoundingConvention) -> Decimal:
    """Round an exact rational to ``decimals`` places under ``convention``.

    Derived quantities (a ratio of two stored values, say) are rarely finite
    decimals, so they are rounded from the exact fraction, never from a
    truncated decimal expansion that could move a tie.
    """
    if isinstance(value, float):
        raise TypeError("floats are never accepted; pass a Fraction or Decimal")
    value = Fraction(value)
    scaled = _scaled_round(value.numerator, value.denominator, _decimals(decimals), RoundingConvention(convention))
    return _scaled_decimal(scaled, decimals)


def round_with(value: Decimal, decimals: int, convention: RoundingConvention) -> Decimal:
    """Round ``value`` to ``decimals`` places under ``convention``, exactly as that toolchain would.

    FLOAT_FIRST equals ``Decimal(repr(round(float(text), decimals)))``,
    quantized to ``decimals`` places.
    """
    if isinstance(value, float) or not isinstance(value, Decimal) or not value.is_finite():
        raise TypeError("round_with takes a finite Decimal; floats are never accepted")
    return round_fraction(Fraction(value), decimals, convention)


def _conventions(
    value: Iterable[RoundingConvention | str], *, exact_only: bool = False
) -> frozenset[RoundingConvention]:
    """A non-empty convention set. ``exact_only`` refuses FLOAT_FIRST, which has no exact preimage."""
    if isinstance(value, (str, RoundingConvention)):
        raise TypeError("conventions must be a collection of RoundingConvention values")
    conventions = frozenset(RoundingConvention(item) for item in value)
    if not conventions:
        raise ValueError("at least one rounding convention is required")
    if exact_only and RoundingConvention.FLOAT_FIRST in conventions:
        raise ValueError("FLOAT_FIRST is a toolchain behaviour with no exact decimal preimage; it is not accepted here")
    return conventions


def _convention_names(conventions: Iterable[RoundingConvention]) -> list[str]:
    return sorted(convention.value for convention in conventions)


def _count(value: Any, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an int >= {minimum}, got {value!r}")
    return value


def _exact_text(value: Fraction) -> str:
    """An exact text for a rational: a plain decimal when it terminates, else ``p/q``."""
    denominator, places = value.denominator, 0
    for prime in (2, 5):
        power = 0
        while denominator % prime == 0:
            denominator //= prime
            power += 1
        places = max(places, power)
    if denominator != 1:
        return f"{value.numerator}/{value.denominator}"
    return _scaled_text(value.numerator * 10**places // value.denominator, places)


# ---------------------------------------------------------------------------
# Preimages
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoundingInterval:
    """The values a printed number (or a quantity derived from printed numbers) can stand for.

    The bounds are exact rationals. Each end is open or closed, because
    whether a tie belongs to a printed value is exactly what rounding rules
    disagree about.
    """

    low: Fraction
    high: Fraction
    low_inclusive: bool
    high_inclusive: bool
    conventions: frozenset[RoundingConvention]

    def contains(self, value: str | int | Decimal | Fraction) -> bool:
        """Whether ``value`` (a plain printed string, an int, a Decimal or a Fraction) lies in the interval."""
        if isinstance(value, str):
            number = printed_number(value).fraction
        elif isinstance(value, float):
            raise TypeError("floats are never accepted; pass the printed string")
        else:
            number = Fraction(value)
        above = number > self.low or (self.low_inclusive and number == self.low)
        below = number < self.high or (self.high_inclusive and number == self.high)
        return above and below

    @property
    def notation(self) -> str:
        left, right = "[" if self.low_inclusive else "(", "]" if self.high_inclusive else ")"
        return f"{left}{_exact_text(self.low)}, {_exact_text(self.high)}{right}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "low": _exact_text(self.low),
            "high": _exact_text(self.high),
            "low_inclusive": self.low_inclusive,
            "high_inclusive": self.high_inclusive,
            "conventions": _convention_names(self.conventions),
            "notation": self.notation,
        }


_Bounds = tuple[Fraction, Fraction, bool, bool]


def _convention_bounds(scaled: int, decimals: int, convention: RoundingConvention) -> _Bounds:
    """The values ``convention`` prints as ``scaled / 10**decimals``.

    HALF_EVEN owns both ties exactly when the last digit is even. HALF_UP
    owns the tie on the side nearer zero. TRUNCATE, CEILING and FLOOR own a
    whole unit of the last place on one side.
    """
    unit = Fraction(1, 10**decimals)
    point, half = scaled * unit, unit / 2
    if convention is RoundingConvention.HALF_EVEN:
        even = scaled % 2 == 0
        return point - half, point + half, even, even
    if convention is RoundingConvention.HALF_UP:
        return point - half, point + half, scaled > 0, scaled < 0
    if convention is RoundingConvention.TRUNCATE:
        if scaled == 0:
            return -unit, unit, False, False
        return (point, point + unit, True, False) if scaled > 0 else (point - unit, point, False, True)
    if convention is RoundingConvention.CEILING:
        return point - unit, point, False, True
    if convention is RoundingConvention.FLOOR:
        return point, point + unit, True, False
    raise ValueError("FLOAT_FIRST has no exact decimal preimage")


def _union(bounds: Iterable[_Bounds]) -> _Bounds:
    """The union of intervals that all contain the printed value (so the union is one interval)."""
    items = list(bounds)
    low = min(item[0] for item in items)
    high = max(item[1] for item in items)
    low_inclusive = any(item[2] for item in items if item[0] == low)
    high_inclusive = any(item[3] for item in items if item[1] == high)
    return low, high, low_inclusive, high_inclusive


def _preimage_of(scaled: int, decimals: int, conventions: frozenset[RoundingConvention]) -> RoundingInterval:
    low, high, low_inclusive, high_inclusive = _union(
        _convention_bounds(scaled, decimals, convention) for convention in conventions
    )
    return RoundingInterval(low, high, low_inclusive, high_inclusive, conventions)


def preimage(
    printed: str, *, conventions: Iterable[RoundingConvention] = (RoundingConvention.HALF_EVEN,)
) -> RoundingInterval:
    """Every value that some convention in ``conventions`` prints as ``printed``.

    The union of the per-convention preimages is a single interval, because
    each of them contains the printed value itself.
    """
    number = printed_number(printed, "printed")
    return _preimage_of(number.scaled, number.decimals, _conventions(conventions, exact_only=True))


# ---------------------------------------------------------------------------
# Test results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NumericTest:
    """The outcome of one exact numeric test, with the discrimination that makes a pass meaningful.

    ``verdict``, ``reason``, ``execution_state`` and ``failure_modes`` come
    from :data:`~science_gate.models.NUMERIC_OUTCOME_VERDICTS`. A CONSISTENT
    outcome is refused unless its discrimination is defined and above zero,
    so a pass that could not have failed cannot even be constructed.
    """

    test: str
    outcome: NumericOutcome
    discrimination: Ratio
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", NumericOutcome(self.outcome))
        if not isinstance(self.discrimination, Ratio):
            raise TypeError("discrimination must be a Ratio")
        if self.outcome is NumericOutcome.CONSISTENT and not _discriminates(self.discrimination):
            raise ValueError("a CONSISTENT outcome needs a defined discrimination above zero")
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))

    @property
    def holds(self) -> bool | None:
        """True when consistent (vacuously or not), False when inconsistent, None when not testable."""
        if self.outcome is NumericOutcome.NOT_TESTABLE:
            return None
        return self.outcome is not NumericOutcome.INCONSISTENT

    @property
    def execution_state(self) -> ExecutionState:
        return NUMERIC_OUTCOME_VERDICTS[self.outcome][0]

    @property
    def verdict(self) -> Status:
        return NUMERIC_OUTCOME_VERDICTS[self.outcome][1]

    @property
    def reason(self) -> Reason:
        return NUMERIC_OUTCOME_VERDICTS[self.outcome][2]

    @property
    def failure_modes(self) -> tuple[FailureMode, ...]:
        return NUMERIC_OUTCOME_VERDICTS[self.outcome][3]

    def to_dict(self) -> dict[str, Any]:
        return {
            "test": self.test,
            "outcome": self.outcome.value,
            "holds": self.holds,
            "execution_state": self.execution_state.value,
            "verdict": self.verdict.value,
            "reason": self.reason.value,
            "failure_modes": [mode.value for mode in self.failure_modes],
            "discrimination": self.discrimination.decimal,
            "discrimination_ratio": self.discrimination.to_dict(),
            "evidence": dict(self.evidence),
        }


_UNAVAILABLE = Ratio(None, None)


def _discriminates(ratio: Ratio) -> bool:
    return ratio.state is RatioState.DEFINED and bool(ratio.numerator)


def _holding_outcome(discrimination: Ratio) -> NumericOutcome:
    """A test that held is CONSISTENT only if it could have rejected something."""
    return NumericOutcome.CONSISTENT if _discriminates(discrimination) else NumericOutcome.NOT_TESTABLE


def _unit_grid(number: PrintedNumber) -> tuple[int, int, str]:
    """The grid every GRIM-family test is scored on: each value with the printed decimals in [floor, floor + 1).

    Returns the first grid point (scaled), the number of points, and a description.
    """
    points = 10**number.decimals
    floor = number.scaled // points
    return floor * points, points, f"every value printed with {number.decimals} decimal(s) in [{floor}, {floor + 1})"


# ---------------------------------------------------------------------------
# GRIM: can a mean come from integer data?
# ---------------------------------------------------------------------------


def _reproduces(
    numerator: int, denominator: int, decimals: int, target: int, conventions: Iterable[RoundingConvention]
) -> bool:
    return any(_scaled_round(numerator, denominator, decimals, convention) == target for convention in conventions)


@lru_cache(maxsize=4096)
def _grim_discrimination(
    first: int, decimals: int, denominator: int, conventions: frozenset[RoundingConvention]
) -> Ratio:
    """How many points of the unit grid starting at ``first`` no integer total over ``denominator`` prints as.

    When ``denominator >= 10**decimals`` the multiples of ``1/denominator``
    are at least as dense as the grid, so every point is reachable and the
    test cannot fail: zero, computed without enumeration. Otherwise each
    total ``k`` near the unit is rounded under every convention and the
    distinct grid points hit are counted. Cached, because a property test
    asks the same question for many means.
    """
    points = 10**decimals
    if points > MAX_GRID_POINTS:
        return _UNAVAILABLE
    if denominator >= points and RoundingConvention.FLOAT_FIRST not in conventions:
        return Ratio(0, points)
    if 3 * denominator + 1 > MAX_ENUMERATION:
        return _UNAVAILABLE
    unit = first // points
    hit: set[int] = set()
    for total in range((unit - 1) * denominator, (unit + 2) * denominator + 1):
        for convention in conventions:
            scaled = _scaled_round(total, denominator, decimals, convention)
            if first <= scaled < first + points:
                hit.add(scaled)
    return Ratio(points - len(hit), points)


def grim(
    mean: str, n: int, *, items: int = 1, conventions: Iterable[RoundingConvention] = EITHER_HALF
) -> NumericTest:
    """GRIM: is ``mean`` the rounding of some integer total divided by ``n * items``?

    Data on an integer scale (``items`` integer items per respondent) have a
    total that is an integer, so their mean is ``k / (n * items)``. The test
    can only fail when ``n * items < 10**decimals``; otherwise every printed
    mean is reachable, the discrimination is zero and the outcome is
    NOT_TESTABLE. An inconsistent mean reports the nearest consistent printed
    values below and above it.
    """
    number = printed_number(mean, "mean")
    denominator = _count(n, "n", 1) * _count(items, "items", 1)
    chosen = _conventions(conventions)
    decimals, target = number.decimals, number.scaled
    below_total = target * denominator // 10**decimals
    above_total = -(-target * denominator // 10**decimals)
    totals = sorted(
        {total for total in (below_total, above_total) if _reproduces(total, denominator, decimals, target, chosen)}
    )
    first, _, grid = _unit_grid(number)
    discrimination = _grim_discrimination(first, decimals, denominator, chosen)
    evidence: dict[str, Any] = {
        "mean": number.text,
        "n": n,
        "items": items,
        "denominator": denominator,
        "decimals": decimals,
        "conventions": _convention_names(chosen),
        "witness_totals": totals,
        "nearest_consistent": None,
        "grid": grid,
        "can_fail_only_when": "n * items < 10^decimals",
    }
    if totals:
        return NumericTest("grim", _holding_outcome(discrimination), discrimination, evidence)
    # The mean is unreachable, so below_total/denominator rounds strictly below it and
    # above_total/denominator strictly above it under every convention: the nearest
    # consistent printed values are the closest of those roundings.
    below = max(_scaled_round(below_total, denominator, decimals, convention) for convention in chosen)
    above = min(_scaled_round(above_total, denominator, decimals, convention) for convention in chosen)
    evidence["nearest_consistent"] = {"below": _scaled_text(below, decimals), "above": _scaled_text(above, decimals)}
    return NumericTest("grim", NumericOutcome.INCONSISTENT, discrimination, evidence)


def _totals_reproducing(
    number: PrintedNumber, denominator: int, conventions: frozenset[RoundingConvention]
) -> list[int] | None:
    """Every integer total whose mean over ``denominator`` prints as ``number``; None past the enumeration bound."""
    unit = 10**number.decimals
    low = (number.scaled - 1) * denominator // unit
    high = -(-(number.scaled + 1) * denominator // unit)
    if high - low + 1 > MAX_ENUMERATION:
        return None
    return [
        total
        for total in range(low, high + 1)
        if _reproduces(total, denominator, number.decimals, number.scaled, conventions)
    ]


# ---------------------------------------------------------------------------
# GRIMMER and DEBIT: can a standard deviation come from such data?
# ---------------------------------------------------------------------------


def _variance_bounds(interval: RoundingInterval, scale: int) -> tuple[Fraction, Fraction, bool, bool]:
    """Bounds on ``(scale * sd)**2`` for an SD in ``interval``. An SD is never negative."""
    low, low_inclusive = interval.low, interval.low_inclusive
    if low < 0:
        low, low_inclusive = Fraction(0), True
    return (scale * low) ** 2, (scale * interval.high) ** 2, low_inclusive, interval.high_inclusive


def _sum_of_squares_witness(total: int, n: int, bounds: tuple[Fraction, Fraction, bool, bool]) -> int | None:
    """An integer sum of squares for ``n`` integers summing to ``total`` whose sample variance is within ``bounds``.

    ``Q = (n - 1) * variance + total**2 / n``. Q must be an integer, must
    have the parity of ``total`` (because x**2 and x share parity), and
    cannot be below the minimum for that total (values as equal as possible).
    """
    variance_low, variance_high, low_inclusive, high_inclusive = bounds
    shift = Fraction(total * total, n)
    low, high = (n - 1) * variance_low + shift, (n - 1) * variance_high + shift
    base, remainder = divmod(total, n)
    minimum = (n - remainder) * base * base + remainder * (base + 1) ** 2
    candidate = -(-low.numerator // low.denominator)
    if not low_inclusive and candidate == low:
        candidate += 1
    candidate = max(candidate, minimum)
    if (candidate - total) % 2:
        candidate += 1
    if candidate < high or (high_inclusive and candidate == high):
        return candidate
    return None


def _sd_grid_discrimination(
    sd: PrintedNumber,
    conventions: frozenset[RoundingConvention],
    admits: Callable[[RoundingInterval], bool],
    candidates: int,
) -> tuple[Ratio, str]:
    """Reject count over the unit grid of SD values; ``admits(interval)`` says whether an SD interval fits."""
    first, points, grid = _unit_grid(sd)
    if points > MAX_GRID_POINTS or points * max(candidates, 1) > MAX_ENUMERATION:
        return _UNAVAILABLE, grid
    rejected = sum(
        1 for scaled in range(first, first + points) if not admits(_preimage_of(scaled, sd.decimals, conventions))
    )
    return Ratio(rejected, points), grid


def grimmer(
    mean: str, sd: str, n: int, *, items: int = 1, conventions: Iterable[RoundingConvention] = EITHER_HALF
) -> NumericTest:
    """GRIMMER: can integer data of size ``n`` have both the printed mean and the printed (sample) SD?

    The mean must pass GRIM, and for some consistent total there must be an
    integer sum of squares with the total's parity that puts the sample
    variance inside the SD's preimage. Discrimination is scored on the unit
    grid of SD values at the SD's printed decimals, with the mean as printed.
    FLOAT_FIRST is refused: an SD preimage must be exact.
    """
    mean_number, sd_number = printed_number(mean, "mean"), printed_number(sd, "sd")
    if sd_number.value < 0:
        raise ValueError("sd must not be negative")
    _count(n, "n", 2)
    _count(items, "items", 1)
    chosen = _conventions(conventions, exact_only=True)
    totals = _totals_reproducing(mean_number, n * items, chosen)
    evidence: dict[str, Any] = {
        "mean": mean_number.text,
        "sd": sd_number.text,
        "n": n,
        "items": items,
        "conventions": _convention_names(chosen),
        "mean_consistent": None if totals is None else bool(totals),
        "consistent_totals": None if totals is None else len(totals),
        "witness": None,
    }
    if totals is None:
        evidence["grid"] = "not evaluated: the mean admits too many totals to enumerate"
        return NumericTest("grimmer", NumericOutcome.NOT_TESTABLE, _UNAVAILABLE, evidence)

    def witness(interval: RoundingInterval) -> tuple[int, int] | None:
        bounds = _variance_bounds(interval, items)
        for total in totals:
            squares = _sum_of_squares_witness(total, n, bounds)
            if squares is not None:
                return total, squares
        return None

    found = witness(_preimage_of(sd_number.scaled, sd_number.decimals, chosen))
    discrimination, evidence["grid"] = _sd_grid_discrimination(
        sd_number, chosen, lambda interval: witness(interval) is not None, len(totals)
    )
    if found is None:
        return NumericTest("grimmer", NumericOutcome.INCONSISTENT, discrimination, evidence)
    evidence["witness"] = {"total": found[0], "sum_of_squares": found[1]}
    return NumericTest("grimmer", _holding_outcome(discrimination), discrimination, evidence)


def debit(proportion: str, sd: str, n: int, *, conventions: Iterable[RoundingConvention] = EITHER_HALF) -> NumericTest:
    """DEBIT: for binary data the SD is fixed by the proportion and ``n``.

    With ``k`` ones among ``n`` values the sample variance is
    ``k * (n - k) / (n * (n - 1))``. The test asks whether some ``k`` that
    reproduces the printed proportion also reproduces the printed SD.
    Discrimination is scored on the unit grid of SD values.
    """
    share, sd_number = printed_number(proportion, "proportion"), printed_number(sd, "sd")
    if sd_number.value < 0:
        raise ValueError("sd must not be negative")
    _count(n, "n", 2)
    chosen = _conventions(conventions, exact_only=True)
    counts = _totals_reproducing(share, n, chosen)
    evidence: dict[str, Any] = {
        "proportion": share.text,
        "sd": sd_number.text,
        "n": n,
        "conventions": _convention_names(chosen),
        "proportion_consistent": None,
        "consistent_counts": None,
        "witness": None,
    }
    if counts is None:
        evidence["grid"] = "not evaluated: the proportion admits too many counts to enumerate"
        return NumericTest("debit", NumericOutcome.NOT_TESTABLE, _UNAVAILABLE, evidence)
    counts = [count for count in counts if 0 <= count <= n]
    evidence.update(proportion_consistent=bool(counts), consistent_counts=len(counts))
    variances = {count: Fraction(count * (n - count), n * (n - 1)) for count in counts}

    def witness(interval: RoundingInterval) -> int | None:
        low, high, low_inclusive, high_inclusive = _variance_bounds(interval, 1)
        for count, variance in variances.items():
            if (variance > low or (low_inclusive and variance == low)) and (
                variance < high or (high_inclusive and variance == high)
            ):
                return count
        return None

    found = witness(_preimage_of(sd_number.scaled, sd_number.decimals, chosen))
    discrimination, evidence["grid"] = _sd_grid_discrimination(
        sd_number, chosen, lambda interval: witness(interval) is not None, len(counts)
    )
    if found is None:
        return NumericTest("debit", NumericOutcome.INCONSISTENT, discrimination, evidence)
    evidence["witness"] = {"ones": found, "variance": _exact_text(variances[found])}
    return NumericTest("debit", _holding_outcome(discrimination), discrimination, evidence)


# ---------------------------------------------------------------------------
# Classifier metrics
# ---------------------------------------------------------------------------


def _metric_value(name: str, tp: int, tn: int, positives: int, negatives: int) -> Fraction | None:
    """The exact value of a metric for one confusion matrix, or None where it is undefined (0/0)."""
    fp, fn = negatives - tn, positives - tp
    numerator, denominator = {
        "sensitivity": (tp, positives),
        "specificity": (tn, negatives),
        "precision": (tp, tp + fp),
        "npv": (tn, tn + fn),
        "accuracy": (tp + tn, positives + negatives),
        "f1": (2 * tp, 2 * tp + fp + fn),
        "balanced_accuracy": (tp * negatives + tn * positives, 2 * positives * negatives),
    }[name]
    return Fraction(numerator, denominator) if denominator else None


def metric_feasibility(
    metrics: Mapping[str, str], *, p: int, n: int, conventions: Iterable[RoundingConvention] = EITHER_HALF
) -> NumericTest:
    """Could any confusion matrix with ``p`` positives and ``n`` negatives produce every reported metric?

    Every pair (tp, tn) is enumerated and each metric is rounded exactly at
    its printed decimals. ``n_valid_tptn_pairs`` counts the matrices that
    reproduce all of them; zero means the stated protocol is impossible.
    Discrimination uses a one-at-a-time grid: each metric in turn takes every
    value in [0, 1] at its printed decimals while the others stay as
    reported, and the grid points no matrix can produce are rejected.
    """
    if not isinstance(metrics, Mapping) or not metrics:
        raise ValueError("metrics must map at least one metric name to its printed value")
    unknown = sorted(set(metrics) - set(METRICS))
    if unknown:
        raise ValueError(f"unknown metric(s) {unknown}; known: {list(METRICS)}")
    _count(p, "p", 0)
    _count(n, "n", 0)
    if p + n == 0:
        raise ValueError("p + n must be at least 1")
    chosen = _conventions(conventions)
    names = sorted(metrics)
    reported = {name: printed_number(metrics[name], name) for name in names}
    evidence: dict[str, Any] = {
        "p": p,
        "n": n,
        "metrics": {name: reported[name].text for name in names},
        "conventions": _convention_names(chosen),
        "n_valid_tptn_pairs": None,
        "valid_pairs": [],
    }
    pairs = (p + 1) * (n + 1)
    grid_points = {name: 10 ** reported[name].decimals + 1 for name in names}
    if pairs * len(names) > MAX_ENUMERATION or sum(grid_points.values()) > MAX_GRID_POINTS:
        evidence["grid"] = "not evaluated: too many confusion matrices to enumerate"
        return NumericTest("metric_feasibility", NumericOutcome.NOT_TESTABLE, _UNAVAILABLE, evidence)

    feasible: dict[str, set[int]] = {name: set() for name in names}
    valid: list[dict[str, int]] = []
    for tp in range(p + 1):
        for tn in range(n + 1):
            printed: dict[str, set[int]] = {}
            for name in names:
                value = _metric_value(name, tp, tn, p, n)
                printed[name] = (
                    set()
                    if value is None
                    else {
                        _scaled_round(value.numerator, value.denominator, reported[name].decimals, convention)
                        for convention in chosen
                    }
                )
            misses = [name for name in names if reported[name].scaled not in printed[name]]
            if not misses:
                valid.append({"tp": tp, "tn": tn})
            # A matrix that reproduces every *other* metric shows a value this metric could
            # take: all metrics when it misses none, only the missed one when it misses one.
            informative = names if not misses else misses if len(misses) == 1 else []
            for name in informative:
                feasible[name].update(scaled for scaled in printed[name] if 0 <= scaled < grid_points[name])
    rejected = sum(grid_points[name] - len(feasible[name]) for name in names)
    discrimination = Ratio(rejected, sum(grid_points.values()))
    evidence.update(
        n_valid_tptn_pairs=len(valid),
        valid_pairs=valid[:MAX_LISTED_WITNESSES],
        grid=(
            "one metric at a time takes every value in [0, 1] at its printed decimals while the others stay "
            "as reported"
        ),
        grid_per_metric={
            name: {"points": grid_points[name], "feasible": len(feasible[name])} for name in names
        },
    )
    if not valid:
        return NumericTest("metric_feasibility", NumericOutcome.INCONSISTENT, discrimination, evidence)
    return NumericTest("metric_feasibility", _holding_outcome(discrimination), discrimination, evidence)


# ---------------------------------------------------------------------------
# Derived quantities
# ---------------------------------------------------------------------------


def apply_formula(formula: str, operands: Sequence[Fraction]) -> Fraction | None:
    """Evaluate a registered derivation exactly over two ordered operands; None where it is undefined.

    ``difference`` is a - b, ``ratio`` a / b, ``percent`` 100 * a / b, and
    ``f1`` the harmonic mean 2ab / (a + b) of precision a and recall b.
    """
    if formula not in FORMULAS:
        raise ValueError(f"unknown formula {formula!r}; known: {list(FORMULAS)}")
    if len(operands) != 2:
        raise ValueError(f"{formula} takes exactly two operands, got {len(operands)}")
    first, second = (Fraction(item) for item in operands)
    if formula == "difference":
        return first - second
    if formula == "f1":
        return 2 * first * second / (first + second) if first + second else None
    if second == 0:
        return None
    return first / second * (100 if formula == "percent" else 1)


def derived_interval(
    formula: str, operands: Mapping[str, str], *, conventions: Iterable[RoundingConvention] = EITHER_HALF
) -> RoundingInterval:
    """The guaranteed range of ``formula`` over operands known only as printed (rounded) values.

    ``operands`` maps names to printed values in derivation order (first,
    second). Each operand stands for its whole preimage, so the result is
    the range of the formula over the box of preimages. Every formula here
    is monotone in each operand on the admitted boxes, so the range is
    spanned by the four corners. A ratio whose denominator could be zero,
    or an F1 whose operands could be zero or negative, has no bounded range
    and is refused.
    """
    if not isinstance(operands, Mapping) or len(operands) != 2:
        raise ValueError("derived_interval takes exactly two named operands")
    chosen = _conventions(conventions, exact_only=True)
    first, second = (preimage(text, conventions=chosen) for text in operands.values())
    if formula in ("ratio", "percent") and second.low <= 0 <= second.high:
        raise ValueError(f"the denominator interval {second.notation} contains zero")
    if formula == "f1" and (first.low <= 0 or second.low <= 0):
        raise ValueError("f1 needs precision and recall whose preimages are strictly positive")
    corners = []
    for a, a_inclusive in ((first.low, first.low_inclusive), (first.high, first.high_inclusive)):
        for b, b_inclusive in ((second.low, second.low_inclusive), (second.high, second.high_inclusive)):
            value = apply_formula(formula, (a, b))
            if value is None:
                raise ValueError(f"{formula} is undefined at an operand bound")
            corners.append((value, a_inclusive and b_inclusive))
    low = min(value for value, _ in corners)
    high = max(value for value, _ in corners)
    return RoundingInterval(
        low,
        high,
        any(inclusive for value, inclusive in corners if value == low),
        any(inclusive for value, inclusive in corners if value == high),
        chosen,
    )


# ---------------------------------------------------------------------------
# Tolerance comparisons
# ---------------------------------------------------------------------------


def _non_negative(text: str, name: str) -> Fraction:
    number = printed_number(text, name)
    if number.value < 0:
        raise ValueError(f"{name} must not be negative")
    return number.fraction


def compare_with_tolerance(
    expected: str, observed: str, *, relative: str = "0", absolute: str = "0"
) -> NumericTest:
    """Does ``observed`` lie within ``max(relative * |expected|, absolute)`` of ``expected``?

    The band is recorded. A band wider than ``|expected|`` reaches past zero,
    so the comparison could not tell the value from nothing: such a pass is
    VACUOUSLY_CONSISTENT. Discrimination probes ``observed`` moved by k units
    of its last printed digit (k = -10..10) and counts the probes the band
    rejects; when none is rejected the comparison is NOT_TESTABLE at this
    precision.
    """
    want, got = printed_number(expected, "expected"), printed_number(observed, "observed")
    relative_tolerance, absolute_tolerance = _non_negative(relative, "relative"), _non_negative(absolute, "absolute")
    centre = want.fraction
    band = max(relative_tolerance * abs(centre), absolute_tolerance)
    difference = abs(got.fraction - centre)
    unit = Fraction(1, 10**got.decimals)
    probes = [got.fraction + step * unit for step in range(-TOLERANCE_GRID_STEPS, TOLERANCE_GRID_STEPS + 1)]
    discrimination = Ratio(sum(1 for probe in probes if abs(probe - centre) > band), len(probes))
    wider = band > abs(centre)
    evidence = {
        "expected": want.text,
        "observed": got.text,
        "relative": relative,
        "absolute": absolute,
        "band": _exact_text(band),
        "difference": _exact_text(difference),
        "band_exceeds_expected": wider,
        "grid": f"observed +/- k x 10^-{got.decimals} for k = -{TOLERANCE_GRID_STEPS}..{TOLERANCE_GRID_STEPS}",
    }
    if difference > band:
        outcome = NumericOutcome.INCONSISTENT
    elif wider:
        outcome = NumericOutcome.VACUOUSLY_CONSISTENT
    else:
        outcome = _holding_outcome(discrimination)
    return NumericTest("compare_with_tolerance", outcome, discrimination, evidence)


# ---------------------------------------------------------------------------
# Tie-rule fingerprints (#7)
# ---------------------------------------------------------------------------


def rounding_fingerprint(stored: str, printed: str) -> frozenset[RoundingConvention]:
    """The conventions that turn ``stored`` into ``printed`` at ``printed``'s decimals.

    A number reproduced only by a convention the toolchain does not use was
    rounded somewhere else, typically retyped by hand: stored 0.125 printed
    as 0.13 is HALF_UP or CEILING, never HALF_EVEN.
    """
    source, target = printed_number(stored, "stored"), printed_number(printed, "printed")
    fraction = source.fraction
    return frozenset(
        convention
        for convention in RoundingConvention
        if _scaled_round(fraction.numerator, fraction.denominator, target.decimals, convention) == target.scaled
    )


# ---------------------------------------------------------------------------
# Candidate readings of a manuscript token (#17)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Reading:
    """One way to read a printed token, and every (thousands, decimal_point) pairing that gives it.

    ``declared`` is true only for the reading under the separators the
    manuscript declared. Readings found under other pairings are candidates
    to name, never values to use.
    """

    value: Decimal
    decimals: int
    declared: bool
    marks: tuple[tuple[str | None, str], ...]

    @property
    def plain(self) -> str:
        """The value as a plain printed number with its decimals (``.`` mark, no grouping)."""
        return format(self.value, "f")

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.plain,
            "decimals": self.decimals,
            "declared": self.declared,
            "marks": [{"thousands": thousands, "decimal_point": point} for thousands, point in self.marks],
        }


def _plausible_grouping(text: str, thousands: str) -> bool:
    """Digit grouping never starts with a zero group: "0,031" is not thirty-one."""
    leading = text.lstrip("+-−").split(thousands, 1)[0]
    return not leading.startswith("0")


def candidate_readings(text: str, *, thousands: str | None = None, decimal_point: str = ".") -> tuple[Reading, ...]:
    """Every distinct value ``text`` can mean.

    When the declared separators read the token, that is its only reading:
    a declaration exists precisely to settle the ambiguity. Otherwise every
    pairing of a grouping mark (or none) with a decimal mark is tried, and
    the distinct results are returned sorted. None means the token is not a
    number under any convention; two or more mean it is ambiguous; one
    undeclared reading names the locale the token was written in.
    """
    declared = parse_decimal(text, thousands=thousands, decimal_point=decimal_point)
    if declared.ok:
        return (Reading(declared.value, declared.decimals, True, ((thousands, decimal_point),)),)
    found: dict[tuple[Decimal, int], list[tuple[str | None, str]]] = {}
    for point in DECIMAL_MARKS:
        for grouping in (None, *GROUPING_MARKS):
            if grouping is not None and (
                grouping == point or grouping not in text or not _plausible_grouping(text, grouping)
            ):
                continue
            parsed = parse_decimal(text, thousands=grouping, decimal_point=point)
            if parsed.ok:
                found.setdefault((parsed.value, parsed.decimals), []).append((grouping, point))
    return tuple(
        Reading(value, decimals, False, tuple(marks)) for (value, decimals), marks in sorted(found.items())
    )
