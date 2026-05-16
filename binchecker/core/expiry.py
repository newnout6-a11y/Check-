"""Card expiry-date utilities.

This module provides pure helpers for normalizing and comparing card
expiry dates:

- :func:`normalize_expiry` coerces ``(month, year)`` pairs (in either int
  or string form, with 2- or 4-digit years) into a canonical
  ``(int_month, int_4digit_year)`` tuple.
- :func:`is_expired` returns whether a card with the given normalized
  expiry has passed its end-of-month expiry boundary.

Per ISO/IEC 7813 and standard card-network rules, a card is considered
valid through the *last day* of its printed expiry month and becomes
expired on the first day of the following month.

These helpers underpin Property 4 ("Pipeline ordered short-circuit") in
the project design document and validate Requirements 2.4 and 2.7. They
use only the Python standard library and perform no I/O.
"""

from __future__ import annotations

from calendar import monthrange
from datetime import date

__all__ = ["normalize_expiry", "is_expired"]


# Sliding-window pivot used to disambiguate 2-digit years. Two-digit years
# less than or equal to ``today.year % 100 + _PIVOT_OFFSET`` map to the
# 2000s; anything strictly greater maps to the 1900s. A 50-year window is
# the de-facto industry default for payment cards.
_PIVOT_OFFSET = 50


def _coerce_int(value: int | str, *, name: str) -> int:
    """Return ``value`` as an ``int`` or raise ``ValueError``.

    Accepts existing ``int`` values verbatim and strings that parse cleanly
    via :class:`int`. Booleans are explicitly rejected because in Python
    ``bool`` is a subclass of ``int`` and silently coercing ``True`` to
    ``1`` would mask caller bugs.
    """
    if isinstance(value, bool):  # bool is an int subclass; reject it.
        raise ValueError(f"{name} must be an int or digit string, got bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError(f"{name} must be a non-empty string")
        try:
            return int(stripped, 10)
        except ValueError as exc:
            raise ValueError(
                f"{name} must be a base-10 integer string, got {value!r}"
            ) from exc
    raise ValueError(
        f"{name} must be an int or digit string, got {type(value).__name__}"
    )


def normalize_expiry(
    month: int | str,
    year: int | str,
    *,
    today: date | None = None,
) -> tuple[int, int]:
    """Normalize ``(month, year)`` to ``(int_month, int_4digit_year)``.

    ``month`` and ``year`` may be supplied as ints or as digit strings
    (with optional surrounding whitespace and leading zeros, e.g. ``"07"``
    or ``" 2028 "``).

    Two-digit years are expanded using a sliding 50-year window anchored
    on ``today``: a 2-digit year ``yy`` such that
    ``yy <= today.year % 100 + 50`` maps to ``2000 + yy``; otherwise it
    maps to ``1900 + yy``. Four-digit years are returned unchanged.

    Args:
        month: The expiry month (must satisfy ``1 <= month <= 12``).
        year: The expiry year as either a 2-digit or 4-digit value.
        today: Reference date used for 2-digit-year disambiguation.
            Defaults to :func:`datetime.date.today`. Exposed primarily for
            deterministic testing.

    Returns:
        A ``(month, year)`` tuple where ``month`` is in ``[1, 12]`` and
        ``year`` is a 4-digit year.

    Raises:
        ValueError: If ``month`` is not in ``[1, 12]``, or if ``month`` /
            ``year`` cannot be parsed as integers, or if the resolved year
            is negative.
    """
    if today is None:
        today = date.today()

    month_int = _coerce_int(month, name="month")
    year_int = _coerce_int(year, name="year")

    if not 1 <= month_int <= 12:
        raise ValueError(f"month must be in 1..12, got {month_int}")

    if year_int < 0:
        raise ValueError(f"year must be non-negative, got {year_int}")

    if year_int < 100:
        # Two-digit year: expand via the sliding 50-year window.
        pivot = today.year % 100 + _PIVOT_OFFSET
        if year_int <= pivot:
            year_int = 2000 + year_int
        else:
            year_int = 1900 + year_int

    return month_int, year_int


def is_expired(
    month: int,
    year: int,
    *,
    today: date | None = None,
) -> bool:
    """Return ``True`` iff a card with expiry ``(month, year)`` is expired.

    A card "expires at end of month": it remains valid through the last
    calendar day of its expiry month and is considered expired starting
    the first day of the following month. Concretely, this returns
    ``today > last_day_of(month, year)``.

    Both ``month`` and ``year`` are expected to be already normalized
    (``month`` in ``[1, 12]``, ``year`` as a 4-digit year). Use
    :func:`normalize_expiry` first if your inputs may be 2-digit years or
    string-typed.

    Args:
        month: Expiry month, in ``[1, 12]``.
        year: Expiry year as a 4-digit integer.
        today: Reference date for the comparison. Defaults to
            :func:`datetime.date.today`. Exposed primarily for
            deterministic testing.

    Returns:
        ``True`` if ``today`` is strictly after the last day of the given
        expiry month/year; ``False`` otherwise.

    Raises:
        ValueError: If ``month`` is not in ``[1, 12]`` or ``year`` is
            negative.
    """
    if not 1 <= month <= 12:
        raise ValueError(f"month must be in 1..12, got {month}")
    if year < 0:
        raise ValueError(f"year must be non-negative, got {year}")

    if today is None:
        today = date.today()

    # monthrange returns (first_weekday, days_in_month). We only need the
    # day count so we can construct the last calendar day of the expiry
    # month.
    last_day = monthrange(year, month)[1]
    end_of_month = date(year, month, last_day)
    return today > end_of_month
