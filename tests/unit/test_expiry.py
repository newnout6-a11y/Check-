"""Unit tests for ``binchecker.core.expiry``.

Validates Requirements 2.4, 2.7.

These tests cover the boundary cases called out in design task 2.9:

* ``normalize_expiry`` correctly passes through 4-digit years, expands
  2-digit years on either side of the 50-year sliding pivot, accepts
  string inputs with leading zeros / surrounding whitespace, and rejects
  out-of-range months and unparseable year strings.
* ``is_expired`` treats the *last day* of the expiry month as still valid
  and the *first day* of the following month as expired, including the
  February 29 leap-year boundary.
"""

from __future__ import annotations

from datetime import date

import pytest

from binchecker.core.expiry import is_expired, normalize_expiry


# ---------------------------------------------------------------------------
# normalize_expiry
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_normalize_expiry_passes_through_four_digit_year() -> None:
    """A 4-digit year is returned unchanged regardless of pivot."""
    assert normalize_expiry(12, 2028, today=date(2025, 1, 1)) == (12, 2028)


@pytest.mark.unit
def test_normalize_expiry_two_digit_year_at_or_below_pivot_maps_to_2000s() -> None:
    """With today=2025, pivot = 25 + 50 = 75; 30 ≤ 75 → 2030."""
    assert normalize_expiry(7, "30", today=date(2025, 1, 1)) == (7, 2030)


@pytest.mark.unit
def test_normalize_expiry_two_digit_year_above_pivot_maps_to_1900s() -> None:
    """With today=2025, pivot = 75; 99 > 75 → 1999."""
    assert normalize_expiry(7, "99", today=date(2025, 1, 1)) == (7, 1999)


@pytest.mark.unit
def test_normalize_expiry_strips_whitespace_and_leading_zeros() -> None:
    """String inputs may have leading zeros and surrounding whitespace."""
    assert normalize_expiry("07", " 28 ", today=date(2025, 1, 1)) == (7, 2028)


@pytest.mark.unit
@pytest.mark.parametrize("bad_month", [0, 13])
def test_normalize_expiry_rejects_month_out_of_range(bad_month: int) -> None:
    """Months outside [1, 12] must raise ``ValueError``."""
    with pytest.raises(ValueError):
        normalize_expiry(bad_month, 2028, today=date(2025, 1, 1))


@pytest.mark.unit
def test_normalize_expiry_rejects_non_numeric_year_string() -> None:
    """A year string that does not parse as a base-10 int must raise."""
    with pytest.raises(ValueError):
        normalize_expiry(1, "abc", today=date(2025, 1, 1))


# ---------------------------------------------------------------------------
# is_expired
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_is_expired_future_month_is_not_expired() -> None:
    """A card whose expiry is far in the future is not expired."""
    assert is_expired(12, 2099, today=date(2025, 1, 1)) is False


@pytest.mark.unit
def test_is_expired_past_month_is_expired() -> None:
    """A card whose expiry month is fully in the past is expired."""
    assert is_expired(1, 2024, today=date(2025, 1, 1)) is True


@pytest.mark.unit
def test_is_expired_last_day_of_current_month_is_not_expired() -> None:
    """A card remains valid through the last calendar day of its expiry month."""
    assert is_expired(1, 2025, today=date(2025, 1, 31)) is False


@pytest.mark.unit
def test_is_expired_first_day_of_next_month_is_expired() -> None:
    """A card becomes expired on the first day of the following month."""
    assert is_expired(1, 2025, today=date(2025, 2, 1)) is True


@pytest.mark.unit
def test_is_expired_february_29_leap_year_is_not_expired() -> None:
    """On Feb 29 of a leap year, a Feb-expiry card is still valid."""
    assert is_expired(2, 2024, today=date(2024, 2, 29)) is False


@pytest.mark.unit
def test_is_expired_first_of_march_after_february_expiry_is_expired() -> None:
    """On March 1 a Feb-expiry card has expired (boundary across leap years)."""
    assert is_expired(2, 2024, today=date(2024, 3, 1)) is True
