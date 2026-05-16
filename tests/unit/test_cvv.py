"""Unit tests for ``binchecker.core.cvv``.

Validates Requirements 2.4, 2.7.

These tests cover the AMEX vs non-AMEX length distinction called out in
design task 2.9, plus the rejection paths for non-digit, missing, and
empty values, and the UNKNOWN-brand fallback to a 3-digit CVV.
"""

from __future__ import annotations

import pytest

from binchecker.core.cvv import validate_cvv
from binchecker.core.models import CardBrand


# ---------------------------------------------------------------------------
# 3-digit and 4-digit happy paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "brand",
    [
        CardBrand.VISA,
        CardBrand.MASTERCARD,
        CardBrand.DISCOVER,
        CardBrand.JCB,
    ],
)
def test_validate_cvv_three_digit_brands_accept_three_digit_cvv(
    brand: CardBrand,
) -> None:
    """Visa / MasterCard / Discover / JCB accept a 3-digit CVV2/CVC2."""
    result = validate_cvv(brand, "123")

    assert result.valid is True
    assert result.expected_length == 3
    assert result.actual_length == 3
    assert result.reason == ""


@pytest.mark.unit
def test_validate_cvv_amex_accepts_four_digit_cid() -> None:
    """AMEX accepts a 4-digit CID printed on the front of the card."""
    result = validate_cvv(CardBrand.AMEX, "1234")

    assert result.valid is True
    assert result.expected_length == 4
    assert result.actual_length == 4
    assert result.reason == ""


# ---------------------------------------------------------------------------
# Wrong-length rejection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_cvv_amex_rejects_three_digit_cvv() -> None:
    """AMEX requires 4 digits; a 3-digit value is invalid."""
    result = validate_cvv(CardBrand.AMEX, "123")

    assert result.valid is False
    assert result.expected_length == 4
    assert result.actual_length == 3


@pytest.mark.unit
def test_validate_cvv_visa_rejects_four_digit_cvv() -> None:
    """Visa requires 3 digits; a 4-digit value is invalid."""
    result = validate_cvv(CardBrand.VISA, "1234")

    assert result.valid is False
    assert result.expected_length == 3
    assert result.actual_length == 4


# ---------------------------------------------------------------------------
# Non-digit rejection
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("bad_cvv", ["abc", "12a"])
def test_validate_cvv_rejects_non_digit_characters(bad_cvv: str) -> None:
    """Any non-ASCII-digit character must cause rejection."""
    result = validate_cvv(CardBrand.VISA, bad_cvv)

    assert result.valid is False
    assert result.expected_length == 3


# ---------------------------------------------------------------------------
# Missing / empty input
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_cvv_rejects_none() -> None:
    """``None`` is not a valid CVV; actual_length is reported as 0."""
    result = validate_cvv(CardBrand.VISA, None)  # type: ignore[arg-type]

    assert result.valid is False
    assert result.expected_length == 3
    assert result.actual_length == 0


@pytest.mark.unit
def test_validate_cvv_rejects_empty_string() -> None:
    """Empty string is not a valid CVV."""
    result = validate_cvv(CardBrand.VISA, "")

    assert result.valid is False
    assert result.expected_length == 3
    assert result.actual_length == 0


# ---------------------------------------------------------------------------
# UNKNOWN brand fallback
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_cvv_unknown_brand_defaults_to_three_digits() -> None:
    """An UNKNOWN brand falls back to the 3-digit non-AMEX expectation."""
    result = validate_cvv(CardBrand.UNKNOWN, "123")

    assert result.valid is True
    assert result.expected_length == 3
    assert result.actual_length == 3
    assert result.reason == ""
