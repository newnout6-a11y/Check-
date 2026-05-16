"""Card Verification Value (CVV/CVC/CID) format validation.

This module provides pure helpers for validating the *format* of a card
verification value supplied alongside a PAN. It deliberately performs
only structural checks:

- AMEX cards use a 4-digit CID printed on the front of the card.
- All other major networks (Visa, MasterCard, Discover, JCB, Diners,
  UnionPay, Maestro, etc.) use a 3-digit CVV2/CVC2 printed on the back.
- Unknown / unrecognized brands fall back to a 3-digit expectation,
  which is the most common case in practice.

This module does not, and cannot, verify whether a CVV is *correct* —
that requires a live authorization through the issuing bank. It only
ensures the value the user supplied has the right shape so we can fail
fast before making a network call.

These helpers underpin Property 4 ("Pipeline ordered short-circuit") in
the project design document and validate Requirements 2.4 and 2.7. They
use only the Python standard library and perform no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from binchecker.core.models import CardBrand

__all__ = ["CvvValidation", "validate_cvv"]


# AMEX uses a 4-digit Card Identification Number (CID); every other
# supported brand uses a 3-digit CVV2/CVC2.
_AMEX_CVV_LENGTH = 4
_DEFAULT_CVV_LENGTH = 3


@dataclass(frozen=True, slots=True)
class CvvValidation:
    """Result of a CVV format check.

    Attributes:
        valid: ``True`` iff the supplied value is a string of decimal
            digits with the expected length for the card's brand.
        expected_length: The number of digits the brand requires (3 or 4).
        actual_length: The length of the supplied value, or ``0`` when the
            input was ``None``.
        reason: Short, human-readable description of why validation
            failed. Empty string when ``valid`` is ``True``.
    """

    valid: bool
    expected_length: int
    actual_length: int
    reason: str = ""


def _expected_length_for(brand: CardBrand) -> int:
    """Return the expected CVV digit count for the given brand."""
    if brand is CardBrand.AMEX:
        return _AMEX_CVV_LENGTH
    return _DEFAULT_CVV_LENGTH


def validate_cvv(brand: CardBrand, cvv: str) -> CvvValidation:
    """Validate the *format* of ``cvv`` against the brand's expected length.

    The function is total: it returns a :class:`CvvValidation` for every
    input, including ``None`` and non-string values. It never raises for
    bad data, which lets callers fold the result into a structured
    pipeline failure rather than handling exceptions.

    Args:
        brand: The detected card brand. ``CardBrand.AMEX`` requires a
            4-digit CID; every other brand (including
            ``CardBrand.UNKNOWN``) requires a 3-digit CVV.
        cvv: The candidate CVV string. May be ``None`` or empty, in which
            case the result is invalid with ``actual_length`` reported as
            ``0``.

    Returns:
        A :class:`CvvValidation` describing whether the input matches the
        expected format, the expected and actual lengths, and a short
        ``reason`` when invalid.
    """
    expected = _expected_length_for(brand)

    if cvv is None:
        return CvvValidation(
            valid=False,
            expected_length=expected,
            actual_length=0,
            reason="cvv is missing",
        )

    if not isinstance(cvv, str):
        # Defensive: callers should pass strings, but if an int (or other
        # type) sneaks in we fail closed rather than coerce.
        return CvvValidation(
            valid=False,
            expected_length=expected,
            actual_length=0,
            reason=f"cvv must be a string, got {type(cvv).__name__}",
        )

    actual = len(cvv)

    if actual == 0:
        return CvvValidation(
            valid=False,
            expected_length=expected,
            actual_length=0,
            reason="cvv is empty",
        )

    # Reject anything that is not strictly an ASCII decimal digit. Using
    # str.isdigit() alone would accept characters like '²' or Eastern
    # Arabic digits which are not valid CVV characters on a payment card.
    for ch in cvv:
        if ch < "0" or ch > "9":
            return CvvValidation(
                valid=False,
                expected_length=expected,
                actual_length=actual,
                reason="cvv must contain only ASCII decimal digits",
            )

    if actual != expected:
        return CvvValidation(
            valid=False,
            expected_length=expected,
            actual_length=actual,
            reason=f"cvv must be {expected} digits for {brand.value}, got {actual}",
        )

    return CvvValidation(
        valid=True,
        expected_length=expected,
        actual_length=actual,
        reason="",
    )
