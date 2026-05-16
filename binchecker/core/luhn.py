"""Luhn checksum utilities for Primary Account Numbers (PANs).

This module provides pure, deterministic, side-effect-free helpers implementing
the standard Luhn (ISO/IEC 7812-1) algorithm:

- :func:`luhn_check` returns whether a given digit-only string passes the Luhn
  checksum.
- :func:`luhn_compute_check_digit` returns the trailing check digit that, when
  appended to the supplied body, would make the resulting PAN pass
  :func:`luhn_check`.

These helpers underpin Property 1 ("Luhn correctness") defined in the project
design document and validate Requirement 2.1. They use only the Python
standard library and perform no I/O.
"""

from __future__ import annotations

__all__ = ["luhn_check", "luhn_compute_check_digit"]


def _luhn_sum(digits: str) -> int:
    """Compute the Luhn-weighted digit sum of ``digits``.

    Iterates ``digits`` right-to-left, doubles every second digit (starting
    from the rightmost), subtracts 9 from any doubled value greater than 9,
    and returns the running sum.

    Args:
        digits: A non-empty string of decimal digit characters. The caller is
            responsible for validating the input.

    Returns:
        The Luhn-weighted digit sum as a non-negative integer.
    """
    total = 0
    # Walk right-to-left; index 0 from the right is NOT doubled, index 1 is.
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48  # '0' is 48; faster and equivalent to int(ch) here
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total


def luhn_check(pan: str) -> bool:
    """Return ``True`` iff ``pan`` passes the Luhn checksum.

    Implements Property 1: for any string of digits ``d``, ``luhn_check(d)``
    returns ``True`` if and only if the Luhn-weighted sum of ``d``'s digits is
    divisible by 10.

    The function is total: it never raises. Empty strings, ``None``-like
    values, and strings containing any non-digit character return ``False``.

    Args:
        pan: An arbitrary string. Only ASCII decimal digit characters
            ``'0'``-``'9'`` are accepted; any other character (including
            spaces, dashes, or non-ASCII digits) makes the function return
            ``False``.

    Returns:
        ``True`` if ``pan`` is a non-empty string of ASCII digits whose
        Luhn-weighted digit sum is divisible by 10; ``False`` otherwise.
    """
    if not pan or not isinstance(pan, str):
        return False
    # Reject anything that is not strictly an ASCII decimal digit. Using
    # str.isdigit() alone would accept characters like '²' or Eastern Arabic
    # digits which are not valid PAN characters.
    for ch in pan:
        if ch < "0" or ch > "9":
            return False
    return _luhn_sum(pan) % 10 == 0


def luhn_compute_check_digit(pan_without_check: str) -> int:
    """Return the Luhn check digit for the supplied PAN body.

    Given ``pan_without_check`` representing a PAN minus its trailing check
    digit, return the single digit ``c`` (in ``[0, 9]``) such that
    ``luhn_check(pan_without_check + str(c))`` would be ``True``.

    Args:
        pan_without_check: A non-empty string of ASCII decimal digits
            representing the PAN body (everything except the trailing check
            digit).

    Returns:
        The Luhn check digit as an integer in the inclusive range ``[0, 9]``.

    Raises:
        ValueError: If ``pan_without_check`` is empty or contains any
            character outside ``'0'``-``'9'``.
    """
    if not pan_without_check or not isinstance(pan_without_check, str):
        raise ValueError("pan_without_check must be a non-empty string of digits")
    for ch in pan_without_check:
        if ch < "0" or ch > "9":
            raise ValueError(
                "pan_without_check must contain only ASCII decimal digits"
            )
    # When the check digit is appended, its position from the right is 0
    # (i.e. NOT doubled). That means every digit in the body shifts one
    # position to the left, so the body's rightmost digit becomes the
    # "doubled" position. _luhn_sum treats index 0 (rightmost) as undoubled,
    # so we must compute the sum as if the body were already shifted left by
    # one position. We do that by appending a placeholder '0' (which adds 0
    # to the sum) before calling _luhn_sum.
    body_sum = _luhn_sum(pan_without_check + "0")
    return (10 - (body_sum % 10)) % 10
