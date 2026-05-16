"""PAN normalization, masking, and BIN extraction utilities.

This module provides pure, deterministic, side-effect-free helpers for working
with Primary Account Numbers (PANs):

- :func:`normalize_pan` strips non-digit characters from raw input.
- :func:`mask_pan` redacts a PAN, exposing only the first-6 and last-4 digits
  for PANs of length >= 10, and fully masking shorter strings (so no inner
  digit is ever exposed).
- :func:`bin_of` returns the leading BIN/IIN portion of a PAN.

These functions are intentionally dependency-free (stdlib only) and contain no
I/O. They underpin Property 3 (PAN masking exposes only first-6 and last-4)
defined in the project design document and validate Requirements 8.1 and 8.4.
"""

from __future__ import annotations

__all__ = ["normalize_pan", "mask_pan", "bin_of"]


def normalize_pan(raw: str) -> str:
    """Strip every non-digit character from ``raw`` and return the result.

    Empty input, or input containing no digits, returns the empty string.

    Args:
        raw: Arbitrary user-supplied string that may contain digits mixed
            with separators (spaces, dashes, etc.).

    Returns:
        A string consisting solely of the decimal digits found in ``raw``,
        in their original order. Returns ``""`` if ``raw`` has no digits.
    """
    if not raw:
        return ""
    return "".join(ch for ch in raw if ch.isascii() and ch.isdigit())


def mask_pan(pan: str) -> str:
    """Redact a PAN, exposing only the first-6 and last-4 digits.

    Implements Property 3: for any PAN ``p`` with ``len(p) >= 10``,
    ``mask_pan(p)`` returns a string of equal length where:

    - the first 6 characters equal ``p[:6]``,
    - the last 4 characters equal ``p[-4:]``, and
    - every character in between equals ``'*'``.

    For PANs of length < 10, the entire string is replaced with asterisks so
    that no inner digit is ever exposed.

    Args:
        pan: A normalized PAN (digits only) or any string. The function does
            not validate that the input is purely numeric; it operates on the
            characters as given.

    Returns:
        The masked representation of ``pan``. Length is always preserved.
    """
    n = len(pan)
    if n >= 10:
        return pan[:6] + "*" * (n - 10) + pan[-4:]
    return "*" * n


def bin_of(pan: str, length: int = 6) -> str:
    """Return the leading BIN/IIN portion of ``pan``.

    Args:
        pan: A normalized PAN (digits only) or any string. The function does
            not validate that the input is purely numeric; it returns the
            leading characters as-is.
        length: Number of leading characters to return. Must be in the
            inclusive range ``[1, 8]``.

    Returns:
        ``pan[:length]`` when ``len(pan) >= length``; otherwise the entire
        ``pan`` string is returned unchanged.

    Raises:
        ValueError: If ``length`` is outside the inclusive range ``[1, 8]``.
    """
    if not 1 <= length <= 8:
        raise ValueError(
            f"length must be in [1, 8], got {length!r}"
        )
    if len(pan) < length:
        return pan
    return pan[:length]
