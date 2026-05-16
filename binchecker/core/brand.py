"""Card brand detection and brand-aware length validation.

This module exposes a static :data:`BRAND_RULES` table mapping each
:class:`~binchecker.core.models.CardBrand` to its IIN/BIN prefixes and
allowed PAN lengths. Two pure helpers are provided:

* :func:`detect_card_brand` — return the most specific brand whose
  prefix table matches the given PAN.
* :func:`valid_brand_length` — check whether a PAN's length is allowed
  for the given brand.

The detector is deterministic: rules are scanned in declared order, and
ties are broken by preferring the *longest* matching prefix. This means
``VISA_ELECTRON`` (which uses 4- to 6-digit prefixes starting with ``4``)
correctly wins over plain ``VISA`` (which only requires a leading
``4``) when the longer prefix matches.

Mastercard's modern 2-series (BINs 2221-2720) cannot be expressed as a
finite set of string prefixes without enumerating 500 entries, so the
table also encodes a small list of numeric range rules.

The module is part of the pure ``core`` layer: stdlib only, no I/O.
"""

from __future__ import annotations

from binchecker.core.models import CardBrand

__all__ = ["detect_card_brand", "valid_brand_length", "BRAND_RULES"]


# ---------------------------------------------------------------------------
# Brand rule table
# ---------------------------------------------------------------------------

#: Per-brand prefix and length rules. Each entry is a 3-tuple of
#: ``(brand, prefixes, lengths)`` where ``prefixes`` is a tuple of
#: leading digit strings the PAN must start with, and ``lengths`` is a
#: tuple of allowed PAN lengths.
#:
#: Order matters: rules earlier in the tuple are considered first when
#: ties on prefix length need to be broken. ``VISA_ELECTRON`` is listed
#: before ``VISA`` so that its longer (4- and 6-digit) prefixes win the
#: longest-match comparison cleanly.
BRAND_RULES: tuple[tuple[CardBrand, tuple[str, ...], tuple[int, ...]], ...] = (
    (
        CardBrand.VISA_ELECTRON,
        ("4026", "417500", "4508", "4844", "4913", "4917"),
        (16,),
    ),
    (
        CardBrand.VISA,
        ("4",),
        (13, 16, 19),
    ),
    (
        CardBrand.MASTERCARD,
        ("51", "52", "53", "54", "55"),
        (16,),
    ),
    (
        CardBrand.AMEX,
        ("34", "37"),
        (15,),
    ),
    (
        CardBrand.DISCOVER,
        ("6011", "65", "644", "645", "646", "647", "648", "649"),
        (16, 19),
    ),
    (
        CardBrand.JCB,
        ("3528", "3529", "353", "354", "355", "356", "357", "358"),
        (16, 19),
    ),
    (
        CardBrand.DINERS,
        ("300", "301", "302", "303", "304", "305", "36", "38", "39"),
        (14, 16, 19),
    ),
    (
        CardBrand.UNIONPAY,
        ("62",),
        (16, 17, 18, 19),
    ),
    (
        CardBrand.MAESTRO,
        ("50", "56", "57", "58", "6", "67"),
        (12, 13, 14, 15, 16, 17, 18, 19),
    ),
)


#: Numeric range rules for prefixes that span a contiguous integer block.
#: Each entry is ``(brand, start, end, prefix_length)`` meaning: if the
#: first ``prefix_length`` digits of the PAN, parsed as an integer, fall
#: within ``[start, end]`` (inclusive), the rule matches.
_RANGE_RULES: tuple[tuple[CardBrand, int, int, int], ...] = (
    # Mastercard 2-series: BINs 222100-272099 (i.e. 2221-2720 at 4 digits).
    (CardBrand.MASTERCARD, 2221, 2720, 4),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pan_starts_with_in_range(
    pan: str, start: int, end: int, prefix_length: int
) -> bool:
    """Return True if the leading ``prefix_length`` digits of ``pan``
    parse to an integer within ``[start, end]`` (inclusive).

    Returns False if the PAN is shorter than ``prefix_length`` or if the
    leading slice is not all digits.
    """
    if len(pan) < prefix_length:
        return False
    head = pan[:prefix_length]
    if not head.isdigit():
        return False
    value = int(head)
    return start <= value <= end


def _lengths_for_brand(brand: CardBrand) -> tuple[int, ...]:
    """Return the union of allowed lengths declared for ``brand``.

    A brand can in principle appear in both the prefix table and the
    range table (e.g. Mastercard); the allowed lengths are the union of
    every matching entry.
    """
    lengths: set[int] = set()
    for entry_brand, _prefixes, entry_lengths in BRAND_RULES:
        if entry_brand is brand:
            lengths.update(entry_lengths)
    return tuple(sorted(lengths))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_card_brand(pan: str) -> CardBrand:
    """Detect the card brand for ``pan`` using a longest-prefix match.

    Returns :attr:`CardBrand.UNKNOWN` for empty input, non-digit input,
    or PANs whose leading digits match no rule. When multiple rules
    match, the one with the *longest* prefix wins; ties are broken by
    declaration order in :data:`BRAND_RULES`, so ``VISA_ELECTRON``
    correctly takes precedence over ``VISA`` when its longer prefix
    matches.
    """
    if not pan or not pan.isdigit():
        return CardBrand.UNKNOWN

    best_brand: CardBrand = CardBrand.UNKNOWN
    best_match_length = -1

    # Scan static prefix rules first.
    for brand, prefixes, _lengths in BRAND_RULES:
        for prefix in prefixes:
            if pan.startswith(prefix) and len(prefix) > best_match_length:
                best_brand = brand
                best_match_length = len(prefix)

    # Scan numeric range rules; treat ``prefix_length`` as the match
    # length so they participate in the longest-match comparison.
    for brand, start, end, prefix_length in _RANGE_RULES:
        if (
            _pan_starts_with_in_range(pan, start, end, prefix_length)
            and prefix_length > best_match_length
        ):
            best_brand = brand
            best_match_length = prefix_length

    return best_brand


def valid_brand_length(pan: str, brand: CardBrand) -> bool:
    """Return True iff ``len(pan)`` is allowed for ``brand``.

    For :attr:`CardBrand.UNKNOWN`, any length in the broad payment-card
    range ``[12, 19]`` is accepted as a graceful default. Other brands
    use the union of lengths declared in :data:`BRAND_RULES`.
    """
    pan_length = len(pan)
    if brand is CardBrand.UNKNOWN:
        return 12 <= pan_length <= 19
    allowed = _lengths_for_brand(brand)
    return pan_length in allowed
