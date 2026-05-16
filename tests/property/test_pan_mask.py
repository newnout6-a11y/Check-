# Property 3: PAN masking exposes only first-6 and last-4
"""Property-based tests for ``binchecker.core.pan.mask_pan``.

**Validates: Requirements 8.1, 8.4**

The four properties below pin down the contract spelled out in the design
document for Property 3 ("PAN masking exposes only first-6 and last-4"):

1. ``test_mask_pan_preserves_length`` — for any digit string ``p`` of length
   1..30, ``len(mask_pan(p)) == len(p)``. Length is invariant so downstream
   formatting / column widths cannot leak the original length difference.
2. ``test_mask_pan_long_pan_invariant`` — for any digit string ``p`` of
   length ≥ 10, ``mask_pan(p) == p[:6] + "*" * (len(p) - 10) + p[-4:]``.
   Only the first-6 and last-4 digits are ever exposed.
3. ``test_mask_pan_short_pan_fully_masked`` — for any digit string ``p`` of
   length 0..9, ``mask_pan(p) == "*" * len(p)``. Short inputs are never
   partially exposed (no first-6, no last-4).
4. ``test_mask_pan_no_inner_digit_for_short_inputs`` — strengthens (3) by
   asserting that for any short PAN the result contains no decimal digit
   anywhere, so no inner digit is ever surfaced even incidentally.
"""

from __future__ import annotations

import pytest
from hypothesis import given, strategies as st

from binchecker.core.pan import mask_pan

# Digit-only alphabet used by every property in this module. ``mask_pan``
# itself does not require pure-digit input (it operates character-wise), but
# the contract under test is stated in terms of digit strings, so the
# strategies stay inside that input space.
_DIGITS = "0123456789"


@pytest.mark.property
@given(p=st.text(alphabet=_DIGITS, min_size=1, max_size=30))
def test_mask_pan_preserves_length(p: str) -> None:
    """``len(mask_pan(p)) == len(p)`` for any digit string of length 1..30.

    Validates: Requirements 8.1, 8.4
    """
    assert len(mask_pan(p)) == len(p)


@pytest.mark.property
@given(p=st.text(alphabet=_DIGITS, min_size=10, max_size=30))
def test_mask_pan_long_pan_invariant(p: str) -> None:
    """For length ≥ 10, ``mask_pan(p) == p[:6] + '*' * (len(p) - 10) + p[-4:]``.

    Validates: Requirements 8.1, 8.4
    """
    expected = p[:6] + "*" * (len(p) - 10) + p[-4:]
    assert mask_pan(p) == expected


@pytest.mark.property
@given(p=st.text(alphabet=_DIGITS, min_size=0, max_size=9))
def test_mask_pan_short_pan_fully_masked(p: str) -> None:
    """For length 0..9, ``mask_pan(p) == '*' * len(p)``.

    Validates: Requirements 8.1, 8.4
    """
    assert mask_pan(p) == "*" * len(p)


@pytest.mark.property
@given(p=st.text(alphabet=_DIGITS, min_size=0, max_size=9))
def test_mask_pan_no_inner_digit_for_short_inputs(p: str) -> None:
    """For short PANs no character of the result is a decimal digit.

    Validates: Requirements 8.1, 8.4
    """
    masked = mask_pan(p)
    assert not any(ch.isdigit() for ch in masked), (
        f"short PAN leaked a digit through mask_pan: "
        f"input={p!r}, masked={masked!r}"
    )
