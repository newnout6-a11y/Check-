# Property 1: Luhn correctness
"""Property-based tests for ``binchecker.core.luhn``.

**Validates: Requirements 2.1**

The four properties below pin down the contract spelled out in the design
document for Property 1 ("Luhn correctness"):

1. ``test_luhn_check_digit_round_trip`` — appending the digit returned by
   :func:`luhn_compute_check_digit` to any digit body always produces a
   PAN that :func:`luhn_check` accepts.
2. ``test_luhn_check_rejects_off_by_one`` — every digit other than the
   computed check digit is rejected, so the check digit is unique.
3. ``test_luhn_check_total_on_arbitrary_strings`` — :func:`luhn_check` is
   total: it returns a ``bool`` for any unicode input and never raises.
4. ``test_luhn_check_definition`` — :func:`luhn_check` agrees with an
   independent re-implementation of the Luhn-weighted digit sum on
   arbitrary digit strings (the iff direction of Property 1).
"""

from __future__ import annotations

import pytest
from hypothesis import given, strategies as st

from binchecker.core.luhn import luhn_check, luhn_compute_check_digit
from tests.strategies import unicode_text_strategy

# A digit-only string strategy parameterised on length bounds. Constrained
# inside each test so the generators stay focused on their respective input
# spaces (1..18 for round-trip / off-by-one tests, 1..30 for the definition
# test).
_DIGITS = "0123456789"


def _independent_luhn_sum(digits: str) -> int:
    """Independent re-implementation of the Luhn-weighted digit sum.

    Walks ``digits`` left-to-right, doubling every digit whose 0-indexed
    distance from the rightmost position is odd (i.e. the 2nd, 4th, ...
    digit counting from the right). When a doubled value exceeds 9, the
    canonical Luhn algorithm subtracts 9, which is equivalent to summing
    its decimal digits.

    Implementation note: this routine intentionally diverges in style from
    :func:`binchecker.core.luhn._luhn_sum` (which iterates right-to-left
    via :func:`reversed`) so that test 4 catches off-by-one or
    direction-of-iteration regressions.
    """
    n = len(digits)
    total = 0
    for i, ch in enumerate(digits):
        d = int(ch)
        # Position from the right, 0-indexed. The rightmost digit (index
        # n - 1) has from_right == 0 and is NOT doubled.
        from_right = n - 1 - i
        if from_right % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total


@pytest.mark.property
@given(body=st.text(alphabet=_DIGITS, min_size=1, max_size=18))
def test_luhn_check_digit_round_trip(body: str) -> None:
    """``luhn_check(body + check_digit(body))`` is always ``True``.

    Validates: Requirements 2.1
    """
    check_digit = luhn_compute_check_digit(body)
    assert 0 <= check_digit <= 9
    assert luhn_check(body + str(check_digit)) is True


@pytest.mark.property
@given(body=st.text(alphabet=_DIGITS, min_size=1, max_size=18))
def test_luhn_check_rejects_off_by_one(body: str) -> None:
    """Every digit other than the canonical check digit is rejected.

    Validates: Requirements 2.1
    """
    correct = luhn_compute_check_digit(body)
    for d in range(10):
        if d == correct:
            continue
        assert luhn_check(body + str(d)) is False, (
            f"Expected luhn_check({body + str(d)!r}) to be False; "
            f"correct check digit is {correct}"
        )


@pytest.mark.property
@given(s=unicode_text_strategy())
def test_luhn_check_total_on_arbitrary_strings(s: str) -> None:
    """:func:`luhn_check` is total — returns a ``bool`` and never raises.

    Validates: Requirements 2.1
    """
    result = luhn_check(s)
    assert isinstance(result, bool)


@pytest.mark.property
@given(p=st.text(alphabet=_DIGITS, min_size=1, max_size=30))
def test_luhn_check_definition(p: str) -> None:
    """:func:`luhn_check` matches the independent definition (the iff of P1).

    For any digit string ``p``, ``luhn_check(p)`` must be ``True`` if and
    only if the Luhn-weighted digit sum of ``p`` is divisible by 10.

    Validates: Requirements 2.1
    """
    expected = (_independent_luhn_sum(p) % 10) == 0
    assert luhn_check(p) is expected
