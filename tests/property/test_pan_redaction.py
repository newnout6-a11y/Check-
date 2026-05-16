# Property 9: PAN redaction filter is universal
"""Property-based tests for ``binchecker.log.pan_filter.PanRedactionFilter``.

**Validates: Requirements 8.1, 8.4**

The four properties below pin down the contract spelled out in the design
document for Property 9 ("PAN redaction filter is universal"):

1. ``test_filter_redacts_luhn_valid_pan_anywhere`` - for any Luhn-valid PAN
   embedded between arbitrary unicode prefix/suffix text, the filter
   replaces the PAN with its :func:`~binchecker.core.pan.mask_pan` form.
   The resulting record message no longer contains the cleartext PAN.
2. ``test_filter_preserves_non_luhn_digit_runs`` - 12-19 digit runs that
   fail the Luhn check are left untouched (so random ids, timestamps, and
   non-card numerics are preserved verbatim).
3. ``test_filter_never_raises`` - the filter is total: it returns ``True``
   for any arbitrary ``msg`` / ``args`` combination, including malformed
   ``%`` format strings, mismatched argument tuples, and dict args.
4. ``test_filter_handles_args_format`` - when the PAN is supplied via
   ``record.args`` rather than baked into ``record.msg`` (the standard
   stdlib ``logging`` pattern, e.g. ``logger.info("card=%s", pan)``),
   the filter still redacts the formatted output.
"""

from __future__ import annotations

import logging

import pytest
from hypothesis import given, strategies as st

from binchecker.core.pan import mask_pan
from binchecker.log.pan_filter import PanRedactionFilter
from tests.strategies import (
    invalid_pan_strategy,
    unicode_text_strategy,
    valid_pan_strategy,
)


def _make_record(msg: object, args: object = None) -> logging.LogRecord:
    """Build a minimal :class:`logging.LogRecord` for filter input.

    Mirrors the snippet supplied in the task brief: positional metadata is
    not interesting for these tests, so we use placeholder values.
    """
    return logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=msg,
        args=args,
        exc_info=None,
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# The PAN-redaction filter scans for runs of 12-19 ASCII decimal digits.
# Concatenating ``prefix + pan + suffix`` to build the test message could
# accidentally merge ``pan`` into a longer digit run when the surrounding
# unicode happens to end / start with ASCII digits, in which case the
# greedy regex would match a *different* substring than the cleartext PAN.
# To keep the test focused on the property under test (Luhn-valid runs are
# masked), we strip ASCII digits from the prefix/suffix while still drawing
# the rest of the unicode space from the project's stock strategy. This
# preserves the "for any unicode text" intent of Property 9 because the
# filter's contract is keyed on digit-run boundaries.
_text_no_ascii_digits: st.SearchStrategy[str] = unicode_text_strategy().map(
    lambda s: "".join(ch for ch in s if not (ch.isascii() and ch.isdigit()))
)


# A ``record.args`` strategy mixing the three shapes that
# :mod:`logging` supports as valid ``LogRecord`` ``args`` payloads:
#
# * ``None`` or the empty tuple model "no args".
# * Tuples of zero or more values cover the standard positional case
#   (``logger.info("msg %s %d", "a", 1)``).
# * A 1-tuple containing a dict is auto-unwrapped by ``LogRecord.__init__``
#   into the named-substitution form (``logger.info("%(k)s", {"k": "v"})``).
# * A 1-tuple containing a single non-mapping value covers the
#   "single-value" args case (``logger.info("%s", value)``).
#
# Bare dicts and bare scalars are *not* legal inputs to ``LogRecord``: its
# constructor unconditionally probes ``args[0]`` which crashes on a dict
# whose keys are not ``0`` and on any non-indexable scalar. Property 9
# concerns the filter's behaviour, not the stdlib constructor's, so the
# strategy stays inside the documented input space.
_args_strategy: st.SearchStrategy[object] = st.one_of(
    st.none(),
    st.just(()),
    st.tuples(st.text(max_size=20)),
    st.tuples(st.text(max_size=20), st.integers()),
    st.tuples(st.integers(), st.integers(), st.text(max_size=20)),
    st.tuples(st.integers()),
    st.tuples(
        st.dictionaries(
            st.text(
                alphabet="abcdefghijklmnopqrstuvwxyz_",
                min_size=1,
                max_size=10,
            ),
            st.one_of(st.text(max_size=20), st.integers()),
            max_size=4,
        )
    ),
)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@pytest.mark.property
@given(
    prefix=_text_no_ascii_digits,
    suffix=_text_no_ascii_digits,
    pan=valid_pan_strategy(),
)
def test_filter_redacts_luhn_valid_pan_anywhere(
    prefix: str, suffix: str, pan: str
) -> None:
    """A Luhn-valid PAN embedded in unicode text is replaced with its mask.

    Validates: Requirements 8.1, 8.4
    """
    record = _make_record(prefix + pan + suffix)
    flt = PanRedactionFilter()

    assert flt.filter(record) is True

    out = record.msg
    assert isinstance(out, str)
    assert pan not in out, (
        f"cleartext PAN leaked through filter: pan={pan!r}, out={out!r}"
    )
    assert mask_pan(pan) in out, (
        f"masked PAN missing from filter output: "
        f"expected mask={mask_pan(pan)!r}, got out={out!r}"
    )
    # ``record.args`` is consumed by the filter to avoid downstream
    # re-formatting of the (now redacted) message.
    assert record.args == ()


@pytest.mark.property
@given(invalid_pan=invalid_pan_strategy())
def test_filter_preserves_non_luhn_digit_runs(invalid_pan: str) -> None:
    """Non-Luhn 12-19 digit runs pass through the filter unchanged.

    Validates: Requirements 8.1, 8.4
    """
    record = _make_record(invalid_pan)
    flt = PanRedactionFilter()

    assert flt.filter(record) is True
    assert record.msg == invalid_pan
    assert record.args == ()


@pytest.mark.property
@given(msg=st.text(), args=_args_strategy)
def test_filter_never_raises(msg: str, args: object) -> None:
    """The filter is total: it returns ``True`` and never raises.

    Validates: Requirements 8.1, 8.4
    """
    record = _make_record(msg, args)
    flt = PanRedactionFilter()

    raised: BaseException | None = None
    result: bool | None = None
    try:
        result = flt.filter(record)
    except BaseException as exc:  # noqa: BLE001 - the property asserts no raise
        raised = exc

    assert raised is None, (
        f"PanRedactionFilter.filter raised {type(raised).__name__}: {raised}"
    )
    assert result is True


@pytest.mark.property
@given(pan=valid_pan_strategy())
def test_filter_handles_args_format(pan: str) -> None:
    """A PAN supplied via ``record.args`` is redacted in the rendered output.

    Validates: Requirements 8.1, 8.4
    """
    record = _make_record("%s", (pan,))
    flt = PanRedactionFilter()

    assert flt.filter(record) is True

    out = record.msg
    assert isinstance(out, str)
    assert pan not in out, (
        f"cleartext PAN leaked when delivered via record.args: "
        f"pan={pan!r}, out={out!r}"
    )
    assert mask_pan(pan) in out, (
        f"masked PAN missing from filter output: "
        f"expected mask={mask_pan(pan)!r}, got out={out!r}"
    )
    assert record.args == ()
