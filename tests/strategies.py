"""Custom Hypothesis strategies for the binchecker test suite.

Stubs declared by task 1.2 of the ``project-enhancement`` spec. Each strategy
returns sensible values that downstream property tests (tasks 2.x onward) can
build on. Refinements — e.g. brand-aware PAN lengths, per-provider BIN response
shapes, real ``AppConfig`` field constraints — happen incrementally as the
matching production modules land.

Strategy catalogue (see design.md → "Generators (custom strategies)"):

- ``valid_pan_strategy``         13-19 digit strings with a valid Luhn check.
- ``invalid_pan_strategy``       13-19 digit strings that fail the Luhn check.
- ``card_strategy``              dicts with ``pan, month, year, cvv`` keys.
- ``bin_response_strategy``      binlist.net-shaped JSON responses.
- ``html_with_signatures_strategy``  HTML snippets with/without gateway hits.
- ``unicode_text_strategy``      Unicode strings of length 0-200.
- ``config_dict_strategy``       dicts with valid ``AppConfig`` keys.

The Luhn helper (``_luhn_check_digit``) is local to this module so the test
suite is independent of the (yet-to-be-implemented) ``binchecker.core.luhn``.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Well-known gateway substrings used by ``html_with_signatures_strategy``.
# Task 9.x will replace this with the real ``GatewayPool`` so each emitted
# document carries pool-driven signatures.
_GATEWAY_SIGNATURE_POOL: tuple[str, ...] = (
    "stripe.com/v3",
    "js.braintreegateway.com",
    "checkout.adyen.com",
    "paypal.com/sdk/js",
    "checkout.stripe.com",
    "js.stripe.com",
    "squareup.com/sqpaymentform",
    "checkout.razorpay.com",
)


def _luhn_check_digit(digits: str) -> str:
    """Compute the Luhn check digit for ``digits`` (no check digit yet)."""
    total = 0
    # iterate right-to-left, doubling every second digit
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - total % 10) % 10)


def _luhn_is_valid(digits: str) -> bool:
    """Return True iff the trailing digit of ``digits`` is its Luhn check."""
    if len(digits) < 2 or not digits.isdigit():
        return False
    return _luhn_check_digit(digits[:-1]) == digits[-1]


# ---------------------------------------------------------------------------
# Public strategies
# ---------------------------------------------------------------------------


def valid_pan_strategy() -> st.SearchStrategy[str]:
    """Emit 13-19 digit strings whose Luhn checksum is valid.

    Generation strategy: draw a body of length 12-18, append the computed
    Luhn check digit so the result is always Luhn-valid and falls in the
    canonical PAN length range.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        body_len = draw(st.integers(min_value=12, max_value=18))
        body = draw(
            st.text(alphabet="0123456789", min_size=body_len, max_size=body_len)
        )
        return body + _luhn_check_digit(body)

    return _build()


def invalid_pan_strategy() -> st.SearchStrategy[str]:
    """Emit 13-19 digit strings that fail the Luhn check."""
    return st.text(alphabet="0123456789", min_size=13, max_size=19).filter(
        lambda s: not _luhn_is_valid(s)
    )


def card_strategy() -> st.SearchStrategy[dict[str, str]]:
    """Emit card record dicts with ``pan``, ``month``, ``year``, ``cvv`` keys.

    All values are strings to match the wire format used by
    ``card_checker.py``; expiry covers a 2000-2099 window and CVV widens to
    4 digits for AMEX prefixes (``34`` / ``37``).
    """

    @st.composite
    def _build(draw: st.DrawFn) -> dict[str, str]:
        pan = draw(valid_pan_strategy())
        month = draw(st.integers(min_value=1, max_value=12))
        year = draw(st.integers(min_value=2000, max_value=2099))
        cvv_len = 4 if pan.startswith(("34", "37")) else 3
        cvv = draw(
            st.text(alphabet="0123456789", min_size=cvv_len, max_size=cvv_len)
        )
        return {
            "pan": pan,
            "month": f"{month:02d}",
            "year": f"{year:04d}",
            "cvv": cvv,
        }

    return _build()


def bin_response_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Emit dicts matching the binlist.net BIN response schema.

    Schema reference (https://binlist.net/): top-level ``scheme``, ``type``,
    ``brand``, ``prepaid`` plus nested ``country`` and ``bank`` objects.
    Values are emitted as plausible-but-arbitrary strings; later tasks
    (10.3-10.5) add per-provider variants (handyapi, bincheck.io) and
    error-envelope mutations.
    """
    return st.fixed_dictionaries(
        {
            "scheme": st.sampled_from(
                ["visa", "mastercard", "amex", "discover", "jcb", "maestro"]
            ),
            "type": st.sampled_from(["debit", "credit", "prepaid"]),
            "brand": st.text(min_size=0, max_size=20),
            "prepaid": st.booleans(),
            "country": st.fixed_dictionaries(
                {
                    "name": st.text(min_size=0, max_size=40),
                    "alpha2": st.text(
                        alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                        min_size=2,
                        max_size=2,
                    ),
                }
            ),
            "bank": st.fixed_dictionaries(
                {
                    "name": st.text(min_size=0, max_size=60),
                    "url": st.text(min_size=0, max_size=80),
                }
            ),
        }
    )


def html_with_signatures_strategy() -> st.SearchStrategy[str]:
    """Emit small HTML snippets that include or exclude well-known gateway
    substrings (``stripe.com/v3``, ``braintreegateway.com``, ...).

    The empty-subset case is intentionally allowed so property tests can
    exercise both ``detect_gateways`` hits and misses.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        chosen = draw(
            st.lists(
                st.sampled_from(_GATEWAY_SIGNATURE_POOL),
                min_size=0,
                max_size=len(_GATEWAY_SIGNATURE_POOL),
                unique=True,
            )
        )
        scripts = "\n".join(f'<script src="https://{s}"></script>' for s in chosen)
        return (
            "<!doctype html><html><head>"
            f"{scripts}"
            "</head><body><p>checkout</p></body></html>"
        )

    return _build()


def unicode_text_strategy() -> st.SearchStrategy[str]:
    """Emit arbitrary Unicode strings of length 0-200.

    Excludes surrogate codepoints (which are invalid in UTF-8) but otherwise
    spans the BMP and supplementary planes used by the round-trip tests.
    """
    return st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),  # exclude surrogates
            min_codepoint=0,
            max_codepoint=0x10FFFF,
        ),
        min_size=0,
        max_size=200,
    )


def config_dict_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Emit dicts with valid keys for ``AppConfig``.

    Keys mirror the design's ``AppConfig`` schema (see design.md → "config"):
    ``concurrency``, ``api_timeout``, ``bin_cache_ttl_hours``, ``log_level``,
    ``profile``, ``locale``. Values stay inside the documented ranges so
    later property tests can opt in to adversarial values via filters /
    custom strategies built on top of this stub.
    """
    return st.fixed_dictionaries(
        {
            "concurrency": st.integers(min_value=1, max_value=20),
            "api_timeout": st.floats(
                min_value=0.1,
                max_value=120.0,
                allow_nan=False,
                allow_infinity=False,
            ),
            "bin_cache_ttl_hours": st.integers(min_value=1, max_value=168),
            "log_level": st.sampled_from(["DEBUG", "INFO", "WARNING", "ERROR"]),
            "profile": st.sampled_from(["development", "testing", "production"]),
            "locale": st.sampled_from(["en", "ru"]),
        }
    )
