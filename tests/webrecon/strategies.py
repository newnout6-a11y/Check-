"""Custom Hypothesis strategies for the ``webrecon`` test suite.

Per task 1.2 of the ``web-reconnaissance`` spec, this module exposes
generators for the three input families that property tests need:

* **URLs** — ``url_strategy``, ``http_url_strategy``, ``hostname_strategy``,
  ``url_path_strategy``. Used by URL-normalisation, deduplication and
  database round-trip properties.

* **HTML** — ``html_strategy``, ``html_with_form_strategy``,
  ``html_with_stripe_keys_strategy``. Used by the form-discovery and
  Stripe-key-extraction property tests.

* **API responses** — ``fofa_response_strategy``, ``shodan_response_strategy``,
  ``serper_response_strategy``, ``github_search_response_strategy``,
  ``stripe_balance_response_strategy``. Used by the discovery-module
  property tests to assert that arbitrary-but-shape-conforming
  responses parse without crashing.

Strategies are kept *narrow* on purpose: they constrain to the input
space the production code actually accepts (valid scheme + host, ASCII
paths, JSON-serialisable payloads). Property tests that want broader
coverage should compose these with ``hypothesis.strategies`` primitives
rather than re-implementing the constraint logic.

These strategies do not depend on any ``webrecon`` runtime module so the
test suite collects cleanly during the early phases of implementation
when the production modules are still empty.
"""

from __future__ import annotations

import datetime as _dt
import string
from typing import Any

from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Top-level domains used by URL strategies. Limited to a small, well-known
# set so generated hostnames are always parseable and registry-friendly.
_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "io",
    "co",
    "dev",
    "info",
    "shop",
    "store",
    "test",
)

_HOST_LABEL_ALPHABET = string.ascii_lowercase + string.digits + "-"
_PATH_SEGMENT_ALPHABET = string.ascii_letters + string.digits + "-_."

# Stripe key prefixes recognised by the mass-parser and GitHub modules.
_STRIPE_PREFIXES: tuple[str, ...] = ("pk_live_", "sk_live_", "pk_test_", "sk_test_")

# Stripe key body alphabet (per the published key format).
_STRIPE_BODY_ALPHABET = string.ascii_letters + string.digits


# ---------------------------------------------------------------------------
# URL primitives
# ---------------------------------------------------------------------------


def _host_label_strategy(min_size: int = 1, max_size: int = 20) -> st.SearchStrategy[str]:
    """Single DNS label: 1-63 chars, alnum + hyphen, no leading/trailing hyphen."""
    return (
        st.text(alphabet=_HOST_LABEL_ALPHABET, min_size=min_size, max_size=max_size)
        .filter(lambda s: not s.startswith("-") and not s.endswith("-"))
    )


def hostname_strategy() -> st.SearchStrategy[str]:
    """Generate a syntactically valid hostname with a known TLD.

    The total length is bounded well under 253 chars (the DNS limit) so
    the strategy is cheap to shrink.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        n_labels = draw(st.integers(min_value=1, max_value=3))
        labels = [draw(_host_label_strategy(2, 12)) for _ in range(n_labels)]
        tld = draw(st.sampled_from(_TLDS))
        return ".".join([*labels, tld])

    return _build()


def url_path_strategy() -> st.SearchStrategy[str]:
    """Generate a URL path starting with ``/``.

    Yields between zero and four segments. The empty-path case (``"/"``)
    is included so URL-normalisation properties can assert that the
    canonical form is preserved.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        segments = draw(
            st.lists(
                st.text(
                    alphabet=_PATH_SEGMENT_ALPHABET,
                    min_size=1,
                    max_size=20,
                ),
                min_size=0,
                max_size=4,
            )
        )
        return "/" + "/".join(segments)

    return _build()


def http_url_strategy(
    schemes: tuple[str, ...] = ("http", "https"),
    with_path: bool = True,
) -> st.SearchStrategy[str]:
    """Generate ``http(s)://`` URLs with a hostname and optional path.

    No port, query string or fragment is emitted by default; tests that
    need those should compose this strategy with ``map`` / ``flatmap``.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        scheme = draw(st.sampled_from(schemes))
        host = draw(hostname_strategy())
        path = draw(url_path_strategy()) if with_path else ""
        return f"{scheme}://{host}{path}"

    return _build()


# Public alias for the most common case.
url_strategy = http_url_strategy


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def stripe_key_strategy(
    prefixes: tuple[str, ...] = _STRIPE_PREFIXES,
) -> st.SearchStrategy[str]:
    """Generate plausible-looking Stripe API keys (``pk_live_…`` / ``sk_live_…``).

    Real Stripe keys follow ``<prefix><24+ alnum>``. The strategy emits
    24-char bodies so produced keys parse cleanly with the documented
    regex (``[A-Za-z0-9]{24,}``).
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        prefix = draw(st.sampled_from(prefixes))
        body = draw(
            st.text(
                alphabet=_STRIPE_BODY_ALPHABET,
                min_size=24,
                max_size=40,
            )
        )
        return prefix + body

    return _build()


def html_strategy() -> st.SearchStrategy[str]:
    """Generate small, syntactically valid HTML5 documents.

    The body holds 0-3 paragraphs of arbitrary text. No nested tags are
    emitted so the result is trivial to parse with BeautifulSoup4.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        title = draw(st.text(min_size=0, max_size=40))
        paragraphs = draw(
            st.lists(st.text(min_size=0, max_size=80), min_size=0, max_size=3)
        )
        body = "".join(f"<p>{p}</p>" for p in paragraphs)
        return (
            "<!doctype html><html><head>"
            f"<title>{title}</title>"
            "</head><body>"
            f"{body}"
            "</body></html>"
        )

    return _build()


def html_with_stripe_keys_strategy() -> st.SearchStrategy[tuple[str, list[str]]]:
    """Generate HTML containing zero or more Stripe keys.

    Returns ``(html, keys)`` so property tests can assert that the
    extractor recovers exactly the embedded keys (Requirement 3.2,
    5.2). Keys are placed inside ``<script>`` blocks because real
    WooCommerce / Stripe.js bundles ship them that way.
    """

    @st.composite
    def _build(draw: st.DrawFn) -> tuple[str, list[str]]:
        keys = draw(st.lists(stripe_key_strategy(), min_size=0, max_size=5, unique=True))
        scripts = "\n".join(
            f"<script>var key = '{k}';</script>" for k in keys
        )
        html = (
            "<!doctype html><html><head><title>store</title></head>"
            f"<body>{scripts}<p>checkout</p></body></html>"
        )
        return html, keys

    return _build()


def html_with_form_strategy() -> st.SearchStrategy[str]:
    """Generate HTML containing a single form with 1-5 fields.

    The form has a deterministic ``action`` attribute and ``method``
    chosen from ``{GET, POST}``. Every field has a ``name`` and a
    ``type``. CSRF tokens are emitted ~50% of the time so form-discovery
    tests can cover both branches (Requirement 4.6).
    """

    field_types = ("text", "email", "password", "number", "checkbox", "hidden")

    @st.composite
    def _build(draw: st.DrawFn) -> str:
        method = draw(st.sampled_from(("GET", "POST")))
        action = draw(http_url_strategy())
        n_fields = draw(st.integers(min_value=1, max_value=5))
        fields_html: list[str] = []
        seen_names: set[str] = set()
        for _ in range(n_fields):
            # Unique field names so the form is well-formed.
            for _attempt in range(5):
                name = draw(
                    st.text(
                        alphabet=string.ascii_lowercase + "_",
                        min_size=1,
                        max_size=12,
                    )
                )
                if name not in seen_names:
                    seen_names.add(name)
                    break
            else:
                continue
            ftype = draw(st.sampled_from(field_types))
            fields_html.append(
                f'<input type="{ftype}" name="{name}" />'
            )
        if draw(st.booleans()):
            fields_html.append(
                '<input type="hidden" name="csrf_token" value="abc123" />'
            )
        body = (
            f'<form action="{action}" method="{method}">'
            + "".join(fields_html)
            + '<button type="submit">Send</button>'
            + "</form>"
        )
        return (
            "<!doctype html><html><head><title>form</title></head>"
            f"<body>{body}</body></html>"
        )

    return _build()


# ---------------------------------------------------------------------------
# API response shapes
# ---------------------------------------------------------------------------


def fofa_response_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate FOFA-shaped search responses.

    Schema (extended mode): ``error`` flag, ``size`` total, ``page``,
    ``mode``, ``query`` and ``results`` — a list of ``[host, ip, port]``
    triples. Tests that only care about the result list can ignore the
    metadata fields.
    """
    result_row = st.tuples(
        http_url_strategy(),
        hostname_strategy(),
        st.sampled_from(("80", "443", "8080", "8443")),
    ).map(list)

    return st.fixed_dictionaries(
        {
            "error": st.just(False),
            "size": st.integers(min_value=0, max_value=1000),
            "page": st.integers(min_value=1, max_value=20),
            "mode": st.just("extended"),
            "query": st.text(min_size=0, max_size=80),
            "results": st.lists(result_row, min_size=0, max_size=10),
        }
    )


def shodan_response_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate Shodan-shaped search responses."""
    match = st.fixed_dictionaries(
        {
            "ip_str": st.from_regex(
                r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$",
                fullmatch=True,
            ),
            "port": st.integers(min_value=1, max_value=65535),
            "hostnames": st.lists(hostname_strategy(), min_size=0, max_size=3),
            "product": st.sampled_from(["nginx", "Apache", "IIS", "lighttpd", ""]),
            "data": st.text(min_size=0, max_size=120),
        }
    )

    return st.fixed_dictionaries(
        {
            "matches": st.lists(match, min_size=0, max_size=10),
            "total": st.integers(min_value=0, max_value=10_000),
        }
    )


def serper_response_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate Serper-shaped (Google search) responses."""
    organic = st.fixed_dictionaries(
        {
            "title": st.text(min_size=0, max_size=80),
            "link": http_url_strategy(),
            "snippet": st.text(min_size=0, max_size=200),
            "position": st.integers(min_value=1, max_value=100),
        }
    )

    return st.fixed_dictionaries(
        {
            "searchParameters": st.fixed_dictionaries(
                {
                    "q": st.text(min_size=0, max_size=120),
                    "type": st.just("search"),
                }
            ),
            "organic": st.lists(organic, min_size=0, max_size=10),
        }
    )


def github_search_response_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate GitHub-shaped code-search responses (`/search/code`)."""
    repo = st.fixed_dictionaries(
        {
            "full_name": st.tuples(
                _host_label_strategy(2, 20), _host_label_strategy(2, 20)
            ).map(lambda t: f"{t[0]}/{t[1]}"),
            "html_url": http_url_strategy(schemes=("https",)),
            "private": st.just(False),
        }
    )

    item = st.fixed_dictionaries(
        {
            "name": st.text(
                alphabet=_PATH_SEGMENT_ALPHABET, min_size=1, max_size=30
            ),
            "path": url_path_strategy().map(lambda p: p.lstrip("/")),
            "sha": st.text(alphabet="0123456789abcdef", min_size=40, max_size=40),
            "url": http_url_strategy(schemes=("https",)),
            "html_url": http_url_strategy(schemes=("https",)),
            "repository": repo,
        }
    )

    return st.fixed_dictionaries(
        {
            "total_count": st.integers(min_value=0, max_value=10_000),
            "incomplete_results": st.booleans(),
            "items": st.lists(item, min_size=0, max_size=10),
        }
    )


def stripe_balance_response_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate Stripe ``/v1/balance`` shaped responses.

    Used by the GitHub-dorker and mass-parser key-validation property
    tests (Requirements 2.3, 3.3).
    """
    money = st.fixed_dictionaries(
        {
            "amount": st.integers(min_value=0, max_value=10_000_000),
            "currency": st.sampled_from(["usd", "eur", "gbp", "jpy", "aud"]),
            "source_types": st.fixed_dictionaries(
                {"card": st.integers(min_value=0, max_value=10_000_000)}
            ),
        }
    )

    return st.fixed_dictionaries(
        {
            "object": st.just("balance"),
            "available": st.lists(money, min_size=1, max_size=3),
            "pending": st.lists(money, min_size=0, max_size=3),
            "livemode": st.booleans(),
        }
    )


# ---------------------------------------------------------------------------
# Core data-model strategies
# ---------------------------------------------------------------------------
#
# These strategies build VALID instances of the ``webrecon.core.models``
# dataclasses so property tests that assert ``model.validate()`` does
# not raise can rely on them as a baseline. Tests that need invalid
# instances mutate one field after generation.
#
# Imported lazily inside ``@composite`` builders so this module stays
# importable when ``webrecon`` itself is not installed (e.g. during
# scaffold-only test runs).


_FORM_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")


def _utc_past_datetime_strategy(
    min_seconds_ago: int = 10,
) -> st.SearchStrategy[_dt.datetime]:
    """UTC-aware datetimes between 2020-01-01 and ``now - min_seconds_ago``.

    Using ``min_seconds_ago=10`` keeps generated timestamps comfortably
    in the past so :py:meth:`webrecon.core.models.WebsiteAsset.validate`
    (which uses a 1-second future-tolerance window) does not flake when
    test execution drifts.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    upper = (now - _dt.timedelta(seconds=min_seconds_ago)).replace(tzinfo=None)
    lower = _dt.datetime(2020, 1, 1)
    if upper <= lower:
        # Defensive: clock skew should never put us this far in the past.
        upper = lower + _dt.timedelta(seconds=1)
    return st.datetimes(min_value=lower, max_value=upper).map(
        lambda dt: dt.replace(tzinfo=_dt.timezone.utc)
    )


def _identifier_strategy(min_size: int = 1, max_size: int = 32) -> st.SearchStrategy[str]:
    """Non-empty alphanumeric/underscore identifier."""
    return st.text(
        alphabet=string.ascii_letters + string.digits + "_-",
        min_size=min_size,
        max_size=max_size,
    )


def _str_dict_strategy(
    max_size: int = 4,
) -> st.SearchStrategy[dict[str, str]]:
    """Small ``dict[str, str]`` — used for model ``metadata`` fields."""
    return st.dictionaries(
        keys=st.text(min_size=1, max_size=12),
        values=st.text(min_size=0, max_size=24),
        max_size=max_size,
    )


def form_field_strategy() -> st.SearchStrategy[Any]:
    """Generate a valid ``FormField`` instance."""
    from webrecon.core.models import FormField

    field_types = (
        "text",
        "email",
        "password",
        "number",
        "checkbox",
        "hidden",
        "textarea",
        "tel",
    )

    @st.composite
    def _build(draw: st.DrawFn) -> Any:
        return FormField(
            name=draw(_identifier_strategy(1, 24)),
            field_type=draw(st.sampled_from(field_types)),
            required=draw(st.booleans()),
            default_value=draw(st.one_of(st.none(), st.text(min_size=0, max_size=32))),
            validation_pattern=draw(
                st.one_of(st.none(), st.text(min_size=0, max_size=32))
            ),
            metadata=draw(_str_dict_strategy()),
        )

    return _build()


def form_discovery_strategy(
    *,
    website_id: str | None = None,
    max_fields: int = 4,
) -> st.SearchStrategy[Any]:
    """Generate a valid ``FormDiscovery`` instance.

    Pairs ``discovered_at`` and ``last_tested`` so the latter is never
    before the former. The submission method is restricted to a
    well-known HTTP verb set so :py:meth:`FormDiscovery.validate`
    accepts the result.
    """
    from webrecon.core.models import FormDiscovery

    @st.composite
    def _build(draw: st.DrawFn) -> Any:
        t1 = draw(_utc_past_datetime_strategy())
        t2 = draw(_utc_past_datetime_strategy())
        discovered, tested = sorted([t1, t2])
        last_tested = draw(st.one_of(st.none(), st.just(tested)))
        return FormDiscovery(
            id=draw(_identifier_strategy(1, 24)),
            website_id=website_id or draw(_identifier_strategy(1, 24)),
            url=draw(http_url_strategy()),
            form_html=draw(st.text(min_size=0, max_size=80)),
            fields=draw(
                st.lists(form_field_strategy(), min_size=0, max_size=max_fields)
            ),
            discovered_at=discovered,
            last_tested=last_tested,
            has_csrf_token=draw(st.booleans()),
            requires_auth=draw(st.booleans()),
            submission_method=draw(st.sampled_from(_FORM_METHODS)),
            action_url=draw(st.one_of(st.just(""), http_url_strategy())),
        )

    return _build()


def stripe_key_strategy_model() -> st.SearchStrategy[Any]:
    """Generate a valid ``StripeKey`` instance.

    Picks a ``key_type`` first, then crafts a ``key_value`` whose prefix
    matches the type so :py:meth:`StripeKey.validate` does not reject
    it. Pairs ``discovered_at`` with ``validated_at`` so the latter is
    either ``None`` or in ``[discovered_at, now)``.

    Different from :func:`stripe_key_strategy` (which yields raw key
    strings); this builder returns a ``StripeKey`` dataclass instance.
    """
    from webrecon.core.models import KeyType, StripeKey

    @st.composite
    def _build(draw: st.DrawFn) -> Any:
        key_type = draw(st.sampled_from(list(KeyType)))
        if key_type is KeyType.PK_LIVE:
            prefix = draw(st.sampled_from(("pk_live_", "pk_test_")))
        elif key_type is KeyType.SK_LIVE:
            prefix = draw(st.sampled_from(("sk_live_", "sk_test_")))
        else:
            # KeyType.OTHER has no prefix constraint; use a non-pk/sk
            # sentinel so it cannot accidentally pass a stricter check.
            prefix = draw(st.sampled_from(("rk_live_", "whsec_", "tok_")))
        body = draw(
            st.text(
                alphabet=_STRIPE_BODY_ALPHABET,
                min_size=24,
                max_size=40,
            )
        )
        key_value = prefix + body

        t1 = draw(_utc_past_datetime_strategy())
        t2 = draw(_utc_past_datetime_strategy())
        discovered, validated = sorted([t1, t2])
        validated_at = draw(st.one_of(st.none(), st.just(validated)))

        balance_available = draw(
            st.one_of(
                st.none(),
                st.lists(
                    st.fixed_dictionaries(
                        {
                            "currency": st.sampled_from(["usd", "eur", "gbp"]),
                            "amount": st.integers(min_value=0, max_value=10_000_000),
                        }
                    ),
                    min_size=0,
                    max_size=3,
                ),
            )
        )

        return StripeKey(
            id=draw(_identifier_strategy(1, 24)),
            key_value=key_value,
            key_type=key_type,
            discovered_at=discovered,
            source_url=draw(http_url_strategy()),
            validated_at=validated_at,
            is_valid=draw(st.booleans()),
            source_file=draw(
                st.one_of(st.none(), st.text(min_size=0, max_size=32))
            ),
            metadata=draw(_str_dict_strategy()),
            balance_available=balance_available,
            error_message=draw(
                st.one_of(st.none(), st.text(min_size=0, max_size=64))
            ),
            validation_count=draw(st.integers(min_value=0, max_value=100)),
        )

    return _build()


def website_asset_strategy(
    *,
    max_stripe_keys: int = 3,
) -> st.SearchStrategy[Any]:
    """Generate a valid ``WebsiteAsset`` instance.

    The strategy guarantees the validation contract:

    * ``check_count >= error_count >= 0``
    * ``success_rate in [0, 1]``
    * ``discovered_at <= last_checked``, both in the past
    * Each nested ``StripeKey``'s ``discovered_at`` is at-or-after the
      asset's ``discovered_at`` (relevant for downstream tests that
      sort by time).
    """
    from webrecon.core.models import (
        AssetStatus,
        DiscoverySource,
        WebsiteAsset,
    )

    @st.composite
    def _build(draw: st.DrawFn) -> Any:
        t1 = draw(_utc_past_datetime_strategy())
        t2 = draw(_utc_past_datetime_strategy())
        discovered, checked = sorted([t1, t2])

        check_count = draw(st.integers(min_value=0, max_value=1000))
        error_count = draw(st.integers(min_value=0, max_value=check_count))
        success_rate = draw(
            st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
        )

        return WebsiteAsset(
            id=draw(_identifier_strategy(1, 24)),
            url=draw(http_url_strategy()),
            # ``normalized_url`` has a UNIQUE constraint at the DB level;
            # ``_identifier_strategy`` is unique-enough per Hypothesis
            # example because it concatenates a random ID with a URL.
            normalized_url=draw(http_url_strategy())
            + "?id="
            + draw(_identifier_strategy(4, 12)),
            discovered_at=discovered,
            last_checked=checked,
            status=draw(st.sampled_from(list(AssetStatus))),
            discovery_source=draw(st.sampled_from(list(DiscoverySource))),
            technology_stack=draw(
                st.lists(st.text(min_size=1, max_size=16), max_size=4)
            ),
            metadata=draw(_str_dict_strategy()),
            stripe_keys=draw(
                st.lists(
                    stripe_key_strategy_model(),
                    min_size=0,
                    max_size=max_stripe_keys,
                    unique_by=(lambda k: k.id, lambda k: k.key_value),
                )
            ),
            tokenization_status=draw(
                st.one_of(st.none(), st.sampled_from(("server-side", "client-side")))
            ),
            stripe_plugin_version=draw(
                st.one_of(st.none(), st.sampled_from(("UPE", "blocks", "legacy")))
            ),
            woocommerce_version=draw(
                st.one_of(st.none(), st.text(min_size=1, max_size=12))
            ),
            store_api_available=draw(st.booleans()),
            country=draw(
                st.one_of(st.none(), st.text(alphabet=string.ascii_uppercase, min_size=2, max_size=2))
            ),
            currency=draw(
                st.one_of(st.none(), st.sampled_from(("USD", "EUR", "GBP", "JPY")))
            ),
            check_count=check_count,
            error_count=error_count,
            success_rate=success_rate,
        )

    return _build()
