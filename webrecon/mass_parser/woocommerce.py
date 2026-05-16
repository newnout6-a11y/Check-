"""WooCommerce Store API validator for the mass-parser pipeline.

This module detects and validates WooCommerce websites by probing the
Store API, extracting public Stripe keys from page HTML, testing
server-side tokenization, and identifying the Stripe plugin version
(legacy, UPE, or blocks checkout).

The validator is the ``webrecon`` counterpart of the validation logic
in the ``fofa_scraper``, ``serper_deep``, and ``site_scraper``
standalone scripts, refactored to use the shared
:class:`~webrecon.mass_parser.client.MassParserClient` transport
layer and the :class:`~webrecon.core.models` dataclasses.

Usage::

    async with MassParserClient() as http:
        validator = WooCommerceValidator(http)
        asset = await validator.validate("https://example.com")
        if asset and asset.store_api_available:
            print(asset.tokenization_status, asset.stripe_plugin_version)

Validates: Requirement 3.4 (WooCommerce Store API detection),
Requirement 5.1 (Stripe key extraction from page content),
Requirement 5.2 (tokenization testing).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from webrecon.core.models import (
    AssetStatus,
    DiscoverySource,
    KeyType,
    StripeKey,
    WebsiteAsset,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.mass_parser.client import MassParserClient

__all__ = [
    "WooCommerceValidator",
    "WooValidationResult",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Stripe key extraction patterns
# ---------------------------------------------------------------------------

# Ordered by specificity: patterns with capture groups first.
_PK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""publishableKey["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""publishable_key["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""stripe_pk["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""stripeKey["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""key["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""Stripe\(\s*\{[^}]*key\s*:\s*["\'](pk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""Stripe\(["\']?(pk_live_[0-9a-zA-Z]{24,})["\']?\)"""),
    # Broadest: bare pk_live_ in quotes.
    re.compile(r"""['"](pk_live_[0-9a-zA-Z]{24,})['"]"""),
    # Fallback: bare pk_live_ without quotes.
    re.compile(r"""(pk_live_[0-9a-zA-Z]{24,})"""),
]

# Country/currency extraction.
_COUNTRY_RE: re.Pattern[str] = re.compile(
    r"""country["\']?\s*[:=]\s*["']([A-Z]{2})"""
)
_CURRENCY_RE: re.Pattern[str] = re.compile(
    r"""currency["\']?\s*[:=]\s*["']([a-z]{3})"""
)
_CURRENCY_TO_COUNTRY: dict[str, str] = {
    "USD": "US", "EUR": "DE", "GBP": "GB", "CAD": "CA",
    "AUD": "AU", "JPY": "JP", "CHF": "CH", "SEK": "SE",
    "NOK": "NO", "DKK": "DK", "NZD": "NZ",
}

# WooCommerce version extraction from HTML.
_WC_VERSION_RE: re.Pattern[str] = re.compile(
    r"""woocommerce.*?version["\']?\s*[:=]\s*["']([0-9.]+)""",
    re.IGNORECASE,
)

# Stripe plugin version markers in checkout HTML.
_STRIPE_LEGACY_MARKERS: list[str] = [
    "wc_stripe_params",
    "wc-gateway-stripe",
    "woocommerce_stripe",
]
_STRIPE_UPE_MARKERS: list[str] = [
    "wc-stripe-upe",
    "wc_stripe_upe_params",
]
_STRIPE_BLOCKS_MARKERS: list[str] = [
    "wc-stripe-blocks",
    "wc-stripe-payment-element",
    "wc-stripe-blocks-payment-method",
]

# Pages to check for pk_live_ key, in order of likelihood.
_CHECKOUT_PAGES: list[str] = [
    "/checkout/",
    "/shop/",
    "/",
    "/cart/",
    "/product/",
    "/store/",
    "/buy/",
    "/pricing/",
    "/subscribe/",
    "/product-category/",
]

# Stripe API version for tokenization test.
_STRIPE_API_VERSION: str = "2023-10-16"

# Test card for tokenization (Stripe's official test card).
_TEST_CARD: dict[str, str] = {
    "type": "card",
    "card[number]": "4242424242424242",
    "card[exp_month]": "12",
    "card[exp_year]": "35",
    "card[cvc]": "123",
}

# Tokenization request headers.
_STRIPE_HEADERS: dict[str, str] = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://js.stripe.com",
    "Referer": "https://js.stripe.com/",
    "Accept": "application/json",
    "Stripe-Version": _STRIPE_API_VERSION,
}


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass
class WooValidationResult:
    """Detailed result of validating a single WooCommerce site.

    Attributes:
        asset: A :class:`WebsiteAsset` if the site is a valid
            WooCommerce + Stripe target, or ``None`` if validation
            failed at any step.
        store_api_available: Whether the WooCommerce Store API
            responded successfully.
        nonce: The ``X-WC-Store-API-Nonce`` from the Store API
            response, if present.
        pk_key: The ``pk_live_`` key found on the site, or empty.
        tokenization_status: ``"ok"``, ``"blocked"``, ``"other"``,
            ``"error"``, or empty if not tested.
        stripe_version: ``"legacy"``, ``"upe"``, ``"blocks"``, or
            empty if not detected.
        woocommerce_version: WooCommerce version string, or empty.
        country: Detected country code (e.g. ``"US"``), or empty.
        currency: Detected currency code (e.g. ``"USD"``), or empty.
    """

    asset: WebsiteAsset | None = None
    store_api_available: bool = False
    nonce: str = ""
    pk_key: str = ""
    tokenization_status: str = ""
    stripe_version: str = ""
    woocommerce_version: str = ""
    country: str = ""
    currency: str = ""


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class WooCommerceValidator:
    """Validate WooCommerce + Stripe websites.

    The validator performs a multi-step check:

    1. **Store API** -- probe ``/wp-json/wc/store/v1/cart`` to
       confirm the site runs WooCommerce.
    2. **Key extraction** -- crawl checkout-related pages to find
       ``pk_live_`` keys in the HTML.
    3. **Plugin version** -- detect the Stripe plugin checkout mode
       (legacy, UPE, or blocks).
    4. **Tokenization test** -- attempt to create a
       ``payment_method`` via Stripe's public API using the
       discovered key.

    Args:
        client: A :class:`MassParserClient` for HTTP transport.
        test_tokenization: Whether to test server-side tokenization.
            Defaults to ``True``.
    """

    def __init__(
        self,
        client: MassParserClient,
        *,
        test_tokenization: bool = True,
    ) -> None:
        self._client = client
        self._tokenization_enabled = test_tokenization

    # ---- Public API ---------------------------------------------------

    async def validate(
        self,
        url: str,
        *,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL,
    ) -> WooValidationResult:
        """Validate a single URL as a WooCommerce + Stripe target.

        Args:
            url: The target URL (e.g. ``"https://example.com"``).
            discovery_source: The intelligence source that surfaced
                this URL.

        Returns:
            A :class:`WooValidationResult` with the findings.
        """
        url = url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        result = WooValidationResult()

        # Step 1: Store API check.
        store_ok, nonce, wc_version = await self._check_store_api(url)
        if not store_ok:
            _LOGGER.debug(
                "mass_parser.woocommerce.store_api_unavailable",
                url=url,
            )
            return result

        result.store_api_available = True
        result.nonce = nonce
        result.woocommerce_version = wc_version

        # Step 2: Extract pk_live_ from pages.
        pk, country, currency = await self._extract_pk_and_meta(url)
        if not pk:
            _LOGGER.debug(
                "mass_parser.woocommerce.no_pk_key",
                url=url,
            )
            return result

        result.pk_key = pk
        result.country = country
        result.currency = currency

        # Step 3: Detect Stripe plugin version.
        stripe_version = await self._detect_stripe_version(url)
        result.stripe_version = stripe_version

        # Step 4: Test tokenization.
        tok_status = ""
        if self._tokenization_enabled:
            tok_status = await self._test_tokenization(pk)
        result.tokenization_status = tok_status

        # Build the WebsiteAsset.
        now = datetime.now(timezone.utc)
        asset_id = str(uuid.uuid4())

        stripe_key = StripeKey(
            id=str(uuid.uuid4()),
            key_value=pk,
            key_type=KeyType.PK_LIVE,
            discovered_at=now,
            source_url=url,
            is_valid=False,
            metadata={
                "discovery_method": "woocommerce_validation",
                "tokenization_status": tok_status,
                "stripe_version": stripe_version,
            },
        )

        asset = WebsiteAsset(
            id=asset_id,
            url=url,
            normalized_url=url,
            discovered_at=now,
            last_checked=now,
            status=AssetStatus.ACTIVE,
            discovery_source=discovery_source,
            technology_stack=["woocommerce", "wordpress", "stripe"],
            stripe_keys=[stripe_key],
            tokenization_status=tok_status or None,
            stripe_plugin_version=stripe_version or None,
            woocommerce_version=wc_version or None,
            store_api_available=True,
            country=country or None,
            currency=currency or None,
        )

        result.asset = asset

        _LOGGER.info(
            "mass_parser.woocommerce.validated",
            url=url,
            tokenization=tok_status,
            stripe_version=stripe_version,
            country=country,
        )

        return result

    async def validate_batch(
        self,
        urls: list[str],
        *,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL,
    ) -> list[WooValidationResult]:
        """Validate a batch of URLs concurrently.

        Concurrency is bounded by the
        :class:`~webrecon.mass_parser.client.MassParserClient`
        semaphore.

        Args:
            urls: List of target URLs.
            discovery_source: Intelligence source for all URLs.

        Returns:
            List of :class:`WooValidationResult` objects.
        """
        import asyncio

        async def _validate_one(u: str) -> WooValidationResult:
            return await self.validate(u, discovery_source=discovery_source)

        results = await asyncio.gather(
            *[_validate_one(u) for u in urls],
            return_exceptions=False,
        )
        return list(results)

    # ---- Internal: Store API ------------------------------------------

    async def _check_store_api(
        self,
        base_url: str,
    ) -> tuple[bool, str, str]:
        """Check WooCommerce Store API availability.

        Returns:
            ``(available, nonce, wc_version)`` tuple.
        """
        cart_url = f"{base_url}/wp-json/wc/store/v1/cart"
        resp = await self._client.get(
            cart_url,
            headers={"Accept": "application/json"},
            timeout=10.0,
        )

        if resp.status_code != 200:
            return False, "", ""

        nonce = resp.headers.get("X-WC-Store-API-Nonce", "")
        if not nonce:
            nonce = resp.headers.get("Nonce", "")

        # Try to extract WC version from the cart response body.
        wc_version = ""
        try:
            body = resp.text
            m = _WC_VERSION_RE.search(body)
            if m:
                wc_version = m.group(1)
        except Exception:
            pass

        return True, nonce, wc_version

    # ---- Internal: Key extraction --------------------------------------

    async def _extract_pk_and_meta(
        self,
        base_url: str,
    ) -> tuple[str, str, str]:
        """Extract pk_live_ key, country, and currency from site pages.

        Returns:
            ``(pk_key, country, currency)`` tuple. Empty strings when
            not found.
        """
        pk = ""
        country = ""
        currency = ""
        first_html = ""

        for page in _CHECKOUT_PAGES:
            if pk:
                break
            resp = await self._client.get(
                f"{base_url}{page}",
                timeout=10.0,
            )
            if resp.status_code != 200:
                continue

            html = resp.text
            if not first_html:
                first_html = html

            pk = self._find_pk_in_html(html)

        # If no pk found on checkout pages, try the first page HTML.
        if not pk and first_html:
            pk = self._find_pk_in_html(first_html)

        if pk and first_html:
            country = self._extract_country(first_html)
            currency = self._extract_currency(first_html)

        return pk, country, currency

    @staticmethod
    def _find_pk_in_html(html: str) -> str:
        """Search HTML for a pk_live_ key using ordered patterns."""
        for pattern in _PK_PATTERNS:
            m = pattern.search(html)
            if m:
                # Some patterns have the key in group 1, some in group 0.
                for g in m.groups():
                    if g and g.startswith("pk_live_"):
                        return g
                val = m.group(0).strip("'\"")
                if val.startswith("pk_live_"):
                    return val
        return ""

    @staticmethod
    def _extract_country(html: str) -> str:
        """Extract a country code from HTML content."""
        m = _COUNTRY_RE.search(html)
        if m:
            return m.group(1).upper()
        return ""

    @staticmethod
    def _extract_currency(html: str) -> str:
        """Extract a currency code from HTML content."""
        m = _CURRENCY_RE.search(html)
        if m:
            return m.group(1).upper()
        return ""

    # ---- Internal: Stripe version -------------------------------------

    async def _detect_stripe_version(self, base_url: str) -> str:
        """Detect the Stripe plugin checkout mode.

        Returns:
            ``"legacy"``, ``"upe"``, ``"blocks"``, or empty string.
        """
        resp = await self._client.get(
            f"{base_url}/checkout/",
            timeout=10.0,
        )
        if resp.status_code != 200:
            return ""

        html = resp.text

        # Check in order of specificity (blocks is newest).
        for marker in _STRIPE_BLOCKS_MARKERS:
            if marker in html:
                return "blocks"

        for marker in _STRIPE_UPE_MARKERS:
            if marker in html:
                return "upe"

        for marker in _STRIPE_LEGACY_MARKERS:
            if marker in html:
                return "legacy"

        return ""

    # ---- Internal: Tokenization test -----------------------------------

    async def _test_tokenization(self, pk_key: str) -> str:
        """Test server-side tokenization with the discovered pk_live_ key.

        Returns:
            ``"ok"`` if tokenization works, ``"blocked"`` if Stripe
            blocks server-side tokenization, ``"other"`` for other
            errors, ``"error"`` for transport errors.
        """
        headers = {
            "Authorization": f"Bearer {pk_key}",
            **_STRIPE_HEADERS,
        }

        try:
            resp = await self._client.post(
                "https://api.stripe.com/v1/payment_methods",
                data=_TEST_CARD,
                headers=headers,
                timeout=10.0,
            )
        except Exception:
            return "error"

        if resp.error is not None:
            return "error"

        try:
            data = __import__("json").loads(resp.text)
        except Exception:
            return "error"

        if data.get("object") == "payment_method":
            return "ok"

        err_msg = data.get("error", {}).get("message", "").lower()
        if "unsupported" in err_msg:
            return "blocked"
        if "declined" in err_msg or "live mode" in err_msg:
            # Test card declined in live mode = tokenization WORKS.
            return "ok"

        return "other"
