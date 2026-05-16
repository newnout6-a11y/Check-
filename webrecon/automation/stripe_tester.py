"""Stripe key validation and payment testing for the automation pipeline.

This module validates Stripe API keys against Stripe's official API
and tests server-side tokenization for ``pk_live_`` keys. It covers:

* **Secret key validation** -- ``sk_live_`` / ``sk_test_`` keys are
  validated against ``/v1/balance``.
* **Public key tokenization test** -- ``pk_live_`` keys are tested
  by creating a ``payment_method`` via Stripe's public API.
* **Plugin version detection** -- identifies the Stripe checkout
  mode (legacy, UPE, blocks) on WooCommerce sites.
* **Security assessment** -- evaluates the risk level of exposed keys.

Usage::

    async with MassParserClient() as http:
        tester = StripeTester(http)
        result = await tester.validate_sk("sk_live_...")
        print(result.is_valid, result.balance_currency)

Validates: Requirement 5.1 (Stripe key validation via official API),
Requirement 5.2 (tokenization testing),
Requirement 5.3 (plugin version detection).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from webrecon.core.models import KeyType, StripeKey
from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.mass_parser.client import MassParserClient

__all__ = [
    "PkTestResult",
    "SkValidationResult",
    "StripeTester",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Stripe API constants
# ---------------------------------------------------------------------------

_STRIPE_API_BASE: str = "https://api.stripe.com"
_STRIPE_API_VERSION: str = "2023-10-16"

# Test card for public key tokenization test.
_TEST_CARD_NUMBER: str = "4242424242424242"
_TEST_CARD_EXP_MONTH: str = "12"
_TEST_CARD_EXP_YEAR: str = "35"
_TEST_CARD_CVC: str = "123"

# Stripe error messages that indicate specific states.
_MSG_UNSUPPORTED_INTEGRATION: str = "integration_surface_unsupported"
_MSG_LIVE_MODE_KEYS: str = "testmode_charges_only"
_MSG_INVALID_KEY: str = "invalid_request_error"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SkValidationResult:
    """Result of validating a Stripe secret key.

    Attributes:
        key_value: The key that was validated (masked for logging).
        is_valid: Whether the key is valid against Stripe's API.
        key_type: Classified key type.
        account_id: Stripe account ID, if the key is valid.
        account_country: Account country code, if available.
        balance_available: Available balance in the account (list of
            ``{amount, currency}`` dicts).
        balance_currency: Primary balance currency code.
        error_message: Stripe error message if validation failed.
        risk_level: Assessed risk level (``"critical"``, ``"high"``,
            ``"medium"``, ``"low"``, ``"none"``).
        stripe_key: Updated :class:`StripeKey` model with validation
            results, or ``None`` if the key was not provided as a
            model.
    """

    key_value: str = ""
    is_valid: bool = False
    key_type: KeyType = KeyType.OTHER
    account_id: str = ""
    account_country: str = ""
    balance_available: list[dict[str, Any]] = field(default_factory=list)
    balance_currency: str = ""
    error_message: str = ""
    risk_level: str = "none"
    stripe_key: StripeKey | None = None


@dataclass
class PkTestResult:
    """Result of testing a Stripe public key for tokenization.

    Attributes:
        key_value: The key that was tested (masked).
        tokenization_status: ``"ok"``, ``"blocked"``, ``"other"``,
            ``"error"``, or empty.
        payment_method_id: The ``pm_`` ID returned on success.
        error_message: Stripe error message if the test failed.
        stripe_key: Updated :class:`StripeKey` model, or ``None``.
    """

    key_value: str = ""
    tokenization_status: str = ""
    payment_method_id: str = ""
    error_message: str = ""
    stripe_key: StripeKey | None = None


# ---------------------------------------------------------------------------
# Stripe tester
# ---------------------------------------------------------------------------


class StripeTester:
    """Validate Stripe keys and test server-side tokenization.

    Args:
        client: A :class:`MassParserClient` for HTTP transport.
        stripe_api_version: Stripe API version string for requests.
    """

    def __init__(
        self,
        client: MassParserClient,
        *,
        stripe_api_version: str = _STRIPE_API_VERSION,
    ) -> None:
        self._client = client
        self._api_version = stripe_api_version

    # ---- Public API: Secret key validation ----------------------------

    async def validate_sk(
        self,
        key: str,
        *,
        stripe_key_model: StripeKey | None = None,
    ) -> SkValidationResult:
        """Validate a Stripe secret key against the Balance API.

        Calls ``/v1/balance`` with the key as Bearer token. A valid
        key returns account info; an invalid key returns an error.

        Args:
            key: The ``sk_live_`` / ``sk_test_`` / ``rk_`` key.
            stripe_key_model: Optional existing :class:`StripeKey`
                model to update with validation results.

        Returns:
            An :class:`SkValidationResult` with the findings.
        """
        result = SkValidationResult(
            key_value=self._mask_key(key),
            key_type=self._classify_key(key),
        )

        headers: dict[str, str] = {
            "Authorization": f"Bearer {key}",
            "Stripe-Version": self._api_version,
        }

        resp = await self._client.get(
            f"{_STRIPE_API_BASE}/v1/balance",
            headers=headers,
            timeout=10.0,
        )

        if resp.error is not None:
            result.error_message = str(resp.error)
            result.risk_level = "low"
            return result

        try:
            data = json.loads(resp.text)
        except Exception:
            result.error_message = "Non-JSON response"
            return result

        # Check for Stripe error.
        if "error" in data:
            err = data["error"]
            result.error_message = err.get("message", "Unknown error")
            result.is_valid = False
            result.risk_level = "none"
            return result

        # Successful balance response = key is valid.
        result.is_valid = True
        result.account_id = data.get("account", "")

        # Extract balance info.
        available = data.get("available", [])
        if isinstance(available, list):
            result.balance_available = [
                {"amount": item.get("amount", 0), "currency": item.get("currency", "")}
                for item in available
                if isinstance(item, dict)
            ]
            if result.balance_available:
                result.balance_currency = result.balance_available[0].get("currency", "")

        # Assess risk.
        if key.startswith("sk_live_"):
            result.risk_level = "critical"
        elif key.startswith("rk_live_"):
            result.risk_level = "high"
        elif key.startswith("sk_test_"):
            result.risk_level = "low"
        else:
            result.risk_level = "medium"

        # Update the model if provided.
        if stripe_key_model is not None:
            metadata = dict(stripe_key_model.metadata)
            metadata["validation_status"] = "valid"
            metadata["account_id"] = result.account_id
            metadata["risk_level"] = result.risk_level
            if result.balance_currency:
                metadata["balance_currency"] = result.balance_currency

            result.stripe_key = StripeKey(
                id=stripe_key_model.id,
                key_value=stripe_key_model.key_value,
                key_type=result.key_type,
                discovered_at=stripe_key_model.discovered_at,
                source_url=stripe_key_model.source_url,
                is_valid=True,
                metadata=metadata,
            )

        _LOGGER.info(
            "automation.stripe_tester.sk_validated",
            key_prefix=key[:8] + "...",
            is_valid=result.is_valid,
            risk_level=result.risk_level,
        )

        return result

    # ---- Public API: Public key tokenization test ---------------------

    async def test_pk_tokenization(
        self,
        key: str,
        *,
        stripe_key_model: StripeKey | None = None,
    ) -> PkTestResult:
        """Test server-side tokenization with a Stripe public key.

        Attempts to create a ``payment_method`` via Stripe's public
        API using the test card ``4242 4242 4242 4242``.

        Args:
            key: The ``pk_live_`` key to test.
            stripe_key_model: Optional :class:`StripeKey` model to
                update.

        Returns:
            A :class:`PkTestResult` with the tokenization outcome.
        """
        result = PkTestResult(key_value=self._mask_key(key))

        headers: dict[str, str] = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://js.stripe.com",
            "Referer": "https://js.stripe.com/",
            "Stripe-Version": self._api_version,
        }

        data: dict[str, str] = {
            "type": "card",
            "card[number]": _TEST_CARD_NUMBER,
            "card[exp_month]": _TEST_CARD_EXP_MONTH,
            "card[exp_year]": _TEST_CARD_EXP_YEAR,
            "card[cvc]": _TEST_CARD_CVC,
        }

        resp = await self._client.post(
            f"{_STRIPE_API_BASE}/v1/payment_methods",
            data=data,
            headers=headers,
            timeout=10.0,
        )

        if resp.error is not None:
            result.error_message = str(resp.error)
            result.tokenization_status = "error"
            return result

        try:
            body = json.loads(resp.text)
        except Exception:
            result.error_message = "Non-JSON response"
            result.tokenization_status = "error"
            return result

        # Successful payment_method creation.
        if body.get("object") == "payment_method":
            result.tokenization_status = "ok"
            result.payment_method_id = body.get("id", "")
        else:
            # Error analysis.
            err = body.get("error", {})
            err_msg = err.get("message", "").lower()
            err_code = err.get("code", "").lower()
            result.error_message = err.get("message", "")

            if _MSG_UNSUPPORTED_INTEGRATION in err_msg or _MSG_UNSUPPORTED_INTEGRATION in err_code:
                result.tokenization_status = "blocked"
            elif "declined" in err_msg or "live mode" in err_msg:
                # Test card declined in live mode = tokenization WORKS.
                result.tokenization_status = "ok"
            elif _MSG_LIVE_MODE_KEYS in err_msg:
                result.tokenization_status = "blocked"
            else:
                result.tokenization_status = "other"

        # Update the model if provided.
        if stripe_key_model is not None:
            metadata = dict(stripe_key_model.metadata)
            metadata["tokenization_status"] = result.tokenization_status
            if result.payment_method_id:
                metadata["payment_method_id"] = result.payment_method_id

            result.stripe_key = StripeKey(
                id=stripe_key_model.id,
                key_value=stripe_key_model.key_value,
                key_type=stripe_key_model.key_type,
                discovered_at=stripe_key_model.discovered_at,
                source_url=stripe_key_model.source_url,
                is_valid=stripe_key_model.is_valid,
                metadata=metadata,
            )

        _LOGGER.info(
            "automation.stripe_tester.pk_tested",
            key_prefix=key[:8] + "...",
            status=result.tokenization_status,
        )

        return result

    # ---- Internal -----------------------------------------------------

    @staticmethod
    def _mask_key(key: str) -> str:
        """Mask a Stripe key for safe logging."""
        if len(key) <= 12:
            return key[:4] + "..." + key[-4:]
        return key[:8] + "..." + key[-4:]

    @staticmethod
    def _classify_key(key: str) -> KeyType:
        """Classify a Stripe key by prefix."""
        if key.startswith("sk_live_") or key.startswith("rk_live_"):
            return KeyType.SK_LIVE
        if key.startswith("pk_live_"):
            return KeyType.PK_LIVE
        return KeyType.OTHER
