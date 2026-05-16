"""Core data models for the ``webrecon`` package.

This module defines the asset data shapes used across the reconnaissance
pipeline:

* :class:`WebsiteAsset` -- primary asset record for a discovered website.
* :class:`StripeKey` -- discovered Stripe API key with validation state.
* :class:`FormDiscovery` -- a web form found on a website.
* :class:`FormField` -- a single field inside a discovered form.

The dataclasses are intentionally **mutable** (``frozen=False``) because
the pipeline incrementally updates running statistics on
:class:`WebsiteAsset` (``check_count``, ``error_count``,
``success_rate``) and validation state on :class:`StripeKey`
(``is_valid``, ``balance_available``, ``validation_count``). All other
mutation in production code goes through the repository layer.

Every model exposes:

* :py:meth:`to_dict` / :py:meth:`from_dict` -- JSON-friendly dict
  conversion (datetimes become ISO 8601 strings, enums become their
  string values, nested dataclasses are converted recursively).
* :py:meth:`to_json` / :py:meth:`from_json` -- thin :mod:`json` wrappers
  that operate on UTF-8 strings.
* :py:meth:`validate` -- raises :class:`ValueError` when the instance
  violates the domain constraints documented on the method.

This module is part of the pure ``core`` layer and intentionally has no
I/O dependencies (no networking, no filesystem reads).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


# ``enum.StrEnum`` only exists on Python 3.11+. The version-guarded
# branch below gives mypy (configured with ``python_version = 3.10``)
# a concrete class to type-check against while still preferring the
# stdlib implementation at runtime on 3.11+.
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of :class:`enum.StrEnum` for Python 3.10.

        Members subclass :class:`str` so they serialise cleanly through
        :func:`json.dumps` and compare equal to their underlying string
        values.
        """

        def __new__(cls, value: str) -> StrEnum:
            obj = str.__new__(cls, value)
            obj._value_ = value
            return obj

        def __str__(self) -> str:
            return str.__str__(self)


__all__ = [
    "AssetStatus",
    "DiscoverySource",
    "FormDiscovery",
    "FormField",
    "KeyType",
    "StripeKey",
    "WebsiteAsset",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AssetStatus(StrEnum):
    """Operational status of a discovered :class:`WebsiteAsset`."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UNKNOWN = "unknown"


class KeyType(StrEnum):
    """Category of a discovered Stripe key.

    ``PK_LIVE`` and ``SK_LIVE`` correspond to Stripe's publishable and
    secret live keys; ``OTHER`` covers test keys, restricted keys, and
    anything else the discovery layer cannot classify confidently.
    """

    PK_LIVE = "pk_live"
    SK_LIVE = "sk_live"
    OTHER = "other"


class DiscoverySource(StrEnum):
    """Intelligence source that surfaced an asset."""

    FOFA = "fofa"
    SHODAN = "shodan"
    SERPER = "serper"
    GITHUB = "github"
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_datetime(value: Any) -> datetime:
    """Coerce ``value`` into a :class:`datetime` instance.

    Accepts an existing :class:`datetime` or an ISO 8601 string. Raises
    :class:`TypeError` on unsupported types and :class:`ValueError` on
    malformed strings (delegated to :meth:`datetime.fromisoformat`).
    """
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    raise TypeError(
        f"Cannot parse datetime from {type(value).__name__}: {value!r}"
    )


def _parse_optional_datetime(value: Any) -> datetime | None:
    """Like :func:`_parse_datetime` but returns ``None`` for ``None``."""
    if value is None:
        return None
    return _parse_datetime(value)


def _iso_or_none(value: datetime | None) -> str | None:
    """ISO-format ``value`` or return ``None``."""
    return value.isoformat() if value is not None else None


def _str_dict(value: Any) -> dict[str, str]:
    """Coerce ``value`` (or ``None``) to a ``dict[str, str]``."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(
            f"Expected dict for metadata, got {type(value).__name__}"
        )
    return {str(k): str(v) for k, v in value.items()}


def _str_list(value: Any) -> list[str]:
    """Coerce ``value`` (or ``None``) to a ``list[str]``."""
    if value is None:
        return []
    return [str(item) for item in value]


def _now_utc() -> datetime:
    """Return a timezone-aware UTC ``datetime`` (used for validation)."""
    return datetime.now(timezone.utc)


def _is_future(value: datetime, *, tolerance_seconds: float = 1.0) -> bool:
    """Return ``True`` when ``value`` is meaningfully in the future.

    Naive datetimes are compared in UTC; the small ``tolerance_seconds``
    window forgives clock drift between machines that produced the
    timestamp and machines that validate it.
    """
    now = _now_utc()
    if value.tzinfo is None:
        now = now.replace(tzinfo=None)
    delta = (value - now).total_seconds()
    return delta > tolerance_seconds


# ---------------------------------------------------------------------------
# FormField
# ---------------------------------------------------------------------------


@dataclass
class FormField:
    """A single field inside a discovered :class:`FormDiscovery`.

    ``field_type`` mirrors the HTML ``type`` attribute (``text``,
    ``email``, ``password``, ``hidden``, ``checkbox``, ...). It is kept
    as a free-form string rather than an enum because real-world forms
    use a wide variety of custom widget names that cannot be enumerated
    exhaustively.
    """

    name: str
    field_type: str
    required: bool = False
    default_value: str | None = None
    validation_pattern: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    # ---- Serialisation -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "field_type": self.field_type,
            "required": self.required,
            "default_value": self.default_value,
            "validation_pattern": self.validation_pattern,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FormField:
        return cls(
            name=str(data["name"]),
            field_type=str(data["field_type"]),
            required=bool(data.get("required", False)),
            default_value=(
                None if data.get("default_value") is None else str(data["default_value"])
            ),
            validation_pattern=(
                None
                if data.get("validation_pattern") is None
                else str(data["validation_pattern"])
            ),
            metadata=_str_dict(data.get("metadata")),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, payload: str) -> FormField:
        return cls.from_dict(json.loads(payload))

    # ---- Validation ----------------------------------------------------

    def validate(self) -> None:
        """Validate field constraints.

        Raises:
            ValueError: ``name`` or ``field_type`` is empty.
        """
        if not self.name:
            raise ValueError("FormField.name must be non-empty")
        if not self.field_type:
            raise ValueError("FormField.field_type must be non-empty")


# ---------------------------------------------------------------------------
# FormDiscovery
# ---------------------------------------------------------------------------


@dataclass
class FormDiscovery:
    """A web form discovered while crawling a :class:`WebsiteAsset`."""

    id: str
    website_id: str
    url: str
    form_html: str
    fields: list[FormField] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=_now_utc)
    last_tested: datetime | None = None
    has_csrf_token: bool = False
    requires_auth: bool = False
    submission_method: str = "GET"
    action_url: str = ""

    # ---- Serialisation -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "website_id": self.website_id,
            "url": self.url,
            "form_html": self.form_html,
            "fields": [f.to_dict() for f in self.fields],
            "discovered_at": self.discovered_at.isoformat(),
            "last_tested": _iso_or_none(self.last_tested),
            "has_csrf_token": self.has_csrf_token,
            "requires_auth": self.requires_auth,
            "submission_method": self.submission_method,
            "action_url": self.action_url,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FormDiscovery:
        fields_raw = data.get("fields") or []
        return cls(
            id=str(data["id"]),
            website_id=str(data["website_id"]),
            url=str(data["url"]),
            form_html=str(data.get("form_html", "")),
            fields=[FormField.from_dict(f) for f in fields_raw],
            discovered_at=_parse_datetime(data["discovered_at"]),
            last_tested=_parse_optional_datetime(data.get("last_tested")),
            has_csrf_token=bool(data.get("has_csrf_token", False)),
            requires_auth=bool(data.get("requires_auth", False)),
            submission_method=str(data.get("submission_method", "GET")),
            action_url=str(data.get("action_url", "")),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, payload: str) -> FormDiscovery:
        return cls.from_dict(json.loads(payload))

    # ---- Validation ----------------------------------------------------

    def validate(self) -> None:
        """Validate :class:`FormDiscovery` constraints.

        Raises:
            ValueError: identifiers are empty, the URL is empty, the
                submission method is not a recognised HTTP verb,
                ``discovered_at`` is in the future, ``last_tested`` is
                before ``discovered_at``, or any nested
                :class:`FormField` fails validation.
        """
        if not self.id:
            raise ValueError("FormDiscovery.id must be non-empty")
        if not self.website_id:
            raise ValueError("FormDiscovery.website_id must be non-empty")
        if not self.url:
            raise ValueError("FormDiscovery.url must be non-empty")
        method = self.submission_method.upper()
        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if method not in allowed_methods:
            raise ValueError(
                f"FormDiscovery.submission_method must be one of {sorted(allowed_methods)}, "
                f"got {self.submission_method!r}"
            )
        if _is_future(self.discovered_at):
            raise ValueError("FormDiscovery.discovered_at must not be in the future")
        if self.last_tested is not None and self.last_tested < self.discovered_at:
            raise ValueError(
                "FormDiscovery.last_tested must not predate discovered_at"
            )
        for f in self.fields:
            f.validate()


# ---------------------------------------------------------------------------
# StripeKey
# ---------------------------------------------------------------------------


@dataclass
class StripeKey:
    """A Stripe API key surfaced by the discovery pipeline.

    The model carries both the raw key value and the validation state
    accumulated from official Stripe API calls. ``balance_available``
    holds the structured balance payload (a list of currency-amount
    dicts) returned by Stripe when ``key_type`` is ``SK_LIVE``.
    """

    id: str
    key_value: str
    key_type: KeyType
    discovered_at: datetime
    source_url: str
    validated_at: datetime | None = None
    is_valid: bool = False
    source_file: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    balance_available: list[dict[str, Any]] | None = None
    error_message: str | None = None
    validation_count: int = 0

    # ---- Serialisation -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key_value": self.key_value,
            "key_type": self.key_type.value,
            "discovered_at": self.discovered_at.isoformat(),
            "validated_at": _iso_or_none(self.validated_at),
            "is_valid": self.is_valid,
            "source_url": self.source_url,
            "source_file": self.source_file,
            "metadata": dict(self.metadata),
            "balance_available": (
                None
                if self.balance_available is None
                else [dict(item) for item in self.balance_available]
            ),
            "error_message": self.error_message,
            "validation_count": self.validation_count,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StripeKey:
        balance_raw = data.get("balance_available")
        if balance_raw is None:
            balance: list[dict[str, Any]] | None = None
        else:
            balance = [dict(item) for item in balance_raw]
        return cls(
            id=str(data["id"]),
            key_value=str(data["key_value"]),
            key_type=KeyType(data["key_type"]),
            discovered_at=_parse_datetime(data["discovered_at"]),
            source_url=str(data["source_url"]),
            validated_at=_parse_optional_datetime(data.get("validated_at")),
            is_valid=bool(data.get("is_valid", False)),
            source_file=(
                None if data.get("source_file") is None else str(data["source_file"])
            ),
            metadata=_str_dict(data.get("metadata")),
            balance_available=balance,
            error_message=(
                None if data.get("error_message") is None else str(data["error_message"])
            ),
            validation_count=int(data.get("validation_count", 0)),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, payload: str) -> StripeKey:
        return cls.from_dict(json.loads(payload))

    # ---- Validation ----------------------------------------------------

    def validate(self) -> None:
        """Validate :class:`StripeKey` constraints.

        Raises:
            ValueError: identifiers or key value are empty, key type
                does not match the key prefix, ``source_url`` is empty,
                ``validation_count`` is negative, ``discovered_at`` is
                in the future, ``validated_at`` is in the future, or
                ``validated_at`` predates ``discovered_at``.
        """
        if not self.id:
            raise ValueError("StripeKey.id must be non-empty")
        if not self.key_value:
            raise ValueError("StripeKey.key_value must be non-empty")
        if not self.source_url:
            raise ValueError("StripeKey.source_url must be non-empty")
        if self.validation_count < 0:
            raise ValueError(
                "StripeKey.validation_count must be non-negative, "
                f"got {self.validation_count}"
            )
        if self.key_type is KeyType.PK_LIVE and not self.key_value.startswith("pk_"):
            raise ValueError(
                "StripeKey.key_value must start with 'pk_' when key_type is PK_LIVE"
            )
        if self.key_type is KeyType.SK_LIVE and not self.key_value.startswith("sk_"):
            raise ValueError(
                "StripeKey.key_value must start with 'sk_' when key_type is SK_LIVE"
            )
        if _is_future(self.discovered_at):
            raise ValueError("StripeKey.discovered_at must not be in the future")
        if self.validated_at is not None:
            if _is_future(self.validated_at):
                raise ValueError("StripeKey.validated_at must not be in the future")
            if self.validated_at < self.discovered_at:
                raise ValueError(
                    "StripeKey.validated_at must not predate discovered_at"
                )


# ---------------------------------------------------------------------------
# WebsiteAsset
# ---------------------------------------------------------------------------


@dataclass
class WebsiteAsset:
    """Primary asset record for a discovered website.

    The model aggregates every signal the pipeline collects about a
    target: identification (``url``, ``normalized_url``), provenance
    (``discovery_source``, ``discovered_at``), reachability state
    (``status``, ``last_checked``, ``check_count``, ``error_count``,
    ``success_rate``), and the application-layer findings (Stripe keys,
    WooCommerce metadata, technology stack).
    """

    id: str
    url: str
    normalized_url: str
    discovered_at: datetime
    last_checked: datetime
    status: AssetStatus
    discovery_source: DiscoverySource
    technology_stack: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    # Stripe-related fields
    stripe_keys: list[StripeKey] = field(default_factory=list)
    tokenization_status: str | None = None
    stripe_plugin_version: str | None = None

    # WooCommerce fields
    woocommerce_version: str | None = None
    store_api_available: bool = False
    country: str | None = None
    currency: str | None = None

    # Statistics
    check_count: int = 0
    error_count: int = 0
    success_rate: float = 0.0

    # ---- Serialisation -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "discovered_at": self.discovered_at.isoformat(),
            "last_checked": self.last_checked.isoformat(),
            "status": self.status.value,
            "technology_stack": list(self.technology_stack),
            "discovery_source": self.discovery_source.value,
            "metadata": dict(self.metadata),
            "stripe_keys": [k.to_dict() for k in self.stripe_keys],
            "tokenization_status": self.tokenization_status,
            "stripe_plugin_version": self.stripe_plugin_version,
            "woocommerce_version": self.woocommerce_version,
            "store_api_available": self.store_api_available,
            "country": self.country,
            "currency": self.currency,
            "check_count": self.check_count,
            "error_count": self.error_count,
            "success_rate": self.success_rate,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> WebsiteAsset:
        keys_raw = data.get("stripe_keys") or []
        return cls(
            id=str(data["id"]),
            url=str(data["url"]),
            normalized_url=str(data["normalized_url"]),
            discovered_at=_parse_datetime(data["discovered_at"]),
            last_checked=_parse_datetime(data["last_checked"]),
            status=AssetStatus(data["status"]),
            discovery_source=DiscoverySource(data["discovery_source"]),
            technology_stack=_str_list(data.get("technology_stack")),
            metadata=_str_dict(data.get("metadata")),
            stripe_keys=[StripeKey.from_dict(k) for k in keys_raw],
            tokenization_status=(
                None
                if data.get("tokenization_status") is None
                else str(data["tokenization_status"])
            ),
            stripe_plugin_version=(
                None
                if data.get("stripe_plugin_version") is None
                else str(data["stripe_plugin_version"])
            ),
            woocommerce_version=(
                None
                if data.get("woocommerce_version") is None
                else str(data["woocommerce_version"])
            ),
            store_api_available=bool(data.get("store_api_available", False)),
            country=(None if data.get("country") is None else str(data["country"])),
            currency=(None if data.get("currency") is None else str(data["currency"])),
            check_count=int(data.get("check_count", 0)),
            error_count=int(data.get("error_count", 0)),
            success_rate=float(data.get("success_rate", 0.0)),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, payload: str) -> WebsiteAsset:
        return cls.from_dict(json.loads(payload))

    # ---- Validation ----------------------------------------------------

    def validate(self) -> None:
        """Validate :class:`WebsiteAsset` constraints.

        Raises:
            ValueError: identifiers are empty, URLs are empty,
                statistics are out of range (counts negative,
                ``success_rate`` outside ``[0, 1]``, ``error_count``
                exceeds ``check_count``), timestamps disagree
                (``discovered_at`` in the future, ``last_checked``
                before ``discovered_at`` or in the future), or any
                nested :class:`StripeKey` fails validation.
        """
        if not self.id:
            raise ValueError("WebsiteAsset.id must be non-empty")
        if not self.url:
            raise ValueError("WebsiteAsset.url must be non-empty")
        if not self.normalized_url:
            raise ValueError("WebsiteAsset.normalized_url must be non-empty")
        if self.check_count < 0:
            raise ValueError(
                f"WebsiteAsset.check_count must be non-negative, got {self.check_count}"
            )
        if self.error_count < 0:
            raise ValueError(
                f"WebsiteAsset.error_count must be non-negative, got {self.error_count}"
            )
        if self.error_count > self.check_count:
            raise ValueError(
                "WebsiteAsset.error_count must not exceed check_count "
                f"({self.error_count} > {self.check_count})"
            )
        if not 0.0 <= self.success_rate <= 1.0:
            raise ValueError(
                f"WebsiteAsset.success_rate must be in [0, 1], got {self.success_rate}"
            )
        if _is_future(self.discovered_at):
            raise ValueError("WebsiteAsset.discovered_at must not be in the future")
        if _is_future(self.last_checked):
            raise ValueError("WebsiteAsset.last_checked must not be in the future")
        if self.last_checked < self.discovered_at:
            raise ValueError(
                "WebsiteAsset.last_checked must not predate discovered_at"
            )
        for key in self.stripe_keys:
            key.validate()
