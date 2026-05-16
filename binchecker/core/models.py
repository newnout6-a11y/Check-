"""Immutable data models and string enums for the binchecker package.

All public types in this module are frozen dataclasses or string enums so
they can be safely shared across asyncio tasks. Each dataclass exposes
``to_dict`` / ``from_dict`` helpers that round-trip through JSON-friendly
dictionaries: ``datetime`` values become ISO 8601 strings, enums become
their string values, tuples become lists, paths become strings, and
nested dataclasses are converted recursively.

This module is part of the pure ``core`` layer and intentionally has no
I/O dependencies (no networking, no filesystem reads).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone  # noqa: F401  (timezone re-exported for callers)
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

try:  # Python 3.11+
    from enum import StrEnum
except ImportError:  # pragma: no cover - 3.10 fallback
    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Backport of :class:`enum.StrEnum` for Python 3.10.

        Members are subclasses of :class:`str` so they serialize cleanly
        through ``json.dumps`` and compare equal to their string values.
        """

        def __new__(cls, value: str) -> "StrEnum":
            obj = str.__new__(cls, value)
            obj._value_ = value
            return obj

        def __str__(self) -> str:  # type: ignore[override]
            return str.__str__(self)


__all__ = [
    # enums
    "CardBrand",
    "CardType",
    "LiveStatus",
    "FailureStep",
    # data models
    "CardData",
    "BINInfo",
    "LiveCheckResult",
    "CardCheckResult",
    "GatewayMatch",
    "SiteCheckResult",
    "BatchSummary",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CardBrand(StrEnum):
    """Card network brand detected from a PAN's leading digits."""

    VISA = "VISA"
    MASTERCARD = "MASTERCARD"
    AMEX = "AMEX"
    DISCOVER = "DISCOVER"
    JCB = "JCB"
    DINERS = "DINERS"
    UNIONPAY = "UNIONPAY"
    MAESTRO = "MAESTRO"
    VISA_ELECTRON = "VISA_ELECTRON"
    UNKNOWN = "UNKNOWN"


class CardType(StrEnum):
    """Funding type returned by BIN lookup providers."""

    DEBIT = "DEBIT"
    CREDIT = "CREDIT"
    PREPAID = "PREPAID"
    UNKNOWN = "UNKNOWN"


class LiveStatus(StrEnum):
    """Outcome of a live-check tokenization / authorization attempt."""

    LIVE = "LIVE"
    DEAD = "DEAD"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class FailureStep(StrEnum):
    """Pipeline step at which validation first failed.

    Values mirror the strict 7-step sequence defined in the design doc:
    Luhn → brand/length → expiry → CVV → BIN lookup → live check.
    """

    LUHN = "luhn"
    BRAND_LENGTH = "brand_length"
    EXPIRY = "expiry"
    CVV = "cvv"
    BIN_LOOKUP = "bin_lookup"
    LIVE_CHECK = "live_check"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a value into a ``datetime`` or ``None``.

    Accepts ``None``, ``datetime`` instances, or ISO 8601 strings.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    raise TypeError(f"Cannot parse datetime from {type(value).__name__}")


def _parse_str_tuple(value: Any) -> tuple[str, ...]:
    """Coerce an iterable (or ``None``) to a ``tuple[str, ...]``."""
    if value is None:
        return ()
    return tuple(str(item) for item in value)


# ---------------------------------------------------------------------------
# Card data
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CardData:
    """Parsed card input. Only ``pan`` is required; all other fields are
    optional because some flows (BIN-only lookup) do not need them."""

    pan: str
    month: int | None = None
    year: int | None = None
    cvv: str | None = None
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pan": self.pan,
            "month": self.month,
            "year": self.year,
            "cvv": self.cvv,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CardData":
        return cls(
            pan=data["pan"],
            month=data.get("month"),
            year=data.get("year"),
            cvv=data.get("cvv"),
            raw=data.get("raw", ""),
        )


# ---------------------------------------------------------------------------
# BIN info
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BINInfo:
    """Result of a BIN lookup against an external provider."""

    bin_code: str
    scheme: str = ""
    card_type: CardType = CardType.UNKNOWN
    brand: str = ""
    bank_name: str = ""
    bank_url: str = ""
    country: str = ""
    country_code: str = ""
    prepaid: bool | None = None
    source: str = ""
    fetched_at: datetime | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "bin_code": self.bin_code,
            "scheme": self.scheme,
            "card_type": self.card_type.value,
            "brand": self.brand,
            "bank_name": self.bank_name,
            "bank_url": self.bank_url,
            "country": self.country,
            "country_code": self.country_code,
            "prepaid": self.prepaid,
            "source": self.source,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BINInfo":
        card_type_raw = data.get("card_type")
        return cls(
            bin_code=data["bin_code"],
            scheme=data.get("scheme", ""),
            card_type=CardType(card_type_raw) if card_type_raw else CardType.UNKNOWN,
            brand=data.get("brand", ""),
            bank_name=data.get("bank_name", ""),
            bank_url=data.get("bank_url", ""),
            country=data.get("country", ""),
            country_code=data.get("country_code", ""),
            prepaid=data.get("prepaid"),
            source=data.get("source", ""),
            fetched_at=_parse_datetime(data.get("fetched_at")),
            error=data.get("error", ""),
        )


# ---------------------------------------------------------------------------
# Live check result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LiveCheckResult:
    """Outcome of a live-check attempt against a payment backend."""

    status: LiveStatus
    backend: str
    decline_reason: str = ""
    auth_code: str = ""
    fingerprint: str = ""
    network_status: str = ""
    risk_score: str = ""
    raw_response_id: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "backend": self.backend,
            "decline_reason": self.decline_reason,
            "auth_code": self.auth_code,
            "fingerprint": self.fingerprint,
            "network_status": self.network_status,
            "risk_score": self.risk_score,
            "raw_response_id": self.raw_response_id,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LiveCheckResult":
        return cls(
            status=LiveStatus(data["status"]),
            backend=data["backend"],
            decline_reason=data.get("decline_reason", ""),
            auth_code=data.get("auth_code", ""),
            fingerprint=data.get("fingerprint", ""),
            network_status=data.get("network_status", ""),
            risk_score=data.get("risk_score", ""),
            raw_response_id=data.get("raw_response_id", ""),
            error=data.get("error", ""),
        )


# ---------------------------------------------------------------------------
# Card check result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CardCheckResult:
    """Aggregate result of a single card validation pipeline run."""

    card: CardData
    brand: CardBrand
    luhn_valid: bool
    expired: bool
    cvv_valid: bool
    bin_info: BINInfo | None
    live_result: LiveCheckResult | None
    failure_step: FailureStep | None
    failure_reason: str
    duration_ms: int
    timestamp: datetime
    schema_version: str = "1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "card": self.card.to_dict(),
            "brand": self.brand.value,
            "luhn_valid": self.luhn_valid,
            "expired": self.expired,
            "cvv_valid": self.cvv_valid,
            "bin_info": self.bin_info.to_dict() if self.bin_info is not None else None,
            "live_result": self.live_result.to_dict() if self.live_result is not None else None,
            "failure_step": self.failure_step.value if self.failure_step is not None else None,
            "failure_reason": self.failure_reason,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CardCheckResult":
        bin_raw = data.get("bin_info")
        live_raw = data.get("live_result")
        failure_raw = data.get("failure_step")
        timestamp = _parse_datetime(data["timestamp"])
        if timestamp is None:
            raise ValueError("CardCheckResult.timestamp is required")
        return cls(
            card=CardData.from_dict(data["card"]),
            brand=CardBrand(data["brand"]),
            luhn_valid=bool(data["luhn_valid"]),
            expired=bool(data["expired"]),
            cvv_valid=bool(data["cvv_valid"]),
            bin_info=BINInfo.from_dict(bin_raw) if bin_raw is not None else None,
            live_result=LiveCheckResult.from_dict(live_raw) if live_raw is not None else None,
            failure_step=FailureStep(failure_raw) if failure_raw is not None else None,
            failure_reason=data.get("failure_reason", ""),
            duration_ms=int(data["duration_ms"]),
            timestamp=timestamp,
            schema_version=data.get("schema_version", "1"),
        )


# ---------------------------------------------------------------------------
# Site-side models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GatewayMatch:
    """A single payment-gateway detection hit on a site's HTML."""

    gateway: str
    confidence: int
    matched_signatures: tuple[str, ...] = ()
    evidence_urls: tuple[str, ...] = ()
    low_confidence: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "gateway": self.gateway,
            "confidence": self.confidence,
            "matched_signatures": list(self.matched_signatures),
            "evidence_urls": list(self.evidence_urls),
            "low_confidence": self.low_confidence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GatewayMatch":
        return cls(
            gateway=data["gateway"],
            confidence=int(data["confidence"]),
            matched_signatures=_parse_str_tuple(data.get("matched_signatures")),
            evidence_urls=_parse_str_tuple(data.get("evidence_urls")),
            low_confidence=bool(data.get("low_confidence", False)),
        )


@dataclass(frozen=True, slots=True)
class SiteCheckResult:
    """Aggregate result of a single site analysis pipeline run."""

    url: str
    reachable: bool
    http_status: int
    redirect_chain: tuple[str, ...]
    gateways: tuple[GatewayMatch, ...]
    antifraud: tuple[str, ...]
    threeds: bool
    threeds_markers: tuple[str, ...]
    ssl_issuer: str
    ssl_country: str
    tld: str
    mcc_hints: tuple[str, ...]
    score: int
    verdict: str
    verdict_detail: str
    duration_ms: int
    timestamp: datetime
    schema_version: str = "1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "http_status": self.http_status,
            "redirect_chain": list(self.redirect_chain),
            "gateways": [g.to_dict() for g in self.gateways],
            "antifraud": list(self.antifraud),
            "threeds": self.threeds,
            "threeds_markers": list(self.threeds_markers),
            "ssl_issuer": self.ssl_issuer,
            "ssl_country": self.ssl_country,
            "tld": self.tld,
            "mcc_hints": list(self.mcc_hints),
            "score": self.score,
            "verdict": self.verdict,
            "verdict_detail": self.verdict_detail,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SiteCheckResult":
        timestamp = _parse_datetime(data["timestamp"])
        if timestamp is None:
            raise ValueError("SiteCheckResult.timestamp is required")
        gateways_raw = data.get("gateways") or ()
        return cls(
            url=data["url"],
            reachable=bool(data["reachable"]),
            http_status=int(data["http_status"]),
            redirect_chain=_parse_str_tuple(data.get("redirect_chain")),
            gateways=tuple(GatewayMatch.from_dict(g) for g in gateways_raw),
            antifraud=_parse_str_tuple(data.get("antifraud")),
            threeds=bool(data.get("threeds", False)),
            threeds_markers=_parse_str_tuple(data.get("threeds_markers")),
            ssl_issuer=data.get("ssl_issuer", ""),
            ssl_country=data.get("ssl_country", ""),
            tld=data.get("tld", ""),
            mcc_hints=_parse_str_tuple(data.get("mcc_hints")),
            score=int(data["score"]),
            verdict=data.get("verdict", ""),
            verdict_detail=data.get("verdict_detail", ""),
            duration_ms=int(data["duration_ms"]),
            timestamp=timestamp,
            schema_version=data.get("schema_version", "1"),
        )


# ---------------------------------------------------------------------------
# Batch summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BatchSummary:
    """End-of-run statistics for a batch processing job."""

    total: int
    successful: int
    failed: int
    errors_by_type: dict[str, int] = field(default_factory=dict)
    avg_ms_per_item: float = 0.0
    peak_memory_mb: float = 0.0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output_files: dict[str, Path] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "successful": self.successful,
            "failed": self.failed,
            "errors_by_type": dict(self.errors_by_type),
            "avg_ms_per_item": self.avg_ms_per_item,
            "peak_memory_mb": self.peak_memory_mb,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "output_files": {k: str(v) for k, v in self.output_files.items()},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BatchSummary":
        errors_raw = data.get("errors_by_type") or {}
        files_raw = data.get("output_files") or {}
        return cls(
            total=int(data["total"]),
            successful=int(data["successful"]),
            failed=int(data["failed"]),
            errors_by_type={str(k): int(v) for k, v in errors_raw.items()},
            avg_ms_per_item=float(data.get("avg_ms_per_item", 0.0)),
            peak_memory_mb=float(data.get("peak_memory_mb", 0.0)),
            started_at=_parse_datetime(data.get("started_at")),
            finished_at=_parse_datetime(data.get("finished_at")),
            output_files={str(k): Path(v) for k, v in files_raw.items()},
        )
