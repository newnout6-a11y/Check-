"""Certificate Transparency discovery via crt.sh.

Certificate Transparency (CT) logs are public, append-only records
of every TLS certificate issued by trusted CAs. crt.sh
(https://crt.sh) is a free public mirror of these logs with a JSON
search API, which makes it the closest free analogue of FOFA /
Shodan for hostname discovery.

Why CT discovery is useful:

* Free, no API key required.
* Returns every (sub)domain that has ever had a public certificate
  for the searched organisation, identity, or domain pattern.
  Modern issuers (Let's Encrypt, Sectigo, DigiCert, ...) all log
  to CT, so coverage is broad.
* The result set surfaces forgotten staging hosts, dev mirrors,
  and CDN endpoints that a website owner typically does not
  advertise.

Module surface mirrors :mod:`webrecon.discovery.fofa`:

* :class:`CrtShError` / :class:`CrtShApiError` -- exception hierarchy.
* :class:`CrtShEntry` -- one row of a crt.sh search response.
* :class:`CrtShClient` -- async client with :py:meth:`search` and
  :py:meth:`search_to_assets`.

Validates: Requirement 1.x extension (free Certificate Transparency
based discovery as a fallback when paid intelligence sources are
unavailable).
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from uuid import uuid4

import httpx

from webrecon.core.models import (
    AssetStatus,
    DiscoverySource,
    WebsiteAsset,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


__all__ = [
    "CrtShApiError",
    "CrtShClient",
    "CrtShEntry",
    "CrtShError",
    "RateLimiter",
]


_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


_DEFAULT_BASE_URL: str = "https://crt.sh"
_REQUEST_TIMEOUT_SECONDS: float = 60.0  # crt.sh is occasionally slow.
_MAX_RETRIES: int = 3
_BACKOFF_BASE_SECONDS: float = 2.0
_BACKOFF_JITTER_SECONDS: float = 1.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CrtShError(Exception):
    """Base class for every crt.sh-related runtime error."""


class CrtShApiError(CrtShError):
    """Raised when crt.sh returns a non-success response.

    Attributes:
        status_code: HTTP status code (or ``None`` if the failure
            happened before a response was received).
        body: Response body preserved verbatim for diagnostics.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


# ---------------------------------------------------------------------------
# Rate-limiter protocol (mirrors fofa/shodan/serper)
# ---------------------------------------------------------------------------


@runtime_checkable
class RateLimiter(Protocol):
    """Minimal awaitable rate limiter consumed by :class:`CrtShClient`."""

    async def acquire(self) -> None:
        """Block until the caller is allowed to issue one request."""


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrtShEntry:
    """One row of a crt.sh search response.

    The crt.sh JSON shape includes ``id``, ``logged_at``,
    ``not_before``, ``not_after``, ``common_name``, ``name_value``
    (newline-separated SAN list), and ``issuer_name``. The dataclass
    surfaces the fields most useful for discovery and keeps the raw
    payload for callers that want richer metadata.
    """

    common_name: str
    name_value: str
    issuer_name: str
    not_before: str
    not_after: str
    raw: dict[str, Any]

    def hostnames(self) -> tuple[str, ...]:
        """Return every hostname recorded on this certificate.

        ``name_value`` is newline-separated; some issuers also include
        ``*.example.com`` wildcards which are normalised by stripping
        the leading wildcard component.
        """
        result: list[str] = []
        seen: set[str] = set()
        # Common name first (sometimes missing from name_value).
        for raw in (self.common_name, self.name_value):
            for line in raw.splitlines():
                host = line.strip().lstrip("*.").lower()
                if not host or host in seen:
                    continue
                seen.add(host)
                result.append(host)
        return tuple(result)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class CrtShClient:
    """Asynchronous client for crt.sh's JSON search endpoint.

    crt.sh accepts queries via the ``q=`` parameter; a leading ``%``
    enables substring matches (``%example.com`` returns every cert
    whose CN/SAN contains ``example.com``). The client expects the
    caller to supply the literal query string they want, including
    the wildcard if needed.

    Example::

        async with httpx.AsyncClient() as http:
            client = CrtShClient(http)
            async for asset in client.search_to_assets("%example.com"):
                print(asset.url)
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._http = http_client
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = rate_limiter

    async def search(self, query: str) -> AsyncIterator[CrtShEntry]:
        """Iterate crt.sh search results for ``query``.

        crt.sh returns the entire result set in a single JSON
        response (no pagination), so the iterator yields once-per-row
        without any further round-trips.
        """
        if not query.strip():
            raise ValueError("crt.sh query must be non-empty")

        payload = await self._fetch(query)
        rows = payload if isinstance(payload, list) else []

        log = _LOGGER.bind(crtsh_query_length=len(query), result_count=len(rows))
        log.info("crtsh.search.complete")

        for row in rows:
            if not isinstance(row, dict):
                continue
            yield CrtShEntry(
                common_name=str(row.get("common_name") or ""),
                name_value=str(row.get("name_value") or ""),
                issuer_name=str(row.get("issuer_name") or ""),
                not_before=str(row.get("not_before") or ""),
                not_after=str(row.get("not_after") or ""),
                raw=dict(row),
            )

    async def search_to_assets(
        self,
        query: str,
        *,
        scheme: str = "https",
        discovery_source: DiscoverySource = DiscoverySource.MANUAL,
    ) -> AsyncIterator[WebsiteAsset]:
        """Yield :class:`WebsiteAsset` instances, one per unique hostname.

        Each certificate may contribute multiple SAN-listed hostnames;
        the iterator deduplicates per call so a hostname surfacing on
        ten different certs only produces one asset. ``scheme``
        defaults to ``"https"`` because hostnames discovered through
        TLS certificates trivially expose at least one HTTPS service.

        ``discovery_source`` defaults to :class:`DiscoverySource.MANUAL`
        to keep the existing enum intact; operators that want a
        dedicated marker can extend the enum or override the value.
        """
        seen: set[str] = set()
        async for entry in self.search(query):
            for host in entry.hostnames():
                if host in seen:
                    continue
                seen.add(host)
                url = f"{scheme}://{host}"
                now = datetime.now(timezone.utc)
                yield WebsiteAsset(
                    id=uuid4().hex,
                    url=url,
                    normalized_url=url,
                    discovered_at=now,
                    last_checked=now,
                    status=AssetStatus.UNKNOWN,
                    discovery_source=discovery_source,
                    metadata={
                        "crtsh_issuer": entry.issuer_name,
                        "crtsh_not_before": entry.not_before,
                        "crtsh_not_after": entry.not_after,
                    },
                )

    # ---- Internal -----------------------------------------------------

    async def _fetch(self, query: str) -> Any:
        """Issue the JSON search request with retry + backoff."""
        url = f"{self._base_url}/"
        params = {"q": query, "output": "json"}

        last_error: CrtShError | None = None
        for attempt in range(_MAX_RETRIES):
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()
            try:
                response = await self._http.get(
                    url, params=params, timeout=_REQUEST_TIMEOUT_SECONDS
                )
            except httpx.HTTPError as exc:
                last_error = CrtShApiError(f"crt.sh transport error: {exc}")
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last_error = CrtShApiError(
                    f"crt.sh transient error (HTTP {response.status_code})",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code >= 400:
                raise CrtShApiError(
                    f"crt.sh returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            try:
                return response.json()
            except ValueError as exc:
                raise CrtShApiError(
                    "crt.sh returned non-JSON payload",
                    status_code=response.status_code,
                    body=_safe_text(response),
                ) from exc

        if last_error is not None:
            raise last_error
        raise CrtShApiError("crt.sh request failed after retries")

    @staticmethod
    async def _sleep_for_retry(attempt: int) -> None:
        delay = _BACKOFF_BASE_SECONDS * (2**attempt)
        delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
        await asyncio.sleep(delay)


def _safe_text(response: httpx.Response) -> str:
    try:
        return response.text
    except Exception:  # pragma: no cover - defensive
        return ""
