"""Wayback Machine CDX-API discovery.

The Internet Archive's Wayback Machine exposes a public CDX server
that returns every URL it has archived for a domain. It is free,
requires no API key, and covers ~700 billion captures going back to
1996.

Use cases for `webrecon`:

* Enumerate **every URL ever seen** for a target domain (paths,
  parameters, hidden endpoints) without crawling the live site.
* Find historical leaks: an exposed `.env` that has since been
  removed from the live host is often still archived.
* Discover sibling hosts and CDN endpoints that the live DNS no
  longer publishes.

API reference: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server

Module surface mirrors :mod:`webrecon.discovery.crtsh`:

* :class:`WaybackError` / :class:`WaybackApiError` -- exception hierarchy.
* :class:`WaybackCapture` -- one captured URL with its archive metadata.
* :class:`WaybackClient` -- async client with :py:meth:`search` and
  :py:meth:`search_to_assets`.

Validates: free Wayback-based discovery as a fallback when paid
intelligence sources are unavailable.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from webrecon.core.models import (
    AssetStatus,
    DiscoverySource,
    WebsiteAsset,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence


__all__ = [
    "RateLimiter",
    "WaybackApiError",
    "WaybackCapture",
    "WaybackClient",
    "WaybackError",
]


_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


_DEFAULT_BASE_URL: str = "http://web.archive.org/cdx/search/cdx"
_REQUEST_TIMEOUT_SECONDS: float = 60.0
_MAX_RETRIES: int = 3
_BACKOFF_BASE_SECONDS: float = 2.0
_BACKOFF_JITTER_SECONDS: float = 1.0
# CDX returns rows as JSON arrays; the first row is a header. Default
# fields cover the most common use cases.
_DEFAULT_FIELDS: tuple[str, ...] = (
    "timestamp",
    "original",
    "mimetype",
    "statuscode",
    "digest",
    "length",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class WaybackError(Exception):
    """Base class for every Wayback-related runtime error."""


class WaybackApiError(WaybackError):
    """Raised when the CDX server returns a non-success response.

    Attributes:
        status_code: HTTP status code, or ``None`` if no response
            was received.
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
# Rate-limiter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class RateLimiter(Protocol):
    """Minimal awaitable rate limiter consumed by :class:`WaybackClient`."""

    async def acquire(self) -> None:
        """Block until the caller is allowed to issue one request."""


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WaybackCapture:
    """One archived URL returned by the CDX server.

    Attributes:
        timestamp: ``YYYYMMDDhhmmss`` capture time string.
        original: The original URL that was archived.
        mimetype: MIME type recorded for the capture.
        statuscode: HTTP status code at capture time.
        digest: Content digest (SHA1).
        length: Captured payload length in bytes.
    """

    timestamp: str
    original: str
    mimetype: str
    statuscode: str
    digest: str
    length: str

    @property
    def host(self) -> str:
        """Return the hostname component of :attr:`original`."""
        try:
            return urlsplit(self.original).hostname or ""
        except Exception:  # pragma: no cover - defensive
            return ""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class WaybackClient:
    """Asynchronous client for the Wayback Machine CDX search API.

    The CDX endpoint accepts a URL pattern (``url=`` parameter). With
    ``matchType=domain`` Wayback returns every capture for that
    domain and its subdomains; ``matchType=prefix`` matches by URL
    prefix only.

    Example::

        async with httpx.AsyncClient() as http:
            client = WaybackClient(http)
            async for asset in client.search_to_assets("example.com",
                                                        match_type="domain"):
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
        self._base_url = base_url
        self._rate_limiter = rate_limiter

    async def search(
        self,
        url_pattern: str,
        *,
        match_type: str = "domain",
        limit: int = 1000,
        from_date: str | None = None,
        to_date: str | None = None,
        filter_status: str | None = "200",
        collapse: str | None = "urlkey",
        fields: Sequence[str] | None = None,
    ) -> AsyncIterator[WaybackCapture]:
        """Iterate Wayback CDX results for ``url_pattern``.

        Args:
            url_pattern: Domain or URL pattern to search for.
            match_type: One of ``"exact"``, ``"prefix"``, ``"host"``,
                or ``"domain"`` (the default; also matches subdomains).
            limit: Maximum number of rows to return. CDX caps each
                response at 100k rows; lower the limit to keep
                responses manageable.
            from_date: Optional ``YYYYMMDD`` lower bound on capture
                time.
            to_date: Optional ``YYYYMMDD`` upper bound on capture
                time.
            filter_status: Optional HTTP status filter (default
                ``"200"`` so we only see successful captures).
                Pass ``None`` to disable filtering.
            collapse: Optional dedup field. The default ``"urlkey"``
                collapses identical URLs, returning each unique URL
                once even if it was captured many times.
            fields: Override the columns to fetch. Defaults to
                :data:`_DEFAULT_FIELDS`.

        Yields:
            One :class:`WaybackCapture` per row.
        """
        if not url_pattern.strip():
            raise ValueError("Wayback url_pattern must be non-empty")

        effective_fields = tuple(fields) if fields else _DEFAULT_FIELDS
        params: dict[str, str] = {
            "url": url_pattern,
            "output": "json",
            "matchType": match_type,
            "fl": ",".join(effective_fields),
            "limit": str(limit),
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date
        if filter_status:
            params["filter"] = f"statuscode:{filter_status}"
        if collapse:
            params["collapse"] = collapse

        rows = await self._fetch(params)
        if not rows:
            return

        # CDX JSON output: first row is the header; remaining rows
        # are aligned positionally with that header.
        header = [str(col) for col in rows[0]]
        log = _LOGGER.bind(
            wayback_url=url_pattern,
            match_type=match_type,
            row_count=max(0, len(rows) - 1),
        )
        log.info("wayback.search.complete")

        idx = {name: i for i, name in enumerate(header)}
        for row in rows[1:]:
            if not isinstance(row, list):
                continue
            yield WaybackCapture(
                timestamp=_safe_index(row, idx.get("timestamp")),
                original=_safe_index(row, idx.get("original")),
                mimetype=_safe_index(row, idx.get("mimetype")),
                statuscode=_safe_index(row, idx.get("statuscode")),
                digest=_safe_index(row, idx.get("digest")),
                length=_safe_index(row, idx.get("length")),
            )

    async def search_to_assets(
        self,
        url_pattern: str,
        *,
        match_type: str = "domain",
        limit: int = 1000,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL,
        deduplicate_by_host: bool = True,
    ) -> AsyncIterator[WebsiteAsset]:
        """Yield :class:`WebsiteAsset` instances from CDX captures.

        ``deduplicate_by_host=True`` (the default) returns one asset
        per unique hostname, regardless of how many paths Wayback
        archived for that host. Set it to ``False`` to emit one asset
        per captured URL.
        """
        seen_hosts: set[str] = set()
        async for capture in self.search(
            url_pattern,
            match_type=match_type,
            limit=limit,
        ):
            target_url = capture.original
            host = capture.host
            if not target_url or not host:
                continue
            if deduplicate_by_host:
                if host in seen_hosts:
                    continue
                seen_hosts.add(host)
                target_url = f"https://{host}"

            now = datetime.now(timezone.utc)
            yield WebsiteAsset(
                id=uuid4().hex,
                url=target_url,
                normalized_url=target_url,
                discovered_at=now,
                last_checked=now,
                status=AssetStatus.UNKNOWN,
                discovery_source=discovery_source,
                metadata={
                    "wayback_timestamp": capture.timestamp,
                    "wayback_status": capture.statuscode,
                    "wayback_mimetype": capture.mimetype,
                },
            )

    # ---- Internal -----------------------------------------------------

    async def _fetch(self, params: dict[str, str]) -> list[Any]:
        """Issue the CDX request with retry + backoff."""
        last_error: WaybackError | None = None
        for attempt in range(_MAX_RETRIES):
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()
            try:
                response = await self._http.get(
                    self._base_url,
                    params=params,
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                last_error = WaybackApiError(f"Wayback transport error: {exc}")
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last_error = WaybackApiError(
                    f"Wayback transient error (HTTP {response.status_code})",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code >= 400:
                raise WaybackApiError(
                    f"Wayback returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise WaybackApiError(
                    "Wayback returned non-JSON payload",
                    status_code=response.status_code,
                    body=_safe_text(response),
                ) from exc

            if not isinstance(payload, list):
                raise WaybackApiError(
                    "Wayback returned unexpected JSON shape (not a list)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )
            return payload

        if last_error is not None:
            raise last_error
        raise WaybackApiError("Wayback request failed after retries")

    @staticmethod
    async def _sleep_for_retry(attempt: int) -> None:
        delay = _BACKOFF_BASE_SECONDS * (2**attempt)
        delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
        await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_index(row: list[Any], position: int | None) -> str:
    """Read ``row[position]`` defensively, returning ``""`` on miss."""
    if position is None or position < 0 or position >= len(row):
        return ""
    value = row[position]
    return "" if value is None else str(value)


def _safe_text(response: httpx.Response) -> str:
    try:
        return response.text
    except Exception:  # pragma: no cover - defensive
        return ""
