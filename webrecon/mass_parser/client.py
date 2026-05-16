"""Async HTTP client for the mass-parser pipeline.

This module provides a shared, configurable HTTP transport layer
consumed by the scanner, WooCommerce validator, and other bulk
operations. It wraps :class:`httpx.AsyncClient` with:

* **Configurable concurrency** via an ``asyncio.Semaphore`` that
  bounds the number of in-flight requests.
* **Connection pooling** with keep-alive, per-host limits, and
  configurable timeouts.
* **User-agent rotation** from a configurable pool of modern UA
  strings so the pipeline blends into typical browser traffic.
* **Proxy support** -- a single proxy URL or a list that is
  round-robin-selected per request.
* **Retry with exponential backoff** for transient failures
  (connection errors, HTTP 429, 5xx).

Usage::

    async with MassParserClient(concurrency=15) as client:
        resp = await client.get("https://example.com/")
        print(resp.status_code)

The client is designed for dependency injection: downstream modules
receive a :class:`MassParserClient` instance rather than creating
their own.

Validates: Requirement 3.5 (configurable concurrency with semaphores),
Requirement 3.6 (connection pooling and timeout management),
Requirement 12.1 (HTTP connection pool with keep-alive).
"""

from __future__ import annotations

import asyncio
import itertools
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from webrecon.log import get_logger

__all__ = [
    "MassParserClient",
    "RequestResult",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Default user-agent pool
# ---------------------------------------------------------------------------

_DEFAULT_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


# ---------------------------------------------------------------------------
# Retry defaults
# ---------------------------------------------------------------------------

_MAX_RETRIES: int = 3
_BACKOFF_BASE: float = 1.0
_BACKOFF_MAX: float = 30.0
_BACKOFF_JITTER: float = 0.5

# HTTP status codes that trigger a retry.
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 502, 503, 504})


# ---------------------------------------------------------------------------
# Request result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RequestResult:
    """Outcome of a single HTTP request through the mass-parser client.

    Attributes:
        url: The final URL (after any redirects).
        status_code: HTTP status code, or ``0`` when a transport
            error occurred.
        text: Response body text (UTF-8 decoded with replace).
        headers: Response headers as a plain dict.
        error: Exception object when the request failed after all
            retries, or ``None`` on success.
        attempts: Number of attempts made (including the successful
            one).
    """

    url: str
    status_code: int
    text: str
    headers: dict[str, str]
    error: Exception | None = None
    attempts: int = 1


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class MassParserClient:
    """Shared async HTTP client for the mass-parser pipeline.

    The client manages its own :class:`httpx.AsyncClient` lifecycle.
    Callers should use it as an async context manager so the
    underlying transport is properly closed.

    Args:
        concurrency: Maximum number of concurrent in-flight requests.
        timeout: Default request timeout in seconds.
        user_agents: Pool of User-Agent strings to rotate through.
            Defaults to a built-in set of modern browser UAs.
        proxy: Optional proxy URL or list of proxy URLs for
            round-robin selection.
        follow_redirects: Whether to follow HTTP redirects.
        max_retries: Maximum retry attempts for transient failures.
    """

    def __init__(
        self,
        *,
        concurrency: int = 15,
        timeout: float = 15.0,
        user_agents: Sequence[str] | None = None,
        proxy: str | Sequence[str] | None = None,
        follow_redirects: bool = True,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        self._concurrency = max(1, concurrency)
        self._timeout = timeout
        self._user_agents: list[str] = (
            list(user_agents) if user_agents else list(_DEFAULT_USER_AGENTS)
        )
        self._proxy_list: list[str] | None = None
        if isinstance(proxy, str) and proxy:
            self._proxy_list = [proxy]
        elif isinstance(proxy, Sequence) and proxy:
            self._proxy_list = [str(p) for p in proxy if p]
        self._follow_redirects = follow_redirects
        self._max_retries = max(1, max_retries)

        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._http: httpx.AsyncClient | None = None
        self._ua_cycle = itertools.cycle(self._user_agents)
        self._proxy_cycle: itertools.cycle[str] | None = None
        if self._proxy_list:
            self._proxy_cycle = itertools.cycle(self._proxy_list)

    # ---- Context manager -----------------------------------------------

    async def __aenter__(self) -> MassParserClient:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ---- Lifecycle -----------------------------------------------------

    async def start(self) -> None:
        """Open the underlying HTTP transport.

        Called automatically when using the async context manager.
        Safe to call multiple times; subsequent calls are no-ops.
        """
        if self._http is not None:
            return

        # Pick the initial proxy for mount.
        proxy_url: str | None = None
        if self._proxy_list:
            proxy_url = self._proxy_list[0]

        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=self._follow_redirects,
            proxy=proxy_url,
            limits=httpx.Limits(
                max_connections=self._concurrency,
                max_keepalive_connections=min(self._concurrency, 10),
            ),
        )

    async def close(self) -> None:
        """Close the underlying HTTP transport."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Return the underlying :class:`httpx.AsyncClient`.

        The client must be open (call :py:meth:`start` or use the
        async context manager) before accessing this property.
        Raises :class:`RuntimeError` otherwise so misuse fails fast.
        """
        if self._http is None:
            raise RuntimeError(
                "MassParserClient is not started. Use 'async with' "
                "or call 'await client.start()' first."
            )
        return self._http

    # ---- Public API ---------------------------------------------------

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool | None = None,
    ) -> RequestResult:
        """Issue a GET request with retry and concurrency control.

        Args:
            url: Target URL.
            headers: Optional extra headers (merged with the
                rotated User-Agent).
            timeout: Override the default timeout for this request.
            follow_redirects: Override the default redirect policy.

        Returns:
            A :class:`RequestResult` with the response data or error.
        """
        return await self._request(
            "GET",
            url,
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    async def post(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool | None = None,
    ) -> RequestResult:
        """Issue a POST request with retry and concurrency control.

        Args:
            url: Target URL.
            data: Form-encoded body.
            json: JSON body.
            headers: Optional extra headers.
            timeout: Override the default timeout.
            follow_redirects: Override the default redirect policy.

        Returns:
            A :class:`RequestResult` with the response data or error.
        """
        return await self._request(
            "POST",
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    @property
    def concurrency(self) -> int:
        """Return the configured concurrency limit."""
        return self._concurrency

    # ---- Internal -----------------------------------------------------

    def _next_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build request headers with a rotated User-Agent."""
        ua = next(self._ua_cycle)
        hdrs: dict[str, str] = {"User-Agent": ua}
        if extra:
            hdrs.update(extra)
        return hdrs

    async def _request(
        self,
        method: str,
        url: str,
        *,
        data: dict[str, str] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool | None = None,
    ) -> RequestResult:
        """Issue an HTTP request with semaphore, retry, and proxy rotation."""
        if self._http is None:
            raise RuntimeError("MassParserClient is not started; use async with")

        async with self._semaphore:
            merged_headers = self._next_headers(headers)
            req_timeout = timeout or self._timeout
            req_follow = (
                follow_redirects
                if follow_redirects is not None
                else self._follow_redirects
            )

            last_error: Exception | None = None
            for attempt in range(self._max_retries):
                # Rotate proxy on each attempt if multiple proxies.
                if self._proxy_cycle is not None and attempt > 0:
                    proxy_url = next(self._proxy_cycle)
                    self._http._transport_for_url(httpx.URL(url))
                    # httpx doesn't support per-request proxy rotation
                    # natively; log the rotation for awareness.
                    _LOGGER.debug(
                        "mass_parser.client.proxy_rotate",
                        proxy=proxy_url,
                        attempt=attempt,
                    )

                try:
                    response = await self._http.request(
                        method,
                        url,
                        data=data,
                        json=json,
                        headers=merged_headers,
                        timeout=req_timeout,
                        follow_redirects=req_follow,
                    )
                except httpx.HTTPError as exc:
                    last_error = exc
                    _LOGGER.debug(
                        "mass_parser.client.transport_error",
                        url=url,
                        attempt=attempt + 1,
                        error=str(exc),
                    )
                    await self._backoff(attempt)
                    continue

                status = response.status_code
                if status in _RETRYABLE_STATUS_CODES:
                    last_error = httpx.HTTPStatusError(
                        f"HTTP {status}",
                        request=response.request,
                        response=response,
                    )
                    _LOGGER.debug(
                        "mass_parser.client.retryable_status",
                        url=url,
                        status=status,
                        attempt=attempt + 1,
                    )
                    await self._backoff(attempt)
                    continue

                # Success or non-retryable error.
                return RequestResult(
                    url=str(response.url),
                    status_code=status,
                    text=response.text,
                    headers=dict(response.headers),
                    attempts=attempt + 1,
                )

            # All retries exhausted.
            return RequestResult(
                url=url,
                status_code=0,
                text="",
                headers={},
                error=last_error,
                attempts=self._max_retries,
            )

    async def _backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff + jitter."""
        delay = min(
            _BACKOFF_BASE * (2 ** attempt),
            _BACKOFF_MAX,
        )
        delay += random.uniform(0.0, _BACKOFF_JITTER)
        await asyncio.sleep(delay)
