"""Rate limiter implementations for the ``webrecon`` safety layer.

This module provides the concrete rate-limiter classes that satisfy
the :class:`RateLimiter` protocol declared in
:mod:`webrecon.discovery.fofa` and :mod:`webrecon.github.client`.

Three implementations are provided:

* :class:`GlobalRateLimiter` -- a simple token-bucket that caps the
  global request rate across all hosts.
* :class:`DomainRateLimiter` -- per-host rate limiting with
  configurable per-domain limits and optional ``robots.txt``
  ``Crawl-Delay`` respect.
* :class:`AdaptiveRateLimiter` -- combines global and per-domain
  limits with exponential backoff for 429 responses.

Usage::

    limiter = AdaptiveRateLimiter(
        global_rps=10.0,
        per_host_rps=2.0,
        respect_robots=True,
    )
    # Plug into any client that accepts a RateLimiter protocol.
    client = GithubClient(http, token="...", rate_limiter=limiter)

Validates: Requirement 9.1 (per-host and global rate limits),
Requirement 9.2 (robots.txt / crawl-delay respect),
Requirement 9.3 (exponential backoff for 429 responses).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from webrecon.log import get_logger

__all__ = [
    "AdaptiveRateLimiter",
    "DomainRateLimiter",
    "GlobalRateLimiter",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Global rate limiter (token bucket)
# ---------------------------------------------------------------------------


class GlobalRateLimiter:
    """Token-bucket rate limiter for the global request rate.

    The bucket refills at ``requests_per_second`` tokens per second.
    Each :py:meth:`acquire` call consumes one token; if the bucket
    is empty the caller sleeps until a token is available.

    Args:
        requests_per_second: Sustained request rate ceiling.
        burst: Maximum burst size (tokens that can be consumed
            instantaneously). Defaults to ``1``.
    """

    def __init__(
        self,
        *,
        requests_per_second: float = 10.0,
        burst: int = 1,
    ) -> None:
        self._rps = max(0.1, requests_per_second)
        self._burst = max(1, burst)
        self._tokens: float = float(self._burst)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a request permit is available."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

            # No token available; sleep for one token's worth of time.
            wait = 1.0 / self._rps
            await asyncio.sleep(wait)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._burst),
            self._tokens + elapsed * self._rps,
        )
        self._last_refill = now


# ---------------------------------------------------------------------------
# Per-domain rate limiter
# ---------------------------------------------------------------------------


@dataclass
class _DomainState:
    """Internal state for one domain."""

    limiter: GlobalRateLimiter
    crawl_delay: float = 0.0
    last_request: float = 0.0


class DomainRateLimiter:
    """Per-host rate limiter with optional robots.txt respect.

    Maintains a separate token bucket per domain and optionally
    fetches and parses ``robots.txt`` to honour ``Crawl-Delay``
    directives.

    Args:
        per_host_rps: Default per-domain request rate.
        respect_robots: Whether to fetch and honour ``robots.txt``.
        default_crawl_delay: Default crawl delay when ``robots.txt``
            does not specify one.
    """

    def __init__(
        self,
        *,
        per_host_rps: float = 2.0,
        respect_robots: bool = True,
        default_crawl_delay: float = 0.0,
    ) -> None:
        self._per_host_rps = per_host_rps
        self._respect_robots = respect_robots
        self._default_crawl_delay = default_crawl_delay
        self._domains: dict[str, _DomainState] = {}
        self._lock = asyncio.Lock()
        self._robots_cache: dict[str, float] = {}  # domain → crawl_delay

    async def acquire(self) -> None:
        """Acquire a permit for the current request context.

        Note: This generic ``acquire`` is used by clients that don't
        know the target URL. For per-domain limiting, use
        :py:meth:`acquire_for_url` instead.
        """
        # Fall back to a global rate.
        await asyncio.sleep(1.0 / self._per_host_rps)

    async def acquire_for_url(self, url: str) -> None:
        """Acquire a permit for a specific target URL.

        Args:
            url: The URL about to be requested.
        """
        domain = self._extract_domain(url)
        state = await self._get_domain_state(domain)

        # Respect crawl delay.
        if state.crawl_delay > 0:
            now = time.monotonic()
            elapsed = now - state.last_request
            if elapsed < state.crawl_delay:
                await asyncio.sleep(state.crawl_delay - elapsed)

        await state.limiter.acquire()
        state.last_request = time.monotonic()

    async def _get_domain_state(self, domain: str) -> _DomainState:
        """Get or create the rate-limiter state for a domain."""
        async with self._lock:
            if domain not in self._domains:
                crawl_delay = self._default_crawl_delay
                if self._respect_robots:
                    crawl_delay = await self._fetch_crawl_delay(domain)

                self._domains[domain] = _DomainState(
                    limiter=GlobalRateLimiter(requests_per_second=self._per_host_rps),
                    crawl_delay=crawl_delay,
                )
            return self._domains[domain]

    async def _fetch_crawl_delay(self, domain: str) -> float:
        """Fetch Crawl-Delay from a domain's robots.txt."""
        if domain in self._robots_cache:
            return self._robots_cache[domain]

        try:
            import httpx
            async with httpx.AsyncClient() as http:
                resp = await http.get(
                    f"https://{domain}/robots.txt",
                    timeout=5.0,
                    follow_redirects=True,
                )
                if resp.status_code == 200:
                    delay = self._parse_crawl_delay(resp.text)
                    self._robots_cache[domain] = delay
                    return delay
        except Exception:
            pass

        self._robots_cache[domain] = self._default_crawl_delay
        return self._default_crawl_delay

    @staticmethod
    def _parse_crawl_delay(robots_txt: str) -> float:
        """Parse Crawl-Delay from robots.txt content."""
        for line in robots_txt.splitlines():
            line = line.strip().lower()
            if line.startswith("crawl-delay:"):
                try:
                    return float(line.split(":", 1)[1].strip())
                except (ValueError, IndexError):
                    continue
        return 0.0

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the domain from a URL."""
        try:
            parsed = urlparse(url)
            return parsed.hostname or ""
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Adaptive rate limiter (global + per-domain + backoff)
# ---------------------------------------------------------------------------


class AdaptiveRateLimiter:
    """Combined rate limiter with global cap, per-domain limits,
    and adaptive backoff for rate-limit responses.

    This is the primary rate limiter for the ``webrecon`` pipeline.
    It composes a :class:`GlobalRateLimiter` and a
    :class:`DomainRateLimiter` and adds exponential backoff when
    the caller reports a 429 response via :py:meth:`report_429`.

    Args:
        global_rps: Global request rate ceiling.
        per_host_rps: Per-domain request rate ceiling.
        respect_robots: Whether to honour ``robots.txt``.
        default_crawl_delay: Default crawl delay.
        backoff_base: Base delay for exponential backoff (seconds).
        backoff_max: Maximum backoff delay (seconds).
    """

    def __init__(
        self,
        *,
        global_rps: float = 10.0,
        per_host_rps: float = 2.0,
        respect_robots: bool = True,
        default_crawl_delay: float = 0.0,
        backoff_base: float = 1.0,
        backoff_max: float = 60.0,
    ) -> None:
        self._global = GlobalRateLimiter(requests_per_second=global_rps)
        self._domain = DomainRateLimiter(
            per_host_rps=per_host_rps,
            respect_robots=respect_robots,
            default_crawl_delay=default_crawl_delay,
        )
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._429_counts: dict[str, int] = {}  # domain → consecutive 429s

    async def acquire(self) -> None:
        """Acquire a global permit (used by protocol-based clients)."""
        await self._global.acquire()

    async def acquire_for_url(self, url: str) -> None:
        """Acquire both global and per-domain permits for a URL."""
        await self._global.acquire()
        await self._domain.acquire_for_url(url)

    def report_429(self, url: str) -> float:
        """Report a 429 response and get the recommended backoff delay.

        Callers should invoke this after receiving a 429 and sleep
        for the returned duration before retrying.

        Args:
            url: The URL that received a 429.

        Returns:
            Recommended backoff delay in seconds.
        """
        domain = DomainRateLimiter._extract_domain(url)
        count = self._429_counts.get(domain, 0) + 1
        self._429_counts[domain] = count

        delay: float = min(
            self._backoff_base * (2 ** (count - 1)),
            self._backoff_max,
        )

        _LOGGER.info(
            "safety.rate_limiter.backoff",
            domain=domain,
            consecutive_429s=count,
            delay=delay,
        )

        return delay

    def report_success(self, url: str) -> None:
        """Report a successful request, resetting the 429 counter."""
        domain = DomainRateLimiter._extract_domain(url)
        self._429_counts.pop(domain, None)
