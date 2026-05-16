"""Shodan discovery module.

This module implements the Shodan-side of the
:class:`webrecon.core.models.DiscoverySource.SHODAN` channel: a thin,
type-strict, asynchronous client around the public Shodan REST API
(https://developer.shodan.io). It mirrors the structure of
:mod:`webrecon.discovery.fofa` for consistency:

* :class:`ShodanQueryBuilder` -- a fluent, immutable builder that
  produces Shodan search expressions (``product:nginx port:443
  country:US``). Chainable instance methods (:py:meth:`product`,
  :py:meth:`port`, :py:meth:`country`, ...) accumulate clauses;
  :py:meth:`and_` / :py:meth:`or_` combine builders into compound
  expressions, and :py:meth:`build` materialises the string. Every
  chainable call returns a fresh instance so a partially-built query
  can be safely shared between concurrent callers.

* :class:`ShodanMatch` -- a frozen dataclass describing one match in
  a Shodan ``/shodan/host/search`` response. The minimal useful
  normalisation (:py:meth:`~ShodanMatch.to_url`) reconstructs a URL
  from the ``ip_str``/``port``/``hostnames`` columns; the original
  match object is preserved verbatim under :attr:`ShodanMatch.raw`
  so callers needing richer metadata (banners, vulns, SSL info,
  ...) can extract it without re-querying.

* :class:`ShodanClient` -- the asynchronous client itself. Accepts an
  externally-managed :class:`httpx.AsyncClient` (so the project-wide
  connection pool and the test suite's :class:`httpx.MockTransport`
  plug in trivially) plus an ``api_key`` credential. The
  :py:meth:`~ShodanClient.search` coroutine is an async iterator that
  walks pagination until ``total`` is reached or ``max_pages`` hits
  its cap. :py:meth:`~ShodanClient.search_to_assets` wraps the same
  loop but yields :class:`webrecon.core.models.WebsiteAsset` instances
  ready to feed into the asset repository.
  :py:meth:`~ShodanClient.get_host` and :py:meth:`~ShodanClient.info`
  expose the per-host detail endpoint and the API-quota endpoint
  respectively.

* Exception hierarchy: :class:`ShodanError` (base),
  :class:`ShodanApiError` (HTTP non-2xx or ``error`` field in
  payload), :class:`ShodanRateLimitError` (HTTP 429), and
  :class:`ShodanQuotaExceededError` (HTTP 403 with quota-exhaustion
  body). The transport layer retries rate-limited requests with
  exponential backoff up to ``_MAX_RETRIES`` attempts; if the
  server is still rate-limiting after the final attempt the
  exception escapes to the caller.

Like :mod:`webrecon.discovery.fofa`, this module declares the minimal
:class:`RateLimiter` :class:`typing.Protocol` it needs locally so a
real rate limiter can be plugged in later without circular
dependencies on :mod:`webrecon.safety`.

Validates: Requirement 1.2 (Shodan API search returns discovered
services with metadata), Requirement 1.5 (API keys via configuration
with rate-limit handling).
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
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
    from collections.abc import AsyncIterator, Mapping

    from typing_extensions import Self


__all__ = [
    "RateLimiter",
    "ShodanApiError",
    "ShodanClient",
    "ShodanError",
    "ShodanMatch",
    "ShodanQueryBuilder",
    "ShodanQuotaExceededError",
    "ShodanRateLimitError",
]


_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Default base URL for the Shodan REST API. ``base_url`` on
# :class:`ShodanClient` is overridable so an operator can swap in a
# region-specific endpoint or a mock server.
_DEFAULT_BASE_URL: str = "https://api.shodan.io"

# REST endpoint suffixes relative to ``base_url``. The leading slash
# matters because :class:`httpx.AsyncClient` joins the two with
# :func:`urllib.parse.urljoin` semantics.
_SEARCH_PATH: str = "/shodan/host/search"
_HOST_PATH_TEMPLATE: str = "/shodan/host/{ip}"
_INFO_PATH: str = "/api-info"

# Shodan returns at most 100 matches per page. Surface the value as a
# constant so callers can clamp their own ``page_size`` choices.
_DEFAULT_PAGE_SIZE: int = 100

# Page cap: protects callers that forget to specify ``max_pages``
# from accidentally walking a 100 000-row result set (Shodan caps
# free queries at 100 results but enterprise tiers can return many
# thousands).
_DEFAULT_MAX_PAGES: int = 10

# Retry policy for transient rate-limit responses. Backoff grows as
# ``_BACKOFF_BASE * 2 ** attempt`` with a small jitter so concurrent
# clients do not synchronise their retries. The values mirror
# :mod:`webrecon.discovery.fofa` so an operator running both clients
# in parallel sees comparable behaviour.
_MAX_RETRIES: int = 3
_BACKOFF_BASE_SECONDS: float = 1.0
_BACKOFF_JITTER_SECONDS: float = 0.5

# HTTP request timeout. Shodan search responses can take several
# seconds for popular queries; 30 s is generous enough for slow
# paginated responses without hanging the discovery pipeline.
_REQUEST_TIMEOUT_SECONDS: float = 30.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ShodanError(Exception):
    """Base class for every Shodan-related runtime error.

    Catching :class:`ShodanError` lets a caller treat any Shodan
    failure mode uniformly (skip the source, fall back to another
    intelligence channel, ...) without having to enumerate the
    sub-classes.
    """


class ShodanApiError(ShodanError):
    """Raised when the Shodan API returns a non-success response.

    Attributes:
        status_code: The HTTP status code returned by the server, or
            ``None`` if the failure happened before a response was
            received (for example: a JSON payload with an ``error``
            field on top of a 200 response).
        body: The response body (decoded text, truncated by the
            transport when very large) preserved verbatim so an
            operator can inspect what the server complained about.
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


class ShodanRateLimitError(ShodanApiError):
    """Raised when the Shodan API rate-limits the client.

    Surfaces HTTP 429 responses. The retry machinery in
    :class:`ShodanClient` raises this exception only after every
    retry attempt has been exhausted.
    """


class ShodanQuotaExceededError(ShodanError):
    """Raised when the Shodan account has exhausted its query quota.

    Distinct from :class:`ShodanRateLimitError` because quota
    exhaustion is a *persistent* condition (until the account's
    monthly counter resets or the operator upgrades the plan) while
    rate limiting is transient and worth retrying. Surfaced when
    Shodan returns HTTP 403 whose body indicates the account is out
    of query credits.
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
    """Minimal protocol consumed by :class:`ShodanClient`.

    The full rate-limiter implementation lives in
    :mod:`webrecon.safety` (task 14.1). This module only needs an
    awaitable :py:meth:`acquire` slot that pauses the caller until a
    request permit is available; declaring the protocol locally
    avoids a circular import while still letting type-checkers
    verify that callers pass an object with the right shape.
    """

    async def acquire(self) -> None:
        """Block until the caller is allowed to issue one request."""


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------


def _quote(value: str) -> str:
    """Quote a Shodan filter value when it contains whitespace.

    Shodan's query language uses ``filter:value`` pairs separated by
    spaces; values containing whitespace must be wrapped in double
    quotes. Embedded double quotes are not officially documented as
    escapable, so we conservatively replace them with single quotes
    to keep the resulting expression syntactically valid. Values
    without whitespace are returned unchanged for readability.
    """
    if not value:
        return '""'
    needs_quoting = any(ch.isspace() for ch in value) or '"' in value
    if not needs_quoting:
        return value
    sanitised = value.replace('"', "'")
    return f'"{sanitised}"'


@dataclass(frozen=True)
class ShodanQueryBuilder:
    """Fluent, immutable builder for Shodan search expressions.

    Each :py:meth:`product`/:py:meth:`port`/... call returns a new
    builder with one extra clause appended; the original instance is
    never mutated. :py:meth:`build` joins the accumulated clauses
    with a single space, which Shodan interprets as logical AND.
    Use :py:meth:`and_` / :py:meth:`or_` to combine builders into
    compound expressions with explicit parenthesisation.
    """

    clauses: tuple[str, ...] = field(default_factory=tuple)

    # ---- Field-level helpers ------------------------------------------

    def product(self, name: str) -> Self:
        """Match services whose ``product`` banner matches ``name``.

        Maps to Shodan's ``product:`` filter (e.g. ``"nginx"``,
        ``"Apache httpd"``, ``"Microsoft IIS"``).
        """
        return self._with_clause(f"product:{_quote(name)}")

    def port(self, port: int) -> Self:
        """Filter results to TCP port ``port``."""
        if port < 0 or port > 65535:
            raise ValueError(f"port must be in [0, 65535], got {port}")
        return self._with_clause(f"port:{port}")

    def country(self, code: str) -> Self:
        """Filter results to ISO 3166-1 alpha-2 country code ``code``."""
        return self._with_clause(f"country:{_quote(code)}")

    def os(self, name: str) -> Self:
        """Filter results to operating-system fingerprint ``name``."""
        return self._with_clause(f"os:{_quote(name)}")

    def hostname(self, host: str) -> Self:
        """Match services whose hostname contains ``host``."""
        return self._with_clause(f"hostname:{_quote(host)}")

    def org(self, org: str) -> Self:
        """Filter results to organisation/owner ``org`` (ASN owner)."""
        return self._with_clause(f"org:{_quote(org)}")

    def net(self, cidr: str) -> Self:
        """Filter results to the IPv4/IPv6 network ``cidr``."""
        return self._with_clause(f"net:{_quote(cidr)}")

    def raw(self, expression: str) -> Self:
        """Append a raw, pre-formatted Shodan expression.

        Provides an escape hatch for Shodan filters the builder does
        not yet wrap (e.g. ``ssl.cert.subject.cn``,
        ``vuln:CVE-...``). The caller is responsible for proper
        quoting; the value is inserted verbatim.
        """
        if not expression.strip():
            raise ValueError("raw expression must be non-empty")
        return self._with_clause(expression.strip())

    # ---- Combinators --------------------------------------------------

    def and_(self, other: ShodanQueryBuilder) -> ShodanQueryBuilder:
        """Combine ``self`` and ``other`` with logical AND.

        The resulting builder produces ``(self) (other)`` -- both
        sides are parenthesised so the precedence is unambiguous
        regardless of what each side contained. Shodan treats a
        space between expressions as logical AND.
        """
        left = self.build()
        right = other.build()
        if not left:
            return other
        if not right:
            return self
        combined = f"({left}) ({right})"
        return ShodanQueryBuilder(clauses=(combined,))

    def or_(self, other: ShodanQueryBuilder) -> ShodanQueryBuilder:
        """Combine ``self`` and ``other`` with logical OR."""
        left = self.build()
        right = other.build()
        if not left:
            return other
        if not right:
            return self
        combined = f"({left}) OR ({right})"
        return ShodanQueryBuilder(clauses=(combined,))

    # ---- Materialisation ----------------------------------------------

    def build(self) -> str:
        """Materialise the accumulated clauses into a Shodan query.

        Returns the empty string when the builder is empty (no
        clauses appended yet). Otherwise joins clauses with a single
        space, which Shodan interprets as logical AND.
        """
        return " ".join(self.clauses)

    def __str__(self) -> str:
        return self.build()

    # ---- Internal -----------------------------------------------------

    def _with_clause(self, clause: str) -> Self:
        """Return a new builder with ``clause`` appended."""
        return self.__class__(clauses=(*self.clauses, clause))


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShodanMatch:
    """One match in a Shodan ``/shodan/host/search`` response.

    The fields surfaced as named attributes are the canonical columns
    every Shodan match contains; everything else (banner data, SSL
    metadata, vuln info, ASN, ...) is available under :attr:`raw` so
    callers needing richer information can extract it without
    re-querying.

    Attributes:
        ip_str: Resolved IPv4/IPv6 address (Shodan's ``ip_str``).
        port: Numeric port the service was discovered on.
        hostnames: Reverse-resolved hostnames Shodan associates with
            the IP. Stored as a tuple to keep the dataclass hashable.
        product: Product/fingerprint name (``"nginx"``, ``"Apache
            httpd"``, ...) when Shodan was able to identify the
            service; empty string otherwise.
        data: Banner text (HTTP response, SSH banner, ...) Shodan
            captured. Trimmed to a sensible length by the API.
        raw: The original match object from the API, preserved
            verbatim. Stored as :class:`dict` so callers can use
            :py:meth:`dict.get` / pattern-match without coercing.
    """

    ip_str: str
    port: int
    hostnames: tuple[str, ...]
    product: str
    data: str
    raw: dict[str, Any]

    def to_url(self, scheme: str = "http") -> str:
        """Reconstruct a normalised URL from the match.

        Prefers the first hostname when present (so the URL is
        operator-friendly and preserves SNI for follow-up TLS
        connections); falls back to ``ip_str`` when no hostname is
        associated. The port is suppressed when it matches the
        well-known port for ``scheme`` (``80`` / ``443``) so the
        resulting URL is canonical and safe to use as a deduplication
        key.

        Args:
            scheme: Application-layer protocol. Defaults to ``"http"``
                because Shodan's most common results are HTTP banners;
                callers that know the service is TLS-protected should
                pass ``"https"`` to get a correctly-normalised URL.

        Returns:
            The reconstructed URL. Never raises -- when the match
            lacks both ``ip_str`` and ``hostnames`` the result is the
            scheme-only URL ``"http://"`` which the caller can detect
            and skip.
        """
        host = ""
        if self.hostnames:
            host = self.hostnames[0].strip()
        if not host:
            host = self.ip_str.strip()
        # Wrap raw IPv6 addresses so the resulting URL parses cleanly:
        # ``http://[::1]:443`` rather than ``http://::1:443``.
        if host and ":" in host and "." not in host and not host.startswith("["):
            host = f"[{host}]"

        clean_scheme = scheme.strip().lower() or "http"
        port = self.port
        if port == 0 or port == _default_port_for(clean_scheme):
            return f"{clean_scheme}://{host}"
        return f"{clean_scheme}://{host}:{port}"


def _default_port_for(scheme: str) -> int:
    """Return the well-known TCP port for ``scheme`` or ``-1``.

    Used by :py:meth:`ShodanMatch.to_url` to decide whether to
    suppress a port from the canonical URL.
    """
    return {
        "http": 80,
        "https": 443,
        "ftp": 21,
        "ftps": 990,
    }.get(scheme.lower(), -1)


def _match_from_payload(payload: Mapping[str, Any]) -> ShodanMatch:
    """Translate a single Shodan match dict into :class:`ShodanMatch`.

    Defensive about missing / wrong-typed fields: the Shodan API is
    documented but real-world responses sometimes omit fields when
    the data was not collected. Missing strings become ``""``, missing
    integers become ``0``, missing hostname lists become an empty
    tuple. The original payload is preserved on :attr:`ShodanMatch.raw`
    so callers can recover any field the normaliser dropped.
    """
    ip_str = str(payload.get("ip_str") or "")

    port_value = payload.get("port", 0)
    try:
        port = int(port_value) if port_value is not None else 0
    except (TypeError, ValueError):
        port = 0

    hostnames_value = payload.get("hostnames")
    if isinstance(hostnames_value, (list, tuple)):
        hostnames = tuple(str(h) for h in hostnames_value if h)
    else:
        hostnames = ()

    product = str(payload.get("product") or "")
    data = str(payload.get("data") or "")

    return ShodanMatch(
        ip_str=ip_str,
        port=port,
        hostnames=hostnames,
        product=product,
        data=data,
        raw=dict(payload),
    )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ShodanClient:
    """Asynchronous client for the Shodan REST API.

    The client is intentionally thin: it owns the credential
    handling, drives pagination, and translates HTTP / payload
    errors into the local exception hierarchy. Everything else --
    connection pooling, proxy/UA configuration, retry policy for
    transport errors -- lives on the injected
    :class:`httpx.AsyncClient`.

    Example:
        >>> async with httpx.AsyncClient() as http:
        ...     client = ShodanClient(http, api_key="...")
        ...     async for match in client.search("product:nginx"):
        ...         print(match.to_url())
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("ShodanClient requires a non-empty api_key")
        self._http = http_client
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = rate_limiter

    # ---- Public API ---------------------------------------------------

    async def search(
        self,
        query: str | ShodanQueryBuilder,
        *,
        max_pages: int = _DEFAULT_MAX_PAGES,
        page_size: int = _DEFAULT_PAGE_SIZE,
        facets: list[str] | None = None,
    ) -> AsyncIterator[ShodanMatch]:
        """Iterate Shodan search results across pagination.

        Args:
            query: Either a literal Shodan query string or a
                :class:`ShodanQueryBuilder` that materialises one.
            max_pages: Hard cap on the number of pages this call will
                walk. The default mirrors :data:`_DEFAULT_MAX_PAGES`.
                Passing a non-positive value yields nothing.
            page_size: Rows requested per page. Shodan caps this at
                100; values above that are silently clamped. The
                value is plumbed through so the caller can shrink it
                for tests / debugging.
            facets: Optional list of facet names (e.g. ``"country"``,
                ``"port"``) Shodan should aggregate over. The facet
                results are not surfaced through the iterator -- use
                :py:meth:`info` if facet aggregates are needed.

        Yields:
            One :class:`ShodanMatch` per match, in the order Shodan
            returned them.

        Raises:
            ShodanApiError: The API returned a non-2xx response or a
                JSON payload with an ``error`` field.
            ShodanRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
            ShodanQuotaExceededError: The Shodan account has
                exhausted its query quota.
        """
        query_str = (
            query.build() if isinstance(query, ShodanQueryBuilder) else query
        )
        if not query_str:
            raise ValueError("Shodan query must be non-empty")

        clamped_size = max(1, min(int(page_size), _DEFAULT_PAGE_SIZE))

        log = _LOGGER.bind(
            shodan_query_length=len(query_str),
            page_size=clamped_size,
            max_pages=max_pages,
            facets=",".join(facets) if facets else "",
        )
        log.info("shodan.search.start")

        seen = 0
        total_reported: int | None = None
        for page in range(1, max_pages + 1):
            page_log = log.bind(page=page)
            page_log.debug("shodan.search.page.request")

            payload = await self._fetch_search_page(
                query=query_str,
                page=page,
                facets=facets,
            )

            matches = _coerce_matches(payload.get("matches"))
            if total_reported is None:
                # ``total`` is the server-side estimate of overall
                # matches -- record it once on the first page so the
                # iterator can stop walking when ``seen`` reaches it.
                total_value = payload.get("total")
                try:
                    total_reported = (
                        int(total_value) if total_value is not None else None
                    )
                except (TypeError, ValueError):
                    total_reported = None

            page_log.info(
                "shodan.search.page.received",
                match_count=len(matches),
                total=total_reported,
            )
            for match_payload in matches:
                yield _match_from_payload(match_payload)
                seen += 1

            # Stop early if the page came back short -- Shodan's
            # documented page size is 100, so anything less means we
            # ran past the last page of results.
            if len(matches) < clamped_size:
                page_log.debug("shodan.search.page.exhausted")
                break

            # Also stop if the cumulative hit count has caught up
            # with the server's reported ``total``. This avoids one
            # wasted round-trip at the end of every full result set.
            if total_reported is not None and seen >= total_reported:
                page_log.debug("shodan.search.total.reached")
                break

        log.info("shodan.search.complete", result_count=seen)

    async def get_host(self, ip: str) -> dict[str, Any]:
        """Return Shodan's full host record for ``ip``.

        Wraps ``GET /shodan/host/{ip}``. The full record (banners,
        history, vulns, services, ...) is returned as a plain
        :class:`dict` so callers can extract fields without coupling
        to a richer dataclass.

        Args:
            ip: IPv4 or IPv6 address to look up. Must be non-empty.

        Returns:
            The decoded JSON object Shodan returned.

        Raises:
            ShodanApiError: The API returned a non-2xx response or a
                JSON payload with an ``error`` field.
            ShodanRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
            ShodanQuotaExceededError: The account is out of query
                credits.
        """
        if not ip:
            raise ValueError("ip must be non-empty")

        path = _HOST_PATH_TEMPLATE.format(ip=ip)
        url = f"{self._base_url}{path}"
        params: dict[str, str] = {"key": self._api_key}

        _LOGGER.info("shodan.get_host.start", ip=ip)
        payload = await self._fetch_json(url=url, params=params)
        _LOGGER.info("shodan.get_host.complete", ip=ip)
        return payload

    async def info(self) -> dict[str, Any]:
        """Return the account's API quota / plan information.

        Wraps ``GET /api-info``. The response includes ``query_credits``,
        ``scan_credits``, ``plan`` and similar fields useful for
        monitoring the account's remaining budget.

        Raises:
            ShodanApiError: The API returned a non-2xx response.
            ShodanRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
        """
        url = f"{self._base_url}{_INFO_PATH}"
        params: dict[str, str] = {"key": self._api_key}

        _LOGGER.info("shodan.info.start")
        payload = await self._fetch_json(url=url, params=params)
        _LOGGER.info("shodan.info.complete")
        return payload

    async def search_to_assets(
        self,
        query: str | ShodanQueryBuilder,
        *,
        scheme: str = "http",
        discovery_source: DiscoverySource = DiscoverySource.SHODAN,
        max_pages: int = _DEFAULT_MAX_PAGES,
        page_size: int = _DEFAULT_PAGE_SIZE,
        facets: list[str] | None = None,
    ) -> AsyncIterator[WebsiteAsset]:
        """Wrap :py:meth:`search` and yield :class:`WebsiteAsset` instances.

        Each asset is given a fresh UUID identifier, the
        Shodan-derived URL as both ``url`` and ``normalized_url``
        (the discovery layer does not yet have access to the
        project-wide URL normaliser), :class:`AssetStatus.UNKNOWN`
        (validation runs downstream), and the supplied
        ``discovery_source``.

        Args:
            query: Same semantics as :py:meth:`search`.
            scheme: Application-layer protocol assumed for the
                generated URL. Defaults to ``"http"``; pass
                ``"https"`` when the query is known to target TLS
                services.
            discovery_source: Recorded on every emitted asset.
                Defaults to :class:`DiscoverySource.SHODAN`; an
                operator can override it to tag assets discovered
                through a derived Shodan pipeline.
            max_pages: See :py:meth:`search`.
            page_size: See :py:meth:`search`.
            facets: See :py:meth:`search`.

        Yields:
            One :class:`WebsiteAsset` per match that produced a
            non-empty URL. Matches whose URL would degenerate to a
            scheme-only string (no host and no IP) are skipped
            silently.
        """
        async for match in self.search(
            query,
            max_pages=max_pages,
            page_size=page_size,
            facets=facets,
        ):
            url = match.to_url(scheme)
            host_present = bool(match.ip_str.strip()) or bool(match.hostnames)
            if not host_present:
                continue
            now = datetime.now(timezone.utc)
            metadata: dict[str, str] = {
                "shodan_ip": match.ip_str,
                "shodan_port": str(match.port),
            }
            if match.product:
                metadata["shodan_product"] = match.product
            yield WebsiteAsset(
                id=uuid4().hex,
                url=url,
                normalized_url=url,
                discovered_at=now,
                last_checked=now,
                status=AssetStatus.UNKNOWN,
                discovery_source=discovery_source,
                metadata=metadata,
            )

    # ---- Internal: HTTP -----------------------------------------------

    async def _fetch_search_page(
        self,
        *,
        query: str,
        page: int,
        facets: list[str] | None,
    ) -> dict[str, Any]:
        """Issue a single search request and return its JSON body."""
        url = f"{self._base_url}{_SEARCH_PATH}"
        params: dict[str, str] = {
            "key": self._api_key,
            "query": query,
            "page": str(page),
        }
        if facets:
            # Shodan accepts comma-separated facet names. ``minify``
            # is intentionally not set: the caller relies on the
            # full match payload through :attr:`ShodanMatch.raw`.
            params["facets"] = ",".join(facets)

        return await self._fetch_json(url=url, params=params)

    async def _fetch_json(
        self,
        *,
        url: str,
        params: Mapping[str, str],
    ) -> dict[str, Any]:
        """Issue a GET that expects a JSON object response, with retries.

        Implements exponential backoff for transient rate-limit
        responses. Raises :class:`ShodanApiError` on permanent
        failures, :class:`ShodanRateLimitError` once the retry
        budget is exhausted, and :class:`ShodanQuotaExceededError`
        when the API reports quota exhaustion (HTTP 403 with a body
        mentioning quota/credits).
        """
        last_error: ShodanError | None = None
        for attempt in range(_MAX_RETRIES):
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()

            try:
                response = await self._http.get(
                    url,
                    params=dict(params),
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                # Transport-level failures (DNS, connect, read
                # timeout, ...) are wrapped as :class:`ShodanApiError`
                # so the caller has a single base class to catch.
                # They are not retried here because the project-wide
                # HTTP client is expected to provide its own
                # transport retry policy.
                raise ShodanApiError(
                    f"Shodan HTTP transport error: {exc}"
                ) from exc

            if response.status_code == 401:
                raise ShodanApiError(
                    "Shodan API rejected the API key (HTTP 401). "
                    "Verify the configured api_key is valid.",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            if response.status_code == 403:
                body = _safe_text(response)
                if _looks_like_quota_exhaustion(body):
                    raise ShodanQuotaExceededError(
                        "Shodan account has exhausted its query "
                        "quota (HTTP 403)",
                        status_code=response.status_code,
                        body=body,
                    )
                raise ShodanApiError(
                    "Shodan API forbade the request (HTTP 403)",
                    status_code=response.status_code,
                    body=body,
                )

            if response.status_code == 429:
                last_error = ShodanRateLimitError(
                    "Shodan rate-limited the request (HTTP 429)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code >= 400:
                raise ShodanApiError(
                    f"Shodan API returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise ShodanApiError(
                    "Shodan API returned non-JSON payload",
                    status_code=response.status_code,
                    body=_safe_text(response),
                ) from exc

            if not isinstance(payload, dict):
                raise ShodanApiError(
                    "Shodan API returned unexpected JSON shape "
                    "(not an object)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            error_value = payload.get("error")
            if isinstance(error_value, str) and error_value:
                if _looks_like_quota_exhaustion(error_value):
                    raise ShodanQuotaExceededError(
                        f"Shodan reported quota exhaustion: {error_value}",
                        status_code=response.status_code,
                        body=_safe_text(response),
                    )
                raise ShodanApiError(
                    f"Shodan API error: {error_value}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            return payload

        # Retry budget exhausted: surface the last rate-limit error.
        if last_error is not None:
            raise last_error
        # Defensive: should not be reachable because every loop
        # iteration either returns, raises, or assigns ``last_error``.
        raise ShodanApiError(
            "Shodan API failed after retries with no diagnostic"
        )

    @staticmethod
    async def _sleep_for_retry(attempt: int) -> None:
        """Sleep before retrying after a rate-limited response.

        Backoff schedule: ``base * 2 ** attempt + jitter``. The
        jitter is uniform in ``[0, _BACKOFF_JITTER_SECONDS)`` so a
        fleet of concurrent clients does not synchronise their
        retries.
        """
        delay = _BACKOFF_BASE_SECONDS * (2**attempt)
        delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
        await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_matches(value: Any) -> list[Mapping[str, Any]]:
    """Return a list of match dicts from a Shodan ``matches`` field.

    Shodan returns either ``null``/missing (no results) or a list
    of objects, where each object is a mapping of fields. This
    helper coerces the value to a uniform shape so the caller can
    iterate without ``isinstance`` gymnastics.
    """
    if not value:
        return []
    if not isinstance(value, list):
        return []
    matches: list[Mapping[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            matches.append(item)
        # Non-dict items are silently skipped: they cannot be
        # turned into a :class:`ShodanMatch` and dropping them is
        # less harmful than crashing the whole iterator.
    return matches


def _looks_like_quota_exhaustion(message: str) -> bool:
    """Heuristic: does ``message`` describe an API-quota condition?

    Shodan's documented error strings for quota exhaustion include
    "No query credits available" and "Request rate limit reached".
    Matching on case-insensitive substrings is good enough since
    Shodan does not currently expose a dedicated machine-readable
    error code for this case.
    """
    if not message:
        return False
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in (
            "query credits",
            "scan credits",
            "no credits",
            "out of credits",
            "quota",
            "upgrade your api plan",
            "upgrade your plan",
        )
    )


def _safe_text(response: httpx.Response) -> str:
    """Best-effort decode of ``response.text`` for diagnostics."""
    try:
        return response.text
    except Exception:  # pragma: no cover - defensive
        try:
            return response.content.decode("utf-8", errors="replace")
        except Exception:
            return ""
