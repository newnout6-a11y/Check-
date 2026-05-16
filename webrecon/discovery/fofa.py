"""FOFA discovery module.

This module implements the FOFA-side of the
:class:`webrecon.core.models.DiscoverySource.FOFA` channel: a thin,
type-strict, asynchronous client around the public FOFA REST API
(https://en.fofa.info/api). The module is composed of four pieces
that are intended to be used together but are independently testable:

* :class:`FofaQueryBuilder` -- a small fluent builder that produces
  the FOFA query expressions documented at
  https://en.fofa.info/api ("query syntax"). Chainable instance
  methods (:py:meth:`~FofaQueryBuilder.app`,
  :py:meth:`~FofaQueryBuilder.country`, ...) accumulate clauses;
  :py:meth:`~FofaQueryBuilder.and_` and
  :py:meth:`~FofaQueryBuilder.or_` combine builders into compound
  expressions, and :py:meth:`~FofaQueryBuilder.build` materialises the
  string. The builder is **immutable**: every chainable call returns
  a fresh instance so a partially-built query can be safely shared
  between concurrent callers.

* :class:`FofaResult` -- a frozen dataclass describing one row of a
  FOFA search response. The minimum useful normalisation
  (:py:meth:`~FofaResult.to_url`) reconstructs a fully-qualified URL
  from the raw ``host``/``ip``/``port``/``protocol`` columns FOFA
  returns; the original row is preserved verbatim under
  :attr:`FofaResult.raw` so callers that need richer metadata (CDN
  flags, ASN, ...) can extract it without re-querying.

* :class:`FofaClient` -- the asynchronous client itself. It accepts
  an externally-managed :class:`httpx.AsyncClient` (dependency
  injection makes integration with the project-wide connection pool
  and the test suite's :class:`httpx.MockTransport` trivial) plus
  ``email`` and ``key`` credentials. The :py:meth:`~FofaClient.search`
  coroutine is an async iterator that walks pagination until the
  server reports exhaustion or the caller-supplied ``max_pages``
  cap is hit; :py:meth:`~FofaClient.search_to_assets` wraps the same
  loop but yields :class:`webrecon.core.models.WebsiteAsset` instances
  ready to feed into the asset repository.

* Exception hierarchy: :class:`FofaError` (base),
  :class:`FofaApiError` (HTTP non-2xx or ``error: true`` payload),
  :class:`FofaRateLimitError` (HTTP 429 or rate-limit error message
  in the JSON body). The transport layer retries rate-limited
  requests with exponential backoff up to ``_MAX_RETRIES`` attempts;
  if the server is still rate-limiting after the final attempt the
  exception escapes to the caller.

The module imports nothing from :mod:`webrecon.safety` (which lives
in task 14.1); instead it declares the minimal :class:`RateLimiter`
:class:`typing.Protocol` it needs so a real rate limiter can be
plugged in later without circular dependencies.

Validates: Requirement 1.1 (FOFA API search with pagination),
Requirement 1.5 (API keys via configuration with rate-limit handling).
"""

from __future__ import annotations

import asyncio
import base64
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
    from collections.abc import AsyncIterator, Iterable, Sequence

    from typing_extensions import Self


__all__ = [
    "FofaApiError",
    "FofaClient",
    "FofaError",
    "FofaQueryBuilder",
    "FofaRateLimitError",
    "FofaResult",
    "RateLimiter",
]


_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Default base URL for the FOFA REST API. ``base_url`` on
# :class:`FofaClient` is overridable so an operator can swap in a
# region-specific endpoint or a mock server.
_DEFAULT_BASE_URL: str = "https://fofa.info"

# REST endpoint suffix relative to ``base_url``. The leading slash
# matters because :class:`httpx.AsyncClient` joins the two with
# :func:`urllib.parse.urljoin` semantics.
_SEARCH_PATH: str = "/api/v1/search/all"

# FOFA returns up to 10 000 hits per query and 100 hits per page is
# the maximum per page across paid + free tiers (see API docs). The
# value is plumbed through to :py:meth:`FofaClient.search` so the
# caller can shrink it for tests / debugging.
_DEFAULT_PAGE_SIZE: int = 100

# Page cap: protects callers that forget to specify ``max_pages``
# from accidentally walking a 100 000-row result set.
_DEFAULT_MAX_PAGES: int = 10

# Default fields requested from the API. ``host`` is the canonical
# authority (``example.com:443``), ``ip`` is the resolved address,
# ``port`` is the numeric port, ``protocol`` is the application-layer
# protocol (``http``, ``https``, ``ftp``, ...). Together they allow
# :py:meth:`FofaResult.to_url` to reconstruct a URL without further
# heuristics.
_DEFAULT_FIELDS: tuple[str, ...] = ("host", "ip", "port", "protocol")

# Retry policy for transient rate-limit responses. Backoff grows as
# ``_BACKOFF_BASE * 2 ** attempt`` with a small jitter so concurrent
# clients do not synchronise their retries.
_MAX_RETRIES: int = 3
_BACKOFF_BASE_SECONDS: float = 1.0
_BACKOFF_JITTER_SECONDS: float = 0.5

# HTTP request timeout. The FOFA endpoint occasionally takes several
# seconds to return for large queries; 30 s is generous enough for
# slow paginated responses without hanging the discovery pipeline.
_REQUEST_TIMEOUT_SECONDS: float = 30.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FofaError(Exception):
    """Base class for every FOFA-related runtime error.

    Catching :class:`FofaError` lets a caller treat any FOFA
    failure mode uniformly (skip the source, fall back to another
    intelligence channel, ...) without having to enumerate the
    sub-classes.
    """


class FofaApiError(FofaError):
    """Raised when the FOFA API returns a non-success response.

    Attributes:
        status_code: The HTTP status code returned by the server, or
            ``None`` if the failure happened before a response was
            received (for example: a JSON payload with ``error: true``
            on top of a 200 response).
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


class FofaRateLimitError(FofaApiError):
    """Raised when the FOFA API rate-limits the client.

    Surfaces both HTTP 429 responses and JSON error payloads whose
    ``errmsg`` mentions throttling or quota exhaustion. The retry
    machinery in :class:`FofaClient` raises this exception only after
    every retry attempt has been exhausted.
    """


# ---------------------------------------------------------------------------
# Rate-limiter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class RateLimiter(Protocol):
    """Minimal protocol consumed by :class:`FofaClient`.

    The full rate-limiter implementation lives in :mod:`webrecon.safety`
    (task 14.1). This module only needs an awaitable
    :py:meth:`acquire` slot that pauses the caller until a request
    permit is available; declaring the protocol locally avoids a
    circular import while still letting type-checkers verify that
    callers pass an object with the right shape.
    """

    async def acquire(self) -> None:
        """Block until the caller is allowed to issue one request."""


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------


def _quote(value: str) -> str:
    """Quote a FOFA query value.

    FOFA's query language uses double-quotes around values; embedded
    quotes inside a value are escaped by doubling them (the same
    convention SQL ``LIKE`` patterns use). Returning a properly
    escaped fragment keeps :class:`FofaQueryBuilder` from accidentally
    producing malformed queries when the caller feeds data containing
    quotes (e.g. an ``app="3WiFi"`` lookup).
    """
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


@dataclass(frozen=True)
class FofaQueryBuilder:
    """Fluent, immutable builder for FOFA search expressions.

    Each :py:meth:`app`/:py:meth:`country`/... call returns a new
    builder with one extra clause appended; the original instance is
    never mutated. :py:meth:`build` joins the accumulated clauses
    with ``&&`` (logical AND) which matches the implicit semantics
    FOFA's query syntax assigns to space-separated clauses but is
    explicit and unambiguous. Use :py:meth:`and_` / :py:meth:`or_`
    to combine builders into compound expressions with explicit
    parenthesisation.
    """

    clauses: tuple[str, ...] = field(default_factory=tuple)

    # ---- Field-level helpers ------------------------------------------

    def app(self, name: str) -> Self:
        """Match assets identified as running ``name``.

        Maps to FOFA's ``app="..."`` key, which keys into the
        application fingerprint database (e.g. ``"WordPress"``,
        ``"WooCommerce"``).
        """
        return self._with_clause(f"app={_quote(name)}")

    def country(self, code: str) -> Self:
        """Filter results to ISO 3166-1 alpha-2 country code ``code``."""
        return self._with_clause(f"country={_quote(code)}")

    def port(self, port: int) -> Self:
        """Filter results to TCP port ``port``."""
        if port < 0 or port > 65535:
            raise ValueError(f"port must be in [0, 65535], got {port}")
        # FOFA expects ``port="80"`` (string-quoted), not ``port=80``.
        return self._with_clause(f"port={_quote(str(port))}")

    def domain(self, domain: str) -> Self:
        """Filter results whose domain contains ``domain``."""
        return self._with_clause(f"domain={_quote(domain)}")

    def body(self, text: str) -> Self:
        """Match assets whose response body contains ``text``."""
        return self._with_clause(f"body={_quote(text)}")

    def title(self, text: str) -> Self:
        """Match assets whose HTML ``<title>`` contains ``text``."""
        return self._with_clause(f"title={_quote(text)}")

    def raw(self, expression: str) -> Self:
        """Append a raw, pre-formatted FOFA expression.

        Provides an escape hatch for FOFA syntax features the builder
        does not yet wrap (e.g. ``cert.subject``, ``icp``, ...). The
        caller is responsible for proper quoting; the value is
        inserted verbatim.
        """
        if not expression.strip():
            raise ValueError("raw expression must be non-empty")
        return self._with_clause(expression.strip())

    # ---- Combinators --------------------------------------------------

    def and_(self, other: FofaQueryBuilder) -> FofaQueryBuilder:
        """Combine ``self`` and ``other`` with logical AND.

        The resulting builder produces ``(self) && (other)`` -- both
        sides are parenthesised so the precedence is unambiguous
        regardless of what each side contained.
        """
        left = self.build()
        right = other.build()
        if not left:
            return other
        if not right:
            return self
        combined = f"({left}) && ({right})"
        return FofaQueryBuilder(clauses=(combined,))

    def or_(self, other: FofaQueryBuilder) -> FofaQueryBuilder:
        """Combine ``self`` and ``other`` with logical OR."""
        left = self.build()
        right = other.build()
        if not left:
            return other
        if not right:
            return self
        combined = f"({left}) || ({right})"
        return FofaQueryBuilder(clauses=(combined,))

    # ---- Materialisation ----------------------------------------------

    def build(self) -> str:
        """Materialise the accumulated clauses into a FOFA query string.

        Returns the empty string when the builder is empty (no
        clauses appended yet). Otherwise joins clauses with FOFA's
        logical-AND operator ``&&``.
        """
        return " && ".join(self.clauses)

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
class FofaResult:
    """One row of a FOFA search response.

    The four canonical columns FOFA returns by default are surfaced
    as named attributes; everything else (including the unparsed row
    itself) is available under :attr:`raw` so callers needing richer
    metadata can extract it without re-querying.

    Attributes:
        host: Host authority (``"example.com"`` or
            ``"example.com:8443"``). Sometimes returned with a
            ``"http://"`` / ``"https://"`` prefix; :py:meth:`to_url`
            normalises it.
        ip: Resolved IPv4/IPv6 address, or empty string when FOFA did
            not include the ``ip`` field.
        port: Numeric port. ``0`` indicates an unknown / not-returned
            port.
        scheme: Application-layer protocol (``"http"``, ``"https"``,
            ``"ftp"``, ...).
        raw: The original row tuple from the API, preserved verbatim.
    """

    host: str
    ip: str
    port: int
    scheme: str
    raw: tuple[str, ...]

    def to_url(self) -> str:
        """Reconstruct a normalised URL from the row.

        The host is preferred over the IP because it preserves SNI
        information when present. The port is omitted when it matches
        the well-known port for the scheme (``80`` for ``http``,
        ``443`` for ``https``) so the resulting URL is canonical and
        safe to use as a deduplication key.
        """
        host = self.host.strip()
        # Strip a leading scheme that some FOFA queries return
        # accidentally: when the ``host`` field itself encodes a URL
        # the call ``urljoin`` and friends produce surprising results.
        for prefix in ("https://", "http://"):
            if host.lower().startswith(prefix):
                host = host[len(prefix) :]
                break
        host = host.rstrip("/")

        scheme = self.scheme.strip().lower() or "http"
        # Some FOFA rows include the port in ``host`` ("foo.example:8443"),
        # others split it out into ``port``. Prefer the embedded port so
        # we don't double-emit ``:443:443``.
        if ":" in host and not host.startswith("["):
            return f"{scheme}://{host}"

        port = self.port
        if port in (0, _default_port_for(scheme)):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"


def _default_port_for(scheme: str) -> int:
    """Return the well-known TCP port for ``scheme`` or ``-1``.

    Used by :py:meth:`FofaResult.to_url` to decide whether to suppress
    a port from the canonical URL.
    """
    return {
        "http": 80,
        "https": 443,
        "ftp": 21,
        "ftps": 990,
    }.get(scheme.lower(), -1)


def _row_to_result(row: Sequence[Any], fields: Sequence[str]) -> FofaResult:
    """Translate a raw API row into a :class:`FofaResult`.

    FOFA returns rows as positional arrays whose columns correspond
    to the comma-separated ``fields`` parameter the client sent. This
    helper builds a name->value mapping from that ordering so we can
    look up the four canonical columns regardless of the order the
    caller specified.
    """
    raw_tuple = tuple(str(item) if item is not None else "" for item in row)
    by_name: dict[str, str] = {}
    for index, name in enumerate(fields):
        if index < len(raw_tuple):
            by_name[name] = raw_tuple[index]

    host = by_name.get("host", "")
    ip = by_name.get("ip", "")
    port_str = by_name.get("port", "")
    try:
        port = int(port_str) if port_str else 0
    except ValueError:
        port = 0
    scheme = by_name.get("protocol", "")

    return FofaResult(host=host, ip=ip, port=port, scheme=scheme, raw=raw_tuple)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class FofaClient:
    """Asynchronous client for the FOFA REST API.

    The client is intentionally thin: it owns the credential handling,
    base64-encodes the query (a FOFA quirk: queries travel as
    ``qbase64`` rather than as a plain URL parameter), drives
    pagination, and translates HTTP / payload errors into the local
    exception hierarchy. Everything else -- connection pooling,
    proxy/UA configuration, retry policy for transport errors --
    lives on the injected :class:`httpx.AsyncClient`.

    Example:
        >>> async with httpx.AsyncClient() as http:
        ...     client = FofaClient(http, email="me@example.com", key="...")
        ...     async for result in client.search('app="WordPress"'):
        ...         print(result.to_url())
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        email: str,
        key: str,
        base_url: str = _DEFAULT_BASE_URL,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        if not email:
            raise ValueError("FofaClient requires a non-empty email")
        if not key:
            raise ValueError("FofaClient requires a non-empty API key")
        self._http = http_client
        self._email = email
        self._key = key
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = rate_limiter

    # ---- Public API ---------------------------------------------------

    async def search(
        self,
        query: str | FofaQueryBuilder,
        *,
        max_pages: int = _DEFAULT_MAX_PAGES,
        page_size: int = _DEFAULT_PAGE_SIZE,
        fields: Sequence[str] | None = None,
    ) -> AsyncIterator[FofaResult]:
        """Iterate FOFA search results across pagination.

        Args:
            query: Either a literal FOFA query string or a
                :class:`FofaQueryBuilder` that materialises one.
            max_pages: Hard cap on the number of pages this call will
                walk. The default mirrors :data:`_DEFAULT_MAX_PAGES`.
                Passing a non-positive value yields nothing.
            page_size: Rows requested per page. FOFA caps this at
                100; values above that are silently clamped.
            fields: Override the columns returned. The default is
                :data:`_DEFAULT_FIELDS` which is sufficient for
                :py:meth:`FofaResult.to_url`. When customising,
                include at least one of ``host`` / ``ip`` so the
                rows can still be turned into URLs.

        Yields:
            One :class:`FofaResult` per row, in the order FOFA
            returned them.

        Raises:
            FofaApiError: The API returned a non-2xx response or a
                JSON payload with ``error: true``.
            FofaRateLimitError: The API kept rate-limiting the client
                across every retry attempt.
        """
        query_str = query.build() if isinstance(query, FofaQueryBuilder) else query
        if not query_str:
            raise ValueError("FOFA query must be non-empty")

        effective_fields = tuple(fields) if fields else _DEFAULT_FIELDS
        clamped_size = max(1, min(int(page_size), _DEFAULT_PAGE_SIZE))

        log = _LOGGER.bind(
            fofa_query_length=len(query_str),
            page_size=clamped_size,
            max_pages=max_pages,
            fields=",".join(effective_fields),
        )
        log.info("fofa.search.start")

        total_results = 0
        for page in range(1, max_pages + 1):
            page_log = log.bind(page=page)
            page_log.debug("fofa.search.page.request")

            payload = await self._fetch_page(
                query=query_str,
                page=page,
                size=clamped_size,
                fields=effective_fields,
            )

            rows = _coerce_rows(payload.get("results"))
            page_log.info("fofa.search.page.received", row_count=len(rows))
            for row in rows:
                yield _row_to_result(row, effective_fields)
                total_results += 1

            # Stop early when the page came back short -- FOFA does not
            # always populate the ``size`` field consistently and the
            # short-page heuristic mirrors the reference scraper.
            if len(rows) < clamped_size:
                page_log.debug("fofa.search.page.exhausted")
                break

        log.info("fofa.search.complete", result_count=total_results)

    async def search_to_assets(
        self,
        query: str | FofaQueryBuilder,
        *,
        discovery_source: DiscoverySource = DiscoverySource.FOFA,
        max_pages: int = _DEFAULT_MAX_PAGES,
        page_size: int = _DEFAULT_PAGE_SIZE,
        fields: Sequence[str] | None = None,
    ) -> AsyncIterator[WebsiteAsset]:
        """Wrap :py:meth:`search` and yield :class:`WebsiteAsset` instances.

        Each asset is given a fresh UUID identifier, the FOFA-derived
        URL as both ``url`` and ``normalized_url`` (the discovery
        layer does not yet have access to the project-wide URL
        normaliser), :class:`AssetStatus.UNKNOWN` (validation runs
        downstream), and the supplied ``discovery_source``.

        Args:
            query: Same semantics as :py:meth:`search`.
            discovery_source: Recorded on every emitted asset.
                Defaults to :class:`DiscoverySource.FOFA`; an operator
                can override it to tag assets discovered through a
                derived FOFA pipeline (e.g. enrichment workflows).
            max_pages: See :py:meth:`search`.
            page_size: See :py:meth:`search`.
            fields: See :py:meth:`search`.

        Yields:
            One :class:`WebsiteAsset` per FOFA row that produced a
            non-empty URL. Rows whose URL would degenerate to an
            empty string (no host and no IP) are skipped silently.
        """
        async for result in self.search(
            query,
            max_pages=max_pages,
            page_size=page_size,
            fields=fields,
        ):
            url = result.to_url()
            # Skip rows where the host degenerated to nothing useful
            # so we don't pollute the asset database with placeholder
            # entries like ``"http://"`` or ``"https:///"``.
            host_present = bool(result.host.strip()) or bool(result.ip.strip())
            if not host_present:
                continue
            now = datetime.now(timezone.utc)
            yield WebsiteAsset(
                id=uuid4().hex,
                url=url,
                normalized_url=url,
                discovered_at=now,
                last_checked=now,
                status=AssetStatus.UNKNOWN,
                discovery_source=discovery_source,
                metadata={"fofa_host": result.host, "fofa_ip": result.ip},
            )

    # ---- Internal: HTTP -----------------------------------------------

    async def _fetch_page(
        self,
        *,
        query: str,
        page: int,
        size: int,
        fields: Sequence[str],
    ) -> dict[str, Any]:
        """Issue a single GET to the FOFA search endpoint with retries.

        Implements exponential backoff for transient rate-limit
        responses. Raises :class:`FofaApiError` on permanent failures
        and :class:`FofaRateLimitError` once the retry budget is
        exhausted.
        """
        qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        params: dict[str, str] = {
            "email": self._email,
            "key": self._key,
            "qbase64": qbase64,
            "page": str(page),
            "size": str(size),
            "fields": ",".join(fields),
        }
        url = f"{self._base_url}{_SEARCH_PATH}"

        last_error: FofaError | None = None
        for attempt in range(_MAX_RETRIES):
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()

            try:
                response = await self._http.get(
                    url,
                    params=params,
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                # Transport-level failures (DNS, connect, read timeout,
                # ...) are wrapped as :class:`FofaApiError` so the
                # caller has a single base class to catch. They are
                # not retried here because the project-wide HTTP
                # client is expected to provide its own transport
                # retry policy.
                raise FofaApiError(f"FOFA HTTP transport error: {exc}") from exc

            if response.status_code == 429:
                last_error = FofaRateLimitError(
                    "FOFA rate-limited the request (HTTP 429)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code >= 400:
                raise FofaApiError(
                    f"FOFA API returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise FofaApiError(
                    "FOFA API returned non-JSON payload",
                    status_code=response.status_code,
                    body=_safe_text(response),
                ) from exc

            if not isinstance(payload, dict):
                raise FofaApiError(
                    "FOFA API returned unexpected JSON shape (not an object)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            error_flag = payload.get("error")
            if error_flag is True or (isinstance(error_flag, str) and error_flag):
                errmsg = str(payload.get("errmsg") or payload.get("error") or "")
                if _looks_like_rate_limit(errmsg):
                    last_error = FofaRateLimitError(
                        f"FOFA reported rate-limit error: {errmsg}",
                        status_code=response.status_code,
                        body=_safe_text(response),
                    )
                    await self._sleep_for_retry(attempt)
                    continue
                raise FofaApiError(
                    f"FOFA API error: {errmsg}" if errmsg else "FOFA API error",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            return payload

        # Retry budget exhausted: surface the last rate-limit error.
        if last_error is not None:
            raise last_error
        # Defensive: should not be reachable because every loop
        # iteration either returns, raises, or assigns ``last_error``.
        raise FofaApiError("FOFA API failed after retries with no diagnostic")

    @staticmethod
    async def _sleep_for_retry(attempt: int) -> None:
        """Sleep before retrying after a rate-limited response.

        Backoff schedule: ``base * 2 ** attempt + jitter``. The jitter
        is uniform in ``[0, _BACKOFF_JITTER_SECONDS)`` so a fleet of
        concurrent clients does not synchronise their retries.
        """
        delay = _BACKOFF_BASE_SECONDS * (2**attempt)
        delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
        await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_rows(value: Any) -> list[Sequence[Any]]:
    """Return a list of row sequences from a FOFA ``results`` field.

    FOFA returns either ``null``/missing (no results) or a list of
    rows, where each row is itself a list/tuple of strings. This
    helper coerces the value to a uniform shape so the caller can
    iterate without ``isinstance`` gymnastics.
    """
    if not value:
        return []
    if not isinstance(value, list):
        return []
    rows: list[Sequence[Any]] = []
    for row in value:
        if isinstance(row, (list, tuple)):
            rows.append(row)
        else:
            # Non-list rows are unexpected but not fatal -- wrap in a
            # single-element tuple so downstream code can still see
            # the raw value via ``FofaResult.raw``.
            rows.append((row,))
    return rows


def _looks_like_rate_limit(errmsg: str) -> bool:
    """Heuristic: does ``errmsg`` describe a rate-limit condition?

    FOFA's documented error strings for throttling include phrases
    like "Frequent Requests" and "rate limit"; matching on
    case-insensitive substrings is good enough since the alternative
    is a hard-coded list of error codes the API does not currently
    expose.
    """
    if not errmsg:
        return False
    lowered = errmsg.lower()
    return any(
        marker in lowered
        for marker in ("rate limit", "rate-limit", "frequent", "too many", "quota")
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


def _ensure_iterable(value: Iterable[str] | None) -> list[str]:
    """Return ``value`` as a list, coercing ``None`` to an empty list.

    Currently unused by the public API but kept so a future caller
    that wants to plumb a generator of fields through doesn't have
    to repeat the ``None``-coercion incantation.
    """
    if value is None:
        return []
    return list(value)
