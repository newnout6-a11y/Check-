"""Serper discovery module.

This module implements the Serper-side of the
:class:`webrecon.core.models.DiscoverySource.SERPER` channel: a thin,
type-strict, asynchronous client around the Serper.dev REST API
(https://serper.dev) that surfaces Google search results -- the
cornerstone of the project's "Google dorking" discovery flow. It
mirrors the structure of :mod:`webrecon.discovery.fofa` and
:mod:`webrecon.discovery.shodan` for consistency:

* :class:`GoogleDorkBuilder` -- a fluent, immutable builder that
  produces Google search expressions ("dorks", e.g.
  ``site:example.com inurl:admin filetype:pdf``). Chainable instance
  methods (:py:meth:`site`, :py:meth:`inurl`, :py:meth:`intitle`, ...)
  accumulate clauses; :py:meth:`exact` quotes a phrase, :py:meth:`exclude`
  emits a ``-term`` clause and :py:meth:`or_term` produces a
  parenthesised ``(a OR b)`` expression. Every chainable call returns
  a fresh instance so a partially-built dork can be safely shared
  between concurrent callers.

* :class:`SerperResult` -- a frozen dataclass describing one ``organic``
  result in a Serper response. The canonical columns (``title``,
  ``link``, ``snippet``, ``position``) are surfaced as named
  attributes; the original payload is preserved verbatim under
  :attr:`SerperResult.raw` so callers needing richer metadata
  (sitelinks, dates, attributes) can extract it without re-querying.

* :class:`SerperClient` -- the asynchronous client itself. It accepts an
  externally-managed :class:`httpx.AsyncClient` (so the project-wide
  connection pool and the test suite's :class:`httpx.MockTransport`
  plug in trivially) plus an ``api_key`` credential. The
  :py:meth:`~SerperClient.search` coroutine is an async iterator that
  yields one :class:`SerperResult` per organic result on a *single*
  page, sorted by :attr:`SerperResult.position`. The
  :py:meth:`~SerperClient.search_paginated` iterator walks pages
  until the server returns an empty page or ``max_pages`` is hit, and
  :py:meth:`~SerperClient.search_to_assets` wraps the same loop but
  yields :class:`webrecon.core.models.WebsiteAsset` instances ready
  to feed into the asset repository.

* Exception hierarchy: :class:`SerperError` (base),
  :class:`SerperApiError` (HTTP non-2xx) and
  :class:`SerperRateLimitError` (HTTP 429). The transport layer
  retries rate-limited requests with exponential backoff up to
  ``_MAX_RETRIES`` attempts; if the server is still rate-limiting
  after the final attempt the exception escapes to the caller.

Like :mod:`webrecon.discovery.fofa` and :mod:`webrecon.discovery.shodan`,
this module declares the minimal :class:`RateLimiter`
:class:`typing.Protocol` it needs locally so a real rate limiter can
be plugged in later without circular dependencies on
:mod:`webrecon.safety`.

Validates: Requirement 1.3 (Serper API search returns relevant
websites with result ranking), Requirement 1.5 (API keys via
configuration with rate-limit handling).
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
    "GoogleDorkBuilder",
    "RateLimiter",
    "SerperApiError",
    "SerperClient",
    "SerperError",
    "SerperRateLimitError",
    "SerperResult",
]


_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Default base URL for the Serper.dev REST API. ``base_url`` on
# :class:`SerperClient` is overridable so an operator can swap in a
# region-specific endpoint or a mock server.
_DEFAULT_BASE_URL: str = "https://google.serper.dev"

# REST endpoint suffix relative to ``base_url``. The leading slash
# matters because :class:`httpx.AsyncClient` joins the two with
# :func:`urllib.parse.urljoin` semantics.
_SEARCH_PATH: str = "/search"

# Header name Serper.dev uses for credential authentication. Listed
# as a constant so the test suite can assert against it without
# duplicating the literal.
_API_KEY_HEADER: str = "X-API-KEY"

# Serper accepts ``num`` between 1 and 100 per request (the documented
# Google-search ceiling). Pages cap out at 10 by convention; values
# above that produce diminishing returns because Google itself rarely
# surfaces more than ~100 organic results per query.
_DEFAULT_NUM: int = 10
_MAX_NUM: int = 100
_DEFAULT_MAX_PAGES: int = 5

# Retry policy for transient rate-limit responses. Backoff grows as
# ``_BACKOFF_BASE * 2 ** attempt`` with a small jitter so concurrent
# clients do not synchronise their retries. The values mirror
# :mod:`webrecon.discovery.fofa` and :mod:`webrecon.discovery.shodan`
# so an operator running every client in parallel sees comparable
# behaviour.
_MAX_RETRIES: int = 3
_BACKOFF_BASE_SECONDS: float = 1.0
_BACKOFF_JITTER_SECONDS: float = 0.5

# HTTP request timeout. Serper search responses are typically fast
# (< 2 s) but slow Google upstreams can occasionally take several
# seconds; 30 s is generous enough without hanging the discovery
# pipeline.
_REQUEST_TIMEOUT_SECONDS: float = 30.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SerperError(Exception):
    """Base class for every Serper-related runtime error.

    Catching :class:`SerperError` lets a caller treat any Serper
    failure mode uniformly (skip the source, fall back to another
    intelligence channel, ...) without having to enumerate the
    sub-classes.
    """


class SerperApiError(SerperError):
    """Raised when the Serper API returns a non-success response.

    Attributes:
        status_code: The HTTP status code returned by the server, or
            ``None`` if the failure happened before a response was
            received (for example: a JSON payload that could not be
            decoded on top of a 200 response).
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


class SerperRateLimitError(SerperApiError):
    """Raised when the Serper API rate-limits the client.

    Surfaces HTTP 429 responses. The retry machinery in
    :class:`SerperClient` raises this exception only after every
    retry attempt has been exhausted.
    """


# ---------------------------------------------------------------------------
# Rate-limiter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class RateLimiter(Protocol):
    """Minimal protocol consumed by :class:`SerperClient`.

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


def _quote_phrase(value: str) -> str:
    """Return ``value`` wrapped in double quotes for an exact-phrase match.

    Embedded double quotes are not officially documented as escapable
    in Google's query syntax, so we conservatively replace them with
    single quotes to keep the resulting expression syntactically
    valid. Empty values produce the literal ``""``.
    """
    if not value:
        return '""'
    sanitised = value.replace('"', "'")
    return f'"{sanitised}"'


@dataclass(frozen=True)
class GoogleDorkBuilder:
    """Fluent, immutable builder for Google search expressions ("dorks").

    Each :py:meth:`site`/:py:meth:`inurl`/... call returns a new
    builder with one extra clause appended; the original instance is
    never mutated. :py:meth:`build` joins the accumulated clauses
    with a single space, which Google interprets as logical AND.

    The builder covers the most useful classical-dorking operators:

    * :py:meth:`site` -- ``site:example.com``
    * :py:meth:`inurl` -- ``inurl:admin``
    * :py:meth:`intitle` -- ``intitle:login``
    * :py:meth:`intext` -- ``intext:password``
    * :py:meth:`filetype` / :py:meth:`ext` -- ``filetype:pdf``
    * :py:meth:`exclude` -- ``-shopify``
    * :py:meth:`exact` -- ``"exact phrase"``
    * :py:meth:`or_term` -- ``(stripe OR braintree)``
    * :py:meth:`raw` -- arbitrary expression for operators not yet wrapped.
    """

    clauses: tuple[str, ...] = field(default_factory=tuple)

    # ---- Field-level helpers ------------------------------------------

    def site(self, domain: str) -> Self:
        """Restrict results to ``domain`` via Google's ``site:`` operator."""
        if not domain.strip():
            raise ValueError("site domain must be non-empty")
        return self._with_clause(f"site:{domain.strip()}")

    def inurl(self, text: str) -> Self:
        """Match results whose URL contains ``text`` (``inurl:`` operator)."""
        if not text.strip():
            raise ValueError("inurl text must be non-empty")
        return self._with_clause(f"inurl:{text.strip()}")

    def intitle(self, text: str) -> Self:
        """Match results whose title contains ``text`` (``intitle:``)."""
        if not text.strip():
            raise ValueError("intitle text must be non-empty")
        return self._with_clause(f"intitle:{text.strip()}")

    def intext(self, text: str) -> Self:
        """Match results whose body contains ``text`` (``intext:``)."""
        if not text.strip():
            raise ValueError("intext text must be non-empty")
        return self._with_clause(f"intext:{text.strip()}")

    def filetype(self, ext: str) -> Self:
        """Restrict results to documents of file type ``ext``.

        Maps to Google's ``filetype:`` operator (e.g. ``"pdf"``,
        ``"xls"``, ``"sql"``). The leading dot is stripped so callers
        can pass either ``"pdf"`` or ``".pdf"``.
        """
        cleaned = ext.strip().lstrip(".")
        if not cleaned:
            raise ValueError("filetype extension must be non-empty")
        return self._with_clause(f"filetype:{cleaned}")

    def ext(self, ext: str) -> Self:
        """Alias for :py:meth:`filetype`.

        Google's ``ext:`` operator is a synonym for ``filetype:``.
        Exposing both keeps the builder consistent with the
        terminology used by various dork collections.
        """
        return self.filetype(ext)

    def exclude(self, term: str) -> Self:
        """Exclude results containing ``term`` (Google's ``-term`` syntax)."""
        cleaned = term.strip()
        if not cleaned:
            raise ValueError("exclude term must be non-empty")
        # Allow callers to pass a raw ``-term`` and avoid double-prefixing.
        if cleaned.startswith("-"):
            return self._with_clause(cleaned)
        return self._with_clause(f"-{cleaned}")

    def exact(self, phrase: str) -> Self:
        """Match the literal ``phrase`` by wrapping it in double quotes."""
        if not phrase.strip():
            raise ValueError("exact phrase must be non-empty")
        return self._with_clause(_quote_phrase(phrase.strip()))

    def or_term(self, *terms: str) -> Self:
        """Match any of ``terms`` via a parenthesised OR expression.

        At least two terms must be supplied; calling with a single
        term is almost certainly a mistake (it produces
        ``(term)`` which is equivalent to plain ``term``) and is
        rejected to surface the bug at the call site.
        """
        cleaned = [term.strip() for term in terms if term.strip()]
        if len(cleaned) < 2:
            raise ValueError("or_term requires at least two non-empty terms")
        joined = " OR ".join(cleaned)
        return self._with_clause(f"({joined})")

    def raw(self, expression: str) -> Self:
        """Append a raw, pre-formatted Google query fragment.

        Provides an escape hatch for Google operators the builder
        does not yet wrap (e.g. ``daterange:``, ``cache:``,
        ``related:``). The caller is responsible for proper quoting;
        the value is inserted verbatim.
        """
        if not expression.strip():
            raise ValueError("raw expression must be non-empty")
        return self._with_clause(expression.strip())

    # ---- Materialisation ----------------------------------------------

    def build(self) -> str:
        """Materialise the accumulated clauses into a Google query string.

        Returns the empty string when the builder is empty (no
        clauses appended yet). Otherwise joins clauses with a single
        space, which Google interprets as logical AND.
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
class SerperResult:
    """One organic result in a Serper search response.

    The four canonical columns Serper returns for every organic
    result are surfaced as named attributes; everything else
    (sitelinks, displayed link, attributes, dates, ...) is available
    under :attr:`raw` so callers needing richer metadata can extract
    it without re-querying.

    Attributes:
        title: The result's title text as Google rendered it.
        link: Fully-qualified URL of the result.
        snippet: Short Google-rendered snippet describing the page.
            May be empty when Google omitted it.
        position: 1-based ranking inside the result page. Used as
            the deterministic sort key in
            :py:meth:`SerperClient.search`.
        raw: The original organic-result object from the API,
            preserved verbatim. Stored as :class:`dict` so callers
            can use :py:meth:`dict.get` / pattern-match without
            coercing.
    """

    title: str
    link: str
    snippet: str
    position: int
    raw: dict[str, Any]


def _result_from_payload(payload: Mapping[str, Any]) -> SerperResult:
    """Translate a single organic-result dict into :class:`SerperResult`.

    Defensive about missing / wrong-typed fields: real Serper
    responses sometimes omit ``snippet`` or report unusual
    ``position`` values. Missing strings become ``""``, missing /
    invalid integers become ``0``. The original payload is
    preserved on :attr:`SerperResult.raw` so callers can recover any
    field the normaliser dropped.
    """
    title = str(payload.get("title") or "")
    link = str(payload.get("link") or "")
    snippet = str(payload.get("snippet") or "")

    position_value = payload.get("position", 0)
    try:
        position = int(position_value) if position_value is not None else 0
    except (TypeError, ValueError):
        position = 0

    return SerperResult(
        title=title,
        link=link,
        snippet=snippet,
        position=position,
        raw=dict(payload),
    )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class SerperClient:
    """Asynchronous client for the Serper.dev REST API.

    The client is intentionally thin: it owns the credential
    handling, drives pagination, and translates HTTP / payload
    errors into the local exception hierarchy. Everything else --
    connection pooling, proxy/UA configuration, retry policy for
    transport errors -- lives on the injected
    :class:`httpx.AsyncClient`.

    Example:
        >>> async with httpx.AsyncClient() as http:
        ...     client = SerperClient(http, api_key="...")
        ...     dork = GoogleDorkBuilder().site("example.com").inurl("admin")
        ...     async for result in client.search(dork):
        ...         print(result.position, result.link)
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
            raise ValueError("SerperClient requires a non-empty api_key")
        self._http = http_client
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = rate_limiter

    # ---- Public API ---------------------------------------------------

    async def search(
        self,
        query: str | GoogleDorkBuilder,
        *,
        num: int = _DEFAULT_NUM,
        page: int = 1,
        gl: str | None = None,
        hl: str | None = None,
    ) -> AsyncIterator[SerperResult]:
        """Issue a single Serper search request and iterate organic results.

        Each yielded :class:`SerperResult` corresponds to one entry
        in the response's ``organic`` list. Results are sorted by
        :attr:`SerperResult.position` ascending so the iterator
        produces a deterministic ranking even when the upstream
        order is jumbled.

        Args:
            query: Either a literal Google query string or a
                :class:`GoogleDorkBuilder` that materialises one.
            num: Number of organic results to request (Serper caps
                this at 100).
            page: 1-based page number. The first page is ``1``.
            gl: Optional ISO 3166-1 alpha-2 geo-location override
                (e.g. ``"us"``, ``"de"``) -- maps to Google's ``gl``
                parameter.
            hl: Optional ISO 639-1 language override (e.g. ``"en"``,
                ``"fr"``) -- maps to Google's ``hl`` parameter.

        Yields:
            One :class:`SerperResult` per organic result, sorted by
            :attr:`SerperResult.position` ascending.

        Raises:
            SerperApiError: The API returned a non-2xx response or a
                non-JSON payload.
            SerperRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
        """
        query_str = (
            query.build() if isinstance(query, GoogleDorkBuilder) else query
        )
        if not query_str:
            raise ValueError("Serper query must be non-empty")
        if page < 1:
            raise ValueError(f"page must be >= 1, got {page}")

        clamped_num = max(1, min(int(num), _MAX_NUM))

        body: dict[str, Any] = {
            "q": query_str,
            "num": clamped_num,
            "page": page,
        }
        if gl:
            body["gl"] = gl
        if hl:
            body["hl"] = hl

        log = _LOGGER.bind(
            serper_query_length=len(query_str),
            num=clamped_num,
            page=page,
            gl=gl or "",
            hl=hl or "",
        )
        log.info("serper.search.start")

        payload = await self._post_json(_SEARCH_PATH, body=body)

        organic = _coerce_organic(payload.get("organic"))
        results = [_result_from_payload(item) for item in organic]
        # Deterministic ranking: Serper *usually* returns ``organic``
        # already sorted by position, but the API does not guarantee
        # it -- sorting client-side gives the iterator a stable
        # contract regardless of upstream quirks.
        results.sort(key=lambda r: r.position)

        log.info("serper.search.complete", result_count=len(results))
        for result in results:
            yield result

    async def search_paginated(
        self,
        query: str | GoogleDorkBuilder,
        *,
        max_pages: int = _DEFAULT_MAX_PAGES,
        num: int = _DEFAULT_NUM,
        gl: str | None = None,
        hl: str | None = None,
    ) -> AsyncIterator[SerperResult]:
        """Walk Serper pages 1..``max_pages`` and stream every organic result.

        Stops early when a page returns no organic results -- Google
        does not always populate the response's ``searchInformation``
        consistently, so the empty-page heuristic is the most
        reliable termination signal.

        Args:
            query: Same semantics as :py:meth:`search`.
            max_pages: Hard cap on the number of pages this call
                will walk. The default mirrors
                :data:`_DEFAULT_MAX_PAGES`. Passing a non-positive
                value yields nothing.
            num: Per-page result count. See :py:meth:`search`.
            gl: Optional geo-location override. See :py:meth:`search`.
            hl: Optional language override. See :py:meth:`search`.

        Yields:
            One :class:`SerperResult` per organic result across every
            page walked. Results are sorted by position within a
            page; cross-page ordering follows the page sequence.

        Raises:
            SerperApiError: See :py:meth:`search`.
            SerperRateLimitError: See :py:meth:`search`.
        """
        log = _LOGGER.bind(max_pages=max_pages, num=num)
        log.info("serper.search_paginated.start")

        total = 0
        for page in range(1, max(0, max_pages) + 1):
            page_log = log.bind(page=page)
            page_log.debug("serper.search_paginated.page.request")

            page_results = 0
            async for result in self.search(
                query,
                num=num,
                page=page,
                gl=gl,
                hl=hl,
            ):
                page_results += 1
                total += 1
                yield result

            page_log.info(
                "serper.search_paginated.page.received",
                result_count=page_results,
            )
            # An empty page is the signal Google has run out of
            # organic results for the query; further pagination
            # would only burn API credits.
            if page_results == 0:
                page_log.debug("serper.search_paginated.page.exhausted")
                break

        log.info("serper.search_paginated.complete", result_count=total)

    async def search_to_assets(
        self,
        query: str | GoogleDorkBuilder,
        *,
        discovery_source: DiscoverySource = DiscoverySource.SERPER,
        max_pages: int = _DEFAULT_MAX_PAGES,
        num: int = _DEFAULT_NUM,
        gl: str | None = None,
        hl: str | None = None,
    ) -> AsyncIterator[WebsiteAsset]:
        """Wrap :py:meth:`search_paginated` and yield :class:`WebsiteAsset`.

        Each asset is given a fresh UUID identifier, the Serper
        result link as both ``url`` and ``normalized_url`` (the
        discovery layer does not yet have access to the project-wide
        URL normaliser), :class:`AssetStatus.UNKNOWN` (validation
        runs downstream), and the supplied ``discovery_source``. The
        Serper-specific provenance is stored under ``metadata``:
        ``serper_position``, ``serper_snippet`` and ``serper_title``
        so downstream filtering / ranking layers can re-use the
        original signal without re-querying.

        Args:
            query: Same semantics as :py:meth:`search`.
            discovery_source: Recorded on every emitted asset.
                Defaults to :class:`DiscoverySource.SERPER`; an
                operator can override it to tag assets discovered
                through a derived Serper pipeline (e.g. enrichment
                workflows).
            max_pages: See :py:meth:`search_paginated`.
            num: See :py:meth:`search_paginated`.
            gl: See :py:meth:`search`.
            hl: See :py:meth:`search`.

        Yields:
            One :class:`WebsiteAsset` per organic result with a
            non-empty ``link``. Results whose link is empty (which
            should not happen but the API contract is not guaranteed)
            are skipped silently.
        """
        async for result in self.search_paginated(
            query,
            max_pages=max_pages,
            num=num,
            gl=gl,
            hl=hl,
        ):
            link = result.link.strip()
            if not link:
                continue
            now = datetime.now(timezone.utc)
            metadata: dict[str, str] = {
                "serper_position": str(result.position),
                "serper_snippet": result.snippet,
                "serper_title": result.title,
            }
            yield WebsiteAsset(
                id=uuid4().hex,
                url=link,
                normalized_url=link,
                discovered_at=now,
                last_checked=now,
                status=AssetStatus.UNKNOWN,
                discovery_source=discovery_source,
                metadata=metadata,
            )

    # ---- Internal: HTTP -----------------------------------------------

    async def _post_json(
        self,
        path: str,
        *,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Issue a POST that expects a JSON object response, with retries.

        Implements exponential backoff for transient rate-limit
        responses. Raises :class:`SerperApiError` on permanent
        failures and :class:`SerperRateLimitError` once the retry
        budget is exhausted.
        """
        url = f"{self._base_url}{path}"
        headers: dict[str, str] = {
            _API_KEY_HEADER: self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        last_error: SerperError | None = None
        for attempt in range(_MAX_RETRIES):
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()

            try:
                response = await self._http.post(
                    url,
                    json=dict(body),
                    headers=headers,
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                # Transport-level failures (DNS, connect, read
                # timeout, ...) are wrapped as :class:`SerperApiError`
                # so the caller has a single base class to catch.
                # They are not retried here because the project-wide
                # HTTP client is expected to provide its own
                # transport retry policy.
                raise SerperApiError(
                    f"Serper HTTP transport error: {exc}"
                ) from exc

            if response.status_code == 401:
                raise SerperApiError(
                    "Serper API rejected the api_key (HTTP 401). "
                    "Verify the configured api_key is valid.",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            if response.status_code == 403:
                raise SerperApiError(
                    "Serper API forbade the request (HTTP 403)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            if response.status_code == 429:
                last_error = SerperRateLimitError(
                    "Serper rate-limited the request (HTTP 429)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )
                await self._sleep_for_retry(attempt)
                continue

            if response.status_code >= 500:
                # Server-side failures: surface as a generic API
                # error so the caller can decide whether to retry at
                # a higher level. Not retried inline because Serper
                # 5xx responses are usually persistent.
                raise SerperApiError(
                    f"Serper API returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            if response.status_code >= 400:
                raise SerperApiError(
                    f"Serper API returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise SerperApiError(
                    "Serper API returned non-JSON payload",
                    status_code=response.status_code,
                    body=_safe_text(response),
                ) from exc

            if not isinstance(payload, dict):
                raise SerperApiError(
                    "Serper API returned unexpected JSON shape "
                    "(not an object)",
                    status_code=response.status_code,
                    body=_safe_text(response),
                )

            return payload

        # Retry budget exhausted: surface the last rate-limit error.
        if last_error is not None:
            raise last_error
        # Defensive: should not be reachable because every loop
        # iteration either returns, raises, or assigns ``last_error``.
        raise SerperApiError(
            "Serper API failed after retries with no diagnostic"
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


def _coerce_organic(value: Any) -> list[Mapping[str, Any]]:
    """Return a list of organic-result dicts from a Serper ``organic`` field.

    Serper returns either ``null``/missing (no results) or a list
    of objects, where each object is a mapping of fields. This
    helper coerces the value to a uniform shape so the caller can
    iterate without ``isinstance`` gymnastics.
    """
    if not value:
        return []
    if not isinstance(value, list):
        return []
    organic: list[Mapping[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            organic.append(item)
        # Non-dict items are silently skipped: they cannot be
        # turned into a :class:`SerperResult` and dropping them is
        # less harmful than crashing the whole iterator.
    return organic


def _safe_text(response: httpx.Response) -> str:
    """Best-effort decode of ``response.text`` for diagnostics."""
    try:
        return response.text
    except Exception:  # pragma: no cover - defensive
        try:
            return response.content.decode("utf-8", errors="replace")
        except Exception:
            return ""
