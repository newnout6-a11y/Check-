"""GitHub repository intelligence module.

This module implements the GitHub side of the
:class:`webrecon.core.models.DiscoverySource.GITHUB` channel: a thin,
type-strict, asynchronous client around the public GitHub REST API
v3 (https://docs.github.com/en/rest). It mirrors the structure of
:mod:`webrecon.discovery.fofa` and :mod:`webrecon.discovery.serper`
for consistency:

* :class:`GithubQueryBuilder` -- a fluent, immutable builder that
  produces GitHub search expressions
  (``"sk_live_" filename:.env extension:env`` …). Chainable instance
  methods (:py:meth:`keyword`, :py:meth:`language`, :py:meth:`filename`,
  :py:meth:`repo`, :py:meth:`user`, :py:meth:`in_`, ...) accumulate
  clauses; :py:meth:`raw` provides an escape hatch for advanced
  qualifiers; :py:meth:`build` materialises the final string. Every
  chainable call returns a fresh instance so a partially-built
  query can be safely shared between concurrent callers.

* :class:`GithubCodeMatch` -- a frozen dataclass describing one entry
  in a GitHub ``/search/code`` response. The canonical columns
  (``name``, ``path``, ``sha``, ``html_url``, ``repository``) are
  surfaced as named attributes; the original payload is preserved
  verbatim under :attr:`GithubCodeMatch.raw` so callers needing
  richer metadata (text-matches, score, ...) can extract it without
  re-querying. :py:meth:`~GithubCodeMatch.download_url` returns the
  ``raw.githubusercontent.com`` URL when present in the payload or
  derives one from ``html_url``.

* :class:`GithubClient` -- the asynchronous client itself. It accepts
  an externally-managed :class:`httpx.AsyncClient` (so the
  project-wide connection pool and the test suite's
  :class:`httpx.MockTransport` plug in trivially) plus a personal
  access ``token``. The :py:meth:`~GithubClient.search_code` and
  :py:meth:`~GithubClient.search_repositories` coroutines are async
  iterators that walk pagination; :py:meth:`~GithubClient.get_file_content`
  returns the decoded bytes of a tracked file via the ``contents``
  endpoint, and :py:meth:`~GithubClient.get_raw_file` fetches an
  arbitrary ``raw.githubusercontent.com`` URL without authentication.

* Exception hierarchy: :class:`GithubError` (base),
  :class:`GithubApiError` (HTTP non-2xx), :class:`GithubRateLimitError`
  (HTTP 403 with ``X-RateLimit-Remaining: 0`` -- exposes the parsed
  ``reset_at`` timestamp), :class:`GithubAuthError` (HTTP 401). The
  transport layer waits for the documented reset window (capped at
  60 s, max 3 attempts) for primary rate-limit responses before
  retrying.

Like :mod:`webrecon.discovery.fofa` and :mod:`webrecon.discovery.serper`,
this module declares the minimal :class:`RateLimiter`
:class:`typing.Protocol` it needs locally so a real rate limiter can
be plugged in later without circular dependencies on
:mod:`webrecon.safety`.

Validates: Requirement 2.1 (GitHub repository search with pagination
and result filtering), Requirement 2.4 (rate-limit handling with
exponential backoff and request queuing).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Protocol, TypeVar, runtime_checkable
from urllib.parse import quote

import httpx

from webrecon.log import get_logger
from webrecon.version import __version__ as _WEBRECON_VERSION  # noqa: N812

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Mapping

    from typing_extensions import Self


# TypeVar used by :py:meth:`GithubClient._iter_search` to keep the
# generic transform callable strict-friendly under mypy ``--strict``.
_T = TypeVar("_T")


__all__ = [
    "GithubApiError",
    "GithubAuthError",
    "GithubClient",
    "GithubCodeMatch",
    "GithubError",
    "GithubQueryBuilder",
    "GithubRateLimitError",
    "RateLimiter",
]


_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Default base URL for the GitHub REST API. ``base_url`` on
# :class:`GithubClient` is overridable so an operator can swap in a
# GitHub Enterprise endpoint or a mock server.
_DEFAULT_BASE_URL: str = "https://api.github.com"

# REST endpoint suffixes relative to ``base_url``.
_SEARCH_CODE_PATH: str = "/search/code"
_SEARCH_REPOSITORIES_PATH: str = "/search/repositories"

# GitHub caps every search response at 1000 results -- 100 results
# per page * 10 pages. Expose both bounds so callers can shrink the
# walk for tests / debugging.
_MAX_PER_PAGE: int = 100
_DEFAULT_PER_PAGE: int = 30
_DEFAULT_MAX_PAGES: int = 10

# Retry policy for primary rate-limit responses (HTTP 403 with
# ``X-RateLimit-Remaining: 0``). Each retry waits for the documented
# reset window, capped at :data:`_MAX_RATE_LIMIT_WAIT_SECONDS` so a
# misbehaving server cannot freeze the discovery pipeline. A small
# jitter avoids waking every concurrent client at the same instant.
_MAX_RETRIES: int = 3
_MAX_RATE_LIMIT_WAIT_SECONDS: float = 60.0
_BACKOFF_JITTER_SECONDS: float = 0.5

# Fallback backoff schedule when a 403 / 429 carries no usable
# ``X-RateLimit-Reset`` / ``Retry-After`` header. ``base * 2 ** attempt``
# matches the pattern used in :mod:`webrecon.discovery.fofa` so an
# operator running every client in parallel sees comparable behaviour.
_BACKOFF_BASE_SECONDS: float = 1.0

# HTTP request timeout. GitHub search responses are usually fast
# (< 2 s) but heavy queries can occasionally take several seconds;
# 30 s is generous enough without hanging the discovery pipeline.
_REQUEST_TIMEOUT_SECONDS: float = 30.0

# Static request headers. ``Accept`` requests the v3 JSON envelope
# *with* text-match annotations (so callers can highlight the matched
# fragment); ``X-GitHub-Api-Version`` pins the schema GitHub
# documents at https://docs.github.com/en/rest/overview/api-versions.
# ``User-Agent`` is required by GitHub for every request -- omitting
# it causes the API to reject the call with HTTP 403.
_ACCEPT_HEADER: str = "application/vnd.github.text-match+json"
_API_VERSION_HEADER: str = "2022-11-28"
_USER_AGENT: str = f"webrecon/{_WEBRECON_VERSION}"

# When fetching the raw content of a file via ``/repos/.../contents/...``,
# GitHub returns base64 in ``content`` by default. We decode that ourselves
# so callers always see plain bytes regardless of whether the API
# returned ``encoding: base64`` or a redirect.
_CONTENT_ENCODING_BASE64: str = "base64"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GithubError(Exception):
    """Base class for every GitHub-related runtime error.

    Catching :class:`GithubError` lets a caller treat any GitHub
    failure mode uniformly (skip the source, fall back to another
    intelligence channel, ...) without having to enumerate the
    sub-classes.
    """


class GithubApiError(GithubError):
    """Raised when the GitHub API returns a non-success response.

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


class GithubAuthError(GithubApiError):
    """Raised when the GitHub API rejects the supplied token (HTTP 401).

    Surfaces unauthenticated / revoked-token responses as a dedicated
    sub-class so callers can short-circuit the discovery pipeline
    rather than retrying the request with the same broken credentials.
    """


class GithubRateLimitError(GithubApiError):
    """Raised when the GitHub API rate-limits the client.

    Surfaces both the primary ``X-RateLimit-Remaining: 0`` rate-limit
    (HTTP 403 with the ``X-RateLimit-Reset`` header set) and secondary
    rate-limit responses (HTTP 429 with ``Retry-After``). The retry
    machinery in :class:`GithubClient` raises this exception only
    after every retry attempt has been exhausted.

    Attributes:
        reset_at: UTC :class:`datetime` parsed from the
            ``X-RateLimit-Reset`` header (or, for HTTP 429,
            constructed from ``Retry-After``). ``None`` when neither
            header was present.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: str | None = None,
        reset_at: datetime | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, body=body)
        self.reset_at = reset_at


# ---------------------------------------------------------------------------
# Rate-limiter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class RateLimiter(Protocol):
    """Minimal protocol consumed by :class:`GithubClient`.

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


def _quote_qualifier(value: str) -> str:
    """Quote a GitHub search-qualifier value if it contains whitespace.

    GitHub's search syntax treats space as a clause separator, so
    values with embedded spaces (rare in practice for ``filename:`` /
    ``language:`` qualifiers but possible for ``path:``) must be
    wrapped in double quotes. Embedded double quotes are conservatively
    replaced with single quotes -- they are not officially escapable
    in the GitHub query language and keeping a syntactically valid
    expression is more important than preserving an exotic literal.
    """
    if not value:
        return '""'
    if any(ch.isspace() or ch == '"' for ch in value):
        sanitised = value.replace('"', "'")
        return f'"{sanitised}"'
    return value


@dataclass(frozen=True)
class GithubQueryBuilder:
    """Fluent, immutable builder for GitHub search expressions.

    Each :py:meth:`keyword`/:py:meth:`language`/:py:meth:`filename`/...
    call returns a new builder with one extra clause appended; the
    original instance is never mutated. :py:meth:`build` joins the
    accumulated clauses with a single space, which GitHub interprets
    as logical AND between qualifiers.

    The builder covers the most useful GitHub code/repository search
    qualifiers:

    * :py:meth:`keyword` -- free-text search term
    * :py:meth:`language` -- ``language:python``
    * :py:meth:`extension` -- ``extension:env``
    * :py:meth:`filename` -- ``filename:.env``
    * :py:meth:`repo` -- ``repo:owner/name``
    * :py:meth:`user` -- ``user:octocat``
    * :py:meth:`org` -- ``org:github``
    * :py:meth:`path` -- ``path:src/config``
    * :py:meth:`size` -- ``size:>100``
    * :py:meth:`in_` -- ``in:file`` / ``in:path``
    * :py:meth:`raw` -- arbitrary expression for qualifiers not yet wrapped.
    """

    clauses: tuple[str, ...] = field(default_factory=tuple)

    # ---- Field-level helpers ------------------------------------------

    def keyword(self, text: str) -> Self:
        """Append a free-text search term.

        GitHub treats unqualified terms as full-text search across the
        indexed code/repository content. Multi-word phrases are
        wrapped in double quotes so they are matched as a single
        token; bare alphanumerics travel through verbatim.
        """
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("keyword must be non-empty")
        return self._with_clause(_quote_qualifier(cleaned))

    def language(self, lang: str) -> Self:
        """Restrict results to a programming language (``language:`` qualifier)."""
        cleaned = lang.strip()
        if not cleaned:
            raise ValueError("language must be non-empty")
        return self._with_clause(f"language:{_quote_qualifier(cleaned)}")

    def extension(self, ext: str) -> Self:
        """Restrict results to a file extension (``extension:`` qualifier).

        The leading dot is stripped so callers can pass either ``"env"``
        or ``".env"``.
        """
        cleaned = ext.strip().lstrip(".")
        if not cleaned:
            raise ValueError("extension must be non-empty")
        return self._with_clause(f"extension:{_quote_qualifier(cleaned)}")

    def filename(self, name: str) -> Self:
        """Restrict results to a file name (``filename:`` qualifier)."""
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("filename must be non-empty")
        return self._with_clause(f"filename:{_quote_qualifier(cleaned)}")

    def repo(self, owner_repo: str) -> Self:
        """Restrict results to a single repository (``repo:owner/name``).

        Validates the ``owner/repo`` shape because GitHub silently
        ignores ``repo:`` qualifiers that are missing the slash, which
        produces confusing zero-result responses.
        """
        cleaned = owner_repo.strip()
        if "/" not in cleaned:
            raise ValueError(
                f"repo must be in 'owner/name' format, got {owner_repo!r}"
            )
        return self._with_clause(f"repo:{_quote_qualifier(cleaned)}")

    def user(self, name: str) -> Self:
        """Restrict results to repositories owned by ``name``."""
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("user must be non-empty")
        return self._with_clause(f"user:{_quote_qualifier(cleaned)}")

    def org(self, name: str) -> Self:
        """Restrict results to repositories under organisation ``name``."""
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("org must be non-empty")
        return self._with_clause(f"org:{_quote_qualifier(cleaned)}")

    def path(self, p: str) -> Self:
        """Restrict results to files under ``path`` (``path:`` qualifier)."""
        cleaned = p.strip()
        if not cleaned:
            raise ValueError("path must be non-empty")
        return self._with_clause(f"path:{_quote_qualifier(cleaned)}")

    def size(self, spec: str) -> Self:
        """Restrict results by file size (``size:`` qualifier).

        GitHub accepts comparison operators (``size:>1000``,
        ``size:<=500``) and explicit ranges (``size:100..500``) so
        the value is passed through verbatim after a non-empty
        check; quoting only kicks in for whitespace-containing
        specifications (which are unusual but legal).
        """
        cleaned = spec.strip()
        if not cleaned:
            raise ValueError("size must be non-empty")
        return self._with_clause(f"size:{_quote_qualifier(cleaned)}")

    def in_(self, scope: str) -> Self:
        """Restrict the search scope (``in:`` qualifier).

        GitHub accepts ``in:file`` and ``in:path`` for code search
        (and a handful of values like ``in:name``, ``in:description``
        for repository search). The value is normalised to lower-case
        so callers can pass either ``"file"`` or ``"FILE"``.
        """
        cleaned = scope.strip().lower()
        if not cleaned:
            raise ValueError("in_ scope must be non-empty")
        return self._with_clause(f"in:{cleaned}")

    def raw(self, expression: str) -> Self:
        """Append a raw, pre-formatted GitHub query fragment.

        Provides an escape hatch for qualifiers the builder does not
        yet wrap (e.g. ``stars:``, ``created:``, ``license:``). The
        caller is responsible for proper quoting; the value is
        inserted verbatim.
        """
        cleaned = expression.strip()
        if not cleaned:
            raise ValueError("raw expression must be non-empty")
        return self._with_clause(cleaned)

    # ---- Materialisation ----------------------------------------------

    def build(self) -> str:
        """Materialise the accumulated clauses into a GitHub query string.

        Returns the empty string when the builder is empty (no
        clauses appended yet). Otherwise joins clauses with a single
        space, which GitHub interprets as logical AND.
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
class GithubCodeMatch:
    """One entry in a GitHub ``/search/code`` response.

    The five canonical columns GitHub returns for every code-search
    item are surfaced as named attributes; everything else
    (``score``, ``text_matches``, ``git_url``, ``last_modified_at``,
    ...) is available under :attr:`raw` so callers needing richer
    metadata can extract it without re-querying.

    Attributes:
        name: Basename of the matched file (e.g. ``"config.py"``).
        path: Repository-relative path of the matched file (e.g.
            ``"src/config.py"``).
        sha: 40-character SHA-1 of the file blob.
        html_url: Web-UI URL pointing at the file in the repository.
        repository: The ``repository`` sub-object verbatim. Stored as
            :class:`dict` so callers can use :py:meth:`dict.get` /
            pattern-match without coercing.
        raw: The original item object from the API, preserved
            verbatim. Stored as :class:`dict` for the same reasons
            as :attr:`repository`.
    """

    name: str
    path: str
    sha: str
    html_url: str
    repository: dict[str, Any]
    raw: dict[str, Any]

    def download_url(self) -> str:
        """Return a ``raw.githubusercontent.com`` URL for the matched file.

        Strategy, in priority order:

        1. If the API payload included a ``download_url`` field (the
           ``contents`` endpoint sometimes inlines it on code-search
           items), use it verbatim.
        2. Otherwise reconstruct the URL from
           :attr:`repository.full_name`, the file :attr:`path`, and
           the file :attr:`sha`. Using the SHA (rather than a branch
           name) guarantees that the returned URL points at the exact
           blob version the search returned, even when the default
           branch advances afterwards.
        3. As a last-resort fallback when the repository payload is
           empty, return :attr:`html_url` -- not a true raw URL but
           still a valid pointer the caller can render.
        """
        existing = self.raw.get("download_url")
        if isinstance(existing, str) and existing:
            return existing

        full_name = ""
        repo = self.repository
        if isinstance(repo, dict):
            value = repo.get("full_name")
            if isinstance(value, str):
                full_name = value

        if full_name and self.sha and self.path:
            quoted_path = quote(self.path, safe="/")
            return (
                f"https://raw.githubusercontent.com/"
                f"{full_name}/{self.sha}/{quoted_path}"
            )

        return self.html_url


def _match_from_payload(payload: Mapping[str, Any]) -> GithubCodeMatch:
    """Translate one ``/search/code`` item dict into :class:`GithubCodeMatch`.

    Defensive about missing / wrong-typed fields: real GitHub
    responses occasionally omit ``sha`` for legacy index entries and
    occasionally return ``repository: null`` for archived projects.
    Missing strings become ``""``, missing dicts become ``{}``. The
    original payload is preserved on :attr:`GithubCodeMatch.raw` so
    callers can recover any field the normaliser dropped.
    """
    name = str(payload.get("name") or "")
    path = str(payload.get("path") or "")
    sha = str(payload.get("sha") or "")
    html_url = str(payload.get("html_url") or "")

    repo_value = payload.get("repository")
    repository: dict[str, Any] = (
        dict(repo_value) if isinstance(repo_value, dict) else {}
    )

    return GithubCodeMatch(
        name=name,
        path=path,
        sha=sha,
        html_url=html_url,
        repository=repository,
        raw=dict(payload),
    )



# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GithubClient:
    """Asynchronous client for the GitHub REST API.

    The client is intentionally thin: it owns the credential
    handling, drives pagination, and translates HTTP / payload
    errors into the local exception hierarchy. Everything else --
    connection pooling, proxy/UA configuration, transport-level
    retry policy -- lives on the injected
    :class:`httpx.AsyncClient`.

    Example:
        >>> async with httpx.AsyncClient() as http:
        ...     client = GithubClient(http, token="ghp_...")
        ...     query = GithubQueryBuilder().keyword("sk_live_").filename(".env")
        ...     async for match in client.search_code(query):
        ...         print(match.repository["full_name"], match.path)
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        token: str,
        base_url: str = _DEFAULT_BASE_URL,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        if not token:
            raise ValueError("GithubClient requires a non-empty token")
        self._http = http_client
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = rate_limiter

    # ---- Public API ---------------------------------------------------

    async def search_code(
        self,
        query: str | GithubQueryBuilder,
        *,
        max_pages: int = _DEFAULT_MAX_PAGES,
        per_page: int = _DEFAULT_PER_PAGE,
    ) -> AsyncIterator[GithubCodeMatch]:
        """Iterate ``/search/code`` results across pagination.

        Args:
            query: Either a literal GitHub query string or a
                :class:`GithubQueryBuilder` that materialises one.
            max_pages: Hard cap on the number of pages this call will
                walk. The default mirrors :data:`_DEFAULT_MAX_PAGES`
                (which matches GitHub's documented 1000-result ceiling
                with the default ``per_page``). Passing a non-positive
                value yields nothing.
            per_page: Items requested per page. GitHub caps this at
                100; values above that are silently clamped.

        Yields:
            One :class:`GithubCodeMatch` per item in the order GitHub
            returned them.

        Raises:
            GithubAuthError: The supplied token is invalid (HTTP 401).
            GithubApiError: The API returned a non-2xx response or a
                non-JSON payload.
            GithubRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
        """
        async for match in self._iter_search(
            path=_SEARCH_CODE_PATH,
            query=query,
            max_pages=max_pages,
            per_page=per_page,
            transform=_match_from_payload,
        ):
            yield match

    async def search_repositories(
        self,
        query: str | GithubQueryBuilder,
        *,
        max_pages: int = _DEFAULT_MAX_PAGES,
        per_page: int = _DEFAULT_PER_PAGE,
    ) -> AsyncIterator[dict[str, Any]]:
        """Iterate ``/search/repositories`` results across pagination.

        The repository-search response is dramatically richer than
        the code-search response (license, stars, default branch,
        topics, ...) and stable enough across API versions that
        callers benefit more from the verbatim dict than from a
        narrow projection. The iterator therefore yields raw
        ``items`` dicts; downstream code can map them onto domain
        objects as needed.

        Args:
            query: Either a literal GitHub query string or a
                :class:`GithubQueryBuilder` that materialises one.
            max_pages: Hard cap on the number of pages this call
                will walk. See :py:meth:`search_code`.
            per_page: Items requested per page. See
                :py:meth:`search_code`.

        Yields:
            One :class:`dict` per item in the order GitHub returned
            them.

        Raises:
            GithubAuthError: The supplied token is invalid (HTTP 401).
            GithubApiError: The API returned a non-2xx response or a
                non-JSON payload.
            GithubRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
        """

        def _identity(item: Mapping[str, Any]) -> dict[str, Any]:
            return dict(item)

        async for repo in self._iter_search(
            path=_SEARCH_REPOSITORIES_PATH,
            query=query,
            max_pages=max_pages,
            per_page=per_page,
            transform=_identity,
        ):
            yield repo

    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        *,
        ref: str | None = None,
    ) -> bytes:
        """Fetch and decode the raw bytes of a tracked file.

        Calls ``/repos/{owner}/{repo}/contents/{path}`` and decodes
        the base64-encoded ``content`` field. When the file is too
        large for the inline payload (GitHub returns
        ``encoding: "none"`` and an empty ``content``) the call
        falls back to :py:meth:`get_raw_file` against the response's
        ``download_url``.

        Args:
            owner: Repository owner (user or organisation).
            repo: Repository name.
            path: Repository-relative file path.
            ref: Optional branch / tag / SHA selector. When omitted,
                GitHub returns the file at the default branch tip.

        Returns:
            The file's raw bytes.

        Raises:
            GithubAuthError: The supplied token is invalid (HTTP 401).
            GithubApiError: The API returned a non-2xx response, an
                unexpected payload shape, or content the client could
                not decode.
            GithubRateLimitError: The API kept rate-limiting the
                client across every retry attempt.
        """
        if not owner or not repo or not path:
            raise ValueError(
                "owner, repo and path are required to fetch file content"
            )

        # ``path`` may include forward slashes; quote each segment
        # individually so the slashes are preserved while special
        # characters (spaces, accents, ...) are percent-encoded.
        quoted_path = quote(path.lstrip("/"), safe="/")
        endpoint = f"/repos/{owner}/{repo}/contents/{quoted_path}"

        params: dict[str, str] = {}
        if ref:
            params["ref"] = ref

        log = _LOGGER.bind(
            github_owner=owner,
            github_repo=repo,
            github_path=path,
            github_ref=ref or "",
        )
        log.debug("github.get_file_content.request")

        payload = await self._request_json(
            "GET",
            endpoint,
            params=params or None,
        )

        if not isinstance(payload, dict):
            raise GithubApiError(
                "GitHub contents endpoint returned an unexpected JSON shape "
                "(expected an object)",
            )

        encoding = str(payload.get("encoding") or "")
        content_value = payload.get("content")
        if encoding == _CONTENT_ENCODING_BASE64 and isinstance(content_value, str):
            try:
                # GitHub returns base64 with embedded newlines; the
                # standard decoder ignores them when ``validate`` is
                # left at its default of ``False``.
                return base64.b64decode(content_value)
            except (ValueError, binascii.Error) as exc:
                raise GithubApiError(
                    f"GitHub contents endpoint returned malformed base64: {exc}",
                ) from exc

        # Files larger than ~1 MiB are returned with ``encoding: "none"``
        # and an empty ``content`` -- the caller is expected to follow
        # ``download_url`` instead. Surface that path transparently.
        download_url = payload.get("download_url")
        if isinstance(download_url, str) and download_url:
            return await self.get_raw_file(download_url)

        raise GithubApiError(
            "GitHub contents endpoint returned no decodable content "
            f"(encoding={encoding!r})",
        )

    async def get_raw_file(self, url: str) -> bytes:
        """Fetch raw bytes from an arbitrary URL without authentication.

        Designed for ``raw.githubusercontent.com`` / GitHub-hosted
        download URLs returned by the search and contents endpoints.
        The ``Authorization`` header is intentionally omitted because
        ``raw.githubusercontent.com`` rejects requests that carry a
        bearer token meant for ``api.github.com`` (and, for public
        repositories, the resource is anonymous-readable anyway).

        Args:
            url: Absolute URL to fetch.

        Returns:
            The response body bytes.

        Raises:
            GithubApiError: The fetch failed at the transport layer
                or returned a non-2xx response.
        """
        if not url:
            raise ValueError("url must be non-empty")

        log = _LOGGER.bind(github_raw_url=url)
        log.debug("github.get_raw_file.request")

        headers: dict[str, str] = {
            "Accept": "*/*",
            "User-Agent": _USER_AGENT,
        }

        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()

        try:
            response = await self._http.get(
                url,
                headers=headers,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise GithubApiError(
                f"GitHub raw fetch transport error: {exc}",
            ) from exc

        if response.status_code >= 400:
            raise GithubApiError(
                f"GitHub raw fetch returned HTTP {response.status_code}",
                status_code=response.status_code,
                body=_safe_text(response),
            )

        return response.content

    # ---- Internal: search pagination ----------------------------------

    async def _iter_search(
        self,
        *,
        path: str,
        query: str | GithubQueryBuilder,
        max_pages: int,
        per_page: int,
        transform: Callable[[Mapping[str, Any]], _T],
    ) -> AsyncIterator[_T]:
        """Drive pagination for any of GitHub's ``/search/...`` endpoints.

        GitHub's search responses always carry a ``total_count`` and
        an ``items`` list; this helper walks pages until either
        ``max_pages`` is reached, ``items`` comes back short of
        ``per_page`` (signalling exhaustion), or the running yield
        count meets ``total_count``. Each item is transformed by the
        ``transform`` callable so the same loop can serve both
        :py:meth:`search_code` (yielding :class:`GithubCodeMatch`)
        and :py:meth:`search_repositories` (yielding raw dicts).
        """
        query_str = (
            query.build() if isinstance(query, GithubQueryBuilder) else query
        )
        if not query_str:
            raise ValueError("GitHub query must be non-empty")
        if max_pages <= 0:
            return

        clamped_per_page = max(1, min(int(per_page), _MAX_PER_PAGE))

        log = _LOGGER.bind(
            github_endpoint=path,
            github_query_length=len(query_str),
            per_page=clamped_per_page,
            max_pages=max_pages,
        )
        log.info("github.search.start")

        total_yielded = 0
        for page in range(1, max_pages + 1):
            page_log = log.bind(page=page)
            page_log.debug("github.search.page.request")

            params: dict[str, str] = {
                "q": query_str,
                "page": str(page),
                "per_page": str(clamped_per_page),
            }
            payload = await self._request_json("GET", path, params=params)

            items = _coerce_items(payload.get("items"))
            total_count = _coerce_total(payload.get("total_count"))

            page_log.info(
                "github.search.page.received",
                item_count=len(items),
                total_count=total_count,
            )

            for item in items:
                yield transform(item)
                total_yielded += 1
                if total_count is not None and total_yielded >= total_count:
                    log.info(
                        "github.search.complete",
                        result_count=total_yielded,
                        reason="total_count_reached",
                    )
                    return

            # An incomplete page means GitHub has nothing more to
            # offer for this query; further pagination would only
            # burn API budget.
            if len(items) < clamped_per_page:
                page_log.debug("github.search.page.exhausted")
                break

        log.info("github.search.complete", result_count=total_yielded)

    # ---- Internal: HTTP -----------------------------------------------

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Issue an authenticated request and decode a JSON object response.

        Implements bounded retries for primary rate-limit responses
        (HTTP 403 with ``X-RateLimit-Remaining: 0``) and secondary
        rate-limit responses (HTTP 429). Raises
        :class:`GithubAuthError` on HTTP 401 (no retry -- a broken
        token will still be broken on the next attempt) and
        :class:`GithubApiError` on every other non-2xx response.
        """
        url = f"{self._base_url}{path}"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._token}",
            "Accept": _ACCEPT_HEADER,
            "X-GitHub-Api-Version": _API_VERSION_HEADER,
            "User-Agent": _USER_AGENT,
        }

        last_error: GithubError | None = None
        for attempt in range(_MAX_RETRIES):
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()

            try:
                response = await self._http.request(
                    method,
                    url,
                    params=dict(params) if params else None,
                    headers=headers,
                    timeout=_REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                # Transport-level failures (DNS, connect, read
                # timeout, ...) are wrapped as :class:`GithubApiError`
                # so the caller has a single base class to catch.
                # They are not retried here because the project-wide
                # HTTP client is expected to provide its own
                # transport retry policy.
                raise GithubApiError(
                    f"GitHub HTTP transport error: {exc}",
                ) from exc

            status = response.status_code

            if status == 401:
                raise GithubAuthError(
                    "GitHub API rejected the token (HTTP 401). "
                    "Verify the configured token is valid and has the "
                    "required scopes.",
                    status_code=status,
                    body=_safe_text(response),
                )

            if status == 422:
                # 422 indicates a validation error -- almost always a
                # malformed search query. There's no point retrying.
                raise GithubApiError(
                    "GitHub API rejected the search query (HTTP 422 "
                    "Unprocessable Entity)",
                    status_code=status,
                    body=_safe_text(response),
                )

            if status == 403 and _is_primary_rate_limit(response):
                reset_at = _parse_reset_at(response)
                last_error = GithubRateLimitError(
                    "GitHub primary rate limit exhausted (HTTP 403 with "
                    "X-RateLimit-Remaining: 0)",
                    status_code=status,
                    body=_safe_text(response),
                    reset_at=reset_at,
                )
                await _sleep_until_reset(reset_at, attempt)
                continue

            if status == 429:
                reset_at = _parse_retry_after(response)
                last_error = GithubRateLimitError(
                    "GitHub secondary rate limit exhausted (HTTP 429)",
                    status_code=status,
                    body=_safe_text(response),
                    reset_at=reset_at,
                )
                await _sleep_until_reset(reset_at, attempt)
                continue

            if status >= 400:
                raise GithubApiError(
                    f"GitHub API returned HTTP {status}",
                    status_code=status,
                    body=_safe_text(response),
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise GithubApiError(
                    "GitHub API returned non-JSON payload",
                    status_code=status,
                    body=_safe_text(response),
                ) from exc

            if not isinstance(payload, dict):
                raise GithubApiError(
                    "GitHub API returned unexpected JSON shape "
                    "(expected an object)",
                    status_code=status,
                    body=_safe_text(response),
                )

            return payload

        # Retry budget exhausted: surface the last rate-limit error.
        if last_error is not None:
            raise last_error
        # Defensive: should not be reachable because every loop
        # iteration either returns, raises, or assigns ``last_error``.
        raise GithubApiError(
            "GitHub API failed after retries with no diagnostic",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_items(value: Any) -> list[Mapping[str, Any]]:
    """Return a list of item dicts from a search response's ``items`` field.

    GitHub search responses always include ``items`` as a list when
    the response is well-formed, but defensive coercion shields the
    caller from upstream malformations (``items: null``, ``items: {}``)
    that would otherwise crash iteration.
    """
    if not value:
        return []
    if not isinstance(value, list):
        return []
    items: list[Mapping[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(item)
        # Non-dict entries cannot be turned into a usable match and
        # dropping them is less harmful than raising mid-iteration.
    return items


def _coerce_total(value: Any) -> int | None:
    """Return ``total_count`` as an int, or ``None`` when unparseable."""
    if value is None:
        return None
    try:
        total = int(value)
    except (TypeError, ValueError):
        return None
    if total < 0:
        return None
    return total


def _is_primary_rate_limit(response: httpx.Response) -> bool:
    """Detect GitHub's primary rate-limit response.

    Per https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api
    the primary rate-limit signature is HTTP 403 (or 429) accompanied
    by ``X-RateLimit-Remaining: 0``. The 429 case is handled
    separately so this helper only inspects the 403 path; callers that
    invoke it with a non-403 response already short-circuited above.
    """
    remaining = response.headers.get("X-RateLimit-Remaining")
    return bool(remaining == "0")


def _parse_reset_at(response: httpx.Response) -> datetime | None:
    """Parse ``X-RateLimit-Reset`` into a UTC :class:`datetime`.

    Returns ``None`` when the header is absent or unparseable. Callers
    that need to wait until the reset window can compute the delta
    against :func:`datetime.now(timezone.utc)`; :func:`_sleep_until_reset`
    encapsulates the bounds-checking logic.
    """
    raw = response.headers.get("X-RateLimit-Reset")
    if not raw:
        return None
    try:
        epoch_seconds = int(raw)
    except (TypeError, ValueError):
        return None
    try:
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_retry_after(response: httpx.Response) -> datetime | None:
    """Parse ``Retry-After`` into a UTC :class:`datetime`.

    GitHub uses ``Retry-After`` only on HTTP 429 (secondary rate
    limit). The header is documented as a delta in seconds; we
    compute the absolute reset timestamp so the caller can use the
    same wait-and-retry helper as for the primary limit.
    """
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        delta_seconds = int(raw)
    except (TypeError, ValueError):
        return None
    if delta_seconds < 0:
        return None
    return datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)


async def _sleep_until_reset(
    reset_at: datetime | None,
    attempt: int,
) -> None:
    """Sleep until ``reset_at`` (capped) before retrying.

    When ``reset_at`` is unknown, fall back to an exponential-backoff
    schedule keyed on ``attempt`` so the retry loop still makes
    progress on responses that fail to advertise their reset window.

    The wait is capped at :data:`_MAX_RATE_LIMIT_WAIT_SECONDS` to
    keep the discovery pipeline responsive even when the upstream
    server announces a multi-minute reset window.
    """
    if reset_at is not None:
        now = datetime.now(timezone.utc)
        delta_seconds = max(0.0, (reset_at - now).total_seconds())
        delay = min(delta_seconds, _MAX_RATE_LIMIT_WAIT_SECONDS)
    else:
        delay = min(
            _BACKOFF_BASE_SECONDS * (2**attempt),
            _MAX_RATE_LIMIT_WAIT_SECONDS,
        )

    delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
    await asyncio.sleep(delay)


def _safe_text(response: httpx.Response) -> str:
    """Best-effort decode of ``response.text`` for diagnostics."""
    try:
        return response.text
    except Exception:  # pragma: no cover - defensive
        try:
            return response.content.decode("utf-8", errors="replace")
        except Exception:
            return ""
