"""Unit tests for :mod:`webrecon.discovery.fofa`.

Covers the FOFA query builder, the row → URL normaliser, the
asynchronous client (single-page, paginated, capped, error,
rate-limited, and non-JSON paths), and the asset-emission helper.

Validates: Requirement 11.1 (unit tests validate individual module
functionality in isolation with mock dependencies) and 11.2 (mocking
external APIs to avoid live calls).
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from webrecon.core.models import AssetStatus, DiscoverySource, WebsiteAsset
from webrecon.discovery.fofa import (
    FofaApiError,
    FofaClient,
    FofaQueryBuilder,
    FofaRateLimitError,
    FofaResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_response(payload: Any, status_code: int = 200) -> httpx.Response:
    """Build a JSON ``httpx.Response`` with the right content-type."""
    import json

    return httpx.Response(
        status_code=status_code,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _make_client(
    transport: httpx.MockTransport,
    *,
    email: str = "u@example.com",
    key: str = "secret-key",
    rate_limiter: Any = None,
) -> tuple[httpx.AsyncClient, FofaClient]:
    """Build a paired ``httpx.AsyncClient`` + :class:`FofaClient`.

    The async client is wired to ``transport`` so the tests never touch
    the network. The caller is responsible for awaiting ``aclose``.
    """
    http = httpx.AsyncClient(transport=transport)
    client = FofaClient(http, email=email, key=key, rate_limiter=rate_limiter)
    return http, client


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub :func:`asyncio.sleep` so retry backoff is instantaneous."""

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)


# ---------------------------------------------------------------------------
# FofaQueryBuilder
# ---------------------------------------------------------------------------


class TestFofaQueryBuilder:
    """Behavioural coverage for :class:`FofaQueryBuilder`."""

    def test_app_produces_quoted_app_clause(self) -> None:
        assert FofaQueryBuilder().app("WordPress").build() == 'app="WordPress"'

    def test_country_and_port_chained_with_logical_and(self) -> None:
        built = FofaQueryBuilder().country("US").port(443).build()
        assert built == 'country="US" && port="443"'

    def test_embedded_quotes_are_escaped(self) -> None:
        # Double-quotes inside a value must be doubled to keep the
        # FOFA expression syntactically valid.
        built = FofaQueryBuilder().app('foo"bar').build()
        assert built == 'app="foo""bar"'

    def test_port_above_max_raises(self) -> None:
        with pytest.raises(ValueError):
            FofaQueryBuilder().port(70_000)

    def test_port_below_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            FofaQueryBuilder().port(-1)

    def test_and_combinator_parenthesises_both_sides(self) -> None:
        left = FofaQueryBuilder().app("WordPress")
        right = FofaQueryBuilder().country("US")
        combined = left.and_(right).build()
        assert combined == '(app="WordPress") && (country="US")'

    def test_or_combinator_parenthesises_both_sides(self) -> None:
        left = FofaQueryBuilder().app("WordPress")
        right = FofaQueryBuilder().app("Drupal")
        combined = left.or_(right).build()
        assert combined == '(app="WordPress") || (app="Drupal")'

    def test_and_with_empty_left_returns_right(self) -> None:
        empty = FofaQueryBuilder()
        right = FofaQueryBuilder().app("WordPress")
        assert empty.and_(right).build() == 'app="WordPress"'

    def test_and_with_empty_right_returns_left(self) -> None:
        left = FofaQueryBuilder().app("WordPress")
        empty = FofaQueryBuilder()
        assert left.and_(empty).build() == 'app="WordPress"'

    def test_or_with_empty_left_returns_right(self) -> None:
        empty = FofaQueryBuilder()
        right = FofaQueryBuilder().country("FR")
        assert empty.or_(right).build() == 'country="FR"'

    def test_builder_is_immutable(self) -> None:
        # Each chainable call returns a fresh builder; the original
        # must remain empty.
        original = FofaQueryBuilder()
        original.app("WordPress")
        assert original.build() == ""


# ---------------------------------------------------------------------------
# FofaResult.to_url
# ---------------------------------------------------------------------------


class TestFofaResultToUrl:
    """:py:meth:`FofaResult.to_url` reconstructs a canonical URL."""

    def test_http_default_port_is_suppressed(self) -> None:
        result = FofaResult(
            host="example.com",
            ip="203.0.113.1",
            port=80,
            scheme="http",
            raw=("example.com", "203.0.113.1", "80", "http"),
        )
        assert result.to_url() == "http://example.com"

    def test_https_default_port_is_suppressed(self) -> None:
        result = FofaResult(
            host="example.com",
            ip="203.0.113.1",
            port=443,
            scheme="https",
            raw=("example.com", "203.0.113.1", "443", "https"),
        )
        assert result.to_url() == "https://example.com"

    def test_embedded_port_in_host_is_preserved(self) -> None:
        # When ``host`` already encodes a non-default port, the ``port``
        # column is ignored to avoid producing ``host:8443:443``.
        result = FofaResult(
            host="example.com:8443",
            ip="203.0.113.1",
            port=443,
            scheme="https",
            raw=(),
        )
        assert result.to_url() == "https://example.com:8443"

    def test_leading_scheme_prefix_is_stripped(self) -> None:
        result = FofaResult(
            host="https://example.com",
            ip="",
            port=443,
            scheme="https",
            raw=(),
        )
        assert result.to_url() == "https://example.com"

    def test_non_default_port_is_included(self) -> None:
        result = FofaResult(
            host="example.com",
            ip="",
            port=8080,
            scheme="http",
            raw=(),
        )
        assert result.to_url() == "http://example.com:8080"


# ---------------------------------------------------------------------------
# FofaClient construction
# ---------------------------------------------------------------------------


class TestFofaClientConstruction:
    """The constructor enforces non-empty credentials."""

    def test_empty_email_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        http = httpx.AsyncClient(transport=transport)
        with pytest.raises(ValueError):
            FofaClient(http, email="", key="x")

    def test_empty_key_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        http = httpx.AsyncClient(transport=transport)
        with pytest.raises(ValueError):
            FofaClient(http, email="u@example.com", key="")


# ---------------------------------------------------------------------------
# FofaClient.search — happy paths
# ---------------------------------------------------------------------------


class TestFofaClientSearchHappyPath:
    """Single-page and paginated search responses."""

    async def test_single_page_yields_rows(self) -> None:
        rows = [
            ["example.com", "203.0.113.1", "80", "http"],
            ["shop.example.org", "198.51.100.2", "443", "https"],
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {"error": False, "size": 2, "page": 1, "results": rows}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search('app="WordPress"')]
        finally:
            await http.aclose()

        assert len(collected) == 2
        assert collected[0].host == "example.com"
        assert collected[0].port == 80
        assert collected[0].scheme == "http"
        assert collected[1].to_url() == "https://shop.example.org"

    async def test_pagination_walks_until_short_page(self) -> None:
        # First page is full (100 rows) -> client must fetch the second
        # page; the second page is short (50 rows) so iteration stops.
        page_one = [[f"host{i}.example.com", "", "443", "https"] for i in range(100)]
        page_two = [[f"host{i + 100}.example.com", "", "443", "https"] for i in range(50)]

        captured_pages: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            page_param = request.url.params.get("page", "1")
            captured_pages.append(page_param)
            if page_param == "1":
                rows = page_one
            elif page_param == "2":
                rows = page_two
            else:
                rows = []
            return _json_response(
                {"error": False, "size": len(rows), "page": int(page_param), "results": rows}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("port=443", page_size=100)]
        finally:
            await http.aclose()

        assert len(collected) == 150
        assert captured_pages == ["1", "2"]

    async def test_max_pages_caps_iteration(self) -> None:
        # Always return a full page; ``max_pages=2`` must terminate the
        # iteration even though the server would happily keep going.
        full_page = [["a.example.com", "", "443", "https"] for _ in range(5)]
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return _json_response(
                {"error": False, "size": 5, "page": 1, "results": full_page}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                r async for r in client.search("port=443", max_pages=2, page_size=5)
            ]
        finally:
            await http.aclose()

        assert request_count == 2
        assert len(collected) == 10

    async def test_empty_results_yields_nothing(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {"error": False, "size": 0, "page": 1, "results": []}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("port=80")]
        finally:
            await http.aclose()

        assert collected == []

    async def test_request_url_carries_qbase64_and_credentials(self) -> None:
        # Capture the first request and assert that the FOFA-required
        # ``qbase64`` parameter is the base64 of the query and that the
        # caller's credentials travelled along.
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response(
                {"error": False, "size": 0, "page": 1, "results": []}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(
            transport, email="agent@example.com", key="abc123"
        )
        try:
            collected = [r async for r in client.search('app="WordPress"')]
        finally:
            await http.aclose()
        assert collected == []

        assert len(seen_requests) == 1
        params = parse_qs(urlsplit(str(seen_requests[0].url)).query)
        assert params["email"] == ["agent@example.com"]
        assert params["key"] == ["abc123"]
        encoded = params["qbase64"][0]
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert decoded == 'app="WordPress"'


# ---------------------------------------------------------------------------
# FofaClient.search — error / retry paths
# ---------------------------------------------------------------------------


class TestFofaClientSearchErrors:
    """HTTP, JSON, and rate-limit error handling."""

    async def test_http_400_raises_fofa_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, content=b"bad query")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(FofaApiError) as exc_info:
                async for _ in client.search("port=80"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 400
        assert exc_info.value.body == "bad query"

    async def test_429_then_200_retries_and_yields_rows(self) -> None:
        # First attempt is rate-limited; the second succeeds. The
        # resulting iterator must yield the rows from the 200 response.
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] == 1:
                return httpx.Response(429, content=b"slow down")
            return _json_response(
                {
                    "error": False,
                    "size": 1,
                    "page": 1,
                    "results": [["example.com", "", "80", "http"]],
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("port=80")]
        finally:
            await http.aclose()

        assert attempts["count"] == 2
        assert len(collected) == 1
        assert collected[0].host == "example.com"

    async def test_429_on_every_attempt_raises_rate_limit_error(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            return httpx.Response(429, content=b"too many")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(FofaRateLimitError) as exc_info:
                async for _ in client.search("port=80"):
                    pass
        finally:
            await http.aclose()

        # _MAX_RETRIES is 3; the client should give up after exactly
        # three attempts and surface the last 429 as a rate-limit error.
        assert attempts["count"] == 3
        assert exc_info.value.status_code == 429

    async def test_json_error_with_rate_limit_message_retries(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] == 1:
                return _json_response(
                    {"error": True, "errmsg": "Frequent Requests, please try later"}
                )
            return _json_response(
                {
                    "error": False,
                    "size": 1,
                    "page": 1,
                    "results": [["example.com", "", "80", "http"]],
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("port=80")]
        finally:
            await http.aclose()

        assert attempts["count"] == 2
        assert len(collected) == 1

    async def test_json_error_without_rate_limit_message_raises_immediately(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            return _json_response(
                {"error": True, "errmsg": "Invalid query syntax"}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(FofaApiError) as exc_info:
                async for _ in client.search("port=80"):
                    pass
        finally:
            await http.aclose()

        # No retry: a non-rate-limit JSON error fails fast.
        assert attempts["count"] == 1
        assert "Invalid query syntax" in str(exc_info.value)
        # Rate-limit subclass must NOT be raised here.
        assert not isinstance(exc_info.value, FofaRateLimitError)

    async def test_non_json_response_raises_fofa_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"<html>not json</html>",
                headers={"content-type": "text/html"},
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(FofaApiError) as exc_info:
                async for _ in client.search("port=80"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 200
        assert "non-JSON" in str(exc_info.value) or "non-json" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# FofaClient.search_to_assets
# ---------------------------------------------------------------------------


class TestFofaClientSearchToAssets:
    """Asset-emission helper preserves provenance and skips empty rows."""

    async def test_emits_website_assets_with_metadata(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "error": False,
                    "size": 1,
                    "page": 1,
                    "results": [["example.com", "203.0.113.1", "443", "https"]],
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [a async for a in client.search_to_assets('app="WordPress"')]
        finally:
            await http.aclose()

        assert len(assets) == 1
        asset = assets[0]
        assert isinstance(asset, WebsiteAsset)
        assert asset.url == "https://example.com"
        assert asset.normalized_url == "https://example.com"
        assert asset.status is AssetStatus.UNKNOWN
        assert asset.discovery_source is DiscoverySource.FOFA
        assert asset.metadata == {
            "fofa_host": "example.com",
            "fofa_ip": "203.0.113.1",
        }

    async def test_skips_rows_without_host_and_ip(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "error": False,
                    "size": 2,
                    "page": 1,
                    "results": [
                        ["", "", "443", "https"],  # both empty -> skipped
                        ["example.com", "", "443", "https"],
                    ],
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [a async for a in client.search_to_assets("port=443")]
        finally:
            await http.aclose()

        assert len(assets) == 1
        assert assets[0].metadata["fofa_host"] == "example.com"


# ---------------------------------------------------------------------------
# Optional rate_limiter
# ---------------------------------------------------------------------------


class _StubRateLimiter:
    """Minimal :class:`webrecon.discovery.fofa.RateLimiter` implementation.

    Counts how many times :py:meth:`acquire` is awaited so a test can
    assert the client honours the contract on every HTTP attempt.
    """

    def __init__(self) -> None:
        self.calls = 0

    async def acquire(self) -> None:
        self.calls += 1


class TestFofaClientRateLimiter:
    """The injected rate limiter is awaited once per HTTP attempt."""

    async def test_acquire_called_once_per_request(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {"error": False, "size": 0, "page": 1, "results": []}
            )

        transport = httpx.MockTransport(handler)
        limiter = _StubRateLimiter()
        http, client = _make_client(transport, rate_limiter=limiter)
        try:
            collected = [r async for r in client.search("port=80")]
        finally:
            await http.aclose()

        assert collected == []
        # One HTTP attempt, therefore one acquire.
        assert limiter.calls == 1

    async def test_acquire_called_for_each_retry(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] < 3:
                return httpx.Response(429, content=b"slow down")
            return _json_response(
                {"error": False, "size": 0, "page": 1, "results": []}
            )

        transport = httpx.MockTransport(handler)
        limiter = _StubRateLimiter()
        http, client = _make_client(transport, rate_limiter=limiter)
        try:
            collected = [r async for r in client.search("port=80")]
        finally:
            await http.aclose()

        assert collected == []
        # Two 429 responses + one success = three acquire calls.
        assert limiter.calls == 3
