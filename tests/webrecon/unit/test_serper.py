"""Unit tests for :mod:`webrecon.discovery.serper`.

Covers the Google dork builder, the asynchronous Serper client
(single-page, paginated, error, rate-limited paths), and the
asset-emission helper.

Validates: Requirement 11.1 (unit tests validate individual module
functionality in isolation with mock dependencies) and 11.2 (mocking
external APIs to avoid live calls).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from webrecon.core.models import AssetStatus, DiscoverySource, WebsiteAsset
from webrecon.discovery.serper import (
    GoogleDorkBuilder,
    SerperApiError,
    SerperClient,
    SerperRateLimitError,
    SerperResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_response(payload: Any, status_code: int = 200) -> httpx.Response:
    """Build a JSON ``httpx.Response`` with the right content-type."""
    return httpx.Response(
        status_code=status_code,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _make_client(
    transport: httpx.MockTransport,
    *,
    api_key: str = "secret-key",
    rate_limiter: Any = None,
) -> tuple[httpx.AsyncClient, SerperClient]:
    """Build a paired ``httpx.AsyncClient`` + :class:`SerperClient`.

    The async client is wired to ``transport`` so the tests never
    touch the network. The caller is responsible for awaiting
    ``aclose``.
    """
    http = httpx.AsyncClient(transport=transport)
    client = SerperClient(http, api_key=api_key, rate_limiter=rate_limiter)
    return http, client


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub :func:`asyncio.sleep` so retry backoff is instantaneous."""

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)


def _request_body(request: httpx.Request) -> dict[str, Any]:
    """Decode a JSON request body for assertions."""
    raw = request.read()
    decoded = json.loads(raw.decode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


# ---------------------------------------------------------------------------
# GoogleDorkBuilder
# ---------------------------------------------------------------------------


class TestGoogleDorkBuilder:
    """Behavioural coverage for :class:`GoogleDorkBuilder`."""

    def test_site_clause(self) -> None:
        assert GoogleDorkBuilder().site("example.com").build() == "site:example.com"

    def test_inurl_clause(self) -> None:
        assert GoogleDorkBuilder().inurl("admin").build() == "inurl:admin"

    def test_intitle_clause(self) -> None:
        assert GoogleDorkBuilder().intitle("login").build() == "intitle:login"

    def test_intext_clause(self) -> None:
        assert GoogleDorkBuilder().intext("password").build() == "intext:password"

    def test_filetype_clause(self) -> None:
        assert GoogleDorkBuilder().filetype("pdf").build() == "filetype:pdf"

    def test_filetype_strips_leading_dot(self) -> None:
        assert GoogleDorkBuilder().filetype(".pdf").build() == "filetype:pdf"

    def test_ext_is_alias_for_filetype(self) -> None:
        assert GoogleDorkBuilder().ext("xls").build() == "filetype:xls"

    def test_exclude_clause(self) -> None:
        assert GoogleDorkBuilder().exclude("shopify").build() == "-shopify"

    def test_exclude_does_not_double_prefix(self) -> None:
        # Calling with an already-negated term must not produce ``--shopify``.
        assert GoogleDorkBuilder().exclude("-shopify").build() == "-shopify"

    def test_exact_wraps_in_quotes(self) -> None:
        built = GoogleDorkBuilder().exact("powered by woocommerce").build()
        assert built == '"powered by woocommerce"'

    def test_or_term_with_two_terms(self) -> None:
        built = GoogleDorkBuilder().or_term("stripe", "braintree").build()
        assert built == "(stripe OR braintree)"

    def test_or_term_with_many_terms(self) -> None:
        built = GoogleDorkBuilder().or_term("a", "b", "c").build()
        assert built == "(a OR b OR c)"

    def test_or_term_with_single_term_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().or_term("solo")

    def test_or_term_with_empty_terms_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().or_term("", "  ", "")

    def test_raw_clause_inserted_verbatim(self) -> None:
        built = GoogleDorkBuilder().raw("daterange:2459580-2459600").build()
        assert built == "daterange:2459580-2459600"

    def test_raw_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().raw("   ")

    def test_site_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().site("")

    def test_inurl_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().inurl("   ")

    def test_filetype_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().filetype(".")

    def test_exclude_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().exclude("")

    def test_exact_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            GoogleDorkBuilder().exact("   ")

    def test_chained_clauses_joined_by_space(self) -> None:
        built = (
            GoogleDorkBuilder()
            .site("example.com")
            .inurl("admin")
            .filetype("pdf")
            .build()
        )
        assert built == "site:example.com inurl:admin filetype:pdf"

    def test_complex_combination(self) -> None:
        # Mirrors the kind of dork the existing serper_deep.py
        # script produces: woocommerce OR magento, exclude shopify.
        built = (
            GoogleDorkBuilder()
            .exact("powered by woocommerce")
            .intext("stripe")
            .or_term("checkout", "shop")
            .exclude("shopify")
            .build()
        )
        assert built == (
            '"powered by woocommerce" intext:stripe '
            "(checkout OR shop) -shopify"
        )

    def test_builder_is_immutable(self) -> None:
        original = GoogleDorkBuilder()
        original.site("example.com")
        # Each chainable call returns a fresh builder; the original
        # must remain empty.
        assert original.build() == ""

    def test_empty_builder_returns_empty_string(self) -> None:
        assert GoogleDorkBuilder().build() == ""


# ---------------------------------------------------------------------------
# SerperClient construction
# ---------------------------------------------------------------------------


class TestSerperClientConstruction:
    """The constructor enforces a non-empty API key."""

    def test_empty_key_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        http = httpx.AsyncClient(transport=transport)
        with pytest.raises(ValueError):
            SerperClient(http, api_key="")


# ---------------------------------------------------------------------------
# SerperClient.search — happy paths
# ---------------------------------------------------------------------------


class TestSerperClientSearchHappyPath:
    """Single-page search responses."""

    async def test_yields_organic_results(self) -> None:
        organic = [
            {
                "title": "First Result",
                "link": "https://a.example.com/",
                "snippet": "First snippet.",
                "position": 1,
            },
            {
                "title": "Second Result",
                "link": "https://b.example.com/",
                "snippet": "Second snippet.",
                "position": 2,
            },
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"organic": organic})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("site:example.com")]
        finally:
            await http.aclose()

        assert len(collected) == 2
        assert collected[0].title == "First Result"
        assert collected[0].link == "https://a.example.com/"
        assert collected[0].position == 1
        assert collected[1].snippet == "Second snippet."
        # ``raw`` preserves the original payload verbatim.
        assert collected[0].raw == organic[0]

    async def test_results_sorted_by_position(self) -> None:
        # Server returns the organic list in a jumbled order; the
        # client must hand them back sorted by position ascending so
        # downstream consumers can rely on a deterministic ranking.
        organic = [
            {"title": "Third", "link": "https://c", "snippet": "", "position": 3},
            {"title": "First", "link": "https://a", "snippet": "", "position": 1},
            {"title": "Second", "link": "https://b", "snippet": "", "position": 2},
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"organic": organic})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("test query")]
        finally:
            await http.aclose()

        assert [r.position for r in collected] == [1, 2, 3]
        assert [r.title for r in collected] == ["First", "Second", "Third"]

    async def test_empty_organic_yields_no_results(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("nothing matches")]
        finally:
            await http.aclose()

        assert collected == []

    async def test_missing_organic_key_yields_no_results(self) -> None:
        # Defensive: a response without the ``organic`` field at all
        # (e.g. a knowledge-graph-only result) must produce zero
        # results rather than crashing.
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"searchInformation": {"totalResults": "0"}})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("query")]
        finally:
            await http.aclose()

        assert collected == []

    async def test_post_request_carries_api_key_and_json_body(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport, api_key="abc123")
        try:
            collected = [
                r
                async for r in client.search(
                    "site:example.com", num=20, page=1, gl="us", hl="en"
                )
            ]
        finally:
            await http.aclose()
        assert collected == []

        assert len(seen_requests) == 1
        request = seen_requests[0]
        # Verb + path must match the documented endpoint.
        assert request.method == "POST"
        assert request.url.path == "/search"
        # ``X-API-KEY`` header carries the credential.
        assert request.headers["X-API-KEY"] == "abc123"
        # JSON content-type negotiated for POST body.
        assert request.headers["content-type"].startswith("application/json")
        body = _request_body(request)
        assert body == {
            "q": "site:example.com",
            "num": 20,
            "page": 1,
            "gl": "us",
            "hl": "en",
        }

    async def test_query_builder_is_materialised_before_request(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            dork = (
                GoogleDorkBuilder()
                .site("example.com")
                .inurl("admin")
                .filetype("pdf")
            )
            collected = [r async for r in client.search(dork)]
        finally:
            await http.aclose()
        assert collected == []

        body = _request_body(seen_requests[0])
        assert body["q"] == "site:example.com inurl:admin filetype:pdf"

    async def test_optional_locale_params_omitted_when_unset(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("query")]
        finally:
            await http.aclose()
        assert collected == []

        body = _request_body(seen_requests[0])
        assert body == {"q": "query", "num": 10, "page": 1}
        assert "gl" not in body
        assert "hl" not in body

    async def test_num_above_max_is_clamped(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("query", num=500)]
        finally:
            await http.aclose()
        assert collected == []

        body = _request_body(seen_requests[0])
        # Serper accepts at most 100; client must clamp.
        assert body["num"] == 100

    async def test_empty_query_raises(self) -> None:
        transport = httpx.MockTransport(
            lambda r: _json_response({"organic": []})
        )
        http, client = _make_client(transport)
        try:
            with pytest.raises(ValueError):
                async for _ in client.search(""):
                    pass
        finally:
            await http.aclose()

    async def test_zero_page_raises(self) -> None:
        transport = httpx.MockTransport(
            lambda r: _json_response({"organic": []})
        )
        http, client = _make_client(transport)
        try:
            with pytest.raises(ValueError):
                async for _ in client.search("query", page=0):
                    pass
        finally:
            await http.aclose()


# ---------------------------------------------------------------------------
# SerperClient.search_paginated
# ---------------------------------------------------------------------------


class TestSerperClientSearchPaginated:
    """Paginated walks across multiple Serper pages."""

    async def test_walks_pages_until_empty(self) -> None:
        # Three "pages" from the server: 2 results, 1 result, then
        # an empty list. Pagination must stop after the empty page.
        captured_pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.read().decode("utf-8"))
            page = int(body["page"])
            captured_pages.append(page)
            if page == 1:
                return _json_response(
                    {
                        "organic": [
                            {
                                "title": "1",
                                "link": "https://1",
                                "snippet": "",
                                "position": 1,
                            },
                            {
                                "title": "2",
                                "link": "https://2",
                                "snippet": "",
                                "position": 2,
                            },
                        ]
                    }
                )
            if page == 2:
                return _json_response(
                    {
                        "organic": [
                            {
                                "title": "3",
                                "link": "https://3",
                                "snippet": "",
                                "position": 1,
                            }
                        ]
                    }
                )
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                r
                async for r in client.search_paginated(
                    "query", max_pages=5, num=10
                )
            ]
        finally:
            await http.aclose()

        assert [r.title for r in collected] == ["1", "2", "3"]
        # Three requests (2 with results + 1 empty); no fourth page.
        assert captured_pages == [1, 2, 3]

    async def test_max_pages_caps_iteration(self) -> None:
        # Server always returns a non-empty page; ``max_pages=2``
        # must cap iteration at exactly two pages.
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return _json_response(
                {
                    "organic": [
                        {
                            "title": f"r{request_count}",
                            "link": f"https://r{request_count}",
                            "snippet": "",
                            "position": 1,
                        }
                    ]
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                r
                async for r in client.search_paginated(
                    "query", max_pages=2, num=10
                )
            ]
        finally:
            await http.aclose()

        assert request_count == 2
        assert len(collected) == 2

    async def test_max_pages_zero_yields_nothing(self) -> None:
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return _json_response(
                {
                    "organic": [
                        {
                            "title": "x",
                            "link": "https://x",
                            "snippet": "",
                            "position": 1,
                        }
                    ]
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                r
                async for r in client.search_paginated(
                    "query", max_pages=0, num=10
                )
            ]
        finally:
            await http.aclose()

        assert collected == []
        assert request_count == 0

    async def test_pages_are_one_indexed(self) -> None:
        # Verifies the iterator starts at page 1 (Google's
        # convention) rather than page 0.
        captured_pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.read().decode("utf-8"))
            captured_pages.append(int(body["page"]))
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                r
                async for r in client.search_paginated(
                    "query", max_pages=1, num=10
                )
            ]
        finally:
            await http.aclose()

        assert collected == []
        assert captured_pages == [1]


# ---------------------------------------------------------------------------
# SerperClient.search — error / retry paths
# ---------------------------------------------------------------------------


class TestSerperClientSearchErrors:
    """HTTP, JSON, and rate-limit error handling."""

    async def test_http_401_raises_serper_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, content=b"unauthorized")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(SerperApiError) as exc_info:
                async for _ in client.search("query"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 401
        assert not isinstance(exc_info.value, SerperRateLimitError)

    async def test_http_403_raises_serper_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, content=b"forbidden")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(SerperApiError) as exc_info:
                async for _ in client.search("query"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 403

    async def test_http_500_raises_serper_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, content=b"server boom")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(SerperApiError) as exc_info:
                async for _ in client.search("query"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 500
        assert not isinstance(exc_info.value, SerperRateLimitError)

    async def test_429_then_200_retries_and_yields_results(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] == 1:
                return httpx.Response(429, content=b"slow down")
            return _json_response(
                {
                    "organic": [
                        {
                            "title": "ok",
                            "link": "https://ok",
                            "snippet": "",
                            "position": 1,
                        }
                    ]
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [r async for r in client.search("query")]
        finally:
            await http.aclose()

        assert attempts["count"] == 2
        assert len(collected) == 1
        assert collected[0].title == "ok"

    async def test_429_on_every_attempt_raises_rate_limit_error(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            return httpx.Response(429, content=b"too many")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(SerperRateLimitError) as exc_info:
                async for _ in client.search("query"):
                    pass
        finally:
            await http.aclose()

        # _MAX_RETRIES is 3; the client should give up after exactly
        # three attempts and surface the last 429 as a rate-limit
        # error.
        assert attempts["count"] == 3
        assert exc_info.value.status_code == 429

    async def test_non_json_response_raises_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"<html>not json</html>",
                headers={"content-type": "text/html"},
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(SerperApiError) as exc_info:
                async for _ in client.search("query"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 200
        assert "non-json" in str(exc_info.value).lower()

    async def test_json_array_response_raises_api_error(self) -> None:
        # The response decodes as JSON but is a list rather than an
        # object; the client must reject it because every supported
        # endpoint returns an object.
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response([1, 2, 3])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(SerperApiError):
                async for _ in client.search("query"):
                    pass
        finally:
            await http.aclose()


# ---------------------------------------------------------------------------
# SerperClient.search_to_assets
# ---------------------------------------------------------------------------


class TestSerperClientSearchToAssets:
    """Asset-emission helper preserves provenance and skips empty links."""

    async def test_emits_website_assets_with_metadata(self) -> None:
        page_state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            page_state["calls"] += 1
            if page_state["calls"] == 1:
                return _json_response(
                    {
                        "organic": [
                            {
                                "title": "Example Shop",
                                "link": "https://shop.example.net/",
                                "snippet": "Powered by WooCommerce.",
                                "position": 1,
                            }
                        ]
                    }
                )
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [
                a
                async for a in client.search_to_assets(
                    "site:example.net", max_pages=2, num=10
                )
            ]
        finally:
            await http.aclose()

        assert len(assets) == 1
        asset = assets[0]
        assert isinstance(asset, WebsiteAsset)
        assert asset.url == "https://shop.example.net/"
        assert asset.normalized_url == "https://shop.example.net/"
        assert asset.status is AssetStatus.UNKNOWN
        assert asset.discovery_source is DiscoverySource.SERPER
        # Metadata records the original Serper provenance so
        # downstream rankers don't need to re-query.
        assert asset.metadata["serper_position"] == "1"
        assert asset.metadata["serper_snippet"] == "Powered by WooCommerce."
        assert asset.metadata["serper_title"] == "Example Shop"

    async def test_skips_results_with_empty_link(self) -> None:
        page_state = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            page_state["calls"] += 1
            if page_state["calls"] == 1:
                return _json_response(
                    {
                        "organic": [
                            {
                                "title": "no link",
                                "link": "",
                                "snippet": "",
                                "position": 1,
                            },
                            {
                                "title": "good",
                                "link": "https://good.example/",
                                "snippet": "",
                                "position": 2,
                            },
                        ]
                    }
                )
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [
                a
                async for a in client.search_to_assets(
                    "query", max_pages=2, num=10
                )
            ]
        finally:
            await http.aclose()

        assert len(assets) == 1
        assert assets[0].url == "https://good.example/"


# ---------------------------------------------------------------------------
# SerperResult dataclass
# ---------------------------------------------------------------------------


class TestSerperResult:
    """Surface-level invariants on the result dataclass."""

    def test_is_frozen(self) -> None:
        result = SerperResult(
            title="t",
            link="https://example.com",
            snippet="s",
            position=1,
            raw={"title": "t"},
        )
        with pytest.raises(Exception):  # noqa: B017 - dataclass FrozenInstanceError
            result.title = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Optional rate_limiter
# ---------------------------------------------------------------------------


class _StubRateLimiter:
    """Minimal :class:`RateLimiter` implementation for assertions."""

    def __init__(self) -> None:
        self.calls = 0

    async def acquire(self) -> None:
        self.calls += 1


class TestSerperClientRateLimiter:
    """The injected rate limiter is awaited once per HTTP attempt."""

    async def test_acquire_called_once_per_request(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        limiter = _StubRateLimiter()
        http, client = _make_client(transport, rate_limiter=limiter)
        try:
            collected = [r async for r in client.search("query")]
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
            return _json_response({"organic": []})

        transport = httpx.MockTransport(handler)
        limiter = _StubRateLimiter()
        http, client = _make_client(transport, rate_limiter=limiter)
        try:
            collected = [r async for r in client.search("query")]
        finally:
            await http.aclose()

        assert collected == []
        # Two 429 responses + one success = three acquire calls.
        assert limiter.calls == 3
