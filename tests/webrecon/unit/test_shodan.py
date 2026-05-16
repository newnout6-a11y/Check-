"""Unit tests for :mod:`webrecon.discovery.shodan`.

Covers the Shodan query builder, the match → URL normaliser, the
asynchronous client (single-page, paginated, capped, error,
rate-limited, quota-exhausted, and non-JSON paths), the
:py:meth:`ShodanClient.get_host` and :py:meth:`ShodanClient.info`
helpers, and the asset-emission helper.

Validates: Requirement 11.1 (unit tests validate individual module
functionality in isolation with mock dependencies) and 11.2 (mocking
external APIs to avoid live calls).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from webrecon.core.models import AssetStatus, DiscoverySource, WebsiteAsset
from webrecon.discovery.shodan import (
    ShodanApiError,
    ShodanClient,
    ShodanMatch,
    ShodanQueryBuilder,
    ShodanQuotaExceededError,
    ShodanRateLimitError,
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
) -> tuple[httpx.AsyncClient, ShodanClient]:
    """Build a paired ``httpx.AsyncClient`` + :class:`ShodanClient`.

    The async client is wired to ``transport`` so the tests never
    touch the network. The caller is responsible for awaiting
    ``aclose``.
    """
    http = httpx.AsyncClient(transport=transport)
    client = ShodanClient(http, api_key=api_key, rate_limiter=rate_limiter)
    return http, client


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub :func:`asyncio.sleep` so retry backoff is instantaneous."""

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)


# ---------------------------------------------------------------------------
# ShodanQueryBuilder
# ---------------------------------------------------------------------------


class TestShodanQueryBuilder:
    """Behavioural coverage for :class:`ShodanQueryBuilder`."""

    def test_product_clause(self) -> None:
        assert ShodanQueryBuilder().product("nginx").build() == "product:nginx"

    def test_port_clause_uses_unquoted_integer(self) -> None:
        assert ShodanQueryBuilder().port(443).build() == "port:443"

    def test_country_clause(self) -> None:
        assert ShodanQueryBuilder().country("US").build() == "country:US"

    def test_os_clause(self) -> None:
        assert ShodanQueryBuilder().os("Linux").build() == "os:Linux"

    def test_hostname_clause(self) -> None:
        built = ShodanQueryBuilder().hostname("example.com").build()
        assert built == "hostname:example.com"

    def test_org_clause(self) -> None:
        # Whitespace forces quoting.
        built = ShodanQueryBuilder().org("Example Org").build()
        assert built == 'org:"Example Org"'

    def test_net_clause(self) -> None:
        built = ShodanQueryBuilder().net("203.0.113.0/24").build()
        assert built == "net:203.0.113.0/24"

    def test_chained_filters_joined_by_space(self) -> None:
        built = (
            ShodanQueryBuilder()
            .product("nginx")
            .port(443)
            .country("US")
            .build()
        )
        # Shodan treats space as logical AND: assert the literal join.
        assert built == "product:nginx port:443 country:US"

    def test_raw_clause_inserted_verbatim(self) -> None:
        built = ShodanQueryBuilder().raw("ssl.cert.subject.cn:example.com").build()
        assert built == "ssl.cert.subject.cn:example.com"

    def test_raw_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            ShodanQueryBuilder().raw("   ")

    def test_port_above_max_raises(self) -> None:
        with pytest.raises(ValueError):
            ShodanQueryBuilder().port(70_000)

    def test_port_below_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            ShodanQueryBuilder().port(-1)

    def test_and_combinator_parenthesises_both_sides(self) -> None:
        left = ShodanQueryBuilder().product("nginx")
        right = ShodanQueryBuilder().country("US")
        combined = left.and_(right).build()
        assert combined == "(product:nginx) (country:US)"

    def test_or_combinator_uses_explicit_operator(self) -> None:
        left = ShodanQueryBuilder().product("nginx")
        right = ShodanQueryBuilder().product("apache")
        combined = left.or_(right).build()
        assert combined == "(product:nginx) OR (product:apache)"

    def test_and_with_empty_left_returns_right(self) -> None:
        empty = ShodanQueryBuilder()
        right = ShodanQueryBuilder().product("nginx")
        assert empty.and_(right).build() == "product:nginx"

    def test_or_with_empty_right_returns_left(self) -> None:
        left = ShodanQueryBuilder().product("nginx")
        empty = ShodanQueryBuilder()
        assert left.or_(empty).build() == "product:nginx"

    def test_builder_is_immutable(self) -> None:
        original = ShodanQueryBuilder()
        original.product("nginx")
        # Each chainable call returns a fresh builder; the original
        # must remain empty.
        assert original.build() == ""


# ---------------------------------------------------------------------------
# ShodanMatch.to_url
# ---------------------------------------------------------------------------


class TestShodanMatchToUrl:
    """:py:meth:`ShodanMatch.to_url` reconstructs a canonical URL."""

    def test_prefers_first_hostname_over_ip(self) -> None:
        match = ShodanMatch(
            ip_str="203.0.113.1",
            port=80,
            hostnames=("example.com", "www.example.com"),
            product="nginx",
            data="HTTP/1.1 200 OK",
            raw={},
        )
        assert match.to_url() == "http://example.com"

    def test_falls_back_to_ip_when_hostnames_empty(self) -> None:
        match = ShodanMatch(
            ip_str="203.0.113.1",
            port=80,
            hostnames=(),
            product="",
            data="",
            raw={},
        )
        assert match.to_url() == "http://203.0.113.1"

    def test_https_default_port_is_suppressed(self) -> None:
        match = ShodanMatch(
            ip_str="203.0.113.1",
            port=443,
            hostnames=("example.com",),
            product="nginx",
            data="",
            raw={},
        )
        assert match.to_url(scheme="https") == "https://example.com"

    def test_http_default_port_is_suppressed(self) -> None:
        match = ShodanMatch(
            ip_str="203.0.113.1",
            port=80,
            hostnames=("example.com",),
            product="nginx",
            data="",
            raw={},
        )
        assert match.to_url(scheme="http") == "http://example.com"

    def test_non_default_port_is_included(self) -> None:
        match = ShodanMatch(
            ip_str="203.0.113.1",
            port=8080,
            hostnames=("example.com",),
            product="",
            data="",
            raw={},
        )
        assert match.to_url() == "http://example.com:8080"

    def test_ipv6_address_is_bracketed(self) -> None:
        match = ShodanMatch(
            ip_str="2001:db8::1",
            port=8443,
            hostnames=(),
            product="",
            data="",
            raw={},
        )
        assert match.to_url(scheme="https") == "https://[2001:db8::1]:8443"


# ---------------------------------------------------------------------------
# ShodanClient construction
# ---------------------------------------------------------------------------


class TestShodanClientConstruction:
    """The constructor enforces a non-empty API key."""

    def test_empty_key_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        http = httpx.AsyncClient(transport=transport)
        with pytest.raises(ValueError):
            ShodanClient(http, api_key="")


# ---------------------------------------------------------------------------
# ShodanClient.search — happy paths
# ---------------------------------------------------------------------------


class TestShodanClientSearchHappyPath:
    """Single-page and paginated search responses."""

    async def test_single_page_yields_matches(self) -> None:
        matches = [
            {
                "ip_str": "203.0.113.1",
                "port": 80,
                "hostnames": ["example.com"],
                "product": "nginx",
                "data": "HTTP/1.1 200 OK",
            },
            {
                "ip_str": "198.51.100.2",
                "port": 443,
                "hostnames": ["api.example.org"],
                "product": "Apache httpd",
                "data": "HTTP/1.1 301 Moved Permanently",
            },
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"matches": matches, "total": 2})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [m async for m in client.search("product:nginx")]
        finally:
            await http.aclose()

        assert len(collected) == 2
        assert collected[0].ip_str == "203.0.113.1"
        assert collected[0].port == 80
        assert collected[0].product == "nginx"
        assert collected[0].hostnames == ("example.com",)
        assert collected[1].to_url() == "http://api.example.org:443"

    async def test_pagination_walks_until_total_reached(self) -> None:
        # Two-page result set: total=150, page 1 returns 100 matches,
        # page 2 returns 50 -- iteration must surface all 150 and
        # stop without a third request.
        page_one = [
            {
                "ip_str": f"203.0.113.{i % 256}",
                "port": 443,
                "hostnames": [f"host{i}.example.com"],
                "product": "nginx",
                "data": "",
            }
            for i in range(100)
        ]
        page_two = [
            {
                "ip_str": f"198.51.100.{i % 256}",
                "port": 443,
                "hostnames": [f"host{i + 100}.example.com"],
                "product": "nginx",
                "data": "",
            }
            for i in range(50)
        ]

        captured_pages: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            page_param = request.url.params.get("page", "1")
            captured_pages.append(page_param)
            if page_param == "1":
                return _json_response({"matches": page_one, "total": 150})
            if page_param == "2":
                return _json_response({"matches": page_two, "total": 150})
            return _json_response({"matches": [], "total": 150})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [m async for m in client.search("product:nginx")]
        finally:
            await http.aclose()

        assert len(collected) == 150
        # Two requests, no wasted third round-trip.
        assert captured_pages == ["1", "2"]

    async def test_max_pages_caps_iteration(self) -> None:
        # Always return a full page; ``max_pages=2`` must terminate
        # the iteration even though the server would happily keep
        # going.
        full_page = [
            {
                "ip_str": "203.0.113.1",
                "port": 443,
                "hostnames": ["a.example.com"],
                "product": "",
                "data": "",
            }
            for _ in range(5)
        ]
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return _json_response({"matches": full_page, "total": 999_999})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                m
                async for m in client.search(
                    "port:443", max_pages=2, page_size=5
                )
            ]
        finally:
            await http.aclose()

        assert request_count == 2
        assert len(collected) == 10

    async def test_empty_results_yields_nothing(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"matches": [], "total": 0})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [m async for m in client.search("port:80")]
        finally:
            await http.aclose()

        assert collected == []

    async def test_request_url_carries_credentials_and_query(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"matches": [], "total": 0})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport, api_key="abc123")
        try:
            collected = [m async for m in client.search("product:nginx")]
        finally:
            await http.aclose()
        assert collected == []

        assert len(seen_requests) == 1
        params = parse_qs(urlsplit(str(seen_requests[0].url)).query)
        assert params["key"] == ["abc123"]
        assert params["query"] == ["product:nginx"]
        assert params["page"] == ["1"]

    async def test_query_builder_is_materialised_before_request(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"matches": [], "total": 0})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            qb = ShodanQueryBuilder().product("nginx").port(443)
            collected = [m async for m in client.search(qb)]
        finally:
            await http.aclose()
        assert collected == []

        assert len(seen_requests) == 1
        params = parse_qs(urlsplit(str(seen_requests[0].url)).query)
        assert params["query"] == ["product:nginx port:443"]

    async def test_facets_are_forwarded(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return _json_response({"matches": [], "total": 0})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [
                m
                async for m in client.search(
                    "port:80", facets=["country", "org"]
                )
            ]
        finally:
            await http.aclose()
        assert collected == []

        params = parse_qs(urlsplit(str(seen_requests[0].url)).query)
        assert params["facets"] == ["country,org"]

    async def test_empty_query_raises(self) -> None:
        transport = httpx.MockTransport(
            lambda r: _json_response({"matches": [], "total": 0})
        )
        http, client = _make_client(transport)
        try:
            with pytest.raises(ValueError):
                async for _ in client.search(""):
                    pass
        finally:
            await http.aclose()


# ---------------------------------------------------------------------------
# ShodanClient.search — error / retry paths
# ---------------------------------------------------------------------------


class TestShodanClientSearchErrors:
    """HTTP, JSON, and rate-limit error handling."""

    async def test_http_401_raises_shodan_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, content=b"unauthorized")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(ShodanApiError) as exc_info:
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 401
        # Distinct error message helps the operator diagnose.
        assert "api_key" in str(exc_info.value).lower() or "401" in str(
            exc_info.value
        )

    async def test_http_403_quota_exhaustion_raises_quota_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                content=b"No query credits available, please upgrade your plan.",
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(ShodanQuotaExceededError) as exc_info:
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 403
        assert "credits" in (exc_info.value.body or "").lower()

    async def test_http_403_non_quota_raises_generic_api_error(self) -> None:
        # 403 without quota-exhaustion markers is a generic
        # forbidden response; it must NOT be classified as quota
        # exhaustion.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, content=b"forbidden region")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(ShodanApiError) as exc_info:
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 403
        assert not isinstance(exc_info.value, ShodanQuotaExceededError)

    async def test_429_then_200_retries_and_yields_matches(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if attempts["count"] == 1:
                return httpx.Response(429, content=b"slow down")
            return _json_response(
                {
                    "matches": [
                        {
                            "ip_str": "203.0.113.1",
                            "port": 80,
                            "hostnames": ["example.com"],
                            "product": "nginx",
                            "data": "",
                        }
                    ],
                    "total": 1,
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [m async for m in client.search("port:80")]
        finally:
            await http.aclose()

        assert attempts["count"] == 2
        assert len(collected) == 1
        assert collected[0].ip_str == "203.0.113.1"

    async def test_429_on_every_attempt_raises_rate_limit_error(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            return httpx.Response(429, content=b"too many")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(ShodanRateLimitError) as exc_info:
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

        # _MAX_RETRIES is 3; the client should give up after exactly
        # three attempts and surface the last 429 as a rate-limit
        # error.
        assert attempts["count"] == 3
        assert exc_info.value.status_code == 429

    async def test_json_error_field_raises_api_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"error": "Invalid query"})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(ShodanApiError) as exc_info:
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

        assert "Invalid query" in str(exc_info.value)
        assert not isinstance(exc_info.value, ShodanQuotaExceededError)

    async def test_json_error_quota_message_raises_quota_error(self) -> None:
        # When Shodan returns a 200 with an ``error`` field that
        # mentions quota exhaustion, the client surfaces the more
        # specific :class:`ShodanQuotaExceededError`.
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {"error": "No query credits available in this account"}
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(ShodanQuotaExceededError):
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

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
            with pytest.raises(ShodanApiError) as exc_info:
                async for _ in client.search("port:80"):
                    pass
        finally:
            await http.aclose()

        assert exc_info.value.status_code == 200
        assert "non-json" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# ShodanClient.get_host
# ---------------------------------------------------------------------------


class TestShodanClientGetHost:
    """:py:meth:`ShodanClient.get_host` returns the full host record."""

    async def test_returns_decoded_dict(self) -> None:
        record = {
            "ip_str": "203.0.113.1",
            "ports": [80, 443],
            "hostnames": ["example.com"],
            "country_code": "US",
        }

        seen_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_paths.append(request.url.path)
            return _json_response(record)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            result = await client.get_host("203.0.113.1")
        finally:
            await http.aclose()

        assert result == record
        assert seen_paths == ["/shodan/host/203.0.113.1"]

    async def test_empty_ip_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        http, client = _make_client(transport)
        try:
            with pytest.raises(ValueError):
                await client.get_host("")
        finally:
            await http.aclose()


# ---------------------------------------------------------------------------
# ShodanClient.info
# ---------------------------------------------------------------------------


class TestShodanClientInfo:
    """:py:meth:`ShodanClient.info` returns API quota information."""

    async def test_returns_quota_dict(self) -> None:
        info = {
            "query_credits": 100,
            "scan_credits": 0,
            "plan": "dev",
            "https": False,
            "unlocked": True,
        }

        seen_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_paths.append(request.url.path)
            return _json_response(info)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            result = await client.info()
        finally:
            await http.aclose()

        assert result == info
        assert seen_paths == ["/api-info"]


# ---------------------------------------------------------------------------
# ShodanClient.search_to_assets
# ---------------------------------------------------------------------------


class TestShodanClientSearchToAssets:
    """Asset-emission helper preserves provenance and skips empty rows."""

    async def test_emits_website_assets_with_metadata(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "matches": [
                        {
                            "ip_str": "203.0.113.10",
                            "port": 443,
                            "hostnames": ["api.example.net"],
                            "product": "nginx",
                            "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
                        }
                    ],
                    "total": 1,
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [
                a
                async for a in client.search_to_assets(
                    "product:nginx", scheme="https"
                )
            ]
        finally:
            await http.aclose()

        assert len(assets) == 1
        asset = assets[0]
        assert isinstance(asset, WebsiteAsset)
        assert asset.url == "https://api.example.net"
        assert asset.normalized_url == "https://api.example.net"
        assert asset.status is AssetStatus.UNKNOWN
        assert asset.discovery_source is DiscoverySource.SHODAN
        assert asset.metadata == {
            "shodan_ip": "203.0.113.10",
            "shodan_port": "443",
            "shodan_product": "nginx",
        }

    async def test_skips_matches_without_host_and_ip(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "matches": [
                        # Both empty -> skipped.
                        {
                            "ip_str": "",
                            "port": 443,
                            "hostnames": [],
                            "product": "",
                            "data": "",
                        },
                        {
                            "ip_str": "203.0.113.1",
                            "port": 443,
                            "hostnames": [],
                            "product": "",
                            "data": "",
                        },
                    ],
                    "total": 2,
                }
            )

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [a async for a in client.search_to_assets("port:443")]
        finally:
            await http.aclose()

        assert len(assets) == 1
        assert assets[0].metadata["shodan_ip"] == "203.0.113.1"


# ---------------------------------------------------------------------------
# Optional rate_limiter
# ---------------------------------------------------------------------------


class _StubRateLimiter:
    """Minimal :class:`RateLimiter` implementation for assertions."""

    def __init__(self) -> None:
        self.calls = 0

    async def acquire(self) -> None:
        self.calls += 1


class TestShodanClientRateLimiter:
    """The injected rate limiter is awaited once per HTTP attempt."""

    async def test_acquire_called_once_per_request(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"matches": [], "total": 0})

        transport = httpx.MockTransport(handler)
        limiter = _StubRateLimiter()
        http, client = _make_client(transport, rate_limiter=limiter)
        try:
            collected = [m async for m in client.search("port:80")]
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
            return _json_response({"matches": [], "total": 0})

        transport = httpx.MockTransport(handler)
        limiter = _StubRateLimiter()
        http, client = _make_client(transport, rate_limiter=limiter)
        try:
            collected = [m async for m in client.search("port:80")]
        finally:
            await http.aclose()

        assert collected == []
        # Two 429 responses + one success = three acquire calls.
        assert limiter.calls == 3
