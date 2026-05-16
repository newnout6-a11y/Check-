"""Unit tests for :mod:`webrecon.discovery.wayback`."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from webrecon.core.models import AssetStatus, DiscoverySource
from webrecon.discovery.wayback import (
    WaybackApiError,
    WaybackClient,
)


def _json_response(payload: Any, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _make_client(transport: httpx.MockTransport) -> tuple[httpx.AsyncClient, WaybackClient]:
    http = httpx.AsyncClient(transport=transport)
    return http, WaybackClient(http)


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(_d: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)


# Header row matches the columns the client requests by default.
_HEADER = ["timestamp", "original", "mimetype", "statuscode", "digest", "length"]


def _row(
    *,
    timestamp: str = "20230101000000",
    original: str = "https://example.com/",
    mimetype: str = "text/html",
    statuscode: str = "200",
    digest: str = "AAAA",
    length: str = "1024",
) -> list[str]:
    return [timestamp, original, mimetype, statuscode, digest, length]


# ---------------------------------------------------------------------------
# search()
# ---------------------------------------------------------------------------


class TestWaybackSearch:
    async def test_yields_one_capture_per_row(self) -> None:
        body = [_HEADER,
                _row(original="https://example.com/"),
                _row(original="https://api.example.com/v1")]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(body)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            captures = [c async for c in client.search("example.com")]
        finally:
            await http.aclose()
        assert [c.original for c in captures] == [
            "https://example.com/",
            "https://api.example.com/v1",
        ]

    async def test_empty_payload_yields_nothing(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response([])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            captures = [c async for c in client.search("nothing.example")]
        finally:
            await http.aclose()
        assert captures == []

    async def test_empty_pattern_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: _json_response([]))
        http, client = _make_client(transport)
        try:
            with pytest.raises(ValueError):
                async for _ in client.search(""):
                    pass
        finally:
            await http.aclose()

    async def test_query_includes_default_filters(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return _json_response([_HEADER])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            captures = [c async for c in client.search("example.com")]
            assert captures == []
        finally:
            await http.aclose()

        assert len(seen) == 1
        params = dict(seen[0].url.params)
        assert params["url"] == "example.com"
        assert params["matchType"] == "domain"
        assert params["filter"] == "statuscode:200"
        assert params["collapse"] == "urlkey"
        assert params["output"] == "json"

    async def test_capture_host_property(self) -> None:
        body = [_HEADER, _row(original="https://shop.example.com/path?x=1")]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(body)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            captures = [c async for c in client.search("example.com")]
        finally:
            await http.aclose()
        assert captures[0].host == "shop.example.com"


# ---------------------------------------------------------------------------
# Error / retry paths
# ---------------------------------------------------------------------------


class TestWaybackErrors:
    async def test_500_then_200_retries(self) -> None:
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(502, content=b"bad gateway")
            return _json_response([_HEADER, _row()])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            captures = [c async for c in client.search("example.com")]
        finally:
            await http.aclose()
        assert attempts["n"] == 2
        assert len(captures) == 1

    async def test_400_raises_immediately(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, content=b"bad")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(WaybackApiError) as exc_info:
                async for _ in client.search("example.com"):
                    pass
        finally:
            await http.aclose()
        assert exc_info.value.status_code == 400

    async def test_unexpected_shape_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response({"not": "a list"})

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(WaybackApiError):
                async for _ in client.search("example.com"):
                    pass
        finally:
            await http.aclose()


# ---------------------------------------------------------------------------
# search_to_assets()
# ---------------------------------------------------------------------------


class TestWaybackToAssets:
    async def test_dedup_by_host(self) -> None:
        body = [
            _HEADER,
            _row(original="https://shop.example.com/"),
            _row(original="https://shop.example.com/cart"),
            _row(original="https://api.example.com/v1"),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(body)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [a async for a in client.search_to_assets("example.com")]
        finally:
            await http.aclose()
        urls = {a.url for a in assets}
        assert urls == {"https://shop.example.com", "https://api.example.com"}
        for asset in assets:
            assert asset.status is AssetStatus.UNKNOWN
            assert asset.discovery_source is DiscoverySource.MANUAL

    async def test_no_dedup(self) -> None:
        body = [
            _HEADER,
            _row(original="https://shop.example.com/"),
            _row(original="https://shop.example.com/cart"),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(body)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [
                a async for a in client.search_to_assets(
                    "example.com", deduplicate_by_host=False
                )
            ]
        finally:
            await http.aclose()
        assert len(assets) == 2
        assert {a.url for a in assets} == {
            "https://shop.example.com/",
            "https://shop.example.com/cart",
        }
