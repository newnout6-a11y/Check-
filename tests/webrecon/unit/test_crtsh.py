"""Unit tests for :mod:`webrecon.discovery.crtsh`."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from webrecon.core.models import AssetStatus, DiscoverySource
from webrecon.discovery.crtsh import (
    CrtShApiError,
    CrtShClient,
    CrtShEntry,
)


def _json_response(payload: Any, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _make_client(transport: httpx.MockTransport) -> tuple[httpx.AsyncClient, CrtShClient]:
    http = httpx.AsyncClient(transport=transport)
    return http, CrtShClient(http)


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(_d: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)


# ---------------------------------------------------------------------------
# CrtShEntry.hostnames
# ---------------------------------------------------------------------------


class TestCrtShEntry:
    def test_hostnames_dedup_and_normalise_wildcards(self) -> None:
        entry = CrtShEntry(
            common_name="*.example.com",
            name_value="example.com\nwww.example.com\n*.staging.example.com",
            issuer_name="Let's Encrypt",
            not_before="2026-01-01",
            not_after="2026-04-01",
            raw={},
        )
        hosts = entry.hostnames()
        # CN comes first (with leading * stripped), SAN entries follow.
        assert hosts[0] == "example.com"
        assert "www.example.com" in hosts
        assert "staging.example.com" in hosts
        # Duplicates suppressed.
        assert len(hosts) == len(set(hosts))


# ---------------------------------------------------------------------------
# CrtShClient.search
# ---------------------------------------------------------------------------


class TestCrtShClientSearch:
    async def test_yields_one_entry_per_row(self) -> None:
        rows = [
            {
                "common_name": "example.com",
                "name_value": "example.com\nwww.example.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2026-01-01",
                "not_after": "2026-04-01",
            },
            {
                "common_name": "*.shop.example.com",
                "name_value": "*.shop.example.com\nshop.example.com",
                "issuer_name": "Sectigo",
                "not_before": "2025-09-01",
                "not_after": "2026-09-01",
            },
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(rows)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [e async for e in client.search("%example.com")]
        finally:
            await http.aclose()

        assert len(collected) == 2
        assert collected[0].common_name == "example.com"
        assert collected[1].issuer_name == "Sectigo"

    async def test_empty_response_yields_nothing(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response([])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [e async for e in client.search("nothing.example")]
        finally:
            await http.aclose()
        assert collected == []

    async def test_empty_query_raises(self) -> None:
        transport = httpx.MockTransport(lambda r: _json_response([]))
        http, client = _make_client(transport)
        try:
            with pytest.raises(ValueError):
                async for _ in client.search(""):
                    pass
        finally:
            await http.aclose()

    async def test_request_includes_json_output_param(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return _json_response([])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [e async for e in client.search("%example.com")]
            assert collected == []
        finally:
            await http.aclose()

        assert len(seen) == 1
        params = dict(seen[0].url.params)
        assert params["q"] == "%example.com"
        assert params["output"] == "json"


# ---------------------------------------------------------------------------
# CrtShClient.search retry / error paths
# ---------------------------------------------------------------------------


class TestCrtShClientErrors:
    async def test_500_then_200_retries(self) -> None:
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(503, content=b"busy")
            return _json_response([{"common_name": "ok.example.com",
                                    "name_value": "ok.example.com",
                                    "issuer_name": "x",
                                    "not_before": "", "not_after": ""}])

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            collected = [e async for e in client.search("%ok.example.com")]
        finally:
            await http.aclose()
        assert attempts["n"] == 2
        assert len(collected) == 1

    async def test_400_raises_immediately(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, content=b"bad query")

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            with pytest.raises(CrtShApiError) as exc_info:
                async for _ in client.search("%bad"):
                    pass
        finally:
            await http.aclose()
        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# CrtShClient.search_to_assets
# ---------------------------------------------------------------------------


class TestCrtShSearchToAssets:
    async def test_emits_one_asset_per_unique_host(self) -> None:
        rows = [
            {
                "common_name": "example.com",
                "name_value": "example.com\nwww.example.com",
                "issuer_name": "x",
                "not_before": "", "not_after": "",
            },
            {
                "common_name": "example.com",  # duplicate from another cert
                "name_value": "example.com\napi.example.com",
                "issuer_name": "y",
                "not_before": "", "not_after": "",
            },
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(rows)

        transport = httpx.MockTransport(handler)
        http, client = _make_client(transport)
        try:
            assets = [a async for a in client.search_to_assets("%example.com")]
        finally:
            await http.aclose()

        urls = {a.url for a in assets}
        assert urls == {
            "https://example.com",
            "https://www.example.com",
            "https://api.example.com",
        }
        for asset in assets:
            assert asset.status is AssetStatus.UNKNOWN
            assert asset.discovery_source is DiscoverySource.MANUAL
