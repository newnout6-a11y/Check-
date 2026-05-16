"""Smoke tests for the `tests/webrecon/` scaffolding (task 1.2).

These tests verify that the test-infrastructure delivered by task 1.2
actually works end-to-end:

* ``pytest-asyncio`` auto-mode picks up plain ``async def test_…``
  functions without per-test decorators.
* ``mock_http_transport`` records every request and the default-deny
  handler raises on unregistered URLs.
* ``mock_http_responses`` matches by URL prefix and serves stub JSON.
* ``async_client`` issues requests through the recording transport.
* The Hypothesis strategies in ``tests/webrecon/strategies.py`` produce
  values that satisfy their declared shapes.

The tests live under ``tests/webrecon/unit`` so they only run when the
webrecon suite is targeted; they impose no dependency on any
``webrecon`` runtime module.
"""

from __future__ import annotations

import re

import httpx
import pytest
from hypothesis import given

from tests.webrecon.strategies import (
    fofa_response_strategy,
    github_search_response_strategy,
    hostname_strategy,
    html_with_form_strategy,
    html_with_stripe_keys_strategy,
    serper_response_strategy,
    shodan_response_strategy,
    stripe_balance_response_strategy,
    url_strategy,
)

# ---------------------------------------------------------------------------
# pytest-asyncio auto-mode wiring
# ---------------------------------------------------------------------------


async def test_async_auto_mode_runs_without_decorator() -> None:
    """A plain ``async def test_...`` should be collected and run."""
    # Trivial async wait — succeeds iff pytest-asyncio is engaged.
    import asyncio

    await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# HTTP mocking
# ---------------------------------------------------------------------------


async def test_async_client_uses_mock_transport(
    async_client: httpx.AsyncClient,
    mock_http_transport,
    mock_http_responses,
    make_json_response,
) -> None:
    """Requests through ``async_client`` are served by the mock transport."""
    mock_http_responses(
        ("http://test.invalid/api", make_json_response({"ok": True})),
    )

    response = await async_client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert len(mock_http_transport.requests) == 1
    assert mock_http_transport.requests[0].method == "GET"


async def test_default_handler_rejects_unstubbed_url(
    async_client: httpx.AsyncClient,
) -> None:
    """Unregistered URLs raise instead of silently hitting the network."""
    with pytest.raises(AssertionError, match="Unexpected outbound HTTP request"):
        await async_client.get("/never/registered")


def test_sqlite_db_path_lives_under_tmp_path(sqlite_db_path, tmp_path) -> None:
    """The database fixture points inside ``tmp_path`` so cleanup is automatic."""
    assert sqlite_db_path.parent == tmp_path
    assert not sqlite_db_path.exists()  # not created until a test writes to it


# ---------------------------------------------------------------------------
# Sample payload fixtures
# ---------------------------------------------------------------------------


def test_fofa_sample_response_has_results(fofa_search_response: dict) -> None:
    assert fofa_search_response["error"] is False
    assert isinstance(fofa_search_response["results"], list)
    assert len(fofa_search_response["results"]) >= 1


def test_shodan_sample_response_has_matches(shodan_search_response: dict) -> None:
    assert isinstance(shodan_search_response["matches"], list)
    assert shodan_search_response["matches"][0]["port"] == 443


def test_serper_sample_response_has_organic(serper_search_response: dict) -> None:
    assert "organic" in serper_search_response
    assert serper_search_response["organic"][0]["link"].startswith("https://")


def test_github_sample_response_has_items(github_search_response: dict) -> None:
    assert github_search_response["items"][0]["repository"]["full_name"]


# ---------------------------------------------------------------------------
# Hypothesis strategies — shape sanity checks
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"^https?://[a-z0-9.\-]+(/[A-Za-z0-9._\-/]*)?$")
_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")
_STRIPE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_]{8,}$")


@given(url_strategy())
def test_url_strategy_produces_parseable_urls(url: str) -> None:
    assert _URL_RE.match(url), f"unexpected url shape: {url!r}"


@given(hostname_strategy())
def test_hostname_strategy_produces_dns_friendly_labels(host: str) -> None:
    assert _HOST_RE.match(host), f"bad host: {host!r}"
    assert ".." not in host
    for label in host.split("."):
        assert label
        assert not label.startswith("-")
        assert not label.endswith("-")


@given(html_with_stripe_keys_strategy())
def test_html_with_stripe_keys_round_trip(payload: tuple[str, list[str]]) -> None:
    html, keys = payload
    for k in keys:
        assert k in html
        assert _STRIPE_KEY_PATTERN.match(k)


@given(html_with_form_strategy())
def test_html_with_form_strategy_emits_form_tag(html: str) -> None:
    assert "<form" in html
    assert "</form>" in html


@given(fofa_response_strategy())
def test_fofa_strategy_shape(payload: dict) -> None:
    assert payload["error"] is False
    assert isinstance(payload["results"], list)
    for row in payload["results"]:
        assert len(row) == 3


@given(shodan_response_strategy())
def test_shodan_strategy_shape(payload: dict) -> None:
    assert isinstance(payload["matches"], list)
    for match in payload["matches"]:
        assert 1 <= match["port"] <= 65535


@given(serper_response_strategy())
def test_serper_strategy_shape(payload: dict) -> None:
    assert payload["searchParameters"]["type"] == "search"
    for item in payload["organic"]:
        assert item["link"].startswith(("http://", "https://"))


@given(github_search_response_strategy())
def test_github_strategy_shape(payload: dict) -> None:
    assert payload["total_count"] >= 0
    for item in payload["items"]:
        assert "/" in item["repository"]["full_name"]


@given(stripe_balance_response_strategy())
def test_stripe_balance_strategy_shape(payload: dict) -> None:
    assert payload["object"] == "balance"
    assert len(payload["available"]) >= 1
