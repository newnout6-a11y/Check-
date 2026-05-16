"""Shared pytest configuration for the ``webrecon`` test suite.

Responsibilities (per task 1.2 of the ``web-reconnaissance`` spec):

1. Register a Hypothesis profile (``webrecon-ci``) so property tests
   under ``tests/webrecon/property`` run with the design-document
   defaults (``max_examples=200``, ``deadline=None``).

2. Provide an HTTP-mocking fixture, ``mock_http_transport``, built on
   ``httpx.MockTransport``. Tests register response handlers for
   specific URLs / hostnames; the fixture surfaces both a ready-to-use
   ``httpx.AsyncClient`` and the underlying transport so tests can
   assert on the captured request log without ever touching the network
   (Requirement 11.2 — "use mocking to avoid live API calls").

3. Provide async helper fixtures (``anyio_backend``-style event loop,
   ``async_client`` factory, ``sqlite_db_path``) that the rest of the
   webrecon suite can depend on. ``pytest-asyncio`` is configured in
   ``pytest.ini`` (``asyncio_mode = auto``); this conftest layers on
   the webrecon-specific helpers without overriding the global mode.

The fixtures here are intentionally **defensive**: ``webrecon``
implementation modules do not yet exist (tasks 2.x onward will land
them), so each fixture either returns a plain primitive (a path, a
transport, an httpx client) or imports from ``webrecon`` lazily inside
the fixture body. That keeps test collection green while the package
is being filled in.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

try:
    from hypothesis import HealthCheck, settings
except ImportError:  # pragma: no cover — hypothesis is a dev dependency
    settings = None  # type: ignore[assignment]
    HealthCheck = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Hypothesis profile (webrecon-scoped)
# ---------------------------------------------------------------------------

_HYPOTHESIS_PROFILE_NAME = "webrecon-ci"


def _register_hypothesis_profile() -> None:
    """Register the webrecon Hypothesis profile.

    The top-level ``tests/conftest.py`` already loads a profile named
    ``"ci"`` for the ``binchecker`` suite. We register a second profile
    here so a future ``--hypothesis-profile=webrecon-ci`` invocation can
    pick the webrecon defaults without disturbing the binchecker run.

    Defaults mirror the design document's testing-strategy section:

    * ``max_examples=200`` — enough iterations to surface boundary bugs
      without making the suite painfully slow.
    * ``deadline=None`` — property tests that exercise mocked HTTP
      paths can have non-deterministic latency.
    """
    if settings is None:
        return
    settings.register_profile(
        _HYPOTHESIS_PROFILE_NAME,
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow] if HealthCheck else [],
    )


_register_hypothesis_profile()


# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------

# pytest-asyncio (configured via `asyncio_mode = auto` in pytest.ini) is
# responsible for creating and tearing down the per-test event loop. We
# therefore do not export an `event_loop` / `event_loop_policy` fixture
# from this conftest — the plugin's defaults are correct on every
# supported platform (Windows, Linux, macOS) and Python version
# (>= 3.10), and overriding them risks tripping the deprecation warning
# emitted by Python 3.12+ for `asyncio.DefaultEventLoopPolicy`.


# ---------------------------------------------------------------------------
# HTTP mocking
# ---------------------------------------------------------------------------

# Type alias: a request handler maps an `httpx.Request` to an `httpx.Response`.
HttpHandler = Callable[[httpx.Request], httpx.Response]


class _RecordingMockTransport(httpx.MockTransport):
    """``httpx.MockTransport`` subclass that records every request.

    Tests can introspect ``transport.requests`` to assert that the code
    under test issued the expected URLs / methods / headers without
    coupling the assertions to internal details of `httpx`.
    """

    def __init__(self, handler: HttpHandler) -> None:
        self.requests: list[httpx.Request] = []
        self._user_handler = handler
        super().__init__(self._wrapped_handler)

    def _wrapped_handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._user_handler(request)


def _default_handler(request: httpx.Request) -> httpx.Response:
    """Fallback handler — fail loudly when a test forgets to register one."""
    raise AssertionError(
        "Unexpected outbound HTTP request during a webrecon test: "
        f"{request.method} {request.url}. "
        "Register a handler via `mock_http_transport` (or "
        "`mock_http_responses`) before exercising the code under test."
    )


@pytest.fixture
def mock_http_transport() -> _RecordingMockTransport:
    """Yield a recording ``httpx.MockTransport`` with a default-deny handler.

    Typical use::

        def test_my_client(mock_http_transport):
            mock_http_transport._user_handler = lambda req: httpx.Response(
                200, json={"ok": True}
            )
            client = httpx.AsyncClient(transport=mock_http_transport)
            ...

    For more ergonomic setup, prefer the ``mock_http_responses`` fixture
    which lets the test register URL → response mappings declaratively.
    """
    return _RecordingMockTransport(_default_handler)


@pytest.fixture
def mock_http_responses(
    mock_http_transport: _RecordingMockTransport,
) -> Callable[..., _RecordingMockTransport]:
    """Return a helper that registers URL → response mappings.

    The returned callable accepts ``(url_or_pattern, response)`` pairs
    and installs a handler that matches incoming requests by URL prefix
    (so tests can stub ``https://api.example.com`` once and have every
    request to that host fall through to a single response).

    Usage::

        def test_fofa_pagination(mock_http_responses):
            transport = mock_http_responses(
                ("https://fofa.info/api/v1/search/all", httpx.Response(
                    200, json={"results": [], "size": 0}
                )),
            )
            ...

    The fixture returns the same recording transport for assertion
    purposes (``transport.requests``).
    """

    def _install(*pairs: tuple[str, httpx.Response]) -> _RecordingMockTransport:
        mapping = list(pairs)

        def _handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            for prefix, response in mapping:
                if url.startswith(prefix):
                    # `httpx.Response` is single-use once read; clone via
                    # `_content` to make the fixture safe for tests that
                    # issue more than one matching request.
                    return httpx.Response(
                        status_code=response.status_code,
                        headers=response.headers,
                        content=response.content,
                        request=request,
                    )
            return _default_handler(request)

        mock_http_transport._user_handler = _handler  # type: ignore[attr-defined]
        return mock_http_transport

    return _install


@pytest.fixture
async def async_client(
    mock_http_transport: _RecordingMockTransport,
) -> AsyncIterator[httpx.AsyncClient]:
    """Yield an ``httpx.AsyncClient`` wired to the recording mock transport.

    Use this fixture for any test that needs an HTTP client without
    talking to the network. The transport rejects unregistered requests
    by default — tests must wire up ``mock_http_responses`` (or set
    ``mock_http_transport._user_handler`` directly) before issuing
    requests.
    """
    async with httpx.AsyncClient(
        transport=mock_http_transport, base_url="http://test.invalid"
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# Database / filesystem helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def sqlite_db_path(tmp_path: Path) -> Path:
    """Return a per-test SQLite path under ``tmp_path``.

    Integration tests use this to point the asset-database layer at a
    fresh on-disk file; the file is automatically removed when pytest
    cleans up ``tmp_path``.
    """
    return tmp_path / "webrecon_test.sqlite3"


# ---------------------------------------------------------------------------
# Sample payload factories (used by unit + integration tests)
# ---------------------------------------------------------------------------


@pytest.fixture
def fofa_search_response() -> dict[str, Any]:
    """Return a minimal FOFA-shaped search response.

    The real schema (see https://en.fofa.info/api) is much richer; this
    fixture intentionally returns only the fields the discovery module
    parses so unit tests stay focused on behaviour rather than payload
    shape. Tests that need richer fixtures can extend this dict.
    """
    return {
        "error": False,
        "size": 2,
        "page": 1,
        "mode": "extended",
        "query": "app=\"WordPress\"",
        "results": [
            ["http://example.com", "example.com", "80"],
            ["https://shop.example.org", "shop.example.org", "443"],
        ],
    }


@pytest.fixture
def shodan_search_response() -> dict[str, Any]:
    """Return a minimal Shodan-shaped search response."""
    return {
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


@pytest.fixture
def serper_search_response() -> dict[str, Any]:
    """Return a minimal Serper-shaped search response."""
    return {
        "searchParameters": {"q": "site:example.com filetype:env", "type": "search"},
        "organic": [
            {
                "title": "Example .env",
                "link": "https://example.com/.env",
                "snippet": "STRIPE_SECRET_KEY=sk_test_...",
                "position": 1,
            }
        ],
    }


@pytest.fixture
def github_search_response() -> dict[str, Any]:
    """Return a minimal GitHub code-search response."""
    return {
        "total_count": 1,
        "incomplete_results": False,
        "items": [
            {
                "name": "config.py",
                "path": "src/config.py",
                "sha": "deadbeef",
                "url": (
                    "https://api.github.com/repositories/1/contents/src/config.py"
                    "?ref=main"
                ),
                "html_url": "https://github.com/example/repo/blob/main/src/config.py",
                "repository": {
                    "full_name": "example/repo",
                    "html_url": "https://github.com/example/repo",
                    "private": False,
                },
            }
        ],
    }


@pytest.fixture
def make_json_response() -> Callable[[Any, int], httpx.Response]:
    """Return a small helper for building ``httpx.Response`` JSON payloads.

    Saves repetitive ``httpx.Response(200, json=..., headers=...)``
    construction in tests::

        resp = make_json_response({"ok": True})
        resp_404 = make_json_response({"err": "not found"}, 404)
    """

    def _build(payload: Any, status_code: int = 200) -> httpx.Response:
        return httpx.Response(
            status_code=status_code,
            content=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
        )

    return _build


# ---------------------------------------------------------------------------
# Network guard (opt-in)
# ---------------------------------------------------------------------------


@pytest.fixture
def block_outbound_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Opt-in fixture that blocks raw socket creation during a test.

    The webrecon HTTP layer is exercised through ``mock_http_transport``
    so the default test path never opens a real socket. For paranoid
    tests that want to fail hard on accidental network access (e.g. a
    code path that calls ``urllib.request`` instead of the configured
    ``httpx`` client) request this fixture explicitly. It is *not*
    autouse so library imports and async event-loop bookkeeping that
    legitimately allocate sockets continue to work.
    """
    import socket

    real_socket = socket.socket

    class _BlockedSocket(real_socket):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError(
                "Outbound socket creation is blocked during this webrecon test. "
                "Use the `mock_http_transport` / `async_client` fixtures."
            )

    monkeypatch.setattr(socket, "socket", _BlockedSocket)
    yield
