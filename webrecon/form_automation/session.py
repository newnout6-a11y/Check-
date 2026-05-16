"""Session management for the form-automation pipeline.

This module provides persistent cookie/session tracking, auth state
management, redirect chain analysis, and concurrent session isolation.
It is consumed by :mod:`webrecon.form_automation.filler` to maintain
state across multi-step form interactions (login → action → logout).

Usage::

    session = FormSession(base_url="https://example.com")
    await session.initialize(client)
    await session.login(username="test", password="test")
    result = await session.submit_form(form, data)
    await session.close()

Validates: Requirement 4.6 (cookie and session persistence,
auth state tracking, redirect handling).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.mass_parser.client import MassParserClient, RequestResult

__all__ = [
    "FormSession",
    "RedirectStep",
    "SessionState",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedirectStep:
    """One hop in a redirect chain.

    Attributes:
        url: The URL that was requested.
        status_code: HTTP status code (typically 301, 302, 303, 307).
        location: The ``Location`` header value (next hop URL).
    """

    url: str
    status_code: int
    location: str


@dataclass
class SessionState:
    """Snapshot of a session's authentication and cookie state.

    Attributes:
        is_authenticated: Whether the session has successfully
            authenticated.
        auth_method: The authentication method used (e.g.
            ``"form_login"``, ``"basic_auth"``, ``"cookie"``).
        cookies: Current cookie jar as ``{name: value}`` dict.
        last_url: The last URL visited in this session.
        request_count: Total number of requests made in this session.
        redirect_chain: Ordered list of redirect hops from the last
            request.
    """

    is_authenticated: bool = False
    auth_method: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    last_url: str = ""
    request_count: int = 0
    redirect_chain: list[RedirectStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class FormSession:
    """Manage a persistent HTTP session for form interactions.

    The session wraps a :class:`MassParserClient` and maintains a
    cookie jar, authentication state, and redirect history across
    multiple requests. It is designed for multi-step workflows:

    1. Initialize the session (fetch the login page to collect
       initial cookies).
    2. Authenticate (submit login form).
    3. Perform actions (submit forms, navigate pages).
    4. Close the session.

    Args:
        base_url: The root URL of the target site. Used to resolve
            relative URLs.
        session_id: Optional identifier for logging. Auto-generated
            if not provided.
    """

    def __init__(
        self,
        *,
        base_url: str = "",
        session_id: str = "",
    ) -> None:
        import uuid

        self._base_url = base_url.rstrip("/")
        self._session_id = session_id or uuid.uuid4().hex[:8]
        self._state = SessionState()
        self._client: MassParserClient | None = None

    # ---- Properties ---------------------------------------------------

    @property
    def state(self) -> SessionState:
        """Return the current session state."""
        return self._state

    @property
    def is_authenticated(self) -> bool:
        """Return whether the session has authenticated."""
        return self._state.is_authenticated

    @property
    def cookies(self) -> dict[str, str]:
        """Return the current cookie jar."""
        return dict(self._state.cookies)

    @property
    def session_id(self) -> str:
        """Return the session identifier."""
        return self._session_id

    # ---- Lifecycle ----------------------------------------------------

    async def initialize(self, client: MassParserClient) -> None:
        """Bind the session to an HTTP client and collect initial cookies.

        Fetches the ``base_url`` to collect any initial cookies the
        server sets (CSRF tokens, session IDs, etc.).

        Args:
            client: A :class:`MassParserClient` to use for requests.
        """
        self._client = client

        if self._base_url:
            resp = await self.get(self._base_url)
            self._extract_cookies(resp)

            _LOGGER.debug(
                "form_automation.session.initialized",
                session_id=self._session_id,
                initial_cookies=len(self._state.cookies),
            )

    async def close(self) -> None:
        """Clean up the session.

        The session does not own the HTTP client, so it only
        clears internal state.
        """
        self._state = SessionState()
        _LOGGER.debug(
            "form_automation.session.closed",
            session_id=self._session_id,
        )

    # ---- HTTP methods -------------------------------------------------

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> RequestResult:
        """Issue a GET request with session cookies.

        Args:
            url: Target URL (relative URLs are resolved against
                ``base_url``).
            headers: Optional extra headers.

        Returns:
            A :class:`RequestResult`.
        """
        resolved = self._resolve_url(url)
        merged_headers = self._build_headers(headers)

        resp = await self._require_client().get(
            resolved,
            headers=merged_headers,
        )

        self._state.request_count += 1
        self._state.last_url = resolved
        self._extract_cookies(resp)
        self._track_redirects(resp)

        return resp

    async def post(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> RequestResult:
        """Issue a POST request with session cookies.

        Args:
            url: Target URL.
            data: Form-encoded body.
            json: JSON body.
            headers: Optional extra headers.

        Returns:
            A :class:`RequestResult`.
        """
        resolved = self._resolve_url(url)
        merged_headers = self._build_headers(headers)

        resp = await self._require_client().post(
            resolved,
            data=data,
            json=json,
            headers=merged_headers,
        )

        self._state.request_count += 1
        self._state.last_url = resolved
        self._extract_cookies(resp)
        self._track_redirects(resp)

        return resp

    # ---- Authentication -----------------------------------------------

    async def login(
        self,
        *,
        login_url: str = "",
        username_field: str = "username",
        password_field: str = "password",
        username: str = "",
        password: str = "",
        extra_data: dict[str, str] | None = None,
    ) -> bool:
        """Attempt to authenticate via form login.

        Args:
            login_url: The login form action URL.
            username_field: Name of the username field.
            password_field: Name of the password field.
            username: The username to submit.
            password: The password to submit.
            extra_data: Additional form fields (CSRF tokens, etc.).

        Returns:
            ``True`` if the login appears to have succeeded.
        """
        if not login_url:
            login_url = f"{self._base_url}/login/"
            if not self._base_url:
                _LOGGER.warning(
                    "form_automation.session.login_no_url",
                    session_id=self._session_id,
                )
                return False

        # First, GET the login page to collect CSRF tokens.
        await self.get(login_url)

        # Build form data.
        form_data: dict[str, str] = {}
        if extra_data:
            form_data.update(extra_data)
        form_data[username_field] = username
        form_data[password_field] = password

        # Submit login.
        post_resp = await self.post(login_url, data=form_data)

        # Heuristic: 2xx/3xx + no error indicators = success.
        success = self._check_login_success(post_resp)

        if success:
            self._state.is_authenticated = True
            self._state.auth_method = "form_login"
            _LOGGER.info(
                "form_automation.session.login_success",
                session_id=self._session_id,
                url=login_url,
            )
        else:
            _LOGGER.warning(
                "form_automation.session.login_failed",
                session_id=self._session_id,
                url=login_url,
                status=post_resp.status_code,
            )

        return success

    # ---- Internal -----------------------------------------------------

    def _resolve_url(self, url: str) -> str:
        """Resolve a possibly-relative URL against the base URL."""
        if url.startswith(("http://", "https://")):
            return url
        if self._base_url:
            return urljoin(self._base_url + "/", url.lstrip("/"))
        return url

    def _build_headers(
        self,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Build request headers including session cookies."""
        headers: dict[str, str] = {}
        if self._state.cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in self._state.cookies.items()
            )
            headers["Cookie"] = cookie_str
        if self._state.last_url:
            headers["Referer"] = self._state.last_url
        if extra:
            headers.update(extra)
        return headers

    def _extract_cookies(self, resp: RequestResult) -> None:
        """Extract Set-Cookie values from a response into the jar."""
        # httpx puts cookies in the "set-cookie" header.
        set_cookie = resp.headers.get("set-cookie", "")
        if not set_cookie:
            return

        # Parse simple Set-Cookie: name=value; ...
        for part in set_cookie.split(","):
            part = part.strip()
            if "=" not in part:
                continue
            name_value = part.split(";")[0].strip()
            name, _, value = name_value.partition("=")
            name = name.strip()
            value = value.strip()
            if name:
                self._state.cookies[name] = value

    def _track_redirects(self, resp: RequestResult) -> None:
        """Record redirect information from a response."""
        self._state.redirect_chain.clear()

        status = resp.status_code
        if status in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if location:
                self._state.redirect_chain.append(
                    RedirectStep(
                        url=resp.url,
                        status_code=status,
                        location=location,
                    )
                )

    @staticmethod
    def _check_login_success(resp: RequestResult) -> bool:
        """Heuristic check for successful login."""
        if resp.error is not None:
            return False

        status = resp.status_code
        if 200 <= status < 400:
            text_lower = resp.text[:2000].lower()
            # Strong failure indicators.
            for indicator in ("invalid credentials", "wrong password",
                              "login failed", "authentication failed",
                              "incorrect username", "access denied"):
                if indicator in text_lower:
                    return False
            return True

        return False

    def _require_client(self) -> MassParserClient:
        """Return the bound HTTP client or raise."""
        if self._client is None:
            raise RuntimeError(
                "FormSession is not initialized; call initialize() first"
            )
        return self._client
