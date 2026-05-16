"""Exposed-file scanner for the mass-parser pipeline.

This module checks a list of common exposed-file paths on target
websites (``/.env``, ``/wp-config.php.bak``, ``/.git/config``, ...)
and analyses the content for leaked secrets -- particularly Stripe
API keys.

The scanner is the ``webrecon`` counterpart of the ``sk_web_hunter``
standalone script, refactored to use the shared
:class:`~webrecon.mass_parser.client.MassParserClient` transport
layer and the :class:`~webrecon.core.models` dataclasses.

Usage::

    async with MassParserClient() as http:
        scanner = ExposedFileScanner(http)
        async for result in scanner.scan_site("https://example.com"):
            print(result.found_keys)

Validates: Requirement 3.1 (configuration of common exposed file paths),
Requirement 3.2 (concurrent checking with configurable limits),
Requirement 3.3 (content analysis for secrets).
"""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from webrecon.core.models import (
    KeyType,
    StripeKey,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from webrecon.mass_parser.client import MassParserClient

__all__ = [
    "DEFAULT_EXPOSED_PATHS",
    "ExposedFileScanner",
    "ScanResult",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Default exposed-file path list
# ---------------------------------------------------------------------------

DEFAULT_EXPOSED_PATHS: list[str] = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.save",
    "/.env.old",
    "/.env.bak",
    "/.env.swp",
    "/.env~",
    "/.env.example",
    "/wp-config.php.bak",
    "/wp-config.php.save",
    "/wp-config.php.old",
    "/wp-config.php.swp",
    "/wp-config.php~",
    "/config.php.bak",
    "/config/settings.json",
    "/config/secrets.json",
    "/stripe/config.json",
    "/api/config",
    "/debug",
    "/.git/config",
    "/.git/HEAD",
    "/server/.env",
    "/backend/.env",
    "/api/.env",
    "/app/.env",
    "/application/.env",
    "/.env.prod",
    "/.env.development",
]


# ---------------------------------------------------------------------------
# Stripe key patterns
# ---------------------------------------------------------------------------

_SK_LIVE_RE: re.Pattern[str] = re.compile(r"(sk_live_[0-9a-zA-Z]{24,})")
_PK_LIVE_RE: re.Pattern[str] = re.compile(r"(pk_live_[0-9a-zA-Z]{24,})")
_SK_TEST_RE: re.Pattern[str] = re.compile(r"(sk_test_[0-9a-zA-Z]{24,})")
_PK_TEST_RE: re.Pattern[str] = re.compile(r"(pk_test_[0-9a-zA-Z]{24,})")

# Generic secret patterns (subset of github/analyzer patterns).
_DB_PASSWORD_RE: re.Pattern[str] = re.compile(
    r"(?:(?:DB_PASSWORD|DATABASE_PASSWORD)\s*[:=]\s*[\"']?)([^\s\"',;]+)"
)
_AWS_KEY_RE: re.Pattern[str] = re.compile(r"(AKIA[0-9A-Z]{16})")
_PRIVATE_KEY_RE: re.Pattern[str] = re.compile(
    r"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)"
)


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Result of scanning one exposed-file path on a website.

    Attributes:
        url: The full URL that was checked.
        status_code: HTTP status code of the response.
        found_keys: Stripe keys found in the response body.
        other_secrets: Non-Stripe secrets found in the response body.
        content_length: Length of the response body in bytes.
        accessible: Whether the path returned a 200 response.
    """

    url: str
    status_code: int = 0
    found_keys: list[StripeKey] = field(default_factory=list)
    other_secrets: list[dict[str, str]] = field(default_factory=list)
    content_length: int = 0
    accessible: bool = False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class ExposedFileScanner:
    """Scan websites for exposed configuration files and leaked secrets.

    The scanner checks a configurable list of paths on each target
    website, analyses the content for Stripe keys and other secrets,
    and produces :class:`ScanResult` objects.

    Args:
        client: A :class:`MassParserClient` for HTTP transport.
        paths: List of paths to check. Defaults to
            :data:`DEFAULT_EXPOSED_PATHS`.
        per_host_concurrency: Maximum concurrent requests per single
            host (to avoid overwhelming a single target).
        max_content_length: Truncate response analysis beyond this
            many bytes to limit memory usage.
    """

    def __init__(
        self,
        client: MassParserClient,
        *,
        paths: Sequence[str] | None = None,
        per_host_concurrency: int = 5,
        max_content_length: int = 100_000,
    ) -> None:
        self._client = client
        self._paths: list[str] = list(paths) if paths else list(DEFAULT_EXPOSED_PATHS)
        self._per_host_sem = asyncio.Semaphore(max(1, per_host_concurrency))
        self._max_content = max_content_length

    # ---- Public API ---------------------------------------------------

    async def scan_site(
        self,
        base_url: str,
        *,
        source_url: str = "",
    ) -> AsyncIterator[ScanResult]:
        """Scan a single website for exposed files.

        Args:
            base_url: The base URL of the target (e.g.
                ``"https://example.com"``).
            source_url: Optional URL that identified this target
                (e.g. a Serper search result link). Stored in the
                ``metadata`` of discovered keys.

        Yields:
            One :class:`ScanResult` per path that returned an
            accessible response or contained secrets.
        """
        base_url = base_url.rstrip("/")

        async def _check_path(path: str) -> ScanResult:
            async with self._per_host_sem:
                return await self._check_one(base_url, path, source_url)

        tasks = [_check_path(p) for p in self._paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, BaseException):
                _LOGGER.debug(
                    "mass_parser.scanner.path_error",
                    base_url=base_url,
                    error=str(result),
                )
                continue
            if result.accessible or result.found_keys or result.other_secrets:
                yield result

    async def scan_sites(
        self,
        urls: Sequence[str],
        *,
        source_url: str = "",
    ) -> AsyncIterator[ScanResult]:
        """Scan multiple websites for exposed files.

        Concurrency is bounded by the
        :class:`~webrecon.mass_parser.client.MassParserClient`
        semaphore.

        Args:
            urls: Sequence of base URLs to scan.
            source_url: Optional provenance URL.

        Yields:
            One :class:`ScanResult` per accessible path with secrets.
        """
        for url in urls:
            async for result in self.scan_site(url, source_url=source_url):
                yield result

    # ---- Internal -----------------------------------------------------

    async def _check_one(
        self,
        base_url: str,
        path: str,
        source_url: str,
    ) -> ScanResult:
        """Check a single path on a single host."""
        full_url = f"{base_url}{path}"
        result = ScanResult(url=full_url)

        resp = await self._client.get(
            full_url,
            timeout=5.0,
            follow_redirects=False,
        )

        result.status_code = resp.status_code

        if resp.error is not None:
            _LOGGER.debug(
                "mass_parser.scanner.request_error",
                url=full_url,
                error=str(resp.error),
            )
            return result

        if resp.status_code != 200:
            return result

        result.accessible = True
        result.content_length = len(resp.text)

        # Truncate analysis to limit memory.
        content = resp.text[: self._max_content]

        # --- Stripe keys ---
        now = datetime.now(timezone.utc)
        for pattern, key_type in [
            (_SK_LIVE_RE, KeyType.SK_LIVE),
            (_PK_LIVE_RE, KeyType.PK_LIVE),
            (_SK_TEST_RE, KeyType.OTHER),
            (_PK_TEST_RE, KeyType.OTHER),
        ]:
            seen: set[str] = set()
            for m in pattern.finditer(content):
                value = m.group(1)
                if value in seen:
                    continue
                seen.add(value)

                metadata: dict[str, str] = {
                    "discovery_method": "exposed_file_scan",
                    "path": path,
                }
                if source_url:
                    metadata["source_url"] = source_url

                result.found_keys.append(
                    StripeKey(
                        id=str(uuid.uuid4()),
                        key_value=value,
                        key_type=key_type,
                        discovered_at=now,
                        source_url=source_url or base_url,
                        source_file=path,
                        is_valid=False,
                        metadata=metadata,
                    )
                )

        # --- Other secrets ---
        for pattern, name, severity in [
            (_DB_PASSWORD_RE, "db_password", "critical"),
            (_AWS_KEY_RE, "aws_access_key_id", "critical"),
            (_PRIVATE_KEY_RE, "private_key_block", "critical"),
        ]:
            seen_vals: set[str] = set()
            for m in pattern.finditer(content):
                val = m.group(1)
                if val in seen_vals:
                    continue
                seen_vals.add(val)
                result.other_secrets.append(
                    {
                        "pattern_name": name,
                        "value": val[:30] + ("..." if len(val) > 30 else ""),
                        "severity": severity,
                        "path": path,
                    }
                )

        if result.found_keys or result.other_secrets:
            _LOGGER.info(
                "mass_parser.scanner.secrets_found",
                url=full_url,
                stripe_keys=len(result.found_keys),
                other_secrets=len(result.other_secrets),
            )

        return result
