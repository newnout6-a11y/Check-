"""Website validation and technology detection for the automation pipeline.

This module performs comprehensive website assessment:

* **Technology stack detection** -- identifies CMS, frameworks, and
  JS libraries from HTTP headers, HTML markers, and JavaScript globals.
* **Security header analysis** -- checks for CSP, HSTS, X-Frame-Options,
  and other security headers.
* **SSL certificate validation** -- basic TLS certificate checks.
* **Performance metrics** -- response time, content size, redirect count.

Usage::

    async with MassParserClient() as http:
        validator = WebsiteValidator(http)
        report = await validator.validate("https://example.com")
        print(report.tech_stack, report.security_score)

Validates: Requirement 6.1 (technology stack detection),
Requirement 6.2 (security header analysis),
Requirement 6.3 (SSL certificate validation).
"""

from __future__ import annotations

import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from webrecon.core.models import (
    AssetStatus,
    DiscoverySource,
    WebsiteAsset,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.mass_parser.client import MassParserClient

__all__ = [
    "SecurityHeaderResult",
    "ValidationReport",
    "WebsiteValidator",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Technology detection markers
# ---------------------------------------------------------------------------

# Header-based tech markers: {(header_name, substring): tech_name}
_HEADER_MARKERS: dict[tuple[str, str], str] = {
    ("server", "nginx"): "nginx",
    ("server", "apache"): "apache",
    ("server", "cloudflare"): "cloudflare",
    ("server", "caddy"): "caddy",
    ("server", "iis"): "IIS",
    ("server", "openresty"): "openresty",
    ("x-powered-by", "express"): "express",
    ("x-powered-by", "php"): "php",
    ("x-powered-by", "asp.net"): "ASP.NET",
    ("x-powered-by", "next"): "nextjs",
    ("x-drupal-cache", ""): "drupal",
    ("x-generator", "wordpress"): "wordpress",
}

# HTML-based tech markers: {(tag_pattern, attribute_substring): tech_name}
_HTML_MARKERS: list[tuple[str, str]] = [
    ('meta[name="generator"][content*="WordPress"]', "wordpress"),
    ('meta[name="generator"][content*="Drupal"]', "drupal"),
    ('meta[name="generator"][content*="Joomla"]', "joomla"),
    ('meta[name="generator"][content*="Shopify"]', "shopify"),
    ('script[src*="woocommerce"]', "woocommerce"),
    ('script[src*="wp-includes"]', "wordpress"),
    ('link[href*="wp-content"]', "wordpress"),
    ('script[src*="react"]', "react"),
    ('script[src*="vue"]', "vue"),
    ('script[src*="angular"]', "angular"),
    ('script[src*="jquery"]', "jquery"),
    ('script[src*="next"]', "nextjs"),
    ('script[src*="nuxt"]', "nuxtjs"),
    ('script[src*="stripe"]', "stripe"),
    ('script[src*="google-analytics"]', "google-analytics"),
    ('script[src*="gtag"]', "google-analytics"),
    ('link[href*="bootstrap"]', "bootstrap"),
    ('link[href*="tailwind"]', "tailwindcss"),
]

# Security headers to check and their descriptions.
_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "Prevents XSS by controlling resource loading",
    "Strict-Transport-Security": "Forces HTTPS connections",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "X-XSS-Protection": "Enables browser XSS filter (deprecated but still checked)",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature access",
    "Cross-Origin-Opener-Policy": "Isolates browsing context",
    "Cross-Origin-Resource-Policy": "Controls cross-origin resource sharing",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class SecurityHeaderResult:
    """Result of checking a single security header.

    Attributes:
        name: Header name.
        present: Whether the header is present in the response.
        value: The header value, or empty string if absent.
        description: What this header protects against.
    """

    name: str
    present: bool = False
    value: str = ""
    description: str = ""


@dataclass
class ValidationReport:
    """Comprehensive validation report for a website.

    Attributes:
        url: The validated URL.
        tech_stack: Detected technologies.
        security_headers: Security header analysis results.
        security_score: Percentage of recommended security headers
            present (0-100).
        has_ssl: Whether the site uses HTTPS with a valid certificate.
        response_time_ms: Response time in milliseconds.
        content_size_bytes: Response body size in bytes.
        redirect_count: Number of HTTP redirects followed.
        asset: A :class:`~webrecon.core.models.WebsiteAsset` populated
            with the validation findings, or ``None`` if the site was
            unreachable.
    """

    url: str
    tech_stack: list[str] = field(default_factory=list)
    security_headers: list[SecurityHeaderResult] = field(default_factory=list)
    security_score: int = 0
    has_ssl: bool = False
    response_time_ms: float = 0.0
    content_size_bytes: int = 0
    redirect_count: int = 0
    asset: WebsiteAsset | None = None


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class WebsiteValidator:
    """Validate and assess websites for technology and security posture.

    Args:
        client: A :class:`MassParserClient` for HTTP transport.
        check_ssl: Whether to perform SSL certificate validation.
    """

    def __init__(
        self,
        client: MassParserClient,
        *,
        check_ssl: bool = True,
    ) -> None:
        self._client = client
        self._check_ssl = check_ssl

    # ---- Public API ---------------------------------------------------

    async def validate(
        self,
        url: str,
        *,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL,
    ) -> ValidationReport:
        """Validate a single website.

        Args:
            url: The target URL.
            discovery_source: How this URL was discovered.

        Returns:
            A :class:`ValidationReport` with the findings.
        """
        url = url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        report = ValidationReport(url=url)

        # Fetch the page.
        import time
        start = time.monotonic()
        resp = await self._client.get(url, timeout=15.0)
        elapsed = time.monotonic() - start

        report.response_time_ms = elapsed * 1000

        if resp.error is not None:
            _LOGGER.info(
                "automation.validator.site_unreachable",
                url=url,
                error=str(resp.error),
            )
            return report

        report.content_size_bytes = len(resp.text)

        # Count redirects (approximate from attempts).
        report.redirect_count = max(0, resp.attempts - 1)

        # Technology detection.
        report.tech_stack = self._detect_tech_stack(resp)

        # Security headers.
        report.security_headers = self._check_security_headers(resp)
        present_count = sum(1 for h in report.security_headers if h.present)
        total = len(report.security_headers)
        report.security_score = (
            int(present_count / total * 100) if total else 0
        )

        # SSL check.
        if self._check_ssl and url.startswith("https://"):
            report.has_ssl = self._check_ssl_cert(url)

        # Build the WebsiteAsset.
        now = datetime.now(timezone.utc)
        metadata = {
            f"security_header_{h.name}": h.value
            for h in report.security_headers
            if h.present
        }
        metadata["has_ssl"] = str(report.has_ssl).lower()
        asset = WebsiteAsset(
            id=str(uuid.uuid4()),
            url=url,
            normalized_url=url,
            discovered_at=now,
            last_checked=now,
            status=AssetStatus.ACTIVE,
            discovery_source=discovery_source,
            technology_stack=report.tech_stack,
            metadata=metadata,
        )
        report.asset = asset

        _LOGGER.info(
            "automation.validator.validated",
            url=url,
            tech_stack=report.tech_stack,
            security_score=report.security_score,
            ssl=report.has_ssl,
        )

        return report

    async def validate_batch(
        self,
        urls: list[str],
        *,
        discovery_source: DiscoverySource = DiscoverySource.MANUAL,
    ) -> list[ValidationReport]:
        """Validate a batch of URLs concurrently.

        Args:
            urls: List of target URLs.
            discovery_source: How these URLs were discovered.

        Returns:
            List of :class:`ValidationReport` objects.
        """
        import asyncio

        results = await asyncio.gather(
            *[self.validate(u, discovery_source=discovery_source) for u in urls],
        )
        return list(results)

    # ---- Internal: Tech stack -----------------------------------------

    def _detect_tech_stack(self, resp: Any) -> list[str]:
        """Detect technologies from headers and HTML content."""
        techs: list[str] = []
        seen: set[str] = set()

        # Header-based detection.
        for (header_name, substring), tech_name in _HEADER_MARKERS.items():
            header_value = resp.headers.get(header_name, "")
            if (
                header_value
                and (not substring or substring.lower() in header_value.lower())
                and tech_name not in seen
            ):
                seen.add(tech_name)
                techs.append(tech_name)

        # HTML-based detection.
        html = resp.text[:100_000]  # Limit analysis size.
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return techs

        for css_selector, tech_name in _HTML_MARKERS:
            if tech_name in seen:
                continue
            try:
                if soup.select_one(css_selector):
                    seen.add(tech_name)
                    techs.append(tech_name)
            except Exception:
                continue

        # Additional string-based markers.
        html_lower = html.lower()
        string_markers: list[tuple[str, str]] = [
            ("wp-json", "wordpress"),
            ("woocommerce", "woocommerce"),
            ("stripe.js", "stripe"),
            ("stripe-v3", "stripe"),
            ("recaptcha", "recaptcha"),
            ("cloudflare", "cloudflare"),
        ]
        for marker, tech_name in string_markers:
            if tech_name not in seen and marker in html_lower:
                seen.add(tech_name)
                techs.append(tech_name)

        return techs

    # ---- Internal: Security headers -----------------------------------

    @staticmethod
    def _check_security_headers(resp: Any) -> list[SecurityHeaderResult]:
        """Check for recommended security headers."""
        results: list[SecurityHeaderResult] = []

        for header_name, description in _SECURITY_HEADERS.items():
            value = resp.headers.get(header_name, "")
            results.append(SecurityHeaderResult(
                name=header_name,
                present=bool(value),
                value=value,
                description=description,
            ))

        return results

    # ---- Internal: SSL ------------------------------------------------

    @staticmethod
    def _check_ssl_cert(url: str) -> bool:
        """Basic SSL certificate validity check.

        Attempts a TLS handshake and verifies the certificate is
        not expired. Returns ``True`` if the certificate is valid,
        ``False`` otherwise.
        """
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        port = parsed.port or 443

        try:
            context = ssl.create_default_context()
            with (
                socket.create_connection((hostname, port), timeout=5) as sock,
                context.wrap_socket(sock, server_hostname=hostname),
            ):
                # If wrap_socket succeeds, the cert is valid.
                return True
        except (ssl.SSLCertVerificationError, ssl.SSLError):
            return False
        except (TimeoutError, OSError, ConnectionError):
            return False
