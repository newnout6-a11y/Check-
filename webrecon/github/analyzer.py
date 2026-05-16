"""Secret detection and analysis for GitHub code-search results.

This module consumes :class:`~webrecon.github.client.GithubCodeMatch`
objects produced by :class:`~webrecon.github.client.GithubClient` and
extracts structured intelligence:

* :class:`SecretPattern` -- a compiled regex + metadata describing one
  category of credential or API key the analyzer recognises.
* :class:`SecretMatch` -- a single secret found inside a file, with
  the surrounding context, the originating file path, and the
  repository provenance.
* :class:`GithubAnalyzer` -- the main analysis engine. It accepts a
  :class:`~webrecon.github.client.GithubClient`, walks code-search
  results, downloads file content, applies every registered
  :class:`SecretPattern`, and yields :class:`SecretMatch` objects.
  Convenience helpers (:py:meth:`~GithubAnalyzer.analyze_query`,
  :py:meth:`~GithubAnalyzer.analyze_matches`) wrap the common
  search-then-analyse workflow.

Stripe-specific helpers:

* :func:`classify_stripe_key` -- map a raw key string to the
  appropriate :class:`~webrecon.core.models.KeyType`.
* :func:`stripe_key_to_model` -- convert a :class:`SecretMatch` whose
  pattern is a Stripe key into a :class:`~webrecon.core.models.StripeKey`
  ready for database persistence.

The default pattern set covers Stripe live/test keys, AWS access keys,
database connection strings, private key markers, JWTs, and generic
secret variable assignments. Operators can extend the set by passing
additional :class:`SecretPattern` instances to the analyzer.

Validates: Requirement 2.2 (pattern matching for API keys, credentials,
tokens), Requirement 2.3 (Stripe key detection and validation),
Requirement 2.5 (batch processing of search results).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from webrecon.core.models import (
    KeyType,
    StripeKey,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from webrecon.github.client import GithubClient, GithubCodeMatch

__all__ = [
    "GithubAnalyzer",
    "SecretMatch",
    "SecretPattern",
    "classify_stripe_key",
    "stripe_key_to_model",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Secret pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    """A compiled regex that describes one category of secret.

    Attributes:
        name: Human-readable label (e.g. ``"stripe_sk_live"``).
        pattern: Compiled regular expression with at least one
            capture group that yields the secret value.
        severity: Rough severity bucket (``"critical"``, ``"high"``,
            ``"medium"``, ``"low"``). Used for prioritisation and
            reporting.
        key_type: If the pattern discovers a Stripe key, the
            corresponding :class:`~webrecon.core.models.KeyType`;
            ``None`` for non-Stripe patterns.
    """

    name: str
    pattern: re.Pattern[str]
    severity: str = "medium"
    key_type: KeyType | None = None


# Default pattern set -- covers the most common credential leaks.
# Each pattern must have at least one capture group around the
# actual secret value.

_DEFAULT_PATTERNS: list[SecretPattern] = [
    # Stripe keys
    SecretPattern(
        name="stripe_sk_live",
        pattern=re.compile(r"(sk_live_[0-9a-zA-Z]{24,})"),
        severity="critical",
        key_type=KeyType.SK_LIVE,
    ),
    SecretPattern(
        name="stripe_pk_live",
        pattern=re.compile(r"(pk_live_[0-9a-zA-Z]{24,})"),
        severity="high",
        key_type=KeyType.PK_LIVE,
    ),
    SecretPattern(
        name="stripe_sk_test",
        pattern=re.compile(r"(sk_test_[0-9a-zA-Z]{24,})"),
        severity="medium",
        key_type=KeyType.OTHER,
    ),
    SecretPattern(
        name="stripe_pk_test",
        pattern=re.compile(r"(pk_test_[0-9a-zA-Z]{24,})"),
        severity="low",
        key_type=KeyType.OTHER,
    ),
    SecretPattern(
        name="stripe_rk_live",
        pattern=re.compile(r"(rk_live_[0-9a-zA-Z]{24,})"),
        severity="critical",
        key_type=KeyType.SK_LIVE,
    ),
    # AWS keys
    SecretPattern(
        name="aws_access_key_id",
        pattern=re.compile(r"(AKIA[0-9A-Z]{16})"),
        severity="critical",
    ),
    SecretPattern(
        name="aws_secret_access_key",
        pattern=re.compile(
            r"(?:(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*)"
            r"([A-Za-z0-9/+=]{40})"
        ),
        severity="critical",
    ),
    # Database connection strings
    SecretPattern(
        name="db_connection_string",
        pattern=re.compile(
            r"((?:mysql|postgres|mongodb|redis)://[^\s\"']+)"
        ),
        severity="critical",
    ),
    SecretPattern(
        name="db_password",
        pattern=re.compile(
            r"(?:(?:DB_PASSWORD|DATABASE_PASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)"
            r"\s*[:=]\s*[\"']?)([^\s\"',;]+)"
        ),
        severity="critical",
    ),
    # Private key markers
    SecretPattern(
        name="private_key_block",
        pattern=re.compile(r"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)"),
        severity="critical",
    ),
    # Generic secret variable assignments
    SecretPattern(
        name="generic_secret",
        pattern=re.compile(
            r"(?:(?:SECRET|TOKEN|PASSWORD|PASS|KEY|CREDENTIAL|AUTH)"
            r"(?:_?(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))?)"
            r"\s*[:=]\s*[\"']([^\s\"']{8,})[\"']"
        ),
        severity="high",
    ),
    # JWT tokens
    SecretPattern(
        name="jwt_token",
        pattern=re.compile(r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"),
        severity="high",
    ),
    # GitHub tokens
    SecretPattern(
        name="github_token",
        pattern=re.compile(r"((?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9_]{36,})"),
        severity="critical",
    ),
    SecretPattern(
        name="github_pat",
        pattern=re.compile(r"(github_pat_[A-Za-z0-9_]{22,})"),
        severity="critical",
    ),
    # Heroku API keys
    SecretPattern(
        name="heroku_api_key",
        pattern=re.compile(r"((?:heroku_api_key|HEROKU_API_KEY)\s*[:=]\s*[\"']?([0-9a-f-]{36})[\"']?)"),
        severity="high",
    ),
    # Slack tokens
    SecretPattern(
        name="slack_token",
        pattern=re.compile(r"(xox[baprs]-[0-9a-zA-Z-]{10,})"),
        severity="high",
    ),
    # SendGrid / Mailgun API keys
    SecretPattern(
        name="sendgrid_api_key",
        pattern=re.compile(r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
        severity="high",
    ),
    SecretPattern(
        name="mailgun_api_key",
        pattern=re.compile(r"(key-[0-9a-zA-Z]{32})"),
        severity="high",
    ),
]


# ---------------------------------------------------------------------------
# Secret match result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretMatch:
    """A single secret discovered in a GitHub-hosted file.

    Attributes:
        pattern_name: The :attr:`SecretPattern.name` that matched.
        secret_value: The captured secret string.
        severity: The pattern's severity bucket.
        key_type: :class:`~webrecon.core.models.KeyType` if the pattern
            is a Stripe key; ``None`` otherwise.
        file_path: Repository-relative path of the file.
        file_name: Basename of the file.
        html_url: Web-UI URL of the file.
        repository_name: ``owner/repo`` string.
        line_number: Approximate 1-indexed line number within the file
            where the match starts, or ``0`` if the line could not be
            determined.
        context: A short snippet of text surrounding the match (up to
            200 characters before and after the match), useful for
            triage and manual verification.
    """

    pattern_name: str
    secret_value: str
    severity: str
    key_type: KeyType | None
    file_path: str
    file_name: str
    html_url: str
    repository_name: str
    line_number: int = 0
    context: str = ""


# ---------------------------------------------------------------------------
# Stripe helpers
# ---------------------------------------------------------------------------


def classify_stripe_key(value: str) -> KeyType:
    """Classify a Stripe key string into a :class:`KeyType`.

    The classification is prefix-based:

    * ``sk_live_`` / ``rk_live_`` → ``SK_LIVE``
    * ``pk_live_`` → ``PK_LIVE``
    * Everything else (test keys, restricted keys with unknown
      prefixes, ...) → ``OTHER``
    """
    if value.startswith("sk_live_") or value.startswith("rk_live_"):
        return KeyType.SK_LIVE
    if value.startswith("pk_live_"):
        return KeyType.PK_LIVE
    return KeyType.OTHER


def stripe_key_to_model(
    match: SecretMatch,
    *,
    website_id: str = "",
) -> StripeKey:
    """Convert a Stripe-key :class:`SecretMatch` into a :class:`StripeKey`.

    The caller must ensure that ``match.key_type`` is not ``None``
    (i.e. the match came from a Stripe-key pattern). If it *is*
    ``None``, the function falls back to :func:`classify_stripe_key`
    on the raw value.

    Args:
        match: A :class:`SecretMatch` whose ``secret_value`` is a
            Stripe key.
        website_id: Optional ``WebsiteAsset.id`` to associate the key
            with. Empty string when the key is not yet linked to a
            website record.

    Returns:
        A :class:`StripeKey` instance with ``is_valid`` initialised
        to ``False`` (actual validation happens in
        :mod:`webrecon.automation.stripe_tester`).
    """
    key_type = match.key_type or classify_stripe_key(match.secret_value)
    now = datetime.now(timezone.utc)

    metadata: dict[str, str] = {
        "pattern_name": match.pattern_name,
        "severity": match.severity,
    }
    if website_id:
        metadata["website_id"] = website_id

    return StripeKey(
        id=str(uuid.uuid4()),
        key_value=match.secret_value,
        key_type=key_type,
        discovered_at=now,
        source_url=match.html_url,
        source_file=match.file_path,
        is_valid=False,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class GithubAnalyzer:
    """Analyze GitHub code-search results for leaked secrets.

    The analyzer orchestrates the search-then-analyse workflow:

    1. Accept a :class:`~webrecon.github.client.GithubClient` and a
       list of :class:`SecretPattern` instances.
    2. For each search query or pre-fetched set of
       :class:`~webrecon.github.client.GithubCodeMatch` objects,
       download the file content and scan it against every pattern.
    3. Yield :class:`SecretMatch` objects for every hit.

    Usage::

        async with httpx.AsyncClient() as http:
            gh = GithubClient(http, token="ghp_...")
            analyzer = GithubAnalyzer(gh)
            async for secret in analyzer.analyze_query('"sk_live_" filename:.env'):
                print(secret.secret_value, secret.repository_name)
    """

    def __init__(
        self,
        client: GithubClient,
        *,
        patterns: Sequence[SecretPattern] | None = None,
        max_concurrent_downloads: int = 5,
    ) -> None:
        self._client = client
        self._patterns: list[SecretPattern] = (
            list(patterns) if patterns is not None else list(_DEFAULT_PATTERNS)
        )
        self._max_concurrent = max(1, max_concurrent_downloads)

    # ---- Public API ---------------------------------------------------

    async def analyze_query(
        self,
        query: str,
        *,
        max_pages: int = 10,
        per_page: int = 30,
    ) -> AsyncIterator[SecretMatch]:
        """Search GitHub for ``query`` and analyze every result for secrets.

        This is a convenience wrapper that combines
        :py:meth:`~GithubClient.search_code` with
        :py:meth:`analyze_matches`. It yields
        :class:`SecretMatch` objects as they are discovered.

        Args:
            query: GitHub code-search query string.
            max_pages: Maximum pages to walk.
            per_page: Results per page.

        Yields:
            One :class:`SecretMatch` per secret found.
        """
        matches: list[GithubCodeMatch] = []
        async for match in self._client.search_code(
            query, max_pages=max_pages, per_page=per_page
        ):
            matches.append(match)

        async for secret in self.analyze_matches(matches):
            yield secret

    async def analyze_matches(
        self,
        matches: Sequence[GithubCodeMatch],
    ) -> AsyncIterator[SecretMatch]:
        """Download and analyze a sequence of code-search matches.

        For each :class:`~webrecon.github.client.GithubCodeMatch`, the
        analyzer downloads the raw file content and scans it against
        every registered :class:`SecretPattern`. Downloads are bounded
        by the ``max_concurrent_downloads`` constructor parameter.

        Args:
            matches: Pre-fetched code-search results.

        Yields:
            One :class:`SecretMatch` per secret found.
        """
        import asyncio

        sem = asyncio.Semaphore(self._max_concurrent)

        async def _process_one(
            code_match: GithubCodeMatch,
        ) -> list[SecretMatch]:
            async with sem:
                return await self._analyze_single(code_match)

        tasks = [_process_one(m) for m in matches]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, BaseException):
                _LOGGER.warning(
                    "github.analyzer.match_error",
                    error=str(result),
                )
                continue
            for secret in result:
                yield secret

    async def analyze_content(
        self,
        content: str,
        *,
        file_path: str = "",
        file_name: str = "",
        html_url: str = "",
        repository_name: str = "",
    ) -> list[SecretMatch]:
        """Scan a string against all registered patterns.

        This is the lowest-level entry point: the caller provides the
        text content directly (e.g. from a cached download or a local
        file) and receives a list of :class:`SecretMatch` objects.

        Args:
            content: The text to scan.
            file_path: Repository-relative path (for metadata).
            file_name: Basename of the file (for metadata).
            html_url: Web-UI URL (for metadata).
            repository_name: ``owner/repo`` string (for metadata).

        Returns:
            A (possibly empty) list of :class:`SecretMatch` objects.
        """
        secrets: list[SecretMatch] = []
        seen: set[tuple[str, str]] = set()

        for pat in self._patterns:
            for m in pat.pattern.finditer(content):
                value = m.group(1)
                # Deduplicate: same pattern + same value in this file.
                dedup_key = (pat.name, value)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Approximate line number.
                line_no = content[: m.start()].count("\n") + 1

                # Context snippet.
                ctx_start = max(0, m.start() - 200)
                ctx_end = min(len(content), m.end() + 200)
                context = content[ctx_start:ctx_end].replace("\n", " ")

                secrets.append(
                    SecretMatch(
                        pattern_name=pat.name,
                        secret_value=value,
                        severity=pat.severity,
                        key_type=pat.key_type,
                        file_path=file_path,
                        file_name=file_name,
                        html_url=html_url,
                        repository_name=repository_name,
                        line_number=line_no,
                        context=context,
                    )
                )

        return secrets

    # ---- Internal -----------------------------------------------------

    async def _analyze_single(
        self,
        match: GithubCodeMatch,
    ) -> list[SecretMatch]:
        """Download one file and scan it for secrets."""
        repo = match.repository
        full_name = (
            repo.get("full_name", "") if isinstance(repo, dict) else ""
        )

        # Parse owner/repo from full_name for the contents endpoint.
        parts = full_name.split("/", 1) if full_name else []
        if len(parts) == 2:
            owner, repo_name = parts
        else:
            owner, repo_name = "", ""

        log = _LOGGER.bind(
            github_file=match.path,
            github_repo=full_name,
        )
        log.debug("github.analyzer.download_start")

        try:
            if owner and repo_name:
                content_bytes = await self._client.get_file_content(
                    owner, repo_name, match.path
                )
            else:
                # Fallback: download via raw URL.
                raw_url = match.download_url()
                content_bytes = await self._client.get_raw_file(raw_url)
        except Exception as exc:
            log.warning(
                "github.analyzer.download_failed",
                error=str(exc),
            )
            return []

        try:
            content_text = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            content_text = content_bytes.decode("latin-1", errors="replace")

        log.debug(
            "github.analyzer.scan_start",
            content_length=len(content_text),
        )

        secrets = await self.analyze_content(
            content_text,
            file_path=match.path,
            file_name=match.name,
            html_url=match.html_url,
            repository_name=full_name,
        )

        if secrets:
            log.info(
                "github.analyzer.secrets_found",
                count=len(secrets),
                patterns=[s.pattern_name for s in secrets],
            )

        return secrets
