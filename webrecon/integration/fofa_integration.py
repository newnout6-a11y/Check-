"""FOFA scraper integration -- refactored from ``fofa_scraper.py``.

This module replicates the functionality of the original
``fofa_scraper.py`` using the ``webrecon`` package:

1. Search FOFA for WooCommerce + Stripe sites.
2. Extract ``pk_live_`` keys from discovered sites.
3. Test server-side tokenization via Stripe API.
4. Save results to the database (replaces ``gateway_pool.json``).

Original script interface preserved for backward compatibility.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webrecon.core.models import (
    DiscoverySource,
    KeyType,
    WebsiteAsset,
)
from webrecon.log import get_logger

__all__ = ["run_fofa_scraper"]

_LOGGER = get_logger(__name__)

# Default FOFA query matching the original script.
_DEFAULT_FOFA_QUERY: str = 'app="WooCommerce" && header="Stripe"'


async def run_fofa_scraper(
    *,
    fofa_email: str = "",
    fofa_key: str = "",
    query: str = _DEFAULT_FOFA_QUERY,
    max_pages: int = 10,
    test_tokenization: bool = True,
    save_to_db: bool = True,
    db_path: str = "webrecon.sqlite3",
    gateway_pool_path: str = "gateway_pool.json",
    concurrency: int = 15,
) -> list[WebsiteAsset]:
    """Run the FOFA scraper pipeline.

    This is the refactored equivalent of ``fofa_scraper.py``'s
    ``main()`` function, using the ``webrecon`` package modules.

    Args:
        fofa_email: FOFA account email.
        fofa_key: FOFA API key.
        query: FOFA search query.
        max_pages: Maximum pages to fetch from FOFA.
        test_tokenization: Whether to test Stripe tokenization.
        save_to_db: Whether to persist results to the database.
        db_path: Path to the SQLite database file.
        gateway_pool_path: Path to ``gateway_pool.json`` for
            backward-compatible output.
        concurrency: HTTP concurrency limit.

    Returns:
        List of validated :class:`WebsiteAsset` instances.
    """
    import httpx

    from webrecon.discovery.fofa import FofaClient
    from webrecon.mass_parser.client import MassParserClient
    from webrecon.mass_parser.woocommerce import WooCommerceValidator

    if not fofa_email or not fofa_key:
        _LOGGER.error("fofa_integration.missing_credentials")
        return []

    assets: list[WebsiteAsset] = []

    async with httpx.AsyncClient() as http:
        # Step 1: FOFA search.
        fofa = FofaClient(http, email=fofa_email, key=fofa_key)
        discovered_urls: list[str] = []

        async for asset in fofa.search_to_assets(query, max_pages=max_pages):
            discovered_urls.append(asset.url)
            _LOGGER.info("fofa_integration.discovered", url=asset.url)

        _LOGGER.info("fofa_integration.search_complete", total=len(discovered_urls))

        # Step 2: Validate each discovered site.
        async with MassParserClient(concurrency=concurrency) as mass_http:
            validator = WooCommerceValidator(
                mass_http,
                test_tokenization=test_tokenization,
            )

            for url in discovered_urls:
                result = await validator.validate(
                    url,
                    discovery_source=DiscoverySource.FOFA,
                )
                if result.asset:
                    assets.append(result.asset)
                    _LOGGER.info(
                        "fofa_integration.validated",
                        url=url,
                        tokenization=result.tokenization_status,
                    )

    # Step 3: Save to database.
    if save_to_db and assets:
        from webrecon.database import WebsiteAssetRepository, open_database
        pool = await open_database(db_path)
        repo = WebsiteAssetRepository(pool)
        for asset in assets:
            try:
                await repo.upsert(asset)
            except Exception as exc:
                _LOGGER.warning("fofa_integration.db_error", error=str(exc))
        await pool.close()

    # Step 4: Write gateway_pool.json for backward compatibility.
    if gateway_pool_path:
        _write_gateway_pool(assets, gateway_pool_path)

    _LOGGER.info(
        "fofa_integration.complete",
        discovered=len(discovered_urls),
        validated=len(assets),
    )

    return assets


def _write_gateway_pool(assets: list[WebsiteAsset], path: str) -> None:
    """Write a ``gateway_pool.json`` file for backward compatibility.

    The format matches the original script's output:
    ``[{url, pk_key, tokenization, ...}, ...]``.
    """
    entries: list[dict[str, Any]] = []
    for asset in assets:
        pk_keys = [k for k in asset.stripe_keys if k.key_type == KeyType.PK_LIVE]
        entry: dict[str, Any] = {
            "url": asset.url,
            "pk_key": pk_keys[0].key_value if pk_keys else "",
            "tokenization": asset.tokenization_status or "",
            "stripe_version": asset.stripe_plugin_version or "",
            "country": asset.country or "",
            "currency": asset.currency or "",
            "woocommerce_version": asset.woocommerce_version or "",
            "discovered_at": asset.discovered_at.isoformat() if asset.discovered_at else "",
        }
        entries.append(entry)

    pool_path = Path(path)
    # Merge with existing pool if present.
    existing: list[dict[str, Any]] = []
    if pool_path.exists():
        try:
            existing = json.loads(pool_path.read_text(encoding="utf-8"))
        except Exception:
            existing = []

    # Deduplicate by URL.
    existing_urls = {e.get("url", "") for e in existing}
    for entry in entries:
        if entry["url"] not in existing_urls:
            existing.append(entry)
            existing_urls.add(entry["url"])

    pool_path.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
