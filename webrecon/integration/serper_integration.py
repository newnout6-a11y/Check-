"""Serper deep search integration -- refactored from ``serper_deep.py``.

This module replicates the functionality of the original
``serper_deep.py`` using the ``webrecon`` package:

1. Search Serper.dev for WooCommerce + Stripe sites.
2. Validate discovered sites via WooCommerce Store API.
3. Extract ``pk_live_`` keys and test tokenization.
4. Save results to the database (replaces ``gateway_pool.json``).

Original script interface preserved for backward compatibility.
"""

from __future__ import annotations

from webrecon.core.models import (
    DiscoverySource,
    WebsiteAsset,
)
from webrecon.log import get_logger

__all__ = ["run_serper_deep"]

_LOGGER = get_logger(__name__)

# Default Google dork matching the original script.
_DEFAULT_DORK: str = 'inurl:checkout "pk_live_" woocommerce -site:stripe.com'


async def run_serper_deep(
    *,
    serper_key: str = "",
    query: str = _DEFAULT_DORK,
    max_pages: int = 5,
    test_tokenization: bool = True,
    save_to_db: bool = True,
    db_path: str = "webrecon.sqlite3",
    gateway_pool_path: str = "gateway_pool.json",
    concurrency: int = 15,
) -> list[WebsiteAsset]:
    """Run the Serper deep search pipeline.

    This is the refactored equivalent of ``serper_deep.py``'s
    ``main()`` function.

    Args:
        serper_key: Serper.dev API key.
        query: Google dork query.
        max_pages: Maximum pages to fetch from Serper.
        test_tokenization: Whether to test Stripe tokenization.
        save_to_db: Whether to persist results to the database.
        db_path: Path to the SQLite database file.
        gateway_pool_path: Path to ``gateway_pool.json``.
        concurrency: HTTP concurrency limit.

    Returns:
        List of validated :class:`WebsiteAsset` instances.
    """
    import httpx

    from webrecon.discovery.serper import SerperClient
    from webrecon.mass_parser.client import MassParserClient
    from webrecon.mass_parser.woocommerce import WooCommerceValidator

    if not serper_key:
        _LOGGER.error("serper_integration.missing_key")
        return []

    assets: list[WebsiteAsset] = []

    async with httpx.AsyncClient() as http:
        # Step 1: Serper search.
        serper = SerperClient(http, api_key=serper_key)
        discovered_urls: list[str] = []

        async for serper_asset in serper.search_to_assets(query, max_pages=max_pages):
            discovered_urls.append(serper_asset.url)
            _LOGGER.info("serper_integration.discovered", url=serper_asset.url)

        _LOGGER.info("serper_integration.search_complete", total=len(discovered_urls))

        # Step 2: Validate each discovered site.
        async with MassParserClient(concurrency=concurrency) as mass_http:
            validator = WooCommerceValidator(
                mass_http,
                test_tokenization=test_tokenization,
            )

            for url in discovered_urls:
                woo_result = await validator.validate(
                    url,
                    discovery_source=DiscoverySource.SERPER,
                )
                if woo_result.asset:
                    assets.append(woo_result.asset)
                    _LOGGER.info(
                        "serper_integration.validated",
                        url=url,
                        tokenization=woo_result.tokenization_status,
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
                _LOGGER.warning("serper_integration.db_error", error=str(exc))
        await pool.close()

    # Step 4: Write gateway_pool.json.
    if gateway_pool_path:
        from webrecon.integration.fofa_integration import _write_gateway_pool
        _write_gateway_pool(assets, gateway_pool_path)

    _LOGGER.info(
        "serper_integration.complete",
        discovered=len(discovered_urls),
        validated=len(assets),
    )

    return assets
