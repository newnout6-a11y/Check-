"""``webrecon discover`` subcommand implementation."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_discover"]

_LOGGER = get_logger(__name__)


async def run_discover(args: argparse.Namespace) -> int:
    """Execute the discover subcommand."""
    from webrecon.config import load_config
    from webrecon.database import open_database
    from webrecon.mass_parser.client import MassParserClient

    # Load config.
    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("discover.config_error", error=str(exc))
        return 2

    sources = args.source
    query = args.query
    max_pages = args.max_pages
    save = args.save
    output_fmt = getattr(args, "output", "table")

    if not query and sources != "all":
        print("Error: --query is required when using a specific source", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    concurrency = args.concurrency or config.concurrency.semaphore_size

    async with MassParserClient(concurrency=concurrency) as http:
        # FOFA discovery.
        if sources in ("fofa", "all") and config.api_keys.fofa:
            from webrecon.discovery import FofaClient
            fofa = FofaClient(
                http.http_client,
                email=config.api_keys.fofa.email,
                key=config.api_keys.fofa.key,
            )
            fofa_query = query or 'app="WooCommerce" && header="Stripe"'
            async for asset in fofa.search_to_assets(fofa_query, max_pages=max_pages):
                results.append(asset.to_dict())
                _LOGGER.info("discover.fofa.found", url=asset.url)

        # Shodan discovery.
        if sources in ("shodan", "all") and config.api_keys.shodan:
            from webrecon.discovery import ShodanClient
            shodan = ShodanClient(http.http_client, api_key=config.api_keys.shodan)
            shodan_query = query or "product:woocommerce stripe"
            async for asset in shodan.search_to_assets(shodan_query, max_pages=max_pages):
                results.append(asset.to_dict())
                _LOGGER.info("discover.shodan.found", url=asset.url)

        # Serper discovery.
        if sources in ("serper", "all") and config.api_keys.serper:
            from webrecon.discovery import SerperClient
            serper = SerperClient(http.http_client, api_key=config.api_keys.serper)
            serper_query = query or 'inurl:checkout "pk_live_" woocommerce'
            async for asset in serper.search_to_assets(serper_query, max_pages=max_pages):
                results.append(asset.to_dict())
                _LOGGER.info("discover.serper.found", url=asset.url)

    # Save to database if requested.
    if save and results:
        pool = await open_database(config.database.path)
        from webrecon.database import WebsiteAssetRepository
        repo = WebsiteAssetRepository(pool)
        for r in results:
            try:
                from webrecon.core.models import WebsiteAsset
                asset = WebsiteAsset.from_dict(r)
                await repo.upsert(asset)
            except Exception as exc:
                _LOGGER.warning("discover.save_error", error=str(exc))
        await pool.close()

    # Output results.
    _output_results(results, output_fmt)

    if not results:
        _LOGGER.info("discover.no_results")
        return 5

    return 0


def _output_results(results: list[dict[str, Any]], fmt: str) -> None:
    """Format and print results."""
    from webrecon.cli.formatting import format_records

    print(format_records(results, fmt=fmt))
    if fmt in ("table", "csv") and results:
        print(f"\nTotal: {len(results)}")
