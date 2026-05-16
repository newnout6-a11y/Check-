"""``webrecon db`` subcommand implementation."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_db"]

_LOGGER = get_logger(__name__)


async def run_db(args: argparse.Namespace) -> int:
    """Execute the db subcommand."""
    from webrecon.config import load_config
    from webrecon.database import open_database

    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("db.config_error", error=str(exc))
        return 2

    pool = await open_database(config.database.path)
    action = args.action

    try:
        if action == "stats":
            from webrecon.database.analytics import DatabaseAnalytics
            analytics = DatabaseAnalytics(pool)

            overview = await analytics.overview()
            print("=== Database Overview ===")
            print(f"  Total assets:       {overview.total_assets}")
            print(f"  Active assets:      {overview.active_assets}")
            print(f"  Total Stripe keys:  {overview.total_stripe_keys}")
            print(f"  Valid Stripe keys:  {overview.valid_stripe_keys}")
            print(f"  pk_live keys:       {overview.pk_live_keys}")
            print(f"  sk_live keys:       {overview.sk_live_keys}")
            print(f"  Tokenization OK:    {overview.tokenization_ok}")
            print(f"  Tokenization blocked: {overview.tokenization_blocked}")
            print(f"  Total forms:        {overview.total_forms}")
            print(f"  Assets with SSL:    {overview.assets_with_ssl}")
            print(f"  Unique countries:   {overview.unique_countries}")
            print(f"  Unique technologies: {overview.unique_technologies}")

            # Source effectiveness.
            print("\n=== Source Effectiveness ===")
            sources = await analytics.source_effectiveness()
            for s in sources:
                print(f"  {s.source}: total={s.total_assets} "
                      f"active={s.active_assets} "
                      f"tok_ok={s.tokenization_ok_rate:.1%} "
                      f"valid_key={s.valid_key_rate:.1%}")

        elif action == "query":
            from webrecon.core.models import AssetStatus, DiscoverySource
            from webrecon.database.query import AssetQuery

            query = AssetQuery(pool).limit(args.limit).sort_by(args.sort)

            # Parse filters.
            if args.filter:
                for pair in args.filter.split(","):
                    if "=" not in pair:
                        continue
                    key, value = pair.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if key == "status":
                        with contextlib.suppress(ValueError):
                            query.filter(status=AssetStatus(value))
                    elif key == "source":
                        with contextlib.suppress(ValueError):
                            query.filter(discovery_source=DiscoverySource(value))
                    elif key == "country":
                        query.filter(country=value)
                    elif key == "url":
                        query.filter(url_pattern=f"%{value}%")

            result = await query.execute()
            print(f"Found {result.total_count} assets (showing {len(result.items)}):")
            for asset in result.items:
                print(f"  {asset.url} [{asset.status.value}] "
                      f"source={asset.discovery_source.value} "
                      f"country={asset.country or '-'} "
                      f"keys={len(asset.stripe_keys)}")

        elif action == "migrate":
            from webrecon.database.migrations import apply_migrations
            async with pool.acquire() as conn:
                await apply_migrations(conn)
            print("Migrations applied successfully.")

        elif action == "backup":
            import shutil
            from datetime import datetime, timezone
            from pathlib import Path

            db_path = pool.path
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = Path(f"{db_path}.backup_{timestamp}")

            shutil.copy2(str(db_path), str(backup_path))
            print(f"Backup created: {backup_path}")

    except Exception as exc:
        _LOGGER.error("db.error", error=str(exc))
        await pool.close()
        return 1

    await pool.close()
    return 0
