"""Data export for the ``webrecon`` asset database.

This module provides multi-format export of asset data from the
database, supporting CSV, JSON, and SQL dump formats. It is consumed
by the CLI ``export`` subcommand.

Usage::

    pool = await open_database("webrecon.sqlite3")
    exporter = DataExporter(pool)
    await exporter.export_csv("assets.csv", status=AssetStatus.ACTIVE)
    await exporter.export_json("assets.json")
    await exporter.export_sql_dump("backup.sql")

Validates: Requirement 7.4 (CSV export with column selection),
Requirement 7.5 (JSON export with nested structures),
Requirement 7.6 (SQL dump for migration).
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from webrecon.database.query import AssetQuery
from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.core.models import AssetStatus, DiscoverySource, WebsiteAsset
    from webrecon.database.connection import ConnectionPool

__all__ = [
    "DataExporter",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Default CSV columns
# ---------------------------------------------------------------------------

_DEFAULT_CSV_COLUMNS: list[str] = [
    "id",
    "url",
    "status",
    "discovery_source",
    "discovered_at",
    "last_checked",
    "country",
    "currency",
    "tokenization_status",
    "stripe_plugin_version",
    "woocommerce_version",
    "store_api_available",
    "has_ssl",
    "technology_stack",
]


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class DataExporter:
    """Export asset data from the database in multiple formats.

    Args:
        pool: A :class:`~webrecon.database.connection.ConnectionPool`.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    # ---- CSV export ---------------------------------------------------

    async def export_csv(
        self,
        path: str | Path,
        *,
        columns: list[str] | None = None,
        status: AssetStatus | None = None,
        discovery_source: DiscoverySource | None = None,
    ) -> int:
        """Export assets to a CSV file.

        Args:
            path: Output file path.
            columns: Column names to include. Defaults to
                :data:`_DEFAULT_CSV_COLUMNS`.
            status: Optional status filter.
            discovery_source: Optional source filter.

        Returns:
            Number of rows exported.
        """
        cols = columns or _DEFAULT_CSV_COLUMNS
        query = AssetQuery(self._pool).limit(10000)

        if status is not None:
            query.filter(status=status)
        if discovery_source is not None:
            query.filter(discovery_source=discovery_source)

        result = await query.execute()
        assets = result.items

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()

        for asset in assets:
            row = self._asset_to_flat_dict(asset)
            # Filter to selected columns.
            filtered = {k: row.get(k, "") for k in cols}
            writer.writerow(filtered)

        Path(path).write_text(buf.getvalue(), encoding="utf-8")

        _LOGGER.info(
            "database.export.csv",
            path=str(path),
            rows=len(assets),
        )

        return len(assets)

    # ---- JSON export --------------------------------------------------

    async def export_json(
        self,
        path: str | Path,
        *,
        include_stripe_keys: bool = True,
        include_forms: bool = False,
        status: AssetStatus | None = None,
    ) -> int:
        """Export assets to a JSON file with nested structures.

        Args:
            path: Output file path.
            include_stripe_keys: Include Stripe key details.
            include_forms: Include form discovery details.
            status: Optional status filter.

        Returns:
            Number of assets exported.
        """
        query = AssetQuery(self._pool).limit(10000)
        if status is not None:
            query.filter(status=status)

        result = await query.execute()
        assets = result.items

        output: list[dict[str, Any]] = []
        for asset in assets:
            entry = asset.to_dict()
            if not include_stripe_keys:
                entry.pop("stripe_keys", None)
            if not include_forms:
                entry.pop("form_discoveries", None)
            output.append(entry)

        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_assets": len(output),
            "assets": output,
        }

        Path(path).write_text(
            json.dumps(data, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )

        _LOGGER.info(
            "database.export.json",
            path=str(path),
            assets=len(output),
        )

        return len(output)

    # ---- SQL dump -----------------------------------------------------

    async def export_sql_dump(
        self,
        path: str | Path,
    ) -> int:
        """Export the entire database as a SQL dump.

        Uses SQLite's ``.dump``-style output: schema DDL followed by
        INSERT statements for every row.

        Args:
            path: Output file path.

        Returns:
            Total number of rows dumped across all tables.
        """
        tables = [
            "websites",
            "stripe_keys",
            "form_discoveries",
            "form_fields",
            "system_config",
            "audit_log",
            "schema_version",
        ]

        lines: list[str] = []
        total_rows = 0

        async with self._pool.acquire() as conn:
            for table in tables:
                # Check if table exists.
                cursor = await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                )
                row = await cursor.fetchone()
                await cursor.close()

                if not row:
                    continue

                # Get CREATE TABLE statement.
                cursor = await conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                )
                ddl_row = await cursor.fetchone()
                await cursor.close()

                if ddl_row and ddl_row[0]:
                    lines.append(f"{ddl_row[0]};")
                    lines.append("")

                # Get all rows.
                cursor = await conn.execute(f"SELECT * FROM {table}")
                rows = await cursor.fetchall()
                await cursor.close()

                # Get column names.
                col_cursor = await conn.execute(f"PRAGMA table_info({table})")
                col_info = await col_cursor.fetchall()
                await col_cursor.close()
                col_names = [str(c[1]) for c in col_info]

                for data_row in rows:
                    values = []
                    for val in data_row:
                        if val is None:
                            values.append("NULL")
                        elif isinstance(val, (int, float)):
                            values.append(str(val))
                        else:
                            escaped = str(val).replace("'", "''")
                            values.append(f"'{escaped}'")

                    cols_str = ", ".join(col_names)
                    vals_str = ", ".join(values)
                    lines.append(
                        f"INSERT INTO {table} ({cols_str}) VALUES ({vals_str});"
                    )
                    total_rows += 1

                lines.append("")

        Path(path).write_text("\n".join(lines), encoding="utf-8")

        _LOGGER.info(
            "database.export.sql_dump",
            path=str(path),
            total_rows=total_rows,
        )

        return total_rows

    # ---- Internal -----------------------------------------------------

    @staticmethod
    def _asset_to_flat_dict(asset: WebsiteAsset) -> dict[str, str]:
        """Flatten a WebsiteAsset into a string-valued dict for CSV."""
        d: dict[str, str] = {}
        d["id"] = asset.id
        d["url"] = asset.url
        d["normalized_url"] = asset.normalized_url
        d["status"] = asset.status.value
        d["discovery_source"] = asset.discovery_source.value
        d["discovered_at"] = asset.discovered_at.isoformat() if asset.discovered_at else ""
        d["last_checked"] = asset.last_checked.isoformat() if asset.last_checked else ""
        d["country"] = asset.country or ""
        d["currency"] = asset.currency or ""
        d["tokenization_status"] = asset.tokenization_status or ""
        d["stripe_plugin_version"] = asset.stripe_plugin_version or ""
        d["woocommerce_version"] = asset.woocommerce_version or ""
        d["store_api_available"] = str(asset.store_api_available)
        d["has_ssl"] = asset.metadata.get("has_ssl", "")
        d["technology_stack"] = json.dumps(asset.technology_stack, ensure_ascii=False)
        d["stripe_key_count"] = str(len(asset.stripe_keys))
        d["pk_live_count"] = str(sum(1 for k in asset.stripe_keys if k.key_type.value == "pk_live"))
        d["sk_live_count"] = str(sum(1 for k in asset.stripe_keys if k.key_type.value == "sk_live"))
        return d
