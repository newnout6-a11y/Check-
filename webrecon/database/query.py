"""Advanced query builder for the ``webrecon`` asset database.

This module extends the basic ``list_all`` pagination from
:mod:`webrecon.database.repository` with rich filtering, full-text
search, aggregation, and sorting. It is consumed by the CLI and the
export/analytics layers.

Usage::

    pool = await open_database("webrecon.sqlite3")
    query = AssetQuery(pool)
    results = await query.filter(
        status=AssetStatus.ACTIVE,
        discovery_source=DiscoverySource.FOFA,
        has_stripe=True,
    ).sort_by("discovered_at", descending=True).limit(50).execute()

Validates: Requirement 7.1 (advanced filtering by status, source,
date range, tech stack), Requirement 7.2 (full-text search on
metadata), Requirement 7.3 (aggregation queries).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from webrecon.database.repository import (
    WebsiteAssetRepository,
)
from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.core.models import (
        AssetStatus,
        DiscoverySource,
        WebsiteAsset,
    )
    from webrecon.database.connection import ConnectionPool

__all__ = [
    "AssetQuery",
    "QueryFilter",
    "QueryResult",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Query filter specification
# ---------------------------------------------------------------------------


@dataclass
class QueryFilter:
    """Filter criteria for asset queries.

    All fields are optional; ``None`` means "no filter on this field".

    Attributes:
        status: Filter by asset status.
        discovery_source: Filter by discovery source.
        has_stripe: Only include assets with at least one Stripe key.
        has_valid_stripe: Only include assets with at least one
            *valid* Stripe key.
        tokenization_status: Filter by tokenization status string.
        stripe_plugin_version: Filter by Stripe plugin version.
        country: Filter by country code.
        tech_contains: Technology stack must contain this string.
        discovered_after: Only assets discovered after this ISO
            datetime string.
        discovered_before: Only assets discovered before this ISO
            datetime string.
        url_pattern: SQL LIKE pattern for URL matching.
        search_text: Free-text search across URL, metadata, and
            technology stack.
    """

    status: AssetStatus | None = None
    discovery_source: DiscoverySource | None = None
    has_stripe: bool | None = None
    has_valid_stripe: bool | None = None
    tokenization_status: str | None = None
    stripe_plugin_version: str | None = None
    country: str | None = None
    tech_contains: str | None = None
    discovered_after: str | None = None
    discovered_before: str | None = None
    url_pattern: str | None = None
    search_text: str | None = None


# ---------------------------------------------------------------------------
# Query result
# ---------------------------------------------------------------------------


@dataclass
class QueryResult:
    """Paginated result set from an asset query.

    Attributes:
        items: The matching assets on the current page.
        total_count: Total number of matching assets (ignoring
            limit/offset).
        offset: The offset used for this page.
        limit: The limit used for this page.
    """

    items: list[WebsiteAsset] = field(default_factory=list)
    total_count: int = 0
    offset: int = 0
    limit: int = 100


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------


class AssetQuery:
    """Fluent query builder for the asset database.

    The builder pattern lets callers chain filter/sort/limit calls
    and materialise the result with :py:meth:`execute`.

    Args:
        pool: A :class:`~webrecon.database.connection.ConnectionPool`.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool
        self._filter = QueryFilter()
        self._sort_column: str = "discovered_at"
        self._sort_desc: bool = True
        self._limit: int = 100
        self._offset: int = 0

    # ---- Fluent API ---------------------------------------------------

    def filter(self, **kwargs: Any) -> AssetQuery:
        """Apply filter criteria (see :class:`QueryFilter` fields)."""
        for key, value in kwargs.items():
            if hasattr(self._filter, key) and value is not None:
                setattr(self._filter, key, value)
        return self

    def sort_by(
        self,
        column: str,
        *,
        descending: bool = True,
    ) -> AssetQuery:
        """Set the sort column and direction.

        Allowed columns: ``discovered_at``, ``last_checked``,
        ``url``, ``status``, ``country``.
        """
        allowed = {"discovered_at", "last_checked", "url", "status", "country"}
        if column not in allowed:
            raise ValueError(f"Invalid sort column: {column!r}. Allowed: {allowed}")
        self._sort_column = column
        self._sort_desc = descending
        return self

    def limit(self, n: int) -> AssetQuery:
        """Set the page size."""
        self._limit = max(1, n)
        return self

    def offset(self, n: int) -> AssetQuery:
        """Set the page offset."""
        self._offset = max(0, n)
        return self

    # ---- Execution ----------------------------------------------------

    async def execute(self) -> QueryResult:
        """Execute the query and return a paginated result.

        The query builds a dynamic WHERE clause from the filter
        criteria and runs a COUNT + SELECT pair.
        """
        conditions: list[str] = []
        params: list[Any] = []

        f = self._filter

        if f.status is not None:
            conditions.append("status = ?")
            params.append(f.status.value)

        if f.discovery_source is not None:
            conditions.append("discovery_source = ?")
            params.append(f.discovery_source.value)

        if f.discovered_after is not None:
            conditions.append("discovered_at >= ?")
            params.append(f.discovered_after)

        if f.discovered_before is not None:
            conditions.append("discovered_at <= ?")
            params.append(f.discovered_before)

        if f.url_pattern is not None:
            conditions.append("url LIKE ?")
            params.append(f.url_pattern)

        if f.country is not None:
            conditions.append("country = ?")
            params.append(f.country)

        if f.tokenization_status is not None:
            conditions.append("tokenization_status = ?")
            params.append(f.tokenization_status)

        if f.stripe_plugin_version is not None:
            conditions.append("stripe_plugin_version = ?")
            params.append(f.stripe_plugin_version)

        if f.tech_contains is not None:
            conditions.append("technology_stack LIKE ?")
            params.append('%"' + f.tech_contains + '"%')

        if f.search_text is not None:
            conditions.append(
                "(url LIKE ? OR technology_stack LIKE ? OR metadata LIKE ?)"
            )
            like_val = f"%{f.search_text}%"
            params.extend([like_val, like_val, like_val])

        # Stripe key filters require a subquery.
        if f.has_stripe is True:
            conditions.append(
                "id IN (SELECT website_id FROM stripe_keys WHERE website_id IS NOT NULL)"
            )
        if f.has_valid_stripe is True:
            conditions.append(
                "id IN (SELECT website_id FROM stripe_keys WHERE is_valid = 1)"
            )

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Sort direction.
        sort_dir = "DESC" if self._sort_desc else "ASC"

        # Count query.
        count_sql = f"SELECT COUNT(*) FROM websites WHERE {where_clause}"
        # Data query.
        data_sql = (
            f"SELECT * FROM websites WHERE {where_clause} "
            f"ORDER BY {self._sort_column} {sort_dir} "
            f"LIMIT ? OFFSET ?"
        )

        repo = WebsiteAssetRepository(self._pool)

        async with self._pool.acquire() as conn:
            # Count.
            cursor = await conn.execute(count_sql, params)
            row = await cursor.fetchone()
            await cursor.close()
            total_count = int(row[0]) if row else 0

            # Data.
            data_params = [*params, self._limit, self._offset]
            cursor = await conn.execute(data_sql, data_params)
            rows = await cursor.fetchall()
            await cursor.close()

        # Decode rows into WebsiteAsset objects.
        items: list[WebsiteAsset] = []
        for row in rows:
            try:
                asset = await repo.get(row[0])
                if asset is not None:
                    items.append(asset)
            except Exception:
                continue

        _LOGGER.info(
            "database.query.executed",
            conditions=len(conditions),
            total=total_count,
            returned=len(items),
        )

        return QueryResult(
            items=items,
            total_count=total_count,
            offset=self._offset,
            limit=self._limit,
        )

    # ---- Aggregation helpers ------------------------------------------

    async def count_by_status(self) -> dict[str, int]:
        """Count assets grouped by status."""
        return await self._aggregate("status")

    async def count_by_source(self) -> dict[str, int]:
        """Count assets grouped by discovery source."""
        return await self._aggregate("discovery_source")

    async def count_by_country(self) -> dict[str, int]:
        """Count assets grouped by country."""
        return await self._aggregate("country")

    async def count_by_tokenization(self) -> dict[str, int]:
        """Count assets grouped by tokenization status."""
        return await self._aggregate("tokenization_status")

    async def _aggregate(self, column: str) -> dict[str, int]:
        """Generic GROUP BY aggregation on a column."""
        sql = f"SELECT {column}, COUNT(*) FROM websites GROUP BY {column}"
        result: dict[str, int] = {}

        async with self._pool.acquire() as conn:
            cursor = await conn.execute(sql)
            rows = await cursor.fetchall()
            await cursor.close()

        for row in rows:
            key = str(row[0]) if row[0] else "unknown"
            result[key] = int(row[1])

        return result
