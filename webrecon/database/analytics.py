"""Analytics and statistics for the ``webrecon`` asset database.

This module computes aggregate statistics, success rates, time-trend
analysis, and source-effectiveness metrics. It is consumed by the CLI
``db stats`` subcommand and the reporting layer.

Usage::

    pool = await open_database("webrecon.sqlite3")
    analytics = DatabaseAnalytics(pool)
    stats = await analytics.overview()
    print(stats["total_assets"], stats["active_assets"])

Validates: Requirement 7.7 (success rate calculations),
Requirement 7.8 (time-trend analysis),
Requirement 7.9 (source effectiveness metrics).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.database.connection import ConnectionPool

__all__ = [
    "DatabaseAnalytics",
    "OverviewStats",
    "SourceEffectiveness",
    "TimeTrend",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class OverviewStats:
    """High-level overview of the asset database.

    Attributes:
        total_assets: Total number of website assets.
        active_assets: Assets with status ``active``.
        total_stripe_keys: Total Stripe keys across all assets.
        valid_stripe_keys: Stripe keys confirmed valid.
        pk_live_keys: Number of ``pk_live_`` keys.
        sk_live_keys: Number of ``sk_live_`` keys.
        tokenization_ok: Assets where tokenization works.
        tokenization_blocked: Assets where tokenization is blocked.
        total_forms: Total form discoveries.
        assets_with_ssl: Assets with valid SSL.
        assets_without_ssl: Assets without valid SSL.
        unique_countries: Number of distinct countries.
        unique_technologies: Number of distinct technologies.
    """

    total_assets: int = 0
    active_assets: int = 0
    total_stripe_keys: int = 0
    valid_stripe_keys: int = 0
    pk_live_keys: int = 0
    sk_live_keys: int = 0
    tokenization_ok: int = 0
    tokenization_blocked: int = 0
    total_forms: int = 0
    assets_with_ssl: int = 0
    assets_without_ssl: int = 0
    unique_countries: int = 0
    unique_technologies: int = 0


@dataclass
class SourceEffectiveness:
    """Effectiveness metrics for a single discovery source.

    Attributes:
        source: The discovery source name.
        total_assets: Assets found by this source.
        active_assets: Assets still active.
        tokenization_ok_rate: Fraction of assets with working
            tokenization (0.0 - 1.0).
        valid_key_rate: Fraction of assets with at least one valid
            Stripe key (0.0 - 1.0).
    """

    source: str = ""
    total_assets: int = 0
    active_assets: int = 0
    tokenization_ok_rate: float = 0.0
    valid_key_rate: float = 0.0


@dataclass
class TimeTrend:
    """Asset count trend over time.

    Attributes:
        period: The aggregation period (e.g. ``"day"``, ``"week"``,
            ``"month"``).
        data_points: Ordered list of ``(period_start, count)`` tuples.
    """

    period: str = "day"
    data_points: list[tuple[str, int]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


class DatabaseAnalytics:
    """Compute analytics and statistics from the asset database.

    Args:
        pool: A :class:`~webrecon.database.connection.ConnectionPool`.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    # ---- Overview -----------------------------------------------------

    async def overview(self) -> OverviewStats:
        """Compute a high-level overview of the database."""
        stats = OverviewStats()

        async with self._pool.acquire() as conn:
            # Total assets.
            cursor = await conn.execute("SELECT COUNT(*) FROM websites")
            row = await cursor.fetchone()
            await cursor.close()
            stats.total_assets = int(row[0]) if row else 0

            # Active assets.
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM websites WHERE status = 'active'"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.active_assets = int(row[0]) if row else 0

            # Stripe key counts.
            cursor = await conn.execute("SELECT COUNT(*) FROM stripe_keys")
            row = await cursor.fetchone()
            await cursor.close()
            stats.total_stripe_keys = int(row[0]) if row else 0

            cursor = await conn.execute(
                "SELECT COUNT(*) FROM stripe_keys WHERE is_valid = 1"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.valid_stripe_keys = int(row[0]) if row else 0

            cursor = await conn.execute(
                "SELECT COUNT(*) FROM stripe_keys WHERE key_type = 'pk_live'"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.pk_live_keys = int(row[0]) if row else 0

            cursor = await conn.execute(
                "SELECT COUNT(*) FROM stripe_keys WHERE key_type = 'sk_live'"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.sk_live_keys = int(row[0]) if row else 0

            # Tokenization counts.
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM websites WHERE tokenization_status = 'ok'"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.tokenization_ok = int(row[0]) if row else 0

            cursor = await conn.execute(
                "SELECT COUNT(*) FROM websites WHERE tokenization_status = 'blocked'"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.tokenization_blocked = int(row[0]) if row else 0

            # Form count.
            cursor = await conn.execute("SELECT COUNT(*) FROM form_discoveries")
            row = await cursor.fetchone()
            await cursor.close()
            stats.total_forms = int(row[0]) if row else 0

            # SSL.
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM websites WHERE has_ssl = 1"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.assets_with_ssl = int(row[0]) if row else 0
            stats.assets_without_ssl = stats.total_assets - stats.assets_with_ssl

            # Unique countries.
            cursor = await conn.execute(
                "SELECT COUNT(DISTINCT country) FROM websites WHERE country IS NOT NULL"
            )
            row = await cursor.fetchone()
            await cursor.close()
            stats.unique_countries = int(row[0]) if row else 0

            # Unique technologies (approximate from JSON).
            cursor = await conn.execute(
                "SELECT technology_stack FROM websites WHERE technology_stack IS NOT NULL"
            )
            rows = await cursor.fetchall()
            await cursor.close()
            all_techs: set[str] = set()
            for r in rows:
                try:
                    import json
                    techs = json.loads(r[0]) if isinstance(r[0], str) else r[0]
                    if isinstance(techs, list):
                        all_techs.update(str(t) for t in techs)
                except Exception:
                    continue
            stats.unique_technologies = len(all_techs)

        return stats

    # ---- Source effectiveness -----------------------------------------

    async def source_effectiveness(self) -> list[SourceEffectiveness]:
        """Compute effectiveness metrics per discovery source."""
        results: list[SourceEffectiveness] = []

        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                "SELECT discovery_source, COUNT(*), "
                "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN tokenization_status = 'ok' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN id IN ("
                "  SELECT website_id FROM stripe_keys WHERE is_valid = 1"
                ") THEN 1 ELSE 0 END) "
                "FROM websites GROUP BY discovery_source"
            )
            rows = await cursor.fetchall()
            await cursor.close()

        for row in rows:
            source = str(row[0]) if row[0] else "unknown"
            total = int(row[1])
            active = int(row[2])
            tok_ok = int(row[3])
            valid_key = int(row[4])

            results.append(SourceEffectiveness(
                source=source,
                total_assets=total,
                active_assets=active,
                tokenization_ok_rate=tok_ok / total if total else 0.0,
                valid_key_rate=valid_key / total if total else 0.0,
            ))

        return results

    # ---- Time trends --------------------------------------------------

    async def time_trend(
        self,
        *,
        period: str = "day",
        days: int = 30,
    ) -> TimeTrend:
        """Compute asset discovery trend over time.

        Args:
            period: Aggregation period (``"day"``, ``"week"``,
                ``"month"``).
            days: Number of recent days to include.

        Returns:
            A :class:`TimeTrend` with ordered data points.
        """
        if period == "week":
            date_expr = "strftime('%Y-W%W', discovered_at)"
        elif period == "month":
            date_expr = "strftime('%Y-%m', discovered_at)"
        else:
            date_expr = "strftime('%Y-%m-%d', discovered_at)"

        cutoff = datetime.now(timezone.utc)
        # Compute cutoff date string.
        from datetime import timedelta
        cutoff_date = (cutoff - timedelta(days=days)).strftime("%Y-%m-%d")

        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                f"SELECT {date_expr}, COUNT(*) "
                f"FROM websites "
                f"WHERE discovered_at >= ? "
                f"GROUP BY {date_expr} "
                f"ORDER BY {date_expr}",
                (cutoff_date,),
            )
            rows = await cursor.fetchall()
            await cursor.close()

        data_points = [(str(r[0]), int(r[1])) for r in rows if r[0]]

        return TimeTrend(period=period, data_points=data_points)

    # ---- Performance benchmark ----------------------------------------

    async def performance_summary(self) -> dict[str, Any]:
        """Compute a performance summary of the discovery pipeline.

        Returns a dict with average response times, success rates,
        and throughput estimates.
        """
        async with self._pool.acquire() as conn:
            # Average response time (from metadata if available).
            cursor = await conn.execute(
                "SELECT COUNT(*), "
                "SUM(CASE WHEN tokenization_status = 'ok' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN has_ssl = 1 THEN 1 ELSE 0 END) "
                "FROM websites"
            )
            row = await cursor.fetchone()
            await cursor.close()

            total = int(row[0]) if row else 0
            tok_ok = int(row[1]) if row else 0
            ssl_ok = int(row[2]) if row else 0

        return {
            "total_assets": total,
            "tokenization_success_rate": tok_ok / total if total else 0.0,
            "ssl_rate": ssl_ok / total if total else 0.0,
            "discovery_rate_per_day": await self._discovery_rate(),
        }

    async def _discovery_rate(self) -> float:
        """Compute the average assets discovered per day."""
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                "SELECT MIN(discovered_at), MAX(discovered_at), COUNT(*) "
                "FROM websites"
            )
            row = await cursor.fetchone()
            await cursor.close()

        if not row or not row[0] or not row[1] or not row[2]:
            return 0.0

        try:
            from datetime import datetime as dt
            first = dt.fromisoformat(str(row[0]))
            last = dt.fromisoformat(str(row[1]))
            days = max(1, (last - first).days)
            return int(row[2]) / days
        except Exception:
            return 0.0
