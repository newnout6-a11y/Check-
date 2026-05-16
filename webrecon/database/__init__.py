"""Persistence layer for the ``webrecon`` package.

This sub-package exposes the public database surface used by the rest
of the system:

* :mod:`webrecon.database.schema` -- DDL for all tables and indexes.
* :mod:`webrecon.database.migrations` -- versioned schema migrations.
* :mod:`webrecon.database.connection` -- async connection pool.
* :mod:`webrecon.database.repository` -- typed CRUD repositories.
* :mod:`webrecon.database.query` -- advanced query builder with
  filtering, sorting, and aggregation.
* :mod:`webrecon.database.export` -- multi-format data export
  (CSV, JSON, SQL dump).
* :mod:`webrecon.database.analytics` -- statistics, source
  effectiveness, and time-trend analysis.

The public surface of each sub-module is re-exported here so callers
can write ``from webrecon.database import open_database`` instead of
following the longer module path.
"""

from __future__ import annotations

from webrecon.database.analytics import (
    DatabaseAnalytics,
    OverviewStats,
    SourceEffectiveness,
    TimeTrend,
)
from webrecon.database.connection import ConnectionPool, open_database
from webrecon.database.export import DataExporter
from webrecon.database.migrations import (
    MIGRATIONS,
    SCHEMA_VERSION_TABLE,
    apply_migrations,
    get_current_version,
)
from webrecon.database.query import AssetQuery, QueryFilter, QueryResult
from webrecon.database.repository import (
    FormDiscoveryRepository,
    StripeKeyRepository,
    WebsiteAssetRepository,
)
from webrecon.database.schema import INITIAL_SCHEMA

__all__ = [
    "INITIAL_SCHEMA",
    "MIGRATIONS",
    "SCHEMA_VERSION_TABLE",
    "AssetQuery",
    "ConnectionPool",
    "DataExporter",
    "DatabaseAnalytics",
    "FormDiscoveryRepository",
    "OverviewStats",
    "QueryFilter",
    "QueryResult",
    "SourceEffectiveness",
    "StripeKeyRepository",
    "TimeTrend",
    "WebsiteAssetRepository",
    "apply_migrations",
    "get_current_version",
    "open_database",
]
