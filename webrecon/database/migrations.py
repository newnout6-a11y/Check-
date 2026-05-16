"""Versioned schema migrations for the ``webrecon`` asset database.

The migrations layer is intentionally small: one ``schema_version``
table, one ordered list of migrations, and one ``apply_migrations``
coroutine that wraps each pending migration in a transaction.

The contract is:

* :data:`MIGRATIONS` is an ordered list of
  ``(version, description, statements)`` tuples. Versions start at 1
  and increase by 1.
* :func:`apply_migrations` reads the current version from
  ``schema_version`` and applies every migration with a strictly
  greater version, in order, each in its own transaction.
* Recording the migration in ``schema_version`` happens inside the
  same transaction as the DDL, so a crash mid-migration leaves the
  database in the previous (consistent) state.

This module is independent from :mod:`webrecon.database.connection`
so callers can drive it with any ``aiosqlite.Connection`` (for example
in unit tests that open a connection directly).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from webrecon.database.schema import INITIAL_SCHEMA

if TYPE_CHECKING:
    import aiosqlite


__all__ = [
    "MIGRATIONS",
    "SCHEMA_VERSION_TABLE",
    "apply_migrations",
    "get_current_version",
]


# ``schema_version`` is created on demand by ``apply_migrations`` so
# the very first call against a fresh database can boot-strap itself.
SCHEMA_VERSION_TABLE: str = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL,
    description TEXT NOT NULL
)
""".strip()


# Ordered migration list. Add new entries at the end; never rewrite
# history. Each tuple is ``(version, description, statements)``.
MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (1, "Initial schema (websites, stripe_keys, forms, config, audit)", INITIAL_SCHEMA),
]


async def get_current_version(conn: aiosqlite.Connection) -> int:
    """Return the highest applied schema version, or ``0`` if none.

    Creates the ``schema_version`` table if it doesn't yet exist so the
    very first call against a brand-new database returns ``0`` rather
    than raising.
    """
    await conn.execute(SCHEMA_VERSION_TABLE)
    cursor = await conn.execute("SELECT MAX(version) FROM schema_version")
    try:
        row = await cursor.fetchone()
    finally:
        await cursor.close()
    if row is None or row[0] is None:
        return 0
    return int(row[0])


async def apply_migrations(conn: aiosqlite.Connection) -> None:
    """Apply every pending migration to ``conn``.

    Each migration runs inside its own transaction (``BEGIN`` /
    ``COMMIT`` / ``ROLLBACK``) so a failure in migration *N* leaves
    the database at version *N - 1*.
    """
    from datetime import datetime, timezone

    current = await get_current_version(conn)
    for version, description, statements in MIGRATIONS:
        if version <= current:
            continue
        try:
            await conn.execute("BEGIN")
            for stmt in statements:
                await conn.execute(stmt)
            await conn.execute(
                "INSERT INTO schema_version (version, applied_at, description) "
                "VALUES (?, ?, ?)",
                (version, datetime.now(timezone.utc).isoformat(), description),
            )
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise
