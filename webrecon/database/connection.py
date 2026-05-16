"""Async connection-pool management for the ``webrecon`` asset database.

SQLite is a single-writer, multi-reader engine: opening many
connections concurrently buys very little parallelism and risks
``database is locked`` errors. The :class:`ConnectionPool` exposed
below therefore caps the number of concurrent borrowers via an
``asyncio.Semaphore`` and keeps a small pool of pre-opened
``aiosqlite.Connection`` objects ready for reuse.

Usage::

    pool = await open_database("webrecon.sqlite3")
    async with pool.acquire() as conn:
        await conn.execute("INSERT INTO websites ...")
        await conn.commit()
    await pool.close()

On the first connection opened the pool also enables the foreign-key
enforcement pragma (off by default in SQLite) and switches the journal
to WAL mode for concurrent read performance.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import aiosqlite

from webrecon.database.migrations import apply_migrations

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


__all__ = ["ConnectionPool", "open_database"]


_DEFAULT_POOL_SIZE = 5


class ConnectionPool:
    """Bounded async pool over ``aiosqlite.Connection``.

    The pool serialises borrowers with an ``asyncio.Semaphore`` and
    keeps a list of pre-opened connections that are checked out and
    returned in LIFO order. ``close()`` is idempotent.
    """

    def __init__(self, path: Path | str, *, pool_size: int = _DEFAULT_POOL_SIZE) -> None:
        if pool_size < 1:
            raise ValueError(f"pool_size must be >= 1, got {pool_size}")
        self._path = Path(path)
        self._pool_size = pool_size
        self._semaphore = asyncio.Semaphore(pool_size)
        self._idle: list[aiosqlite.Connection] = []
        self._all: list[aiosqlite.Connection] = []
        self._lock = asyncio.Lock()
        self._closed = False
        self._initialised = False

    @property
    def path(self) -> Path:
        """Return the on-disk path the pool is bound to."""
        return self._path

    @property
    def pool_size(self) -> int:
        """Return the maximum number of concurrent connections."""
        return self._pool_size

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def _new_connection(self) -> aiosqlite.Connection:
        """Open a fresh ``aiosqlite.Connection`` with the project pragmas."""
        conn = await aiosqlite.connect(str(self._path))
        # Foreign key enforcement is off by default in SQLite.
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.commit()
        return conn

    async def _initialise(self) -> None:
        """Apply one-time database setup (WAL journal + migrations)."""
        if self._initialised:
            return
        self._initialised = True
        # Use a dedicated bootstrap connection so the WAL/migration
        # work doesn't consume a slot in the runtime pool.
        bootstrap = await self._new_connection()
        try:
            # WAL improves concurrent read performance and is safe to
            # set repeatedly.
            await bootstrap.execute("PRAGMA journal_mode = WAL")
            await bootstrap.commit()
            await apply_migrations(bootstrap)
        finally:
            await bootstrap.close()

    async def acquire_connection(self) -> aiosqlite.Connection:
        """Borrow a connection from the pool.

        Prefer :meth:`acquire` (an async context manager) in production
        code — this method exists for tests and callers that need to
        drive the lifecycle manually.
        """
        if self._closed:
            raise RuntimeError("ConnectionPool is closed")
        await self._semaphore.acquire()
        try:
            async with self._lock:
                if self._idle:
                    return self._idle.pop()
            conn = await self._new_connection()
            async with self._lock:
                self._all.append(conn)
            return conn
        except BaseException:
            self._semaphore.release()
            raise

    async def release_connection(self, conn: aiosqlite.Connection) -> None:
        """Return a previously-acquired connection to the pool."""
        try:
            if self._closed:
                await conn.close()
                return
            async with self._lock:
                self._idle.append(conn)
        finally:
            self._semaphore.release()

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[aiosqlite.Connection]:
        """Yield a connection bound to the lifetime of the ``with`` block."""
        conn = await self.acquire_connection()
        try:
            yield conn
        finally:
            await self.release_connection(conn)

    async def close(self) -> None:
        """Close every connection ever opened by the pool."""
        if self._closed:
            return
        self._closed = True
        async with self._lock:
            connections = list(self._all)
            self._all.clear()
            self._idle.clear()
        for conn in connections:
            try:
                await conn.close()
            except Exception:
                # Closing one connection should never block closing
                # the rest of the pool; swallow individual errors.
                continue


async def open_database(
    path: Path | str,
    *,
    pool_size: int = _DEFAULT_POOL_SIZE,
    run_migrations: bool = True,
) -> ConnectionPool:
    """Create a :class:`ConnectionPool` and optionally apply migrations.

    The pool's parent directory is created if it doesn't already
    exist (so callers can pass ``tmp_path / "webrecon.sqlite3"`` in
    tests without manual ``mkdir`` calls).
    """
    db_path = Path(path)
    if db_path.parent and not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)
    pool = ConnectionPool(db_path, pool_size=pool_size)
    if run_migrations:
        await pool._initialise()
    return pool
