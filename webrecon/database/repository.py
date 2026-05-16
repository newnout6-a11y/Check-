"""Async CRUD repositories for the ``webrecon`` asset database.

Each repository wraps a :class:`~webrecon.database.connection.ConnectionPool`
and exposes a small, typed surface for the model it owns:

* :class:`WebsiteAssetRepository` -- :class:`~webrecon.core.models.WebsiteAsset`
  (with cascading writes for the asset's :class:`~webrecon.core.models.StripeKey`
  children).
* :class:`StripeKeyRepository` -- standalone reads/writes for
  :class:`~webrecon.core.models.StripeKey`.
* :class:`FormDiscoveryRepository` --
  :class:`~webrecon.core.models.FormDiscovery` (with cascading writes for
  the form's :class:`~webrecon.core.models.FormField` children).

Design notes
------------

* All queries are parameterised — no string interpolation of user data.
* Booleans go to/from SQLite as ``0`` / ``1``.
* Datetimes go to/from SQLite as ISO 8601 strings via the model
  ``to_dict`` / ``from_dict`` helpers (which ultimately use
  ``datetime.isoformat`` / ``datetime.fromisoformat``).
* JSON-shaped fields (``technology_stack``, ``metadata``,
  ``balance_available``) are encoded with :mod:`json` on write and
  decoded on read.
* Advanced filtering is *out of scope* for task 2.2 -- it lands later
  in task 11.1 (``database/query.py``). The :py:meth:`list_all`
  helpers here only support ``limit`` / ``offset`` pagination.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from webrecon.core.models import (
    AssetStatus,
    DiscoverySource,
    FormDiscovery,
    FormField,
    KeyType,
    StripeKey,
    WebsiteAsset,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    import aiosqlite

    from webrecon.database.connection import ConnectionPool


__all__ = [
    "FormDiscoveryRepository",
    "StripeKeyRepository",
    "WebsiteAssetRepository",
]


# ---------------------------------------------------------------------------
# Internal serialisation helpers
# ---------------------------------------------------------------------------


def _bool_to_int(value: bool) -> int:
    return 1 if value else 0


def _int_to_bool(value: Any) -> bool:
    return bool(value)


def _dump_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _load_json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    return json.loads(value)


def _iso_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


# ---------------------------------------------------------------------------
# Row → model decoding
# ---------------------------------------------------------------------------


def _row_to_website(row: Sequence[Any]) -> WebsiteAsset:
    """Decode a ``websites`` row (without nested stripe keys)."""
    (
        id_,
        url,
        normalized_url,
        discovered_at,
        last_checked,
        status,
        technology_stack,
        discovery_source,
        metadata,
        tokenization_status,
        stripe_plugin_version,
        woocommerce_version,
        store_api_available,
        country,
        currency,
        check_count,
        error_count,
        success_rate,
    ) = row
    return WebsiteAsset(
        id=str(id_),
        url=str(url),
        normalized_url=str(normalized_url),
        discovered_at=datetime.fromisoformat(str(discovered_at)),
        last_checked=datetime.fromisoformat(str(last_checked)),
        status=AssetStatus(str(status)),
        technology_stack=list(_load_json(technology_stack, [])),
        discovery_source=DiscoverySource(str(discovery_source)),
        metadata=dict(_load_json(metadata, {})),
        stripe_keys=[],
        tokenization_status=(
            None if tokenization_status is None else str(tokenization_status)
        ),
        stripe_plugin_version=(
            None if stripe_plugin_version is None else str(stripe_plugin_version)
        ),
        woocommerce_version=(
            None if woocommerce_version is None else str(woocommerce_version)
        ),
        store_api_available=_int_to_bool(store_api_available),
        country=(None if country is None else str(country)),
        currency=(None if currency is None else str(currency)),
        check_count=int(check_count),
        error_count=int(error_count),
        success_rate=float(success_rate),
    )


def _row_to_stripe_key(row: Sequence[Any]) -> StripeKey:
    (
        id_,
        key_value,
        key_type,
        discovered_at,
        validated_at,
        is_valid,
        source_url,
        source_file,
        metadata,
        balance_available,
        error_message,
        validation_count,
        _website_id,
    ) = row
    return StripeKey(
        id=str(id_),
        key_value=str(key_value),
        key_type=KeyType(str(key_type)),
        discovered_at=datetime.fromisoformat(str(discovered_at)),
        validated_at=(
            None if validated_at is None else datetime.fromisoformat(str(validated_at))
        ),
        is_valid=_int_to_bool(is_valid),
        source_url=str(source_url),
        source_file=(None if source_file is None else str(source_file)),
        metadata=dict(_load_json(metadata, {})),
        balance_available=_load_json(balance_available, None),
        error_message=(None if error_message is None else str(error_message)),
        validation_count=int(validation_count),
    )


def _row_to_form_discovery(row: Sequence[Any]) -> FormDiscovery:
    (
        id_,
        website_id,
        url,
        form_html,
        discovered_at,
        last_tested,
        has_csrf_token,
        requires_auth,
        submission_method,
        action_url,
    ) = row
    return FormDiscovery(
        id=str(id_),
        website_id=str(website_id),
        url=str(url),
        form_html=str(form_html),
        fields=[],
        discovered_at=datetime.fromisoformat(str(discovered_at)),
        last_tested=(
            None if last_tested is None else datetime.fromisoformat(str(last_tested))
        ),
        has_csrf_token=_int_to_bool(has_csrf_token),
        requires_auth=_int_to_bool(requires_auth),
        submission_method=str(submission_method),
        action_url=str(action_url),
    )


def _row_to_form_field(row: Sequence[Any]) -> FormField:
    (
        _id,
        _form_id,
        name,
        field_type,
        required,
        default_value,
        validation_pattern,
        metadata,
        _field_order,
    ) = row
    return FormField(
        name=str(name),
        field_type=str(field_type),
        required=_int_to_bool(required),
        default_value=(None if default_value is None else str(default_value)),
        validation_pattern=(
            None if validation_pattern is None else str(validation_pattern)
        ),
        metadata=dict(_load_json(metadata, {})),
    )


# ---------------------------------------------------------------------------
# WebsiteAssetRepository
# ---------------------------------------------------------------------------


_WEBSITE_COLUMNS = (
    "id, url, normalized_url, discovered_at, last_checked, status, "
    "technology_stack, discovery_source, metadata, tokenization_status, "
    "stripe_plugin_version, woocommerce_version, store_api_available, "
    "country, currency, check_count, error_count, success_rate"
)

_STRIPE_KEY_COLUMNS = (
    "id, key_value, key_type, discovered_at, validated_at, is_valid, "
    "source_url, source_file, metadata, balance_available, error_message, "
    "validation_count, website_id"
)

_FORM_DISCOVERY_COLUMNS = (
    "id, website_id, url, form_html, discovered_at, last_tested, "
    "has_csrf_token, requires_auth, submission_method, action_url"
)

_FORM_FIELD_COLUMNS = (
    "id, form_id, name, field_type, required, default_value, "
    "validation_pattern, metadata, field_order"
)


class WebsiteAssetRepository:
    """CRUD operations for :class:`WebsiteAsset` and its nested keys."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    # ---- Encoding helpers ----------------------------------------------

    @staticmethod
    def _website_params(asset: WebsiteAsset) -> tuple[Any, ...]:
        return (
            asset.id,
            asset.url,
            asset.normalized_url,
            asset.discovered_at.isoformat(),
            asset.last_checked.isoformat(),
            asset.status.value,
            _dump_json(list(asset.technology_stack)),
            asset.discovery_source.value,
            _dump_json(dict(asset.metadata)),
            asset.tokenization_status,
            asset.stripe_plugin_version,
            asset.woocommerce_version,
            _bool_to_int(asset.store_api_available),
            asset.country,
            asset.currency,
            asset.check_count,
            asset.error_count,
            asset.success_rate,
        )

    @staticmethod
    def _stripe_key_params(key: StripeKey, website_id: str | None) -> tuple[Any, ...]:
        balance = (
            None
            if key.balance_available is None
            else _dump_json(key.balance_available)
        )
        return (
            key.id,
            key.key_value,
            key.key_type.value,
            key.discovered_at.isoformat(),
            _iso_or_none(key.validated_at),
            _bool_to_int(key.is_valid),
            key.source_url,
            key.source_file,
            _dump_json(dict(key.metadata)),
            balance,
            key.error_message,
            key.validation_count,
            website_id,
        )

    # ---- Internal nested-collection helpers ----------------------------

    @staticmethod
    async def _insert_stripe_keys(
        conn: aiosqlite.Connection,
        website_id: str,
        keys: list[StripeKey],
    ) -> None:
        if not keys:
            return
        placeholders = ", ".join(["?"] * 13)
        sql = (
            f"INSERT INTO stripe_keys ({_STRIPE_KEY_COLUMNS}) "
            f"VALUES ({placeholders})"
        )
        for key in keys:
            await conn.execute(
                sql,
                WebsiteAssetRepository._stripe_key_params(key, website_id),
            )

    @staticmethod
    async def _replace_stripe_keys(
        conn: aiosqlite.Connection,
        website_id: str,
        keys: list[StripeKey],
    ) -> None:
        await conn.execute(
            "DELETE FROM stripe_keys WHERE website_id = ?", (website_id,)
        )
        await WebsiteAssetRepository._insert_stripe_keys(conn, website_id, keys)

    @staticmethod
    async def _load_stripe_keys(
        conn: aiosqlite.Connection, website_id: str
    ) -> list[StripeKey]:
        cursor = await conn.execute(
            f"SELECT {_STRIPE_KEY_COLUMNS} FROM stripe_keys WHERE website_id = ? "
            "ORDER BY discovered_at, id",
            (website_id,),
        )
        try:
            rows = await cursor.fetchall()
        finally:
            await cursor.close()
        return [_row_to_stripe_key(row) for row in rows]

    # ---- Public API ----------------------------------------------------

    async def add(self, asset: WebsiteAsset) -> WebsiteAsset:
        """Insert ``asset`` (and its nested stripe keys) as a new row."""
        placeholders = ", ".join(["?"] * 18)
        sql = f"INSERT INTO websites ({_WEBSITE_COLUMNS}) VALUES ({placeholders})"
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                await conn.execute(sql, self._website_params(asset))
                await self._insert_stripe_keys(conn, asset.id, list(asset.stripe_keys))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return asset

    async def get(self, asset_id: str) -> WebsiteAsset | None:
        """Return the asset with ``asset_id`` (with nested keys), or ``None``."""
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                f"SELECT {_WEBSITE_COLUMNS} FROM websites WHERE id = ?",
                (asset_id,),
            )
            try:
                row = await cursor.fetchone()
            finally:
                await cursor.close()
            if row is None:
                return None
            asset = _row_to_website(row)
            asset.stripe_keys = await self._load_stripe_keys(conn, asset.id)
            return asset

    async def update(self, asset: WebsiteAsset) -> bool:
        """Update every column for ``asset.id`` and replace nested keys.

        Returns ``True`` when a matching row was found, ``False``
        otherwise (no-op).
        """
        sql = (
            "UPDATE websites SET "
            "url = ?, normalized_url = ?, discovered_at = ?, last_checked = ?, "
            "status = ?, technology_stack = ?, discovery_source = ?, metadata = ?, "
            "tokenization_status = ?, stripe_plugin_version = ?, "
            "woocommerce_version = ?, store_api_available = ?, country = ?, "
            "currency = ?, check_count = ?, error_count = ?, success_rate = ? "
            "WHERE id = ?"
        )
        params = self._website_params(asset)
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                cursor = await conn.execute(sql, (*params[1:], asset.id))
                changed = cursor.rowcount
                await cursor.close()
                if changed == 0:
                    await conn.rollback()
                    return False
                await self._replace_stripe_keys(conn, asset.id, list(asset.stripe_keys))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return True

    async def upsert(self, asset: WebsiteAsset) -> WebsiteAsset:
        """Insert ``asset`` if missing, otherwise update it.

        Uses SQLite's ``INSERT ... ON CONFLICT`` so the operation is
        atomic at the SQL level.
        """
        placeholders = ", ".join(["?"] * 18)
        update_cols = (
            "url = excluded.url, normalized_url = excluded.normalized_url, "
            "discovered_at = excluded.discovered_at, "
            "last_checked = excluded.last_checked, status = excluded.status, "
            "technology_stack = excluded.technology_stack, "
            "discovery_source = excluded.discovery_source, "
            "metadata = excluded.metadata, "
            "tokenization_status = excluded.tokenization_status, "
            "stripe_plugin_version = excluded.stripe_plugin_version, "
            "woocommerce_version = excluded.woocommerce_version, "
            "store_api_available = excluded.store_api_available, "
            "country = excluded.country, currency = excluded.currency, "
            "check_count = excluded.check_count, "
            "error_count = excluded.error_count, "
            "success_rate = excluded.success_rate"
        )
        sql = (
            f"INSERT INTO websites ({_WEBSITE_COLUMNS}) VALUES ({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {update_cols}"
        )
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                await conn.execute(sql, self._website_params(asset))
                await self._replace_stripe_keys(conn, asset.id, list(asset.stripe_keys))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return asset

    async def delete(self, asset_id: str) -> bool:
        """Delete the asset (cascades to nested keys). Returns whether a row matched."""
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                cursor = await conn.execute(
                    "DELETE FROM websites WHERE id = ?", (asset_id,)
                )
                changed = cursor.rowcount
                await cursor.close()
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return changed > 0

    async def list_all(
        self, *, limit: int | None = None, offset: int = 0
    ) -> list[WebsiteAsset]:
        """Return assets ordered by discovery time. Basic pagination only."""
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        sql = (
            f"SELECT {_WEBSITE_COLUMNS} FROM websites "
            "ORDER BY discovered_at, id"
        )
        params: list[Any] = []
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        elif offset > 0:
            sql += " LIMIT -1 OFFSET ?"
            params.append(offset)
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(sql, tuple(params))
            try:
                rows = await cursor.fetchall()
            finally:
                await cursor.close()
            assets = [_row_to_website(row) for row in rows]
            for asset in assets:
                asset.stripe_keys = await self._load_stripe_keys(conn, asset.id)
        return assets


# ---------------------------------------------------------------------------
# StripeKeyRepository
# ---------------------------------------------------------------------------


class StripeKeyRepository:
    """Standalone CRUD for :class:`StripeKey` rows.

    Use this when you need to operate on keys without going through a
    :class:`WebsiteAsset` (for example: scrubbing invalid keys or
    listing every key irrespective of its parent website).
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    async def add(self, key: StripeKey, *, website_id: str | None = None) -> StripeKey:
        placeholders = ", ".join(["?"] * 13)
        sql = (
            f"INSERT INTO stripe_keys ({_STRIPE_KEY_COLUMNS}) VALUES ({placeholders})"
        )
        params = WebsiteAssetRepository._stripe_key_params(key, website_id)
        async with self._pool.acquire() as conn:
            await conn.execute(sql, params)
            await conn.commit()
        return key

    async def get(self, key_id: str) -> StripeKey | None:
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                f"SELECT {_STRIPE_KEY_COLUMNS} FROM stripe_keys WHERE id = ?",
                (key_id,),
            )
            try:
                row = await cursor.fetchone()
            finally:
                await cursor.close()
        if row is None:
            return None
        return _row_to_stripe_key(row)

    async def update(self, key: StripeKey, *, website_id: str | None = None) -> bool:
        sql = (
            "UPDATE stripe_keys SET "
            "key_value = ?, key_type = ?, discovered_at = ?, validated_at = ?, "
            "is_valid = ?, source_url = ?, source_file = ?, metadata = ?, "
            "balance_available = ?, error_message = ?, validation_count = ?, "
            "website_id = ? "
            "WHERE id = ?"
        )
        params = WebsiteAssetRepository._stripe_key_params(key, website_id)
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(sql, (*params[1:], key.id))
            changed = cursor.rowcount
            await cursor.close()
            await conn.commit()
        return changed > 0

    async def upsert(
        self, key: StripeKey, *, website_id: str | None = None
    ) -> StripeKey:
        placeholders = ", ".join(["?"] * 13)
        update_cols = (
            "key_value = excluded.key_value, key_type = excluded.key_type, "
            "discovered_at = excluded.discovered_at, "
            "validated_at = excluded.validated_at, is_valid = excluded.is_valid, "
            "source_url = excluded.source_url, source_file = excluded.source_file, "
            "metadata = excluded.metadata, "
            "balance_available = excluded.balance_available, "
            "error_message = excluded.error_message, "
            "validation_count = excluded.validation_count, "
            "website_id = excluded.website_id"
        )
        sql = (
            f"INSERT INTO stripe_keys ({_STRIPE_KEY_COLUMNS}) VALUES ({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {update_cols}"
        )
        params = WebsiteAssetRepository._stripe_key_params(key, website_id)
        async with self._pool.acquire() as conn:
            await conn.execute(sql, params)
            await conn.commit()
        return key

    async def delete(self, key_id: str) -> bool:
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                "DELETE FROM stripe_keys WHERE id = ?", (key_id,)
            )
            changed = cursor.rowcount
            await cursor.close()
            await conn.commit()
        return changed > 0

    async def list_all(
        self, *, limit: int | None = None, offset: int = 0
    ) -> list[StripeKey]:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        sql = (
            f"SELECT {_STRIPE_KEY_COLUMNS} FROM stripe_keys "
            "ORDER BY discovered_at, id"
        )
        params: list[Any] = []
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        elif offset > 0:
            sql += " LIMIT -1 OFFSET ?"
            params.append(offset)
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(sql, tuple(params))
            try:
                rows = await cursor.fetchall()
            finally:
                await cursor.close()
        return [_row_to_stripe_key(row) for row in rows]


# ---------------------------------------------------------------------------
# FormDiscoveryRepository
# ---------------------------------------------------------------------------


class FormDiscoveryRepository:
    """CRUD operations for :class:`FormDiscovery` and its fields."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    @staticmethod
    def _form_params(form: FormDiscovery) -> tuple[Any, ...]:
        return (
            form.id,
            form.website_id,
            form.url,
            form.form_html,
            form.discovered_at.isoformat(),
            _iso_or_none(form.last_tested),
            _bool_to_int(form.has_csrf_token),
            _bool_to_int(form.requires_auth),
            form.submission_method,
            form.action_url,
        )

    @staticmethod
    def _field_params(
        form_id: str, index: int, field_obj: FormField
    ) -> tuple[Any, ...]:
        return (
            f"{form_id}:{index}",
            form_id,
            field_obj.name,
            field_obj.field_type,
            _bool_to_int(field_obj.required),
            field_obj.default_value,
            field_obj.validation_pattern,
            _dump_json(dict(field_obj.metadata)),
            index,
        )

    @staticmethod
    async def _insert_fields(
        conn: aiosqlite.Connection, form_id: str, fields: list[FormField]
    ) -> None:
        if not fields:
            return
        placeholders = ", ".join(["?"] * 9)
        sql = (
            f"INSERT INTO form_fields ({_FORM_FIELD_COLUMNS}) VALUES ({placeholders})"
        )
        for index, field_obj in enumerate(fields):
            await conn.execute(
                sql, FormDiscoveryRepository._field_params(form_id, index, field_obj)
            )

    @staticmethod
    async def _replace_fields(
        conn: aiosqlite.Connection, form_id: str, fields: list[FormField]
    ) -> None:
        await conn.execute(
            "DELETE FROM form_fields WHERE form_id = ?", (form_id,)
        )
        await FormDiscoveryRepository._insert_fields(conn, form_id, fields)

    @staticmethod
    async def _load_fields(
        conn: aiosqlite.Connection, form_id: str
    ) -> list[FormField]:
        cursor = await conn.execute(
            f"SELECT {_FORM_FIELD_COLUMNS} FROM form_fields WHERE form_id = ? "
            "ORDER BY field_order, id",
            (form_id,),
        )
        try:
            rows = await cursor.fetchall()
        finally:
            await cursor.close()
        return [_row_to_form_field(row) for row in rows]

    async def add(self, form: FormDiscovery) -> FormDiscovery:
        placeholders = ", ".join(["?"] * 10)
        sql = (
            f"INSERT INTO form_discoveries ({_FORM_DISCOVERY_COLUMNS}) "
            f"VALUES ({placeholders})"
        )
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                await conn.execute(sql, self._form_params(form))
                await self._insert_fields(conn, form.id, list(form.fields))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return form

    async def get(self, form_id: str) -> FormDiscovery | None:
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(
                f"SELECT {_FORM_DISCOVERY_COLUMNS} FROM form_discoveries WHERE id = ?",
                (form_id,),
            )
            try:
                row = await cursor.fetchone()
            finally:
                await cursor.close()
            if row is None:
                return None
            form = _row_to_form_discovery(row)
            form.fields = await self._load_fields(conn, form.id)
            return form

    async def update(self, form: FormDiscovery) -> bool:
        sql = (
            "UPDATE form_discoveries SET "
            "website_id = ?, url = ?, form_html = ?, discovered_at = ?, "
            "last_tested = ?, has_csrf_token = ?, requires_auth = ?, "
            "submission_method = ?, action_url = ? "
            "WHERE id = ?"
        )
        params = self._form_params(form)
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                cursor = await conn.execute(sql, (*params[1:], form.id))
                changed = cursor.rowcount
                await cursor.close()
                if changed == 0:
                    await conn.rollback()
                    return False
                await self._replace_fields(conn, form.id, list(form.fields))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return True

    async def upsert(self, form: FormDiscovery) -> FormDiscovery:
        placeholders = ", ".join(["?"] * 10)
        update_cols = (
            "website_id = excluded.website_id, url = excluded.url, "
            "form_html = excluded.form_html, "
            "discovered_at = excluded.discovered_at, "
            "last_tested = excluded.last_tested, "
            "has_csrf_token = excluded.has_csrf_token, "
            "requires_auth = excluded.requires_auth, "
            "submission_method = excluded.submission_method, "
            "action_url = excluded.action_url"
        )
        sql = (
            f"INSERT INTO form_discoveries ({_FORM_DISCOVERY_COLUMNS}) "
            f"VALUES ({placeholders}) ON CONFLICT(id) DO UPDATE SET {update_cols}"
        )
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                await conn.execute(sql, self._form_params(form))
                await self._replace_fields(conn, form.id, list(form.fields))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return form

    async def delete(self, form_id: str) -> bool:
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("BEGIN")
                cursor = await conn.execute(
                    "DELETE FROM form_discoveries WHERE id = ?", (form_id,)
                )
                changed = cursor.rowcount
                await cursor.close()
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return changed > 0

    async def list_all(
        self,
        *,
        website_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[FormDiscovery]:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        sql = f"SELECT {_FORM_DISCOVERY_COLUMNS} FROM form_discoveries"
        params: list[Any] = []
        if website_id is not None:
            sql += " WHERE website_id = ?"
            params.append(website_id)
        sql += " ORDER BY discovered_at, id"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        elif offset > 0:
            sql += " LIMIT -1 OFFSET ?"
            params.append(offset)
        async with self._pool.acquire() as conn:
            cursor = await conn.execute(sql, tuple(params))
            try:
                rows = await cursor.fetchall()
            finally:
                await cursor.close()
            forms = [_row_to_form_discovery(row) for row in rows]
            for form in forms:
                form.fields = await self._load_fields(conn, form.id)
        return forms
