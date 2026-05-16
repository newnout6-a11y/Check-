"""SQLite DDL definitions for the ``webrecon`` asset database.

This module is the single source of truth for the v1 database schema
described in the *Database Schema* section of ``design.md``. The DDL
strings below are adapted for SQLite, which has the following relevant
quirks compared to the design document's MySQL/PostgreSQL-flavoured
sketch:

* SQLite does not support inline ``INDEX`` clauses inside
  ``CREATE TABLE``. Indexes are emitted as separate
  ``CREATE INDEX`` statements (executed in the same migration).
* SQLite has no native ``BOOLEAN`` type; booleans are stored as
  ``INTEGER`` columns with ``0`` / ``1`` values.
* SQLite has no native ``TIMESTAMP`` type; datetimes are stored as
  ISO 8601 ``TEXT`` (matching ``datetime.isoformat()`` output).
* SQLite has no native ``JSON`` type; JSON payloads are stored as
  ``TEXT`` (the JSON1 extension still operates on text columns and
  every Python sqlite build ships with it enabled by default).

Foreign keys use ``ON DELETE CASCADE`` so deleting a website also
removes its dependent ``stripe_keys`` and ``form_discoveries`` rows,
and deleting a ``form_discoveries`` row removes its ``form_fields``.

The ``INITIAL_SCHEMA`` list contains every statement applied as
migration v1 — see :mod:`webrecon.database.migrations`.
"""

from __future__ import annotations

__all__ = [
    "AUDIT_LOG_TABLE",
    "FORM_DISCOVERIES_TABLE",
    "FORM_FIELDS_TABLE",
    "INITIAL_SCHEMA",
    "STRIPE_KEYS_TABLE",
    "SYSTEM_CONFIG_TABLE",
    "WEBSITES_TABLE",
]


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

WEBSITES_TABLE = """
CREATE TABLE IF NOT EXISTS websites (
    id                    TEXT    PRIMARY KEY,
    url                   TEXT    NOT NULL,
    normalized_url        TEXT    NOT NULL UNIQUE,
    discovered_at         TEXT    NOT NULL,
    last_checked          TEXT    NOT NULL,
    status                TEXT    NOT NULL,
    technology_stack      TEXT    NOT NULL DEFAULT '[]',
    discovery_source      TEXT    NOT NULL,
    metadata              TEXT    NOT NULL DEFAULT '{}',
    tokenization_status   TEXT,
    stripe_plugin_version TEXT,
    woocommerce_version   TEXT,
    store_api_available   INTEGER NOT NULL DEFAULT 0,
    country               TEXT,
    currency              TEXT,
    check_count           INTEGER NOT NULL DEFAULT 0,
    error_count           INTEGER NOT NULL DEFAULT 0,
    success_rate          REAL    NOT NULL DEFAULT 0.0
)
""".strip()

STRIPE_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS stripe_keys (
    id                TEXT    PRIMARY KEY,
    key_value         TEXT    NOT NULL UNIQUE,
    key_type          TEXT    NOT NULL,
    discovered_at     TEXT    NOT NULL,
    validated_at      TEXT,
    is_valid          INTEGER NOT NULL DEFAULT 0,
    source_url        TEXT    NOT NULL,
    source_file       TEXT,
    metadata          TEXT    NOT NULL DEFAULT '{}',
    balance_available TEXT,
    error_message     TEXT,
    validation_count  INTEGER NOT NULL DEFAULT 0,
    website_id        TEXT    REFERENCES websites(id) ON DELETE CASCADE
)
""".strip()

FORM_DISCOVERIES_TABLE = """
CREATE TABLE IF NOT EXISTS form_discoveries (
    id                TEXT    PRIMARY KEY,
    website_id        TEXT    NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    url               TEXT    NOT NULL,
    form_html         TEXT    NOT NULL DEFAULT '',
    discovered_at     TEXT    NOT NULL,
    last_tested       TEXT,
    has_csrf_token    INTEGER NOT NULL DEFAULT 0,
    requires_auth     INTEGER NOT NULL DEFAULT 0,
    submission_method TEXT    NOT NULL DEFAULT 'GET',
    action_url        TEXT    NOT NULL DEFAULT ''
)
""".strip()

FORM_FIELDS_TABLE = """
CREATE TABLE IF NOT EXISTS form_fields (
    id                 TEXT    PRIMARY KEY,
    form_id            TEXT    NOT NULL REFERENCES form_discoveries(id) ON DELETE CASCADE,
    name               TEXT    NOT NULL,
    field_type         TEXT    NOT NULL,
    required           INTEGER NOT NULL DEFAULT 0,
    default_value      TEXT,
    validation_pattern TEXT,
    metadata           TEXT    NOT NULL DEFAULT '{}',
    field_order        INTEGER NOT NULL DEFAULT 0
)
""".strip()

SYSTEM_CONFIG_TABLE = """
CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    description TEXT
)
""".strip()

AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT    PRIMARY KEY,
    timestamp     TEXT    NOT NULL,
    module        TEXT    NOT NULL,
    operation     TEXT    NOT NULL,
    details       TEXT,
    success       INTEGER NOT NULL DEFAULT 1,
    error_message TEXT
)
""".strip()


# ---------------------------------------------------------------------------
# Indexes (separate statements — SQLite has no inline INDEX clause)
# ---------------------------------------------------------------------------

_WEBSITE_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_websites_status ON websites(status)",
    "CREATE INDEX IF NOT EXISTS idx_websites_discovery_source ON websites(discovery_source)",
    "CREATE INDEX IF NOT EXISTS idx_websites_country ON websites(country)",
    "CREATE INDEX IF NOT EXISTS idx_websites_last_checked ON websites(last_checked)",
]

_STRIPE_KEY_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_stripe_keys_key_type ON stripe_keys(key_type)",
    "CREATE INDEX IF NOT EXISTS idx_stripe_keys_is_valid ON stripe_keys(is_valid)",
    "CREATE INDEX IF NOT EXISTS idx_stripe_keys_website_id ON stripe_keys(website_id)",
]

_FORM_DISCOVERY_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_form_discoveries_website_id ON form_discoveries(website_id)",
    (
        "CREATE INDEX IF NOT EXISTS idx_form_discoveries_discovered_at "
        "ON form_discoveries(discovered_at)"
    ),
]

_FORM_FIELD_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_form_fields_form_id ON form_fields(form_id)",
    "CREATE INDEX IF NOT EXISTS idx_form_fields_field_type ON form_fields(field_type)",
]


# ---------------------------------------------------------------------------
# Migration v1: full initial schema
# ---------------------------------------------------------------------------

INITIAL_SCHEMA: list[str] = [
    WEBSITES_TABLE,
    *_WEBSITE_INDEXES,
    STRIPE_KEYS_TABLE,
    *_STRIPE_KEY_INDEXES,
    FORM_DISCOVERIES_TABLE,
    *_FORM_DISCOVERY_INDEXES,
    FORM_FIELDS_TABLE,
    *_FORM_FIELD_INDEXES,
    SYSTEM_CONFIG_TABLE,
    AUDIT_LOG_TABLE,
]
