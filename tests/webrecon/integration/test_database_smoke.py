"""Integration smoke test for the ``webrecon.database`` layer.

Opens a real SQLite database under ``tmp_path``, applies the schema
migrations, inserts a :class:`WebsiteAsset` (with a nested
:class:`StripeKey` and a sibling :class:`FormDiscovery`), and asserts
that reads round-trip back to objects equal to the originals.

This guards Requirements 6.1, 6.2, and 6.3 — schema, deduplication,
and persistence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webrecon.core.models import (
    AssetStatus,
    DiscoverySource,
    FormDiscovery,
    FormField,
    KeyType,
    StripeKey,
    WebsiteAsset,
)
from webrecon.database import (
    FormDiscoveryRepository,
    StripeKeyRepository,
    WebsiteAssetRepository,
    apply_migrations,
    get_current_version,
    open_database,
)


def _now_minus(seconds: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


@pytest.fixture
def sample_website() -> WebsiteAsset:
    discovered = _now_minus(60)
    return WebsiteAsset(
        id="site-1",
        url="https://shop.example.com",
        normalized_url="https://shop.example.com/",
        discovered_at=discovered,
        last_checked=_now_minus(30),
        status=AssetStatus.ACTIVE,
        discovery_source=DiscoverySource.FOFA,
        technology_stack=["WordPress", "WooCommerce"],
        metadata={"campaign": "demo", "operator": "kiro"},
        stripe_keys=[
            StripeKey(
                id="key-1",
                key_value="pk_live_abcdef1234567890",
                key_type=KeyType.PK_LIVE,
                discovered_at=discovered,
                source_url="https://shop.example.com/checkout",
                source_file=None,
                metadata={"surface": "checkout"},
            ),
            StripeKey(
                id="key-2",
                key_value="sk_live_zyxwvut0987654321",
                key_type=KeyType.SK_LIVE,
                discovered_at=discovered,
                validated_at=_now_minus(15),
                is_valid=True,
                source_url="https://shop.example.com/.env",
                source_file=".env",
                metadata={"leak": "env-file"},
                balance_available=[
                    {"currency": "usd", "amount": 12345},
                    {"currency": "eur", "amount": 6789},
                ],
                error_message=None,
                validation_count=3,
            ),
        ],
        tokenization_status="server-side",
        stripe_plugin_version="UPE",
        woocommerce_version="8.1.0",
        store_api_available=True,
        country="US",
        currency="USD",
        check_count=10,
        error_count=2,
        success_rate=0.8,
    )


@pytest.fixture
def sample_form() -> FormDiscovery:
    discovered = _now_minus(45)
    return FormDiscovery(
        id="form-1",
        website_id="site-1",
        url="https://shop.example.com/contact",
        form_html="<form action='/contact' method='POST'>...</form>",
        fields=[
            FormField(
                name="email",
                field_type="email",
                required=True,
                default_value=None,
                validation_pattern=r"^[^@]+@[^@]+$",
                metadata={"label": "Email"},
            ),
            FormField(
                name="message",
                field_type="textarea",
                required=True,
                default_value="",
                metadata={},
            ),
        ],
        discovered_at=discovered,
        last_tested=None,
        has_csrf_token=True,
        requires_auth=False,
        submission_method="POST",
        action_url="https://shop.example.com/contact",
    )


async def test_database_smoke_round_trip(
    sqlite_db_path: Path,
    sample_website: WebsiteAsset,
    sample_form: FormDiscovery,
) -> None:
    pool = await open_database(sqlite_db_path)
    try:
        # Migrations must have run via open_database.
        async with pool.acquire() as conn:
            assert await get_current_version(conn) >= 1

        websites = WebsiteAssetRepository(pool)
        keys = StripeKeyRepository(pool)
        forms = FormDiscoveryRepository(pool)

        # Insert a website with nested keys.
        await websites.add(sample_website)

        # Read it back and verify equality.
        fetched = await websites.get(sample_website.id)
        assert fetched is not None
        assert fetched.to_dict() == sample_website.to_dict()

        # Standalone key lookup goes through StripeKeyRepository.
        fetched_key = await keys.get("key-2")
        assert fetched_key is not None
        assert fetched_key.to_dict() == sample_website.stripe_keys[1].to_dict()

        # Insert a form with nested fields.
        await forms.add(sample_form)
        fetched_form = await forms.get(sample_form.id)
        assert fetched_form is not None
        assert fetched_form.to_dict() == sample_form.to_dict()

        # Listing must surface what we inserted, with nested children.
        listed_websites = await websites.list_all()
        assert [w.to_dict() for w in listed_websites] == [sample_website.to_dict()]
        listed_forms = await forms.list_all(website_id=sample_website.id)
        assert [f.to_dict() for f in listed_forms] == [sample_form.to_dict()]

        # Update path: changing a stat should be persisted.
        sample_website.check_count = 20
        sample_website.error_count = 5
        sample_website.success_rate = 0.75
        sample_website.last_checked = _now_minus(5)
        assert await websites.update(sample_website) is True
        refreshed = await websites.get(sample_website.id)
        assert refreshed is not None
        assert refreshed.check_count == 20
        assert refreshed.error_count == 5
        assert refreshed.success_rate == pytest.approx(0.75)

        # Upsert path: changing a key collection must replace it atomically.
        sample_website.stripe_keys = [sample_website.stripe_keys[0]]
        await websites.upsert(sample_website)
        refreshed_after_upsert = await websites.get(sample_website.id)
        assert refreshed_after_upsert is not None
        assert len(refreshed_after_upsert.stripe_keys) == 1
        assert refreshed_after_upsert.stripe_keys[0].id == "key-1"

        # Cascade delete should also remove the form (linked via website_id).
        assert await websites.delete(sample_website.id) is True
        assert await websites.get(sample_website.id) is None
        assert await forms.get(sample_form.id) is None
    finally:
        await pool.close()


async def test_apply_migrations_is_idempotent(sqlite_db_path: Path) -> None:
    """Running migrations twice must leave the schema version unchanged."""
    pool = await open_database(sqlite_db_path)
    try:
        async with pool.acquire() as conn:
            first = await get_current_version(conn)
            await apply_migrations(conn)
            second = await get_current_version(conn)
        assert first == second >= 1
    finally:
        await pool.close()
