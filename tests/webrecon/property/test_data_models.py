"""Property-based tests for ``webrecon.core.models`` round-trip behaviour.

This module implements the tests required by task 2.3 of the
``web-reconnaissance`` spec (Requirement 10.4 — *for all valid asset
collections, serializing then deserializing SHALL produce equivalent
data structures*). It exercises three families of properties:

1. **Serialisation round-trips** — ``to_dict`` / ``from_dict`` and
   ``to_json`` / ``from_json`` preserve all fields and are idempotent
   across nested encode/decode cycles.

2. **Database round-trips** — inserting an asset (or stripe key, or
   form-discovery) through the repository layer and reading it back
   yields an equivalent object (compared via ``to_dict`` since the
   dataclasses are mutable and the equality contract follows the
   default field-wise compare).

3. **Validation rejection** — instances mutated to violate a domain
   invariant are rejected by ``model.validate()`` with
   :class:`ValueError`, while strategy-generated valid instances are
   accepted unchanged.

Each test is marked ``@pytest.mark.property`` so the suite can deselect
property tests with ``-m "not property"`` when iterating on a single
module.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from tests.webrecon.strategies import (
    form_discovery_strategy,
    form_field_strategy,
    stripe_key_strategy_model,
    website_asset_strategy,
)
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
    open_database,
)

pytestmark = pytest.mark.property


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro: Awaitable[Any]) -> Any:
    """Drive ``coro`` to completion on a fresh event loop.

    Hypothesis re-runs the test function many times per fixture
    lifecycle, so each example must spin its own loop instead of
    sharing the pytest-asyncio event loop (which would already be
    closed by the time the strategy starts producing values).
    """
    return asyncio.run(coro)


def _unique_db_path(base: Path) -> Path:
    """Return a fresh DB path next to ``base`` for one Hypothesis example."""
    return base.parent / f"webrecon_test_{uuid.uuid4().hex}.sqlite3"


async def _with_repos(
    db_path: Path,
    body: Callable[
        [WebsiteAssetRepository, StripeKeyRepository, FormDiscoveryRepository],
        Awaitable[None],
    ],
) -> None:
    """Open a pool, hand the repositories to ``body``, then close cleanly."""
    pool = await open_database(db_path)
    try:
        await body(
            WebsiteAssetRepository(pool),
            StripeKeyRepository(pool),
            FormDiscoveryRepository(pool),
        )
    finally:
        await pool.close()


# ---------------------------------------------------------------------------
# 1) Serialisation round-trip properties
# ---------------------------------------------------------------------------
#
# Validates: Requirement 10.4 — serialise/deserialise preserves every
# field for the four core dataclasses.


@given(form_field_strategy())
@settings(max_examples=100, deadline=None)
def test_form_field_dict_round_trip(field_obj: FormField) -> None:
    """``FormField.from_dict(field.to_dict()) == field`` for all valid fields."""
    restored = FormField.from_dict(field_obj.to_dict())
    assert restored == field_obj


@given(form_field_strategy())
@settings(max_examples=100, deadline=None)
def test_form_field_json_round_trip(field_obj: FormField) -> None:
    """``FormField.from_json(field.to_json()) == field`` for all valid fields."""
    restored = FormField.from_json(field_obj.to_json())
    assert restored == field_obj


@given(stripe_key_strategy_model())
@settings(max_examples=100, deadline=None)
def test_stripe_key_dict_round_trip(key: StripeKey) -> None:
    """``StripeKey`` round-trips through ``to_dict`` / ``from_dict``."""
    restored = StripeKey.from_dict(key.to_dict())
    assert restored == key


@given(stripe_key_strategy_model())
@settings(max_examples=100, deadline=None)
def test_stripe_key_json_round_trip(key: StripeKey) -> None:
    """``StripeKey`` round-trips through ``to_json`` / ``from_json``."""
    restored = StripeKey.from_json(key.to_json())
    assert restored == key


@given(form_discovery_strategy())
@settings(max_examples=100, deadline=None)
def test_form_discovery_dict_round_trip(form: FormDiscovery) -> None:
    """``FormDiscovery`` (including nested fields) round-trips via dicts."""
    restored = FormDiscovery.from_dict(form.to_dict())
    assert restored == form


@given(form_discovery_strategy())
@settings(max_examples=100, deadline=None)
def test_form_discovery_json_round_trip(form: FormDiscovery) -> None:
    """``FormDiscovery`` round-trips via JSON without information loss."""
    restored = FormDiscovery.from_json(form.to_json())
    assert restored == form


@given(website_asset_strategy())
@settings(max_examples=75, deadline=None)
def test_website_asset_dict_round_trip(asset: WebsiteAsset) -> None:
    """``WebsiteAsset`` (with nested keys) round-trips via dicts."""
    restored = WebsiteAsset.from_dict(asset.to_dict())
    assert restored == asset


@given(website_asset_strategy())
@settings(max_examples=75, deadline=None)
def test_website_asset_json_round_trip(asset: WebsiteAsset) -> None:
    """``WebsiteAsset`` round-trips via JSON without information loss."""
    restored = WebsiteAsset.from_json(asset.to_json())
    assert restored == asset


# Idempotence: two consecutive encode/decode cycles produce identical
# dicts. This guards against subtle representation drift (e.g. a
# datetime that loses sub-second precision after one round but not the
# next).


@given(stripe_key_strategy_model())
@settings(max_examples=75, deadline=None)
def test_stripe_key_dict_idempotent(key: StripeKey) -> None:
    """``from_dict(to_dict(x))`` and one further cycle produce equal dicts."""
    once = StripeKey.from_dict(key.to_dict())
    twice = StripeKey.from_dict(once.to_dict())
    assert once.to_dict() == twice.to_dict()


@given(form_discovery_strategy())
@settings(max_examples=75, deadline=None)
def test_form_discovery_dict_idempotent(form: FormDiscovery) -> None:
    """``FormDiscovery`` dict encoding is idempotent under repeated cycling."""
    once = FormDiscovery.from_dict(form.to_dict())
    twice = FormDiscovery.from_dict(once.to_dict())
    assert once.to_dict() == twice.to_dict()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_dict_idempotent(asset: WebsiteAsset) -> None:
    """``WebsiteAsset`` dict encoding is idempotent under repeated cycling."""
    once = WebsiteAsset.from_dict(asset.to_dict())
    twice = WebsiteAsset.from_dict(once.to_dict())
    assert once.to_dict() == twice.to_dict()


# ---------------------------------------------------------------------------
# 2) Database round-trip properties
# ---------------------------------------------------------------------------
#
# Validates: Requirement 10.4 — repository writes followed by reads
# produce equivalent objects (compared on their dict view because the
# dataclasses are mutable and order of nested children is normalised
# by the schema sort).


@given(website_asset_strategy())
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_website_asset_db_round_trip(
    sqlite_db_path: Path, asset: WebsiteAsset
) -> None:
    """``websites.add(asset)`` then ``websites.get(id)`` recovers ``asset``."""
    db_path = _unique_db_path(sqlite_db_path)

    async def _body(
        websites: WebsiteAssetRepository,
        _keys: StripeKeyRepository,
        _forms: FormDiscoveryRepository,
    ) -> None:
        await websites.add(asset)
        fetched = await websites.get(asset.id)
        assert fetched is not None
        # ``stripe_keys`` are reloaded ordered by ``(discovered_at, id)`` —
        # mirror that ordering on the input before comparing dicts.
        expected = asset.to_dict()
        expected_keys = sorted(
            expected["stripe_keys"], key=lambda k: (k["discovered_at"], k["id"])
        )
        expected["stripe_keys"] = expected_keys
        actual = fetched.to_dict()
        actual["stripe_keys"] = sorted(
            actual["stripe_keys"], key=lambda k: (k["discovered_at"], k["id"])
        )
        assert actual == expected

    _run(_with_repos(db_path, _body))


@given(stripe_key_strategy_model())
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_stripe_key_db_round_trip(sqlite_db_path: Path, key: StripeKey) -> None:
    """Standalone ``StripeKey`` insert/get yields an equivalent dict."""
    db_path = _unique_db_path(sqlite_db_path)

    async def _body(
        _websites: WebsiteAssetRepository,
        keys: StripeKeyRepository,
        _forms: FormDiscoveryRepository,
    ) -> None:
        await keys.add(key, website_id=None)
        fetched = await keys.get(key.id)
        assert fetched is not None
        assert fetched.to_dict() == key.to_dict()

    _run(_with_repos(db_path, _body))


@given(website_asset_strategy(max_stripe_keys=0), form_discovery_strategy())
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_form_discovery_db_round_trip(
    sqlite_db_path: Path, parent: WebsiteAsset, form: FormDiscovery
) -> None:
    """``forms.add(form)`` then ``forms.get(id)`` recovers ``form``.

    A parent :class:`WebsiteAsset` is generated alongside the form to
    satisfy the ``form_discoveries.website_id`` foreign key. The form's
    ``website_id`` is overwritten with the parent's id before insert.
    """
    db_path = _unique_db_path(sqlite_db_path)
    form.website_id = parent.id

    async def _body(
        websites: WebsiteAssetRepository,
        _keys: StripeKeyRepository,
        forms: FormDiscoveryRepository,
    ) -> None:
        await websites.add(parent)
        await forms.add(form)
        fetched = await forms.get(form.id)
        assert fetched is not None
        assert fetched.to_dict() == form.to_dict()

    _run(_with_repos(db_path, _body))


# ---------------------------------------------------------------------------
# 3) Validation properties
# ---------------------------------------------------------------------------
#
# Validates: Requirement 10.4 — ``validate()`` accepts every
# strategy-generated valid instance and rejects mutations that violate
# a documented invariant.


@given(form_field_strategy())
@settings(max_examples=100, deadline=None)
def test_form_field_validate_accepts_valid(field_obj: FormField) -> None:
    """Strategy-generated ``FormField`` instances pass validation."""
    field_obj.validate()


@given(stripe_key_strategy_model())
@settings(max_examples=100, deadline=None)
def test_stripe_key_validate_accepts_valid(key: StripeKey) -> None:
    """Strategy-generated ``StripeKey`` instances pass validation."""
    key.validate()


@given(form_discovery_strategy())
@settings(max_examples=100, deadline=None)
def test_form_discovery_validate_accepts_valid(form: FormDiscovery) -> None:
    """Strategy-generated ``FormDiscovery`` instances pass validation."""
    form.validate()


@given(website_asset_strategy())
@settings(max_examples=75, deadline=None)
def test_website_asset_validate_accepts_valid(asset: WebsiteAsset) -> None:
    """Strategy-generated ``WebsiteAsset`` instances pass validation."""
    asset.validate()


# ---- Targeted invalid-input rejection ------------------------------------
#
# Each test below mutates one field of an otherwise-valid model so the
# test stays focused on the constraint under check.


@given(form_field_strategy())
@settings(max_examples=50, deadline=None)
def test_form_field_validate_rejects_empty_name(field_obj: FormField) -> None:
    """``FormField`` with an empty ``name`` must be rejected."""
    field_obj.name = ""
    with pytest.raises(ValueError):
        field_obj.validate()


@given(form_field_strategy())
@settings(max_examples=50, deadline=None)
def test_form_field_validate_rejects_empty_type(field_obj: FormField) -> None:
    """``FormField`` with an empty ``field_type`` must be rejected."""
    field_obj.field_type = ""
    with pytest.raises(ValueError):
        field_obj.validate()


@given(stripe_key_strategy_model())
@settings(max_examples=50, deadline=None)
def test_stripe_key_validate_rejects_empty_id(key: StripeKey) -> None:
    """``StripeKey`` with an empty ``id`` must be rejected."""
    key.id = ""
    with pytest.raises(ValueError):
        key.validate()


@given(stripe_key_strategy_model())
@settings(max_examples=50, deadline=None)
def test_stripe_key_validate_rejects_negative_validation_count(
    key: StripeKey,
) -> None:
    """``StripeKey.validation_count`` must be non-negative."""
    key.validation_count = -1
    with pytest.raises(ValueError):
        key.validate()


@given(stripe_key_strategy_model(), st.text(min_size=1, max_size=8))
@settings(max_examples=50, deadline=None)
def test_stripe_key_validate_rejects_prefix_mismatch(
    key: StripeKey, bogus_prefix: str
) -> None:
    """``key_value`` whose prefix mismatches ``key_type`` is rejected.

    Only meaningful for ``PK_LIVE`` and ``SK_LIVE`` (``OTHER`` accepts
    any prefix), so the test short-circuits when the strategy picks
    ``KeyType.OTHER``.
    """
    if key.key_type is KeyType.OTHER:
        return
    # Force a non-pk_/sk_ prefix that cannot match either branch.
    key.key_value = "xx_" + bogus_prefix + "padding_padding_padding"
    with pytest.raises(ValueError):
        key.validate()


@given(form_discovery_strategy())
@settings(max_examples=50, deadline=None)
def test_form_discovery_validate_rejects_unknown_method(
    form: FormDiscovery,
) -> None:
    """Submission methods outside the recognised HTTP verb set are rejected."""
    form.submission_method = "TEAPOT"
    with pytest.raises(ValueError):
        form.validate()


@given(form_discovery_strategy())
@settings(max_examples=50, deadline=None)
def test_form_discovery_validate_rejects_tested_before_discovered(
    form: FormDiscovery,
) -> None:
    """``last_tested`` must not predate ``discovered_at``."""
    form.last_tested = form.discovered_at - timedelta(days=1)
    with pytest.raises(ValueError):
        form.validate()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_validate_rejects_high_success_rate(
    asset: WebsiteAsset,
) -> None:
    """``success_rate`` outside ``[0, 1]`` is rejected."""
    asset.success_rate = 1.5
    with pytest.raises(ValueError):
        asset.validate()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_validate_rejects_negative_success_rate(
    asset: WebsiteAsset,
) -> None:
    """Negative ``success_rate`` is rejected."""
    asset.success_rate = -0.1
    with pytest.raises(ValueError):
        asset.validate()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_validate_rejects_errors_exceeding_checks(
    asset: WebsiteAsset,
) -> None:
    """``error_count`` must not exceed ``check_count``."""
    asset.error_count = asset.check_count + 1
    with pytest.raises(ValueError):
        asset.validate()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_validate_rejects_checked_before_discovered(
    asset: WebsiteAsset,
) -> None:
    """``last_checked`` must not predate ``discovered_at``."""
    asset.last_checked = asset.discovered_at - timedelta(days=1)
    with pytest.raises(ValueError):
        asset.validate()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_validate_rejects_future_discovered_at(
    asset: WebsiteAsset,
) -> None:
    """``discovered_at`` in the future is rejected."""
    asset.discovered_at = datetime.now(timezone.utc) + timedelta(days=1)
    # ``last_checked`` must stay >= discovered_at to isolate the check.
    asset.last_checked = asset.discovered_at + timedelta(seconds=1)
    with pytest.raises(ValueError):
        asset.validate()


@given(website_asset_strategy())
@settings(max_examples=50, deadline=None)
def test_website_asset_validate_rejects_empty_id(asset: WebsiteAsset) -> None:
    """``WebsiteAsset.id`` must be non-empty."""
    asset.id = ""
    with pytest.raises(ValueError):
        asset.validate()


# ---------------------------------------------------------------------------
# Anchor: example-based smoke check for the property markers
# ---------------------------------------------------------------------------


def test_validate_rejects_known_invalid_example() -> None:
    """An explicit example that crosses every documented invariant.

    Acts as a trivial guard against accidental "all-tests-pass-when-they-
    shouldn't" regressions in the validation methods (e.g. a future
    refactor that turns ``raise ValueError`` into ``logger.warning``).
    """
    asset = WebsiteAsset(
        id="",  # invalid: empty id
        url="https://example.com",
        normalized_url="https://example.com/",
        discovered_at=datetime.now(timezone.utc) - timedelta(seconds=60),
        last_checked=datetime.now(timezone.utc) - timedelta(seconds=30),
        status=AssetStatus.ACTIVE,
        discovery_source=DiscoverySource.MANUAL,
    )
    with pytest.raises(ValueError):
        asset.validate()
