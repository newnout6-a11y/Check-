"""Unit tests for :mod:`webrecon.config.schema`.

Covers:

* Field defaults are sensible (matches the design document).
* Range / bounds violations raise ``pydantic.ValidationError``.
* Stripe and GitHub key format validators reject malformed inputs.
* The cross-field safety rule rejects "both guards off" configurations.
* Environment-variable loading (with the ``WEBRECON_`` prefix and the
  ``__`` nested delimiter) feeds the resolved ``AppConfig`` correctly.

The tests are intentionally framework-agnostic: they exercise the
public API of :class:`AppConfig` and the sub-section models without
poking at private attributes, so future refactors that re-organise
the model internals will not break the suite as long as the public
contract is preserved.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from webrecon.config.schema import (
    ApiKeys,
    AppConfig,
    ConcurrencySettings,
    DatabaseSettings,
    FofaCredentials,
    RateLimitSettings,
    SafetySettings,
    get_default_config,
)


# Every test in this module should run with a clean environment so a
# leaking ``WEBRECON_*`` value in the developer shell never silently
# turns a default-values test into something else. ``autouse`` is the
# simplest way to apply the scrub uniformly.
@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Strip ``WEBRECON_*`` env vars and chdir to an empty ``tmp_path``.

    ``AppConfig`` is configured with ``env_file=".env"`` so it will
    transparently read whatever ``.env`` happens to be next to the
    process's CWD. Switching to ``tmp_path`` (which has no ``.env``)
    makes every test independent of the developer's working tree.
    """
    import os

    for env_key in [k for k in os.environ if k.startswith("WEBRECON_")]:
        monkeypatch.delenv(env_key, raising=False)
    monkeypatch.chdir(tmp_path)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    """Field defaults must match the design document."""

    def test_get_default_config_returns_app_config(self) -> None:
        cfg = get_default_config()
        assert isinstance(cfg, AppConfig)

    def test_concurrency_defaults(self) -> None:
        cfg = get_default_config()
        assert cfg.concurrency.max_connections == 20
        assert cfg.concurrency.per_host_limit == 5
        assert cfg.concurrency.semaphore_size == 15

    def test_rate_limiting_defaults(self) -> None:
        cfg = get_default_config()
        assert cfg.rate_limiting.requests_per_second == pytest.approx(10.0)
        assert cfg.rate_limiting.delay_between_requests == pytest.approx(0.0)
        assert cfg.rate_limiting.respect_robots_txt is True
        assert cfg.rate_limiting.crawl_delay == pytest.approx(0.0)

    def test_database_defaults(self) -> None:
        cfg = get_default_config()
        assert cfg.database.path == Path("webrecon.sqlite3")
        assert cfg.database.use_sqlite is True
        assert cfg.database.auto_backup is False
        assert cfg.database.backup_interval_hours == 24

    def test_safety_defaults_are_conservative(self) -> None:
        cfg = get_default_config()
        # The safety defaults must keep the system in test mode with
        # confirmation prompts on -- the design enforces conservative
        # defaults so a fresh install cannot accidentally run a
        # destructive operation against a real target.
        assert cfg.safety.test_mode is True
        assert cfg.safety.use_test_data_only is True
        assert cfg.safety.require_confirmation is True
        assert cfg.safety.max_requests_per_site == 100

    def test_api_keys_default_to_none(self) -> None:
        cfg = get_default_config()
        assert cfg.api_keys.fofa is None
        assert cfg.api_keys.shodan is None
        assert cfg.api_keys.serper is None
        assert cfg.api_keys.github is None
        assert cfg.api_keys.stripe is None

    def test_log_level_default(self) -> None:
        cfg = get_default_config()
        assert cfg.log_level == "INFO"


# ---------------------------------------------------------------------------
# Range / bounds enforcement
# ---------------------------------------------------------------------------


class TestRangeValidation:
    """Bounds declared via ``Field(ge=..., le=...)`` must be enforced."""

    @pytest.mark.parametrize(
        "field, value",
        [
            ("max_connections", 0),
            ("max_connections", 101),
            ("per_host_limit", 0),
            ("per_host_limit", 11),
            ("semaphore_size", 0),
            ("semaphore_size", 51),
        ],
    )
    def test_concurrency_out_of_range(self, field: str, value: int) -> None:
        with pytest.raises(ValidationError):
            ConcurrencySettings(**{field: value})

    @pytest.mark.parametrize(
        "field, value",
        [
            ("requests_per_second", 0.0),
            ("requests_per_second", 100.1),
            ("delay_between_requests", -0.1),
            ("delay_between_requests", 10.5),
            ("crawl_delay", -0.1),
            ("crawl_delay", 60.5),
        ],
    )
    def test_rate_limiting_out_of_range(self, field: str, value: float) -> None:
        with pytest.raises(ValidationError):
            RateLimitSettings(**{field: value})

    def test_database_backup_interval_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            DatabaseSettings(backup_interval_hours=0)

    def test_safety_max_requests_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            SafetySettings(max_requests_per_site=0)


# ---------------------------------------------------------------------------
# API-key format validators
# ---------------------------------------------------------------------------


class TestStripeKeyValidator:
    """Stripe key prefixes must be one of the documented forms."""

    @pytest.mark.parametrize(
        "key",
        [
            "sk_live_abc123",
            "sk_test_abc123",
            "rk_live_abc123",
            "rk_test_abc123",
        ],
    )
    def test_accepts_documented_prefixes(self, key: str) -> None:
        keys = ApiKeys(stripe=key)
        assert keys.stripe == key

    @pytest.mark.parametrize(
        "key",
        [
            "pk_live_abc",  # publishable key, not valid as a server credential
            "ak_live_abc",  # made-up prefix
            "abc123",
            "sk_abc",  # missing live/test infix
        ],
    )
    def test_rejects_bad_prefix(self, key: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ApiKeys(stripe=key)
        assert "stripe" in str(exc_info.value).lower()

    def test_empty_string_normalises_to_none(self) -> None:
        # An empty value (typical when a shell exports the variable
        # without a value) should be treated as "key not configured"
        # rather than as a malformed key.
        assert ApiKeys(stripe="").stripe is None
        assert ApiKeys(stripe="   ").stripe is None


class TestGithubTokenValidator:
    """GitHub token validator must accept all documented formats."""

    @pytest.mark.parametrize(
        "token",
        [
            "ghp_" + "a" * 36,
            "gho_" + "a" * 36,
            "ghs_" + "a" * 36,
            "ghu_" + "a" * 36,
            "ghr_" + "a" * 36,
            "github_pat_" + "x" * 22,
            "0123456789abcdef0123456789abcdef01234567",  # 40-char legacy hex
        ],
    )
    def test_accepts_documented_formats(self, token: str) -> None:
        keys = ApiKeys(github=token)
        assert keys.github == token

    @pytest.mark.parametrize(
        "token",
        [
            "garbage",
            "0123",  # too short for legacy
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  # 40 chars but not hex
        ],
    )
    def test_rejects_bad_formats(self, token: str) -> None:
        with pytest.raises(ValidationError):
            ApiKeys(github=token)


# ---------------------------------------------------------------------------
# Cross-field safety rule
# ---------------------------------------------------------------------------


class TestSafetyCrossField:
    """At least one of test_mode / require_confirmation must stay on."""

    def test_both_guards_off_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            AppConfig.model_validate(
                {
                    "safety": {
                        "test_mode": False,
                        "require_confirmation": False,
                    }
                }
            )
        message = str(exc_info.value)
        assert "test_mode" in message and "require_confirmation" in message

    def test_only_test_mode_off_is_ok(self) -> None:
        cfg = AppConfig.model_validate(
            {
                "safety": {
                    "test_mode": False,
                    "require_confirmation": True,
                }
            }
        )
        assert cfg.safety.test_mode is False
        assert cfg.safety.require_confirmation is True

    def test_only_require_confirmation_off_is_ok(self) -> None:
        cfg = AppConfig.model_validate(
            {
                "safety": {
                    "test_mode": True,
                    "require_confirmation": False,
                }
            }
        )
        assert cfg.safety.test_mode is True
        assert cfg.safety.require_confirmation is False


# ---------------------------------------------------------------------------
# Environment-variable loading
# ---------------------------------------------------------------------------


class TestEnvLoading:
    """``WEBRECON_`` prefixed env vars must populate the resolved config."""

    def test_log_level_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEBRECON_LOG_LEVEL", "DEBUG")
        cfg = AppConfig()
        assert cfg.log_level == "DEBUG"

    def test_log_level_is_uppercased(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEBRECON_LOG_LEVEL", "warning")
        cfg = AppConfig()
        assert cfg.log_level == "WARNING"

    def test_invalid_log_level_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WEBRECON_LOG_LEVEL", "trace")
        with pytest.raises(ValidationError):
            AppConfig()

    def test_nested_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WEBRECON_API_KEYS__SHODAN", "shodan-secret-token")
        cfg = AppConfig()
        assert cfg.api_keys.shodan == "shodan-secret-token"

    def test_nested_concurrency_setting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WEBRECON_CONCURRENCY__MAX_CONNECTIONS", "42")
        cfg = AppConfig()
        assert cfg.concurrency.max_connections == 42

    def test_unknown_env_var_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # ``extra="ignore"`` means a typo in the env name does not
        # break loading -- the value is silently dropped. This keeps
        # legacy deployments compatible when fields are renamed.
        monkeypatch.setenv("WEBRECON_DOES_NOT_EXIST", "value")
        cfg = AppConfig()
        assert cfg.log_level == "INFO"


# ---------------------------------------------------------------------------
# FOFA credentials
# ---------------------------------------------------------------------------


class TestFofaCredentials:
    """FOFA credentials must require both email and key when set."""

    def test_both_fields_required(self) -> None:
        with pytest.raises(ValidationError):
            FofaCredentials(email="", key="")  # type: ignore[arg-type]

    def test_valid_pair(self) -> None:
        creds = FofaCredentials(email="user@example.com", key="abc123")
        assert creds.email == "user@example.com"
        assert creds.key == "abc123"

    def test_via_app_config_nested_dict(self) -> None:
        cfg = AppConfig.model_validate(
            {
                "api_keys": {
                    "fofa": {"email": "u@example.com", "key": "k"},
                }
            }
        )
        assert cfg.api_keys.fofa is not None
        assert cfg.api_keys.fofa.email == "u@example.com"
        assert cfg.api_keys.fofa.key == "k"
