"""Configuration schema for the ``webrecon`` package.

This module defines the strongly-typed configuration tree used across
the reconnaissance pipeline. It is the canonical Python translation of
the JSON Schema documented in ``design.md`` (section "JSON Schema for
Configuration"), and it is consumed by every long-running component
(:mod:`webrecon.discovery`, :mod:`webrecon.mass_parser`,
:mod:`webrecon.automation`, ...) through the loader implemented in
:mod:`webrecon.config.loader`.

Layout:

* :class:`FofaCredentials`, :class:`ApiKeys` -- credentials for the
  external intelligence sources (FOFA, Shodan, Serper, GitHub, Stripe).
* :class:`ConcurrencySettings`, :class:`RateLimitSettings` -- knobs that
  bound the network footprint of bulk operations (Requirement 12.1,
  Requirement 9.1).
* :class:`DatabaseSettings` -- on-disk asset database location and
  housekeeping toggles.
* :class:`SafetySettings` -- safety + compliance switches enforced
  before any destructive operation runs (Requirement 9.3 -- 9.5).
* :class:`AppConfig` -- root :class:`pydantic_settings.BaseSettings`
  model that aggregates the sub-sections, reads from environment
  variables (prefix ``WEBRECON_``, nested delimiter ``__``) and an
  optional ``.env`` file.

Validators:

* Each API-key-bearing field has a format validator. Stripe keys must
  start with ``sk_live_`` / ``sk_test_`` (``rk_`` restricted keys are
  also accepted because Stripe's restricted-key prefixes are valid for
  validation calls). GitHub tokens must use one of the documented
  prefixes (``ghp_``, ``gho_``, ``ghs_``, ``ghu_``, ``ghr_``,
  ``github_pat_``) or be a 40-character hexadecimal legacy token.
* :meth:`AppConfig._enforce_safety_rules` rejects configurations that
  would disable both ``test_mode`` *and* ``require_confirmation`` --
  the design requires at least one of those guards to remain on.
* :meth:`DatabaseSettings._validate_path` ensures the database parent
  directory exists or can be created. Sentinel paths
  (``:memory:`` for SQLite in-memory mode) bypass the filesystem check.

The module is type-strict (``from __future__ import annotations`` plus
``if TYPE_CHECKING:`` guards for non-runtime imports) so it passes
``mypy --strict`` under the configuration in ``mypy.ini``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from typing_extensions import Self

__all__ = [
    "ApiKeys",
    "AppConfig",
    "ConcurrencySettings",
    "DatabaseSettings",
    "FofaCredentials",
    "RateLimitSettings",
    "SafetySettings",
    "get_default_config",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Stripe accepts a small family of secret-key prefixes. Live and test
# secret keys are the canonical forms; ``rk_`` restricted keys are
# valid against Stripe's validation endpoints with reduced scopes and
# are therefore accepted here.
_STRIPE_VALID_PREFIXES: tuple[str, ...] = (
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
)

# GitHub personal-access-token prefixes (https://github.blog/changelog).
# ``ghp_`` -- classic PAT, ``gho_`` -- OAuth tokens issued by GitHub
# Apps, ``ghs_`` -- server-to-server installation tokens, ``ghu_`` --
# user-to-server tokens, ``ghr_`` -- refresh tokens, ``github_pat_`` --
# the new fine-grained PAT format.
_GITHUB_TOKEN_PREFIXES: tuple[str, ...] = (
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
)

# Legacy GitHub PATs were 40-character lowercase hex strings.
_GITHUB_LEGACY_TOKEN_RE: re.Pattern[str] = re.compile(r"^[0-9a-f]{40}$")


def _empty_to_none(value: str | None) -> str | None:
    """Treat an empty / whitespace-only string as ``None``.

    ``pydantic-settings`` resolves missing environment variables to an
    empty string when the host process exports the variable without a
    value (a common shell idiom). Coercing those to ``None`` keeps the
    optional API-key fields semantically correct -- "absent" should
    behave the same whether the variable is unset or set to "".
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


# ---------------------------------------------------------------------------
# Sub-sections
# ---------------------------------------------------------------------------


class FofaCredentials(BaseModel):
    """FOFA API authentication pair.

    FOFA's REST API requires a registered email plus the corresponding
    API key (https://en.fofa.info/api). Both fields are mandatory when
    the FOFA discovery module is used; the discovery client treats the
    surrounding :class:`ApiKeys.fofa` field as optional so the rest of
    the system keeps working when the operator hasn't provisioned a
    FOFA account.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    email: str = Field(..., min_length=1, description="Registered FOFA account email.")
    key: str = Field(..., min_length=1, description="FOFA API key.")


class ApiKeys(BaseModel):
    """Optional credentials for the external intelligence sources.

    Every field is optional so a partial deployment (for example
    GitHub-only) does not require provisioning credentials for sources
    the operator does not intend to query. Modules consuming a missing
    key are expected to fail fast with a descriptive error rather than
    silently skipping the source.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    fofa: FofaCredentials | None = Field(
        default=None,
        description="FOFA email + API key. Required by the FOFA discovery module.",
    )
    shodan: str | None = Field(
        default=None,
        description="Shodan API key. Required by the Shodan discovery module.",
    )
    serper: str | None = Field(
        default=None,
        description="Serper.dev API key. Required by the Serper discovery module.",
    )
    github: str | None = Field(
        default=None,
        description="GitHub personal access token (classic or fine-grained).",
    )
    stripe: str | None = Field(
        default=None,
        description="Stripe secret/restricted key used for live key validation.",
    )

    # ---- Validators ----------------------------------------------------

    @field_validator("shodan", "serper", mode="before")
    @classmethod
    def _normalise_optional_string(cls, value: str | None) -> str | None:
        """Coerce empty strings to ``None`` for free-form API keys."""
        return _empty_to_none(value)

    @field_validator("github", mode="before")
    @classmethod
    def _validate_github_token(cls, value: str | None) -> str | None:
        """Reject GitHub tokens with unrecognised formats.

        Accepts the documented PAT prefixes (``ghp_``, ``gho_``,
        ``ghs_``, ``ghu_``, ``ghr_``, ``github_pat_``) and the legacy
        40-character hex format. Anything else is rejected so a
        misconfigured token is caught at startup rather than at first
        API call.
        """
        normalised = _empty_to_none(value)
        if normalised is None:
            return None
        if normalised.startswith(_GITHUB_TOKEN_PREFIXES):
            return normalised
        if _GITHUB_LEGACY_TOKEN_RE.match(normalised):
            return normalised
        allowed = ", ".join(_GITHUB_TOKEN_PREFIXES)
        raise ValueError(
            "GitHub token format not recognised. Expected one of "
            f"{allowed} or a 40-character hexadecimal legacy token."
        )

    @field_validator("stripe", mode="before")
    @classmethod
    def _validate_stripe_key(cls, value: str | None) -> str | None:
        """Reject Stripe keys with unrecognised prefixes.

        Live and test secret keys (``sk_live_``, ``sk_test_``) are the
        canonical forms accepted by Stripe's validation endpoints.
        Restricted keys (``rk_live_``, ``rk_test_``) are also accepted
        because they remain valid for the read-only operations the
        validator performs.
        """
        normalised = _empty_to_none(value)
        if normalised is None:
            return None
        if normalised.startswith(_STRIPE_VALID_PREFIXES):
            return normalised
        allowed = ", ".join(_STRIPE_VALID_PREFIXES)
        raise ValueError(
            "Stripe key format not recognised. Expected one of "
            f"{allowed}."
        )


class ConcurrencySettings(BaseModel):
    """Bounds on concurrent network operations.

    The defaults match the design document: ``max_connections=20``
    keeps the global httpx connection pool modest enough to stay below
    typical NAT / ISP per-host limits, ``per_host_limit=5`` matches
    httpx's own default and ``semaphore_size=15`` matches the bounded
    concurrency pattern used by the existing reconnaissance scripts.
    """

    model_config = ConfigDict(extra="ignore")

    max_connections: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Total concurrent connections across all hosts.",
    )
    per_host_limit: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum concurrent connections per remote host.",
    )
    semaphore_size: int = Field(
        default=15,
        ge=1,
        le=50,
        description="Bound on logical concurrency for batch parsers.",
    )


class RateLimitSettings(BaseModel):
    """Per-host rate-limit + politeness knobs.

    These values feed both the global rate limiter and the per-task
    politeness logic. ``respect_robots_txt`` defaults to ``True`` to
    keep the system aligned with Requirement 9.1 (respect robots.txt
    and crawl delays).
    """

    model_config = ConfigDict(extra="ignore")

    requests_per_second: float = Field(
        default=10.0,
        gt=0.0,
        le=100.0,
        description="Sustained request rate ceiling.",
    )
    delay_between_requests: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Mandatory inter-request delay in seconds.",
    )
    respect_robots_txt: bool = Field(
        default=True,
        description="Honour the target site's robots.txt directives.",
    )
    crawl_delay: float = Field(
        default=0.0,
        ge=0.0,
        le=60.0,
        description="Default crawl delay to apply when robots.txt does not specify one.",
    )


class DatabaseSettings(BaseModel):
    """Asset-database location and housekeeping toggles."""

    model_config = ConfigDict(extra="ignore")

    path: Path = Field(
        default=Path("webrecon.sqlite3"),
        description="Filesystem path of the SQLite database file.",
    )
    use_sqlite: bool = Field(
        default=True,
        description="Use the SQLite backend (the only supported option for now).",
    )
    auto_backup: bool = Field(
        default=False,
        description="Take periodic backups of the database file.",
    )
    backup_interval_hours: int = Field(
        default=24,
        ge=1,
        description="Interval between automatic backups, in hours.",
    )

    # ---- Validators ----------------------------------------------------

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: Path) -> Path:
        """Ensure the parent directory of ``path`` exists or is creatable.

        ``:memory:`` is accepted as a sentinel for SQLite in-memory
        mode and bypasses the filesystem check; bare filenames (no
        parent) implicitly resolve to the current working directory.
        """
        if str(value) == ":memory:":
            return value
        parent = value.parent
        # ``Path("foo.sqlite3").parent`` is ``Path(".")`` -- a path that
        # always exists, so ``parent.exists()`` short-circuits the
        # ``mkdir`` branch. For nested paths we attempt to create the
        # directory tree eagerly so a misconfigured location is caught
        # at startup rather than the first INSERT.
        if str(parent) in {"", "."}:
            return value
        if parent.exists():
            if not parent.is_dir():
                raise ValueError(
                    f"DatabaseSettings.path parent {parent!s} exists but is not a directory."
                )
            return value
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValueError(
                f"DatabaseSettings.path parent {parent!s} cannot be created: {exc}"
            ) from exc
        return value


class SafetySettings(BaseModel):
    """Safety and compliance switches.

    The defaults are deliberately conservative: ``test_mode``,
    ``use_test_data_only``, and ``require_confirmation`` all default to
    ``True``. The cross-field validator on :class:`AppConfig` rejects
    configurations that would disable both ``test_mode`` *and*
    ``require_confirmation`` -- at least one of those guards must
    remain on so the operator cannot accidentally arm both
    destructive-operation paths in a single edit.
    """

    model_config = ConfigDict(extra="ignore")

    max_requests_per_site: int = Field(
        default=100,
        ge=1,
        description="Hard cap on requests issued to a single target site.",
    )
    test_mode: bool = Field(
        default=True,
        description="Restrict the system to non-destructive operations.",
    )
    use_test_data_only: bool = Field(
        default=True,
        description="Use only synthetic test data when interacting with target sites.",
    )
    require_confirmation: bool = Field(
        default=True,
        description="Prompt for confirmation before destructive operations.",
    )


# ---------------------------------------------------------------------------
# Root model
# ---------------------------------------------------------------------------


class AppConfig(BaseSettings):
    """Root configuration model loaded from environment + ``.env``.

    Sources, in increasing precedence:

    1. Field defaults declared on the sub-section models above.
    2. Variables read from ``.env`` in the working directory (UTF-8).
    3. Environment variables prefixed with ``WEBRECON_``. Nested
       sections are addressed with ``__`` -- for example
       ``WEBRECON_API_KEYS__SHODAN=xxx`` populates
       ``AppConfig.api_keys.shodan``.

    Unknown environment variables are ignored so adding a new key in a
    deployment-specific ``.env`` never breaks an older binary that
    doesn't know about it.
    """

    model_config = SettingsConfigDict(
        env_prefix="WEBRECON_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    api_keys: ApiKeys = Field(
        default_factory=ApiKeys,
        description="Credentials for the external intelligence sources.",
    )
    concurrency: ConcurrencySettings = Field(
        default_factory=ConcurrencySettings,
        description="Bounds on concurrent network operations.",
    )
    rate_limiting: RateLimitSettings = Field(
        default_factory=RateLimitSettings,
        description="Per-host rate-limit and politeness knobs.",
    )
    database: DatabaseSettings = Field(
        default_factory=DatabaseSettings,
        description="Asset-database location and housekeeping toggles.",
    )
    safety: SafetySettings = Field(
        default_factory=SafetySettings,
        description="Safety and compliance switches.",
    )
    log_level: str = Field(
        default="INFO",
        description="Root structlog level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    # ---- Validators ----------------------------------------------------

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: str | None, info: ValidationInfo) -> str:
        """Upper-case the log level and reject unknown values.

        Pydantic-settings forwards strings verbatim from the
        environment, so ``WEBRECON_LOG_LEVEL=debug`` and
        ``WEBRECON_LOG_LEVEL=DEBUG`` should both work.
        """
        del info
        if value is None:
            return "INFO"
        normalised = str(value).strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalised not in allowed:
            raise ValueError(
                f"log_level must be one of {sorted(allowed)}, got {value!r}."
            )
        return normalised

    @model_validator(mode="after")
    def _enforce_safety_rules(self) -> Self:
        """Reject configurations that disable both safety guards.

        ``test_mode=False`` makes destructive operations possible at
        all; ``require_confirmation=False`` removes the interactive
        last-resort prompt. Allowing both to be off simultaneously
        would let a single misconfiguration arm the destructive path
        with no human-in-the-loop check, which violates the safety
        defaults documented in Requirement 9.3 / 9.4.
        """
        if not self.safety.test_mode and not self.safety.require_confirmation:
            raise ValueError(
                "Cannot disable both safety.test_mode and safety.require_confirmation: "
                "at least one safety mechanism must remain enabled."
            )
        return self


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def get_default_config() -> AppConfig:
    """Return an :class:`AppConfig` instance with field defaults only.

    Used by tests and the CLI to obtain a configuration that is not
    contaminated by ambient environment variables or ``.env`` files.

    Implementation note: ``BaseSettings.__init__`` is the entry point
    that pulls values from the configured settings sources. Going
    through :py:meth:`BaseModel.model_validate` with an empty dict
    bypasses those sources entirely while still running every field
    and model validator against the resolved defaults.
    """
    return AppConfig.model_validate({})
