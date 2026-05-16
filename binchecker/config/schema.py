"""Configuration schema for the binchecker package.

This module defines :class:`AppConfig`, the canonical settings object for
the runtime. Per the design's *Configuration Resolution* section, the
effective configuration is built by deep-merging — in increasing order
of precedence — built-in defaults, profile overlays, ``.env`` from
``$HOME``, ``.env`` from the current working directory, environment
variables prefixed with ``BINCHECKER_``, and explicit CLI overrides.
The resulting dict is validated by pydantic; on failure the surrounding
loader exits with code ``78`` (``EX_CONFIG``) and a structured
multi-line error.

Only the schema lives here. The precedence resolver, profile overlays,
loader, masked summary, and ``.env`` watcher live in sibling modules
(``profiles.py``, ``loader.py``, ``summary.py``, ``watcher.py``).

Validates: Requirements 5.1, 5.5.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["AppConfig"]


class AppConfig(BaseSettings):
    """Runtime configuration for the binchecker package.

    Field defaults reflect the design's recommended production posture:
    INFO logging, conservative concurrency (10), 24-hour BIN cache TTL,
    English locale, and a three-provider BIN lookup chain. All paths
    default to repository-relative locations so a fresh checkout works
    without configuration.

    Secrets (Stripe keys) are wrapped in :class:`pydantic.SecretStr` so
    they never appear in repr / logs. The masked summary renderer
    (``config/summary.py``) is the only sanctioned way to surface them.
    """

    model_config = SettingsConfigDict(
        env_prefix="BINCHECKER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Network / I/O ---------------------------------------------------
    api_timeout: float = 10.0
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_dir: Path = Path("./logs")
    cache_dir: Path = Path("./.cache/binchecker")
    bin_cache_ttl_hours: int = 24
    concurrency: int = 10

    # --- Profile / locale ------------------------------------------------
    profile: Literal["development", "testing", "production"] = "production"
    locale: Literal["en", "ru"] = "en"

    # --- BIN providers ---------------------------------------------------
    bin_providers: list[str] = Field(
        default_factory=lambda: ["binlist", "handyapi", "bincheck_io"],
    )

    # --- Stripe credentials (optional) ----------------------------------
    stripe_publishable_key: SecretStr | None = None
    stripe_restricted_key: SecretStr | None = None

    # --- Plugins ---------------------------------------------------------
    plugin_paths: list[Path] = Field(default_factory=list)

    # --- Gateway pool ----------------------------------------------------
    gateway_pool_path: Path | None = None
    gateway_pool_update_url: str | None = None

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------
    @field_validator("api_timeout")
    @classmethod
    def _validate_api_timeout(cls, v: float) -> float:
        """Reject timeouts outside the ``(0, 120]`` second window."""
        if not (0 < v <= 120):
            raise ValueError(
                f"api_timeout must be > 0 and <= 120 seconds, got {v!r}"
            )
        return v

    @field_validator("bin_cache_ttl_hours")
    @classmethod
    def _validate_bin_cache_ttl_hours(cls, v: int) -> int:
        """Reject TTLs outside the ``[1, 168]`` hour (1 hour - 1 week) window."""
        if not (1 <= v <= 168):
            raise ValueError(
                f"bin_cache_ttl_hours must be between 1 and 168, got {v!r}"
            )
        return v

    @field_validator("concurrency", mode="before")
    @classmethod
    def _clamp_concurrency(cls, v: Any) -> int:
        """Clamp concurrency into ``[1, 20]`` rather than rejecting it.

        Per the design, the runner enforces a hard upper bound on
        concurrency to protect remote APIs. Clamping (instead of raising)
        keeps the user moving when they pass a value slightly outside
        the supported range.
        """
        try:
            ivalue = int(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"concurrency must be an integer, got {v!r}") from exc
        return max(1, min(20, ivalue))

    @field_validator("plugin_paths", mode="after")
    @classmethod
    def _warn_missing_plugin_paths(cls, v: list[Path]) -> list[Path]:
        """Warn (do not reject) when an optional plugin path is missing.

        The plugin loader is responsible for hard-enforcing existence
        when a path is actually used; here we only surface a developer
        hint via :func:`warnings.warn` so a stray entry does not abort
        config validation.
        """
        for path in v:
            if not path.exists():
                warnings.warn(
                    f"plugin_paths entry does not exist: {path}",
                    stacklevel=2,
                )
        return v

    # ------------------------------------------------------------------
    # Cross-field validators
    # ------------------------------------------------------------------
    @model_validator(mode="after")
    def _check_stripe_key_dependency(self) -> "AppConfig":
        """Restricted key requires a publishable key to be useful.

        The live-check Stripe backend tokenizes via the publishable key
        first; the restricted key is used only for the optional $0
        PaymentIntent confirm path. Allowing a restricted key without a
        publishable one would silently break the primary code path.
        """
        if self.stripe_restricted_key is not None and self.stripe_publishable_key is None:
            raise ValueError(
                "stripe_restricted_key is set but stripe_publishable_key is not; "
                "a publishable key is required for the primary tokenization path"
            )
        return self
