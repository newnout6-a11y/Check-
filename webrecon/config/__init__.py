"""Configuration package for the ``webrecon`` reconnaissance toolkit.

Public API:

* :class:`AppConfig` -- root configuration model.
* :class:`ApiKeys`, :class:`FofaCredentials`, :class:`ConcurrencySettings`,
  :class:`RateLimitSettings`, :class:`DatabaseSettings`,
  :class:`SafetySettings` -- typed sub-sections.
* :func:`get_default_config` -- factory that returns an ``AppConfig``
  with field defaults only (no environment / ``.env`` lookup).
* :func:`load_config` -- hierarchical loader that merges defaults,
  ``~/.env``, ``./.env``, ``WEBRECON_*`` env vars, and CLI overrides
  into a validated :class:`AppConfig` plus a per-leaf resolution map.
* :class:`LoadedConfig`, :class:`ConfigSource`, :class:`ResolvedField`
  -- result types produced by :func:`load_config`.
* :class:`ConfigLoadError` -- raised when validation fails.
* :class:`MissingOptionalConfigWarning` -- emitted once per absent
  optional API-key field.
"""

from webrecon.config.loader import (
    ConfigLoadError,
    ConfigSource,
    LoadedConfig,
    MissingOptionalConfigWarning,
    ResolvedField,
    load_config,
    merge_dicts,
)
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

__all__ = [
    "ApiKeys",
    "AppConfig",
    "ConcurrencySettings",
    "ConfigLoadError",
    "ConfigSource",
    "DatabaseSettings",
    "FofaCredentials",
    "LoadedConfig",
    "MissingOptionalConfigWarning",
    "RateLimitSettings",
    "ResolvedField",
    "SafetySettings",
    "get_default_config",
    "load_config",
    "merge_dicts",
]
