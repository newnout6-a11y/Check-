"""Configuration profile overlays for development, testing, and production.

This module defines built-in configuration profiles that apply environment-specific
defaults BEFORE values from ``.env`` files, environment variables, and CLI overrides
are layered on top by :mod:`binchecker.config.loader`.

Profiles supply sensible per-environment baselines (logging verbosity, BIN cache
TTL, concurrency) without requiring the operator to repeat them in every
``.env``. The loader deep-merges the chosen profile overlay into the effective
configuration dictionary, where downstream layers may still override individual
keys.

Validates: Requirement 5.8 - "THE System SHALL support configuration profiles
(development, testing, production) with environment-specific overrides and
validation rules".
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

__all__ = [
    "DEVELOPMENT_PROFILE",
    "TESTING_PROFILE",
    "PRODUCTION_PROFILE",
    "PROFILES",
    "get_profile_overlay",
    "apply_profile_overlay",
]


# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

#: Development overlay: verbose logging, short cache TTL, low concurrency for
#: easier local debugging.
DEVELOPMENT_PROFILE: dict[str, Any] = {
    "log_level": "DEBUG",
    "bin_cache_ttl_hours": 1,
    "concurrency": 2,
    "profile": "development",
}

#: Testing overlay: quiet logs, single-threaded, short cache to avoid stale
#: data leaking across test runs.
TESTING_PROFILE: dict[str, Any] = {
    "log_level": "WARNING",
    "bin_cache_ttl_hours": 1,
    "concurrency": 1,
    "profile": "testing",
}

#: Production overlay: standard log level, long cache TTL.
PRODUCTION_PROFILE: dict[str, Any] = {
    "log_level": "INFO",
    "bin_cache_ttl_hours": 24,
    "profile": "production",
}

#: Registry mapping profile names to their overlay dictionaries.
PROFILES: dict[str, dict[str, Any]] = {
    "development": DEVELOPMENT_PROFILE,
    "testing": TESTING_PROFILE,
    "production": PRODUCTION_PROFILE,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_profile_overlay(name: str) -> dict[str, Any]:
    """Return a deep copy of the overlay dict for the named profile.

    Parameters
    ----------
    name:
        Profile name. Must be one of the keys in :data:`PROFILES`.

    Returns
    -------
    dict[str, Any]
        A deep-copied overlay dictionary safe for the caller to mutate.

    Raises
    ------
    ConfigError
        If ``name`` is not a registered profile. The message lists the valid
        profile names so callers can correct misconfiguration quickly.
    """
    # Lazy import keeps this module importable even before
    # ``binchecker.errors`` is available (e.g. during partial bootstrap).
    try:
        from binchecker.errors import ConfigError
    except ImportError:  # pragma: no cover - defensive bootstrap fallback
        class ConfigError(Exception):  # type: ignore[no-redef]
            """Local fallback used only when ``binchecker.errors`` is unavailable."""

    if name not in PROFILES:
        valid = ", ".join(sorted(PROFILES))
        raise ConfigError(
            f"Unknown configuration profile: {name!r}. Valid profiles: {valid}."
        )
    return deepcopy(PROFILES[name])


def apply_profile_overlay(
    base: dict[str, Any], profile_name: str
) -> dict[str, Any]:
    """Return ``base`` deep-merged with the overlay for ``profile_name``.

    Profile values take precedence over ``base`` values for keys that exist in
    the overlay. Keys present only in ``base`` are preserved unchanged. Nested
    dictionaries are merged recursively; non-dict values from the overlay
    replace the corresponding values in ``base`` wholesale.

    Parameters
    ----------
    base:
        Existing configuration dictionary (e.g. builtin defaults). Not
        mutated.
    profile_name:
        Profile to overlay on top of ``base``.

    Returns
    -------
    dict[str, Any]
        A new dictionary representing the merged configuration.

    Raises
    ------
    ConfigError
        Propagated from :func:`get_profile_overlay` when ``profile_name`` is
        unknown.
    """
    overlay = get_profile_overlay(profile_name)
    merged = deepcopy(base)
    _deep_merge(merged, overlay)
    return merged


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> None:
    """Recursively merge ``source`` into ``target`` in place.

    For overlapping keys whose values are both dicts, recurse. Otherwise the
    value from ``source`` replaces the value in ``target``.
    """
    for key, src_val in source.items():
        if (
            key in target
            and isinstance(target[key], dict)
            and isinstance(src_val, dict)
        ):
            _deep_merge(target[key], src_val)
        else:
            target[key] = deepcopy(src_val)
