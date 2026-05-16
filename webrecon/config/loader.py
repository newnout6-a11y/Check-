"""Hierarchical configuration loader for the ``webrecon`` package.

This module assembles the runtime :class:`~webrecon.config.schema.AppConfig`
instance from a layered set of sources.  Each source contributes values
that override the layer below it; the final dictionary is then handed to
pydantic for validation.

Resolution order, lowest to highest priority::

    1. Field defaults declared on AppConfig and its sub-sections.
    2. ``~/.env`` (home directory) -- optional.
    3. ``./.env`` (current working directory) -- optional.
    4. Process environment variables prefixed ``WEBRECON_``.
    5. Explicit CLI overrides (already-nested ``dict``).

In addition to producing a validated ``AppConfig`` the loader returns a
``resolution`` mapping that records *which* layer supplied the final
value for every leaf field (dotted path -> :class:`ConfigSource`).
That information is consumed by ``webrecon config show`` and by
diagnostics tooling so an operator can answer "where did this value
come from?" without having to re-run a manual bisect.

Behaviour summary:

* Validation failures are surfaced as :class:`ConfigLoadError` with a
  multi-line message listing every offending field (one per line).
  The loader never calls :func:`sys.exit` -- the caller decides how to
  react to a bad configuration.
* Optional API-key fields that fall back to defaults emit a
  :class:`MissingOptionalConfigWarning` once per process so a
  partially-configured deployment is still usable but the operator is
  reminded that downstream features may be unavailable.
* Empty / unset ``WEBRECON_*`` values are coerced to ``None`` by the
  schema's field validators; they are treated as "explicitly unset"
  and therefore do **not** trigger the missing-optional warning.

The module is type-strict (``from __future__ import annotations``), is
clean under ``ruff`` with the project rule set, and passes
``mypy --strict`` against ``mypy.ini``.
"""

from __future__ import annotations

import os
import sys
import warnings
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ``enum.StrEnum`` only exists on Python 3.11+. The version-guarded
# branch below gives mypy (configured with ``python_version = 3.10``)
# a concrete class to type-check against while still preferring the
# stdlib implementation at runtime on 3.11+. Mirrors the same pattern
# used in :mod:`webrecon.core.models`.
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of :class:`enum.StrEnum` for Python 3.10."""

        def __new__(cls, value: str) -> StrEnum:
            obj = str.__new__(cls, value)
            obj._value_ = value
            return obj

        def __str__(self) -> str:
            return str.__str__(self)

from pydantic import BaseModel, ValidationError

from webrecon.config.schema import AppConfig

try:  # python-dotenv is a transitive dependency of pydantic-settings
    from dotenv import dotenv_values as _dotenv_values
except ImportError:  # pragma: no cover -- dotenv is always available in the wheel
    _dotenv_values = None  # type: ignore[assignment]


__all__ = [
    "ConfigLoadError",
    "ConfigSource",
    "LoadedConfig",
    "MissingOptionalConfigWarning",
    "ResolvedField",
    "load_config",
    "merge_dicts",
]


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class ConfigSource(StrEnum):
    """Origin of a resolved configuration value.

    Members are ordered from lowest to highest precedence.  The string
    values are stable identifiers that can be safely surfaced in logs,
    diagnostics, and CLI output.
    """

    DEFAULT = "default"
    ENV_FILE_HOME = "env_file_home"
    ENV_FILE_CWD = "env_file_cwd"
    ENV_VARS = "env_vars"
    CLI_ARGS = "cli_args"


@dataclass(frozen=True)
class ResolvedField:
    """A single resolved field with its origin annotation.

    The loader does not currently return a list of these directly --
    it returns a flat ``resolution`` mapping inside :class:`LoadedConfig`
    -- but this dataclass exists as a convenient public type for
    callers that want to iterate over resolved fields with strong
    typing.
    """

    name: str
    value: Any
    source: ConfigSource


@dataclass
class LoadedConfig:
    """Result of :func:`load_config`.

    Attributes:
        config:     The validated :class:`AppConfig` instance.
        resolution: Mapping of dotted leaf paths (e.g. ``"api_keys.shodan"``)
                    to the :class:`ConfigSource` that supplied the
                    final value for that leaf.
    """

    config: AppConfig
    resolution: dict[str, ConfigSource] = field(default_factory=dict)


class ConfigLoadError(RuntimeError):
    """Raised when configuration validation fails.

    The exception's string form is a multi-line, human-readable summary
    listing every validator violation discovered by pydantic.  The
    original :class:`pydantic.ValidationError` is attached as
    ``__cause__`` so callers that want structured access to the errors
    (e.g. for JSON-formatted CLI output) can still reach them.
    """


class MissingOptionalConfigWarning(UserWarning):
    """Warning category emitted for absent optional configuration values.

    Subclasses :class:`UserWarning` so callers can selectively filter
    these warnings via :func:`warnings.simplefilter`.
    """


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Mirrors ``AppConfig.model_config["env_prefix"]`` and
# ``env_nested_delimiter`` from :mod:`webrecon.config.schema`.  Defined
# here as module-level constants because the loader walks raw mappings
# (e.g. ``os.environ``) before pydantic has a chance to interpret them.
_ENV_PREFIX = "WEBRECON_"
_ENV_NESTED_DELIM = "__"


# Optional fields that, when absent, indicate a feature will be
# unavailable.  Each entry is a dotted path into the resolved
# ``AppConfig``.  Surfaced via :class:`MissingOptionalConfigWarning`.
_OPTIONAL_API_KEY_PATHS: tuple[str, ...] = (
    "api_keys.fofa",
    "api_keys.shodan",
    "api_keys.serper",
    "api_keys.github",
    "api_keys.stripe",
)


# Process-lifetime dedup set for missing-optional warnings.  Reset by
# tests via ``monkeypatch.setattr`` when fresh state is required.
_warned_missing_paths: set[str] = set()


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def merge_dicts(
    base: Mapping[str, Any],
    overlay: Mapping[str, Any],
) -> dict[str, Any]:
    """Deep-merge ``overlay`` over ``base``.

    Rules:

    * If a key exists in both layers and both values are mappings,
      recurse.
    * Otherwise, the overlay wins (including when the overlay value is
      ``None`` -- explicit ``None`` is treated as a deliberate
      override, not a no-op).

    Returns a freshly-allocated ``dict``; neither input is mutated.
    """
    result: dict[str, Any] = dict(base)
    for key, overlay_value in overlay.items():
        existing = result.get(key)
        if isinstance(existing, Mapping) and isinstance(overlay_value, Mapping):
            result[key] = merge_dicts(existing, overlay_value)
        else:
            result[key] = overlay_value
    return result


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a ``.env`` file into a flat ``dict[str, str]``.

    Uses :mod:`dotenv` when available so the parser handles quoted
    values, escapes, and inline comments the same way pydantic-settings
    does.  Falls back to a minimal hand-rolled parser only if the
    optional dependency is missing.

    Returns an empty dict when the file does not exist; missing files
    are not an error -- they are simply an empty layer.
    """
    if not path.is_file():
        return {}

    if _dotenv_values is not None:
        raw = _dotenv_values(str(path))
        return {k: v for k, v in raw.items() if v is not None}

    # Fallback parser: covers the common ``KEY=VALUE`` / ``KEY="VALUE"``
    # forms.  This branch is exercised only when python-dotenv is not
    # installed, which never happens in our pinned deployments.
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    return result


def _flat_env_to_nested(flat: Mapping[str, str]) -> dict[str, Any]:
    """Convert prefixed flat keys to a nested dictionary.

    ``WEBRECON_API_KEYS__SHODAN=xxx`` maps to
    ``{"api_keys": {"shodan": "xxx"}}``.  Keys that do not start with
    the configured prefix are dropped so foreign environment variables
    cannot pollute the resolved configuration.

    A non-mapping intermediate (e.g. an env var that tries to write
    into a leaf already set by another env var with shallower nesting)
    is replaced rather than treated as an error: pydantic-settings
    behaves the same way and we preserve the contract.
    """
    nested: dict[str, Any] = {}
    for raw_key, value in flat.items():
        if not raw_key.startswith(_ENV_PREFIX):
            continue
        rest = raw_key[len(_ENV_PREFIX) :]
        if not rest:
            continue
        parts = [segment for segment in rest.lower().split(_ENV_NESTED_DELIM) if segment]
        if not parts:
            continue
        cursor: dict[str, Any] = nested
        for segment in parts[:-1]:
            existing = cursor.get(segment)
            if not isinstance(existing, dict):
                existing = {}
                cursor[segment] = existing
            cursor = existing
        cursor[parts[-1]] = value
    return nested


def _walk_leaves(data: Mapping[str, Any], prefix: str = "") -> Iterator[str]:
    """Yield dotted leaf paths for every non-mapping value in ``data``."""
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, Mapping):
            yield from _walk_leaves(value, path)
        else:
            yield path


def _path_present(path: str, layer: Mapping[str, Any]) -> bool:
    """Return ``True`` iff ``layer`` contains the exact dotted ``path``.

    A path "a.b.c" is considered present only if ``layer["a"]["b"]["c"]``
    can be resolved by ``Mapping`` lookups; intermediate non-mapping
    values cause the lookup to short-circuit to ``False``.
    """
    cursor: Any = layer
    for segment in path.split("."):
        if not isinstance(cursor, Mapping) or segment not in cursor:
            return False
        cursor = cursor[segment]
    return True


def _build_resolution(
    final: Mapping[str, Any],
    layers_high_to_low: Iterable[tuple[ConfigSource, Mapping[str, Any]]],
) -> dict[str, ConfigSource]:
    """Attribute every leaf of ``final`` to the highest-priority layer that wrote it.

    Walks the merged dictionary's leaves once, then for each leaf
    scans the supplied layers from highest to lowest precedence and
    records the first match.  The defaults layer is the canonical
    floor and must always be supplied last so every leaf receives an
    attribution.
    """
    layers = list(layers_high_to_low)
    resolution: dict[str, ConfigSource] = {}
    for path in _walk_leaves(final):
        for source, layer in layers:
            if _path_present(path, layer):
                resolution[path] = source
                break
    return resolution


def _format_validation_error(error: ValidationError) -> str:
    """Render a :class:`ValidationError` as a multi-line, structured message."""
    issues = error.errors()
    header = (
        f"Configuration validation failed with {len(issues)} error(s):"
        if issues
        else "Configuration validation failed."
    )
    lines = [header]
    for issue in issues:
        loc_parts = [str(part) for part in issue.get("loc", ())]
        loc = ".".join(loc_parts) if loc_parts else "<root>"
        msg = issue.get("msg", "<no message>")
        type_ = issue.get("type", "")
        suffix = f" [type={type_}]" if type_ else ""
        lines.append(f"  - {loc}: {msg}{suffix}")
    return "\n".join(lines)


def _resolve_attribute(config: AppConfig, dotted_path: str) -> Any:
    """Walk a dotted attribute path on the resolved :class:`AppConfig`."""
    cursor: Any = config
    for attr in dotted_path.split("."):
        if cursor is None:
            return None
        cursor = getattr(cursor, attr, None)
    return cursor


def _emit_missing_optional_warnings(
    config: AppConfig,
    resolution: Mapping[str, ConfigSource],
) -> None:
    """Warn -- once per process per path -- about absent optional fields.

    A field is considered "absent" when both:

    1. its resolved value is ``None``, and
    2. the resolution attribution is :attr:`ConfigSource.DEFAULT`.

    The second condition is what implements the "do not warn for fields
    explicitly set to ``None``" rule from the spec: when the operator
    sets ``WEBRECON_API_KEYS__SHODAN=`` (empty), the value normalises
    to ``None`` but the resolution will be :attr:`ConfigSource.ENV_VARS`,
    so we stay silent.
    """
    for path in _OPTIONAL_API_KEY_PATHS:
        if path in _warned_missing_paths:
            continue
        if resolution.get(path) is not ConfigSource.DEFAULT:
            continue
        if _resolve_attribute(config, path) is not None:
            continue
        _warned_missing_paths.add(path)
        warnings.warn(
            (
                f"Optional configuration value '{path}' is not set; "
                "features that depend on it will be unavailable. "
                f"Set it via the {_ENV_PREFIX}{path.upper().replace('.', _ENV_NESTED_DELIM)} "
                "environment variable, a .env file, or a CLI override to silence this warning."
            ),
            MissingOptionalConfigWarning,
            stacklevel=3,
        )


def _compute_defaults() -> dict[str, Any]:
    """Compute the defaults layer without consulting any settings source.

    ``AppConfig`` is a :class:`pydantic_settings.BaseSettings` subclass,
    so calling ``AppConfig.model_validate({})`` would still pick up
    ``WEBRECON_*`` environment variables and ``.env`` files.  That is
    exactly what the loader is trying to compose manually, so the
    defaults layer must be derived from the field declarations alone.

    The walk descends into :class:`pydantic.BaseModel` sub-sections so
    nested defaults (e.g. ``api_keys.shodan == None``) end up in the
    resulting dict at their dotted location.  Non-model leaves are
    materialised via ``default`` / ``default_factory``; missing
    defaults yield ``None`` so the resulting dict still has full
    coverage and the resolution attribution stays consistent.
    """

    def _walk(model_cls: type[BaseModel]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, info in model_cls.model_fields.items():
            annotation = info.annotation
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                result[name] = _walk(annotation)
                continue
            if info.default_factory is not None:
                result[name] = info.default_factory()  # type: ignore[call-arg]
            elif info.default is not None:
                result[name] = info.default
            else:
                result[name] = None
        return result

    raw = _walk(AppConfig)

    # Sub-section default factories (e.g. ``ApiKeys``, ``DatabaseSettings``)
    # produce ``BaseModel`` instances rather than plain dicts.  Normalise
    # the whole tree so the merged dict only contains primitives.
    def _normalise(value: Any) -> Any:
        if isinstance(value, BaseModel):
            return {k: _normalise(v) for k, v in value.model_dump(mode="python").items()}
        if isinstance(value, Mapping):
            return {k: _normalise(v) for k, v in value.items()}
        return value

    return _normalise(raw)  # type: ignore[no-any-return]


def load_config(
    *,
    cli_overrides: Mapping[str, Any] | None = None,
    cwd: Path | None = None,
    home: Path | None = None,
) -> LoadedConfig:
    """Build a validated :class:`AppConfig` from the layered priority chain.

    Args:
        cli_overrides: Already-nested mapping of CLI overrides.  Pass
            ``{"api_keys": {"shodan": "..."}}`` to override
            ``api_keys.shodan``; pass ``None`` (the default) when no
            CLI overrides apply.
        cwd: Directory to search for a ``./.env`` file.  Defaults to
            :func:`Path.cwd`.  Tests can supply a temporary path to
            keep the loader hermetic.
        home: Directory to search for a ``~/.env`` file.  Defaults to
            :func:`Path.home`.  Tests can supply a temporary path.

    Returns:
        A :class:`LoadedConfig` containing the validated configuration
        and the per-leaf resolution mapping.

    Raises:
        ConfigLoadError: When pydantic validation rejects the merged
            configuration.  The exception message lists every offending
            field on its own line.

    Side effects:
        Emits :class:`MissingOptionalConfigWarning` once per process
        per missing optional API-key path.
    """
    effective_cwd = cwd if cwd is not None else Path.cwd()
    effective_home = home if home is not None else Path.home()
    cli_layer: dict[str, Any] = dict(cli_overrides) if cli_overrides else {}

    # Layer 1: defaults.  We walk the field declarations rather than
    # calling ``AppConfig.model_validate({})`` because BaseSettings
    # would still consult ``WEBRECON_*`` env vars and the project
    # ``.env`` file.  The loader composes that chain manually below.
    defaults_layer: dict[str, Any] = _compute_defaults()

    # Layer 2: ~/.env
    home_layer = _flat_env_to_nested(_parse_env_file(effective_home / ".env"))

    # Layer 3: ./.env
    cwd_layer = _flat_env_to_nested(_parse_env_file(effective_cwd / ".env"))

    # Layer 4: process environment.
    env_layer = _flat_env_to_nested(os.environ)

    # Layer 5: explicit CLI overrides.
    # (No transformation -- callers pass an already-nested dict.)

    merged: dict[str, Any] = defaults_layer
    merged = merge_dicts(merged, home_layer)
    merged = merge_dicts(merged, cwd_layer)
    merged = merge_dicts(merged, env_layer)
    merged = merge_dicts(merged, cli_layer)

    # Compute resolution against the merged dict so attribution always
    # reflects what actually ended up in the validated config.  The
    # defaults layer is the floor and is consulted last; every leaf in
    # ``merged`` should match at least the defaults (or a higher
    # layer), so every entry receives an attribution.
    resolution = _build_resolution(
        merged,
        layers_high_to_low=[
            (ConfigSource.CLI_ARGS, cli_layer),
            (ConfigSource.ENV_VARS, env_layer),
            (ConfigSource.ENV_FILE_CWD, cwd_layer),
            (ConfigSource.ENV_FILE_HOME, home_layer),
            (ConfigSource.DEFAULT, defaults_layer),
        ],
    )

    try:
        config = AppConfig.model_validate(merged)
    except ValidationError as exc:
        raise ConfigLoadError(_format_validation_error(exc)) from exc

    _emit_missing_optional_warnings(config, resolution)

    return LoadedConfig(config=config, resolution=resolution)
