"""Plugin discovery and compatibility loader for binchecker.

This module reads ``importlib.metadata`` entry points in the
``binchecker.plugins`` group, instantiates the registered objects, classifies
each one against the four plugin protocols defined in
:mod:`binchecker.plugins.protocols`, and returns a :class:`Registry`
containing only plugins compatible with the host's supported API version.

Discovery is fault-tolerant: any exception raised while loading or
instantiating a plugin is logged at WARNING level and the offending entry
point is skipped. The host process is never aborted by a misbehaving plugin.

Validates: Requirements 15.4, 15.5.
"""

from __future__ import annotations

import inspect
import logging
from importlib.metadata import entry_points
from typing import Any

from binchecker.plugins.protocols import (
    BINProviderPlugin,
    CardValidatorPlugin,
    ExporterPlugin,
    GatewayDetectorPlugin,
)
from binchecker.plugins.registry import LoadedPlugin, Registry

__all__ = ["discover_plugins", "load_compatible"]

_logger = logging.getLogger(__name__)


def _classify(instance: Any) -> str | None:
    """Return the registry category for ``instance`` or ``None`` if unknown.

    The protocol checks are ordered from most specific (gateway detector,
    validator, BIN provider) to most generic (exporter); since each protocol
    requires distinct method names this ordering does not produce ambiguity
    in practice.
    """
    if isinstance(instance, GatewayDetectorPlugin):
        return "gateway_detector"
    if isinstance(instance, CardValidatorPlugin):
        return "validator"
    if isinstance(instance, BINProviderPlugin):
        return "bin_provider"
    if isinstance(instance, ExporterPlugin):
        return "exporter"
    return None


def discover_plugins(group: str = "binchecker.plugins") -> list[LoadedPlugin]:
    """Discover and instantiate all plugins registered under ``group``.

    Each entry point is resolved via :meth:`importlib.metadata.EntryPoint.load`.
    Class entry points are instantiated with a no-argument call; non-class
    objects (module-level singletons or factory results) are used as-is.

    Errors raised during discovery, loading, or instantiation result in a
    WARNING log line and the entry point being skipped. The function never
    raises.

    Args:
        group: The entry-point group to scan. Defaults to
            ``"binchecker.plugins"``.

    Returns:
        A list of :class:`LoadedPlugin` records, one per successfully loaded
        and classified entry point.
    """
    try:
        eps = entry_points(group=group)
    except Exception as exc:  # pragma: no cover - defensive
        _logger.warning(
            "Failed to enumerate entry points for group %s: %s", group, exc
        )
        return []

    found: list[LoadedPlugin] = []
    for ep in eps:
        try:
            obj = ep.load()
        except Exception as exc:
            _logger.warning(
                "Failed to load plugin entry point %s (%s): %s",
                ep.name,
                getattr(ep, "value", "?"),
                exc,
            )
            continue

        try:
            instance = obj() if inspect.isclass(obj) else obj
        except Exception as exc:
            _logger.warning(
                "Failed to instantiate plugin %s: %s", ep.name, exc
            )
            continue

        category = _classify(instance)
        if category is None:
            _logger.warning(
                "Plugin %s does not implement any known plugin protocol; "
                "skipping",
                ep.name,
            )
            continue

        found.append(
            LoadedPlugin(
                name=getattr(instance, "name", ep.name),
                instance=instance,
                category=category,
                api_version=getattr(instance, "api_version", ""),
                entry_point_name=ep.name,
            )
        )

    return found


def load_compatible(
    found: list[LoadedPlugin],
    *,
    supported_api_version: str = "1",
) -> Registry:
    """Build a :class:`Registry` containing only API-compatible plugins.

    Plugins whose ``api_version`` differs from ``supported_api_version`` are
    skipped, with one INFO line emitted per skipped plugin. The function
    never raises: malformed registry insertions are logged and skipped so a
    single bad plugin cannot prevent startup.

    Args:
        found: Output of :func:`discover_plugins`.
        supported_api_version: The host's supported plugin API version.

    Returns:
        A :class:`Registry` populated with the compatible plugins.
    """
    registry = Registry()
    for plugin in found:
        if plugin.api_version != supported_api_version:
            _logger.info(
                "Skipping plugin %s (api_version=%s; expected=%s)",
                plugin.name,
                plugin.api_version,
                supported_api_version,
            )
            continue
        try:
            registry.add(plugin)
        except Exception as exc:  # pragma: no cover - defensive
            _logger.warning(
                "Failed to register plugin %s: %s", plugin.name, exc
            )
            continue
    return registry
