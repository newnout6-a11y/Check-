"""Plugin registry for binchecker.

This module defines the in-memory registry that holds plugins loaded by the
host application. Plugins are dispatched into category-specific lists so the
rest of the system can iterate over only the plugin kinds it cares about
(gateway detectors, card validators, BIN providers, exporters).

The :class:`LoadedPlugin` record bundles metadata captured at discovery time
(category, declared API version, originating entry-point name) alongside the
instantiated plugin object. Registry lists are typed as ``list[Any]`` so the
container does not depend on the plugin protocol module at runtime; the
loader is responsible for ensuring only protocol-conforming instances are
inserted.

Validates: Requirements 15.4, 15.5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["LoadedPlugin", "Registry"]


_VALID_CATEGORIES = frozenset(
    {"gateway_detector", "validator", "bin_provider", "exporter"}
)


@dataclass(frozen=True, slots=True)
class LoadedPlugin:
    """A plugin instance discovered through entry points.

    Attributes:
        name: Human-readable plugin identifier (typically ``instance.name``
            or the originating entry-point name).
        instance: The plugin object itself; satisfies one of the four plugin
            protocols.
        category: One of ``"gateway_detector"``, ``"validator"``,
            ``"bin_provider"``, ``"exporter"``.
        api_version: Plugin-declared API version string. Used by the loader
            to filter incompatible plugins.
        entry_point_name: The ``name`` of the originating
            ``importlib.metadata`` entry point.
    """

    name: str
    instance: Any
    category: str
    api_version: str
    entry_point_name: str


class Registry:
    """Mutable container of loaded plugins, partitioned by category."""

    def __init__(self) -> None:
        self.gateway_detectors: list[Any] = []
        self.validators: list[Any] = []
        self.bin_providers: list[Any] = []
        self.exporters: list[Any] = []

    def add(self, plugin: LoadedPlugin) -> None:
        """Dispatch ``plugin.instance`` into the list matching its category.

        Raises:
            ValueError: If ``plugin.category`` is not a recognised category.
        """
        category = plugin.category
        if category == "gateway_detector":
            self.gateway_detectors.append(plugin.instance)
        elif category == "validator":
            self.validators.append(plugin.instance)
        elif category == "bin_provider":
            self.bin_providers.append(plugin.instance)
        elif category == "exporter":
            self.exporters.append(plugin.instance)
        else:
            raise ValueError(
                f"Unknown plugin category {category!r}; "
                f"expected one of {sorted(_VALID_CATEGORIES)}"
            )

    def as_dict(self) -> dict[str, list[Any]]:
        """Return a snapshot of the registry as plain lists.

        The returned dict contains shallow copies of each category list, so
        callers may mutate the snapshot without affecting the registry.
        """
        return {
            "gateway_detectors": list(self.gateway_detectors),
            "validators": list(self.validators),
            "bin_providers": list(self.bin_providers),
            "exporters": list(self.exporters),
        }
