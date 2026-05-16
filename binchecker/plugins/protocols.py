"""Plugin protocol definitions for binchecker.

This module defines the PEP 544 ``Protocol`` interfaces that third-party
plugins must satisfy in order to integrate with binchecker. Each protocol is
decorated with :func:`typing.runtime_checkable` so that ``isinstance`` checks
can be used at runtime to validate plugin objects discovered via entry
points.

Every protocol exposes an ``api_version`` class attribute. The host
application uses this value to negotiate compatibility with a plugin; plugins
that do not declare a supported version are rejected during discovery.

Validates: Requirements 15.1, 15.2, 15.3.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterable, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - import only for static type checking
    from binchecker.core.models import BINInfo, CardData
    from binchecker.detection.signatures import GatewaySignatures


__all__ = [
    "GatewayDetectorPlugin",
    "CardValidatorPlugin",
    "BINProviderPlugin",
    "ExporterPlugin",
]


# ``ValidationOutcome`` is intentionally kept as ``Any`` for now. The concrete
# shape is owned by the validation subsystem and wiring it in here would
# create an import cycle. Plugins should treat the return value as opaque to
# the host and use the documented validation result types in their own code.
ValidationOutcome = Any


@runtime_checkable
class GatewayDetectorPlugin(Protocol):
    """Plugin that contributes payment-gateway detection signatures."""

    api_version: str = "1"
    name: str

    def signatures(self) -> Iterable["GatewaySignatures"]:
        """Return the gateway signatures contributed by this plugin."""
        ...


@runtime_checkable
class CardValidatorPlugin(Protocol):
    """Plugin that performs validation on a single card."""

    api_version: str = "1"
    name: str

    def validate(self, card: "CardData") -> ValidationOutcome:
        """Validate ``card`` and return a validation outcome."""
        ...


@runtime_checkable
class BINProviderPlugin(Protocol):
    """Plugin that resolves BIN information from a remote or local source."""

    api_version: str = "1"
    name: str

    async def lookup(
        self, bin_code: str, client: Any
    ) -> "BINInfo | None":
        """Look up ``bin_code`` and return :class:`BINInfo` if found."""
        ...


@runtime_checkable
class ExporterPlugin(Protocol):
    """Plugin that registers an exporter for a specific output format."""

    api_version: str = "1"
    format_id: str

    def make_exporter(self, cfg: Any) -> Any:
        """Build and return an exporter instance configured by ``cfg``."""
        ...
