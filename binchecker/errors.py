"""Typed exception hierarchy and exit-code mapping for binchecker.

This module defines the full error hierarchy used across the package so that
callers (CLI, plugins, batch workers) can branch on category without parsing
strings, and so that the process exit code can be derived deterministically
from the raised exception.

All exception classes derive from :class:`BinCheckerError` and carry a
structured payload (``self.payload``) suitable for log serialization. The
:func:`exit_code_for` helper maps any exception to a process exit code from
:data:`EXIT_CODES`.

Validates: Requirements 6.1, 6.3
"""

from __future__ import annotations

from typing import Any

__all__ = [
    # Root
    "BinCheckerError",
    # Config
    "ConfigError",
    "ConfigValidationError",
    "ConfigSourceError",
    # Network
    "NetworkError",
    "ProviderError",
    "InsecureUrlError",
    # Validation
    "ValidationError",
    "LuhnError",
    "BrandError",
    "ExpiryError",
    "CvvError",
    "BatchInputFormatError",
    # Lookup
    "LookupError",
    "BINLookupError",
    "LiveCheckError",
    "BackendError",
    "DeclineError",
    # Export
    "ExportError",
    "UnsupportedFormatError",
    "TemplateValidationError",
    "IntegrityError",
    # Plugins
    "PluginError",
    "PluginCompatibilityError",
    "PluginLoadError",
    # Exit-code helpers
    "EXIT_CODES",
    "EXIT_CODES_BY_EXCEPTION",
    "exit_code_for",
]


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


class BinCheckerError(Exception):
    """Root of the binchecker exception hierarchy.

    Subclasses inherit a uniform constructor that accepts a human-readable
    ``message`` plus arbitrary keyword payload. The payload is stored on
    ``self.payload`` and surfaced through :meth:`to_dict` so loggers can emit
    structured records without any per-exception serialization code.
    """

    def __init__(self, message: str = "", **payload: Any) -> None:
        super().__init__(message)
        self.payload: dict[str, Any] = dict(payload)

    def to_dict(self) -> dict[str, Any]:
        """Return a structured representation suitable for log serialization."""
        return {
            "error_type": self.__class__.__name__,
            "message": str(self),
            **self.payload,
        }


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class ConfigError(BinCheckerError):
    """Base class for configuration-related failures."""


class ConfigValidationError(ConfigError):
    """Raised when configuration values fail schema or range validation."""


class ConfigSourceError(ConfigError):
    """Raised when a configuration source (file, env) cannot be read or parsed."""


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


class NetworkError(BinCheckerError):
    """Base class for network-related failures."""


class ProviderError(NetworkError):
    """Transient provider-side failure (timeout, 5xx, rate limit)."""


class InsecureUrlError(NetworkError):
    """Raised when a non-HTTPS URL is used in a profile that forbids it."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(BinCheckerError):
    """Base class for input/card validation failures."""


class LuhnError(ValidationError):
    """PAN failed the Luhn check."""


class BrandError(ValidationError):
    """PAN does not match a known brand or violates brand-length rules."""


class ExpiryError(ValidationError):
    """Expiry month/year is invalid or in the past."""


class CvvError(ValidationError):
    """CVV is malformed for the detected brand."""


class BatchInputFormatError(ValidationError):
    """Batch input file is malformed or uses an unsupported encoding."""


# ---------------------------------------------------------------------------
# Lookup / live check
# ---------------------------------------------------------------------------


# NOTE: This intentionally shadows :class:`builtins.LookupError`. The package
# uses its own ``LookupError`` for BIN/live-check lookup failures and does NOT
# inherit from the builtin so the hierarchy stays anchored at
# :class:`BinCheckerError`. If you need the builtin, import it as
# ``builtins.LookupError``.
class LookupError(BinCheckerError):  # noqa: A001 - deliberate shadow of builtin
    """Base class for lookup-related failures (BIN, live check)."""


class BINLookupError(LookupError):
    """Raised when every BIN provider in the chain has been exhausted."""


class LiveCheckError(LookupError):
    """Base class for live-check failures."""


class BackendError(LiveCheckError):
    """Live-check backend (Stripe, Braintree, WC Store API) returned an error."""


class DeclineError(LiveCheckError):
    """Card was declined.

    Note: the pipeline encodes declines into ``LiveCheckResult`` rather than
    raising, so this class is reserved for callers that opt into raising.
    """


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class ExportError(BinCheckerError):
    """Base class for export/reporting failures."""


class UnsupportedFormatError(ExportError):
    """Requested export format has no registered exporter."""


class TemplateValidationError(ExportError):
    """Jinja template failed pre-render validation."""


class IntegrityError(ExportError):
    """Export integrity check (record count, checksum) failed."""


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------


class PluginError(BinCheckerError):
    """Base class for plugin-related failures."""


class PluginCompatibilityError(PluginError):
    """Plugin advertises an incompatible API version (logged, not raised)."""


class PluginLoadError(PluginError):
    """Plugin entry point could not be imported or instantiated."""


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


# Symbolic exit-code table. Values follow the BSD ``sysexits.h`` conventions
# where applicable so the binary integrates cleanly with shell pipelines.
EXIT_CODES: dict[str, int] = {
    "OK": 0,
    "GENERAL_ERROR": 1,
    "VALIDATION_ERROR": 2,
    "USAGE_ERROR": 64,
    "DATA_ERROR": 65,
    "NO_INPUT": 66,
    "UNAVAILABLE": 69,
    "CONFIG_ERROR": 78,
}


# Direct exception-class to exit-code mapping. ``exit_code_for`` is the
# preferred entry point because it honours the inheritance chain via
# ``isinstance`` checks; this dict is exposed for tooling that needs the
# explicit table.
EXIT_CODES_BY_EXCEPTION: dict[type[BaseException], int] = {
    # Config family -> 78
    ConfigError: EXIT_CODES["CONFIG_ERROR"],
    ConfigValidationError: EXIT_CODES["CONFIG_ERROR"],
    ConfigSourceError: EXIT_CODES["CONFIG_ERROR"],
    # Batch input format -> 65 (more specific than ValidationError)
    BatchInputFormatError: EXIT_CODES["DATA_ERROR"],
    # Validation family -> 2
    ValidationError: EXIT_CODES["VALIDATION_ERROR"],
    LuhnError: EXIT_CODES["VALIDATION_ERROR"],
    BrandError: EXIT_CODES["VALIDATION_ERROR"],
    ExpiryError: EXIT_CODES["VALIDATION_ERROR"],
    CvvError: EXIT_CODES["VALIDATION_ERROR"],
    # Everything else under the root falls through to GENERAL_ERROR.
    BinCheckerError: EXIT_CODES["GENERAL_ERROR"],
}


def exit_code_for(exc: BaseException) -> int:
    """Return the process exit code that corresponds to ``exc``.

    The mapping is layered most-specific-first so subclasses that should map
    to a distinct code (e.g. :class:`BatchInputFormatError` -> 65) win over
    their more general parents (:class:`ValidationError` -> 2).
    Non-:class:`BinCheckerError` exceptions map to ``GENERAL_ERROR``.
    """
    if isinstance(exc, ConfigError):
        return EXIT_CODES["CONFIG_ERROR"]
    if isinstance(exc, BatchInputFormatError):
        return EXIT_CODES["DATA_ERROR"]
    if isinstance(exc, ValidationError):
        return EXIT_CODES["VALIDATION_ERROR"]
    if isinstance(exc, BinCheckerError):
        return EXIT_CODES["GENERAL_ERROR"]
    return EXIT_CODES["GENERAL_ERROR"]
