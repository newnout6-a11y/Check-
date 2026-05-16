"""Logging bootstrap for the ``webrecon`` reconnaissance toolkit.

This module exposes :func:`configure_logging`, the single entry point
that wires together :mod:`structlog` and the stdlib :mod:`logging`
module so log records produced anywhere in the system pass through the
same processor chain. The chain in order is:

1. ``structlog.processors.add_log_level`` -- record the severity level.
2. ``structlog.contextvars.merge_contextvars`` -- merge context-bound
   keys (used by callers that bind values via
   :func:`structlog.contextvars.bind_contextvars`).
3. :func:`webrecon.log.correlation.add_request_id_processor` -- inject
   the active request id, if any.
4. ``structlog.processors.TimeStamper`` -- add an ISO-8601 UTC
   timestamp under the ``timestamp`` key.
5. :func:`webrecon.log.redaction.redact_sensitive_processor` -- mask
   API-key prefixes (Stripe / GitHub) and sensitive URL query
   parameters before any renderer sees them.
6. The renderer -- either :class:`structlog.processors.JSONRenderer`
   when ``json_output=True`` or :class:`structlog.dev.ConsoleRenderer`
   for human-readable terminal output.

When ``log_file`` is supplied, a :class:`logging.handlers.RotatingFileHandler`
is installed on the root logger so foreign log records (``httpx``,
``asyncio``, third-party libraries) and structlog records both end up
in the rotated file. Without ``log_file`` the system writes to
``sys.stderr`` via a :class:`logging.StreamHandler`.

The function is idempotent: each call clears any handlers previously
installed by the bootstrap and re-applies a fresh stack, which makes
it safe to invoke during configuration hot-reload or repeated calls
in tests.

Validates: Requirement 7.5 (consistent logging system across all
modules with configurable log levels and output formats).
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import TYPE_CHECKING

import structlog

from webrecon.log.correlation import add_request_id_processor
from webrecon.log.redaction import redact_sensitive_processor

if TYPE_CHECKING:
    from pathlib import Path

    from structlog.stdlib import BoundLogger
    from structlog.typing import Processor

__all__ = ["configure_logging", "get_logger"]


# Marker attribute used to identify handlers installed by this module.
# The bootstrap removes only handlers carrying this attribute on
# subsequent calls so handlers added by application code (e.g. a
# Sentry handler attached during process startup) survive a re-bootstrap.
_HANDLER_MARKER: str = "_webrecon_log_handler"

# Default rotation policy: 10 MB per file, 5 backups (~50 MB cap).
# Aligned with the design's "log files rotate at a bounded size" rule.
_DEFAULT_MAX_BYTES: int = 10 * 1024 * 1024
_DEFAULT_BACKUP_COUNT: int = 5


def _resolve_level(level: str) -> int:
    """Translate a level string to a stdlib logging level integer.

    Accepts the canonical names (``DEBUG``, ``INFO``, ``WARNING``,
    ``ERROR``, ``CRITICAL``) case-insensitively. Falls back to
    :data:`logging.INFO` for unrecognised values; this matches the
    config schema validator's coercion behaviour and means a
    misconfigured ``WEBRECON_LOG_LEVEL`` does not crash the bootstrap.
    """
    if not isinstance(level, str):
        return logging.INFO
    canonical = level.strip().upper()
    resolved = logging.getLevelName(canonical)
    if isinstance(resolved, int):
        return resolved
    return logging.INFO


def _build_processor_chain(json_output: bool) -> list[Processor]:
    """Return the structlog processor chain for the requested renderer.

    The order matches the docstring of this module: level / contextvars
    / request-id / timestamp / redaction / renderer. Putting redaction
    immediately before the renderer guarantees nothing introduced by
    earlier processors (e.g. an exception traceback that mentions an
    API key) escapes the masking step.
    """
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp")
    chain: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        add_request_id_processor,
        timestamper,
        redact_sensitive_processor,
    ]
    renderer: Processor
    if json_output:
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    chain.append(renderer)
    return chain


def _remove_marked_handlers(root: logging.Logger) -> None:
    """Drop only the handlers previously installed by this module."""
    for handler in list(root.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            try:
                handler.close()
            finally:
                root.removeHandler(handler)


def _install_file_handler(
    root: logging.Logger,
    log_file: Path,
    *,
    max_bytes: int,
    backup_count: int,
    formatter: logging.Formatter,
) -> None:
    """Attach a rotating file handler at ``log_file`` to the root logger.

    Creates the parent directory tree if missing so the caller does
    not have to ``mkdir`` ahead of time.
    """
    log_file.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)
    setattr(handler, _HANDLER_MARKER, True)
    root.addHandler(handler)


def _install_stream_handler(
    root: logging.Logger,
    formatter: logging.Formatter,
) -> None:
    """Attach a stderr stream handler to the root logger."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    setattr(handler, _HANDLER_MARKER, True)
    root.addHandler(handler)


def configure_logging(
    *,
    level: str = "INFO",
    json_output: bool = False,
    log_file: Path | None = None,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    backup_count: int = _DEFAULT_BACKUP_COUNT,
) -> None:
    """Configure ``structlog`` and stdlib ``logging`` for the package.

    The function accepts primitives only (no ``AppConfig``) so callers
    that want to derive settings from the validated configuration
    object can do so themselves -- for example::

        from webrecon.config import AppConfig

        cfg = AppConfig.model_validate({})
        configure_logging(level=cfg.log_level, json_output=True,
                          log_file=Path("logs/webrecon.log"))

    Args:
        level: Severity threshold for both structlog and the root
            stdlib logger. Accepts the canonical names case-insensitively.
        json_output: When ``True`` records are rendered as JSON (one
            object per line, sorted keys); when ``False`` records are
            rendered through :class:`structlog.dev.ConsoleRenderer`
            for interactive use.
        log_file: Optional path to a rotated log file. When supplied
            the rotating file handler is installed in addition to the
            stderr handler so records appear in both places. The
            parent directory is created if missing.
        max_bytes: Soft cap on the size of a single log file in bytes.
            Once the active file exceeds this, rotation kicks in.
        backup_count: Number of rotated backups to retain. Older
            files are deleted automatically.
    """
    root_level = _resolve_level(level)

    chain = _build_processor_chain(json_output)
    structlog.configure(
        processors=chain,
        wrapper_class=structlog.make_filtering_bound_logger(root_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    root = logging.getLogger()
    root.setLevel(root_level)

    _remove_marked_handlers(root)

    # Always install a stderr handler so interactive operators see
    # output even when a file is configured. When no file is supplied,
    # this is the only sink.
    _install_stream_handler(root, formatter)

    if log_file is not None:
        _install_file_handler(
            root,
            log_file,
            max_bytes=max_bytes,
            backup_count=backup_count,
            formatter=formatter,
        )


def get_logger(name: str | None = None) -> BoundLogger:
    """Return a :class:`structlog.stdlib.BoundLogger`.

    Wraps :func:`structlog.get_logger` so callers do not need to
    import structlog directly. The returned logger inherits the
    processor chain configured by :func:`configure_logging`; calling
    :func:`get_logger` before :func:`configure_logging` is supported
    -- structlog uses a lazy proxy that picks up the configuration on
    first use.

    Args:
        name: Optional logger name. Conventionally the importing
            module's ``__name__``. ``None`` returns the root webrecon
            logger.

    Returns:
        A bound logger ready to receive ``info``, ``warning``, ...
        calls. Type annotated as :class:`structlog.stdlib.BoundLogger`
        so static type checkers see the stdlib-style method signatures.
    """
    if name is None:
        return structlog.get_logger()  # type: ignore[no-any-return]
    return structlog.get_logger(name)  # type: ignore[no-any-return]
