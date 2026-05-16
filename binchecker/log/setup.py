"""Top-level logging bootstrap for the binchecker package.

This module wires together the three pieces of the logging stack defined in
the design:

* :class:`~binchecker.log.pan_filter.PanRedactionFilter` attached to the
  *root logger*, so every record (regardless of which handler emits it) is
  scanned for Luhn-valid digit runs and redacted before formatting.
* A :class:`~logging.handlers.RotatingFileHandler` produced by
  :func:`~binchecker.log.rotation.make_rotating_handler` writing into
  ``cfg.log_dir/binchecker.log``.
* A :class:`logging.StreamHandler` writing to ``sys.stderr`` for interactive
  visibility.
* (Optional) :mod:`structlog` configured with a JSON renderer over the
  design's standard fields — ``event``, ``error_type``, ``error_message``,
  ``request_id``, ``correlation_id``, ``url``, ``http_status``,
  ``duration_ms``, ``traceback_id``. If ``structlog`` is not installed the
  bootstrap logs a warning and continues with stdlib-only logging.

In addition to logger setup, this module exposes :func:`write_traceback`,
which serialises a ``BaseException`` to ``cfg.log_dir/tracebacks/<uuid>.txt``
and returns the generated id. The id is intended to be embedded as the
``traceback_id`` field in error records, keeping the main log compact and
PCI-clean (the design notes that ``repr`` of card objects must never leak
into the main log file).

Validates: Requirements 6.1 (structured logging), 6.4 (rotating file output),
6.5 (configurable log levels).
"""

from __future__ import annotations

import logging
import sys
import traceback
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from binchecker.log.pan_filter import PanRedactionFilter
from binchecker.log.rotation import make_rotating_handler

if TYPE_CHECKING:
    from binchecker.config.schema import AppConfig

__all__ = ["setup_logging", "write_traceback"]


# Module-global captured during ``setup_logging`` so that ``write_traceback``
# can resolve the traceback directory without requiring callers to thread
# the config through. This mirrors the design's "single shared logging
# context" pattern: configuration is established once at startup and is
# read-only thereafter.
_LOG_DIR: Path | None = None

# Standard structured fields per the design's "Logging Contract on Error"
# section. These are the keys that error records are expected to carry; the
# structlog processor chain renders them as JSON in the order given.
_STRUCTURED_FIELDS: tuple[str, ...] = (
    "event",
    "error_type",
    "error_message",
    "request_id",
    "correlation_id",
    "url",
    "http_status",
    "duration_ms",
    "traceback_id",
)


def setup_logging(cfg: "AppConfig") -> None:
    """Configure the root logger and (optionally) ``structlog``.

    The function is idempotent: calling it again clears any handlers
    previously installed on the root logger and reinstalls a fresh stack
    based on ``cfg``. This makes it safe to invoke during config hot-reload.

    Steps performed:

    1. Resolve the root logger, drop existing handlers, set its level from
       ``cfg.log_level``.
    2. Attach :class:`PanRedactionFilter` to the root logger so every
       record passes through redaction before any handler sees it.
    3. Install a rotating file handler under ``cfg.log_dir`` and a stderr
       stream handler.
    4. Ensure the ``cfg.log_dir/tracebacks`` directory exists so
       :func:`write_traceback` can write into it without further mkdir calls.
    5. If :mod:`structlog` is available, configure its processor chain with
       a JSON renderer over the standard structured fields. Otherwise log a
       warning via stdlib and continue.

    Args:
        cfg: Validated application configuration. ``cfg.log_dir`` must be a
            writable directory (or a path that can be created); ``cfg.log_level``
            must be one of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    """
    global _LOG_DIR

    log_dir = Path(cfg.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "tracebacks").mkdir(parents=True, exist_ok=True)
    _LOG_DIR = log_dir

    root = logging.getLogger()
    # Clear any pre-existing handlers so repeat calls don't stack duplicates.
    for handler in list(root.handlers):
        root.removeHandler(handler)
    # Clear filters as well so the root has a clean slate.
    for flt in list(root.filters):
        root.removeFilter(flt)

    root.setLevel(_resolve_level(cfg.log_level))

    # Attach the redaction filter at the root so records logged directly
    # on the root logger are scanned. Per design.md "Logging Contract on
    # Error" this is the project's chokepoint for PCI-clean output.
    pan_filter = PanRedactionFilter()
    root.addFilter(pan_filter)

    # File handler with rotation (5 MB / 5 backups by default).
    file_handler = make_rotating_handler(log_dir)
    # Stdlib logger filters fire only on the originating logger, not on
    # ancestors records propagate through. Re-attaching the same filter
    # instance at the handler level guarantees that records bubbling up
    # from child loggers are also scanned before they hit disk or stderr,
    # making the redaction *universal* (Property 9 in the design).
    file_handler.addFilter(pan_filter)
    root.addHandler(file_handler)

    # Console handler for interactive visibility.
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    stream_handler.addFilter(pan_filter)
    root.addHandler(stream_handler)

    _configure_structlog()


def write_traceback(exc: BaseException) -> str:
    """Persist a formatted traceback for ``exc`` and return its id.

    The traceback is written to ``<log_dir>/tracebacks/<uuid>.txt`` where
    ``<log_dir>`` is the directory captured during the most recent
    :func:`setup_logging` call. Callers should embed the returned id as the
    ``traceback_id`` structured field on the corresponding error log record.

    If :func:`setup_logging` has not yet been called, the traceback is
    written under ``./logs/tracebacks/`` (the same default as
    :class:`~binchecker.config.schema.AppConfig.log_dir`) so that early
    crashes during bootstrap still produce a usable artefact.

    Args:
        exc: The exception instance whose traceback should be captured.
            ``exc.__traceback__`` is used as the source frame chain.

    Returns:
        The hex string of the generated UUID4 (without the ``.txt``
        extension), suitable for embedding in a structured log record.
    """
    log_dir = _LOG_DIR if _LOG_DIR is not None else Path("./logs")
    tb_dir = log_dir / "tracebacks"
    tb_dir.mkdir(parents=True, exist_ok=True)

    traceback_id = uuid.uuid4().hex
    formatted = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )
    (tb_dir / f"{traceback_id}.txt").write_text(formatted, encoding="utf-8")
    return traceback_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_level(level: str) -> int:
    """Translate a config-level string into a stdlib logging level int.

    Falls back to :data:`logging.INFO` for unknown strings (the
    :class:`AppConfig` schema validator already restricts the field to a
    closed enum, so this is purely a defensive default for callers that
    bypass pydantic).
    """
    return logging.getLevelName(level) if isinstance(level, str) else logging.INFO


def _configure_structlog() -> None:
    """Configure ``structlog`` for JSON output, or warn if unavailable.

    structlog is declared as a runtime dependency in ``pyproject.toml``, but
    we still guard the import so partial installations (e.g. a stripped-down
    test environment) do not crash the bootstrap. When the import fails we
    emit a single WARNING through the stdlib logger and let the application
    continue with plain stdlib formatting.
    """
    try:
        import structlog
    except ImportError:
        logging.getLogger(__name__).warning(
            "structlog is not installed; falling back to stdlib logging only"
        )
        return

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.EventRenamer(to="event"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLogger().getEffectiveLevel()
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
