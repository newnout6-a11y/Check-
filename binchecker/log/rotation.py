"""Rotating file handler factory for the binchecker logging pipeline.

This module provides :func:`make_rotating_handler`, a thin factory around
:class:`logging.handlers.RotatingFileHandler`. It encapsulates the project's
default rotation policy (5 MB per file, 5 backups) and attaches a structured
formatter that emits the design's standard fields (timestamp, level, logger
name, message). The handler is consumed by :func:`binchecker.log.setup.setup_logging`,
which composes it with a :class:`~binchecker.log.pan_filter.PanRedactionFilter`
on the root logger so every record passes through redaction before reaching disk.

Validates: Requirements 6.4 (log files rotate at a bounded size and bounded
backup count, so disk usage is capped).
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

__all__ = ["make_rotating_handler"]


# Default formatter format string. The design's *Logging Contract on Error*
# (design.md line 931) calls for structured fields rendered as JSON via
# structlog; the stdlib formatter here is the fallback used by the
# RotatingFileHandler when records are not pre-rendered by structlog (e.g.
# logs emitted by third-party libraries that use stdlib logging directly).
_DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def make_rotating_handler(
    log_dir: Path,
    *,
    filename: str = "binchecker.log",
    max_bytes: int = 5_000_000,
    backup_count: int = 5,
) -> RotatingFileHandler:
    """Build a :class:`RotatingFileHandler` writing into ``log_dir``.

    The target directory is created (with parents) if it does not exist, so
    callers can pass a freshly-resolved config path without pre-flight
    ``mkdir`` calls. The returned handler has a :class:`logging.Formatter`
    attached using the project's default structured field layout.

    Args:
        log_dir: Directory in which the log file lives. Created if missing.
        filename: Name of the log file. Defaults to ``"binchecker.log"``.
        max_bytes: Soft cap on the size of a single log file in bytes.
            When exceeded, ``logging`` rotates the file. Defaults to 5 MB.
        backup_count: Number of rotated backups to retain (``filename.1``,
            ``filename.2`` ...). Defaults to 5, matching the design's
            log-rotation cap (Property 31 / Requirement 6.4).

    Returns:
        A configured :class:`RotatingFileHandler` with the default formatter
        attached. The handler does not yet have any filters; the caller is
        responsible for attaching :class:`PanRedactionFilter` to the root
        logger so every handler (including this one) inherits it.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / filename,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT))
    return handler
