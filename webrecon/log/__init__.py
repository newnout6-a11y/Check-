"""Structured logging package for the ``webrecon`` reconnaissance toolkit.

Provides:

* :func:`configure_logging` -- bootstrap entry point that wires together
  ``structlog`` and the stdlib ``logging`` module so foreign log records
  (e.g. from :mod:`httpx`, :mod:`asyncio`) and structlog records share
  the same processor chain (timestamp, level, logger name, request-id
  correlation, sensitive-data redaction).
* :func:`get_logger` -- preferred way to obtain a :class:`structlog.stdlib.BoundLogger`.
* :class:`RequestIDContext`, :func:`new_request_id`, :func:`get_request_id`,
  :func:`add_request_id_processor` -- correlation-id machinery built on
  :class:`contextvars.ContextVar` so an id propagates through
  :class:`asyncio.Task` boundaries (``asyncio.create_task`` /
  ``asyncio.gather``) automatically.
* :func:`redact_sensitive_processor`, :func:`mask_value` -- redaction
  helpers that mask known API-key prefixes (Stripe ``sk_live_`` /
  ``pk_live_``, GitHub ``ghp_`` / ``github_pat_`` ...) and URL query
  string parameters such as ``api_key``, ``token``, ``password``,
  ``secret``, and ``authorization``.

This package is independent of (and must coexist with) the
:mod:`binchecker.log` package, which focuses on PAN redaction for
payment card data.

Validates: Requirement 7.5 (consistent logging system across all modules
with configurable log levels and output formats).
"""

from webrecon.log.correlation import (
    RequestIDContext,
    add_request_id_processor,
    get_request_id,
    new_request_id,
)
from webrecon.log.redaction import mask_value, redact_sensitive_processor
from webrecon.log.setup import configure_logging, get_logger

__all__ = [
    "RequestIDContext",
    "add_request_id_processor",
    "configure_logging",
    "get_logger",
    "get_request_id",
    "mask_value",
    "new_request_id",
    "redact_sensitive_processor",
]
