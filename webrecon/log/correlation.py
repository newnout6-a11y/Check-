"""Request-id correlation for structured logging.

This module implements the "correlation id" piece of the webrecon
logging contract: every log record produced while handling a logical
request carries a stable identifier that lets an operator follow the
request across asynchronous task boundaries.

The id is held in a :class:`contextvars.ContextVar`. Python's
:mod:`asyncio` copies the current context whenever a task is spawned
(``asyncio.create_task``, ``asyncio.gather``, ``loop.run_in_executor``),
so a request id set on the parent automatically reaches every child
task without explicit threading. Resetting the var via the token
returned by :meth:`ContextVar.set` keeps nested requests properly
scoped: a child id installed inside an outer ``RequestIDContext`` does
not leak back into the outer scope when the inner context exits.

Module API:

* :data:`request_id_var` -- the underlying :class:`ContextVar[str | None]`.
  Direct access is rarely needed; prefer :func:`get_request_id`.
* :func:`new_request_id` -- factory that returns a fresh ``uuid4().hex``.
* :func:`get_request_id` -- read the current id (``None`` if unset).
* :class:`RequestIDContext` -- sync + async context manager that sets
  the id on entry and resets it on exit.
* :func:`add_request_id_processor` -- structlog processor that injects
  the current id (when set) into the event dict under the
  ``request_id`` key. Passive when the var is unset so it does not
  pollute records produced outside any request scope.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from types import TracebackType

    from structlog.typing import EventDict, WrappedLogger

__all__ = [
    "RequestIDContext",
    "add_request_id_processor",
    "get_request_id",
    "new_request_id",
    "request_id_var",
]


# Module-level ContextVar so the same instance is shared by every
# importer. The default is ``None`` so callers can distinguish "no
# request scope active" from "request scope active with empty id".
request_id_var: ContextVar[str | None] = ContextVar("webrecon_request_id", default=None)


def new_request_id() -> str:
    """Return a fresh hexadecimal request id (uuid4, 32 chars).

    Used by :class:`RequestIDContext` when no explicit id is supplied,
    and by callers that want to mint an id ahead of entering a context
    (e.g. for inclusion in an outbound HTTP header).
    """
    return uuid.uuid4().hex


def get_request_id() -> str | None:
    """Return the current request id, or ``None`` if no scope is active."""
    return request_id_var.get()


class RequestIDContext:
    """Context manager that scopes a request id to a block of code.

    The same instance can be used as either a synchronous or
    asynchronous context manager:

    Synchronous::

        with RequestIDContext() as rid:
            log.info("processing", target=url)

    Asynchronous::

        async with RequestIDContext() as rid:
            await process(url)

    Nested usage is supported: each ``__enter__`` / ``__aenter__`` call
    captures the :class:`Token` returned by ``ContextVar.set`` and
    ``__exit__`` / ``__aexit__`` resets the var via that token, so the
    parent id (if any) is restored cleanly.

    The class is intentionally re-usable across multiple ``with``
    blocks: each entry mints a fresh token and stack frame, so the
    same instance can be entered concurrently from different async
    tasks (each task has its own copy of the ContextVar).
    """

    __slots__ = ("_explicit_request_id", "_token_stack")

    def __init__(self, request_id: str | None = None) -> None:
        """Initialise the context manager.

        Args:
            request_id: Optional explicit id. When ``None`` (the
                default) :func:`new_request_id` is used to mint a
                fresh id on every ``__enter__`` / ``__aenter__`` call,
                so re-using the same ``RequestIDContext`` instance
                across multiple ``with`` blocks produces distinct ids.
        """
        self._explicit_request_id: str | None = request_id
        # A stack of tokens supports nested entries on the same
        # instance from a single task. Concurrent entries from
        # different tasks each get their own ContextVar copy and do
        # not interfere with each other.
        self._token_stack: list[Token[str | None]] = []

    # -- helpers ---------------------------------------------------------

    def _resolve_id(self) -> str:
        if self._explicit_request_id is not None:
            return self._explicit_request_id
        return new_request_id()

    def _enter(self) -> str:
        rid = self._resolve_id()
        token = request_id_var.set(rid)
        self._token_stack.append(token)
        return rid

    def _exit(self) -> None:
        # Pop in LIFO order so reset undoes the most recent set.
        if self._token_stack:
            token = self._token_stack.pop()
            request_id_var.reset(token)

    # -- sync context manager protocol -----------------------------------

    def __enter__(self) -> str:
        return self._enter()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._exit()

    # -- async context manager protocol ----------------------------------

    async def __aenter__(self) -> str:
        return self._enter()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._exit()


def add_request_id_processor(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """structlog processor: inject the current request id, if any.

    Adds a ``request_id`` key to ``event_dict`` when a scope is active.
    No-op when the contextvar is unset so records produced outside a
    request (e.g. during process startup) are not polluted with a
    bogus id.

    The signature matches the structlog processor protocol exactly so
    the function can be used directly in
    :func:`structlog.configure(processors=[...])`.
    """
    del logger, method_name  # unused; required by the protocol
    rid: Any = request_id_var.get()
    if rid is not None and "request_id" not in event_dict:
        event_dict["request_id"] = rid
    return event_dict
