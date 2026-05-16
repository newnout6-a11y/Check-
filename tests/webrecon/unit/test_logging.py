"""Unit tests for :mod:`webrecon.log`.

Covers task 3.3 of the ``web-reconnaissance`` spec:

* request-id correlation propagates through asyncio task boundaries
  (``asyncio.create_task`` / ``asyncio.gather``);
* the redaction processor masks Stripe / GitHub token prefixes at the
  top level and inside nested structures;
* URL redaction strips ``api_key`` (and friends) query parameters;
* :func:`configure_logging` with ``log_file`` creates the file and
  writes a structured record;
* JSON output mode emits parseable JSON, one object per line.

Validates: Requirements 7.5.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path

import pytest
import structlog

from webrecon.log import (
    RequestIDContext,
    add_request_id_processor,
    configure_logging,
    get_logger,
    get_request_id,
    mask_value,
    new_request_id,
    redact_sensitive_processor,
)
from webrecon.log.correlation import request_id_var

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_logging_state():
    """Snapshot and restore root-logger / structlog state around each test."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_filters = list(root.filters)

    yield

    # Drop everything the test added and put the originals back.
    for handler in list(root.handlers):
        root.removeHandler(handler)
        with contextlib.suppress(Exception):
            handler.close()
    for handler in saved_handlers:
        root.addHandler(handler)
    for flt in list(root.filters):
        root.removeFilter(flt)
    for flt in saved_filters:
        root.addFilter(flt)
    root.setLevel(saved_level)

    structlog.reset_defaults()


# ---------------------------------------------------------------------------
# Correlation tests
# ---------------------------------------------------------------------------


def test_new_request_id_returns_unique_hex() -> None:
    """new_request_id mints distinct 32-char hex strings."""
    ids = {new_request_id() for _ in range(50)}
    assert len(ids) == 50
    for rid in ids:
        assert len(rid) == 32
        int(rid, 16)  # validates hex


def test_get_request_id_is_none_outside_scope() -> None:
    """Without an active context manager the var reads as None."""
    assert get_request_id() is None


def test_request_id_context_sets_and_resets() -> None:
    """Entering the context publishes an id; exiting clears it."""
    assert get_request_id() is None
    with RequestIDContext() as rid:
        assert rid is not None
        assert get_request_id() == rid
    assert get_request_id() is None


def test_request_id_context_accepts_explicit_id() -> None:
    """An explicit id is used verbatim instead of auto-minted."""
    with RequestIDContext("fixed-12345") as rid:
        assert rid == "fixed-12345"
        assert get_request_id() == "fixed-12345"


def test_request_id_context_nesting() -> None:
    """Nested contexts restore the parent id on exit."""
    with RequestIDContext("outer") as outer:
        assert outer == "outer"
        assert get_request_id() == "outer"
        with RequestIDContext("inner") as inner:
            assert inner == "inner"
            assert get_request_id() == "inner"
        assert get_request_id() == "outer"
    assert get_request_id() is None


async def test_request_id_propagates_through_create_task() -> None:
    """asyncio.create_task copies the contextvar to the new task."""
    seen: list[str | None] = []

    async def child() -> None:
        seen.append(get_request_id())

    with RequestIDContext("parent-id"):
        task = asyncio.create_task(child())
        await task

    assert seen == ["parent-id"]


async def test_request_id_propagates_through_gather_with_distinct_ids() -> None:
    """Each task installs its own id; siblings do not bleed into each other."""

    async def worker(task_id: str) -> tuple[str, str | None]:
        async with RequestIDContext(task_id):
            # Yield to let the other task make progress while we hold our id.
            await asyncio.sleep(0)
            return task_id, get_request_id()

    results = await asyncio.gather(
        worker("task-a"),
        worker("task-b"),
        worker("task-c"),
    )

    # Each task observes its own id even though they run concurrently.
    assert results == [("task-a", "task-a"), ("task-b", "task-b"), ("task-c", "task-c")]
    # Outer scope is undisturbed.
    assert get_request_id() is None


async def test_request_id_async_context_manager() -> None:
    """The async with form sets and resets the id correctly."""
    async with RequestIDContext("async-id") as rid:
        assert rid == "async-id"
        assert get_request_id() == "async-id"
    assert get_request_id() is None


def test_add_request_id_processor_injects_when_set() -> None:
    """When a scope is active, the processor adds request_id to the event."""
    with RequestIDContext("xyz") as rid:
        out = add_request_id_processor(None, "info", {"event": "hi"})
        assert out == {"event": "hi", "request_id": rid}


def test_add_request_id_processor_noop_when_unset() -> None:
    """Outside a scope, the processor leaves the event dict untouched."""
    # Make sure no scope is active.
    request_id_var.set(None)
    out = add_request_id_processor(None, "info", {"event": "hi"})
    assert out == {"event": "hi"}


def test_add_request_id_processor_does_not_overwrite() -> None:
    """An explicit request_id key in the event dict wins over the contextvar."""
    with RequestIDContext("ctx-id"):
        out = add_request_id_processor(None, "info", {"request_id": "explicit"})
    assert out == {"request_id": "explicit"}


# ---------------------------------------------------------------------------
# Redaction tests
# ---------------------------------------------------------------------------


def test_mask_value_includes_kind_and_last4() -> None:
    masked = mask_value("sk_live_abcdefghijklmnop", "stripe_secret_live")
    assert masked == "<redacted:stripe_secret_live:mnop>"


def test_mask_value_short_value() -> None:
    """A value shorter than four chars masks to whatever is available."""
    masked = mask_value("abc", "kind")
    assert masked == "<redacted:kind:abc>"


def test_mask_value_empty_value_uses_kind_only() -> None:
    masked = mask_value("", "kind")
    assert masked == "<redacted:kind>"


def test_redact_processor_masks_stripe_secret() -> None:
    event = {"event": "key found", "key": "sk_live_abcdef1234567890"}
    out = redact_sensitive_processor(None, "info", event)
    assert out["key"].startswith("<redacted:stripe_secret_live:")
    assert "sk_live_abcdef1234567890" not in str(out["key"])
    # last4 of the body is preserved
    assert out["key"].endswith(":7890>")


def test_redact_processor_masks_github_pat() -> None:
    event = {"token": "ghp_abcdefghijklmnop1234"}
    out = redact_sensitive_processor(None, "info", event)
    assert out["token"].startswith("<redacted:github_pat_classic:")


def test_redact_processor_masks_long_github_pat() -> None:
    """github_pat_ must take precedence over the shorter ghp_ prefix."""
    event = {"token": "github_pat_11ABCDEFG0_xxxxxxxxxxxxxxxxxxxxxxxx"}
    out = redact_sensitive_processor(None, "info", event)
    assert out["token"].startswith("<redacted:github_pat:")


def test_redact_processor_masks_publishable_key() -> None:
    event = {"key": "pk_live_xxxxxxxxxxxxxxx"}
    out = redact_sensitive_processor(None, "info", event)
    assert out["key"].startswith("<redacted:stripe_publishable_live:")


def test_redact_processor_walks_nested_dict() -> None:
    event = {
        "event": "scan",
        "context": {
            "headers": {"X-Stripe-Key": "sk_test_abcdef1234567890"},
            "url": "https://api.example.com/v1?api_key=secret123",
        },
    }
    out = redact_sensitive_processor(None, "info", event)
    nested = out["context"]
    assert nested["headers"]["X-Stripe-Key"].startswith("<redacted:stripe_secret_test:")
    assert "api_key=%3Credacted%3E" in nested["url"] or "api_key=<redacted>" in nested["url"]


def test_redact_processor_walks_lists() -> None:
    event = {"keys": ["sk_live_abcdef1234567890", "ok_value", "ghp_abcdef12345678"]}
    out = redact_sensitive_processor(None, "info", event)
    keys = out["keys"]
    assert keys[0].startswith("<redacted:stripe_secret_live:")
    assert keys[1] == "ok_value"
    assert keys[2].startswith("<redacted:github_pat_classic:")


def test_redact_processor_walks_tuples() -> None:
    event = {"keys": ("sk_live_abcdef1234567890", "ok_value")}
    out = redact_sensitive_processor(None, "info", event)
    assert isinstance(out["keys"], tuple)
    assert out["keys"][0].startswith("<redacted:stripe_secret_live:")
    assert out["keys"][1] == "ok_value"


def test_redact_processor_redacts_url_query_string() -> None:
    """URLs with sensitive query parameters are masked but path is kept."""
    url = "https://api.example.com/users?api_key=topsecret&filter=alive"
    out = redact_sensitive_processor(None, "info", {"url": url})
    redacted = out["url"]
    assert "topsecret" not in redacted
    assert "api_key=" in redacted
    assert "filter=alive" in redacted
    assert redacted.startswith("https://api.example.com/users")


def test_redact_processor_handles_multiple_sensitive_params() -> None:
    url = (
        "https://example.com/x?token=tok_xyz&password=hunter2"
        "&authorization=Bearer+xyz&plain=keep"
    )
    out = redact_sensitive_processor(None, "info", {"url": url})
    redacted = out["url"]
    assert "tok_xyz" not in redacted
    assert "hunter2" not in redacted
    assert "Bearer" not in redacted
    assert "plain=keep" in redacted


def test_redact_processor_redacts_url_inside_text() -> None:
    """A URL embedded in a free-form string is still redacted."""
    text = "called https://api.example.com/v1?api_key=topsecret in 12ms"
    out = redact_sensitive_processor(None, "info", {"event": text})
    assert "topsecret" not in out["event"]


def test_redact_processor_leaves_safe_values() -> None:
    event = {"event": "ok", "count": 42, "ok": True, "value": None}
    out = redact_sensitive_processor(None, "info", event)
    assert out == {"event": "ok", "count": 42, "ok": True, "value": None}


def test_redact_processor_handles_bytes() -> None:
    event = {"raw": b"sk_live_abcdef1234567890 and more"}
    out = redact_sensitive_processor(None, "info", event)
    assert isinstance(out["raw"], bytes)
    assert b"sk_live_abcdef1234567890" not in out["raw"]


# ---------------------------------------------------------------------------
# configure_logging / get_logger tests
# ---------------------------------------------------------------------------


def test_configure_logging_writes_log_file(tmp_path: Path) -> None:
    """A structured record is written to the configured rotating file."""
    log_file = tmp_path / "subdir" / "webrecon.log"
    configure_logging(level="DEBUG", json_output=True, log_file=log_file)

    log = get_logger("webrecon.test")
    log.info("hello", target="https://example.com")

    # Flush all rotating-file handlers so the test sees the bytes immediately.
    for handler in logging.getLogger().handlers:
        handler.flush()

    assert log_file.parent.is_dir()
    assert log_file.is_file()
    contents = log_file.read_text(encoding="utf-8")
    assert "hello" in contents
    assert "https://example.com" in contents


def test_configure_logging_json_output_is_parseable(
    capfd: pytest.CaptureFixture[str],
) -> None:
    """JSON output mode emits one parseable JSON object per line on stderr."""
    configure_logging(level="INFO", json_output=True)

    log = get_logger("webrecon.json")
    log.info("test_event", value=1, other="two")

    captured = capfd.readouterr()
    # The handler emits both structlog records and any non-structlog
    # records; structlog's JSON renderer produces the JSON object as
    # the message body. When stdlib's StreamHandler runs the message
    # through the configured stdlib formatter, the JSON object appears
    # at the end of the line. Search any line that contains a "{" for
    # a parseable suffix.
    parsed: list[dict[str, object]] = []
    for line in captured.err.splitlines():
        idx = line.find("{")
        if idx == -1:
            continue
        try:
            parsed.append(json.loads(line[idx:]))
        except json.JSONDecodeError:
            continue

    assert any(
        record.get("event") == "test_event" and record.get("value") == 1
        for record in parsed
    ), f"no matching JSON record found; stderr was:\n{captured.err}\n"
    # The renderer attached the timestamper -> a `timestamp` key is present.
    matching = next(
        record for record in parsed if record.get("event") == "test_event"
    )
    assert "timestamp" in matching
    assert matching.get("level") == "info"


def test_configure_logging_redacts_in_output(tmp_path: Path) -> None:
    """Configured pipeline redacts API keys before they reach the file."""
    log_file = tmp_path / "redacted.log"
    configure_logging(level="DEBUG", json_output=True, log_file=log_file)

    log = get_logger("webrecon.redact")
    log.info("found_key", key="sk_live_abcdef1234567890")

    for handler in logging.getLogger().handlers:
        handler.flush()

    contents = log_file.read_text(encoding="utf-8")
    assert "sk_live_abcdef1234567890" not in contents
    assert "<redacted:stripe_secret_live:" in contents


def test_configure_logging_includes_request_id(tmp_path: Path) -> None:
    """Records emitted inside a RequestIDContext include the id."""
    log_file = tmp_path / "rid.log"
    configure_logging(level="DEBUG", json_output=True, log_file=log_file)

    log = get_logger("webrecon.rid")
    with RequestIDContext("req-001"):
        log.info("inside_scope")
    log.info("outside_scope")

    for handler in logging.getLogger().handlers:
        handler.flush()

    contents = log_file.read_text(encoding="utf-8")
    in_scope_line = next(line for line in contents.splitlines() if "inside_scope" in line)
    out_scope_line = next(line for line in contents.splitlines() if "outside_scope" in line)
    assert "req-001" in in_scope_line
    assert "req-001" not in out_scope_line


def test_configure_logging_is_idempotent(tmp_path: Path) -> None:
    """Calling configure_logging twice does not stack handlers."""
    log_file = tmp_path / "idem.log"
    configure_logging(level="INFO", json_output=False, log_file=log_file)
    first_count = sum(
        1 for h in logging.getLogger().handlers if getattr(h, "_webrecon_log_handler", False)
    )
    configure_logging(level="INFO", json_output=False, log_file=log_file)
    second_count = sum(
        1 for h in logging.getLogger().handlers if getattr(h, "_webrecon_log_handler", False)
    )
    assert first_count == second_count


def test_configure_logging_unknown_level_falls_back_to_info(tmp_path: Path) -> None:
    """A junk level string falls back to INFO instead of raising."""
    log_file = tmp_path / "fallback.log"
    configure_logging(level="not-a-level", json_output=True, log_file=log_file)
    assert logging.getLogger().level == logging.INFO


def test_get_logger_returns_bound_logger() -> None:
    """get_logger wraps structlog.get_logger and returns a usable logger."""
    configure_logging(level="INFO", json_output=True)
    log = get_logger("webrecon.unit")
    assert hasattr(log, "info")
    assert hasattr(log, "warning")
    assert hasattr(log, "error")
    # Without a name we still get a logger.
    log2 = get_logger()
    assert hasattr(log2, "info")
