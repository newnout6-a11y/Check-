"""Performance monitoring utilities for the webrecon pipeline.

This module exposes three small primitives used by the long-running
discovery and scan loops:

* :class:`MetricsCollector` -- lock-free, async-safe counter and timer
  collector. Records request counts, success/error counts, and rolling
  latency stats. Renders a summary as a :class:`PerformanceReport`
  consumable by the CLI ``--summary`` flag.
* :class:`Checkpoint` -- atomic, JSON-backed checkpoint file used by
  long-running operations to record progress so an interrupted run
  can resume without re-processing already-completed targets.
* :func:`stream_in_batches` -- async generator that batches an
  arbitrary async iterator into fixed-size chunks. Used by the mass
  parser and database export to bound memory.

Validates: Requirement 12.2 (streaming processing and result
batching), Requirement 12.5 (performance metrics), Requirement 12.6
(checkpointing and resume).
"""

from __future__ import annotations

import asyncio
import json
import statistics
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

__all__ = [
    "Checkpoint",
    "MetricsCollector",
    "PerformanceReport",
    "stream_in_batches",
]


T = TypeVar("T")


# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------


@dataclass
class PerformanceReport:
    """Snapshot of pipeline performance.

    Attributes:
        operation: Name of the operation the metrics describe.
        elapsed_seconds: Wall-clock time since the collector was started.
        total: Total number of operations recorded.
        success: Number of successful operations.
        errors: Number of failed operations.
        success_rate: Fraction of successful operations in ``[0, 1]``.
        throughput_per_second: Operations per second.
        latency_avg_ms: Mean latency across all timed operations.
        latency_p50_ms: Median latency.
        latency_p95_ms: 95th-percentile latency.
        counters: Operator-defined counters (e.g. per-source totals).
    """

    operation: str
    elapsed_seconds: float
    total: int
    success: int
    errors: int
    success_rate: float
    throughput_per_second: float
    latency_avg_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    counters: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "total": self.total,
            "success": self.success,
            "errors": self.errors,
            "success_rate": round(self.success_rate, 4),
            "throughput_per_second": round(self.throughput_per_second, 2),
            "latency_avg_ms": round(self.latency_avg_ms, 2),
            "latency_p50_ms": round(self.latency_p50_ms, 2),
            "latency_p95_ms": round(self.latency_p95_ms, 2),
            "counters": dict(self.counters),
        }


class MetricsCollector:
    """Async-safe metrics collector for one logical operation.

    The collector is bound to one operation name (``"fofa.search"``,
    ``"mass_parser.scan"``, ...) and aggregates counters and latency
    samples until :py:meth:`report` is called. It is safe to call
    :py:meth:`record_success` / :py:meth:`record_error` /
    :py:meth:`record_latency` from concurrent asyncio tasks because
    every public method completes synchronously without awaiting.

    Use :py:meth:`time_operation` (an async context manager) to time
    a coroutine and record the resulting latency in one shot.
    """

    __slots__ = (
        "_counters",
        "_errors",
        "_latencies_ms",
        "_max_samples",
        "_operation",
        "_started_at",
        "_success",
    )

    def __init__(self, operation: str, *, max_samples: int = 10_000) -> None:
        self._operation = operation
        self._started_at = time.monotonic()
        self._success = 0
        self._errors = 0
        self._latencies_ms: list[float] = []
        self._counters: dict[str, int] = {}
        self._max_samples = max(1, max_samples)

    # ---- Recording ----------------------------------------------------

    def record_success(self, *, count: int = 1) -> None:
        """Increment the success counter."""
        self._success += max(0, count)

    def record_error(self, *, count: int = 1) -> None:
        """Increment the error counter."""
        self._errors += max(0, count)

    def record_latency(self, latency_ms: float) -> None:
        """Append ``latency_ms`` to the rolling latency window.

        The window is bounded by ``max_samples``; when full, the oldest
        sample is dropped. Bounding the window keeps memory predictable
        for long-running scans without distorting recent percentile
        estimates.
        """
        if latency_ms < 0:
            return
        self._latencies_ms.append(latency_ms)
        if len(self._latencies_ms) > self._max_samples:
            self._latencies_ms = self._latencies_ms[-self._max_samples :]

    def increment(self, key: str, *, by: int = 1) -> None:
        """Increment a named counter by ``by``."""
        self._counters[key] = self._counters.get(key, 0) + by

    @asynccontextmanager
    async def time_operation(self, *, on_error: bool = True) -> AsyncIterator[None]:
        """Async context manager that records latency and outcome.

        Usage::

            async with metrics.time_operation():
                await client.fetch(url)

        On success the elapsed time is recorded and ``record_success``
        is incremented. On exception the elapsed time is still
        recorded and ``record_error`` is incremented (when
        ``on_error`` is true) before the exception is re-raised.
        """
        start = time.monotonic()
        try:
            yield
        except BaseException:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            self.record_latency(elapsed_ms)
            if on_error:
                self.record_error()
            raise
        else:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            self.record_latency(elapsed_ms)
            self.record_success()

    # ---- Reporting ----------------------------------------------------

    @property
    def total(self) -> int:
        """Return the total number of recorded operations."""
        return self._success + self._errors

    def report(self) -> PerformanceReport:
        """Build a :class:`PerformanceReport` snapshot.

        Repeated calls are safe and produce snapshots reflecting the
        state at call time; the underlying counters keep growing.
        """
        elapsed = max(time.monotonic() - self._started_at, 1e-6)
        total = self.total
        success_rate = (self._success / total) if total else 0.0
        throughput = total / elapsed
        if self._latencies_ms:
            avg = sum(self._latencies_ms) / len(self._latencies_ms)
            ordered = sorted(self._latencies_ms)
            p50 = statistics.median(ordered)
            idx_p95 = max(0, int(len(ordered) * 0.95) - 1)
            p95 = ordered[idx_p95]
        else:
            avg = p50 = p95 = 0.0
        return PerformanceReport(
            operation=self._operation,
            elapsed_seconds=elapsed,
            total=total,
            success=self._success,
            errors=self._errors,
            success_rate=success_rate,
            throughput_per_second=throughput,
            latency_avg_ms=avg,
            latency_p50_ms=p50,
            latency_p95_ms=p95,
            counters=dict(self._counters),
        )

    def reset(self) -> None:
        """Clear all recorded state and restart the elapsed-time clock."""
        self._started_at = time.monotonic()
        self._success = 0
        self._errors = 0
        self._latencies_ms.clear()
        self._counters.clear()


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------


class Checkpoint:
    """Atomic, JSON-backed checkpoint for long-running operations.

    The checkpoint records the set of *completed* identifiers (URLs,
    repo names, ...) so an interrupted run can resume without
    re-processing them. Writes are atomic via temp-file + rename so
    a crash mid-write leaves the previous checkpoint intact.

    Usage::

        cp = Checkpoint(Path("scan.checkpoint"))
        for url in urls:
            if cp.contains(url):
                continue
            await scan(url)
            cp.add(url)
            cp.flush()  # explicit flush for hard durability
    """

    __slots__ = ("_completed", "_lock", "_path")

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._completed: set[str] = set()
        self._lock = asyncio.Lock()

    def load(self) -> None:
        """Populate the in-memory state from the on-disk file.

        Missing or malformed files are treated as empty: a fresh run
        is the same as a corrupted checkpoint from the operator's
        point of view.
        """
        if not self._path.is_file():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        completed = data.get("completed", []) if isinstance(data, dict) else data
        if isinstance(completed, list):
            self._completed = {str(item) for item in completed}

    def contains(self, identifier: str) -> bool:
        """Return ``True`` when ``identifier`` was already completed."""
        return identifier in self._completed

    def add(self, identifier: str) -> None:
        """Mark ``identifier`` as completed (in-memory only)."""
        self._completed.add(identifier)

    def remove(self, identifier: str) -> None:
        """Remove ``identifier`` from the completed set."""
        self._completed.discard(identifier)

    def __len__(self) -> int:
        return len(self._completed)

    def __iter__(self) -> Iterator[str]:
        return iter(self._completed)

    def flush(self) -> None:
        """Persist the in-memory state to disk atomically."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = {
            "completed": sorted(self._completed),
            "saved_at": time.time(),
        }
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self._path)

    async def aflush(self) -> None:
        """Async-safe wrapper around :py:meth:`flush`."""
        async with self._lock:
            await asyncio.to_thread(self.flush)


# ---------------------------------------------------------------------------
# Streaming helpers
# ---------------------------------------------------------------------------


async def stream_in_batches(
    source: AsyncIterator[T],
    *,
    batch_size: int = 100,
) -> AsyncIterator[list[T]]:
    """Yield items from ``source`` in fixed-size batches.

    The final batch may be smaller than ``batch_size`` if the source
    iterator is exhausted before the batch fills. Used by the mass
    parser and database export layers to bound memory while
    processing large result sets.

    Args:
        source: An asynchronous iterator producing items of type ``T``.
        batch_size: Maximum number of items per batch (must be >= 1).

    Yields:
        A ``list[T]`` of length at most ``batch_size``.
    """
    if batch_size < 1:
        raise ValueError(f"batch_size must be >= 1, got {batch_size}")
    batch: list[T] = []
    async for item in source:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


# Generic class re-export so callers that want a typed reference
# can ``isinstance(x, _BatchT)`` if needed in the future. Kept
# minimal so the runtime cost is zero.
class _BatchT(Generic[T]):  # pragma: no cover - typing helper
    """Marker class so ``Generic[T]`` is reachable from this module."""
