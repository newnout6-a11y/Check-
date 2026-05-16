"""Unit tests for :mod:`webrecon.utils.metrics`.

Covers ``MetricsCollector`` (counters, latency window, time_operation
context manager, success/error classification, report shape),
``Checkpoint`` (atomic write, load, dedup), and ``stream_in_batches``
(batching and final partial batch).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from webrecon.utils.metrics import (
    Checkpoint,
    MetricsCollector,
    PerformanceReport,
    stream_in_batches,
)

# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------


class TestMetricsCollector:
    def test_counts_success_and_errors(self) -> None:
        m = MetricsCollector("test")
        m.record_success()
        m.record_success()
        m.record_error()
        report = m.report()
        assert report.total == 3
        assert report.success == 2
        assert report.errors == 1
        assert report.success_rate == pytest.approx(2 / 3)

    def test_named_counters(self) -> None:
        m = MetricsCollector("test")
        m.increment("fofa.found", by=10)
        m.increment("fofa.found")
        m.increment("shodan.found", by=5)
        report = m.report()
        assert report.counters == {"fofa.found": 11, "shodan.found": 5}

    def test_latency_percentiles(self) -> None:
        m = MetricsCollector("test")
        for ms in (10, 20, 30, 40, 50, 60, 70, 80, 90, 100):
            m.record_latency(ms)
        report = m.report()
        # Median of 10 samples is the average of the two middle values.
        assert report.latency_p50_ms == pytest.approx(55.0)
        # 95th percentile should be at the high end.
        assert report.latency_p95_ms >= 90.0

    def test_latency_window_is_bounded(self) -> None:
        m = MetricsCollector("test", max_samples=5)
        for ms in range(100):
            m.record_latency(float(ms))
        # Only the last 5 samples are kept (95..99).
        report = m.report()
        assert report.latency_avg_ms == pytest.approx(97.0)

    def test_negative_latency_ignored(self) -> None:
        m = MetricsCollector("test")
        m.record_latency(-1.0)
        report = m.report()
        # No latency samples were retained.
        assert report.latency_avg_ms == 0.0

    async def test_time_operation_records_success(self) -> None:
        import asyncio

        m = MetricsCollector("test")
        async with m.time_operation():
            await asyncio.sleep(0.01)
        report = m.report()
        assert report.success == 1
        assert report.errors == 0
        # Latency should be at least the sleep duration.
        assert report.latency_avg_ms >= 8.0

    async def test_time_operation_records_error_on_exception(self) -> None:
        m = MetricsCollector("test")
        with pytest.raises(RuntimeError):
            async with m.time_operation():
                raise RuntimeError("boom")
        report = m.report()
        assert report.success == 0
        assert report.errors == 1

    def test_to_dict_produces_serialisable_shape(self) -> None:
        m = MetricsCollector("test")
        m.record_success()
        m.record_latency(15.5)
        report = m.report()
        d = report.to_dict()
        assert d["operation"] == "test"
        assert d["total"] == 1
        assert d["latency_avg_ms"] == pytest.approx(15.5)
        assert isinstance(d["counters"], dict)

    def test_reset_clears_state(self) -> None:
        m = MetricsCollector("test")
        m.record_success()
        m.record_latency(10.0)
        m.increment("found")
        m.reset()
        report = m.report()
        assert isinstance(report, PerformanceReport)
        assert report.total == 0
        assert report.counters == {}


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------


class TestCheckpoint:
    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        cp = Checkpoint(tmp_path / "missing.json")
        cp.load()
        assert len(cp) == 0

    def test_add_and_persist(self, tmp_path: Path) -> None:
        cp = Checkpoint(tmp_path / "cp.json")
        cp.add("https://a.example.com")
        cp.add("https://b.example.com")
        cp.flush()

        # New instance reads the same file.
        cp2 = Checkpoint(tmp_path / "cp.json")
        cp2.load()
        assert cp2.contains("https://a.example.com")
        assert cp2.contains("https://b.example.com")
        assert not cp2.contains("https://c.example.com")
        assert len(cp2) == 2

    def test_add_is_idempotent(self, tmp_path: Path) -> None:
        cp = Checkpoint(tmp_path / "cp.json")
        cp.add("x")
        cp.add("x")
        cp.add("x")
        assert len(cp) == 1

    def test_remove(self, tmp_path: Path) -> None:
        cp = Checkpoint(tmp_path / "cp.json")
        cp.add("x")
        cp.remove("x")
        assert not cp.contains("x")
        cp.remove("x")  # idempotent

    def test_load_corrupt_file_treated_as_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "cp.json"
        path.write_text("{not valid json", encoding="utf-8")
        cp = Checkpoint(path)
        cp.load()
        assert len(cp) == 0

    async def test_aflush_persists_atomically(self, tmp_path: Path) -> None:
        cp = Checkpoint(tmp_path / "cp.json")
        cp.add("y")
        await cp.aflush()
        cp2 = Checkpoint(tmp_path / "cp.json")
        cp2.load()
        assert cp2.contains("y")


# ---------------------------------------------------------------------------
# stream_in_batches
# ---------------------------------------------------------------------------


async def _agen(items: list[int]) -> AsyncIterator[int]:
    for i in items:
        yield i


class TestStreamInBatches:
    async def test_full_batches(self) -> None:
        batches = [b async for b in stream_in_batches(_agen([1, 2, 3, 4]), batch_size=2)]
        assert batches == [[1, 2], [3, 4]]

    async def test_partial_final_batch(self) -> None:
        batches = [b async for b in stream_in_batches(_agen([1, 2, 3]), batch_size=2)]
        assert batches == [[1, 2], [3]]

    async def test_empty_source(self) -> None:
        batches = [b async for b in stream_in_batches(_agen([]), batch_size=10)]
        assert batches == []

    async def test_invalid_batch_size_raises(self) -> None:
        with pytest.raises(ValueError):
            async for _ in stream_in_batches(_agen([1]), batch_size=0):
                pass
