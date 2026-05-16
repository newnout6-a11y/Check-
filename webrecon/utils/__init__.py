"""Cross-cutting utilities for the webrecon package.

Currently exposes:

* :mod:`webrecon.utils.metrics` -- :class:`MetricsCollector` for
  per-operation throughput/latency tracking, :class:`Checkpoint` for
  resume-capable long-running runs, and :func:`stream_in_batches`
  for memory-bounded async iteration.
"""

from webrecon.utils.metrics import (
    Checkpoint,
    MetricsCollector,
    PerformanceReport,
    stream_in_batches,
)

__all__ = [
    "Checkpoint",
    "MetricsCollector",
    "PerformanceReport",
    "stream_in_batches",
]
