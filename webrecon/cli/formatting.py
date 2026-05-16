"""Output formatting and progress reporting helpers for the CLI.

The webrecon CLI surfaces results in four formats: ``json``, ``csv``,
``table``, and ``yaml``. ``ProgressReporter`` provides a tiny,
dependency-free progress indicator suitable for long-running scans
(no `tqdm` dependency on purpose so the CLI stays installable through
a minimal wheel).

Usage::

    from webrecon.cli.formatting import format_records, ProgressReporter

    print(format_records(records, fmt="table"))

    reporter = ProgressReporter(total=len(targets))
    for target in targets:
        await scan(target)
        reporter.advance()
    reporter.finish()

Validates: Requirement 8.3 (progress feedback, summary statistics),
Requirement 8.4 (multiple output formats with configurable verbosity),
Requirement 8.5 (error reporting and recovery options).
"""

from __future__ import annotations

import csv
import io
import json
import sys
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "ProgressReporter",
    "format_records",
    "format_summary",
]


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _to_yaml(records: Sequence[dict[str, Any]]) -> str:
    """Render ``records`` as YAML.

    Uses the optional :mod:`pyyaml` dependency when available; falls
    back to a minimal hand-rolled emitter that produces a valid (but
    unstyled) document for the common ``dict[str, scalar | list[str]]``
    shape webrecon emits.
    """
    try:
        import yaml

        return str(yaml.safe_dump(list(records), sort_keys=False, allow_unicode=True))
    except ImportError:
        # Defensive fallback so a YAML request still produces something.
        lines: list[str] = []
        for rec in records:
            lines.append("- " + _yaml_record(rec, indent=2))
        return "\n".join(lines) + "\n"


def _yaml_record(rec: dict[str, Any], *, indent: int) -> str:
    pad = " " * indent
    body: list[str] = []
    first = True
    for key, value in rec.items():
        prefix = "" if first else pad
        first = False
        if isinstance(value, list):
            body.append(f"{prefix}{key}:")
            for item in value:
                body.append(f"{pad}  - {item}")
        else:
            body.append(f"{prefix}{key}: {value}")
    return "\n".join(body)


def _to_csv(records: Sequence[dict[str, Any]]) -> str:
    """Render ``records`` as CSV with a header row."""
    if not records:
        return ""
    columns: list[str] = list(records[0].keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for rec in records:
        flat = {
            k: ",".join(str(item) for item in v) if isinstance(v, list) else v
            for k, v in rec.items()
        }
        writer.writerow(flat)
    return buf.getvalue()


def _to_table(records: Sequence[dict[str, Any]]) -> str:
    """Render ``records`` as an aligned plain-text table."""
    if not records:
        return "(no records)"
    columns: list[str] = list(records[0].keys())
    rows: list[list[str]] = []
    for rec in records:
        rows.append([_cell(rec.get(c, "")) for c in columns])

    widths = [len(c) for c in columns]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def _fmt_row(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    header = _fmt_row(columns)
    separator = "  ".join("-" * w for w in widths)
    body = "\n".join(_fmt_row(row) for row in rows)
    return f"{header}\n{separator}\n{body}"


def _cell(value: Any) -> str:
    """Render one cell value for the table format."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def format_records(
    records: Iterable[dict[str, Any]],
    *,
    fmt: str = "table",
) -> str:
    """Render ``records`` in the requested output format.

    Args:
        records: An iterable of records (dicts) to render.
        fmt: One of ``"json"``, ``"csv"``, ``"table"``, ``"yaml"``.

    Returns:
        The rendered output as a string. Unknown formats fall back to
        ``"json"`` so the CLI never silently drops output.
    """
    materialised = list(records)
    fmt_lower = fmt.lower().strip()
    if fmt_lower == "json":
        return json.dumps(materialised, indent=2, default=str, ensure_ascii=False)
    if fmt_lower == "csv":
        return _to_csv(materialised)
    if fmt_lower == "yaml":
        return _to_yaml(materialised)
    if fmt_lower == "table":
        return _to_table(materialised)
    return json.dumps(materialised, indent=2, default=str, ensure_ascii=False)


def format_summary(stats: dict[str, Any]) -> str:
    """Render a summary block of ``key: value`` lines."""
    if not stats:
        return ""
    width = max(len(str(k)) for k in stats)
    return "\n".join(f"{str(k).ljust(width)} : {v}" for k, v in stats.items())


# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------


class ProgressReporter:
    """Lightweight TTY progress indicator with throughput estimate.

    Renders a single-line bar to ``stderr`` (so it does not pollute
    stdout-bound JSON / CSV pipelines). Falls back to milestone
    ``[N/total]`` lines when the destination is not a TTY (CI, file
    redirect) so log files stay readable.

    Usage::

        reporter = ProgressReporter(total=len(targets), label="scan")
        for target in targets:
            await work(target)
            reporter.advance()
        reporter.finish()
    """

    __slots__ = (
        "_completed",
        "_label",
        "_last_render",
        "_min_interval",
        "_started_at",
        "_stream",
        "_total",
    )

    def __init__(
        self,
        *,
        total: int,
        label: str = "progress",
        min_interval: float = 0.2,
        stream: Any | None = None,
    ) -> None:
        self._total = max(total, 0)
        self._label = label
        self._min_interval = max(0.0, min_interval)
        self._stream = stream if stream is not None else sys.stderr
        self._completed = 0
        self._started_at = time.monotonic()
        self._last_render = 0.0

    def advance(self, n: int = 1) -> None:
        """Increment the completed counter and re-render if due."""
        self._completed += max(0, n)
        now = time.monotonic()
        if now - self._last_render < self._min_interval and self._completed < self._total:
            return
        self._last_render = now
        self._render(now)

    def finish(self) -> None:
        """Emit the final progress line."""
        self._completed = max(self._completed, self._total)
        self._render(time.monotonic(), final=True)
        if self._is_tty():
            print("", file=self._stream, flush=True)

    def _is_tty(self) -> bool:
        try:
            return bool(self._stream.isatty())
        except (AttributeError, ValueError):
            return False

    def _render(self, now: float, *, final: bool = False) -> None:
        elapsed = max(now - self._started_at, 1e-6)
        rate = self._completed / elapsed
        if self._total:
            percent = (self._completed / self._total) * 100
            remaining = max(self._total - self._completed, 0)
            eta = remaining / rate if rate > 0 else 0.0
            line = (
                f"{self._label}: {self._completed}/{self._total} "
                f"({percent:5.1f}%) {rate:.1f}/s eta={eta:.0f}s"
            )
        else:
            line = f"{self._label}: {self._completed} {rate:.1f}/s"

        if self._is_tty() and not final:
            print(f"\r{line}", end="", file=self._stream, flush=True)
        else:
            print(line, file=self._stream, flush=True)
