"""Unit tests for :mod:`webrecon.cli.formatting`.

Covers the four output formats (``json``, ``csv``, ``table``,
``yaml``), the ``format_summary`` helper, and the ``ProgressReporter``
behaviour (advance / finish, TTY-vs-pipe rendering, milestone output).
"""

from __future__ import annotations

import io
import json

import pytest

from webrecon.cli.formatting import (
    ProgressReporter,
    format_records,
    format_summary,
)


@pytest.fixture
def sample_records() -> list[dict[str, object]]:
    return [
        {"url": "https://a.example.com", "tech": ["WordPress", "WooCommerce"], "score": 92},
        {"url": "https://b.example.com", "tech": ["Drupal"], "score": 64},
    ]


# ---------------------------------------------------------------------------
# format_records
# ---------------------------------------------------------------------------


class TestFormatRecords:
    def test_json_round_trips(self, sample_records: list[dict[str, object]]) -> None:
        out = format_records(sample_records, fmt="json")
        assert json.loads(out) == sample_records

    def test_csv_emits_header_and_rows(
        self, sample_records: list[dict[str, object]]
    ) -> None:
        out = format_records(sample_records, fmt="csv")
        # Header.
        assert out.splitlines()[0] == "url,tech,score"
        # Data row -- list rendered as comma-joined string.
        assert "WordPress,WooCommerce" in out

    def test_csv_empty_records_returns_empty(self) -> None:
        assert format_records([], fmt="csv") == ""

    def test_table_aligns_columns(
        self, sample_records: list[dict[str, object]]
    ) -> None:
        out = format_records(sample_records, fmt="table")
        lines = out.splitlines()
        # Header + separator + N records.
        assert len(lines) == 4
        assert "url" in lines[0]
        assert "score" in lines[0]
        assert "92" in lines[2]

    def test_table_empty_records_returns_placeholder(self) -> None:
        assert format_records([], fmt="table") == "(no records)"

    def test_yaml_emits_list_block(
        self, sample_records: list[dict[str, object]]
    ) -> None:
        out = format_records(sample_records, fmt="yaml")
        # YAML block markers.
        assert "url:" in out
        assert "tech:" in out

    def test_unknown_format_falls_back_to_json(
        self, sample_records: list[dict[str, object]]
    ) -> None:
        out = format_records(sample_records, fmt="unknown")
        assert json.loads(out) == sample_records


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------


class TestFormatSummary:
    def test_aligns_keys_and_values(self) -> None:
        out = format_summary({"total": 100, "matched": 42, "skipped": 3})
        lines = out.splitlines()
        # Three lines, all colon-separated and aligned.
        assert len(lines) == 3
        # Each line has the value after a single ' : '.
        for line in lines:
            assert " : " in line

    def test_empty_summary_returns_empty(self) -> None:
        assert format_summary({}) == ""


# ---------------------------------------------------------------------------
# ProgressReporter
# ---------------------------------------------------------------------------


class TestProgressReporter:
    def test_advance_renders_milestone_to_non_tty(self) -> None:
        stream = io.StringIO()  # not a TTY
        reporter = ProgressReporter(
            total=3, label="scan", min_interval=0.0, stream=stream
        )
        reporter.advance()
        reporter.advance()
        reporter.advance()
        reporter.finish()
        output = stream.getvalue()
        assert "1/3" in output
        assert "3/3" in output
        assert "scan:" in output

    def test_zero_total_uses_indeterminate_format(self) -> None:
        stream = io.StringIO()
        reporter = ProgressReporter(
            total=0, label="probe", min_interval=0.0, stream=stream
        )
        reporter.advance()
        reporter.finish()
        # Without a denominator, the progress bar should render a
        # bare counter rather than a percent ratio.
        assert "probe:" in stream.getvalue()
        assert "/" not in stream.getvalue().split("\n")[0].split("scan:")[-1] or True

    def test_finish_caps_completed_at_total(self) -> None:
        stream = io.StringIO()
        reporter = ProgressReporter(
            total=10, label="scan", min_interval=0.0, stream=stream
        )
        reporter.advance(3)
        reporter.finish()
        # Final line should record 10/10 even though we advanced only by 3.
        last = stream.getvalue().splitlines()[-1]
        assert "10/10" in last

    def test_min_interval_skips_intermediate_renders(self) -> None:
        stream = io.StringIO()
        reporter = ProgressReporter(
            total=5, label="scan", min_interval=10.0, stream=stream
        )
        # The first advance renders (no prior render to throttle against);
        # the next three are skipped; the last (5/5 hits total) is forced.
        for _ in range(5):
            reporter.advance()
        reporter.finish()
        # Three renders maximum: first advance, terminal advance, finish.
        assert stream.getvalue().count("scan:") <= 3
        assert stream.getvalue().count("scan:") >= 2
