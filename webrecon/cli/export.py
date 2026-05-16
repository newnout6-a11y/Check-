"""``webrecon export`` subcommand implementation."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_export"]

_LOGGER = get_logger(__name__)


async def run_export(args: argparse.Namespace) -> int:
    """Execute the export subcommand."""
    from webrecon.config import load_config
    from webrecon.database import open_database
    from webrecon.database.export import DataExporter

    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("export.config_error", error=str(exc))
        return 2

    pool = await open_database(config.database.path)
    exporter = DataExporter(pool)

    fmt = args.format
    output = args.output

    # Parse filters.
    from webrecon.core.models import AssetStatus, DiscoverySource
    status = None
    if args.status:
        try:
            status = AssetStatus(args.status)
        except ValueError:
            print(f"Error: Invalid status: {args.status}", file=sys.stderr)
            await pool.close()
            return 1

    source = None
    if args.source:
        try:
            source = DiscoverySource(args.source)
        except ValueError:
            print(f"Error: Invalid source: {args.source}", file=sys.stderr)
            await pool.close()
            return 1

    try:
        if fmt == "csv":
            path = f"{output}.csv"
            count = await exporter.export_csv(path, status=status, discovery_source=source)
            print(f"Exported {count} assets to {path}")

        elif fmt == "json":
            path = f"{output}.json"
            count = await exporter.export_json(path, status=status, include_stripe_keys=True)
            print(f"Exported {count} assets to {path}")

        elif fmt == "sql":
            path = f"{output}.sql"
            count = await exporter.export_sql_dump(path)
            print(f"Exported {count} rows to {path}")

        elif fmt == "html":
            from webrecon.automation.reporter import AssessmentReporter
            from webrecon.database.query import AssetQuery

            query = AssetQuery(pool).limit(10000)
            if status:
                query.filter(status=status)

            # Run the query for its side effect (validates the filter
            # and surfaces any DB errors before we touch the reporter).
            # TODO: convert assets into ValidationReport entries and
            # feed them to ``generate_report(validation_reports=...)``.
            await query.execute()
            reporter = AssessmentReporter()
            report = reporter.generate_report()
            path = f"{output}.html"
            reporter.save_html(report, path)
            print(f"Exported report to {path}")

    except Exception as exc:
        _LOGGER.error("export.error", error=str(exc))
        await pool.close()
        return 1

    await pool.close()
    return 0
