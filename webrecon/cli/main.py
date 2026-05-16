"""Root command-line interface for the ``webrecon`` toolkit.

This module defines the top-level ``webrecon`` command with subcommands
for every pipeline stage:

* ``webrecon discover`` -- multi-source target discovery (FOFA, Shodan,
  Serper).
* ``webrecon github`` -- GitHub repository reconnaissance and secret
  detection.
* ``webrecon parse`` -- bulk website parsing and validation.
* ``webrecon automate`` -- form automation and interaction.
* ``webrecon validate`` -- website validation and Stripe testing.
* ``webrecon export`` -- data export and reporting.
* ``webrecon config`` -- configuration management.
* ``webrecon db`` -- database operations and queries.

Global flags:

* ``--config`` -- path to a configuration file.
* ``--log-level`` -- override the log level (DEBUG, INFO, WARNING, ERROR).
* ``--output`` -- output format (json, csv, table).
* ``--concurrency`` -- override the concurrency limit.
* ``--verbose`` / ``--quiet`` -- increase / decrease output verbosity.

Usage::

    webrecon discover --source fofa --query "woocommerce+stripe"
    webrecon github --query "sk_live_ filename:.env"
    webrecon parse --input urls.txt
    webrecon validate --url https://example.com
    webrecon export --format csv --output assets.csv
    webrecon db stats

Validates: Requirement 8.1 (root argparse with subcommands),
Requirement 8.2 (global flags and configuration),
Requirement 8.3 (exit codes).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import configure_logging, get_logger
from webrecon.version import __version__

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["main"]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_AUTH_ERROR = 3
EXIT_RATE_LIMIT = 4
EXIT_NO_RESULTS = 5
EXIT_INTERRUPTED = 130


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the root argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="Web reconnaissance and automation toolkit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"webrecon {__version__}",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Override log level",
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["json", "csv", "table"],
        default="table",
        help="Output format",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Override concurrency limit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Increase output verbosity",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Decrease output verbosity",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        help="Available subcommands",
    )

    # ---- discover ----
    discover_p = subparsers.add_parser(
        "discover",
        help="Multi-source target discovery",
    )
    _add_discover_args(discover_p)

    # ---- github ----
    github_p = subparsers.add_parser(
        "github",
        help="GitHub repository reconnaissance",
    )
    _add_github_args(github_p)

    # ---- parse ----
    parse_p = subparsers.add_parser(
        "parse",
        help="Bulk website parsing and validation",
    )
    _add_parse_args(parse_p)

    # ---- automate ----
    automate_p = subparsers.add_parser(
        "automate",
        help="Form automation and interaction",
    )
    _add_automate_args(automate_p)

    # ---- validate ----
    validate_p = subparsers.add_parser(
        "validate",
        help="Website validation and Stripe testing",
    )
    _add_validate_args(validate_p)

    # ---- export ----
    export_p = subparsers.add_parser(
        "export",
        help="Data export and reporting",
    )
    _add_export_args(export_p)

    # ---- config ----
    config_p = subparsers.add_parser(
        "config",
        help="Configuration management",
    )
    _add_config_args(config_p)

    # ---- db ----
    db_p = subparsers.add_parser(
        "db",
        help="Database operations and queries",
    )
    _add_db_args(db_p)

    return parser


# ---------------------------------------------------------------------------
# Subcommand argument definitions
# ---------------------------------------------------------------------------


def _add_discover_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``discover`` subcommand."""
    p.add_argument(
        "--source",
        type=str,
        choices=["fofa", "shodan", "serper", "all"],
        default="all",
        help="Discovery source(s) to use",
    )
    p.add_argument(
        "--query",
        type=str,
        default="",
        help="Search query string",
    )
    p.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Maximum pages to fetch per source",
    )
    p.add_argument(
        "--save",
        action="store_true",
        help="Save discovered assets to the database",
    )


def _add_github_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``github`` subcommand."""
    p.add_argument(
        "--query",
        type=str,
        default="",
        help="GitHub search query or dork",
    )
    p.add_argument(
        "--token",
        type=str,
        default="",
        help="GitHub personal access token (overrides config)",
    )
    p.add_argument(
        "--analyze",
        action="store_true",
        help="Download and analyze files for secrets",
    )
    p.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Maximum pages to fetch",
    )


def _add_parse_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``parse`` subcommand."""
    p.add_argument(
        "--input",
        type=str,
        default="",
        help="Input file with URLs (one per line)",
    )
    p.add_argument(
        "--url",
        type=str,
        default="",
        help="Single URL to parse",
    )
    p.add_argument(
        "--scan-exposed",
        action="store_true",
        help="Scan for exposed configuration files",
    )
    p.add_argument(
        "--validate-woo",
        action="store_true",
        help="Validate WooCommerce Store API",
    )
    p.add_argument(
        "--save",
        action="store_true",
        help="Save results to the database",
    )


def _add_automate_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``automate`` subcommand."""
    p.add_argument(
        "--url",
        type=str,
        default="",
        help="Target URL for form automation",
    )
    p.add_argument(
        "--discover-forms",
        action="store_true",
        help="Discover forms on the target page",
    )
    p.add_argument(
        "--fill-forms",
        action="store_true",
        help="Fill and submit discovered forms",
    )
    p.add_argument(
        "--login",
        action="store_true",
        help="Attempt login before form interaction",
    )
    p.add_argument(
        "--username",
        type=str,
        default="",
        help="Username for login",
    )
    p.add_argument(
        "--password",
        type=str,
        default="",
        help="Password for login",
    )


def _add_validate_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``validate`` subcommand."""
    p.add_argument(
        "--url",
        type=str,
        default="",
        help="Single URL to validate",
    )
    p.add_argument(
        "--input",
        type=str,
        default="",
        help="Input file with URLs",
    )
    p.add_argument(
        "--test-stripe",
        action="store_true",
        help="Test Stripe key validation",
    )
    p.add_argument(
        "--stripe-key",
        type=str,
        default="",
        help="Stripe key to validate (sk_live_ or pk_live_)",
    )
    p.add_argument(
        "--report",
        type=str,
        default="",
        help="Output path for assessment report",
    )


def _add_export_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``export`` subcommand."""
    p.add_argument(
        "--format",
        type=str,
        choices=["csv", "json", "sql", "html"],
        default="csv",
        help="Export format",
    )
    p.add_argument(
        "--output",
        type=str,
        default="export",
        help="Output file path (without extension)",
    )
    p.add_argument(
        "--status",
        type=str,
        default="",
        help="Filter by asset status",
    )
    p.add_argument(
        "--source",
        type=str,
        default="",
        help="Filter by discovery source",
    )


def _add_config_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``config`` subcommand."""
    p.add_argument(
        "action",
        choices=["show", "check", "path"],
        help="Config action: show current, check validity, show config path",
    )


def _add_db_args(p: argparse.ArgumentParser) -> None:
    """Add arguments for the ``db`` subcommand."""
    p.add_argument(
        "action",
        choices=["stats", "query", "migrate", "backup"],
        help="Database action",
    )
    p.add_argument(
        "--filter",
        type=str,
        default="",
        help="Query filter (key=value pairs)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Query result limit",
    )
    p.add_argument(
        "--sort",
        type=str,
        default="discovered_at",
        help="Sort column",
    )


# ---------------------------------------------------------------------------
# Subcommand dispatch
# ---------------------------------------------------------------------------


async def _cmd_discover(args: argparse.Namespace) -> int:
    """Execute the ``discover`` subcommand."""
    from webrecon.cli.discover import run_discover
    return await run_discover(args)


async def _cmd_github(args: argparse.Namespace) -> int:
    """Execute the ``github`` subcommand."""
    from webrecon.cli.github_cmd import run_github
    return await run_github(args)


async def _cmd_parse(args: argparse.Namespace) -> int:
    """Execute the ``parse`` subcommand."""
    from webrecon.cli.parse import run_parse
    return await run_parse(args)


async def _cmd_automate(args: argparse.Namespace) -> int:
    """Execute the ``automate`` subcommand."""
    from webrecon.cli.automate import run_automate
    return await run_automate(args)


async def _cmd_validate(args: argparse.Namespace) -> int:
    """Execute the ``validate`` subcommand."""
    from webrecon.cli.validate import run_validate
    return await run_validate(args)


async def _cmd_export(args: argparse.Namespace) -> int:
    """Execute the ``export`` subcommand."""
    from webrecon.cli.export import run_export
    return await run_export(args)


async def _cmd_config(args: argparse.Namespace) -> int:
    """Execute the ``config`` subcommand."""
    from webrecon.cli.config import run_config
    return await run_config(args)


async def _cmd_db(args: argparse.Namespace) -> int:
    """Execute the ``db`` subcommand."""
    from webrecon.cli.db import run_db
    return await run_db(args)


_COMMAND_DISPATCH: dict[str, Callable[..., Any]] = {
    "discover": _cmd_discover,
    "github": _cmd_github,
    "parse": _cmd_parse,
    "automate": _cmd_automate,
    "validate": _cmd_validate,
    "export": _cmd_export,
    "config": _cmd_config,
    "db": _cmd_db,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``webrecon`` CLI.

    Args:
        argv: Command-line arguments. Defaults to ``sys.argv[1:]``.

    Returns:
        Exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Configure logging.
    log_level = args.log_level
    if args.verbose:
        log_level = "DEBUG"
    elif args.quiet:
        log_level = "WARNING"
    configure_logging(level=log_level)

    # No subcommand → print help.
    if not args.command:
        parser.print_help()
        return EXIT_OK

    # Dispatch to the subcommand handler.
    handler = _COMMAND_DISPATCH.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_ERROR

    try:
        rc = asyncio.run(handler(args))
        return int(rc)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception as exc:
        _LOGGER.error("webrecon.cli.fatal_error", error=str(exc))
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
