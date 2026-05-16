"""``webrecon github`` subcommand implementation."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_github"]

_LOGGER = get_logger(__name__)


async def run_github(args: argparse.Namespace) -> int:
    """Execute the github subcommand."""
    from webrecon.config import load_config

    # Load config.
    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("github.config_error", error=str(exc))
        return 2

    token = args.token or (config.api_keys.github or "")
    if not token:
        print(
            "Error: GitHub token required (--token or WEBRECON_API_KEYS__GITHUB)",
            file=sys.stderr,
        )
        return 3

    query = args.query
    if not query:
        print("Error: --query is required", file=sys.stderr)
        return 1

    analyze = args.analyze
    max_pages = args.max_pages
    output_fmt = getattr(args, "output", "table")

    import httpx

    from webrecon.github import GithubClient
    from webrecon.github.analyzer import GithubAnalyzer

    secrets_found: list[dict[str, Any]] = []
    matches_found: list[dict[str, Any]] = []

    async with httpx.AsyncClient() as http:
        client = GithubClient(http, token=token)

        if analyze:
            # Search + analyze workflow.
            analyzer = GithubAnalyzer(client)
            async for secret in analyzer.analyze_query(query, max_pages=max_pages):
                secrets_found.append({
                    "pattern_name": secret.pattern_name,
                    "secret_value": secret.secret_value[:20] + "...",
                    "severity": secret.severity,
                    "file_path": secret.file_path,
                    "repository_name": secret.repository_name,
                    "html_url": secret.html_url,
                })
                _LOGGER.info(
                    "github.secret_found",
                    pattern=secret.pattern_name,
                    repo=secret.repository_name,
                    severity=secret.severity,
                )
        else:
            # Search-only workflow.
            async for match in client.search_code(query, max_pages=max_pages):
                matches_found.append({
                    "name": match.name,
                    "path": match.path,
                    "repository": match.repository.get("full_name", ""),
                    "html_url": match.html_url,
                })
                _LOGGER.info(
                    "github.match_found",
                    repo=match.repository.get("full_name", ""),
                    path=match.path,
                )

    # Output.
    if analyze:
        _output_results(secrets_found, output_fmt, "secrets")
    else:
        _output_results(matches_found, output_fmt, "matches")

    if not (secrets_found or matches_found):
        _LOGGER.info("github.no_results")
        return 5

    return 0


def _output_results(results: list[dict[str, Any]], fmt: str, label: str) -> None:
    """Format and print results."""
    if fmt == "json":
        print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
    else:
        if not results:
            print(f"No {label} found.")
            return
        for r in results:
            parts = [f"{k}={v}" for k, v in r.items() if v]
            print("  ".join(parts))
        print(f"\nTotal {label}: {len(results)}")
