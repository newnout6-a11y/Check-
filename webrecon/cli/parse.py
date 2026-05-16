"""``webrecon parse`` subcommand implementation."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_parse"]

_LOGGER = get_logger(__name__)


async def run_parse(args: argparse.Namespace) -> int:
    """Execute the parse subcommand."""
    from webrecon.config import load_config
    from webrecon.database import open_database
    from webrecon.mass_parser.client import MassParserClient

    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("parse.config_error", error=str(exc))
        return 2

    # Collect URLs.
    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    if args.input:
        from pathlib import Path
        input_path = Path(args.input)
        if input_path.exists():
            for line in input_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

    if not urls:
        print("Error: --url or --input is required", file=sys.stderr)
        return 1

    scan_exposed = args.scan_exposed
    validate_woo = args.validate_woo
    save = args.save
    output_fmt = getattr(args, "output", "table")
    concurrency = args.concurrency or config.concurrency.semaphore_size

    # Resolve proxies from --proxy / --proxy-file.
    from webrecon.cli.proxy import resolve_proxies
    try:
        proxies = resolve_proxies(
            getattr(args, "proxy", ""),
            getattr(args, "proxy_file", ""),
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    proxy_arg: str | list[str] | None = None
    if len(proxies) == 1:
        proxy_arg = proxies[0]
    elif proxies:
        proxy_arg = proxies

    results: list[dict[str, Any]] = []

    async with MassParserClient(
        concurrency=concurrency, proxy=proxy_arg
    ) as http:
        # Exposed file scanning.
        if scan_exposed:
            from webrecon.mass_parser.scanner import ExposedFileScanner
            scanner = ExposedFileScanner(http)
            async for scan_result in scanner.scan_sites(urls):
                results.append({
                    "type": "exposed_file",
                    "url": scan_result.url,
                    "status_code": scan_result.status_code,
                    "accessible": scan_result.accessible,
                    "stripe_keys": [k.key_value[:20] + "..." for k in scan_result.found_keys],
                    "other_secrets": len(scan_result.other_secrets),
                })

        # WooCommerce validation.
        if validate_woo:
            from webrecon.mass_parser.woocommerce import WooCommerceValidator
            validator = WooCommerceValidator(http)
            for url in urls:
                woo_result = await validator.validate(url)
                if woo_result.asset:
                    results.append({
                        "type": "woocommerce",
                        "url": url,
                        "store_api": woo_result.store_api_available,
                        "pk_key": woo_result.pk_key[:20] + "..." if woo_result.pk_key else "",
                        "tokenization": woo_result.tokenization_status,
                        "stripe_version": woo_result.stripe_version,
                        "country": woo_result.country,
                    })

        # If neither scan nor validate, just do a basic fetch.
        if not scan_exposed and not validate_woo:
            for url in urls:
                resp = await http.get(url, timeout=10.0)
                results.append({
                    "type": "fetch",
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.text),
                })

    # Save to database.
    if save and results:
        pool = await open_database(config.database.path)
        await pool.close()

    # Output.
    if output_fmt == "json":
        print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
    else:
        for r in results:
            parts = [f"{k}={v}" for k, v in r.items() if v]
            print("  ".join(parts))
        print(f"\nTotal: {len(results)}")

    return 0
