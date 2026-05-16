"""``webrecon validate`` subcommand implementation."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_validate"]

_LOGGER = get_logger(__name__)


async def run_validate(args: argparse.Namespace) -> int:
    """Execute the validate subcommand."""
    from webrecon.config import load_config
    from webrecon.mass_parser.client import MassParserClient

    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("validate.config_error", error=str(exc))
        return 2

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

    # Single Stripe key validation.
    if args.stripe_key:
        async with MassParserClient(
            concurrency=1, proxy=proxy_arg
        ) as http:
            from webrecon.automation.stripe_tester import StripeTester
            tester = StripeTester(http)

            key = args.stripe_key
            if key.startswith(("sk_", "rk_")):
                sk_result = await tester.validate_sk(key)
                _print_sk_result(sk_result, output_fmt)
                return 0 if sk_result.is_valid else 5
            if key.startswith("pk_"):
                pk_result = await tester.test_pk_tokenization(key)
                _print_pk_result(pk_result, output_fmt)
                return 0 if pk_result.tokenization_status == "ok" else 5
            print(f"Error: Unrecognised key prefix: {key[:8]}", file=sys.stderr)
            return 1

    # Website validation.
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
        print("Error: --url, --input, or --stripe-key is required", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []

    async with MassParserClient(
        concurrency=concurrency, proxy=proxy_arg
    ) as http:
        from webrecon.automation.validator import WebsiteValidator
        validator = WebsiteValidator(http)

        for url in urls:
            validation_report = await validator.validate(url)
            results.append({
                "url": url,
                "tech_stack": validation_report.tech_stack,
                "security_score": validation_report.security_score,
                "has_ssl": validation_report.has_ssl,
                "response_time_ms": round(validation_report.response_time_ms, 1),
            })

        # Stripe testing on validated sites.
        if args.test_stripe:
            from webrecon.automation.reporter import AssessmentReporter
            from webrecon.automation.stripe_tester import StripeTester
            tester = StripeTester(http)

            sk_results: list[Any] = []
            pk_results: list[Any] = []

            for url in urls:
                # Check for pk_live_ keys in the page.
                from webrecon.mass_parser.woocommerce import WooCommerceValidator
                woo = WooCommerceValidator(http, test_tokenization=True)
                woo_result = await woo.validate(url)

                if woo_result.pk_key:
                    pk_result = await tester.test_pk_tokenization(woo_result.pk_key)
                    pk_results.append(pk_result)

            # Generate report if requested.
            if args.report:
                reporter = AssessmentReporter()
                assessment = reporter.generate_report(
                    validation_reports=None,
                    sk_results=sk_results if sk_results else None,
                    pk_results=pk_results if pk_results else None,
                )
                if args.report.endswith(".html"):
                    reporter.save_html(assessment, args.report)
                elif args.report.endswith(".json"):
                    reporter.save_json(assessment, args.report)
                else:
                    reporter.save_json(assessment, args.report + ".json")

    # Output.
    if output_fmt == "json":
        print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
    else:
        for r in results:
            print(f"{r['url']}: tech={','.join(r['tech_stack'][:5])} "
                  f"security={r['security_score']}% ssl={r['has_ssl']} "
                  f"time={r['response_time_ms']}ms")
        print(f"\nTotal: {len(results)}")

    return 0


def _print_sk_result(result: Any, fmt: str) -> None:
    """Print a secret key validation result."""
    if fmt == "json":
        print(json.dumps({
            "is_valid": result.is_valid,
            "key_type": result.key_type.value,
            "account_id": result.account_id,
            "risk_level": result.risk_level,
            "error": result.error_message,
        }, indent=2))
    else:
        status = "VALID" if result.is_valid else "INVALID"
        print(f"Key: {result.key_value} → {status} "
              f"type={result.key_type.value} risk={result.risk_level}")
        if result.account_id:
            print(f"  Account: {result.account_id}")
        if result.error_message:
            print(f"  Error: {result.error_message}")


def _print_pk_result(result: Any, fmt: str) -> None:
    """Print a public key tokenization result."""
    if fmt == "json":
        print(json.dumps({
            "tokenization_status": result.tokenization_status,
            "payment_method_id": result.payment_method_id,
            "error": result.error_message,
        }, indent=2))
    else:
        status = result.tokenization_status or "unknown"
        print(f"Key: {result.key_value} → tokenization={status}")
        if result.payment_method_id:
            print(f"  PM ID: {result.payment_method_id}")
        if result.error_message:
            print(f"  Error: {result.error_message}")
