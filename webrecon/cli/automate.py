"""``webrecon automate`` subcommand implementation."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_automate"]

_LOGGER = get_logger(__name__)


async def run_automate(args: argparse.Namespace) -> int:
    """Execute the automate subcommand."""
    from webrecon.config import load_config
    from webrecon.mass_parser.client import MassParserClient

    try:
        loaded = load_config()
        config = loaded.config
    except Exception as exc:
        _LOGGER.error("automate.config_error", error=str(exc))
        return 2

    url = args.url
    if not url:
        print("Error: --url is required", file=sys.stderr)
        return 1

    discover_forms = args.discover_forms
    fill_forms = args.fill_forms
    do_login = args.login
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
        # Form discovery.
        if discover_forms or fill_forms:
            from webrecon.form_automation.discovery import FormDiscoverer
            discoverer = FormDiscoverer(http)
            forms = await discoverer.discover(url)

            for form in forms:
                form_info = {
                    "action_url": form.action_url,
                    "method": form.submission_method,
                    "field_count": len(form.fields),
                    "has_csrf": form.has_csrf_token,
                    "requires_auth": form.requires_auth,
                    "fields": [f.name for f in form.fields],
                }
                results.append({"type": "form_discovery", **form_info})

        # Form filling.
        if fill_forms and results:
            from webrecon.form_automation.discovery import FormDiscoverer
            from webrecon.form_automation.filler import FormFiller
            from webrecon.form_automation.session import FormSession

            # Re-discover forms (we need the actual objects).
            discoverer = FormDiscoverer(http)
            forms = await discoverer.discover(url)

            filler = FormFiller(http)
            session = FormSession(base_url=url)
            await session.initialize(http)

            # Login if requested.
            if do_login and args.username:
                await session.login(
                    login_url=f"{url}/login/",
                    username=args.username,
                    password=args.password,
                )

            for form in forms:
                submission = await filler.fill_and_submit(
                    form,
                    base_url=url,
                    cookies=session.cookies,
                )
                results.append({
                    "type": "form_submission",
                    "action_url": submission.url,
                    "status_code": submission.status_code,
                    "success": submission.is_success,
                    "redirect_url": submission.redirect_url,
                })

            await session.close()

    # Output.
    if output_fmt == "json":
        print(json.dumps(results, indent=2, default=str, ensure_ascii=False))
    else:
        for r in results:
            rtype = r.get("type", "unknown")
            if rtype == "form_discovery":
                print(f"Form: {r.get('action_url', '')} [{r.get('method', '')}] "
                      f"fields={r.get('field_count', 0)} csrf={r.get('has_csrf', False)}")
            elif rtype == "form_submission":
                print(f"Submit: {r.get('action_url', '')} → "
                      f"status={r.get('status_code', 0)} success={r.get('success', False)}")
        print(f"\nTotal: {len(results)}")

    return 0
