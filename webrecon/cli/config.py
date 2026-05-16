"""``webrecon config`` subcommand implementation."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from webrecon.log import get_logger

if TYPE_CHECKING:
    import argparse

__all__ = ["run_config"]

_LOGGER = get_logger(__name__)


async def run_config(args: argparse.Namespace) -> int:
    """Execute the config subcommand."""
    from webrecon.config import load_config

    action = args.action

    if action == "show":
        try:
            loaded = load_config()
            config = loaded.config
        except Exception as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2

        # Print the resolved config (with sensitive values masked).
        data = config.model_dump()
        _mask_sensitive(data)
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))

        # Print resolution map if available.
        if loaded.resolution:
            print("\n--- Resolution map ---")
            for field_path, source in sorted(loaded.resolution.items()):
                src = source.value if hasattr(source, "value") else str(source)
                print(f"  {field_path}: {src}")

    elif action == "check":
        try:
            loaded = load_config()
            print("Configuration is valid.")
            # Report missing optional keys.
            missing = []
            if not loaded.config.api_keys.fofa:
                missing.append("fofa")
            if not loaded.config.api_keys.shodan:
                missing.append("shodan")
            if not loaded.config.api_keys.serper:
                missing.append("serper")
            if not loaded.config.api_keys.github:
                missing.append("github")
            if not loaded.config.api_keys.stripe:
                missing.append("stripe")
            if missing:
                print(f"Optional API keys not configured: {', '.join(missing)}")
            return 0
        except Exception as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2

    elif action == "path":
        from pathlib import Path
        # Show potential config file paths.
        home = Path.home()
        print(f"Home .env: {home / '.env'}")
        print(f"CWD .env: {Path.cwd() / '.env'}")
        print(f"Database: {Path.cwd() / 'webrecon.sqlite3'}")

    return 0


def _mask_sensitive(data: dict[str, Any], _depth: int = 0) -> None:
    """Mask sensitive values in a config dict for safe display."""
    sensitive_keys = {"key", "token", "secret", "password", "stripe", "shodan", "serper", "github"}
    for k, v in list(data.items()):
        if isinstance(v, dict):
            _mask_sensitive(v, _depth + 1)
        elif isinstance(v, str) and any(s in k.lower() for s in sensitive_keys):
            if len(v) > 8:
                data[k] = v[:4] + "..." + v[-4:]
            elif v:
                data[k] = "***"
