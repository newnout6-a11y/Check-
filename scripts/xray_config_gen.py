"""Generate an Xray-core config from a list of VLESS URLs.

Reads a file with one ``vless://...`` URL per line and produces an
Xray-core configuration that:

* exposes a single local SOCKS5 inbound on ``127.0.0.1:10808``
  (and an HTTP inbound on ``127.0.0.1:10809``);
* parses every VLESS URL into a fully-formed outbound;
* groups all outbounds into a balancer so successive requests are
  load-balanced across the entire pool (round-robin / random
  selector).

The resulting config plugs straight into ``xray.exe -c config.json``.
Once Xray is running, point ``webrecon`` at the local SOCKS5 endpoint:

::

    webrecon discover --proxy socks5://127.0.0.1:10808 ...

VLESS URL format reference:
    https://xtls.github.io/Xray-docs-next/en/document/level-2/vless.html

Usage::

    python scripts/xray_config_gen.py --input keys.txt --output config.json
    python scripts/xray_config_gen.py --input keys.txt --output config.json \\
        --selector random
    python scripts/xray_config_gen.py --input keys.txt --output config.json \\
        --inbound-port 10808 --http-port 10809

The script is intentionally dependency-free (stdlib only) so it can
run on a stock Python 3.10+ install with no further setup.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

__all__ = [
    "build_config",
    "main",
    "parse_vless_url",
    "read_vless_file",
]


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_INBOUND_HOST: str = "127.0.0.1"
_DEFAULT_SOCKS_PORT: int = 10808
_DEFAULT_HTTP_PORT: int = 10809
_DEFAULT_SELECTOR: str = "round-robin"  # "random" also accepted by Xray.


# ---------------------------------------------------------------------------
# VLESS URL parsing
# ---------------------------------------------------------------------------


def parse_vless_url(url: str) -> dict[str, Any] | None:
    """Convert a ``vless://...`` URL into an Xray outbound dict.

    VLESS URL grammar (subset commonly seen in client share links)::

        vless://<UUID>@<HOST>:<PORT>?<query>#<remark>

    Where ``query`` carries ``type``, ``security``, ``encryption``,
    ``flow``, ``sni``, ``fp`` (fingerprint), ``pbk`` (public key for
    Reality), ``sid`` (short id for Reality), ``host``, ``path``,
    ``serviceName`` (gRPC), and friends. The function recognises the
    most common combinations: TCP/Reality, TCP/TLS, ws+TLS, grpc.
    Unknown query keys are dropped silently rather than failing the
    whole config build.

    Returns:
        An Xray outbound mapping ready to be serialised into
        ``config.json``, or ``None`` if the URL cannot be parsed.
    """
    cleaned = url.strip()
    if not cleaned.lower().startswith("vless://"):
        return None

    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return None

    if not parsed.username or not parsed.hostname or not parsed.port:
        return None

    user_id = parsed.username
    host = parsed.hostname
    port = int(parsed.port)
    remark = unquote(parsed.fragment or "")

    qs = parse_qs(parsed.query, keep_blank_values=True)
    network = (qs.get("type", ["tcp"])[0] or "tcp").lower()
    security = (qs.get("security", ["none"])[0] or "none").lower()
    encryption = qs.get("encryption", ["none"])[0] or "none"
    flow = qs.get("flow", [""])[0] or ""

    sni = qs.get("sni", [""])[0] or qs.get("peer", [""])[0] or ""
    fingerprint = qs.get("fp", [""])[0] or "chrome"
    public_key = qs.get("pbk", [""])[0] or ""
    short_id = qs.get("sid", [""])[0] or ""
    spider_x = qs.get("spx", [""])[0] or ""

    user: dict[str, Any] = {
        "id": user_id,
        "encryption": encryption,
    }
    if flow:
        user["flow"] = flow

    outbound: dict[str, Any] = {
        "tag": _make_tag(host, port, remark),
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": _build_stream_settings(
            network=network,
            security=security,
            sni=sni,
            fingerprint=fingerprint,
            public_key=public_key,
            short_id=short_id,
            spider_x=spider_x,
            host_header=qs.get("host", [""])[0] or "",
            path=qs.get("path", ["/"])[0] or "/",
            service_name=qs.get("serviceName", [""])[0] or "",
        ),
    }

    return outbound


def _build_stream_settings(
    *,
    network: str,
    security: str,
    sni: str,
    fingerprint: str,
    public_key: str,
    short_id: str,
    spider_x: str,
    host_header: str,
    path: str,
    service_name: str,
) -> dict[str, Any]:
    """Translate the URL parameters into Xray ``streamSettings``."""
    settings: dict[str, Any] = {
        "network": network,
        "security": security,
    }

    if security == "reality":
        reality: dict[str, Any] = {
            "fingerprint": fingerprint or "chrome",
        }
        if sni:
            reality["serverName"] = sni
        if public_key:
            reality["publicKey"] = public_key
        if short_id:
            reality["shortId"] = short_id
        if spider_x:
            reality["spiderX"] = spider_x
        settings["realitySettings"] = reality
    elif security == "tls":
        tls: dict[str, Any] = {"fingerprint": fingerprint or "chrome"}
        if sni:
            tls["serverName"] = sni
        settings["tlsSettings"] = tls
    elif security == "xtls":
        # Legacy xtls; mostly superseded by reality + flow=xtls-rprx-vision.
        xtls: dict[str, Any] = {"fingerprint": fingerprint or "chrome"}
        if sni:
            xtls["serverName"] = sni
        settings["xtlsSettings"] = xtls

    if network == "ws":
        ws: dict[str, Any] = {"path": path or "/"}
        if host_header:
            ws["headers"] = {"Host": host_header}
        settings["wsSettings"] = ws
    elif network == "grpc":
        settings["grpcSettings"] = {
            "serviceName": service_name or "",
        }
    elif network == "tcp":
        settings["tcpSettings"] = {"header": {"type": "none"}}

    return settings


def _make_tag(host: str, port: int, remark: str) -> str:
    """Construct a stable, human-readable outbound tag.

    The tag must start with ``vless-`` because the balancer selector
    (configured in :func:`build_config`) targets that prefix.
    """
    safe_remark = "".join(
        ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in remark
    )
    safe_remark = safe_remark.strip("-")
    if safe_remark:
        return f"vless-{host}-{port}-{safe_remark}"[:120]
    return f"vless-{host}-{port}"[:120]


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------


def read_vless_file(path: Path) -> list[str]:
    """Read a file with one VLESS URL per line.

    Blank lines and lines starting with ``#`` are ignored so the
    operator can keep human-readable comments next to each key.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    urls: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


# ---------------------------------------------------------------------------
# Config assembly
# ---------------------------------------------------------------------------


def build_config(
    outbounds: list[dict[str, Any]],
    *,
    socks_port: int = _DEFAULT_SOCKS_PORT,
    http_port: int = _DEFAULT_HTTP_PORT,
    inbound_host: str = _DEFAULT_INBOUND_HOST,
    selector: str = _DEFAULT_SELECTOR,
) -> dict[str, Any]:
    """Assemble the final ``config.json`` document.

    Args:
        outbounds: List of VLESS outbounds (output of
            :func:`parse_vless_url`). At least one is required.
        socks_port: TCP port for the SOCKS5 inbound on ``127.0.0.1``.
        http_port: TCP port for the HTTP inbound. Pass ``0`` to skip
            the HTTP inbound.
        inbound_host: Bind address for the local inbounds.
            ``127.0.0.1`` is the safe default; ``0.0.0.0`` is
            available for VM/container scenarios but exposes the
            proxy to the local network.
        selector: Balancer strategy. Xray accepts ``"random"`` and
            ``"round-robin"`` (the default).

    Returns:
        The serialisable Xray-core config.
    """
    if not outbounds:
        raise ValueError("at least one outbound is required")

    inbounds: list[dict[str, Any]] = [
        {
            "tag": "socks-in",
            "listen": inbound_host,
            "port": socks_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True,
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
            },
        }
    ]
    if http_port:
        inbounds.append(
            {
                "tag": "http-in",
                "listen": inbound_host,
                "port": http_port,
                "protocol": "http",
            }
        )

    config: dict[str, Any] = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            *outbounds,
            # A direct outbound is needed so locally-resolved DNS
            # queries and similar can bypass the proxy if Xray's
            # routing rules opt them out.
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [
                {
                    "tag": "vless-pool",
                    "selector": ["vless-"],
                    "strategy": {"type": selector},
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "balancerTag": "vless-pool",
                    "network": "tcp,udp",
                }
            ],
        },
    }
    return config


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        prog="xray_config_gen",
        description=(
            "Generate an Xray-core config from a list of VLESS URLs. "
            "Produces one local SOCKS5 inbound that load-balances "
            "every key in the pool."
        ),
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to the file with VLESS URLs (one per line)",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Path to the resulting config.json",
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=_DEFAULT_SOCKS_PORT,
        help=f"Local SOCKS5 port (default {_DEFAULT_SOCKS_PORT})",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=_DEFAULT_HTTP_PORT,
        help=(
            f"Local HTTP proxy port (default {_DEFAULT_HTTP_PORT}, "
            "set to 0 to disable)"
        ),
    )
    parser.add_argument(
        "--inbound-host",
        type=str,
        default=_DEFAULT_INBOUND_HOST,
        help=(
            f"Inbound bind address (default {_DEFAULT_INBOUND_HOST}). "
            "Use 0.0.0.0 only on isolated VMs."
        ),
    )
    parser.add_argument(
        "--selector",
        type=str,
        default=_DEFAULT_SELECTOR,
        choices=("round-robin", "random"),
        help="Balancer strategy",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_path = Path(args.output)

    try:
        urls = read_vless_file(input_path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not urls:
        print(f"Error: no VLESS URLs in {input_path}", file=sys.stderr)
        return 1

    outbounds: list[dict[str, Any]] = []
    bad: list[str] = []
    for url in urls:
        ob = parse_vless_url(url)
        if ob is None:
            bad.append(url)
            continue
        outbounds.append(ob)

    if bad:
        print(
            f"Warning: skipped {len(bad)} unparseable URL(s):",
            file=sys.stderr,
        )
        for u in bad[:5]:
            print(f"  - {u[:80]}", file=sys.stderr)
        if len(bad) > 5:
            print(f"  ... and {len(bad) - 5} more", file=sys.stderr)

    if not outbounds:
        print("Error: no parseable VLESS URLs found", file=sys.stderr)
        return 1

    config = build_config(
        outbounds,
        socks_port=args.socks_port,
        http_port=args.http_port,
        inbound_host=args.inbound_host,
        selector=args.selector,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        f"Wrote Xray config: {output_path} "
        f"({len(outbounds)} outbound(s), socks5 on "
        f"{args.inbound_host}:{args.socks_port})",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
