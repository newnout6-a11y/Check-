"""Proxy resolution helpers for the CLI.

The ``--proxy`` and ``--proxy-file`` global flags accept proxy URLs
in any of the schemes supported by :mod:`httpx`:

* ``http://[user:pass@]host:port``
* ``https://[user:pass@]host:port``
* ``socks5://[user:pass@]host:port`` (requires the ``httpx[socks]``
  extra; SOCKS support is provided by the ``socksio`` package).
* ``socks5h://...`` is mapped to ``socks5://...`` because
  ``httpx`` resolves DNS through the proxy by default.

Multiple URLs can be supplied either by:

* comma-separating them in ``--proxy``
  (``--proxy "socks5://127.0.0.1:10808,socks5://127.0.0.1:10809"``);
* listing one per line in a file passed via ``--proxy-file``
  (lines starting with ``#`` are comments; blank lines are
  ignored).

The two sources are merged in declaration order. A single resolved
proxy is returned as a string (used directly by clients that take
one proxy); a list is returned to clients that support
round-robin rotation.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "resolve_proxies",
]


def _normalise(url: str) -> str:
    """Strip whitespace and rewrite ``socks5h://`` to ``socks5://``.

    httpx routes DNS through the proxy for every SOCKS scheme, so the
    distinction between ``socks5`` and ``socks5h`` does not matter to
    it; rewriting keeps the input space tidy.
    """
    cleaned = url.strip()
    if cleaned.lower().startswith("socks5h://"):
        return "socks5://" + cleaned[len("socks5h://"):]
    return cleaned


def _split_inline(value: str) -> list[str]:
    """Parse a comma-separated proxy list."""
    if not value:
        return []
    return [_normalise(part) for part in value.split(",") if part.strip()]


def _read_file(path: str) -> list[str]:
    """Read a proxy file, ignoring blank lines and ``#`` comments."""
    if not path:
        return []
    proxies: list[str] = []
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"--proxy-file not found: {path}")
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        proxies.append(_normalise(line))
    return proxies


def resolve_proxies(
    inline: str | None,
    file_path: str | None,
) -> list[str]:
    """Merge ``--proxy`` and ``--proxy-file`` into a deduplicated list.

    Args:
        inline: Value of the ``--proxy`` flag (may be empty).
        file_path: Value of the ``--proxy-file`` flag (may be empty).

    Returns:
        Ordered, deduplicated list of proxy URLs. Empty when neither
        source provided any proxies.
    """
    merged: list[str] = []
    seen: set[str] = set()

    for source in (_split_inline(inline or ""), _read_file(file_path or "")):
        for url in source:
            if url and url not in seen:
                merged.append(url)
                seen.add(url)

    return merged
