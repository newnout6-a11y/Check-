"""Unit tests for :mod:`webrecon.cli.proxy`."""

from __future__ import annotations

from pathlib import Path

import pytest

from webrecon.cli.proxy import resolve_proxies


class TestResolveProxies:
    def test_inline_only_comma_separated(self) -> None:
        result = resolve_proxies(
            "socks5://127.0.0.1:10808, http://proxy.example:8080",
            None,
        )
        assert result == [
            "socks5://127.0.0.1:10808",
            "http://proxy.example:8080",
        ]

    def test_socks5h_rewritten_to_socks5(self) -> None:
        result = resolve_proxies("socks5h://127.0.0.1:10808", None)
        assert result == ["socks5://127.0.0.1:10808"]

    def test_file_only_with_comments_and_blanks(self, tmp_path: Path) -> None:
        path = tmp_path / "proxies.txt"
        path.write_text(
            "# Header\n\n"
            "socks5://127.0.0.1:10808\n"
            "  socks5://127.0.0.1:10809  \n"
            "# socks5://127.0.0.1:10810\n",
            encoding="utf-8",
        )
        result = resolve_proxies(None, str(path))
        assert result == [
            "socks5://127.0.0.1:10808",
            "socks5://127.0.0.1:10809",
        ]

    def test_inline_and_file_merged_dedup(self, tmp_path: Path) -> None:
        path = tmp_path / "proxies.txt"
        path.write_text(
            "socks5://127.0.0.1:10808\n"
            "socks5://127.0.0.1:10809\n",
            encoding="utf-8",
        )
        result = resolve_proxies(
            "socks5://127.0.0.1:10808, http://proxy.example:8080",
            str(path),
        )
        # Inline first, file appended, duplicates removed.
        assert result == [
            "socks5://127.0.0.1:10808",
            "http://proxy.example:8080",
            "socks5://127.0.0.1:10809",
        ]

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            resolve_proxies(None, str(tmp_path / "missing.txt"))

    def test_no_inputs_returns_empty(self) -> None:
        assert resolve_proxies(None, None) == []
        assert resolve_proxies("", "") == []
