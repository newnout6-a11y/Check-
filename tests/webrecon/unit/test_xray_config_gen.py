"""Unit tests for ``scripts/xray_config_gen.py``.

Covers VLESS URL parsing (TCP/Reality, ws+TLS, gRPC), error
handling for malformed URLs, file reading (comments and blank
lines), and the assembled Xray configuration shape.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# The script lives outside the package import path; load it as a
# top-level module so the tests can exercise it directly.
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS_DIR))

from xray_config_gen import (  # noqa: E402  -- post sys.path tweak
    build_config,
    main,
    parse_vless_url,
    read_vless_file,
)

# ---------------------------------------------------------------------------
# parse_vless_url
# ---------------------------------------------------------------------------


class TestParseVlessUrl:
    def test_tcp_reality_url(self) -> None:
        url = (
            "vless://uuid-aaaa-1111@example.com:443"
            "?type=tcp&security=reality&pbk=PUB&sid=ID&sni=www.microsoft.com"
            "&fp=chrome&flow=xtls-rprx-vision#node-1"
        )
        ob = parse_vless_url(url)
        assert ob is not None
        assert ob["protocol"] == "vless"
        assert ob["tag"].startswith("vless-")
        assert "node-1" in ob["tag"]
        vnext = ob["settings"]["vnext"][0]
        assert vnext["address"] == "example.com"
        assert vnext["port"] == 443
        user = vnext["users"][0]
        assert user["id"] == "uuid-aaaa-1111"
        assert user["flow"] == "xtls-rprx-vision"
        ss = ob["streamSettings"]
        assert ss["network"] == "tcp"
        assert ss["security"] == "reality"
        reality = ss["realitySettings"]
        assert reality["serverName"] == "www.microsoft.com"
        assert reality["publicKey"] == "PUB"
        assert reality["shortId"] == "ID"
        assert reality["fingerprint"] == "chrome"

    def test_ws_tls_url(self) -> None:
        url = (
            "vless://uuid-bbbb@cdn.example.com:443"
            "?type=ws&security=tls&path=%2Fapi&host=cdn.example.com"
            "&sni=cdn.example.com#ws-node"
        )
        ob = parse_vless_url(url)
        assert ob is not None
        ss = ob["streamSettings"]
        assert ss["network"] == "ws"
        assert ss["security"] == "tls"
        assert ss["wsSettings"]["path"] == "/api"
        assert ss["wsSettings"]["headers"]["Host"] == "cdn.example.com"
        assert ss["tlsSettings"]["serverName"] == "cdn.example.com"

    def test_grpc_url(self) -> None:
        url = (
            "vless://uuid-cccc@grpc.example.com:443"
            "?type=grpc&security=tls&serviceName=secret/grpc&sni=grpc.example.com"
        )
        ob = parse_vless_url(url)
        assert ob is not None
        ss = ob["streamSettings"]
        assert ss["network"] == "grpc"
        assert ss["grpcSettings"]["serviceName"] == "secret/grpc"

    def test_unknown_scheme_returns_none(self) -> None:
        assert parse_vless_url("https://example.com") is None
        assert parse_vless_url("vmess://abc") is None

    def test_missing_credentials_returns_none(self) -> None:
        assert parse_vless_url("vless://@example.com:443") is None
        assert parse_vless_url("vless://uuid@example.com") is None

    def test_blank_returns_none(self) -> None:
        assert parse_vless_url("") is None
        assert parse_vless_url("   ") is None

    def test_remark_with_special_chars_is_sanitised(self) -> None:
        # Hash characters / unicode in the remark must not break the tag.
        url = (
            "vless://uuid-dddd@host.example.com:443"
            "?type=tcp&security=none#A B/Test"
        )
        ob = parse_vless_url(url)
        assert ob is not None
        # Tag should not contain whitespace or '/'.
        assert " " not in ob["tag"]
        assert "/" not in ob["tag"]


# ---------------------------------------------------------------------------
# read_vless_file
# ---------------------------------------------------------------------------


class TestReadVlessFile:
    def test_strips_comments_and_blank_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "keys.txt"
        path.write_text(
            "# Pool of VLESS keys\n\n"
            "vless://uuid1@host1:443\n"
            "  vless://uuid2@host2:443  \n"
            "\n"
            "# vless://commented-out@disabled:443\n"
            "vless://uuid3@host3:443\n",
            encoding="utf-8",
        )
        urls = read_vless_file(path)
        assert urls == [
            "vless://uuid1@host1:443",
            "vless://uuid2@host2:443",
            "vless://uuid3@host3:443",
        ]

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            read_vless_file(tmp_path / "nope.txt")


# ---------------------------------------------------------------------------
# build_config
# ---------------------------------------------------------------------------


class TestBuildConfig:
    def test_assembles_full_config_shape(self) -> None:
        ob = parse_vless_url(
            "vless://uuid@host.example.com:443?type=tcp&security=none#a"
        )
        assert ob is not None
        cfg = build_config([ob])
        assert cfg["inbounds"][0]["protocol"] == "socks"
        assert cfg["inbounds"][0]["port"] == 10808
        assert any(o["tag"] == "direct" for o in cfg["outbounds"])
        assert any(o["tag"] == "block" for o in cfg["outbounds"])
        # The VLESS outbound is preserved before the helper outbounds.
        assert cfg["outbounds"][0]["protocol"] == "vless"
        # Balancer wires every vless-* outbound.
        balancer = cfg["routing"]["balancers"][0]
        assert balancer["selector"] == ["vless-"]

    def test_http_port_zero_disables_http_inbound(self) -> None:
        ob = parse_vless_url(
            "vless://uuid@host.example.com:443?type=tcp&security=none#a"
        )
        assert ob is not None
        cfg = build_config([ob], http_port=0)
        assert len(cfg["inbounds"]) == 1
        assert cfg["inbounds"][0]["protocol"] == "socks"

    def test_random_selector(self) -> None:
        ob = parse_vless_url(
            "vless://uuid@host.example.com:443?type=tcp&security=none#a"
        )
        assert ob is not None
        cfg = build_config([ob], selector="random")
        assert cfg["routing"]["balancers"][0]["strategy"]["type"] == "random"

    def test_empty_outbounds_raises(self) -> None:
        with pytest.raises(ValueError):
            build_config([])


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


class TestMain:
    def test_writes_config_file(self, tmp_path: Path) -> None:
        keys = tmp_path / "keys.txt"
        keys.write_text(
            "vless://uuid-1@host1.example.com:443?type=tcp&security=reality"
            "&pbk=K&sid=I&sni=www.microsoft.com&flow=xtls-rprx-vision#node-1\n"
            "vless://uuid-2@host2.example.com:443?type=ws&security=tls"
            "&path=/api&host=cdn.example.com#node-2\n",
            encoding="utf-8",
        )
        cfg_path = tmp_path / "out" / "config.json"
        rc = main(
            [
                "--input", str(keys),
                "--output", str(cfg_path),
                "--socks-port", "10800",
                "--http-port", "0",
            ]
        )
        assert rc == 0
        assert cfg_path.is_file()
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        # Two VLESS outbounds + direct + block.
        assert len(cfg["outbounds"]) == 4
        assert cfg["inbounds"][0]["port"] == 10800
        # No HTTP inbound when http_port=0.
        assert len(cfg["inbounds"]) == 1

    def test_no_urls_returns_error(self, tmp_path: Path) -> None:
        keys = tmp_path / "empty.txt"
        keys.write_text("# only comments\n\n", encoding="utf-8")
        rc = main(
            [
                "--input", str(keys),
                "--output", str(tmp_path / "out.json"),
            ]
        )
        assert rc == 1

    def test_missing_input_returns_error(self, tmp_path: Path) -> None:
        rc = main(
            [
                "--input", str(tmp_path / "missing.txt"),
                "--output", str(tmp_path / "out.json"),
            ]
        )
        assert rc == 2

    def test_unparseable_urls_skipped_with_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        keys = tmp_path / "mix.txt"
        keys.write_text(
            "vless://uuid@host.example.com:443?type=tcp&security=none#ok\n"
            "https://not-a-vless-url.example.com\n"
            "garbage line\n",
            encoding="utf-8",
        )
        cfg_path = tmp_path / "out.json"
        rc = main(
            [
                "--input", str(keys),
                "--output", str(cfg_path),
                "--http-port", "0",
            ]
        )
        assert rc == 0
        captured = capsys.readouterr()
        assert "skipped 2" in captured.err
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        # 1 VLESS outbound + direct + block.
        assert len(cfg["outbounds"]) == 3
