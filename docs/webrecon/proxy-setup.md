# Proxy setup (VLESS / SOCKS / HTTP)

`webrecon` talks to remote services over plain HTTP/HTTPS through
`httpx`. To route that traffic through a proxy you have two options:

1. **HTTP / HTTPS / SOCKS5 proxy** -- supported by `httpx` natively.
   Pass the URL via `--proxy` and you are done.
2. **VLESS (Xray-core / V2Ray)** -- not an HTTP-level protocol;
   needs a local bridge that exposes a SOCKS5 endpoint to `httpx`.

This document covers both. Skip ahead to the [Quick recipes](#quick-recipes)
if you already have a proxy URL.

## Concepts

```
+-----------+       +--------------------+        +------------------+
|  webrecon |  -->  |  local proxy       |  -->   |  remote service  |
| (httpx)   |       |  (Xray / Squid /   |        |  (FOFA / Stripe) |
|           |       |   raw SOCKS / ...) |        |                  |
+-----------+       +--------------------+        +------------------+
        --proxy socks5://127.0.0.1:10808
```

Anything `httpx` accepts as `proxy=` is supported. The CLI flags
`--proxy` and `--proxy-file` route the value into
`MassParserClient(proxy=...)` for every subcommand that opens an
HTTP client.

## Supported proxy URL forms

| Scheme | Example | Notes |
| --- | --- | --- |
| `http://` | `http://user:pass@proxy.example:8080` | Plain HTTP CONNECT |
| `https://` | `https://proxy.example:8443` | TLS upstream of the proxy |
| `socks5://` | `socks5://127.0.0.1:10808` | Requires `httpx[socks]` (the `socksio` dependency, included with the project's `dev` extra) |
| `socks5h://` | `socks5h://127.0.0.1:10808` | Same as `socks5://`; `httpx` resolves DNS through the proxy by default |

## VLESS via Xray-core

VLESS is the protocol most "free" key-pool services hand out. Xray
(or V2Ray) terminates VLESS locally and re-exposes the connection as
a SOCKS5 inbound that `webrecon` can use.

### One-time setup on Windows

1. Download Xray-core release zip:
   <https://github.com/XTLS/Xray-core/releases>.
2. Extract somewhere stable, e.g. `C:\xray\`.
3. Generate a config from your VLESS pool with the helper script
   shipped in this repo:

```cmd
python scripts\xray_config_gen.py ^
    --input C:\xray\keys.txt ^
    --output C:\xray\config.json
```

The script accepts a file with one `vless://...` URL per line
(`#`-prefixed lines are comments). It produces:

* a single SOCKS5 inbound on `127.0.0.1:10808`;
* a single HTTP inbound on `127.0.0.1:10809`;
* one outbound per VLESS key, all members of a `vless-pool`
  balancer (round-robin by default; pass `--selector random` to
  spread load uniformly).

4. Launch Xray:

```cmd
C:\xray\xray.exe -c C:\xray\config.json
```

Leave the terminal open. To run Xray as a Windows service, use
[NSSM](https://nssm.cc/) or Task Scheduler with "run on logon /
without console window".

5. Sanity-check the proxy:

```cmd
curl -x socks5://127.0.0.1:10808 https://api.ipify.org
```

The returned IP should be one of your VLESS exit nodes, not your
home address.

### Switching from a single key to a 100-key pool

Drop every `vless://...` URL into `C:\xray\keys.txt`. Rerun
`xray_config_gen.py` and restart Xray. The balancer rotates the
pool automatically; `webrecon` does not need any further changes.

### Legacy / minimal config

If you would rather hand-craft the Xray config (e.g. one key only),
the project's [getting-started document](getting-started.md) and
the [Xray VLESS reference](https://xtls.github.io/Xray-docs-next/en/document/level-2/vless.html)
both walk through it. The generator output is a good starting
template.

## Wiring the proxy into webrecon

Three equivalent ways:

**Inline:**

```cmd
webrecon discover --source serper --query "site:example.com" ^
    --proxy socks5://127.0.0.1:10808
```

**File (one URL per line):**

```cmd
:: proxies.txt:
::    socks5://127.0.0.1:10808
::    socks5://127.0.0.1:10810
::    socks5://127.0.0.1:10811
webrecon parse --input urls.txt --proxy-file proxies.txt --save
```

**Both at once** (merged in declaration order, deduplicated):

```cmd
webrecon validate --url https://example.com ^
    --proxy http://upstream.example:3128 ^
    --proxy-file proxies.txt
```

When more than one proxy is supplied, `MassParserClient` rotates
through them per request.

## Quick recipes

### Recipe 1 -- one VLESS key, full discovery sweep

```cmd
:: 1. Generate Xray config from a single VLESS URL
echo vless://uuid@host:443?type=tcp^&security=reality^&pbk=...^&sni=... > C:\xray\keys.txt
python scripts\xray_config_gen.py --input C:\xray\keys.txt --output C:\xray\config.json

:: 2. Start Xray
start /B C:\xray\xray.exe -c C:\xray\config.json

:: 3. Sanity check
curl -x socks5://127.0.0.1:10808 https://api.ipify.org

:: 4. Run discovery through it
webrecon discover --source crtsh --query "example.com" ^
    --proxy socks5://127.0.0.1:10808 --save
```

### Recipe 2 -- 100-key VLESS pool, mass parsing

```cmd
:: 1. Build pool config (pool.txt has 100 vless:// URLs)
python scripts\xray_config_gen.py --input pool.txt --output C:\xray\pool.json --selector random

:: 2. Start Xray with the pool config
start /B C:\xray\xray.exe -c C:\xray\pool.json

:: 3. Mass parse 10k URLs through the pool
webrecon parse --input candidates.txt --scan-exposed --validate-woo --save ^
    --proxy socks5://127.0.0.1:10808 --concurrency 30
```

### Recipe 3 -- HTTP proxy provider with auth

```cmd
webrecon discover --source serper --query "..." ^
    --proxy "http://user:password@proxy.provider.com:8080"
```

### Recipe 4 -- chain of HTTP + SOCKS proxies (round-robin)

```cmd
:: proxies.txt:
::    socks5://127.0.0.1:10808
::    http://user:pass@upstream.example:3128
webrecon parse --input urls.txt --proxy-file proxies.txt
```

## Troubleshooting

### `httpx.ProxyError: Proxy URL scheme 'socks5' is unsupported`

`httpx` ships SOCKS support behind an extra. Install it via the
project's `dev` extra (already included):

```cmd
pip install -e .[dev]
```

If you only want the SOCKS bits without the rest of dev tooling:

```cmd
pip install httpx[socks]
```

### `curl -x socks5://...` returns my real IP

Most likely Xray is not running. Re-check:

```cmd
tasklist | findstr xray.exe
netstat -an | findstr 10808
```

### `--proxy-file` says "not found"

The path is resolved against the **current** working directory, not
relative to the script. Use an absolute path or `cd` to the project
root first.

### The xray-config-gen script "skipped N URL(s)"

The skipped URLs are not valid VLESS share links. Common causes:

* `vmess://` URLs (different protocol -- not supported by this
  generator).
* truncated / line-wrapped URLs (re-paste them on a single line).
* private VLESS dialects from individual providers that omit
  required fields. Open them in a GUI client (v2rayN, NekoBox) and
  export back to a canonical `vless://` URL.

### Each request hangs for 60 seconds

The balancer is round-robining over a dead key. Either prune the
dead key from `keys.txt` and regenerate the config, or switch the
selector to `random` so dead keys are amortised over the pool:

```cmd
python scripts\xray_config_gen.py --input keys.txt --output config.json --selector random
```

### I want every request through the *same* exit IP

Run a single-key Xray (or use a single SOCKS proxy) and do not pass
`--proxy-file`. Round-robin only kicks in when more than one URL is
supplied.

## See also

- `webrecon/cli/proxy.py` -- the helper that resolves
  `--proxy` and `--proxy-file` into the list passed to
  `MassParserClient`.
- `scripts/xray_config_gen.py` -- VLESS pool to Xray config.
- [`docs/webrecon/configuration.md`](configuration.md) --
  full configuration reference.
- [Xray-core docs](https://xtls.github.io/Xray-docs-next/en/) --
  upstream reference for protocol options.
