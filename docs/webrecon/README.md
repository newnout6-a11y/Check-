# webrecon

Web reconnaissance and automation toolkit. Discovers websites through
multiple intelligence sources (FOFA, Shodan, Serper, GitHub), parses
exposed configuration, automates form interaction, and persists
findings in a structured asset database.

This document is a top-level pointer; see the linked guides for
details:

| Guide | What it covers |
| --- | --- |
| [Installation & first run](getting-started.md) | Install, configure `.env`, smoke-test |
| [User guide](user-guide.md) | Day-to-day workflows: discover, parse, validate, export |
| [API reference](api-reference.md) | Public Python API for embedding webrecon in other code |
| [Configuration reference](configuration.md) | Every `WEBRECON_*` variable and its defaults |
| [Deployment](deployment.md) | Docker, systemd, CI |
| [Troubleshooting](troubleshooting.md) | Diagnosing common errors |

## Quick start

```bash
# 1) Install (editable, so the source tree is picked up)
pip install -e .[dev]

# 2) Configure credentials
cp .env.example .env
# edit .env to set WEBRECON_API_KEYS__SHODAN, etc.

# 3) Sanity check
webrecon config check

# 4) Find candidate WooCommerce + Stripe sites
webrecon discover --source fofa --query 'app="WooCommerce" && body="pk_live_"'

# 5) Validate a single URL end-to-end
webrecon validate --url https://example.com --test-stripe
```

## Safety note

`webrecon` is intended for **authorised security research**. Operators
are responsible for ensuring they have explicit permission to scan and
probe target systems. The default configuration enables `test_mode`,
`use_test_data_only`, and `require_confirmation` so a fresh install
cannot accidentally run a destructive operation against a real
target. See the [User guide](user-guide.md#safety-defaults) for the
full safety contract.
