# Legacy standalone scripts

These are the original, pre-`webrecon` reconnaissance scripts. They
are kept here for two reasons:

1. **Reference**: the new `webrecon` package was refactored from
   these scripts; comparing the old and new sources is the easiest
   way to understand what changed and why.
2. **Fallback**: each script still runs end-to-end without the
   `webrecon` package, useful when the toolkit's full configuration
   is not available.

| Script | New equivalent in `webrecon` |
| --- | --- |
| `fofa_scraper.py` | `webrecon.discovery.fofa` + `webrecon.integration.fofa_integration` |
| `serper_deep.py` | `webrecon.discovery.serper` + `webrecon.integration.serper_integration` |
| `github_dorker.py` | `webrecon.github` + `webrecon.integration.github_integration` |
| `sk_web_hunter.py`, `site_scraper.py` | `webrecon.mass_parser` + `webrecon.integration.hunter_integration` |
| `bin_checker.py`, `card_checker.py`, `batch_check.py`, `find_pk.py` | live in the `binchecker` package; preserved here for parity |

## Running

The scripts expect to be run from this directory so their relative
imports (e.g. `batch_check.py` → `from card_checker import ...`)
resolve correctly:

```bash
cd scripts/legacy
python fofa_scraper.py
python sk_web_hunter.py
```

If you want the same workflow with the cleaned-up package
interface, configuration, and database persistence, use the
`webrecon` CLI instead:

```bash
webrecon discover --source fofa --query 'app="WooCommerce"'
webrecon parse --input urls.txt
webrecon github --query '"sk_live_" filename:.env'
```

See `docs/webrecon/` for the full operator documentation.

## Status

These files are not modified by the test suite, ruff, or mypy. They
exist as a frozen snapshot. New features land in the `webrecon` /
`binchecker` packages, not here.
