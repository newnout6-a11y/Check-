# Getting started

This guide walks through the first 15 minutes of using `webrecon`:
installing it, configuring credentials, and running a smoke test.

## Prerequisites

- Python **3.10 or newer**.
- A POSIX shell or PowerShell. The CLI works the same on Linux,
  macOS, and Windows.
- Optional API keys for the discovery sources you intend to use:
  FOFA, Shodan, Serper.dev, GitHub.

## Install

`webrecon` ships in the same wheel as `binchecker`. The recommended
installation is editable so the source tree is picked up directly:

```bash
git clone <repo-url> webrecon
cd webrecon
pip install -e ".[dev]"
```

The optional `dev` extra installs `pytest`, `hypothesis`, `ruff`, and
`mypy` so the verification commands documented further down work
out of the box.

## Configure

Create a `.env` file at the project root with the credentials you
have. Every variable is optional; modules whose credential is missing
fail fast with a descriptive error rather than silently skipping.

```dotenv
# Optional: enable verbose logging.
WEBRECON_LOG_LEVEL=INFO

# FOFA (https://en.fofa.info/api).
WEBRECON_API_KEYS__FOFA__EMAIL=you@example.com
WEBRECON_API_KEYS__FOFA__KEY=your-fofa-key

# Shodan (https://developer.shodan.io).
WEBRECON_API_KEYS__SHODAN=your-shodan-key

# Serper.dev (https://serper.dev).
WEBRECON_API_KEYS__SERPER=your-serper-key

# GitHub PAT (classic ghp_..., or fine-grained github_pat_..., or 40-char hex).
WEBRECON_API_KEYS__GITHUB=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Stripe secret/restricted key for live-key validation
# (sk_live_..., sk_test_..., rk_live_..., rk_test_...).
WEBRECON_API_KEYS__STRIPE=sk_test_xxxxxxxx
```

The full list of variables is documented in the
[Configuration reference](configuration.md).

## Verify the installation

```bash
# Show the resolved configuration with sources of each value.
webrecon config show

# Re-run validators and report any malformed credentials.
webrecon config check

# Exit codes:
#   0 - configuration valid
#   2 - configuration validation failed
```

`webrecon config show` masks API keys in its output: only the first
four and last four characters are printed.

## Smoke test

```bash
# Dry-run discover with the fastest source.
webrecon discover --source serper --query "site:example.com" --max-pages 1

# Validate a single URL.
webrecon validate --url https://example.com

# Inspect the asset database.
webrecon db stats
webrecon db query --filter "status=active" --limit 10
```

If `webrecon db stats` reports zeros, the discovery run did not
persist anything yet. Re-run with `--save` to write results to the
asset database.

## Run the test suite

```bash
pytest tests/webrecon -q
ruff check webrecon
mypy -p webrecon
```

All three commands should complete cleanly. The combined `pytest`
suite includes property-based tests via Hypothesis and integration
tests against a temporary SQLite database.
