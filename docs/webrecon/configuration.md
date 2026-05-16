# Configuration reference

`webrecon` reads its configuration from five sources, in increasing
priority order:

1. Field defaults declared on `AppConfig` and its sub-sections.
2. `~/.env` (home directory).
3. `./.env` (current working directory).
4. Process environment variables prefixed `WEBRECON_`.
5. Explicit CLI overrides.

The `--config show` subcommand prints both the resolved configuration
and a `field_path: source` resolution map so an operator can answer
"where did this value come from?" without bisecting layers manually.

## Variable reference

Nested sections are addressed with `__` (double underscore). For
example: `WEBRECON_API_KEYS__SHODAN=...` populates
`AppConfig.api_keys.shodan`.

### `WEBRECON_LOG_LEVEL`

Severity threshold for both `structlog` and the root stdlib logger.
One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
(case-insensitive). **Default: `INFO`.**

### `WEBRECON_API_KEYS__*`

| Variable | Purpose | Format |
| --- | --- | --- |
| `__FOFA__EMAIL` | FOFA account email | non-empty string |
| `__FOFA__KEY` | FOFA API key | non-empty string |
| `__SHODAN` | Shodan API key | non-empty string |
| `__SERPER` | Serper.dev API key | non-empty string |
| `__GITHUB` | GitHub PAT | `ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_`, or 40-char lowercase hex |
| `__STRIPE` | Stripe secret/restricted key | `sk_live_`, `sk_test_`, `rk_live_`, or `rk_test_` |

Empty strings (a common shell idiom for "unset") normalise to `None`
and do **not** trigger the missing-optional warning.

### `WEBRECON_CONCURRENCY__*`

| Variable | Range | Default | Purpose |
| --- | --- | --- | --- |
| `__MAX_CONNECTIONS` | 1-100 | 20 | Total concurrent connections |
| `__PER_HOST_LIMIT` | 1-10 | 5 | Per-remote-host concurrency |
| `__SEMAPHORE_SIZE` | 1-50 | 15 | Logical concurrency for batch parsers |

### `WEBRECON_RATE_LIMITING__*`

| Variable | Range | Default | Purpose |
| --- | --- | --- | --- |
| `__REQUESTS_PER_SECOND` | 0.1-100.0 | 10.0 | Sustained request rate ceiling |
| `__DELAY_BETWEEN_REQUESTS` | 0-10 | 0.0 | Mandatory inter-request delay (s) |
| `__RESPECT_ROBOTS_TXT` | bool | `true` | Honour robots.txt directives |
| `__CRAWL_DELAY` | 0-60 | 0.0 | Default crawl delay when robots.txt is silent |

### `WEBRECON_DATABASE__*`

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `__PATH` | path | `webrecon.sqlite3` | SQLite file path. `:memory:` for in-memory mode |
| `__USE_SQLITE` | bool | `true` | Use the SQLite backend (only supported option for now) |
| `__AUTO_BACKUP` | bool | `false` | Take periodic backups |
| `__BACKUP_INTERVAL_HOURS` | int >=1 | 24 | Backup interval |

### `WEBRECON_SAFETY__*`

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `__MAX_REQUESTS_PER_SITE` | int >=1 | 100 | Hard cap on requests per target |
| `__TEST_MODE` | bool | `true` | Restrict to non-destructive operations |
| `__USE_TEST_DATA_ONLY` | bool | `true` | Use only synthetic test data |
| `__REQUIRE_CONFIRMATION` | bool | `true` | Prompt before destructive ops |

The configuration validator rejects the combination
`TEST_MODE=false AND REQUIRE_CONFIRMATION=false`. At least one of
the two guards must remain on.

## Global CLI flags

| Flag | Purpose | Equivalent env var |
| --- | --- | --- |
| `--config PATH` | Override config-file lookup root | n/a |
| `--log-level LVL` | Override log level | `WEBRECON_LOG_LEVEL` |
| `--output FMT` | `json` / `csv` / `table` / `yaml` | n/a |
| `--concurrency N` | Override `concurrency.semaphore_size` | `WEBRECON_CONCURRENCY__SEMAPHORE_SIZE` |
| `--verbose` / `--quiet` | Adjust output verbosity | n/a |

## Programmatic access

The hierarchical loader is exposed via `webrecon.config.load_config`:

```python
from webrecon.config import load_config

loaded = load_config(
    cli_overrides={"log_level": "DEBUG"},
    cwd=Path("/srv/webrecon"),  # optional override of './'
    home=Path("/home/op"),       # optional override of '~/'
)

# Inspect resolved sources.
for path, source in sorted(loaded.resolution.items()):
    print(f"{path}: {source.value}")
```

## Resolution sources

`ConfigSource` is a `StrEnum` with five members ordered from lowest
to highest precedence: `default`, `env_file_home`, `env_file_cwd`,
`env_vars`, `cli_args`.
