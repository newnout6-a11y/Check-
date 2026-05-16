# User guide

Day-to-day workflows. Each section starts with the shortest invocation
that produces useful output, then drills into the relevant flags.

## Subcommand cheat sheet

| Command | What it does |
| --- | --- |
| `webrecon discover` | Multi-source target discovery (FOFA, Shodan, Serper) |
| `webrecon github` | GitHub repository reconnaissance and secret detection |
| `webrecon parse` | Bulk website parsing and validation |
| `webrecon automate` | Form automation and interaction |
| `webrecon validate` | Single-URL validation, optional Stripe testing |
| `webrecon export` | Data export (CSV, JSON, SQL dump, HTML report) |
| `webrecon config` | View / check the resolved configuration |
| `webrecon db` | Inspect and query the asset database |

Run any subcommand with `--help` for a complete flag listing. Global
flags (`--config`, `--log-level`, `--output`, `--concurrency`,
`--verbose`, `--quiet`) accepted by every subcommand are documented in
[Configuration reference](configuration.md#global-cli-flags).

## Discover

```bash
# FOFA: find WooCommerce sites running Stripe.
webrecon discover --source fofa --query 'app="WooCommerce" && body="pk_live_"' --max-pages 5

# Shodan: probe popular tech.
webrecon discover --source shodan --query "product:nginx country:US" --max-pages 3

# Serper: dork for exposed env files.
webrecon discover --source serper --query 'inurl:.env "DB_PASSWORD"' --max-pages 2

# All sources at once with a fan-in dedup pass.
webrecon discover --source all --query "checkout stripe" --save
```

Use `--save` to upsert discovered assets into the database.
Without `--save` the output is printed only.

## Parse

```bash
# Stream a list of URLs through the mass parser.
webrecon parse --input urls.txt --output json
```

Each URL is checked against the standard exposed-file path list
(`/.env`, `/wp-config.php.bak`, `/.git/config`, ...) and the response
body is mined for Stripe keys and other secrets. Results are saved
to the asset database when `--save` is supplied.

## Validate

```bash
# Single URL with full assessment.
webrecon validate --url https://shop.example.com --test-stripe

# Stripe key validation in isolation.
webrecon validate --stripe-key sk_test_...

# Generate an HTML report for the assessment.
webrecon validate --url https://shop.example.com --test-stripe --report assessment.html
```

The validator runs technology detection, security-header analysis,
basic SSL certificate checks, and -- with `--test-stripe` -- runs
the Stripe tester against any `pk_live_` key it finds in the page
HTML.

## Export

```bash
webrecon export --format csv  --output assets.csv
webrecon export --format json --output assets.json
webrecon export --format sql  --output backup.sql
webrecon export --format html --output assessment.html
```

`--format html` generates the assessment report driven by the
findings stored in the database. The other formats dump the raw
asset table.

## Database

```bash
# Aggregate stats.
webrecon db stats

# Filter and sort.
webrecon db query --filter "status=active,source=fofa" --sort discovered_at --limit 50
```

Filters are comma-separated `key=value` pairs. Supported keys:
`status`, `source`, `country`, `url`. Use the `webrecon db migrate`
helper to apply pending schema migrations explicitly (this is also
done implicitly on every other invocation).

## Safety defaults

Three settings are on by default; each disables one safety guard
when set to `false`:

- `WEBRECON_SAFETY__TEST_MODE`: blocks operations that would mutate
  external state.
- `WEBRECON_SAFETY__USE_TEST_DATA_ONLY`: refuses to submit anything
  except synthetic test data to remote forms.
- `WEBRECON_SAFETY__REQUIRE_CONFIRMATION`: prompts before each
  destructive operation.

The configuration validator rejects the combination
`test_mode=False AND require_confirmation=False` -- at least one
guard must remain on. Toggle them only after reading the
[ethical use notes](../../webrecon/safety/warnings.py).

## Output formats

Every subcommand that emits results accepts `--output {json,csv,table,yaml}`
(see `webrecon.cli.formatting`). The default is `table` for
interactive use and `json` for CI / pipelines.

## Progress reporting

Long-running scans surface progress on stderr via
`ProgressReporter`, so stdout-bound output (JSON / CSV) stays
machine-parseable. The reporter falls back to milestone lines when
the destination is not a TTY (CI logs, redirected files).

Disable progress entirely with `--quiet`. Force progress with
`--verbose` even when the destination is not a TTY.
