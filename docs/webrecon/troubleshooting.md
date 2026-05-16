# Troubleshooting

Common issues and their resolutions, ordered by frequency in the
field.

## `MissingOptionalConfigWarning: api_keys.fofa is not set`

**Symptom**: warning at startup; the affected discovery source
returns an empty result set or fails on first call.

**Cause**: the credential is missing from every layer (defaults,
`.env`, env vars, CLI).

**Fix**: set `WEBRECON_API_KEYS__FOFA__EMAIL` /
`WEBRECON_API_KEYS__FOFA__KEY` (or the equivalent for other
sources) in `.env` or as environment variables. Empty strings count
as "explicitly unset" and silence the warning without enabling the
source.

## `ConfigLoadError: log_level must be one of ...`

**Symptom**: the CLI exits with code 2 and a multi-line error
message listing every offending field.

**Cause**: pydantic rejected the merged configuration.

**Fix**: read each `- field.path: ...` line in the error message;
fix the offending values. The original `pydantic.ValidationError`
is chained as `__cause__` if a structured handler needs it.

## `FofaRateLimitError: FOFA rate-limited the request after 3 retries`

**Symptom**: discovery stops after a burst of requests.

**Cause**: FOFA's per-account rate limit was hit and the retries
with exponential backoff did not recover.

**Fix**: reduce `WEBRECON_RATE_LIMITING__REQUESTS_PER_SECOND` and
`WEBRECON_CONCURRENCY__MAX_CONNECTIONS`, or wait for the rate
window to roll over. The same pattern applies to
`ShodanRateLimitError` and `ShodanQuotaExceededError` (the latter is
**not** retryable: the account ran out of query credits).

## `aiosqlite.OperationalError: database is locked`

**Symptom**: intermittent error during a high-concurrency write
load.

**Cause**: SQLite is single-writer, multi-reader. The connection
pool serialises writers but a long-running transaction can still
trigger lock timeouts.

**Fix**: lower `WEBRECON_CONCURRENCY__SEMAPHORE_SIZE`, or move the
hot path to batched writes via `stream_in_batches` followed by a
single transaction.

## Tests fail with `ModuleNotFoundError: No module named 'aiosqlite'`

**Symptom**: `pytest tests/webrecon/integration` fails immediately.

**Cause**: the test environment is missing optional runtime deps.

**Fix**: `pip install -e ".[dev]"` installs every dependency the
suite needs.

## `mypy` reports `Cannot find implementation or library stub for module named "jinja2"`

**Symptom**: `mypy -p webrecon` errors on the reporter module.

**Cause**: jinja2 ships without bundled stubs; `mypy.ini` is
expected to silence the warning per-package.

**Fix**: ensure `mypy.ini` contains:

```ini
[mypy-jinja2.*]
ignore_missing_imports = True
```

The committed configuration already includes this rule; the error
typically appears only when an operator overrides `mypy.ini`
manually.

## `webrecon validate --stripe-key sk_live_...` reports `is_valid=false`

**Symptom**: a key that worked yesterday is now reported invalid.

**Causes** (in order of likelihood):
1. The key was rotated or revoked.
2. The Stripe API rejected the request because of a network egress
   policy (corporate proxy, transparent firewall).
3. A typo in the key (extra whitespace, missing prefix character).

**Fix**: check the Stripe dashboard for the key state; verify the
egress path with `curl -sS https://api.stripe.com/v1/balance -u
sk_live_...:`; re-paste the key inside fresh quotes.

## `Outbound socket creation is blocked during this webrecon test`

**Symptom**: a unit test fails with the message above.

**Cause**: the test opted into `block_outbound_network` and a code
path tried to open a real socket -- typically because it bypassed
the `mock_http_transport` / `async_client` fixtures.

**Fix**: route the HTTP call through the injected `httpx.AsyncClient`
the fixture provides. Mock-driven tests must never touch the
network.

## `webrecon db stats` shows zeros after a discovery sweep

**Symptom**: discovery printed assets to stdout but the database
is empty.

**Cause**: `--save` was not passed.

**Fix**: re-run with `webrecon discover --source all --save` so
results are upserted into the asset database. Without `--save` the
discovery layer prints results without persisting them.

## Where to look next

- `webrecon config show` -- prints the resolved configuration with
  per-leaf source attribution.
- Structured logs (JSON mode) -- `WEBRECON_LOG_LEVEL=DEBUG webrecon
  ... 2>logs.json` and grep by `event=`.
- The asset database itself -- `sqlite3 webrecon.sqlite3 'select *
  from websites limit 10'`.
