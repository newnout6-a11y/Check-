# Implementation Plan: Project Enhancement (binchecker package)

## Overview

This plan converts the `project-enhancement` design into incremental coding steps that evolve the existing flat scripts (`bin_checker.py`, `card_checker.py`, `batch_check.py`, etc.) into a layered `binchecker` Python package. Tasks proceed bottom-up: scaffolding → pure core → safety/config foundations → infrastructure (http, plugins) → detection / lookup / live → orchestration → batch & export → i18n & CLI → backward-compat shims → integration. Property-based tests are placed next to the components they validate so each correctness property from the design (Properties 1-31) has a dedicated test task that explicitly references its property number and the requirement clauses it covers.

Implementation language: **Python 3.10+** (matches design and existing code). Primary HTTP dependency: `httpx`. Property-based testing: `hypothesis`. Config: `pydantic` / `pydantic-settings`. Logging: `structlog` + stdlib. Templates: `jinja2`. PDF: `weasyprint`. i18n: `babel`. Cache: `diskcache`.

## Tasks

- [x] 1. Set up package scaffolding and tooling
  - [x] 1.1 Create `binchecker/` package skeleton and `pyproject.toml`
    - Add directories `binchecker/{core,detection,lookup,lookup/providers,live,pipeline,batch,export,export/templates,config,plugins,http,log,i18n,i18n/messages,cli}` each with empty `__init__.py`
    - Author `pyproject.toml` declaring runtime deps (`httpx`, `pydantic`, `pydantic-settings`, `structlog`, `diskcache`, `jinja2`, `weasyprint`, `babel`, `prompt_toolkit`) and dev deps (`pytest`, `hypothesis`, `pytest-cov`, `ruff`, `mypy`)
    - Declare console script entry point `binchecker = binchecker.cli.main:main`
    - Declare plugin entry-point group `binchecker.plugins`
    - Add `binchecker/version.py` with `__version__`
    - _Requirements: 13.1, 13.3_

  - [x] 1.2 Set up testing layout and Hypothesis defaults
    - Create `tests/{property,unit,integration,compliance,fixtures}` with `__init__.py` and `conftest.py`
    - Add `tests/conftest.py` registering Hypothesis profile (`max_examples=200`, `deadline=None`) and a `pytest_collection_modifyitems` hook that fails CI if any "Property N" tag from the design lacks a matching test
    - Add custom Hypothesis strategies module `tests/strategies.py` (stubs for `valid_pan_strategy`, `invalid_pan_strategy`, `card_strategy`, `bin_response_strategy`, `html_with_signatures_strategy`, `unicode_text_strategy`, `config_dict_strategy`)
    - _Requirements: 11.1, 11.3, 11.5_

  - [x] 1.3 Configure linting, typing, and coverage
    - Add `ruff` config and `mypy --strict` config scoped to `binchecker/{core,pipeline,config,log,lookup}`
    - Add `pytest --cov` config with 80% gate on critical packages (`core/`, `pipeline/`, `lookup/chain.py`, `log/pan_filter.py`, `config/loader.py`)
    - _Requirements: 11.5_


- [ ] 2. Implement pure core models and validators
  - [x] 2.1 Define enums and immutable data models in `core/models.py`
    - Implement `CardBrand`, `CardType`, `LiveStatus`, `FailureStep` as `StrEnum`
    - Implement frozen dataclasses `CardData`, `BINInfo`, `LiveCheckResult`, `CardCheckResult`, `GatewayMatch`, `SiteCheckResult`, `BatchSummary` exactly as specified in the design's Data Models section
    - Add `schema_version` field on `CardCheckResult`, `SiteCheckResult` defaulted to `"1"`
    - Add `from_dict`/`to_dict` helpers on each model for export round-trip support
    - _Requirements: 2.1, 2.7, 4.4, 13.3_

  - [x] 2.2 Implement `core/pan.py` (normalize, mask, bin extraction)
    - `normalize_pan(raw: str) -> str` strips non-digit characters
    - `mask_pan(pan: str) -> str` returns `first6 + '*' * inner + last4` for length ≥ 10, fully masked otherwise
    - `bin_of(pan: str, length: int = 6) -> str`
    - _Requirements: 8.1, 8.4_

  - [x] 2.3 Property test for PAN masking
    - **Property 3: PAN masking exposes only first-6 and last-4**
    - **Validates: Requirements 8.1, 8.4**
    - File: `tests/property/test_pan_mask.py`

  - [x] 2.4 Implement `core/luhn.py`
    - `luhn_check(pan: str) -> bool`
    - `luhn_compute_check_digit(pan_without_check: str) -> int`
    - _Requirements: 2.1_

  - [x] 2.5 Property test for Luhn correctness
    - **Property 1: Luhn correctness**
    - **Validates: Requirements 2.1**
    - File: `tests/property/test_luhn.py`

  - [x] 2.6 Implement `core/brand.py`
    - Static brand prefix table covering VISA, MASTERCARD, AMEX, DISCOVER, JCB, DINERS, UNIONPAY, MAESTRO, VISA_ELECTRON
    - `detect_card_brand(pan: str) -> CardBrand`
    - `valid_brand_length(pan: str, brand: CardBrand) -> bool` using per-brand `[min_length, max_length]`
    - _Requirements: 2.7_

  - [-] 2.7 Property test for brand detection round-trip
    - **Property 2: Brand detection round-trip**
    - **Validates: Requirements 2.7**
    - File: `tests/property/test_brand.py`

  - [x] 2.8 Implement `core/expiry.py` and `core/cvv.py`
    - `normalize_expiry(month, year, *, today=None) -> tuple[int,int]` (handles 2-digit/4-digit years)
    - `is_expired(month, year, *, today=None) -> bool`
    - `validate_cvv(brand, cvv) -> CvvValidation` (3 digits for non-AMEX, 4 for AMEX)
    - _Requirements: 2.4, 2.7_

  - [x] 2.9 Unit tests for expiry and CVV
    - Test boundary cases (current month, past month, future month, 2-digit year normalization)
    - Test AMEX 4-digit vs 3-digit CVV
    - _Requirements: 2.4, 2.7_

  - [x] 2.10 Implement `core/scoring.py`
    - `SiteFeatures` dataclass capturing inputs (gateway count, antifraud presence, 3DS markers, TLD risk, SSL issuer)
    - `compute_site_score(features) -> int` returning a score in `[0, 100]`
    - `is_low_confidence(score, threshold=70) -> bool`
    - _Requirements: 1.5, 1.7_

- [ ] 3. Implement PCI-safe logging foundation
  - [x] 3.1 Implement `log/pan_filter.py`
    - `PanRedactionFilter(logging.Filter)` scans `record.msg` and formatted args for digit runs of length 12-19
    - For each run, run Luhn; if Luhn-valid, replace with `mask_pan(run)`
    - Fail-closed: if redaction itself raises, replace the message with `"<redacted>"`
    - _Requirements: 8.1, 8.4_

  - [x] 3.2 Property test for PAN redaction filter universality
    - **Property 9: PAN redaction filter is universal**
    - **Validates: Requirements 8.1, 8.4**
    - File: `tests/property/test_pan_redaction.py`

  - [x] 3.3 Implement `log/setup.py` and `log/rotation.py`
    - `setup_logging(cfg)` attaches `PanRedactionFilter` to the **root logger** (so every handler inherits it)
    - Configure `structlog` JSON renderer + stdlib `RotatingFileHandler` (configurable `maxBytes`, `backupCount`)
    - Honor `log_level` from config; emit traceback files into `tracebacks/{traceback_id}.txt`
    - Define structured fields: `event`, `error_type`, `error_message`, `request_id`, `correlation_id`, `url`, `http_status`, `duration_ms`, `traceback_id`
    - _Requirements: 6.1, 6.4, 6.5_

  - [ ] 3.4 Property test for log level filtering
    - **Property 30: Log level filter**
    - **Validates: Requirements 6.5**
    - File: `tests/property/test_log_level_filter.py`

  - [ ] 3.5 Property test for log rotation cap
    - **Property 31: Rotation cap**
    - **Validates: Requirements 6.4**
    - File: `tests/property/test_rotation_cap.py`

- [ ] 4. Implement configuration management
  - [x] 4.1 Implement `config/schema.py` with `AppConfig` (pydantic BaseSettings)
    - Fields: `api_timeout`, `log_level`, `log_dir`, `cache_dir`, `bin_cache_ttl_hours`, `concurrency`, `profile`, `locale`, `bin_providers`, `stripe_publishable_key` (SecretStr), `stripe_restricted_key` (SecretStr), `plugin_paths`, `gateway_pool_path`, `gateway_pool_update_url`
    - Apply ranges (`concurrency` 1-20 clamp, `bin_cache_ttl_hours` 1-168, `api_timeout` 0-120)
    - `env_prefix="BINCHECKER_"`, `env_file=".env"`
    - Field validators for path existence and dependency rules (e.g. `stripe_restricted_key` requires `stripe_publishable_key`)
    - _Requirements: 5.1, 5.5_

  - [x] 4.2 Implement `config/profiles.py` (development / testing / production overlays)
    - Each profile is a dict applied as defaults overlay before `.env`
    - `development`: log_level=DEBUG, cache TTL shortened, allow http
    - `production`: log_level=INFO, enforce HTTPS-only
    - _Requirements: 5.8_

  - [ ] 4.3 Implement `config/loader.py` with explicit precedence chain
    - Build effective dict by deep-merging: builtin_defaults → profile_defaults → `.env` in `$HOME` → `.env` in CWD → env vars (`BINCHECKER_*`) → CLI overrides
    - Track `resolution_log: dict[field_name, source_name]` and emit at INFO
    - Validate via pydantic; on failure print structured multi-line error and exit with code `78` (`EX_CONFIG`)
    - Apply default fallback warnings for missing-but-optional fields
    - _Requirements: 5.2, 5.3, 5.6, 5.7_

  - [ ] 4.4 Property test for configuration precedence
    - **Property 24: Configuration precedence**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.7, 5.8**
    - File: `tests/property/test_config_precedence.py`

  - [ ] 4.5 Property test for configuration validation rejection
    - **Property 25: Configuration validation rejects invalid input**
    - **Validates: Requirements 5.5, 5.6**
    - File: `tests/property/test_config_validation.py`

  - [ ] 4.6 Implement `config/summary.py` (masked summary renderer)
    - `render(cfg) -> str` walks fields; replaces `SecretStr` values with `"***"`
    - Always include source attribution from `resolution_log`
    - _Requirements: 5.9, 8.1_

  - [ ] 4.7 Property test for masked summary
    - **Property 26: Masked summary never leaks secrets**
    - **Validates: Requirements 5.9, 8.1**
    - File: `tests/property/test_masked_summary.py`

  - [ ] 4.8 Implement `config/watcher.py` for hot reload
    - Background thread polls `.env` mtime every 1 second
    - On change call `load_config(...)` and atomically swap `app.config`
    - Emit reload event (with masked diff) to log
    - Reload completes within 5 seconds of change
    - _Requirements: 5.4_

  - [ ] 4.9 Integration test for `.env` hot reload
    - Modify a watched `.env` file; assert config reflects new value within 5 seconds
    - File: `tests/integration/test_dotenv_reload.py`
    - _Requirements: 5.4_

- [x] 5. Implement error hierarchy
  - [x] 5.1 Create `binchecker/errors.py` with the full hierarchy
    - Root `BinCheckerError`; subclasses: `ConfigError`, `ConfigValidationError`, `ConfigSourceError`, `NetworkError`, `ProviderError`, `InsecureUrlError`, `ValidationError`, `LuhnError`, `BrandError`, `ExpiryError`, `CvvError`, `BatchInputFormatError`, `LookupError`, `BINLookupError`, `LiveCheckError`, `BackendError`, `DeclineError`, `ExportError`, `UnsupportedFormatError`, `TemplateValidationError`, `IntegrityError`, `PluginError`, `PluginCompatibilityError`, `PluginLoadError`
    - Each error carries a structured payload (dict) for log serialization
    - Add `EXIT_CODES` map (0/1/2/64/65/66/69/78) per design
    - _Requirements: 6.1, 6.3_

- [ ] 6. Checkpoint - ensure core, logging, config, errors are in place
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement HTTP infrastructure
  - [ ] 7.1 Implement `http/client.py`
    - `make_client(cfg, *, async_=True)` returns `httpx.AsyncClient` or `httpx.Client`
    - Enforce TLS-only in `production` profile: any `http://` URL raises `InsecureUrlError`; in `development` accept both with WARNING log
    - Set timeouts from `cfg.api_timeout`; attach per-request `request_id` header
    - _Requirements: 8.5_

  - [ ] 7.2 Property test for HTTPS enforcement
    - **Property 10: HTTPS enforcement in production profile**
    - **Validates: Requirements 8.5**
    - File: `tests/property/test_https_enforcement.py`

  - [ ] 7.3 Implement `http/retry.py` with exponential backoff + jitter
    - `with_retry(fn, *, max_attempts=3, base_backoff=0.5, retry_on=(...))`
    - Delay between attempt `i` and `i+1` lies in `[base_backoff * 2**i, base_backoff * 2**i * 1.25]`
    - Jitter is `random.uniform(0, 0.25)` of the base delay
    - _Requirements: 7.2_

  - [ ] 7.4 Property test for exponential backoff bounds
    - **Property 7: Exponential backoff bounds**
    - **Validates: Requirements 7.2**
    - File: `tests/property/test_backoff.py`

  - [ ] 7.5 Implement `http/ratelimit.py` for 429 handling
    - Read `Retry-After` header; sleep that duration (capped at 60s) then retry through `with_retry`
    - Fall through to next provider once max attempts exhausted
    - _Requirements: 7.2_

- [ ] 8. Implement plugin architecture
  - [x] 8.1 Implement `plugins/protocols.py`
    - `GatewayDetectorPlugin`, `CardValidatorPlugin`, `BINProviderPlugin`, `ExporterPlugin` Protocols
    - All carry `api_version: str = "1"`
    - _Requirements: 15.1, 15.2, 15.3_

  - [-] 8.2 Implement `plugins/registry.py` and `plugins/loader.py`
    - `discover_plugins(group="binchecker.plugins")` reads `importlib.metadata` entry points
    - `load_compatible(found)` filters out plugins where `api_version != "1"`, logs an INFO line per skipped plugin, never raises
    - `Registry` exposes `gateway_detectors`, `validators`, `bin_providers`, `exporters`
    - _Requirements: 15.4, 15.5_

  - [ ] 8.3 Property test for plugin compatibility filter
    - **Property 13: Plugin compatibility filter**
    - **Validates: Requirements 15.5**
    - File: `tests/property/test_plugin_compat.py`

- [ ] 9. Implement gateway/antifraud/3DS/MCC detection
  - [ ] 9.1 Implement `detection/signatures.py`
    - Frozen dataclasses `GatewaySignatures` and `GatewayPool`
    - `GatewayPool.load(path)` supports both legacy v0 schema (existing `gateway_pool.json`) and new v1 (`schema_version` field) — produces equivalent in-memory pool
    - `GatewayPool.with_added(sig)` returns a new merged pool
    - _Requirements: 1.4, 13.5_

  - [ ] 9.2 Property test for legacy pool compatibility
    - **Property 27: Legacy gateway-pool config loads identically**
    - **Validates: Requirements 13.5**
    - File: `tests/property/test_legacy_pool.py`

  - [ ] 9.3 Implement `detection/gateway.py` with default 20-gateway pool
    - Bundle default signatures for: Stripe, Braintree, Adyen, PayPal, Square, Shopify Payments, Checkout.com, Worldpay, Authorize.Net, Mollie, Klarna, WooCommerce Payments, Recurly, 2Checkout, Amazon Pay, Google Pay, Apple Pay, WePay, PayU, Razorpay
    - `detect_gateways(html, pool, *, threshold=70) -> list[GatewayMatch]`: case-insensitive substring + URL pattern match; weighted confidence; sets `low_confidence = (confidence < threshold)`
    - Merge plugin-contributed signatures into pool at runtime
    - _Requirements: 1.4, 1.5, 1.7, 15.1_

  - [ ] 9.4 Property test for gateway match invariants
    - **Property 11: Gateway match confidence and low-confidence flag**
    - **Validates: Requirements 1.5, 1.7**
    - File: `tests/property/test_gateway_match.py`

  - [ ] 9.5 Property test for plugin-contributed signatures
    - **Property 12: Plugin pool merge**
    - **Validates: Requirements 15.1, 15.4**
    - File: `tests/property/test_plugin_merge.py`

  - [ ] 9.6 Implement `detection/antifraud.py`, `detection/threeds.py`, `detection/mcc.py`
    - `detect_antifraud(html) -> tuple[str, ...]` for Kount, Sift, Signifyd, ThreatMetrix, MaxMind, ReCaptcha
    - `detect_threeds(html) -> ThreeDSResult` (markers list + boolean)
    - `infer_mcc(html, gateways) -> tuple[str, ...]` heuristic hints
    - _Requirements: 1.4_

  - [ ] 9.7 Implement `detection/confidence.py` aggregator
    - Combines per-signature weights into final 0-100 confidence
    - _Requirements: 1.5_

  - [ ] 9.8 Diagnostic logging for failed detections
    - When `detect_gateways` returns empty, log diagnostic: URL, HTTP status, response size, pool size
    - _Requirements: 1.3_

- [ ] 10. Implement BIN lookup providers and chain
  - [ ] 10.1 Implement `lookup/provider.py` Protocol and `lookup/cache.py`
    - `BINProvider` Protocol with `name` and `async lookup(bin_code, client) -> BINInfo | None`
    - `BINCache` backed by `diskcache` keyed on normalized 6-8 digit BIN; entry includes `fetched_at`
    - `cache.get(bin, now)` returns hit only when `now - fetched_at < ttl`
    - _Requirements: 2.8, 7.3, 7.4_

  - [ ] 10.2 Property test for BIN cache TTL
    - **Property 6: BIN cache honours TTL**
    - **Validates: Requirements 2.8, 7.3, 7.4**
    - File: `tests/property/test_bin_cache.py`

  - [ ] 10.3 Implement provider `lookup/providers/binlist.py`
    - Calls `https://lookup.binlist.net/{bin}`, maps response → `BINInfo`
    - Distinguishes `None` (not found) from raised `ProviderError` (transient)
    - _Requirements: 2.2, 7.5_

  - [ ] 10.4 Implement provider `lookup/providers/handyapi.py`
    - Calls `https://data.handyapi.com/bin/{bin}`, supports API key from config
    - Maps response → `BINInfo`
    - _Requirements: 2.2, 7.5_

  - [ ] 10.5 Implement provider `lookup/providers/bincheck_io.py`
    - Calls `https://bincheck.io/api/{bin}` (or equivalent), maps response → `BINInfo`
    - _Requirements: 7.5_

  - [ ] 10.6 Implement `lookup/chain.py` with fallback
    - `ProviderChain.lookup(bin)` iterates providers in order, applies `with_retry` per provider, advances on exhaustion
    - On all-fail raises `BINLookupError` listing each provider's failure
    - On success writes to cache with TTL
    - _Requirements: 2.2, 7.1_

  - [ ] 10.7 Property test for provider chain fallback
    - **Property 5: Provider chain fallback**
    - **Validates: Requirements 2.2, 7.1**
    - File: `tests/property/test_provider_chain.py`

  - [ ] 10.8 Unit test for default chain bundles ≥3 providers
    - Verify default chain composition
    - File: `tests/unit/test_default_chain.py`
    - _Requirements: 7.5_

- [ ] 11. Implement live-check backends and decline interpreter
  - [ ] 11.1 Implement `live/interpreter.py` decline-code table
    - `interpret_decline(code, message) -> (LiveStatus, normalized_reason)`
    - Cover Stripe codes (`card_declined`, `insufficient_funds`, `incorrect_cvc`, `expired_card`, `do_not_honor`, `authentication_required`, `lost_card`, `stolen_card`, etc.) and Braintree gateway rejection reasons
    - Unknown codes return `(LiveStatus.ERROR, code)` with original code preserved
    - _Requirements: 2.9_

  - [ ] 11.2 Property test for decline interpreter determinism
    - **Property 8: Decline interpretation determinism**
    - **Validates: Requirements 2.9**
    - File: `tests/property/test_decline_interpreter.py`

  - [ ] 11.3 Implement `live/backend.py` Protocol and context
    - `LiveCheckBackend` Protocol with `name` and `async check(card, ctx)`
    - `LiveCheckContext` dataclass holding HTTP client, publishable key, site URL, request ID
    - _Requirements: 2.3_

  - [ ] 11.4 Implement `live/stripe.py` backend
    - Uses Stripe tokenization on `https://api.stripe.com/v1/tokens` with publishable key
    - Optional $0 PaymentIntent confirm path through restricted key
    - Maps result through `interpret_decline`
    - _Requirements: 2.3, 2.9_

  - [ ] 11.5 Implement `live/braintree.py` backend
    - Tokenization via gateway client_token + verify call; minimal-amount path ≤ $0.50 when `$0` not supported
    - Maps result through `interpret_decline`
    - _Requirements: 2.3, 2.9_

  - [ ] 11.6 Implement `live/wc_store_api.py` backend
    - WooCommerce Store API checkout flow (port from existing `card_checker.py`); minimal-amount path
    - _Requirements: 2.3_

- [ ] 12. Checkpoint - ensure HTTP, plugins, detection, lookup, live are in place
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Implement card pipeline orchestration
  - [ ] 13.1 Implement `pipeline/card.py` with strict 7-step sequence
    - `CardValidationOptions` dataclass (do_bin_lookup, do_live_check, site_url, publishable_key, timeout)
    - `validate_card(raw, opts, ctx) -> CardCheckResult` runs in order: parse → Luhn → brand/length → expiry → CVV format → BIN lookup → live check
    - First failing step recorded in `failure_step`; subsequent steps skipped
    - Always populates `duration_ms`, `timestamp`, `schema_version`
    - _Requirements: 2.1, 2.4, 2.7, 9.2_

  - [ ] 13.2 Property test for pipeline ordered short-circuit
    - **Property 4: Pipeline ordered short-circuit**
    - **Validates: Requirements 2.1, 2.4, 2.7**
    - File: `tests/property/test_pipeline_order.py`

  - [ ] 13.3 Integration test for card validation latency
    - Assert p95 ≤ 5 seconds against mocked backends
    - File: `tests/integration/test_latency.py`
    - _Requirements: 9.2_

- [ ] 14. Implement site analysis pipeline
  - [ ] 14.1 Implement `pipeline/site.py`
    - `analyse_site(url, opts) -> SiteCheckResult` orchestrates: fetch HTML (with redirect chain) → detect gateways → antifraud → 3DS → MCC hints → SSL info → score → verdict
    - Records `duration_ms`, `timestamp`
    - Surfaces low-confidence gateways and alternative suggestions
    - _Requirements: 1.1, 1.5, 1.7, 9.1_

  - [ ] 14.2 Integration test for site analysis latency
    - Assert p95 ≤ 10 seconds against representative URL list with mocked HTTP
    - Extends `tests/integration/test_latency.py`
    - _Requirements: 9.1_

  - [ ] 14.3 Integration test for gateway detection accuracy
    - Use `tests/fixtures/gateway_corpus/` (1000 labeled HTML samples)
    - Assert ≥95% accuracy
    - File: `tests/integration/test_gateway_corpus.py`
    - _Requirements: 1.1, 1.6_

- [ ] 15. Implement batch processing
  - [ ] 15.1 Implement `batch/reader.py` streaming reader
    - Async generator yielding one normalized line at a time from file or stdin
    - Validates batch file format up-front; raises `BatchInputFormatError` on malformed input or unsupported encoding
    - Never holds entire file in memory
    - _Requirements: 3.6, 3.7, 9.5_

  - [ ] 15.2 Implement `batch/checkpoint.py` JSONL checkpoints
    - `Checkpoint` writes one JSON object per processed line with `{line_hash, status, result_id, timestamp}`
    - `is_processed(line_hash) -> bool`; `mark(...)`; `flush()`; `Checkpoint.resume(path)` reads existing checkpoint
    - Uses sha256 of normalized line as `line_hash` for duplicate detection
    - _Requirements: 3.7, 3.8_

  - [ ] 15.3 Property test for checkpoint resume
    - **Property 16: Checkpoint resume avoids duplicates**
    - **Validates: Requirements 3.8**
    - File: `tests/property/test_checkpoint_resume.py`

  - [ ] 15.4 Implement `batch/progress.py` progress reporter
    - `Progress(total)` with `processed`, `remaining`, `eta`, `rate`, `percent` fields
    - Emits to stderr at configurable interval; counters monotonically non-decreasing
    - _Requirements: 3.3, 10.4_

  - [ ] 15.5 Property test for progress monotonicity
    - **Property 18: Progress counters are monotonic**
    - **Validates: Requirements 3.3, 10.4**
    - File: `tests/property/test_progress_monotonic.py`

  - [ ] 15.6 Implement `batch/runner.py` async worker pool
    - `BatchRunner(concurrency, checkpoint, progress)` with concurrency clamped to `[1, 20]`
    - Workers consume from bounded `asyncio.Queue` of size `concurrency*2`
    - Per-line failures captured in `errors.jsonl` without aborting; results partitioned into `live_results.jsonl` / `failed.jsonl` / `errors.jsonl`
    - On OS-level fatal flush checkpoint and shut down gracefully
    - _Requirements: 3.1, 3.2, 3.5, 3.9, 9.3_

  - [ ] 15.7 Property test for concurrency clamp
    - **Property 14: Concurrency is clamped to [1, 20]**
    - **Validates: Requirements 3.1, 9.3**
    - File: `tests/property/test_concurrency_clamp.py`

  - [ ] 15.8 Property test for batch result partition
    - **Property 15: Batch result partition**
    - **Validates: Requirements 3.2, 3.4, 3.9**
    - File: `tests/property/test_batch_partition.py`

  - [ ] 15.9 Property test for streaming memory bound
    - **Property 17: Streaming keeps memory bounded**
    - **Validates: Requirements 3.7, 9.5**
    - File: `tests/property/test_streaming_memory.py`

  - [ ] 15.10 Implement `batch/summary.py` summary report
    - `BatchSummary` with totals, error breakdown by type, avg ms/item, peak memory (`tracemalloc`), durations, output file paths
    - _Requirements: 3.4_

  - [ ] 15.11 Integration test for batch throughput
    - Process 1000 cards through mocked Stripe at concurrency 10 in under one hour
    - File: `tests/integration/test_throughput.py`
    - _Requirements: 3.5_

  - [ ] 15.12 Integration test for memory bound
    - `tracemalloc` peak ≤ 100 MB on 100-card run; bounded constant on 100k stream
    - File: `tests/integration/test_memory.py`
    - _Requirements: 9.4, 9.5_

- [ ] 16. Implement export and reporting
  - [ ] 16.1 Implement `export/exporter.py` Protocol and `ExportSummary`
    - `Exporter` Protocol: `format_id`, `extension`, `async write(results, dst, template=None) -> ExportSummary`
    - `ExportSummary` carries `record_count`, `sha256_checksum`, `schema_version`
    - Registry function `get_exporter(format_id)` raises `UnsupportedFormatError` (with full list of supported ids) when not found
    - _Requirements: 4.6, 4.8_

  - [ ] 16.2 Property test for unknown export format error
    - **Property 22: Unknown export format raises ExportError**
    - **Validates: Requirements 4.6**
    - File: `tests/property/test_export_unknown.py`

  - [ ] 16.3 Implement `export/json_exporter.py` (RFC 8259, UTF-8, streaming)
    - Streams records into a JSON array without loading all into memory
    - Computes sha256 of output bytes during write
    - Always includes `schema_version` and package `version`
    - _Requirements: 4.1, 4.4, 4.8, 13.3_

  - [ ] 16.4 Property test for JSON export round trip
    - **Property 19: JSON export round trip preserves all data**
    - **Validates: Requirements 4.1, 4.4, 4.8, 13.3**
    - File: `tests/property/test_json_roundtrip.py`

  - [ ] 16.5 Implement `export/csv_exporter.py` (RFC 4180, UTF-8)
    - Header row, comma delimiter, double-quote escaping, supports embedded commas/newlines/quotes
    - Streaming write
    - _Requirements: 4.2_

  - [ ] 16.6 Property test for CSV export round trip
    - **Property 20: CSV export round trip is robust to special characters**
    - **Validates: Requirements 4.2**
    - File: `tests/property/test_csv_roundtrip.py`

  - [ ] 16.7 Property test for export integrity reporting
    - **Property 21: Export integrity reporting is honest**
    - **Validates: Requirements 4.8**
    - File: `tests/property/test_export_integrity.py`

  - [ ] 16.8 Implement `export/html_exporter.py` with jinja2 templates
    - Default templates in `export/templates/` for fraud_analysis, compliance, infrastructure_assessment, batch_summary
    - Pre-render template validation via `jinja2.Environment.parse`; raises `TemplateValidationError` before any record is rendered
    - _Requirements: 4.3, 4.5, 4.7_

  - [ ] 16.9 Property test for template validation precedes render
    - **Property 23: Template validation precedes render**
    - **Validates: Requirements 4.5, 4.7**
    - File: `tests/property/test_template_validation.py`

  - [ ] 16.10 Implement `export/pdf_exporter.py` via weasyprint
    - Composes HTML exporter output then renders to PDF
    - Includes charts via embedded SVG (matplotlib-rendered or jinja-emitted)
    - Fails loudly with clear error when required template component missing
    - _Requirements: 4.3_

- [ ] 17. Checkpoint - ensure pipeline, batch, and export work end-to-end
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 18. Implement internationalization
  - [ ] 18.1 Implement `i18n/locale.py`
    - `set_locale(code)` raises `UnsupportedLocaleError` for unregistered locales
    - `t(key, **fmt)` performs gettext lookup with fmt substitution; falls back to msgid when missing
    - _Requirements: 14.1, 14.2_

  - [ ] 18.2 Implement `i18n/currency.py`
    - `format_amount(amount, currency, locale)` uses `babel.numbers.format_currency`
    - Locale-specific thousands/decimal separators and currency symbols
    - _Requirements: 14.3, 14.5_

  - [ ] 18.3 Author `i18n/messages/en.po` and `i18n/messages/ru.po`
    - All user-facing strings (CLI help summaries, error messages, report headings) are catalogued
    - Compile to `.mo` via babel build step in `pyproject.toml`
    - _Requirements: 14.2_

  - [ ] 18.4 Property test for locale switching
    - **Property 28: Locale switch is deterministic and total**
    - **Validates: Requirements 14.1, 14.3, 14.5**
    - File: `tests/property/test_locale_switch.py`

  - [ ] 18.5 Property test for unicode round-trip
    - **Property 29: Unicode round-trips through I/O**
    - **Validates: Requirements 14.4**
    - File: `tests/property/test_unicode_roundtrip.py`

  - [ ] 18.6 Unit test for both locales present
    - Verify `en` and `ru` `.po` files exist and compile
    - File: `tests/unit/test_locales_present.py`
    - _Requirements: 14.2_

- [ ] 19. Implement CLI
  - [ ] 19.1 Implement `cli/main.py` with argparse root
    - Top-level `binchecker` with subcommands `site`, `card`, `batch`, `pool`, `config`, `plugins`, `repl`
    - Global flags: `--profile`, `--locale`, `--log-level`, `--log-dir`, `--config`, `--quiet`, `--verbose`, `--export`, `--out`, `--json`
    - Initializes config (via `load_config`), logging (via `setup_logging`), plugin registry, locale before dispatch
    - Returns exit codes per `EXIT_CODES` table
    - _Requirements: 10.1, 10.2, 10.5_

  - [ ] 19.2 Implement `cli/site.py` subcommand
    - `binchecker site <url> [--json] [--export <fmt>] [--out <path>]`
    - Calls `analyse_site` and pipes `SiteCheckResult` through chosen exporter
    - _Requirements: 1.1, 4.1, 10.5_

  - [ ] 19.3 Implement `cli/card.py` subcommand
    - `binchecker card <pan|mm|yy|cvv> [--site <url>] [--key <pk>] [--no-bin] [--no-live]`
    - Accepts pipe-separated card or four positional args
    - Calls `validate_card`; outputs through exporter
    - _Requirements: 2.1, 10.5_

  - [ ] 19.4 Implement `cli/batch.py` subcommand
    - `binchecker batch [--file <path>] [--concurrency N] [--resume] [--out-dir <dir>]`
    - Streams reader → `BatchRunner.run` → exporters per output stream
    - Honors `--resume` via `Checkpoint.resume`
    - _Requirements: 3.1, 3.7, 3.8_

  - [ ] 19.5 Implement `cli/pool.py` subcommand
    - `binchecker pool list | update | add <signatures.json>`
    - `update` pulls from configured URL and writes new pool file (auto-update path for Req. 1.2)
    - _Requirements: 1.2, 13.4_

  - [ ] 19.6 Implement `cli/config.py` subcommand
    - `binchecker config show | validate | diff`
    - `show` prints masked summary; `validate` returns exit 0/78; `diff` shows resolution sources
    - _Requirements: 5.9_

  - [ ] 19.7 Implement `cli/plugins.py` subcommand
    - `binchecker plugins list` prints discovered plugins with compatibility status
    - _Requirements: 15.4, 15.5_

  - [ ] 19.8 Implement `cli/interactive.py` REPL
    - `binchecker repl` opens prompt_toolkit-based loop with subcommand tab completion and history
    - _Requirements: 10.3_

  - [ ] 19.9 Implement `cli/help.py` consistent formatting helpers
    - Shared formatters for output blocks, color (auto-disable on non-tty), JSON pretty print
    - _Requirements: 10.1, 10.5_

  - [ ] 19.10 Snapshot tests for `--help` of every subcommand
    - File: `tests/unit/test_cli_help.py`
    - _Requirements: 10.1, 10.3_

- [ ] 20. Implement legacy compatibility shims
  - [ ] 20.1 Refactor existing `bin_checker.py` to thin shim
    - Existing CLI usage `python bin_checker.py <url>` re-dispatches to `binchecker site <url>`
    - Preserves stdout shape for current consumers
    - _Requirements: 13.5_

  - [ ] 20.2 Refactor existing `card_checker.py` to thin shim
    - `python card_checker.py <pan>|<mm>|<yy>|<cvv>` re-dispatches to `binchecker card`
    - Preserves backward-compatible output formatting
    - _Requirements: 13.5_

  - [ ] 20.3 Refactor existing `batch_check.py` to thin shim
    - `python batch_check.py --file cards.txt` re-dispatches to `binchecker batch --file cards.txt`
    - _Requirements: 13.5_

  - [ ] 20.4 Preserve legacy `gateway_pool.json` loading
    - Verify existing file in repo loads through `GatewayPool.load` without modification
    - Add migration helper `binchecker pool migrate` writing v1 schema in-place (optional)
    - _Requirements: 13.5_

- [ ] 21. Implement default plugins and example
  - [ ] 21.1 Implement an example `GatewayDetectorPlugin`
    - Located at `binchecker/plugins/examples/example_detector.py` and registered as entry point in `pyproject.toml`
    - Demonstrates plugin contract for documentation
    - _Requirements: 15.1, 15.3_

  - [ ] 21.2 Unit test for example plugin loads
    - File: `tests/unit/test_default_pool.py` extended with default-pool size and plugin merge
    - _Requirements: 1.4, 15.3_

- [ ] 22. Documentation and dependency hygiene
  - [ ] 22.1 Update top-level `README.md`
    - Document subcommands, config keys, plugin authoring, migration from legacy scripts
    - Include usage examples for site / card / batch / pool / config / plugins / repl
    - Document export formats and template authoring
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

  - [ ] 22.2 Author `CHANGELOG.md` and `MIGRATION.md`
    - CHANGELOG entries for the v1 release
    - Migration notes from legacy flat scripts to `binchecker` package
    - _Requirements: 13.2_

  - [ ] 22.3 Update `requirements.txt` to mirror `pyproject.toml` runtime deps
    - Pinned versions; ensures `pip install -r requirements.txt` keeps working alongside `pip install -e .`
    - _Requirements: 13.1_

  - [ ] 22.4 Compliance tests for documentation and changelog
    - File: `tests/compliance/test_changelog_present.py` verifies CHANGELOG/README cover key items
    - _Requirements: 12.1, 12.4, 13.2_

- [ ] 23. Compliance and integration glue
  - [ ] 23.1 Implement no-PAN-in-logs compliance test
    - Replays a recorded test log through `PanRedactionFilter`; greps for any Luhn-valid PAN
    - File: `tests/compliance/test_no_pan_in_logs.py`
    - _Requirements: 8.1, 8.4_

  - [ ] 23.2 Implement coverage gate compliance test
    - File: `tests/compliance/test_coverage_gate.py`
    - _Requirements: 11.5_

  - [ ] 23.3 Quarterly accuracy suite scaffolding
    - Mark with `@pytest.mark.quarterly`; runs against curated 100-site corpus
    - File: `tests/integration/test_gateway_corpus.py` extended
    - _Requirements: 1.6_

  - [ ] 23.4 Integration tests for end-to-end card validation accuracy
    - 500 valid + 500 invalid card corpus; assert ≥90% / ≥95% rates respectively
    - File: `tests/integration/test_card_corpus.py`
    - _Requirements: 2.5, 2.6_

  - [ ] 23.5 Integration test for real-API smoke (gated by `INTEGRATION_REAL=1`)
    - One query per live BIN provider to detect upstream schema drift
    - File: `tests/integration/test_provider_smoke.py`
    - _Requirements: 7.5_

- [ ] 24. Final wiring and version stamping
  - [ ] 24.1 Wire all subsystems in `binchecker/app.py` (composition root)
    - Builds `AppContext` with `cfg`, `client`, `registry`, `bin_chain`, `pool`, `locale`
    - All CLI subcommands and the batch runner consume `AppContext`
    - _Requirements: 5.1, 6.1, 7.5, 13.3, 15.4_

  - [ ] 24.2 Stamp `__version__` into all exporter outputs and CLI banners
    - Read `binchecker.version.__version__` and include in JSON/CSV/HTML/PDF outputs and CLI `--version`
    - _Requirements: 13.3_

  - [ ] 24.3 Implement startup configuration summary log
    - On startup emit one INFO line per resolved config field with source attribution; secrets masked
    - _Requirements: 5.3, 5.9_

- [ ] 25. Final checkpoint - ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP.
- Property tests are the primary correctness gate; each cites the specific Property number from the design and the requirement clauses it validates.
- Checkpoints (tasks 6, 12, 17, 25) provide explicit pause points for review.
- The pipeline's strict 7-step ordering (Property 4) is the central invariant for card validation correctness.
- `PanRedactionFilter` (Property 9) is attached to the **root** logger so PCI safety is a runtime invariant, not a coding convention.
- Default profile is `production`, which enforces HTTPS-only on the HTTP client (Property 10).
- Backward compatibility is preserved through thin shims (tasks 20.1-20.3) and legacy schema support in `GatewayPool.load` (Property 27).
- Integration and accuracy tests (tasks 14.3, 15.11, 23.3, 23.4) require curated fixtures stored in `tests/fixtures/`; create them as part of task 1.2 or before running these tests.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3"] },
    { "id": 1, "tasks": ["2.1", "5.1"] },
    { "id": 2, "tasks": ["2.2", "2.4", "2.6", "2.8", "2.10", "3.1", "4.1", "8.1"] },
    { "id": 3, "tasks": ["2.3", "2.5", "2.7", "2.9", "3.2", "3.3", "4.2", "8.2"] },
    { "id": 4, "tasks": ["3.4", "3.5", "4.3", "4.6", "7.1", "7.3", "7.5", "8.3", "9.1", "10.1", "11.1", "11.3", "16.1"] },
    { "id": 5, "tasks": ["4.4", "4.5", "4.7", "4.8", "7.2", "7.4", "9.2", "9.3", "9.6", "9.7", "9.8", "10.2", "10.3", "10.4", "10.5", "11.2", "11.4", "11.5", "11.6", "16.2", "16.3", "16.5", "16.8", "18.1", "18.2"] },
    { "id": 6, "tasks": ["4.9", "9.4", "9.5", "10.6", "16.4", "16.6", "16.7", "16.9", "16.10", "18.3", "18.4", "18.5", "18.6"] },
    { "id": 7, "tasks": ["10.7", "10.8", "13.1", "14.1", "15.1", "15.2", "15.4", "15.10", "21.1"] },
    { "id": 8, "tasks": ["13.2", "13.3", "14.3", "15.3", "15.5", "15.6", "21.2"] },
    { "id": 9, "tasks": ["14.2", "15.7", "15.8", "15.9", "15.11", "15.12", "19.1"] },
    { "id": 10, "tasks": ["19.2", "19.3", "19.4", "19.5", "19.6", "19.7", "19.8", "19.9"] },
    { "id": 11, "tasks": ["19.10", "20.1", "20.2", "20.3", "20.4", "22.1", "22.2", "22.3", "24.1"] },
    { "id": 12, "tasks": ["22.4", "23.1", "23.2", "23.3", "23.4", "23.5", "24.2", "24.3"] }
  ]
}
```
