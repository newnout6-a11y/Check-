# API reference

`webrecon` is structured as a set of cooperating sub-packages with a
small public surface per layer. Embedding webrecon in other Python
code typically goes through these entry points.

## Top-level

```python
from webrecon import __version__
```

## Configuration

```python
from webrecon.config import (
    AppConfig, ApiKeys, ConcurrencySettings, RateLimitSettings,
    DatabaseSettings, SafetySettings,
    load_config, get_default_config,
    LoadedConfig, ConfigSource, ConfigLoadError,
    MissingOptionalConfigWarning,
)

# Recommended: load with the full priority chain.
loaded = load_config()
print(loaded.config.log_level)
print(loaded.resolution["api_keys.shodan"])  # ConfigSource enum

# Tests / scripts: get the schema defaults without env / .env lookup.
cfg = get_default_config()
```

## Core data models

```python
from webrecon.core.models import (
    AssetStatus, KeyType, DiscoverySource,
    WebsiteAsset, StripeKey, FormDiscovery, FormField,
)

asset = WebsiteAsset.from_dict(data)
asset.validate()           # raises ValueError on bad input
restored = WebsiteAsset.from_json(asset.to_json())
```

All four dataclasses round-trip cleanly through `to_dict` /
`from_dict` and `to_json` / `from_json`.

## Discovery clients

Each client takes an externally-managed `httpx.AsyncClient` so the
caller controls connection pooling, proxies, and timeouts.

```python
import httpx
from webrecon.discovery import (
    FofaClient, FofaQueryBuilder,
    ShodanClient, ShodanQueryBuilder,
    SerperClient, GoogleDorkBuilder,
)

async with httpx.AsyncClient() as http:
    fofa = FofaClient(http, email="...", key="...")
    query = FofaQueryBuilder().app("WooCommerce").body("pk_live_")
    async for asset in fofa.search_to_assets(query, max_pages=5):
        print(asset.url)
```

`search_to_assets` yields `WebsiteAsset` instances ready to feed into
the asset database. Use `search` if you need the raw row / match
objects with provider-specific metadata.

## GitHub reconnaissance

```python
from webrecon.github import GithubClient
from webrecon.github.analyzer import GithubAnalyzer

async with httpx.AsyncClient() as http:
    client = GithubClient(http, token="ghp_...")
    analyzer = GithubAnalyzer(client)
    async for match in analyzer.analyze_query('"sk_live_" filename:.env'):
        print(match.pattern_name, match.repository_name, match.snippet)
```

## Mass parser

```python
from webrecon.mass_parser import (
    MassParserClient, ExposedFileScanner, WooCommerceValidator,
)

async with MassParserClient(concurrency=15) as http:
    scanner = ExposedFileScanner(http)
    async for result in scanner.scan_sites(urls):
        print(result.url, result.found_keys)

    woo = WooCommerceValidator(http, test_tokenization=True)
    woo_result = await woo.validate("https://shop.example.com")
```

`MassParserClient` exposes `http_client` for callers that need to
share its underlying `httpx.AsyncClient` with the discovery clients.

## Form automation

```python
from webrecon.form_automation import FormDiscoverer, FormFiller, FormSession

async with MassParserClient() as http:
    forms = await FormDiscoverer(http).discover("https://example.com/contact")
    async with FormSession(base_url="https://example.com") as session:
        filler = FormFiller(http)
        for form in forms:
            await filler.fill_and_submit(form, session=session)
```

## Web automation

```python
from webrecon.automation import WebsiteValidator, StripeTester, AssessmentReporter

async with MassParserClient() as http:
    validator = WebsiteValidator(http)
    report = await validator.validate("https://example.com")

    tester = StripeTester(http)
    sk_result = await tester.validate_sk("sk_test_...")
    pk_result = await tester.test_pk_tokenization("pk_test_...")

    reporter = AssessmentReporter()
    assessment = reporter.generate_report(
        validation_reports=[report],
        sk_results=[sk_result],
        pk_results=[pk_result],
    )
    reporter.save_html(assessment, "assessment.html")
```

## Database

```python
from webrecon.database import (
    open_database, ConnectionPool,
    WebsiteAssetRepository, StripeKeyRepository, FormDiscoveryRepository,
    apply_migrations,
)
from webrecon.database.query import AssetQuery
from webrecon.database.export import DataExporter
from webrecon.database.analytics import DatabaseAnalytics

pool = await open_database("webrecon.sqlite3")
try:
    repo = WebsiteAssetRepository(pool)
    asset = await repo.get(asset_id)

    query = AssetQuery(pool).filter(status=AssetStatus.ACTIVE).limit(50)
    result = await query.execute()
    for asset in result.items:
        print(asset.url)

    exporter = DataExporter(pool)
    await exporter.export_csv("assets.csv")

    analytics = DatabaseAnalytics(pool)
    stats = await analytics.success_rate_by_source()
finally:
    await pool.close()
```

## Logging

```python
from webrecon.log import (
    configure_logging, get_logger,
    RequestIDContext, new_request_id,
    redact_sensitive_processor, mask_value,
)

configure_logging(level="INFO", json_output=False, log_file=None)
log = get_logger(__name__)

with RequestIDContext():
    log.info("scan_started", target="example.com")
```

`RequestIDContext` works as both a sync and an async context manager
and propagates the id through `asyncio.create_task` and `gather`.

## Safety

```python
from webrecon.safety import (
    AdaptiveRateLimiter, DomainRateLimiter, GlobalRateLimiter,
    SafetyValidator,
)
from webrecon.safety.warnings import check_first_use, display_ethical_warning

if check_first_use():
    display_ethical_warning()
```

## Performance utilities

```python
from webrecon.utils import MetricsCollector, Checkpoint, stream_in_batches

metrics = MetricsCollector("scan")
async with metrics.time_operation():
    await scan_target()

report = metrics.report()
print(report.success_rate, report.latency_p95_ms)

cp = Checkpoint("scan.checkpoint")
cp.load()
for url in urls:
    if cp.contains(url):
        continue
    await scan(url)
    cp.add(url)
    await cp.aflush()
```
