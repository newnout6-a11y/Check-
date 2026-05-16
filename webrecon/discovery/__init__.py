"""Target discovery sub-package.

This package wraps the external intelligence sources used by the
reconnaissance pipeline:

* :mod:`webrecon.discovery.fofa` -- FOFA REST API client,
  query builder, and result/asset adapters.
* :mod:`webrecon.discovery.shodan` -- Shodan REST API client,
  query builder, and match/asset adapters.
* :mod:`webrecon.discovery.serper` -- Serper.dev (Google search) REST
  API client, Google-dork builder, and result/asset adapters.

The public surface of each sub-module is re-exported here so callers
can write ``from webrecon.discovery import FofaClient`` or
``from webrecon.discovery import ShodanClient`` instead of following
the longer module path.
"""

from webrecon.discovery.fofa import (
    FofaApiError,
    FofaClient,
    FofaError,
    FofaQueryBuilder,
    FofaRateLimitError,
    FofaResult,
    RateLimiter,
)
from webrecon.discovery.serper import (
    GoogleDorkBuilder,
    SerperApiError,
    SerperClient,
    SerperError,
    SerperRateLimitError,
    SerperResult,
)
from webrecon.discovery.shodan import (
    ShodanApiError,
    ShodanClient,
    ShodanError,
    ShodanMatch,
    ShodanQueryBuilder,
    ShodanQuotaExceededError,
    ShodanRateLimitError,
)

__all__ = [
    "FofaApiError",
    "FofaClient",
    "FofaError",
    "FofaQueryBuilder",
    "FofaRateLimitError",
    "FofaResult",
    "GoogleDorkBuilder",
    "RateLimiter",
    "SerperApiError",
    "SerperClient",
    "SerperError",
    "SerperRateLimitError",
    "SerperResult",
    "ShodanApiError",
    "ShodanClient",
    "ShodanError",
    "ShodanMatch",
    "ShodanQueryBuilder",
    "ShodanQuotaExceededError",
    "ShodanRateLimitError",
]
