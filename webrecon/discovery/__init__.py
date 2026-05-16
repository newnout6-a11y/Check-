"""Target discovery sub-package.

This package wraps the external intelligence sources used by the
reconnaissance pipeline:

* :mod:`webrecon.discovery.fofa` -- FOFA REST API client,
  query builder, and result/asset adapters.
* :mod:`webrecon.discovery.shodan` -- Shodan REST API client,
  query builder, and match/asset adapters.
* :mod:`webrecon.discovery.serper` -- Serper.dev (Google search) REST
  API client, Google-dork builder, and result/asset adapters.
* :mod:`webrecon.discovery.crtsh` -- Certificate Transparency
  discovery via crt.sh. Free, no API key required.
* :mod:`webrecon.discovery.wayback` -- Wayback Machine CDX-API
  discovery. Free, no API key required.

The public surface of each sub-module is re-exported here so callers
can write ``from webrecon.discovery import FofaClient`` or
``from webrecon.discovery import ShodanClient`` instead of following
the longer module path.
"""

from webrecon.discovery.crtsh import (
    CrtShApiError,
    CrtShClient,
    CrtShEntry,
    CrtShError,
)
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
from webrecon.discovery.wayback import (
    WaybackApiError,
    WaybackCapture,
    WaybackClient,
    WaybackError,
)

__all__ = [
    "CrtShApiError",
    "CrtShClient",
    "CrtShEntry",
    "CrtShError",
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
    "WaybackApiError",
    "WaybackCapture",
    "WaybackClient",
    "WaybackError",
]
