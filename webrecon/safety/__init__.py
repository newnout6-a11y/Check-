"""Safety sub-package for rate limiting, validation, and ethical use.

This package provides the cross-cutting safety mechanisms:

* :mod:`webrecon.safety.rate_limiter` -- per-host and global rate
  limits, robots.txt respect, exponential backoff.
* :mod:`webrecon.safety.validator` -- test data generation, safety
  checks, confirmation prompts, audit logging.
* :mod:`webrecon.safety.warnings` -- first-use ethical use warnings,
  legal boundary documentation, safe defaults.
"""

from webrecon.safety.rate_limiter import (
    AdaptiveRateLimiter,
    DomainRateLimiter,
    GlobalRateLimiter,
)
from webrecon.safety.validator import SafetyValidator
from webrecon.safety.warnings import check_first_use, display_ethical_warning

__all__ = [
    "AdaptiveRateLimiter",
    "DomainRateLimiter",
    "GlobalRateLimiter",
    "SafetyValidator",
    "check_first_use",
    "display_ethical_warning",
]
