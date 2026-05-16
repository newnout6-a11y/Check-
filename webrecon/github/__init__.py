"""GitHub repository intelligence sub-package.

This package wraps the GitHub REST API for the reconnaissance
pipeline:

* :mod:`webrecon.github.client` -- asynchronous GitHub API client,
  query builder, code-match adapter, and rate-limit-aware error
  hierarchy.
* :mod:`webrecon.github.analyzer` -- secret detection and analysis
  for code-search results, Stripe key classification, and batch
  processing.

The public surface of each sub-module is re-exported here so callers
can write ``from webrecon.github import GithubClient`` instead of
following the longer module path.
"""

from webrecon.github.analyzer import (
    GithubAnalyzer,
    SecretMatch,
    SecretPattern,
    classify_stripe_key,
    stripe_key_to_model,
)
from webrecon.github.client import (
    GithubApiError,
    GithubAuthError,
    GithubClient,
    GithubCodeMatch,
    GithubError,
    GithubQueryBuilder,
    GithubRateLimitError,
    RateLimiter,
)

__all__ = [
    "GithubAnalyzer",
    "GithubApiError",
    "GithubAuthError",
    "GithubClient",
    "GithubCodeMatch",
    "GithubError",
    "GithubQueryBuilder",
    "GithubRateLimitError",
    "RateLimiter",
    "SecretMatch",
    "SecretPattern",
    "classify_stripe_key",
    "stripe_key_to_model",
]
