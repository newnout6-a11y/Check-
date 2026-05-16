"""Mass-parser sub-package for bulk website scanning and validation.

This package provides the bulk-processing pipeline for discovered
websites:

* :mod:`webrecon.mass_parser.client` -- shared async HTTP client
  with concurrency control, UA rotation, and retry logic.
* :mod:`webrecon.mass_parser.scanner` -- exposed-file scanner that
  checks common paths for leaked secrets.
* :mod:`webrecon.mass_parser.woocommerce` -- WooCommerce Store API
  validator with Stripe key extraction and tokenization testing.
"""

from webrecon.mass_parser.client import MassParserClient, RequestResult
from webrecon.mass_parser.scanner import (
    DEFAULT_EXPOSED_PATHS,
    ExposedFileScanner,
    ScanResult,
)
from webrecon.mass_parser.woocommerce import (
    WooCommerceValidator,
    WooValidationResult,
)

__all__ = [
    "DEFAULT_EXPOSED_PATHS",
    "ExposedFileScanner",
    "MassParserClient",
    "RequestResult",
    "ScanResult",
    "WooCommerceValidator",
    "WooValidationResult",
]
