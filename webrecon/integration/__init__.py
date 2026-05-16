"""Integration layer for refactoring existing standalone scripts.

This sub-package provides backward-compatible wrappers around the
original reconnaissance scripts (``fofa_scraper.py``, ``github_dorker.py``,
``serper_deep.py``, ``sk_web_hunter.py``, ``site_scraper.py``), wired
into the new ``webrecon`` package modules.

Each integration module preserves the original script's CLI interface
while delegating to the package's discovery, mass-parser, github,
and database layers.

* :mod:`webrecon.integration.fofa_integration` -- FOFA scraper
  refactored to use :mod:`webrecon.discovery.fofa` +
  :mod:`webrecon.mass_parser.woocommerce` + DB.
* :mod:`webrecon.integration.github_integration` -- GitHub dorker
  refactored to use :mod:`webrecon.github.client` +
  :mod:`webrecon.github.analyzer` + DB.
* :mod:`webrecon.integration.serper_integration` -- Serper deep search
  refactored to use :mod:`webrecon.discovery.serper` +
  :mod:`webrecon.mass_parser.woocommerce` + DB.
* :mod:`webrecon.integration.hunter_integration` -- Web hunter and
  site scraper refactored to use :mod:`webrecon.mass_parser.scanner` +
  :mod:`webrecon.mass_parser.woocommerce` + DB.
"""

from webrecon.integration.fofa_integration import run_fofa_scraper
from webrecon.integration.github_integration import run_github_dorker
from webrecon.integration.hunter_integration import run_web_hunter
from webrecon.integration.serper_integration import run_serper_deep

__all__ = [
    "run_fofa_scraper",
    "run_github_dorker",
    "run_serper_deep",
    "run_web_hunter",
]
