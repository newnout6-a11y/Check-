"""webrecon package.

Web reconnaissance and automation toolkit. Discovers websites through
multiple intelligence sources (FOFA, Shodan, Serper, GitHub), parses
exposed configuration, automates form interaction, and persists
findings in a structured asset database. See `design.md` for the full
architecture.
"""

from webrecon.version import __version__

__all__ = ["__version__"]
