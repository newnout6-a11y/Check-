"""Command-line interface sub-package for the ``webrecon`` toolkit.

This package implements the CLI subcommands:

* :mod:`webrecon.cli.main` -- root parser and dispatch.
* :mod:`webrecon.cli.discover` -- multi-source target discovery.
* :mod:`webrecon.cli.github_cmd` -- GitHub reconnaissance.
* :mod:`webrecon.cli.parse` -- bulk website parsing.
* :mod:`webrecon.cli.automate` -- form automation.
* :mod:`webrecon.cli.validate` -- website validation and Stripe testing.
* :mod:`webrecon.cli.export` -- data export.
* :mod:`webrecon.cli.config` -- configuration management.
* :mod:`webrecon.cli.db` -- database operations.
"""

from webrecon.cli.main import main

__all__ = ["main"]
