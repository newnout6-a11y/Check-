"""Form automation sub-package for HTML form discovery, filling, and session management.

This package provides the form-interaction pipeline:

* :mod:`webrecon.form_automation.discovery` -- HTML form parsing with
  BeautifulSoup4, field extraction, and CSRF token detection.
* :mod:`webrecon.form_automation.filler` -- test data generation and
  automated form submission with response analysis.
* :mod:`webrecon.form_automation.session` -- persistent cookie/session
  management, auth state tracking, and redirect handling.
"""

from webrecon.form_automation.discovery import FormDiscoverer
from webrecon.form_automation.filler import FormFiller, SubmissionResult
from webrecon.form_automation.session import FormSession, RedirectStep, SessionState

__all__ = [
    "FormDiscoverer",
    "FormFiller",
    "FormSession",
    "RedirectStep",
    "SessionState",
    "SubmissionResult",
]
