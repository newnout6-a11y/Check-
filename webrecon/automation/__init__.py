"""Automation sub-package for website validation, Stripe testing, and reporting.

This package provides the assessment pipeline:

* :mod:`webrecon.automation.validator` -- technology detection,
  security header analysis, and SSL validation.
* :mod:`webrecon.automation.stripe_tester` -- Stripe key validation
  and server-side tokenization testing.
* :mod:`webrecon.automation.reporter` -- vulnerability scoring,
  multi-format report generation, and risk assessment.
"""

from webrecon.automation.reporter import (
    AssessmentReport,
    AssessmentReporter,
    Finding,
    RiskLevel,
)
from webrecon.automation.stripe_tester import (
    PkTestResult,
    SkValidationResult,
    StripeTester,
)
from webrecon.automation.validator import (
    SecurityHeaderResult,
    ValidationReport,
    WebsiteValidator,
)

__all__ = [
    "AssessmentReport",
    "AssessmentReporter",
    "Finding",
    "PkTestResult",
    "RiskLevel",
    "SecurityHeaderResult",
    "SkValidationResult",
    "StripeTester",
    "ValidationReport",
    "WebsiteValidator",
]
