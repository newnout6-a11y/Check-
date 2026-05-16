"""Assessment reporting for the automation pipeline.

This module generates structured reports from validation and testing
results, supporting multiple output formats (JSON, CSV, HTML via
Jinja2). It provides vulnerability scoring, risk categorization, and
actionable recommendations.

Usage::

    reporter = AssessmentReporter()
    report = reporter.generate_report(
        validation_reports=[...],
        stripe_results=[...],
    )
    reporter.save_json(report, "report.json")
    reporter.save_html(report, "report.html")

Validates: Requirement 6.4 (vulnerability scoring and categorization),
Requirement 6.5 (multi-format report generation),
Requirement 6.6 (risk assessment and recommendations).
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.automation.stripe_tester import PkTestResult, SkValidationResult
    from webrecon.automation.validator import ValidationReport

__all__ = [
    "AssessmentReport",
    "AssessmentReporter",
    "Finding",
    "RiskLevel",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


class RiskLevel:
    """Risk level constants for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"

    _ORDER: ClassVar[dict[str, int]] = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1,
        NONE: 0,
    }

    @classmethod
    def max_level(cls, *levels: str) -> str:
        """Return the highest risk level from a set."""
        if not levels:
            return cls.NONE
        return max(levels, key=lambda lvl: cls._ORDER.get(lvl, 0))

    @classmethod
    def all_levels(cls) -> list[str]:
        """Return all risk levels from highest to lowest."""
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO, cls.NONE]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single security finding in an assessment.

    Attributes:
        id: Unique finding identifier.
        title: Short description of the finding.
        description: Detailed description.
        risk_level: Assessed risk level.
        url: The URL where the finding was observed.
        category: Finding category (e.g. ``"exposed_key"``,
            ``"missing_header"``, ``"tokenization"``).
        recommendation: Suggested remediation action.
        evidence: Supporting evidence (key value, header name, etc.).
    """

    id: str = ""
    title: str = ""
    description: str = ""
    risk_level: str = RiskLevel.NONE
    url: str = ""
    category: str = ""
    recommendation: str = ""
    evidence: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Assessment report
# ---------------------------------------------------------------------------


@dataclass
class AssessmentReport:
    """Comprehensive assessment report for a set of targets.

    Attributes:
        id: Unique report identifier.
        generated_at: Timestamp of report generation.
        findings: Ordered list of findings (highest risk first).
        summary: Aggregated counts by risk level and category.
        total_targets: Number of targets assessed.
        total_findings: Total number of findings.
        overall_risk: The highest risk level across all findings.
    """

    id: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    total_targets: int = 0
    total_findings: int = 0
    overall_risk: str = RiskLevel.NONE


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class AssessmentReporter:
    """Generate assessment reports from validation and testing results.

    The reporter aggregates findings from
    :class:`~webrecon.automation.validator.ValidationReport` and
    :class:`~webrecon.automation.stripe_tester.SkValidationResult` /
    :class:`~webrecon.automation.stripe_tester.PkTestResult` objects,
    scores them, and produces multi-format reports.
    """

    def generate_report(
        self,
        *,
        validation_reports: list[ValidationReport] | None = None,
        sk_results: list[SkValidationResult] | None = None,
        pk_results: list[PkTestResult] | None = None,
    ) -> AssessmentReport:
        """Generate an assessment report from collected results.

        Args:
            validation_reports: Website validation reports.
            sk_results: Stripe secret key validation results.
            pk_results: Stripe public key tokenization results.

        Returns:
            An :class:`AssessmentReport` with scored findings.
        """
        findings: list[Finding] = []

        # Process validation reports.
        if validation_reports:
            for vr in validation_reports:
                findings.extend(self._findings_from_validation(vr))

        # Process SK validation results.
        if sk_results:
            for sk in sk_results:
                findings.extend(self._findings_from_sk(sk))

        # Process PK tokenization results.
        if pk_results:
            for pk in pk_results:
                findings.extend(self._findings_from_pk(pk))

        # Sort by risk level (highest first).
        risk_order = RiskLevel._ORDER
        findings.sort(key=lambda f: risk_order.get(f.risk_level, 0), reverse=True)

        # Build summary.
        summary: dict[str, int] = {}
        for level in RiskLevel.all_levels():
            count = sum(1 for f in findings if f.risk_level == level)
            if count:
                summary[level] = count

        # Category summary.
        category_counts: dict[str, int] = {}
        for f in findings:
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
        summary.update({f"cat_{k}": v for k, v in category_counts.items()})

        # Overall risk.
        all_risks = [f.risk_level for f in findings]
        overall = RiskLevel.max_level(*all_risks) if all_risks else RiskLevel.NONE

        total_targets = len(validation_reports or [])

        report = AssessmentReport(
            id=str(uuid.uuid4()),
            findings=findings,
            summary=summary,
            total_targets=total_targets,
            total_findings=len(findings),
            overall_risk=overall,
        )

        _LOGGER.info(
            "automation.reporter.report_generated",
            findings=len(findings),
            overall_risk=overall,
        )

        return report

    # ---- Output formats -----------------------------------------------

    def to_json(self, report: AssessmentReport) -> str:
        """Serialize a report to JSON."""
        return json.dumps(self._report_to_dict(report), indent=2, default=str)

    def to_csv(self, report: AssessmentReport) -> str:
        """Serialize findings to CSV."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "title", "risk_level", "category", "url",
            "description", "recommendation",
        ])
        for f in report.findings:
            writer.writerow([
                f.id, f.title, f.risk_level, f.category, f.url,
                f.description, f.recommendation,
            ])
        return buf.getvalue()

    def to_html(self, report: AssessmentReport) -> str:
        """Generate an HTML report using Jinja2."""
        try:
            import jinja2
        except ImportError:
            return self._fallback_html(report)

        template_str = _HTML_TEMPLATE
        env = jinja2.Environment(autoescape=True)
        template = env.from_string(template_str)
        rendered = template.render(
            report=report,
            risk_levels=RiskLevel.all_levels(),
        )
        return str(rendered)

    def save_json(self, report: AssessmentReport, path: str | Path) -> None:
        """Save a JSON report to a file."""
        Path(path).write_text(self.to_json(report), encoding="utf-8")

    def save_csv(self, report: AssessmentReport, path: str | Path) -> None:
        """Save a CSV report to a file."""
        Path(path).write_text(self.to_csv(report), encoding="utf-8")

    def save_html(self, report: AssessmentReport, path: str | Path) -> None:
        """Save an HTML report to a file."""
        Path(path).write_text(self.to_html(report), encoding="utf-8")

    # ---- Internal: Finding generators ----------------------------------

    @staticmethod
    def _findings_from_validation(vr: ValidationReport) -> list[Finding]:
        """Generate findings from a validation report."""
        findings: list[Finding] = []

        # Missing security headers.
        for sh in vr.security_headers:
            if not sh.present:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Missing security header: {sh.name}",
                    description=f"The {sh.name} header is not set. {sh.description}.",
                    risk_level=RiskLevel.MEDIUM,
                    url=vr.url,
                    category="missing_header",
                    recommendation=f"Set the {sh.name} header on all responses.",
                    evidence={"header_name": sh.name},
                ))

        # No SSL.
        if not vr.has_ssl and vr.url.startswith("https://"):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Invalid or missing SSL certificate",
                description="The site uses HTTPS but the SSL certificate is invalid or missing.",
                risk_level=RiskLevel.HIGH,
                url=vr.url,
                category="ssl",
                recommendation="Obtain a valid SSL certificate from a trusted CA.",
            ))

        return findings

    @staticmethod
    def _findings_from_sk(sk: SkValidationResult) -> list[Finding]:
        """Generate findings from an SK validation result."""
        findings: list[Finding] = []

        if sk.is_valid:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title=f"Valid Stripe secret key exposed ({sk.key_value[:8]}...)",
                description=(
                    f"A valid {sk.key_type.value} Stripe key was found and confirmed "
                    f"active. Account: {sk.account_id or 'unknown'}. "
                    f"Balance currency: {sk.balance_currency or 'unknown'}."
                ),
                risk_level=sk.risk_level,
                url="",
                category="exposed_key",
                recommendation="Rotate the exposed key immediately in the Stripe dashboard.",
                evidence={
                    "key_prefix": sk.key_value[:8],
                    "key_type": sk.key_type.value,
                    "account_id": sk.account_id,
                },
            ))

        return findings

    @staticmethod
    def _findings_from_pk(pk: PkTestResult) -> list[Finding]:
        """Generate findings from a PK tokenization result."""
        findings: list[Finding] = []

        if pk.tokenization_status == "ok":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title=f"Server-side tokenization enabled ({pk.key_value[:8]}...)",
                description=(
                    "The Stripe public key allows server-side tokenization, "
                    "meaning payment methods can be created from the server "
                    "without client-side Stripe.js integration."
                ),
                risk_level=RiskLevel.HIGH,
                url="",
                category="tokenization",
                recommendation=(
                    "Review whether server-side tokenization is required. "
                    "Consider restricting the integration surface in Stripe settings."
                ),
                evidence={
                    "key_prefix": pk.key_value[:8],
                    "status": pk.tokenization_status,
                },
            ))
        elif pk.tokenization_status == "blocked":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title=f"Server-side tokenization blocked ({pk.key_value[:8]}...)",
                description="Server-side tokenization is blocked for this key.",
                risk_level=RiskLevel.INFO,
                url="",
                category="tokenization",
                recommendation="No action needed; the integration surface is properly restricted.",
                evidence={
                    "key_prefix": pk.key_value[:8],
                    "status": pk.tokenization_status,
                },
            ))

        return findings

    # ---- Internal: Serialization --------------------------------------

    @staticmethod
    def _report_to_dict(report: AssessmentReport) -> dict[str, Any]:
        """Convert a report to a JSON-serializable dict."""
        return {
            "id": report.id,
            "generated_at": report.generated_at.isoformat(),
            "total_targets": report.total_targets,
            "total_findings": report.total_findings,
            "overall_risk": report.overall_risk,
            "summary": report.summary,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "risk_level": f.risk_level,
                    "url": f.url,
                    "category": f.category,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                }
                for f in report.findings
            ],
        }

    @staticmethod
    def _fallback_html(report: AssessmentReport) -> str:
        """Generate a minimal HTML report without Jinja2."""
        rows = ""
        for f in report.findings:
            rows += (
                f"<tr>"
                f"<td>{f.risk_level}</td>"
                f"<td>{f.title}</td>"
                f"<td>{f.url}</td>"
                f"<td>{f.recommendation}</td>"
                f"</tr>"
            )
        return (
            "<html><body>"
            f"<h1>Assessment Report</h1>"
            f"<p>Overall risk: {report.overall_risk}</p>"
            f"<p>Findings: {report.total_findings}</p>"
            f"<table border=1>{rows}</table>"
            "</body></html>"
        )


# ---------------------------------------------------------------------------
# HTML template for Jinja2 reports
# ---------------------------------------------------------------------------

_HTML_TEMPLATE: str = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebRecon Assessment Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; }
  h1 { color: #1a1a2e; }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .summary-card { padding: 1rem; border-radius: 8px; min-width: 120px; text-align: center; }
  .critical { background: #ff4444; color: white; }
  .high { background: #ff8800; color: white; }
  .medium { background: #ffbb00; color: black; }
  .low { background: #00bb00; color: white; }
  .info { background: #0088ff; color: white; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { padding: 0.5rem 1rem; text-align: left; border-bottom: 1px solid #ddd; }
  th { background: #1a1a2e; color: white; }
  tr:hover { background: #f5f5f5; }
  .risk-badge { padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
</style>
</head>
<body>
<h1>WebRecon Assessment Report</h1>
<p>Generated: {{ report.generated_at.isoformat() }}</p>
<p>Overall risk: <span class="risk-badge {{ report.overall_risk }}">\
{{ report.overall_risk | upper }}</span></p>

<div class="summary">
{% for level in risk_levels %}
{% if report.summary.get(level, 0) > 0 %}
<div class="summary-card {{ level }}">
  <div style="font-size:2rem">{{ report.summary[level] }}</div>
  <div>{{ level | upper }}</div>
</div>
{% endif %}
{% endfor %}
</div>

<p>Targets assessed: {{ report.total_targets }} | Findings: {{ report.total_findings }}</p>

<table>
<thead>
<tr><th>Risk</th><th>Title</th><th>URL</th><th>Category</th><th>Recommendation</th></tr>
</thead>
<tbody>
{% for f in report.findings %}
<tr>
  <td><span class="risk-badge {{ f.risk_level }}">{{ f.risk_level | upper }}</span></td>
  <td>{{ f.title }}</td>
  <td>{{ f.url }}</td>
  <td>{{ f.category }}</td>
  <td>{{ f.recommendation }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>
"""
