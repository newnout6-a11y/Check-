"""Safety validator for the ``webrecon`` safety layer.

This module provides:

* **Test data generation** -- safe, synthetic data for form filling
  and validation.
* **Safety checks** -- pre-operation validation that the requested
  action complies with the current safety settings.
* **Confirmation prompts** -- interactive confirmation for
  destructive operations.
* **Audit logging** -- structured logging of all safety-relevant
  events.

Usage::

    validator = SafetyValidator(test_mode=True, require_confirmation=True)
    if await validator.check_operation("validate_key", key="sk_live_..."):
        result = await tester.validate_sk(key)

Validates: Requirement 9.4 (test data generation for safe validation),
Requirement 9.5 (confirmation prompts for destructive ops),
Requirement 9.6 (safety checks and audit logging).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from webrecon.log import get_logger

__all__ = [
    "AuditEntry",
    "SafetyValidator",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Audit entry
# ---------------------------------------------------------------------------


@dataclass
class AuditEntry:
    """One entry in the safety audit log.

    Attributes:
        id: Unique entry identifier.
        timestamp: When the event occurred.
        operation: The operation being performed.
        allowed: Whether the operation was allowed.
        reason: Why the operation was allowed or denied.
        details: Additional context (key prefix, URL, etc.).
    """

    id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    operation: str = ""
    allowed: bool = False
    reason: str = ""
    details: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Safety validator
# ---------------------------------------------------------------------------


class SafetyValidator:
    """Validate and gatekeep operations based on safety settings.

    The validator enforces the safety constraints defined in
    :class:`~webrecon.config.schema.SafetySettings`:

    * ``test_mode`` -- restrict to non-destructive operations.
    * ``use_test_data_only`` -- only use synthetic test data.
    * ``require_confirmation`` -- prompt for destructive operations.

    Args:
        test_mode: Whether test mode is active.
        use_test_data_only: Whether to restrict to test data.
        require_confirmation: Whether to prompt for confirmation.
        max_requests_per_site: Hard cap on requests per site.
    """

    def __init__(
        self,
        *,
        test_mode: bool = True,
        use_test_data_only: bool = True,
        require_confirmation: bool = True,
        max_requests_per_site: int = 100,
    ) -> None:
        self._test_mode = test_mode
        self._use_test_data_only = use_test_data_only
        self._require_confirmation = require_confirmation
        self._max_requests = max_requests_per_site
        self._request_counts: dict[str, int] = {}  # domain → count
        self._audit_log: list[AuditEntry] = []

    # ---- Properties ---------------------------------------------------

    @property
    def test_mode(self) -> bool:
        return self._test_mode

    @property
    def use_test_data_only(self) -> bool:
        return self._use_test_data_only

    @property
    def audit_log(self) -> list[AuditEntry]:
        return list(self._audit_log)

    # ---- Operation checks ---------------------------------------------

    async def check_operation(
        self,
        operation: str,
        **details: Any,
    ) -> bool:
        """Check whether an operation is allowed under current safety settings.

        Args:
            operation: The operation name (e.g. ``"validate_key"``,
                ``"scan_site"``, ``"fill_form"``).
            **details: Operation-specific details.

        Returns:
            ``True`` if the operation is allowed, ``False`` otherwise.
        """
        reason = ""
        allowed = True

        # Destructive operations in test mode.
        destructive_ops = {
            "submit_form",
            "create_payment",
            "modify_data",
            "delete_data",
        }
        if operation in destructive_ops and self._test_mode:
            allowed = False
            reason = "Destructive operation blocked in test mode"

        # Request count per site.
        url = str(details.get("url", ""))
        if url:
            domain = self._extract_domain(url)
            count = self._request_counts.get(domain, 0)
            if count >= self._max_requests:
                allowed = False
                reason = f"Max requests ({self._max_requests}) reached for {domain}"

        # Confirmation for potentially sensitive operations.
        sensitive_ops = {
            "validate_sk_key",
            "test_tokenization",
            "scan_exposed_files",
        }
        if operation in sensitive_ops and self._require_confirmation:
            confirmed = self._prompt_confirmation(operation, details)
            if not confirmed:
                allowed = False
                reason = "User did not confirm operation"

        # Log the check.
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            operation=operation,
            allowed=allowed,
            reason=reason,
            details={k: str(v)[:100] for k, v in details.items()},
        )
        self._audit_log.append(entry)

        if not allowed:
            _LOGGER.warning(
                "safety.validator.operation_blocked",
                operation=operation,
                reason=reason,
            )

        return allowed

    # ---- Request counting ---------------------------------------------

    def record_request(self, url: str) -> None:
        """Record a request to a URL for per-site counting."""
        domain = self._extract_domain(url)
        self._request_counts[domain] = self._request_counts.get(domain, 0) + 1

    def get_request_count(self, url: str) -> int:
        """Return the number of requests made to a domain."""
        domain = self._extract_domain(url)
        return self._request_counts.get(domain, 0)

    # ---- Test data generation -----------------------------------------

    @staticmethod
    def generate_test_email() -> str:
        """Generate a random test email address."""
        return f"test_{uuid.uuid4().hex[:8]}@example.com"

    @staticmethod
    def generate_test_card() -> dict[str, str]:
        """Return Stripe's official test card data."""
        return {
            "number": "4242424242424242",
            "exp_month": "12",
            "exp_year": "35",
            "cvc": "123",
        }

    @staticmethod
    def generate_test_address() -> dict[str, str]:
        """Return a standard test address (US)."""
        return {
            "line1": "123 Test Street",
            "city": "New York",
            "state": "NY",
            "postal_code": "10001",
            "country": "US",
        }

    # ---- Audit log export ---------------------------------------------

    def export_audit_log(self) -> str:
        """Export the audit log as JSON."""
        entries = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "operation": e.operation,
                "allowed": e.allowed,
                "reason": e.reason,
                "details": e.details,
            }
            for e in self._audit_log
        ]
        return json.dumps(entries, indent=2, ensure_ascii=False)

    # ---- Internal -----------------------------------------------------

    @staticmethod
    def _prompt_confirmation(operation: str, details: dict[str, Any]) -> bool:
        """Prompt the user for confirmation.

        In non-interactive contexts, defaults to ``False`` (deny).
        """
        try:
            print(f"\n⚠  Confirmation required for: {operation}")
            for k, v in details.items():
                val = str(v)
                # Mask sensitive values.
                if any(s in k.lower() for s in ("key", "token", "password", "secret")):
                    val = val[:8] + "..." + val[-4:] if len(val) > 12 else "***"
                print(f"  {k}: {val}")
            response = input("  Proceed? [y/N]: ").strip().lower()
            return response in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the domain from a URL."""
        from urllib.parse import urlparse
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""
