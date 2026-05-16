"""Automated form filler for the form-automation pipeline.

This module generates test data based on field types, submits forms
with session management, and analyses the responses. It works in
concert with :mod:`webrecon.form_automation.discovery` (which finds
the forms) and :mod:`webrecon.form_automation.session` (which
manages cookies and auth state).

Usage::

    async with MassParserClient() as http:
        filler = FormFiller(http)
        result = await filler.fill_and_submit(form, session_cookies={})
        print(result.status_code, result.is_success)

Validates: Requirement 4.2 (test data generation based on field types),
Requirement 4.3 (form submission with session management),
Requirement 4.4 (response analysis and validation),
Requirement 4.5 (support for authentication mechanisms).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from webrecon.log import get_logger

if TYPE_CHECKING:
    from webrecon.core.models import FormDiscovery, FormField
    from webrecon.mass_parser.client import MassParserClient

__all__ = [
    "FormFiller",
    "SubmissionResult",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# Test data generators by field type
# ---------------------------------------------------------------------------

# Mapping from field type / name pattern to a test value generator.
# Each generator takes the FormField and returns a string value.

def _gen_email(f: FormField) -> str:
    return f"test_{uuid.uuid4().hex[:8]}@example.com"

def _gen_text(f: FormField) -> str:
    name_lower = f.name.lower()
    # Name-based heuristics.
    if any(kw in name_lower for kw in ("first_name", "firstname", "fname")):
        return "John"
    if any(kw in name_lower for kw in ("last_name", "lastname", "lname")):
        return "Doe"
    if any(kw in name_lower for kw in ("name", "full_name", "fullname")):
        return "John Doe"
    if any(kw in name_lower for kw in ("address", "addr", "street")):
        return "123 Test Street"
    if any(kw in name_lower for kw in ("city", "town")):
        return "New York"
    if any(kw in name_lower for kw in ("state", "province", "region")):
        return "NY"
    if any(kw in name_lower for kw in ("zip", "postal", "postcode")):
        return "10001"
    if any(kw in name_lower for kw in ("country", "nation")):
        return "US"
    if any(kw in name_lower for kw in ("phone", "tel", "mobile")):
        return "+1234567890"
    if any(kw in name_lower for kw in ("company", "organization", "org")):
        return "Test Corp"
    if any(kw in name_lower for kw in ("subject", "title", "topic")):
        return "Test Inquiry"
    if any(kw in name_lower for kw in ("message", "comment", "body", "description")):
        return "This is a test message from the webrecon toolkit."
    if any(kw in name_lower for kw in ("username", "user", "login", "account")):
        return f"testuser_{uuid.uuid4().hex[:6]}"
    return "test_value"

def _gen_password(f: FormField) -> str:
    return "TestP@ss123456!"

def _gen_number(f: FormField) -> str:
    name_lower = f.name.lower()
    if any(kw in name_lower for kw in ("quantity", "qty", "amount", "count")):
        return "1"
    if any(kw in name_lower for kw in ("price", "cost", "total")):
        return "10.00"
    return "1"

def _gen_url(f: FormField) -> str:
    return "https://example.com"

def _gen_tel(f: FormField) -> str:
    return "+1234567890"

def _gen_date(f: FormField) -> str:
    return "2025-01-01"

def _gen_hidden(f: FormField) -> str:
    # Use the default value for hidden fields (CSRF tokens, etc.).
    return f.default_value or ""

def _gen_checkbox(f: FormField) -> str:
    return "1"

def _gen_select(f: FormField) -> str:
    # Use the default value or first option.
    if f.default_value:
        return f.default_value
    options_str = f.metadata.get("options", "")
    if options_str:
        first = options_str.split("|")[0]
        return first.split(":")[0]
    return ""

def _gen_textarea(f: FormField) -> str:
    return _gen_text(f)


_FIELD_GENERATORS: dict[str, Any] = {
    "email": _gen_email,
    "text": _gen_text,
    "password": _gen_password,
    "number": _gen_number,
    "url": _gen_url,
    "tel": _gen_tel,
    "date": _gen_date,
    "hidden": _gen_hidden,
    "checkbox": _gen_checkbox,
    "select": _gen_select,
    "textarea": _gen_textarea,
    # Fallback for less common types.
    "search": _gen_text,
    "color": lambda f: "#ff0000",
    "range": lambda f: "50",
    "file": lambda f: "",
    "radio": _gen_checkbox,
    "submit": lambda f: "",
    "button": lambda f: "",
    "reset": lambda f: "",
}


# ---------------------------------------------------------------------------
# Submission result
# ---------------------------------------------------------------------------


@dataclass
class SubmissionResult:
    """Result of a form submission attempt.

    Attributes:
        form_id: The :class:`FormDiscovery.id` that was submitted.
        url: The URL the form was submitted to.
        status_code: HTTP status code of the response.
        is_success: Whether the submission was considered successful.
        redirect_url: URL the server redirected to, if any.
        response_snippet: First 500 characters of the response body.
        error: Exception if the submission failed at the transport
            level.
        submitted_data: The data that was submitted (field names +
            truncated values).
        elapsed_seconds: Wall-clock time for the submission.
    """

    form_id: str
    url: str
    status_code: int = 0
    is_success: bool = False
    redirect_url: str = ""
    response_snippet: str = ""
    error: Exception | None = None
    submitted_data: dict[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Form filler
# ---------------------------------------------------------------------------


class FormFiller:
    """Generate test data and submit discovered forms.

    The filler inspects each :class:`~webrecon.core.models.FormField`
    in a :class:`~webrecon.core.models.FormDiscovery`, generates
    appropriate test values, and submits the form. It analyses the
    response to determine whether the submission was successful.

    Args:
        client: A :class:`MassParserClient` for HTTP transport.
        custom_generators: Optional mapping from field type to a
            callable that generates a test value. Overrides the
            built-in generators.
    """

    def __init__(
        self,
        client: MassParserClient,
        *,
        custom_generators: dict[str, Any] | None = None,
    ) -> None:
        self._client = client
        self._generators = dict(_FIELD_GENERATORS)
        if custom_generators:
            self._generators.update(custom_generators)

    # ---- Public API ---------------------------------------------------

    def generate_test_data(
        self,
        form: FormDiscovery,
    ) -> dict[str, str]:
        """Generate test data for all fields in a form.

        Args:
            form: The :class:`FormDiscovery` to generate data for.

        Returns:
            A ``{field_name: test_value}`` dict.
        """
        data: dict[str, str] = {}
        for f in form.fields:
            # Skip submit/button/reset fields.
            if f.field_type in ("submit", "button", "reset"):
                continue
            # Skip file fields (can't submit files via form data).
            if f.field_type == "file":
                continue

            # Use default value if available and not empty.
            if f.default_value and f.field_type != "hidden":
                # For non-hidden fields, prefer generated data.
                pass

            generator = self._generators.get(f.field_type, _gen_text)
            try:
                value = generator(f)
            except Exception:
                value = "test_value"

            if value is not None:
                data[f.name] = value

        return data

    async def fill_and_submit(
        self,
        form: FormDiscovery,
        *,
        base_url: str = "",
        cookies: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> SubmissionResult:
        """Generate test data and submit a form.

        Args:
            form: The :class:`FormDiscovery` to submit.
            base_url: Base URL for resolving relative action URLs.
            cookies: Optional cookies to include in the request.
            extra_headers: Optional extra request headers.

        Returns:
            A :class:`SubmissionResult` with the outcome.
        """
        import time

        start = time.monotonic()

        data = self.generate_test_data(form)

        # Determine the submission URL.
        action_url = form.action_url
        if not action_url and base_url:
            action_url = base_url
        if action_url and not action_url.startswith(("http://", "https://")):
            action_url = urljoin(base_url, action_url)

        if not action_url:
            return SubmissionResult(
                form_id=form.id,
                url="",
                error=ValueError("No action URL for form"),
                submitted_data=data,
            )

        # Build headers.
        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)
        # Add Referer header.
        if form.url:
            headers["Referer"] = form.url

        # Add cookies.
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        # Submit.
        method = form.submission_method.upper()
        result = SubmissionResult(
            form_id=form.id,
            url=action_url,
            submitted_data=data,
        )

        try:
            if method == "GET":
                resp = await self._client.get(
                    action_url,
                    headers=headers,
                )
            else:
                resp = await self._client.post(
                    action_url,
                    data=data,
                    headers=headers,
                )
        except Exception as exc:
            result.error = exc
            result.elapsed_seconds = time.monotonic() - start
            return result

        result.status_code = resp.status_code
        result.elapsed_seconds = time.monotonic() - start

        if resp.error is not None:
            result.error = resp.error
            return result

        # Analyse response.
        result.response_snippet = resp.text[:500]
        result.is_success = self._analyse_success(resp, form)

        # Detect redirect.
        location = resp.headers.get("location", "")
        if location:
            result.redirect_url = location

        _LOGGER.info(
            "form_automation.filler.submitted",
            form_id=form.id,
            url=action_url,
            status=resp.status_code,
            success=result.is_success,
        )

        return result

    # ---- Internal -----------------------------------------------------

    @staticmethod
    def _analyse_success(
        resp: Any,
        form: FormDiscovery,
    ) -> bool:
        """Heuristic to determine if a form submission was successful.

        Considers:
        * HTTP 2xx status codes as success.
        * HTTP 3xx redirects as success (the server accepted the
          data and is redirecting).
        * HTTP 4xx/5xx as failure.
        * Response body containing common error indicators as failure.
        """
        status = resp.status_code

        # 2xx and 3xx are generally positive.
        if 200 <= status < 400:
            # Check for error indicators in the response body.
            text_lower = resp.text[:2000].lower()
            error_indicators = [
                "error",
                "invalid",
                "failed",
                "incorrect",
                "wrong",
                "not found",
                "denied",
                "forbidden",
                "unauthorized",
                "captcha",
                "spam",
            ]
            # Only flag as failure if multiple indicators are present
            # (single "error" could be in CSS/JS unrelated to the form).
            indicator_count = sum(1 for ind in error_indicators if ind in text_lower)
            return indicator_count < 2

        return False
