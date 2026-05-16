"""HTML form discovery and analysis for the form-automation pipeline.

This module parses HTML pages with BeautifulSoup4, identifies ``<form>``
elements, extracts their fields, detects CSRF tokens, and produces
:class:`~webrecon.core.models.FormDiscovery` instances ready for
database persistence.

Usage::

    async with MassParserClient() as http:
        discoverer = FormDiscoverer(http)
        forms = await discoverer.discover("https://example.com/contact")
        for form in forms:
            print(form.action_url, len(form.fields))

Validates: Requirement 4.1 (HTML parsing with BeautifulSoup4,
form identification and extraction), Requirement 4.6 (CSRF token
detection and handling).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup, Tag

from webrecon.core.models import FormDiscovery, FormField
from webrecon.log import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

    from webrecon.mass_parser.client import MassParserClient

__all__ = [
    "FormDiscoverer",
]

_LOGGER = get_logger(__name__)


# ---------------------------------------------------------------------------
# CSRF token field name patterns
# ---------------------------------------------------------------------------

_CSRF_FIELD_NAMES: frozenset[str] = frozenset({
    "csrfmiddlewaretoken",
    "csrf_token",
    "_token",
    "authenticity_token",
    "_csrf_token",
    "csrf",
    "token",
    "nonce",
    "wpnonce",
    "_wpnonce",
    "_nonce",
})

# Common hidden-field names that indicate auth requirements.
_AUTH_HIDDEN_NAMES: frozenset[str] = frozenset({
    "login",
    "password",
    "passwd",
    "pass",
    "secret",
    "apikey",
    "api_key",
})


# ---------------------------------------------------------------------------
# Discoverer
# ---------------------------------------------------------------------------


class FormDiscoverer:
    """Discover and analyse HTML forms on web pages.

    Args:
        client: A :class:`MassParserClient` for HTTP transport.
        max_forms_per_page: Maximum forms to extract from a single
            page (to limit memory on pages with many forms).
    """

    def __init__(
        self,
        client: MassParserClient,
        *,
        max_forms_per_page: int = 50,
    ) -> None:
        self._client = client
        self._max_forms = max(1, max_forms_per_page)

    # ---- Public API ---------------------------------------------------

    async def discover(
        self,
        url: str,
        *,
        website_id: str = "",
    ) -> list[FormDiscovery]:
        """Fetch a page and extract all forms.

        Args:
            url: The page URL to fetch and parse.
            website_id: The :class:`~webrecon.core.models.WebsiteAsset`
                id to associate discovered forms with.

        Returns:
            A list of :class:`FormDiscovery` instances (possibly empty).
        """
        resp = await self._client.get(url, timeout=10.0)
        if resp.error is not None or resp.status_code != 200:
            _LOGGER.debug(
                "form_automation.discovery.fetch_failed",
                url=url,
                status=resp.status_code,
            )
            return []

        return self.parse_forms(
            resp.text,
            url=url,
            website_id=website_id,
        )

    async def discover_multiple(
        self,
        urls: Sequence[str],
        *,
        website_id: str = "",
    ) -> list[FormDiscovery]:
        """Discover forms on multiple pages.

        Args:
            urls: Sequence of page URLs.
            website_id: Associated website asset id.

        Returns:
            Aggregated list of :class:`FormDiscovery` instances.
        """
        import asyncio

        results = await asyncio.gather(
            *[self.discover(u, website_id=website_id) for u in urls],
            return_exceptions=True,
        )

        all_forms: list[FormDiscovery] = []
        for r in results:
            if isinstance(r, list):
                all_forms.extend(r)
        return all_forms

    def parse_forms(
        self,
        html: str,
        *,
        url: str = "",
        website_id: str = "",
    ) -> list[FormDiscovery]:
        """Parse HTML and extract forms without fetching.

        This is the pure-parsing entry point for callers that already
        have the HTML content (e.g. from a cached response).

        Args:
            html: The HTML content to parse.
            url: The page URL (for metadata).
            website_id: Associated website asset id.

        Returns:
            A list of :class:`FormDiscovery` instances.
        """
        soup = BeautifulSoup(html, "lxml")
        form_tags = soup.find_all("form")

        if not form_tags:
            return []

        discoveries: list[FormDiscovery] = []
        now = datetime.now(timezone.utc)

        for idx, form_tag in enumerate(form_tags[: self._max_forms]):
            if not isinstance(form_tag, Tag):
                continue

            discovery = self._parse_one_form(
                form_tag,
                index=idx,
                url=url,
                website_id=website_id,
                now=now,
            )
            discoveries.append(discovery)

        _LOGGER.info(
            "form_automation.discovery.forms_found",
            url=url,
            count=len(discoveries),
        )

        return discoveries

    # ---- Internal -----------------------------------------------------

    def _parse_one_form(
        self,
        form_tag: Tag,
        *,
        index: int,
        url: str,
        website_id: str,
        now: datetime,
    ) -> FormDiscovery:
        """Parse a single ``<form>`` tag into a :class:`FormDiscovery`."""
        # Form attributes.
        action = str(form_tag.get("action", "") or "")
        method = str(form_tag.get("method", "GET") or "GET").upper()

        # Build the action URL (resolve relative URLs).
        action_url = action
        if (
            action_url
            and not action_url.startswith(("http://", "https://"))
            and url
        ):
            from urllib.parse import urljoin
            action_url = urljoin(url, action_url)

        # Extract fields.
        fields = self._extract_fields(form_tag)

        # Detect CSRF token.
        has_csrf = any(
            f.name.lower() in _CSRF_FIELD_NAMES
            for f in fields
        )

        # Detect auth requirement.
        requires_auth = any(
            f.name.lower() in _AUTH_HIDDEN_NAMES
            or f.field_type == "password"
            for f in fields
        )

        # Form HTML snippet (truncated for storage).
        form_html = str(form_tag)[:5000]

        return FormDiscovery(
            id=str(uuid.uuid4()),
            website_id=website_id,
            url=url,
            form_html=form_html,
            fields=fields,
            discovered_at=now,
            has_csrf_token=has_csrf,
            requires_auth=requires_auth,
            submission_method=method,
            action_url=action_url,
        )

    @staticmethod
    def _extract_fields(form_tag: Tag) -> list[FormField]:
        """Extract all input/textarea/select fields from a form."""
        fields: list[FormField] = []

        # Input elements.
        for input_tag in form_tag.find_all("input"):
            if not isinstance(input_tag, Tag):
                continue
            name = str(input_tag.get("name", "") or "")
            if not name:
                continue

            field_type = str(input_tag.get("type", "text") or "text").lower()
            required = "required" in input_tag.attrs
            default_value = str(input_tag.get("value", "") or "") or None
            pattern = str(input_tag.get("pattern", "") or "") or None

            metadata: dict[str, str] = {}
            if input_tag.get("id"):
                metadata["id"] = str(input_tag["id"])
            if input_tag.get("class"):
                cls = input_tag.get("class")
                if isinstance(cls, list):
                    metadata["class"] = " ".join(cls)
                elif cls:
                    metadata["class"] = str(cls)
            if input_tag.get("placeholder"):
                metadata["placeholder"] = str(input_tag["placeholder"])
            if input_tag.get("maxlength"):
                metadata["maxlength"] = str(input_tag["maxlength"])

            fields.append(FormField(
                name=name,
                field_type=field_type,
                required=required,
                default_value=default_value,
                validation_pattern=pattern,
                metadata=metadata,
            ))

        # Textarea elements.
        for ta in form_tag.find_all("textarea"):
            if not isinstance(ta, Tag):
                continue
            name = str(ta.get("name", "") or "")
            if not name:
                continue

            required = "required" in ta.attrs
            default_value = ta.string or None
            if default_value:
                default_value = str(default_value)

            metadata = {}
            if ta.get("id"):
                metadata["id"] = str(ta["id"])
            if ta.get("placeholder"):
                metadata["placeholder"] = str(ta["placeholder"])

            fields.append(FormField(
                name=name,
                field_type="textarea",
                required=required,
                default_value=default_value,
                metadata=metadata,
            ))

        # Select elements.
        for sel in form_tag.find_all("select"):
            if not isinstance(sel, Tag):
                continue
            name = str(sel.get("name", "") or "")
            if not name:
                continue

            required = "required" in sel.attrs
            # Get the default selected option value.
            default_value = None
            selected = sel.find("option", selected=True)
            if selected and isinstance(selected, Tag):
                default_value = str(selected.get("value", "") or "")

            metadata = {}
            if sel.get("id"):
                metadata["id"] = str(sel["id"])
            # Store available options.
            options = []
            for opt in sel.find_all("option"):
                if isinstance(opt, Tag):
                    val = str(opt.get("value", "") or "")
                    text = opt.string or ""
                    if val:
                        options.append(f"{val}:{text}")
            if options:
                metadata["options"] = "|".join(options[:20])

            fields.append(FormField(
                name=name,
                field_type="select",
                required=required,
                default_value=default_value,
                metadata=metadata,
            ))

        return fields
