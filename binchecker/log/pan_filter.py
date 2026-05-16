"""PAN redaction logging filter.

This module provides :class:`PanRedactionFilter`, a :class:`logging.Filter`
that scans every log record for runs of ASCII decimal digits resembling
Primary Account Numbers (PANs), validates each candidate with the Luhn
checksum, and replaces matches with their masked form before the record is
emitted by any handler.

The filter implements Property 9 ("Universality of redaction") from the
project design document: for every log record produced anywhere in the
application, the rendered output observed by handlers contains no
Luhn-valid 12-19 digit substring. It validates Requirements 8.1 (PANs must
never be logged in cleartext) and 8.4 (logging must be fail-closed: any
internal error within the redaction filter must result in the record being
replaced by a safe placeholder rather than the original message leaking
through).

The filter uses only the Python standard library (:mod:`logging`, :mod:`re`)
plus :func:`binchecker.core.luhn.luhn_check` and
:func:`binchecker.core.pan.mask_pan`. It performs no I/O and never raises:
any unexpected exception encountered while redacting is caught and the
record's message is replaced with the literal string ``"<redacted>"``.
"""

from __future__ import annotations

import logging
import re

from binchecker.core.luhn import luhn_check
from binchecker.core.pan import mask_pan

__all__ = ["PanRedactionFilter"]


# Match runs of 12 to 19 ASCII decimal digits. We deliberately use the
# explicit character class ``[0-9]`` rather than ``\d`` so that Unicode
# digits (e.g. Eastern Arabic digits, superscripts) do not match: PANs are
# always ASCII digits and ``luhn_check`` rejects non-ASCII input anyway.
_PAN_CANDIDATE_RE = re.compile(r"[0-9]{12,19}")


class PanRedactionFilter(logging.Filter):
    """Logging filter that redacts Luhn-valid PAN-like digit runs.

    Attached to a handler (or a logger), this filter rewrites every record's
    ``msg`` attribute so that any run of 12-19 ASCII decimal digits which
    passes the Luhn checksum is replaced with its
    :func:`~binchecker.core.pan.mask_pan` form. The record's ``args`` are
    folded into the rendered text and then cleared, so downstream
    formatters see the already-redacted string.

    The filter is fail-closed: if any exception is raised during redaction,
    the record's message is replaced with ``"<redacted>"`` and the record is
    still allowed through (``filter`` returns ``True``). This guarantees the
    original, possibly-sensitive payload is never emitted.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        """Redact PAN-like substrings on ``record`` in place.

        Args:
            record: The :class:`logging.LogRecord` about to be emitted.

        Returns:
            Always ``True`` so the (now redacted) record continues through
            the logging pipeline.
        """
        try:
            # Render ``msg`` together with ``args`` so we scan the same text
            # the handler would otherwise emit. ``record.args`` may be a
            # tuple, a single value, or a mapping; ``%`` formatting handles
            # all three. If formatting fails for any reason, fall back to
            # ``str(record.msg)`` so we still scan something safe.
            msg = record.msg
            args = record.args
            if args:
                try:
                    text = str(msg) % args
                except Exception:
                    text = str(msg)
            else:
                text = str(msg)

            redacted = _PAN_CANDIDATE_RE.sub(_redact_match, text)

            record.msg = redacted
            record.args = ()
            return True
        except Exception:
            # Fail closed: never let the original message leak through.
            record.msg = "<redacted>"
            record.args = ()
            return True


def _redact_match(match: re.Match[str]) -> str:
    """Return ``mask_pan(s)`` if ``s`` is Luhn-valid, else ``s`` unchanged.

    Used as the replacement callable for :func:`re.sub` in
    :meth:`PanRedactionFilter.filter`.
    """
    candidate = match.group(0)
    if luhn_check(candidate):
        return mask_pan(candidate)
    return candidate
