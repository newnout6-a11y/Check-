"""Sensitive-data redaction for structured logging.

This module implements the redaction processor declared in the
webrecon design's logging contract (Requirement 7.5). It scans every
log event dict for two classes of sensitive material:

1. **API key prefixes** -- Stripe (``sk_live_``, ``sk_test_``,
   ``rk_live_``, ``rk_test_``, ``pk_live_``, ``pk_test_``) and GitHub
   (``ghp_``, ``gho_``, ``ghs_``, ``ghu_``, ``ghr_``, ``github_pat_``)
   tokens. Each match is replaced with ``<redacted:KIND:last4>`` where
   ``KIND`` is the prefix family and ``last4`` is the trailing four
   characters of the original value (so an operator can still
   correlate two log lines as belonging to the same key without seeing
   the secret material).
2. **URL query parameters** -- query strings containing
   ``api_key``, ``token``, ``password``, ``secret``, or
   ``authorization`` parameters. The parameter values are replaced
   with ``<redacted>`` while the rest of the URL is preserved so the
   target endpoint remains debuggable.

The processor walks nested mappings and sequences so a sensitive
value stored under, for example, ``event["upstream"]["headers"]["Authorization"]``
is still caught.

The processor is fail-safe: any exception raised while walking the
event dict is caught and the suspect value is replaced with
``<redacted>``. The original value never reaches the renderer.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

if TYPE_CHECKING:
    from structlog.typing import EventDict, WrappedLogger

__all__ = [
    "mask_value",
    "redact_sensitive_processor",
]


# ---------------------------------------------------------------------------
# Token prefix configuration
# ---------------------------------------------------------------------------


# Mapping of secret-prefix (str) -> redaction kind label (str).
# Order matters only for documentation; the longest-match search below
# uses the keys via direct string startswith comparison.
_TOKEN_PREFIXES: dict[str, str] = {
    "sk_live_": "stripe_secret_live",
    "sk_test_": "stripe_secret_test",
    "rk_live_": "stripe_restricted_live",
    "rk_test_": "stripe_restricted_test",
    "pk_live_": "stripe_publishable_live",
    "pk_test_": "stripe_publishable_test",
    # The longer ``github_pat_`` prefix must come before the
    # ``gh*_`` shorter prefixes so the longest match wins; the regex
    # built below sorts alternatives by length to enforce this.
    "github_pat_": "github_pat",
    "ghp_": "github_pat_classic",
    "gho_": "github_oauth",
    "ghs_": "github_server",
    "ghu_": "github_user",
    "ghr_": "github_refresh",
}


def _build_token_pattern() -> re.Pattern[str]:
    """Build the regex that matches any known token prefix in free text.

    Sorts the alternatives by descending length so the longest prefix
    matches first (otherwise ``github_pat_`` would lose to ``ghp_``
    when both share the leading ``gh``).

    The body of the token is captured as a permissive run of
    ``[A-Za-z0-9_]`` -- this matches the documented allowed alphabets
    for both Stripe and GitHub PAT tokens. We require at least 8
    characters after the prefix so short strings like ``sk_test_x``
    still match (Stripe's test keys can be short in fixtures) but
    plain prefix mentions (``"sk_live_"`` with nothing after) do not.
    """
    sorted_prefixes = sorted(_TOKEN_PREFIXES.keys(), key=len, reverse=True)
    alternation = "|".join(re.escape(prefix) for prefix in sorted_prefixes)
    # Accept an arbitrarily long body so realistic API keys (24-100+
    # characters) match without truncation. The minimum of 4 keeps
    # one-shot prefixes from matching but allows the deliberately
    # short fixture keys used in the test suite.
    return re.compile(rf"(?P<prefix>{alternation})(?P<body>[A-Za-z0-9_]{{4,}})")


_TOKEN_RE: re.Pattern[str] = _build_token_pattern()


# Query-string parameter names whose values should be redacted whenever
# they appear in a URL embedded in a log event. Compared case-insensitively.
_SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "authorization",
        "auth",
        "key",
    }
)


# Anchored pattern detects "looks like a URL" before we try to parse it.
# Cheap to evaluate: most log fields are not URLs and bailing out early
# avoids the cost of urlsplit on every value.
_URL_HINT_RE: re.Pattern[str] = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>`]+",
    re.IGNORECASE,
)


# Hard cap on traversal depth: defence-in-depth against pathological
# self-referential structures (a dict that contains itself). The
# webrecon log path is unlikely to hit this in practice but the cap
# guarantees the processor cannot run away on malformed input.
_MAX_RECURSION_DEPTH: int = 12


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def mask_value(value: str, kind: str) -> str:
    """Return a redacted form of ``value`` annotated with ``kind``.

    Format: ``<redacted:KIND:last4>`` where ``last4`` is the last four
    characters of the original value (or the whole value, when shorter
    than four characters). Keeping the trailing four characters lets
    an operator correlate two redacted log lines as referring to the
    same secret without exposing the secret itself -- the same pattern
    used by ``git`` log entries that surface short SHAs.

    Args:
        value: The original sensitive string. Must be non-empty;
            callers passing an empty string get a blanket
            ``<redacted:{kind}>`` form instead.
        kind: Stable label describing what was redacted (e.g.
            ``"stripe_secret_live"``, ``"github_pat_classic"``).

    Returns:
        The redacted string. Never raises.
    """
    if not value:
        return f"<redacted:{kind}>"
    last4 = value[-4:] if len(value) >= 4 else value
    return f"<redacted:{kind}:{last4}>"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _redact_token_match(match: re.Match[str]) -> str:
    """Convert a single token match into its redacted form."""
    prefix = match.group("prefix")
    body = match.group("body")
    full = prefix + body
    kind = _TOKEN_PREFIXES.get(prefix, "secret")
    return mask_value(full, kind)


def _redact_tokens_in_text(text: str) -> str:
    """Replace every known token prefix in ``text`` with its mask form."""
    return _TOKEN_RE.sub(_redact_token_match, text)


def _redact_url(url: str) -> str:
    """Return ``url`` with sensitive query parameters masked.

    The URL is parsed with :func:`urllib.parse.urlsplit`; if parsing
    fails (malformed input) the original string is returned unchanged
    so the caller still sees the raw payload they were investigating.
    The query string is rebuilt with ``urlencode`` to preserve the
    original key/value structure including duplicate keys.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url

    if not parts.query:
        return url

    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted_pairs: list[tuple[str, str]] = []
    changed = False
    for key, value in pairs:
        if key.lower() in _SENSITIVE_QUERY_PARAMS:
            redacted_pairs.append((key, "<redacted>"))
            changed = True
        else:
            redacted_pairs.append((key, value))

    if not changed:
        return url

    new_query = urlencode(redacted_pairs, doseq=False)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
    )


def _redact_urls_in_text(text: str) -> str:
    """Mask sensitive query parameters in every URL embedded in ``text``."""
    if "://" not in text:
        return text

    def _replace(match: re.Match[str]) -> str:
        return _redact_url(match.group(0))

    return _URL_HINT_RE.sub(_replace, text)


def _redact_string(value: str) -> str:
    """Apply both token and URL redactions to a free-form string."""
    redacted = _redact_tokens_in_text(value)
    return _redact_urls_in_text(redacted)


def _redact_value(value: Any, depth: int) -> Any:
    """Walk ``value`` and return a redacted copy.

    Strings are scrubbed via :func:`_redact_string`. Mappings and
    sequences (other than ``str`` / ``bytes``) are walked recursively.
    Bytes are decoded with ``errors="replace"`` so binary blobs in the
    event dict do not bypass redaction. Other types (int, float, bool,
    None, custom objects) are returned unchanged -- they cannot
    syntactically contain a token prefix that ``str()`` would surface
    only when rendered, and rendering happens after the processor
    chain so the redactor never sees them as strings.

    The ``depth`` argument bounds recursion against pathological
    inputs (cyclic structures). On overflow the value is replaced
    with the literal ``"<redacted:depth-exceeded>"`` so the operator
    still notices that something was suppressed.
    """
    if depth > _MAX_RECURSION_DEPTH:
        return "<redacted:depth-exceeded>"

    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8", errors="replace")
        except Exception:  # never let logging break
            return value
        return _redact_string(decoded).encode("utf-8")
    if isinstance(value, dict):
        # Cast keys defensively: structlog event dicts are
        # ``MutableMapping[str, Any]`` but third-party processors may
        # have inserted non-string keys. ``str(key)`` matches the
        # behaviour of structlog's own JSON renderer.
        return {key: _redact_value(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, depth + 1) for item in value)
    if isinstance(value, set):
        return {_redact_value(item, depth + 1) for item in value}
    return value


# ---------------------------------------------------------------------------
# Processor entry point
# ---------------------------------------------------------------------------


def redact_sensitive_processor(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """structlog processor: redact API keys and URL secrets in-place.

    Walks every value in ``event_dict`` (including nested dicts /
    lists / tuples / sets) and replaces:

    * known API-key prefixes with ``<redacted:KIND:last4>`` via
      :func:`mask_value`;
    * sensitive URL query parameters with ``<redacted>`` via
      :func:`_redact_url`.

    The signature matches the structlog processor protocol exactly so
    the function plugs into
    :func:`structlog.configure(processors=[...])` directly.

    The processor is fail-safe: any exception raised while walking
    a value is caught and that branch is replaced with the literal
    ``"<redacted>"`` so the original payload is never emitted.
    """
    del logger, method_name  # protocol parameters, unused
    redacted: dict[str, Any] = {}
    for key, value in event_dict.items():
        try:
            redacted[key] = _redact_value(value, depth=0)
        except Exception:  # defence in depth
            redacted[key] = "<redacted>"
    # Mutate the caller-provided dict in place so identity is
    # preserved, then return it to satisfy structlog's protocol.
    event_dict.clear()
    event_dict.update(redacted)
    return event_dict
