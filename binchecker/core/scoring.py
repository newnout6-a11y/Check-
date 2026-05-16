"""Site quality / risk scoring for card-acceptance pages.

This module implements the pure scoring primitives consumed by the
site-check pipeline. A scraped page is summarised into a
:class:`SiteFeatures` snapshot — a small bag of booleans and integers
describing what the detector saw — and :func:`compute_site_score`
collapses that snapshot into a single ``[0, 100]`` confidence score.
The companion helper :func:`is_low_confidence` answers the simple
question: "should this score trigger the low-confidence warning path?"

The formula is intentionally transparent so it can be audited and
tuned without a model retrain:

* Start at a neutral baseline of ``50``.
* Reward up to three detected payment gateways (``+10`` each, capped
  at ``+30``).
* Reward an anti-fraud signal (``+15``).
* Reward 3-D Secure presence (``+10``).
* Reward a recognised SSL issuer (``+5``).
* Penalise risky TLDs by ``tld_risk // 4`` so a medium-risk TLD
  (``50``) costs ``12`` points and a high-risk TLD (``100``) costs
  ``25``.
* Clamp the result to ``[0, 100]``.

The module is part of the pure ``core`` layer: stdlib only, no I/O,
fully deterministic.

Validates Requirements 1.5, 1.7.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["SiteFeatures", "compute_site_score", "is_low_confidence"]


# ---------------------------------------------------------------------------
# Tunable constants
# ---------------------------------------------------------------------------

_BASELINE: int = 50
_GATEWAY_BONUS_PER: int = 10
_GATEWAY_BONUS_CAP: int = 30
_ANTIFRAUD_BONUS: int = 15
_THREEDS_BONUS: int = 10
_SSL_ISSUER_BONUS: int = 5
_TLD_RISK_DIVISOR: int = 4
_SCORE_MIN: int = 0
_SCORE_MAX: int = 100
_DEFAULT_LOW_CONFIDENCE_THRESHOLD: int = 70


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SiteFeatures:
    """Snapshot of detector-derived signals about a single site.

    All fields default to a neutral / "nothing detected" value so a
    bare ``SiteFeatures()`` collapses to the baseline score.

    Attributes:
        gateway_count: Number of distinct payment gateways detected on
            the page. Only the first three contribute to the score.
        has_antifraud: Whether an anti-fraud signal (e.g. a known
            anti-fraud SDK or CAPTCHA provider) was observed.
        threeds_present: Whether the checkout flow advertises 3-D
            Secure (3DS / 3DS2) authentication.
        tld_risk: Risk score for the site's top-level domain. ``0``
            means low risk, ``50`` medium, ``100`` high. Values
            outside ``[0, 100]`` are accepted and contribute
            proportionally — the final score is clamped.
        ssl_issuer_known: Whether the SSL certificate was issued by a
            recognised certificate authority.
    """

    gateway_count: int = 0
    has_antifraud: bool = False
    threeds_present: bool = False
    tld_risk: int = 0
    ssl_issuer_known: bool = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_site_score(features: SiteFeatures) -> int:
    """Collapse ``features`` into a confidence score in ``[0, 100]``.

    The formula is documented at module level. The result is always an
    ``int`` clamped to ``[0, 100]`` so downstream consumers can treat
    the value as a fixed-range confidence percentage.
    """
    score = _BASELINE

    # Gateway bonus, capped so a page advertising many gateways does
    # not dominate every other signal.
    gateway_bonus = max(0, features.gateway_count) * _GATEWAY_BONUS_PER
    if gateway_bonus > _GATEWAY_BONUS_CAP:
        gateway_bonus = _GATEWAY_BONUS_CAP
    score += gateway_bonus

    if features.has_antifraud:
        score += _ANTIFRAUD_BONUS
    if features.threeds_present:
        score += _THREEDS_BONUS
    if features.ssl_issuer_known:
        score += _SSL_ISSUER_BONUS

    # TLD risk penalty: integer-divide so the penalty grows in steady
    # increments and never overshoots the 0-25 band for sane inputs.
    score -= features.tld_risk // _TLD_RISK_DIVISOR

    if score < _SCORE_MIN:
        return _SCORE_MIN
    if score > _SCORE_MAX:
        return _SCORE_MAX
    return score


def is_low_confidence(
    score: int, threshold: int = _DEFAULT_LOW_CONFIDENCE_THRESHOLD
) -> bool:
    """Return True iff ``score`` is strictly below ``threshold``.

    The default threshold of ``70`` matches the warning cut-off used
    by the live-check UI: a score of exactly ``70`` is *not* flagged
    as low confidence.
    """
    return score < threshold
