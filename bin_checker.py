"""
BIN-Checker: анализ платёжной инфраструктуры сайта.

Принимает URL сайта и определяет, подходит ли он для оплаты
высокотрастовыми DEBIT-картами (Commercial / Corporate Debit).

Анализирует:
 • платёжный шлюз (Stripe, Braintree, Adyen, PayPal …)
 • поддержку 3-D Secure
 • антифрод-системы и фингерпринтинг
 • ограничения по типу карт (prepaid-блок, debit-friendly)
 • MCC-индикаторы
 • гео / юрисдикцию (SSL, headers, TLD)
 • общий «скор доверия» и вердикт

Также поддерживает BIN Lookup (6-8 цифр) через binlist.net API.

Использование:
  python bin_checker.py <url>          # анализ сайта
  python bin_checker.py <bin>          # проверка BIN (6-8 цифр)
  python bin_checker.py <url> --json   # JSON-вывод
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

# ─────────────────────────────────────────────
# Сигнатуры платёжных шлюзов
# ─────────────────────────────────────────────

GATEWAY_SIGNATURES: dict[str, list[str]] = {
    "Stripe": [
        "js.stripe.com",
        "stripe.com/v3",
        "Stripe(",
        "stripe-js",
        "stripe.js",
        "pk_live_",
        "pk_test_",
        "stripe-payment",
        "StripeCheckout",
    ],
    "Braintree": [
        "js.braintreegateway.com",
        "braintree-web",
        "braintree.setup",
        "client-token",
        "braintree-dropin",
        "BraintreeGateway",
    ],
    "Adyen": [
        "checkoutshopper-live",
        "adyen.com",
        "adyen-checkout",
        "AdyenCheckout",
        "adyen.encrypt",
    ],
    "PayPal": [
        "paypal.com/sdk",
        "paypalobjects.com",
        "paypal-checkout",
        "paypal-buttons",
        "paypal.Buttons",
    ],
    "Square": [
        "squareup.com",
        "square-payment",
        "SqPaymentForm",
        "web-payments-sdk",
    ],
    "Shopify Payments": [
        "cdn.shopify.com",
        "shopify-payment",
        "Shopify.Checkout",
    ],
    "Recurly": [
        "js.recurly.com",
        "recurly.configure",
    ],
    "Checkout.com": [
        "checkout.com",
        "frames.js",
        "Frames.init",
        "cko-",
    ],
    "Worldpay": [
        "worldpay.com",
        "worldpay.js",
    ],
    "Authorize.Net": [
        "js.authorize.net",
        "Accept.dispatchData",
        "authorizenet",
    ],
    "2Checkout (Verifone)": [
        "2checkout.com",
        "2co.js",
    ],
    "Mollie": [
        "js.mollie.com",
        "mollie-components",
    ],
    "Klarna": [
        "klarna.com",
        "klarna-payments",
    ],
    "WooCommerce Payments": [
        "woocommerce-payments",
        "wc-stripe",
        "wc-payment",
    ],
}

# ─────────────────────────────────────────────
# Сигнатуры антифрод-систем
# ─────────────────────────────────────────────

ANTIFRAUD_SIGNATURES: dict[str, list[str]] = {
    "Stripe Radar": [
        "m.stripe.com",
        "r.stripe.com",
        "stripe-radar",
    ],
    "Sift Science": [
        "cdn.sift.com",
        "sift.js",
        "_sift",
    ],
    "Signifyd": [
        "cdn-scripts.signifyd.com",
        "signifyd",
    ],
    "Riskified": [
        "beacon.riskified.com",
        "riskified",
    ],
    "Forter": [
        "forter.com",
        "ftr__",
    ],
    "Kount": [
        "kount.com",
        "kount.js",
    ],
    "ThreatMetrix (LexisNexis)": [
        "online-metrix.net",
        "threatmetrix",
    ],
    "Device Fingerprinting (generic)": [
        "fingerprintjs",
        "fpjs",
        "devicefingerprint",
        "browser-fingerprint",
    ],
    "hCaptcha": [
        "hcaptcha.com",
        "h-captcha",
    ],
    "reCAPTCHA": [
        "google.com/recaptcha",
        "grecaptcha",
    ],
}

# ─────────────────────────────────────────────
# 3-D Secure индикаторы
# ─────────────────────────────────────────────

THREEDS_SIGNATURES: list[str] = [
    "3dsecure",
    "3d-secure",
    "three-d-secure",
    "threeDS",
    "3ds2",
    "cardinal",
    "cardinalcommerce",
    "songbird",
    "verified by visa",
    "mastercard identity check",
    "securecode",
    "protectbuy",
]

# ─────────────────────────────────────────────
# MCC-маркеры (по <title> + <meta description>)
# ─────────────────────────────────────────────

# MCC определяется по <title>, <meta description> и og:description,
# а не по всему body (слова "advertising" / "travel" в футере — шум).
MCC_RULES: list[tuple[str, str]] = [
    (r"advertis(?:ing|ement)|рекламн|media\s*buy", "7311 – Рекламные услуги"),
    (r"\bsaas\b|software.as.a.service", "5734 – SaaS / ПО"),
    (r"cloud\s+(?:hosting|platform|computing)", "5734 – Облачные сервисы / ПО"),
    (r"\bhosting\b|хостинг|vps|dedicated\s+server", "4816 – Хостинг / телеком"),
    (r"subscri(?:ption|be)|подписк", "5968 – Подписка / рекуррентный биллинг"),
    (r"\btravel\b|\btour(?:ism)?\b|авиабилет|путешестви", "4722 – Путешествия / туризм"),
    (r"\bairline|авиакомпани|flight\s+book", "3000-3350 – Авиаперевозки"),
    (r"marketplace|маркетплейс", "5399 – Маркетплейс (General Merchandise)"),
    (r"\bcasino\b|online\s+(?:slots|poker|betting)|казино|ставки",
     "7995 – Азартные игры (высокий риск!)"),
    (r"crypto(?:currency)?\s+(?:exchange|trading|платформ)",
     "6051 – Крипто / квази-фин. услуги (высокий риск!)"),
    (r"\badult\b.*content|порно|xxx", "5967 – Контент 18+ (высокий риск!)"),
    (r"online\s+pharmacy|интернет.аптека", "5912 – Фармацевтика"),
]

# ─────────────────────────────────────────────
# Tier-1 GEO (низкий фрод-риск)
# ─────────────────────────────────────────────

TIER1_COUNTRIES = {
    "US", "GB", "CA", "DE", "FR", "NL", "AU", "JP", "SG", "IE",
    "SE", "NO", "DK", "FI", "CH", "AT", "BE", "LU", "NZ",
}

HIGH_RISK_TLDS = {
    ".ru", ".by", ".ir", ".kp", ".sy", ".cu",
}

# ─────────────────────────────────────────────
# Известные платформы: домен → (шлюз, debit-ok?, заметка)
# ─────────────────────────────────────────────

KNOWN_PLATFORMS: dict[str, tuple[str, bool, str]] = {
    "facebook.com": ("Stripe / internal", True,
                     "Meta Ads — принимает DEBIT, блокирует Prepaid"),
    "business.facebook.com": ("Stripe / internal", True,
                              "Meta Business — принимает DEBIT"),
    "ads.google.com": ("Google internal", True,
                       "Google Ads — принимает DEBIT, проверяет AVS"),
    "tiktok.com": ("Stripe / Adyen", True,
                   "TikTok Ads — принимает DEBIT"),
    "ads.tiktok.com": ("Stripe / Adyen", True,
                       "TikTok Ads — принимает DEBIT"),
    "stripe.com": ("Stripe", True,
                   "Stripe — собственный шлюз, полная поддержка DEBIT"),
    "shopify.com": ("Shopify Payments (Stripe)", True,
                    "Shopify — принимает DEBIT"),
    "amazon.com": ("Amazon Pay", True, "Amazon — принимает DEBIT"),
    "aws.amazon.com": ("Amazon Pay", True, "AWS — принимает DEBIT"),
    "cloud.google.com": ("Google internal", True,
                         "GCP — принимает DEBIT"),
    "azure.microsoft.com": ("Stripe / internal", True,
                            "Azure — принимает DEBIT"),
    "digitalocean.com": ("Stripe", True,
                         "DigitalOcean — Stripe, DEBIT ok"),
    "heroku.com": ("Stripe", True, "Heroku — Stripe, DEBIT ok"),
    "vercel.com": ("Stripe", True, "Vercel — Stripe, DEBIT ok"),
    "netlify.com": ("Stripe", True, "Netlify — Stripe, DEBIT ok"),
    "namecheap.com": ("Stripe / PayPal", True,
                      "Namecheap — принимает DEBIT"),
    "godaddy.com": ("Stripe / Braintree", True,
                    "GoDaddy — принимает DEBIT"),
    "cloudflare.com": ("Stripe", True,
                       "Cloudflare — Stripe, DEBIT ok"),
}


# ─────────────────────────────────────────────
# Результат анализа
# ─────────────────────────────────────────────

@dataclass
class CheckResult:
    url: str
    reachable: bool = False
    http_status: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    antifraud: list[str] = field(default_factory=list)
    threeds: bool = False
    threeds_markers: list[str] = field(default_factory=list)
    ssl_issuer: str = ""
    ssl_country: str = ""
    tld: str = ""
    mcc_hints: list[str] = field(default_factory=list)
    high_risk_signals: list[str] = field(default_factory=list)
    debit_friendly_signals: list[str] = field(default_factory=list)
    prepaid_block_signals: list[str] = field(default_factory=list)
    known_platform: str = ""
    # Stripe Checkout deep analysis
    merchant_name: str = ""
    merchant_country: str = ""
    accepted_brands: list[str] = field(default_factory=list)
    blocked_brands: list[str] = field(default_factory=list)
    payment_methods: list[str] = field(default_factory=list)
    card_acceptance: list[str] = field(default_factory=list)
    score: int = 0
    verdict: str = ""
    verdict_detail: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()
                if v or isinstance(v, (bool, int))}


# ─────────────────────────────────────────────
# Утилиты
# ─────────────────────────────────────────────

def _normalise_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _get_ssl_info(hostname: str) -> tuple[str, str]:
    """Возвращает (issuer_org, country) из SSL-сертификата."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        subject_parts = dict(x[0] for x in cert.get("subject", []))
        org = issuer_parts.get("organizationName", "")
        country = subject_parts.get("countryName", "")
        return org, country
    except Exception:
        return "", ""


def _extract_head_text(body: str) -> str:
    """Извлекает текст из <title> и <meta description/og:description>."""
    title_match = re.search(
        r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL,
    )
    meta_desc = re.search(
        r'<meta[^>]+(?:name=["\']description|property=["\']og:description)'
        r'["\'][^>]+content=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    return (
        (title_match.group(1) if title_match else "")
        + " "
        + (meta_desc.group(1) if meta_desc else "")
    )


def _analyse_stripe_checkout(body: str, result: CheckResult) -> None:
    """Глубокий анализ Stripe Checkout: merchant, карточные ограничения."""
    # Имя мерчанта
    m = re.search(r'business_name:"([^"]+)"', body)
    if m:
        result.merchant_name = m.group(1)

    # Страна мерчанта
    m = re.search(
        r'merchant_info:\{business_name:"[^"]+",country:"([^"]+)"', body,
    )
    if m:
        result.merchant_country = m.group(1)

    # Определение принимаемых платёжных методов
    all_brands = {"visa", "mastercard", "amex", "discover", "jcb",
                  "diners", "unionpay", "elo", "cartes_bancaires"}
    found_brands: set[str] = set()
    for brand in all_brands:
        if re.search(rf'["\']?{brand}["\']?', body, re.IGNORECASE):
            found_brands.add(brand.upper())
    if found_brands:
        result.accepted_brands = sorted(found_brands)

    # Blocked card brands
    m = re.search(r'brands_blocked', body)
    if m:
        ctx = body[m.end():m.end() + 200]
        for brand in all_brands:
            if brand in ctx.lower():
                result.blocked_brands.append(brand.upper())

    # Определение payment methods (Klarna, Link, etc.)
    pm_names = {
        "card": "Банковские карты",
        "klarna": "Klarna (BNPL)",
        "affirm": "Affirm (BNPL)",
        "afterpay_clearpay": "Afterpay / Clearpay",
        "link": "Stripe Link",
        "cashapp": "Cash App",
        "apple_pay": "Apple Pay",
        "google_pay": "Google Pay",
    }
    for pm_key, pm_label in pm_names.items():
        if re.search(
            rf'["\']?{re.escape(pm_key)}["\']?\s*[:,]', body,
        ):
            if pm_label not in result.payment_methods:
                result.payment_methods.append(pm_label)

    # Card type acceptance analysis
    body_lower = body.lower()

    # CREDIT/DEBIT/PREPAID handling
    has_credit = bool(re.search(r'case\s*"CREDIT"', body))
    has_debit = bool(re.search(r'case\s*"DEBIT"', body))
    has_prepaid = bool(re.search(r'case\s*"PREPAID"', body))

    if has_credit:
        result.card_acceptance.append("CREDIT — принимает")
    if has_debit:
        result.card_acceptance.append("DEBIT — принимает")
    if has_prepaid:
        result.card_acceptance.append("PREPAID — обрабатывает (может блокировать)")

    # Prepaid restrictions
    prepaid_block_patterns = [
        r"prepaid\s+cards?\s+(?:are\s+)?not\s+(?:accepted|supported)",
        r"no\s+prepaid",
        r"block.*prepaid",
        r"reject.*prepaid",
        r"prepaid.*block",
        r"prepaid.*reject",
        r"prepaid.*decline",
    ]
    for pat in prepaid_block_patterns:
        if re.search(pat, body_lower):
            if "PREPAID — ЗАБЛОКИРОВАН" not in result.card_acceptance:
                result.card_acceptance.append("PREPAID — ЗАБЛОКИРОВАН")
            break

    # Detect 3DS enforcement
    if re.search(r'three[_-]?d[_-]?s|3ds2?|threeDS', body):
        if "3DS обязателен" not in result.card_acceptance:
            result.card_acceptance.append("3DS обязателен — требуется верификация")

    # Link funding sources
    m = re.search(r'link_funding_sources:\["([^"]+)"', body)
    if m:
        result.card_acceptance.append(
            f"Link funding: {m.group(1)}")

    # Testmode detection
    if re.search(r'is_testmode_preview:!0|pk_test_', body):
        result.card_acceptance.append(
            "Тестовый режим (pk_test_) — не production")
    elif re.search(r'pk_live_', body):
        result.card_acceptance.append("Production-режим (pk_live_)")


def _analyse_payment_page(body: str, result: CheckResult) -> None:
    """Общий анализ платёжной страницы для не-Stripe платформ."""
    body_lower = body.lower()

    # Detect card brand logos / acceptance info
    acceptance_patterns = [
        (r"we\s+accept.*?(?:visa|mastercard|amex)",
         "Принимает: Visa, Mastercard"),
        (r"(?:visa|mastercard|amex).*?accepted",
         "Принимает: основные карточные сети"),
        (r"debit\s+cards?\s+accepted|accepts?\s+debit",
         "DEBIT — принимает"),
        (r"credit\s+cards?\s+accepted|accepts?\s+credit",
         "CREDIT — принимает"),
        (r"prepaid\s+cards?\s+(?:are\s+)?not\s+(?:accepted|supported)",
         "PREPAID — НЕ ПРИНИМАЕТ"),
        (r"only\s+credit\s+cards?",
         "Только CREDIT — DEBIT может не пройти"),
        (r"commercial\s+cards?\s+accepted",
         "Commercial карты — принимает"),
        (r"corporate\s+cards?\s+accepted",
         "Corporate карты — принимает"),
    ]
    for pat, label in acceptance_patterns:
        if re.search(pat, body_lower):
            if label not in result.card_acceptance:
                result.card_acceptance.append(label)


# ─────────────────────────────────────────────
# Основной анализатор
# ─────────────────────────────────────────────

def analyse(url: str, *, timeout: float = 20.0,
            follow_links: bool = True) -> CheckResult:
    """Анализирует URL и возвращает CheckResult."""

    url = _normalise_url(url)
    result = CheckResult(url=url)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    result.tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    # ── Known platform? ──
    for domain_key, (kp_gw, _kp_debit, kp_note) in KNOWN_PLATFORMS.items():
        if hostname == domain_key or hostname.endswith("." + domain_key):
            result.known_platform = kp_note
            if kp_gw and kp_gw not in result.gateways:
                result.gateways.append(kp_gw)
            break

    # ── SSL ──
    ssl_org, ssl_country = _get_ssl_info(hostname)
    result.ssl_issuer = ssl_org
    result.ssl_country = ssl_country

    # ── Fetch page ──
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        with httpx.Client(
            follow_redirects=True, timeout=timeout, headers=headers,
        ) as client:
            resp = client.get(url)
            result.http_status = resp.status_code
            result.reachable = True
            result.redirect_chain = [str(r.url) for r in resp.history]
            body = resp.text
    except Exception as exc:
        result.error = f"Не удалось загрузить сайт: {exc}"
        result.verdict = "ОШИБКА"
        result.verdict_detail = result.error
        return result

    body_lower = body.lower()

    # ── Payment gateways ──
    for gw, sigs in GATEWAY_SIGNATURES.items():
        if gw not in result.gateways and any(
            sig.lower() in body_lower for sig in sigs
        ):
            result.gateways.append(gw)

    # ── Anti-fraud ──
    for af, sigs in ANTIFRAUD_SIGNATURES.items():
        if any(sig.lower() in body_lower for sig in sigs):
            result.antifraud.append(af)

    # ── 3-D Secure ──
    found_3ds: list[str] = []
    for sig in THREEDS_SIGNATURES:
        if sig.lower() in body_lower:
            found_3ds.append(sig)
    if found_3ds:
        result.threeds = True
        result.threeds_markers = found_3ds

    # ── MCC hints (только title + meta + og) ──
    head_text_lower = _extract_head_text(body).lower()
    for mcc_pat, mcc_label in MCC_RULES:
        if re.search(mcc_pat, head_text_lower):
            result.mcc_hints.append(mcc_label)

    # ── Prepaid-block signals ──
    prepaid_block_patterns = [
        r"prepaid\s+cards?\s+(?:are\s+)?not\s+(?:accepted|supported|allowed)",
        r"no\s+prepaid",
        r"we\s+do\s+not\s+accept\s+prepaid",
        r"предоплаченные\s+карты\s+не\s+принимаются",
        r"prepaid.*not.*accepted",
        r"block.*prepaid",
    ]
    for pat in prepaid_block_patterns:
        if re.search(pat, body_lower):
            result.prepaid_block_signals.append(pat)

    # ── Debit-friendly signals ──
    debit_patterns = [
        r"debit\s+card",
        r"дебетов\w+\s+карт",
        r"accepts?\s+(?:debit|all\s+major)",
        r"visa.*(?:debit|mastercard)",
        r"bank\s+card",
    ]
    for pat in debit_patterns:
        if re.search(pat, body_lower):
            result.debit_friendly_signals.append(pat)

    # ── High-risk signals (только по title/meta, не по всему body) ──
    high_risk_patterns = [
        (r"\bcasino\b|online\s+(?:slots|poker|betting)|казино|букмекер",
         "Gambling-контент"),
        (r"crypto(?:currency)?\s+(?:exchange|trading)",
         "Crypto-трейдинг"),
        (r"\badult\b.*content|порно|xxx",
         "Adult-контент"),
        (r"online\s+pharmacy|интернет.аптека",
         "Pharma-контент"),
    ]
    for pat, label in high_risk_patterns:
        if re.search(pat, head_text_lower):
            result.high_risk_signals.append(label)

    if result.tld in HIGH_RISK_TLDS:
        result.high_risk_signals.append(f"Высокорисковый TLD: {result.tld}")

    # ── Optionally follow checkout / pricing pages ──
    if follow_links:
        checkout_urls: list[str] = []
        for link_match in re.finditer(
            r'href=["\']([^"\']*(?:checkout|payment|pricing|billing|pay|subscribe)'
            r'[^"\']*)["\']',
            body,
            re.IGNORECASE,
        ):
            href = link_match.group(1)
            if href.startswith("http"):
                checkout_urls.append(href)
            elif href.startswith("/"):
                checkout_urls.append(
                    f"{parsed.scheme}://{parsed.netloc}{href}")
            if len(checkout_urls) >= 3:
                break

        for cpage in checkout_urls:
            try:
                with httpx.Client(
                    follow_redirects=True, timeout=timeout, headers=headers,
                ) as client:
                    sub_resp = client.get(cpage)
                    sub_body = sub_resp.text.lower()

                for gw, sigs in GATEWAY_SIGNATURES.items():
                    if gw not in result.gateways and any(
                        sig.lower() in sub_body for sig in sigs
                    ):
                        result.gateways.append(gw)
                for af, sigs in ANTIFRAUD_SIGNATURES.items():
                    if af not in result.antifraud and any(
                        sig.lower() in sub_body for sig in sigs
                    ):
                        result.antifraud.append(af)
                for sig in THREEDS_SIGNATURES:
                    if (sig.lower() in sub_body
                            and sig not in result.threeds_markers):
                        result.threeds = True
                        result.threeds_markers.append(sig)
            except Exception:
                pass

    # ── Deep payment page analysis ──
    is_stripe_checkout = "checkout.stripe.com" in (hostname or "")
    if is_stripe_checkout or "Stripe" in result.gateways:
        _analyse_stripe_checkout(body, result)
    _analyse_payment_page(body, result)

    # ── Scoring ──
    result.score = _compute_score(result)
    result.verdict, result.verdict_detail = _verdict(result)

    return result


# ─────────────────────────────────────────────
# Скоринг
# ─────────────────────────────────────────────

_TRUSTED_GATEWAYS = {
    "Stripe", "Braintree", "Adyen", "Checkout.com", "Square",
}
_MODERATE_GATEWAYS = {
    "PayPal", "Shopify Payments", "Recurly", "Mollie",
    "WooCommerce Payments",
}


def _compute_score(r: CheckResult) -> int:
    """Вычисляет скор 0..100 — чем выше, тем лучше для DEBIT."""
    s = 50  # базовый

    # Известная платформа — сразу высокий бонус
    if r.known_platform:
        s += 20

    # Шлюз
    if any(g in _TRUSTED_GATEWAYS for g in r.gateways):
        s += 15
    elif any(g in _MODERATE_GATEWAYS for g in r.gateways):
        s += 8
    elif r.gateways:
        s += 5
    else:
        s -= 10

    # Антифрод — знак серьёзного бизнеса
    if r.antifraud:
        s += 5

    # 3DS
    if r.threeds:
        s += 5

    # Prepaid-блок — хорошо для DEBIT
    if r.prepaid_block_signals:
        s += 10

    # Debit-friendly
    if r.debit_friendly_signals:
        s += 5

    # High-risk
    s -= len(r.high_risk_signals) * 10

    # SSL / Geo
    if r.ssl_country in TIER1_COUNTRIES:
        s += 5
    if r.tld in HIGH_RISK_TLDS:
        s -= 15

    return max(0, min(100, s))


def _verdict(r: CheckResult) -> tuple[str, str]:
    """Возвращает (verdict_label, detail)."""
    if not r.reachable:
        return "ОШИБКА", "Сайт недоступен."

    if r.score >= 75:
        v = "ОТЛИЧНО ПОДХОДИТ"
        detail = (
            "Сайт использует надёжный платёжный шлюз, "
            "совместимый с высокотрастовыми DEBIT-картами. "
            "Рекомендуется для привязки Commercial / Corporate Debit."
        )
    elif r.score >= 55:
        v = "ПОДХОДИТ"
        detail = (
            "Сайт имеет платёжную инфраструктуру, которая, как правило, "
            "принимает DEBIT-карты. "
            "Рекомендуется предварительная тестовая транзакция."
        )
    elif r.score >= 35:
        v = "УСЛОВНО ПОДХОДИТ"
        detail = (
            "Есть факторы риска. DEBIT-карта может быть принята, но "
            "возможны дополнительные проверки или отклонения."
        )
    else:
        v = "НЕ ПОДХОДИТ"
        detail = (
            "Высокий риск отклонения. Сайт либо не имеет стандартного "
            "платёжного шлюза, либо относится к высокорисковой категории."
        )

    if r.high_risk_signals:
        detail += (
            " Обнаружены высокорисковые маркеры: "
            + ", ".join(r.high_risk_signals) + "."
        )

    return v, detail


# ─────────────────────────────────────────────
# Форматированный вывод
# ─────────────────────────────────────────────

def format_report(r: CheckResult) -> str:
    """Человекочитаемый отчёт на русском языке."""
    lines: list[str] = []
    hr = "─" * 56

    lines.append(hr)
    lines.append(f"  BIN-Checker — Анализ: {r.url}")
    lines.append(hr)

    if r.error:
        lines.append(f"  ОШИБКА: {r.error}")
        lines.append(hr)
        return "\n".join(lines)

    if r.known_platform:
        lines.append(f"  ИЗВЕСТНАЯ ПЛАТФОРМА: {r.known_platform}")
        lines.append("")

    lines.append(f"  HTTP-статус        : {r.http_status}")
    if r.redirect_chain:
        lines.append(
            f"  Редиректы          : {' → '.join(r.redirect_chain)}")
    lines.append(f"  TLD                : {r.tld}")
    if r.ssl_issuer:
        lines.append(f"  SSL-издатель       : {r.ssl_issuer}")
    if r.ssl_country:
        tier = " (Tier-1)" if r.ssl_country in TIER1_COUNTRIES else ""
        lines.append(f"  SSL-страна субъекта: {r.ssl_country}{tier}")

    lines.append("")
    lines.append("  ПЛАТЁЖНЫЕ ШЛЮЗЫ:")
    if r.gateways:
        for gw in r.gateways:
            marker = "★" if gw in _TRUSTED_GATEWAYS else "●"
            lines.append(f"    {marker} {gw}")
    else:
        lines.append("    (не обнаружены)")

    lines.append("")
    lines.append("  АНТИФРОД-СИСТЕМЫ:")
    if r.antifraud:
        for af in r.antifraud:
            lines.append(f"    ● {af}")
    else:
        lines.append("    (не обнаружены)")

    lines.append("")
    lines.append(f"  3-D SECURE         : {'Да' if r.threeds else 'Нет'}")
    if r.threeds_markers:
        lines.append(f"    маркеры: {', '.join(r.threeds_markers)}")

    if r.mcc_hints:
        lines.append("")
        lines.append("  MCC-ИНДИКАТОРЫ:")
        for mcc in r.mcc_hints:
            lines.append(f"    ● {mcc}")

    if r.prepaid_block_signals:
        lines.append("")
        lines.append(
            "  PREPAID-БЛОК       : Да (сайт явно блокирует prepaid-карты)")

    if r.debit_friendly_signals:
        lines.append("")
        lines.append(
            "  DEBIT-FRIENDLY     : Да (упоминает приём дебетовых карт)")

    if r.high_risk_signals:
        lines.append("")
        lines.append("  ВЫСОКОРИСКОВЫЕ МАРКЕРЫ:")
        for sig in r.high_risk_signals:
            lines.append(f"    ⚠ {sig}")

    # ── Deep payment analysis ──
    if r.merchant_name or r.merchant_country:
        lines.append("")
        lines.append("  ДАННЫЕ МЕРЧАНТА:")
        if r.merchant_name:
            lines.append(f"    Название         : {r.merchant_name}")
        if r.merchant_country:
            mc_tier = (" (Tier-1)"
                       if r.merchant_country in TIER1_COUNTRIES else "")
            lines.append(
                f"    Страна           : {r.merchant_country}{mc_tier}")

    if r.accepted_brands:
        lines.append("")
        lines.append(
            f"  ПРИНИМАЕМЫЕ СЕТИ   : {', '.join(r.accepted_brands)}")
    if r.blocked_brands:
        lines.append(
            f"  ЗАБЛОКИРОВАННЫЕ    : {', '.join(r.blocked_brands)}")

    if r.payment_methods:
        lines.append("")
        lines.append("  СПОСОБЫ ОПЛАТЫ:")
        for pm in r.payment_methods:
            lines.append(f"    ● {pm}")

    if r.card_acceptance:
        lines.append("")
        lines.append("  ПРИЁМ КАРТ (детальный анализ):")
        for ca in r.card_acceptance:
            lines.append(f"    ● {ca}")

    lines.append("")
    lines.append(hr)
    lines.append(f"  СКОР ДОВЕРИЯ       : {r.score} / 100")
    lines.append(f"  ВЕРДИКТ            : {r.verdict}")
    lines.append(f"  {r.verdict_detail}")
    lines.append(hr)

    return "\n".join(lines)


# ─────────────────────────────────────────────
# BIN Lookup (multi-API с автоматическим fallback)
# ─────────────────────────────────────────────

@dataclass
class BINInfo:
    bin_code: str
    scheme: str = ""
    card_type: str = ""
    brand: str = ""
    bank_name: str = ""
    bank_url: str = ""
    country: str = ""
    country_code: str = ""
    prepaid: str = ""
    source: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


def _lookup_binlist(digits: str, client: httpx.Client) -> BINInfo | None:
    """API 1: binlist.net"""
    try:
        resp = client.get(
            f"https://lookup.binlist.net/{digits}",
            headers={"Accept-Version": "3"},
        )
        if resp.status_code in (429, 403):
            return None  # rate-limited → fallback
        if resp.status_code == 404:
            return None
        data = resp.json()
    except Exception:
        return None

    info = BINInfo(bin_code=digits, source="binlist.net")
    info.scheme = (data.get("scheme") or "").upper()
    info.card_type = (data.get("type") or "").upper()
    info.brand = (data.get("brand") or "").upper()
    bank = data.get("bank") or {}
    info.bank_name = bank.get("name") or ""
    info.bank_url = bank.get("url") or ""
    country_info = data.get("country") or {}
    info.country = country_info.get("name") or ""
    info.country_code = (country_info.get("alpha2") or "").upper()
    prepaid_val = data.get("prepaid")
    info.prepaid = ("Да" if prepaid_val
                    else ("Нет" if prepaid_val is False else "Неизвестно"))
    return info


def _lookup_handyapi(digits: str, client: httpx.Client) -> BINInfo | None:
    """API 2: data.handyapi.com"""
    try:
        resp = client.get(f"https://data.handyapi.com/bin/{digits}")
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("Status") != "SUCCESS":
            return None
    except Exception:
        return None

    info = BINInfo(bin_code=digits, source="handyapi.com")
    info.scheme = (data.get("Scheme") or "").upper()
    info.card_type = (data.get("Type") or "").upper()
    card_tier = (data.get("CardTier") or "").upper()
    info.brand = card_tier
    info.bank_name = data.get("Issuer") or ""
    country_info = data.get("Country") or {}
    info.country = country_info.get("Name") or ""
    info.country_code = (country_info.get("A2") or "").upper()
    if "PREPAID" in card_tier:
        info.prepaid = "Да"
        info.card_type = "DEBIT"
    else:
        info.prepaid = "Неизвестно"
    return info


def _lookup_bincodes(digits: str, client: httpx.Client) -> BINInfo | None:
    """API 3: api.bincodes.com (free tier)"""
    try:
        resp = client.get(
            f"https://api.bincodes.com/bin/?format=json&bin={digits}",
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("bin"):
            return None
    except Exception:
        return None

    info = BINInfo(bin_code=digits, source="bincodes.com")
    info.scheme = (data.get("card") or "").upper()
    info.card_type = (data.get("type") or "").upper()
    info.brand = (data.get("level") or "").upper()
    info.bank_name = data.get("bank") or ""
    info.country = data.get("countryname") or ""
    info.country_code = (data.get("country") or "").upper()
    info.prepaid = "Неизвестно"
    return info


# Порядок API — от самого информативного к fallback'ам
_BIN_APIS = [_lookup_binlist, _lookup_handyapi, _lookup_bincodes]


def lookup_bin(bin_code: str, *, timeout: float = 10.0) -> BINInfo:
    """Проверяет BIN через несколько API с автоматическим fallback."""
    digits = re.sub(r"\D", "", bin_code)[:8]
    if len(digits) < 6:
        return BINInfo(
            bin_code=digits,
            error="BIN должен содержать минимум 6 цифр",
        )

    errors: list[str] = []
    with httpx.Client(timeout=timeout) as client:
        for api_fn in _BIN_APIS:
            result = api_fn(digits, client)
            if result is not None:
                return result
            errors.append(api_fn.__doc__ or api_fn.__name__)

    return BINInfo(
        bin_code=digits,
        error=f"BIN не найден. Опрошены: {', '.join(errors)}",
    )


def format_bin_report(b: BINInfo) -> str:
    lines: list[str] = []
    hr = "─" * 56
    lines.append(hr)
    lines.append(f"  BIN Lookup: {b.bin_code}")
    lines.append(hr)

    if b.error:
        lines.append(f"  ОШИБКА: {b.error}")
        lines.append(hr)
        return "\n".join(lines)

    if b.source:
        lines.append(f"  Источник           : {b.source}")
    lines.append(f"  Платёжная сеть     : {b.scheme}")
    lines.append(f"  Тип карты          : {b.card_type}")
    if b.brand:
        lines.append(f"  Уровень / бренд    : {b.brand}")
    lines.append(f"  Банк-эмитент       : {b.bank_name}")
    if b.bank_url:
        lines.append(f"  Сайт банка         : {b.bank_url}")
    lines.append(f"  Страна             : {b.country} ({b.country_code})")
    if b.country_code in TIER1_COUNTRIES:
        lines[-1] += " — Tier-1"
    lines.append(f"  Prepaid            : {b.prepaid}")

    lines.append("")
    if b.card_type == "DEBIT" and b.prepaid != "Да":
        trust = "ВЫСОКИЙ ТРАСТ"
        note = "Карта определена как DEBIT и не является Prepaid."
        if b.country_code in TIER1_COUNTRIES:
            note += " Юрисдикция Tier-1 — максимальное доверие шлюзов."
    elif b.card_type == "CREDIT":
        trust = "ВЫСОКИЙ ТРАСТ"
        note = "Кредитная карта — высокий уровень доверия у шлюзов."
    elif b.prepaid == "Да":
        trust = "НИЗКИЙ ТРАСТ"
        note = ("Prepaid-карта — высокий риск блокировки "
                "рекламными сетями.")
    else:
        trust = "СРЕДНИЙ ТРАСТ"
        note = ("Тип карты не определён однозначно. "
                "Рекомендуется дополнительная проверка.")

    lines.append(f"  ВЕРДИКТ            : {trust}")
    lines.append(f"  {note}")
    lines.append(hr)
    return "\n".join(lines)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def _is_bin(s: str) -> bool:
    """Проверяет, является ли строка BIN-номером (6-8 чистых цифр)."""
    digits = re.sub(r"\D", "", s)
    return digits == s and 6 <= len(digits) <= 8


def _extract_bin_from_card(s: str) -> str:
    """Извлекает BIN (первые 6 цифр) из полного номера карты или строки
    формата PAN|MM|YYYY|CVV."""
    parts = s.split("|")
    pan = re.sub(r"\D", "", parts[0])
    return pan[:6] if len(pan) >= 6 else ""


def _run_batch(card_lines: list[str], args: argparse.Namespace) -> None:
    """Batch-проверка списка карт с дедупликацией по BIN."""
    seen_bins: dict[str, BINInfo] = {}
    results: list[dict] = []
    lookup_count = 0

    for line in card_lines:
        b = _extract_bin_from_card(line)
        if not b:
            continue
        if b not in seen_bins:
            if lookup_count > 0:
                time.sleep(1.5)  # rate-limit cooldown
            seen_bins[b] = lookup_bin(b, timeout=args.timeout)
            lookup_count += 1
        info = seen_bins[b]
        results.append({
            "card": line.split("|")[0],
            "bin": b,
            **info.to_dict(),
        })

    if args.json_output:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print(f"\nПроверено карт: {len(results)}")
        print(f"Уникальных BIN: {len(seen_bins)}\n")
        for b, info in seen_bins.items():
            print(format_bin_report(info))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "BIN-Checker: анализ платёжной инфраструктуры сайта "
            "и проверка BIN-номеров"
        ),
    )
    parser.add_argument(
        "target", nargs="?", default=None,
        help="URL сайта или BIN-номер (6-8 цифр) для проверки",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Вывести результат в формате JSON",
    )
    parser.add_argument(
        "--timeout", type=float, default=20.0,
        help="Таймаут HTTP-запроса (секунды, по умолчанию 20)",
    )
    parser.add_argument(
        "--no-follow", action="store_true",
        help="Не переходить по внутренним ссылкам checkout/payment",
    )
    parser.add_argument(
        "--batch", type=str, default=None,
        help="Файл со списком карт (PAN|MM|YYYY|CVV) — batch-проверка BIN",
    )
    args = parser.parse_args()

    # ── Batch-режим: файл с картами ──
    if args.batch:
        try:
            with open(args.batch) as f:
                card_lines = [
                    ln.strip() for ln in f if ln.strip()
                ]
        except FileNotFoundError:
            print(f"Файл не найден: {args.batch}", file=sys.stderr)
            sys.exit(1)

        _run_batch(card_lines, args)
        sys.exit(0)

    # ── Stdin batch: читаем из stdin если нет target ──
    if args.target is None:
        card_lines = []
        for line in sys.stdin:
            line = line.strip()
            if line:
                card_lines.append(line)

        if not card_lines:
            print("Укажите URL, BIN или передайте карты через stdin",
                  file=sys.stderr)
            sys.exit(1)

        _run_batch(card_lines, args)
        sys.exit(0)

    target = args.target.strip()

    # Если передали полный номер карты (16 цифр) или PAN|MM|YYYY|CVV
    if "|" in target or (re.sub(r"\D", "", target) == target
                         and len(target) > 8):
        b = _extract_bin_from_card(target)
        if b:
            info = lookup_bin(b, timeout=args.timeout)
            if args.json_output:
                print(json.dumps(info.to_dict(),
                                 ensure_ascii=False, indent=2))
            else:
                print(format_bin_report(info))
            sys.exit(0 if not info.error else 1)

    # Если передали чистые цифры (6-8) — это BIN lookup
    if _is_bin(target):
        info = lookup_bin(target, timeout=args.timeout)
        if args.json_output:
            print(json.dumps(info.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(format_bin_report(info))
        sys.exit(0 if not info.error else 1)

    # Иначе — анализ URL
    result = analyse(
        target, timeout=args.timeout,
        follow_links=not args.no_follow,
    )
    if args.json_output:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_report(result))
    sys.exit(0 if result.reachable else 1)


if __name__ == "__main__":
    main()
