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
    currency: str = ""
    accepted_brands: list[str] = field(default_factory=list)
    blocked_brands: list[str] = field(default_factory=list)
    payment_methods: list[str] = field(default_factory=list)
    card_acceptance: list[str] = field(default_factory=list)
    prepaid_blocked: bool = False
    requires_3ds: bool = False
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
            result.prepaid_blocked = True
            if "PREPAID — ЗАБЛОКИРОВАН" not in result.card_acceptance:
                result.card_acceptance.append("PREPAID — ЗАБЛОКИРОВАН")
            break
    if result.prepaid_block_signals:
        result.prepaid_blocked = True

    # Detect 3DS enforcement
    if re.search(r'three[_-]?d[_-]?s|3ds2?|threeDS', body):
        result.requires_3ds = True
        if "3DS обязателен" not in result.card_acceptance:
            result.card_acceptance.append("3DS обязателен — требуется верификация")

    # Currency detection
    m_curr = re.search(r'currency:"([a-z]{3})"', body)
    if m_curr:
        result.currency = m_curr.group(1).upper()

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


# ─────────────────────────────────────────────
# Mapping сетей: нормализация
# ─────────────────────────────────────────────
_NETWORK_ALIASES: dict[str, str] = {
    "VISA": "VISA",
    "MASTERCARD": "MASTERCARD",
    "AMEX": "AMEX",
    "AMERICAN EXPRESS": "AMEX",
    "DISCOVER": "DISCOVER",
    "JCB": "JCB",
    "DINERS": "DINERS",
    "DINERS CLUB": "DINERS",
    "UNIONPAY": "UNIONPAY",
    "CHINA UNIONPAY": "UNIONPAY",
    "ELO": "ELO",
    "CARTES_BANCAIRES": "CARTES_BANCAIRES",
}

# Страны с высоким риском отклонения
HIGH_RISK_COUNTRIES = {
    "RU", "BY", "IR", "KP", "SY", "CU", "VE", "MM", "SD", "SO",
    "AF", "IQ", "LB", "LY", "YE", "ZW", "NG",
}


@dataclass
class CardMatch:
    """Результат сопоставления карты с платёжной страницей."""
    card_line: str
    bin_code: str
    bin_info: BINInfo
    fit_score: int = 0          # 0-100, насколько карта подходит
    verdict: str = ""
    reasons_good: list[str] = field(default_factory=list)
    reasons_bad: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "card": self.card_line.split("|")[0],
            "bin": self.bin_code,
            "fit_score": self.fit_score,
            "verdict": self.verdict,
            "reasons_good": self.reasons_good,
            "reasons_bad": self.reasons_bad,
            **self.bin_info.to_dict(),
        }


def _score_card_for_site(
    bin_info: BINInfo,
    site: CheckResult,
) -> tuple[int, list[str], list[str]]:
    """Оценивает совместимость карты с платёжной страницей.

    Returns (fit_score, reasons_good, reasons_bad).
    """
    score = 50  # базовый
    good: list[str] = []
    bad: list[str] = []

    # 1. Карточная сеть
    network = _NETWORK_ALIASES.get(bin_info.scheme, bin_info.scheme)
    if site.accepted_brands:
        accepted_norm = {
            _NETWORK_ALIASES.get(b, b) for b in site.accepted_brands
        }
        if network in accepted_norm:
            score += 15
            good.append(f"Сеть {network} принимается")
        else:
            score -= 40
            bad.append(
                f"Сеть {network} НЕ в списке принимаемых "
                f"({', '.join(sorted(accepted_norm))})")
    elif network in ("VISA", "MASTERCARD"):
        score += 10
        good.append(f"Сеть {network} — универсально принимается")

    if site.blocked_brands:
        blocked_norm = {
            _NETWORK_ALIASES.get(b, b) for b in site.blocked_brands
        }
        if network in blocked_norm:
            score -= 50
            bad.append(f"Сеть {network} ЗАБЛОКИРОВАНА мерчантом")

    # 2. Тип карты (CREDIT / DEBIT / PREPAID)
    card_type = bin_info.card_type.upper()
    is_prepaid = bin_info.prepaid == "Да"

    if is_prepaid and site.prepaid_blocked:
        score -= 50
        bad.append("PREPAID заблокирован на этом сайте")
    elif is_prepaid:
        score -= 15
        bad.append("PREPAID — повышенный риск отклонения")

    if card_type == "DEBIT" and not is_prepaid:
        if site.debit_friendly_signals:
            score += 15
            good.append("DEBIT — сайт явно поддерживает дебетовые")
        else:
            score += 5
            good.append("DEBIT — стандартный приём")

    if card_type == "CREDIT":
        score += 10
        good.append("CREDIT — максимальный приём у всех шлюзов")

    # 3. Страна карты
    cc = bin_info.country_code
    if cc in TIER1_COUNTRIES:
        score += 15
        good.append(f"Страна {cc} — Tier-1 (низкий риск)")
    elif cc in HIGH_RISK_COUNTRIES:
        score -= 30
        bad.append(f"Страна {cc} — высокий риск блокировки")
    elif cc:
        score += 0
        bad.append(f"Страна {cc} — не Tier-1, возможны ограничения")

    # 4. Совпадение гео карты и мерчанта
    if site.merchant_country and cc:
        if cc == site.merchant_country:
            score += 10
            good.append(
                f"Страна карты совпадает с мерчантом ({cc})")
        elif cc in TIER1_COUNTRIES and site.merchant_country in TIER1_COUNTRIES:
            score += 5
            good.append("Обе стороны Tier-1 — кросс-гео ОК")

    # 5. 3DS
    if site.requires_3ds:
        if cc in TIER1_COUNTRIES:
            good.append("3DS обязателен — Tier-1 карта пройдёт")
        else:
            score -= 5
            bad.append("3DS обязателен — карта из не-Tier-1 страны")

    # 6. Шлюз
    trusted_gw = {"Stripe", "Braintree", "Adyen", "Square",
                  "Checkout.com", "WorldPay", "PayPal"}
    if any(gw in trusted_gw for gw in site.gateways):
        score += 5
        good.append("Надёжный шлюз — минимальные ложные блокировки")

    # 7. Антифрод
    if site.antifraud:
        if is_prepaid or cc in HIGH_RISK_COUNTRIES:
            score -= 10
            bad.append(
                f"Антифрод ({', '.join(site.antifraud)}) "
                "может отклонить данную карту")

    # Clamp
    score = max(0, min(100, score))
    return score, good, bad


def match_cards(
    url: str,
    card_lines: list[str],
    *,
    timeout: float = 20.0,
) -> tuple[CheckResult, list[CardMatch]]:
    """Анализирует URL и сопоставляет каждую карту.

    Returns (site_result, sorted_matches) — от лучшей к худшей.
    """
    site = analyse(url, timeout=timeout)

    seen_bins: dict[str, BINInfo] = {}
    matches: list[CardMatch] = []
    lookup_count = 0

    for line in card_lines:
        b = _extract_bin_from_card(line)
        if not b:
            continue
        if b not in seen_bins:
            if lookup_count > 0:
                time.sleep(1.5)
            seen_bins[b] = lookup_bin(b, timeout=timeout)
            lookup_count += 1
        bi = seen_bins[b]
        fit, good, bad = _score_card_for_site(bi, site)

        if fit >= 75:
            verdict = "ОТЛИЧНО ПОДХОДИТ"
        elif fit >= 55:
            verdict = "ПОДХОДИТ"
        elif fit >= 35:
            verdict = "УСЛОВНО"
        else:
            verdict = "НЕ ПОДХОДИТ"

        matches.append(CardMatch(
            card_line=line,
            bin_code=b,
            bin_info=bi,
            fit_score=fit,
            verdict=verdict,
            reasons_good=good,
            reasons_bad=bad,
        ))

    matches.sort(key=lambda m: m.fit_score, reverse=True)
    return site, matches


def format_match_report(
    site: CheckResult,
    matches: list[CardMatch],
) -> str:
    """Человекочитаемый отчёт сопоставления."""
    lines: list[str] = []
    hr = "═" * 60

    lines.append(hr)
    lines.append("  АВТОПОДБОР КАРТ ДЛЯ ПЛАТЁЖНОЙ СТРАНИЦЫ")
    lines.append(hr)
    lines.append(f"  URL: {site.url}")
    if site.merchant_name:
        lines.append(f"  Мерчант: {site.merchant_name}")
    if site.merchant_country:
        mc_tier = " (Tier-1)" if site.merchant_country in TIER1_COUNTRIES else ""
        lines.append(f"  Страна мерчанта: {site.merchant_country}{mc_tier}")
    if site.currency:
        lines.append(f"  Валюта: {site.currency}")
    if site.gateways:
        lines.append(f"  Шлюз: {', '.join(site.gateways)}")

    # Site restrictions summary
    lines.append("")
    lines.append("  ОГРАНИЧЕНИЯ САЙТА:")
    if site.accepted_brands:
        lines.append(
            f"    Принимает сети: {', '.join(site.accepted_brands)}")
    if site.blocked_brands:
        lines.append(
            f"    Блокирует: {', '.join(site.blocked_brands)}")
    if site.prepaid_blocked:
        lines.append("    Prepaid: ЗАБЛОКИРОВАН")
    else:
        lines.append("    Prepaid: не заблокирован (или неизвестно)")
    if site.requires_3ds:
        lines.append("    3DS: обязателен")
    if site.antifraud:
        lines.append(f"    Антифрод: {', '.join(site.antifraud)}")

    lines.append("")
    lines.append(hr)

    if not matches:
        lines.append("  Подходящих карт не найдено.")
        lines.append(hr)
        return "\n".join(lines)

    # Group by verdict
    best = [m for m in matches if m.fit_score >= 75]
    ok = [m for m in matches if 55 <= m.fit_score < 75]
    maybe = [m for m in matches if 35 <= m.fit_score < 55]
    bad = [m for m in matches if m.fit_score < 35]

    # Show unique BINs with best cards
    seen_display: set[str] = set()

    if best:
        lines.append(f"  ★ ЛУЧШИЕ КАРТЫ ({len(best)} шт):")
        for m in best:
            if m.bin_code in seen_display:
                continue
            seen_display.add(m.bin_code)
            pan = m.card_line.split("|")[0]
            lines.append(
                f"    {pan}  [{m.fit_score}/100 {m.verdict}]")
            lines.append(
                f"      BIN {m.bin_code}: {m.bin_info.scheme} "
                f"{m.bin_info.card_type} / {m.bin_info.bank_name} "
                f"/ {m.bin_info.country_code}")
            if m.reasons_good:
                for r in m.reasons_good:
                    lines.append(f"        + {r}")
            if m.reasons_bad:
                for r in m.reasons_bad:
                    lines.append(f"        - {r}")
        lines.append("")

    if ok:
        lines.append(f"  ● ПОДХОДЯТ ({len(ok)} шт):")
        for m in ok:
            if m.bin_code in seen_display:
                continue
            seen_display.add(m.bin_code)
            pan = m.card_line.split("|")[0]
            lines.append(
                f"    {pan}  [{m.fit_score}/100 {m.verdict}]")
            lines.append(
                f"      BIN {m.bin_code}: {m.bin_info.scheme} "
                f"{m.bin_info.card_type} / {m.bin_info.bank_name} "
                f"/ {m.bin_info.country_code}")
            if m.reasons_bad:
                for r in m.reasons_bad:
                    lines.append(f"        - {r}")
        lines.append("")

    if maybe:
        lines.append(f"  ◐ УСЛОВНО ({len(maybe)} шт):")
        for m in maybe:
            if m.bin_code in seen_display:
                continue
            seen_display.add(m.bin_code)
            pan = m.card_line.split("|")[0]
            lines.append(
                f"    {pan}  [{m.fit_score}/100 {m.verdict}]")
            lines.append(
                f"      BIN {m.bin_code}: {m.bin_info.scheme} "
                f"{m.bin_info.card_type} / {m.bin_info.country_code}")
            if m.reasons_bad:
                for r in m.reasons_bad[:2]:
                    lines.append(f"        - {r}")
        lines.append("")

    if bad:
        lines.append(f"  ✕ НЕ ПОДХОДЯТ ({len(bad)} шт):")
        for m in bad:
            if m.bin_code in seen_display:
                continue
            seen_display.add(m.bin_code)
            pan = m.card_line.split("|")[0]
            lines.append(
                f"    {pan}  [{m.fit_score}/100 {m.verdict}]")
            lines.append(
                f"      BIN {m.bin_code}: {m.bin_info.scheme} "
                f"{m.bin_info.card_type} / {m.bin_info.country_code}")
            if m.reasons_bad:
                for r in m.reasons_bad[:2]:
                    lines.append(f"        - {r}")
        lines.append("")

    # Summary
    lines.append(hr)
    total = len(matches)
    lines.append(f"  ИТОГО: {total} карт проверено")
    lines.append(
        f"    ★ Лучшие: {len(best)}  ● Подходят: {len(ok)}  "
        f"◐ Условно: {len(maybe)}  ✕ Нет: {len(bad)}")
    if best:
        top = best[0]
        lines.append(
            f"\n  ➤ РЕКОМЕНДАЦИЯ: {top.card_line.split('|')[0]} "
            f"(BIN {top.bin_code}, {top.bin_info.scheme} "
            f"{top.bin_info.card_type}, "
            f"{top.bin_info.country_code}) — {top.fit_score}/100")
    elif ok:
        top = ok[0]
        lines.append(
            f"\n  ➤ РЕКОМЕНДАЦИЯ: {top.card_line.split('|')[0]} "
            f"(BIN {top.bin_code}, {top.bin_info.scheme} "
            f"{top.bin_info.card_type}, "
            f"{top.bin_info.country_code}) — {top.fit_score}/100")
    else:
        lines.append(
            "\n  ➤ НЕТ ПОДХОДЯЩИХ КАРТ. Нужна карта "
            "VISA/MC CREDIT или DEBIT (не prepaid) из Tier-1 страны.")
    lines.append(hr)

    return "\n".join(lines)


# ─────────────────────────────────────────────
# Генерация платёжных ссылок
# ─────────────────────────────────────────────

# Поддерживаемые страны и валюты
COUNTRY_CURRENCY: dict[str, dict] = {
    "US": {"name": "США", "currency": "USD"},
    "GB": {"name": "Великобритания", "currency": "GBP"},
    "CA": {"name": "Канада", "currency": "CAD"},
    "DE": {"name": "Германия", "currency": "EUR"},
    "FR": {"name": "Франция", "currency": "EUR"},
    "IT": {"name": "Италия", "currency": "EUR"},
    "ES": {"name": "Испания", "currency": "EUR"},
    "NL": {"name": "Нидерланды", "currency": "EUR"},
    "AU": {"name": "Австралия", "currency": "AUD"},
    "JP": {"name": "Япония", "currency": "JPY"},
    "SG": {"name": "Сингапур", "currency": "SGD"},
    "BR": {"name": "Бразилия", "currency": "BRL"},
    "MX": {"name": "Мексика", "currency": "MXN"},
    "CH": {"name": "Швейцария", "currency": "CHF"},
    "SE": {"name": "Швеция", "currency": "SEK"},
    "NO": {"name": "Норвегия", "currency": "NOK"},
    "DK": {"name": "Дания", "currency": "DKK"},
    "PL": {"name": "Польша", "currency": "PLN"},
    "NZ": {"name": "Новая Зеландия", "currency": "NZD"},
    "KR": {"name": "Южная Корея", "currency": "KRW"},
    "IN": {"name": "Индия", "currency": "INR"},
    "TR": {"name": "Турция", "currency": "TRY"},
    "AE": {"name": "ОАЭ", "currency": "AED"},
    "SA": {"name": "Саудовская Аравия", "currency": "SAR"},
    "IL": {"name": "Израиль", "currency": "ILS"},
    "ZA": {"name": "ЮАР", "currency": "ZAR"},
}


@dataclass
class LinkResult:
    """Результат генерации платёжной ссылки."""
    service: str
    country: str
    currency: str
    promo: str = ""
    checkout_url: str = ""
    checkout_session_id: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


def generate_chatgpt_link(
    token: str,
    *,
    country: str = "GB",
    currency: str = "GBP",
    promo: str = "",
    plan: str = "chatgptteamplan",
    seats: int = 2,
    interval: str = "month",
    workspace: str = "workspace",
    timeout: float = 20.0,
) -> LinkResult:
    """Генерирует Stripe Checkout ссылку для ChatGPT Team/Business.

    Вызывает /backend-api/payments/checkout с заданными параметрами.
    """
    result = LinkResult(
        service="ChatGPT Team",
        country=country,
        currency=currency,
        promo=promo,
    )

    payload: dict = {
        "plan_name": plan,
        "team_plan_data": {
            "workspace_name": workspace,
            "price_interval": interval,
            "seat_quantity": seats,
        },
        "billing_details": {
            "country": country,
            "currency": currency,
        },
        "checkout_ui_mode": "hosted",
        "cancel_url": "https://chatgpt.com/",
    }
    if promo:
        payload["promo_code"] = promo

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                "https://chatgpt.com/backend-api/payments/checkout",
                json=payload,
                headers=headers,
            )

            try:
                data = resp.json()
            except Exception:
                result.error = (
                    f"HTTP {resp.status_code}: "
                    f"Ответ не JSON ({resp.text[:200]})"
                )
                return result

            if not resp.is_success:
                detail = data.get("detail", json.dumps(data))
                result.error = f"HTTP {resp.status_code}: {detail}"
                return result

            url = (
                data.get("url")
                or data.get("stripe_hosted_url")
                or data.get("checkout_url")
            )
            session_id = data.get("checkout_session_id", "")

            if not url and session_id:
                url = (
                    "https://chatgpt.com/checkout/openai_llc/"
                    f"{session_id}"
                )

            if url:
                result.checkout_url = url
                result.checkout_session_id = session_id
            else:
                result.error = (
                    "URL не найден в ответе. "
                    f"Ответ: {json.dumps(data, ensure_ascii=False)}"
                )
    except httpx.HTTPError as exc:
        result.error = f"Сетевая ошибка: {exc}"

    return result


def generate_grok_link(
    token: str,
    *,
    plan: str = "supergrok",
    interval: str = "month",
    timeout: float = 20.0,
) -> LinkResult:
    """Генерирует Stripe Checkout ссылку для SuperGrok.

    Использует SSO cookie для аутентификации и вызывает
    API grok.com для создания checkout-сессии.
    """
    plan_names = {
        "supergrok": "SuperGrok",
        "supergrok_lite": "SuperGrok Lite",
        "supergrok-lite": "SuperGrok Lite",
        "lite": "SuperGrok Lite",
    }
    plan_label = plan_names.get(plan.lower(), plan)

    result = LinkResult(
        service=plan_label,
        country="",
        currency="USD",
    )

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Origin": "https://grok.com",
        "Referer": "https://grok.com/plans",
    }

    # SSO cookie or Bearer token
    is_cookie = not token.startswith("eyJ")
    if is_cookie:
        cookie_val = token.removeprefix("sso=")
        headers["Cookie"] = f"sso={cookie_val}"
    else:
        headers["Authorization"] = f"Bearer {token}"

    # Grok checkout endpoints to try
    endpoints = [
        {
            "url": "https://grok.com/rest/app-subscription/create-checkout-session",
            "payload": {
                "plan": plan.lower(),
                "interval": interval,
            },
        },
        {
            "url": "https://grok.com/rest/billing/checkout",
            "payload": {
                "plan_name": plan.lower(),
                "price_interval": interval,
            },
        },
        {
            "url": "https://grok.com/api/subscription/checkout",
            "payload": {
                "plan": plan.lower(),
                "interval": interval,
            },
        },
    ]

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            last_error = ""
            for ep in endpoints:
                try:
                    resp = client.post(
                        ep["url"],
                        json=ep["payload"],
                        headers=headers,
                    )

                    # Skip if redirect to login
                    if "accounts.x.ai" in str(resp.url):
                        last_error = (
                            "Перенаправлено на логин — "
                            "SSO cookie невалиден"
                        )
                        continue

                    if resp.status_code == 404:
                        last_error = (
                            f"{ep['url']} → 404 Not Found"
                        )
                        continue

                    try:
                        data = resp.json()
                    except Exception:
                        # HTML response (likely Cloudflare/auth)
                        if resp.status_code in (401, 403):
                            last_error = (
                                f"HTTP {resp.status_code}: "
                                "требуется авторизация"
                            )
                            continue
                        last_error = (
                            f"HTTP {resp.status_code}: "
                            f"не JSON ({resp.text[:150]})"
                        )
                        continue

                    if not resp.is_success:
                        detail = data.get(
                            "detail",
                            data.get("error", json.dumps(data)),
                        )
                        last_error = (
                            f"HTTP {resp.status_code}: {detail}"
                        )
                        continue

                    # Extract checkout URL
                    url = (
                        data.get("url")
                        or data.get("checkout_url")
                        or data.get("stripe_url")
                        or data.get("redirect_url")
                    )
                    session_id = (
                        data.get("checkout_session_id")
                        or data.get("session_id")
                        or ""
                    )

                    if url:
                        result.checkout_url = url
                        result.checkout_session_id = session_id
                        return result

                    last_error = (
                        "URL не найден в ответе. "
                        f"Ответ: {json.dumps(data, ensure_ascii=False)}"
                    )

                except httpx.HTTPError as exc:
                    last_error = f"Сетевая ошибка: {exc}"
                    continue

            # None of the endpoints worked — provide console script
            result.error = (
                f"Автоматическая генерация не удалась: {last_error}\n\n"
                "  Используйте консольный скрипт (F12 → Console на grok.com):\n"
                f"  python bin_checker.py --generate grok --script"
            )

    except httpx.HTTPError as exc:
        result.error = f"Сетевая ошибка: {exc}"

    return result


def generate_grok_console_script(
    plan: str = "supergrok",
    interval: str = "month",
) -> str:
    """Генерирует JS-скрипт для вставки в консоль браузера на grok.com."""
    return f"""
// SuperGrok Checkout Link Generator
// Вставьте этот скрипт в консоль браузера (F12) на grok.com
// Вы должны быть авторизованы на grok.com

(async function generateGrokLink() {{
  console.log("⏳ Создание checkout сессии...");

  // Попробуем несколько эндпоинтов
  const endpoints = [
    {{
      url: "/rest/app-subscription/create-checkout-session",
      body: {{ plan: "{plan}", interval: "{interval}" }}
    }},
    {{
      url: "/rest/billing/checkout",
      body: {{ plan_name: "{plan}", price_interval: "{interval}" }}
    }},
    {{
      url: "/api/subscription/checkout",
      body: {{ plan: "{plan}", interval: "{interval}" }}
    }}
  ];

  for (const ep of endpoints) {{
    try {{
      const resp = await fetch(ep.url, {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify(ep.body)
      }});

      if (resp.status === 404) continue;

      const data = await resp.json();
      const url = data?.url || data?.checkout_url || data?.stripe_url || data?.redirect_url;

      if (url) {{
        console.log("─".repeat(60));
        console.log("✅ {plan.replace('"', '')} Checkout Link:");
        console.log("🔗", url);
        if (data?.checkout_session_id || data?.session_id)
          console.log("📋 Session:", data?.checkout_session_id || data?.session_id);
        console.log("─".repeat(60));
        return;
      }}

      console.log(`Endpoint ${{ep.url}}: URL не найден`, data);
    }} catch(e) {{
      console.log(`Endpoint ${{ep.url}}: ошибка`, e.message);
    }}
  }}

  // Fallback: прямой редирект через Stripe Customer Portal
  console.log("─".repeat(60));
  console.log("⚠️ Прямой API не найден.");
  console.log("📌 Stripe Customer Portal:");
  console.log("   https://billing.stripe.com/p/login/eVa4iNeNQ3kla9W6oo");
  console.log("📌 Или перейдите на: https://grok.com/plans");
  console.log("─".repeat(60));
}})();
"""


def format_link_report(link: LinkResult) -> str:
    """Форматирует отчёт о сгенерированной ссылке."""
    hr = "═" * 60
    lines = [hr]
    lines.append("  ГЕНЕРАЦИЯ ПЛАТЁЖНОЙ ССЫЛКИ")
    lines.append(hr)

    cc_info = COUNTRY_CURRENCY.get(link.country, {})
    country_name = cc_info.get("name", link.country)

    lines.append(f"  Сервис     : {link.service}")
    lines.append(f"  Страна     : {country_name} ({link.country})")
    lines.append(f"  Валюта     : {link.currency}")
    if link.promo:
        lines.append(f"  Промокод   : {link.promo}")

    lines.append("")

    if link.error:
        lines.append(f"  ОШИБКА: {link.error}")
    else:
        lines.append("  ССЫЛКА СОЗДАНА:")
        lines.append(f"  {link.checkout_url}")
        if link.checkout_session_id:
            lines.append(f"\n  Session ID: {link.checkout_session_id}")

    lines.append(hr)
    return "\n".join(lines)


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
    parser.add_argument(
        "--match", type=str, default=None,
        help=("URL платёжной страницы для автоподбора карт. "
              "Используется вместе с --batch или stdin."),
    )
    parser.add_argument(
        "--generate", type=str, default=None,
        metavar="SERVICE",
        help=("Генерация Stripe Checkout ссылки. "
              "Поддерживается: chatgpt, grok. "
              "Требует --token."),
    )
    parser.add_argument(
        "--script", action="store_true",
        help="Вывести JS-скрипт для консоли браузера (для grok)",
    )
    parser.add_argument(
        "--countries", action="store_true",
        help="Показать список поддерживаемых стран и валют",
    )
    parser.add_argument(
        "--token", type=str, default=None,
        help=("Access-токен для API. "
              "ChatGPT: accessToken. "
              "Grok: SSO cookie из grok.com"),
    )
    parser.add_argument(
        "--country", type=str, default="GB",
        help="Страна для биллинга (ISO 2-letter, по умолчанию GB)",
    )
    parser.add_argument(
        "--currency", type=str, default=None,
        help="Валюта (например GBP, EUR, USD). Автоопределение по стране.",
    )
    parser.add_argument(
        "--promo", type=str, default="",
        help="Промокод для подписки",
    )
    parser.add_argument(
        "--seats", type=int, default=2,
        help="Количество мест (для ChatGPT Team, по умолчанию 2)",
    )
    parser.add_argument(
        "--plan", type=str, default=None,
        help=("План подписки "
              "(chatgpt: chatgptteamplan, "
              "grok: supergrok / supergrok_lite)"),
    )
    parser.add_argument(
        "--interval", type=str, default="month",
        choices=["month", "year"],
        help="Интервал оплаты (month/year, по умолчанию month)",
    )
    parser.add_argument(
        "--workspace", type=str, default="workspace",
        help="Название workspace (для ChatGPT Team)",
    )
    args = parser.parse_args()

    # ── Список стран ──
    if args.countries:
        print("\nПоддерживаемые страны и валюты:\n")
        print(f"  {'Код':<6}{'Страна':<25}{'Валюта':<8}{'Tier-1'}")
        print("  " + "─" * 50)
        for code, info in sorted(COUNTRY_CURRENCY.items()):
            tier = "★" if code in TIER1_COUNTRIES else ""
            print(
                f"  {code:<6}{info['name']:<25}"
                f"{info['currency']:<8}{tier}")
        print(f"\n  Всего: {len(COUNTRY_CURRENCY)} стран")
        print("  ★ = Tier-1 (низкий риск, приоритет)")
        sys.exit(0)

    # ── Generate-режим: генерация платёжных ссылок ──
    if args.generate:
        service = args.generate.lower()
        supported = ("chatgpt", "chatgpt-team", "grok", "supergrok")
        if service not in supported:
            print(
                f"Неизвестный сервис: {args.generate}. "
                f"Поддерживается: {', '.join(supported)}",
                file=sys.stderr,
            )
            sys.exit(1)

        is_grok = service in ("grok", "supergrok")

        # --script mode: output console JS and exit
        if is_grok and args.script:
            plan = args.plan or "supergrok"
            print(generate_grok_console_script(
                plan=plan, interval=args.interval,
            ))
            sys.exit(0)

        if not args.token:
            if is_grok:
                print(
                    "Для --generate grok требуется --token "
                    "(SSO cookie из grok.com).\n\n"
                    "Как получить SSO cookie:\n"
                    "  1. Откройте https://grok.com и войдите\n"
                    "  2. F12 → Application → Cookies → grok.com\n"
                    "  3. Скопируйте значение cookie 'sso'\n\n"
                    "Альтернатива — JS-скрипт для консоли:\n"
                    "  python bin_checker.py --generate grok --script",
                    file=sys.stderr,
                )
            else:
                print(
                    "Для --generate требуется --token "
                    "(ChatGPT accessToken).\n\n"
                    "Как получить токен:\n"
                    "  1. Откройте https://chatgpt.com\n"
                    "  2. Войдите в аккаунт\n"
                    "  3. F12 → Console → выполните:\n"
                    '     fetch("/api/auth/session")'
                    ".then(r=>r.json())"
                    ".then(d=>console.log(d.accessToken))\n"
                    "  4. Скопируйте токен",
                    file=sys.stderr,
                )
            sys.exit(1)

        if is_grok:
            plan = args.plan or "supergrok"
            print(f"\nГенерация ссылки: {service} "
                  f"/ план: {plan} / {args.interval}...")

            link = generate_grok_link(
                args.token,
                plan=plan,
                interval=args.interval,
                timeout=args.timeout,
            )
        else:
            plan = args.plan or "chatgptteamplan"
            country = args.country.upper()
            currency = args.currency
            if not currency:
                cc_info = COUNTRY_CURRENCY.get(country, {})
                currency = cc_info.get("currency", "USD")
            currency = currency.upper()

            print(f"\nГенерация ссылки: {service} "
                  f"/ {country} / {currency}"
                  f"{' / promo: ' + args.promo if args.promo else ''}...")

            link = generate_chatgpt_link(
                args.token,
                country=country,
                currency=currency,
                promo=args.promo,
                plan=plan,
                seats=args.seats,
                interval=args.interval,
                workspace=args.workspace,
                timeout=args.timeout,
            )

        if args.json_output:
            output: dict = {"link": link.to_dict()}
        else:
            print(format_link_report(link))

        if link.error:
            if args.json_output:
                print(json.dumps(output, ensure_ascii=False, indent=2))
            sys.exit(1)

        # Auto-analyse the generated URL
        print("\nАнализ сгенерированной ссылки...")
        site = analyse(link.checkout_url, timeout=args.timeout)
        if args.json_output:
            output["analysis"] = site.to_dict()
        else:
            print(format_report(site))

        # Auto-match cards if provided
        card_lines_gen: list[str] = []
        if args.batch:
            try:
                with open(args.batch) as f:
                    card_lines_gen = [
                        ln.strip() for ln in f if ln.strip()
                    ]
            except FileNotFoundError:
                print(f"Файл не найден: {args.batch}",
                      file=sys.stderr)
        elif args.target:
            card_lines_gen = [args.target]

        if card_lines_gen:
            print("\nПодбор карт...")
            _, matches = match_cards(
                link.checkout_url, card_lines_gen,
                timeout=args.timeout,
            )
            if args.json_output:
                output["matches"] = [m.to_dict() for m in matches]
            else:
                print(format_match_report(site, matches))

        if args.json_output:
            print(json.dumps(output, ensure_ascii=False, indent=2))

        sys.exit(0)

    # ── Match-режим: автоподбор карт ──
    if args.match:
        card_lines: list[str] = []
        if args.batch:
            try:
                with open(args.batch) as f:
                    card_lines = [ln.strip() for ln in f if ln.strip()]
            except FileNotFoundError:
                print(f"Файл не найден: {args.batch}", file=sys.stderr)
                sys.exit(1)
        elif args.target:
            card_lines = [args.target]
        else:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    card_lines.append(line)

        if not card_lines:
            print("Укажите карты через --batch, аргумент или stdin",
                  file=sys.stderr)
            sys.exit(1)

        site, matches = match_cards(
            args.match, card_lines, timeout=args.timeout,
        )
        if args.json_output:
            print(json.dumps({
                "site": site.to_dict(),
                "matches": [m.to_dict() for m in matches],
            }, ensure_ascii=False, indent=2))
        else:
            print(format_match_report(site, matches))
        sys.exit(0)

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
