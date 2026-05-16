# BIN-Checker

Анализ платёжной инфраструктуры сайтов и проверка BIN-номеров карт.

## Структура репозитория

```text
chek/
  binchecker/         # Пакет: BIN lookup, gateway detection, card validation
  webrecon/           # Пакет: web reconnaissance + automation toolkit
  tests/              # Тесты для обоих пакетов
    binchecker/...    # (существующие тесты бинчекера)
    webrecon/         # тесты нового пакета (unit/integration/property)
  docs/
    webrecon/         # Документация для webrecon (getting started, API, deploy)
  scripts/
    legacy/           # Оригинальные standalone-скрипты (FOFA scraper и т.д.)
  scratch/            # Личные рабочие файлы (НЕ в git: PAN-дампы, скриншоты)
  pyproject.toml      # Один wheel содержит обе утилиты
  .env.example        # Шаблон конфигурации
```

- **`binchecker/`** — этот документ описывает именно его. Подробности ниже.
- **`webrecon/`** — реконсистема: FOFA / Shodan / Serper / GitHub / mass-parser. Полная документация в [`docs/webrecon/`](docs/webrecon/README.md).
- **`scripts/legacy/`** — исходные скрипты, на основе которых был построен `webrecon`. Сохранены для справки и fallback-запуска без полной конфигурации.

## Возможности

### 1. Анализ сайта по URL

Определяет, подходит ли сайт для оплаты высокотрастовыми DEBIT-картами (Commercial / Corporate Debit):

- **Платёжные шлюзы**: Stripe, Braintree, Adyen, PayPal, Square, Shopify Payments, Checkout.com, Worldpay, Authorize.Net, Mollie, Klarna и др.
- **Антифрод-системы**: Stripe Radar, Sift Science, Signifyd, Riskified, Forter, Kount, ThreatMetrix, FingerprintJS
- **3-D Secure**: обнаружение маркеров Verified by Visa, Mastercard Identity Check, Cardinal и др.
- **MCC-индикаторы**: определение категории мерчанта по `<title>` и `<meta description>`
- **Prepaid-блок**: обнаружение сигналов блокировки предоплаченных карт
- **Гео / юрисдикция**: SSL-анализ, Tier-1 страны, высокорисковые TLD
- **База известных платформ**: Meta Ads, Google Ads, TikTok, AWS, Azure, Shopify и ещё 12+ платформ
- **Скоринг 0–100** и вердикт: ОТЛИЧНО ПОДХОДИТ / ПОДХОДИТ / УСЛОВНО ПОДХОДИТ / НЕ ПОДХОДИТ

### 2. BIN Lookup

Проверка BIN-номера (6–8 цифр) через binlist.net API:

- Платёжная сеть (Visa / Mastercard / …)
- Тип карты (DEBIT / CREDIT / PREPAID)
- Банк-эмитент и страна
- Уровень / бренд (Classic, Platinum, Business, Corporate)
- Вердикт по трасту: ВЫСОКИЙ / СРЕДНИЙ / НИЗКИЙ

## Установка

```bash
pip install httpx
```

## Использование

```bash
# Анализ сайта
python scripts/legacy/bin_checker.py stripe.com
python scripts/legacy/bin_checker.py ads.google.com
python scripts/legacy/bin_checker.py shopify.com

# BIN Lookup
python scripts/legacy/bin_checker.py 424631
python scripts/legacy/bin_checker.py 459654

# JSON-вывод
python scripts/legacy/bin_checker.py stripe.com --json

# Без перехода по checkout-ссылкам
python scripts/legacy/bin_checker.py example.com --no-follow

# Кастомный таймаут
python scripts/legacy/bin_checker.py example.com --timeout 30
```

## Пример вывода

```
────────────────────────────────────────────────────────
  BIN-Checker — Анализ: https://ads.google.com
────────────────────────────────────────────────────────
  ИЗВЕСТНАЯ ПЛАТФОРМА: Google Ads — принимает DEBIT, проверяет AVS

  HTTP-статус        : 200
  TLD                : .com
  SSL-издатель       : Google Trust Services

  ПЛАТЁЖНЫЕ ШЛЮЗЫ:
    ● Google internal

  АНТИФРОД-СИСТЕМЫ:
    ● reCAPTCHA

  3-D SECURE         : Нет

  MCC-ИНДИКАТОРЫ:
    ● 7311 – Рекламные услуги

────────────────────────────────────────────────────────
  СКОР ДОВЕРИЯ       : 80 / 100
  ВЕРДИКТ            : ОТЛИЧНО ПОДХОДИТ
────────────────────────────────────────────────────────
```

### 5. Генерация Stripe Checkout ссылок

Автоматическая генерация платёжных ссылок для сервисов:

#### ChatGPT Team
```bash
# Генерация ссылки с промокодом для GB/GBP
python scripts/legacy/bin_checker.py --generate chatgpt \
  --token <accessToken> \
  --country GB --promo codestonegb

# С автоподбором карт
python scripts/legacy/bin_checker.py --generate chatgpt \
  --token <accessToken> \
  --country GB --batch cards.txt
```

#### SuperGrok (Grok / xAI)
```bash
# Генерация ссылки SuperGrok
python scripts/legacy/bin_checker.py --generate grok \
  --token <sso_cookie> \
  --plan supergrok --interval month

# SuperGrok Lite
python scripts/legacy/bin_checker.py --generate grok \
  --token <sso_cookie> \
  --plan supergrok_lite

# JS-скрипт для консоли браузера (альтернатива)
python scripts/legacy/bin_checker.py --generate grok --script
```

**Как получить токен:**
- **ChatGPT**: F12 → Console → `fetch("/api/auth/session").then(r=>r.json()).then(d=>console.log(d.accessToken))`
- **Grok**: F12 → Application → Cookies → grok.com → скопировать значение `sso`

## Зависимости

- Python 3.10+
- [httpx](https://www.python-httpx.org/) — HTTP-клиент
