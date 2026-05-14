# BIN-Checker

Анализ платёжной инфраструктуры сайтов и проверка BIN-номеров карт.

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
python bin_checker.py stripe.com
python bin_checker.py ads.google.com
python bin_checker.py shopify.com

# BIN Lookup
python bin_checker.py 424631
python bin_checker.py 459654

# JSON-вывод
python bin_checker.py stripe.com --json

# Без перехода по checkout-ссылкам
python bin_checker.py example.com --no-follow

# Кастомный таймаут
python bin_checker.py example.com --timeout 30
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

## Зависимости

- Python 3.10+
- [httpx](https://www.python-httpx.org/) — HTTP-клиент
