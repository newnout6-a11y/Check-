"""
Site Scraper — сбор WooCommerce-сайтов через Serper.dev API.
Находит сайты с Store API, извлекает pk_live_ ключи и nonce.
Сохраняет в gateway_pool.json.

Использование:
  python site_scraper.py                  # сбор + валидация
  python site_scraper.py --validate-only  # только валидация пула
  python site_scraper.py --max 50         # лимит сайтов
  python site_scraper.py --serper-key KEY # API ключ Serper.dev
"""

from __future__ import annotations
import argparse, asyncio, json, os, re, sys, time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import httpx

POOL_FILE = Path(__file__).parent / "gateway_pool.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

# Serper.dev API ключ (можно передать через --serper-key или .env)
DEFAULT_SERPER_KEY = "8061e80440f132abe401622d73c98db8e90690c8"

# Поисковые запросы для поиска WooCommerce-магазинов со Stripe
SEARCH_QUERIES = [
    'inurl:"wp-json/wc/store" site:*.com',
    '"woocommerce" "add to cart" "stripe" site:*.com',
    '"woocommerce-checkout" "pk_live" site:*.com',
    'inurl:"/product/" "woocommerce" "stripe" site:*.com',
    '"woocommerce-store" "checkout" site:*.com',
    'inurl:"/shop/" "woocommerce" "buy now" site:*.com',
    '"powered by woocommerce" "stripe" site:*.com',
    '"wc/store/v1" site:*.com',
    'inurl:"/wc-api/" site:*.com',
    '"woocommerce" "payment" "stripe" "cart" site:*.com',
    'inurl:"/product-category/" "woocommerce" site:*.com',
    '"woocommerce" "add-to-cart" site:*.com -shopify',
    '"my account" "woocommerce" site:*.com',
    'inurl:"/cart/" "woocommerce" site:*.com',
    '"woocommerce" "checkout" "billing" site:*.com',
    # Поиск по разным доменным зонам
    'inurl:"wp-json/wc/store" site:*.co.uk',
    'inurl:"wp-json/wc/store" site:*.co',
    'inurl:"wp-json/wc/store" site:*.io',
    '"woocommerce" "stripe" "buy" site:*.co.uk',
    '"woocommerce" "stripe" "shop" site:*.com.au',
    '"woocommerce" "stripe" "order" site:*.ca',
    # Поиск по нишам
    '"woocommerce" "stripe" "subscription" site:*.com',
    '"woocommerce" "stripe" "donate" site:*.com',
    '"woocommerce" "stripe" "membership" site:*.com',
    '"woocommerce" "stripe" "digital download" site:*.com',
    '"woocommerce" "stripe" "booking" site:*.com',
    # Поиск по страницам оплаты
    '"checkout" "billing_first_name" "stripe" site:*.com',
    '"woocommerce-checkout" "card_number" site:*.com',
    '"stripe-pk" "woocommerce" site:*.com',
    'inurl:"/checkout/" "woocommerce" site:*.com',
    '"wc_payment_method" "stripe" site:*.com',
    # Конкретные паттерны Stripe + WC
    '"woocommerce_stripe" "pk_live" site:*.com',
    '"stripe_gateway" "woocommerce" site:*.com',
    '"wc_stripe" "payment" site:*.com',
]

# Реальные WooCommerce-магазины (проверенные)
SEED_SITES = [
    "https://mythemeshop.com",
    "https://www.allbirds.com",
    "https://www.florachic.com",
    "https://sodashi.com.au",
    "https://www.bluecrate.com",
    "https://www.nutribullet.com",
    "https://woocommerce.com",
    "https://www.creativefabrica.com",
    "https://www.henryjsocks.com",
    "https://www.magnatiles.com",
    "https://elecbrakes.com",
    "https://www.jococups.com",
    "https://www.houseofmalt.co.uk",
    "https://www.daelmans.com",
    "https://sawmilldesigns.com",
    "https://minipop.co",
    "https://wildsouls.com",
    "https://nighthawks.co",
    "https://www.rootscience.com",
    "https://www.thecoolhunter.net",
    "https://offermanwoodshop.com",
]


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
    tokenization: str = ""  # "ok", "blocked", ""
    product_id: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def load_pool() -> list[Gateway]:
    if not POOL_FILE.exists():
        return []
    try:
        data = json.loads(POOL_FILE.read_text(encoding="utf-8"))
        return [Gateway(**item) for item in data]
    except Exception:
        return []


def save_pool(gateways: list[Gateway]) -> None:
    POOL_FILE.write_text(
        json.dumps([g.to_dict() for g in gateways], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _normalise(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _extract_pk_from_html(html: str) -> str:
    for pat in [
        r"""['"]pk_live_[0-9a-zA-Z]{24,}['"]""",
        r'pk_live_[0-9a-zA-Z]{24,}',
        r'publishableKey["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})',
        r'publishable_key["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})',
        r'stripe_pk["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})',
        r'stripeKey["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})',
        r'key["\']?\s*[:=]\s*["\'](pk_live_[0-9a-zA-Z]{24,})',
        r'Stripe\(["\']?pk_live_[0-9a-zA-Z]{24,}["\']?\)',
        r'Stripe\(\s*\{[^}]*key\s*:\s*["\'](pk_live_[0-9a-zA-Z]{24,})',
    ]:
        m = re.search(pat, html)
        if m:
            key = m.group(0).strip("'\"")
            if key.startswith("pk_live_"):
                return key
            # Try to extract from group
            try:
                for g in m.groups():
                    if g and g.startswith("pk_live_"):
                        return g
            except Exception:
                pass
    return ""


def _country_from_html(html: str) -> str:
    for pat in [
        r'country["\']?\s*[:=]\s*["\']([A-Z]{2})',
        r'currency["\']?\s*[:=]\s*["\']([a-z]{3})',
    ]:
        m = re.search(pat, html)
        if m:
            val = m.group(1).upper()
            cur_map = {"USD": "US", "EUR": "DE", "GBP": "GB", "CAD": "CA", "AUD": "AU"}
            return cur_map.get(val, val if len(val) == 2 else "")
    return ""


async def serper_search(client: httpx.AsyncClient, query: str, api_key: str) -> list[str]:
    """Поиск через Serper.dev API (Google результаты)."""
    urls: list[str] = []
    try:
        resp = await client.post(
            "https://google.serper.dev/search",
            json={"q": query, "num": 20, "gl": "us"},
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
            },
        )
        if resp.status_code != 200:
            print(f"  [!] Serper API error: HTTP {resp.status_code}")
            return urls
        data = resp.json()
        # Organic results
        for r in data.get("organic", []):
            link = r.get("link", "")
            if link:
                parsed = urlparse(link)
                urls.append(f"{parsed.scheme}://{parsed.netloc}")
        # Knowledge graph / sitelinks
        for r in data.get("knowledgeGraph", {}).get("siteLinks", []):
            link = r.get("link", "")
            if link:
                parsed = urlparse(link)
                urls.append(f"{parsed.scheme}://{parsed.netloc}")
    except Exception as e:
        print(f"  [!] Serper error: {e}")
    return list(set(urls))


async def validate_site(client: httpx.AsyncClient, url: str) -> Gateway | None:
    """Проверяет сайт: Store API + pk_live_ ключ."""
    try:
        # Шаг 1: Проверяем Store API
        cart_url = f"{url}/wp-json/wc/store/v1/cart"
        resp = await client.get(cart_url)
        if resp.status_code != 200:
            return None

        nonce = resp.headers.get("X-WC-Store-API-Nonce", "") or resp.headers.get("Nonce", "")

        # Шаг 2: Ищем pk_live_ на главной
        html_resp = await client.get(url)
        html = html_resp.text
        pk = _extract_pk_from_html(html)

        # Шаг 3: Если не нашли — проверяем подстраницы
        if not pk:
            for sub in ["/shop", "/product", "/checkout", "/cart", "/pricing", "/subscribe", "/store", "/buy"]:
                try:
                    sr = await client.get(f"{url}{sub}")
                    pk = _extract_pk_from_html(sr.text)
                    if pk:
                        break
                except Exception:
                    continue

        if not pk:
            return None

        country = _country_from_html(html)

        # Шаг 4: Тестируем серверную токенизацию
        tok_status = ""
        if pk:
            try:
                tok_resp = await client.post(
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
                        "Accept": "application/json",
                        "Stripe-Version": "2023-10-16",
                    },
                )
                tok_data = tok_resp.json()
                if tok_data.get("object") == "payment_method":
                    tok_status = "ok"
                else:
                    err_msg = tok_data.get("error", {}).get("message", "")
                    if "unsupported" in err_msg.lower():
                        tok_status = "blocked"
                    elif "declined" in err_msg.lower() or "live mode" in err_msg.lower():
                        # Тестовая карта 4242 отклонена в live mode = токенизация РАБОТАЕТ
                        tok_status = "ok"
                    else:
                        tok_status = "other"
            except Exception:
                tok_status = "error"

        now = datetime.now(timezone.utc).isoformat()
        return Gateway(url=url, pk_key=pk, nonce=nonce, nonce_ts=now, country=country, status="active", tokenization=tok_status)
    except Exception:
        return None


async def run(max_sites: int = 100, validate_only: bool = False, serper_key: str = "") -> None:
    pool = load_pool()
    existing_urls = {g.url for g in pool}
    new_urls: list[str] = []
    api_key = serper_key or DEFAULT_SERPER_KEY

    if not validate_only:
        # Добавляем seed-сайты
        print(f"[*] Seed-список: {len(SEED_SITES)} сайтов")
        for s in SEED_SITES:
            u = _normalise(s)
            if u not in existing_urls:
                new_urls.append(u)

        # Serper.dev поиск
        print(f"[*] Serper.dev поиск ({len(SEARCH_QUERIES)} запросов)...")
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for i, query in enumerate(SEARCH_QUERIES):
                print(f"  [{i+1}/{len(SEARCH_QUERIES)}] {query[:60]}...")
                found = await serper_search(client, query, api_key)
                for u in found:
                    nu = _normalise(u)
                    if nu not in existing_urls and nu not in new_urls:
                        new_urls.append(nu)
                await asyncio.sleep(1)  # rate limit для Serper

        new_urls = list(set(new_urls))
        print(f"[*] Всего URL для проверки: {len(new_urls)}")

    targets = new_urls if not validate_only else [g.url for g in pool]
    if max_sites and len(targets) > max_sites:
        targets = targets[:max_sites]

    print(f"[*] Валидация {len(targets)} сайтов (Store API + pk_live_)...")
    sem = asyncio.Semaphore(10)

    async def validate_one(url: str) -> Gateway | None:
        async with sem:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers={"User-Agent": UA}) as client:
                return await validate_site(client, url)

    tasks = [validate_one(u) for u in targets]
    results = await asyncio.gather(*tasks)

    new_valid = 0
    for gw in results:
        if gw is not None and gw.url not in existing_urls:
            pool.append(gw)
            existing_urls.add(gw.url)
            new_valid += 1
            tok_label = "✓TOK" if gw.tokenization == "ok" else "✗TOK" if gw.tokenization == "blocked" else "?TOK"
            print(f"  [+] {gw.url} | pk={gw.pk_key[:25]}... | {gw.country} | {tok_label}")

    save_pool(pool)
    print(f"\n[OK] Валидных новых: {new_valid}. Всего в пуле: {len(pool)}")
    print(f"    Файл: {POOL_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Site Scraper — сбор WooCommerce-сайтов")
    parser.add_argument("--validate-only", action="store_true", help="Только валидация существующего пула")
    parser.add_argument("--max", type=int, default=100, help="Максимум сайтов для проверки")
    parser.add_argument("--serper-key", type=str, default="", help="Serper.dev API ключ")
    args = parser.parse_args()
    asyncio.run(run(max_sites=args.max, validate_only=args.validate_only, serper_key=args.serper_key))


if __name__ == "__main__":
    main()
