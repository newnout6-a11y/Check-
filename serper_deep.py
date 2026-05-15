"""
Serper Deep — расширенный поиск через Serper.dev с фокусом на legacy WC Stripe.

Фокус: найти магазины с LEGACY Stripe плагином (< v6) — они пробрасывают
реальные decline codes. Это лучшие шлюзы для чекинга.

Стратегия:
  1. Специальные запросы ищущие "wc_stripe_params" (маркер legacy)
  2. Обычные WC+Stripe запросы по малым нишам
  3. Валидация через site_scraper.validate_site()

Использование:
  python serper_deep.py                     # поиск legacy шлюзов
  python serper_deep.py --max 300           # больше сайтов
  python serper_deep.py --serper-key KEY    # свой ключ
"""

from __future__ import annotations
import asyncio, json, sys
from pathlib import Path
import httpx

# Импортируем логику из site_scraper
from site_scraper import (
    load_pool, save_pool, _normalise, validate_site,
    quick_check, serper_search, _load_serper_key,
    UA, POOL_FILE,
)

# Запросы специально для LEGACY Stripe (wc_stripe_params = маркер < v6)
LEGACY_QUERIES = [
    '"wc_stripe_params" "pk_live_" site:*.com',
    '"wc_stripe_params" "pk_live_" site:*.co.uk',
    '"wc_stripe_params" "pk_live_" site:*.com.au',
    '"wc_stripe_params" site:*.com -shopify',
    '"wc-gateway-stripe" "pk_live_" "checkout" site:*.com',
    '"wc-gateway-stripe" "add to cart" site:*.com',
    '"stripe_params" "woocommerce" "pk_live_"',
    # Старые магазины (legacy чаще)
    '"powered by woocommerce" "stripe" "2020" -shopify',
    '"powered by woocommerce" "stripe" "2021" -shopify',
    '"powered by woocommerce" "stripe" "est" -shopify',
]

# Малые ниши (чаще legacy — не обновляют плагины)
NICHE_QUERIES = [
    '"woocommerce" "stripe" "farm" "shop" -shopify',
    '"woocommerce" "stripe" "pottery" -shopify',
    '"woocommerce" "stripe" "bakery" "order" -shopify',
    '"woocommerce" "stripe" "florist" "delivery" -shopify',
    '"woocommerce" "stripe" "yarn" "knitting" -shopify',
    '"woocommerce" "stripe" "brewery" "shop" -shopify',
    '"woocommerce" "stripe" "cheese" "shop" -shopify',
    '"woocommerce" "stripe" "honey" "buy" -shopify',
    '"woocommerce" "stripe" "spice" "shop" -shopify',
    '"woocommerce" "stripe" "tea" "loose leaf" -shopify',
    '"woocommerce" "stripe" "chocolate" "handmade" -shopify',
    '"woocommerce" "stripe" "leather" "workshop" -shopify',
    '"woocommerce" "stripe" "ceramics" "studio" -shopify',
    '"woocommerce" "stripe" "woodwork" "custom" -shopify',
    '"woocommerce" "stripe" "print" "studio" -shopify',
]

ALL_DEEP_QUERIES = LEGACY_QUERIES + NICHE_QUERIES


async def run(max_sites: int = 300, serper_key: str = "") -> None:
    pool = load_pool()
    existing = {g.get("url", "") for g in pool}
    api_key = serper_key or _load_serper_key()

    if not api_key:
        print("[!] SERPER_KEY не найден. Укажите --serper-key или добавьте в .env")
        sys.exit(1)

    # ── Поиск ──
    new_urls: set[str] = set()
    print(f"[*] Serper Deep — {len(ALL_DEEP_QUERIES)} запросов (фокус: legacy + ниши)")
    print(f"{'─' * 60}")

    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"User-Agent": UA}) as client:
        for i, q in enumerate(ALL_DEEP_QUERIES):
            is_legacy_q = i < len(LEGACY_QUERIES)
            tag = "LEGACY" if is_legacy_q else "NICHE"
            print(f"  [{tag}][{i+1}/{len(ALL_DEEP_QUERIES)}] {q[:50]}...", end=" ", flush=True)
            found = await serper_search(client, q, api_key)
            added = 0
            for u in found:
                nu = _normalise(u)
                if nu not in existing and nu not in new_urls:
                    new_urls.add(nu)
                    added += 1
            print(f"+{added}")
            await asyncio.sleep(1.2)

    targets = list(new_urls)
    if max_sites and len(targets) > max_sites:
        targets = targets[:max_sites]
    print(f"\n[*] Новых URL: {len(targets)}")

    if not targets:
        print("[*] Новых сайтов не найдено.")
        return

    # ── Быстрый отсев ──
    print(f"\n[Phase 1] Quick check (Store API alive?)...")
    sem = asyncio.Semaphore(25)

    async def qc(url):
        async with sem:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True,
                                         headers={"User-Agent": UA}) as c:
                ok = await quick_check(c, url)
                return url, ok

    qc_results = await asyncio.gather(*[qc(u) for u in targets])
    alive = [url for url, ok in qc_results if ok]
    print(f"  Alive: {len(alive)} / {len(targets)}")

    # ── Полная валидация ──
    print(f"\n[Phase 2] Full validation...")
    val_sem = asyncio.Semaphore(8)

    async def val(url):
        async with val_sem:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                         headers={"User-Agent": UA}) as c:
                return await validate_site(c, url)

    val_results = await asyncio.gather(*[val(u) for u in alive])

    # ── Сохранение ──
    new_valid = 0
    new_legacy = 0
    new_ready = 0
    for gw in val_results:
        if gw and gw["url"] not in existing:
            pool.append(gw)
            existing.add(gw["url"])
            new_valid += 1
            if gw.get("stripe_version") == "legacy":
                new_legacy += 1
            if gw.get("checkout_ready"):
                new_ready += 1
            tok = "✓" if gw["tokenization"] == "ok" else "✗" if gw["tokenization"] == "blocked" else "?"
            ver = gw.get("stripe_version", "?") or "?"
            ready = "★" if gw.get("checkout_ready") else " "
            print(f"  [{ready}] {gw['url'][:40]:40s} | {tok}TOK | v={ver}")

    save_pool(pool)

    # ── Итого ──
    print(f"\n{'═' * 60}")
    print(f"  Новых: {new_valid} | Legacy: {new_legacy} | Ready: {new_ready}")
    print(f"  Всего в пуле: {len(pool)}")
    print(f"{'═' * 60}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Serper Deep — поиск legacy WC Stripe шлюзов")
    parser.add_argument("--max", type=int, default=300, help="Макс. сайтов")
    parser.add_argument("--serper-key", type=str, default="", help="Serper.dev API ключ")
    args = parser.parse_args()
    asyncio.run(run(max_sites=args.max, serper_key=args.serper_key))


if __name__ == "__main__":
    main()
