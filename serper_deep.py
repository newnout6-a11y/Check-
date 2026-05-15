"""
Serper Deep Scraper — расширенный поиск через Serper.dev + валидация.
Фокус: найти WC+Stripe сайты где серверная токенизация работает.
"""
import asyncio, json, re, httpx, base64
from pathlib import Path
from datetime import datetime, timezone

POOL_FILE = Path(__file__).parent / "gateway_pool.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
SERPER_KEY = "8061e80440f132abe401622d73c98db8e90690c8"

# Более точные запросы — ищем конкретные признаки WC+Stripe
QUERIES = [
    # Прямые признаки
    '"woocommerce" "stripe" "pk_live_" "checkout"',
    '"woocommerce" "stripe" "add to cart" "payment"',
    '"woocommerce" "stripe" "cart" "billing"',
    # Конкретные ниши
    '"woocommerce" "stripe" "shop" "buy" -shopify -magento',
    '"woocommerce" "stripe" "product" "price" -shopify',
    '"woocommerce" "stripe" "order" "payment" -shopify',
    # По регионам
    '"woocommerce" "stripe" "shop" site:*.com -shopify',
    '"woocommerce" "stripe" "shop" site:*.co.uk -shopify',
    '"woocommerce" "stripe" "shop" site:*.com.au -shopify',
    '"woocommerce" "stripe" "shop" site:*.ca -shopify',
    '"woocommerce" "stripe" "shop" site:*.de -shopify',
    '"woocommerce" "stripe" "shop" site:*.fr -shopify',
    '"woocommerce" "stripe" "shop" site:*.nl -shopify',
    '"woocommerce" "stripe" "shop" site:*.se -shopify',
    '"woocommerce" "stripe" "shop" site:*.jp -shopify',
    # WP-specific
    '"wp-json" "wc/store" "stripe"',
    '"wp-content" "woocommerce-gateway-stripe"',
    '"wc_stripe" "payment_method" "checkout"',
    # Малые магазины (больше шансов на старый Stripe)
    '"powered by woocommerce" "stripe" "buy" -shopify',
    '"powered by woocommerce" "stripe" "cart" -shopify',
    '"powered by woocommerce" "stripe" "checkout" -shopify',
    # Нишевые
    '"woocommerce" "stripe" "subscription" -shopify',
    '"woocommerce" "stripe" "donation" -shopify',
    '"woocommerce" "stripe" "membership" -shopify',
    '"woocommerce" "stripe" "booking" -shopify',
    '"woocommerce" "stripe" "digital download" -shopify',
    '"woocommerce" "stripe" "coffee" -shopify',
    '"woocommerce" "stripe" "wine" -shopify',
    '"woocommerce" "stripe" "fashion" -shopify',
    '"woocommerce" "stripe" "jewelry" -shopify',
    '"woocommerce" "stripe" "cosmetics" -shopify',
    '"woocommerce" "stripe" "supplements" -shopify',
    '"woocommerce" "stripe" "cbd" -shopify',
    '"woocommerce" "stripe" "vape" -shopify',
    '"woocommerce" "stripe" "pet" -shopify',
    '"woocommerce" "stripe" "garden" -shopify',
    '"woocommerce" "stripe" "craft" -shopify',
    '"woocommerce" "stripe" "art" -shopify',
    '"woocommerce" "stripe" "music" -shopify',
    '"woocommerce" "stripe" "book" -shopify',
]

def load_pool():
    if POOL_FILE.exists():
        return json.loads(POOL_FILE.read_text(encoding="utf-8"))
    return []

def save_pool(pool):
    POOL_FILE.write_text(json.dumps(pool, ensure_ascii=False, indent=2), encoding="utf-8")

async def serper_search(client, query):
    """Search via Serper.dev."""
    r = await client.post("https://google.serper.dev/search",
        json={"q": query, "num": 20, "gl": "us"},
        headers={"X-API-KEY": SERPER_KEY, "Content-Type": "application/json"},
        timeout=15)
    if r.status_code != 200:
        return []
    data = r.json()
    urls = []
    for item in data.get("organic", []):
        link = item.get("link", "")
        if link:
            urls.append(link)
    for item in data.get("knowledgeGraph", {}):
        pass  # skip
    return urls

def normalise(url):
    url = url.strip().rstrip("/")
    if not url.startswith("https://"):
        url = "https://" + url.replace("http://", "")
    # Remove path, keep domain only
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"https://{p.netloc}"

async def validate_site(client, url):
    """Full validation: Store API + pk_live_ + tokenization."""
    try:
        # Store API
        r = await client.get(f"{url}/wp-json/wc/store/v1/cart",
            headers={"User-Agent": UA, "Accept": "application/json"}, timeout=10)
        if r.status_code != 200:
            return None
        
        # pk_live_ on pages
        pk = ""
        for page in ["/checkout/", "/shop/", "/"]:
            try:
                r2 = await client.get(f"{url}{page}", headers={"User-Agent": UA}, timeout=10)
                m = re.search(r'pk_live_[0-9a-zA-Z]{24,}', r2.text)
                if m:
                    pk = m.group(0)
                    break
            except:
                continue
        if not pk:
            return None
        
        # Tokenization test
        tok = ""
        try:
            tok_r = await client.post("https://api.stripe.com/v1/payment_methods",
                data={"type": "card", "card[number]": "4242424242424242",
                      "card[exp_month]": "12", "card[exp_year]": "35", "card[cvc]": "123"},
                headers={"Authorization": f"Bearer {pk}", "Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": UA, "Origin": "https://js.stripe.com", "Referer": "https://js.stripe.com/",
                         "Accept": "application/json", "Stripe-Version": "2023-10-16"},
                timeout=10)
            d = tok_r.json()
            if d.get("object") == "payment_method":
                tok = "ok"
            else:
                err = d.get("error", {}).get("message", "")
                if "unsupported" in err.lower():
                    tok = "blocked"
                elif "declined" in err.lower() or "live mode" in err.lower():
                    tok = "ok"  # test card declined in live = tokenization works
                else:
                    tok = "other"
        except:
            tok = "error"
        
        return {"url": url, "pk_key": pk, "status": "active", "tokenization": tok,
                "error_count": 0, "check_count": 0}
    except:
        return None

async def run():
    pool = load_pool()
    existing = {g.get("url", "") for g in pool}
    
    all_urls = set()
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": UA}) as client:
        for i, q in enumerate(QUERIES):
            print(f"[{i+1}/{len(QUERIES)}] {q[:60]}...")
            found = await serper_search(client, q)
            for u in found:
                nu = normalise(u)
                if nu not in existing:
                    all_urls.add(nu)
            await asyncio.sleep(1.5)
        
        print(f"\n[*] Unique URLs: {len(all_urls)}")
        
        # Validate
        sem = asyncio.Semaphore(15)
        async def check(url):
            async with sem:
                return await validate_site(client, url)
        
        results = await asyncio.gather(*[check(u) for u in all_urls])
        
        new_valid = 0
        for gw in results:
            if gw and gw["url"] not in existing:
                pool.append(gw)
                existing.add(gw["url"])
                new_valid += 1
                tok = "✓TOK" if gw["tokenization"] == "ok" else "✗TOK" if gw["tokenization"] == "blocked" else "?TOK"
                print(f"  [+] {gw['url']} | pk={gw['pk_key'][:25]}... | {tok}")
    
    save_pool(pool)
    print(f"\n[OK] New: {new_valid}. Total: {len(pool)}")

if __name__ == "__main__":
    asyncio.run(run())
