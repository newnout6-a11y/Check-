"""
FOFA Scraper — поиск WooCommerce+Stripe сайтов через FOFA API.
Ищет сайты с pk_live_ ключами в HTML, валидирует через Store API.
"""
import asyncio, json, re, base64, httpx
from pathlib import Path
from datetime import datetime, timezone

POOL_FILE = Path(__file__).parent / "gateway_pool.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
FOFA_KEY = "a3f08d9788db1be6998214a3fda1adc5"
FOFA_EMAIL = "test@test.com"  # FOFA требует email

QUERIES = [
    'body="pk_live_" && body="woocommerce"',
    'body="pk_live_" && body="wc-stripe"',
    'body="pk_live_" && body="checkout" && body="wordpress"',
    'body="pk_live_" && body="add to cart"',
    'body="pk_live_" && body="wc/store"',
    'body="woocommerce-gateway-stripe"',
    'body="stripe_payment_method" && body="woocommerce"',
    'body="pk_live_" && body="product" && body="wordpress"',
    'body="pk_live_" && header="Set-Cookie" && body="cart"',
    'body="pk_live_" && body="billing"',
]

def load_pool():
    if POOL_FILE.exists():
        return json.loads(POOL_FILE.read_text(encoding="utf-8"))
    return []

def save_pool(pool):
    POOL_FILE.write_text(json.dumps(pool, ensure_ascii=False, indent=2), encoding="utf-8")

async def fofa_search(client, query, page=1, size=100):
    """Search FOFA API."""
    qbase64 = base64.b64encode(query.encode()).decode()
    url = "https://fofa.info/api/v1/search/all"
    params = {
        "email": FOFA_EMAIL,
        "key": FOFA_KEY,
        "qbase64": qbase64,
        "page": page,
        "size": size,
        "fields": "host,url,title",
    }
    try:
        r = await client.get(url, params=params, timeout=20)
        if r.status_code == 200:
            data = r.json()
            if data.get("error") and data["error"] != False:
                print(f"  FOFA error: {data.get('errmsg', '')[:100]}")
                return [], 0
            results = data.get("results", [])
            total = data.get("size", 0)
            return results, total
        else:
            print(f"  FOFA HTTP {r.status_code}: {r.text[:100]}")
            return [], 0
    except Exception as e:
        print(f"  FOFA error: {e}")
        return [], 0

async def validate_site(client, url):
    """Validate: Store API + pk_live_ + tokenization test."""
    url = url.rstrip("/")
    if not url.startswith("https://"):
        url = "https://" + url
    
    try:
        # Step 1: Store API
        r = await client.get(f"{url}/wp-json/wc/store/v1/cart",
            headers={"User-Agent": UA, "Accept": "application/json"}, timeout=10)
        if r.status_code != 200:
            return None
        
        # Step 2: Find pk_live_ on checkout page
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
        
        # Step 3: Test tokenization
        tok_status = ""
        try:
            tok_r = await client.post("https://api.stripe.com/v1/payment_methods",
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
                }, timeout=10)
            tok_data = tok_r.json()
            if tok_data.get("object") == "payment_method":
                tok_status = "ok"
            else:
                err = tok_data.get("error", {}).get("message", "")
                tok_status = "blocked" if "unsupported" in err.lower() else "other"
        except:
            tok_status = "error"
        
        return {
            "url": url,
            "pk_key": pk,
            "status": "active",
            "tokenization": tok_status,
            "error_count": 0,
            "check_count": 0,
        }
    except:
        return None

async def run(max_pages=2):
    pool = load_pool()
    existing = {g.get("url", "") for g in pool}
    
    all_urls = set()
    
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": UA}) as client:
        for i, q in enumerate(QUERIES):
            print(f"\n[{i+1}/{len(QUERIES)}] {q[:60]}...")
            for page in range(1, max_pages + 1):
                results, total = await fofa_search(client, q, page=page, size=100)
                print(f"  Page {page}: {len(results)} results (total: {total})")
                
                for r in results:
                    # results format: [host, url, title]
                    if len(r) >= 2:
                        furl = r[1] if r[1] else f"https://{r[0]}"
                        furl = furl.rstrip("/")
                        if furl not in existing:
                            all_urls.add(furl)
                
                if len(results) < 100:
                    break
                await asyncio.sleep(1)
            
            await asyncio.sleep(1)
        
        print(f"\n[*] Unique URLs to validate: {len(all_urls)}")
        
        # Validate all
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
                tok_label = "✓TOK" if gw["tokenization"] == "ok" else "✗TOK" if gw["tokenization"] == "blocked" else "?TOK"
                print(f"  [+] {gw['url']} | pk={gw['pk_key'][:25]}... | {tok_label}")
    
    save_pool(pool)
    print(f"\n[OK] New valid: {new_valid}. Total pool: {len(pool)}")

if __name__ == "__main__":
    asyncio.run(run())
