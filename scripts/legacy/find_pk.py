import httpx, re

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

for url in ["https://vollstart.com", "https://slabfudge.co.uk", "https://www.hanwellwine.co.uk"]:
    c = httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": UA})
    r = c.get(url)
    html = r.text
    
    # Search for pk_live_ in HTML
    pks = re.findall(r'pk_live_[0-9a-zA-Z]{24,}', html)
    print(f"\n{url}:")
    print(f"  pk_live_ in HTML: {pks[:3] if pks else 'NONE'}")
    
    # Search for stripe-related JS files
    js_files = re.findall(r'src=["\']([^"\']*stripe[^"\']*)["\']', html, re.IGNORECASE)
    js_files += re.findall(r'src=["\']([^"\']*wc-stripe[^"\']*)["\']', html, re.IGNORECASE)
    print(f"  stripe JS files: {js_files[:3]}")
    
    # Search for checkout page
    r2 = c.get(f"{url}/checkout/", headers={"User-Agent": UA})
    pks2 = re.findall(r'pk_live_[0-9a-zA-Z]{24,}', r2.text)
    print(f"  pk_live_ in checkout: {pks2[:3] if pks2 else 'NONE'}")
    
    # Search for wc-stripe params
    m = re.search(r'wc_stripe_params\s*=\s*({.*?});', r2.text)
    if m:
        print(f"  wc_stripe_params found in checkout page")
