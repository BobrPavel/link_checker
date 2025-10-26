import json
import time
import os
import asyncio
from typing import Optional
from services.validator import is_working_url

from services.google_safe_browsing import check_google_safebrowsing
from services.virustotal import check_virustotal
from services.blacklist_check import check_blacklists
from utils.scoring import calculate_risk_score

CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "common", "cache.json")


TTL = 60 * 30  # 30 минут
_cache = {}

def load_cache():
    global _cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}
    else:
        _cache = {}

def save_cache():
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(_cache, f, ensure_ascii=False)

def get_cache(url: str) -> Optional[dict]:
    if url in _cache:
        entry = _cache[url]
        if time.time() - entry["timestamp"] < TTL:
            return entry["data"]
    return None

def set_cache(url: str, data: dict):
    _cache[url] = {"timestamp": time.time(), "data": data}
    save_cache()

def clear_cache():
    global _cache
    _cache = {}
    save_cache()
    print("[CACHE] Очищен кэш")

async def refresh_cache():
    """Обновление кэша в 00:00: удаляем мертвые ссылки и обновляем рабочие"""
    global _cache
    urls = list(_cache.keys())

    for url in urls:
        # Проверяем, доступен ли URL
        if not await is_working_url(url):
            print(f"[CACHE] ❌ {url} — недоступен, удаляю из кэша")
            del _cache[url]
            continue

        # Если рабочий — перезапрашиваем данные
        try:
            google_res, vt_res, bl_res = await asyncio.gather(
                check_google_safebrowsing(url),
                check_virustotal(url),
                check_blacklists(url)
            )
            results = {"google": google_res, "vt": vt_res, "blacklist": bl_res}
            level, score = calculate_risk_score(results)

            text = (
                f"🔗 Проверка ссылки: {url}\n\n"
                f"🧭 Google Safe Browsing: {google_res['status']}\n"
                f"🧪 VirusTotal: {vt_res['status']}\n"
                f"🚨 Blacklists: {bl_res['status']}\n\n"
                f"⚠️ Уровень риска: *{level.upper()}* ({score} баллов)"
            )

            _cache[url] = {
                "timestamp": time.time(),
                "data": {"report": text, "results": results}
            }
            print(f"[CACHE] 🔁 {url} — обновлён")
        except Exception as e:
            print(f"[CACHE] ⚠️ Ошибка обновления {url}: {e}")

    save_cache()
