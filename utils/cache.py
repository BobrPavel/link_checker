import json
import time
import os
import asyncio
from typing import Optional
from datetime import datetime

from services.validator import is_working_url
from services.google_safe_browsing import check_google_safebrowsing
from services.virustotal import check_virustotal
from services.blacklist_check import check_blacklists
from utils.calculate_risk import calculate_risk_score


CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "common", "cache.json")
TTL = 60 * 30  # 30 минут

_cache = {}


# =========================
#   БАЗОВЫЕ ОПЕРАЦИИ
# =========================

def load_cache():
    """Загружает кэш из файла"""
    global _cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                _cache = json.load(f)
            print(f"[CACHE] Загружено {len(_cache)} записей из файла")
        except Exception as e:
            print(f"[CACHE] Ошибка загрузки: {e}")
            _cache = {}
    else:
        _cache = {}


def save_cache():
    """Сохраняет кэш в файл"""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[CACHE] Ошибка сохранения: {e}")


def get_cache(url: str) -> Optional[dict]:
    """Возвращает данные из кэша, если они актуальны"""
    entry = _cache.get(url)
    if not entry:
        return None

    # Проверка TTL
    if time.time() - entry["timestamp"] > TTL:
        print(f"[CACHE] ⏰ {url} — запись устарела, удаляю")
        del _cache[url]
        save_cache()
        return None

    return entry["data"]


def set_cache(url: str, data: dict):
    """Добавляет новую запись в кэш"""
    _cache[url] = {"timestamp": time.time(), "data": data}
    save_cache()
    print(f"[CACHE] 💾 {url} — записано в кэш")


def clear_cache():
    """Полная очистка кэша"""
    global _cache
    _cache = {}
    save_cache()
    print("[CACHE] 🧹 Очищен весь кэш")


# =========================
#   ЕЖЕДНЕВНОЕ ОБНОВЛЕНИЕ
# =========================

async def refresh_cache():
    """
    Обновление кэша в 00:00:
    - удаляет мертвые и устаревшие ссылки
    - пересчитывает данные по рабочим
    """
    global _cache
    load_cache()

    print(f"\n[CACHE] 🌙 Запуск ночного обновления ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")

    urls = list(_cache.keys())
    updated = 0
    deleted = 0

    for url in urls:
        # Удаляем старые записи
        if time.time() - _cache[url]["timestamp"] > TTL:
            print(f"[CACHE] ⏳ {url} — устарел, удаляю")
            del _cache[url]
            deleted += 1
            continue

        # Проверяем доступность
        if not await is_working_url(url):
            print(f"[CACHE] ❌ {url} — недоступен, удаляю из кэша")
            del _cache[url]
            deleted += 1
            continue

        # Обновляем данные
        try:
            google_res, vt_res, bl_res = await asyncio.gather(
                check_google_safebrowsing(url),
                check_virustotal(url),
                check_blacklists(url),
            )
            results = {"google": google_res, "vt": vt_res, "blacklist": bl_res}
            level, score, reasons = calculate_risk_score(results)

            text = (
                f"🔗 Проверка ссылки: {url}\n\n"
                f"🧭 Google Safe Browsing: {google_res['status']}\n"
                f"🧪 VirusTotal: {vt_res['status']}\n"
                f"🚨 Blacklists: {bl_res['status']}\n\n"
                f"⚠️ Уровень риска: *{level.upper()}* ({score} баллов)\n\n"
                f"📋 Причины начисления:\n" +
                "\n".join([f"• {r}" for r in reasons])
            )

            _cache[url] = {
                "timestamp": time.time(),
                "data": {"report": text, "results": results},
            }
            updated += 1
            print(f"[CACHE] 🔁 {url} — обновлён ({score} баллов)")
        except Exception as e:
            print(f"[CACHE] ⚠️ Ошибка обновления {url}: {e}")

    save_cache()
    print(f"[CACHE] ✅ Обновление завершено: обновлено {updated}, удалено {deleted}\n")
