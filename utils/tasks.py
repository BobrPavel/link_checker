import asyncio
import datetime

from utils.cache import refresh_cache


async def schedule_cache_refresh():
    """Фоновая задача: обновляет кэш каждый день в 00:00"""
    while True:
        now = datetime.datetime.now()
        tomorrow = (now + datetime.timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        seconds_until_midnight = (tomorrow - now).total_seconds()

        await asyncio.sleep(seconds_until_midnight)
        print("[TASKS] 🕛 Обновление кэша в 00:00...")
        await refresh_cache()
