import asyncio
import aiohttp
from urllib.parse import urlparse

async def is_working_url(url: str) -> bool:
    """Проверяет, что URL корректен и доступен"""
    # 🔹 Приводим URL к корректной форме
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url  # добавляем схему по умолчанию

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "Mozilla/5.0 (URLCheckerBot/1.0)"}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                # Считаем рабочими все ответы от 200 до 399
                return 200 <= response.status < 400

    except aiohttp.ClientConnectorError:
        # Ошибка DNS или соединения
        return False
    except aiohttp.InvalidURL:
        # Совсем невалидный URL
        return False
    except asyncio.TimeoutError:
        # Превышен таймаут
        return False
    except Exception:
        # Любая другая ошибка (например, SSL)
        return False
