import aiohttp
import validators

async def is_working_url(url: str) -> bool:
    """Проверяет, валидный ли URL и доступен ли он"""
    if not validators.url(url):
        return False

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as response:
                return response.status == 200
    except Exception:
        return False
