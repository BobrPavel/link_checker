import aiohttp
import os
import base64

from dotenv import find_dotenv, load_dotenv
load_dotenv(find_dotenv())

VT_KEY = os.getenv('VIRUSTOTAL_KEY')
VT_URL = "https://www.virustotal.com/api/v3/urls"

async def check_virustotal(url: str) -> dict:
    headers = {"x-apikey": VT_KEY}

    # Кодируем URL в base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async with aiohttp.ClientSession(headers=headers) as session:
        # Проверяем, есть ли уже анализ
        async with session.get(f"{VT_URL}/{url_id}") as resp:
            data = await resp.json()

            # Если анализа нет — отправляем URL на сканирование
            if "error" in data:
                async with session.post(VT_URL, data={"url": url}) as post_resp:
                    post_data = await post_resp.json()
                    return {"status": "submitted", "details": post_data}

            # Извлекаем статистику анализа
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                return {"status": "danger", "details": stats}
            return {"status": "clean", "details": stats}
