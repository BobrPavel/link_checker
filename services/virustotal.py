import aiohttp
import os

VT_KEY = os.getenv("VIRUSTOTAL_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

async def check_virustotal(url: str) -> dict:
    headers = {"x-apikey": VT_KEY}

    async with aiohttp.ClientSession(headers=headers) as session:
        # Сначала нужно получить ID
        async with session.post(VT_URL, data={"url": url}) as resp:
            res = await resp.json()
            url_id = res["data"]["id"]

        # Теперь получить анализ
        async with session.get(f"{VT_URL}/{url_id}") as resp:
            data = await resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            # можно делать собственный риск на основе stats
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                return {"status": "danger", "details": stats}
            return {"status": "clean", "details": stats}
