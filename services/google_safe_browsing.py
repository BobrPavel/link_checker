import aiohttp
import os

API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

async def check_google_safebrowsing(url: str) -> dict:
    payload = {
        "client": {"clientId": "your-bot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        }
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}?key={API_KEY}", json=payload) as resp:
            data = await resp.json()
            if "matches" in data:
                return {"status": "danger", "details": data["matches"]}
            return {"status": "clean", "details": None}
