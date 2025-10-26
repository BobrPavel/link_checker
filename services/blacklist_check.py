import aiohttp

BLACKLISTS = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt",
    # можно добавить другие
]

async def check_blacklists(url: str) -> dict:
    for bl_url in BLACKLISTS:
        async with aiohttp.ClientSession() as session:
            async with session.get(bl_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if url in text:
                        return {"status": "danger", "details": {"blacklist": bl_url}}
    return {"status": "clean", "details": None}
