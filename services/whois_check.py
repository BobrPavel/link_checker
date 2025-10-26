import asyncio
import datetime
import re
import aiohttp

async def fetch_whois_data(domain: str) -> dict:
    """
    Получает WHOIS-информацию с публичного API.
    """

    # ✅ Используем RDAP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://rdap.org/domain/{domain}") as resp:
                if resp.status != 200:
                    return {"error": f"WHOIS data not available (HTTP {resp.status})"}
                data = await resp.json()

        # Извлекаем нужные поля
        registrar = data.get("registrar", {}).get("name") or data.get("entities", [{}])[0].get("vcardArray", [[], []])[1][1] if data.get("entities") else "Unknown"

        created_str = data.get("events", [{}])[0].get("eventDate")  # usually 'registration'
        expires_str = None
        for e in data.get("events", []):
            if e.get("eventAction") == "expiration":
                expires_str = e.get("eventDate")
            elif e.get("eventAction") == "registration":
                created_str = e.get("eventDate")

        if created_str:
            created = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            age_days = (datetime.datetime.utcnow() - created).days
            age_years = age_days // 365
        else:
            created = None
            age_days = None
            age_years = None

        if expires_str:
            expires = datetime.datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            days_left = (expires - datetime.datetime.utcnow()).days
        else:
            expires = None
            days_left = None

        # Определяем уровень риска по возрасту домена
        if age_days is not None:
            if age_days < 90:
                freshness = "🚨 Новый (меньше 3 месяцев)"
                risk = "Высокий"
            elif age_days < 365:
                freshness = "⚠️ Молодой (менее 1 года)"
                risk = "Средний"
            else:
                freshness = "✅ Старый (более года)"
                risk = "Низкий"
        else:
            freshness = "❔ Не удалось определить"
            risk = "Неизвестен"

        return {
            "domain": domain,
            "registrar": registrar or "Unknown",
            "created": str(created) if created else "Unknown",
            "expires": str(expires) if expires else "Unknown",
            "age_days": age_days,
            "age_years": age_years,
            "freshness": freshness,
            "risk": risk,
            "days_left": days_left
        }

    except Exception as e:
        return {"error": f"WHOIS error: {e}"}
