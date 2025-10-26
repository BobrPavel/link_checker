import socket
import ssl
import datetime
import aiohttp
import re

async def get_ssl_info(hostname: str) -> dict:
    """Проверяет SSL-сертификат и его срок действия"""
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])
        issued_to = subject.get("commonName", "")
        issued_by = issuer.get("organizationName", "")
        valid_from = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        valid_to = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (valid_to - datetime.datetime.utcnow()).days

        return {
            "valid": True,
            "issued_to": issued_to,
            "issued_by": issued_by,
            "valid_from": str(valid_from),
            "valid_to": str(valid_to),
            "days_left": days_left
        }

    except ssl.SSLError:
        return {"valid": False, "error": "SSL certificate invalid or missing"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


async def get_ip_info(hostname: str) -> dict:
    """Получает IP и информацию о хостинге / стране"""
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return {"error": "Cannot resolve hostname"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://ipapi.co/{ip}/json/") as resp:
                data = await resp.json()

        return {
            "ip": ip,
            "country": data.get("country_name", "Unknown"),
            "org": data.get("org", "Unknown"),
            "asn": data.get("asn", "Unknown")
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


async def detect_cdn(org_name: str) -> str:
    """Пытается определить CDN по имени организации"""
    if not org_name:
        return "Не определен"

    cdn_patterns = {
        "Cloudflare": "Cloudflare",
        "Akamai": "Akamai",
        "Fastly": "Fastly",
        "Amazon": "Amazon CloudFront",
        "Google": "Google CDN",
        "Microsoft": "Azure CDN",
        "Incapsula": "Imperva/Incapsula",
        "Bunny": "BunnyCDN",
        "StackPath": "StackPath CDN",
        "Tencent": "Tencent CDN"
    }

    for key, name in cdn_patterns.items():
        if re.search(key, org_name, re.IGNORECASE):
            return name
    return "Не используется или неизвестен"


async def check_infrastructure(url: str) -> dict:
    """Главная функция анализа инфраструктуры сайта"""
    # Извлекаем hostname
    hostname = url.replace("http://", "").replace("https://", "").split("/")[0]

    ssl_info = await get_ssl_info(hostname)
    ip_info = await get_ip_info(hostname)
    cdn = await detect_cdn(ip_info.get("org", ""))

    is_https = url.startswith("https://")
    proxy_suspect = any(
        term in (ip_info.get("org") or "").lower()
        for term in ["vpn", "proxy", "tor", "hosting", "server"]
    )

    return {
        "hostname": hostname,
        "is_https": is_https,
        "ssl_info": ssl_info,
        "ip_info": ip_info,
        "cdn": cdn,
        "proxy_suspect": proxy_suspect
    }
