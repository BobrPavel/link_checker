import re
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin

SUSPICIOUS_KEYWORDS = ["login", "secure", "verify", "update", "bank", "paypal", "signin", "account"]
TRACKING_PARAMS = ["utm_", "ref", "fbclid", "gclid", "mc_eid", "yclid", "igshid", "si"]

async def analyze_link(url: str) -> dict:
    """
    Анализирует структуру и содержимое ссылки.
    Возвращает мета-информацию и подозрительные признаки.
    """

    result = {
        "masked_domain": None,
        "is_punycode": False,
        "redirect_count": 0,
        "iframe_count": 0,
        "internal_links": 0,
        "external_links": 0,
        "tracking_params": [],
        "risk_flags": [],
    }

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 🕵️ 1. Проверка на маскировку (пример: google.com.hacker.io)
    parts = hostname.split(".")
    if len(parts) > 2:
        main_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])
        # Подозрительно, если поддомен похож на известные бренды
        if any(kw in subdomain.lower() for kw in ["google", "apple", "bank", "paypal", "amazon"]):
            result["masked_domain"] = f"⚠️ Маскировка: {subdomain}.{main_domain}"
            result["risk_flags"].append("masked_domain")

    # 🧩 2. Проверка на Punycode
    if "xn--" in hostname:
        result["is_punycode"] = True
        result["risk_flags"].append("punycode")

    # 🌐 3. Проверка редиректов и контента
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "Mozilla/5.0 (URLAnalyzerBot/1.0)"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                result["redirect_count"] = len(response.history)
                html = await response.text(errors="ignore")

                soup = BeautifulSoup(html, "html.parser")

                # 🔗 4. Подсчёт ссылок
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    full = urljoin(url, href)
                    if full.startswith(url):
                        result["internal_links"] += 1
                    else:
                        result["external_links"] += 1

                # 🪟 5. Подсчёт iframe
                result["iframe_count"] = len(soup.find_all("iframe"))

                # 🧭 6. Поиск трекинговых параметров
                query_params = parse_qs(parsed.query)
                tracking = [k for k in query_params.keys() if any(tp in k for tp in TRACKING_PARAMS)]
                if tracking:
                    result["tracking_params"] = tracking
                    result["risk_flags"].append("tracking")

                # 🧠 7. Поиск подозрительных слов в контенте
                body_text = soup.get_text(" ").lower()
                if any(kw in body_text for kw in SUSPICIOUS_KEYWORDS):
                    result["risk_flags"].append("phishing_keywords")

    except Exception as e:
        result["error"] = str(e)

    return result
