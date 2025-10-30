def calculate_risk_score(results: dict) -> tuple[str, int, list[str]]:
    """
    Расширенный подсчёт риска:
    Возвращает уровень (низкий/средний/высокий), баллы (0–100), и объяснения.
    """

    score = 0
    reasons = []

    # --- Базовые источники ---
    if results["google"]["status"] == "danger":
        score += 50
        reasons.append("🚨 Замечен в Google Safe Browsing")

    if results["vt"]["status"] == "danger":
        score += 30
        reasons.append("🧪 Обнаружены угрозы по данным VirusTotal")

    if results["blacklist"]["status"] == "danger":
        score += 20
        reasons.append("⚠️ Сайт в известных чёрных списках")

    # --- Расширенные проверки ---
    infra = results.get("infra", {})
    link = results.get("link_analysis", {})
    whois = infra.get("whois", {})
    ssl_info = infra.get("ssl_info", {})

    # 1️⃣ Свежий домен
    if whois.get("age_days", 9999) < 90:
        score += 30
        reasons.append("🆕 Свежий домен (менее 3 месяцев)")

    # 2️⃣ HTTPS отсутствует
    if not infra.get("is_https", True):
        score += 20
        reasons.append("🔓 Отсутствует HTTPS")

    # 3️⃣ Недействительный SSL
    if ssl_info and not ssl_info.get("valid", True):
        score += 20
        reasons.append("🔒 Недействительный SSL-сертификат")

    # 4️⃣ Маскировка домена
    if link.get("masked_domain"):
        score += 15
        reasons.append("🎭 Маскировка домена (например, google.com.hacker.io)")

    # 5️⃣ Punycode
    if link.get("is_punycode"):
        score += 15
        reasons.append("⚠️ Домен использует Punycode (турбосквотинг)")

    # 6️⃣ Много редиректов
    if link.get("redirect_count", 0) > 2:
        score += 10
        reasons.append(f"🔁 Слишком много редиректов ({link['redirect_count']})")

    # 7️⃣ Трекинг-параметры
    if link.get("tracking_params"):
        score += 10
        reasons.append("📊 Найдены трекинговые параметры в URL")

    # 8️⃣ Подозрительный хостинг или прокси
    if infra.get("proxy_suspect"):
        score += 15
        reasons.append("🕵️ Подозрение на использование прокси или подозрительного хостинга")

    # --- Ограничим максимум ---
    score = min(score, 100)

    # --- Определяем уровень ---
    if score >= 60:
        level = "высокий"
    elif score >= 30:
        level = "средний"
    else:
        level = "низкий"

    return level, score, reasons
