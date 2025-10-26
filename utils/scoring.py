def calculate_risk_score(results: dict) -> tuple[str, int]:
    score = 0

    if results["google"]["status"] == "danger":
        score += 50
    if results["vt"]["status"] == "danger":
        score += 30
    if results["blacklist"]["status"] == "danger":
        score += 20

    if score >= 60:
        return "высокий", score
    elif score >= 30:
        return "средний", score
    else:
        return "низкий", score
