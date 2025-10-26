import asyncio
from aiogram import F, types, Router
from aiogram.filters import CommandStart, Command

from filters.chat_types import ChatTypeFilter

from services.validator import is_working_url
from services.google_safe_browsing import check_google_safebrowsing
from services.virustotal import check_virustotal
from services.blacklist_check import check_blacklists
from services.infrastructure_check import check_infrastructure

from utils.cache import get_cache, set_cache
from utils.scoring import calculate_risk_score


user_private_router = Router()
user_private_router.message.filter(ChatTypeFilter(["private"]))


@user_private_router.message(CommandStart())
async def start_cmd(message: types.Message):
    await message.answer(
        "Я ИИ ассистент для проверки ссылок на безопасность. "
        "Отправь мне ссылку и скажу насколько можно ей доверять"
    )


@user_private_router.message(Command("help"))
async def help_cmd(message: types.Message):
    await message.answer(
        "/start - запуск бота \n"
        "/help - инструкция \n"
        "Просто напишите ссылку, вызывающую у вас подозрения и бот пришлёт вам ответ \n"
        "\n"
        "Обращаю ваше внимание, что бот не даёт 100% информации о безопасности или опасности сайта."
        "Бот выводит информацию, которая позволяет вам принять соответсвующее решение"
    )


@user_private_router.message(F.text)
async def handle_link_check(message: types.Message):
    url = message.text.strip()

    # ✅ Проверяем валидность и доступность
    if not await is_working_url(url):
        await message.answer("🚫 Невалидная или недоступная ссылка.")
        return

    # ⚡ Проверяем кэш
    cached = get_cache(url)
    if cached:
        await message.answer(f"⚡ Результат из кэша:\n{cached['report']}", parse_mode="Markdown")
        return

    await message.answer("🔍 Выполняю расширенную проверку сайта...")

    # 🧠 Проверка в 4 источниках (параллельно)
    google_res, vt_res, bl_res, infra = await asyncio.gather(
        check_google_safebrowsing(url),
        check_virustotal(url),
        check_blacklists(url),
        check_infrastructure(url)
    )

    # 🔎 Подсчёт риска
    results = {
        "google": google_res,
        "vt": vt_res,
        "blacklist": bl_res,
        "infra": infra
    }

    level, score = calculate_risk_score(results)

    # 🧾 Формирование текста отчёта
    ssl_info = infra.get("ssl_info", {})
    ip_info = infra.get("ip_info", {})

    text = (
        f"🔗 *Проверка ссылки:* {url}\n\n"
        f"🧭 Google Safe Browsing: {google_res['status']}\n"
        f"🧪 VirusTotal: {vt_res['status']}\n"
        f"🚨 Blacklists: {bl_res['status']}\n\n"
        f"⚠️ *Уровень риска:* {level.upper()} ({score} баллов)\n\n"
        f"🌐 *Инфраструктура сайта:*\n"
        f"🏠 Домен: `{infra['hostname']}`\n"
        f"🔒 HTTPS: {'Да' if infra['is_https'] else 'Нет'}\n"
    )

    # SSL-инфо
    if ssl_info.get("valid"):
        text += (
            f"📜 Сертификат выдан: *{ssl_info.get('issued_by', 'N/A')}*\n"
            f"📅 Действителен до: `{ssl_info.get('valid_to', 'N/A')}`\n"
            f"🕐 Осталось дней: `{ssl_info.get('days_left', 'N/A')}`\n"
        )
    else:
        text += f"⚠️ SSL: {ssl_info.get('error', 'Нет данных')}\n"

    # IP и хостинг
    text += (
        f"\n🌍 *Хостинг:*\n"
        f"🧩 IP: `{ip_info.get('ip', 'неизвестен')}`\n"
        f"🏳️ Страна: {ip_info.get('country', 'Unknown')}\n"
        f"🏢 Организация: {ip_info.get('org', 'Unknown')}\n"
        f"🛰 ASN: {ip_info.get('asn', 'Unknown')}\n"
        f"📦 CDN: {infra.get('cdn', 'Не определён')}\n"
    )

    # Проверка прокси / подозрительного хостинга
    if infra.get("proxy_suspect"):
        text += "\n🚨 *Обнаружены признаки прокси или подозрительного хостинга*"
    else:
        text += "\n✅ Признаков прокси или подозрительного хостинга не найдено"

    # 💾 Сохраняем в кэш
    set_cache(url, {"report": text, "results": results})

@user_private_router.message()
async def handle_link_check_incorrect(message: types.Message):
    await message.answer("Введите url ссылку")
    