import asyncio
from aiogram import F, types, Router
from aiogram.filters import CommandStart, Command

from filters.chat_types import ChatTypeFilter

from utils.validators import is_working_url
from utils.check import ai_checker, fetch_real_url, fetch_site_data


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
async def lick_checher(message: types.Message):
    input_url = message.text.strip()

    if not await is_working_url(input_url):
        await message.answer("URL введён не правильно или не работает")
        return

    # Параллельно выполняем запросы
    real_url_task = fetch_real_url(input_url)
    site_data_task = fetch_site_data(input_url)
    ai_check_task = ai_checker(input_url)

    real_url_result, site_data_result, ai_check_result = await asyncio.gather(
        real_url_task, site_data_task, ai_check_task, return_exceptions=True
    )

    # Проверка на ошибки
    if (
        isinstance(real_url_result, Exception)
        or isinstance(site_data_result, Exception)
        or isinstance(ai_check_result, Exception)
    ):
        await message.answer("Произошла внутренняя ошибка при обработке URL")
        return

    real_url, redirect_count = real_url_result
    title, description = site_data_result

    # Дополнительная проверка значений
    if not all(
        [real_url, redirect_count is not None, title, description, ai_check_result]
    ):
        await message.answer("Произошла внутренняя ошибка")
        return

    response = (
        "🔗 Результат проверки ссылки\n\n"
        f"📍 Реальный адрес:\n{real_url}\n"
        f"🔗 Конечный адрес:\n{input_url}\n\n"
        f"🔄 Редиректы: всего: {redirect_count}\n\n"
        f"📜 Заголовок сайта:\n{title}\n"
        f"📋 Описание сайта:\n{description}\n\n"
        "Что это за сайт и является ли это примером typosquatting?\n"
        f"{ai_check_result}"
    )

    await message.answer(response)


@user_private_router.message()
async def lick_checher2(message: types.Message):
    await message.answer("Пожалуйста введите ссылку")
