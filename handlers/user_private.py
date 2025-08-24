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
    input_url = message.text

    status = await is_working_url(input_url)

    if status is False:
        await message.answer("URL введён не правильно или не работает")
    else:
        real_url, redirect_count = await fetch_real_url(input_url)
        title, description = await fetch_site_data(input_url)
        print(real_url, redirect_count, title, description)
        ai_check_result = await ai_checker(input_url)

        if real_url is None or redirect_count is None or title is None or description is None:
            await message.answer("Произошла внутренная ошибка")
        else:
            await message.answer(
                "🔗 Результат проверки ссылки \n"
                "\n"
                "📍 Реальный адрес: \n"
                f"{real_url} \n"
                "🔗 Конечный адрес: \n"
                f"{input_url} \n"
                "\n"
                f"🔄 Редиректы: всего: {redirect_count}\n"
                "\n"
                "📜 Заголовок сайта: \n"
                f"{title} \n"
                "📋 Описание сайта: \n"
                f"{description} \n"
                "\n"
                "Что это за сайт и является ли это примером typosquatting? \n "
                f"{ai_check_result}"
            )



@user_private_router.message()
async def lick_checher2(message: types.Message):
    await message.answer("Пожалуйста введите ссылку")


