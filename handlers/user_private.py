import os
import aiohttp
from bs4 import BeautifulSoup

from aiogram import F, types, Router
from aiogram.filters import CommandStart, Command

import openai

from filters.chat_types import ChatTypeFilter


openai_key = os.getenv("KEY")   # если создавать файл .env

# key = you_key
# openai_key = os.getenv(key) # если не создавать файл .env

user_private_router = Router()
user_private_router.message.filter(ChatTypeFilter(["private"]))


async def fetch_final_url(input_url):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(input_url, allow_redirects=True) as response:
                final_url = str(response.url)
                redirect_count = len(response.history)
                return final_url, redirect_count
        except Exception as e:
            return None, None


async def fetch_site_data(input_url):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(input_url, timeout=10) as response:
                if response.status != 200:
                    return input_url, None, None

                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")

                title = (
                    soup.title.string.strip()
                    if soup.title and soup.title.string
                    else "Нет данных"
                )

                description_tag = soup.find("meta", attrs={"name": "description"})
                description = (
                    description_tag["content"].strip()
                    if description_tag and "content" in description_tag.attrs
                    else "Нет данных"
                )

                return title, description

        except Exception as e:
            return None, None


async def ai_checker(input_url):
    prompt = [
        f"Проверь эту ссылку: {input_url} Ответь одной строкой: Что это за сайт, является ли это примером typosquatting"
    ]

    client = openai.AsyncOpenAI(api_key=openai_key)
    response = await client.chat.completions.create(
        model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


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

    real_url, redirect_count = await fetch_final_url(input_url)
    title, description = await fetch_site_data(input_url)
    ai_check_result = await ai_checker(input_url)

    if redirect_count > 0:
        redirect_opinion = "данная ссылка пытается маскироваться"
    else:
        redirect_opinion = "данная ссылка не пытается маскироваться"

    await message.answer(
        "🔗 Результат проверки ссылки \n"
        "\n"
        "📍 Реальный адрес: \n"
        f"{real_url} \n"
        "🔗 Конечный адрес: \n"
        f"{input_url} \n"
        "\n"
        f"🔄 Редиректы: Всего: {redirect_count}, {redirect_opinion} \n"
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


