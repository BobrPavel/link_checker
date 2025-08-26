import os
import aiohttp

from bs4 import BeautifulSoup

import openai
from openai import OpenAIError


openai_key = os.getenv("KEY")  # если создавать файл .env

# key = you_key
# openai_key = os.getenv(key) # если не создавать файл .env


async def fetch_real_url(input_url):  # получение реального пути и количества редиректов
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(input_url, allow_redirects=True) as response:
                final_url = str(response.url)
                redirect_count = len(response.history)
                return final_url, redirect_count
        except Exception:
            return None, None


async def fetch_site_data(input_url):  # получение заголовка и
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(input_url) as response:
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

        except Exception:
            return None, None


async def ai_checker(input_url):
    try:
        prompt = [
            f"Проверь эту ссылку: {input_url} Ответь одной строкой: Что это за сайт, является ли это примером typosquatting"
        ]

        client = openai.AsyncOpenAI(api_key=openai_key)
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except OpenAIError:
        return None
