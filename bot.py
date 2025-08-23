import asyncio
import os

from aiogram import Bot, Dispatcher, types
from aiogram.client.bot import DefaultBotProperties
from aiogram.enums.parse_mode import ParseMode

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv())



from handlers.user_private import user_private_router


from common.bot_cmds_list import private

# bot = Bot(token=os.getenv('you_token'), default=DefaultBotProperties(parse_mode=ParseMode.HTML)) если не создавать файл .env

bot = Bot(token=os.getenv('TOKEN'), default=DefaultBotProperties(parse_mode=ParseMode.HTML)) # если создать файл .env
bot.my_admins_list = []

dp = Dispatcher()

dp.include_router(user_private_router)



async def on_startup(bot):
    print("Бот запущен")



async def on_shutdown(bot):
    print('бот лег')


async def main():
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    # dp.update.middleware(DataBaseSession(session_pool=session_maker))

    await bot.delete_webhook(drop_pending_updates=True)
    # await bot.delete_my_commands(scope=types.BotCommandScopeAllPrivateChats())
    await bot.set_my_commands(commands=private, scope=types.BotCommandScopeAllPrivateChats())
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())

asyncio.run(main())