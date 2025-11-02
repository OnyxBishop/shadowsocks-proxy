import asyncio
import logging
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message

try:
    from config import Config
    from message_handler import router
    from keyboard import get_keyboard
except ImportError:
    from config import Config
    from message_handler import router
    from keyboard import get_keyboard

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    if not Config.BOT_TOKEN:
        logger.error("BOT_TOKEN is not set!")
        return

    bot = Bot(token=Config.BOT_TOKEN)
    dp = Dispatcher()

    # Register router
    dp.include_router(router)

    # Start command handler
    @dp.message(Command("start"))
    async def cmd_start(message: Message):
        if message.from_user.id not in Config.admin_ids():
            await message.answer("Доступ запрещён")
            return

        await message.answer(
            "Добро пожаловать в Ramee VPN бот!\n\n"
            "Выберите действие:",
            reply_markup=get_keyboard()
        )

    logger.info("Starting bot...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
