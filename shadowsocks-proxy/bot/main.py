import asyncio
import logging
import sys
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.types import BotCommand, InlineKeyboardMarkup
from keyboard import get_keyboard

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import Config
from message_handler import router
from proxy_server import CustomProxyServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    logger.info("=" * 50)
    logger.info("🚀 Starting Shadowsocks Bot + Proxy Server")
    logger.info("=" * 50)

    # Validate configuration
    if not Config.BOT_TOKEN:
        logger.error("❌ BOT_TOKEN not set!")
        return
    if not Config.SS_Master_Secret:
        logger.error("❌ SS_MASTER_SECRET not set!")
        return
    if not Config.admin_ids():
        logger.warning("⚠️ No ADMIN_IDS set - bot will reject all users")

    logger.info(f"✅ Bot token: {Config.BOT_TOKEN[:10]}...")
    logger.info(f"✅ Proxy: {Config.PROXY_HOST}:{Config.PROXY_PORT}")
    logger.info(f"✅ Admin IDs: {Config.admin_ids()}")

    # Initialize bot
    bot = Bot(token=Config.BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    # Set bot commands
    await bot.set_my_commands([
        BotCommand(command="start", description="Получить доступ к VPN")
    ])

    @dp.message(lambda message: message.text == "/start")
    async def start_cmd(message):
        if message.from_user.id not in Config.admin_ids():
            await message.answer("❌ Доступ запрещён")
            return
        await message.answer(
            f"👋 Добро пожаловать, {message.from_user.first_name}!\n\n"
            "Выберите действие:",
            reply_markup=get_keyboard()
        )

    # Start proxy server in background
    try:
        proxy = CustomProxyServer(protocol="shadowsocks")
        proxy_task = asyncio.create_task(
            proxy.start(host=Config.PROXY_HOST, port=Config.PROXY_PORT)
        )
        logger.info("✅ Proxy server task created")
    except Exception as e:
        logger.error(f"❌ Failed to start proxy server: {e}")
        await bot.session.close()
        return

    # Start bot polling
    logger.info("✅ Starting bot polling...")
    try:
        await dp.start_polling(bot)
    except KeyboardInterrupt:
        logger.info("⏹️ Stopping bot...")
    finally:
        proxy_task.cancel()
        await bot.session.close()
        logger.info("✅ Shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Goodbye!")
