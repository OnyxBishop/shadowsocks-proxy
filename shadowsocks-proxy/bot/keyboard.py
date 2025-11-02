from aiogram.types import InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder


def get_keyboard() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🔗 Авто-конфигурация", callback_data="auto_config")
    kb.button(text="🔑 Показать данные", callback_data="show_creds")
    kb.adjust(1)
    return kb.as_markup()
