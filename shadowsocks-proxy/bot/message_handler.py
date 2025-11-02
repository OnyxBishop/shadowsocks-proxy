import json
import base64
from pathlib import Path
from datetime import datetime, timezone

from aiogram import Router, F
from aiogram.types import CallbackQuery
from ss_password_utils import generate_ss_password, generate_credentials
from config import Config

router = Router()
USERS_FILE = Path(__file__).parent.parent / "users.json"


def load_users():
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_user(user_id, username, ss_password):
    users = load_users()
    users[str(user_id)] = {
        "user_id": user_id,
        "username": username,
        "ss_password": ss_password,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


@router.callback_query(F.data == "auto_config")
async def auto_config_callback(callback: CallbackQuery):
    if callback.from_user.id not in Config.admin_ids():
        await callback.answer("Доступ запрещён", show_alert=True)
        return

    users = load_users()
    user_id = callback.from_user.id
    
    if str(user_id) in users:
        user_data = users[str(user_id)]
        username = user_data["username"]
        ss_pass = user_data["ss_password"]
    else:
        username = generate_credentials()
        ss_pass = generate_ss_password(username=username, master_secret=Config.SS_Master_Secret)
        save_user(user_id, username, ss_pass)

    userinfo = f"{Config.SS_Method}:{ss_pass}"
    userinfo_b64 = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip('=')
    remark = "Ramee_VPN"
    ss_link = f"ss://{userinfo_b64}@{Config.PROXY_HOST}:{Config.PROXY_PORT}#{remark}"

    await callback.message.answer(
        f"✅ Конфигурация готова!\n\n"
        f"Скопируйте ссылку и вставьте в приложение (V2Box, Shadowrocket и т.д.):  \n\n"
        f"<code>{ss_link}</code>",
        parse_mode="HTML"
    )
    await callback.answer()


@router.callback_query(F.data == "show_creds")
async def show_creds_callback(callback: CallbackQuery):
    if callback.from_user.id not in Config.admin_ids():
        await callback.answer("Доступ запрещён", show_alert=True)
        return

    users = load_users()
    user_id = callback.from_user.id
    
    if str(user_id) in users:
        user_data = users[str(user_id)]
        username = user_data["username"]
        ss_pass = user_data["ss_password"]
    else:
        username = generate_credentials()
        ss_pass = generate_ss_password(username=username, master_secret=Config.SS_Master_Secret)
        save_user(user_id, username, ss_pass)

    await callback.message.answer(
        f"🔑 Ваши учетные данные:\n\n"
        f"Username: <code>{username}</code>\n"
        f"Password: <code>{ss_pass}</code>\n\n"
        f"Server: <code>{Config.PROXY_HOST}:{Config.PROXY_PORT}</code>\n"
        f"Method: <code>{Config.SS_Method}</code>",
        parse_mode="HTML"
    )
    await callback.answer()
