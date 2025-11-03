import httpx

from aiogram import Router, F
from aiogram.types import CallbackQuery
from config import Config

router = Router()


@router.callback_query(F.data == "get_outline_key")
async def get_outline_key_callback(callback: CallbackQuery):
    if callback.from_user.id not in Config.admin_ids():
        await callback.answer("Доступ запрещён", show_alert=True)
        return

    api_url = Config.OUTLINE_API_URL
    if not api_url:
        await callback.message.answer("Ошибка: URL API Outline не настроен.")
        await callback.answer()
        return

    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(f"{api_url}/access-keys", timeout=10.0)
            response.raise_for_status()
            key_data = response.json()

            # Извлекаем нужные данные из ответа API
            # Пример успешного ответа:
            # {
            #   "id": "12345",
            #   "name": "My Key",
            #   "password": "some_password",
            #   "port": 12345,
            #   "method": "chacha20-ietf-poly1305",
            #   "accessUrl": "ss://abcd...==@1.2.3.4:12345",
            #   "streamingUrl": "ss://abcd...==@1.2.3.4:12345",
            #   "dataLimit": null,
            #   "usedBytes": 0,
            #   "createdTimestampMs": 1234567890123,
            #   "lastUsedTimestampMs": null
            # }

            # Используем accessUrl для отправки пользователю, так как он содержит все данные для подключения
            access_url = key_data.get('accessUrl', '')
            key_name = key_data.get('name', 'Безымянный ключ (ID: ' + str(key_data.get('id', 'N/A')) + ')')

            if not access_url:
                await callback.message.answer("Ошибка: Не удалось получить URL доступа из API Outline.")
                await callback.answer()
                return

            # Отправляем URL ключа пользователю
            await callback.message.answer(
                f"🔑 Новый ключ доступа Outline:\n\n"
                f"Название: <code>{key_name}</code>\n\n"
                f"Скопируйте и используйте этот URL в клиенте Outline:\n"
                f"<code>{access_url}</code>",
                parse_mode="HTML"
            )

    except httpx.HTTPStatusError as e:
        await callback.message.answer(f"Ошибка API Outline (HTTP {e.response.status_code}): {e.response.text}")
    except httpx.RequestError as e:
        await callback.message.answer(f"Ошибка запроса к API Outline: {str(e)}")
    except Exception as e:
        await callback.message.answer(f"Произошла непредвиденная ошибка: {str(e)}")

    await callback.answer()
