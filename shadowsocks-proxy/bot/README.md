# Telegram Bot для Shadowsocks Proxy

## Описание

Telegram бот для автоматической генерации учетных данных Shadowsocks и выдачи ссылок для подключения.

## Установка

### 1. Установите зависимости

```bash
cd shadowsocks-proxy/bot
pip install -r requirements.txt
```

### 2. Настройте переменные окружения

Создайте `.env` файл в корне проекта:

```bash
# Токен бота от @BotFather
BOT_TOKEN=your_bot_token_here

# Адрес и порт вашего Shadowsocks сервера
PROXY_HOST=your.server.com
PROXY_PORT=1080

# Мастер-секрет (тот же, что используется в proxy_server)
SS_MASTER_SECRET=your_master_secret_here

# Метод шифрования
SS_METHOD=chacha20-ietf-poly1305

# ID администраторов (через запятую)
ADMIN_IDS=123456789,987654321
```

### 3. Запустите бота

```bash
python main.py
```

## Использование

1. Отправьте команду `/start` боту
2. Нажмите кнопку "🔗 Авто-конфигурация" для получения ссылки SS
3. Скопируйте ссылку и вставьте в приложение (V2Box, Shadowrocket и т.д.)

Либо нажмите "🔑 Показать данные" для получения username и password.

## Файлы

- `main.py` - Главный файл бота с инициализацией
- `message_handler.py` - Обработчики сообщений
- `keyboard.py` - Клавиатуры бота
- `config.py` - Конфигурация
- `ss_password_utils.py` - Утилиты для генерации паролей

## Хранение данных

Все пользователи сохраняются в `../users.json` в формате:

```json
{
  "123456789": {
    "user_id": 123456789,
    "username": "Ramee_vpn_1234567890_abc123",
    "ss_password": "generated_password_hash",
    "created_at": "2024-01-01T00:00:00+00:00"
  }
}
```

Этот же файл читается `shadowsocks_handler.py` для аутентификации подключений.
