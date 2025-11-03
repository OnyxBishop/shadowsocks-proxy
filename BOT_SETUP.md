# Telegram Bot Setup Guide

## Prerequisites

1. Get a bot token from [@BotFather](https://t.me/botfather)
2. Get your Telegram user ID from [@userinfobot](https://t.me/userinfobot)

## Setup

### Option 1: Docker (Recommended)

1. Edit `.env` file:
```bash
SS_MASTER_SECRET=your_generated_secret
BOT_TOKEN=your_bot_token_here
PROXY_HOST=your.server.com
ADMIN_IDS=123456789
SS_METHOD=chacha20-ietf-poly1305
```

2. Start services:
```bash
docker-compose up -d
```

The bot will start automatically alongside the proxy server.

### Option 2: Manual (Development)

1. Install dependencies:
```bash
cd shadowsocks-proxy
pip install -r requirements.txt
cd bot
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export SS_MASTER_SECRET="your_secret"
export BOT_TOKEN="your_bot_token"
export PROXY_HOST="your.server.com"
export ADMIN_IDS="123456789"
export SS_METHOD="chacha20-ietf-poly1305"
```

3. Start the proxy server:
```bash
cd shadowsocks-proxy
python proxy_server.py &
```

4. Start the bot:
```bash
cd shadowsocks-proxy/bot
python main.py
```

### Option 3: Using Startup Scripts

**Linux/Mac:**
```bash
cd shadowsocks-proxy
./start.sh.save
```

**Windows:**
```cmd
cd shadowsocks-proxy
start.bat
```

## Usage

1. Send `/start` to your bot
2. Click "🔗 Авто-конфигурация" to get an SS link
3. Copy the link and paste it into your Shadowsocks client (V2Box, Shadowrocket, etc.)

## How It Works

1. Bot generates unique username for each Telegram user
2. Password is derived from username using HMAC-SHA256
3. User data is saved to `users.json`
4. Shadowsocks server reads `users.json` to authenticate connections
5. Each user gets their own credentials that work across all devices

## Troubleshooting

### Bot doesn't start
- Check `BOT_TOKEN` is set correctly
- Verify bot token is valid with @BotFather
- Check logs for error messages

### "Доступ запрещён" (Access denied)
- Make sure your Telegram user ID is in `ADMIN_IDS`
- IDs should be comma-separated: `ADMIN_IDS=123456789,987654321`

### Connection fails
- Verify `PROXY_HOST` matches your server's IP/domain
- Check port 1080 is open and accessible
- Ensure `SS_MASTER_SECRET` is the same for bot and proxy

## Files

- `users.json` - Stored user credentials (auto-created)
- `bot/main.py` - Bot entry point
- `bot/message_handler.py` - Command handlers
- `bot/keyboard.py` - Inline keyboard
- `bot/config.py` - Configuration
- `bot/ss_password_utils.py` - Password generation
