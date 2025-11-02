@echo off

echo Starting Shadowsocks proxy server...
start /B python -u proxy_server.py

if not "%BOT_TOKEN%"=="" (
    echo Starting Telegram bot...
    cd bot
    start /B python -u main.py
    cd ..
) else (
    echo BOT_TOKEN not set, skipping bot startup
)

echo Services started. Press Ctrl+C to stop.
pause
