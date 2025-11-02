#!/bin/bash

# Start proxy server in background
echo "Starting Shadowsocks proxy server..."
python -u proxy_server.py &
PROXY_PID=$!

# Check if BOT_TOKEN is set and start bot
if [ ! -z "$BOT_TOKEN" ]; then
    echo "Starting Telegram bot..."
    cd bot
    python -u main.py &
    BOT_PID=$!
    cd ..
else
    echo "BOT_TOKEN not set, skipping bot startup"
fi

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
