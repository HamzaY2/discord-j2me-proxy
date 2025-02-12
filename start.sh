#!/bin/bash
set -e

echo "Starting frontend (proxy)..."
cd /app/proxy
node . &  # Run in background
PROXY_PID=$!

echo "Starting frontend (websocket)..."
cd /app/websocket
node out &  # Run in background
WEBSOCKET_PID=$!

echo "Starting nginx..."
nginx -g "daemon off;"

wait