#!/bin/bash
set -e

echo "Starting frontend..."
cd /app/proxy
node .

echo "Starting frontend..."
cd /app/websocket
node out

echo "Starting nginx..."
nginx -g "daemon off;"

wait