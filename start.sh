#!/bin/bash
set -e

start_proxy() {
  echo "Starting frontend..."
  cd /app/proxy
  node .
}

start_websocket() {
  echo "Starting frontend..."
  cd /app/websocket
  node out
}

start_nginx() {
  echo "Starting nginx..."
  nginx -g "daemon off;"
}

start_proxy &
start_websocket &
start_nginx &
wait