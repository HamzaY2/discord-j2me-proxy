#!/bin/bash
set -e

# Start the proxy service
node /app/proxy/index.js &

# Start the websocket service
node /app/websocket/out/index.js &

# Start NGINX in the foreground
exec nginx -g 'daemon off;'

wait