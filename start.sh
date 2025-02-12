#!/bin/bash
set -e

run() {
  local workdir="$1"
  local message="$2"
  shift 2
  echo "$message"
  if [ -n "$workdir" ]; then
    (cd "$workdir" && exec "$@")
  else
    exec "$@"
  fi
}

# Start each service in the background.
run "/app/proxy" "Starting proxy..." node . &
run "/app/websocket" "Starting websocket..." node out &
run "" "Starting nginx..." nginx -g "daemon off;" &

wait