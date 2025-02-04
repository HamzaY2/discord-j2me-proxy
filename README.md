# HTTP proxy for Discord J2ME
Discord API proxy which reduces data transfers by up to 90% by not sending data that the Discord J2ME client doesn't use.

npm i emoji-js@3.8.1

## Proxy Installation ./proxy
1. Install Node.js.
2. Open a terminal in this directory and run `npm i`.
3. If you want to use a different port, change the `PORT` variable near the top of index.js.
4. Run `node .` to start the server.

## Websocket Installation ./websocket
1. Install Node.js.
2. Open a terminal in this directory and run `npm i`.
3. Then run `npm run build` to build the client.
4. Then run `node out` to start the server.