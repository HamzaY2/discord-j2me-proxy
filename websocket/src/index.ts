import { createServer } from 'net';
import { Client } from "./Client";

const { WS_PORT = 8081 } = process.env;

const server = createServer((socket) => {
    new Client(socket).handleConnection();
});

server.listen(WS_PORT, () => {
    console.log(`TCP server is listening on port ${WS_PORT}.`);
});