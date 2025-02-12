import asyncio
import json
import re
import os
import logging
import aiohttp
import websockets
import emoji

# Set up logging
logging.basicConfig(level=logging.INFO)

# Global default headers (used for HTTP requests)
default_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "X-Debug-Options": "bugReporterEnabled",
    "X-Discord-Locale": "en-GB",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin"
}


# --- Emoji and Message Parsing Functions ---

def parse_message_content(content: str, show_guild_emoji: bool) -> str:
    """
    Process the message content:
      - If show_guild_emoji is False, replaces Discord’s guild emoji format (<:name:12345...>)
        with a simpler :name: form.
      - Converts Unicode emojis to their :name: representation.
      - Converts regional indicator emojis into :regional_indicator_x: form.
    """
    if not show_guild_emoji:
        content = re.sub(r'<a?(:\w*:)\d{15,}>', r'\1', content)

    # Convert unicode emojis to text (e.g., 😄 -> :smiling_face_with_smiling_eyes:)
    content = emoji.demojize(content)

    # Convert regional indicator symbols (U+1F1E6 to U+1F1FF) into :regional_indicator_x:
    def replace_regional(match):
        ch = match.group(0)
        codepoint = ord(ch)
        letter = chr(codepoint - 0x1F1E6 + ord('a'))
        return f":regional_indicator_{letter}:"

    content = re.sub(r'([\U0001F1E6-\U0001F1FF])', replace_regional, content)
    return content


def parse_message_object(msg: dict, show_guild_emoji: bool) -> dict:
    """
    Transforms a Discord message object into a simplified dictionary.
    """
    result = {
        "id": msg.get("id"),
        "channel_id": msg.get("channel_id"),
        "guild_id": msg.get("guild_id")
    }

    if "author" in msg:
        author = msg["author"]
        result["author"] = {
            "id": author.get("id"),
            "avatar": author.get("avatar"),
            "global_name": author.get("global_name")
        }
        if author.get("global_name") is None:
            result["author"]["username"] = author.get("username")

    if "type" in msg and 1 <= msg["type"] <= 11:
        result["type"] = msg["type"]

    if "content" in msg:
        parsed_content = parse_message_content(msg["content"], show_guild_emoji)
        result["content"] = parsed_content
        if parsed_content != msg["content"]:
            result["_rc"] = msg["content"]

    if "referenced_message" in msg and msg["referenced_message"]:
        ref_msg = msg["referenced_message"]
        content = parse_message_content(ref_msg.get("content", ""), show_guild_emoji)
        # Replace newlines with spaces (reply is shown as one line)
        content = re.sub(r'\r\n|\r|\n', "  ", content)
        if content and len(content) > 50:
            content = content[:47].strip() + '...'
        result["referenced_message"] = {
            "author": {
                "global_name": ref_msg["author"].get("global_name"),
                "id": ref_msg["author"].get("id"),
                "avatar": ref_msg["author"].get("avatar")
            },
            "content": content
        }
        if ref_msg["author"].get("global_name") is None:
            result["referenced_message"]["author"]["username"] = ref_msg["author"].get("username")

    if "attachments" in msg and msg["attachments"]:
        result["attachments"] = [{
            "filename": att.get("filename"),
            "size": att.get("size"),
            "width": att.get("width"),
            "height": att.get("height"),
            "proxy_url": att.get("proxy_url")
        } for att in msg["attachments"]]

    if "sticker_items" in msg and msg["sticker_items"]:
        result["sticker_items"] = [{"name": msg["sticker_items"][0].get("name")}]

    if "embeds" in msg and msg["embeds"]:
        result["embeds"] = [{
            "title": emb.get("title"),
            "description": emb.get("description")
        } for emb in msg["embeds"]]

    if "mentions" in msg and msg["mentions"]:
        mentions = []
        for ment in msg["mentions"]:
            mention_obj = {
                "id": ment.get("id"),
                "global_name": ment.get("global_name")
            }
            if ment.get("global_name") is None:
                mention_obj["username"] = ment.get("username")
            mentions.append(mention_obj)
        result["mentions"] = mentions

    return result


# --- Client Class ---

class Client:
    """
    Represents a connected TCP client.
    """
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, initial_data: bytes = b""):
        self.reader = reader
        self.writer = writer
        self.buffer = initial_data  # Pre-read bytes from the client (if any)
        self.websocket = None  # Will hold the websockets connection object
        self.gateway_task = None  # Task for receiving messages from the gateway
        self.supported_events = []
        self.show_guild_emoji = False
        self.token = None
        self.lock = asyncio.Lock()  # Ensures safe writes to the TCP stream

    async def handle_connection(self):
        # Start the task to receive messages from the client.
        asyncio.create_task(self.client_receiver())
        # Send initial greeting message to the client.
        await self.send_object({
            "op": -1,
            "t": "GATEWAY_HELLO"
        })

    async def client_receiver(self):
        try:
            while True:
                # Read data until a newline is found.
                while b'\n' not in self.buffer:
                    data = await self.reader.read(4096)
                    if not data:
                        break
                    self.buffer += data
                if not self.buffer:
                    break
                if b'\n' in self.buffer:
                    line, self.buffer = self.buffer.split(b'\n', 1)
                else:
                    line = self.buffer
                    self.buffer = b""
                message = line.decode('utf-8', errors='replace').strip()
                if message:
                    await self.handle_message(message)
        except Exception as e:
            logging.exception("Error receiving data from client:")
        finally:
            await self.handle_close()

    async def handle_message(self, message: str):
        logging.info("Received message from client: %s", message)
        try:
            parsed = json.loads(message)
            # If op is -1, then it’s a proxy command from the client.
            if "op" in parsed and parsed["op"] == -1:
                await self.handle_proxy_message(parsed)
            else:
                # If a token is provided, save it.
                d = parsed.get("d")
                if isinstance(d, dict) and "token" in d:
                    self.token = d["token"]
                # Forward the message to the WebSocket if connected.
                if self.websocket:
                    try:
                        await self.websocket.send(message)
                    except Exception as e:
                        logging.exception("Error sending message to gateway:")
        except Exception as e:
            logging.exception("Error handling client message:")

    async def handle_proxy_message(self, payload: dict):
        t = payload.get("t")
        d = payload.get("d")
        if t == "GATEWAY_CONNECT":
            if d:
                self.supported_events = d.get("supported_events", [])
                url = d.get("url")
                if url:
                    await self.connect_gateway(url)
        elif t == "GATEWAY_DISCONNECT":
            if self.websocket:
                try:
                    await self.websocket.close()
                except Exception:
                    pass
                self.websocket = None
        elif t == "GATEWAY_UPDATE_SUPPORTED_EVENTS":
            if d:
                self.supported_events = d.get("supported_events", [])
        elif t == "GATEWAY_SHOW_GUILD_EMOJI":
            self.show_guild_emoji = bool(d)
        elif t == "GATEWAY_SEND_TYPING":
            channel_id = str(d)
            if not re.fullmatch(r"\d{17,30}", channel_id):
                return
            try:
                headers = default_headers.copy()
                if self.token:
                    headers["Authorization"] = self.token
                url = f"https://discord.com/api/v9/channels/{channel_id}/typing"
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, headers=headers, data="") as resp:
                        await resp.text()  # consume the response
            except Exception as e:
                logging.exception("Error sending typing indicator:")

    async def connect_gateway(self, gateway_url: str):
        try:
            self.websocket = await websockets.connect(gateway_url)
            # Start the task to receive messages from the gateway.
            self.gateway_task = asyncio.create_task(self.gateway_receiver(self.websocket))
        except Exception as e:
            logging.exception("Error connecting to gateway:")

    async def gateway_receiver(self, ws):
        try:
            async for message in ws:
                try:
                    parsed = json.loads(message)
                    t = parsed.get("t")
                    # When the READY event is received, send back a J2ME_READY with the user ID.
                    if t == "READY":
                        user_id = parsed.get("d", {}).get("user", {}).get("id")
                        if user_id:
                            await self.send_object({
                                "op": -1,
                                "t": "J2ME_READY",
                                "d": {"id": user_id}
                            })
                    elif ((t == "MESSAGE_CREATE" and "J2ME_MESSAGE_CREATE" in self.supported_events) or
                          (t == "MESSAGE_UPDATE" and "J2ME_MESSAGE_UPDATE" in self.supported_events)):
                        parsed_data = parse_message_object(parsed.get("d", {}), self.show_guild_emoji)
                        await self.send_object({
                            "op": -1,
                            "t": "J2ME_" + t,
                            "d": parsed_data
                        })
                    elif (not t or not self.supported_events or t in self.supported_events):
                        await self.send_message(message)
                except Exception as e:
                    logging.exception("Error handling gateway message:")
        except Exception as e:
            logging.error("WebSocket error: %s", e)
            await self.send_object({
                "op": -1,
                "t": "GATEWAY_DISCONNECT",
                "d": {"message": str(e)}
            })
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        finally:
            logging.info("WebSocket closed")
            await self.send_object({
                "op": -1,
                "t": "GATEWAY_DISCONNECT",
                "d": {"message": "WebSocket closed"}
            })
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass

    async def send_message(self, data: str):
        logging.info("Sending to client: %s", data)
        try:
            async with self.lock:
                self.writer.write((data + "\n").encode("utf-8"))
                await self.writer.drain()
        except Exception as e:
            logging.exception("Error sending message to client:")

    async def send_object(self, obj: dict):
        await self.send_message(json.dumps(obj))

    async def handle_close(self):
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception:
                pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


# --- HTTP Request Handler ---

async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, initial: bytes):
    """
    Handles an HTTP GET request.
    If the request is for the root ("/"), responds with HTTP 200 and a simple message.
    Otherwise, returns a 404 Not Found.
    """
    try:
        # Read the rest of the HTTP request.
        rest = await reader.read(1024)
        request = initial + rest
        request_str = request.decode("utf-8", errors="replace")
    except Exception as e:
        logging.exception("Error reading HTTP request:")
        writer.close()
        await writer.wait_closed()
        return

    request_line = request_str.splitlines()[0] if request_str.splitlines() else ""
    parts = request_line.split()
    if len(parts) >= 2 and parts[0] == "GET" and parts[1] == "/":
        response_body = "J2ME Discord Socket Server"
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{response_body}"
        )
    else:
        response = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
    try:
        writer.write(response.encode("utf-8"))
        await writer.drain()
    except Exception as e:
        logging.exception("Error sending HTTP response:")
    finally:
        writer.close()
        await writer.wait_closed()


# --- TCP Server Setup ---

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        # Read the first 4 bytes to check if the connection is an HTTP GET request.
        initial = await reader.read(4)
        try:
            print("initial_data: " + initial.decode('utf-8', errors='replace'))
        except Exception:
            pass

        if initial.startswith(b"GET "):
            await handle_http(reader, writer, initial)
        else:
            client = Client(reader, writer, initial)
            await client.handle_connection()
    except Exception as e:
        logging.exception("Error in handle_client:")
        writer.close()
        await writer.wait_closed()


async def main():
    WS_PORT = int(os.environ.get("WS_PORT", 8081))
    server = await asyncio.start_server(handle_client, host="", port=WS_PORT)
    logging.info("TCP server is listening on port %d.", WS_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
