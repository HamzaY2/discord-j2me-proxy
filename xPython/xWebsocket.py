# deploy this app on Render.com

import socket
import threading
import json
import re
import os
import requests
import logging
import websocket  # from the websocket-client package
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
    def __init__(self, client_socket: socket.socket):
        self.socket = client_socket
        self.websocket = None  # Will hold a websocket.WebSocketApp instance
        self.supported_events = []
        self.show_guild_emoji = False
        self.token = None
        self.buffer = b""
        self.lock = threading.Lock()  # Ensures safe writes to the TCP socket
    
    def handle_connection(self):
        threading.Thread(target=self.create_message_receiver, daemon=True).start()
        # Send initial greeting message to the client.
        self.send_object({
            "op": -1,
            "t": "GATEWAY_HELLO"
        })
    
    def create_message_receiver(self):
        try:
            while True:
                data = self.socket.recv(4096)
                if not data:
                    break
                self.buffer += data
                while b'\n' in self.buffer:
                    line, self.buffer = self.buffer.split(b'\n', 1)
                    message = line.decode('utf-8', errors='replace')
                    self.handle_message(message)
        except Exception as e:
            logging.exception("Error receiving data from client:")
        finally:
            self.handle_close()
    
    def handle_close(self):
        if self.websocket:
            try:
                self.websocket.close()
            except Exception:
                pass
        try:
            self.socket.close()
        except Exception:
            pass
    
    def handle_message(self, message: str):
        logging.info("Received message from client: %s", message)
        try:
            parsed = json.loads(message)
            # If op is -1, then it’s a proxy command from the client.
            if "op" in parsed and parsed["op"] == -1:
                self.handle_proxy_message(parsed)
            else:
                # If a token is provided, save it.
                d = parsed.get("d")
                if isinstance(d, dict) and "token" in d:
                    self.token = d["token"]
                # Forward the message to the WebSocket if connected.
                if self.websocket:
                    self.websocket.send(message)
        except Exception as e:
            logging.exception("Error handling client message:")
    
    def handle_proxy_message(self, payload: dict):
        t = payload.get("t")
        d = payload.get("d")
        if t == "GATEWAY_CONNECT":
            if d:
                self.supported_events = d.get("supported_events", [])
                url = d.get("url")
                if url:
                    self.connect_gateway(url)
        elif t == "GATEWAY_DISCONNECT":
            if self.websocket:
                self.websocket.close()
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
                requests.post(url, headers=headers, data="")  # POST with an empty body
            except Exception as e:
                logging.exception("Error sending typing indicator:")
    
    def connect_gateway(self, gateway_url: str):
        def on_message(ws, message):
            try:
                parsed = json.loads(message)
                t = parsed.get("t")
                # When the READY event is received, send back a J2ME_READY with the user ID.
                if t == "READY":
                    user_id = parsed.get("d", {}).get("user", {}).get("id")
                    if user_id:
                        self.send_object({
                            "op": -1,
                            "t": "J2ME_READY",
                            "d": {"id": user_id}
                        })
                elif ((t == "MESSAGE_CREATE" and "J2ME_MESSAGE_CREATE" in self.supported_events) or
                      (t == "MESSAGE_UPDATE" and "J2ME_MESSAGE_UPDATE" in self.supported_events)):
                    parsed_data = parse_message_object(parsed.get("d", {}), self.show_guild_emoji)
                    self.send_object({
                        "op": -1,
                        "t": "J2ME_" + t,
                        "d": parsed_data
                    })
                elif (not t or not self.supported_events or t in self.supported_events):
                    self.send_message(message)
            except Exception as e:
                logging.exception("Error handling gateway message:")
        
        def on_error(ws, error):
            logging.error("WebSocket error: %s", error)
            self.send_object({
                "op": -1,
                "t": "GATEWAY_DISCONNECT",
                "d": {"message": str(error)}
            })
            try:
                self.socket.close()
            except Exception:
                pass
        
        def on_close(ws, close_status_code, close_msg):
            logging.info("WebSocket closed: %s %s", close_status_code, close_msg)
            self.send_object({
                "op": -1,
                "t": "GATEWAY_DISCONNECT",
                "d": {"message": str(close_msg)}
            })
            try:
                self.socket.close()
            except Exception:
                pass
        
        self.websocket = websocket.WebSocketApp(
            gateway_url,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        
        # Run the WebSocket connection in a new thread.
        def run_ws():
            try:
                self.websocket.run_forever()
            except Exception as e:
                logging.exception("Exception in WebSocket run_forever:")
        threading.Thread(target=run_ws, daemon=True).start()
    
    def send_message(self, data: str):
        logging.info("Sending to client: %s", data)
        try:
            with self.lock:
                self.socket.sendall((data + "\n").encode("utf-8"))
        except Exception as e:
            logging.exception("Error sending message to client:")
    
    def send_object(self, obj: dict):
        self.send_message(json.dumps(obj))

# --- HTTP Request Handler ---

def handle_http(client_socket: socket.socket):
    """
    Handles an HTTP GET request.
    If the request is for the root ("/"), responds with HTTP 200 and "live".
    Otherwise, returns a 404 Not Found.
    """
    try:
        request = client_socket.recv(1024).decode("utf-8", errors="replace")
    except Exception as e:
        logging.exception("Error reading HTTP request:")
        client_socket.close()
        return

    request_line = request.splitlines()[0] if request.splitlines() else ""
    parts = request_line.split()
    if len(parts) >= 2 and parts[0] == "GET" and parts[1] == "/":
        response_body = "live"
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
        client_socket.sendall(response.encode("utf-8"))
    except Exception as e:
        logging.exception("Error sending HTTP response:")
    finally:
        client_socket.close()

# --- TCP Server Setup ---

def handle_client(client_socket: socket.socket, address):
    # Check if the connection is an HTTP GET request (using MSG_PEEK)
    try:
        client_socket.settimeout(0.5)
        initial_data = client_socket.recv(1024, socket.MSG_PEEK)
    except Exception as e:
        initial_data = b""
    finally:
        client_socket.settimeout(None)
    
    # If the request starts with "GET ", handle as an HTTP request.
    if initial_data.startswith(b"GET "):
        handle_http(client_socket)
    else:
        client = Client(client_socket)
        client.handle_connection()

def start_tcp_server():
    WS_PORT = int(os.environ.get("WS_PORT", 8081))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", WS_PORT))
    server_socket.listen(5)
    logging.info("TCP server is listening on port %d.", WS_PORT)
    try:
        while True:
            client_sock, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_tcp_server()
