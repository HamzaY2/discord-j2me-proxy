import re
import json
import secrets
import bleach
import logging
from datetime import datetime, timedelta

import httpx
import emoji as pemoji

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

# Global caches and constants
upload_tokens = {}    # maps upload token string -> { "token": <str>, "expires": datetime }
user_cache = {}       # maps user id -> username
channel_cache = {}    # maps channel id -> channel name
CACHE_SIZE = 10000

PORT = 8080
BASE = "/api/v9"
BASE_L = "/api/l"
DEST_BASE = "https://discord.com/api/v9"

# Helper: JSON stringifier with unicode escaping (like ensure_ascii)
def stringify_unicode(obj):
    return json.dumps(obj, ensure_ascii=True)

# Helper: get token from an “upload token”
def get_token_from_upload_token(token: str) -> str:
    if not token.startswith("j2me-"):
        return token
    token_info = upload_tokens.get(token)
    if not token_info:
        return token
    if datetime.utcnow() > token_info["expires"]:
        return token
    return token_info["token"]

# Dependency: extract token from query/headers/body and build headers
async def get_token_dependency(request: Request):
    token = request.query_params.get("token")
    if not token:
        token = request.headers.get("authorization")
    if not token:
        try:
            body = await request.json()
        except Exception:
            body = {}
        token = body.get("token")
    upload_token_local = None
    if request.url.path.startswith(f"{BASE}/channels/") and request.url.path.endswith("/upload"):
        upload_token_local = token
        token = get_token_from_upload_token(token)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Authorization": token,
        "X-Discord-Locale": "en-GB",
        "X-Debug-Options": "bugReporterEnabled",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    }
    return {"headers": headers, "upload_token": upload_token_local}

# Parse a message’s content – convert Discord mention and emoji formats
def parse_message_content(content: str, show_guild_emoji: bool, convert_tags: bool = True) -> str:
    if not content:
        return content
    result = content
    if convert_tags:
        def replace_mention(match):
            uid = match.group(1)
            return "@" + user_cache.get(uid, uid)
        result = re.sub(r"<@(\d{15,})>", replace_mention, result)

        def replace_channel(match):
            cid = match.group(1)
            return "#" + channel_cache.get(cid, cid)
        result = re.sub(r"<#(\d{15,})>", replace_channel, result)
    if not show_guild_emoji:
        # Replace Discord’s animated/static emoji markup with simple :name:
        result = re.sub(r"<a?(:\w*:)\d{15,}>", r"\1", result)
    # Replace Unicode emoji with colon names (e.g. 😀 → :grinning_face:)
    result = pemoji.demojize(result)
    # Also replace regional indicator symbols with :regional_indicator_x:
    def replace_regional(match):
        ch = match.group(0)
        code = ord(ch) - 0x1F1E6
        return f":regional_indicator_{chr(97 + code)}:"
    result = re.sub(r"[\U0001F1E6-\U0001F1FF]", replace_regional, result)
    return result

# Parse a full message object from Discord into our desired format
def parse_message_object(msg: dict, request: Request, show_guild_emoji: bool, show_edited: bool) -> dict:
    result = {"id": msg.get("id")}
    if show_edited and msg.get("edited_timestamp"):
        result["edited_timestamp"] = msg["edited_timestamp"]
    if "author" in msg:
        author = msg["author"]
        result["author"] = {
            "id": author.get("id"),
            "avatar": author.get("avatar"),
            "global_name": author.get("global_name")
        }
        if author.get("global_name") is None or request.query_params.get("droidcord"):
            result["author"]["username"] = author.get("username")
    if 1 <= msg.get("type", 0) <= 11:
        result["type"] = msg.get("type")
    if msg.get("content"):
        parsed = parse_message_content(msg.get("content"), show_guild_emoji)
        result["content"] = parsed
        if parsed != msg.get("content"):
            result["_rc"] = msg.get("content")
    if msg.get("referenced_message"):
        ref_msg = msg["referenced_message"]
        content = parse_message_content(ref_msg.get("content", ""), show_guild_emoji)
        content = re.sub(r"[\r\n]+", "  ", content)
        if show_guild_emoji:
            new_content = content[:80]
            i = 81
            while i < len(content) and new_content.rfind(">") < new_content.rfind("<"):
                new_content = content[:i]
                i += 1
            content = new_content
        else:
            if content and len(content) > 50:
                content = content[:47].strip() + "..."
        result["referenced_message"] = {
            "author": {
                "global_name": ref_msg["author"].get("global_name"),
                "id": ref_msg["author"].get("id"),
                "avatar": ref_msg["author"].get("avatar")
            },
            "content": content
        }
        if ref_msg["author"].get("global_name") is None or request.query_params.get("droidcord"):
            result["referenced_message"]["author"]["username"] = ref_msg["author"].get("username")
    if msg.get("attachments"):
        atts = []
        for att in msg["attachments"]:
            ret = {
                "filename": att.get("filename"),
                "size": att.get("size"),
                "width": att.get("width"),
                "height": att.get("height"),
                "proxy_url": att.get("proxy_url")
            }
            if request.query_params.get("droidcord"):
                ret["content_type"] = att.get("content_type")
            atts.append(ret)
        result["attachments"] = atts
    if msg.get("sticker_items"):
        result["sticker_items"] = [{"name": msg["sticker_items"][0].get("name")}]
    if msg.get("embeds"):
        embeds = []
        for emb in msg["embeds"]:
            ret = {
                "title": parse_message_content(emb.get("title", ""), True, False),
                "description": parse_message_content(emb.get("description", ""), True, False)
            }
            if request.query_params.get("droidcord"):
                ret["url"] = emb.get("url")
                ret["author"] = emb.get("author")
                ret["provider"] = emb.get("provider")
                ret["footer"] = emb.get("footer")
                ret["timestamp"] = emb.get("timestamp")
                ret["color"] = emb.get("color")
                ret["thumbnail"] = emb.get("thumbnail")
                ret["image"] = emb.get("image")
                ret["video"] = emb.get("video")
                ret["fields"] = emb.get("fields")
            embeds.append(ret)
        result["embeds"] = embeds
    if msg.get("type") in [1, 2] and msg.get("mentions"):
        mention = msg["mentions"][0]
        result["mentions"] = [{
            "id": mention.get("id"),
            "global_name": mention.get("global_name")
        }]
        if mention.get("global_name") is None:
            result["mentions"][0]["username"] = mention.get("username")
    return result

# Helpers to generate a “lite” user ID hash
def base36encode(number: int) -> str:
    alph = "0123456789abcdefghijklmnopqrstuvwxyz"
    if number == 0:
        return "0"
    result = ""
    while number:
        number, i = divmod(number, 36)
        result = alph[i] + result
    return result

def generate_lite_id_hash(id_str: str) -> str:
    try:
        num = int(id_str)
    except Exception:
        num = 0
    mod = num % 100000
    return base36encode(mod)

# Generate an upload token (which is a “j2me-…” string valid for 7 days)
def generate_upload_token(token: str) -> str:
    rand_hex = secrets.token_hex(16)
    result = "j2me-" + rand_hex
    expires = datetime.utcnow() + timedelta(days=7)
    upload_tokens[result] = {"token": token, "expires": expires}
    return result

# Create the FastAPI app and mount the static folder.
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

###############################################################################
# API Endpoints (Full and Lite)
###############################################################################

# GET /api/v9/users/@me/guilds
@app.get(f"{BASE}/users/@me/guilds")
async def get_guilds(token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/users/@me/guilds", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        guilds = []
        for g in r.json():
            item = {"id": g.get("id"), "name": g.get("name")}
            if g.get("icon") is not None:
                item["icon"] = g.get("icon")
            guilds.append(item)
        return Response(content=stringify_unicode(guilds), media_type="application/json")

# GET /api/v9/guilds/{guild}/channels
@app.get(f"{BASE}/guilds/{{guild}}/channels")
async def get_guild_channels(guild: str, token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/guilds/{guild}/channels", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        channels_data = r.json()
        # Populate channel cache
        for ch in channels_data:
            channel_cache[ch.get("id")] = ch.get("name")
            if len(channel_cache) > CACHE_SIZE:
                oldest = next(iter(channel_cache))
                del channel_cache[oldest]
        channels = []
        for ch in channels_data:
            if ch.get("type") in [0, 5, 15, 16]:
                channels.append({
                    "id": ch.get("id"),
                    "type": ch.get("type"),
                    "guild_id": ch.get("guild_id"),
                    "name": ch.get("name"),
                    "position": ch.get("position"),
                    "last_message_id": ch.get("last_message_id")
                })
        return Response(content=stringify_unicode(channels), media_type="application/json")

# GET /upload – simple HTML page
@app.get("/upload", response_class=HTMLResponse)
async def get_upload():
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Upload</title>
</head>
<body>
  <p>File uploading is currently disabled due to concerns about Discord flagging file uploads from third‐party clients as spam.</p>
  <p>If you want to try uploading anyway, <a href="/upload2">click here</a> at your own risk.</p>
</body>
</html>
    """
    return HTMLResponse(content=html)

# GET /upload2 – file upload form (requires query parameters: channel and token; optional reply)
@app.get("/upload2", response_class=HTMLResponse)
async def get_upload2(request: Request, channel: str = None, token: str = None, reply: str = None):
    if not channel or not token:
        return HTMLResponse(content="<p>Token or destination channel not defined</p>")
    username = ""
    content_text = ""
    if reply:
        async with httpx.AsyncClient() as client:
            try:
                r = await client.get(
                    f"{DEST_BASE}/channels/{channel}/messages",
                    params={"around": reply, "limit": 1},
                    headers={"Authorization": get_token_from_upload_token(token)}
                )
                r.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise HTTPException(status_code=e.response.status_code,
                                    detail=e.response.text or e.response.reason_phrase)
            messages = r.json()
            if messages:
                msg = messages[0]
                username = msg["author"].get("global_name") or msg["author"].get("username") or "(no name)"
                content_text = msg.get("content") or ""
        username = bleach.clean(username)
        content_text = bleach.clean(content_text[:50])
    form_action = f"{BASE}/channels/{channel}/upload"
    token_field = f'<input type="hidden" name="token" value="{token}" />'
    bypass_field = '<input type="hidden" name="bypass" value="1" />'
    reply_field = f'<input type="hidden" name="reply" value="{reply}" />' if reply else ""
    ping_field = '<input type="checkbox" name="ping" id="ping" checked></input><label for="ping">Mention author</label><br />' if reply else ""
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Upload</title>
</head>
<body>
  <h1>Upload file</h1>
  {f"<p>Replying to {username}</p><p>{content_text}</p>" if reply else ""}
  <form method="post" enctype="multipart/form-data" action="{form_action}">
    {token_field}
    {bypass_field}
    {reply_field}
    <label for="file">File:</label><br />
    <input type="file" name="files" id="files"><br />
    <label for="content">Text:</label><br />
    <textarea name="content" id="content"></textarea><br />
    {ping_field}
    <input type="submit" value="Upload" />
  </form>
</body>
</html>
    """
    return HTMLResponse(content=html)

# GET /api/v9/users/@me/channels – DM channels (full)
@app.get(f"{BASE}/users/@me/channels")
async def get_dm_channels(token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/users/@me/channels", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        channels_data = r.json()
        channels = []
        for ch in channels_data:
            if ch.get("type") in [1, 3]:
                result = {
                    "id": ch.get("id"),
                    "type": ch.get("type"),
                    "last_message_id": ch.get("last_message_id")
                }
                if ch.get("type") == 3:
                    result["name"] = ch.get("name")
                    if ch.get("icon") is not None:
                        result["icon"] = ch.get("icon")
                else:
                    rec = ch.get("recipients", [{}])[0]
                    result["recipients"] = [{
                        "global_name": rec.get("global_name")
                    }]
                    if rec.get("avatar") is not None:
                        result["recipients"][0]["id"] = rec.get("id")
                        result["recipients"][0]["avatar"] = rec.get("avatar")
                    if rec.get("global_name") is None:
                        result["recipients"][0]["username"] = rec.get("username")
                channels.append(result)
        return Response(content=stringify_unicode(channels), media_type="application/json")

# GET /api/v9/channels/{channel}/messages – fetch messages (full)
@app.get(f"{BASE}/channels/{{channel}}/messages")
async def get_messages(channel: str, request: Request, limit: int = None, before: str = None,
                       after: str = None, emoji: bool = False, edit: bool = False,
                       token_info: dict = Depends(get_token_dependency)):
    query_params = {}
    if limit:
        query_params["limit"] = limit
    if before:
        query_params["before"] = before
    if after:
        query_params["after"] = after
    proxy_url = f"{DEST_BASE}/channels/{channel}/messages"
    if query_params:
        proxy_url += "?" + "&".join(f"{k}={v}" for k, v in query_params.items())
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(proxy_url, headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        messages_raw = r.json()
        # Update username cache
        for msg in messages_raw:
            user_cache[msg["author"]["id"]] = msg["author"].get("username")
            if len(user_cache) > CACHE_SIZE:
                oldest = next(iter(user_cache))
                del user_cache[oldest]
        messages = []
        for msg in messages_raw:
            parsed = parse_message_object(msg, request, show_guild_emoji=emoji, show_edited=edit)
            if msg.get("message_snapshots"):
                parsed["message_snapshots"] = [{
                    "message": parse_message_object(msg["message_snapshots"][0].get("message", {}), request,
                                                    show_guild_emoji=emoji, show_edited=edit)
                }]
            messages.append(parsed)
        return Response(content=stringify_unicode(messages), media_type="application/json")

# POST /api/v9/channels/{channel}/messages – send a message
@app.post(f"{BASE}/channels/{{channel}}/messages")
async def send_message(channel: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(f"{DEST_BASE}/channels/{channel}/messages", headers=token_info["headers"], json=body)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
    return Response(content=stringify_unicode({"id": r.json().get("id")}), media_type="application/json")

# POST /api/v9/channels/{channel}/upload – send message with attachment(s)
@app.post(f"{BASE}/channels/{{channel}}/upload")
async def upload_message(
    channel: str,
    request: Request,
    token_info: dict = Depends(get_token_dependency),
    files: UploadFile = File(None),
    content: str = Form(""),
    bypass: str = Form(None),
    reply: str = Form(None),
    ping: str = Form(None)
):
    file_bytes = None
    if files is not None:
        file_bytes = await files.read()
    is_bypass = False
    if bypass:
        is_bypass = True
    elif content and content.startswith("#"):
        is_bypass = True
        content = content[1:]
    if not is_bypass:
        raise HTTPException(status_code=400,
                            detail=("Uploading is disabled due to Discord flagging uploads from 3rd-party clients as spam. "
                                    "To upload anyway at your own risk, include a '#' at the beginning of your message. "
                                    "The '#' will not be included in the actual message."))
    payload = {"content": content}
    if reply:
        payload["message_reference"] = {"message_id": reply}
    if ping not in ["1", "on"]:
        payload["allowed_mentions"] = {"replied_user": False}
    # Build multipart/form-data for httpx
    multipart_data = []
    if file_bytes is not None:
        multipart_data.append(("files[0]", (files.filename, file_bytes, files.content_type)))
    multipart_data.append(("payload_json", (None, json.dumps(payload), "application/json")))
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(f"{DEST_BASE}/channels/{channel}/messages",
                                  headers=token_info["headers"],
                                  files=multipart_data)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
    upload_token = token_info.get("upload_token") or token_info["headers"]["Authorization"]
    html = f'<p>{"File sent!" if file_bytes is not None else "Message sent!"}</p>' \
           f'<a href="/upload?channel={channel}&token={upload_token}">Send another</a>'
    return HTMLResponse(content=html)

# POST /api/v9/channels/{channel}/messages/{message}/ack – mark message as read
@app.post(f"{BASE}/channels/{{channel}}/messages/{{message}}/ack")
async def ack_message(channel: str, message: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(f"{DEST_BASE}/channels/{channel}/messages/{message}/ack",
                                  headers=token_info["headers"],
                                  json=body)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
    return PlainTextResponse("ok")

# GET /api/v9/users/@me – get user info and extra proxy info
@app.get(f"{BASE}/users/@me")
async def get_user(token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/users/@me", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        data = r.json()
        response_data = {
            "id": data.get("id"),
            "_uploadtoken": generate_upload_token(token_info["headers"]["Authorization"]),
            "_liteproxy": True,
            "_latest": 12,
            "_latestname": "4.1.0",
            "_latestbeta": 15,
            "_latestbetaname": "5.0.0 beta3",
            "_emojiversion": 4,
            "_emojisheets": [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 2]
        }
        return Response(content=json.dumps(response_data, ensure_ascii=True), media_type="application/json")

# GET /api/v9/guilds/{guild}/members/{member} – get server member info
@app.get(f"{BASE}/guilds/{{guild}}/members/{{member}}")
async def get_guild_member(guild: str, member: str, token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/guilds/{guild}/members/{member}", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        data = r.json()
        member_info = {
            "user": data.get("user"),
            "roles": data.get("roles"),
            "joined_at": data.get("joined_at")
        }
        if data.get("nick") is not None:
            member_info["avatar"] = data.get("nick")
        if data.get("avatar") is not None:
            member_info["avatar"] = data.get("avatar")
        if data.get("permissions") is not None:
            member_info["permissions"] = data.get("permissions")
        return Response(content=stringify_unicode(member_info), media_type="application/json")

# POST /api/v9/channels/{channel}/messages/{message}/edit – edit message
@app.post(f"{BASE}/channels/{{channel}}/messages/{{message}}/edit")
async def edit_message(channel: str, message: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient() as client:
        try:
            r = await client.patch(f"{DEST_BASE}/channels/{channel}/messages/{message}",
                                   headers=token_info["headers"],
                                   json=body)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
    return PlainTextResponse("ok")

# GET /api/v9/channels/{channel}/messages/{message}/delete – delete message
@app.get(f"{BASE}/channels/{{channel}}/messages/{{message}}/delete")
async def delete_message(channel: str, message: str, token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.delete(f"{DEST_BASE}/channels/{channel}/messages/{message}", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
    return PlainTextResponse("ok")

# GET /api/v9/guilds/{guild}/roles – get role list
@app.get(f"{BASE}/guilds/{{guild}}/roles")
async def get_roles(guild: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/guilds/{guild}/roles", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        roles_raw = r.json()
        roles_raw.sort(key=lambda r: r.get("position", 0))
        roles = []
        for r_item in roles_raw:
            ret = {"id": r_item.get("id"), "color": r_item.get("color")}
            if request.query_params.get("droidcord"):
                ret["name"] = r_item.get("name")
                ret["position"] = r_item.get("position")
                ret["permissions"] = r_item.get("permissions")
            roles.append(ret)
        return Response(content=stringify_unicode(roles), media_type="application/json")

# GET /api/v9/channels/{channel}/threads/search – search threads
@app.get(f"{BASE}/channels/{{channel}}/threads/search")
async def search_threads(channel: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    params = {}
    for param in ["archived", "sort_by", "sort_order", "limit", "tag_setting", "offset"]:
        if request.query_params.get(param):
            params[param] = request.query_params.get(param)
    proxy_url = f"{DEST_BASE}/channels/{channel}/threads/search"
    if params:
        proxy_url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(proxy_url, headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        data = r.json()
        output = {
            "threads": [
                {"id": thr.get("id"), "name": thr.get("name"), "last_message_id": thr.get("last_message_id")}
                for thr in data.get("threads", [])
            ]
        }
        return Response(content=stringify_unicode(output), media_type="application/json")

###############################################################################
# Lite Endpoints (/api/l)
###############################################################################

# GET /api/l/users/@me/guilds – lite server list
@app.get(f"{BASE_L}/users/@me/guilds")
async def get_guilds_lite(token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/users/@me/guilds", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        guilds = [[g.get("id"), g.get("name")] for g in r.json()]
        return Response(content=stringify_unicode(guilds), media_type="application/json")

# GET /api/l/guilds/{guild}/channels – lite channel list
@app.get(f"{BASE_L}/guilds/{{guild}}/channels")
async def get_guild_channels_lite(guild: str, token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/guilds/{guild}/channels", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        channels_data = r.json()
        for ch in channels_data:
            channel_cache[ch.get("id")] = ch.get("name")
            if len(channel_cache) > CACHE_SIZE:
                oldest = next(iter(channel_cache))
                del channel_cache[oldest]
        # Sort channels by position then map to [id, name]
        channels_data = sorted(channels_data, key=lambda ch: ch.get("position", 0))
        channels = [[ch.get("id"), ch.get("name")] for ch in channels_data if ch.get("type") in [0, 5]]
        return Response(content=stringify_unicode(channels), media_type="application/json")

# GET /api/l/users/@me/channels – lite DM channels
@app.get(f"{BASE_L}/users/@me/channels")
async def get_dm_channels_lite(token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/users/@me/channels", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        channels_data = r.json()
        channels_filtered = [ch for ch in channels_data if ch.get("type") in [1, 3]]
        channels_filtered.sort(key=lambda ch: int(ch.get("last_message_id") or 0), reverse=True)
        output = []
        for ch in channels_filtered[:30]:
            if ch.get("type") == 3:
                output.append([ch.get("id"), ch.get("name")])
            else:
                recipient = ch.get("recipients", [{}])[0]
                name = recipient.get("global_name") or recipient.get("username")
                output.append([ch.get("id"), name])
        return Response(content=stringify_unicode(output), media_type="application/json")

# GET /api/l/channels/{channel}/messages – lite messages
@app.get(f"{BASE_L}/channels/{{channel}}/messages")
async def get_messages_lite(channel: str, limit: int = None, before: str = None,
                            after: str = None, token_info: dict = Depends(get_token_dependency)):
    query_params = {}
    if limit:
        query_params["limit"] = limit
    if before:
        query_params["before"] = before
    if after:
        query_params["after"] = after
    proxy_url = f"{DEST_BASE}/channels/{channel}/messages"
    if query_params:
        proxy_url += "?" + "&".join(f"{k}={v}" for k, v in query_params.items())
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(proxy_url, headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        messages_raw = r.json()
        for msg in messages_raw:
            user_cache[msg["author"]["id"]] = msg["author"].get("username")
            if len(user_cache) > CACHE_SIZE:
                oldest = next(iter(user_cache))
                del user_cache[oldest]
        messages = []
        for msg in messages_raw:
            # For status messages, leave content empty
            if 1 <= msg.get("type", 0) <= 11:
                content = ""
            else:
                content = msg.get("content") or ""
                content = re.sub(r"<@(\d{15,})>", lambda m: "@" + user_cache.get(m.group(1), m.group(1)), content)
                content = re.sub(r"<#(\d{15,})>", lambda m: "#" + channel_cache.get(m.group(1), m.group(1)), content)
                content = re.sub(r"<a?(:\w*:)\d{15,}>", r"\1", content)
                content = pemoji.demojize(content)
                if msg.get("attachments"):
                    for att in msg["attachments"]:
                        if content:
                            content += "\n"
                        content += f"(file: {att.get('filename')})"
                if msg.get("sticker_items"):
                    if content:
                        content += "\n"
                    content += f"(sticker: {msg['sticker_items'][0].get('name')})"
                if msg.get("embeds"):
                    for emb in msg["embeds"]:
                        if emb.get("title"):
                            if content:
                                content += "\n"
                            content += f"(embed: {emb.get('title')})"
                if content == "":
                    content = "(unsupported message)"
            recipient = ""
            if msg.get("type") in [1, 2] and msg.get("mentions"):
                mention = msg["mentions"][0]
                recipient = mention.get("global_name") or mention.get("username")
            elif msg.get("referenced_message") and msg["referenced_message"].get("author"):
                recipient = msg["referenced_message"]["author"].get("global_name") or msg["referenced_message"]["author"].get("username")
            messages.append([
                msg.get("id"),
                msg["author"].get("global_name") or msg["author"].get("username"),
                content,
                recipient,
                msg.get("type"),
                generate_lite_id_hash(msg["author"].get("id"))
            ])
        return Response(content=stringify_unicode(messages), media_type="application/json")

# GET /api/l/users/@me – returns a short user id hash as plain text
@app.get(f"{BASE_L}/users/@me")
async def get_user_lite(token_info: dict = Depends(get_token_dependency)):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{DEST_BASE}/users/@me", headers=token_info["headers"])
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code,
                                detail=e.response.text or e.response.reason_phrase)
        user = r.json()
        lite_id = generate_lite_id_hash(user.get("id"))
        return PlainTextResponse(lite_id)

# For lite endpoints, re-use the same send/edit/delete functions as the full API.
@app.post(f"{BASE_L}/channels/{{channel}}/messages")
async def send_message_lite(channel: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    return await send_message(channel, request, token_info)

@app.post(f"{BASE_L}/channels/{{channel}}/messages/{{message}}/edit")
async def edit_message_lite(channel: str, message: str, request: Request, token_info: dict = Depends(get_token_dependency)):
    return await edit_message(channel, message, request, token_info)

@app.get(f"{BASE_L}/channels/{{channel}}/messages/{{message}}/delete")
async def delete_message_lite(channel: str, message: str, token_info: dict = Depends(get_token_dependency)):
    return await delete_message(channel, message, token_info)

# GET "/" – simple live check
@app.get("/")
async def root():
    print("Request received")
    return PlainTextResponse("live")

###############################################################################
# End of API
###############################################################################

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
