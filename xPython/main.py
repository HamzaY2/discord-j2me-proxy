import os
import re
import json
import logging
import emoji
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, JSONResponse
import httpx

# Global configuration and caches
DEST_BASE = "https://discord.com/api/v9"
BASE = "/api/v9"
BASE_L = "/api/l"
CACHE_SIZE = 10000

user_cache = {}      # id -> username
channel_cache = {}   # id -> channel name
upload_tokens = {}   # upload token mapping; key: token string, value: dict(token, expires)

app = FastAPI()

# ---------------------------
# Utility functions
# ---------------------------

def stringify_unicode(obj) -> str:
    # json.dumps with ensure_ascii True produces unicode escapes
    return json.dumps(obj, ensure_ascii=True)

def get_token_from_upload_token(token: str) -> str:
    if not token.startswith("j2me-"):
        return token
    ut = upload_tokens.get(token)
    if not ut:
        return token
    if datetime.now() > ut["expires"]:
        return token
    return ut["token"]

def generate_upload_token(token: str) -> str:
    rand_bytes = os.urandom(16)
    token_str = "j2me-" + ''.join(f'{b:02x}' for b in rand_bytes)
    expires = datetime.now() + timedelta(days=7)
    upload_tokens[token_str] = {"token": token, "expires": expires}
    return token_str

def base36encode(number: int) -> str:
    chars = '0123456789abcdefghijklmnopqrstuvwxyz'
    if number < 0:
        raise ValueError("number must be non-negative")
    if number == 0:
        return '0'
    result = ''
    while number:
        number, i = divmod(number, 36)
        result = chars[i] + result
    return result

def generate_lite_id_hash(id_str: str) -> str:
    num = int(id_str) % 100000
    return base36encode(num)

def parse_message_content(content: str, show_guild_emoji: bool, convert_tags: bool = True) -> str:
    if not content:
        return content
    result = content
    if convert_tags:
        # Replace Discord user/channel mentions if we have them cached
        result = re.sub(r'<@(\d{15,})>', lambda m: f"@{user_cache.get(m.group(1), m.group(0))}", result)
        result = re.sub(r'<#(\d{15,})>', lambda m: f"#{channel_cache.get(m.group(1), m.group(0))}", result)
    if not show_guild_emoji:
        # Replace Discord custom emoji with :name:
        result = re.sub(r'<a?(:\w*:)\d{15,}>', r'\1', result)
    # Replace Unicode emojis with colon style names (using the python-emoji package)
    result = emoji.demojize(result)
    # Replace regional indicator symbols (U+1F1E6 - U+1F1FF) with textual representation
    result = re.sub(r'([\U0001F1E6-\U0001F1FF])',
                    lambda m: f":regional_indicator_{chr(ord(m.group(1)) - 0x1F1E6 + ord('a'))}:",
                    result)
    return result

def parse_message_object(msg: dict, query: dict, show_guild_emoji: bool, show_edited: bool) -> dict:
    result = {"id": msg.get("id")}
    if show_edited and msg.get("edited_timestamp"):
        result["edited_timestamp"] = msg["edited_timestamp"]
    if msg.get("author"):
        result["author"] = {
            "id": msg["author"]["id"],
            "avatar": msg["author"].get("avatar"),
            "global_name": msg["author"].get("global_name")
        }
        if msg["author"].get("global_name") is None or query.get("droidcord"):
            result["author"]["username"] = msg["author"].get("username")
    if msg.get("type") is not None and 1 <= msg["type"] <= 11:
        result["type"] = msg["type"]
    if msg.get("content"):
        content = parse_message_content(msg["content"], show_guild_emoji)
        result["content"] = content
        if content != msg["content"]:
            result["_rc"] = msg["content"]
    if msg.get("referenced_message"):
        ref_msg = msg["referenced_message"]
        ref_content = parse_message_content(ref_msg.get("content", ""), show_guild_emoji)
        ref_content = re.sub(r'\r\n|\r|\n', "  ", ref_content)
        if show_guild_emoji:
            new_content = ref_content[:80]
            i = 81
            while i < len(ref_content) and new_content.rfind(">") < new_content.rfind("<"):
                new_content = ref_content[:i]
                i += 1
            ref_content = new_content
        else:
            if ref_content and len(ref_content) > 50:
                ref_content = ref_content[:47].strip() + "..."
        result["referenced_message"] = {
            "author": {
                "global_name": ref_msg["author"].get("global_name"),
                "id": ref_msg["author"]["id"],
                "avatar": ref_msg["author"].get("avatar")
            },
            "content": ref_content
        }
        if ref_msg["author"].get("global_name") is None or query.get("droidcord"):
            result["referenced_message"]["author"]["username"] = ref_msg["author"].get("username")
    if msg.get("attachments"):
        result["attachments"] = []
        for att in msg["attachments"]:
            ret = {
                "filename": att.get("filename"),
                "size": att.get("size"),
                "width": att.get("width"),
                "height": att.get("height"),
                "proxy_url": att.get("proxy_url")
            }
            if query.get("droidcord"):
                ret["content_type"] = att.get("content_type")
            result["attachments"].append(ret)
    if msg.get("sticker_items"):
        result["sticker_items"] = [{"name": msg["sticker_items"][0].get("name")}]
    if msg.get("embeds"):
        result["embeds"] = []
        for emb in msg["embeds"]:
            ret = {
                "title": parse_message_content(emb.get("title", ""), True, False),
                "description": parse_message_content(emb.get("description", ""), True, False)
            }
            if query.get("droidcord"):
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
            result["embeds"].append(ret)
    if (msg.get("type") in [1, 2]) and msg.get("mentions"):
        mention = msg["mentions"][0]
        result["mentions"] = [{
            "id": mention.get("id"),
            "global_name": mention.get("global_name")
        }]
        if mention.get("global_name") is None:
            result["mentions"][0]["username"] = mention.get("username")
    return result

# ---------------------------
# Dependency to get token headers
# ---------------------------

async def get_headers(request: Request, token: str = None) -> dict:
    # Try query parameter then header if not provided
    if token is None:
        token = request.query_params.get("token")
    if token is None:
        token = request.headers.get("authorization")
    if token is None:
        raise HTTPException(status_code=400, detail="Token not provided")
    return {
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

# ---------------------------
# Endpoints (API v9)
# ---------------------------

@app.get(f"{BASE}/users/@me/guilds")
async def get_guilds(request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/users/@me/guilds", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            guilds = []
            for g in data:
                result = {"id": g["id"], "name": g["name"]}
                if g.get("icon") is not None:
                    result["icon"] = g["icon"]
                guilds.append(result)
            return Response(content=stringify_unicode(guilds), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE}/guilds/{{guild}}/channels")
async def get_guild_channels(guild: str, request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/guilds/{guild}/channels", headers=headers)
            resp.raise_for_status()
            channels_data = resp.json()
            # Populate channel cache
            for ch in channels_data:
                channel_cache[ch["id"]] = ch["name"]
                if len(channel_cache) > CACHE_SIZE:
                    channel_cache.pop(next(iter(channel_cache)))
            channels = [
                {
                    "id": ch["id"],
                    "type": ch["type"],
                    "guild_id": ch.get("guild_id"),
                    "name": ch["name"],
                    "position": ch.get("position"),
                    "last_message_id": ch.get("last_message_id")
                }
                for ch in channels_data if ch["type"] in [0, 5, 15, 16]
            ]
            return Response(content=stringify_unicode(channels), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    html_content = f"""<!DOCTYPE html>
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
</html>"""
    return HTMLResponse(content=html_content)

@app.get("/upload2", response_class=HTMLResponse)
async def upload_page2(request: Request, channel: str = None, token: str = None, reply: str = None):
    if not channel or not token:
        return HTMLResponse(content="<p>Token or destination channel not defined</p>")
    username = ""
    content_text = ""
    if reply:
        try:
            real_token = get_token_from_upload_token(token)
            temp_headers = {"Authorization": real_token}
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{DEST_BASE}/channels/{channel}/messages",
                                          params={"around": reply, "limit": "1"},
                                          headers=temp_headers)
                resp.raise_for_status()
                message_data = resp.json()
                if message_data:
                    msg = message_data[0]
                    username = msg["author"].get("global_name") or msg["author"].get("username") or "(no name)"
                    content_text = msg.get("content", "")
        except Exception as e:
            logging.error(e)
    safe_username = username  # In production you might want to sanitize this HTML
    safe_content = content_text[:50]
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Upload</title>
</head>
<body>
  <h1>Upload file</h1>
  {f"<p>Replying to {safe_username}</p><p>{safe_content}</p>" if reply else ""}
  <form method="post" enctype="multipart/form-data" action="{BASE}/channels/{channel}/upload">
    <input type="hidden" name="token" value="{token}" />
    <input type="hidden" name="bypass" value="1" />
    {f"<input type='hidden' name='reply' value='{reply}' />" if reply else ""}
    <label for="file">File:</label><br />
    <input type="file" name="files" id="files"><br />
    <label for="content">Text:</label><br />
    <textarea name="content" id="content"></textarea><br />
    {f"<input type='checkbox' name='ping' id='ping' checked><label for='ping'>Mention author</label><br />" if reply else ""}
    <input type="submit" value="Upload" />
  </form>
</body>
</html>"""
    return HTMLResponse(content=html_content)

@app.get(f"{BASE}/users/@me/channels")
async def get_dm_channels(request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/users/@me/channels", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            channels = []
            for ch in data:
                if ch["type"] in [1, 3]:
                    result = {"id": ch["id"], "type": ch["type"], "last_message_id": ch.get("last_message_id")}
                    if ch["type"] == 3:
                        result["name"] = ch.get("name")
                        if ch.get("icon") is not None:
                            result["icon"] = ch["icon"]
                    else:
                        if ch.get("recipients") and len(ch["recipients"]) > 0:
                            recipient = ch["recipients"][0]
                            result["recipients"] = [{
                                "global_name": recipient.get("global_name")
                            }]
                            if recipient.get("avatar") is not None:
                                result["recipients"][0]["id"] = recipient.get("id")
                                result["recipients"][0]["avatar"] = recipient.get("avatar")
                            if recipient.get("global_name") is None:
                                result["recipients"][0]["username"] = recipient.get("username")
                    channels.append(result)
            return Response(content=stringify_unicode(channels), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE}/channels/{{channel}}/messages")
async def get_messages(channel: str, request: Request, headers: dict = Depends(get_headers)):
    query_params = dict(request.query_params)
    params = {}
    show_guild_emoji = False
    show_edited = False
    if "limit" in query_params:
        params["limit"] = query_params["limit"]
    if "before" in query_params:
        params["before"] = query_params["before"]
    if "after" in query_params:
        params["after"] = query_params["after"]
    if "emoji" in query_params:
        show_guild_emoji = True
    if "edit" in query_params:
        show_edited = True
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/channels/{channel}/messages", params=params, headers=headers)
            resp.raise_for_status()
            messages_data = resp.json()
            # Populate user cache
            for msg in messages_data:
                user_cache[msg["author"]["id"]] = msg["author"].get("username")
                if len(user_cache) > CACHE_SIZE:
                    user_cache.pop(next(iter(user_cache)))
            messages = []
            for msg in messages_data:
                parsed = parse_message_object(msg, query_params, show_guild_emoji, show_edited)
                if msg.get("message_snapshots"):
                    parsed["message_snapshots"] = [{
                        "message": parse_message_object(msg["message_snapshots"][0]["message"],
                                                        query_params, show_guild_emoji, show_edited)
                    }]
                messages.append(parsed)
            return Response(content=stringify_unicode(messages), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

# Helper functions for send/edit/delete message operations

async def send_message(channel: str, request: Request, headers: dict) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{DEST_BASE}/channels/{channel}/messages", json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return Response(content=stringify_unicode({"id": data["id"]}), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

async def edit_message(channel: str, message: str, request: Request, headers: dict) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.patch(f"{DEST_BASE}/channels/{channel}/messages/{message}",
                                        json=body, headers=headers)
            resp.raise_for_status()
            return PlainTextResponse("ok")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

async def delete_message(channel: str, message: str, headers: dict) -> Response:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.delete(f"{DEST_BASE}/channels/{channel}/messages/{message}", headers=headers)
            resp.raise_for_status()
            return PlainTextResponse("ok")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.post(f"{BASE}/channels/{{channel}}/messages")
async def send_message_endpoint(channel: str, request: Request, headers: dict = Depends(get_headers)):
    return await send_message(channel, request, headers)

@app.post(f"{BASE}/channels/{{channel}}/upload")
async def upload_file(
    channel: str,
    request: Request,
    file: UploadFile = File(None),
    token: str = Form(...),
    bypass: str = Form(None),
    reply: str = Form(None),
    content: str = Form(""),
    ping: str = Form(None)
):
    original_token = token
    real_token = get_token_from_upload_token(token)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Authorization": real_token,
        "X-Discord-Locale": "en-GB",
        "X-Debug-Options": "bugReporterEnabled",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    }
    # Prepare multipart form fields
    form_fields = {"payload_json": json.dumps({"content": content})}
    files = {}
    text = "Message sent!"
    if file is not None:
        file_content = await file.read()
        files["files[0]"] = (file.filename, file_content, file.content_type)
        text = "File sent!"
    bypass_flag = False
    if bypass or (content and content.startswith("#")):
        bypass_flag = True
        if content.startswith("#"):
            content = content[1:]
    # Build payload JSON with optional reply and allowed_mentions
    payload = {"content": content}
    if reply:
        payload["message_reference"] = {"message_id": reply}
    if not (ping == "1" or ping == "on"):
        payload["allowed_mentions"] = {"replied_user": False}
    form_fields["payload_json"] = json.dumps(payload)
    if not bypass_flag:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Uploading is disabled due to Discord flagging uploads from 3rd-party clients as spam. "
                           "To upload anyway at your own risk, include a # at the beginning of your message. "
                           "The # will not be included in the actual message."
            }
        )
    async with httpx.AsyncClient() as client:
        try:
            url = f"{DEST_BASE}/channels/{channel}/messages"
            resp = await client.post(url, data=form_fields, files=files, headers=headers)
            resp.raise_for_status()
            html_resp = f'<p>{text}</p><a href="/upload?channel={channel}&token={original_token}">Send another</a>'
            return HTMLResponse(content=html_resp)
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.post(f"{BASE}/channels/{{channel}}/messages/{{message}}/ack")
async def ack_message(channel: str, message: str, request: Request, headers: dict = Depends(get_headers)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{DEST_BASE}/channels/{channel}/messages/{message}/ack",
                                     json=body, headers=headers)
            resp.raise_for_status()
            return PlainTextResponse("ok")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE}/users/@me")
async def get_user_info(request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/users/@me", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            result = {
                "id": data["id"],
                "_uploadtoken": generate_upload_token(headers["Authorization"]),
                "_liteproxy": True,
                "_latest": 12,
                "_latestname": "4.1.0",
                "_latestbeta": 15,
                "_latestbetaname": "5.0.0 beta3",
                "_emojiversion": 4,
                "_emojisheets": [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 2]
            }
            return Response(content=stringify_unicode(result), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE}/guilds/{{guild}}/members/{{member}}")
async def get_guild_member(guild: str, member: str, request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/guilds/{guild}/members/{member}", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            member_data = {
                "user": data.get("user"),
                "roles": data.get("roles"),
                "joined_at": data.get("joined_at")
            }
            if data.get("nick") is not None:
                member_data["avatar"] = data.get("nick")
            if data.get("avatar") is not None:
                member_data["avatar"] = data.get("avatar")
            if data.get("permissions") is not None:
                member_data["permissions"] = data.get("permissions")
            return Response(content=stringify_unicode(member_data), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.post(f"{BASE}/channels/{{channel}}/messages/{{message}}/edit")
async def edit_message_endpoint(channel: str, message: str, request: Request, headers: dict = Depends(get_headers)):
    return await edit_message(channel, message, request, headers)

@app.get(f"{BASE}/channels/{{channel}}/messages/{{message}}/delete")
async def delete_message_endpoint(channel: str, message: str, headers: dict = Depends(get_headers)):
    return await delete_message(channel, message, headers)

@app.get(f"{BASE}/guilds/{{guild}}/roles")
async def get_roles(guild: str, request: Request, headers: dict = Depends(get_headers)):
    query_params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/guilds/{guild}/roles", headers=headers)
            resp.raise_for_status()
            roles_data = resp.json()
            roles_data.sort(key=lambda r: r.get("position", 0))
            roles = []
            for r in roles_data:
                ret = {"id": r["id"], "color": r.get("color")}
                if query_params.get("droidcord"):
                    ret["name"] = r.get("name")
                    ret["position"] = r.get("position")
                    ret["permissions"] = r.get("permissions")
                roles.append(ret)
            return Response(content=stringify_unicode(roles), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE}/channels/{{channel}}/threads/search")
async def search_threads(channel: str, request: Request, headers: dict = Depends(get_headers)):
    query_params = dict(request.query_params)
    params = {}
    for key in ["archived", "sort_by", "sort_order", "limit", "tag_setting", "offset"]:
        if key in query_params:
            params[key] = query_params[key]
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/channels/{channel}/threads/search", params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            output = {
                "threads": [
                    {
                        "id": thr["id"],
                        "name": thr["name"],
                        "last_message_id": thr.get("last_message_id")
                    }
                    for thr in data.get("threads", [])
                ]
            }
            return Response(content=stringify_unicode(output), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

# ---------------------------
# Lite Endpoints (API lite)
# ---------------------------

@app.get("/avatars/{user_id}/{avatar_hash}.jpg")
async def serve_avatar(user_id: str, avatar_hash: str):
    url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.jpg?size=16"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return Response(content=resp.content, media_type="image/jpeg")

@app.get(f"{BASE_L}/users/@me/guilds")
async def get_guilds_lite(request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/users/@me/guilds", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            guilds = [[g["id"], g["name"]] for g in data]
            return Response(content=stringify_unicode(guilds), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE_L}/guilds/{{guild}}/channels")
async def get_guild_channels_lite(guild: str, request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/guilds/{guild}/channels", headers=headers)
            resp.raise_for_status()
            channels_data = resp.json()
            for ch in channels_data:
                channel_cache[ch["id"]] = ch["name"]
                if len(channel_cache) > CACHE_SIZE:
                    channel_cache.pop(next(iter(channel_cache)))
            channels = [[ch["id"], ch["name"]] for ch in channels_data if ch["type"] in [0, 5]]
            channels.sort(key=lambda x: x[1])
            return Response(content=stringify_unicode(channels), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE_L}/users/@me/channels")
async def get_dm_channels_lite(request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/users/@me/channels", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            channels = [ch for ch in data if ch["type"] in [1, 3]]
            channels.sort(key=lambda ch: int(ch.get("last_message_id") or "0"), reverse=True)
            output = []
            for ch in channels[:30]:
                if ch["type"] == 3:
                    output.append([ch["id"], ch.get("name")])
                else:
                    recipient = ch["recipients"][0]
                    name = recipient.get("global_name") or recipient.get("username")
                    output.append([ch["id"], name])
            return Response(content=stringify_unicode(output), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE_L}/channels/{{channel}}/messages")
async def get_messages_lite(channel: str, request: Request, headers: dict = Depends(get_headers)):
    query_params = dict(request.query_params)
    params = {}
    if "limit" in query_params:
        params["limit"] = query_params["limit"]
    if "before" in query_params:
        params["before"] = query_params["before"]
    if "after" in query_params:
        params["after"] = query_params["after"]
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/channels/{channel}/messages", params=params, headers=headers)
            resp.raise_for_status()
            messages_data = resp.json()
            for msg in messages_data:
                user_cache[msg["author"]["id"]] = msg["author"].get("username")
                if len(user_cache) > CACHE_SIZE:
                    user_cache.pop(next(iter(user_cache)))
            messages = []
            for msg in messages_data:
                if msg.get("type") is not None and 1 <= msg["type"] <= 11:
                    content_text = ""
                else:
                    content_text = msg.get("content", "")
                    content_text = re.sub(r'<@(\d{15,})>', lambda m: f"@{user_cache.get(m.group(1), m.group(0))}", content_text)
                    content_text = re.sub(r'<#(\d{15,})>', lambda m: f"#{channel_cache.get(m.group(1), m.group(0))}", content_text)
                    content_text = re.sub(r'<a?(:\w*:)\d{15,}>', r'\1', content_text)
                    content_text = emoji.demojize(content_text)
                    if msg.get("attachments"):
                        for att in msg["attachments"]:
                            if content_text:
                                content_text += "\n"
                            content_text += f"(file: {att.get('filename')})"
                    if msg.get("sticker_items"):
                        if content_text:
                            content_text += "\n"
                        content_text += f"(sticker: {msg['sticker_items'][0].get('name')})"
                    if msg.get("embeds"):
                        for emb in msg["embeds"]:
                            if not emb.get("title"):
                                continue
                            if content_text:
                                content_text += "\n"
                            content_text += f"(embed: {emb.get('title')})"
                    if content_text == "":
                        content_text = "(unsupported message)"
                recipient = ""
                if (msg.get("type") in [1, 2]) and msg.get("mentions"):
                    recipient = msg["mentions"][0].get("global_name") or msg["mentions"][0].get("username")
                elif msg.get("referenced_message") and msg["referenced_message"].get("author"):
                    recipient = msg["referenced_message"]["author"].get("global_name") or msg["referenced_message"]["author"].get("username")
                lite_entry = [
                    msg["id"],
                    msg["author"].get("global_name") or msg["author"].get("username"),
                    content_text,
                    recipient,
                    msg.get("type"),
                    generate_lite_id_hash(msg["author"]["id"])
                ]
                messages.append(lite_entry)
            return Response(content=stringify_unicode(messages), media_type="application/json")
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

@app.get(f"{BASE_L}/users/@me")
async def get_user_info_lite(request: Request, headers: dict = Depends(get_headers)):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{DEST_BASE}/users/@me", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return PlainTextResponse(generate_lite_id_hash(data["id"]))
        except httpx.HTTPStatusError as e:
            logging.error(e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logging.error(e)
            raise HTTPException(status_code=500, detail="Proxy error")

# Lite versions of send/edit/delete (same behavior as full endpoints)

@app.post(f"{BASE_L}/channels/{{channel}}/messages")
async def send_message_lite(channel: str, request: Request, headers: dict = Depends(get_headers)):
    return await send_message(channel, request, headers)

@app.post(f"{BASE_L}/channels/{{channel}}/messages/{{message}}/edit")
async def edit_message_lite(channel: str, message: str, request: Request, headers: dict = Depends(get_headers)):
    return await edit_message(channel, message, request, headers)

@app.get(f"{BASE_L}/channels/{{channel}}/messages/{{message}}/delete")
async def delete_message_lite(channel: str, message: str, headers: dict = Depends(get_headers)):
    return await delete_message(channel, message, headers)

# ---------------------------
# Root endpoint
# ---------------------------

@app.get("/")
async def root(request: Request):
    logging.info("Request received")
    return PlainTextResponse("live")

# ---------------------------
# To run:
#   uvicorn your_module_name:app --host 0.0.0.0 --port 8080
# ---------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)