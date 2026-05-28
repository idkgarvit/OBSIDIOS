import aiohttp, json, pathlib, os, time, asyncio
from collections import defaultdict
from loguru import logger
from config.settings import alerts as alert_cfg

_COLORS = {
    "critical": 15548997,
    "high": 15105570,
    "medium": 16705372,
    "low": 5793266,
    "info": 5763719,
    "success": 3066993,
}

_buffer: dict[str, list[dict]] = defaultdict(list)
_cooldowns: dict[str, float] = {}
_CATEGORY_LABELS = {
    "critical_cves": "🚨 Critical CVEs Found",
    "exploit_rules": "🎯 Exploit Rules Deployed",
    "wireless": "📡 Wireless Threats Detected",
    "sentinel": "🔴 Sentinel Alerts",
}

def get_discord_webhook():
    if alert_cfg.discord_webhook_url:
        return alert_cfg.discord_webhook_url
    env_file = pathlib.Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("OBSIDIOS_DISCORD_WEBHOOK="):
                return line.split("=", 1)[1].strip()
    return os.getenv("OBSIDIOS_DISCORD_WEBHOOK", "")

def get_telegram_creds():
    token = alert_cfg.telegram_bot_token
    chat_id = alert_cfg.telegram_chat_id
    env_file = pathlib.Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("OBSIDIOS_TELEGRAM_TOKEN="):
                token = line.split("=", 1)[1].strip()
            elif line.startswith("OBSIDIOS_TELEGRAM_CHAT="):
                chat_id = line.split("=", 1)[1].strip()
    return token, chat_id

def check_cooldown(key: str, seconds: int = 60) -> bool:
    now = time.time()
    if key in _cooldowns and now - _cooldowns[key] < seconds:
        return False
    _cooldowns[key] = now
    return True

async def send_alert(title: str, message: str = "", color: int | str = 15548997, fields: list | None = None, footer: str | None = None):
    if isinstance(color, str):
        color = _COLORS.get(color.lower(), 15548997)
    tasks = []
    discord_url = get_discord_webhook()
    if discord_url:
        tasks.append(_send_discord(title, message, color, discord_url, fields, footer))
    tg_token, tg_chat = get_telegram_creds()
    if tg_token and tg_chat:
        tasks.append(_send_telegram(title, message, tg_token, tg_chat))
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"[ALERTS] Alert task failed: {res}")

async def buffer_alert(category: str, title: str = "", message: str = "", color: int | str = "info", fields: list | None = None, footer: str | None = None):
    if isinstance(color, str):
        color = _COLORS.get(color.lower(), 15548997)
    _buffer[category].append(dict(title=title, message=message, color=color, fields=fields, footer=footer))

async def flush_alerts(category: str | None = None):
    categories = [category] if category else list(_buffer.keys())
    for cat in categories:
        items = _buffer.pop(cat, [])
        if not items:
            continue
        if len(items) == 1:
            await send_alert(**items[0])
        else:
            await _send_consolidated(cat, items)

async def _send_consolidated(category: str, items: list[dict]):
    if not items:
        return
    label = _CATEGORY_LABELS.get(category, f"📋 {category.replace('_',' ').title()}")
    color = items[0].get("color", 5763719)
    fields = []
    for i, item in enumerate(items):
        title = item.get("title", "")
        msg = item.get("message", "")
        label_text = f"#{i+1}"
        val = f"**{title}**\n{msg[:200]}"
        if item.get("fields"):
            for f in item["fields"]:
                fname = f.get("name", "")
                fval = f.get("value", "")
                val += f"\n{fname}: {fval[:100]}"
        fields.append({"name": label_text, "value": val[:1024], "inline": True})
        if len(fields) >= 25:
            fields.append({"name": f"... and {len(items)-i-1} more", "value": "Truncated due to Discord field limit", "inline": False})
            break
    await send_alert(title=label, message=f"**{len(items)}** event(s) in this batch", color=color, fields=fields, footer="OBSIDIOS v2.0")

async def _send_discord(title: str, message: str, color: int, webhook_url: str, fields: list | None = None, footer: str | None = None):
    embed = {"title": title, "color": color}
    if message:
        embed["description"] = message
    if fields:
        embed["fields"] = fields
    if footer:
        embed["footer"] = {"text": footer}
    embed["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    payload = {
        "username": "OBSIDIOS",
        "avatar_url": "https://i.imgur.com/rN9n1aK.png",
        "embeds": [embed],
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as resp:
                if resp.status not in (200, 204):
                    logger.warning(f"[ALERTS] Discord returned {resp.status}")
    except Exception as e:
        logger.warning(f"[ALERTS] Failed to send Discord alert: {e}")

async def _send_telegram(title: str, message: str, token: str, chat_id: str):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": f"*{title}*\n{message}", "parse_mode": "Markdown"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.warning(f"[ALERTS] Telegram returned {resp.status}")
    except Exception as e:
        logger.debug(f"[ALERTS] Failed to send Telegram alert: {e}")
