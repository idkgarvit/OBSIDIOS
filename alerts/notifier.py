import asyncio
import html
import os
import pathlib
import re
import time
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urlparse

import aiohttp
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
_delivery_failures: dict[str, int] = {}
_MAX_COOLDOWN_KEYS = 4096
_MAX_BUFFERED_PER_CATEGORY = 200
# Discord rejects an embed whose title, description, fields and footer total
# more than 6000 characters. The batch builder used to cap only the field
# count (25) and each value (1024), so a full batch was ~24k characters and
# the whole notification was rejected, retried, then dropped.
_DISCORD_EMBED_CHAR_LIMIT = 6000
# After this many consecutive failed flushes the batch is dropped with an
# error log. Without a ceiling a permanently broken webhook would retry the
# same payload at every scan cycle, forever.
_MAX_DELIVERY_FAILURES = 3
_CATEGORY_LABELS = {
    "critical_cves": "🚨 Critical CVEs Found",
    "exploit_rules": "🎯 Exploit Rules Deployed",
    "wireless": "📡 Wireless Threats Detected",
    "sentinel": "🔴 Sentinel Alerts",
}

# Discord webhooks are only accepted from Discord-owned hosts. This prevents a
# poisoned config value from turning alerts into an SSRF/exfiltration channel.
_DISCORD_HOSTS = {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"}
_TELEGRAM_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")
_TELEGRAM_CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(text, limit: int = 1024) -> str:
    """Bound length, strip control characters and defuse mass mentions."""
    if text is None:
        return ""
    value = _CONTROL_CHARS_RE.sub("", str(text))
    value = value.replace("@everyone", "@\u200beveryone").replace("@here", "@\u200bhere")
    return value[:limit]


def _valid_discord_webhook(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return False
    host = (parsed.hostname or "").lower()
    if host not in _DISCORD_HOSTS and not host.endswith(".discord.com"):
        return False
    if port not in (None, 443):
        return False
    return parsed.path.startswith("/api/webhooks/")


def _valid_telegram_creds(token: str, chat_id: str) -> bool:
    return bool(_TELEGRAM_TOKEN_RE.fullmatch(token or "")) and bool(
        _TELEGRAM_CHAT_RE.fullmatch(chat_id or "")
    )


def _env_file_lines() -> list[str]:
    """Local `.env` overrides, or nothing when the file is absent/unreadable.

    `.env` is operator-managed, so it can be a root-owned file or a directory
    in the container. Reading it used to raise out of `send_alert`, which
    contradicts the rule that alerting must never abort the pipeline it
    reports on; the process environment is a valid fallback.
    """
    env_file = pathlib.Path(__file__).parent.parent / ".env"
    try:
        if not env_file.exists():
            return []
        return env_file.read_text().splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning(f"[ALERTS] Cannot read .env overrides: {type(exc).__name__}")
        return []


def get_discord_webhook():
    if alert_cfg.discord_webhook_url:
        return alert_cfg.discord_webhook_url
    for line in _env_file_lines():
        if line.startswith("OBSIDIOS_DISCORD_WEBHOOK="):
            return line.split("=", 1)[1].strip().strip("\"'")
    return os.getenv("OBSIDIOS_DISCORD_WEBHOOK", "")


def get_telegram_creds():
    token = alert_cfg.telegram_bot_token
    chat_id = alert_cfg.telegram_chat_id
    for line in _env_file_lines():
        if line.startswith("OBSIDIOS_TELEGRAM_TOKEN="):
            token = line.split("=", 1)[1].strip().strip("\"'")
        elif line.startswith("OBSIDIOS_TELEGRAM_CHAT="):
            chat_id = line.split("=", 1)[1].strip().strip("\"'")
    return token, chat_id


def check_cooldown(key: str, seconds: int = 60) -> bool:
    now = time.time()
    if key in _cooldowns and now - _cooldowns[key] < seconds:
        return False
    # Keys include attacker-controlled addresses, so the map is pruned and
    # capped instead of growing for the lifetime of the process.
    if len(_cooldowns) >= _MAX_COOLDOWN_KEYS:
        expired = [k for k, ts in _cooldowns.items() if now - ts >= seconds]
        for k in expired:
            _cooldowns.pop(k, None)
        if len(_cooldowns) >= _MAX_COOLDOWN_KEYS:
            _cooldowns.clear()
    _cooldowns[key] = now
    return True


class DeliveryError(RuntimeError):
    """A webhook/bot endpoint rejected the alert or could not be reached."""


async def send_alert(title: str, message: str = "", color: int | str = 15548997,
                     fields: list | None = None, footer: str | None = None) -> bool:
    """Deliver an alert. Returns True when every configured channel accepted it.

    Failures are logged and reported through the return value instead of being
    raised: alerting must never abort the security pipeline it reports on.
    """
    if isinstance(color, str):
        color = _COLORS.get(color.lower(), 15548997)
    tasks = []
    delivered = True
    discord_url = get_discord_webhook()
    if discord_url:
        if _valid_discord_webhook(discord_url):
            tasks.append(_send_discord(title, message, color, discord_url, fields, footer))
        else:
            # A poisoned config must not silence a working Telegram channel.
            logger.error("[ALERTS] Ignoring Discord webhook with an untrusted URL")
            delivered = False
    tg_token, tg_chat = get_telegram_creds()
    if tg_token and tg_chat:
        if _valid_telegram_creds(tg_token, tg_chat):
            tasks.append(_send_telegram(title, message, tg_token, tg_chat))
        else:
            logger.error("[ALERTS] Ignoring Telegram credentials with an invalid format")
            delivered = False
    if not tasks:
        return delivered
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, Exception):
            # Never interpolate exception text: aiohttp errors can embed
            # the webhook/bot URL (which contains the secret token).
            logger.error(f"[ALERTS] Alert task failed: {type(res).__name__}")
            delivered = False
    return delivered


async def buffer_alert(category: str, title: str = "", message: str = "",
                       color: int | str = "info", fields: list | None = None,
                       footer: str | None = None):
    if isinstance(color, str):
        color = _COLORS.get(color.lower(), 15548997)
    _buffer[category].append(dict(title=title, message=message, color=color, fields=fields, footer=footer))
    # Keep the in-memory buffer bounded even if flushing stops.
    if len(_buffer[category]) > _MAX_BUFFERED_PER_CATEGORY:
        del _buffer[category][:-_MAX_BUFFERED_PER_CATEGORY]


async def flush_alerts(category: str | None = None):
    categories = [category] if category else list(_buffer.keys())
    for cat in categories:
        items = _buffer.pop(cat, [])
        if not items:
            continue
        try:
            if len(items) == 1:
                # send_alert reports channel-level failures via its return
                # value so that this loop can retry them.
                if await send_alert(**items[0]) is False:
                    raise DeliveryError("no channel accepted the alert")
            else:
                if await _send_consolidated(cat, items) is False:
                    raise DeliveryError("no channel accepted the batch")
        except Exception as exc:
            failures = _delivery_failures.get(cat, 0) + 1
            _delivery_failures[cat] = failures
            if failures >= _MAX_DELIVERY_FAILURES:
                _delivery_failures.pop(cat, None)
                logger.error(
                    f"[ALERTS] Dropping {len(items)} {cat} alert(s) after "
                    f"{failures} failed deliveries ({type(exc).__name__})")
                continue
            # Delivery failure must not destroy the alert: keep it buffered
            # (bounded) so the next flush retries it.
            logger.warning(
                f"[ALERTS] Flush failed for {cat} (attempt {failures}/"
                f"{_MAX_DELIVERY_FAILURES}): {type(exc).__name__}")
            _buffer[cat] = (items + _buffer[cat])[-_MAX_BUFFERED_PER_CATEGORY:]
        else:
            _delivery_failures.pop(cat, None)


async def _send_consolidated(category: str, items: list[dict]) -> bool:
    if not items:
        return True
    label = _CATEGORY_LABELS.get(category, f"📋 {category.replace('_', ' ').title()}")
    color = items[0].get("color", 5763719) if isinstance(items[0], dict) else 5763719
    message = f"**{len(items)}** event(s) in this batch"
    footer = "OBSIDIOS v2.0"
    # Leave room for the truncation notice and field labels; Discord counts
    # every character in the embed against the same 6000-character limit.
    budget = (_DISCORD_EMBED_CHAR_LIMIT - len(label) - len(message)
              - len(footer) - 200)
    fields = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            # A malformed buffered item must not poison the whole batch: the
            # old code raised AttributeError and the category was re-buffered
            # forever without ever being delivered.
            continue
        title = _clean(item.get("title", ""), 200)
        msg = _clean(item.get("message", ""), 200)
        label_text = f"#{i + 1}"
        val = f"**{title}**\n{msg}"
        item_fields = item.get("fields")
        if isinstance(item_fields, list):
            for field in item_fields[:8]:
                if not isinstance(field, dict):
                    continue
                fname = _clean(field.get("name", ""), 60)
                fval = _clean(field.get("value", ""), 100)
                val += f"\n{fname}: {fval}"
        field_value = val[:min(1024, max(0, budget))]
        if not field_value:
            remaining = len(items) - i
            fields.append({
                "name": f"... and {remaining} more",
                "value": "Truncated due to Discord embed size limit",
                "inline": False,
            })
            break
        fields.append({"name": label_text, "value": field_value, "inline": True})
        budget -= len(field_value) + len(label_text)
        # Discord accepts at most 25 fields; the 25th is reserved for the
        # truncation notice. The old code appended a 26th and the whole
        # payload was rejected, dropping every alert in the batch.
        if len(fields) >= 24 or budget <= 0:
            remaining = len(items) - i - 1
            if remaining > 0:
                fields.append({
                    "name": f"... and {remaining} more",
                    "value": "Truncated due to Discord limits",
                    "inline": False,
                })
            break
    return await send_alert(
        title=label, message=message,
        color=color, fields=fields, footer=footer)


async def _send_discord(title: str, message: str, color: int, webhook_url: str,
                        fields: list | None = None, footer: str | None = None):
    embed = {"title": _clean(title, 256) or "OBSIDIOS", "color": int(color)}
    if message:
        embed["description"] = _clean(message, 4096)
    if fields:
        embed["fields"] = [
            {
                "name": _clean(f.get("name", ""), 256) or "field",
                "value": _clean(f.get("value", ""), 1024) or "-",
                "inline": bool(f.get("inline", False)),
            }
            for f in fields[:25]
            if isinstance(f, dict)
        ]
    if footer:
        embed["footer"] = {"text": _clean(footer, 2048)}
    embed["timestamp"] = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    payload = {
        "username": "OBSIDIOS",
        "avatar_url": "https://i.imgur.com/rN9n1aK.png",
        "embeds": [embed],
    }
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(webhook_url, json=payload, allow_redirects=False) as resp:
                if resp.status not in (200, 204):
                    raise DeliveryError(f"Discord returned {resp.status}")
    except DeliveryError:
        raise
    except Exception as e:
        # Only the exception type: aiohttp messages embed the webhook URL,
        # which contains the secret token.
        raise DeliveryError(f"Discord delivery failed: {type(e).__name__}") from None


async def _send_telegram(title: str, message: str, token: str, chat_id: str):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    # HTML mode plus escaping avoids Markdown injection and parse failures that
    # would silently drop security alerts.
    payload = {
        "chat_id": chat_id,
        "text": f"<b>{html.escape(_clean(title, 512))}</b>\n{html.escape(_clean(message, 3500))}",
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload, allow_redirects=False) as resp:
                if resp.status != 200:
                    raise DeliveryError(f"Telegram returned {resp.status}")
    except DeliveryError:
        raise
    except Exception as e:
        raise DeliveryError(f"Telegram delivery failed: {type(e).__name__}") from None
