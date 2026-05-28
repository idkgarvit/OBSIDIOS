"""iris/heartbeat.py — Ultra-fast ARP heartbeat loop"""
from __future__ import annotations
import asyncio
import time
from loguru import logger
from chronicle import db
from iris.wired_scanner import _arp_sweep

async def run_heartbeat_loop(target: str, socketio=None):
    """
    Continuous 15s ARP pulse to detect host presence changes.
    Emits SocketIO events for real-time dashboard updates.
    """
    logger.info(f"[IRIS/HEARTBEAT] Starting real-time pulse on {target}")
    
    while True:
        try:
            # 1. Fast 2s ARP Sweep
            loop = asyncio.get_running_loop()
            current_hosts = await loop.run_in_executor(None, _arp_sweep, target, 2.0)
            live_ips = {h["ip"] for h in current_hosts}
            
            # 2. Sync with DB
            db_active = await db.fetch_all("SELECT ip FROM hosts WHERE is_active=1")
            db_active_ips = {r["ip"] for r in db_active}
            
            new_ips = live_ips - db_active_ips
            gone_ips = db_active_ips - live_ips
            
            # 3. Process UP events
            for ip in new_ips:
                logger.success(f"[IRIS/HEARTBEAT] Host UP: {ip}")
                await db.execute(
                    "INSERT INTO hosts (ip, is_active, last_seen) VALUES (?, 1, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET is_active=1, last_seen=excluded.last_seen",
                    (ip, time.time())
                )
                if socketio:
                    socketio.emit("host_event", {"type": "UP", "ip": ip}, namespace="/")
            
            # 4. Process DOWN events
            for ip in gone_ips:
                logger.warning(f"[IRIS/HEARTBEAT] Host DOWN: {ip}")
                await db.execute("UPDATE hosts SET is_active=0 WHERE ip=?", (ip,))
                if socketio:
                    socketio.emit("host_event", {"type": "DOWN", "ip": ip}, namespace="/")

            if new_ips or gone_ips:
                # Trigger a global stats refresh on clients
                if socketio: 
                    socketio.emit("scan_progress", {"status": "refresh", "message": "Network topology changed"}, namespace="/")

        except Exception as e:
            logger.error(f"[IRIS/HEARTBEAT] Loop error: {e}")
            
        await asyncio.sleep(15) # Pulse every 15 seconds
