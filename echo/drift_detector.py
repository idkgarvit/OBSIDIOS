"""
echo/drift_detector.py
───────────────────────
ECHO — The Behavioral Immune System.

Learns what "normal" looks like for every device on the network.
Detects zero-days, compromised hosts, and insider threats purely
by recognizing behavioral drift — no CVE, no signature needed.

How it works:
  1. Capture live traffic via Scapy on the Host-Only interface
  2. Build per-device behavioral DNA over 7+ days:
       - Traffic volume (bytes in/out per 5-min window)
       - Active hours (bitmap of hours 0-23)
       - Peer set (which IPs does this device talk to?)
       - Protocol distribution (TCP/UDP/ICMP ratios)
       - Session frequency (connections per minute)
       - DNS query rate
  3. After baseline is ready, compare every new window
     against the baseline using Z-score anomaly detection
  4. Flag anything that deviates > 2.5 standard deviations
  5. Specific detectors for:
       - C2 beaconing (regular outbound intervals)
       - DNS tunneling (abnormally large DNS queries)
       - Data exfiltration (sudden spike in bytes_out)
       - New peer (device talking to IP it never has before)
       - Off-hours activity (device active outside normal hours)

Zero dependencies on CVEs or signatures — purely statistical.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import os
import time
from collections import defaultdict
from typing import Any

from loguru import logger

from chronicle import db
from chronicle.models import Anomaly, AnomalyType, BehavioralEvent

# ── Constants ──────────────────────────────────────────────────────────────
WINDOW_SECONDS      = 300      # 5-minute observation windows
MIN_SAMPLES_BASELINE = 20      # Need 20 windows before baseline is "ready"
ZSCORE_THRESHOLD    = 2.5      # Flag if Z-score > this
BEACON_CHECK_SECS   = 600      # Check for beaconing every 10 min
DNS_LARGE_QUERY_BYTES = 200    # DNS query > this bytes = suspicious
MAX_TRACKED_PEERS   = 2048     # Cap per-host peer sets (memory + baseline size)
MAX_BASELINE_PEERS  = 5000     # Cap peers persisted in a baseline row
MAX_TRACKED_HOSTS   = 4096     # Cap per-window host buckets against spoofed sources
DEFAULT_IFACE       = os.environ.get("OBSIDIOS_CAPTURE_IFACE", "eth0")
AUTORESPOND_MIN_CONFIDENCE = 0.85   # SHIELD may act without a human
# "New peer" is the noisiest signal ECHO produces (a laptop visiting one new
# site is not an intrusion), so it is capped just below the autonomous-action
# gate and always needs an operator.
NEW_PEER_MAX_CONFIDENCE = 0.8


def _resolve_network(network: str | None) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse an observation network; None means "fall back to configured target"."""
    if not network:
        try:
            from config import settings
            network = settings.scan.target_network
        except Exception:
            network = ""
    if not network:
        return None
    try:
        return ipaddress.ip_network(network, strict=False)
    except ValueError:
        logger.error(f"[ECHO] Invalid observation network {network!r} — not tracking any hosts")
        return None




# ─────────────────────────────────────────────────────────────────────────────
# Live packet capture (Scapy)
# ─────────────────────────────────────────────────────────────────────────────

class PacketCollector:
    """
    Collects packets in a rolling 5-minute window per host.
    Runs in a background thread (Scapy is synchronous).
    """

    def __init__(self, iface: str = DEFAULT_IFACE, network: str | None = None):
        self.iface    = iface
        self.network  = _resolve_network(network)
        self._running = False

        # Per-host counters for current window
        # {ip: {bytes_in, bytes_out, sessions, protocols, peers, dns_queries}}
        self._counters: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "bytes_in":    0,
                "bytes_out":   0,
                "sessions":    0,
                "protocols":   defaultdict(int),
                "peers":       set(),
                "dns_queries": 0,
            }
        )
        self._window_start = time.time()

    def _is_local(self, ip: str) -> bool:
        """True when ip belongs to the observed network (network-aware, not string prefix)."""
        if self.network is None:
            return False
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False

    def _track_peer(self, bucket: dict[str, Any], peer: str) -> None:
        peers = bucket["peers"]
        if len(peers) < MAX_TRACKED_PEERS:
            peers.add(peer)

    def _bucket(self, ip: str) -> dict[str, Any] | None:
        """Return the counter bucket for ip, or None once the host cap is hit."""
        bucket = self._counters.get(ip)
        if bucket is not None:
            return bucket
        if len(self._counters) >= MAX_TRACKED_HOSTS:
            return None
        return self._counters[ip]

    def _process_packet(self, pkt: Any) -> None:
        """Process one packet — update counters for src and dst hosts."""
        try:
            # Import here to avoid Scapy loading at module level
            from scapy.all import DNS, DNSQR, IP, TCP, UDP, IPv6

            # IPv6 is a normal deployment for this product; ignoring it made
            # ECHO silently observe nothing on a v6-only network.
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            else:
                return
            length = len(pkt)

            # Only track hosts inside the observation network
            src_local = self._is_local(src)
            dst_local = self._is_local(dst)

            if not (src_local or dst_local):
                return

            src_bucket = self._bucket(src) if src_local else None
            dst_bucket = self._bucket(dst) if dst_local else None
            if src_bucket is None and dst_bucket is None:
                return

            # Update bytes
            if src_bucket is not None:
                src_bucket["bytes_out"] += length
                self._track_peer(src_bucket, dst)
            if dst_bucket is not None:
                dst_bucket["bytes_in"] += length
                self._track_peer(dst_bucket, src)

            # Protocol tracking
            if pkt.haslayer(TCP):
                if src_bucket is not None:
                    src_bucket["protocols"]["tcp"] += 1
                    # New connection (SYN flag)
                    if pkt[TCP].flags == "S":
                        src_bucket["sessions"] += 1
            elif pkt.haslayer(UDP):
                if src_bucket is not None:
                    src_bucket["protocols"]["udp"] += 1

            # DNS query detection. `DNSQR` is also present in responses, and
            # any DNS response over 200 bytes (EDNS/DNSSEC/TXT) used to be
            # counted as a "large query", flagging DNS tunneling constantly.
            dns = pkt.getlayer(DNS)
            if dns is not None and dns.qr == 0 and pkt.haslayer(DNSQR):
                host_bucket = src_bucket if src_local else dst_bucket
                if host_bucket is not None:
                    host_bucket["dns_queries"] += 1
                    # Large DNS query = potential tunneling
                    if length > DNS_LARGE_QUERY_BYTES:
                        host_bucket["protocols"]["dns_large"] += 1

        except Exception:
            pass  # Never let packet errors crash the collector

    def get_window_snapshot(self) -> dict[str, BehavioralEvent]:
        """
        Take a snapshot of current window counters.
        Returns {ip: BehavioralEvent} and resets counters.
        """
        now      = time.time()
        snapshot = {}

        for ip, counters in self._counters.items():
            snapshot[ip] = BehavioralEvent(
                host_id   = 0,   # filled in by caller after DB lookup
                ts        = now,
                bytes_in  = counters["bytes_in"],
                bytes_out = counters["bytes_out"],
                sessions  = counters["sessions"],
                protocols = dict(counters["protocols"]),
                peers     = list(counters["peers"]),
                dns_queries = counters["dns_queries"],
            )

        # Reset counters for next window
        self._counters.clear()
        self._window_start = now
        return snapshot

    def start_capture(self, duration: int = WINDOW_SECONDS) -> None:
        """Capture packets for `duration` seconds (blocking)."""
        try:
            from scapy.all import sniff
            self._running = True
            sniff(
                iface   = self.iface,
                prn     = self._process_packet,
                timeout = duration,
                store   = False,   # Don't store packets — saves memory
            )
        except Exception as exc:
            logger.error(f"[ECHO] Packet capture error: {exc}")
        finally:
            self._running = False


# ─────────────────────────────────────────────────────────────────────────────
# Baseline management
# ─────────────────────────────────────────────────────────────────────────────

async def _get_or_create_baseline(host_id: int) -> dict[str, Any] | None:
    """Load existing baseline for a host from DB."""
    row = await db.fetch_one(
        "SELECT * FROM behavioral_baselines WHERE host_id=?", (host_id,)
    )
    if row:
        return dict(row)
    return None


def _count(value: Any) -> int:
    """Non-negative integer from stored/JSON data, without ever raising."""
    try:
        number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, number)


async def _update_baseline(host_id: int, event: BehavioralEvent) -> None:
    """
    Update behavioral baseline with a new observation using
    Welford's online algorithm for running mean and variance.
    This is O(1) memory — no need to store all historical values.
    """
    baseline = await _get_or_create_baseline(host_id)
    now      = time.time()
    hour     = time.localtime(event.ts).tm_hour

    if baseline is None:
        # First observation — create baseline
        hour_bit = 1 << hour
        await db.execute_returning(
            """INSERT INTO behavioral_baselines
               (host_id, window_start, window_end,
                bytes_in_mean, bytes_in_std,
                bytes_out_mean, bytes_out_std,
                session_count_mean, session_count_std,
                active_hours_bitmap, peer_set_json,
                protocol_dist_json, dns_query_rate_mean,
                dns_query_rate_std, sample_count, is_baseline_ready)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)
               RETURNING id""",
            (
                host_id, now, now,
                float(event.bytes_in), 0.0,
                float(event.bytes_out), 0.0,
                float(event.sessions), 0.0,
                hour_bit,
                json.dumps(sorted(event.peers)[:MAX_BASELINE_PEERS]),
                json.dumps(dict(event.protocols)),
                float(event.dns_queries), 0.0,
                1,
            ),
        )
        return

    # Welford's online algorithm for mean and variance. Legacy/hand-edited
    # rows can carry NULL or non-numeric aggregates; coerce instead of
    # raising, otherwise that host never becomes baseline-ready.
    baseline = {
        key: (0 if value is None else value)
        for key, value in baseline.items()
    }
    n      = _count(baseline["sample_count"]) + 1
    ready  = 1 if n >= MIN_SAMPLES_BASELINE else 0

    def welford_update(mean: float, std: float, new_val: float, n: int):
        delta  = new_val - mean
        mean  += delta / n
        delta2 = new_val - mean
        # variance = M2 / n (we store std as variance for simplicity)
        variance = ((std ** 2) * (n - 1) + delta * delta2) / n
        return mean, math.sqrt(max(variance, 0))

    bi_mean, bi_std  = welford_update(_coerce(baseline["bytes_in_mean"]),  _coerce(baseline["bytes_in_std"]),  event.bytes_in,  n)
    bo_mean, bo_std  = welford_update(_coerce(baseline["bytes_out_mean"]), _coerce(baseline["bytes_out_std"]), event.bytes_out, n)
    sc_mean, sc_std  = welford_update(_coerce(baseline["session_count_mean"]), _coerce(baseline["session_count_std"]), event.sessions, n)
    dns_mean, dns_std = welford_update(_coerce(baseline["dns_query_rate_mean"]), _coerce(baseline["dns_query_rate_std"]), event.dns_queries, n)

    # Update active hours bitmap
    hour_bit = _count(baseline["active_hours_bitmap"]) | (1 << hour)

    # Update peer set (union of all seen peers, bounded to keep rows small).
    # Once the cap is reached the stored set is left alone: keeping the
    # lexicographically-first N would forget every later peer and re-alert on
    # it in every single window.
    try:
        existing_peers = set(json.loads(baseline["peer_set_json"]))
    except Exception:
        try:
            existing_peers = set(json.loads(baseline["peer_set_json"].replace("'", '"')))
        except Exception:
            existing_peers = set()
    if len(existing_peers) < MAX_BASELINE_PEERS:
        new_peers = sorted(existing_peers | set(event.peers))[:MAX_BASELINE_PEERS]
    else:
        new_peers = sorted(existing_peers)

    # Merge protocol distribution counts so the baseline describes normal traffic mix
    try:
        protocol_dist = json.loads(baseline["protocol_dist_json"] or "{}")
        if not isinstance(protocol_dist, dict):
            protocol_dist = {}
    except Exception:
        protocol_dist = {}
    for proto, count in (event.protocols or {}).items():
        protocol_dist[proto] = _count(protocol_dist.get(proto, 0)) + _count(count)

    await db.execute_returning(
        """UPDATE behavioral_baselines SET
           window_end=?, bytes_in_mean=?, bytes_in_std=?,
           bytes_out_mean=?, bytes_out_std=?,
           session_count_mean=?, session_count_std=?,
           active_hours_bitmap=?, peer_set_json=?, protocol_dist_json=?,
           dns_query_rate_mean=?, dns_query_rate_std=?,
           sample_count=?, is_baseline_ready=?
           WHERE host_id=? RETURNING id""",
        (
            now, bi_mean, bi_std, bo_mean, bo_std,
            sc_mean, sc_std, hour_bit,
            json.dumps(new_peers), json.dumps(protocol_dist, sort_keys=True),
            dns_mean, dns_std,
            n, ready, host_id,
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

def _coerce(value: Any) -> float:
    """Best-effort float for a stored aggregate (NULL/NULL-ish -> 0.0)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _zscore(value: float, mean: float, std: float) -> float:
    """Calculate Z-score. Returns 0 if std is 0 or the row is malformed."""
    value, mean, std = _coerce(value), _coerce(mean), _coerce(std)
    if std < 0.001:
        return 0.0
    return abs(value - mean) / std


def _increase_zscore(value: float, mean: float, std: float) -> float:
    """Z-score for increases only.

    A host whose DNS rate *drops* to zero is quiet, not tunnelling. Using the
    absolute deviation here labelled every quiet host as a DNS anomaly.
    """
    value, mean, std = _coerce(value), _coerce(mean), _coerce(std)
    if std < 0.001:
        return 0.0
    return max(0.0, (value - mean) / std)


async def _detect_anomalies(
    host_id: int,
    event: BehavioralEvent,
    baseline: dict[str, Any],
) -> list[Anomaly]:
    """
    Run all anomaly detectors against a new observation.
    Returns list of detected anomalies.
    """
    anomalies: list[Anomaly] = []

    if not _count(baseline.get("is_baseline_ready")):
        return anomalies   # Not enough data yet

    # A hand-edited or legacy row can carry NULL/non-numeric aggregates; the
    # comparisons below assume numbers.
    baseline = {k: (0 if v is None else v) for k, v in baseline.items()}

    # ── 1. Traffic spike detector ──────────────────────────────────────
    # Increase-only: a host going silent is not exfiltration, but an absolute
    # Z-score flagged 0 bytes against a 50 kB mean as one.
    bytes_out_z = _increase_zscore(event.bytes_out, baseline["bytes_out_mean"], baseline["bytes_out_std"])
    if bytes_out_z > ZSCORE_THRESHOLD:
        confidence = min(bytes_out_z / 10.0, 1.0)
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.DATA_EXFIL_SUSPECT if bytes_out_z > 5 else AnomalyType.TRAFFIC_SPIKE,
            confidence   = confidence,
            z_score      = bytes_out_z,
            detail       = (
                f"Outbound traffic {event.bytes_out} bytes vs baseline "
                f"mean={baseline['bytes_out_mean']:.0f} std={baseline['bytes_out_std']:.0f} "
                f"(Z={bytes_out_z:.1f})"
            ),
        ))

    bytes_in_z = _increase_zscore(event.bytes_in, baseline["bytes_in_mean"], baseline["bytes_in_std"])
    if bytes_in_z > ZSCORE_THRESHOLD:
        confidence = min(bytes_in_z / 10.0, 1.0)
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.TRAFFIC_SPIKE,
            confidence   = confidence,
            z_score      = bytes_in_z,
            detail       = (
                f"Inbound traffic spike: {event.bytes_in} bytes "
                f"(Z={bytes_in_z:.1f})"
            ),
        ))

    # ── 2. New peer detector ───────────────────────────────────────────
    try:
        known_peers = set(json.loads(baseline["peer_set_json"]))
    except Exception:
        try:
            known_peers = set(json.loads(baseline["peer_set_json"].replace("'", '"')))
        except Exception:
            known_peers = set()

    new_peers = set(event.peers) - known_peers
    # A saturated baseline has forgotten peers; re-reporting them every window
    # produced an alert storm for any host with broad internet egress.
    if new_peers and len(known_peers) < MAX_BASELINE_PEERS:
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.NEW_PEER,
            confidence   = min(len(new_peers) * 0.3, NEW_PEER_MAX_CONFIDENCE),
            detail       = ("New communication peers detected: "
                            + ", ".join(sorted(new_peers)[:5])),
        ))

    # ── 3. Off-hours activity detector ────────────────────────────────
    current_hour = time.localtime(event.ts).tm_hour
    hour_bit     = _count(baseline["active_hours_bitmap"])
    if hour_bit and not (hour_bit & (1 << current_hour)):
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.HOUR_DRIFT,
            confidence   = 0.7,
            detail       = f"Activity detected at hour {current_hour} — outside normal active hours",
        ))

    # ── 4. DNS anomaly detector ────────────────────────────────────────
    dns_z = _increase_zscore(event.dns_queries, baseline["dns_query_rate_mean"], baseline["dns_query_rate_std"])
    if dns_z > ZSCORE_THRESHOLD:
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.DNS_ANOMALY,
            confidence   = min(dns_z / 8.0, 1.0),
            z_score      = dns_z,
            detail       = f"DNS query rate {event.dns_queries} vs baseline mean={baseline['dns_query_rate_mean']:.1f} (Z={dns_z:.1f}) — possible DNS tunneling",
        ))

    # ── 5. Protocol drift detector ─────────────────────────────────────
    if event.protocols.get("dns_large", 0) > 0:
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.DNS_ANOMALY,
            confidence   = 0.8,
            detail       = f"Large DNS queries detected ({event.protocols['dns_large']} packets > {DNS_LARGE_QUERY_BYTES} bytes) — DNS tunneling suspected",
        ))

    # ── 6. Beacon pattern detector ────────────────────────────────────
    # Check session regularity: if sessions are suspiciously regular
    # (low variance, consistent count), it may be C2 beaconing
    session_mean = _coerce(baseline["session_count_mean"])
    session_std  = _coerce(baseline["session_count_std"])
    session_z = _zscore(event.sessions, session_mean, session_std)
    if (event.sessions > 5 and session_z < 0.3 and
            session_std < 1.0 and
            session_mean > 3):
        # Suspiciously regular — low variance means machine-like regularity
        anomalies.append(Anomaly(
            host_id      = host_id,
            anomaly_type = AnomalyType.BEACON_PATTERN,
            confidence   = 0.65,
            detail       = (
                f"Suspiciously regular outbound sessions detected "
                f"({event.sessions} sessions, Z={session_z:.2f}) — possible C2 beaconing"
            ),
        ))

    return anomalies


async def _persist_anomaly(anomaly: Anomaly) -> int | None:
    """Save anomaly to CHRONICLE. Returns the new row id (or None on failure)."""
    row = await db.execute_returning(
        """INSERT INTO anomalies
           (host_id, anomaly_type, confidence, z_score, detail)
           VALUES (?,?,?,?,?) RETURNING id""",
        (
            anomaly.host_id,
            str(anomaly.anomaly_type),
            anomaly.confidence,
            anomaly.z_score,
            anomaly.detail,
        ),
    )
    return row["id"] if row else None


async def _autorespond(anomaly: Anomaly, anomaly_id: int | None) -> dict | None:
    """Hand a high-confidence anomaly to SHIELD (quarantine is opt-in + dry-run gated)."""
    if anomaly_id is None:
        return None
    if anomaly.confidence < AUTORESPOND_MIN_CONFIDENCE:
        return None
    try:
        from shield.reconfigurer import respond_to_anomaly
        return await respond_to_anomaly(anomaly_id, anomaly.host_id, anomaly.confidence)
    except Exception as exc:  # never let auto-response break detection
        logger.error(f"[ECHO] SHIELD auto-response failed for anomaly #{anomaly_id}: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def process_window(snapshot: dict[str, BehavioralEvent]) -> list[Anomaly]:
    """
    Process one 5-minute window of behavioral observations.
    Updates baselines and runs anomaly detection for each host.
    Returns all anomalies detected in this window.
    """
    all_anomalies: list[Anomaly] = []

    for ip, event in snapshot.items():
        # One malformed event or DB hiccup must not abort the whole window.
        try:
            # Get host ID from DB
            host_row = await db.fetch_one("SELECT id FROM hosts WHERE ip=?", (ip,))
            if not host_row:
                continue

            host_id    = host_row["id"]
            event.host_id = host_id

            # Store raw behavioral event
            await db.execute(
                """INSERT INTO behavioral_events
                   (host_id, ts, bytes_in, bytes_out, sessions, dns_queries)
                   VALUES (?,?,?,?,?,?)""",
                (host_id, event.ts, event.bytes_in, event.bytes_out,
                 event.sessions, event.dns_queries),
            )

            # Get or create baseline
            baseline = await _get_or_create_baseline(host_id)

            # Detect anomalies (only if baseline exists and is ready)
            if baseline and baseline["is_baseline_ready"]:
                anomalies = await _detect_anomalies(host_id, event, baseline)
                for anomaly in anomalies:
                    anomaly_id = await _persist_anomaly(anomaly)
                    all_anomalies.append(anomaly)
                    # Autonomous quarantine stays opt-in (SHIELD_AUTO_QUARANTINE=0 by default)
                    await _autorespond(anomaly, anomaly_id)

            # Update baseline with this observation
            await _update_baseline(host_id, event)
        except Exception as exc:
            logger.error(f"[ECHO] Failed to process window for {ip}: {exc}")
            continue

    return all_anomalies


async def run_echo(
    iface: str = DEFAULT_IFACE,
    network: str | None = None,
    duration_minutes: int = 5,
) -> list[Anomaly]:
    """
    Run ECHO for one observation period.
    Captures traffic, processes window, detects anomalies.
    """
    from rich.console import Console
    console = Console()

    collector = PacketCollector(iface=iface, network=network)
    shown_network = str(collector.network) if collector.network else "—"

    console.print("[bold cyan]👁  ECHO — Behavioral Monitor[/]")
    console.print(f"  Interface : [yellow]{iface}[/]")
    console.print(f"  Network   : [yellow]{shown_network}[/]")
    console.print(f"  Duration  : [yellow]{duration_minutes} min[/]\n")

    # Run packet capture in executor (blocking Scapy call)
    logger.info(f"[ECHO] Capturing traffic for {duration_minutes} minutes...")
    loop = asyncio.get_running_loop()

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        await loop.run_in_executor(
            executor,
            collector.start_capture,
            duration_minutes * 60,
        )

    logger.info("[ECHO] Processing behavioral window...")
    snapshot  = collector.get_window_snapshot()
    anomalies = await process_window(snapshot)

    # Check baseline status
    hosts = await db.fetch_all("SELECT id, ip FROM hosts WHERE is_active=1")
    console.print("\n[bold]Behavioral Baseline Status:[/]")
    for h in hosts:
        baseline = await _get_or_create_baseline(h["id"])
        if baseline:
            samples = baseline["sample_count"]
            ready   = "✅ Ready" if baseline["is_baseline_ready"] else f"⏳ Building ({samples}/{MIN_SAMPLES_BASELINE} samples)"
            console.print(f"  [cyan]{h['ip']:<20}[/] {ready}")
        else:
            console.print(f"  [cyan]{h['ip']:<20}[/] [dim]No data yet[/]")

    # Print anomalies
    if anomalies:
        console.print(f"\n[bold red]⚠  {len(anomalies)} ANOMALIES DETECTED[/]\n")
        for a in anomalies:
            host_row = await db.fetch_one("SELECT ip FROM hosts WHERE id=?", (a.host_id,))
            ip = host_row["ip"] if host_row else "?"
            conf_color = "red" if a.confidence > 0.7 else "yellow"
            console.print(
                f"  [{conf_color}]●[/] [cyan]{ip:<18}[/] "
                f"[yellow]{a.anomaly_type:<25}[/] "
                f"Confidence: [{conf_color}]{a.confidence:.0%}[/]"
            )
            console.print(f"    [dim]{a.detail}[/]\n")
    else:
        console.print("\n[green]✅ No anomalies detected — network behavior is normal[/]")

    logger.success(f"[ECHO] Window processed: {len(snapshot)} hosts, {len(anomalies)} anomalies")
    return anomalies


async def get_anomaly_summary() -> dict:
    """Get summary of all anomalies stored in CHRONICLE."""
    rows = await db.fetch_all(
        """SELECT a.anomaly_type, COUNT(*) as cnt,
                  AVG(a.confidence) as avg_conf,
                  h.ip
           FROM anomalies a JOIN hosts h ON h.id = a.host_id
           WHERE a.acknowledged = 0
           GROUP BY a.anomaly_type, h.ip
           ORDER BY avg_conf DESC"""
    )
    total = await db.fetch_val(
        "SELECT COUNT(*) FROM anomalies WHERE acknowledged = 0", default=0
    )
    return {
        "total": int(total or 0),
        "by_type": [dict(r) for r in rows],
    }
