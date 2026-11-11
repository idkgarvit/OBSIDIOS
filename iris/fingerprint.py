"""iris/fingerprint.py — device identity from discovery metadata.

A host label of ``UNKN`` or ``LNX`` tells an operator nothing. The scanner
already collects the evidence needed to name most devices: a PTR name, the MAC
OUI, Nmap's OS guess and the ports that are open. This module combines that
evidence into a single device class (``ROUTER``, ``PHONE``, ``LAPTOP`` …) and
resolves missing hostnames through NSS, which catches the mDNS names that a
plain reverse DNS lookup on this network misses.
"""
from __future__ import annotations

import asyncio
import re
import socket

from loguru import logger

from iris.osint_scanner import _lookup_mac_vendor

# Device classes stored in hosts.device and rendered by the topology.
ROUTER = "ROUTER"
AP = "AP"
PHONE = "PHONE"
TABLET = "TABLET"
LAPTOP = "LAPTOP"
DESKTOP = "DESKTOP"
SERVER = "SERVER"
NAS = "NAS"
PRINTER = "PRINTER"
CAMERA = "CAMERA"
TV = "TV"
MEDIA = "MEDIA"
IOT = "IOT"
VM = "VM"
HOST = "HOST"

_UNKNOWN_MACS = {"", "UNKNOWN", "NONE", "N/A", "NA"}
_UNKNOWN_VENDORS = {"", "UNKNOWN", "UNKNOWN VENDOR", "N/A", "NA", "NONE"}

_LOCAL_SUFFIXES = (
    ".local", ".lan", ".localdomain", ".home", ".home.arpa", ".internal",
    ".fritz.box",
)

_HOSTNAME_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (ROUTER, re.compile(
        r"(?:^|[^a-z0-9])(router|gateway|firewall|pfsense|opnsense|openwrt|"
        r"dd-?wrt|fritzbox|fritz|unifi|edgerouter|routeros|zyxel|d-?link|"
        r"tplink|tp-link|netgear|mikrotik|archer|deco|orbi|airport|repeater|"
        r"extender|access-?point)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (TABLET, re.compile(
        r"(?:^|[^a-z0-9])(ipad|tablet|tab[0-9]|galaxy-?tab|matepad|"
        r"lenovo-?tab|surface-?go)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (PHONE, re.compile(
        r"(?:^|[^a-z0-9])(iphone|ipod|android|galaxy|pixel|nexus|oneplus|"
        r"one-plus|realme|narzo|redmi|poco|xiaomi|mi-[0-9]|honor|huawei|oppo|"
        r"vivo|moto|sm-[a-z0-9]|xperia|nokia|infinix|tecno|itel|micromax|"
        r"nothing-?phone)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (PRINTER, re.compile(
        r"(?:^|[^a-z0-9])(printer|print|mfp|laserjet|deskjet|officejet|pixma|"
        r"ecotank|workforce|imageclass|brother|epson|canon|lexmark|xerox|"
        r"ricoh|kyocera)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (NAS, re.compile(
        r"(?:^|[^a-z0-9])(nas|synology|diskstation|qnap|truenas|freenas|"
        r"unraid|openmediavault|readynas)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (LAPTOP, re.compile(
        r"(?:^|[^a-z0-9])(laptop|notebook|macbook|thinkpad|ideapad|legion|"
        r"pavilion|elitebook|probook|spectre|envy|latitude|inspiron|vostro|"
        r"xps|surface|chromebook|zenbook|vivobook|aspire|predator|nitro|"
        r"travelmate|swift|gram|matebook)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (DESKTOP, re.compile(
        r"(?:^|[^a-z0-9])(desktop|workstation|optiplex|thinkcentre|prodesk|"
        r"elitedesk|gaming-?pc|tower)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (VM, re.compile(
        r"(?:^|[^a-z0-9])(vm|virtual-?machine|vbox|vmware|qemu|kvm)(?:[^a-z0-9]|$)",
        re.IGNORECASE)),
    (MEDIA, re.compile(
        r"(?:^|[^a-z0-9])(plex|emby|jellyfin|kodi|mediaserver|media-server)"
        r"(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (SERVER, re.compile(
        r"(?:^|[^a-z0-9])(server|srv|proxmox|esxi|vcenter|docker|kubernetes|"
        r"k8s|hypervisor)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (CAMERA, re.compile(
        r"(?:^|[^a-z0-9])(cam|camera|ipcam|webcam|hikvision|dahua|reolink|"
        r"amcrest|foscam|arlo|wyze|uniview|axis)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (TV, re.compile(
        r"(?:^|[^a-z0-9])(tv|smart-?tv|bravia|roku|fire-?tv|firestick|"
        r"chromecast|apple-?tv|appletv|nvidia-?shield|sonos|vizio|hisense|"
        r"playstation|ps[45]|xbox)(?:[^a-z0-9]|$)", re.IGNORECASE)),
    (IOT, re.compile(
        r"(?:^|[^a-z0-9])(esp[0-9]*|espressif|tuya|shelly|sonoff|tasmota|"
        r"zigbee|z-?wave|smart-?plug|alexa|echo|nest|ring|doorbell|thermostat|"
        r"sensor|raspberry-?pi|rpi)(?:[^a-z0-9]|$)", re.IGNORECASE)),
)

# Vendors that make networking gear in addition to (or instead of) endpoints.
_NETWORK_VENDORS = (
    "zyxel", "ubiquiti", "ubnt", "netgear", "tp-link", "tplink", "d-link",
    "dlink", "mikrotik", "cisco", "arris", "technicolor", "sagemcom",
    "fritz", "avm", "tenda", "mercusys", "linksys", "belkin", "juniper",
    "fortinet", "watchguard", "sophos", "palo alto", "extreme networks",
)
_PHONE_VENDORS = (
    "samsung", "xiaomi", "oneplus", "oppo", "vivo", "realme", "motorola",
    "nokia", "sony", "lg electronics", "htc", "zte", "tecno", "infinix",
    "itel", "nothing", "huawei", "honor",
)
_LAPTOP_VENDORS = (
    "hp", "hewlett", "dell", "lenovo", "acer", "toshiba", "razer", "msi",
    "fujitsu", "clevo", "system76",
)
_PRINTER_VENDORS = (
    "brother", "epson", "canon", "xerox", "ricoh", "kyocera", "lexmark",
    "konica", "sharp",
)
_CAMERA_VENDORS = (
    "hikvision", "dahua", "reolink", "amcrest", "foscam", "axis", "uniview",
    "arlo", "wyze",
)
_NAS_VENDORS = (
    "synology", "qnap", "western digital", "buffalo", "asustor",
    "terramaster", "drobo",
)
_VM_VENDORS = (
    "vmware", "virtualbox", "oracle virtualbox", "hyper-v", "qemu",
    "parallels", "xen",
)
_TV_VENDORS = ("roku", "sonos", "vizio", "hisense", "tcl")
_IOT_VENDORS = (
    "espressif", "tuya", "shelly", "sonoff", "raspberry pi", "arduino",
    "particle", "nordic semiconductor", "texas instruments",
)
# Vendors whose OUI is used by both laptops and routers; only a gateway role
# or a matching hostname may decide.
_AMBIGUOUS_VENDORS = (
    "asus", "microsoft", "apple", "intel", "realtek", "google", "amazon",
)

_DB_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017}
_PRINTER_PORTS = {515, 631, 9100}
_CAMERA_PORTS = {554, 8554, 37777}
_IOT_PORTS = {502, 1883, 8883}
_MEDIA_PORTS = {32400, 8096}
_TV_PORTS = {8008, 8009}
_ROUTER_PORTS = {53, 67, 68, 80, 443, 161}


def _clean_text(value, limit: int = 128) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:limit]


# Nmap ships the full IEEE OUI list; the built-in table only names a few
# dozen vendors. Read Nmap's copy instead of vendoring ~30k rows.
_NMAP_PREFIX_FILES = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
)
_nmap_prefixes: dict[str, str] | None = None


def _load_nmap_prefixes() -> dict[str, str]:
    """Load Nmap's OUI table once; an absent file simply yields no entries."""
    global _nmap_prefixes
    if _nmap_prefixes is not None:
        return _nmap_prefixes
    table: dict[str, str] = {}
    for path in _NMAP_PREFIX_FILES:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
                    vendor = parts[1].strip()[:128]
                    if len(prefix) >= 6 and vendor:
                        table[prefix[:6]] = vendor
        except OSError:
            continue
        if table:
            break
    _nmap_prefixes = table
    return table


def _nmap_oui_vendor(mac: str) -> str | None:
    """Vendor from Nmap's prefix list, for OUIs the local table misses."""
    hex_only = re.sub(r"[^0-9A-F]", "", (mac or "").upper())
    if len(hex_only) < 6:
        return None
    return _load_nmap_prefixes().get(hex_only[:6])


def _clean_hostname(name, ip: str | None = None) -> str | None:
    """Normalise a PTR/NSS name, dropping IPs, local domains and placeholders."""
    if not isinstance(name, str):
        return None
    name = name.strip().rstrip(".")
    if not name:
        return None
    if ip and name == ip:
        return None
    lowered = name.lower()
    if lowered in {"localhost", "localhost.localdomain", "unknown", "none",
                   "(none)", "_gateway", "_gateway.local"}:
        return None
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", name):
        return None
    for suffix in _LOCAL_SUFFIXES:
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name[:128] or None


def lookup_mac_vendor(mac: str) -> str | None:
    """Return the OUI vendor for a real (non-randomised) MAC address.

    Locally administered addresses — the second-least-significant bit of the
    first octet — are randomised client MACs. Looking their prefix up in an OUI
    table produces confident nonsense, so they carry no vendor evidence.
    """
    if not isinstance(mac, str):
        return None
    raw = mac.strip().upper()
    if not raw or raw in _UNKNOWN_MACS:
        return None
    hex_only = re.sub(r"[^0-9A-F]", "", raw)
    if len(hex_only) < 6:
        return None
    try:
        first = int(hex_only[:2], 16)
    except ValueError:
        return None
    if first & 0x01 or first & 0x02:
        return None
    vendor = _lookup_mac_vendor(raw)
    return vendor or _nmap_oui_vendor(raw)


def resolve_vendor(mac: str | None, nmap_vendor: str | None = None) -> str | None:
    """Prefer Nmap's OUI name, then the local table/operator overrides."""
    candidate = _clean_text(nmap_vendor)
    if candidate and candidate.upper() not in _UNKNOWN_VENDORS:
        return candidate
    return lookup_mac_vendor(mac) if isinstance(mac, str) else None


async def _getent_hostname(ip: str, timeout_s: float) -> str | None:
    """Ask NSS for a name; this sees mDNS names that DNS PTR lookups miss."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "getent", "hosts", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except (FileNotFoundError, NotImplementedError, OSError):
        return None
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout_s)
    except TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return None
    if proc.returncode != 0:
        return None
    for line in (stdout or b"").decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            return _clean_hostname(parts[1], ip)
    return None


async def reverse_dns(ip: str, timeout_s: float = 1.5) -> str | None:
    """Resolve one address with a bounded wait; never raises.

    ``socket.gethostbyaddr`` runs in the default executor because it is
    synchronous. If it finds nothing, ``getent hosts`` retries through the full
    NSS chain (mDNS/Avahi included).
    """
    if not isinstance(ip, str) or not ip.strip():
        return None
    ip = ip.strip()
    loop = asyncio.get_running_loop()
    try:
        answer = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout_s)
        name = answer[0] if isinstance(answer, tuple) and answer else answer
        cleaned = _clean_hostname(name, ip)
        if cleaned:
            return cleaned
    except (TimeoutError, OSError, UnicodeError, TypeError) as exc:
        logger.debug(f"[IRIS/FINGERPRINT] PTR lookup failed for {ip}: {exc}")
    try:
        return await _getent_hostname(ip, timeout_s)
    except Exception as exc:
        logger.debug(f"[IRIS/FINGERPRINT] NSS lookup failed for {ip}: {exc}")
        return None


async def resolve_hostnames(
    ips: list[str], concurrency: int = 16, timeout_s: float = 1.5,
) -> dict[str, str]:
    """Resolve a batch of addresses without letting one lookup stall the rest."""
    unique = []
    seen = set()
    for ip in ips or []:
        if isinstance(ip, str) and ip.strip() and ip not in seen:
            seen.add(ip)
            unique.append(ip.strip())
    if not unique:
        return {}

    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(address: str):
        async with sem:
            return address, await reverse_dns(address, timeout_s)

    results = await asyncio.gather(*(one(ip) for ip in unique),
                                   return_exceptions=True)
    resolved: dict[str, str] = {}
    for item in results:
        if isinstance(item, BaseException):
            continue
        address, name = item
        if name:
            resolved[address] = name
    return resolved


def _port_set(ports) -> set[int]:
    numbers: set[int] = set()
    for entry in ports or []:
        value = entry.get("port") if isinstance(entry, dict) else getattr(entry, "port", None)
        if isinstance(value, int) and not isinstance(value, bool):
            numbers.add(value)
    return numbers


def _has_word(text: str, names: tuple[str, ...]) -> bool:
    return any(
        re.search(rf"(?:^|[^a-z0-9]){re.escape(name)}(?:[^a-z0-9]|$)", text)
        for name in names
    )


def _classify_hostname(hostname: str) -> str | None:
    text = (hostname or "").strip().lower()
    if not text:
        return None
    for device, pattern in _HOSTNAME_RULES:
        if pattern.search(text):
            return device
    return None


def _classify_os(os_name: str | None) -> str | None:
    text = (os_name or "").strip().lower()
    if not text:
        return None
    if "ipad" in text or "tablet" in text:
        return TABLET
    if "cisco ios" in text or "routeros" in text or "openwrt" in text:
        return ROUTER
    if re.search(r"\bios\b", text) or "iphone" in text or "android" in text:
        return PHONE
    if "mac os" in text or "macos" in text or "darwin" in text or "os x" in text:
        return LAPTOP
    if "windows" in text:
        return DESKTOP
    if "vmware" in text or "virtualbox" in text or "hypervisor" in text:
        return VM
    return None


def _classify_vendor(vendor: str) -> str | None:
    text = (vendor or "").strip().lower()
    if not text:
        return None
    if _has_word(text, _NETWORK_VENDORS):
        return ROUTER
    if _has_word(text, _VM_VENDORS):
        return VM
    if _has_word(text, _NAS_VENDORS):
        return NAS
    if _has_word(text, _PRINTER_VENDORS):
        return PRINTER
    if _has_word(text, _CAMERA_VENDORS):
        return CAMERA
    if _has_word(text, _TV_VENDORS):
        return TV
    if _has_word(text, _PHONE_VENDORS):
        return PHONE
    if _has_word(text, _AMBIGUOUS_VENDORS):
        return None
    if _has_word(text, _LAPTOP_VENDORS):
        return LAPTOP
    if _has_word(text, _IOT_VENDORS):
        return IOT
    return None


def _looks_like_gateway(ip: str | None, vendor: str, ports: set[int]) -> bool:
    if not isinstance(ip, str):
        return False
    last = ip.rsplit(".", 1)[-1]
    if last not in {"1", "254"}:
        return False
    if vendor and _has_word(vendor.lower(), _NETWORK_VENDORS):
        return True
    if {67, 68} & ports:
        return True
    return bool(_ROUTER_PORTS & ports)


def infer_device(
    ip: str | None = None,
    mac: str | None = None,
    hostname: str | None = None,
    vendor: str | None = None,
    os_name: str | None = None,
    ports=None,
    nmap_vendor: str | None = None,
) -> str:
    """Return the most likely device class from the available evidence.

    A hostname that names an end device wins over the gateway heuristic; a
    gateway address with router services wins over a silent, unnamed host.
    """
    vendor_name = resolve_vendor(mac, nmap_vendor or vendor) or ""
    port_set = _port_set(ports)
    host_class = _classify_hostname(hostname or "")

    if host_class and host_class != ROUTER:
        return host_class
    if _looks_like_gateway(ip, vendor_name, port_set):
        return ROUTER
    if host_class == ROUTER:
        return ROUTER

    if _PRINTER_PORTS & port_set:
        return PRINTER
    if _CAMERA_PORTS & port_set:
        return CAMERA
    if 3389 in port_set:
        return DESKTOP
    if _DB_PORTS & port_set:
        return SERVER
    if _IOT_PORTS & port_set:
        return IOT
    if _MEDIA_PORTS & port_set:
        return MEDIA
    if _TV_PORTS & port_set:
        return TV

    vendor_class = _classify_vendor(vendor_name)
    if vendor_class:
        return vendor_class
    os_class = _classify_os(os_name)
    if os_class:
        return os_class
    return HOST
