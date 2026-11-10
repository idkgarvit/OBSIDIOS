"""
config/network_detector.py
──────────────────────────
Network detection utilities for auto-detecting the current network.
"""
import ipaddress
import re
import socket
import subprocess
from typing import Any


def _valid_iface(name: str | None) -> bool:
    """Reject values that could be parsed as an `ip` command-line option.

    The name must start alphanumerically: a regex that allowed a leading dash
    accepted "--all" and passed it to `ip addr show`.
    """
    return bool(name) and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}", name
    ) is not None


def get_default_interface() -> str:
    """Get the default network interface (e.g., eth0, wlan0)."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'default' in line:
                parts = line.split()
                if 'dev' in parts:
                    idx = parts.index('dev')
                    if idx + 1 < len(parts):
                        return parts[idx + 1].split('@', 1)[0]
    except Exception:
        pass
    return 'eth0'


def _interface_ipv4(interface: str) -> str | None:
    """Return the first IPv4 address configured on `interface`."""
    if not _valid_iface(interface):
        return None
    try:
        result = subprocess.run(
            ['ip', 'addr', 'show', interface],
            capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        if 'inet ' not in line:
            continue
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        addr = parts[1].split('/')[0]
        try:
            ipaddress.IPv4Address(addr)
        except ValueError:
            continue
        return addr
    # The interface exists but has no IPv4 address. Do not silently report a
    # different interface's address.
    return None


def get_local_ip(interface: str = None) -> str | None:
    """Get local IP address. If interface specified, get IP for that interface."""
    if interface:
        return _interface_ipv4(interface)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        pass
    finally:
        if sock is not None:
            sock.close()

    # Air-gapped and segmented sensor networks have no route to 8.8.8.8.
    # Falling back to the kernel's default interface is what the operator
    # means by "this box's address"; without it, detection reported nothing
    # on exactly the offline networks OBSIDIOS is deployed into.
    return _interface_ipv4(get_default_interface())


def detect_network() -> dict[str, Any]:
    """
    Auto-detect the current network.
    Returns: {
        "interface": "wlan0",
        "local_ip": "192.168.1.45",
        "gateway": "192.168.1.1",
        "cidr": "192.168.1.0/24",
        "netmask": "255.255.255.0"
    }
    """
    interface = get_default_interface()
    local_ip = get_local_ip(interface)
    
    if not local_ip:
        return {
            "interface": interface,
            "local_ip": None,
            "gateway": None,
            "cidr": None,
            "error": "Could not detect local IP"
        }
    
    gateway = _get_gateway(interface)
    netmask = _get_netmask(interface)
    
    if netmask:
        try:
            network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            cidr = _clamp_cidr(str(network), local_ip)
        except Exception:
            cidr = _guess_cidr(local_ip)
    else:
        cidr = _guess_cidr(local_ip)
    
    return {
        "interface": interface,
        "local_ip": local_ip,
        "gateway": gateway,
        "cidr": cidr,
        "netmask": netmask
    }


def _get_gateway(interface: str) -> str | None:
    """Get the default gateway, restricted to `interface` when given."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'default' not in line:
                continue
            parts = line.split()
            if 'via' not in parts:
                continue
            if interface:
                if 'dev' not in parts or parts[parts.index('dev') + 1] != interface:
                    continue
            idx = parts.index('via')
            if idx + 1 < len(parts):
                return parts[idx + 1]
    except Exception:
        pass
    return None


def _get_netmask(interface: str) -> str | None:
    """Get the dotted netmask for the interface (e.g. 255.255.255.0)."""
    if not _valid_iface(interface):
        return None
    try:
        result = subprocess.run(
            ['ip', 'addr', 'show', interface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'inet ' in line:
                parts = line.strip().split()
                if len(parts) < 2 or '/' not in parts[1]:
                    continue
                prefix = parts[1].split('/')[1]
                if prefix.isdigit() and 0 <= int(prefix) <= 32:
                    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    except Exception:
        pass
    return None


def _clamp_cidr(cidr: str, local_ip: str) -> str:
    """Never auto-select a range broader than /16 — and use /24 beyond it."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    if net.prefixlen < 16:
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return str(net)


def _guess_cidr(local_ip: str) -> str:
    """Guess a /24 around the local address.

    Older versions returned /8, /12 or /16 based on the first octet, which
    could turn a single mis-detection into a 16-million-host scan.
    """
    try:
        ip = ipaddress.IPv4Address(local_ip)
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"
