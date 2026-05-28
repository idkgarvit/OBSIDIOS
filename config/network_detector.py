"""
config/network_detector.py
──────────────────────────
Network detection utilities for auto-detecting the current network.
"""
import socket
import subprocess
import ipaddress
from typing import Any


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
                        return parts[idx + 1]
    except Exception:
        pass
    return 'eth0'


def get_local_ip(interface: str = None) -> str | None:
    """Get local IP address. If interface specified, get IP for that interface."""
    if interface:
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if 'inet ' in line:
                    parts = line.strip().split()
                    ip = parts[1].split('/')[0]
                    return ip
        except Exception:
            pass
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_interface_ip(interface: str) -> str | None:
    """Get IP address for a specific interface."""
    return get_local_ip(interface)


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
            cidr = str(network.network_address) + "/" + str(network.prefixlen)
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
    """Get default gateway IP."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'default' in line:
                parts = line.split()
                if 'via' in parts:
                    idx = parts.index('via')
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
    except Exception:
        pass
    return None


def _get_netmask(interface: str) -> str | None:
    """Get netmask for the interface."""
    try:
        result = subprocess.run(
            ['ip', 'addr', 'show', interface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if 'inet ' in line:
                parts = line.strip().split()
                if '/' in parts[1]:
                    return parts[1].split('/')[1]
    except Exception:
        pass
    return None


def _guess_cidr(local_ip: str) -> str:
    """Guess CIDR based on common home network patterns."""
    try:
        ip_parts = local_ip.split('.')
        if len(ip_parts) == 4:
            first_octet = int(ip_parts[0])
            if first_octet == 10:
                return "10.0.0.0/8"
            elif first_octet == 172:
                return "172.16.0.0/12"
            elif first_octet == 192:
                return "192.168.0.0/16"
    except Exception:
        pass
    return "192.168.1.0/24"


def list_interfaces() -> list[dict[str, Any]]:
    """List all available network interfaces."""
    interfaces = []
    try:
        result = subprocess.run(
            ['ip', '-o', 'link', 'show'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if ':' in line:
                parts = line.split(':')
                if_name = parts[1].strip()
                if if_name != 'lo':
                    ip = get_local_ip(if_name)
                    interfaces.append({
                        "name": if_name,
                        "ip": ip,
                        "status": "up" if 'UP' in line else "down"
                    })
    except Exception:
        pass
    return interfaces


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation."""
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except Exception:
        return False
