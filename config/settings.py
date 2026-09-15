"""
config/settings.py
Central configuration for OBSIDIOS.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings

BASE_DIR    = Path(__file__).resolve().parent.parent
DB_PATH     = BASE_DIR / "chronicle" / "obsidios.db"
REPORTS_DIR = BASE_DIR / "reports" / "output"
LOGS_DIR    = BASE_DIR / "logs"

for _d in (DB_PATH.parent, REPORTS_DIR, LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class ScanSettings(BaseSettings):
    target_network:         str   = Field("192.168.1.0/24", env="OBSIDIOS_TARGET")
    scan_interval_seconds:  int   = Field(3600,             env="OBSIDIOS_SCAN_INTERVAL")
    # ── Scan Profiles ─────────────────────────────────────────────────────
    # Switch profiles by setting OBSIDIOS_SCAN_PROFILE in .env
    # FAST   → lab/trusted network, no firewall     (~30 sec)
    # STEALTH → firewall evasion, production ready  (~15-20 min)
    # GHOST   → maximum evasion, all 65535 ports    (~2-4 hours)

    SCAN_PROFILES: dict = {
        "FAST":    "-sV -O -T4 --min-parallelism 20 --max-retries 1 --top-ports 100",
        "STEALTH": "-sS -sV -O -Pn -f --mtu 24 -D RND:10 --source-port 53 -T2 --scan-delay 2s --max-retries 2 --top-ports 1000",
        "GHOST":   "-sS -sV -O -Pn -f --mtu 24 -D RND:20 --source-port 53 --badsum -T1 --scan-delay 5s --max-retries 1 -p-",
        "STEALTH_IDLE": "-sS -sV -O -Pn -f --mtu 24 --source-port 53 -T2 --scan-delay 3s --max-retries 2 --top-ports 1000 -sI ZOMBIE",
    }

    scan_profile:   str = Field("FAST",  env="OBSIDIOS_SCAN_PROFILE")
    nmap_arguments: str = Field("",      env="OBSIDIOS_NMAP_ARGS")

    @property
    def active_nmap_args(self) -> str:
        """Returns active nmap args — .env override takes priority, else profile."""
        if self.nmap_arguments:
            args = self.nmap_arguments
        else:
            args = self.SCAN_PROFILES.get(self.scan_profile, self.SCAN_PROFILES["FAST"])
        # Sub ZOMBIE placeholder with actual zombie host if set
        if self.zombie_host:
            args = args.replace("ZOMBIE", self.zombie_host)
        return args

    nmap_top_ports:    int   = Field(1000,             env="OBSIDIOS_NMAP_TOP_PORTS")
    scan_concurrency:  int   = Field(20,               env="OBSIDIOS_SCAN_CONCURRENCY")
    arp_timeout:       float = Field(2.0,              env="OBSIDIOS_ARP_TIMEOUT")
    zombie_host:       str   = Field("",               env="OBSIDIOS_ZOMBIE_HOST")
    nvd_api_key:       str   = Field("",               env="NVD_API_KEY")
    wireless_interface: str = Field("wlan0",         env="OBSIDIOS_WLAN_IFACE")
    enable_wireless:   bool  = Field(True,             env="OBSIDIOS_WIRELESS")
    model_config = {"env_file": ".env", "extra": "ignore"}


class DatabaseSettings(BaseSettings):
    db_path:              Path = DB_PATH
    cache_size_kb:        int  = Field(65536,     env="OBSIDIOS_DB_CACHE_KB")
    mmap_size_bytes:      int  = Field(268435456, env="OBSIDIOS_MMAP")
    wal_autocheckpoint:   int  = Field(1000,      env="OBSIDIOS_WAL_CHECKPOINT")
    model_config = {"env_file": ".env", "extra": "ignore"}


class AISettings(BaseSettings):
    anthropic_api_key: str = Field("", env="ANTHROPIC_API_KEY")
    nvidia_api_key:    str = Field("", env="NVIDIA_API_KEY")
    nvidia_base_url:   str = Field("https://integrate.api.nvidia.com/v1", env="NVIDIA_BASE_URL")
    nvidia_model:      str = Field("meta/llama-3.1-8b-instruct", env="NVIDIA_MODEL")
    openai_api_key:    str = Field("", env="OPENAI_API_KEY")
    openai_base_url:   str = Field("https://openrouter.ai/api/v1", env="OPENAI_BASE_URL")
    openai_model:      str = Field("liquid/lfm-2.5-1.2b-instruct:free", env="OPENAI_MODEL")
    model:             str = Field("claude-opus-4-5", env="OBSIDIOS_AI_MODEL")
    max_tokens:        int = Field(4096, env="OBSIDIOS_AI_MAX_TOKENS")
    model_config = {"env_file": ".env", "extra": "ignore"}


class AlertSettings(BaseSettings):
    discord_webhook_url: str = Field("", env="OBSIDIOS_DISCORD_WEBHOOK")
    telegram_bot_token:  str = Field("", env="OBSIDIOS_TELEGRAM_TOKEN")
    telegram_chat_id:    str = Field("", env="OBSIDIOS_TELEGRAM_CHAT")
    model_config = {"env_file": ".env", "extra": "ignore"}


class MetasploitSettings(BaseSettings):
    host:     str  = Field("127.0.0.1", env="MSF_HOST")
    port:     int  = Field(55553,       env="MSF_PORT")
    password: str  = Field("",           env="MSF_PASSWORD")
    ssl:      bool = Field(False,       env="MSF_SSL")
    model_config = {"env_file": ".env", "extra": "ignore"}


class OSINTSettings(BaseSettings):
    shodan_api_key: str = Field("", env="SHODAN_API_KEY")
    hibp_api_key:   str = Field("", env="HIBP_API_KEY")
    model_config = {"env_file": ".env", "extra": "ignore"}


class DashboardSettings(BaseSettings):
    host:       str  = Field("0.0.0.0", env="OBSIDIOS_DASH_HOST")
    port:       int  = Field(8080,       env="OBSIDIOS_DASH_PORT")
    debug:      bool = Field(False,      env="OBSIDIOS_DASH_DEBUG")
    secret_key: str  = Field("", env="OBSIDIOS_SECRET")
    model_config = {"env_file": ".env", "extra": "ignore"}


class SecuritySettings(BaseSettings):
    """Company-infra hardening knobs. Safe defaults: fail closed."""
    env: str = Field("dev", env="OBSIDIOS_ENV")  # dev | production
    allow_public_scan: bool = Field(False, env="OBSIDIOS_ALLOW_PUBLIC_SCAN")
    cors_origins: str = Field("http://localhost:8080", env="CORS_ORIGINS")
    dashboard_user: str = Field("admin", env="DASHBOARD_USER")
    # DASHBOARD_PASS is read via os.environ in dashboard/app.py to avoid logging;
    # kept here only for prod validation (presence check).
    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def is_production(self) -> bool:
        # Read env directly: pydantic-settings v2 ignores Field(env=...) so
        # self.env may be stale. Env var is source of truth for safety.
        import os
        raw = os.environ.get("OBSIDIOS_ENV", self.env or "dev")
        return raw.strip().lower() in ("prod", "production")


class ShieldSettings(BaseSettings):
    """SHIELD safety: default dry-run so company infra can't be DoS'd."""
    dry_run: bool = Field(True, env="SHIELD_DRY_RUN")
    allowlist: str = Field("", env="SHIELD_ALLOWLIST")  # comma-separated IPs/CIDRs, e.g. "192.168.1.1,192.168.1.2/32"
    auto_quarantine: bool = Field(False, env="SHIELD_AUTO_QUARANTINE")
    max_actions_per_hour: int = Field(10, env="SHIELD_MAX_ACTIONS_PER_HOUR")
    model_config = {"env_file": ".env", "extra": "ignore"}


def _resolve_secret() -> str:
    """Unify OBSIDIOS_SECRET / SECRET_KEY. Returns '' if unset."""
    import os
    for k in ("OBSIDIOS_SECRET", "SECRET_KEY"):
        v = os.environ.get(k, "").strip()
        if v:
            return v
    try:
        if dash.secret_key:
            return dash.secret_key
    except Exception:
        pass
    return ""


_WEAK_SECRETS = {"", "changeme", "obsidios-secret-fallback-for-dev", "obsidios123", "admin", "password"}


def validate_prod_config() -> list[str]:
    """Returns list of blocking errors when OBSIDIOS_ENV=production. Empty = OK."""
    import os
    errors: list[str] = []
    # Source of truth: env var (not cached pydantic object)
    if os.environ.get("OBSIDIOS_ENV", "dev").strip().lower() not in ("prod", "production"):
        return errors
    secret = _resolve_secret()
    if len(secret) < 32 or secret in _WEAK_SECRETS:
        errors.append("OBSIDIOS_SECRET must be >=32 random bytes in production (generate: python3 -c 'import secrets; print(secrets.token_urlsafe(48))')")
    if os.environ.get("DASHBOARD_PASS", "obsidios123") in ("obsidios123", "admin", "password", ""):
        errors.append("DASHBOARD_PASS must be changed from default in production")
    if os.environ.get("OBSIDIOS_DASH_DEBUG", "").strip().lower() in ("1", "true", "yes"):
        errors.append("OBSIDIOS_DASH_DEBUG must be false in production")
    # Target guardrail — read env directly (pydantic Field(env=) is deprecated/ignored on v2)
    target = os.environ.get("OBSIDIOS_TARGET", "")
    if not target:
        try:
            target = scan.target_network
        except Exception:
            target = ""
    ok, reason = validate_target_cidr(target)
    if not ok:
        errors.append(f"Refusing production target {target!r}: {reason}")
    return errors


def validate_target_cidr(cidr: str) -> tuple[bool, str]:
    """Guardrails: deny 0.0.0.0/0, overly broad </8, and public ranges without explicit opt-in."""
    import ipaddress
    import os
    if not cidr:
        return False, "empty — set OBSIDIOS_TARGET to a company-owned private CIDR"
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        return False, f"invalid CIDR: {e}"
    if net.prefixlen == 0:
        return False, "0.0.0.0/0 internet-wide scan is never allowed"
    if net.prefixlen < 8:
        return False, f"/{net.prefixlen} too broad (min /8)"
    allow_public = os.environ.get("OBSIDIOS_ALLOW_PUBLIC_SCAN", "").strip().lower() in ("1", "true", "yes")
    try:
        if not net.is_private and not allow_public:
            return False, "public range requires OBSIDIOS_ALLOW_PUBLIC_SCAN=1 + written authorization"
    except Exception:
        pass
    return True, "ok"


def parse_shield_allowlist(extra_gateway: str = "") -> list[str]:
    """Parse SHIELD_ALLOWLIST + gateway into normalized list. Reads env directly."""
    import os
    raw = os.environ.get("SHIELD_ALLOWLIST", "")
    if not raw:
        try:
            raw = shield_cfg.allowlist or ""
        except Exception:
            raw = ""
    items = [p.strip() for p in raw.split(",") if p.strip()]
    gw = extra_gateway or os.environ.get("OBSIDIOS_GATEWAY", "192.168.1.1")
    if gw and gw not in items:
        items.append(gw)
    # Always protect loopback + unspecified
    for critical in ("127.0.0.1/32", "::1/128"):
        if critical not in items:
            items.append(critical)
    return items


def is_ip_allowlisted(ip: str, allowlist: list[str] | None = None) -> bool:
    """True if ip matches any allowlist entry (IP or CIDR). Fail-closed on parse error."""
    import ipaddress
    if allowlist is None:
        allowlist = parse_shield_allowlist()
    try:
        addr = ipaddress.ip_address(ip.strip())
    except Exception:
        return True  # unparseable -> treat as protected, refuse to block
    for entry in allowlist:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except Exception:
            continue
    return False


scan      = ScanSettings()
db        = DatabaseSettings()
ai        = AISettings()
alerts    = AlertSettings()
msf       = MetasploitSettings()
osint     = OSINTSettings()
dash      = DashboardSettings()
security  = SecuritySettings()
shield_cfg = ShieldSettings()
