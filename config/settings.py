"""
config/settings.py
Central configuration for OBSIDIOS.
"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

BASE_DIR    = Path(__file__).resolve().parent.parent
DB_PATH     = BASE_DIR / "chronicle" / "obsidios.db"
REPORTS_DIR = BASE_DIR / "reports" / "output"
LOGS_DIR    = BASE_DIR / "logs"


def load_env_file(path: Path) -> None:
    """Load ``KEY=VALUE`` pairs from ``.env`` into ``os.environ``.

    pydantic-settings reads ``.env`` for its own models, but modules that read
    ``os.environ`` directly (dashboard credentials, viewer account,
    ``FORGE_RELOAD_CMD``, ``SHIELD_*``) silently ignored the documented
    ``.env`` workflow. Real environment variables win, so container and
    orchestrator configuration is never overridden by a stray file.

    Supports the syntax people actually write: comments, ``export`` prefixes,
    single/double quoted values and trailing ``# comments``.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(key, value)


load_env_file(BASE_DIR / ".env")


def ensure_dir(path: Path) -> bool:
    """Create a runtime directory, tolerating a read-only filesystem.

    The containers bind-mount reports/logs read-only in several services, and a
    fresh clone has no reports/output directory because it is git-ignored.
    Raising here used to take down every service at import time; a missing
    output directory is an operational problem, not a reason to stop IDS.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except OSError as exc:
        if os.environ.get("OBSIDIOS_STRICT_DIRS") == "1":
            raise
        import warnings
        warnings.warn(
            f"[OBSIDIOS] Cannot create {path}: {exc}. Writes to this directory "
            "will fail; mount it read-write or set OBSIDIOS_STRICT_DIRS=1 to "
            "fail fast.",
            RuntimeWarning,
            stacklevel=2,
        )
        return False


for _d in (DB_PATH.parent, REPORTS_DIR, LOGS_DIR):
    ensure_dir(_d)


# pydantic-settings v2 does not understand Pydantic v1's ``Field(env=...)``:
# it silently ignores it and looks up the upper-cased field name instead. Every
# documented variable below (``OBSIDIOS_TARGET``, ``SHIELD_DRY_RUN``, …) was
# therefore dead configuration — Compose wired it, the app scanned the default
# network anyway. ``validation_alias`` is the v2 spelling and is honoured by
# both the environment and ``.env`` sources.
class ScanSettings(BaseSettings):
    target_network:         str   = Field("192.168.1.0/24", validation_alias="OBSIDIOS_TARGET")
    scan_interval_seconds:  int   = Field(3600,             validation_alias="OBSIDIOS_SCAN_INTERVAL")
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

    scan_profile:   str = Field("FAST",  validation_alias="OBSIDIOS_SCAN_PROFILE")
    nmap_arguments: str = Field("",      validation_alias="OBSIDIOS_NMAP_ARGS")

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

    scan_concurrency:  int   = Field(20,               validation_alias="OBSIDIOS_SCAN_CONCURRENCY")
    zombie_host:       str   = Field("",               validation_alias="OBSIDIOS_ZOMBIE_HOST")
    nvd_api_key:       str   = Field("",               validation_alias="NVD_API_KEY")
    wireless_interface: str = Field("wlan0",         validation_alias="OBSIDIOS_WLAN_IFACE")
    enable_wireless:   bool  = Field(True,             validation_alias="OBSIDIOS_WIRELESS")
    model_config = {"env_file": ".env", "extra": "ignore"}


class DatabaseSettings(BaseSettings):
    db_path: Path = DB_PATH
    model_config = {"env_file": ".env", "extra": "ignore"}


class AISettings(BaseSettings):
    anthropic_api_key: str = Field("", validation_alias="ANTHROPIC_API_KEY")
    nvidia_api_key:    str = Field("", validation_alias="NVIDIA_API_KEY")
    nvidia_base_url:   str = Field("https://integrate.api.nvidia.com/v1", validation_alias="NVIDIA_BASE_URL")
    nvidia_model:      str = Field("meta/llama-3.1-8b-instruct", validation_alias="NVIDIA_MODEL")
    openai_api_key:    str = Field("", validation_alias="OPENAI_API_KEY")
    openai_base_url:   str = Field("https://openrouter.ai/api/v1", validation_alias="OPENAI_BASE_URL")
    openai_model:      str = Field("liquid/lfm-2.5-1.2b-instruct:free", validation_alias="OPENAI_MODEL")
    model:             str = Field("claude-opus-4-5", validation_alias="OBSIDIOS_AI_MODEL")
    model_config = {"env_file": ".env", "extra": "ignore"}

    @model_validator(mode="after")
    def _openrouter_alias(self):
        """Accept the OPENROUTER_API_KEY name the docs have always advertised.

        The field only read OPENAI_API_KEY, so an operator who followed
        `.env.example` got the template fallback with no indication why.
        """
        if not self.openai_api_key:
            alias = os.environ.get("OPENROUTER_API_KEY", "").strip()
            if alias:
                self.openai_api_key = alias
        return self


class AlertSettings(BaseSettings):
    discord_webhook_url: str = Field("", validation_alias="OBSIDIOS_DISCORD_WEBHOOK")
    telegram_bot_token:  str = Field("", validation_alias="OBSIDIOS_TELEGRAM_TOKEN")
    telegram_chat_id:    str = Field("", validation_alias="OBSIDIOS_TELEGRAM_CHAT")
    model_config = {"env_file": ".env", "extra": "ignore"}


class OSINTSettings(BaseSettings):
    shodan_api_key: str = Field("", validation_alias="SHODAN_API_KEY")
    model_config = {"env_file": ".env", "extra": "ignore"}


class DashboardSettings(BaseSettings):
    host:       str  = Field("127.0.0.1", validation_alias="OBSIDIOS_DASH_HOST")
    port:       int  = Field(8080,        validation_alias="OBSIDIOS_DASH_PORT")
    secret_key: str  = Field("",          validation_alias="OBSIDIOS_SECRET")
    model_config = {"env_file": ".env", "extra": "ignore"}


class SecuritySettings(BaseSettings):
    """Company-infra hardening knobs. Safe defaults: fail closed."""
    env: str = Field("dev", validation_alias="OBSIDIOS_ENV")  # dev | production
    # The remaining operator knobs are read straight from os.environ where
    # they are used (dashboard credentials/CORS, SHIELD allowlist/scan guard)
    # so a runtime override wins over the value captured at import time.
    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def is_production(self) -> bool:
        # Read env directly as well: a runtime override should beat the value
        # captured when this singleton was built at import time.
        import os
        raw = os.environ.get("OBSIDIOS_ENV", self.env or "dev")
        return raw.strip().lower() in ("prod", "production")


class ShieldSettings(BaseSettings):
    """SHIELD safety: default dry-run so company infra can't be DoS'd."""
    dry_run: bool = Field(True, validation_alias="SHIELD_DRY_RUN")
    allowlist: str = Field("", validation_alias="SHIELD_ALLOWLIST")  # comma-separated IPs/CIDRs, e.g. "192.168.1.1,192.168.1.2/32"
    auto_quarantine: bool = Field(False, validation_alias="SHIELD_AUTO_QUARANTINE")
    max_actions_per_hour: int = Field(10, validation_alias="SHIELD_MAX_ACTIONS_PER_HOUR")
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


_WEAK_SECRETS = {
    "", "changeme", "obsidios123", "admin", "password",
    "obsidios-secret-fallback-for-dev",
    "obsidios-secret-fallback-for-dev-only-do-not-use-in-prod",
}


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
    # Target guardrail — read env directly so a runtime change wins over the
    # value captured when the settings singleton was imported.
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
    """Guardrails: deny 0.0.0.0/0, overly broad ranges, and public ranges
    without explicit opt-in. Defaults to a minimum /16 to prevent a typo from
    turning a company scan into an internet-wide sweep.
    """
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
    broad_ok = os.environ.get("OBSIDIOS_ALLOW_BROAD_SCAN", "").strip().lower() in ("1", "true", "yes")
    min_prefix = 8 if broad_ok else 16
    if net.prefixlen < min_prefix:
        return False, (f"/{net.prefixlen} too broad (min /{min_prefix}); "
                       "set OBSIDIOS_ALLOW_BROAD_SCAN=1 only with written authorization")
    if net.is_loopback or net.is_multicast or net.is_link_local:
        return False, "loopback/link-local/multicast ranges are not valid scan targets"
    allow_public = os.environ.get("OBSIDIOS_ALLOW_PUBLIC_SCAN", "").strip().lower() in ("1", "true", "yes")
    try:
        if not net.is_private and not allow_public:
            return False, "public range requires OBSIDIOS_ALLOW_PUBLIC_SCAN=1 + written authorization"
    except Exception:
        pass
    return True, "ok"


_DENIED_NMAP_OPTIONS = (
    "--script", "--datadir", "-il", "-ir", "--resume", "--stylesheet",
    "--webxml", "--interactive", "--proxies", "--servicedb", "--versiondb",
)
_SHELL_METACHARS = set(";&|`$<>\n\r")


def validate_nmap_arguments(args: str) -> tuple[bool, str]:
    """Reject nmap flags that write files, load scripts, or read target lists.

    The active profile is operator-controlled, but an enterprise deployment
    must not turn OBSIDIOS_NMAP_ARGS into arbitrary file/script execution.
    """
    raw = args or ""
    if any(ch in _SHELL_METACHARS for ch in raw):
        return False, "nmap arguments contain shell metacharacters"
    try:
        import shlex
        tokens = shlex.split(raw)
    except ValueError as e:
        return False, f"unparseable nmap arguments: {e}"
    for tok in tokens:
        lower = tok.lower()
        if tok.startswith("-o") and tok != "-O":
            return False, f"nmap output option not allowed: {tok}"
        for opt in _DENIED_NMAP_OPTIONS:
            if lower == opt or lower.startswith(opt + "="):
                return False, f"nmap option not allowed: {tok}"
            # Short options also accept an attached value (`-iL/etc/passwd`).
            # Matching only the spaced form let an operator read an arbitrary
            # target file — or `-iR100` sweep random internet hosts — while the
            # guard reported "ok".
            if not opt.startswith("--") and lower.startswith(opt):
                return False, f"nmap option not allowed: {tok}"
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
osint     = OSINTSettings()
dash      = DashboardSettings()
security  = SecuritySettings()
shield_cfg = ShieldSettings()
