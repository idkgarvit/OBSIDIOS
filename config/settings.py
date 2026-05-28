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


scan      = ScanSettings()
db        = DatabaseSettings()
ai        = AISettings()
alerts    = AlertSettings()
msf       = MetasploitSettings()
osint     = OSINTSettings()
dash      = DashboardSettings()
