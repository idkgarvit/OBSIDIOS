"""
chronicle/models.py
Pydantic v2 typed data models for all OBSIDIOS data structures.
"""
from __future__ import annotations
import time
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"
    LOW = "LOW"; INFO = "INFO"; NONE = "NONE"

class ExploitStatus(StrEnum):
    THEORETICAL           = "THEORETICAL"
    LIKELY_VULNERABLE     = "LIKELY_VULNERABLE"
    CONFIRMED_EXPLOITABLE = "CONFIRMED_EXPLOITABLE"
    VERIFIED              = "VERIFIED"
    PUBLIC_EXPLOIT        = "PUBLIC_EXPLOIT"
    MSF_AVAILABLE         = "MSF_AVAILABLE"

class DiffType(StrEnum):
    NEW_HOST="NEW_HOST"; GONE_HOST="GONE_HOST"; NEW_PORT="NEW_PORT"
    CLOSED_PORT="CLOSED_PORT"; NEW_CVE="NEW_CVE"; SERVICE_CHANGED="SERVICE_CHANGED"

class AnomalyType(StrEnum):
    TRAFFIC_SPIKE="TRAFFIC_SPIKE"; NEW_PEER="NEW_PEER"
    PROTOCOL_DRIFT="PROTOCOL_DRIFT"; HOUR_DRIFT="HOUR_DRIFT"
    DNS_ANOMALY="DNS_ANOMALY"; BEACON_PATTERN="BEACON_PATTERN"
    DATA_EXFIL_SUSPECT="DATA_EXFIL_SUSPECT"

class WirelessThreatType(StrEnum):
    ROGUE_AP="ROGUE_AP"; EVIL_TWIN="EVIL_TWIN"; DEAUTH_FLOOD="DEAUTH_FLOOD"
    WEAK_ENCRYPTION="WEAK_ENCRYPTION"; PMKID_ATTACK="PMKID_ATTACK"


class Host(BaseModel):
    id: int | None = None; ip: str; mac: str | None = None
    hostname: str | None = None; os_name: str | None = None
    os_accuracy: int | None = None; vendor: str | None = None
    first_seen: float = Field(default_factory=time.time)
    last_seen:  float = Field(default_factory=time.time)
    is_active: bool = True; risk_score: float = 0.0; asset_value: int = 5

    @field_validator("risk_score")
    @classmethod
    def clamp_risk(cls, v: float) -> float: return max(0.0, min(100.0, v))

    @field_validator("asset_value")
    @classmethod
    def clamp_asset(cls, v: int) -> int: return max(1, min(10, v))


class Port(BaseModel):
    id: int | None = None; host_id: int; port: int
    protocol: str = "tcp"; state: str = "open"
    service: str | None = None; product: str | None = None
    version: str | None = None; extra_info: str | None = None; cpe: str | None = None
    first_seen: float = Field(default_factory=time.time)
    last_seen:  float = Field(default_factory=time.time)


class CVE(BaseModel):
    id: int | None = None; cve_id: str
    cvss_v3: float | None = None; cvss_v2: float | None = None
    severity: Severity = Severity.NONE; description: str | None = None
    published: float | None = None; last_modified: float | None = None
    fetched_at: float = Field(default_factory=time.time)


class ScanResult(BaseModel):
    scan_id: int | None = None; target: str
    started_at: float = Field(default_factory=time.time)
    finished_at: float | None = None
    hosts: list[Host] = Field(default_factory=list)
    ports: dict[str, list[Port]] = Field(default_factory=dict)
    cves:  dict[str, list[CVE]]  = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class AttackStep(BaseModel):
    host_id: int; ip: str; technique: str; tactic: str
    cve_id: str | None = None; msf_module: str | None = None
    description: str | None = None


class AttackPath(BaseModel):
    id: int | None = None
    simulated_at: float = Field(default_factory=time.time)
    entry_host_id: int | None = None; target_host_id: int | None = None
    steps: list[AttackStep] = Field(default_factory=list)
    narrative: str | None = None; total_steps: int = 0
    attacker_roi: float = 0.0; estimated_time_minutes: float | None = None
    is_active: bool = True; forge_rule_ids: list[int] = Field(default_factory=list)




class PostureScore(BaseModel):
    recorded_at: float = Field(default_factory=time.time)
    overall_score: float = 100.0
    wired_score: float | None = None; wireless_score: float | None = None
    behavioral_score: float | None = None; exploit_score: float | None = None
    osint_score: float | None = None; active_alerts: int = 0
    active_paths: int = 0; confirmed_vulns: int = 0

    @field_validator("overall_score","wired_score","wireless_score",
                     "behavioral_score","exploit_score","osint_score", mode="before")
    @classmethod
    def clamp(cls, v: Any) -> Any:
        return max(0.0, min(100.0, float(v))) if v is not None else v


class ForgeRule(BaseModel):
    id:              int   | None = None
    rule_sid:        int
    attack_path_id:  int   | None = None
    anomaly_id:      int   | None = None
    rule_text:       str
    rule_category:   str
    mitre_technique: str   | None = None
    is_deployed:     bool         = False
    is_active:       bool         = True
    true_positives:  int          = 0
    false_positives: int          = 0
    created_at:      float        = Field(default_factory=time.time)
    last_fired_at:   float | None = None


class BehavioralEvent(BaseModel):
    host_id:     int
    ts:          float = Field(default_factory=time.time)
    bytes_in:    int   = 0
    bytes_out:   int   = 0
    sessions:    int   = 0
    protocols:   dict[str, int] = Field(default_factory=dict)
    peers:       list[str]      = Field(default_factory=list)
    dns_queries: int   = 0


class Anomaly(BaseModel):
    id:                int   | None = None
    host_id:           int
    detected_at:       float        = Field(default_factory=time.time)
    anomaly_type:      AnomalyType
    confidence:        float
    z_score:           float | None = None
    detail:            str   | None = None
    is_false_positive: bool         = False
    acknowledged:      bool         = False


class ShieldAction(BaseModel):
    id:            int   | None = None
    taken_at:      float        = Field(default_factory=time.time)
    action_type:   str
    target_ip:     str   | None = None
    target_port:   int   | None = None
    rule_applied:  str   | None = None
    trigger_type:  str   | None = None
    trigger_id:    int   | None = None
    confidence:    float | None = None
    justification: str   | None = None
    is_active:     bool         = True
    reverted_at:   float | None = None
    reverted_by:   str   | None = None


class ShieldActionType(StrEnum):
    BLOCK_IP        = "BLOCK_IP"
    BLOCK_PATH      = "BLOCK_PATH"
    QUARANTINE_HOST = "QUARANTINE_HOST"
    CLOSE_PORT      = "CLOSE_PORT"
    MICROSEGMENT    = "MICROSEGMENT"
