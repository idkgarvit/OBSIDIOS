"""
chronicle/schema.py
The memory of OBSIDIOS. Full SQLite schema — 15 tables, 30+ indexes.
"""
from __future__ import annotations

SCHEMA_SQL = """
PRAGMA journal_mode   = WAL;
PRAGMA synchronous    = NORMAL;
PRAGMA cache_size     = -65536;
PRAGMA temp_store     = MEMORY;
PRAGMA mmap_size      = 268435456;
PRAGMA foreign_keys   = ON;
PRAGMA auto_vacuum    = INCREMENTAL;
PRAGMA wal_autocheckpoint = 1000;

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY,
    ip              TEXT    NOT NULL UNIQUE,
    mac             TEXT,
    hostname        TEXT,
    os_name          TEXT,
    os_accuracy     INTEGER,
    vendor          TEXT,
    first_seen      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    last_seen       REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    is_active       INTEGER NOT NULL DEFAULT 1,
    risk_score      REAL    NOT NULL DEFAULT 0.0,
    asset_value     INTEGER NOT NULL DEFAULT 5
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip          ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_active_risk ON hosts(is_active, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen   ON hosts(last_seen DESC);

CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    protocol        TEXT    NOT NULL DEFAULT 'tcp',
    state           TEXT    NOT NULL DEFAULT 'open',
    service         TEXT,
    product         TEXT,
    version         TEXT,
    extra_info      TEXT,
    cpe             TEXT,
    first_seen      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    last_seen       REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    UNIQUE(host_id, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_open    ON ports(host_id, port) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service, version);

CREATE TABLE IF NOT EXISTS cves (
    id              INTEGER PRIMARY KEY,
    cve_id          TEXT    NOT NULL UNIQUE,
    cvss_v3         REAL,
    cvss_v2         REAL,
    severity        TEXT,
    description     TEXT,
    published       REAL,
    last_modified   REAL,
    fetched_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec'))
);
CREATE INDEX IF NOT EXISTS idx_cves_id       ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity, cvss_v3 DESC);

CREATE TABLE IF NOT EXISTS port_cves (
    port_id             INTEGER NOT NULL REFERENCES ports(id)  ON DELETE CASCADE,
    cve_id              INTEGER NOT NULL REFERENCES cves(id)   ON DELETE CASCADE,
    exploit_status      TEXT    DEFAULT 'THEORETICAL',
    msf_module          TEXT,
    verified_at         REAL,
    effective_cvss      REAL,
    verified_status     TEXT    DEFAULT 'UNVERIFIED',
    detected_version    TEXT,
    dismissed           INTEGER DEFAULT 0,
    PRIMARY KEY (port_id, cve_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_pcve_exploit ON port_cves(exploit_status)
    WHERE exploit_status != 'THEORETICAL';

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY,
    scan_type       TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    started_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    finished_at     REAL,
    hosts_found     INTEGER DEFAULT 0,
    ports_found     INTEGER DEFAULT 0,
    cves_found      INTEGER DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'RUNNING',
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_type    ON scans(scan_type, started_at DESC);

CREATE TABLE IF NOT EXISTS scan_diffs (
    id              INTEGER PRIMARY KEY,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    diff_type       TEXT    NOT NULL,
    host_id         INTEGER REFERENCES hosts(id),
    port_id         INTEGER REFERENCES ports(id),
    cve_id          INTEGER REFERENCES cves(id),
    detail          TEXT,
    mitre_technique TEXT,
    mitre_tactic    TEXT,
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    created_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec'))
);
CREATE INDEX IF NOT EXISTS idx_diffs_scan ON scan_diffs(scan_id);
CREATE INDEX IF NOT EXISTS idx_diffs_host ON scan_diffs(host_id, created_at DESC);

CREATE TABLE IF NOT EXISTS behavioral_baselines (
    id                  INTEGER PRIMARY KEY,
    host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE UNIQUE,
    window_start        REAL    NOT NULL,
    window_end          REAL    NOT NULL,
    bytes_in_mean       REAL    DEFAULT 0,
    bytes_in_std        REAL    DEFAULT 0,
    bytes_out_mean      REAL    DEFAULT 0,
    bytes_out_std       REAL    DEFAULT 0,
    session_count_mean  REAL    DEFAULT 0,
    session_count_std   REAL    DEFAULT 0,
    active_hours_bitmap INTEGER DEFAULT 0,
    peer_set_json       TEXT    DEFAULT '[]',
    protocol_dist_json  TEXT    DEFAULT '{}',
    dns_query_rate_mean REAL    DEFAULT 0,
    dns_query_rate_std  REAL    DEFAULT 0,
    sample_count        INTEGER DEFAULT 0,
    is_baseline_ready   INTEGER DEFAULT 0,
    created_at          REAL    NOT NULL DEFAULT (unixepoch('now','subsec'))
);
CREATE INDEX IF NOT EXISTS idx_baseline_host ON behavioral_baselines(host_id);

CREATE TABLE IF NOT EXISTS behavioral_events (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ts          REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    bytes_in    INTEGER DEFAULT 0,
    bytes_out   INTEGER DEFAULT 0,
    sessions    INTEGER DEFAULT 0,
    protocols   TEXT    DEFAULT '{}',
    peers       TEXT    DEFAULT '[]',
    dns_queries INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bevents_host_ts ON behavioral_events(host_id, ts DESC);

CREATE TABLE IF NOT EXISTS anomalies (
    id                INTEGER PRIMARY KEY,
    host_id           INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    detected_at       REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    anomaly_type      TEXT    NOT NULL,
    confidence        REAL    NOT NULL,
    z_score           REAL,
    detail            TEXT,
    is_false_positive INTEGER DEFAULT 0,
    acknowledged      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_anomalies_host ON anomalies(host_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_conf ON anomalies(confidence DESC) WHERE acknowledged = 0;

CREATE TABLE IF NOT EXISTS attack_paths (
    id                     INTEGER PRIMARY KEY,
    simulated_at           REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    entry_host_id          INTEGER REFERENCES hosts(id),
    target_host_id         INTEGER REFERENCES hosts(id),
    path_json              TEXT    NOT NULL,
    narrative              TEXT,
    total_steps            INTEGER NOT NULL DEFAULT 0,
    attacker_roi           REAL    NOT NULL DEFAULT 0.0,
    estimated_time_minutes REAL,
    is_active              INTEGER DEFAULT 1,
    forge_rule_ids         TEXT    DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_paths_entry ON attack_paths(entry_host_id);
CREATE INDEX IF NOT EXISTS idx_paths_roi   ON attack_paths(attacker_roi DESC) WHERE is_active = 1;
CREATE INDEX IF NOT EXISTS idx_paths_sim   ON attack_paths(simulated_at DESC);

CREATE TABLE IF NOT EXISTS forge_rules (
    id              INTEGER PRIMARY KEY,
    rule_sid        INTEGER NOT NULL UNIQUE,
    attack_path_id  INTEGER REFERENCES attack_paths(id) ON DELETE SET NULL,
    anomaly_id      INTEGER REFERENCES anomalies(id)    ON DELETE SET NULL,
    rule_text       TEXT    NOT NULL,
    rule_category   TEXT    NOT NULL,
    mitre_technique TEXT,
    is_deployed     INTEGER DEFAULT 0,
    is_active       INTEGER DEFAULT 1,
    true_positives  INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    created_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    last_fired_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_rules_deployed ON forge_rules(is_deployed, is_active);
CREATE INDEX IF NOT EXISTS idx_rules_sid      ON forge_rules(rule_sid);

CREATE TABLE IF NOT EXISTS sentinel_alerts (
    id              INTEGER PRIMARY KEY,
    alerted_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    rule_sid        INTEGER,
    forge_rule_id   INTEGER REFERENCES forge_rules(id)   ON DELETE SET NULL,
    attack_path_id  INTEGER REFERENCES attack_paths(id)  ON DELETE SET NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    severity        INTEGER,
    message         TEXT,
    payload_hex     TEXT,
    predicted       INTEGER DEFAULT 0,
    acknowledged    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_salerts_time    ON sentinel_alerts(alerted_at DESC);
CREATE INDEX IF NOT EXISTS idx_salerts_src     ON sentinel_alerts(src_ip, alerted_at DESC);
CREATE INDEX IF NOT EXISTS idx_salerts_unacked ON sentinel_alerts(acknowledged) WHERE acknowledged = 0;

CREATE TABLE IF NOT EXISTS ghost_honeypots (
    id                INTEGER PRIMARY KEY,
    ip                TEXT    NOT NULL,
    port              INTEGER NOT NULL,
    service_type      TEXT    NOT NULL,
    attack_path_id    INTEGER REFERENCES attack_paths(id) ON DELETE SET NULL,
    deployed_at       REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    is_active         INTEGER DEFAULT 1,
    interaction_count INTEGER DEFAULT 0,
    UNIQUE(ip, port)
);
CREATE INDEX IF NOT EXISTS idx_honeypots_active ON ghost_honeypots(is_active);

CREATE TABLE IF NOT EXISTS ghost_interactions (
    id               INTEGER PRIMARY KEY,
    honeypot_id      INTEGER NOT NULL REFERENCES ghost_honeypots(id) ON DELETE CASCADE,
    ts               REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    attacker_ip      TEXT    NOT NULL,
    attacker_port    INTEGER,
    session_log      TEXT,
    credentials_tried TEXT,
    commands_run     TEXT,
    files_accessed   TEXT,
    duration_seconds REAL
);
CREATE INDEX IF NOT EXISTS idx_ghost_int_time ON ghost_interactions(ts DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_int_attk ON ghost_interactions(attacker_ip);

CREATE TABLE IF NOT EXISTS shield_actions (
    id            INTEGER PRIMARY KEY,
    taken_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    action_type   TEXT    NOT NULL,
    target_ip     TEXT,
    target_port   INTEGER,
    rule_applied  TEXT,
    trigger_type  TEXT,
    trigger_id    INTEGER,
    confidence    REAL,
    justification TEXT,
    is_active     INTEGER DEFAULT 1,
    reverted_at   REAL,
    reverted_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_shield_time   ON shield_actions(taken_at DESC);
CREATE INDEX IF NOT EXISTS idx_shield_active ON shield_actions(is_active, target_ip);

CREATE TABLE IF NOT EXISTS wireless_threats (
    id              INTEGER PRIMARY KEY,
    detected_at     REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    threat_type     TEXT    NOT NULL,
    bssid           TEXT,
    ssid            TEXT,
    channel         INTEGER,
    signal_strength INTEGER,
    encryption      TEXT,
    detail          TEXT,
    is_active       INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_wireless_time ON wireless_threats(detected_at DESC);

CREATE TABLE IF NOT EXISTS osint_findings (
    id            INTEGER PRIMARY KEY,
    source        TEXT    NOT NULL,
    finding_type  TEXT    NOT NULL,
    target        TEXT    NOT NULL,
    detail        TEXT,
    severity      TEXT    NOT NULL DEFAULT 'MEDIUM',
    discovered_at REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    is_remediated INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_osint_source ON osint_findings(source, discovered_at DESC);

CREATE TABLE IF NOT EXISTS posture_scores (
    id               INTEGER PRIMARY KEY,
    recorded_at      REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    overall_score    REAL    NOT NULL,
    wired_score      REAL,
    wireless_score   REAL,
    behavioral_score REAL,
    exploit_score    REAL,
    osint_score      REAL,
    active_alerts    INTEGER DEFAULT 0,
    active_paths     INTEGER DEFAULT 0,
    confirmed_vulns  INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_posture_time ON posture_scores(recorded_at DESC);

CREATE TABLE IF NOT EXISTS antibody_feedback (
    id                INTEGER PRIMARY KEY,
    recorded_at       REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
    event_type        TEXT    NOT NULL,
    attack_path_id    INTEGER REFERENCES attack_paths(id),
    forge_rule_id     INTEGER REFERENCES forge_rules(id),
    sentinel_alert_id INTEGER REFERENCES sentinel_alerts(id),
    learning_note     TEXT,
    applied           INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_antibody_time ON antibody_feedback(recorded_at DESC);

CREATE TABLE IF NOT EXISTS saved_targets (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    target_cidr     TEXT NOT NULL,
    interface       TEXT,
    scan_profile    TEXT DEFAULT 'FAST',
    notes           TEXT,
    created_at      REAL NOT NULL DEFAULT (unixepoch('now','subsec')),
    last_used_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_targets_name ON saved_targets(name);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT OR IGNORE INTO system_settings (key, value) VALUES ('scanner_enabled', '0');
INSERT OR IGNORE INTO system_settings (key, value) VALUES ('target_network', '');
INSERT OR IGNORE INTO system_settings (key, value) VALUES ('scan_profile', 'FAST');
INSERT OR IGNORE INTO system_settings (key, value) VALUES ('scan_interface', '');
"""
