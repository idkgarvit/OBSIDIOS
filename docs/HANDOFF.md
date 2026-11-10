# OBSIDIOS — session handoff

**Date:** 2026-11-10
**Repo:** `/home/shiga0_0/Projects/OBSIDIOS`
**Git:** working tree intentionally **uncommitted**; last commit `eed9768`
**Gates:** `1229 passed, 1 warning` (the warning is the intentional
`ensure_dir` read-only probe); `ruff check .` clean; `node --check
dashboard/static/app.js` / `risk.js` clean; bandit 0 Medium / 0 High (62 Low);
`pip-audit -r requirements.txt` clean. Coverage: `dashboard/app.py` 99%,
`forge/rule_generator.py` 100%, `alerts/notifier.py` 100%.

Detailed test-level handoff: `/tmp/opencode/obsidios-handoff-2026-11-09.md`.

## Resume in 60 seconds

```bash
cd /home/shiga0_0/Projects/OBSIDIOS
nohup .venv/bin/python obsidios.py dash --host 127.0.0.1 --port 8080 \
  > /tmp/opencode/obsidios-dash.log 2>&1 &

.venv/bin/python -m pytest tests/ -q
~/.local/bin/ruff check .
node --check dashboard/static/app.js
node --check dashboard/static/risk.js
.venv/bin/bandit -r . -x ./tests,./.venv -ll
.venv/bin/pip-audit -r requirements.txt
```

- Dashboard: `http://127.0.0.1:8080`, login `admin` / `obsidios123`
  (dev-fallback secret warning is expected).
- Static mock: `python3 -m http.server 8090 --bind 127.0.0.1
  --directory /tmp/opencode/obsidios-mockup` → `http://127.0.0.1:8090`.
- Scratch scripts in `/tmp/opencode` need
  `PYTHONPATH=/home/shiga0_0/Projects/OBSIDIOS`.
- In-process dashboard DB tests must use `run_async(...)`, never `asyncio.run`.

## Fixes in the working tree

### Dashboard / UI
- **Overview selected-asset card on first load**: `loadHosts()` now renders the
  card as soon as the inventory payload lands, `initDashboard()` fetches hosts
  up front, and `renderSelectedAsset()` falls back to the highest-risk host when
  the 3D graph / CVE list are still empty. The card no longer shows only "Asset"
  until Inventory is opened. Regression:
  `test_dashboard_overview_asset_card_is_populated_at_init`
  (`tests/test_hardening.py`).
- **Calm command deck port**: bundled IBM Plex Sans + JetBrains Mono
  (`dashboard/static/fonts/`), `dashboard/static/theme.css`, rail/main/topbar
  layout, rebuilt Overview and Findings, all 16 nav pages verified. Legacy CSS
  kept as the base layer. All live DOM IDs and API bindings preserved.
- **Inventory risk bars**: `risk_score` is 0–100; new
  `dashboard/static/risk.js` (`bar`/`color`/`band`) replaces the old 0–10 math.
- **Login input width**: `#login-modal .login-input{width:100%}` beats the
  legacy `input[type=text]{width:160px}`.
- **Overview scrolling**: kept scrollable (`#page-dashboard{overflow-y:auto}`)
  because the live page has a third Signals row the mock lacks. Primary deck is
  above the fold (ends y≈844 at 879px viewport). The mock itself clips ~16px.
- **Topology clipping**: `fitTopologyCamera()` fits the camera to the node set
  and card aspect; manual orbit opts out until the node set changes.
- **War Room TUI**: `_markup_safe()` validates/escapes feed lines; hostile
  hostnames, SSIDs and command output no longer kill the render loop.

### SHIELD
- `revert_action()` keeps rule specs still required by other active
  `BLOCK_IP` / `QUARANTINE_HOST` rows (`_rules_kept_by_other_actions`).
- `block_ip()` refreshes an existing active row on kernel drift instead of
  inserting duplicates.
- **`CLOSE_PORT` is fully implemented** (`shield/reconfigurer.py`): emits
  protocol-aware DROP rules, refreshes drifted rows instead of duplicating
  chains, deduplicates rules, protects rules shared with another active action,
  reconstructs the exact rule set on revert, and records audit rows for both
  apply and revert. Regressions: `TestClosePort`
  (`tests/test_shield_hardening.py`).

### Scan control / scheduling
- **Pause is truthful**: `scanner_enabled=0` now silences the main scan cycle,
  the 15s heartbeat/scheduled loops, and the APScheduler cron job, not just the
  dashboard card. The map still rebuilds from the DB while paused, and
  `config set-scanner on|off` persists and audits the switch.
- **No overlapping sweeps**: the daemon sets `_scan_busy` around a scan; a
  dashboard trigger while a scan is running returns HTTP 409 instead of
  cancelling the in-flight row. RUNNING rows older than 12h are reaped before a
  trigger so a crashed sweep cannot lock scanning out forever.
- **Cancellation discards partial data**: `run_scan` / `_scan_pipeline` check
  the scan row after discovery and after host scanning; a cancelled sweep
  skips CVE persistence, graph rebuild and post-processing.
- **Profile/target precedence**: dashboard-selected profile applies to the next
  real scan without a daemon restart; `OBSIDIOS_NMAP_ARGS` remains the final
  override. An explicit CLI `run --target/--profile` is persisted so daemon and
  dashboard agree; defaults never overwrite dashboard settings.
- **Schedule timezone**: the UI, API validation message, next-run estimate and
  `AsyncIOScheduler` all use the daemon host's local timezone (previously the UI
  claimed UTC while the scheduler used local time). Hourly schedules are
  anchored to daemon start and ignore the time-of-day field.

### Detection / data logic
- **Version matching** (`iris/cve_mapper.py`): `_version_key()` orders
  `1.2.3-rc1 < 1.2.3`; unparseable bounds (`*`, `unknown`, empty) are treated
  as absent, not zero; `_parse_version` keeps its historical tuple contract.
- **CPE extraction**: NVD `configurations` ranges are authoritative over
  description regex; all ranges kept, `vulnerable:false` skipped, exclusive
  start preserved, prose results deduped and capped.
- **`chronicle/db.py`**: `_run_write()` rolls back on every exception
  (including `IntegrityError` and cancellation) before re-raising; lock retries
  unchanged.
- **`GONE_HOST`**: `compute_scan_diff` uses `NOT EXISTS` against
  `scan_diffs.created_at >= offline_since`, so a persistent outage is reported
  once.
- **Heartbeat**: `iris/heartbeat.heartbeat_once()` is the daemon's single
  presence path. It reuses `wired_scanner.discover_hosts` (ARP + nmap/MAC
  parity), treats a zero-result sweep as a failed sweep (no mass-offline
  write), upserts MACs, writes `offline_since=unixepoch()` on DOWN, and emits
  the optional dashboard events. `obsidios.pulse_loop` calls it before
  `rebuild_graph()`; `wired_scanner.fast_host_discovery()` delegates to it.
  `run_heartbeat_loop` remains a thin loop wrapper for callers that need the
  SocketIO event path. Regressions: `tests/test_osint_patch_heartbeat.py`,
  `tests/test_iris_hardening.py`.
- **Heartbeat row access**: `heartbeat_once()` uses `_row_get()` so
  `sqlite3.Row` values without `.get` no longer crash presence reconciliation
  on any non-empty hosts table. Dashboard CSV/PDF row consumers use the same
  defensive helper.
- **FORGE delivery**: the ruleset is rewritten and reloaded even with zero
  paths (comment-only file); `ensure_rules_file()` runs on daemon start so
  Suricata has a rule file, and C2 `HOME_NET` resolves the DB target.
- **Patch queue**: excludes `dismissed` and `NOT_AFFECTED` CVEs.
- **ORACLE AI context**: excludes `dismissed` / `NOT_AFFECTED`; ports/CVEs
  scoped to the same top-500 hosts sent to the model.
- **`/api/v2/cves/exploit_status`**: excludes `dismissed` and `NOT_AFFECTED`
  rows like every other finding view. Regression:
  `test_exploit_status_excludes_dismissed_and_not_affected`
  (`tests/test_api.py`).
- **Prose version ranges** (`iris/cve_mapper.py`): "from X to Y" treats `Y` as
  inclusive (fail-safe for a security tool), while CPE ranges keep their
  explicit `versionEndExcluding` semantics. Regression:
  `tests/test_cve_mapper.py`.
- **Dashboard auth/session contract** (`tests/test_dashboard_hardening.py`):
  login lockout, oversized-credential rejection, refresh-token rotation and
  replay refusal, logout revoking both tokens, viewer read-only RBAC, metrics
  token gating, trusted-proxy client identity, and single-use JTI consumption.
- **Dashboard failure contract** (`tests/test_dashboard_hardening.py`): 34
  authenticated read/write endpoints are asserted to return a JSON 500 (not a
  traceback or a false success) when CHRONICLE is unreachable.
- **Dashboard operator actions** (`tests/test_dashboard_hardening.py`):
  saved-target apply/validation, SHIELD revert success/failure/crash, sentinel
  ack/ack-all, CSV formula neutralisation, FORGE include/exclude with exact
  rollback of `is_active` + `operator_excluded` on a failed write, and AI-brief
  retry on a locked database.
- **FORGE SID retry** (`forge/rule_generator.py`): the bounded unique-SID retry
  no longer reserves a SID after the final failed insert (it could never be
  used). The retry still revalidates every candidate before storing it.

### Previously landed (still in tree)
- `chronicle/backup.py`: WAL-safe restore via SQLite online backup API;
  atomic publication (`*.tmp` + `Path.replace()`); corrupt sources never
  publish a 0-byte backup.
- Retention prune by `COALESCE(finished_at, started_at)`; daemon range matches
  dashboard 1–3650 days.
- CLI/daemon scan parity; OSINT MAC-vendor longest-prefix override; Discord
  6000-char embed budget + 25-field cap; PHANTOM/SHIELD markup escaping.

## Audit decisions (do not "fix" these)

- `/metrics` 401 with a dashboard JWT is **intended** (separate
  `OBSIDIOS_METRICS_TOKEN`).
- `posture_score` intentionally excludes wireless/OSINT from the composite.
- `forge.write_rules_file` reporting `EMPTY` / `ok=True` when no rules exist is
  intentional.
- `/api/v2/refresh` returning 400 when no refresh cookie/token exists is
  intended (there is nothing to rotate).
- The two uncovered `dashboard/app.py` lines are the second defensive
  `jwt.decode` failure branch in `logout()`; `requires_auth` already validated
  the same token, so the branch only guards a key-rotation race.
- `run_heartbeat_loop` is now only the event-emitting loop wrapper;
  `heartbeat_once` is the single presence implementation.

## Deferred candidates

- None. All previously deferred items (prose version ranges, lower-coverage
  branches, `CLOSE_PORT` revert) are implemented and covered.
- The intermittent dashboard teardown `Event loop is closed` warning could not
  be reproduced in 18 consecutive full/subset runs after the heartbeat
  refactor; treat it as resolved unless it reappears with a fresh traceback.

## Live verification (previous round)

- Dashboard restarted on `127.0.0.1:8080` (fresh gunicorn pair after killing
  the old master/worker); session restored through the refresh cookie.
- Overview selected-asset card: **192.168.1.50 · build-server · Ubuntu 22.04 ·
  VMware · RISK 81.5**, chips `8080/http-proxy`, `9200/elasticsearch` — with
  no visit to Inventory in this session.
- `GET /api/v2/cves/exploit_status` → 200, 2 rows (CVE-2019-0708,
  CVE-2024-6387), dismissed/NOT_AFFECTED excluded.
- Read-only page sweep (Inventory 4 cards, Findings 5 rows, Audit 387 rows,
  back to Overview) → no console errors.

## Verification (this round, 2026-11-10)

- No network scan was started and no live SHIELD block was reverted.
- Full suite, ruff, `node --check`, bandit and `pip-audit` all pass as recorded
  at the top of this file.
- Coverage was measured with `--cov=dashboard.app`;
  `tests/test_dashboard_hardening.py`, `tests/test_forge_generation.py` and
  `tests/test_notifier_hardening.py` are the new suites from this round.

## Warnings

- Do **not** start a real network scan or revert live SHIELD blocks during
  verification unless explicitly asked.
- Keep all changes uncommitted until the user says otherwise.
- The live DB currently has no scan younger than ~130h; `/api/v2/oracle/ai_brief`
  correctly returns the freshness guard instead of stale AI output.
