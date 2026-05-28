"""iris/cve_mapper.py — Enhanced NVD API v2 Mapper with CPE support + version verification"""
from __future__ import annotations
import asyncio, hashlib, re, time
from collections import OrderedDict
import aiohttp
from loguru import logger
from chronicle import db
from chronicle.models import CVE, Severity

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Free NVD API: ~5 req/30s → safe = 1 req/7s
_RATE_SEMAPHORE = asyncio.Semaphore(1)
_CACHE_TTL = 86400

# Skip generic/noisy services that return ancient, irrelevant CVEs
_GENERIC_SERVICES = {"domain", "rtsp", "microsoft-ds", "netbios-ssn", "rpcbind"}
_GENERIC_PROTOCOLS = {"http", "https", "tcp", "udp"}

# Nmap service fingerprint misidentification overrides
# Key = product string Nmap reports, Value = (true_product, true_service)
_KNOWN_MISIDENTIFICATIONS: dict[str, tuple[str, str]] = {}

# Product name → description aliases for CVE description matching
# Nmap may report a product as "Apache httpd" but CVE descriptions
# use variants like "Apache HTTP Server", "httpd", etc.
_PRODUCT_ALIASES: dict[str, list[str]] = {
    "apache httpd":    ["apache", "httpd", "apache http server", "apache web server"],
    "apache tomcat":   ["tomcat", "apache tomcat"],
    "nginx":           ["nginx", "nginx web server"],
    "microsoft iis":   ["iis", "internet information services"],
    "vsftpd":          ["vsftpd", "ftp server"],
    "openssh":         ["openssh", "ssh"],
    "postgresql":      ["postgresql", "postgres"],
    "mariadb":         ["mariadb", "mysql"],
    "mongodb":         ["mongodb", "mongo"],
}

# Product → (CPE vendor, CPE product) for CVE filtering via CPE match strings
_CPE_MAP: dict[str, tuple[str, str]] = {
    "apache httpd":                   ("apache", "http_server"),
    "apache tomcat":                  ("apache", "tomcat"),
    "apache tomcat 10":               ("apache", "tomcat"),
    "apache tomcat 8":                ("apache", "tomcat"),
    "nginx":                          ("nginx", "nginx"),
    "microsoft iis":                  ("microsoft", "internet_information_services"),
    "iis":                            ("microsoft", "internet_information_services"),
    "vsftpd":                         ("beasts", "vsftpd"),
    "openssh":                        ("openbsd", "openssh"),
    "postgresql":                     ("postgresql", "postgresql"),
    "mariadb":                        ("mariadb", "mariadb"),
    "mongodb":                        ("mongodb", "mongodb"),
    "mysql":                          ("oracle", "mysql"),
    "redis":                          ("redislabs", "redis"),
    "redis key-value store":          ("redislabs", "redis"),
    "apache hadoop":                  ("apache", "hadoop"),
    "apache kafka":                   ("apache", "kafka"),
    "apache zookeeper":               ("apache", "zookeeper"),
    "caddy":                          ("caddyserver", "caddy"),
    "gunicorn":                       ("gunicorn", "gunicorn"),
    "uvicorn":                        ("encode", "uvicorn"),
    "node.js":                        ("nodejs", "node.js"),
    "php":                            ("php", "php"),
    "python":                         ("python", "python"),
    "python 3":                       ("python", "python"),
    "docker":                         ("docker", "docker"),
    "kubernetes":                     ("kubernetes", "kubernetes"),
    "elasticsearch":                  ("elasticsearch", "elasticsearch"),
    "nginx ingress controller":       ("nginx", "nginx"),
    "haproxy":                        ("haproxy", "haproxy"),
    "lighttpd":                       ("lighttpd", "lighttpd"),
    "squid":                          ("squid-cache", "squid"),
    "sendmail":                       ("sendmail", "sendmail"),
    "exim":                           ("exim", "exim"),
    "dovecot":                        ("dovecot", "dovecot"),
    "proftpd":                        ("proftpd", "proftpd"),
    "pure-ftpd":                      ("pureftpd", "pure-ftpd"),
    "opensmtpd":                      ("openbsd", "opensmtpd"),
    "ntp":                            ("ntp", "ntp"),
    "openntpd":                       ("openbsd", "openntpd"),
    "chrony":                         ("chrony", "chrony"),
    "memcached":                      ("memcached", "memcached"),
    "rabbitmq":                       ("pivotal_software", "rabbitmq"),
    "mosquitto":                      ("eclipse", "mosquitto"),
    "emqx":                           ("emqx", "emqx"),
    "tensorflow":                     ("google", "tensorflow"),
    "pytorch":                        ("pytorch", "pytorch"),
    "gitlab":                         ("gitlab", "gitlab"),
    "jenkins":                        ("jenkins", "jenkins"),
    "sonarqube":                      ("sonarsource", "sonarqube"),
    "wordpress":                      ("wordpress", "wordpress"),
    "drupal":                         ("drupal", "drupal"),
    "joomla":                         ("joomla", "joomla"),
    "mediawiki":                      ("mediawiki", "mediawiki"),
    "cgi":                            ("apache", "http_server"),
    "fastcgi":                        ("apache", "http_server"),
    "dnsmasq":                        ("the_kelleys", "dnsmasq"),
    "bind":                           ("isc", "bind"),
    "isc bind":                       ("isc", "bind"),
    "unbound":                        ("nlnetlabs", "unbound"),
    "nginx reverse proxy":            ("nginx", "nginx"),
    "jetty":                          ("eclipse", "jetty"),
    "wildfly":                        ("wildfly", "wildfly"),
    "jboss":                          ("redhat", "jboss_enterprise_application_platform"),
    "glassfish":                      ("oracle", "glassfish_server"),
    "zeek":                           ("zeek", "zeek"),
    "suricata":                       ("suricata", "suricata"),
}

# Generic words too broad for product-word matching (never use alone)
_GENERIC_PRODUCT_WORDS = {"httpd", "server", "web", "http", "https", "tcp", "udp", "proxy", "client", "service", "application", "device", "daemon", "protocol", "api", "rest", "soap", "linux"}

# Products known to produce false-positive CVE matches (description contains product name
# but CVE is about a DIFFERENT product with similar name)
_NEGATIVE_PRODUCT_WORDS: dict[str, list[str]] = {
    "mysql":             ["mariadb", "mod_authnz_external", "phpmyadmin", "adminer", "percona", "trustwave", "webdefend", "advanced poll", "postgresql", "mongodb", "redis"],
    "apache httpd":      ["tomcat", "activemq", "cxf", "struts", "log4j", "spark", "flink", "hadoop", "cassandra", "akeneo", "pim", "sonicwall", "ivanti", "mobileiron", "pulpcore", "artifactory", "nexus", "jira", "confluence", "gitlab", "jenkins", "drupal", "wordpress"],
    "nginx":             ["unit", "ingress"],
    "http":              ["pulpcore", "sonicwall", "smc", "sophos", "fortinet", "palo_alto"],
    "https":             ["pulpcore", "sonicwall", "smc", "sophos", "fortinet", "palo_alto"],
    "vsftpd":            ["proftpd", "pure-ftpd", "wu-ftpd"],
    "gunicorn":          ["galaxy", "mlflow"],
    "uvicorn":           ["mlflow", "cognita"],
}

class _LRUCache:
    def __init__(self, maxsize=2048):
        self._data = OrderedDict()
        self._maxsize = maxsize
    def get(self, key):
        if key not in self._data: return None
        ts, val = self._data[key]
        if time.time()-ts > _CACHE_TTL:
            del self._data[key]; return None
        self._data.move_to_end(key); return val
    def set(self, key, value):
        if len(self._data) >= self._maxsize: self._data.popitem(last=False)
        self._data[key] = (time.time(), value)

_cache = _LRUCache()

def _normalize_service(svc: str) -> str:
    """Normalize nmap service names: strip uncertainty markers, whitespace, lowercase."""
    return re.sub(r'[?*#].*$', '', svc).strip().lower()

def _cache_key(service, version, cpe):
    return hashlib.md5(f"{service}:{version or ''}:{cpe or ''}".encode()).hexdigest()

# ── Version Parsing & Comparison ──────────────────────────────────────────

def _extract_affected_versions(description: str, cve_config: list | dict | None = None) -> list[dict]:
    """Extract affected version constraints from CVE description using regex patterns."""
    if not description: return []
    constraints = []

    patterns = [
        (r'versions?\s+(?:prior\s+to|before)\s+(\d+[\d.]*(?:[a-z]\d*)?)', 'end', True),
        (r'(\d+[\d.]*(?:[a-z]\d*)?)\s+(?:and\s+earlier|and\s+prior|or\s+earlier|or\s+prior)', 'end', True),
        (r'(?:through\s+version|up\s+to)\s+(\d+[\d.]*(?:[a-z]\d*)?)', 'end', True),
        (r'from\s+(\d+[\d.]*(?:[a-z]\d*)?)\s+to\s+(\d+[\d.]*(?:[a-z]\d*)?)', 'range', False),
        (r'before\s+(\d+[\d.]*(?:[a-z]\d*)?)', 'end', False),
    ]

    for pattern, mode, inclusive in patterns:
        for match in re.finditer(pattern, description, re.IGNORECASE):
            groups = match.groups()
            if mode == 'range' and len(groups) >= 2:
                constraints.append({"versionStart": groups[0], "versionEnd": groups[1], "inclusive": False})
            elif groups[0]:
                constraints.append({"versionEnd": groups[0], "inclusive": inclusive})
            if len(constraints) >= 2:
                break
        if constraints:
            break

    # Also parse CVE config CPE match if available
    if cve_config and not constraints:
        configs = cve_config if isinstance(cve_config, list) else [cve_config]
        for conf in configs:
            nodes = conf.get("nodes", [])
            for node in nodes:
                for m in node.get("cpeMatch", []):
                    end = m.get("versionEndExcluding") or m.get("versionEndIncluding")
                    start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                    if end or start:
                        constraints.append({
                            "versionStart": start,
                            "versionEnd": end,
                            "inclusive": bool(m.get("versionEndIncluding") or m.get("versionStartIncluding"))
                        })
                        break
                if constraints: break
            if constraints: break

    return constraints


def _parse_version(ver: str | None) -> tuple:
    """Parse a version string into comparable tuple. Handles '7.2p2', '2.4.41', etc."""
    if not ver: return ()
    cleaned = re.sub(r'^[^\d]*', '', str(ver))
    cleaned = re.sub(r'[a-zA-Z].*$', '', cleaned)
    parts = cleaned.replace('-', '.').split('.')
    result = []
    for p in parts:
        try: result.append(int(p))
        except ValueError: result.append(0)
    return tuple(result)


def _version_in_range(detected: str | None, constraints: list[dict]) -> str:
    """Returns 'CONFIRMED', 'NOT_AFFECTED', or 'UNVERIFIED'."""
    if not detected or not constraints: return 'UNVERIFIED'
    dv = _parse_version(detected)
    if not dv: return 'UNVERIFIED'

    for c in constraints:
        end_ver = c.get("versionEnd")
        start_ver = c.get("versionStart")
        inclusive = c.get("inclusive", True)
        ev = _parse_version(end_ver) if end_ver else None
        sv = _parse_version(start_ver) if start_ver else None

        if ev is not None and sv is not None:
            if inclusive and sv <= dv <= ev: return 'CONFIRMED'
            if not inclusive and sv <= dv < ev: return 'CONFIRMED'
        elif ev is not None:
            if inclusive and dv <= ev: return 'CONFIRMED'
            if not inclusive and dv < ev: return 'CONFIRMED'
        elif sv is not None:
            if dv >= sv: return 'CONFIRMED'

    return 'NOT_AFFECTED' if constraints else 'UNVERIFIED'


def _parse_response(data: dict) -> tuple[list[CVE], dict[str, list[dict]], dict[str, set[tuple[str, str]]]]:
    """Parse NVD response. Returns (list of CVE, version_affected, cpe_map).
    cpe_map is cve_id -> set of (vendor, product) from CPE match strings."""
    cves = []
    affected_map = {}
    cpe_map: dict[str, set[tuple[str, str]]] = {}
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id", "")
        if not cve_id: continue

        try:
            pub_year = int(cve_id.split("-")[1])
            if pub_year < 2010: continue
        except: pass

        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        cvss_v3 = sev = None
        m = c.get("metrics", {})

        if "cvssMetricV31" in m:
            cvss_v3 = m["cvssMetricV31"][0]["cvssData"].get("baseScore")
            sev = m["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "NONE").upper()
        elif "cvssMetricV30" in m:
            cvss_v3 = m["cvssMetricV30"][0]["cvssData"].get("baseScore")
            sev = m["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "NONE").upper()
        elif "cvssMetricV2" in m:
            cvss_v3 = m["cvssMetricV2"][0]["cvssData"].get("baseScore")
            score = cvss_v3 or 0
            if score >= 9.0: sev = "CRITICAL"
            elif score >= 7.0: sev = "HIGH"
            elif score >= 4.0: sev = "MEDIUM"
            else: sev = "LOW"

        try: severity = Severity(sev or "NONE")
        except: severity = Severity.NONE

        config = c.get("configurations", {})
        affected = _extract_affected_versions(desc, config)
        affected_map[cve_id] = affected

        # Extract CPE vendor:product pairs from configurations
        cpe_set: set[tuple[str, str]] = set()
        configs = config if isinstance(config, list) else [config]
        for conf in configs:
            nodes = conf.get("nodes", []) if isinstance(conf, dict) else []
            for node in nodes:
                for m in node.get("cpeMatch", []):
                    criteria = m.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 6 and parts[0] == "cpe":
                        vendor = parts[3]
                        product = parts[4]
                        if vendor != "*" and product != "*":
                            cpe_set.add((vendor, product))
        if cpe_set:
            cpe_map[cve_id] = cpe_set

        cves.append(CVE(
            cve_id=cve_id, cvss_v3=cvss_v3, severity=severity,
            description=desc[:1000] or None,
        ))
    return cves, affected_map, cpe_map


async def lookup_cves(session, service, version=None, product=None, api_key=None) -> tuple[list[CVE], dict[str, list[dict]]]:
    if not service: return [], {}
    svc = _normalize_service(service)
    if svc in _GENERIC_SERVICES: return [], {}
    if svc in _GENERIC_PROTOCOLS and not product: return [], {}
    key = _cache_key(service, version, product)
    cached = _cache.get(key)
    if cached is not None:
        return cached[0], cached[1] if len(cached) > 1 else {}
    results, aff_map = [], {}
    cpe_map: dict[str, set[tuple[str, str]]] = {}
    headers = {"apiKey": api_key} if api_key else {}
    async with _RATE_SEMAPHORE:
        try:
            # Resolve known Nmap misidentifications to correct product name
            effective_product = product
            effective_service = service
            if product and product in _KNOWN_MISIDENTIFICATIONS:
                effective_product, effective_service = _KNOWN_MISIDENTIFICATIONS[product]

            # Only query NVD for known products (have CPE or alias mapping)
            # or for services with a detected product
            prod_lower_q = (effective_product or "").lower()
            has_known_mapping = bool(prod_lower_q and (
                prod_lower_q in _CPE_MAP
                or prod_lower_q in _PRODUCT_ALIASES
                or _KNOWN_MISIDENTIFICATIONS.get(effective_product)
            ))
            if not has_known_mapping and not effective_product:
                results, aff_map, cpe_map = [], {}, {}
                logger.info(f"[IRIS/CVE] Skipping {effective_service} — no product and no known mapping")
                _cache.set(key, (results, aff_map))
                await asyncio.sleep(6.5)
                return results, aff_map
            search_terms = effective_product or effective_service
            if effective_product and len(effective_product.split()) > 3:
                search_terms = effective_service
            params = {
                "keywordSearch": f"{search_terms} vulnerability",
                "resultsPerPage": 50 if has_known_mapping else 10,
            }
            logger.info(f"[IRIS/CVE] Searching {effective_service} ({effective_product}) → \"{search_terms} vulnerability\"")
            async with session.get(_NVD_BASE, params=params, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    results, aff_map, cpe_map = _parse_response(await resp.json(content_type=None))
                    # ── Filter by CPE match first, then description ──
                    if results:
                        prod_lower = (effective_product or "").lower()
                        svc_lower = (effective_service or "").lower()
                        product_words = [w.lower() for w in (effective_product or "").split() if len(w) > 2]
                        aliases = _PRODUCT_ALIASES.get(prod_lower, [])
                        # Get expected CPE vendor:product for this product
                        expected_cpe = _CPE_MAP.get(prod_lower)
                        negative_words = _NEGATIVE_PRODUCT_WORDS.get(
                            prod_lower,
                            _NEGATIVE_PRODUCT_WORDS.get(svc_lower, [])
                        )
                        filtered = []
                        for cve in results:
                            # 1. CPE-based match (most reliable)
                            desc = (cve.description or "").lower()
                            cpe_matches = cpe_map.get(cve.cve_id, set())
                            if expected_cpe and cpe_matches:
                                ev, ep = expected_cpe
                                cpe_hit = expected_cpe in cpe_matches or any(v == ev and p == ep for v, p in cpe_matches)
                                if cpe_hit:
                                    # CPE matched — but check if CVE is about a BUNDLED product (not ours)
                                    other_vendors = {v for v, p in cpe_matches if v != ev}
                                    if other_vendors and desc:
                                        other_names = [p.replace('_', ' ') for v, p in cpe_matches if v != ev]
                                        # If description mentions other bundled products more prominently than ours
                                        if any(re.search(r'\b' + re.escape(n) + r'\b', desc) for n in other_names if len(n) > 3):
                                            prod_in_desc = prod_lower and re.search(r'\b' + re.escape(prod_lower) + r'\b', desc)
                                            if not prod_in_desc and not any(
                                                re.search(r'\b' + re.escape(w) + r'\b', desc) for w in product_words
                                            ):
                                                continue  # description talks about the bundled product, not ours
                                        if negative_words and any(w in desc for w in negative_words):
                                            continue
                                    filtered.append(cve)
                                    continue
                            # 2. Description-based match (fallback for CVEs without CPE config)
                            if not desc: continue
                            # Skip if any negative keyword matches
                            if negative_words and any(w in desc for w in negative_words):
                                continue
                            # Word-boundary match on raw product name
                            if prod_lower and re.search(r'\b' + re.escape(prod_lower) + r'\b', desc):
                                filtered.append(cve)
                                continue
                            # Match on significant product words (skip generic/short words)
                            if product_words and any(
                                len(w) >= 4 and w not in _GENERIC_PRODUCT_WORDS
                                and re.search(r'\b' + re.escape(w) + r'\b', desc) for w in product_words
                            ):
                                filtered.append(cve)
                                continue
                            # Match on aliases
                            if aliases and any(
                                re.search(r'\b' + re.escape(a) + r'\b', desc) for a in aliases
                            ):
                                filtered.append(cve)
                                continue
                            # Match on service name ONLY if no product was detected at all
                            # (prevents flooding generic http/tcp CVEs for unknown products)
                            if not effective_product and svc_lower and re.search(r'\b' + re.escape(svc_lower) + r'\b', desc):
                                filtered.append(cve)
                                continue
                        cpe_count = sum(1 for cv in filtered if cpe_map.get(cv.cve_id))
                        logger.info(
                            f"[IRIS/CVE] {effective_service} ({effective_product}): "
                            f"{len(results)} API → {len(filtered)} after filter "
                            f"(CPE-matched: {cpe_count})"
                        )
                        results = filtered
                else:
                    logger.warning(f"[IRIS/CVE] NVD API returned {resp.status} for {effective_service}")
        except Exception as exc:
            logger.warning(f"[IRIS/CVE] Lookup error for {effective_service}: {exc}")
        await asyncio.sleep(6.5)
    _cache.set(key, (results, aff_map))
    return results, aff_map


async def map_cves_for_scan(scan_result, api_key=None) -> tuple[dict[str, list[CVE]], dict[str, list[dict]]]:
    """Maps CVEs per host:port. Returns (cve_map, affected_map)."""
    result_map = {}
    affected_map = {}  # cve_id -> list of constraints
    unique = {}
    port_to_key = {}
    skipped_generic = 0
    for ip, ports in scan_result.ports.items():
        for port in ports:
            if not port.service:
                continue
            svc = _normalize_service(port.service)
            if svc in _GENERIC_SERVICES:
                logger.debug(f"[IRIS/CVE] Skipping {ip}:{port.port} — generic service '{svc}'")
                skipped_generic += 1
                continue
            if svc in _GENERIC_PROTOCOLS and not port.product and not port.cpe:
                logger.debug(f"[IRIS/CVE] Skipping {ip}:{port.port} — {svc} without product/CPE")
                skipped_generic += 1
                continue
            k = _cache_key(port.service, port.version, port.product or port.cpe)
            unique[k] = (port.service, port.version, port.product)
            port_to_key[(ip, port.port)] = k
    if skipped_generic:
        logger.info(f"[IRIS/CVE] Skipped {skipped_generic} ports (generic/no-product)")
    if not unique:
        logger.warning(f"[IRIS/CVE] No unique service+product combinations to query — all ports filtered out")
        return result_map, affected_map
    logger.info(f"[IRIS/CVE] Querying {len(unique)} unique service+product combo(s) for CVEs")
    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = {k: asyncio.create_task(lookup_cves(session, s, v, p, api_key))
                 for k, (s, v, p) in unique.items()}
        await asyncio.gather(*tasks.values(), return_exceptions=True)
        for k, t in tasks.items():
            if not t.exception():
                cves, aff = t.result()
                if aff: affected_map.update(aff)
                matched_ports = [(ip2, pn2) for (ip2, pn2), k2 in port_to_key.items() if k2 == k]
                s, v, p = unique[k]
                logger.info(f"[IRIS/CVE] {s} ({p or 'no product'}): {len(cves)} CVEs for {len(matched_ports)} port(s)")
                for (ip2, port_num2), k2 in port_to_key.items():
                    if k2 == k:
                        if cves: result_map[f"{ip2}:{port_num2}"] = cves
    return result_map, affected_map


async def persist_cves(cve_map: dict, scan_result, affected_map: dict | None = None) -> int:
    all_cves = {cve.cve_id: cve for cves in cve_map.values() for cve in cves}
    if not all_cves: return 0
    cve_id_map = {}
    if affected_map is None: affected_map = {}

    async with db.transaction() as conn:
        for cve in all_cves.values():
            if cve.severity == Severity.CRITICAL:
                from alerts.notifier import buffer_alert
                await buffer_alert(
                    category="critical_cves",
                    title=cve.cve_id,
                    message=f"CVSS **{cve.cvss_v3}** — {cve.description[:200]}",
                    color="critical",
                    fields=[{"name": "CVE", "value": f"`{cve.cve_id}`", "inline": True},
                            {"name": "CVSS", "value": f"**{cve.cvss_v3}**", "inline": True},
                            {"name": "NVD", "value": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}", "inline": False}],
                )
            # Use conn.execute directly inside transaction
            async with conn.execute(
                """INSERT INTO cves (cve_id, cvss_v3, severity, description)
                   VALUES (?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET
                     cvss_v3     = COALESCE(excluded.cvss_v3, cvss_v3),
                     severity    = COALESCE(excluded.severity, severity),
                     description = COALESCE(excluded.description, description)
                   RETURNING id""",
                (cve.cve_id, cve.cvss_v3, str(cve.severity), cve.description),
            ) as cur:
                row = await cur.fetchone()
                if row: cve_id_map[cve.cve_id] = row[0]

        # Build port version map
        port_version_map = {}
        for ip, ports in scan_result.ports.items():
            for port in ports:
                port_version_map[(ip, port.port)] = port.version

        for ip, ports in scan_result.ports.items():
            host_row = await db.fetch_one("SELECT id FROM hosts WHERE ip=?", (ip,))
            if not host_row: continue
            host_id = host_row["id"]
            for port in ports:
                port_product = port.product or port.cpe
                # Belt-and-suspenders: never write CVEs for generic protocols without product
                if _normalize_service(port.service) in _GENERIC_PROTOCOLS and not port_product:
                    continue
                port_row = await db.fetch_one("SELECT id FROM ports WHERE host_id=? AND port=?", (host_id, port.port))
                if not port_row: continue
                port_db_id = port_row["id"]
                for cve in cve_map.get(f"{ip}:{port.port}", []):
                    cve_db_id = cve_id_map.get(cve.cve_id)
                    if cve_db_id:
                        detected_ver = port_version_map.get((ip, port.port))
                        constraints = affected_map.get(cve.cve_id, [])
                        status = _version_in_range(detected_ver, constraints)
                        await conn.execute(
                            """INSERT OR IGNORE INTO port_cves (port_id, cve_id, verified_status, detected_version)
                               VALUES (?, ?, ?, ?)""",
                            (port_db_id, cve_db_id, status, detected_ver)
                        )
                        await conn.execute(
                            "UPDATE port_cves SET verified_status=?, detected_version=COALESCE(detected_version, ?) WHERE port_id=? AND cve_id=?",
                            (status, detected_ver, port_db_id, cve_db_id)
                        )
    return len(all_cves)


async def verify_all_cves() -> int:
    """Re-verify all port_cves entries against their CVE description + detected versions."""
    rows = await db.fetch_all("""
        SELECT pc.port_id, pc.cve_id, pc.verified_status, pc.detected_version,
               p.version as port_version, c.description
        FROM port_cves pc
        JOIN ports p ON p.id = pc.port_id
        JOIN cves c ON c.id = pc.cve_id
        WHERE pc.verified_status != 'CONFIRMED'
    """)
    updated = 0
    if not rows: return 0
    async with db.transaction() as conn:
        for row in rows:
            version = row.get("detected_version") or row.get("port_version")
            desc = row.get("description") or ""
            affected = _extract_affected_versions(desc)
            status = _version_in_range(version, affected)
            if status != row.get("verified_status"):
                await conn.execute(
                    "UPDATE port_cves SET verified_status=?, detected_version=COALESCE(detected_version, ?) WHERE port_id=? AND cve_id=?",
                    (status, version, row["port_id"], row["cve_id"])
                )
                updated += 1
    return updated