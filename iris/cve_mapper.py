"""iris/cve_mapper.py — Enhanced NVD API v2 Mapper with CPE support + version verification"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections import OrderedDict

import aiohttp
from loguru import logger

from chronicle import db
from chronicle.models import CVE, Severity

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Free NVD API: ~5 req/30s → safe = 1 req/7s
_RATE_SEMAPHORE = asyncio.Semaphore(1)
_REQUEST_INTERVAL = 6.5   # seconds between NVD calls (patched in tests)
_CACHE_TTL = 86400


async def _rate_limit_pause() -> None:
    await asyncio.sleep(_REQUEST_INTERVAL)

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
    "dnsmasq":                        ("thekelleys", "dnsmasq"),
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
    "openssh":           ["dropbear", "vyos"],
    "dnsmasq":           ["luci", "oray", "pugongying", "libvirt"],
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
    return hashlib.md5(f"{service}:{version or ''}:{cpe or ''}".encode(), usedforsecurity=False).hexdigest()  # non-security cache key


def _cpe_vendor_product(cpe: str | None) -> tuple[str, str] | None:
    """Return the raw ``(vendor, product)`` of a CPE 2.2/2.3 URI.

    Kept in NVD's underscore form because that is what the CPE match strings in
    a vulnerability response use, so the pair can be compared directly.
    """
    if not isinstance(cpe, str) or not cpe:
        return None
    text = cpe.strip()
    parts = text.split(":")
    if text.startswith("cpe:/"):
        # cpe:/<part>:<vendor>:<product>[:<version>]
        vendor, product = (parts[2], parts[3]) if len(parts) > 3 else ("", "")
    elif text.startswith("cpe:2.3:"):
        # cpe:2.3:<part>:<vendor>:<product>:...
        vendor, product = (parts[3], parts[4]) if len(parts) > 4 else ("", "")
    else:
        return None
    vendor = vendor.replace("\\", "").strip().lower()
    product = product.replace("\\", "").strip().lower()
    if not vendor or not product or vendor in {"*", "-"} or product in {"*", "-"}:
        return None
    return vendor, product


def _product_from_cpe(cpe: str | None) -> str | None:
    """Human-readable product name derived from a CPE URI.

    Nmap sometimes fingerprints a service with a CPE but no product name.
    `lookup_cves()` refuses to search without one, so those ports silently
    produced zero CVEs; the CPE is enough to name what is running.
    """
    pair = _cpe_vendor_product(cpe)
    if pair is None:
        return None
    return pair[1].replace("_", " ").strip() or None

# ── Version Parsing & Comparison ──────────────────────────────────────────

def _iter_cpe_matches(cve_config: object):
    """Yield the CPE match dicts of an NVD ``configurations`` value.

    `configurations` is external data: any level of it can be missing, null or
    the wrong type. Indexing into it blindly (`node.get(...)` on a string) made
    one malformed entry discard every CVE from the whole service.
    """
    configs = cve_config if isinstance(cve_config, list) else [cve_config]
    for conf in configs:
        if not isinstance(conf, dict):
            continue
        nodes = conf.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if isinstance(match, dict):
                    yield match


# NVD configurations can list many affected CPE ranges for one CVE (a vendor
# fixes several release lines at once). Keep a bounded but useful number.
_MAX_AFFECTED_CONSTRAINTS = 64
_MAX_DESCRIPTION_CONSTRAINTS = 8


def _extract_affected_versions(
    description: str,
    cve_config: list | dict | None = None,
    expected_cpe: tuple[str, str] | None = None,
) -> list[dict]:
    """Extract affected version constraints for a CVE.

    NVD's machine-readable ``configurations`` block is authoritative: it is
    what scanners and NVD itself use. The prose description is only a fallback
    for CVEs that have no version bounds in their CPE matches. The old code
    did the reverse, so a loose description regex could override precise NVD
    bounds — and a second release line was ignored entirely.

    When ``expected_cpe`` is supplied, only CPE matches for that exact
    ``(vendor, product)`` pair may contribute bounds. Advisories routinely
    list a bundled OS or appliance alongside the application; merging their
    ranges produced ``CONFIRMED`` verdicts for versions the advisory never
    named.
    """
    constraints: list[dict] = []
    seen: set[tuple] = set()

    def add(constraint: dict) -> None:
        key = (
            constraint.get("versionStart"),
            constraint.get("versionEnd"),
            bool(constraint.get("inclusive", True)),
            bool(constraint.get("startInclusive", True)),
        )
        if key in seen:
            return
        seen.add(key)
        constraints.append(constraint)

    matches = list(_iter_cpe_matches(cve_config))
    cpe_authoritative = bool(matches)
    if expected_cpe:
        expected_pair = (str(expected_cpe[0]).lower(), str(expected_cpe[1]).lower())
        scoped = [
            m for m in matches
            if _cpe_vendor_product(m.get("criteria")) == expected_pair
        ]
        if cpe_authoritative:
            if not scoped:
                # Authoritative CPE data exists and none of it names the
                # fingerprinted product: this advisory is about something else.
                return []
            matches = scoped

    # Prefer authoritative CPE bounds. Only ranges with at least one bound are
    # useful; a bare ``criteria`` version is the product fingerprint, not an
    # affected-version statement.
    for m in matches:
        if m.get("vulnerable") is False:
            continue
        end_including = m.get("versionEndIncluding")
        end_excluding = m.get("versionEndExcluding")
        start_including = m.get("versionStartIncluding")
        start_excluding = m.get("versionStartExcluding")
        start = start_including or start_excluding
        end = end_including or end_excluding
        if not end and not start:
            continue
        constraint = {
            "versionStart": start,
            "versionEnd": end,
            # An explicit `versionEndExcluding` bound must not be read as
            # inclusive just because a start bound was written down.
            "inclusive": bool(end_including) if end else True,
        }
        if start_excluding and not start_including:
            constraint["startInclusive"] = False
        add(constraint)
        if len(constraints) >= _MAX_AFFECTED_CONSTRAINTS:
            break

    if constraints:
        return constraints

    # With an exact product fingerprint, a CPE block that names the product
    # but carries no version bounds is still authoritative. Falling back to
    # prose here can import a bound that describes a different product in the
    # same bundled advisory, so leave the verdict UNVERIFIED instead.
    if cpe_authoritative and expected_cpe:
        return []

    patterns = [
        (r'versions?\s+(?:prior\s+to|before)\s+(\d+(?:\.\d+)*(?:[a-z]\d*)?)', 'end', True),
        (r'(\d+(?:\.\d+)*(?:[a-z]\d*)?)\s+(?:and\s+earlier|and\s+prior|or\s+earlier|or\s+prior)', 'end', True),
        (r'(?:through\s+version|up\s+to)\s+(\d+(?:\.\d+)*(?:[a-z]\d*)?)', 'end', True),
        (r'from\s+(\d+(?:\.\d+)*(?:[a-z]\d*)?)\s+to\s+(\d+(?:\.\d+)*(?:[a-z]\d*)?)', 'range', True),
        (r'before\s+(\d+(?:\.\d+)*(?:[a-z]\d*)?)', 'end', False),
    ]

    # Prose can mention more than one affected release line. Collect every
    # non-duplicate bound instead of stopping at the first regex hit.
    for pattern, mode, inclusive in patterns:
        for match in re.finditer(pattern, description or "", re.IGNORECASE):
            groups = match.groups()
            if mode == 'range' and len(groups) >= 2:
                # "versions from X to Y" names Y as the last affected release;
                # excluding Y hid the release the advisory just called affected.
                # This path only runs for CVEs with no machine-readable range,
                # so prefer the false positive over a silent false negative.
                add({"versionStart": groups[0], "versionEnd": groups[1], "inclusive": True})
            elif groups[0]:
                add({"versionEnd": groups[0], "inclusive": inclusive})
            if len(constraints) >= _MAX_DESCRIPTION_CONSTRAINTS:
                return constraints

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


# Semver-style pre-release markers. NVD uses forms such as ``1.2.3-rc1``,
# ``1.2.3-beta.2`` and ``1.2.3alpha``; a pre-release is *older* than the
# release it leads up to. `_parse_version` deliberately keeps its historical
# tuple shape (other callers rely on it), so comparison uses a separate key.
_PRERELEASE_RE = re.compile(
    r'(?<![a-z])(alpha|beta|rc|pre|preview|dev|snapshot|nightly|milestone)[._-]?(\d*)',
    re.IGNORECASE,
)
_RELEASE_PAD = 8


def _version_key(ver: str | None) -> tuple | None:
    """Comparable key that orders pre-releases before their final release.

    Returns ``None`` when the value carries no numeric version at all (``*``,
    ``unknown``, empty). Callers must treat such bounds as absent rather than
    as zero, which is what produced false NOT_AFFECTED verdicts.
    """
    if ver is None:
        return None
    text = str(ver).strip()
    if not text or not re.search(r"\d", text):
        return None

    match = _PRERELEASE_RE.search(text)
    if match and text[:match.start()].rstrip("._-+ ").endswith(tuple("0123456789")):
        release_text = text[:match.start()].rstrip("._-+ ")
        prerelease = re.findall(r"[a-z]+|\d+", text[match.start():].lower())
        prerelease_key = tuple(
            (0, int(token)) if token.isdigit() else (1, token)
            for token in prerelease
        )
        is_prerelease = 0
    else:
        release_text = text
        prerelease_key = ()
        is_prerelease = 1

    numbers = list(_parse_version(release_text))
    if not numbers:
        return None
    numbers.extend([0] * max(0, _RELEASE_PAD - len(numbers)))
    return (tuple(numbers), is_prerelease, prerelease_key)


def _version_in_range(detected: str | None, constraints: list[dict]) -> str:
    """Returns 'CONFIRMED', 'NOT_AFFECTED', or 'UNVERIFIED'."""
    if not detected or not constraints: return 'UNVERIFIED'
    dv = _version_key(detected)
    if dv is None: return 'UNVERIFIED'

    checked = 0
    for c in constraints:
        if not isinstance(c, dict):
            continue
        end_ver = c.get("versionEnd")
        start_ver = c.get("versionStart")
        inclusive = c.get("inclusive", True)
        start_inclusive = c.get("startInclusive", True)
        ev = _version_key(end_ver) if end_ver else None
        sv = _version_key(start_ver) if start_ver else None
        # An unusable bound ("*", "unknown") is not a bound. Treating it as
        # version zero inverted the verdict for the whole constraint.
        if ev is None and sv is None:
            continue
        checked += 1

        if ev is not None and sv is not None:
            start_ok = sv <= dv if start_inclusive else sv < dv
            end_ok = dv <= ev if inclusive else dv < ev
            if start_ok and end_ok: return 'CONFIRMED'
        elif ev is not None:
            if inclusive and dv <= ev: return 'CONFIRMED'
            if not inclusive and dv < ev: return 'CONFIRMED'
        elif sv is not None:
            if start_inclusive and dv >= sv: return 'CONFIRMED'
            if not start_inclusive and dv > sv: return 'CONFIRMED'

    return 'NOT_AFFECTED' if checked else 'UNVERIFIED'


def _first_cvss_metric(metrics: dict, key: str) -> tuple[float | None, str | None]:
    """Read the first CVSS entry from an NVD metrics block.

    NVD occasionally returns an empty list or an entry without ``cvssData``;
    the old code indexed straight into it and one malformed entry made the
    whole response unusable for that service.
    """
    entries = metrics.get(key)
    if not isinstance(entries, list) or not entries:
        return None, None
    data = entries[0].get("cvssData") if isinstance(entries[0], dict) else None
    if not isinstance(data, dict):
        return None, None
    score = data.get("baseScore")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    return score, data.get("baseSeverity")


def _severity_from(score: float | None, label: object) -> Severity:
    """Map NVD's ``baseSeverity`` (or a bare score) to our Severity enum."""
    if isinstance(label, str) and label.strip():
        try:
            return Severity(label.strip().upper())
        except ValueError:
            pass
    if score is not None:
        if score >= 9.0: return Severity.CRITICAL
        if score >= 7.0: return Severity.HIGH
        if score >= 4.0: return Severity.MEDIUM
        if score > 0:    return Severity.LOW
    return Severity.NONE


def _parse_response(
    data: dict,
    expected_cpe: tuple[str, str] | None = None,
) -> tuple[list[CVE], dict[str, list[dict]], dict[str, set[tuple[str, str]]]]:
    """Parse NVD response. Returns (list of CVE, version_affected, cpe_map).
    cpe_map is cve_id -> set of (vendor, product) from CPE match strings.

    ``expected_cpe`` is the product the port actually fingerprints. NVD
    configurations are authoritative: when a CVE carries CPE data but none of
    it names the expected product, the CVE is discarded before prose matching
    gets a chance to attach a Bash advisory to an OpenSSH port.
    """
    cves = []
    affected_map = {}
    cpe_map: dict[str, set[tuple[str, str]]] = {}
    expected_pair = None
    if expected_cpe:
        expected_pair = (str(expected_cpe[0]).lower(), str(expected_cpe[1]).lower())
    if not isinstance(data, dict):
        return cves, affected_map, cpe_map
    for item in (data.get("vulnerabilities") or []):
        if not isinstance(item, dict):
            continue
        c = item.get("cve")
        if not isinstance(c, dict):
            continue
        cve_id = c.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            continue

        try:
            if int(cve_id.split("-")[1]) < 2010:
                continue
        except (IndexError, ValueError):
            pass

        descriptions = c.get("descriptions")
        if not isinstance(descriptions, list):
            descriptions = []
        desc = next(
            (d.get("value") or "" for d in descriptions
             if isinstance(d, dict) and d.get("lang") == "en"),
            "",
        )
        if not isinstance(desc, str):
            desc = ""

        cvss_v3 = sev = None
        m = c.get("metrics")
        if not isinstance(m, dict):
            m = {}

        if "cvssMetricV31" in m:
            cvss_v3, sev = _first_cvss_metric(m, "cvssMetricV31")
        elif "cvssMetricV30" in m:
            cvss_v3, sev = _first_cvss_metric(m, "cvssMetricV30")
        elif "cvssMetricV2" in m:
            cvss_v3, _ = _first_cvss_metric(m, "cvssMetricV2")
        severity = _severity_from(cvss_v3, sev)

        config = c.get("configurations", {})
        # A ``vulnerable: false`` match describes the platform the vulnerable
        # product runs on, not a product the advisory covers. Only vulnerable
        # matches may authorise a CVE for this fingerprint.
        cpe_set: set[tuple[str, str]] = set()
        cpe_matches = list(_iter_cpe_matches(config))
        for match in cpe_matches:
            if match.get("vulnerable") is False:
                continue
            pair = _cpe_vendor_product(match.get("criteria"))
            if pair is not None:
                cpe_set.add(pair)

        if expected_pair and cpe_matches and expected_pair not in cpe_set:
            # The authoritative CPE block names only other products (or only
            # platforms, as ``vulnerable: false`` entries). Do not let a prose
            # mention of "OpenSSH" smuggle in a GNU Bash advisory.
            continue

        affected = _extract_affected_versions(desc, config, expected_pair)
        affected_map[cve_id] = affected
        if cpe_set:
            cpe_map[cve_id] = cpe_set

        cves.append(CVE(
            cve_id=cve_id, cvss_v3=cvss_v3, severity=severity,
            description=desc[:1000] or None,
        ))
    return cves, affected_map, cpe_map


def _mentions_in_opening(description: str, names: list[str]) -> bool:
    """True when a product name appears in the advisory's opening sentence.

    NVD states the affected product in the first sentence ("A flaw was found
    in dnsmasq. ..."). A later mention can be an incidental component of a
    different product ("... in Oray Pugongying X5 Pro. ... component Dnsmasq"),
    which is not a claim about the fingerprinted product.
    """
    text = (description or "").strip()
    if not text:
        return False
    opening = re.split(r"(?<=[.!?])\s+|\n", text, maxsplit=1)[0].lower()
    for name in names or []:
        if not isinstance(name, str) or not name:
            continue
        if re.search(r"(?:^|[^a-z0-9])" + re.escape(name) + r"(?:[^a-z0-9]|$)",
                     opening):
            return True
    return False


async def lookup_cves(session, service, version=None, product=None,
                      api_key=None, cpe=None) -> tuple[list[CVE], dict[str, list[dict]]]:
    if not service: return [], {}
    svc = _normalize_service(service)
    if svc in _GENERIC_SERVICES and not product and not cpe: return [], {}
    # A CPE is a usable fingerprint even when Nmap named no product.
    if svc in _GENERIC_PROTOCOLS and not product and not cpe: return [], {}
    key = _cache_key(service, version, product or cpe)
    cached = _cache.get(key)
    if cached is not None:
        return cached[0], cached[1] if len(cached) > 1 else {}
    results, aff_map = [], {}
    headers = {"apiKey": api_key} if api_key else {}

    # Resolve known Nmap misidentifications to the correct product name
    effective_product = product or _product_from_cpe(cpe)
    effective_service = service
    if product and product in _KNOWN_MISIDENTIFICATIONS:
        effective_product, effective_service = _KNOWN_MISIDENTIFICATIONS[product]

    # Only query NVD for known products (have a CPE or alias mapping) or for
    # services with a detected product. A CPE-only fingerprint is both.
    prod_lower_q = (effective_product or "").lower()
    aliases = _PRODUCT_ALIASES.get(prod_lower_q, [])
    expected_cpe = _CPE_MAP.get(prod_lower_q) or _cpe_vendor_product(cpe)
    has_known_mapping = bool(expected_cpe or aliases)

    if not has_known_mapping and not effective_product:
        # This path makes no API request: it must neither sleep for the rate
        # limit nor sit on the semaphore and delay every real lookup.
        logger.info(f"[IRIS/CVE] Skipping {effective_service} — no product and no known mapping")
        _cache.set(key, (results, aff_map))
        return results, aff_map

    completed = False
    async with _RATE_SEMAPHORE:
        try:
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
                    results, aff_map, cpe_map = _parse_response(
                        await resp.json(content_type=None), expected_cpe)
                    completed = True
                    # ── Filter by CPE match first, then description ──
                    if results:
                        prod_lower = (effective_product or "").lower()
                        svc_lower = (effective_service or "").lower()
                        product_words = [w.lower() for w in (effective_product or "").split() if len(w) > 2]
                        negative_words = _NEGATIVE_PRODUCT_WORDS.get(
                            prod_lower,
                            _NEGATIVE_PRODUCT_WORDS.get(svc_lower, [])
                        )
                        filtered = []
                        for cve in results:
                            # 1. CPE-based match (most reliable)
                            desc = (cve.description or "").lower()
                            cpe_matches = cpe_map.get(cve.cve_id, set())
                            if cpe_matches and expected_cpe:
                                ev, ep = expected_cpe
                                if (ev, ep) not in cpe_matches:
                                    # Hard gate: authoritative CPE data that
                                    # does not name this product beats any
                                    # amount of prose similarity.
                                    continue
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
                            opening_names = [prod_lower, *product_words, *aliases]
                            if not effective_product:
                                opening_names.append(svc_lower)
                            if not _mentions_in_opening(desc, opening_names):
                                # The product is only an incidental component
                                # of another vendor's product in this text.
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
        finally:
            await _rate_limit_pause()
    # Only successful lookups are cached. A failed lookup used to be cached for
    # 24 h, so one NVD outage blanked CVEs for the rest of the day.
    if completed:
        _cache.set(key, (results, aff_map))
    return results, aff_map


async def map_cves_for_scan(scan_result, api_key=None) -> tuple[dict[str, list[CVE]], dict[str, list[dict]]]:
    """Maps CVEs per host:port. Returns (cve_map, affected_map)."""
    import os
    if not api_key:
        # Fall back to env / settings so callers don't need to thread the key.
        # NVD allows 5 req/30s without key, 50 req/30s with key.
        api_key = os.environ.get("NVD_API_KEY", "").strip() or None
        if not api_key:
            try:
                from config.settings import scan as _scan_cfg
                api_key = (_scan_cfg.nvd_api_key or "").strip() or None
            except Exception:
                pass
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
            # A generic service label is not a reason to ignore a concrete
            # product/CPE fingerprint. Nmap calls the router's TLS multiplexer
            # "rtsp" while identifying mini_httpd; skipping the port preserved
            # old Belkin/Linksys mappings that the CPE gate would now reject.
            if svc in _GENERIC_SERVICES and not port.product and not port.cpe:
                logger.debug(f"[IRIS/CVE] Skipping {ip}:{port.port} — generic service '{svc}'")
                skipped_generic += 1
                continue
            if svc in _GENERIC_PROTOCOLS and not port.product and not port.cpe:
                logger.debug(f"[IRIS/CVE] Skipping {ip}:{port.port} — {svc} without product/CPE")
                skipped_generic += 1
                continue
            k = _cache_key(port.service, port.version, port.product or port.cpe)
            unique[k] = (port.service, port.version, port.product, port.cpe)
            port_to_key[(ip, port.port)] = k
    if skipped_generic:
        logger.info(f"[IRIS/CVE] Skipped {skipped_generic} ports (generic/no-product)")
    if not unique:
        logger.warning("[IRIS/CVE] No unique service+product combinations to query — all ports filtered out")
        return result_map, affected_map
    logger.info(f"[IRIS/CVE] Querying {len(unique)} unique service+product combo(s) for CVEs")
    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = {k: asyncio.create_task(lookup_cves(session, s, v, p, api_key, cp))
                 for k, (s, v, p, cp) in unique.items()}
        await asyncio.gather(*tasks.values(), return_exceptions=True)
        for k, t in tasks.items():
            if not t.exception():
                cves, aff = t.result()
                if aff: affected_map.update(aff)
                matched_ports = [(ip2, pn2) for (ip2, pn2), k2 in port_to_key.items() if k2 == k]
                s, v, p, _cp = unique[k]
                logger.info(f"[IRIS/CVE] {s} ({p or 'no product'}): {len(cves)} CVEs for {len(matched_ports)} port(s)")
                for (ip2, port_num2), k2 in port_to_key.items():
                    if k2 == k:
                        if cves: result_map[f"{ip2}:{port_num2}"] = cves
    return result_map, affected_map


_NVD_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _lookup_succeeded(port) -> bool:
    """True when this scan received an authoritative NVD answer for the port.

    `lookup_cves` caches every successful response, including an empty one,
    and never caches a failure. The cache is therefore the record of which
    fingerprints were actually checked. Pruning on a failed lookup would
    erase valid history during an NVD outage.
    """
    service = getattr(port, "service", None)
    if not service:
        return False
    key = _cache_key(
        service,
        getattr(port, "version", None),
        getattr(port, "product", None) or getattr(port, "cpe", None),
    )
    return _cache.get(key) is not None


async def persist_cves(cve_map: dict, scan_result, affected_map: dict | None = None) -> int:
    all_cves = {cve.cve_id: cve for cves in cve_map.values() for cve in cves}
    cve_id_map = {}
    if affected_map is None: affected_map = {}

    # Critical-CVE notifications are in-memory and best-effort. They used to be
    # composed inside the write transaction, so a slow channel held the write
    # lock for every critical CVE in the scan.
    for cve in all_cves.values():
        if cve.severity != Severity.CRITICAL:
            continue
        from alerts.notifier import buffer_alert
        try:
            await buffer_alert(
                category="critical_cves",
                title=cve.cve_id,
                # description is optional: _parse_response stores
                # `desc[:1000] or None`, so slicing it blindly raised
                # TypeError and lost every CVE in the scan.
                message=f"CVSS **{cve.cvss_v3}** — {(cve.description or '')[:200]}",
                color="critical",
                fields=[{"name": "CVE", "value": f"`{cve.cve_id}`", "inline": True},
                        {"name": "CVSS", "value": f"**{cve.cvss_v3}**", "inline": True},
                        {"name": "NVD", "value": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}", "inline": False}],
            )
        except Exception as exc:
            logger.warning(f"[IRIS/CVE] Alert buffer failed for {cve.cve_id}: {exc}")

    # Resolve host/port ids *before* opening the transaction. The old code ran
    # one SELECT per host and per port inside it, which serialised every scan
    # behind the write lock and read the pre-transaction snapshot.
    ips = [ip for ip, ports in scan_result.ports.items() if ports]
    host_ids: dict[str, int] = {}
    if ips:
        for row in await db.fetch_all(
            "SELECT id, ip FROM hosts "
            "WHERE ip IN (SELECT value FROM json_each(?))",
            (json.dumps(ips),),
        ):
            host_ids[row["ip"]] = row["id"]

    port_ids: dict[tuple[str, int], int] = {}
    for ip in ips:
        host_id = host_ids.get(ip)
        if host_id is None: continue
        numbers = sorted({p.port for p in scan_result.ports[ip]})
        for row in await db.fetch_all(
            "SELECT id, port FROM ports "
            "WHERE host_id=? AND port IN (SELECT value FROM json_each(?)) "
            "ORDER BY id",
            (host_id, json.dumps(numbers)),
        ):
            # A host can hold tcp/53 and udp/53; keep the first deterministically.
            port_ids.setdefault((ip, row["port"]), row["id"])

    async with db.transaction() as conn:
        for cve in all_cves.values():
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

        rows_to_write = []
        for ip, ports in scan_result.ports.items():
            if host_ids.get(ip) is None:
                continue
            for port in ports:
                port_product = port.product or port.cpe
                # Belt-and-suspenders: never write CVEs for generic protocols
                # without a product. `port.service` may be None on ports built
                # by other scanners; `_normalize_service(None)` used to raise
                # and abort the whole batch.
                if _normalize_service(port.service or "") in _GENERIC_PROTOCOLS and not port_product:
                    continue
                port_db_id = port_ids.get((ip, port.port))
                if port_db_id is None: continue
                detected_ver = port.version
                for cve in cve_map.get(f"{ip}:{port.port}", []):
                    cve_db_id = cve_id_map.get(cve.cve_id)
                    if not cve_db_id:
                        continue
                    status = _version_in_range(
                        detected_ver, affected_map.get(cve.cve_id) or [])
                    rows_to_write.append(
                        (port_db_id, cve_db_id, status, detected_ver))

        if rows_to_write:
            # One upsert replaces the old INSERT OR IGNORE + unconditional
            # UPDATE pair (two writes per CVE). A version fingerprinted by an
            # earlier scan is kept when this scan did not detect one.
            await conn.executemany(
                """INSERT INTO port_cves (port_id, cve_id, verified_status, detected_version)
                   VALUES (?,?,?,?)
                   ON CONFLICT(port_id, cve_id) DO UPDATE SET
                     verified_status  = excluded.verified_status,
                     detected_version = COALESCE(port_cves.detected_version,
                                                 excluded.detected_version)""",
                rows_to_write,
            )

        # ── Retire stale mappings for authoritative lookups ──────────────
        # A successful NVD response is the complete answer for that exact
        # fingerprint. Rows left over from an older matcher (Shellshock on
        # OpenSSH, Linksys firmware on mini_httpd) otherwise survive forever
        # because the old write path only ever upserted.
        allowed_by_port: dict[int, set[int]] = {}
        for ip, ports in scan_result.ports.items():
            if host_ids.get(ip) is None:
                continue
            for port in ports:
                if not _lookup_succeeded(port):
                    continue
                port_db_id = port_ids.get((ip, port.port))
                if port_db_id is None:
                    continue
                allowed = allowed_by_port.setdefault(port_db_id, set())
                allowed.update(
                    cve_id_map[cve.cve_id]
                    for cve in cve_map.get(f"{ip}:{port.port}", [])
                    if cve.cve_id in cve_id_map
                )

        if allowed_by_port:
            port_id_json = json.dumps(sorted(allowed_by_port))
            async with conn.execute(
                "SELECT pc.port_id, pc.cve_id, c.cve_id AS external_id "
                "FROM port_cves pc JOIN cves c ON c.id = pc.cve_id "
                "WHERE pc.port_id IN (SELECT value FROM json_each(?)) "
                "AND COALESCE(pc.dismissed, 0) = 0",
                (port_id_json,),
            ) as cur:
                existing = await cur.fetchall()
            stale = [
                (row["port_id"], row["cve_id"])
                for row in existing
                # Nuclei findings are keyed by rule id, not NVD data. Only
                # NVD CVE rows are within this lookup's authority.
                if _NVD_CVE_RE.match(str(row["external_id"] or ""))
                and row["cve_id"] not in allowed_by_port.get(row["port_id"], set())
            ]
            if stale:
                await conn.executemany(
                    "DELETE FROM port_cves WHERE port_id=? AND cve_id=?",
                    stale,
                )
                logger.info(
                    f"[IRIS/CVE] Pruned {len(stale)} stale CVE mapping(s) "
                    "for authoritatively re-checked ports"
                )
    return len(all_cves)


async def verify_all_cves() -> int:
    """Re-verify port_cves entries that are not confirmed yet.

    `verified_status != 'CONFIRMED'` is NULL-unsafe in SQL, so rows written by
    older schema versions (or by a NULL column) were never re-checked.
    """
    rows = await db.fetch_all("""
        SELECT pc.port_id, pc.cve_id, pc.verified_status, pc.detected_version,
               p.version as port_version, c.description
        FROM port_cves pc
        JOIN ports p ON p.id = pc.port_id
        JOIN cves c ON c.id = pc.cve_id
        WHERE pc.verified_status IS NULL OR pc.verified_status != 'CONFIRMED'
    """)
    updated = 0
    if not rows: return 0
    async with db.transaction() as conn:
        for row in rows:
            version = row["detected_version"] or row["port_version"]
            desc = row["description"] or ""
            affected = _extract_affected_versions(desc)
            if not affected:
                # The stored verdict may have come from CPE constraints that
                # the description does not repeat. Re-deriving from a weaker
                # source would silently downgrade a real finding.
                continue
            status = _version_in_range(version, affected)
            if status != row["verified_status"]:
                await conn.execute(
                    "UPDATE port_cves SET verified_status=?, detected_version=COALESCE(detected_version, ?) WHERE port_id=? AND cve_id=?",
                    (status, version, row["port_id"], row["cve_id"])
                )
                updated += 1
    return updated
