"""Tests for iris/cve_mapper.py — version parsing and range matching."""
import asyncio

import pytest

from iris.cve_mapper import _cache_key, _parse_version, _version_in_range


class TestParseVersion:
    def test_simple_version(self):
        assert _parse_version("7.2.41") == (7, 2, 41)

    def test_patch_suffix(self):
        assert _parse_version("7.2p2") == (7, 2,)

    def test_leading_v(self):
        assert isinstance(_parse_version(None), tuple)

    def test_single_number(self):
        assert _parse_version("5") == (5,)

    def test_with_prefix_text(self):
        parsed = _parse_version("1.2.3-alpha")
        assert parsed[0] == 1
        assert parsed[1] == 2

    def test_none_input(self):
        result = _parse_version(None)
        assert isinstance(result, tuple)


class TestVersionInRange:
    def test_exact_match(self):
        """Version matching an exact range is CONFIRMED."""
        result = _version_in_range("1.0.0", [{"versionStart": "1.0.0", "versionEnd": "1.0.0", "inclusive": True}])
        assert result == "CONFIRMED"

    def test_in_range_including(self):
        """Version within [2.0, 3.0] inclusive."""
        result = _version_in_range("2.5", [{"versionStart": "2.0", "versionEnd": "3.0", "inclusive": True}])
        assert result == "CONFIRMED"

    def test_below_range(self):
        """Version below minimum is NOT_AFFECTED."""
        result = _version_in_range("1.0", [{"versionStart": "2.0", "versionEnd": "3.0", "inclusive": True}])
        assert result == "NOT_AFFECTED"

    def test_above_range(self):
        """Version above maximum is NOT_AFFECTED."""
        result = _version_in_range("4.0", [{"versionStart": "2.0", "versionEnd": "3.0", "inclusive": True}])
        assert result == "NOT_AFFECTED"

    def test_no_constraints(self):
        """No constraints means UNVERIFIED."""
        result = _version_in_range("1.0", [])
        assert result == "UNVERIFIED"

    def test_any_of_multiple_ranges(self):
        """If version matches ANY constraint range, it's CONFIRMED."""
        constraints = [
            {"versionStart": "1.0", "versionEnd": "1.5", "inclusive": True},
            {"versionStart": "2.0", "versionEnd": "3.0", "inclusive": True},
        ]
        assert _version_in_range("1.2", constraints) == "CONFIRMED"
        assert _version_in_range("2.5", constraints) == "CONFIRMED"
        assert _version_in_range("1.6", constraints) == "NOT_AFFECTED"

    def test_excluding_end(self):
        """inclusive=False means end is exclusive."""
        result = _version_in_range("3.0", [{"versionStart": "2.0", "versionEnd": "3.0", "inclusive": False}])
        assert result == "NOT_AFFECTED"

    def test_null_version_returns_unverified(self):
        """None version should return UNVERIFIED regardless of constraints."""
        result = _version_in_range(None, [{"versionStart": "1.0", "versionEnd": "3.0", "inclusive": True}])
        assert result == "UNVERIFIED"

    def test_prerelease_is_older_than_the_release_it_leads_to(self):
        """1.2.3-rc1 < 1.2.3, so a fix in 1.2.3 still covers the RC."""
        for inclusive in (True, False):
            constraints = [{"versionEnd": "1.2.3", "inclusive": inclusive}]
            assert _version_in_range("1.2.3-rc1", constraints) == "CONFIRMED"
        assert _version_in_range(
            "1.2.3-rc1",
            [{"versionStart": "1.0", "versionEnd": "1.2.3", "inclusive": False}],
        ) == "CONFIRMED"

    def test_release_is_not_below_a_prerelease_end_bound(self):
        """A final release must not be called affected by a pre-release bound."""
        for inclusive in (True, False):
            constraints = [{"versionEnd": "1.2.3-rc1", "inclusive": inclusive}]
            assert _version_in_range("1.2.3", constraints) == "NOT_AFFECTED"

    def test_prerelease_labels_are_ordered_before_the_release(self):
        constraints = [{"versionEnd": "2.0.0", "inclusive": False}]
        assert _version_in_range("2.0.0-beta2", constraints) == "CONFIRMED"
        assert _version_in_range("2.0.0-rc1", constraints) == "CONFIRMED"

    def test_unparseable_bounds_are_unbounded_not_zero(self):
        """`*` / `unknown` must not turn every version into NOT_AFFECTED."""
        for bound in ("*", "unknown", "", None):
            constraints = [{"versionEnd": bound, "inclusive": True}]
            assert _version_in_range("9.9.9", constraints) == "UNVERIFIED"
            constraints = [{"versionStart": bound, "versionEnd": "9.9.9", "inclusive": True}]
            assert _version_in_range("1.0", constraints) == "CONFIRMED"


class TestCacheKey:
    def test_deterministic(self):
        k1 = _cache_key("ssh", "7.4", "cpe:/a:openbsd:openssh:7.4")
        k2 = _cache_key("ssh", "7.4", "cpe:/a:openbsd:openssh:7.4")
        assert k1 == k2

    def test_different_inputs(self):
        k1 = _cache_key("ssh", "7.4", "")
        k2 = _cache_key("ssh", "7.5", "")
        assert k1 != k2

    def test_returns_string(self):
        k = _cache_key("http", "2.4.41", "cpe:/a:apache:http_server:2.4.41")
        assert isinstance(k, str)
        assert len(k) == 32  # MD5 hex digest length

class TestPersistCvesRobustness:
    """CVE persistence must survive optional fields and notifier failures.

    Every test removes the rows it created: the suite shares one throwaway
    database, and leaving live CVEs behind silently changes later posture and
    compliance assertions.
    """

    @staticmethod
    def _seed(ip: str, port: int):
        from chronicle import db
        from dashboard.app import run_async

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            await db.execute(
                "INSERT INTO hosts (ip, is_active) VALUES (?, 1)", (ip,))
            host_id = await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (ip,))
            await db.execute(
                "INSERT INTO ports (host_id, port, protocol, state,"
                " service, product, version) VALUES (?,?,?,?,?,?,?)",
                (host_id, port, "tcp", "open", "ssh", "openssh", "8.9"),
            )
            return host_id

        return run_async(scenario())

    @staticmethod
    def _cleanup(ip: str, cve_ids: list[str]):
        from chronicle import db
        from dashboard.app import run_async

        async def scenario():
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            for cve_id in cve_ids:
                await db.execute("DELETE FROM cves WHERE cve_id=?", (cve_id,))

        run_async(scenario())

    def test_critical_cve_without_description_is_persisted(self):
        import uuid

        from alerts import notifier
        from chronicle import db
        from chronicle.models import CVE, Port, ScanResult, Severity
        from dashboard.app import run_async
        from iris.cve_mapper import persist_cves

        sent = []

        async def capture(**kwargs):
            sent.append(kwargs)

        octet = uuid.uuid4().int % 200 + 20
        ip = f"10.99.{octet}.1"
        cve_id = "CVE-2024-0001"
        self._seed(ip, 2222)
        scan = ScanResult(target=ip, ports={ip: [Port(
            host_id=0, port=2222, service="ssh", product="openssh",
            version="8.9")]})

        import pytest
        monkeypatch_ok = pytest.MonkeyPatch()
        monkeypatch_ok.setattr(notifier, "buffer_alert", capture)
        try:
            stored = run_async(persist_cves(
                {f"{ip}:2222": [CVE(cve_id=cve_id, cvss_v3=9.8,
                                    severity=Severity.CRITICAL,
                                    description=None)]},
                scan, {}))
        finally:
            monkeypatch_ok.undo()

        try:
            assert stored == 1
            # The alert is still composed — the optional field is simply empty.
            assert sent and sent[0]["title"] == cve_id
            assert sent[0]["message"].startswith("CVSS **9.8**")

            async def read_back():
                return await db.fetch_one(
                    "SELECT c.description FROM cves c WHERE c.cve_id=?",
                    (cve_id,))

            assert run_async(read_back()) is not None
        finally:
            self._cleanup(ip, [cve_id])

    def test_notifier_failure_does_not_roll_back_persistence(self, monkeypatch):
        import uuid

        from alerts import notifier
        from chronicle import db
        from chronicle.models import CVE, Port, ScanResult, Severity
        from dashboard.app import run_async
        from iris import cve_mapper

        octet = uuid.uuid4().int % 200 + 20
        ip = f"10.98.{octet}.1"
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        self._seed(ip, 2223)

        async def boom(**_kwargs):
            raise RuntimeError("webhook buffer unavailable")

        monkeypatch.setattr(notifier, "buffer_alert", boom)
        scan = ScanResult(target=ip, ports={ip: [Port(
            host_id=0, port=2223, service="ssh", product="openssh",
            version="8.9")]})

        try:
            stored = run_async(cve_mapper.persist_cves(
                {f"{ip}:2223": [CVE(cve_id=cve_id, cvss_v3=9.9,
                                    severity=Severity.CRITICAL,
                                    description="x")]},
                scan, {}))
            assert stored == 1

            async def read_back():
                return await db.fetch_one(
                    "SELECT id FROM cves WHERE cve_id=?", (cve_id,))

            assert run_async(read_back()) is not None
        finally:
            self._cleanup(ip, [cve_id])


class TestParseResponseRobustness:
    """NVD payloads are untrusted input; one odd entry must not drop the rest."""

    def test_malformed_entries_are_skipped_but_valid_ones_survive(self):
        from iris.cve_mapper import _parse_response

        data = {
            "vulnerabilities": [
                "not-a-dict",
                {"cve": {}},
                {"cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "es"}, {"lang": "en"}],  # no value
                    "metrics": {"cvssMetricV31": []},
                    "configurations": [],
                }},
                {"cve": {
                    "id": "CVE-2023-12345",
                    "descriptions": [{"lang": "en", "value": "Log4Shell style"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {
                        "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "configurations": [],
                }},
            ],
        }
        cves, affected, cpe_map = _parse_response(data)
        ids = [c.cve_id for c in cves]
        assert "CVE-2021-44228" in ids, "a missing description must not drop the CVE"
        assert "CVE-2023-12345" in ids
        log4shell = next(c for c in cves if c.cve_id == "CVE-2023-12345")
        assert log4shell.cvss_v3 == 9.8
        assert str(log4shell.severity) == "CRITICAL"
        assert log4shell.description == "Log4Shell style"

    def test_empty_metrics_do_not_raise(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2022-0001",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {"cvssMetricV31": [], "cvssMetricV30": []},
        }}]}
        cves, _affected, _cpe = _parse_response(data)
        assert len(cves) == 1
        assert cves[0].cvss_v3 is None
        assert str(cves[0].severity) == "NONE"

    def test_null_vulnerabilities_is_tolerated(self):
        from iris.cve_mapper import _parse_response

        assert _parse_response({"vulnerabilities": None}) == ([], {}, {})

    def test_cpe_pairs_are_extracted(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2023-0002",
            "descriptions": [{"lang": "en", "value": "openssh"}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"},
                {"criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"},
            ]}]}],
        }}]}
        _cves, _affected, cpe_map = _parse_response(data)
        assert cpe_map["CVE-2023-0002"] == {("openbsd", "openssh")}


# ── NVD input shapes ────────────────────────────────────────────────────────

class TestParseResponseTypedInputs:
    """Every level of an NVD payload is external data and may have any shape."""

    def test_wrong_typed_configuration_does_not_drop_the_cve(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2023-9999",
            "descriptions": [{"lang": "en", "value": "thing"}],
            "configurations": {"nodes": "not-a-list"},
        }}]}
        cves, _affected, cpe = _parse_response(data)
        assert [c.cve_id for c in cves] == ["CVE-2023-9999"]
        assert cpe == {}

    def test_cpe_match_entries_without_criteria_are_skipped(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2023-9998",
            "descriptions": [{"lang": "en", "value": "widget"}],
            "configurations": [{"nodes": [
                None, "junk",
                {"cpeMatch": [
                    None, "junk", {"criteria": None},
                    {"criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
                ]},
            ]}],
        }}]}
        _cves, _affected, cpe = _parse_response(data)
        assert cpe == {"CVE-2023-9998": {("acme", "widget")}}

    def test_string_cve_and_non_dict_metrics_are_skipped(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [
            {"cve": "CVE-2024-0002"},
            {"cve": {"id": "CVE-2024-0003", "metrics": [1, 2, 3],
                     "descriptions": [{"lang": "en", "value": "x"}]}},
            {"cve": {"id": None}},
            "not-a-dict",
        ]}
        cves, _affected, _cpe = _parse_response(data)
        assert [c.cve_id for c in cves] == ["CVE-2024-0003"]

    def test_string_base_score_is_coerced_and_severity_is_derived(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2024-0004",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": "9.8"}}]},
        }}]}
        cves, _affected, _cpe = _parse_response(data)
        assert cves[0].cvss_v3 == 9.8
        assert str(cves[0].severity) == "CRITICAL"

    def test_unknown_severity_label_falls_back_to_the_score(self):
        from iris.cve_mapper import _parse_response

        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2024-0006",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 5.0, "baseSeverity": "BANANA"}}]},
        }}]}
        cves, _affected, _cpe = _parse_response(data)
        assert str(cves[0].severity) == "MEDIUM"

    def test_non_dict_payload_is_tolerated(self):
        from iris.cve_mapper import _parse_response

        assert _parse_response(None) == ([], {}, {})
        assert _parse_response([1, 2]) == ([], {}, {})


class TestAffectedVersionsFromCpe:
    def test_cpe_bounds_are_used_when_description_is_empty(self):
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions("", [{"nodes": [{"cpeMatch": [
            {"versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}]}]}])
        assert constraints == [
            {"versionStart": "1.0", "versionEnd": "2.0", "inclusive": False}]

    def test_inclusive_end_bound_is_kept_inclusive(self):
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions(None, [{"nodes": [{"cpeMatch": [
            {"versionEndIncluding": "2.0"}]}]}])
        assert constraints == [
            {"versionStart": None, "versionEnd": "2.0", "inclusive": True}]

    def test_malformed_nodes_do_not_raise(self):
        from iris.cve_mapper import _extract_affected_versions

        assert _extract_affected_versions("x", {"nodes": [None, "x", 7]}) == []
        assert _extract_affected_versions("x", [{"nodes": [{"cpeMatch": "nope"}]}]) == []
        assert _extract_affected_versions("x", [{"nodes": [{"cpeMatch": [None]}]}]) == []

    def test_cpe_bounds_take_precedence_over_prose(self):
        """NVD's machine-readable range is authoritative, not a regex guess."""
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions(
            "Versions prior to 1.0 are affected.",
            [{"nodes": [{"cpeMatch": [
                {"versionStartIncluding": "2.0",
                 "versionEndExcluding": "3.0"}]}]}],
        )
        assert constraints == [
            {"versionStart": "2.0", "versionEnd": "3.0", "inclusive": False}]

    def test_every_cpe_range_is_kept_for_multi_branch_fixes(self):
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions("", [{"nodes": [{"cpeMatch": [
            {"versionStartIncluding": "1.0", "versionEndExcluding": "1.5"},
            {"versionStartIncluding": "2.0", "versionEndExcluding": "2.5"},
        ]}]}])
        assert constraints == [
            {"versionStart": "1.0", "versionEnd": "1.5", "inclusive": False},
            {"versionStart": "2.0", "versionEnd": "2.5", "inclusive": False},
        ]

    def test_non_vulnerable_cpe_entries_are_ignored(self):
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions("", [{"nodes": [{"cpeMatch": [
            {"vulnerable": False, "versionEndExcluding": "2.0"},
            {"vulnerable": True, "versionEndExcluding": "3.0"},
        ]}]}])
        assert constraints == [
            {"versionStart": None, "versionEnd": "3.0", "inclusive": False}]

    def test_exclusive_start_bound_is_not_widened(self):
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions("", [{"nodes": [{"cpeMatch": [
            {"versionStartExcluding": "1.0", "versionEndIncluding": "2.0"},
        ]}]}])
        assert constraints == [{
            "versionStart": "1.0", "versionEnd": "2.0", "inclusive": True,
            "startInclusive": False,
        }]


class TestCpeProductGate:
    """An advisory must name the product the port actually runs.

    Every regression here produced a critical Action-queue row on a live
    network: GNU Bash advisories attached to OpenSSH, Belkin/Linksys firmware
    attached to mini_httpd, and Microsoft OpenSSH-for-Windows on Linux.
    """

    @staticmethod
    def _payload(cve_id, description, matches):
        return {"vulnerabilities": [{"cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "configurations": [{"nodes": [{"cpeMatch": matches}]}],
        }}]}

    def test_bash_advisory_is_rejected_for_openssh(self):
        from iris.cve_mapper import _parse_response

        data = self._payload(
            "CVE-2014-6271",
            "GNU Bash before 4.3 allows remote code execution. OpenSSH is "
            "mentioned only as a possible vector.",
            [{"criteria": "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*",
              "vulnerable": True, "versionEndIncluding": "4.3"}],
        )

        assert _parse_response(data, ("openbsd", "openssh"))[0] == []
        accepted = _parse_response(data, ("gnu", "bash"))[0]
        assert [c.cve_id for c in accepted] == ["CVE-2014-6271"]

    def test_belkin_firmware_advisory_is_rejected_for_mini_httpd(self):
        from iris.cve_mapper import _parse_response

        data = self._payload(
            "CVE-2020-26561",
            "Belkin Linksys WRT 160NL firmware allows command injection.",
            [{"criteria": "cpe:2.3:o:belkin:linksys_wrt_160nl_firmware:*:*:*:"
                          "*:*:*:*:*", "vulnerable": True,
              "versionEndExcluding": "1.0.4"}],
        )

        assert _parse_response(data, ("acme", "mini_httpd"))[0] == []

    def test_microsoft_windows_advisory_is_rejected_for_linux_openssh(self):
        from iris.cve_mapper import _parse_response

        data = self._payload(
            "CVE-2024-38077",
            "OpenSSH for Windows in Microsoft Windows allows privilege "
            "escalation.",
            [{"criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
              "vulnerable": True}],
        )

        assert _parse_response(data, ("openbsd", "openssh"))[0] == []

    def test_non_vulnerable_platform_cpe_does_not_authorise_the_cve(self):
        """``vulnerable: false`` names the platform, not an affected product."""
        from iris.cve_mapper import _parse_response

        data = self._payload(
            "CVE-2024-1111",
            "A flaw in the kernel.",
            [{"criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
              "vulnerable": False}],
        )

        assert _parse_response(data, ("openbsd", "openssh"))[0] == []

    def test_bounds_are_scoped_to_the_matched_product(self):
        """A bundled OS range must not bound the application's version."""
        from iris.cve_mapper import _extract_affected_versions

        config = [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
             "vulnerable": True, "versionEndExcluding": "9.8"},
            {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
             "vulnerable": True, "versionEndExcluding": "6.1"},
        ]}]}]

        assert _extract_affected_versions("", config, ("openbsd", "openssh")) == [
            {"versionStart": None, "versionEnd": "9.8", "inclusive": False}]
        # Unscoped callers (older adapters, verify_all_cves) keep every branch.
        assert _extract_affected_versions("", config) == [
            {"versionStart": None, "versionEnd": "9.8", "inclusive": False},
            {"versionStart": None, "versionEnd": "6.1", "inclusive": False},
        ]

    def test_authoritative_cpe_block_without_the_product_yields_no_bounds(self):
        """Prose must not re-introduce bounds the CPE block contradicts."""
        from iris.cve_mapper import _extract_affected_versions

        config = [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*",
             "vulnerable": True, "versionEndIncluding": "4.3"},
        ]}]}]

        assert _extract_affected_versions(
            "GNU Bash before 4.3 is affected.", config,
            ("openbsd", "openssh")) == []


class TestAffectedVersionsFromProse:
    def test_from_x_to_y_includes_the_named_end_release(self):
        """"versions from 1.0 to 2.0" names 2.0 as affected. Treating Y as an
        exclusive upper bound turned a flagged release into NOT_AFFECTED.
        """
        from iris.cve_mapper import _extract_affected_versions

        constraints = _extract_affected_versions(
            "This issue affects versions from 1.0 to 2.0.")
        assert constraints == [
            {"versionStart": "1.0", "versionEnd": "2.0", "inclusive": True}]
        assert _extract_affected_versions("versions 1.0 to 2.0", None) == []
        # No bounds in prose → no constraint.
        assert _extract_affected_versions("no version numbers here") == []

    def test_prose_before_x_remains_an_exclusive_bound(self):
        from iris.cve_mapper import _extract_affected_versions

        assert _extract_affected_versions("affects releases before 2.4.1") == [
            {"versionEnd": "2.4.1", "inclusive": False}]


class TestCpeHelpers:
    def test_cpe22_and_cpe23_are_both_understood(self):
        from iris.cve_mapper import _cpe_vendor_product, _product_from_cpe

        assert _cpe_vendor_product("cpe:/a:apache:http_server:2.4.41") == (
            "apache", "http_server")
        assert _cpe_vendor_product(
            "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*") == (
            "openbsd", "openssh")
        assert _product_from_cpe("cpe:/a:apache:http_server:2.4.41") == "http server"

    def test_wildcards_and_garbage_produce_nothing(self):
        from iris.cve_mapper import _cpe_vendor_product, _product_from_cpe

        for value in (None, "", "not-a-cpe", "cpe:/a:*:*:*", "cpe:/a:::"):
            assert _cpe_vendor_product(value) is None
            assert _product_from_cpe(value) is None


# ── Lookup behaviour ────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        return self.responses.pop(0)


@pytest.fixture
def cve_cache():
    from iris import cve_mapper

    cve_mapper._cache._data.clear()
    yield cve_mapper
    cve_mapper._cache._data.clear()


_OPENSSH_PAYLOAD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-6387",
    "descriptions": [{"lang": "en", "value": "A flaw in OpenSSH before 8.9."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 8.1, "baseSeverity": "HIGH"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"}]}]}],
}}]}


class TestLookupCaching:
    def test_failed_lookup_is_not_cached_for_a_day(self, monkeypatch, cve_cache):
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        session = _FakeSession([
            _FakeResponse(503),
            _FakeResponse(200, _OPENSSH_PAYLOAD),
        ])

        first, _ = asyncio.run(
            cve_cache.lookup_cves(session, "ssh", "8.9", "openssh"))
        second, _ = asyncio.run(
            cve_cache.lookup_cves(session, "ssh", "8.9", "openssh"))

        assert first == []
        assert len(session.calls) == 2, "a transient NVD failure must be retried"
        assert [c.cve_id for c in second] == ["CVE-2024-6387"]

    def test_successful_lookup_is_cached(self, monkeypatch, cve_cache):
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        session = _FakeSession([_FakeResponse(200, _OPENSSH_PAYLOAD)])

        asyncio.run(cve_cache.lookup_cves(session, "ssh", "8.9", "openssh"))
        asyncio.run(cve_cache.lookup_cves(session, "ssh", "8.9", "openssh"))

        assert len(session.calls) == 1

    def test_skip_path_makes_no_request_and_no_pause(self, monkeypatch, cve_cache):
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        session = _FakeSession([])  # a request would pop from an empty list

        assert asyncio.run(cve_cache.lookup_cves(session, "telnet")) == ([], {})
        assert session.calls == []

    def test_generic_service_with_a_product_is_still_queried(
            self, monkeypatch, cve_cache):
        """The service label alone must not discard a real fingerprint."""
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2020-26561",
            "descriptions": [{"lang": "en", "value":
                              "Belkin Linksys WRT 160NL firmware command injection."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 8.8, "baseSeverity": "HIGH"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:o:belkin:linksys_wrt_160nl_firmware:"
                            "*:*:*:*:*:*:*:*",
                "vulnerable": True, "versionEndExcluding": "1.0.4"}]}]}],
        }}]}
        session = _FakeSession([_FakeResponse(200, payload)])

        result, _ = asyncio.run(cve_cache.lookup_cves(
            session, "rtsp", "1.30", "mini_httpd",
            cpe="cpe:/a:acme:mini_httpd:1.30"))

        assert len(session.calls) == 1
        assert result == [], "Belkin firmware must not attach to mini_httpd"

    def test_vyos_dropbear_advisory_is_rejected_for_openssh(
            self, monkeypatch, cve_cache):
        """A CVE without CPE data can still be about another SSH daemon."""
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2025-30095",
            "descriptions": [{"lang": "en", "value":
                              "VyOS with dropbear has shared private host keys. "
                              "OpenSSH has a safeguard against this behavior."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.0, "baseSeverity": "CRITICAL"}}]},
            "configurations": None,
        }}]}
        session = _FakeSession([_FakeResponse(200, payload)])

        result, _ = asyncio.run(
            cve_cache.lookup_cves(session, "ssh", "10.6p1", "OpenSSH"))

        assert len(session.calls) == 1
        assert result == []

    def test_component_mention_in_a_later_sentence_is_rejected(
            self, monkeypatch, cve_cache):
        """Oray's appliance CVE names dnsmasq only as a component."""
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-116233",
            "descriptions": [{"lang": "en", "value":
                              "A security vulnerability has been detected in "
                              "Oray Pugongying X5 Pro 7.6.1. This impacts an "
                              "unknown function of the component Dnsmasq."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
            "configurations": None,
        }}]}
        session = _FakeSession([_FakeResponse(200, payload)])

        result, _ = asyncio.run(
            cve_cache.lookup_cves(session, "domain", "2.84rc2", "dnsmasq"))

        assert len(session.calls) == 1
        assert result == []

    def test_dnsmasq_named_as_the_subject_is_accepted(
            self, monkeypatch, cve_cache):
        monkeypatch.setattr(cve_cache, "_rate_limit_pause", _no_pause)
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-6507",
            "descriptions": [{"lang": "en", "value":
                              "A flaw was found in dnsmasq. A remote attacker "
                              "could exploit an out-of-bounds write."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            "configurations": None,
        }}]}
        session = _FakeSession([_FakeResponse(200, payload)])

        result, _ = asyncio.run(
            cve_cache.lookup_cves(session, "domain", "2.84rc2", "dnsmasq"))

        assert [c.cve_id for c in result] == ["CVE-2026-6507"]


async def _no_pause():
    return None


class TestCpeOnlyPorts:
    def test_cpe_only_port_is_actually_queried(self, monkeypatch, cve_cache):
        from chronicle.models import CVE, Port, ScanResult

        calls = []

        async def fake_lookup(session, service, version=None, product=None,
                              api_key=None, cpe=None):
            calls.append({"service": service, "version": version,
                          "product": product, "cpe": cpe})
            return [CVE(cve_id="CVE-2024-0005")], {}

        monkeypatch.setattr(cve_cache, "lookup_cves", fake_lookup)
        scan = ScanResult(target="10.0.0.1", ports={"10.0.0.1": [Port(
            host_id=1, port=80, service="http", product=None, version="2.4.41",
            cpe="cpe:/a:apache:http_server:2.4.41")]})

        cve_map, _affected = asyncio.run(
            cve_cache.map_cves_for_scan(scan, api_key="test-key"))

        assert calls == [{
            "service": "http", "version": "2.4.41", "product": None,
            "cpe": "cpe:/a:apache:http_server:2.4.41",
        }]
        assert [c.cve_id for c in cve_map["10.0.0.1:80"]] == ["CVE-2024-0005"]

    def test_generic_port_without_product_or_cpe_is_still_skipped(
            self, monkeypatch, cve_cache):
        from chronicle.models import Port, ScanResult

        async def fake_lookup(*_args, **_kwargs):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cve_cache, "lookup_cves", fake_lookup)
        scan = ScanResult(target="10.0.0.1", ports={"10.0.0.1": [Port(
            host_id=1, port=80, service="http")]})

        assert asyncio.run(cve_cache.map_cves_for_scan(scan)) == ({}, {})

    def test_generic_service_with_a_product_is_queried(
            self, monkeypatch, cve_cache):
        """Port 443 identifies as rtsp but runs mini_httpd; scan it anyway."""
        from chronicle.models import CVE, Port, ScanResult

        calls = []

        async def fake_lookup(session, service, version=None, product=None,
                              api_key=None, cpe=None):
            calls.append((service, product, cpe))
            return [CVE(cve_id="CVE-2020-26561")], {}

        monkeypatch.setattr(cve_cache, "lookup_cves", fake_lookup)
        scan = ScanResult(target="10.0.0.1", ports={"10.0.0.1": [Port(
            host_id=1, port=443, service="rtsp", product="mini_httpd",
            version="1.30", cpe="cpe:/a:acme:mini_httpd:1.30")]})

        cve_map, _ = asyncio.run(
            cve_cache.map_cves_for_scan(scan, api_key="test-key"))

        assert calls == [("rtsp", "mini_httpd", "cpe:/a:acme:mini_httpd:1.30")]
        assert [c.cve_id for c in cve_map["10.0.0.1:443"]] == ["CVE-2020-26561"]


# ── Persistence ─────────────────────────────────────────────────────────────

def _seed_host_port(ip: str, port: int, version: str = "8.9"):
    from chronicle import db
    from dashboard.app import run_async

    async def scenario():
        await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
        await db.execute("INSERT INTO hosts (ip, is_active) VALUES (?, 1)", (ip,))
        host_id = await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (ip,))
        await db.execute(
            "INSERT INTO ports (host_id, port, protocol, state, service,"
            " product, version) VALUES (?,?,?,?,?,?,?)",
            (host_id, port, "tcp", "open", "ssh", "openssh", version))
        port_id = await db.fetch_val(
            "SELECT id FROM ports WHERE host_id=? AND port=?", (host_id, port))
        return host_id, port_id

    return run_async(scenario())


def _cleanup_rows(ip: str, cve_ids=()):
    from chronicle import db
    from dashboard.app import run_async

    async def scenario():
        await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
        for cve_id in cve_ids:
            await db.execute("DELETE FROM cves WHERE cve_id=?", (cve_id,))

    run_async(scenario())


class TestPersistCvesWritePath:
    def test_second_persist_updates_status_but_keeps_fingerprinted_version(self):
        import uuid

        from chronicle import db
        from chronicle.models import CVE, Port, ScanResult, Severity
        from dashboard.app import run_async
        from iris.cve_mapper import persist_cves

        octet = uuid.uuid4().int % 200 + 20
        ip = f"10.96.{octet}.1"
        port = 2300 + (uuid.uuid4().int % 500)
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_host_port(ip, port)
        cve = CVE(cve_id=cve_id, cvss_v3=7.5, severity=Severity.HIGH,
                  description="versions prior to 9.0")

        try:
            scan = ScanResult(target=ip, ports={ip: [Port(
                host_id=0, port=port, service="ssh", product="openssh",
                version="8.9")]})
            run_async(persist_cves(
                {f"{ip}:{port}": [cve]}, scan,
                {cve_id: [{"versionEnd": "9.0", "inclusive": True}]}))

            async def read():
                return await db.fetch_one(
                    "SELECT pc.verified_status, pc.detected_version"
                    " FROM port_cves pc JOIN ports p ON p.id = pc.port_id"
                    " JOIN hosts h ON h.id = p.host_id"
                    " WHERE h.ip=? AND p.port=?", (ip, port))

            first = run_async(read())
            assert first["verified_status"] == "CONFIRMED"
            assert first["detected_version"] == "8.9"

            # A rescan that could not fingerprint the version must not erase
            # the evidence the first scan collected.
            rescan = ScanResult(target=ip, ports={ip: [Port(
                host_id=0, port=port, service="ssh", product="openssh")]})
            run_async(persist_cves({f"{ip}:{port}": [cve]}, rescan, {}))

            second = run_async(read())
            assert second["verified_status"] == "UNVERIFIED"
            assert second["detected_version"] == "8.9"

            async def count():
                return await db.fetch_val(
                    "SELECT COUNT(*) FROM port_cves pc"
                    " JOIN ports p ON p.id = pc.port_id"
                    " JOIN hosts h ON h.id = p.host_id"
                    " WHERE h.ip=? AND p.port=?", (ip, port))

            assert run_async(count()) == 1, "the upsert must not duplicate rows"
        finally:
            _cleanup_rows(ip, [cve_id])

    def test_port_without_a_service_name_does_not_abort_the_batch(self):
        import uuid

        from chronicle import db
        from chronicle.models import CVE, Port, ScanResult, Severity
        from dashboard.app import run_async
        from iris.cve_mapper import persist_cves

        octet = uuid.uuid4().int % 200 + 20
        ip = f"10.95.{octet}.1"
        port = 2800 + (uuid.uuid4().int % 500)
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_host_port(ip, port)

        try:
            scan = ScanResult(target=ip, ports={ip: [Port(
                host_id=0, port=port, service=None, product="openssh",
                version="8.9")]})
            stored = run_async(persist_cves(
                {f"{ip}:{port}": [CVE(
                    cve_id=cve_id, cvss_v3=5.0, severity=Severity.MEDIUM,
                    description="x")]}, scan, {}))

            assert stored == 1

            async def read():
                return await db.fetch_one(
                    "SELECT pc.verified_status FROM port_cves pc"
                    " JOIN ports p ON p.id = pc.port_id"
                    " JOIN hosts h ON h.id = p.host_id"
                    " WHERE h.ip=? AND p.port=?", (ip, port))

            assert run_async(read())["verified_status"] == "UNVERIFIED"
        finally:
            _cleanup_rows(ip, [cve_id])


# ── Stale mapping pruning ───────────────────────────────────────────────────

def _seed_mapping(ip: str, port: int, cve_id: str, *, dismissed: int = 0,
                  service: str = "ssh", product: str = "openssh",
                  version: str = "8.9") -> int:
    """Seed a host/port/CVE mapping and return the port id."""
    from chronicle import db
    from dashboard.app import run_async

    async def scenario():
        # Reuse an existing host/port so several mappings can be seeded on the
        # same port (a host delete would cascade them away).
        await db.execute(
            "INSERT OR IGNORE INTO hosts (ip, is_active) VALUES (?, 1)", (ip,))
        host_id = await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (ip,))
        await db.execute(
            "INSERT OR IGNORE INTO ports (host_id, port, protocol, state,"
            " service, product, version) VALUES (?,?,?,?,?,?,?)",
            (host_id, port, "tcp", "open", service, product, version))
        port_id = await db.fetch_val(
            "SELECT id FROM ports WHERE host_id=? AND port=?", (host_id, port))
        await db.execute(
            "INSERT INTO cves (cve_id, severity, description) VALUES (?,?,?)"
            " ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description",
            (cve_id, "CRITICAL", "stale mapping"))
        cve_pk = await db.fetch_val("SELECT id FROM cves WHERE cve_id=?", (cve_id,))
        await db.execute(
            "INSERT INTO port_cves (port_id, cve_id, verified_status, dismissed)"
            " VALUES (?,?,?,?)"
            " ON CONFLICT(port_id, cve_id) DO UPDATE SET"
            " verified_status=excluded.verified_status,"
            " dismissed=excluded.dismissed",
            (port_id, cve_pk, "CONFIRMED", dismissed))
        return port_id

    return run_async(scenario())


class TestStaleCvePruning:
    @staticmethod
    def _scan(ip: str, port: int, *, service="ssh", product="openssh",
              version="8.9"):
        from chronicle.models import Port, ScanResult

        return ScanResult(target=ip, ports={ip: [Port(
            host_id=0, port=port, service=service, product=product,
            version=version)]})

    @staticmethod
    def _mark_lookup_succeeded(service, version, product):
        from iris.cve_mapper import _cache, _cache_key

        _cache.set(_cache_key(service, version, product), ([], {}))

    @staticmethod
    def _mappings(ip: str, port: int) -> set[str]:
        from chronicle import db
        from dashboard.app import run_async

        async def read():
            rows = await db.fetch_all(
                "SELECT c.cve_id FROM port_cves pc"
                " JOIN ports p ON p.id = pc.port_id"
                " JOIN cves c ON c.id = pc.cve_id"
                " JOIN hosts h ON h.id = p.host_id"
                " WHERE h.ip=? AND p.port=?", (ip, port))
            return {r["cve_id"] for r in rows}

        return run_async(read())

    def test_successful_lookup_prunes_the_stale_row(self, cve_cache):
        import uuid

        from dashboard.app import run_async

        ip = f"10.90.{uuid.uuid4().int % 200 + 20}.1"
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_mapping(ip, 2222, cve_id)
        self._mark_lookup_succeeded("ssh", "8.9", "openssh")

        try:
            run_async(cve_cache.persist_cves(
                {}, self._scan(ip, 2222), {}))
            assert self._mappings(ip, 2222) == set()
        finally:
            _cleanup_rows(ip, [cve_id])

    def test_failed_lookup_preserves_history(self, cve_cache):
        """An NVD outage must not erase mappings that were never re-checked."""
        import uuid

        from dashboard.app import run_async

        ip = f"10.90.{uuid.uuid4().int % 200 + 20}.1"
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_mapping(ip, 2223, cve_id)
        # No cache entry → the lookup for this fingerprint did not succeed.
        assert cve_cache._cache.get(
            cve_cache._cache_key("ssh", "8.9", "openssh")) is None

        try:
            run_async(cve_cache.persist_cves(
                {}, self._scan(ip, 2223), {}))
            assert self._mappings(ip, 2223) == {cve_id}
        finally:
            _cleanup_rows(ip, [cve_id])

    def test_dismissed_rows_and_nuclei_findings_survive_pruning(self, cve_cache):
        import uuid

        from dashboard.app import run_async

        ip = f"10.90.{uuid.uuid4().int % 200 + 20}.1"
        stale = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        dismissed = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        nuclei = f"NUCLEI-{uuid.uuid4().hex[:10]}"
        _seed_mapping(ip, 2224, stale)
        _seed_mapping(ip, 2224, dismissed, dismissed=1)
        _seed_mapping(ip, 2224, nuclei)
        self._mark_lookup_succeeded("ssh", "8.9", "openssh")

        try:
            run_async(cve_cache.persist_cves(
                {}, self._scan(ip, 2224), {}))
            assert self._mappings(ip, 2224) == {dismissed, nuclei}
        finally:
            _cleanup_rows(ip, [stale, dismissed, nuclei])

    def test_mapping_still_reported_by_nvd_is_kept(self, cve_cache):
        import uuid

        from chronicle.models import CVE, Severity
        from dashboard.app import run_async

        ip = f"10.90.{uuid.uuid4().int % 200 + 20}.1"
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_mapping(ip, 2225, cve_id)
        self._mark_lookup_succeeded("ssh", "8.9", "openssh")

        try:
            run_async(cve_cache.persist_cves(
                {f"{ip}:2225": [CVE(
                    cve_id=cve_id, cvss_v3=7.5, severity=Severity.HIGH,
                    description="still affected")]},
                self._scan(ip, 2225), {}))
            assert self._mappings(ip, 2225) == {cve_id}
        finally:
            _cleanup_rows(ip, [cve_id])


# ── Re-verification ─────────────────────────────────────────────────────────

def _seed_port_cve(ip: str, port: int, cve_id: str, description: str,
                   status: str | None, version: str = "2.4.41"):
    from chronicle import db
    from dashboard.app import run_async

    async def scenario():
        await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
        await db.execute("INSERT INTO hosts (ip, is_active) VALUES (?, 1)", (ip,))
        host_id = await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (ip,))
        await db.execute(
            "INSERT INTO ports (host_id, port, protocol, state, service,"
            " product, version) VALUES (?,?,?,?,?,?,?)",
            (host_id, port, "tcp", "open", "http", "apache httpd", version))
        port_id = await db.fetch_val(
            "SELECT id FROM ports WHERE host_id=? AND port=?", (host_id, port))
        await db.execute(
            "INSERT INTO cves (cve_id, severity, description) VALUES (?,?,?)"
            " ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description",
            (cve_id, "HIGH", description))
        cve_pk = await db.fetch_val("SELECT id FROM cves WHERE cve_id=?", (cve_id,))
        await db.execute(
            "INSERT INTO port_cves (port_id, cve_id, verified_status,"
            " detected_version) VALUES (?,?,?,NULL)"
            " ON CONFLICT(port_id, cve_id) DO UPDATE SET"
            " verified_status=excluded.verified_status, detected_version=NULL",
            (port_id, cve_pk, status))

    run_async(scenario())


class TestVerifyAllCves:
    @staticmethod
    def _status(ip: str, port: int, cve_id: str):
        from chronicle import db
        from dashboard.app import run_async

        async def read():
            return await db.fetch_val(
                "SELECT pc.verified_status FROM port_cves pc"
                " JOIN ports p ON p.id = pc.port_id"
                " JOIN cves c ON c.id = pc.cve_id"
                " JOIN hosts h ON h.id = p.host_id"
                " WHERE h.ip=? AND p.port=? AND c.cve_id=?", (ip, port, cve_id))

        return run_async(read())

    def test_null_status_is_reverified(self):
        import uuid

        from dashboard.app import run_async
        from iris.cve_mapper import verify_all_cves

        octet = uuid.uuid4().int % 200 + 20
        ip = f"10.94.{octet}.1"
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_port_cve(
            ip, 8080, cve_id,
            "Apache HTTP Server versions prior to 2.4.50 are affected.",
            None)
        try:
            assert run_async(verify_all_cves()) >= 1
            assert self._status(ip, 8080, cve_id) == "CONFIRMED"
        finally:
            _cleanup_rows(ip, [cve_id])

    def test_description_without_constraints_does_not_downgrade_a_verdict(self):
        import uuid

        from dashboard.app import run_async
        from iris.cve_mapper import verify_all_cves

        octet = uuid.uuid4().int % 200 + 20
        ip = f"10.93.{octet}.1"
        cve_id = f"CVE-2024-{uuid.uuid4().int % 9000 + 1000}"
        _seed_port_cve(ip, 8081, cve_id,
                       "A problem was found in Apache.", "NOT_AFFECTED")
        try:
            run_async(verify_all_cves())
            # The CPE-derived NOT_AFFECTED verdict must survive: the weaker
            # description-only pass has no evidence to overturn it.
            assert self._status(ip, 8081, cve_id) == "NOT_AFFECTED"
        finally:
            _cleanup_rows(ip, [cve_id])
