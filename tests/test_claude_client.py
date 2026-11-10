"""ORACLE AI-context regressions.

Everything here is about what ORACLE sends to a model, and what it does when
the data it reads is not the shape it hoped for. Scanner output and stored
`path_json` are external data: a valid JSON array of integers must degrade to
an empty path, never a 500 on the analyst's dashboard.
"""
import asyncio
import uuid

import pytest

from oracle import claude_client


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch):
    monkeypatch.setattr(claude_client, "_cache", {
        "narrative": {"result": None, "ts": 0, "hash": ""},
        "remediation": {"result": None, "ts": 0, "hash": ""},
    })
    yield


def _context(**overrides):
    base = {
        "hosts": [{
            "ip": "10.0.0.5",
            "os": "Linux",
            "risk_score": 70,
            "ports": ["22/tcp (ssh )"],
            "cves": [{
                "id": "CVE-2024-0001", "cvss": 9.8,
                "severity": "CRITICAL", "desc": "boom",
            }],
        }],
        "attack_paths": [],
        "total_cves": 1,
        "total_rules": 0,
    }
    base.update(overrides)
    return base


class TestStepNormalization:
    @pytest.mark.parametrize("raw,expected", [
        ('[{"ip": "10.0.0.1"}]', [{"ip": "10.0.0.1"}]),
        ('[1, 2, 3]', []),
        ('{"ip": "10.0.0.1"}', [{"ip": "10.0.0.1"}]),
        ('[{"ip": "a"}, "junk", null, 7]', [{"ip": "a"}]),
        ("not json", []),
        ('"just a string"', []),
        (None, []),
        (42, []),
        ([{"ip": "a"}], [{"ip": "a"}]),
    ])
    def test_only_dict_steps_survive(self, raw, expected):
        assert claude_client._normalize_steps(raw) == expected


class TestAiConfigured:
    """The gate must match `_get_client()`, not just ANTHROPIC_API_KEY."""

    @pytest.mark.parametrize("provider", ["anthropic", "nvidia", "openai"])
    def test_each_supported_provider_counts(self, monkeypatch, provider):
        for name in ("anthropic_api_key", "nvidia_api_key", "openai_api_key"):
            monkeypatch.setattr(claude_client.ai_cfg, name, "")
        monkeypatch.setattr(
            claude_client.ai_cfg, f"{provider}_api_key", "sk-test")
        assert claude_client._ai_configured() is True

    def test_no_keys_means_fallback(self, monkeypatch):
        for name in ("anthropic_api_key", "nvidia_api_key", "openai_api_key"):
            monkeypatch.setattr(claude_client.ai_cfg, name, "")
        assert claude_client._ai_configured() is False

    def test_unused_groq_key_does_not_pretend_ai_is_configured(self, monkeypatch):
        for name in ("anthropic_api_key", "nvidia_api_key", "openai_api_key"):
            monkeypatch.setattr(claude_client.ai_cfg, name, "")
        monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
        assert claude_client._ai_configured() is False


class TestContextLoading:
    class FakeDB:
        def __init__(self):
            self.queries = []

        async def fetch_all(self, sql, params=()):
            self.queries.append((sql, params))
            if "FROM hosts WHERE is_active=1" in sql:
                return [{"ip": "10.0.0.5", "mac": None, "os_name": "Linux",
                         "risk_score": 70, "asset_value": 5, "vendor": None}]
            if "FROM ports p JOIN hosts h" in sql:
                return [{"ip": "10.0.0.5", "port": 22, "service": "ssh",
                         "version": "", "protocol": "tcp"}]
            if "FROM cves c" in sql:
                return [{"ip": "10.0.0.5", "cve_id": "CVE-2024-0001",
                         "cvss_v3": 9.8, "severity": "CRITICAL",
                         "description": "boom"}]
            if "FROM attack_paths" in sql:
                return [
                    {"id": 1, "entry_host_id": 1, "target_host_id": 2,
                     "path_json": '[{"ip": "10.0.0.5", "technique": "ssh"}]',
                     "total_steps": 1, "attacker_roi": 2.0,
                     "estimated_time_minutes": 5},
                    {"id": 2, "entry_host_id": 1, "target_host_id": 2,
                     "path_json": "[1, 2, 3]", "total_steps": 0,
                     "attacker_roi": 1.0, "estimated_time_minutes": 1},
                ]
            if "FROM forge_rules" in sql:
                return [
                    {"rule_sid": 1, "rule_category": None,
                     "mitre_technique": "T1", "rule_text": "alert"},
                    {"rule_sid": 2, "rule_category": "  ",
                     "mitre_technique": "T2", "rule_text": "alert"},
                    {"rule_sid": 3, "rule_category": " RECON ",
                     "mitre_technique": "T3", "rule_text": "alert"},
                ]
            return []

        async def fetch_val(self, sql, params=(), default=None):
            self.queries.append((sql, params))
            if "MAX(simulated_at)" in sql:
                return 1000.0
            if "COUNT(*)" in sql:
                return 42
            return default

    def test_limits_are_parameters_not_string_interpolation(self, monkeypatch):
        fake = self.FakeDB()
        monkeypatch.setattr(claude_client, "db", fake)

        context = asyncio.run(claude_client._load_network_context())

        limits = {
            "FROM hosts WHERE is_active=1": (claude_client._MAX_CONTEXT_HOSTS,),
            "FROM ports p JOIN hosts h": (
                claude_client._MAX_CONTEXT_HOSTS, claude_client._MAX_CONTEXT_PORTS),
            "FROM cves c": (
                claude_client._MAX_CONTEXT_HOSTS, claude_client._MAX_CONTEXT_CVES),
            "FROM forge_rules": (claude_client._MAX_CONTEXT_RULES,),
        }
        for marker, expected in limits.items():
            params = next(p for sql, p in fake.queries if marker in sql)
            assert params == expected
            assert not any(str(expected[0]) in sql for sql, _p in fake.queries
                           if marker in sql), "LIMIT must be bound, not inlined"

        path_params = next(p for sql, p in fake.queries
                           if "ORDER BY attacker_roi" in sql)
        assert path_params == (940.0, claude_client._MAX_CONTEXT_PATHS)

        # A COUNT query keeps the headline honest even when rows are truncated.
        assert context["total_cves"] == 42
        assert context["total_rules"] == 3
        assert context["rules_by_cat"] == {"UNKNOWN": 2, "RECON": 1}

    def test_dismissed_and_not_affected_cves_are_not_sent_to_the_model(self):
        """ORACLE must see the same finding set as the dashboard."""
        from chronicle import db
        from dashboard.app import run_async

        ip = f"10.252.{int(uuid.uuid4().hex[:2], 16)}.{int(uuid.uuid4().hex[2:4], 16)}"
        active_id = f"CVE-2026-{uuid.uuid4().hex[:8]}"
        dismissed_id = f"CVE-2026-{uuid.uuid4().hex[:8]}"
        not_affected_id = f"CVE-2026-{uuid.uuid4().hex[:8]}"

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            host = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,risk_score) VALUES (?,1,100) "
                "RETURNING id", (ip,))
            port = await db.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,443,'tcp','open','https') RETURNING id", (host["id"],))
            for cve_id, dismissed, verified in (
                (active_id, 0, "CONFIRMED"),
                (dismissed_id, 1, "CONFIRMED"),
                (not_affected_id, 0, "NOT_AFFECTED"),
            ):
                cve = await db.execute_returning(
                    "INSERT INTO cves (cve_id,cvss_v3,severity,description) "
                    "VALUES (?,9.8,'CRITICAL','x') RETURNING id", (cve_id,))
                await db.execute(
                    "INSERT INTO port_cves (port_id,cve_id,dismissed,verified_status) "
                    "VALUES (?,?,?,?)",
                    (port["id"], cve["id"], dismissed, verified))
            try:
                context = await claude_client._load_network_context()
                host_ctx = next(h for h in context["hosts"] if h["ip"] == ip)
                return {c["id"] for c in host_ctx["cves"]}
            finally:
                await db.execute("DELETE FROM hosts WHERE id=?", (host["id"],))
                for cve_id in (active_id, dismissed_id, not_affected_id):
                    await db.execute("DELETE FROM cves WHERE cve_id=?", (cve_id,))

        assert run_async(scenario()) == {active_id}

    def test_non_dict_path_steps_are_dropped_not_propagated(self, monkeypatch):
        monkeypatch.setattr(claude_client, "db", self.FakeDB())

        context = asyncio.run(claude_client._load_network_context())

        assert [p["steps"] for p in context["attack_paths"]] == [
            [{"ip": "10.0.0.5", "technique": "ssh"}],
            [],
        ]
        assert context["hosts"][0]["ports"] == ["22/tcp (ssh )"]


class TestPromptBuildingSurvivesBadSteps:
    def test_narrative_uses_fallback_without_ai(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        context = _context(attack_paths=[{
            "id": 1, "steps": [1, 2, 3], "total_steps": 3,
            "roi": 1.0, "est_minutes": 1,
        }])

        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)

        text = asyncio.run(claude_client.generate_attack_narrative(context))
        assert "ATTACK NARRATIVE" in text
        assert "10.0.0.5" in text

    def test_remediation_fallback_prints_na_for_missing_cvss(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)

        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)
        context = _context(hosts=[{
            "ip": "10.0.0.5", "os": "Linux", "risk_score": 1,
            "ports": [], "cves": [{"id": "CVE-2024-0001", "cvss": None,
                                   "severity": "HIGH", "desc": "x"}],
        }])

        text = asyncio.run(claude_client.generate_remediation(context))
        assert "CVSS:N/A" in text
        assert "None" not in text


class TestAiPathIsReachable:
    """An OpenAI/NVIDIA-only deployment must actually call the model."""

    class _Message:
        def __init__(self, text):
            self.choices = [type("C", (), {
                "message": type("M", (), {"content": text})(),
            })()]

    def test_openai_only_key_reaches_the_model(self, monkeypatch):
        for name in ("anthropic_api_key", "nvidia_api_key"):
            monkeypatch.setattr(claude_client.ai_cfg, name, "")
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "sk-test")

        calls = []

        class Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        calls.append(kwargs)
                        return TestAiPathIsReachable._Message("CVE-2024-0001 patched")

        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: Client())

        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)

        text = asyncio.run(
            claude_client.generate_remediation(_context()))
        assert calls, "the model must be called when an OpenAI key exists"
        assert "CVE-2024-0001 patched" in text
        assert "REMEDIATION BRIEF" not in text

    def test_report_skips_non_dict_steps_and_escapes(self, tmp_path, monkeypatch):
        context = _context(attack_paths=[{
            "id": 1,
            "steps": [{"ip": "<b>10.0.0.6</b>", "technique": "<i>x</i>"}, 5],
            "total_steps": 2,
            "roi": 1.0,
            "est_minutes": 5,
        }])

        async def fake_context():
            return context

        async def fake_text(_context=None):
            return "<script>alert(1)</script>"

        monkeypatch.setattr(claude_client, "_load_network_context", fake_context)
        monkeypatch.setattr(claude_client, "generate_attack_narrative", fake_text)
        monkeypatch.setattr(claude_client, "generate_remediation", fake_text)

        out = tmp_path / "report.html"
        asyncio.run(claude_client.generate_report(str(out)))
        report = out.read_text()
        assert "<script>alert" not in report
        assert "<b>10.0.0.6</b>" not in report
        assert "10.0.0.6" in report


class TestFreshnessWindow:
    """A daily scan must stay analysable; the old window was one hour."""

    def test_default_is_a_full_day(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_AI_FRESHNESS_HOURS", raising=False)
        assert claude_client._freshness_window() == 24 * 3600

    @pytest.mark.parametrize("raw,expected", [
        ("6", 6 * 3600),
        ("0.5", 1800),
        ("0", 24 * 3600),          # non-positive falls back
        ("-3", 24 * 3600),
        ("garbage", 24 * 3600),
        ("9999", claude_client._AI_FRESHNESS_HOURS_MAX * 3600),
    ])
    def test_override_is_parsed_and_clamped(self, monkeypatch, raw, expected):
        monkeypatch.setenv("OBSIDIOS_AI_FRESHNESS_HOURS", raw)
        assert claude_client._freshness_window() == expected

    def test_guard_reports_how_stale_the_data_is(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_AI_FRESHNESS_HOURS", raising=False)

        async def age():
            return 30 * 3600
        monkeypatch.setattr(claude_client, "_scan_age", age)
        message = asyncio.run(
            claude_client._ai_data_guard(_context()))
        assert "24h" in message and "30.0h old" in message

    def test_guard_allows_a_scan_from_earlier_today(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_AI_FRESHNESS_HOURS", raising=False)

        async def age():
            return 10 * 3600
        monkeypatch.setattr(claude_client, "_scan_age", age)
        assert asyncio.run(claude_client._ai_data_guard(_context())) is None

    def test_no_scan_at_all_and_no_hosts_have_distinct_messages(self, monkeypatch):
        async def never():
            return None
        monkeypatch.setattr(claude_client, "_scan_age", never)

        assert "Run a scan first" in asyncio.run(
            claude_client._ai_data_guard({"hosts": []}))
        assert "completed scan" in asyncio.run(
            claude_client._ai_data_guard(_context()))


class TestProviderDocAlias:
    """`OPENROUTER_API_KEY` is what the docs tell operators to set."""

    def test_openrouter_alias_populates_the_openai_provider(self, monkeypatch):
        from config.settings import AISettings

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        assert AISettings(_env_file=None).openai_api_key == "sk-or-test"

    def test_explicit_openai_key_wins_over_the_alias(self, monkeypatch):
        from config.settings import AISettings

        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        assert AISettings(_env_file=None).openai_api_key == "sk-openai"

    def test_ai_configured_sees_the_alias(self, monkeypatch):
        from config.settings import AISettings

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        monkeypatch.setattr(claude_client, "ai_cfg", AISettings(_env_file=None))
        for name in ("anthropic_api_key", "nvidia_api_key"):
            monkeypatch.setattr(claude_client.ai_cfg, name, "")
        assert claude_client._ai_configured() is True


class TestUntrustedContextShape:
    """Context fields come from scan data; NULL/duplicate values must not 500."""

    def test_hash_tolerates_duplicate_cves_with_a_null_severity(self):
        context = _context(hosts=[{
            "ip": "10.0.0.5", "os": "Linux", "risk_score": None,
            "ports": None,
            "cves": [
                {"id": "CVE-2024-0001", "severity": "HIGH"},
                {"id": "CVE-2024-0001", "severity": None},
            ],
        }])

        assert isinstance(claude_client._data_hash(context), str)

    def test_hash_ignores_non_dict_entries(self):
        context = _context(
            hosts=["junk", {"ip": "10.0.0.5", "cves": [7, None]}],
            attack_paths=["junk", {"id": 1}],
        )

        claude_client._data_hash(context)

    def test_fallback_narrative_does_not_print_none(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)

        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)
        context = _context(hosts=[{
            "ip": "10.0.0.5", "os": None, "risk_score": None,
            "ports": None, "cves": [],
        }])

        text = asyncio.run(claude_client.generate_attack_narrative(context))

        assert "None" not in text
        assert "Risk Score: 0/100" in text
        assert "Linux/Unknown" in text

    def test_fallback_remediation_skips_malformed_entries(self, monkeypatch):
        context = _context(hosts=[
            "junk",
            {
                "ip": "10.0.0.5", "os": "Linux", "risk_score": 1, "ports": [],
                "cves": [
                    {"id": "CVE-2024-0001", "cvss": 9.8},
                    "junk",
                    None,
                ],
            },
        ])

        text = claude_client._fallback_remediation(context)

        assert "CVE-2024-0001" in text
        assert "junk" not in text


class TestGuardMessagesAreNotCached:
    """A scan completing inside the cache TTL must unblock ORACLE immediately."""

    def test_stale_narrative_guard_is_not_cached(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        ages = [None, 0.0]

        async def age():
            return ages.pop(0)

        monkeypatch.setattr(claude_client, "_scan_age", age)

        first = asyncio.run(
            claude_client.generate_attack_narrative(_context()))
        second = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert "completed scan" in first
        assert "ATTACK NARRATIVE" in second

    def test_stale_remediation_guard_is_not_cached(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        ages = [None, 0.0]

        async def age():
            return ages.pop(0)

        monkeypatch.setattr(claude_client, "_scan_age", age)

        first = asyncio.run(claude_client.generate_remediation(_context()))
        second = asyncio.run(claude_client.generate_remediation(_context()))

        assert "completed scan" in first
        assert "REMEDIATION BRIEF" in second


class _AnthropicMessage:
    def __init__(self, text):
        self.content = [type("Block", (), {"text": text})()]


class _OpenAIMessage:
    def __init__(self, text):
        self.choices = [type("Choice", (), {
            "message": type("Msg", (), {"content": text})(),
        })()]


class TestProviderFallbackChain:
    """429s must fall through NVIDIA/OpenAI → Anthropic → template, not 500."""

    def _recent(self, monkeypatch):
        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)

    def test_rate_limit_falls_back_to_anthropic(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "")
        monkeypatch.setattr(claude_client.ai_cfg, "anthropic_api_key", "sk-ant")

        def rate_limited(*_a, **_k):
            raise RuntimeError("429 rate_limit exceeded")

        monkeypatch.setattr(claude_client, "_get_client", rate_limited)
        self._recent(monkeypatch)

        created = []

        class FakeAnthropic:
            def __init__(self, api_key=None):
                created.append(api_key)

            @property
            def messages(self):
                return self

            def create(self, **_kwargs):
                return _AnthropicMessage("CVE-2024-0001 patched")

        import anthropic
        monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert created == ["sk-ant"]
        assert "CVE-2024-0001 patched" in text

    def test_rate_limit_falls_back_to_openai(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "sk-openai")
        monkeypatch.setattr(claude_client.ai_cfg, "anthropic_api_key", "")

        def rate_limited(*_a, **_k):
            raise RuntimeError("429 rate_limit exceeded")

        monkeypatch.setattr(claude_client, "_get_client", rate_limited)
        self._recent(monkeypatch)

        created = []

        class FakeOpenAI:
            def __init__(self, api_key=None, base_url=None):
                created.append((api_key, base_url))

            @property
            def chat(self):
                return self

            @property
            def completions(self):
                return self

            def create(self, **_kwargs):
                return _OpenAIMessage("CVE-2024-0001 patched")

        import openai
        monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)

        text = asyncio.run(
            claude_client.generate_remediation(_context()))

        assert created == [("sk-openai", claude_client.ai_cfg.openai_base_url)]
        assert "CVE-2024-0001 patched" in text

    def test_all_fallbacks_failing_returns_the_template(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "sk-openai")
        monkeypatch.setattr(claude_client.ai_cfg, "anthropic_api_key", "sk-ant")

        def rate_limited(*_a, **_k):
            raise RuntimeError("429 rate_limit exceeded")

        monkeypatch.setattr(claude_client, "_get_client", rate_limited)
        self._recent(monkeypatch)

        class Boom:
            def __init__(self, **_kwargs):
                raise RuntimeError("provider down")

        import anthropic
        import openai
        monkeypatch.setattr(openai, "OpenAI", Boom)
        monkeypatch.setattr(anthropic, "Anthropic", Boom)

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert "ATTACK NARRATIVE" in text

    def test_non_rate_limit_error_goes_straight_to_the_template(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)

        def broken(*_a, **_k):
            raise RuntimeError("connection reset")

        monkeypatch.setattr(claude_client, "_get_client", broken)
        self._recent(monkeypatch)

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert "ATTACK NARRATIVE" in text


class TestOutputSanitisation:
    @pytest.mark.parametrize("raw,expected", [
        (None, ""),
        (123, "123"),
        (b"bytes", "b'bytes'"),
    ])
    def test_non_string_output_is_coerced(self, raw, expected):
        assert claude_client._sanitize_ai_output(raw, set()) == expected

    def test_control_characters_are_stripped(self):
        text = claude_client._sanitize_ai_output("a\x00b\x1bc\nd", set())
        assert text == "abc\nd"

    def test_invented_cves_are_removed(self):
        text = claude_client._sanitize_ai_output(
            "CVE-2024-0001 is real; CVE-1999-0001 was invented.",
            {"CVE-2024-0001"},
        )

        assert "CVE-2024-0001 is real" in text
        assert "CVE-1999-0001" not in text
        assert "[unverified CVE removed]" in text


class TestPrimaryProviderPaths:
    """The happy path for each client shape used in production."""

    def _recent(self, monkeypatch):
        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)

    def test_openai_compatible_client_generates_the_narrative(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        self._recent(monkeypatch)

        class Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**_kwargs):
                        return _OpenAIMessage("CVE-2024-0001 is exposed")

        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: Client())

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert text == "CVE-2024-0001 is exposed"

    def test_anthropic_client_generates_the_narrative(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        self._recent(monkeypatch)

        class Client:
            class messages:
                @staticmethod
                def create(**_kwargs):
                    return _AnthropicMessage("CVE-2024-0001 is exposed")

        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: Client())

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert text == "CVE-2024-0001 is exposed"

    def test_anthropic_client_generates_remediation(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        self._recent(monkeypatch)

        class Client:
            class messages:
                @staticmethod
                def create(**_kwargs):
                    return _AnthropicMessage("patch openssl")

        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: Client())

        text = asyncio.run(claude_client.generate_remediation(_context()))

        assert text == "patch openssl"

    def test_narrative_rate_limit_uses_openai_fallback(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "sk-openai")

        def rate_limited(*_a, **_k):
            raise RuntimeError("429 rate_limit exceeded")

        monkeypatch.setattr(claude_client, "_get_client", rate_limited)
        self._recent(monkeypatch)

        class FakeOpenAI:
            def __init__(self, **_kwargs):
                pass

            @property
            def chat(self):
                return self

            @property
            def completions(self):
                return self

            def create(self, **_kwargs):
                return _OpenAIMessage("CVE-2024-0001 via OpenAI")

        import openai
        monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert text == "CVE-2024-0001 via OpenAI"

    def test_no_cves_short_circuits_remediation(self, monkeypatch):
        self._recent(monkeypatch)
        context = _context(hosts=[{
            "ip": "10.0.0.5", "os": "Linux", "risk_score": 1,
            "ports": [], "cves": [],
        }])

        text = asyncio.run(claude_client.generate_remediation(context))

        assert text == "No known or critical CVEs found. Keep network monitored."

    def test_a_successful_result_is_cached(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        self._recent(monkeypatch)

        calls = []
        original = claude_client._fallback_narrative

        def counted(context):
            calls.append(True)
            return original(context)

        monkeypatch.setattr(claude_client, "_fallback_narrative", counted)

        asyncio.run(claude_client.generate_attack_narrative(_context()))
        asyncio.run(claude_client.generate_attack_narrative(_context()))

        assert calls == [True]


class TestScanAge:
    """The freshness guard is only as good as the age it reads."""

    class FakeDB:
        def __init__(self, row):
            self.row = row

        async def fetch_one(self, _sql, _params=()):
            return self.row

    def test_no_completed_scan_is_none(self, monkeypatch):
        monkeypatch.setattr(claude_client, "db", self.FakeDB(None))
        assert asyncio.run(claude_client._scan_age()) is None

    def test_null_finished_at_is_none(self, monkeypatch):
        monkeypatch.setattr(
            claude_client, "db", self.FakeDB({"finished_at": None}))
        assert asyncio.run(claude_client._scan_age()) is None

    def test_future_timestamp_clamps_to_zero(self, monkeypatch):
        import time as _time

        monkeypatch.setattr(
            claude_client, "db", self.FakeDB({"finished_at": _time.time() + 3600}))
        assert asyncio.run(claude_client._scan_age()) == 0.0


class TestClientSelection:
    """`_get_client` must route to the provider whose key is configured."""

    def _keys(self, monkeypatch, *, anthropic="", nvidia="", openai=""):
        monkeypatch.setattr(claude_client, "_client", None)
        monkeypatch.setattr(claude_client.ai_cfg, "anthropic_api_key", anthropic)
        monkeypatch.setattr(claude_client.ai_cfg, "nvidia_api_key", nvidia)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", openai)

    def test_nvidia_wins_the_primary_slot(self, monkeypatch):
        self._keys(monkeypatch, nvidia="sk-nv", openai="sk-o", anthropic="sk-a")

        client = claude_client._get_client()

        assert type(client).__name__ == "OpenAI"
        assert str(client.base_url).rstrip("/") == \
            claude_client.ai_cfg.nvidia_base_url.rstrip("/")

    def test_openai_is_used_when_nvidia_is_absent(self, monkeypatch):
        self._keys(monkeypatch, openai="sk-o", anthropic="sk-a")

        client = claude_client._get_client()

        assert type(client).__name__ == "OpenAI"
        assert str(client.base_url).rstrip("/") == \
            claude_client.ai_cfg.openai_base_url.rstrip("/")

    def test_anthropic_is_used_as_the_last_configured_provider(self, monkeypatch):
        self._keys(monkeypatch, anthropic="sk-a")

        client = claude_client._get_client()

        assert type(client).__name__ == "Anthropic"

    def test_no_keys_returns_none(self, monkeypatch):
        self._keys(monkeypatch)
        assert claude_client._get_client() is None

    def test_configured_client_is_reused(self, monkeypatch):
        self._keys(monkeypatch, openai="sk-o")
        sentinel = object()
        monkeypatch.setattr(claude_client, "_client", sentinel)

        assert claude_client._get_client() is sentinel

    def test_fallback_prefers_openai_over_anthropic(self, monkeypatch):
        self._keys(monkeypatch, openai="sk-o", anthropic="sk-a")

        client = claude_client._get_client(use_fallback=True)

        assert type(client).__name__ == "OpenAI"

    def test_fallback_can_use_anthropic(self, monkeypatch):
        self._keys(monkeypatch, anthropic="sk-a")

        client = claude_client._get_client(use_fallback=True)

        assert type(client).__name__ == "Anthropic"

    def test_fallback_without_keys_returns_none(self, monkeypatch):
        self._keys(monkeypatch)
        assert claude_client._get_client(use_fallback=True) is None


class TestRemainingFallbackBranches:
    def _recent(self, monkeypatch):
        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)

    def test_narrative_uses_the_loader_when_no_context_is_passed(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        self._recent(monkeypatch)
        loaded = []

        async def fake_loader():
            loaded.append(True)
            return _context()

        monkeypatch.setattr(claude_client, "_load_network_context", fake_loader)

        text = asyncio.run(claude_client.generate_attack_narrative())

        assert loaded == [True]
        assert "ATTACK NARRATIVE" in text

    def test_remediation_uses_the_loader_when_no_context_is_passed(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        self._recent(monkeypatch)
        loaded = []

        async def fake_loader():
            loaded.append(True)
            return _context()

        monkeypatch.setattr(claude_client, "_load_network_context", fake_loader)

        text = asyncio.run(claude_client.generate_remediation())

        assert loaded == [True]
        assert "REMEDIATION BRIEF" in text

    def test_narrative_handles_a_client_that_disappears(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: None)
        self._recent(monkeypatch)

        text = asyncio.run(
            claude_client.generate_attack_narrative(_context()))

        assert "ATTACK NARRATIVE" in text

    def test_remediation_handles_a_client_that_disappears(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: None)
        self._recent(monkeypatch)

        text = asyncio.run(claude_client.generate_remediation(_context()))

        assert "REMEDIATION BRIEF" in text

    def test_path_steps_reach_the_prompt(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        self._recent(monkeypatch)
        prompts = []

        class Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        prompts.append(kwargs["messages"][0]["content"])
                        return _OpenAIMessage("ok")

        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: Client())
        context = _context(attack_paths=[{
            "id": 7,
            "steps": [{"ip": "10.0.0.1", "technique": "ssh"},
                      {"ip": "10.0.0.2", "technique": "smb"}],
            "total_steps": 2, "roi": 3.0, "est_minutes": 9,
        }])

        asyncio.run(claude_client.generate_attack_narrative(context))

        assert "10.0.0.1" in prompts[0]
        assert "smb" in prompts[0]

    def test_fallback_narrative_describes_a_real_path(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        self._recent(monkeypatch)
        context = _context(attack_paths=[{
            "id": 1,
            "steps": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
            "total_steps": 2, "roi": 3.0, "est_minutes": 9,
        }])

        text = asyncio.run(claude_client.generate_attack_narrative(context))

        assert "begins at 10.0.0.1" in text
        assert "reaches 10.0.0.2" in text

    def test_remediation_builder_skips_junk_hosts_and_cves(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        self._recent(monkeypatch)

        class Client:
            class messages:
                @staticmethod
                def create(**_kwargs):
                    return _AnthropicMessage("ok")

        monkeypatch.setattr(claude_client, "_get_client", lambda *a, **k: Client())
        context = _context(hosts=[
            "junk",
            {"ip": "10.0.0.5", "os": "Linux", "risk_score": 1,
             "ports": [], "cves": ["junk", None,
                                   {"id": "CVE-2024-0001", "cvss": 9.8,
                                    "severity": "HIGH", "desc": "x"}]},
        ])

        text = asyncio.run(claude_client.generate_remediation(context))

        assert text == "ok"

    def test_remediation_survives_both_fallbacks_failing(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        self._recent(monkeypatch)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "sk-o")
        monkeypatch.setattr(claude_client.ai_cfg, "anthropic_api_key", "sk-a")

        def rate_limited(*_a, **_k):
            raise RuntimeError("429 rate_limit exceeded")

        monkeypatch.setattr(claude_client, "_get_client", rate_limited)

        class Boom:
            def __init__(self, **_kwargs):
                raise RuntimeError("provider down")

        import anthropic
        import openai
        monkeypatch.setattr(openai, "OpenAI", Boom)
        monkeypatch.setattr(anthropic, "Anthropic", Boom)

        text = asyncio.run(claude_client.generate_remediation(_context()))

        assert "REMEDIATION BRIEF" in text


class TestRemediationCacheAndAnthropicFallback:
    def _recent(self, monkeypatch):
        async def recent():
            return 0.0

        monkeypatch.setattr(claude_client, "_scan_age", recent)

    def test_cached_remediation_is_reused(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: False)
        self._recent(monkeypatch)

        calls = []
        original = claude_client._fallback_remediation

        def counted(context):
            calls.append(True)
            return original(context)

        monkeypatch.setattr(claude_client, "_fallback_remediation", counted)

        asyncio.run(claude_client.generate_remediation(_context()))
        asyncio.run(claude_client.generate_remediation(_context()))

        assert calls == [True]

    def test_remediation_rate_limit_falls_back_to_anthropic(self, monkeypatch):
        monkeypatch.setattr(claude_client, "_ai_configured", lambda: True)
        monkeypatch.setattr(claude_client.ai_cfg, "openai_api_key", "")
        monkeypatch.setattr(claude_client.ai_cfg, "anthropic_api_key", "sk-ant")

        def rate_limited(*_a, **_k):
            raise RuntimeError("429 rate_limit exceeded")

        monkeypatch.setattr(claude_client, "_get_client", rate_limited)
        self._recent(monkeypatch)

        class FakeAnthropic:
            def __init__(self, api_key=None):
                assert api_key == "sk-ant"

            @property
            def messages(self):
                return self

            def create(self, **_kwargs):
                return _AnthropicMessage("patch openssl")

        import anthropic
        monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)

        text = asyncio.run(claude_client.generate_remediation(_context()))

        assert text == "patch openssl"


class TestReportAtomicWrite:
    def test_a_failed_replace_leaves_no_temp_file(self, tmp_path, monkeypatch):
        context = _context()

        async def fake_context():
            return context

        async def fake_text(_context=None):
            return "text"

        monkeypatch.setattr(claude_client, "_load_network_context", fake_context)
        monkeypatch.setattr(claude_client, "generate_attack_narrative", fake_text)
        monkeypatch.setattr(claude_client, "generate_remediation", fake_text)

        def failing_replace(*_args, **_kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(claude_client.os, "replace", failing_replace)

        with pytest.raises(OSError, match="disk full"):
            asyncio.run(
                claude_client.generate_report(str(tmp_path / "report.html")))

        assert list(tmp_path.glob(".report-*")) == []
