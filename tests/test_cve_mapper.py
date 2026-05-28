"""Tests for iris/cve_mapper.py — version parsing and range matching."""
from iris.cve_mapper import _parse_version, _version_in_range, _cache_key


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