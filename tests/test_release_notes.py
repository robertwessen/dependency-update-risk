"""Tests for release notes fetcher."""

import pytest

from dep_risk.release_notes import (
    _extract_github_info,
    _parse_version,
    _version_in_range,
)


class TestParseVersion:
    def test_simple_version(self):
        # Versions should be comparable tuples
        v123 = _parse_version("1.2.3")
        v124 = _parse_version("1.2.4")
        assert v123 < v124

    def test_version_with_v_prefix(self):
        # v prefix should be stripped
        assert _parse_version("v1.2.3") == _parse_version("1.2.3")
        assert _parse_version("V1.2.3") == _parse_version("1.2.3")

    def test_version_with_suffix(self):
        # Versions with suffixes should be comparable without TypeError
        v123 = _parse_version("1.2.3")
        v123_beta = _parse_version("1.2.3-beta")
        v200_alpha = _parse_version("2.0.0-alpha")
        # Main version numbers should still order correctly
        assert v123 < v200_alpha  # 1.x < 2.x even with suffix
        # No TypeError when comparing mixed numeric/string versions
        try:
            _ = v123_beta < v123
            _ = v123 < v123_beta
        except TypeError:
            pytest.fail("Version comparison raised TypeError")


class TestVersionInRange:
    """Test version range filtering.

    The range is (start, end] - exclusive start, inclusive end.
    This is correct for dependency updates: when updating from 1.0.0 to 1.0.2,
    we want release notes for 1.0.1 and 1.0.2, but NOT 1.0.0 (already have it).
    """

    def test_in_range(self):
        assert _version_in_range("1.5.0", "1.0.0", "2.0.0")

    def test_at_start_excluded(self):
        # Start version is excluded (user already has it)
        assert not _version_in_range("1.0.0", "1.0.0", "2.0.0")

    def test_at_end_included(self):
        # End version is included (this is the target version)
        assert _version_in_range("2.0.0", "1.0.0", "2.0.0")

    def test_before_range(self):
        assert not _version_in_range("0.9.0", "1.0.0", "2.0.0")

    def test_after_range(self):
        assert not _version_in_range("2.1.0", "1.0.0", "2.0.0")

    def test_no_start(self):
        assert _version_in_range("1.5.0", None, "2.0.0")

    def test_no_end(self):
        assert _version_in_range("3.0.0", "1.0.0", None)


class TestExtractGitHubInfo:
    def test_https_url(self):
        result = _extract_github_info("https://github.com/owner/repo")
        assert result == ("owner", "repo")

    def test_https_url_with_git(self):
        result = _extract_github_info("https://github.com/owner/repo.git")
        assert result == ("owner", "repo")

    def test_ssh_url(self):
        result = _extract_github_info("git@github.com:owner/repo.git")
        assert result == ("owner", "repo")

    def test_url_with_path(self):
        result = _extract_github_info("https://github.com/owner/repo/tree/main")
        assert result == ("owner", "repo")

    def test_non_github_url(self):
        result = _extract_github_info("https://gitlab.com/owner/repo")
        assert result is None
