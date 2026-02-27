"""Tests for release notes fetcher."""

from unittest.mock import AsyncMock, patch

import pytest

from dep_risk.config import Config
from dep_risk.models import AffectedPackage, Ecosystem
from dep_risk.release_notes import (
    ReleaseNotesFetcher,
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


class TestFetch:
    """Tests for ReleaseNotesFetcher.fetch() concurrent execution."""

    @pytest.mark.asyncio
    async def test_exception_in_one_package_does_not_affect_others(self):
        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        pkg_ok = AffectedPackage(
            ecosystem=Ecosystem.PYPI, name="requests", affected_versions=[], fixed_versions=[]
        )
        pkg_fail = AffectedPackage(
            ecosystem=Ecosystem.PYPI, name="broken", affected_versions=[], fixed_versions=[]
        )

        async def mock_fetch(pkg, start_version=None, end_version=None):
            if pkg.name == "broken":
                raise RuntimeError("network error")
            return []

        with patch.object(fetcher, "fetch_for_package", side_effect=mock_fetch):
            results = await fetcher.fetch([pkg_ok, pkg_fail])

        assert "requests" in results
        assert results["requests"] == []
        assert "broken" in results
        assert results["broken"] == []

    @pytest.mark.asyncio
    async def test_empty_package_list_returns_empty_dict(self):
        config = Config()
        fetcher = ReleaseNotesFetcher(config)
        results = await fetcher.fetch([])
        assert results == {}


class TestCargoReleases:
    """Tests for crates.io release note fetching."""

    @pytest.mark.asyncio
    async def test_fetches_versions_from_crates_io(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from dep_risk.config import Config
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        crates_response = MagicMock()
        crates_response.status_code = 200
        crates_response.json.return_value = {
            "crate": {"repository": None},
            "versions": [
                {"num": "1.2.0", "created_at": "2024-01-15T10:00:00Z"},
                {"num": "1.1.0", "created_at": "2024-01-01T10:00:00Z"},
                {"num": "1.0.0", "created_at": "2023-12-01T10:00:00Z"},
            ],
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=crates_response)
        fetcher._client = mock_client

        notes = await fetcher._fetch_cargo_releases("serde", "1.0.0", "1.2.0")

        assert len(notes) == 2  # 1.1.0 and 1.2.0 in range; 1.0.0 excluded (start is exclusive)
        assert all(n.source == "crates.io" for n in notes)

    @pytest.mark.asyncio
    async def test_prefers_github_releases_over_crates_stub(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from dep_risk.config import Config
        from dep_risk.models import ReleaseNote
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        crates_response = MagicMock()
        crates_response.status_code = 200
        crates_response.json.return_value = {
            "crate": {"repository": "https://github.com/serde-rs/serde"},
            "versions": [],
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=crates_response)
        fetcher._client = mock_client

        github_note = ReleaseNote(version="1.2.0", content="GitHub release", source="GitHub Releases")
        with patch.object(fetcher, "_fetch_github_releases", return_value=[github_note]):
            notes = await fetcher._fetch_cargo_releases("serde", "1.1.0", "1.2.0")

        assert len(notes) == 1
        assert notes[0].source == "GitHub Releases"

    @pytest.mark.asyncio
    async def test_returns_empty_on_http_error(self):
        from unittest.mock import AsyncMock
        import httpx
        from dep_risk.config import Config
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        fetcher._client = mock_client

        notes = await fetcher._fetch_cargo_releases("serde")
        assert notes == []


class TestMavenReleases:
    """Tests for Maven release note fetching."""

    @pytest.mark.asyncio
    async def test_returns_empty_without_github(self):
        from unittest.mock import AsyncMock, MagicMock
        from dep_risk.config import Config
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        search_response = MagicMock()
        search_response.status_code = 200
        search_response.json.return_value = {
            "response": {"docs": [{"g": "org.example", "a": "mylib"}]}
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=search_response)
        fetcher._client = mock_client

        notes = await fetcher._fetch_maven_releases("org.example:mylib")
        assert notes == []

    @pytest.mark.asyncio
    async def test_uses_github_when_groupid_matches(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from dep_risk.config import Config
        from dep_risk.models import ReleaseNote
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        search_response = MagicMock()
        search_response.status_code = 200
        search_response.json.return_value = {
            "response": {"docs": [{"g": "io.github.myorg", "a": "mylib"}]}
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=search_response)
        fetcher._client = mock_client

        github_note = ReleaseNote(version="2.0.0", content="GitHub release", source="GitHub Releases")
        with patch.object(fetcher, "_fetch_github_releases", return_value=[github_note]):
            notes = await fetcher._fetch_maven_releases("io.github.myorg:mylib")

        assert len(notes) == 1
        assert notes[0].source == "GitHub Releases"
