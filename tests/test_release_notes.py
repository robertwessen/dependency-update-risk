"""Tests for release notes fetcher."""

from unittest.mock import AsyncMock, patch

import pytest

from dep_risk.config import Config
from dep_risk.models import AffectedPackage, Ecosystem
from dep_risk.release_notes import (
    ReleaseNotesFetcher,
    _extract_github_info,
    _extract_github_url_from_pom,
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


class TestExtractGitHubUrlFromPom:
    """Unit tests for the POM XML SCM URL extractor."""

    def test_extracts_url_element(self):
        pom = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <scm>
    <url>https://github.com/apache/logging-log4j2</url>
  </scm>
</project>"""
        assert _extract_github_url_from_pom(pom) == "https://github.com/apache/logging-log4j2"

    def test_strips_scm_git_prefix_from_connection(self):
        pom = """<project>
  <scm>
    <connection>scm:git:https://github.com/owner/repo.git</connection>
  </scm>
</project>"""
        result = _extract_github_url_from_pom(pom)
        assert result is not None
        assert "github.com/owner/repo" in result

    def test_returns_none_when_no_scm_block(self):
        pom = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.example</groupId>
</project>"""
        assert _extract_github_url_from_pom(pom) is None

    def test_returns_none_when_scm_has_no_github(self):
        pom = """<project>
  <scm>
    <url>https://svn.apache.org/repos/asf/myproject</url>
  </scm>
</project>"""
        assert _extract_github_url_from_pom(pom) is None

    def test_returns_none_on_invalid_xml(self):
        assert _extract_github_url_from_pom("not xml at all") is None

    def test_handles_no_namespace(self):
        """Non-namespaced POM (older Maven projects) still parsed correctly."""
        pom = """<project>
  <scm>
    <url>https://github.com/oldorg/oldrepo</url>
  </scm>
</project>"""
        assert _extract_github_url_from_pom(pom) == "https://github.com/oldorg/oldrepo"


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
    async def test_fetches_github_url_from_pom_scm(self):
        """Slow-path: Solr search returns latestVersion → POM fetched → SCM URL parsed → GitHub releases returned."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from dep_risk.config import Config
        from dep_risk.models import ReleaseNote
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        solr_response = MagicMock()
        solr_response.status_code = 200
        solr_response.json.return_value = {
            "response": {
                "docs": [
                    {
                        "g": "org.apache.logging.log4j",
                        "a": "log4j-core",
                        "latestVersion": "2.20.0",
                    }
                ]
            }
        }

        pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <scm>
    <url>https://github.com/apache/logging-log4j2</url>
    <connection>scm:git:https://github.com/apache/logging-log4j2.git</connection>
  </scm>
</project>"""
        pom_response = MagicMock()
        pom_response.status_code = 200
        pom_response.text = pom_xml

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[solr_response, pom_response])
        fetcher._client = mock_client

        github_note = ReleaseNote(
            version="2.15.0", content="Log4j release", source="GitHub Releases"
        )
        with patch.object(fetcher, "_fetch_github_releases", return_value=[github_note]):
            notes = await fetcher._fetch_maven_releases(
                "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0"
            )

        assert len(notes) == 1
        assert notes[0].source == "GitHub Releases"

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


class TestGoReleases:
    """Tests for Go module release note fetching."""

    @pytest.mark.asyncio
    async def test_uses_github_when_module_path_is_github(self):
        from unittest.mock import patch
        from dep_risk.config import Config
        from dep_risk.models import ReleaseNote
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        github_note = ReleaseNote(
            version="1.5.0", content="GitHub release", source="GitHub Releases"
        )
        with patch.object(fetcher, "_fetch_github_releases", return_value=[github_note]):
            notes = await fetcher._fetch_go_releases(
                "github.com/gin-gonic/gin", "1.4.0", "1.5.0"
            )

        assert len(notes) == 1
        assert notes[0].source == "GitHub Releases"

    @pytest.mark.asyncio
    async def test_fetches_from_proxy_when_not_github(self):
        from unittest.mock import AsyncMock, MagicMock
        from dep_risk.config import Config
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        proxy_response = MagicMock()
        proxy_response.status_code = 200
        proxy_response.text = "v1.4.0\nv1.5.0\nv1.6.0\n"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=proxy_response)
        fetcher._client = mock_client

        notes = await fetcher._fetch_go_releases(
            "golang.org/x/crypto", "1.4.0", "1.6.0"
        )

        # 1.5.0 and 1.6.0 in range; 1.4.0 excluded (start is exclusive)
        assert len(notes) == 2
        assert all(n.source == "pkg.go.dev" for n in notes)

    @pytest.mark.asyncio
    async def test_returns_empty_on_404(self):
        from unittest.mock import AsyncMock, MagicMock
        from dep_risk.config import Config
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)

        not_found = MagicMock()
        not_found.status_code = 404
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=not_found)
        fetcher._client = mock_client

        notes = await fetcher._fetch_go_releases("golang.org/x/nonexistent")
        assert notes == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_request_error(self):
        from unittest.mock import AsyncMock
        import httpx
        from dep_risk.config import Config
        from dep_risk.release_notes import ReleaseNotesFetcher

        config = Config()
        fetcher = ReleaseNotesFetcher(config)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        fetcher._client = mock_client

        notes = await fetcher._fetch_go_releases("golang.org/x/crypto")
        assert notes == []
