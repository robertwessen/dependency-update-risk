"""Multi-source release notes fetcher."""

import asyncio
import logging
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import Cache, Config
from .models import AffectedPackage, Ecosystem, ReleaseNote

logger = logging.getLogger(__name__)


def _parse_version(version: str) -> tuple:
    """Parse version string into comparable tuple.

    Returns tuple of (int_or_zero, str_suffix) pairs for each part,
    ensuring consistent comparison between versions with mixed numeric/string parts.
    """
    # Remove common prefixes
    version = re.sub(r"^[vV]", "", version)
    # Split by common separators
    parts = re.split(r"[\.\-_]", version)
    result = []
    for part in parts:
        # Extract leading number and trailing string separately
        match = re.match(r"^(\d*)(.*)$", part)
        if match:
            num_str, suffix = match.groups()
            num = int(num_str) if num_str else 0
            result.append((num, suffix))
        else:
            result.append((0, part))
    return tuple(result)


def _version_in_range(
    version: str, start_version: Optional[str], end_version: Optional[str]
) -> bool:
    """Check if version is within range (exclusive start, inclusive end).

    For dependency updates, we want release notes for versions AFTER the
    current version up to and INCLUDING the target version.
    Example: updating from 1.0.0 to 1.0.2 should show notes for 1.0.1 and 1.0.2,
    but NOT 1.0.0 (which the user already has).
    """
    try:
        v = _parse_version(version)
        if start_version:
            start = _parse_version(start_version)
            if v <= start:  # Exclusive start: version must be > start
                return False
        if end_version:
            end = _parse_version(end_version)
            if v > end:  # Inclusive end: version must be <= end
                return False
        return True
    except Exception:
        return True  # Include if we can't parse


def _extract_github_info(url: str) -> Optional[tuple[str, str]]:
    """Extract owner and repo from GitHub URL."""
    patterns = [
        r"github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/|$)",
        r"github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            repo = match.group(2)
            # Remove .git suffix if present (use removesuffix, not rstrip)
            if repo.endswith(".git"):
                repo = repo[:-4]
            return match.group(1), repo
    return None


class ReleaseNotesFetcher:
    """Fetch release notes from multiple sources."""

    def __init__(self, config: Config, cache: Optional[Cache] = None):
        self.config = config
        self.cache = cache
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ReleaseNotesFetcher":
        headers = {"Accept": "application/json"}
        if self.config.github_token:
            headers["Authorization"] = f"token {self.config.github_token}"
        self._client = httpx.AsyncClient(timeout=30.0, headers=headers)
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    async def _fetch_github_releases(
        self,
        owner: str,
        repo: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch releases from GitHub API."""
        cache_key = f"github_{owner}_{repo}"
        if self.cache and self.config.use_cache:
            cached = self.cache.get("releases", cache_key)
            if cached:
                logger.debug(f"Using cached GitHub releases for {owner}/{repo}")
                releases_data = cached
            else:
                releases_data = None
        else:
            releases_data = None

        if releases_data is None:
            logger.debug(f"Fetching GitHub releases for {owner}/{repo}")
            try:
                response = await self._client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/releases",
                    params={"per_page": 100},
                )
                response.raise_for_status()
                releases_data = response.json()

                if self.cache:
                    self.cache.set("releases", cache_key, releases_data)
            except httpx.HTTPStatusError as e:
                logger.warning(f"GitHub API error for {owner}/{repo}: {e.response.status_code}")
                return []
            except httpx.RequestError as e:
                logger.warning(f"GitHub API request failed for {owner}/{repo}: {e}")
                return []

        notes = []
        for release in releases_data:
            tag = release.get("tag_name", "")
            version = re.sub(r"^[vV]", "", tag)

            if not _version_in_range(version, start_version, end_version):
                continue

            body = release.get("body", "") or ""
            name = release.get("name", "") or tag

            # Parse date
            date_str = release.get("published_at")
            date = None
            if date_str:
                try:
                    date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            content = f"# {name}\n\n{body}" if body else f"# {name}"
            notes.append(
                ReleaseNote(
                    version=version,
                    date=date,
                    content=content,
                    source="GitHub Releases",
                    url=release.get("html_url"),
                )
            )

        return notes

    async def _fetch_github_changelog(self, owner: str, repo: str) -> Optional[str]:
        """Fetch CHANGELOG.md from GitHub repository."""
        changelog_paths = [
            "CHANGELOG.md",
            "CHANGELOG.rst",
            "CHANGELOG.txt",
            "CHANGELOG",
            "CHANGES.md",
            "CHANGES.rst",
            "HISTORY.md",
            "HISTORY.rst",
            "NEWS.md",
            "docs/CHANGELOG.md",
        ]

        for path in changelog_paths:
            try:
                response = await self._client.get(
                    f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
                )
                if response.status_code == 200:
                    return response.text
                # Try master branch
                response = await self._client.get(
                    f"https://raw.githubusercontent.com/{owner}/{repo}/master/{path}"
                )
                if response.status_code == 200:
                    return response.text
            except httpx.RequestError:
                continue

        return None

    def _parse_changelog(
        self,
        content: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Parse a changelog file into release notes."""
        notes = []

        # Common patterns for version headers
        version_patterns = [
            r"^##?\s*\[?[vV]?(\d+\.\d+(?:\.\d+)?(?:[-.]\w+)?)\]?",  # ## [1.2.3] or ## 1.2.3
            r"^[vV]?(\d+\.\d+(?:\.\d+)?(?:[-.]\w+)?)\s*[-–—]\s*",  # 1.2.3 - date
            r"^###?\s*[vV]?(\d+\.\d+(?:\.\d+)?(?:[-.]\w+)?)",  # ### 1.2.3
        ]

        lines = content.split("\n")
        current_version = None
        current_content = []
        current_date = None

        for line in lines:
            version_match = None
            for pattern in version_patterns:
                match = re.match(pattern, line)
                if match:
                    version_match = match
                    break

            if version_match:
                # Save previous section
                if current_version and current_content:
                    if _version_in_range(current_version, start_version, end_version):
                        notes.append(
                            ReleaseNote(
                                version=current_version,
                                date=current_date,
                                content="\n".join(current_content).strip(),
                                source="CHANGELOG",
                            )
                        )

                current_version = version_match.group(1)
                current_content = [line]

                # Try to extract date from the line
                date_match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                if date_match:
                    try:
                        current_date = datetime.strptime(date_match.group(1), "%Y-%m-%d")
                    except ValueError:
                        current_date = None
                else:
                    current_date = None
            elif current_version:
                current_content.append(line)

        # Don't forget the last section
        if current_version and current_content:
            if _version_in_range(current_version, start_version, end_version):
                notes.append(
                    ReleaseNote(
                        version=current_version,
                        date=current_date,
                        content="\n".join(current_content).strip(),
                        source="CHANGELOG",
                    )
                )

        return notes

    async def _fetch_pypi_releases(
        self,
        package_name: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch release information from PyPI."""
        cache_key = f"pypi_{package_name}"
        if self.cache and self.config.use_cache:
            cached = self.cache.get("releases", cache_key)
            if cached:
                logger.debug(f"Using cached PyPI data for {package_name}")
                data = cached
            else:
                data = None
        else:
            data = None

        if data is None:
            logger.debug(f"Fetching PyPI data for {package_name}")
            try:
                response = await self._client.get(f"https://pypi.org/pypi/{package_name}/json")
                response.raise_for_status()
                data = response.json()

                if self.cache:
                    self.cache.set("releases", cache_key, data)
            except httpx.HTTPStatusError as e:
                logger.warning(f"PyPI API error for {package_name}: {e.response.status_code}")
                return []
            except httpx.RequestError as e:
                logger.warning(f"PyPI API request failed for {package_name}: {e}")
                return []

        notes = []
        releases = data.get("releases", {})

        for version, release_files in releases.items():
            if not _version_in_range(version, start_version, end_version):
                continue

            if not release_files:
                continue

            # Get upload date from first file
            date = None
            upload_time = release_files[0].get("upload_time")
            if upload_time:
                try:
                    date = datetime.fromisoformat(upload_time)
                except ValueError:
                    pass

            # PyPI doesn't have release notes, but we note the version exists
            notes.append(
                ReleaseNote(
                    version=version,
                    date=date,
                    content=f"Release {version}",
                    source="PyPI",
                    url=f"https://pypi.org/project/{package_name}/{version}/",
                )
            )

        # Also try to get description which might have changelog
        info = data.get("info", {})
        project_urls = info.get("project_urls", {}) or {}
        homepage = info.get("home_page") or project_urls.get("Homepage", "")

        # If GitHub, try to get more detailed notes
        if homepage:
            github_info = _extract_github_info(homepage)
            if github_info:
                owner, repo = github_info
                github_notes = await self._fetch_github_releases(
                    owner, repo, start_version, end_version
                )
                if github_notes:
                    return github_notes

                # Try changelog
                changelog = await self._fetch_github_changelog(owner, repo)
                if changelog:
                    changelog_notes = self._parse_changelog(
                        changelog, start_version, end_version
                    )
                    if changelog_notes:
                        return changelog_notes

        return notes

    async def _fetch_npm_releases(
        self,
        package_name: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch release information from npm registry."""
        cache_key = f"npm_{package_name}"
        if self.cache and self.config.use_cache:
            cached = self.cache.get("releases", cache_key)
            if cached:
                logger.debug(f"Using cached npm data for {package_name}")
                data = cached
            else:
                data = None
        else:
            data = None

        if data is None:
            logger.debug(f"Fetching npm data for {package_name}")
            try:
                response = await self._client.get(
                    f"https://registry.npmjs.org/{package_name}"
                )
                response.raise_for_status()
                data = response.json()

                if self.cache:
                    self.cache.set("releases", cache_key, data)
            except httpx.HTTPStatusError as e:
                logger.warning(f"npm API error for {package_name}: {e.response.status_code}")
                return []
            except httpx.RequestError as e:
                logger.warning(f"npm API request failed for {package_name}: {e}")
                return []

        notes = []
        versions = data.get("versions", {})
        time_info = data.get("time", {})

        for version, version_data in versions.items():
            if not _version_in_range(version, start_version, end_version):
                continue

            # Get release date
            date = None
            if version in time_info:
                try:
                    date = datetime.fromisoformat(time_info[version].replace("Z", "+00:00"))
                except ValueError:
                    pass

            notes.append(
                ReleaseNote(
                    version=version,
                    date=date,
                    content=f"Release {version}",
                    source="npm",
                    url=f"https://www.npmjs.com/package/{package_name}/v/{version}",
                )
            )

        # Try to get GitHub releases for more detail
        repository = data.get("repository", {})
        if isinstance(repository, dict):
            repo_url = repository.get("url", "")
        else:
            repo_url = str(repository) if repository else ""

        if repo_url:
            github_info = _extract_github_info(repo_url)
            if github_info:
                owner, repo = github_info
                github_notes = await self._fetch_github_releases(
                    owner, repo, start_version, end_version
                )
                if github_notes:
                    return github_notes

        return notes

    async def fetch_for_package(
        self,
        package: AffectedPackage,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch release notes for a package."""
        notes = []

        # Determine version range if not specified
        if end_version is None and package.fixed_versions:
            end_version = package.fixed_versions[0]

        # Try repository URL first for GitHub
        if package.repository_url:
            github_info = _extract_github_info(package.repository_url)
            if github_info:
                owner, repo = github_info
                notes = await self._fetch_github_releases(
                    owner, repo, start_version, end_version
                )
                if not notes:
                    changelog = await self._fetch_github_changelog(owner, repo)
                    if changelog:
                        notes = self._parse_changelog(changelog, start_version, end_version)

        # Fall back to ecosystem-specific sources
        if not notes:
            if package.ecosystem == Ecosystem.PYPI:
                notes = await self._fetch_pypi_releases(
                    package.name, start_version, end_version
                )
            elif package.ecosystem == Ecosystem.NPM:
                notes = await self._fetch_npm_releases(
                    package.name, start_version, end_version
                )

        # Sort by version (newest first)
        notes.sort(key=lambda n: _parse_version(n.version), reverse=True)

        return notes

    async def fetch(
        self,
        packages: list[AffectedPackage],
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> dict[str, list[ReleaseNote]]:
        """Fetch release notes for multiple packages."""
        results = {}

        tasks = []
        for package in packages:
            task = self.fetch_for_package(package, start_version, end_version)
            tasks.append((package.name, task))

        for name, task in tasks:
            try:
                notes = await task
                results[name] = notes
            except Exception as e:
                logger.warning(f"Failed to fetch release notes for {name}: {e}")
                results[name] = []

        return results


async def fetch_release_notes(
    packages: list[AffectedPackage],
    config: Config,
    cache: Optional[Cache] = None,
    start_version: Optional[str] = None,
    end_version: Optional[str] = None,
) -> dict[str, list[ReleaseNote]]:
    """Convenience function to fetch release notes."""
    async with ReleaseNotesFetcher(config, cache) as fetcher:
        return await fetcher.fetch(packages, start_version, end_version)
