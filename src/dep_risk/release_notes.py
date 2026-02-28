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


def _extract_github_url_from_pom(xml_text: str) -> Optional[str]:
    """Parse a Maven POM XML string and return a GitHub URL from the <scm> block.

    Handles both namespaced and non-namespaced POM files.  Checks <url>,
    <connection>, and <developerConnection> elements, stripping any
    ``scm:git:`` prefix that Maven SCM coordinates use.
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    # POM files may carry the Maven namespace or omit it entirely.
    for ns_prefix in ["{http://maven.apache.org/POM/4.0.0}", ""]:
        scm = root.find(f"{ns_prefix}scm")
        if scm is None:
            continue
        for tag in ["url", "connection", "developerConnection"]:
            elem = scm.find(f"{ns_prefix}{tag}")
            if elem is not None and elem.text:
                url = elem.text.strip()
                # Strip Maven SCM coordinate prefix: "scm:git:https://..." → "https://..."
                if url.startswith("scm:"):
                    url = re.sub(r"^scm:[a-z+]+:", "", url)
                if "github.com" in url:
                    return url
    return None


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
        headers = {
            "Accept": "application/json",
            "User-Agent": "dep-risk/1.1.0 (https://github.com/robertwessen/dependency-update-risk)",
        }
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

    async def _fetch_cargo_releases(
        self,
        package_name: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch release information from crates.io, preferring GitHub releases."""
        cache_key = f"cargo_{package_name}"
        if self.cache and self.config.use_cache:
            cached = self.cache.get("releases", cache_key)
            if cached:
                logger.debug(f"Using cached crates.io data for {package_name}")
                data = cached
            else:
                data = None
        else:
            data = None

        if data is None:
            logger.debug(f"Fetching crates.io data for {package_name}")
            try:
                response = await self._client.get(
                    f"https://crates.io/api/v1/crates/{package_name}"
                )
                response.raise_for_status()
                data = response.json()

                if self.cache:
                    self.cache.set("releases", cache_key, data)
            except httpx.HTTPStatusError as e:
                logger.warning(f"crates.io API error for {package_name}: {e.response.status_code}")
                return []
            except httpx.RequestError as e:
                logger.warning(f"crates.io API request failed for {package_name}: {e}")
                return []

        # Try GitHub releases first if repo URL is available
        crate_info = data.get("crate", {})
        repo_url = crate_info.get("repository", "")
        if repo_url:
            github_info = _extract_github_info(repo_url)
            if github_info:
                owner, repo = github_info
                github_notes = await self._fetch_github_releases(
                    owner, repo, start_version, end_version
                )
                if github_notes:
                    return github_notes
                changelog = await self._fetch_github_changelog(owner, repo)
                if changelog:
                    changelog_notes = self._parse_changelog(changelog, start_version, end_version)
                    if changelog_notes:
                        return changelog_notes

        # Fall back to versions list from crates.io
        versions_data = data.get("versions", [])
        notes = []
        for ver in versions_data:
            version = ver.get("num", "")
            if not version or not _version_in_range(version, start_version, end_version):
                continue

            date = None
            created_at = ver.get("created_at")
            if created_at:
                try:
                    date = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                except ValueError:
                    pass

            notes.append(
                ReleaseNote(
                    version=version,
                    date=date,
                    content=f"Release {version}",
                    source="crates.io",
                    url=f"https://crates.io/crates/{package_name}/{version}",
                )
            )

        return notes

    async def _fetch_maven_releases(
        self,
        package_name: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch release notes for Maven packages.

        Strategy (in order):
        1. Fast-path: ``io.github.{owner}`` GroupId pattern → derive GitHub URL directly,
           no network call needed.
        2. Slow-path: query Maven Central Solr for ``latestVersion``, then fetch the POM
           file from ``repo1.maven.org`` and parse its ``<scm>`` block for a GitHub URL.
           Resolved URL is cached so subsequent runs skip the Solr+POM round-trip.
        3. Once a GitHub URL is known, try GitHub Releases then fall back to CHANGELOG.
        """
        if ":" in package_name:
            group_id, artifact_id = package_name.split(":", 1)
        else:
            group_id, artifact_id = None, package_name

        repo_url: Optional[str] = None

        # ── Fast-path: io.github.{owner} GroupId pattern ──────────────────────
        if group_id:
            parts = group_id.split(".")
            if len(parts) >= 3 and parts[1] == "github":
                repo_url = f"https://github.com/{parts[2]}/{artifact_id}"

        # ── Slow-path: Solr search → POM XML → SCM URL ────────────────────────
        if not repo_url and group_id:
            cache_key = f"maven_scm_{package_name}"
            cached_url: Optional[str] = None
            if self.cache and self.config.use_cache:
                cached_url = self.cache.get("releases", cache_key)
            if cached_url:
                repo_url = cached_url
            else:
                logger.debug(f"Searching Maven Central for SCM URL: {package_name}")
                try:
                    query = f"a:{artifact_id} AND g:{group_id}"
                    resp = await self._client.get(
                        "https://search.maven.org/solrsearch/select",
                        params={"q": query, "rows": 1, "wt": "json"},
                    )
                    resp.raise_for_status()
                    docs = resp.json().get("response", {}).get("docs", [])
                    if docs:
                        latest_version = docs[0].get("latestVersion") or docs[0].get("v")
                        if latest_version:
                            # Fetch POM for the resolved latest version
                            group_path = group_id.replace(".", "/")
                            pom_url = (
                                f"https://repo1.maven.org/maven2/{group_path}/"
                                f"{artifact_id}/{latest_version}/"
                                f"{artifact_id}-{latest_version}.pom"
                            )
                            pom_resp = await self._client.get(pom_url)
                            if pom_resp.status_code == 200:
                                repo_url = _extract_github_url_from_pom(pom_resp.text)
                                if repo_url and self.cache:
                                    self.cache.set("releases", cache_key, repo_url)
                except (httpx.HTTPStatusError, httpx.RequestError) as e:
                    logger.debug(
                        f"Maven Central search/POM fetch failed for {package_name}: {e}"
                    )

        # ── Fetch release notes from resolved GitHub URL ───────────────────────
        if repo_url:
            github_info = _extract_github_info(repo_url)
            if github_info:
                owner, repo = github_info
                github_notes = await self._fetch_github_releases(
                    owner, repo, start_version, end_version
                )
                if github_notes:
                    return github_notes
                changelog = await self._fetch_github_changelog(owner, repo)
                if changelog:
                    changelog_notes = self._parse_changelog(changelog, start_version, end_version)
                    if changelog_notes:
                        return changelog_notes

        logger.debug(
            f"No GitHub repository found for Maven package {package_name}; "
            f"release notes unavailable"
        )
        return []

    async def _fetch_go_releases(
        self,
        package_name: str,
        start_version: Optional[str] = None,
        end_version: Optional[str] = None,
    ) -> list[ReleaseNote]:
        """Fetch release notes for Go modules via proxy.golang.org and GitHub fast-path."""
        # Fast-path: Go module paths often embed github.com/owner/repo
        if package_name.startswith("github.com/"):
            parts = package_name.split("/")
            if len(parts) >= 3:
                owner, repo = parts[1], parts[2]
                github_notes = await self._fetch_github_releases(
                    owner, repo, start_version, end_version
                )
                if github_notes:
                    return github_notes
                changelog = await self._fetch_github_changelog(owner, repo)
                if changelog:
                    changelog_notes = self._parse_changelog(changelog, start_version, end_version)
                    if changelog_notes:
                        return changelog_notes

        # Fallback: proxy.golang.org version list
        cache_key = f"go_{package_name.replace('/', '_')}"
        if self.cache and self.config.use_cache:
            cached = self.cache.get("releases", cache_key)
            versions = cached if cached else None
        else:
            versions = None

        if versions is None:
            logger.debug(f"Fetching Go proxy data for {package_name}")
            try:
                response = await self._client.get(
                    f"https://proxy.golang.org/{package_name}/@v/list"
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                versions = [v.strip() for v in response.text.strip().splitlines() if v.strip()]
                if self.cache:
                    self.cache.set("releases", cache_key, versions)
            except httpx.HTTPStatusError as e:
                logger.warning(f"Go proxy error for {package_name}: {e.response.status_code}")
                return []
            except httpx.RequestError as e:
                logger.warning(f"Go proxy request failed for {package_name}: {e}")
                return []

        notes = []
        for version in versions:
            ver_clean = version.lstrip("v")
            if not _version_in_range(ver_clean, start_version, end_version):
                continue
            notes.append(
                ReleaseNote(
                    version=ver_clean,
                    date=None,
                    content=f"Release {version}",
                    source="pkg.go.dev",
                    url=f"https://pkg.go.dev/{package_name}@{version}",
                )
            )

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

        # Warn early when the version range is provably empty so callers can
        # surface a useful message rather than silently returning [].
        if start_version and end_version and start_version != "unknown":
            try:
                from packaging.version import InvalidVersion, Version

                sv = Version(start_version.lstrip("vV"))
                ev = Version(end_version.lstrip("vV"))
                if sv >= ev:
                    logger.warning(
                        f"Empty version range for {package.name}: "
                        f"current ({start_version}) >= fixed ({end_version}). "
                        f"No release notes will be returned. "
                        f"Provide the correct --version to resolve this."
                    )
                    return []
            except (InvalidVersion, Exception):
                pass  # non-PEP-440 versions: proceed and let _version_in_range handle it

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
            elif package.ecosystem == Ecosystem.CARGO:
                notes = await self._fetch_cargo_releases(
                    package.name, start_version, end_version
                )
            elif package.ecosystem == Ecosystem.MAVEN:
                notes = await self._fetch_maven_releases(
                    package.name, start_version, end_version
                )
            elif package.ecosystem == Ecosystem.GO:
                notes = await self._fetch_go_releases(
                    package.name, start_version, end_version
                )
            else:
                logger.debug(
                    f"Unknown ecosystem '{package.ecosystem.value}' for {package.name} — "
                    f"no ecosystem registry fetcher available."
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

        package_names = [pkg.name for pkg in packages]
        coroutines = [
            self.fetch_for_package(pkg, start_version, end_version)
            for pkg in packages
        ]
        gathered = await asyncio.gather(*coroutines, return_exceptions=True)
        for name, result in zip(package_names, gathered):
            if isinstance(result, Exception):
                logger.warning(f"Failed to fetch release notes for {name}: {result}")
                results[name] = []
            else:
                results[name] = result

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
