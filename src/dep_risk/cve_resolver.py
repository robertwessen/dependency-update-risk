"""CVE resolver using NVD and OSV APIs."""

import asyncio
import logging
import re
from typing import Optional

import httpx

from .config import Cache, Config
from .models import AffectedPackage, CVEInfo, Ecosystem, Severity

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_URL = "https://api.osv.dev/v1/vulns"


def _parse_ecosystem(ecosystem_str: str) -> Ecosystem:
    """Parse ecosystem string to Ecosystem enum."""
    mapping = {
        "pypi": Ecosystem.PYPI,
        "npm": Ecosystem.NPM,
        "maven": Ecosystem.MAVEN,
        "crates.io": Ecosystem.CARGO,
        "cargo": Ecosystem.CARGO,
        "nuget": Ecosystem.NUGET,
        "go": Ecosystem.GO,
        "rubygems": Ecosystem.RUBYGEMS,
        "packagist": Ecosystem.PACKAGIST,
    }
    return mapping.get(ecosystem_str.lower(), Ecosystem.UNKNOWN)


def _extract_severity(nvd_data: dict) -> tuple[Severity, Optional[float]]:
    """Extract severity and CVSS score from NVD data."""
    metrics = nvd_data.get("metrics") or {}
    if not isinstance(metrics, dict):
        return Severity.UNKNOWN, None

    # Try CVSS 3.1 first, then 3.0, then 2.0
    for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if cvss_key in metrics and metrics[cvss_key]:
            entry = metrics[cvss_key][0]
            if not isinstance(entry, dict):
                continue
            cvss_data = entry.get("cvssData") or {}
            if not isinstance(cvss_data, dict):
                continue
            score = cvss_data.get("baseScore")
            severity_str = (cvss_data.get("baseSeverity") or "").upper()

            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.UNKNOWN

            return severity, score

    return Severity.UNKNOWN, None


def _extract_packages_from_nvd(nvd_data: dict) -> list[AffectedPackage]:
    """Extract affected packages from NVD configurations."""
    packages = []
    configurations = nvd_data.get("configurations") or []
    if not isinstance(configurations, list):
        return packages

    for config in configurations:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for cpe_match in node.get("cpeMatch") or []:
                if not cpe_match.get("vulnerable", False):
                    continue

                cpe = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    product = parts[4]
                    version_start = cpe_match.get("versionStartIncluding")
                    version_end = cpe_match.get("versionEndExcluding")
                    version_end_incl = cpe_match.get("versionEndIncluding")

                    affected_versions = []
                    if version_start and version_end:
                        affected_versions.append(f">={version_start},<{version_end}")
                    elif version_start and version_end_incl:
                        affected_versions.append(f">={version_start},<={version_end_incl}")
                    elif version_end:
                        affected_versions.append(f"<{version_end}")
                    elif version_end_incl:
                        affected_versions.append(f"<={version_end_incl}")

                    packages.append(
                        AffectedPackage(
                            ecosystem=Ecosystem.UNKNOWN,
                            name=product,
                            affected_versions=affected_versions,
                        )
                    )

    return packages


def _extract_references(nvd_data: dict) -> list[str]:
    """Extract reference URLs from NVD data."""
    references = nvd_data.get("references", [])
    return [ref.get("url") for ref in references if ref.get("url")]


class CVEResolver:
    """Resolve CVE information from NVD and OSV APIs."""

    def __init__(self, config: Config, cache: Optional[Cache] = None):
        self.config = config
        self.cache = cache
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "CVEResolver":
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    async def _fetch_nvd(self, cve_id: str) -> Optional[dict]:
        """Fetch CVE data from NVD API with retry on 429 rate limiting."""
        if self.cache and self.config.use_cache:
            cached = self.cache.get("nvd", cve_id)
            if cached:
                logger.debug(f"Using cached NVD data for {cve_id}")
                return cached

        headers = {}
        if self.config.nvd_api_key:
            headers["apiKey"] = self.config.nvd_api_key

        max_retries = 3
        for attempt in range(max_retries):
            logger.debug(f"Fetching NVD data for {cve_id} (attempt {attempt + 1})")
            try:
                response = await self._client.get(
                    NVD_API_URL, params={"cveId": cve_id}, headers=headers
                )

                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "30")
                    try:
                        wait_seconds = float(retry_after)
                    except ValueError:
                        wait_seconds = 30.0
                    wait_seconds = min(wait_seconds, 60.0)
                    if attempt < max_retries - 1:
                        logger.warning(
                            f"NVD rate limit hit for {cve_id}, retrying in {wait_seconds:.0f}s "
                            f"(attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(wait_seconds)
                        continue
                    else:
                        logger.warning(f"NVD rate limit exceeded for {cve_id} after {max_retries} attempts")
                        return None

                response.raise_for_status()
                data = response.json()

                if self.cache:
                    self.cache.set("nvd", cve_id, data)

                return data

            except httpx.HTTPStatusError as e:
                logger.warning(f"NVD API error for {cve_id}: {e.response.status_code}")
                return None
            except httpx.RequestError as e:
                logger.warning(f"NVD API request failed for {cve_id}: {e}")
                return None

        return None

    async def _fetch_osv(self, cve_id: str) -> Optional[dict]:
        """Fetch CVE data from OSV API."""
        if self.cache and self.config.use_cache:
            cached = self.cache.get("osv", cve_id)
            if cached:
                logger.debug(f"Using cached OSV data for {cve_id}")
                return cached

        logger.debug(f"Fetching OSV data for {cve_id}")
        try:
            response = await self._client.get(f"{OSV_API_URL}/{cve_id}")
            response.raise_for_status()
            data = response.json()

            if self.cache:
                self.cache.set("osv", cve_id, data)

            return data
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"CVE {cve_id} not found in OSV")
            else:
                logger.warning(f"OSV API error for {cve_id}: {e.response.status_code}")
            return None
        except httpx.RequestError as e:
            logger.warning(f"OSV API request failed for {cve_id}: {e}")
            return None

    def _parse_nvd_response(self, data: dict) -> Optional[CVEInfo]:
        """Parse NVD API response into CVEInfo."""
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        vuln = vulnerabilities[0].get("cve", {})
        cve_id = vuln.get("id", "")

        # Get description
        descriptions = vuln.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity, cvss_score = _extract_severity(vuln)
        packages = _extract_packages_from_nvd(vuln)
        references = _extract_references(vuln)

        # Parse published date
        published_str = vuln.get("published")
        published_date = None
        if published_str:
            try:
                from datetime import datetime

                published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        return CVEInfo(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            published_date=published_date,
            affected_packages=packages,
            references=references,
        )

    def _parse_osv_response(self, data: dict) -> list[AffectedPackage]:
        """Parse OSV API response into affected packages."""
        packages = []
        affected_list = data.get("affected", [])

        for affected in affected_list:
            pkg = affected.get("package", {})
            ecosystem_str = pkg.get("ecosystem", "")
            name = pkg.get("name", "")

            if not name:
                continue

            ecosystem = _parse_ecosystem(ecosystem_str)

            # Get version ranges
            ranges = affected.get("ranges", [])
            affected_versions = []
            fixed_versions = []
            repo_url = None

            for range_info in ranges:
                range_type = range_info.get("type", "")
                events = range_info.get("events", [])
                introduced = None

                # Extract repo URL from GIT ranges (this is the actual package repo)
                if range_type == "GIT" and "repo" in range_info:
                    repo_url = range_info["repo"]

                # Only parse version numbers from ECOSYSTEM or SEMVER ranges
                # GIT ranges contain commit hashes, not version numbers
                if range_type in ("ECOSYSTEM", "SEMVER"):
                    for event in events:
                        if "introduced" in event:
                            introduced = event["introduced"]
                        elif "fixed" in event:
                            fixed = event["fixed"]
                            fixed_versions.append(fixed)
                            if introduced:
                                if introduced == "0":
                                    affected_versions.append(f"<{fixed}")
                                else:
                                    affected_versions.append(f">={introduced},<{fixed}")

            # Also check explicit versions list
            versions = affected.get("versions", [])
            if versions and not affected_versions:
                affected_versions = versions

            packages.append(
                AffectedPackage(
                    ecosystem=ecosystem,
                    name=name,
                    affected_versions=affected_versions,
                    fixed_versions=fixed_versions,
                    repository_url=repo_url,
                )
            )

        return packages

    async def resolve(self, cve_id: str) -> CVEInfo:
        """Resolve CVE information from multiple sources."""
        # Validate CVE ID format
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id, re.IGNORECASE):
            raise ValueError(f"Invalid CVE ID format: {cve_id}")

        cve_id = cve_id.upper()

        # Fetch from both APIs concurrently
        nvd_data, osv_data = await asyncio.gather(
            self._fetch_nvd(cve_id),
            self._fetch_osv(cve_id),
        )

        # Start with NVD data as base
        cve_info = None
        if nvd_data:
            cve_info = self._parse_nvd_response(nvd_data)

        if cve_info is None:
            cve_info = CVEInfo(cve_id=cve_id)

        # Collect all packages from OSV sources
        all_osv_packages = []

        # Merge OSV data (better package information)
        if osv_data:
            osv_packages = self._parse_osv_response(osv_data)
            all_osv_packages.extend(osv_packages)

            # Also get description from OSV if NVD didn't have one
            if not cve_info.description:
                details = osv_data.get("details", "")
                summary = osv_data.get("summary", "")
                cve_info.description = details or summary

            # Add OSV references
            osv_refs = [ref.get("url") for ref in osv_data.get("references", []) if ref.get("url")]
            existing_refs = set(cve_info.references)
            for ref in osv_refs:
                if ref not in existing_refs:
                    cve_info.references.append(ref)

            # Check for ecosystem-specific aliases (PYSEC, GHSA, etc.)
            aliases = osv_data.get("aliases", [])
            ecosystem_aliases = [
                a for a in aliases
                if a.startswith(("PYSEC-", "GHSA-", "RUSTSEC-", "GO-"))
            ]

            # Fetch ecosystem-specific aliases for better package info
            if ecosystem_aliases:
                alias_tasks = [self._fetch_osv(alias) for alias in ecosystem_aliases[:3]]  # Limit to 3
                alias_results = await asyncio.gather(*alias_tasks, return_exceptions=True)

                for alias_data in alias_results:
                    if isinstance(alias_data, dict):
                        alias_packages = self._parse_osv_response(alias_data)
                        # Only add packages that have proper ecosystem info
                        for pkg in alias_packages:
                            if pkg.ecosystem != Ecosystem.UNKNOWN and pkg.fixed_versions:
                                all_osv_packages.append(pkg)

        # Use OSV packages if we found any with good data
        if all_osv_packages:
            # Prefer packages with known ecosystem and fixed versions
            good_packages = [p for p in all_osv_packages if p.ecosystem != Ecosystem.UNKNOWN and p.fixed_versions]
            if good_packages:
                # Deduplicate by name, preferring packages with repository_url
                seen = {}
                for pkg in good_packages:
                    key = (pkg.ecosystem, pkg.name)
                    if key not in seen or (pkg.repository_url and not seen[key].repository_url):
                        seen[key] = pkg
                cve_info.affected_packages = list(seen.values())
            elif all_osv_packages:
                cve_info.affected_packages = all_osv_packages

        if not cve_info.affected_packages and not cve_info.description:
            raise ValueError(f"CVE {cve_id} not found in NVD or OSV databases")

        return cve_info


async def resolve_cve(cve_id: str, config: Config, cache: Optional[Cache] = None) -> CVEInfo:
    """Convenience function to resolve a CVE."""
    async with CVEResolver(config, cache) as resolver:
        return await resolver.resolve(cve_id)
