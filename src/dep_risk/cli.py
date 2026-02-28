"""CLI entry point for dependency risk analyzer."""

import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

import click
import httpx
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Cache, Config
from .cve_resolver import CVEResolver
from .llm_analyzer import LLMAnalyzer
from .models import Ecosystem, RiskLevel
from .release_notes import ReleaseNotesFetcher

console = Console()
# Separate stderr console for logging — prevents log lines from polluting stdout
# when users redirect output to a file (e.g. dep-risk analyze --format json > out.json).
_log_console = Console(stderr=True)


def setup_logging(verbose: bool) -> None:
    """Configure logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=_log_console, rich_tracebacks=True, show_path=False)],
    )


_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SUPPORTED_ECOSYSTEMS: frozenset = frozenset(
    {Ecosystem.PYPI, Ecosystem.NPM, Ecosystem.MAVEN, Ecosystem.CARGO, Ecosystem.GO}
)


def _format_markdown(result: dict) -> str:
    """Format analysis result as Markdown."""
    lines = [
        f"# dep-risk Analysis: {result.get('cve_id', 'N/A')}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Package | {result.get('package_name', 'N/A')} ({result.get('ecosystem', 'N/A')}) |",
        f"| Version | {result.get('current_version', '?')} → {result.get('target_version', '?')} |",
        f"| Risk Level | {result.get('risk_level', 'unknown').upper()} |",
    ]
    if "confidence" in result:
        lines.append(f"| Confidence | {result['confidence']:.0%} |")
    lines.append(f"| Release Notes | {result.get('release_notes_analyzed', 0)} analyzed |")

    summary = result.get("analysis_summary", "")
    if summary:
        lines += ["", "## Summary", "", summary]

    breaking_changes = result.get("breaking_changes", [])
    if breaking_changes:
        lines += [
            "",
            "## Breaking Changes",
            "",
            "| Description | Affected API | Migration Hint |",
            "|-------------|-------------|----------------|",
        ]
        for bc in breaking_changes:
            if isinstance(bc, dict):
                desc = bc.get("description", "")
                api = bc.get("affected_api", "-") or "-"
                hint = bc.get("migration_hint", "-") or "-"
                lines.append(f"| {desc} | {api} | {hint} |")

    migration_notes = result.get("migration_notes", [])
    if migration_notes:
        lines += ["", "## Migration Notes", ""]
        lines += [f"- {note}" for note in migration_notes]

    deprecations = result.get("deprecations", [])
    if deprecations:
        lines += ["", "## Deprecations", ""]
        lines += [f"- {dep}" for dep in deprecations]

    return "\n".join(lines) + "\n"


def _format_sarif(result: dict) -> str:
    """Format analysis result as SARIF 2.1.0."""
    cve_id = result.get("cve_id", "UNKNOWN")
    risk_level = result.get("risk_level", "low")
    package_name = result.get("package_name", "unknown")
    ecosystem = result.get("ecosystem", "unknown")
    current_version = result.get("current_version", "unknown")
    target_version = result.get("target_version", "unknown")
    summary = result.get("analysis_summary") or (
        f"Risk level: {risk_level}. "
        f"Update {package_name} from {current_version} to {target_version}."
    )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dep-risk",
                        "version": __version__,
                        "informationUri": "https://github.com/robertwessen/dependency-update-risk",
                        "rules": [
                            {
                                "id": cve_id,
                                "name": "DependencyUpdateRisk",
                                "shortDescription": {
                                    "text": f"Breaking change risk for {cve_id} fix"
                                },
                                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": cve_id,
                        "level": _SARIF_LEVEL.get(risk_level, "note"),
                        "message": {"text": summary},
                        "locations": [
                            {
                                "logicalLocations": [
                                    {
                                        "name": package_name,
                                        "kind": "package",
                                        "fullyQualifiedName": (
                                            f"{ecosystem}/{package_name}@{current_version}"
                                        ),
                                    }
                                ]
                            }
                        ],
                        "properties": {
                            "risk_level": risk_level,
                            "current_version": current_version,
                            "target_version": target_version,
                            "breaking_changes_count": len(result.get("breaking_changes", [])),
                            **({"confidence": result["confidence"]} if "confidence" in result else {}),
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _check_exit_risk(actual_risk: str, threshold: str) -> bool:
    """Return True if actual_risk meets or exceeds threshold."""
    return _RISK_ORDER.get(actual_risk.lower(), -1) >= _RISK_ORDER.get(threshold.lower(), 999)


@dataclass
class ScannerFinding:
    """A CVE finding extracted from a scanner tool's JSON output."""

    cve_id: str
    package_name: Optional[str] = None
    package_version: Optional[str] = None  # installed version = current_version for dep-risk
    ecosystem: Optional[str] = None  # e.g. "PyPI", "npm", "Go"


# Grype artifact.type → ecosystem string used by dep-risk
_GRYPE_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "python": "PyPI",
    "npm": "npm",
    "java-archive": "Maven",
    "rust-crate": "cargo",
    "go-module": "Go",
    "gem": "RubyGems",
    "deb": "Debian",
    "rpm": "RPM",
}

# PURL type → OSV/dep-risk ecosystem string (used for CycloneDX + SPDX SBOM parsing)
_PURL_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "cargo": "crates.io",
    "golang": "Go",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
}


def _parse_scanner_input(path_or_data: "str | dict") -> list[ScannerFinding]:
    """Extract CVE findings (with package context) from Trivy, Grype, or OSV-Scanner JSON.

    Accepts either a file path (str) or an already-parsed dict so the caller can
    avoid reading the file twice when format-detection has already loaded the JSON.

    Each ScannerFinding carries the CVE ID plus the package name and installed version
    reported by the scanner, so dep-risk can (a) filter to the correct affected package
    in the CVE database and (b) use the scanner-reported version as the current version
    without requiring the user to pass --version manually.
    """
    if isinstance(path_or_data, dict):
        data = path_or_data
    else:
        with open(path_or_data) as f:
            data = json.load(f)

    if not isinstance(data, dict):
        return []

    findings: list[ScannerFinding] = []

    # ── Trivy ─────────────────────────────────────────────────────────────────
    # {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-...",
    #               "PkgName": "requests", "InstalledVersion": "2.27.0"}]}]}
    if "Results" in data:
        for result in data.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                vid = vuln.get("VulnerabilityID", "")
                if vid.upper().startswith("CVE-"):
                    findings.append(
                        ScannerFinding(
                            cve_id=vid,
                            package_name=vuln.get("PkgName") or None,
                            package_version=vuln.get("InstalledVersion") or None,
                        )
                    )

    # ── Grype ─────────────────────────────────────────────────────────────────
    # Primary id is often GHSA; CVE appears in relatedVulnerabilities.
    # {"matches": [{"vulnerability": {"id": "GHSA-..."},
    #               "relatedVulnerabilities": [{"id": "CVE-..."}],
    #               "artifact": {"name": "requests", "version": "2.27.0", "type": "python"}}]}
    elif "matches" in data:
        for match in data.get("matches") or []:
            artifact = match.get("artifact", {})
            pkg_name = artifact.get("name") or None
            pkg_version = artifact.get("version") or None
            pkg_type = (artifact.get("type") or "").lower()
            ecosystem = _GRYPE_TYPE_TO_ECOSYSTEM.get(pkg_type)

            vid = match.get("vulnerability", {}).get("id", "")
            cve_found: Optional[str] = None
            if vid.upper().startswith("CVE-"):
                cve_found = vid
            else:
                for related in match.get("relatedVulnerabilities") or []:
                    rid = related.get("id", "")
                    if rid.upper().startswith("CVE-"):
                        cve_found = rid
                        break

            if cve_found:
                findings.append(
                    ScannerFinding(
                        cve_id=cve_found,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        ecosystem=ecosystem,
                    )
                )

    # ── OSV-Scanner ───────────────────────────────────────────────────────────
    # Primary id is GHSA/OSV; CVE appears in aliases.
    # {"results": [{"packages": [{"package": {"name": "requests",
    #                "version": "2.27.0", "ecosystem": "PyPI"},
    #               "vulnerabilities": [{"id": "GHSA-...", "aliases": ["CVE-..."]}]}]}]}
    elif "results" in data:
        for result in data.get("results") or []:
            for pkg_entry in result.get("packages") or []:
                pkg_info = pkg_entry.get("package", {})
                pkg_name = pkg_info.get("name") or None
                pkg_version = pkg_info.get("version") or None
                ecosystem = pkg_info.get("ecosystem") or None

                for vuln in pkg_entry.get("vulnerabilities") or []:
                    vid = vuln.get("id", "")
                    cve_found = None
                    if vid.upper().startswith("CVE-"):
                        cve_found = vid
                    else:
                        for alias in vuln.get("aliases") or []:
                            if alias.upper().startswith("CVE-"):
                                cve_found = alias
                                break

                    if cve_found:
                        findings.append(
                            ScannerFinding(
                                cve_id=cve_found,
                                package_name=pkg_name,
                                package_version=pkg_version,
                                ecosystem=ecosystem,
                            )
                        )

    # Deduplicate: one finding per (cve_id, package_name) pair, preserving order
    seen: set[tuple] = set()
    unique: list[ScannerFinding] = []
    for f in findings:
        key = (f.cve_id, f.package_name)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _parse_purl(purl: str) -> "tuple[str, str, str] | None":
    """Parse a Package URL (PURL) into (ecosystem, name, version) or None.

    Handles: pkg:type/[namespace/]name@version[?qualifiers][#subpath]
    Ref: https://github.com/package-url/purl-spec

    Returns None for unknown types, missing versions, or malformed PURLs.
    No external dependencies — uses only stdlib urllib.parse.unquote.
    """
    from urllib.parse import unquote

    if not purl or not purl.startswith("pkg:"):
        return None

    # Strip qualifiers (?...) and subpath (#...)
    rest = purl[4:]  # drop "pkg:"
    rest = rest.split("?")[0].split("#")[0]

    if "/" not in rest:
        return None

    pkg_type, remainder = rest.split("/", 1)

    ecosystem = _PURL_TYPE_TO_ECOSYSTEM.get(pkg_type.lower())
    if ecosystem is None:
        return None

    # Version is required — separated from path by the last '@'
    if "@" not in remainder:
        return None
    path, version = remainder.rsplit("@", 1)
    if not version:
        return None

    # URL-decode percent-encoded characters (e.g. %40 → @, %2F → /)
    path = unquote(path)
    version = unquote(version)

    # Derive canonical name per ecosystem
    if pkg_type.lower() == "maven":
        # path = "groupId/artifactId" → dep-risk uses "groupId:artifactId"
        parts = path.split("/")
        name = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else parts[0]
    elif pkg_type.lower() == "golang":
        # Full module path preserved (e.g. "github.com/gin-gonic/gin")
        name = path
    else:
        # pypi, npm (incl. scoped), cargo, nuget, gem, composer — path IS the name
        name = path

    return ecosystem, name, version


def _detect_sbom_format(data: dict) -> "str | None":
    """Return 'cyclonedx', 'spdx', or None (scanner JSON or unknown)."""
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in data:
        return "spdx"
    return None


def _parse_cyclonedx(data: dict) -> list[tuple[str, str, str]]:
    """Extract (ecosystem, name, version) tuples from a CycloneDX JSON SBOM.

    Parses top-level ``components[].purl``. Skips components without a PURL
    or with an unrecognised PURL type.  Nested ``components[].components``
    (dependency-tree format) are not traversed — flat SBOM output from Syft /
    cdxgen is the common enterprise case.
    """
    packages: list[tuple[str, str, str]] = []
    for component in data.get("components") or []:
        purl = component.get("purl")
        if purl:
            parsed = _parse_purl(purl)
            if parsed:
                packages.append(parsed)
    return packages


def _parse_spdx(data: dict) -> list[tuple[str, str, str]]:
    """Extract (ecosystem, name, version) tuples from an SPDX JSON SBOM.

    Inspects ``packages[].externalRefs`` for entries where
    ``referenceCategory == "PACKAGE-MANAGER"`` and ``referenceLocator`` is a
    valid PURL.  The first valid PURL per package wins; duplicates are skipped.
    """
    packages: list[tuple[str, str, str]] = []
    for pkg in data.get("packages") or []:
        for ref in pkg.get("externalRefs") or []:
            if ref.get("referenceCategory") == "PACKAGE-MANAGER":
                locator = ref.get("referenceLocator", "")
                if locator.startswith("pkg:"):
                    parsed = _parse_purl(locator)
                    if parsed:
                        packages.append(parsed)
                        break  # first valid PURL per package
    return packages


async def _query_osv_batch(
    packages: list[tuple[str, str, str]],
) -> list[ScannerFinding]:
    """Query OSV /v1/querybatch to find CVEs for a list of (ecosystem, name, version) tuples.

    OSV querybatch returns minimal vuln stubs {id, modified} — aliases (including CVE IDs)
    are NOT present in the batch response.  For any vuln whose id does not start with
    "CVE-", we fetch the full record from /v1/vulns/{id} to extract the CVE alias.
    These secondary fetches are parallelised with asyncio.gather().

    Results are deduplicated on (cve_id, package_name).  HTTP errors are logged
    as warnings and return an empty list — they do not propagate as exceptions.

    Sends requests in chunks of 500 (OSV hard limit is 1000; half used for safety).
    """
    if not packages:
        return []

    _logger = logging.getLogger(__name__)
    _OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    _OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
    _CHUNK_SIZE = 500

    # Intermediate: list of (ecosystem, name, version, vuln_id) pending CVE resolution
    pending: list[tuple[str, str, str, str]] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        # ── Phase 1: querybatch to collect vuln stubs ──────────────────────
        for chunk_start in range(0, len(packages), _CHUNK_SIZE):
            chunk = packages[chunk_start : chunk_start + _CHUNK_SIZE]
            queries = [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for ecosystem, name, version in chunk
            ]
            try:
                resp = await client.post(_OSV_BATCH_URL, json={"queries": queries})
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                _logger.warning(
                    f"OSV querybatch HTTP error {e.response.status_code}: {e}"
                )
                continue
            except httpx.RequestError as e:
                _logger.warning(f"OSV querybatch request error: {e}")
                continue

            results = resp.json().get("results") or []
            for (ecosystem, name, version), result in zip(chunk, results):
                for vuln in result.get("vulns") or []:
                    vid = vuln.get("id", "")
                    if vid:
                        pending.append((ecosystem, name, version, vid))

        if not pending:
            return []

        # ── Phase 2: resolve non-CVE IDs to their CVE aliases ─────────────
        # Collect unique non-CVE vuln IDs that need a full-record fetch
        non_cve_ids: set[str] = {
            vid for _, _, _, vid in pending if not vid.upper().startswith("CVE-")
        }

        # Fetch all non-CVE records in parallel
        async def _fetch_vuln(vid: str) -> tuple[str, Optional[str]]:
            """Return (vuln_id, cve_alias_or_None)."""
            try:
                r = await client.get(_OSV_VULN_URL.format(vid))
                r.raise_for_status()
                data = r.json()
                for alias in data.get("aliases") or []:
                    if alias.upper().startswith("CVE-"):
                        return vid, alias
                return vid, None
            except (httpx.HTTPStatusError, httpx.RequestError) as e:
                _logger.warning(f"OSV vuln fetch failed for {vid}: {e}")
                return vid, None

        fetch_results = await asyncio.gather(*(_fetch_vuln(vid) for vid in non_cve_ids))
        osv_to_cve: dict[str, Optional[str]] = dict(fetch_results)

        # ── Phase 3: assemble ScannerFindings with resolved CVE IDs ────────
        all_findings: list[ScannerFinding] = []
        for ecosystem, name, version, vid in pending:
            if vid.upper().startswith("CVE-"):
                cve_id: Optional[str] = vid
            else:
                cve_id = osv_to_cve.get(vid)

            if cve_id:
                all_findings.append(
                    ScannerFinding(
                        cve_id=cve_id,
                        package_name=name,
                        package_version=version,
                        ecosystem=ecosystem,
                    )
                )

    # Deduplicate on (cve_id, package_name) — preserve first-seen order
    seen: set[tuple] = set()
    unique: list[ScannerFinding] = []
    for f in all_findings:
        key = (f.cve_id, f.package_name)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _estimate_previous_version(fixed_version: str) -> tuple[Optional[str], bool]:
    """Returns (estimated_version, is_ambiguous). None means no reliable estimate."""
    from packaging.version import InvalidVersion, Version

    try:
        v = Version(fixed_version)
    except InvalidVersion:
        return None, True
    major, minor, micro = v.major, v.minor, v.micro
    if micro > 0:
        return f"{major}.{minor}.{micro - 1}", False  # unambiguous
    elif minor > 0:
        return f"{major}.{minor - 1}.0", True  # plausible lower bound
    else:
        return None, True  # X.0.0 — can't reliably guess


def _fuzzy_match_package(pkg_filter: str, candidates: list) -> tuple[list, bool]:
    """Match a package filter against affected packages; return (matches, was_fuzzy).

    Tries exact case-insensitive match first, then falls back to matching on the
    artifact component: last ':' segment for Maven coordinates (groupId:artifactId),
    last '/' segment for Go module paths.
    """
    exact = [p for p in candidates if p.name.lower() == pkg_filter.lower()]
    if exact:
        return exact, False

    def artifact_id(name: str) -> str:
        if ":" in name:
            return name.split(":")[-1]
        if "/" in name:
            return name.split("/")[-1]
        return name

    fuzzy = [p for p in candidates if artifact_id(p.name).lower() == pkg_filter.lower()]
    return fuzzy, bool(fuzzy)


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """Dependency Update Risk Analyzer - Analyze breaking change risk for CVE fixes."""
    pass


@main.command()
@click.argument("cve_id", required=False, default=None)
@click.option(
    "--version",
    "-v",
    "current_version",
    help="Current version (default: N-1 of fix version)",
)
@click.option(
    "--api-url",
    envvar="DEP_RISK_API_URL",
    help="LLM API base URL (appends /v1/chat/completions)",
)
@click.option(
    "--api-key",
    envvar="DEP_RISK_API_KEY",
    help="LLM API key",
)
@click.option(
    "--model",
    envvar="DEP_RISK_MODEL",
    default="gpt-4",
    help="Model name to use",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (default: stdout)",
)
@click.option(
    "--cache-ttl",
    type=int,
    default=24,
    help="Cache TTL in hours (default: 24)",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Bypass cache, fetch fresh data",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug logging",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable detailed LLM API request/response logging for troubleshooting",
)
@click.option(
    "--max-context",
    type=int,
    default=8192,
    help="Max context tokens for LLM (default: 8192, use 128000 for gpt-4-turbo)",
)
@click.option(
    "--package",
    "-p",
    help="Specific package to analyze (if CVE affects multiple)",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["rich", "json", "markdown", "sarif"], case_sensitive=False),
    default="rich",
    help="Output format: rich (default), json, markdown, or sarif",
)
@click.option(
    "--json-only",
    is_flag=True,
    hidden=True,
    help="Deprecated: use --format json instead",
)
@click.option(
    "--nvd-api-key",
    envvar="DEP_RISK_NVD_API_KEY",
    help="NVD API key for higher rate limits (https://nvd.nist.gov/developers/request-an-api-key)",
)
@click.option(
    "--min-exit-risk",
    type=click.Choice(["high", "critical"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if risk level meets or exceeds this threshold (for CI use)",
)
@click.option(
    "--input",
    "input_file",
    type=click.Path(exists=True),
    help="Scanner JSON (Trivy/Grype/OSV-Scanner) or SBOM (CycloneDX/SPDX JSON) — analyze all CVEs found",
)
@click.option(
    "--no-llm",
    is_flag=True,
    default=False,
    help="Skip LLM analysis entirely; show structured release notes without AI summary (useful for air-gapped or data-restricted environments)",
)
def analyze(
    cve_id: str,
    current_version: Optional[str],
    api_url: Optional[str],
    api_key: Optional[str],
    model: str,
    output: Optional[str],
    cache_ttl: int,
    no_cache: bool,
    verbose: bool,
    debug: bool,
    max_context: int,
    package: Optional[str],
    output_format: str,
    json_only: bool,
    nvd_api_key: Optional[str],
    min_exit_risk: Optional[str],
    input_file: Optional[str] = None,
    no_llm: bool = False,
) -> None:
    """Analyze breaking change risk for a CVE security update.

    CVE_ID is the CVE identifier (e.g., CVE-2024-3094).
    """
    # Back-compat: --json-only maps to --format json
    if json_only:
        output_format = "json"

    # Validate: CVE_ID xor --input required
    if input_file and cve_id:
        raise click.UsageError("Cannot use both CVE_ID argument and --input at the same time.")
    if not input_file and not cve_id:
        raise click.UsageError("Provide a CVE_ID argument or use --input FILE.")

    # Build list of items to process — always ScannerFinding objects so the package
    # name and installed version are available throughout the analysis loop.
    if input_file:
        with open(input_file) as _f:
            _raw = json.load(_f)

        sbom_format = _detect_sbom_format(_raw)
        if sbom_format:
            # ── SBOM input (CycloneDX / SPDX) ─────────────────────────────────
            # Parse the SBOM to get (ecosystem, name, version) tuples, then query
            # OSV querybatch to discover which packages have known CVEs.
            sbom_packages = (
                _parse_cyclonedx(_raw) if sbom_format == "cyclonedx" else _parse_spdx(_raw)
            )
            if not sbom_packages:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] No packages with recognised PURLs "
                    f"found in {sbom_format.upper()} SBOM."
                )
                return
            if output_format == "rich":
                console.print(
                    f"[bold blue]Found {len(sbom_packages)} packages in "
                    f"{sbom_format.upper()} SBOM. Querying OSV for CVEs...[/bold blue]"
                )
            items_to_process = asyncio.run(_query_osv_batch(sbom_packages))
            if not items_to_process:
                console.print(
                    "[bold yellow]No CVEs found for any packages in the SBOM.[/bold yellow]"
                )
                return
            if output_format == "rich":
                pkg_count = len({f.package_name for f in items_to_process})
                console.print(
                    f"[bold blue]Found {len(items_to_process)} CVE findings "
                    f"across {pkg_count} package(s).[/bold blue]"
                )
        else:
            # ── Scanner input (Trivy / Grype / OSV-Scanner) ───────────────────
            items_to_process = _parse_scanner_input(_raw)
            if not items_to_process:
                console.print(
                    "[bold yellow]Warning:[/bold yellow] No CVE IDs found in scanner input file."
                )
                return
            if output_format == "rich" and len(items_to_process) > 1:
                console.print(
                    f"[bold blue]Found {len(items_to_process)} CVE findings "
                    f"in scanner output.[/bold blue]"
                )
    else:
        items_to_process = [ScannerFinding(cve_id=cve_id)]

    # Enable verbose logging if debug is set
    setup_logging(verbose or debug)
    logger = logging.getLogger(__name__)

    # Build config
    config = Config.from_env().with_overrides(
        api_url=api_url,
        api_key=api_key,
        model=model,
        cache_ttl=cache_ttl,
        no_cache=no_cache,
        verbose=verbose,
        debug=debug,
        max_context_tokens=max_context,
        nvd_api_key=nvd_api_key,
    )

    # Initialize cache
    cache = Cache(ttl_hours=cache_ttl) if not no_cache else None

    # Per-finding context updated by the outer loop before each asyncio.run() call
    forced_package_name: Optional[str] = None  # from scanner: which package was found
    scanner_current_version: Optional[str] = None  # from scanner: installed version

    async def run_analysis() -> list[dict]:
        """Resolve one CVE and analyze all (or the filtered) affected packages.

        Returns a list of result dicts — one per package analyzed.  The caller
        iterates this list and collects everything into all_results.
        """
        # Step 1: Resolve CVE ─────────────────────────────────────────────────
        if output_format == "rich":
            console.print(f"\n[bold blue]Resolving CVE {cve_id}...[/bold blue]")

        async with CVEResolver(config, cache) as resolver:
            try:
                cve_info = await resolver.resolve(cve_id)
            except ValueError as e:
                console.print(f"[bold red]Error:[/bold red] {e}")
                sys.exit(1)

        if not cve_info.affected_packages:
            console.print(
                f"[bold yellow]Warning:[/bold yellow] No affected packages found for {cve_id}"
            )
            sys.exit(1)

        if output_format == "rich":
            console.print(f"  Found {len(cve_info.affected_packages)} affected package(s)")
            console.print(f"  Severity: {cve_info.severity.value}")
            if cve_info.cvss_score:
                console.print(f"  CVSS Score: {cve_info.cvss_score}")

        # Step 2: Select which packages to analyze ────────────────────────────
        if package:
            # Explicit --package filter: exact match first, then fuzzy on artifact component
            matches, was_fuzzy = _fuzzy_match_package(package, cve_info.affected_packages)
            if not matches:
                console.print(
                    f"[bold red]Error:[/bold red] Package '{package}' not found in affected packages"
                )
                available = [p.name for p in cve_info.affected_packages]
                console.print(f"Available packages: {', '.join(available)}")
                sys.exit(1)
            elif was_fuzzy and len(matches) > 1:
                console.print(
                    f"[bold red]Error:[/bold red] Ambiguous package '{package}' — "
                    f"multiple matches found:"
                )
                for m in matches:
                    console.print(f"  • {m.name}")
                console.print("Use the full package coordinate with --package.")
                sys.exit(1)
            else:
                if was_fuzzy and output_format == "rich":
                    console.print(
                        f"[dim]Note: matched '{package}' to full coordinate "
                        f"'{matches[0].name}'[/dim]"
                    )
                packages_to_analyze = matches
        elif forced_package_name:
            # Scanner context: the scanner told us which specific package it found.
            # Use fuzzy matching so Maven artifactId and Go last-segment work too.
            matches, was_fuzzy = _fuzzy_match_package(
                forced_package_name, cve_info.affected_packages
            )
            if not matches:
                # CVE DB uses a different name than the scanner (e.g. "python-requests"
                # vs "requests").  Fall back to all packages with a note.
                if output_format == "rich":
                    console.print(
                        f"[dim]Note: Scanner found '{forced_package_name}' but CVE database "
                        f"lists different package names. Analyzing all affected packages.[/dim]"
                    )
                packages_to_analyze = cve_info.affected_packages
            else:
                if was_fuzzy and output_format == "rich":
                    console.print(
                        f"[dim]Note: matched '{forced_package_name}' to "
                        f"'{matches[0].name}'[/dim]"
                    )
                packages_to_analyze = matches
        else:
            # No filter: analyze every affected package.
            packages_to_analyze = cve_info.affected_packages
            if len(packages_to_analyze) > 1 and output_format == "rich":
                console.print(
                    f"[dim]CVE affects {len(packages_to_analyze)} package(s) — analyzing all. "
                    f"Use --package to focus on one.[/dim]"
                )

        # Step 3: Fetch release notes for all packages in parallel ────────────
        pkg_results: list[dict] = []

        async with ReleaseNotesFetcher(config, cache) as fetcher:
            for target_package in packages_to_analyze:
                # Determine current/target versions for this specific package.
                # Priority: --version CLI flag > scanner installed version > estimate
                if original_current_version:
                    pkg_current = original_current_version
                elif scanner_current_version:
                    pkg_current = scanner_current_version
                else:
                    pkg_current = None  # will be estimated below

                target_version = (
                    target_package.fixed_versions[0]
                    if target_package.fixed_versions
                    else "unknown"
                )

                # #13 — track whether current_version was estimated
                version_was_estimated = False
                estimate_basis: Optional[str] = None

                if not pkg_current:
                    if target_package.fixed_versions:
                        estimated, version_is_ambiguous = _estimate_previous_version(
                            target_package.fixed_versions[0]
                        )
                        if estimated is None:
                            if output_format == "rich":
                                console.print(
                                    f"[bold yellow]Warning:[/bold yellow] Cannot estimate "
                                    f"previous version for {target_package.fixed_versions[0]} "
                                    f"(likely a major version boundary). "
                                    f"Use --version to specify your current version."
                                )
                            pkg_current = "unknown"
                        else:
                            pkg_current = estimated
                            version_was_estimated = True
                            estimate_basis = (
                                f"decremented from fixed version "
                                f"{target_package.fixed_versions[0]}"
                            )
                            if version_is_ambiguous and output_format == "rich":
                                console.print(
                                    f"[dim]Note: Version {pkg_current} is an estimate. "
                                    f"Use --version for accuracy.[/dim]"
                                )
                    else:
                        pkg_current = "unknown"

                # #14 — detect when no fix is available
                fix_available = target_version != "unknown"

                # Warn when version range is empty (would yield zero release notes)
                if (
                    fix_available
                    and pkg_current != "unknown"
                    and pkg_current == target_version
                ):
                    if output_format == "rich":
                        console.print(
                            f"[bold yellow]Warning:[/bold yellow] {target_package.name}: "
                            f"current version ({pkg_current}) already matches fixed version — "
                            f"no intermediate releases to fetch. "
                            f"Use --version to specify your actual installed version."
                        )

                if output_format == "rich":
                    console.print(
                        f"\n[bold blue]Analyzing {target_package.name}...[/bold blue]"
                    )
                    console.print(f"  Current version: {pkg_current}")
                    console.print(f"  Target version:  {target_version}")
                    if not fix_available:
                        console.print(
                            f"[bold yellow]Warning:[/bold yellow] No fixed version is known "
                            f"for {target_package.name}. There may be no patch available, "
                            f"the package may be abandoned, or the CVE may be disputed. "
                            f"Consider replacing or mitigating this dependency."
                        )

                # Only fetch release notes when a fix exists
                release_notes = []
                if fix_available:
                    if output_format == "rich":
                        console.print(f"\n[bold blue]Fetching release notes...[/bold blue]")
                    release_notes = await fetcher.fetch_for_package(
                        target_package,
                        start_version=pkg_current,
                        end_version=target_version,
                    )
                    if output_format == "rich":
                        console.print(f"  Found {len(release_notes)} release note(s)")

                # #17 — track ecosystem support and release notes availability
                ecosystem_supported = target_package.ecosystem in _SUPPORTED_ECOSYSTEMS
                release_notes_available = len(release_notes) > 0
                if not ecosystem_supported and output_format == "rich":
                    console.print(
                        f"  [dim]⚠ Ecosystem '{target_package.ecosystem.value}' not yet "
                        f"supported — release notes unavailable[/dim]"
                    )

                # Step 4: LLM analysis ────────────────────────────────────────
                # Skip LLM when: no fix available, --no-llm flag, or API not configured
                if not fix_available:
                    result = {
                        "cve_id": cve_info.cve_id,
                        "package_name": target_package.name,
                        "ecosystem": target_package.ecosystem.value,
                        "current_version": pkg_current,
                        "target_version": "unknown",
                        "fix_available": False,
                        "version_estimated": version_was_estimated,
                        "version_estimate_basis": estimate_basis,
                        "ecosystem_supported": ecosystem_supported,
                        "release_notes_available": release_notes_available,
                        "analysis_summary": (
                            f"No fixed version is known for {target_package.name}. "
                            f"This may mean no patch has been released, the package is "
                            f"abandoned, or the CVE is disputed. Consider replacing or "
                            f"mitigating this dependency manually."
                        ),
                    }
                elif no_llm or not api_url or not api_key:
                    if output_format == "rich":
                        if no_llm:
                            console.print(
                                "[dim]LLM analysis disabled (--no-llm). "
                                "Showing release notes.[/dim]"
                            )
                            _print_release_notes_list(release_notes, console)
                        else:
                            console.print(
                                "[bold yellow]Warning:[/bold yellow] LLM API not configured. "
                                "Set --api-url and --api-key or environment variables."
                            )
                            console.print("Skipping LLM analysis.")
                    result = {
                        "cve_id": cve_info.cve_id,
                        "package_name": target_package.name,
                        "ecosystem": target_package.ecosystem.value,
                        "current_version": pkg_current,
                        "target_version": target_version,
                        "fix_available": True,
                        "version_estimated": version_was_estimated,
                        "version_estimate_basis": estimate_basis,
                        "ecosystem_supported": ecosystem_supported,
                        "release_notes_available": release_notes_available,
                        "severity": cve_info.severity.value,
                        "cvss_score": cve_info.cvss_score,
                        "release_notes_analyzed": len(release_notes),
                        "note": (
                            "LLM analysis disabled (--no-llm)"
                            if no_llm
                            else "LLM analysis skipped - API not configured"
                        ),
                    }
                else:
                    if output_format == "rich":
                        console.print(
                            f"\n[bold blue]Analyzing breaking changes with LLM...[/bold blue]"
                        )

                    async with LLMAnalyzer(config) as analyzer:
                        try:
                            analysis = await analyzer.analyze(
                                cve_info,
                                target_package,
                                release_notes,
                                pkg_current,
                                target_version,
                            )
                        except (ValueError, RuntimeError) as e:
                            console.print(f"[bold red]Error:[/bold red] {e}")
                            sys.exit(1)

                    result = analysis.model_dump()
                    result["ecosystem"] = analysis.ecosystem.value
                    result["risk_level"] = analysis.risk_level.value
                    # Overlay CVEInfo fields for output consistency with --no-llm mode
                    result["severity"] = cve_info.severity.value
                    result["cvss_score"] = cve_info.cvss_score
                    # #13 — overlay estimated-version metadata onto the serialized result
                    result["version_estimated"] = version_was_estimated
                    result["version_estimate_basis"] = estimate_basis
                    result["fix_available"] = True
                    # #17 — overlay ecosystem support fields
                    result["ecosystem_supported"] = ecosystem_supported
                    result["release_notes_available"] = release_notes_available

                # Output this package's results ────────────────────────────────
                json_output = json.dumps(result, indent=2, default=str)

                if output_format == "markdown":
                    output_str = _format_markdown(result)
                elif output_format == "sarif":
                    output_str = _format_sarif(result)
                else:
                    output_str = json_output

                if output:
                    # First package writes; subsequent packages append
                    mode = "w" if not pkg_results else "a"
                    with open(output, mode) as f:
                        f.write(output_str + ("\n" if pkg_results else ""))
                    if output_format == "rich" and not pkg_results:
                        console.print(f"\n[green]Results written to {output}[/green]")
                elif output_format == "json":
                    if len(items_to_process) <= 1:
                        # Single-CVE mode: emit one JSON object immediately (backward-compatible).
                        print(json_output)
                    # Multi-CVE (SBOM/scanner) mode: defer — outer loop emits the full array.
                    # Do NOT fall through to the rich output branch in either case.
                elif output_format in ("markdown", "sarif"):
                    print(output_str)
                else:
                    console.print("\n")
                    _print_rich_results(result)

                pkg_results.append(result)

        return pkg_results

    original_current_version = current_version
    all_results: list[dict] = []
    for finding in items_to_process:
        # Rebind outer variables captured by the run_analysis() closure
        cve_id = finding.cve_id  # noqa: F841 (used via closure)
        forced_package_name = finding.package_name  # noqa: F841
        scanner_current_version = finding.package_version  # noqa: F841
        current_version = original_current_version  # reset per-CVE
        pkg_results = asyncio.run(run_analysis())
        all_results.extend(pkg_results)

    # Multi-CVE (SBOM / scanner) mode: emit a single JSON array for all results.
    # Single-CVE mode already printed its one object inside run_analysis().
    if output_format == "json" and len(items_to_process) > 1:
        print(json.dumps(all_results, indent=2, default=str))

    # CI exit code: exit 1 if ANY CVE meets or exceeds threshold
    if min_exit_risk:
        for r in all_results:
            actual_risk = r.get("risk_level", "")
            if _check_exit_risk(actual_risk, min_exit_risk):
                if output_format == "rich":
                    console.print(
                        f"[bold red]Exiting with code 1:[/bold red] risk level "
                        f"[bold]{actual_risk}[/bold] meets --min-exit-risk threshold ({min_exit_risk})"
                    )
                sys.exit(1)


def _print_release_notes_list(release_notes: list, console: Console) -> None:
    """Print release notes as a formatted list (used in --no-llm mode)."""
    if not release_notes:
        console.print("[dim]  No release notes found in the version range.[/dim]")
        return
    console.print("\n[bold]Release Notes[/bold]")
    for note in release_notes[:10]:
        date_str = f" ({note.date.strftime('%Y-%m-%d')})" if note.date else ""
        console.print(
            f"\n  [bold cyan]v{note.version}[/bold cyan]{date_str} — [dim]{note.source}[/dim]"
        )
        content_lines = note.content.strip().split("\n")
        for line in content_lines[:4]:
            if line.strip():
                console.print(f"    {line.strip()}")
    if len(release_notes) > 10:
        console.print(f"\n  [dim]... and {len(release_notes) - 10} more[/dim]")


def _print_rich_results(result: dict) -> None:
    """Print results with rich formatting."""
    # Risk level color
    risk_level = result.get("risk_level", "unknown")
    risk_colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }
    risk_color = risk_colors.get(risk_level, "white")

    # Header panel
    header = f"""[bold]CVE:[/bold] {result.get('cve_id', 'N/A')}
[bold]Package:[/bold] {result.get('package_name', 'N/A')} ({result.get('ecosystem', 'N/A')})
[bold]Version:[/bold] {result.get('current_version', '?')} → {result.get('target_version', '?')}
[bold]Risk Level:[/bold] [{risk_color}]{risk_level.upper()}[/{risk_color}]"""

    if "confidence" in result:
        header += f"\n[bold]Confidence:[/bold] {result['confidence']:.0%}"

    console.print(Panel(header, title="Risk Analysis", border_style="blue"))

    # Summary
    if result.get("analysis_summary"):
        console.print(Panel(result["analysis_summary"], title="Summary", border_style="dim"))

    # Breaking changes
    breaking_changes = result.get("breaking_changes", [])
    if breaking_changes:
        table = Table(title="Breaking Changes", border_style="red")
        table.add_column("Description", style="white")
        table.add_column("Affected API", style="cyan")
        table.add_column("Migration Hint", style="green")

        for bc in breaking_changes:
            if isinstance(bc, dict):
                table.add_row(
                    bc.get("description", ""),
                    bc.get("affected_api", "-"),
                    bc.get("migration_hint", "-"),
                )

        console.print(table)

    # Migration notes
    migration_notes = result.get("migration_notes", [])
    if migration_notes:
        console.print("\n[bold]Migration Notes:[/bold]")
        for note in migration_notes:
            console.print(f"  • {note}")

    # Deprecations
    deprecations = result.get("deprecations", [])
    if deprecations:
        console.print("\n[bold yellow]Deprecations:[/bold yellow]")
        for dep in deprecations:
            console.print(f"  ⚠ {dep}")

    console.print()


@main.command()
@click.option("--namespace", help="Clear only specific namespace (nvd, osv, releases)")
def clear_cache(namespace: Optional[str]) -> None:
    """Clear the local cache."""
    cache = Cache()
    count = cache.clear(namespace)
    console.print(f"[green]Cleared {count} cache entries[/green]")


@main.command()
@click.argument("cve_id")
@click.option("--no-cache", is_flag=True, help="Bypass cache")
@click.option("--verbose", is_flag=True, help="Enable debug logging")
def info(cve_id: str, no_cache: bool, verbose: bool) -> None:
    """Show CVE information without LLM analysis."""
    setup_logging(verbose)

    config = Config.from_env().with_overrides(no_cache=no_cache, verbose=verbose)
    cache = Cache() if not no_cache else None

    async def run():
        async with CVEResolver(config, cache) as resolver:
            try:
                cve_info = await resolver.resolve(cve_id)
            except ValueError as e:
                console.print(f"[bold red]Error:[/bold red] {e}")
                sys.exit(1)

        console.print(Panel(f"[bold]{cve_info.cve_id}[/bold]", title="CVE Information"))
        console.print(f"[bold]Severity:[/bold] {cve_info.severity.value}")
        if cve_info.cvss_score:
            console.print(f"[bold]CVSS Score:[/bold] {cve_info.cvss_score}")
        if cve_info.published_date:
            console.print(f"[bold]Published:[/bold] {cve_info.published_date.date()}")

        console.print(f"\n[bold]Description:[/bold]\n{cve_info.description}")

        if cve_info.affected_packages:
            console.print(f"\n[bold]Affected Packages ({len(cve_info.affected_packages)}):[/bold]")
            for pkg in cve_info.affected_packages:
                console.print(f"  • {pkg.name} ({pkg.ecosystem.value})")
                if pkg.affected_versions:
                    console.print(f"    Affected: {', '.join(pkg.affected_versions)}")
                if pkg.fixed_versions:
                    console.print(f"    Fixed in: {', '.join(pkg.fixed_versions)}")

        if cve_info.references:
            console.print(f"\n[bold]References:[/bold]")
            for ref in cve_info.references[:10]:  # Limit to 10
                console.print(f"  • {ref}")
            if len(cve_info.references) > 10:
                console.print(f"  ... and {len(cve_info.references) - 10} more")

    asyncio.run(run())


if __name__ == "__main__":
    main()
