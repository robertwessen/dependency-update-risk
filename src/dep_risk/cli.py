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

from . import __version__
from .analysis import (
    _SUPPORTED_ECOSYSTEMS,
    _estimate_previous_version,
    _format_markdown,
    _format_sarif,
    _fuzzy_match_package,
    run_cve_analysis,
)
from .config import Cache, Config
from .cve_resolver import CVEResolver
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


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _check_exit_risk(actual_risk: str, threshold: str) -> bool:
    """Return True if actual_risk meets or exceeds threshold."""
    if not isinstance(actual_risk, str) or not isinstance(threshold, str):
        return False
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
    elif isinstance(path_or_data, str):
        try:
            with open(path_or_data) as f:
                data = json.load(f)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return []
    else:
        # Non-str / non-dict input (None, int, list, …) — gracefully return empty
        return []

    if not isinstance(data, dict):
        return []

    findings: list[ScannerFinding] = []

    # ── Trivy ─────────────────────────────────────────────────────────────────
    # {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-...",
    #               "PkgName": "requests", "InstalledVersion": "2.27.0"}]}]}
    if "Results" in data:
        for result in data.get("Results") or []:
            if not isinstance(result, dict):
                continue
            for vuln in result.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = vuln.get("VulnerabilityID") or ""
                if vid and vid.upper().startswith("CVE-"):
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
            if not isinstance(match, dict):
                continue
            artifact = match.get("artifact") or {}
            if not isinstance(artifact, dict):
                artifact = {}
            pkg_name = artifact.get("name") or None
            pkg_version = artifact.get("version") or None
            pkg_type = (artifact.get("type") or "").lower()
            ecosystem = _GRYPE_TYPE_TO_ECOSYSTEM.get(pkg_type)

            vuln_block = match.get("vulnerability") or {}
            if not isinstance(vuln_block, dict):
                vuln_block = {}
            vid = vuln_block.get("id") or ""
            cve_found: Optional[str] = None
            if vid and vid.upper().startswith("CVE-"):
                cve_found = vid
            else:
                for related in match.get("relatedVulnerabilities") or []:
                    if not isinstance(related, dict):
                        continue
                    rid = related.get("id") or ""
                    if rid and rid.upper().startswith("CVE-"):
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
            if not isinstance(result, dict):
                continue
            for pkg_entry in result.get("packages") or []:
                if not isinstance(pkg_entry, dict):
                    continue
                pkg_info = pkg_entry.get("package") or {}
                if not isinstance(pkg_info, dict):
                    pkg_info = {}
                pkg_name = pkg_info.get("name") or None
                pkg_version = pkg_info.get("version") or None
                ecosystem = pkg_info.get("ecosystem") or None

                for vuln in pkg_entry.get("vulnerabilities") or []:
                    if not isinstance(vuln, dict):
                        continue
                    vid = vuln.get("id") or ""
                    cve_found = None
                    if vid and vid.upper().startswith("CVE-"):
                        cve_found = vid
                    else:
                        for alias in vuln.get("aliases") or []:
                            if not isinstance(alias, str):
                                continue
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
    components = data.get("components")
    if not isinstance(components, list):
        return packages
    for component in components:
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        if purl and isinstance(purl, str):
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
    raw_pkgs = data.get("packages")
    if not isinstance(raw_pkgs, list):
        return packages
    for pkg in raw_pkgs:
        if not isinstance(pkg, dict):
            continue
        ext_refs = pkg.get("externalRefs")
        if not isinstance(ext_refs, list):
            continue
        for ref in ext_refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("referenceCategory") == "PACKAGE-MANAGER":
                locator = ref.get("referenceLocator") or ""
                if isinstance(locator, str) and locator.startswith("pkg:"):
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
        try:
            with open(input_file) as _f:
                _raw = json.load(_f)
        except FileNotFoundError:
            console.print(f"[bold red]Error:[/bold red] Input file not found: {input_file}")
            raise SystemExit(1)
        except (json.JSONDecodeError, ValueError) as exc:
            console.print(f"[bold red]Error:[/bold red] Input file is not valid JSON: {exc}")
            raise SystemExit(1)
        except (UnicodeDecodeError, OSError) as exc:
            console.print(f"[bold red]Error:[/bold red] Cannot read input file: {exc}")
            raise SystemExit(1)

        if not isinstance(_raw, dict):
            console.print(
                f"[bold red]Error:[/bold red] Input file must contain a JSON object, "
                f"got {type(_raw).__name__}."
            )
            raise SystemExit(1)

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

    # Dispatch each finding to run_cve_analysis() — the analysis module does the work
    original_current_version = current_version
    all_results: list[dict] = []
    is_multi = len(items_to_process) > 1
    for finding in items_to_process:
        pkg_results = asyncio.run(
            run_cve_analysis(
                cve_id=finding.cve_id,
                config=config,
                cache=cache,
                console=console,
                output_format=output_format,
                current_version=original_current_version,
                package_filter=package,
                forced_package_name=finding.package_name,
                scanner_current_version=finding.package_version,
                no_llm=no_llm,
                output_file=output,
                is_multi_item=is_multi,
            )
        )
        all_results.extend(pkg_results)

    # Multi-CVE (SBOM / scanner) mode: emit a single JSON array for all results.
    if output_format == "json" and is_multi:
        print(json.dumps(all_results, indent=2, default=str))

    # CI exit code: exit 1 if ANY result meets or exceeds the risk threshold
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
