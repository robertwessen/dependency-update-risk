"""CLI entry point for dependency risk analyzer."""

import asyncio
import json
import logging
import sys
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Cache, Config
from .cve_resolver import CVEResolver
from .llm_analyzer import LLMAnalyzer
from .models import RiskLevel
from .release_notes import ReleaseNotesFetcher

console = Console()


def setup_logging(verbose: bool) -> None:
    """Configure logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


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


def _parse_scanner_input(path: str) -> list[str]:
    """Extract CVE IDs from Trivy, Grype, or OSV-Scanner JSON output."""
    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, dict):
        return []

    cve_ids: list[str] = []

    # Trivy: {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-..."}]}]}
    if "Results" in data:
        for result in data.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                vid = vuln.get("VulnerabilityID", "")
                if vid.upper().startswith("CVE-"):
                    cve_ids.append(vid)

    # Grype: primary id is often a GHSA id; CVE appears in relatedVulnerabilities
    # {"matches": [{"vulnerability": {"id": "GHSA-..."}, "relatedVulnerabilities": [{"id": "CVE-..."}]}]}
    elif "matches" in data:
        for match in data.get("matches") or []:
            vid = match.get("vulnerability", {}).get("id", "")
            if vid.upper().startswith("CVE-"):
                cve_ids.append(vid)
            else:
                for related in match.get("relatedVulnerabilities") or []:
                    rid = related.get("id", "")
                    if rid.upper().startswith("CVE-"):
                        cve_ids.append(rid)

    # OSV-Scanner: {"results": [{"packages": [{"vulnerabilities": [{"id": "GHSA-...", "aliases": ["CVE-..."]}]}]}]}
    # The top-level id is an OSV/GHSA id; the CVE appears in the aliases list.
    elif "results" in data:
        for result in data.get("results") or []:
            for pkg in result.get("packages") or []:
                for vuln in pkg.get("vulnerabilities") or []:
                    vid = vuln.get("id", "")
                    if vid.upper().startswith("CVE-"):
                        cve_ids.append(vid)
                    else:
                        for alias in vuln.get("aliases") or []:
                            if alias.upper().startswith("CVE-"):
                                cve_ids.append(alias)

    # Deduplicate preserving order
    seen: set[str] = set()
    unique = []
    for vid in cve_ids:
        if vid not in seen:
            seen.add(vid)
            unique.append(vid)
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
    help="Scanner JSON file (Trivy, Grype, or OSV-Scanner output) — analyze all CVEs found",
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

    # Build list of CVEs to process
    if input_file:
        cve_ids_to_process = _parse_scanner_input(input_file)
        if not cve_ids_to_process:
            console.print("[bold yellow]Warning:[/bold yellow] No CVE IDs found in scanner input file.")
            return
        if output_format == "rich" and len(cve_ids_to_process) > 1:
            console.print(
                f"[bold blue]Found {len(cve_ids_to_process)} CVEs in scanner output.[/bold blue]"
            )
    else:
        cve_ids_to_process = [cve_id]

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

    async def run_analysis():
        nonlocal current_version  # Allow modification of outer variable

        # Step 1: Resolve CVE
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

        # Select package to analyze
        target_package = None
        if package:
            for pkg in cve_info.affected_packages:
                if pkg.name.lower() == package.lower():
                    target_package = pkg
                    break
            if not target_package:
                console.print(
                    f"[bold red]Error:[/bold red] Package '{package}' not found in affected packages"
                )
                available = [p.name for p in cve_info.affected_packages]
                console.print(f"Available packages: {', '.join(available)}")
                sys.exit(1)
        else:
            target_package = cve_info.affected_packages[0]
            if len(cve_info.affected_packages) > 1 and output_format == "rich":
                console.print(
                    f"[dim]Multiple packages affected. Using first: {target_package.name}[/dim]"
                )
                console.print("[dim]Use --package to specify a different one[/dim]")

        # Determine versions
        target_version = (
            target_package.fixed_versions[0] if target_package.fixed_versions else "unknown"
        )
        version_is_ambiguous = False
        if not current_version:
            if target_package.fixed_versions:
                estimated, version_is_ambiguous = _estimate_previous_version(
                    target_package.fixed_versions[0]
                )
                if estimated is None:
                    if output_format == "rich":
                        console.print(
                            f"[bold yellow]Warning:[/bold yellow] Cannot estimate previous version for "
                            f"{target_package.fixed_versions[0]} (likely a major version boundary). "
                            f"Use --version to specify your current version."
                        )
                    current_version = "unknown"
                else:
                    current_version = estimated
                    if version_is_ambiguous and output_format == "rich":
                        console.print(
                            f"[dim]Note: Version {current_version} is an estimate. Use --version for accuracy.[/dim]"
                        )
            else:
                current_version = "unknown"

        if output_format == "rich":
            console.print(f"\n[bold blue]Analyzing {target_package.name}...[/bold blue]")
            console.print(f"  Current version: {current_version}")
            console.print(f"  Target version: {target_version}")

        # Step 2: Fetch release notes
        if output_format == "rich":
            console.print(f"\n[bold blue]Fetching release notes...[/bold blue]")

        async with ReleaseNotesFetcher(config, cache) as fetcher:
            release_notes = await fetcher.fetch_for_package(
                target_package,
                start_version=current_version,
                end_version=target_version,
            )

        if output_format == "rich":
            console.print(f"  Found {len(release_notes)} release note(s)")

        # Step 3: Analyze with LLM
        if not api_url or not api_key:
            console.print(
                "[bold yellow]Warning:[/bold yellow] LLM API not configured. "
                "Set --api-url and --api-key or environment variables."
            )
            console.print("Skipping LLM analysis.")
            # Output basic info
            result = {
                "cve_id": cve_info.cve_id,
                "package_name": target_package.name,
                "ecosystem": target_package.ecosystem.value,
                "current_version": current_version,
                "target_version": target_version,
                "severity": cve_info.severity.value,
                "cvss_score": cve_info.cvss_score,
                "release_notes_found": len(release_notes),
                "note": "LLM analysis skipped - API not configured",
            }
        else:
            if output_format == "rich":
                console.print(f"\n[bold blue]Analyzing breaking changes with LLM...[/bold blue]")

            async with LLMAnalyzer(config) as analyzer:
                try:
                    analysis = await analyzer.analyze(
                        cve_info,
                        target_package,
                        release_notes,
                        current_version,
                        target_version,
                    )
                except (ValueError, RuntimeError) as e:
                    console.print(f"[bold red]Error:[/bold red] {e}")
                    sys.exit(1)

            result = analysis.model_dump()
            result["ecosystem"] = analysis.ecosystem.value
            result["risk_level"] = analysis.risk_level.value

        # Output results
        json_output = json.dumps(result, indent=2, default=str)

        if output_format == "markdown":
            output_str = _format_markdown(result)
        elif output_format == "sarif":
            output_str = _format_sarif(result)
        else:
            output_str = json_output

        if output:
            with open(output, "w") as f:
                f.write(output_str)
            if output_format == "rich":
                console.print(f"\n[green]Results written to {output}[/green]")
        elif output_format == "json":
            print(json_output)
        elif output_format in ("markdown", "sarif"):
            print(output_str)
        else:
            # rich (default)
            console.print("\n")
            _print_rich_results(result)

        return result

    original_current_version = current_version
    all_results = []
    for _cve in cve_ids_to_process:
        cve_id = _cve  # rebind in outer scope; captured by run_analysis() closure
        current_version = original_current_version  # reset per-CVE
        r = asyncio.run(run_analysis())
        if r:
            all_results.append(r)

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
