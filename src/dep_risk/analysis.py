"""Core CVE analysis logic — importable by CLI and future commands (scan, API server, etc.)."""

import json
import logging
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Cache, Config
from .cve_resolver import CVEResolver
from .llm_analyzer import LLMAnalyzer
from .models import Ecosystem, RiskLevel
from .release_notes import ReleaseNotesFetcher

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}

_SUPPORTED_ECOSYSTEMS: frozenset = frozenset(
    {Ecosystem.PYPI, Ecosystem.NPM, Ecosystem.MAVEN, Ecosystem.CARGO, Ecosystem.GO}
)


# ── Output formatters ─────────────────────────────────────────────────────────

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


# ── Display helpers ───────────────────────────────────────────────────────────

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


def _print_rich_results(result: dict, console: Console) -> None:
    """Print results with rich formatting."""
    risk_level = result.get("risk_level", "unknown")
    risk_colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }
    risk_color = risk_colors.get(risk_level, "white")

    header = f"""[bold]CVE:[/bold] {result.get('cve_id', 'N/A')}
[bold]Package:[/bold] {result.get('package_name', 'N/A')} ({result.get('ecosystem', 'N/A')})
[bold]Version:[/bold] {result.get('current_version', '?')} → {result.get('target_version', '?')}
[bold]Risk Level:[/bold] [{risk_color}]{risk_level.upper()}[/{risk_color}]"""

    if "confidence" in result:
        header += f"\n[bold]Confidence:[/bold] {result['confidence']:.0%}"

    console.print(Panel(header, title="Risk Analysis", border_style="blue"))

    if result.get("analysis_summary"):
        console.print(Panel(result["analysis_summary"], title="Summary", border_style="dim"))

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

    migration_notes = result.get("migration_notes", [])
    if migration_notes:
        console.print("\n[bold]Migration Notes:[/bold]")
        for note in migration_notes:
            console.print(f"  • {note}")

    deprecations = result.get("deprecations", [])
    if deprecations:
        console.print("\n[bold yellow]Deprecations:[/bold yellow]")
        for dep in deprecations:
            console.print(f"  ⚠ {dep}")

    console.print()


# ── Version estimation ─────────────────────────────────────────────────────────

def _estimate_previous_version(fixed_version: str) -> tuple[Optional[str], bool]:
    """Estimate the version just before the fix.

    Returns (estimated_version, is_ambiguous).  None means no reliable estimate.
    """
    from packaging.version import Version, InvalidVersion

    try:
        v = Version(fixed_version)
    except (InvalidVersion, TypeError):
        return None, True

    major, minor, micro = v.major, v.minor, v.micro
    if micro > 0:
        return f"{major}.{minor}.{micro - 1}", False   # unambiguous patch decrement
    elif minor > 0:
        return f"{major}.{minor - 1}.0", True          # plausible but may skip versions
    else:
        return None, True                               # X.0.0 — can't reliably guess


# ── Package filter ────────────────────────────────────────────────────────────

def _fuzzy_match_package(pkg_filter: str, candidates: list) -> tuple[list, bool]:
    """Match a package filter string against a list of AffectedPackage objects.

    Returns (matched_packages, was_fuzzy).  Exact match wins; falls back to
    case-insensitive substring match on the last path/coordinate segment.
    """
    if not isinstance(pkg_filter, str):
        return [], False

    # Case-insensitive exact match first (was_fuzzy=False)
    filter_lower = pkg_filter.lower()
    exact = [p for p in candidates if p.name.lower() == filter_lower]
    if exact:
        return exact, False

    # Fuzzy: compare filter against the artifact/last segment of the name
    # Maven: "org.example:artifact" → "artifact"
    # Go:    "github.com/owner/repo" → "repo"
    fuzzy = [
        p for p in candidates
        if p.name.split(":")[-1].split("/")[-1].lower() == filter_lower
    ]
    return fuzzy, bool(fuzzy)


# ── Main analysis function ────────────────────────────────────────────────────

async def run_cve_analysis(
    *,
    cve_id: str,
    config: Config,
    cache: Optional[Cache],
    console: Console,
    output_format: str = "rich",
    current_version: Optional[str] = None,
    package_filter: Optional[str] = None,
    forced_package_name: Optional[str] = None,
    scanner_current_version: Optional[str] = None,
    no_llm: bool = False,
    output_file: Optional[str] = None,
    is_multi_item: bool = False,
) -> list[dict]:
    """Resolve one CVE and analyze all (or the filtered) affected packages.

    Returns a list of result dicts — one per package analyzed.

    Args:
        cve_id: The CVE identifier (e.g. "CVE-2024-3094").
        config: Resolved configuration (API keys, model, cache settings).
        cache: Optional disk cache instance; pass None to disable caching.
        console: Rich console for progress output (progress only — result
            display is handled by the caller).
        output_format: One of "rich", "json", "markdown", "sarif".  Controls
            progress message visibility and per-result output.
        current_version: User-supplied current version (--version flag).  When
            None, the function estimates from the fixed version.
        package_filter: Restrict analysis to a single package (--package flag).
        forced_package_name: Package name provided by a scanner finding.  Used
            for fuzzy matching when the scanner and CVE DB use different names.
        scanner_current_version: Installed version from a scanner finding.
            Takes precedence over the estimated version; lower priority than
            current_version.
        no_llm: Skip LLM analysis entirely; return structured data only.
        output_file: If set, write per-package output to this file path.
        is_multi_item: True when this call is part of a multi-CVE batch (SBOM /
            scanner input).  Controls whether JSON is emitted inline or deferred
            to the caller for array wrapping.
    """
    # Step 1: Resolve CVE ─────────────────────────────────────────────────────
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

    # Step 2: Select which packages to analyze ────────────────────────────────
    if package_filter:
        matches, was_fuzzy = _fuzzy_match_package(package_filter, cve_info.affected_packages)
        if not matches:
            console.print(
                f"[bold red]Error:[/bold red] Package '{package_filter}' not found in affected packages"
            )
            available = [p.name for p in cve_info.affected_packages]
            console.print(f"Available packages: {', '.join(available)}")
            sys.exit(1)
        elif was_fuzzy and len(matches) > 1:
            console.print(
                f"[bold red]Error:[/bold red] Ambiguous package '{package_filter}' — "
                f"multiple matches found:"
            )
            for m in matches:
                console.print(f"  • {m.name}")
            console.print("Use the full package coordinate with --package.")
            sys.exit(1)
        else:
            if was_fuzzy and output_format == "rich":
                console.print(
                    f"[dim]Note: matched '{package_filter}' to full coordinate "
                    f"'{matches[0].name}'[/dim]"
                )
            packages_to_analyze = matches
    elif forced_package_name:
        matches, was_fuzzy = _fuzzy_match_package(
            forced_package_name, cve_info.affected_packages
        )
        if not matches:
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
        packages_to_analyze = cve_info.affected_packages
        if len(packages_to_analyze) > 1 and output_format == "rich":
            console.print(
                f"[dim]CVE affects {len(packages_to_analyze)} package(s) — analyzing all. "
                f"Use --package to focus on one.[/dim]"
            )

    # Step 3: Fetch release notes and analyze each package ────────────────────
    pkg_results: list[dict] = []

    async with ReleaseNotesFetcher(config, cache) as fetcher:
        for target_package in packages_to_analyze:
            # Version priority: --version > scanner installed > estimate
            if current_version:
                pkg_current = current_version
            elif scanner_current_version:
                pkg_current = scanner_current_version
            else:
                pkg_current = None

            target_version = (
                target_package.fixed_versions[0]
                if target_package.fixed_versions
                else "unknown"
            )

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

            fix_available = target_version != "unknown"

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

            ecosystem_supported = target_package.ecosystem in _SUPPORTED_ECOSYSTEMS
            release_notes_available = len(release_notes) > 0
            if not ecosystem_supported and output_format == "rich":
                console.print(
                    f"  [dim]⚠ Ecosystem '{target_package.ecosystem.value}' not yet "
                    f"supported — release notes unavailable[/dim]"
                )

            # Step 4: LLM analysis ────────────────────────────────────────────
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
            elif no_llm or not config.api_url or not config.api_key:
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
                result["severity"] = cve_info.severity.value
                result["cvss_score"] = cve_info.cvss_score
                result["version_estimated"] = version_was_estimated
                result["version_estimate_basis"] = estimate_basis
                result["fix_available"] = True
                result["ecosystem_supported"] = ecosystem_supported
                result["release_notes_available"] = release_notes_available

            # Output this package's result ─────────────────────────────────────
            json_output = json.dumps(result, indent=2, default=str)

            if output_format == "markdown":
                output_str = _format_markdown(result)
            elif output_format == "sarif":
                output_str = _format_sarif(result)
            else:
                output_str = json_output

            if output_file:
                mode = "w" if not pkg_results else "a"
                with open(output_file, mode) as f:
                    f.write(output_str + ("\n" if pkg_results else ""))
                if output_format == "rich" and not pkg_results:
                    console.print(f"\n[green]Results written to {output_file}[/green]")
            elif output_format == "json":
                if not is_multi_item:
                    print(json_output)
            elif output_format in ("markdown", "sarif"):
                print(output_str)
            else:
                console.print("\n")
                _print_rich_results(result, console)

            pkg_results.append(result)

    return pkg_results
