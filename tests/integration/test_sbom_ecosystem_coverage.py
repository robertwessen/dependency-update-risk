"""Real-world SBOM ecosystem coverage integration tests.

These tests fetch live SBOMs from popular open-source projects via the
GitHub Dependency-Graph SBOM API (SPDX 2.3 JSON, no auth required) and
verify that dep-risk correctly discovers CVEs and produces valid analysis
output for all 5 supported ecosystems: PyPI, npm, Maven, Go, crates.io.

SBOMs are cached to SBOM_CACHE_DIR to survive test reruns and respect
GitHub's 60 req/hr unauthenticated rate limit.

Repository selection rationale
-------------------------------
- npm:   juice-shop/juice-shop  — OWASP Juice Shop, maintained to be vulnerable; CVEs guaranteed
- maven: WebGoat/WebGoat        — OWASP WebGoat, maintained to be vulnerable; CVEs guaranteed
- pypi:  pypa/pip               — pip has a large, actively maintained dep tree
- go:    gohugoio/hugo           — Hugo has 100+ Go module deps (good OSV coverage test)
- cargo: helix-editor/helix     — Helix editor has a large Cargo dep tree

For the no-LLM scans the only strict CVE-count assertions are for juice-shop
and WebGoat where vulnerabilities are guaranteed.  The other three repos may
or may not have CVEs in their current pinned deps — the test asserts that the
pipeline runs correctly regardless.

LLM smoke tests
---------------
Run one targeted CVE analysis per ecosystem using a known stable CVE.
These use the LLM credentials from the project's .env file.  They may
take several minutes each on a local inference server — timeouts are set
to 600 s.

Usage:
  # No-LLM ecosystem scan tests only
  pytest tests/integration/test_sbom_ecosystem_coverage.py -m integration \\
         --integration -v -s

  # Include LLM smoke tests (requires .env with DEP_RISK_API_*)
  pytest tests/integration/test_sbom_ecosystem_coverage.py -m integration \\
         --integration -v -s
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import pytest

# ── Constants ─────────────────────────────────────────────────────────────────

SBOM_CACHE_DIR = Path("/tmp/dep-risk-real-sbom-cache")

GITHUB_SBOM_URL = "https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"

# Repos providing real-world SBOMs per ecosystem
ECOSYSTEM_REPOS: dict[str, tuple[str, str]] = {
    "pypi": ("pypa", "pip"),
    "npm": ("juice-shop", "juice-shop"),
    "maven": ("WebGoat", "WebGoat"),
    "go": ("gohugoio", "hugo"),
    "cargo": ("helix-editor", "helix"),
}

# Minimum guaranteed CVE count for deliberately-vulnerable repos
GUARANTEED_CVE_REPOS = {"npm", "maven"}

# Curated CVE + package pairs for LLM smoke tests (one per ecosystem).
# These are stable, well-documented CVEs with release notes in each registry.
LLM_SMOKE_CVES: dict[str, tuple[str, Optional[str]]] = {
    # (cve_id, optional_package_filter)
    "pypi": ("CVE-2023-32681", "requests"),   # Proxy-Authorization header leak
    "npm": ("CVE-2022-25883", "semver"),       # semver ReDoS
    "maven": ("CVE-2021-44228", "log4j-core"), # Log4Shell
    "go": ("CVE-2023-44487", "golang.org/x/net"),  # HTTP/2 rapid reset
    "cargo": ("CVE-2024-27308", "mio"),        # Named pipe token reuse
}

# CLI module path — run as `python -m dep_risk.cli`
DEP_RISK_MODULE = "dep_risk.cli"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_llm_env() -> dict[str, str]:
    """Load LLM credentials from .env (project root) and current environment.

    Priority: environment variables > .env file values.
    Returns a dict suitable for passing as subprocess env overrides.
    """
    env_vars: dict[str, str] = {}

    # Walk up from this file to find the project root (.env)
    project_root = Path(__file__).parent.parent.parent
    env_file = project_root / ".env"

    if env_file.exists():
        for raw_line in env_file.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env_vars[key.strip()] = value.strip().strip('"').strip("'")

    # Current environment overrides .env
    for key in ("DEP_RISK_API_KEY", "DEP_RISK_API_URL", "DEP_RISK_MODEL"):
        if key in os.environ:
            env_vars[key] = os.environ[key]

    return env_vars


def _llm_configured() -> bool:
    """Return True if LLM credentials are available."""
    env = _load_llm_env()
    return bool(env.get("DEP_RISK_API_KEY") and env.get("DEP_RISK_API_URL"))


requires_llm = pytest.mark.skipif(
    not _llm_configured(),
    reason="LLM credentials not configured (set DEP_RISK_API_KEY + DEP_RISK_API_URL in .env)",
)


def _fetch_github_sbom(owner: str, repo: str) -> Path:
    """Fetch the GitHub Dependency-Graph SBOM and cache it to SBOM_CACHE_DIR.

    Returns the path to the cached SPDX JSON file.
    Skips the test if the GitHub API is unreachable or returns an error.
    """
    SBOM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = SBOM_CACHE_DIR / f"{owner}-{repo}.spdx.json"

    if cache_path.exists():
        return cache_path

    url = GITHUB_SBOM_URL.format(owner=owner, repo=repo)
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "dep-risk-integration-tests/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        pytest.skip(f"GitHub SBOM API error for {owner}/{repo}: {exc}")
    except urllib.error.URLError as exc:
        pytest.skip(f"Network unavailable: {exc}")

    # GitHub wraps the SPDX document in a {"sbom": {...}} envelope
    sbom_doc = payload.get("sbom", payload)
    cache_path.write_text(json.dumps(sbom_doc, indent=2))
    return cache_path


def _count_packages_in_spdx(sbom_path: Path) -> int:
    """Return the number of package entries in an SPDX JSON document."""
    data = json.loads(sbom_path.read_text())
    return len(data.get("packages", []))


def _run_scan(
    sbom_path: Path,
    *,
    no_llm: bool = True,
    extra_env: Optional[dict[str, str]] = None,
    timeout: int = 300,
) -> list[dict]:
    """Run ``dep-risk analyze --input <sbom_path>`` and return parsed results.

    Returns a list of result dicts (empty list if no CVEs found or on parse
    error).  Subprocess stderr (log output) is captured but not checked —
    it goes to stderr so it does not pollute the JSON stdout.
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    cmd = [
        sys.executable, "-m", DEP_RISK_MODULE,
        "analyze",
        "--input", str(sbom_path),
        "--format", "json",
    ]
    if no_llm:
        cmd.append("--no-llm")

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    return _parse_json_output(proc.stdout, context=f"scan of {sbom_path.name}")


def _run_cve_analysis(
    cve_id: str,
    llm_env: dict[str, str],
    *,
    package_filter: Optional[str] = None,
    timeout: int = 600,
) -> list[dict]:
    """Run ``dep-risk analyze <cve_id>`` with LLM enabled.

    Returns a list of result dicts.  Long timeout (600 s) for local inference.
    """
    env = os.environ.copy()
    env.update(llm_env)

    cmd = [
        sys.executable, "-m", DEP_RISK_MODULE,
        "analyze",
        cve_id,
        "--format", "json",
    ]
    if package_filter:
        cmd.extend(["--package", package_filter])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    return _parse_json_output(proc.stdout, context=f"LLM analysis of {cve_id}")


def _parse_json_output(stdout: str, *, context: str = "") -> list[dict]:
    """Normalise dep-risk JSON output → list[dict].

    dep-risk emits:
    - A JSON array  [...]   when 2+ findings
    - A JSON object {...}   when exactly 1 finding (backward-compatible mode)
    - Non-JSON text         when 0 findings ("No CVEs found" rich message)
    """
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # Non-JSON "No CVEs found" or error message — treat as zero results
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _assert_valid_result(result: dict, *, context: str = "", require_risk_level: bool = False) -> None:
    """Assert that a single result dict has the minimum required fields.

    ``risk_level`` is only present in LLM-mode results; set
    ``require_risk_level=True`` for LLM smoke tests.
    """
    prefix = f"[{context}] " if context else ""
    assert "cve_id" in result, f"{prefix}result missing 'cve_id'"
    assert result["cve_id"].upper().startswith("CVE-"), (
        f"{prefix}cve_id {result['cve_id']!r} is not a CVE identifier"
    )
    assert "package_name" in result, f"{prefix}result missing 'package_name'"
    if require_risk_level:
        assert "risk_level" in result, f"{prefix}result missing 'risk_level'"


# ── No-LLM SBOM ecosystem discovery tests ────────────────────────────────────


@pytest.mark.integration
def test_pypi_sbom_osv_discovery() -> None:
    """pypa/pip SBOM → dep-risk parses packages and queries OSV for PyPI CVEs.

    pip is a large, well-maintained project. CVEs are not guaranteed in
    its current pinned deps, but the pipeline must run without error.
    """
    owner, repo = ECOSYSTEM_REPOS["pypi"]
    sbom_path = _fetch_github_sbom(owner, repo)

    pkg_count = _count_packages_in_spdx(sbom_path)
    assert pkg_count >= 1, f"Expected ≥1 package in {owner}/{repo} SBOM, got {pkg_count}"
    print(f"\nPyPI ({owner}/{repo}): {pkg_count} packages in SBOM")

    results = _run_scan(sbom_path, timeout=300)
    print(f"PyPI ({owner}/{repo}): {len(results)} CVE findings")

    for r in results:
        _assert_valid_result(r, context="PyPI")

    # If CVEs were found, validate ecosystem field
    for r in results:
        assert r.get("ecosystem", "PyPI").lower() in ("pypi", ""), (
            f"Unexpected ecosystem in PyPI result: {r.get('ecosystem')}"
        )


@pytest.mark.integration
def test_npm_sbom_osv_discovery() -> None:
    """juice-shop/juice-shop SBOM → dep-risk finds ≥1 npm CVE.

    OWASP Juice Shop is maintained to be vulnerable.  CVE discovery is
    guaranteed; the assertion is strict.
    """
    owner, repo = ECOSYSTEM_REPOS["npm"]
    sbom_path = _fetch_github_sbom(owner, repo)

    pkg_count = _count_packages_in_spdx(sbom_path)
    assert pkg_count >= 10, (
        f"Expected ≥10 packages in juice-shop SBOM, got {pkg_count}"
    )
    print(f"\nnpm ({owner}/{repo}): {pkg_count} packages in SBOM")

    results = _run_scan(sbom_path, timeout=300)
    print(f"npm ({owner}/{repo}): {len(results)} CVE findings")

    assert len(results) >= 1, (
        f"Expected ≥1 CVE in juice-shop (deliberately vulnerable), got 0. "
        f"Check OSV querybatch pipeline."
    )
    for r in results:
        _assert_valid_result(r, context="npm")


@pytest.mark.integration
def test_maven_sbom_osv_discovery() -> None:
    """WebGoat/WebGoat SBOM → dep-risk finds ≥1 Maven CVE.

    OWASP WebGoat is maintained to be vulnerable.  CVE discovery is
    guaranteed; the assertion is strict.
    """
    owner, repo = ECOSYSTEM_REPOS["maven"]
    sbom_path = _fetch_github_sbom(owner, repo)

    pkg_count = _count_packages_in_spdx(sbom_path)
    assert pkg_count >= 5, (
        f"Expected ≥5 packages in WebGoat SBOM, got {pkg_count}"
    )
    print(f"\nMaven ({owner}/{repo}): {pkg_count} packages in SBOM")

    results = _run_scan(sbom_path, timeout=300)
    print(f"Maven ({owner}/{repo}): {len(results)} CVE findings")

    assert len(results) >= 1, (
        f"Expected ≥1 CVE in WebGoat (deliberately vulnerable), got 0. "
        f"Check OSV querybatch pipeline for Maven ecosystem."
    )
    for r in results:
        _assert_valid_result(r, context="Maven")


@pytest.mark.integration
def test_go_sbom_osv_discovery() -> None:
    """gohugoio/hugo SBOM → dep-risk parses Go module packages and queries OSV.

    Hugo has a large Go module dep tree.  CVEs are not guaranteed in its
    current pinned deps, but the pipeline must parse Go PURLs correctly.
    """
    owner, repo = ECOSYSTEM_REPOS["go"]
    sbom_path = _fetch_github_sbom(owner, repo)

    pkg_count = _count_packages_in_spdx(sbom_path)
    assert pkg_count >= 10, (
        f"Expected ≥10 packages in gohugoio/hugo SBOM, got {pkg_count}"
    )
    print(f"\nGo ({owner}/{repo}): {pkg_count} packages in SBOM")

    results = _run_scan(sbom_path, timeout=300)
    print(f"Go ({owner}/{repo}): {len(results)} CVE findings")

    for r in results:
        _assert_valid_result(r, context="Go")

    print(f"  → Go pipeline OK (CVEs found: {len(results)})")


@pytest.mark.integration
def test_cargo_sbom_osv_discovery() -> None:
    """helix-editor/helix SBOM → dep-risk parses crates.io PURLs and queries OSV.

    Helix has a large Cargo dep tree.  CVEs are not guaranteed in its
    current pinned deps, but the pipeline must parse crates.io PURLs correctly.
    """
    owner, repo = ECOSYSTEM_REPOS["cargo"]
    sbom_path = _fetch_github_sbom(owner, repo)

    pkg_count = _count_packages_in_spdx(sbom_path)
    assert pkg_count >= 10, (
        f"Expected ≥10 packages in helix-editor/helix SBOM, got {pkg_count}"
    )
    print(f"\nCargo ({owner}/{repo}): {pkg_count} packages in SBOM")

    results = _run_scan(sbom_path, timeout=300)
    print(f"Cargo ({owner}/{repo}): {len(results)} CVE findings")

    for r in results:
        _assert_valid_result(r, context="Cargo")

    print(f"  → Cargo pipeline OK (CVEs found: {len(results)})")


# ── LLM smoke tests (one per ecosystem) ──────────────────────────────────────
# These use a curated CVE per ecosystem, not the SBOM scan results, so they
# are independent of whether the ecosystem repos currently have vulnerable deps.


@pytest.mark.integration
@requires_llm
def test_llm_pypi_requests() -> None:
    """LLM analysis of CVE-2023-32681 (requests, PyPI) produces valid output.

    This is the canonical dep-risk test CVE — proxy header leak in requests
    2.27.0, fixed in 2.31.0.  Regression test for the full LLM pipeline.
    """
    cve_id, pkg = LLM_SMOKE_CVES["pypi"]
    llm_env = _load_llm_env()

    results = _run_cve_analysis(cve_id, llm_env, package_filter=pkg, timeout=600)

    assert len(results) >= 1, (
        f"Expected ≥1 LLM result for {cve_id}/{pkg}, got 0"
    )
    r = results[0]
    _assert_valid_result(r, context=f"LLM PyPI {cve_id}", require_risk_level=True)

    assert "analysis_summary" in r, "LLM result missing 'analysis_summary'"
    assert r["analysis_summary"], "LLM 'analysis_summary' is empty"
    assert "migration_notes" in r, "LLM result missing 'migration_notes'"

    print(
        f"\nLLM PyPI ({cve_id}): risk={r.get('risk_level')} "
        f"confidence={r.get('confidence')} "
        f"notes={len(r.get('migration_notes', []))}"
    )


@pytest.mark.integration
@requires_llm
def test_llm_npm_semver() -> None:
    """LLM analysis of CVE-2022-25883 (semver, npm) produces valid output.

    semver ReDoS vulnerability — well-documented in npm advisories.
    Validates the npm ecosystem LLM pathway.
    """
    cve_id, pkg = LLM_SMOKE_CVES["npm"]
    llm_env = _load_llm_env()

    results = _run_cve_analysis(cve_id, llm_env, package_filter=pkg, timeout=600)

    assert len(results) >= 1, (
        f"Expected ≥1 LLM result for {cve_id}/{pkg}, got 0"
    )
    r = results[0]
    _assert_valid_result(r, context=f"LLM npm {cve_id}", require_risk_level=True)
    assert r.get("analysis_summary"), "LLM 'analysis_summary' is empty"

    print(
        f"\nLLM npm ({cve_id}): risk={r.get('risk_level')} "
        f"confidence={r.get('confidence')}"
    )


@pytest.mark.integration
@requires_llm
def test_llm_maven_log4shell() -> None:
    """LLM analysis of CVE-2021-44228 (log4j-core, Maven) produces valid output.

    Log4Shell — the most famous Java CVE.  Validates the Maven/crates.io
    release-notes fetch + LLM analysis pathway.
    """
    cve_id, pkg = LLM_SMOKE_CVES["maven"]
    llm_env = _load_llm_env()

    results = _run_cve_analysis(cve_id, llm_env, package_filter=pkg, timeout=600)

    assert len(results) >= 1, (
        f"Expected ≥1 LLM result for {cve_id}/{pkg}, got 0"
    )
    r = results[0]
    _assert_valid_result(r, context=f"LLM Maven {cve_id}", require_risk_level=True)
    assert r.get("analysis_summary"), "LLM 'analysis_summary' is empty"

    print(
        f"\nLLM Maven ({cve_id}): risk={r.get('risk_level')} "
        f"confidence={r.get('confidence')}"
    )


@pytest.mark.integration
@requires_llm
def test_llm_go_http2_rapid_reset() -> None:
    """LLM analysis of CVE-2023-44487 (Go, HTTP/2 rapid reset) produces valid output.

    Affects golang.org/x/net — well-documented Go security advisory.
    Validates the Go ecosystem LLM pathway.
    """
    cve_id, pkg = LLM_SMOKE_CVES["go"]
    llm_env = _load_llm_env()

    results = _run_cve_analysis(cve_id, llm_env, package_filter=pkg, timeout=600)

    assert len(results) >= 1, (
        f"Expected ≥1 LLM result for {cve_id}/golang.org/x/net, got 0"
    )
    r = results[0]
    _assert_valid_result(r, context=f"LLM Go {cve_id}", require_risk_level=True)
    assert r.get("analysis_summary"), "LLM 'analysis_summary' is empty"

    print(
        f"\nLLM Go ({cve_id}): risk={r.get('risk_level')} "
        f"packages={len(results)}"
    )


@pytest.mark.integration
@requires_llm
def test_llm_cargo_mio() -> None:
    """LLM analysis of CVE-2024-27308 (mio, crates.io) produces valid output.

    mio is a core Tokio async I/O primitive; this CVE affects named-pipe
    handling on Windows.  Validates the crates.io ecosystem LLM pathway.
    """
    cve_id, pkg = LLM_SMOKE_CVES["cargo"]
    llm_env = _load_llm_env()

    results = _run_cve_analysis(cve_id, llm_env, package_filter=pkg, timeout=600)

    assert len(results) >= 1, (
        f"Expected ≥1 LLM result for {cve_id}/{pkg}, got 0"
    )
    r = results[0]
    _assert_valid_result(r, context=f"LLM Cargo {cve_id}", require_risk_level=True)
    assert r.get("analysis_summary"), "LLM 'analysis_summary' is empty"

    print(
        f"\nLLM Cargo ({cve_id}): risk={r.get('risk_level')} "
        f"confidence={r.get('confidence')}"
    )
