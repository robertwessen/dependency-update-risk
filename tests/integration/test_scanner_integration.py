"""Integration tests for scanner JSON input parsing.

These tests run real scanner binaries via Docker against a deterministic
vulnerable target and verify that _parse_scanner_input() correctly extracts
CVE IDs from each tool's actual JSON output format.

Requirements:
  - Docker daemon must be running
  - Run with: pytest tests/integration/ --integration

Version pins — update when a new minor version of each tool is released:

  Tool          Current (latest)   n-1
  ─────────────────────────────────────
  Trivy         0.69.1             0.68.2       (updated 2026-02-27)
  Grype         v0.109.0           v0.108.0     (updated 2026-02-27)
  OSV-Scanner   v2.3.2             v2.3.1       (updated 2026-02-27)
"""

import json
import subprocess
from pathlib import Path

import pytest

from dep_risk.cli import _parse_scanner_input

# ── Version pins ──────────────────────────────────────────────────────────────

TRIVY_VERSIONS = [
    "0.69.1",  # current  — released 2026-02-05
    "0.68.2",  # n-1      — released 2025-12-17
]

GRYPE_VERSIONS = [
    "v0.109.0",  # current  — released 2026-02-19
    "v0.108.0",  # n-1      — released 2026-02-10
]

OSV_SCANNER_VERSIONS = [
    "v2.3.2",  # current  — released 2026-02-23
    "v2.3.1",  # n-1      — released 2025-12-11
]

# ── Vulnerable scan target ────────────────────────────────────────────────────
# Pinned packages with confirmed CVEs in all three scanner databases:
#   requests==2.27.0  →  CVE-2023-32681  (certificate verification bypass)
#   urllib3==1.26.4   →  CVE-2021-33503  (ReDoS in url parsing)

VULNERABLE_REQUIREMENTS = """\
requests==2.27.0
urllib3==1.26.4
"""

# ── Helpers ───────────────────────────────────────────────────────────────────


def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon not available"
)


def _run_scanner(image: str, cmd_args: list[str], mount_dir: Path) -> str:
    """Run a containerised scanner, return stdout.

    Accepts exit codes 0 (clean) and 1 (vulnerabilities found) as success.
    Any other exit code raises RuntimeError with the captured stderr.
    """
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{mount_dir}:/scan:ro", image] + cmd_args,
        capture_output=True,
        text=True,
        timeout=300,  # 5 min ceiling; image pulls can be slow on first run
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"{image} exited {result.returncode}.\nSTDERR: {result.stderr[:1000]}"
        )
    return result.stdout


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def vuln_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Session-scoped directory containing the vulnerable requirements.txt."""
    d = tmp_path_factory.mktemp("scanner_target")
    (d / "requirements.txt").write_text(VULNERABLE_REQUIREMENTS)
    return d


# ── Trivy ─────────────────────────────────────────────────────────────────────


@pytest.mark.integration
@requires_docker
@pytest.mark.parametrize("version", TRIVY_VERSIONS)
def test_trivy_extracts_cve_ids(version: str, vuln_dir: Path, tmp_path: Path) -> None:
    """Trivy fs scan JSON → _parse_scanner_input() returns ≥1 CVE ID."""
    raw = _run_scanner(
        f"aquasec/trivy:{version}",
        # --exit-code 0: don't fail when vulns found (default, explicit for clarity)
        # --quiet: suppress progress bars to stdout
        ["fs", "--format", "json", "--quiet", "--exit-code", "0", "/scan"],
        vuln_dir,
    )

    out_file = tmp_path / f"trivy_{version}.json"
    out_file.write_text(raw)

    findings = _parse_scanner_input(str(out_file))

    assert len(findings) >= 1, (
        f"Trivy {version}: expected ≥1 CVE finding, got 0.\n"
        f"Raw output (first 800 chars):\n{raw[:800]}"
    )
    assert all(f.cve_id.upper().startswith("CVE-") for f in findings), (
        f"Non-CVE IDs slipped through: {[f.cve_id for f in findings]}"
    )
    # Trivy should carry package name and installed version
    assert all(f.package_name for f in findings), (
        f"Trivy {version}: expected package_name to be populated in every finding"
    )
    assert all(f.package_version for f in findings), (
        f"Trivy {version}: expected package_version (InstalledVersion) to be populated"
    )


# ── Grype ─────────────────────────────────────────────────────────────────────


@pytest.mark.integration
@requires_docker
@pytest.mark.parametrize("version", GRYPE_VERSIONS)
def test_grype_extracts_cve_ids(version: str, vuln_dir: Path, tmp_path: Path) -> None:
    """Grype dir scan JSON → _parse_scanner_input() returns ≥1 CVE ID."""
    raw = _run_scanner(
        f"ghcr.io/anchore/grype:{version}",
        # dir:/scan  : scan the mounted directory
        # -o json    : JSON output format
        # NOTE: --quiet intentionally omitted; in Grype v0.109+ it suppresses JSON stdout
        ["dir:/scan", "-o", "json"],
        vuln_dir,
    )

    out_file = tmp_path / f"grype_{version}.json"
    out_file.write_text(raw)

    findings = _parse_scanner_input(str(out_file))

    assert len(findings) >= 1, (
        f"Grype {version}: expected ≥1 CVE finding, got 0.\n"
        f"Raw output (first 800 chars):\n{raw[:800]}"
    )
    assert all(f.cve_id.upper().startswith("CVE-") for f in findings), (
        f"Non-CVE IDs slipped through: {[f.cve_id for f in findings]}"
    )
    # Grype artifact block should carry package name and version
    assert all(f.package_name for f in findings), (
        f"Grype {version}: expected package_name to be populated from artifact"
    )
    assert all(f.package_version for f in findings), (
        f"Grype {version}: expected package_version to be populated from artifact"
    )


# ── OSV-Scanner ───────────────────────────────────────────────────────────────


@pytest.mark.integration
@requires_docker
@pytest.mark.parametrize("version", OSV_SCANNER_VERSIONS)
def test_osv_scanner_extracts_cve_ids(version: str, vuln_dir: Path, tmp_path: Path) -> None:
    """OSV-Scanner JSON (with GHSA ids + CVE aliases) → _parse_scanner_input() returns ≥1 CVE ID.

    OSV-Scanner uses GHSA/OSV IDs as the primary identifier; CVE IDs appear in
    the 'aliases' array.  Our parser checks aliases — this test verifies that
    path works with real tool output.
    """
    raw = _run_scanner(
        f"ghcr.io/google/osv-scanner:{version}",
        # scan subcommand (v2+); --lockfile targets the specific file
        ["scan", "--lockfile", "/scan/requirements.txt", "--format", "json"],
        vuln_dir,
    )

    out_file = tmp_path / f"osv_scanner_{version}.json"
    out_file.write_text(raw)

    findings = _parse_scanner_input(str(out_file))

    assert len(findings) >= 1, (
        f"OSV-Scanner {version}: expected ≥1 CVE finding, got 0.\n"
        f"Reminder: OSV uses GHSA IDs with CVEs in aliases — check aliases support.\n"
        f"Raw output (first 800 chars):\n{raw[:800]}"
    )
    assert all(f.cve_id.upper().startswith("CVE-") for f in findings), (
        f"Non-CVE IDs slipped through: {[f.cve_id for f in findings]}"
    )
    # OSV-Scanner carries package name, version, and ecosystem
    assert all(f.package_name for f in findings), (
        f"OSV-Scanner {version}: expected package_name from package block"
    )
    assert all(f.package_version for f in findings), (
        f"OSV-Scanner {version}: expected package_version from package block"
    )


# ── Schema snapshot tests ─────────────────────────────────────────────────────
# These tests verify that the top-level JSON structure we expect is actually
# present in the output, catching schema changes before they silently break
# the parser.


@pytest.mark.integration
@requires_docker
def test_trivy_output_has_results_key(vuln_dir: Path, tmp_path: Path) -> None:
    """Sanity check: Trivy JSON has the top-level 'Results' key we depend on."""
    raw = _run_scanner(
        f"aquasec/trivy:{TRIVY_VERSIONS[0]}",
        ["fs", "--format", "json", "--quiet", "--exit-code", "0", "/scan"],
        vuln_dir,
    )
    data = json.loads(raw)
    assert "Results" in data, (
        f"Trivy JSON schema changed — 'Results' key missing. Keys: {list(data.keys())}"
    )


@pytest.mark.integration
@requires_docker
def test_grype_output_has_matches_key(vuln_dir: Path, tmp_path: Path) -> None:
    """Sanity check: Grype JSON has the top-level 'matches' key we depend on."""
    raw = _run_scanner(
        f"ghcr.io/anchore/grype:{GRYPE_VERSIONS[0]}",
        ["dir:/scan", "-o", "json"],
        vuln_dir,
    )
    data = json.loads(raw)
    assert "matches" in data, (
        f"Grype JSON schema changed — 'matches' key missing. Keys: {list(data.keys())}"
    )


@pytest.mark.integration
@requires_docker
def test_osv_scanner_output_has_results_key(vuln_dir: Path, tmp_path: Path) -> None:
    """Sanity check: OSV-Scanner JSON has the top-level 'results' key we depend on."""
    raw = _run_scanner(
        f"ghcr.io/google/osv-scanner:{OSV_SCANNER_VERSIONS[0]}",
        ["scan", "--lockfile", "/scan/requirements.txt", "--format", "json"],
        vuln_dir,
    )
    data = json.loads(raw)
    assert "results" in data, (
        f"OSV-Scanner JSON schema changed — 'results' key missing. Keys: {list(data.keys())}"
    )
