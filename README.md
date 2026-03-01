# dep-risk — Dependency Update Risk Analyzer

Analyze the **breaking change risk** of applying a security patch. Given a CVE, dep-risk resolves the affected packages from NVD/OSV, fetches release notes from the official registries and GitHub, then uses an LLM to classify migration complexity and surface any API-breaking changes.

```
dep-risk analyze CVE-2023-32681
dep-risk analyze CVE-2023-32681 --api-url https://api.openai.com/v1 --api-key $KEY
dep-risk analyze CVE-2023-32681 --format json | jq .risk_level
dep-risk analyze --input trivy.json --format json   # batch from scanner output
dep-risk analyze --input sbom.cdx.json              # CycloneDX / SPDX SBOM
dep-risk info CVE-2023-32681                        # raw CVE details, no LLM
```

---

## Installation

```bash
pip install dep-risk
# or from source:
pip install -e .
```

**Requirements:** Python ≥ 3.10.

### Pre-built binaries

Download a single-file binary (no Python required) from [GitHub Releases](https://github.com/robertwessen/dependency-update-risk/releases):

```bash
# macOS arm64
curl -LO https://github.com/robertwessen/dependency-update-risk/releases/latest/download/dep-risk-macos-arm64
chmod +x dep-risk-macos-arm64 && mv dep-risk-macos-arm64 /usr/local/bin/dep-risk

# Linux x86_64
curl -LO https://github.com/robertwessen/dependency-update-risk/releases/latest/download/dep-risk-linux-x86_64
chmod +x dep-risk-linux-x86_64 && mv dep-risk-linux-x86_64 /usr/local/bin/dep-risk
```

### Docker

```bash
docker run --rm \
  -e DEP_RISK_API_URL=https://api.openai.com/v1 \
  -e DEP_RISK_API_KEY=$OPENAI_API_KEY \
  ghcr.io/robertwessen/dep-risk:latest analyze CVE-2023-32681
```

---

## Commands

### `dep-risk analyze` — analyze a CVE

```
dep-risk analyze [CVE_ID] [OPTIONS]
```

Either `CVE_ID` or `--input` is required (not both).

#### Options

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `CVE_ID` | — | — | CVE identifier, e.g. `CVE-2024-3094` |
| `--version, -v VERSION` | — | N-1 of fix | Your currently installed version |
| `--package, -p NAME` | — | all | Filter to one package (supports fuzzy matching for Maven/Go) |
| `--api-url URL` | `DEP_RISK_API_URL` | — | LLM base URL (e.g. `https://api.openai.com/v1`) |
| `--api-key KEY` | `DEP_RISK_API_KEY` | — | LLM API key |
| `--model NAME` | `DEP_RISK_MODEL` | `gpt-4` | Model name |
| `--max-context N` | — | `8192` | Max tokens sent to LLM (use `128000` for GPT-4 Turbo) |
| `--format FORMAT` | — | `rich` | Output format: `rich` \| `json` \| `markdown` \| `sarif` |
| `--no-llm` | — | off | Skip LLM; return structured release notes only |
| `--input FILE` | — | — | Scanner JSON (Trivy/Grype/OSV-Scanner) or SBOM (CycloneDX/SPDX JSON) |
| `--output, -o FILE` | — | stdout | Write results to file |
| `--nvd-api-key KEY` | `DEP_RISK_NVD_API_KEY` | — | NVD API key for higher rate limits |
| `--min-exit-risk LEVEL` | — | — | Exit code 1 if risk ≥ `high` or `critical` (CI use) |
| `--no-cache` | — | off | Bypass cache; fetch fresh data |
| `--cache-ttl HOURS` | — | `24` | Cache time-to-live |
| `--verbose` | — | off | Enable debug logging |
| `--debug` | — | off | Log full LLM request/response bodies |

### `dep-risk info` — inspect a CVE without LLM

```bash
dep-risk info CVE-2023-32681
dep-risk info CVE-2023-32681 --no-cache --verbose
```

Resolves the CVE from NVD and OSV, prints affected packages, severity, CVSS score, published date, and references. No LLM call.

### `dep-risk clear-cache`

```bash
dep-risk clear-cache                  # clear everything
dep-risk clear-cache --namespace nvd  # clear only NVD responses
dep-risk clear-cache --namespace osv
dep-risk clear-cache --namespace releases
```

---

## Examples

### Single CVE, rich output (default)

```bash
dep-risk analyze CVE-2023-32681
```

### Single CVE with LLM, JSON output

```bash
dep-risk analyze CVE-2023-32681 \
  --api-url https://api.openai.com/v1 \
  --api-key $OPENAI_API_KEY \
  --format json
```

### Specify your installed version

```bash
dep-risk analyze CVE-2023-32681 --version 2.27.0 --format json
```

### Filter to one package (CVE affects multiple)

```bash
# Exact name
dep-risk analyze CVE-2021-44228 --package "org.apache.logging.log4j:log4j-core"

# Fuzzy — matches the artifact ID component
dep-risk analyze CVE-2021-44228 --package log4j-core
```

### Scanner input (Trivy / Grype / OSV-Scanner)

```bash
# Run Trivy, then analyze every CVE it found
trivy fs . --format json -o trivy.json
dep-risk analyze --input trivy.json --format json

# Same with Grype
grype . -o json > grype.json
dep-risk analyze --input grype.json
```

### SBOM input (CycloneDX / SPDX)

```bash
# Generate SBOM with Syft, then discover and analyze all CVEs
syft . -o cyclonedx-json > sbom.cdx.json
dep-risk analyze --input sbom.cdx.json --format json

# SPDX format also supported
dep-risk analyze --input sbom.spdx.json
```

### Air-gapped / data-restricted: skip LLM

```bash
dep-risk analyze CVE-2023-32681 --no-llm --format json
```

Returns structured release note metadata without sending data to an external API.

### CI gate: fail build on high-risk CVEs

```bash
dep-risk analyze CVE-2023-32681 \
  --api-url $DEP_RISK_API_URL \
  --api-key $DEP_RISK_API_KEY \
  --format json \
  --min-exit-risk high   # exits 1 if risk is high or critical
echo "exit: $?"
```

### Save results to file

```bash
dep-risk analyze CVE-2023-32681 --format markdown -o report.md
dep-risk analyze CVE-2023-32681 --format sarif -o results.sarif
```

### Self-hosted LLM (Ollama)

```bash
dep-risk analyze CVE-2023-32681 \
  --api-url http://localhost:11434 \
  --api-key ollama \
  --model llama3.1
```

### High-rate NVD API key

```bash
dep-risk analyze CVE-2023-32681 --nvd-api-key $NVD_KEY
# or via environment:
export DEP_RISK_NVD_API_KEY=$NVD_KEY
```

---

## Configuration

### Environment variables

Set these to avoid repeating flags on every invocation:

```bash
export DEP_RISK_API_URL=https://api.openai.com/v1
export DEP_RISK_API_KEY=sk-...
export DEP_RISK_MODEL=gpt-4o
export DEP_RISK_NVD_API_KEY=...   # optional; raises NVD rate limit
export GITHUB_TOKEN=ghp_...       # optional; raises GitHub API rate limit
```

---

## Output formats

### `--format rich` (default)

Human-readable terminal output with colored panels, tables, and progress indicators.

### `--format json`

Single CVE → one JSON object on stdout.
Scanner/SBOM input with multiple CVEs → a JSON **array** of objects.

```json
{
  "cve_id": "CVE-2023-32681",
  "package_name": "requests",
  "ecosystem": "PyPI",
  "current_version": "2.30.0",
  "target_version": "2.31.0",
  "risk_level": "low",
  "confidence": 0.95,
  "fix_available": true,
  "version_estimated": false,
  "version_estimate_basis": null,
  "ecosystem_supported": true,
  "release_notes_available": true,
  "severity": "MEDIUM",
  "cvss_score": 6.1,
  "breaking_changes": [
    {
      "description": "Proxy authentication headers are no longer forwarded on redirect",
      "affected_api": "requests.get() / requests.Session.get()",
      "migration_hint": "Use allow_redirects=False and handle redirects manually if proxy auth is needed"
    }
  ],
  "migration_notes": [
    "Review any code that uses proxy authentication with redirects",
    "No changes needed if you do not use proxies"
  ],
  "deprecations": [],
  "release_notes_analyzed": 1,
  "analysis_summary": "Low risk update. The only breaking change affects proxy authentication on redirects — a narrow edge case. Most users can update safely."
}
```

#### JSON field reference

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier |
| `package_name` | string | Package name as recorded in the CVE database |
| `ecosystem` | string | Package ecosystem: `PyPI`, `npm`, `Maven`, `crates.io`, `Go` |
| `current_version` | string | Version being analyzed from (user-supplied or estimated) |
| `target_version` | string | Fix version to update to (`"unknown"` when no patch exists) |
| `risk_level` | string | `low` \| `medium` \| `high` \| `critical` (absent in `--no-llm` mode) |
| `confidence` | float | LLM confidence in the risk classification, 0–1 (absent in `--no-llm` mode) |
| `fix_available` | bool | `false` when no `fixed_versions` exist in CVE databases |
| `version_estimated` | bool | `true` when `current_version` was computed (not user-supplied) |
| `version_estimate_basis` | string\|null | How the estimate was derived, e.g. `"decremented from fixed version 2.31.0"` |
| `ecosystem_supported` | bool | `false` for NuGet, RubyGems, etc. where release notes are not yet fetched |
| `release_notes_available` | bool | `false` when release notes fetch returned 0 results (even for supported ecosystems) |
| `severity` | string | CVE severity from NVD: `NONE` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `cvss_score` | float\|null | CVSS base score |
| `breaking_changes` | array | List of breaking change objects (see below) |
| `migration_notes` | array | Ordered migration recommendations |
| `deprecations` | array | Deprecation warnings found in release notes |
| `release_notes_analyzed` | int | Number of release note entries read by the LLM |
| `analysis_summary` | string | Human-readable summary of the risk assessment |
| `note` | string | Present only when LLM was skipped; explains why |

#### Breaking change object

```json
{
  "description": "What changed and why it breaks",
  "affected_api": "Optional: specific function/class/option affected",
  "migration_hint": "Optional: how to update your code"
}
```

### `--format markdown`

GitHub-flavored Markdown suitable for PR comments, Confluence, or Notion.

### `--format sarif`

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for upload to GitHub Code Scanning or other SAST platforms.

```bash
dep-risk analyze CVE-2023-32681 --format sarif -o dep-risk.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -F sarif=@dep-risk.sarif \
  -F ref=refs/heads/main \
  -F commit_sha=$(git rev-parse HEAD)
```

---

## Supported ecosystems

| Ecosystem | Release notes source | Fuzzy `--package` |
|-----------|---------------------|-------------------|
| **PyPI** | PyPI JSON API + GitHub Releases | — |
| **npm** | npm registry + GitHub Releases | — |
| **Maven** | Maven Central (SCM URL via Solr) → GitHub Releases | artifactId matching |
| **crates.io** | crates.io API + GitHub Releases | — |
| **Go** | proxy.golang.org + GitHub Releases | last path segment |
| NuGet, RubyGems, etc. | Not yet supported (`ecosystem_supported: false`) | — |

---

## Data sources

### CVE resolution

1. **NVD** (`services.nvd.nist.gov`) — severity, CVSS score, affected package ranges
2. **OSV** (`api.osv.dev`) — better package ecosystem data and fix versions

Both are queried in parallel. NVD provides the base; OSV package data takes precedence when both are available.

### Release notes

Queried in parallel for each affected package:
- GitHub Releases API (primary, when repository URL is known)
- PyPI JSON API (`pypi.org/pypi/{package}/json`)
- npm registry (`registry.npmjs.org/{package}`)
- crates.io API (`crates.io/api/v1/crates/{crate}`)
- proxy.golang.org (`proxy.golang.org/{module}/@v/list`)
- Maven Central Solr search (resolves SCM URL → GitHub)

### Caching

API responses are cached in `~/.cache/dep-risk/` for 24 hours by default. Use `--no-cache` or `--cache-ttl` to control.

---

## Scanner and SBOM input modes

### Scanner input (Trivy, Grype, OSV-Scanner)

Pass the scanner's JSON output via `--input`. dep-risk auto-detects the format.

| Scanner | Detection key | CVE field path |
|---------|--------------|----------------|
| Trivy | `Results` array | `Results[].Vulnerabilities[].VulnerabilityID` |
| Grype | `matches` array | `matches[].vulnerability.id` |
| OSV-Scanner | `results` array | `results[].packages[].vulnerabilities[].id` |

The scanner's reported package name and installed version are used automatically, so `--version` is not required.

### SBOM input (CycloneDX, SPDX)

Pass any CycloneDX JSON or SPDX JSON SBOM. dep-risk extracts packages via their PURLs, queries OSV's batch API to discover which have known CVEs, then analyzes each CVE.

```bash
# Generate and analyze
syft . -o cyclonedx-json | dep-risk analyze --input /dev/stdin --format json

# Save first, then analyze
cdxgen -o sbom.cdx.json .
dep-risk analyze --input sbom.cdx.json
```

**Multi-CVE output:** When `--format json` and multiple CVEs are found, the output is a JSON **array** (not newline-delimited objects).

---

## Using dep-risk from an AI agent

dep-risk is designed to be called from AI coding agents, security automation, and CI pipelines. Recommended integration pattern:

### 1. Check if a dependency update is safe

```bash
# Agent receives a Dependabot alert for CVE-2023-32681 in requests 2.27.0
dep-risk analyze CVE-2023-32681 \
  --version 2.27.0 \
  --api-url $DEP_RISK_API_URL \
  --api-key $DEP_RISK_API_KEY \
  --format json
```

Parse the JSON output:
- `risk_level`: `"low"` → safe to merge; `"high"` / `"critical"` → needs human review
- `breaking_changes`: list what your agent needs to check in the codebase
- `migration_notes`: steps the agent should apply
- `fix_available: false` → no patch exists; flag for manual triage

### 2. Batch-analyze a scanner report

```bash
# Output is a JSON array when multiple CVEs are found
dep-risk analyze --input trivy.json --format json > dep-risk-results.json

# Agent processes results
python -c "
import json, sys
results = json.load(sys.stdin)
high_risk = [r for r in results if r.get('risk_level') in ('high', 'critical')]
print(json.dumps(high_risk, indent=2))
" < dep-risk-results.json
```

### 3. Interpret the output

```python
import subprocess, json

def analyze_cve(cve_id: str, version: str, api_url: str, api_key: str) -> dict:
    result = subprocess.run(
        ["dep-risk", "analyze", cve_id,
         "--version", version,
         "--api-url", api_url,
         "--api-key", api_key,
         "--format", "json"],
        capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)

data = analyze_cve("CVE-2023-32681", "2.27.0", api_url, api_key)

if not data["fix_available"]:
    print("No patch available — consider replacing or mitigating")
elif data["risk_level"] in ("high", "critical"):
    for change in data["breaking_changes"]:
        print(f"BREAKING: {change['description']}")
        if change.get("migration_hint"):
            print(f"  Fix: {change['migration_hint']}")
else:
    print(f"Safe to update (risk: {data['risk_level']})")
```

### 4. Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Risk level meets `--min-exit-risk` threshold, or fatal error |

### 5. Handling `--no-llm` mode

When `--no-llm` is set, the `risk_level` and `confidence` fields are **absent** from the JSON output. Always check for their presence:

```python
risk = data.get("risk_level")  # may be None
if risk is None:
    # LLM was skipped — use release notes to make decision
    notes_count = data.get("release_notes_analyzed", 0)
```

---

## Risk levels

| Level | Meaning | Recommended action |
|-------|---------|-------------------|
| `low` | No breaking changes; mostly bug fixes or security patches | Merge safely |
| `medium` | Minor breaking changes; edge cases; easy migration | Review `migration_notes`, then merge |
| `high` | Significant API changes; code modifications required | Apply `migration_notes`, test, then merge |
| `critical` | Major architectural changes; extensive migration | Schedule dedicated migration sprint |

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run unit tests (fast, no network)
pytest tests/ --ignore=tests/integration

# Run integration tests (requires network + optional LLM keys)
pytest tests/integration --integration

# Run linting
ruff check src/

# Type checking
mypy src/dep_risk/
```

---

## Architecture

```
dep_risk/
├── cli.py          — Click commands; input parsing (scanner/SBOM); thin dispatch loop
├── analysis.py     — Core async CVE analysis: resolves CVE → fetches notes → LLM → result dict
├── cve_resolver.py — NVD + OSV API client with retry and caching
├── release_notes.py — Multi-source release note fetcher (PyPI, npm, crates.io, Maven, Go)
├── llm_analyzer.py — OpenAI-compatible LLM client; builds prompt; parses JSON response
├── models.py       — Pydantic models: CVEInfo, RiskAnalysis, AffectedPackage, …
└── config.py       — Config dataclass; Cache with disk persistence
```

`analysis.run_cve_analysis()` is importable directly for programmatic use:

```python
import asyncio
from rich.console import Console
from dep_risk.analysis import run_cve_analysis
from dep_risk.config import Config, Cache

async def main():
    config = Config.from_env()
    cache = Cache()
    results = await run_cve_analysis(
        cve_id="CVE-2023-32681",
        config=config,
        cache=cache,
        console=Console(),
        output_format="json",
        current_version="2.27.0",
        no_llm=False,
    )
    for r in results:
        print(r["risk_level"], r["package_name"])

asyncio.run(main())
```

---

## License

MIT
