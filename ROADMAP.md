# dep-risk Improvement Roadmap

Ordered by impact-to-effort ratio. Items at the top deliver the most value for the least work.

---

## ~~#1 — NVD retry + rate limit handling~~ ✅ Done
**Impact:** High | **Effort:** Low

- Add `asyncio.sleep` on 429 responses, honoring the `Retry-After` header
- Add `--nvd-api-key` CLI option for the higher-rate-limit NVD tier
- Prevents silent failures when the NVD API throttles requests

---

## ~~#2 — `--exit-code` flag for CI~~ ✅ Done
**Impact:** High | **Effort:** Low

- Non-zero exit when risk meets or exceeds a threshold
- Flag: `--min-exit-risk [high|critical]`
- ~2-line change after the output block; enables `dep-risk analyze` in CI pipelines

---

## #3 — Config file `~/.dep-risk.toml`
**Impact:** High | **Effort:** Medium

- Use `platformdirs.user_config_dir("dep-risk")` for platform-correct path
- Load order: config file → env vars → CLI flags
- Add `tomli` backport for Python 3.10 (stdlib `tomllib` is 3.11+)
- Lets users persist `--api-url`, `--api-key`, `--model` without env vars

---

## #4 — `dep-risk scan` command
**Impact:** High | **Effort:** High

- Read requirements.txt / package.json / Cargo.lock and extract all dependencies
- Batch-query OSV `/v1/querybatch` endpoint for CVEs across all deps
- Output a rich risk table sorted by severity
- Prerequisite: Item #5 (refactor `analyze()`) should be done first

---

## #5 — Refactor `analyze()` in cli.py
**Impact:** Medium | **Effort:** Medium

- Extract `async def run_cve_analysis()` into a new `analysis.py` module
- CLI handler becomes a thin wrapper (arg parsing + output only)
- Prerequisite for `scan` command (#4) and easier unit testing of core logic

---

## ~~#6 — crates.io + Maven release notes~~ ✅ Done
**Impact:** Medium | **Effort:** Medium

- Add `elif` branches in `fetch_for_package()` for Cargo and Maven ecosystems
- crates.io API is clean and well-documented
- Maven requires a GitHub fallback (no standard release notes endpoint)

---

## ~~#7 — `--format` flag (markdown, SARIF)~~ ✅ Done
**Impact:** Medium | **Effort:** Medium

- Flag: `--format [rich|json|markdown|sarif]`
- SARIF 2.1 maps cleanly to `RiskAnalysis` fields; enables GitHub Code Scanning integration
- No new library required for any format

---

## ~~#8 — Scanner input mode (`--input`)~~ ✅ Done
**Impact:** High | **Effort:** Low

- Accept JSON output from Trivy, Grype, or `osv-scanner` as input: `dep-risk analyze --input trivy.json`
- Extracts CVE IDs from the scan result and runs `analyze` on each
- Positions dep-risk as a "second stage" tool in existing security pipelines — no workflow disruption
- Trivy JSON schema: `Results[].Vulnerabilities[].VulnerabilityID`; Grype schema: `matches[].vulnerability.id`
- OSV-Scanner JSON: `results[].packages[].vulnerabilities[].id`
- Prerequisite: Item #5 (refactor `analyze()`) makes batching cleaner

---

## #9 — GitHub Action (`dep-risk/analyze-action`)
**Impact:** High | **Effort:** Medium

- Publish `dep-risk/analyze-action` to the GitHub Actions Marketplace
- Runs on `pull_request` events triggered by Dependabot or Renovate security updates
- Reads CVE IDs from the PR description or from a Trivy/Grype scan step
- Posts analysis as a PR comment (rich markdown) and uploads SARIF to Code Scanning
- Closes the loop: Dependabot flags the CVE → dep-risk comments "here's what breaks and how to migrate"
- No OSS tool fills this gap today (Adaptly had the idea; it was abandoned Nov 2023)

---

## ~~#10 — Go module support~~ ✅ Done
**Impact:** Medium | **Effort:** Low

- Add `Ecosystem.GO` branch in `fetch_for_package()` using `pkg.go.dev/` API
- `GET https://proxy.golang.org/{module}/@v/list` for version list; GitHub releases as fallback
- Mirrors the crates.io pattern already implemented in #6 — low incremental effort
- Go is the #3 server-side language; no OSS CVE-risk tool covers it today

---

## #11 — Reachability filter (`--codebase-path`)
**Impact:** High | **Effort:** High

- Flag: `--codebase-path .`
- After LLM identifies breaking changes (e.g. "function `requests.get` signature changed"), grep the codebase for call sites
- Report: "2 of 3 breaking changes affect your code at src/api.py:42, src/client.py:17"
- Collapses high risk → low risk when your code doesn't actually use the changed API
- Use `ast.parse` for Python, `@babel/parser` for JS — ecosystem-appropriate static analysis
- Prerequisite: Item #5 (analysis module refactor) required for clean integration

---

## #12 — Maven release notes via GitHub URL fallback
**Impact:** High | **Effort:** Medium
**Source:** AppSec evaluation P0 — correctness gap confirmed by live test

The Maven release notes fetcher currently returns 0 results for any package that does not have a GitHub repository URL embedded in its NVD or OSV metadata. This was confirmed with CVE-2021-44228 (Log4Shell, CVSS 10.0): despite being the highest-profile Java vulnerability in a decade, `dep-risk analyze` reported `"release_notes_analyzed": 0`. The tool still produced output because the LLM fell back on training knowledge, but for CVEs filed after the LLM's training cutoff — exactly the ones a security team needs to understand urgently — the LLM will hallucinate or return empty analysis.

The fix requires two steps: (1) Enrich Maven package metadata with a GitHub URL lookup. When NVD/OSV do not supply a source repository URL, query the Maven Central search API (`search.maven.org/solrsearch`) for the artifact's `scm` block, which almost always contains the GitHub URL. (2) Once a GitHub URL is resolved, the existing `_fetch_github_releases` path already works — Log4j, Spring Boot, Hibernate, and essentially all major Apache/Spring/JetBrains packages are on GitHub. This is the same fallback pattern already used by the crates.io fetcher.

**Implementation notes:**
- `GET https://search.maven.org/solrsearch/select?q=g:{groupId}+AND+a:{artifactId}&rows=1&wt=json`
- Response contains `response.docs[0].latestVersion` and links usable to construct the GitHub URL pattern
- Cache the resolved GitHub URL in the dep-risk disk cache keyed by `{groupId}:{artifactId}` to avoid re-querying Maven Central on every run
- Prerequisite: none; can be implemented as a new `_resolve_maven_github_url()` helper in `release_notes.py`

---

## #13 — `"is_estimated"` flag when current version is guessed
**Impact:** High | **Effort:** Low
**Source:** AppSec evaluation P0 — correctness gap; silent incorrect baseline

When `--version` is not supplied, dep-risk estimates the current version by decrementing the fixed version (e.g., for a fix at `5.4`, it estimates current as `5.3.0`). This estimation is surfaced in the CLI's rich output with a dim note, but the JSON output carries no signal — `current_version` is `"5.3.0"` with no indication it was guessed. A downstream system (CI gate, ticket system, SIEM) consuming the JSON cannot distinguish a user-supplied version from an inferred one.

This matters because the estimated version is frequently wrong. An enterprise running PyYAML `5.1.2` will receive a risk assessment computed for the `5.3.0 → 5.4` range, missing any breaking changes introduced between `5.1.2` and `5.3.0`. The LLM `confidence` score does not capture this uncertainty — it reflects the LLM's confidence in the risk classification, not uncertainty about the version inputs.

**Implementation notes:**
- Add `"version_estimated": bool` to the `RiskAnalysis` Pydantic model (default `False`)
- Set `True` in `cli.py` whenever `_estimate_previous_version()` is used as the source of `current_version`
- Add `"version_estimate_basis"` string field explaining what fixed version the estimate was derived from (e.g. `"decremented from fixed version 5.4"`)
- Surface in all output formats: JSON field, markdown note, SARIF property bag, rich dim annotation (already present, just needs to be driven by the model field)
- Low effort: 2-field Pydantic change + 3 assignment sites in `cli.py`

---

## #14 — Explicit "no fix available" signal in output
**Impact:** High | **Effort:** Low
**Source:** AppSec evaluation P0 — correctness gap; misleading output for unfixable CVEs

When a CVE has no `fixed_versions` in the NVD/OSV record — either because no patch has been released, the package is abandoned, or the CVE is disputed — dep-risk currently returns `"target_version": "unknown"` with an LLM analysis that produces confident-sounding (but fabricated) migration notes. Live example: CVE-2022-42969 against the `py` package (deprecated project with no fix) returned `"risk_level": "low"` and `"confidence": 0.9` with empty migration notes. A security engineer interpreting this as "safe to stay on current version" would be making a risk decision without the key fact: there is no patch to apply.

The correct behavior is a distinct output state: `"fix_available": false`, with a message explaining the situation (no patch exists / package abandoned / CVE disputed). The LLM should not be invoked at all for this case, or should be invoked with an explicit prompt that frames the question as "given there is no fix, what are the user's options?" rather than "what breaks when upgrading?"

**Implementation notes:**
- Add `"fix_available": bool` to `RiskAnalysis` model (default `True`)
- In `cli.py`, check `target_package.fixed_versions` before constructing the LLM prompt; if empty, set `fix_available = False`, set `risk_level = None` or a new sentinel `"unknown"`, and skip the release notes fetch + LLM call
- Output a dedicated `"fix_available": false` block in JSON and a yellow-boxed warning in the rich output
- Consider a `--unfixable-action [warn|error|skip]` flag for CI pipeline control: `error` exits non-zero when no fix exists (enables blocking pipelines on unfixable CVEs)

---

## #15 — `--no-llm` mode for data-restricted environments
**Impact:** High | **Effort:** Medium
**Source:** AppSec evaluation P1 — enterprise adoption blocker; data privacy in regulated industries

dep-risk sends CVE details, package names, installed version strings, and full release note text to an external LLM API. For companies in financial services, healthcare, government contracting, or any environment with a data classification policy, this payload may constitute: internal dependency inventory (competitive intelligence about technology choices), pre-patch vulnerability details before public disclosure windows close, or simply "third-party data sharing" that requires a vendor review.

The Ollama self-hosted path (demonstrated working in this evaluation) solves the data egress problem, but it is not documented as the recommended enterprise deployment and requires operational overhead (GPU/CPU server, model management). A `--no-llm` mode that runs the full CVE resolution + release notes pipeline and returns structured extraction without LLM synthesis gives security teams an immediately deployable option that keeps all data on-premises.

**Implementation notes:**
- Flag: `--no-llm` (or `no_llm = true` in `~/.dep-risk.toml` once #3 is implemented)
- When active: skip `LLMAnalyzer.analyze()` entirely; populate `RiskAnalysis` with `risk_level = None`, `breaking_changes = []`, `migration_notes = []`, `analysis_summary = "LLM analysis disabled (--no-llm)"`
- Still return `release_notes_analyzed`, `deprecations` extracted by structured parsing (if any), and the raw release note URLs — giving engineers the source material to read themselves
- In rich output, print the release notes as a formatted list instead of the LLM summary panel
- Config file integration: `no_llm = true` in `~/.dep-risk.toml` makes the default safe for enterprise deployment

---

## #16 — LLM result caching by input hash (deterministic replay)
**Impact:** High | **Effort:** Medium
**Source:** AppSec evaluation P1 — compliance blocker; non-deterministic output breaks audit trails

Running `dep-risk analyze CVE-2023-32681 --version 2.27.0` twice may produce different `risk_level` values if the LLM's temperature or model version changes between calls. Enterprise change management, SOC 2 audit evidence, and vulnerability management platforms that ingest dep-risk output all require reproducible results — the same CVE + version + release notes should always produce the same risk classification. Non-determinism also erodes trust: a security engineer who notices the tool gives different answers on successive runs will stop trusting either answer.

The dep-risk disk cache already stores HTTP responses (NVD, OSV, GitHub releases). Extending it to cache LLM analysis results keyed by a deterministic hash of the inputs makes LLM calls idempotent: the second call to analyze the same CVE at the same version returns the cached result instantly without an API call.

**Implementation notes:**
- Cache key: `sha256(cve_id + current_version + target_version + sorted(release_note_urls) + model_name)`
- Store the full `RiskAnalysis` JSON in the cache with a TTL (suggested: 30 days, configurable via `~/.dep-risk.toml`)
- Cache is per-user in `~/.cache/dep-risk/llm/` (already using `platformdirs` for other cache paths)
- `--no-cache` bypasses both the HTTP response cache and the LLM cache (useful for "fresh run" in CI)
- LLM temperature: set to `0` (already at `0.1` — lower to `0` for maximum determinism); document that `temperature=0` is the reproducible-output mode

---

## ~~#17 — `"ecosystem_supported"` and `"release_notes_available"` output fields~~ ✅ Done
**Impact:** Medium | **Effort:** Low
**Source:** AppSec evaluation P2 — output clarity; false-positive noise in multi-package CVEs

When dep-risk analyzes a CVE that affects packages in unsupported ecosystems (RubyGems, Debian, RPM, NuGet), it emits a `WARNING: Unknown ecosystem` log line and returns an empty release notes list. The JSON output gives no indication of *why* release notes are 0 — a downstream consumer cannot distinguish "we fetched notes and there were none" from "we don't support this ecosystem." In multi-package CVEs like CVE-2021-23337 (lodash), the lodash-rails (RubyGems) result looks identical in JSON to lodash (npm) except for the note count, forcing engineers to infer the reason.

**Implementation notes:**
- Add two boolean fields to `RiskAnalysis`: `"ecosystem_supported": bool` and `"release_notes_available": bool`
- `ecosystem_supported = False` when `Ecosystem.UNKNOWN` is resolved; `True` for all explicitly handled ecosystems
- `release_notes_available = False` when `release_notes_analyzed == 0` AND `ecosystem_supported == True` (i.e., we tried and found nothing) — helps distinguish "unsupported" from "maintainer doesn't publish release notes"
- Rich output: replace the existing WARNING log with an inline panel note: `⚠ Ecosystem 'RubyGems' not yet supported — release notes unavailable`
- This is a ~10-line change: 2 model fields + 2 assignment sites + 1 output rendering update

---

## ~~#18 — CycloneDX and SPDX SBOM input support (`--input sbom.json`)~~ ✅ Done
**Impact:** High | **Effort:** High
**Source:** AppSec evaluation P2 — feature gap; primary enterprise SCA output format not supported

dep-risk's `--input` flag currently accepts Trivy, Grype, and OSV-Scanner JSON output. Enterprise SCA tools (Black Duck, Snyk, Semgrep, GitHub Advanced Security, FOSSA) output CycloneDX (`.cdx.json`) or SPDX (`.spdx.json`) SBOMs — the two OASIS/Linux Foundation standard formats. A security team whose existing pipeline generates a CycloneDX SBOM cannot feed it directly to dep-risk without running an additional conversion step or running a separate scanner.

Supporting SBOM input positions dep-risk as an SBOM-enrichment tool: given "here is what you have installed" (SBOM), produce "here is what breaks if you apply these CVE patches" (dep-risk output). This is the missing piece between SBOM generation (Syft, cdxgen) and patch prioritization.

**Implementation notes:**
- CycloneDX JSON: `components[].purl` contains `pkg:pypi/requests@2.27.0`, `pkg:npm/lodash@4.17.20`, etc. Parse PURL using `packageurl-python` (add to dependencies) to extract name, version, ecosystem
- SPDX JSON: `packages[].externalRefs[].referenceLocator` contains PURL when `referenceCategory == "PACKAGE-MANAGER"`
- Format detection: check top-level keys — CycloneDX has `"bomFormat": "CycloneDX"`, SPDX has `"spdxVersion"`
- After extracting (name, version, ecosystem) tuples, cross-reference against OSV `/v1/querybatch` to find CVEs for each package (same pipeline as the planned `dep-risk scan` command in #4)
- Prerequisite: #5 (analysis module refactor) and #4 (scan command) — SBOM input is essentially a `scan` with a different manifest format

---

## ~~#19 — Self-contained binary distribution (PyInstaller / Docker image)~~ ✅ Done
**Impact:** Medium | **Effort:** Medium
**Source:** AppSec evaluation P2 — enterprise adoption barrier; deployment friction vs. Go-based comparators

dep-risk requires Python ≥3.10 and 8 dependencies installed in the user's environment. Trivy and Grype — the tools dep-risk is designed to complement — ship as single Go binaries installable via `brew install trivy`, `winget install Anchore.Grype`, or a one-line `curl | sh`. A security engineer who already has Trivy in their pipeline hits an installation friction gap when adding dep-risk: they must install Python, manage a virtual environment or use pipx, and ensure the correct Python version. In enterprises with locked-down workstations, this can be a multi-week procurement and IT ticket process.

Two distribution paths reduce this friction to near-zero:

1. **PyInstaller binary**: `pyinstaller dep_risk/cli.py --onefile --name dep-risk` produces a single executable (~15–25MB) with Python and all dependencies bundled. Built via GitHub Actions on push to `main` for Linux x86_64, Linux arm64, macOS arm64, Windows x64. Attached as GitHub Release assets.

2. **Docker image**: `docker run --rm -v $(pwd):/scan ghcr.io/[owner]/dep-risk:latest analyze CVE-2023-32681 --version 2.27.0`. This is especially relevant for the `--input` workflow where dep-risk is already running in a container alongside Trivy/Grype.

**Implementation notes:**
- PyInstaller: add `pyinstaller` to `[project.optional-dependencies] dev`; add `.github/workflows/release-binaries.yml` triggered on version tags
- Docker: `FROM python:3.12-slim`, `pip install dep-risk==$VERSION`, `ENTRYPOINT ["dep-risk"]`; publish to `ghcr.io` on tag
- The `--api-key` flag means the binary must NOT bundle credentials — document that `DEP_RISK_API_KEY` env var is the secure path for container deployments

---

## ~~#20 — Fuzzy `--package` matching for Maven artifactId~~ ✅ Done
**Impact:** Medium | **Effort:** Medium
**Source:** AppSec evaluation P3 — UX friction; Maven coordinate format unfamiliar to most security engineers

dep-risk requires the full Maven coordinate `groupId:artifactId` format when filtering multi-package CVEs for Maven packages (e.g., `--package "org.apache.logging.log4j:log4j-core"`). Security engineers working from Dependabot alerts, Jira vulnerability tickets, or NVD advisories typically see only the artifactId (`log4j-core`) and are unfamiliar with the Maven groupId convention. Passing `--package log4j-core` currently returns "package not found in affected packages" with no suggestion of the correct format.

The fix has two parts: (1) fuzzy matching — when `--package X` fails an exact match, attempt a case-insensitive substring match on the artifactId portion of each Maven coordinate in the affected packages list; (2) helpful error — when the match fails entirely, print the full coordinates of all affected packages so the engineer can copy-paste the correct one.

**Implementation notes:**
- In `cli.py` package filtering logic: after exact match fails, try `[p for p in packages if p.name.split(":")[-1].lower() == pkg_filter.lower()]`
- If fuzzy match returns exactly one result: use it and print `Note: matched 'log4j-core' to full coordinate 'org.apache.logging.log4j:log4j-core'`
- If fuzzy match returns multiple results (ambiguous): print all matches and ask user to be specific
- If no match: print all affected package names from the CVE record so the user can identify the correct one
- Apply the same fuzzy logic to Go modules (`module/path` → match on last path segment)

---

## #21 — LLM token usage and cost reporting
**Impact:** Low | **Effort:** Low
**Source:** AppSec evaluation P3 — operational visibility; cost predictability at enterprise scale

The LLM API response includes token usage (`input_tokens`, `output_tokens`) for every call. dep-risk currently discards this data. At small scale this is irrelevant, but an enterprise running dep-risk across 50 product teams scanning weekly will want to budget LLM API costs and monitor for runaway usage (e.g., a CVE with 50 affected packages triggering 50 LLM calls in one run).

**Implementation notes:**
- Capture `usage.input_tokens` and `usage.output_tokens` from the LLM response in `llm_analyzer.py`
- Add `"llm_tokens_used": {"input": int, "output": int}` to `RiskAnalysis` model
- In rich output: print a dim footer line `LLM: {input}↑ {output}↓ tokens` (only when `--debug` or a new `--show-costs` flag)
- In JSON output: always include the field so downstream systems can aggregate
- Add a `--cost-per-1k-tokens` option (default `0.0`) that multiplies token count and prints estimated cost — useful for teams building budget dashboards
