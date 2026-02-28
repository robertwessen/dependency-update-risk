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
