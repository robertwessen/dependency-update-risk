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

## #6 — crates.io + Maven release notes
**Impact:** Medium | **Effort:** Medium

- Add `elif` branches in `fetch_for_package()` for Cargo and Maven ecosystems
- crates.io API is clean and well-documented
- Maven requires a GitHub fallback (no standard release notes endpoint)

---

## #7 — `--format` flag (markdown, SARIF)
**Impact:** Medium | **Effort:** Medium

- Flag: `--format [rich|json|markdown|sarif]`
- SARIF 2.1 maps cleanly to `RiskAnalysis` fields; enables GitHub Code Scanning integration
- No new library required for any format
