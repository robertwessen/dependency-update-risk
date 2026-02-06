# Dependency Update Risk Analyzer

A CLI tool that analyzes breaking change risk for security updates by fetching CVE information, release notes, and using an LLM to assess migration complexity.

## Installation

```bash
pip install -e .
```

## Usage

### Analyze a CVE

```bash
# Basic usage
dep-risk analyze CVE-2023-32681

# With LLM analysis (requires API configuration)
dep-risk analyze CVE-2023-32681 --api-url https://api.openai.com --api-key $OPENAI_API_KEY

# Specify current version
dep-risk analyze CVE-2023-32681 --version 2.30.0

# Output to file
dep-risk analyze CVE-2023-32681 -o results.json

# JSON-only output (no rich formatting)
dep-risk analyze CVE-2023-32681 --json-only
```

### View CVE Information

```bash
# Show CVE info without LLM analysis
dep-risk info CVE-2023-32681
```

### Manage Cache

```bash
# Clear all cache
dep-risk clear-cache

# Clear specific namespace
dep-risk clear-cache --namespace nvd
```

## Configuration

### Environment Variables

- `DEP_RISK_API_KEY`: LLM API key
- `DEP_RISK_API_URL`: LLM API base URL (optional, can use `--api-url`)
- `DEP_RISK_MODEL`: Default model name (default: `gpt-4`)
- `GITHUB_TOKEN`: Optional, for higher GitHub API rate limits

### CLI Options

| Option | Description |
|--------|-------------|
| `--version, -v` | Specify current version (default: N-1 of fix) |
| `--api-url` | LLM API base URL (appends `/v1/chat/completions`) |
| `--api-key` | LLM API key |
| `--model` | Model name to use |
| `--output, -o` | Output file path (default: stdout) |
| `--cache-ttl` | Cache TTL in hours (default: 24) |
| `--no-cache` | Bypass cache, fetch fresh data |
| `--verbose` | Enable debug logging |
| `--package, -p` | Specific package to analyze |
| `--json-only` | Output only JSON |

## Output Format

The tool outputs a JSON object with the following structure:

```json
{
  "cve_id": "CVE-2023-32681",
  "package_name": "requests",
  "ecosystem": "PyPI",
  "current_version": "2.30.0",
  "target_version": "2.31.0",
  "risk_level": "low",
  "confidence": 0.85,
  "breaking_changes": [
    {
      "description": "Description of the breaking change",
      "affected_api": "function_name()",
      "migration_hint": "Use new_function() instead"
    }
  ],
  "migration_notes": [
    "Recommendation for safe update"
  ],
  "deprecations": [
    "Deprecated feature warning"
  ],
  "release_notes_analyzed": 3,
  "analysis_summary": "Human-readable summary"
}
```

### Risk Levels

- **low**: No breaking changes, mostly bug fixes or security patches
- **medium**: Minor breaking changes that affect edge cases, easy migration
- **high**: Significant API changes requiring code modifications
- **critical**: Major architectural changes, extensive migration required

## Data Sources

The tool fetches data from multiple sources:

1. **CVE Information**:
   - [NVD (National Vulnerability Database)](https://nvd.nist.gov/)
   - [OSV (Open Source Vulnerabilities)](https://osv.dev/)

2. **Release Notes**:
   - GitHub Releases API
   - PyPI package registry
   - npm package registry
   - CHANGELOG files from repositories

## Caching

By default, API responses are cached for 24 hours in `~/.cache/dep-risk/`. Use `--no-cache` to fetch fresh data or `--cache-ttl` to adjust the TTL.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check src/
```

## License

MIT
