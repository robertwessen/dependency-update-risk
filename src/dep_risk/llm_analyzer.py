"""LLM-based risk analyzer using OpenAI-compatible API."""

import json
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import Config
from .models import (
    AffectedPackage,
    BreakingChange,
    CVEInfo,
    ReleaseNote,
    RiskAnalysis,
    RiskLevel,
)

logger = logging.getLogger(__name__)


def _normalize_api_url(base_url: str) -> str:
    """Normalize API URL to end with /v1/chat/completions."""
    parsed = urlparse(base_url)
    path = parsed.path.rstrip("/")
    if path.endswith("/v1/chat/completions") or path.endswith("chat/completions"):
        return base_url.rstrip("/")
    elif path.endswith("/v1"):
        return base_url.rstrip("/") + "/chat/completions"
    else:
        return base_url.rstrip("/") + "/v1/chat/completions"


SYSTEM_PROMPT = """You are an expert software engineer analyzing dependency updates for breaking changes.

Your task is to analyze release notes and changelog entries to identify:
1. Breaking changes (API changes, removed features, behavior changes)
2. Migration complexity and required code changes
3. Deprecations that may affect future updates

When analyzing, consider:
- Function/method signature changes
- Removed or renamed exports
- Changed default values or behaviors
- New required dependencies or configurations
- Database schema changes
- Protocol/wire format changes

Provide your analysis in the following JSON format:
{
    "risk_level": "low|medium|high|critical",
    "confidence": 0.0-1.0,
    "breaking_changes": [
        {
            "description": "Description of the breaking change",
            "affected_api": "Optional: specific API/function affected",
            "migration_hint": "Optional: how to migrate past this change"
        }
    ],
    "migration_notes": ["List of recommendations for updating safely"],
    "deprecations": ["List of deprecation warnings"],
    "summary": "Brief human-readable summary of the analysis"
}

Risk level guidelines:
- low: No breaking changes, mostly bug fixes or security patches
- medium: Minor breaking changes that affect edge cases, easy migration
- high: Significant API changes requiring code modifications
- critical: Major architectural changes, extensive migration required

Be conservative with risk levels - when in doubt, rate higher rather than lower.
Only output valid JSON, no additional text."""


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ≈ 4 chars for English)."""
    return len(text) // 4


def _format_release_notes(notes: list[ReleaseNote], max_tokens: int = 4000) -> str:
    """Format release notes for the LLM prompt, truncating if needed.

    Args:
        notes: List of release notes to format
        max_tokens: Maximum estimated tokens for the release notes section
    """
    if not notes:
        return "No release notes available."

    formatted = []
    total_tokens = 0
    truncated = False

    for note in notes:
        date_str = note.date.strftime("%Y-%m-%d") if note.date else "Unknown date"
        header = f"## Version {note.version} ({date_str}) - Source: {note.source}"
        entry = f"{header}\n\n{note.content}"

        entry_tokens = _estimate_tokens(entry)

        # Check if adding this entry would exceed the limit
        if total_tokens + entry_tokens > max_tokens:
            # Try to include a truncated version of this entry
            remaining_tokens = max_tokens - total_tokens - 100  # Leave room for truncation notice
            if remaining_tokens > 200:  # Only include if we have meaningful space
                max_chars = remaining_tokens * 4
                truncated_content = note.content[:max_chars] + "...[TRUNCATED]"
                entry = f"{header}\n\n{truncated_content}"
                formatted.append(entry)
            truncated = True
            break

        formatted.append(entry)
        total_tokens += entry_tokens

    result = "\n\n---\n\n".join(formatted)

    if truncated:
        remaining = len(notes) - len(formatted)
        if remaining > 0:
            result += f"\n\n[Note: {remaining} additional release note(s) omitted due to length constraints]"

    return result


def _parse_llm_response(response_text: str) -> dict:
    """Parse LLM response into structured data."""
    # Try to extract JSON from the response
    text = response_text.strip()

    # Handle markdown code blocks
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]

    text = text.strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and parsed:
            return parsed
        # LLM returned valid JSON but not a usable object (empty dict, array, scalar) — fall through
        logger.warning(f"LLM response parsed as {type(parsed).__name__}, expected dict; using fallback")
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse LLM response as JSON: {e}")
    # Return a default structure
    return {
            "risk_level": "medium",
            "confidence": 0.3,
            "breaking_changes": [],
            "migration_notes": ["Unable to parse LLM response - manual review recommended"],
            "deprecations": [],
            "summary": f"Analysis parsing failed. Raw response: {response_text[:500]}",
        }


class LLMAnalyzer:
    """Analyze breaking change risk using LLM."""

    def __init__(self, config: Config):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "LLMAnalyzer":
        self._client = httpx.AsyncClient(timeout=120.0)
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    def _build_prompt(
        self,
        cve_info: CVEInfo,
        package: AffectedPackage,
        release_notes: list[ReleaseNote],
        current_version: str,
        target_version: str,
    ) -> str:
        """Build the analysis prompt."""
        # Reserve tokens for: system prompt (~800), response (2000), overhead (500)
        reserved_tokens = 3300
        max_release_notes_tokens = max(1000, self.config.max_context_tokens - reserved_tokens)
        notes_text = _format_release_notes(release_notes, max_tokens=max_release_notes_tokens)

        if self.config.debug:
            logger.info(f"DEBUG: Max context tokens: {self.config.max_context_tokens}")
            logger.info(f"DEBUG: Max release notes tokens: {max_release_notes_tokens}")
            logger.info(f"DEBUG: Release notes estimated tokens: {_estimate_tokens(notes_text)}")

        prompt = f"""Analyze the following dependency update for breaking changes:

## CVE Information
- CVE ID: {cve_info.cve_id}
- Severity: {cve_info.severity.value}
- CVSS Score: {cve_info.cvss_score or 'N/A'}
- Description: {cve_info.description}

## Package Information
- Package: {package.name}
- Ecosystem: {package.ecosystem.value}
- Current Version: {current_version}
- Target Version: {target_version}
- Fixed Versions: {', '.join(package.fixed_versions) if package.fixed_versions else 'N/A'}

## Release Notes
{notes_text}

Please analyze these release notes and provide a breaking change risk assessment."""

        return prompt

    async def analyze(
        self,
        cve_info: CVEInfo,
        package: AffectedPackage,
        release_notes: list[ReleaseNote],
        current_version: str,
        target_version: str,
    ) -> RiskAnalysis:
        """Analyze breaking change risk for a package update."""
        if not self.config.api_url:
            raise ValueError("LLM API URL is required. Set --api-url or DEP_RISK_API_URL")
        if not self.config.api_key:
            raise ValueError("LLM API key is required. Set --api-key or DEP_RISK_API_KEY")

        # Build API URL
        api_url = _normalize_api_url(self.config.api_url)

        prompt = self._build_prompt(
            cve_info, package, release_notes, current_version, target_version
        )

        logger.debug(f"Sending analysis request to {api_url}")

        # Build request payload
        request_payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,  # Low temperature for consistent analysis
            "max_tokens": 2000,
        }

        request_headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        # Debug logging - show full request details
        if self.config.debug:
            logger.info("=" * 60)
            logger.info("DEBUG: LLM API Request")
            logger.info("=" * 60)
            logger.info(f"URL: {api_url}")
            logger.info(f"Method: POST")
            # Mask the API key for security
            masked_headers = {
                k: (v[:15] + "..." + v[-4:] if k == "Authorization" and len(v) > 20 else v)
                for k, v in request_headers.items()
            }
            logger.info(f"Headers: {json.dumps(masked_headers, indent=2)}")
            logger.info(f"Payload:\n{json.dumps(request_payload, indent=2)}")
            logger.info("=" * 60)

        try:
            response = await self._client.post(
                api_url,
                headers=request_headers,
                json=request_payload,
            )

            # Debug logging - show response details
            if self.config.debug:
                logger.info("DEBUG: LLM API Response")
                logger.info("=" * 60)
                logger.info(f"Status Code: {response.status_code}")
                logger.info(f"Response Headers: {dict(response.headers)}")
                logger.info(f"Response Body:\n{response.text}")
                logger.info("=" * 60)

            response.raise_for_status()
            result = response.json()

        except httpx.HTTPStatusError as e:
            # Enhanced error logging for HTTP errors
            error_body = e.response.text
            logger.error(f"LLM API error: {e.response.status_code}")
            if self.config.debug:
                logger.error("DEBUG: Error Response Details")
                logger.error("=" * 60)
                logger.error(f"Status Code: {e.response.status_code}")
                logger.error(f"Response Headers: {dict(e.response.headers)}")
                logger.error(f"Response Body:\n{error_body}")
                logger.error("=" * 60)
            else:
                # Even without debug, show the error body for 400 errors as it's helpful
                logger.error(f"Response body: {error_body[:500]}")
            raise RuntimeError(f"LLM API error: {e.response.status_code} - {error_body}") from e
        except httpx.RequestError as e:
            logger.error(f"LLM API request failed: {e}")
            raise RuntimeError(f"LLM API request failed: {e}") from e

        # Extract response content
        try:
            content = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected LLM response format: {result}")
            raise RuntimeError("Unexpected LLM response format") from e

        # Parse the response
        parsed = _parse_llm_response(content)

        # Build breaking changes list
        breaking_changes = []
        for bc in parsed.get("breaking_changes", []):
            breaking_changes.append(
                BreakingChange(
                    description=bc.get("description", ""),
                    affected_api=bc.get("affected_api"),
                    migration_hint=bc.get("migration_hint"),
                )
            )

        # Parse risk level
        try:
            risk_level = RiskLevel(parsed.get("risk_level", "medium").lower())
        except ValueError:
            risk_level = RiskLevel.MEDIUM

        return RiskAnalysis(
            cve_id=cve_info.cve_id,
            package_name=package.name,
            ecosystem=package.ecosystem,
            current_version=current_version,
            target_version=target_version,
            risk_level=risk_level,
            confidence=min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
            breaking_changes=breaking_changes,
            migration_notes=parsed.get("migration_notes", []),
            deprecations=parsed.get("deprecations", []),
            release_notes_analyzed=len(release_notes),
            analysis_summary=parsed.get("summary", ""),
        )


async def analyze_risk(
    cve_info: CVEInfo,
    package: AffectedPackage,
    release_notes: list[ReleaseNote],
    current_version: str,
    target_version: str,
    config: Config,
) -> RiskAnalysis:
    """Convenience function to analyze risk."""
    async with LLMAnalyzer(config) as analyzer:
        return await analyzer.analyze(
            cve_info, package, release_notes, current_version, target_version
        )
