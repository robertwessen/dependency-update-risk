"""Pydantic data models for dependency risk analysis."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    """Package ecosystem identifiers."""

    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    CARGO = "crates.io"
    NUGET = "NuGet"
    GO = "Go"
    RUBYGEMS = "RubyGems"
    PACKAGIST = "Packagist"
    UNKNOWN = "Unknown"


class Severity(str, Enum):
    """CVE severity levels."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    """Breaking change risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AffectedPackage(BaseModel):
    """Information about an affected package."""

    ecosystem: Ecosystem = Field(description="Package ecosystem (PyPI, npm, etc.)")
    name: str = Field(description="Package name")
    affected_versions: list[str] = Field(
        default_factory=list, description="List of affected version ranges"
    )
    fixed_versions: list[str] = Field(
        default_factory=list, description="List of versions with fixes"
    )
    repository_url: Optional[str] = Field(default=None, description="Source repository URL")


class CVEInfo(BaseModel):
    """CVE metadata and affected packages."""

    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-3094)")
    description: str = Field(default="", description="CVE description")
    severity: Severity = Field(default=Severity.UNKNOWN, description="CVE severity")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score (0-10)")
    published_date: Optional[datetime] = Field(default=None, description="Publication date")
    affected_packages: list[AffectedPackage] = Field(
        default_factory=list, description="List of affected packages"
    )
    references: list[str] = Field(default_factory=list, description="Reference URLs")


class ReleaseNote(BaseModel):
    """Release note for a specific version."""

    version: str = Field(description="Version string")
    date: Optional[datetime] = Field(default=None, description="Release date")
    content: str = Field(description="Release note content")
    source: str = Field(description="Source of the release note (GitHub, PyPI, etc.)")
    url: Optional[str] = Field(default=None, description="URL to the release note")


class BreakingChange(BaseModel):
    """A specific breaking change identified in an update."""

    description: str = Field(description="Description of the breaking change")
    affected_api: Optional[str] = Field(
        default=None, description="Affected API/function/class name"
    )
    migration_hint: Optional[str] = Field(
        default=None, description="Hint for migrating past this change"
    )


class RiskAnalysis(BaseModel):
    """Final risk analysis output."""

    cve_id: str = Field(description="Analyzed CVE identifier")
    package_name: str = Field(description="Package being analyzed")
    ecosystem: Ecosystem = Field(description="Package ecosystem")
    current_version: str = Field(description="Current/starting version")
    target_version: str = Field(description="Target/fixed version")
    risk_level: RiskLevel = Field(description="Overall breaking change risk level")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Model's confidence in the assessment (0-1)"
    )
    breaking_changes: list[BreakingChange] = Field(
        default_factory=list, description="List of identified breaking changes"
    )
    migration_notes: list[str] = Field(
        default_factory=list, description="Recommendations for updating"
    )
    deprecations: list[str] = Field(
        default_factory=list, description="Deprecations to be aware of"
    )
    release_notes_analyzed: int = Field(
        default=0, description="Number of release notes analyzed"
    )
    analysis_summary: str = Field(default="", description="Human-readable summary")
    fix_available: bool = Field(
        default=True,
        description="Whether a fixed version is known for this CVE+package combination",
    )
    version_estimated: bool = Field(
        default=False,
        description="True when current_version was estimated (decremented from fixed version) rather than user-supplied via --version",
    )
    version_estimate_basis: Optional[str] = Field(
        default=None,
        description="Describes what the version estimate was derived from (e.g. 'decremented from fixed version 5.4')",
    )
    ecosystem_supported: bool = Field(
        default=True,
        description="Whether dep-risk has a release notes fetcher for this package's ecosystem",
    )
    release_notes_available: bool = Field(
        default=True,
        description="Whether release notes were successfully retrieved; False means either the ecosystem is unsupported or the maintainer does not publish release notes",
    )


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    from datetime import timezone

    return datetime.now(timezone.utc)


class CacheEntry(BaseModel):
    """Cache entry with timestamp metadata."""

    data: Any = Field(description="Cached data (dict or list)")
    timestamp: datetime = Field(default_factory=_utc_now, description="Cache timestamp")
    ttl_hours: int = Field(default=24, description="TTL in hours")

    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        from datetime import timedelta, timezone

        now = datetime.now(timezone.utc)
        # Handle both naive and aware timestamps
        ts = self.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = now - ts
        return age > timedelta(hours=self.ttl_hours)
