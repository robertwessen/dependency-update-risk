"""Tests for data models."""

from datetime import datetime, timedelta, timezone

import pytest

from dep_risk.models import (
    AffectedPackage,
    BreakingChange,
    CacheEntry,
    CVEInfo,
    Ecosystem,
    ReleaseNote,
    RiskAnalysis,
    RiskLevel,
    Severity,
)


class TestEcosystem:
    def test_ecosystem_values(self):
        assert Ecosystem.PYPI.value == "PyPI"
        assert Ecosystem.NPM.value == "npm"
        assert Ecosystem.MAVEN.value == "Maven"


class TestSeverity:
    def test_severity_values(self):
        assert Severity.LOW.value == "LOW"
        assert Severity.CRITICAL.value == "CRITICAL"


class TestRiskLevel:
    def test_risk_level_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"


class TestAffectedPackage:
    def test_basic_creation(self):
        pkg = AffectedPackage(
            ecosystem=Ecosystem.PYPI,
            name="requests",
            affected_versions=[">=2.0,<2.31.0"],
            fixed_versions=["2.31.0"],
        )
        assert pkg.name == "requests"
        assert pkg.ecosystem == Ecosystem.PYPI

    def test_default_values(self):
        pkg = AffectedPackage(ecosystem=Ecosystem.NPM, name="lodash")
        assert pkg.affected_versions == []
        assert pkg.fixed_versions == []
        assert pkg.repository_url is None


class TestCVEInfo:
    def test_basic_creation(self):
        cve = CVEInfo(
            cve_id="CVE-2023-32681",
            description="Test vulnerability",
            severity=Severity.HIGH,
            cvss_score=7.5,
        )
        assert cve.cve_id == "CVE-2023-32681"
        assert cve.severity == Severity.HIGH

    def test_default_values(self):
        cve = CVEInfo(cve_id="CVE-2024-0001")
        assert cve.description == ""
        assert cve.affected_packages == []
        assert cve.references == []


class TestReleaseNote:
    def test_basic_creation(self):
        note = ReleaseNote(
            version="2.31.0",
            content="Security fix for CVE-2023-32681",
            source="GitHub Releases",
        )
        assert note.version == "2.31.0"
        assert note.source == "GitHub Releases"


class TestBreakingChange:
    def test_basic_creation(self):
        bc = BreakingChange(
            description="Removed deprecated function foo()",
            affected_api="foo()",
            migration_hint="Use bar() instead",
        )
        assert "foo" in bc.description


class TestRiskAnalysis:
    def test_basic_creation(self):
        analysis = RiskAnalysis(
            cve_id="CVE-2023-32681",
            package_name="requests",
            ecosystem=Ecosystem.PYPI,
            current_version="2.30.0",
            target_version="2.31.0",
            risk_level=RiskLevel.LOW,
            confidence=0.85,
        )
        assert analysis.risk_level == RiskLevel.LOW
        assert analysis.confidence == 0.85

    def test_confidence_bounds(self):
        # Test that confidence is validated
        analysis = RiskAnalysis(
            cve_id="CVE-2023-32681",
            package_name="test",
            ecosystem=Ecosystem.PYPI,
            current_version="1.0.0",
            target_version="1.0.1",
            risk_level=RiskLevel.LOW,
            confidence=0.5,
        )
        assert 0.0 <= analysis.confidence <= 1.0


class TestCacheEntry:
    def test_not_expired(self):
        entry = CacheEntry(data={"test": "data"}, ttl_hours=24)
        assert not entry.is_expired()

    def test_expired(self):
        entry = CacheEntry(
            data={"test": "data"},
            timestamp=datetime.now(timezone.utc) - timedelta(hours=25),
            ttl_hours=24,
        )
        assert entry.is_expired()
