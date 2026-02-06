"""Tests for CVE resolver."""

import pytest

from dep_risk.cve_resolver import _parse_ecosystem, _extract_severity
from dep_risk.models import Ecosystem, Severity


class TestParseEcosystem:
    def test_pypi(self):
        assert _parse_ecosystem("PyPI") == Ecosystem.PYPI
        assert _parse_ecosystem("pypi") == Ecosystem.PYPI

    def test_npm(self):
        assert _parse_ecosystem("npm") == Ecosystem.NPM
        assert _parse_ecosystem("NPM") == Ecosystem.NPM

    def test_maven(self):
        assert _parse_ecosystem("Maven") == Ecosystem.MAVEN

    def test_cargo(self):
        assert _parse_ecosystem("crates.io") == Ecosystem.CARGO
        assert _parse_ecosystem("cargo") == Ecosystem.CARGO

    def test_unknown(self):
        assert _parse_ecosystem("unknown-ecosystem") == Ecosystem.UNKNOWN


class TestExtractSeverity:
    def test_cvss_v31(self):
        data = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            }
        }
        severity, score = _extract_severity(data)
        assert severity == Severity.HIGH
        assert score == 7.5

    def test_cvss_v30_fallback(self):
        data = {
            "metrics": {
                "cvssMetricV30": [
                    {
                        "cvssData": {
                            "baseScore": 5.0,
                            "baseSeverity": "MEDIUM",
                        }
                    }
                ]
            }
        }
        severity, score = _extract_severity(data)
        assert severity == Severity.MEDIUM
        assert score == 5.0

    def test_no_metrics(self):
        data = {"metrics": {}}
        severity, score = _extract_severity(data)
        assert severity == Severity.UNKNOWN
        assert score is None
