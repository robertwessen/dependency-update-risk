"""Tests for CLI."""

from click.testing import CliRunner

from dep_risk.cli import _estimate_previous_version, main


class TestCLI:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Dependency Update Risk Analyzer" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.3.0" in result.output

    def test_analyze_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "CVE_ID" in result.output
        assert "--api-url" in result.output

    def test_info_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--help"])
        assert result.exit_code == 0
        assert "CVE_ID" in result.output

    def test_clear_cache_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["clear-cache", "--help"])
        assert result.exit_code == 0
        assert "--namespace" in result.output

    def test_invalid_cve_format(self):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "invalid-cve"])
        assert result.exit_code != 0
        assert "Invalid CVE ID" in result.output or "Error" in result.output


class TestEstimatePreviousVersion:
    def test_patch_decrement(self):
        assert _estimate_previous_version("2.31.1") == ("2.31.0", False)

    def test_minor_decrement(self):
        assert _estimate_previous_version("2.1.0") == ("2.0.0", True)

    def test_major_boundary_zero_minor(self):
        assert _estimate_previous_version("3.0.0") == (None, True)

    def test_major_boundary_one_zero(self):
        assert _estimate_previous_version("1.0.0") == (None, True)

    def test_patch_one(self):
        assert _estimate_previous_version("1.2.1") == ("1.2.0", False)

    def test_invalid_version(self):
        assert _estimate_previous_version("not-a-version") == (None, True)


class TestMinExitRisk:
    """Tests for --min-exit-risk CI exit code logic."""

    def _make_result(self, risk_level: str) -> dict:
        return {"risk_level": risk_level, "package_name": "requests"}

    def test_high_threshold_exits_on_high(self):
        from dep_risk.cli import _check_exit_risk
        assert _check_exit_risk("high", "high") is True

    def test_high_threshold_exits_on_critical(self):
        from dep_risk.cli import _check_exit_risk
        assert _check_exit_risk("critical", "high") is True

    def test_high_threshold_passes_on_medium(self):
        from dep_risk.cli import _check_exit_risk
        assert _check_exit_risk("medium", "high") is False

    def test_critical_threshold_exits_on_critical(self):
        from dep_risk.cli import _check_exit_risk
        assert _check_exit_risk("critical", "critical") is True

    def test_critical_threshold_passes_on_high(self):
        from dep_risk.cli import _check_exit_risk
        assert _check_exit_risk("high", "critical") is False

    def test_unknown_risk_never_triggers_exit(self):
        from dep_risk.cli import _check_exit_risk
        assert _check_exit_risk("unknown", "high") is False


SAMPLE_RESULT = {
    "cve_id": "CVE-2024-1234",
    "package_name": "requests",
    "ecosystem": "PyPI",
    "current_version": "2.30.0",
    "target_version": "2.31.0",
    "risk_level": "high",
    "confidence": 0.85,
    "breaking_changes": [
        {
            "description": "Removed legacy auth",
            "affected_api": "auth.basic",
            "migration_hint": "Use auth.bearer",
        }
    ],
    "migration_notes": ["Update auth calls"],
    "deprecations": [],
    "analysis_summary": "One breaking change found.",
    "release_notes_analyzed": 3,
}


class TestFormatOutput:
    def test_format_markdown_has_headers(self):
        from dep_risk.cli import _format_markdown
        output = _format_markdown(SAMPLE_RESULT)
        assert "# dep-risk Analysis: CVE-2024-1234" in output
        assert "## Summary" in output
        assert "## Breaking Changes" in output
        assert "## Migration Notes" in output

    def test_format_markdown_skips_empty_sections(self):
        from dep_risk.cli import _format_markdown
        result = {**SAMPLE_RESULT, "breaking_changes": [], "deprecations": [], "migration_notes": []}
        output = _format_markdown(result)
        assert "## Breaking Changes" not in output
        assert "## Migration Notes" not in output
        assert "## Deprecations" not in output

    def test_format_markdown_omits_confidence_when_absent(self):
        from dep_risk.cli import _format_markdown
        result = {k: v for k, v in SAMPLE_RESULT.items() if k != "confidence"}
        output = _format_markdown(result)
        assert "Confidence" not in output

    def test_format_sarif_valid_json(self):
        import json
        from dep_risk.cli import _format_sarif
        output = _format_sarif(SAMPLE_RESULT)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["results"][0]["ruleId"] == "CVE-2024-1234"

    def test_format_sarif_level_high_maps_to_error(self):
        import json
        from dep_risk.cli import _format_sarif
        parsed = json.loads(_format_sarif({**SAMPLE_RESULT, "risk_level": "high"}))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_format_sarif_level_medium_maps_to_warning(self):
        import json
        from dep_risk.cli import _format_sarif
        parsed = json.loads(_format_sarif({**SAMPLE_RESULT, "risk_level": "medium"}))
        assert parsed["runs"][0]["results"][0]["level"] == "warning"

    def test_format_sarif_level_low_maps_to_note(self):
        import json
        from dep_risk.cli import _format_sarif
        parsed = json.loads(_format_sarif({**SAMPLE_RESULT, "risk_level": "low"}))
        assert parsed["runs"][0]["results"][0]["level"] == "note"

    def test_format_sarif_critical_maps_to_error(self):
        import json
        from dep_risk.cli import _format_sarif
        parsed = json.loads(_format_sarif({**SAMPLE_RESULT, "risk_level": "critical"}))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_analyze_help_shows_format_option(self):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert "--format" in result.output

    def test_analyze_help_shows_input_option(self):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert "--input" in result.output


class TestScannerInput:
    """Tests for _parse_scanner_input() — scanner JSON parsing."""

    def test_parses_trivy_json(self, tmp_path):
        import json
        from dep_risk.cli import _parse_scanner_input

        trivy_data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-1234", "PkgName": "requests"},
                        {"VulnerabilityID": "CVE-2024-5678", "PkgName": "flask"},
                    ]
                },
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-9999", "PkgName": "django"},
                    ]
                },
            ]
        }
        f = tmp_path / "trivy.json"
        f.write_text(json.dumps(trivy_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]

    def test_parses_grype_json(self, tmp_path):
        import json
        from dep_risk.cli import _parse_scanner_input

        grype_data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2024-1111"}, "artifact": {"name": "requests"}},
                {"vulnerability": {"id": "CVE-2024-2222"}, "artifact": {"name": "flask"}},
            ]
        }
        f = tmp_path / "grype.json"
        f.write_text(json.dumps(grype_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2024-1111", "CVE-2024-2222"]

    def test_parses_osv_scanner_json(self, tmp_path):
        import json
        from dep_risk.cli import _parse_scanner_input

        osv_data = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "requests"},
                            "vulnerabilities": [
                                {"id": "CVE-2024-3333"},
                                {"id": "CVE-2024-4444"},
                            ],
                        }
                    ]
                }
            ]
        }
        f = tmp_path / "osv.json"
        f.write_text(json.dumps(osv_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2024-3333", "CVE-2024-4444"]

    def test_deduplicates_cve_ids(self, tmp_path):
        import json
        from dep_risk.cli import _parse_scanner_input

        trivy_data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-1234"},
                        {"VulnerabilityID": "CVE-2024-1234"},  # duplicate
                        {"VulnerabilityID": "CVE-2024-5678"},
                    ]
                }
            ]
        }
        f = tmp_path / "trivy_dup.json"
        f.write_text(json.dumps(trivy_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2024-1234", "CVE-2024-5678"]

    def test_filters_non_cve_ids(self, tmp_path):
        import json
        from dep_risk.cli import _parse_scanner_input

        grype_data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2024-1111"}},
                {"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz"}},  # GHSA, not CVE
            ]
        }
        f = tmp_path / "grype_mixed.json"
        f.write_text(json.dumps(grype_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2024-1111"]

    def test_empty_vulnerabilities_returns_empty(self, tmp_path):
        import json
        from dep_risk.cli import _parse_scanner_input

        trivy_data = {"Results": [{"Vulnerabilities": []}]}
        f = tmp_path / "trivy_empty.json"
        f.write_text(json.dumps(trivy_data))

        result = _parse_scanner_input(str(f))
        assert result == []

    def test_osv_scanner_uses_aliases_when_id_is_ghsa(self, tmp_path):
        """Real OSV-Scanner output uses GHSA IDs; CVE IDs are in the aliases list."""
        import json
        from dep_risk.cli import _parse_scanner_input

        osv_data = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "requests", "version": "2.27.0"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-j8r2-6x86-q33q",
                                    "aliases": ["CVE-2023-32681"],
                                    "summary": "Certificate verification bypass",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        f = tmp_path / "osv_real.json"
        f.write_text(json.dumps(osv_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2023-32681"]

    def test_grype_uses_related_vulnerabilities_when_id_is_ghsa(self, tmp_path):
        """Real Grype output uses GHSA IDs as primary; CVE IDs are in relatedVulnerabilities."""
        import json
        from dep_risk.cli import _parse_scanner_input

        grype_data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "severity": "Medium",
                    },
                    "relatedVulnerabilities": [
                        {
                            "id": "CVE-2023-32681",
                            "severity": "Medium",
                        }
                    ],
                    "artifact": {"name": "requests", "version": "2.27.0"},
                }
            ]
        }
        f = tmp_path / "grype_real.json"
        f.write_text(json.dumps(grype_data))

        result = _parse_scanner_input(str(f))
        assert result == ["CVE-2023-32681"]

