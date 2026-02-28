"""Tests for CLI."""

from click.testing import CliRunner

from dep_risk.cli import _estimate_previous_version, _fuzzy_match_package, main
from dep_risk.models import AffectedPackage, Ecosystem, RiskAnalysis, RiskLevel


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
        assert "1.4.0" in result.output

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


class TestRiskAnalysisModelFields:
    """Tests that new model fields have correct defaults and types."""

    def test_fix_available_defaults_to_true(self):
        analysis = RiskAnalysis(
            cve_id="CVE-2024-1234",
            package_name="requests",
            ecosystem=Ecosystem.PYPI,
            current_version="2.27.0",
            target_version="2.31.0",
            risk_level=RiskLevel.LOW,
            confidence=0.9,
        )
        assert analysis.fix_available is True

    def test_version_estimated_defaults_to_false(self):
        analysis = RiskAnalysis(
            cve_id="CVE-2024-1234",
            package_name="requests",
            ecosystem=Ecosystem.PYPI,
            current_version="2.27.0",
            target_version="2.31.0",
            risk_level=RiskLevel.LOW,
            confidence=0.9,
        )
        assert analysis.version_estimated is False
        assert analysis.version_estimate_basis is None

    def test_fix_available_can_be_set_false(self):
        analysis = RiskAnalysis(
            cve_id="CVE-2024-1234",
            package_name="py",
            ecosystem=Ecosystem.PYPI,
            current_version="unknown",
            target_version="unknown",
            risk_level=RiskLevel.LOW,
            confidence=0.5,
            fix_available=False,
        )
        assert analysis.fix_available is False

    def test_version_estimated_fields_in_model_dump(self):
        analysis = RiskAnalysis(
            cve_id="CVE-2024-1234",
            package_name="pyyaml",
            ecosystem=Ecosystem.PYPI,
            current_version="5.3.0",
            target_version="5.4",
            risk_level=RiskLevel.LOW,
            confidence=0.7,
            version_estimated=True,
            version_estimate_basis="decremented from fixed version 5.4",
        )
        dumped = analysis.model_dump()
        assert dumped["version_estimated"] is True
        assert dumped["version_estimate_basis"] == "decremented from fixed version 5.4"
        assert dumped["fix_available"] is True


class TestNoLlmFlag:
    """Tests for the --no-llm CLI flag."""

    def test_no_llm_appears_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--no-llm" in result.output

    def test_no_llm_and_cve_required(self):
        """--no-llm without a CVE ID still requires the CVE argument."""
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--no-llm"])
        assert result.exit_code != 0


class TestScannerInput:
    """Tests for _parse_scanner_input() — returns list[ScannerFinding] with package context."""

    def test_parses_trivy_json_with_package_context(self, tmp_path):
        """Trivy output includes PkgName + InstalledVersion — both carried through."""
        import json
        from dep_risk.cli import _parse_scanner_input

        trivy_data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.27.0",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-5678",
                            "PkgName": "flask",
                            "InstalledVersion": "2.0.0",
                        },
                    ]
                },
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-9999",
                            "PkgName": "django",
                            "InstalledVersion": "3.2.0",
                        },
                    ]
                },
            ]
        }
        f = tmp_path / "trivy.json"
        f.write_text(json.dumps(trivy_data))

        result = _parse_scanner_input(str(f))
        assert len(result) == 3
        assert result[0].cve_id == "CVE-2024-1234"
        assert result[0].package_name == "requests"
        assert result[0].package_version == "2.27.0"
        assert result[1].cve_id == "CVE-2024-5678"
        assert result[1].package_name == "flask"
        assert result[2].cve_id == "CVE-2024-9999"

    def test_parses_grype_json_with_package_context(self, tmp_path):
        """Grype artifact carries name, version, and type → ecosystem mapping."""
        import json
        from dep_risk.cli import _parse_scanner_input

        grype_data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-2024-1111"},
                    "artifact": {"name": "requests", "version": "2.27.0", "type": "python"},
                },
                {
                    "vulnerability": {"id": "CVE-2024-2222"},
                    "artifact": {"name": "express", "version": "4.18.0", "type": "npm"},
                },
            ]
        }
        f = tmp_path / "grype.json"
        f.write_text(json.dumps(grype_data))

        result = _parse_scanner_input(str(f))
        assert len(result) == 2
        assert result[0].cve_id == "CVE-2024-1111"
        assert result[0].package_name == "requests"
        assert result[0].package_version == "2.27.0"
        assert result[0].ecosystem == "PyPI"
        assert result[1].cve_id == "CVE-2024-2222"
        assert result[1].ecosystem == "npm"

    def test_parses_osv_scanner_json_with_package_context(self, tmp_path):
        """OSV-Scanner package block carries name, version, and ecosystem."""
        import json
        from dep_risk.cli import _parse_scanner_input

        osv_data = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "requests",
                                "version": "2.27.0",
                                "ecosystem": "PyPI",
                            },
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
        assert len(result) == 2
        assert result[0].cve_id == "CVE-2024-3333"
        assert result[0].package_name == "requests"
        assert result[0].package_version == "2.27.0"
        assert result[0].ecosystem == "PyPI"
        assert result[1].cve_id == "CVE-2024-4444"
        assert result[1].package_name == "requests"

    def test_deduplicates_same_cve_same_package(self, tmp_path):
        """Same (CVE, package) pair reported twice → deduplicated to one finding."""
        import json
        from dep_risk.cli import _parse_scanner_input

        trivy_data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.27.0",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-1234",  # duplicate same pkg
                            "PkgName": "requests",
                            "InstalledVersion": "2.27.0",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-5678",
                            "PkgName": "flask",
                        },
                    ]
                }
            ]
        }
        f = tmp_path / "trivy_dup.json"
        f.write_text(json.dumps(trivy_data))

        result = _parse_scanner_input(str(f))
        cve_ids = [r.cve_id for r in result]
        assert cve_ids == ["CVE-2024-1234", "CVE-2024-5678"]

    def test_same_cve_different_packages_kept_separate(self, tmp_path):
        """Same CVE in two different packages → two separate findings (not deduplicated)."""
        import json
        from dep_risk.cli import _parse_scanner_input

        trivy_data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.27.0",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "urllib3",  # different package, same CVE
                            "InstalledVersion": "1.26.4",
                        },
                    ]
                }
            ]
        }
        f = tmp_path / "trivy_multi_pkg.json"
        f.write_text(json.dumps(trivy_data))

        result = _parse_scanner_input(str(f))
        assert len(result) == 2
        assert result[0].cve_id == "CVE-2024-1234"
        assert result[0].package_name == "requests"
        assert result[1].cve_id == "CVE-2024-1234"
        assert result[1].package_name == "urllib3"

    def test_filters_non_cve_ids_grype(self, tmp_path):
        """GHSA IDs without relatedVulnerabilities with CVE → excluded."""
        import json
        from dep_risk.cli import _parse_scanner_input

        grype_data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-2024-1111"},
                    "artifact": {"name": "requests"},
                },
                {
                    "vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz"},  # no CVE alias
                    "artifact": {"name": "flask"},
                },
            ]
        }
        f = tmp_path / "grype_mixed.json"
        f.write_text(json.dumps(grype_data))

        result = _parse_scanner_input(str(f))
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2024-1111"

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
                            "package": {
                                "name": "requests",
                                "version": "2.27.0",
                                "ecosystem": "PyPI",
                            },
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
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-32681"
        assert result[0].package_name == "requests"
        assert result[0].package_version == "2.27.0"

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
                    "artifact": {"name": "requests", "version": "2.27.0", "type": "python"},
                }
            ]
        }
        f = tmp_path / "grype_real.json"
        f.write_text(json.dumps(grype_data))

        result = _parse_scanner_input(str(f))
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-32681"
        assert result[0].package_name == "requests"
        assert result[0].package_version == "2.27.0"
        assert result[0].ecosystem == "PyPI"


class TestEcosystemSupportedFields:
    """Tests for ecosystem_supported and release_notes_available model fields (#17)."""

    def _make_analysis(self, ecosystem: Ecosystem, **kwargs) -> RiskAnalysis:
        return RiskAnalysis(
            cve_id="CVE-2024-1234",
            package_name="testpkg",
            ecosystem=ecosystem,
            current_version="1.0.0",
            target_version="1.1.0",
            risk_level=RiskLevel.LOW,
            confidence=0.8,
            **kwargs,
        )

    def test_ecosystem_supported_defaults_true(self):
        analysis = self._make_analysis(Ecosystem.PYPI)
        assert analysis.ecosystem_supported is True

    def test_release_notes_available_defaults_true(self):
        analysis = self._make_analysis(Ecosystem.NPM)
        assert analysis.release_notes_available is True

    def test_can_set_ecosystem_supported_false(self):
        analysis = self._make_analysis(Ecosystem.NUGET, ecosystem_supported=False)
        assert analysis.ecosystem_supported is False

    def test_can_set_release_notes_available_false(self):
        analysis = self._make_analysis(Ecosystem.PYPI, release_notes_available=False)
        assert analysis.release_notes_available is False

    def test_ecosystem_fields_in_model_dump(self):
        analysis = self._make_analysis(
            Ecosystem.NUGET, ecosystem_supported=False, release_notes_available=False
        )
        dumped = analysis.model_dump()
        assert dumped["ecosystem_supported"] is False
        assert dumped["release_notes_available"] is False

    def test_supported_ecosystems_constant_contains_expected(self):
        from dep_risk.cli import _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.PYPI in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.NPM in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.MAVEN in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.CARGO in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.GO in _SUPPORTED_ECOSYSTEMS

    def test_unsupported_ecosystems_not_in_constant(self):
        from dep_risk.cli import _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.NUGET not in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.RUBYGEMS not in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.PACKAGIST not in _SUPPORTED_ECOSYSTEMS
        assert Ecosystem.UNKNOWN not in _SUPPORTED_ECOSYSTEMS


class TestFuzzyPackageMatch:
    """Tests for _fuzzy_match_package() helper (#20)."""

    def _pkg(self, name: str, ecosystem: Ecosystem = Ecosystem.MAVEN) -> AffectedPackage:
        return AffectedPackage(ecosystem=ecosystem, name=name)

    def test_exact_match_returns_package(self):
        pkgs = [self._pkg("requests", Ecosystem.PYPI)]
        matches, was_fuzzy = _fuzzy_match_package("requests", pkgs)
        assert len(matches) == 1
        assert was_fuzzy is False

    def test_exact_match_is_case_insensitive(self):
        pkgs = [self._pkg("Requests", Ecosystem.PYPI)]
        matches, was_fuzzy = _fuzzy_match_package("requests", pkgs)
        assert len(matches) == 1
        assert was_fuzzy is False

    def test_fuzzy_match_maven_artifact_id(self):
        pkgs = [self._pkg("org.apache.logging.log4j:log4j-core")]
        matches, was_fuzzy = _fuzzy_match_package("log4j-core", pkgs)
        assert len(matches) == 1
        assert was_fuzzy is True
        assert matches[0].name == "org.apache.logging.log4j:log4j-core"

    def test_fuzzy_match_go_module_last_segment(self):
        pkgs = [self._pkg("github.com/gin-gonic/gin", Ecosystem.GO)]
        matches, was_fuzzy = _fuzzy_match_package("gin", pkgs)
        assert len(matches) == 1
        assert was_fuzzy is True

    def test_no_match_returns_empty_not_fuzzy(self):
        pkgs = [self._pkg("org.apache.logging.log4j:log4j-core")]
        matches, was_fuzzy = _fuzzy_match_package("spring-boot", pkgs)
        assert matches == []
        assert was_fuzzy is False

    def test_ambiguous_fuzzy_match_returns_all(self):
        pkgs = [
            self._pkg("org.apache.logging.log4j:log4j-core"),
            self._pkg("com.other:log4j-core"),
        ]
        matches, was_fuzzy = _fuzzy_match_package("log4j-core", pkgs)
        assert len(matches) == 2
        assert was_fuzzy is True

    def test_exact_match_preferred_over_fuzzy(self):
        """If exact name matches, fuzzy is not tried even if fuzzy would also match."""
        pkgs = [
            self._pkg("log4j-core"),
            self._pkg("org.apache.logging.log4j:log4j-core"),
        ]
        matches, was_fuzzy = _fuzzy_match_package("log4j-core", pkgs)
        assert len(matches) == 1
        assert matches[0].name == "log4j-core"
        assert was_fuzzy is False

    def test_empty_candidate_list_returns_empty(self):
        matches, was_fuzzy = _fuzzy_match_package("requests", [])
        assert matches == []
        assert was_fuzzy is False

