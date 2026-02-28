"""Tests for CLI."""

from click.testing import CliRunner

from dep_risk.cli import (
    _detect_sbom_format,
    _estimate_previous_version,
    _fuzzy_match_package,
    _parse_cyclonedx,
    _parse_purl,
    _parse_spdx,
    _query_osv_batch,
    main,
)
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
        assert "1.5.1" in result.output

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


# ─────────────────────────────────────────────────────────────────────────────
# ROADMAP #18 — CycloneDX + SPDX SBOM input support
# These tests are intentionally more comprehensive than other test classes
# because SBOM ingestion is a primary enterprise adoption path.
# ─────────────────────────────────────────────────────────────────────────────


class TestParsePurl:
    """Unit tests for _parse_purl() — all 8 supported PURL types + edge cases."""

    def test_pypi_simple(self):
        result = _parse_purl("pkg:pypi/requests@2.27.0")
        assert result == ("PyPI", "requests", "2.27.0")

    def test_npm_simple(self):
        result = _parse_purl("pkg:npm/lodash@4.17.20")
        assert result == ("npm", "lodash", "4.17.20")

    def test_npm_scoped_percent_encoded(self):
        """Scoped npm packages are percent-encoded in PURLs: %40 → @."""
        result = _parse_purl("pkg:npm/%40angular%2Fcore@14.0.0")
        assert result == ("npm", "@angular/core", "14.0.0")

    def test_maven_with_namespace(self):
        """Maven PURL has groupId/artifactId → dep-risk uses groupId:artifactId."""
        result = _parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        assert result == ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")

    def test_maven_without_namespace(self):
        """Old/minimal Maven PURLs may omit groupId — handled gracefully."""
        result = _parse_purl("pkg:maven/log4j@1.2.17")
        assert result == ("Maven", "log4j", "1.2.17")

    def test_cargo_simple(self):
        result = _parse_purl("pkg:cargo/tokio@1.0.0")
        assert result == ("crates.io", "tokio", "1.0.0")

    def test_golang_full_module_path(self):
        """Go module name is the full path including host."""
        result = _parse_purl("pkg:golang/github.com/gin-gonic/gin@1.7.0")
        assert result == ("Go", "github.com/gin-gonic/gin", "1.7.0")

    def test_golang_version_with_v_prefix(self):
        """Go versions always carry the 'v' prefix — preserve it as-is for OSV."""
        result = _parse_purl("pkg:golang/github.com/foo/bar@v0.1.2")
        assert result == ("Go", "github.com/foo/bar", "v0.1.2")

    def test_nuget_simple(self):
        result = _parse_purl("pkg:nuget/Newtonsoft.Json@13.0.1")
        assert result == ("NuGet", "Newtonsoft.Json", "13.0.1")

    def test_gem_simple(self):
        result = _parse_purl("pkg:gem/rails@7.0.0")
        assert result == ("RubyGems", "rails", "7.0.0")

    def test_strips_qualifiers(self):
        """Qualifiers after '?' must be dropped before parsing."""
        result = _parse_purl("pkg:pypi/requests@2.27.0?checksum=sha256:abcdef")
        assert result == ("PyPI", "requests", "2.27.0")

    def test_strips_subpath(self):
        """Subpath after '#' must be dropped before parsing."""
        result = _parse_purl("pkg:pypi/requests@2.27.0#some/subpath")
        assert result == ("PyPI", "requests", "2.27.0")

    def test_strips_qualifiers_and_subpath_together(self):
        result = _parse_purl("pkg:pypi/requests@2.27.0?foo=bar#baz")
        assert result == ("PyPI", "requests", "2.27.0")

    def test_missing_version_returns_none(self):
        """Version is required — PURLs without @ are rejected."""
        assert _parse_purl("pkg:pypi/requests") is None

    def test_empty_version_returns_none(self):
        assert _parse_purl("pkg:pypi/requests@") is None

    def test_invalid_prefix_returns_none(self):
        assert _parse_purl("not-a-purl") is None
        assert _parse_purl("") is None

    def test_unknown_type_returns_none(self):
        """Unsupported PURL types (deb, rpm, apk, …) are excluded from dep-risk scope."""
        assert _parse_purl("pkg:deb/debian/libssl@3.0.0") is None
        assert _parse_purl("pkg:rpm/openssl@3.0.0") is None
        assert _parse_purl("pkg:apk/alpine/openssl@3.0.0") is None

    def test_url_encoded_version_decoded(self):
        """Version strings with percent-encoding are decoded correctly."""
        result = _parse_purl("pkg:pypi/some-pkg@1.0.0%2Blocal")
        assert result == ("PyPI", "some-pkg", "1.0.0+local")


class TestDetectSbomFormat:
    """Unit tests for _detect_sbom_format()."""

    def test_cyclonedx_detected(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
        assert _detect_sbom_format(data) == "cyclonedx"

    def test_spdx_detected(self):
        data = {"spdxVersion": "SPDX-2.3", "packages": []}
        assert _detect_sbom_format(data) == "spdx"

    def test_spdx_2_2_detected(self):
        data = {"spdxVersion": "SPDX-2.2", "packages": []}
        assert _detect_sbom_format(data) == "spdx"

    def test_trivy_json_returns_none(self):
        data = {"Results": [{"Vulnerabilities": []}]}
        assert _detect_sbom_format(data) is None

    def test_grype_json_returns_none(self):
        data = {"matches": []}
        assert _detect_sbom_format(data) is None

    def test_osv_scanner_returns_none(self):
        data = {"results": []}
        assert _detect_sbom_format(data) is None

    def test_empty_dict_returns_none(self):
        assert _detect_sbom_format({}) is None

    def test_wrong_bomformat_value_returns_none(self):
        """bomFormat must equal 'CycloneDX' exactly — other values are not SBOMs."""
        data = {"bomFormat": "SomethingElse"}
        assert _detect_sbom_format(data) is None


class TestParseCycloneDX:
    """Unit tests for _parse_cyclonedx()."""

    def _cdx(self, components: list) -> dict:
        return {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": components}

    def _component(self, purl: str, **kwargs) -> dict:
        return {"type": "library", "purl": purl, **kwargs}

    def test_single_pypi_component(self):
        data = self._cdx([self._component("pkg:pypi/requests@2.27.0")])
        result = _parse_cyclonedx(data)
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_multiple_components_different_ecosystems(self):
        data = self._cdx([
            self._component("pkg:pypi/requests@2.27.0"),
            self._component("pkg:npm/lodash@4.17.20"),
            self._component("pkg:maven/org.springframework/spring-core@5.3.20"),
        ])
        result = _parse_cyclonedx(data)
        assert len(result) == 3
        assert ("PyPI", "requests", "2.27.0") in result
        assert ("npm", "lodash", "4.17.20") in result
        assert ("Maven", "org.springframework:spring-core", "5.3.20") in result

    def test_skips_component_without_purl(self):
        """Components lacking a purl field (e.g. custom or unknown artifacts) are skipped."""
        data = self._cdx([
            {"type": "library", "name": "something", "version": "1.0"},
            self._component("pkg:pypi/requests@2.27.0"),
        ])
        result = _parse_cyclonedx(data)
        assert len(result) == 1
        assert result[0] == ("PyPI", "requests", "2.27.0")

    def test_skips_component_with_unsupported_purl_type(self):
        data = self._cdx([
            self._component("pkg:deb/debian/libssl@3.0.0"),
            self._component("pkg:pypi/requests@2.27.0"),
        ])
        result = _parse_cyclonedx(data)
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_empty_components_returns_empty(self):
        assert _parse_cyclonedx(self._cdx([])) == []

    def test_missing_components_key_returns_empty(self):
        assert _parse_cyclonedx({"bomFormat": "CycloneDX"}) == []

    def test_maven_purl_formats_as_group_colon_artifact(self):
        data = self._cdx([self._component("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")])
        result = _parse_cyclonedx(data)
        assert result == [("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.13.4")]

    def test_golang_purl_preserves_full_module_path(self):
        data = self._cdx([self._component("pkg:golang/github.com/gin-gonic/gin@1.7.0")])
        result = _parse_cyclonedx(data)
        assert result == [("Go", "github.com/gin-gonic/gin", "1.7.0")]

    def test_npm_scoped_package_decoded(self):
        data = self._cdx([self._component("pkg:npm/%40angular%2Fcore@14.0.0")])
        result = _parse_cyclonedx(data)
        assert result == [("npm", "@angular/core", "14.0.0")]

    def test_component_with_null_purl_skipped(self):
        """Some SBOMs emit 'purl': null for components they cannot resolve."""
        data = self._cdx([
            {"type": "library", "purl": None},
            self._component("pkg:pypi/requests@2.27.0"),
        ])
        result = _parse_cyclonedx(data)
        assert result == [("PyPI", "requests", "2.27.0")]


class TestParseSpdx:
    """Unit tests for _parse_spdx()."""

    def _spdx(self, packages: list) -> dict:
        return {"spdxVersion": "SPDX-2.3", "packages": packages}

    def _pkg_with_purl(self, purl: str, category: str = "PACKAGE-MANAGER") -> dict:
        return {
            "name": "pkg",
            "versionInfo": "1.0",
            "externalRefs": [
                {"referenceCategory": category, "referenceType": "purl", "referenceLocator": purl}
            ],
        }

    def test_single_package_with_purl(self):
        data = self._spdx([self._pkg_with_purl("pkg:pypi/requests@2.27.0")])
        result = _parse_spdx(data)
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_multiple_packages(self):
        data = self._spdx([
            self._pkg_with_purl("pkg:pypi/requests@2.27.0"),
            self._pkg_with_purl("pkg:npm/lodash@4.17.20"),
        ])
        result = _parse_spdx(data)
        assert len(result) == 2
        assert ("PyPI", "requests", "2.27.0") in result
        assert ("npm", "lodash", "4.17.20") in result

    def test_skips_package_without_external_refs(self):
        data = self._spdx([
            {"name": "nopurl", "versionInfo": "1.0"},
            self._pkg_with_purl("pkg:pypi/requests@2.27.0"),
        ])
        result = _parse_spdx(data)
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_skips_non_package_manager_category(self):
        """Only PACKAGE-MANAGER category externalRefs contain PURLs for dependency scanning."""
        data = self._spdx([self._pkg_with_purl("pkg:pypi/requests@2.27.0", "SECURITY")])
        assert _parse_spdx(data) == []

    def test_skips_other_reference_types(self):
        """Non-purl referenceLocators are silently skipped."""
        pkg = {
            "name": "pkg",
            "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "cpe23Type",
                 "referenceLocator": "cpe:2.3:a:requests:requests:2.27.0:*:*:*:*:*:*:*"},
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                 "referenceLocator": "pkg:pypi/requests@2.27.0"},
            ],
        }
        result = _parse_spdx(self._spdx([pkg]))
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_uses_first_valid_purl_per_package(self):
        """If a package has multiple PACKAGE-MANAGER externalRefs, only the first PURL is used."""
        pkg = {
            "name": "pkg",
            "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                 "referenceLocator": "pkg:pypi/requests@2.27.0"},
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                 "referenceLocator": "pkg:pypi/requests@2.28.0"},  # should be ignored
            ],
        }
        result = _parse_spdx(self._spdx([pkg]))
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_empty_packages_list(self):
        assert _parse_spdx(self._spdx([])) == []

    def test_missing_packages_key(self):
        assert _parse_spdx({"spdxVersion": "SPDX-2.3"}) == []

    def test_skips_unsupported_purl_type_in_spdx(self):
        data = self._spdx([
            self._pkg_with_purl("pkg:deb/debian/libssl@3.0.0"),
            self._pkg_with_purl("pkg:pypi/requests@2.27.0"),
        ])
        result = _parse_spdx(data)
        assert result == [("PyPI", "requests", "2.27.0")]

    def test_maven_purl_in_spdx(self):
        data = self._spdx([self._pkg_with_purl(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        )])
        result = _parse_spdx(data)
        assert result == [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")]


class TestQueryOsvBatch:
    """Tests for _query_osv_batch() — mocked HTTP via pytest-httpx."""

    def _osv_response(self, results: list) -> dict:
        return {"results": results}

    def _vuln(self, vid: str, aliases: list | None = None) -> dict:
        v: dict = {"id": vid}
        if aliases:
            v["aliases"] = aliases
        return v

    async def test_single_package_with_cve_id(self, httpx_mock):
        """Primary id is a CVE → extracted directly."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([{"vulns": [self._vuln("CVE-2023-32681")]}]),
        )
        findings = await _query_osv_batch([("PyPI", "requests", "2.27.0")])
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2023-32681"
        assert findings[0].package_name == "requests"
        assert findings[0].package_version == "2.27.0"
        assert findings[0].ecosystem == "PyPI"

    async def test_extracts_cve_from_aliases_when_primary_is_ghsa(self, httpx_mock):
        """Real OSV querybatch returns minimal stubs (id+modified only, no aliases).
        For non-CVE ids, a second fetch to /v1/vulns/{id} retrieves the full record."""
        # Phase 1: querybatch returns GHSA id (no aliases — matches real API behaviour)
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([
                {"vulns": [{"id": "GHSA-j8r2-6x86-q33q", "modified": "2024-01-01T00:00:00Z"}]}
            ]),
        )
        # Phase 2: individual vuln fetch returns full record with CVE alias
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q",
            json={"id": "GHSA-j8r2-6x86-q33q", "aliases": ["CVE-2023-32681", "PYSEC-2023-74"]},
        )
        findings = await _query_osv_batch([("PyPI", "requests", "2.27.0")])
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2023-32681"

    async def test_skips_vuln_without_cve_id_or_alias(self, httpx_mock):
        """GHSA-only vulnerabilities with no CVE alias in full record are excluded."""
        # Phase 1: querybatch returns non-CVE id
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([
                {"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz", "modified": "2024-01-01T00:00:00Z"}]}
            ]),
        )
        # Phase 2: full record has no CVE aliases
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz",
            json={"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["PYSEC-9999-99"]},
        )
        findings = await _query_osv_batch([("PyPI", "requests", "2.27.0")])
        assert findings == []

    async def test_package_with_no_vulns_skipped(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([{"vulns": []}, {"vulns": [self._vuln("CVE-2021-23337")]}]),
        )
        findings = await _query_osv_batch([
            ("PyPI", "requests", "2.27.0"),
            ("npm", "lodash", "4.17.20"),
        ])
        assert len(findings) == 1
        assert findings[0].package_name == "lodash"

    async def test_multiple_packages_correct_parallel_mapping(self, httpx_mock):
        """results[i] must map to queries[i] — order is significant."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([
                {"vulns": [self._vuln("CVE-2021-29472")]},
                {"vulns": []},
                {"vulns": [self._vuln("CVE-2022-21703")]},
            ]),
        )
        findings = await _query_osv_batch([
            ("PyPI", "composer", "2.0.0"),
            ("npm", "safe-package", "1.0.0"),
            ("PyPI", "grafana", "9.0.0"),
        ])
        assert len(findings) == 2
        assert findings[0].package_name == "composer"
        assert findings[0].cve_id == "CVE-2021-29472"
        assert findings[1].package_name == "grafana"
        assert findings[1].cve_id == "CVE-2022-21703"

    async def test_multiple_cves_per_package(self, httpx_mock):
        """A package with multiple CVEs produces one ScannerFinding per CVE."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([{
                "vulns": [
                    self._vuln("CVE-2021-44228"),
                    self._vuln("CVE-2021-45046"),
                ]
            }]),
        )
        findings = await _query_osv_batch([("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])
        assert len(findings) == 2
        cve_ids = {f.cve_id for f in findings}
        assert cve_ids == {"CVE-2021-44228", "CVE-2021-45046"}

    async def test_deduplicates_same_cve_same_package(self, httpx_mock):
        """If OSV returns the same CVE via both direct id and a GHSA alias, deduplicate."""
        # Phase 1: querybatch returns one direct CVE id and one GHSA id for the same CVE
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([{
                "vulns": [
                    {"id": "CVE-2023-32681", "modified": "2024-01-01T00:00:00Z"},
                    {"id": "GHSA-j8r2-6x86-q33q", "modified": "2024-01-01T00:00:00Z"},
                ]
            }]),
        )
        # Phase 2: full vuln fetch for GHSA resolves to same CVE
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q",
            json={"id": "GHSA-j8r2-6x86-q33q", "aliases": ["CVE-2023-32681"]},
        )
        findings = await _query_osv_batch([("PyPI", "requests", "2.27.0")])
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2023-32681"

    async def test_empty_package_list_returns_empty_without_http_call(self, httpx_mock):
        """Empty input short-circuits before any HTTP request."""
        findings = await _query_osv_batch([])
        assert findings == []
        # httpx_mock would raise if any request was made to an unregistered URL

    async def test_http_status_error_returns_empty_does_not_raise(self, httpx_mock):
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            status_code=429,
        )
        findings = await _query_osv_batch([("PyPI", "requests", "2.27.0")])
        assert findings == []

    async def test_chunking_sends_two_requests_for_501_packages(self, httpx_mock):
        """501 packages → chunk[0..499] + chunk[500..500] = 2 HTTP requests."""
        packages = [("PyPI", f"pkg{i}", "1.0.0") for i in range(501)]
        # Both chunks return empty vulns
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([{"vulns": []} for _ in range(500)]),
        )
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            json=self._osv_response([{"vulns": []}]),
        )
        findings = await _query_osv_batch(packages)
        assert findings == []
        # Two responses were consumed — verifying two requests were made
        assert len(httpx_mock.get_requests()) == 2


class TestSbomCLI:
    """End-to-end CLI tests for SBOM --input path.

    These tests verify format detection, parsing, and early-exit conditions.
    OSV querybatch and CVE resolution are not called because the test SBOMs
    trigger no-package or no-CVE early-exit paths, or we mock the OSV call.
    """

    def _write_json(self, tmp_path, name: str, data: dict):
        f = tmp_path / name
        import json as _json
        f.write_text(_json.dumps(data))
        return str(f)

    def test_cyclonedx_no_packages_exits_with_warning(self, tmp_path):
        """CycloneDX SBOM with no supported PURLs exits cleanly with a warning."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"type": "library", "purl": "pkg:deb/debian/libssl@3.0.0"},  # unsupported
                {"type": "library", "name": "no-purl"},  # no purl at all
            ],
        }
        path = self._write_json(tmp_path, "sbom.json", sbom)
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--input", path])
        assert "No packages with recognised PURLs" in result.output

    def test_spdx_no_packages_exits_with_warning(self, tmp_path):
        """SPDX SBOM with no PACKAGE-MANAGER externalRefs exits cleanly."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "something", "externalRefs": [
                    {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                     "referenceLocator": "cpe:2.3:..."}
                ]},
            ],
        }
        path = self._write_json(tmp_path, "sbom.spdx.json", sbom)
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--input", path])
        assert "No packages with recognised PURLs" in result.output

    def test_input_help_mentions_sbom(self):
        """--input help text should mention CycloneDX/SPDX so users know SBOM is supported."""
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert "CycloneDX" in result.output or "SBOM" in result.output

    def test_cyclonedx_format_detected_not_treated_as_scanner(self, tmp_path):
        """A CycloneDX file must NOT be parsed by the scanner path (which would return 0 findings
        and print the scanner warning, not the SBOM-specific messaging)."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"type": "library", "purl": "pkg:pypi/requests@2.27.0"}],
        }
        path = self._write_json(tmp_path, "cdx.json", sbom)
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--input", path])
        # The SBOM path shows "packages in ... SBOM" — the scanner path would show
        # "No CVE IDs found in scanner input file"
        assert "No CVE IDs found in scanner input file" not in result.output

    def test_scanner_json_not_detected_as_sbom(self, tmp_path):
        """Trivy JSON must still go through the scanner path, not the SBOM path."""
        trivy = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1234", "PkgName": "requests", "InstalledVersion": "2.27.0"}
        ]}]}
        path = self._write_json(tmp_path, "trivy.json", trivy)
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--input", path])
        # Scanner path triggers real CVE resolution which fails in unit test context,
        # but we verify the SBOM messaging is NOT present
        assert "SBOM" not in result.output
        assert "packages in" not in result.output

