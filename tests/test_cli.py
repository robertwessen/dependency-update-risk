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
        assert "0.1.0" in result.output

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
