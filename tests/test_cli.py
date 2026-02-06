"""Tests for CLI."""

from click.testing import CliRunner

from dep_risk.cli import main


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
