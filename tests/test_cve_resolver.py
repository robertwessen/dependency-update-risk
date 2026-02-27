"""Tests for CVE resolver."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dep_risk.config import Config
from dep_risk.cve_resolver import CVEResolver, _extract_severity, _parse_ecosystem
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


class TestNvdRetry:
    """Tests for NVD 429 retry logic."""

    @pytest.mark.asyncio
    async def test_retries_on_429_and_succeeds(self):
        config = Config(nvd_api_key="test-key")
        resolver = CVEResolver(config)

        good_response = MagicMock()
        good_response.status_code = 200
        good_response.json.return_value = {"vulnerabilities": []}

        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "0"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[rate_limited, good_response])
        resolver._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await resolver._fetch_nvd("CVE-2024-1234")

        mock_sleep.assert_called_once()
        assert result == {"vulnerabilities": []}

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self):
        config = Config()
        resolver = CVEResolver(config)

        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "0"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=rate_limited)
        resolver._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await resolver._fetch_nvd("CVE-2024-1234")

        assert result is None

    @pytest.mark.asyncio
    async def test_nvd_api_key_sent_in_header(self):
        config = Config(nvd_api_key="my-secret-key")
        resolver = CVEResolver(config)

        good_response = MagicMock()
        good_response.status_code = 200
        good_response.json.return_value = {"vulnerabilities": []}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=good_response)
        resolver._client = mock_client

        await resolver._fetch_nvd("CVE-2024-1234")

        call_kwargs = mock_client.get.call_args
        assert call_kwargs.kwargs["headers"]["apiKey"] == "my-secret-key"

    @pytest.mark.asyncio
    async def test_no_api_key_sends_no_header(self):
        config = Config(nvd_api_key=None)
        resolver = CVEResolver(config)

        good_response = MagicMock()
        good_response.status_code = 200
        good_response.json.return_value = {"vulnerabilities": []}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=good_response)
        resolver._client = mock_client

        await resolver._fetch_nvd("CVE-2024-1234")

        call_kwargs = mock_client.get.call_args
        assert "apiKey" not in call_kwargs.kwargs["headers"]
