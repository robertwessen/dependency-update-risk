"""Tests for LLM analyzer."""

from dep_risk.llm_analyzer import _normalize_api_url


class TestNormalizeApiUrl:
    def test_v1_path(self):
        result = _normalize_api_url("https://api.openai.com/v1")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_v1_path_trailing_slash(self):
        result = _normalize_api_url("https://api.openai.com/v1/")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_bare_domain(self):
        result = _normalize_api_url("https://api.openai.com")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_already_full_url(self):
        result = _normalize_api_url("https://api.openai.com/v1/chat/completions")
        assert result == "https://api.openai.com/v1/chat/completions"

    def test_localhost_bare(self):
        result = _normalize_api_url("http://localhost:11434")
        assert result == "http://localhost:11434/v1/chat/completions"

    def test_localhost_v1(self):
        result = _normalize_api_url("http://localhost:11434/v1")
        assert result == "http://localhost:11434/v1/chat/completions"

    def test_custom_base_path_v1(self):
        result = _normalize_api_url("http://host/openai/v1")
        assert result == "http://host/openai/v1/chat/completions"
