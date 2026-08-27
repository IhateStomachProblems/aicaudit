"""Tests for relay/transit market support (custom OpenAI-compatible endpoints)."""

import json
import os

from aicaudit.llm.client import AiConfig, _call_llm, load_ai_config


def test_relay_provider_config():
    os.environ["AICAUDIT_AI_PROVIDER"] = "relay"
    os.environ["AICAUDIT_AI_BASE"] = "https://api.example-relay.com/v1"
    os.environ["AICAUDIT_AI_KEY"] = "sk-relay-key"
    os.environ["AICAUDIT_AI_MODEL"] = "gpt-4o-mini"
    cfg = load_ai_config()
    assert cfg.provider == "relay"
    assert cfg.api_base == "https://api.example-relay.com/v1"
    assert cfg.api_key == "sk-relay-key"
    os.environ.pop("AICAUDIT_AI_PROVIDER", None)
    os.environ.pop("AICAUDIT_AI_BASE", None)
    os.environ.pop("AICAUDIT_AI_KEY", None)
    os.environ.pop("AICAUDIT_AI_MODEL", None)


def test_custom_provider_config():
    os.environ["AICAUDIT_AI_PROVIDER"] = "custom"
    os.environ["AICAUDIT_AI_BASE"] = "https://my-openai-compatible.com/v1"
    os.environ["AICAUDIT_AI_MODEL"] = "some-model"
    cfg = load_ai_config()
    assert cfg.provider == "custom"
    assert "my-openai-compatible" in cfg.api_base
    os.environ.pop("AICAUDIT_AI_PROVIDER", None)
    os.environ.pop("AICAUDIT_AI_BASE", None)
    os.environ.pop("AICAUDIT_AI_MODEL", None)


def test_proxy_provider_requires_base():
    os.environ["AICAUDIT_AI_PROVIDER"] = "proxy"
    cfg = load_ai_config()
    assert cfg.provider == "proxy"
    os.environ.pop("AICAUDIT_AI_PROVIDER", None)


def test_relay_uses_openai_compat_path():
    """Relay endpoints call the OpenAI-compatible chat completions path."""
    from unittest import mock
    cfg = AiConfig(provider="relay", model="gpt-4o-mini", api_key="sk-x",
                   api_base="https://relay.example.com/v1")
    mock_response = json.dumps({
        "choices": [{"message": {"content": "[]"}}]
    }).encode()
    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return mock_response
    with mock.patch("urllib.request.urlopen", return_value=FakeResp()) as m:
        _call_llm("test", cfg)
        req = m.call_args[0][0]
        assert req.full_url == "https://relay.example.com/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer sk-x"
