"""Coverage: LLM verification with mocked HTTP."""
import io
import json
from unittest import mock

from codeaudit.llm.client import (
    AiConfig,
    _build_deep_prompt,
    _call_llm,
    _llm_verify,
)
from codeaudit.rules.base import Finding, Severity


def make_finding(line=1, rule_id="S001"):
    return Finding(rule_id=rule_id, message="test", message_zh="test", file="f.py", line=line, severity=Severity.WARNING)


class FakeResp:
    def __init__(self, data):
        self._buf = io.BytesIO(data)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return self._buf.read()


def test_build_deep_prompt_with_snippets():
    prompt = _build_deep_prompt([make_finding(line=3)], {3: "exec(x)"}, {})
    assert "[0]" in prompt
    assert "exec(x)" in prompt
    assert "S001" in prompt


def test_llm_verify_mocked_success():
    findings = [make_finding()]
    cfg = AiConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test", api_base="https://api.openai.com/v1")
    mock_response = json.dumps({"choices": [{"message": {"content": json.dumps([{"index": 0, "is_real": True, "reason": "ok"}])}}]})
    with mock.patch("urllib.request.urlopen", return_value=FakeResp(mock_response.encode())) as m:
        results = _llm_verify(findings, {1: "x=1"}, {}, cfg)
    assert len(results) == 1
    assert results[0]["ai_verified"] == True


def test_llm_verify_mocked_exception():
    findings = [make_finding()]
    cfg = AiConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test", api_base="https://api.openai.com/v1")
    with mock.patch("urllib.request.urlopen", side_effect=Exception("network down")):
        results = _llm_verify(findings, {1: "x=1"}, {}, cfg)
    assert len(results) == 1
    assert results[0]["ai_verified"] == True
    assert "Fallback" in results[0]["ai_reason"]


def test_call_llm_request_construction():
    cfg = AiConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test", api_base="https://api.openai.com/v1")
    mock_response = json.dumps({"choices": [{"message": {"content": "[]"}}]})
    with mock.patch("urllib.request.urlopen", return_value=FakeResp(mock_response.encode())) as m:
        result = _call_llm("test prompt", cfg)
        req = m.call_args[0][0]
        assert req.headers["Authorization"] == "Bearer sk-test"
    assert "[]" in result
