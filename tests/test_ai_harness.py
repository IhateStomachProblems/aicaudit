"""Tests for AI harness: batching, retry, edge cases."""
import io
import json
from unittest import mock

from aicaudit.llm.client import (
    AiConfig,
    _build_deep_prompt,
    _call_llm_with_retry,
    _llm_verify,
    _mock_verify,
    _parse_deep_response,
)
from aicaudit.rules.base import Finding, Severity


def make_finding(rule_id="S001", line=1, file="test.py"):
    return Finding(
        rule_id=rule_id, message="test", message_zh="test",
        file=file, line=line, severity=Severity.WARNING,
        snippet="x = 1",
    )


class FakeResp:
    def __init__(self, data):
        self._buf = io.BytesIO(data)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return self._buf.read()


def make_ok_resp(indices):
    verdicts = [{"index": idx, "is_real": True, "reason": "ok",
                 "severity": "warning", "vuln_type": "", "suggested_fix": ""}
                for idx in indices]
    resp = json.dumps({"choices": [{"message": {"content": json.dumps(verdicts)}}]})
    return FakeResp(resp.encode())


def test_batch_processing_splits_findings():
    findings = [make_finding(line=i) for i in range(12)]
    cfg = AiConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test",
                   api_base="https://api.openai.com/v1")

    call_count = [0]

    def mock_urlopen(req, **kw):
        call_count[0] += 1
        body = json.loads(req.data)
        user_msg = body["messages"][1]["content"]
        indices = [int(line.split("[").pop().split("]")[0])
                   for line in user_msg.split("\n") if "Finding [" in line]
        return make_ok_resp(indices)

    with mock.patch("urllib.request.urlopen", mock_urlopen):
        results = _llm_verify(findings, {}, {}, cfg)

    assert len(results) == 12
    assert call_count[0] == 2


def test_retry_on_failure_then_succeeds():
    cfg = AiConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test",
                   api_base="https://api.openai.com/v1")
    call_count = [0]

    def mock_urlopen(req, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("first attempt failed")
        body = json.loads(req.data)
        user_msg = body["messages"][1]["content"]
        indices = [int(line.split("[").pop().split("]")[0])
                   for line in user_msg.split("\n") if "Finding [" in line]
        return make_ok_resp(indices)

    with mock.patch("urllib.request.urlopen", mock_urlopen):
        result = _call_llm_with_retry("test prompt", cfg, retries=1)

    data = json.loads(result)
    assert isinstance(data, list)
    assert call_count[0] == 2


def test_all_retries_fail_fallback():
    cfg = AiConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test",
                   api_base="https://api.openai.com/v1")

    with mock.patch("urllib.request.urlopen", side_effect=Exception("always down")):
        result = _call_llm_with_retry("test prompt", cfg, retries=0)

    data = json.loads(result)
    assert "error" in data


def test_prompt_offset_correct():
    findings = [make_finding() for _ in range(3)]
    prompt = _build_deep_prompt(findings, {}, {}, offset=5)
    assert "Finding [5]" in prompt
    assert "Finding [6]" in prompt
    assert "Finding [7]" in prompt


def test_mock_verify_edge_cases():
    findings = [
        make_finding(rule_id="S001"),
        make_finding(rule_id="S002"),
        Finding(rule_id="S003", message="err", message_zh="err",
                file="x.py", line=1, severity=Severity.CRITICAL,
                snippet="exec(x)", fix="use safe"),
    ]
    results = _mock_verify(findings)
    assert len(results) == 3
    assert all(r["ai_verified"] for r in results)
    assert results[0]["rule_id"] == "S001"
    assert results[2]["fix"] == "use safe"


def test_parse_deep_response_missing_indices():
    findings = [make_finding(line=1), make_finding(line=2)]
    response = json.dumps([{"index": 0, "is_real": True, "reason": "ok",
                            "severity": "warning", "vuln_type": "", "suggested_fix": ""}])
    results = _parse_deep_response(response, findings, {})
    assert len(results) == 2
    assert results[0]["ai_verified"] == True
    assert results[1]["ai_verified"] == True


def test_parse_deep_response_empty_list():
    findings = [make_finding()]
    response = "[]"
    results = _parse_deep_response(response, findings, {})
    assert len(results) == 1
    assert results[0]["ai_verified"] == True


def test_parse_deep_response_not_list():
    findings = [make_finding()]
    response = '{"error": "some error"}'
    results = _parse_deep_response(response, findings, {})
    assert len(results) == 1
    assert "Fallback" in results[0]["ai_reason"]
