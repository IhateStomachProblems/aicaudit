"""Transport-layer tests: batching, retry, GLM responses, ollama fail-safe."""
import io
import json
from unittest import mock

from aicaudit.llm.client import (
    AiConfig,
    _call_llm_with_retry,
    _extract_response_text,
    _llm_verify,
    verify_findings,
)
from aicaudit.llm.prompts import FindingEvidence


def make_evidence(rule_id="S001", line=1):
    return FindingEvidence(rule_id=rule_id, severity="warning", file="test.py",
                           line=line, message="test", snippet="x = 1")


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
    verdicts = [{"index": idx, "is_real": True, "confidence": 0.9, "reason": "ok",
                 "severity": "warning", "cwe": "", "vuln_type": "", "suggested_fix": ""}
                for idx in indices]
    resp = json.dumps({"choices": [{"message": {"content": json.dumps(verdicts)}}]})
    return FakeResp(resp.encode())


def test_batch_processing_splits_evidences():
    evidences = [make_evidence(line=i) for i in range(12)]
    cfg = AiConfig(provider="openai", model="m", api_key="k",
                   api_base="https://api.test/v1")
    seen_batch_sizes = []

    def fake_urlopen(req, timeout=60):
        body = json.loads(req.data.decode())
        prompt = body["messages"][1]["content"]
        n = prompt.count("=== Finding [")
        seen_batch_sizes.append(n)
        start_idx = seen_batch_sizes[-1] and (len(seen_batch_sizes) - 1) * 10
        indices = list(range(start_idx, start_idx + n))
        return make_ok_resp(indices)

    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        results = _llm_verify(evidences, cfg)
    assert len(results) == 12
    assert all(r["ai_status"] == "confirmed" for r in results)
    assert seen_batch_sizes == [10, 2]


def test_retry_succeeds_after_failure():
    cfg = AiConfig(provider="openai", model="m", api_key="k",
                   api_base="https://api.test/v1")
    call_count = [0]

    def fake_urlopen(req, timeout=60):
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("first attempt failed")
        return make_ok_resp([0])

    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         mock.patch("time.sleep"):
        out = _call_llm_with_retry("prompt", cfg, retries=2)
    parsed = json.loads(out)
    assert isinstance(parsed, list) and parsed[0]["is_real"] is True


def test_retry_exhaustion_returns_error_json():
    cfg = AiConfig(provider="openai", model="m", api_key="k")
    with mock.patch("urllib.request.urlopen", side_effect=RuntimeError("down")), \
         mock.patch("time.sleep"):
        out = _call_llm_with_retry("prompt", cfg, retries=1)
    assert "error" in json.loads(out)


def test_glm_reasoning_content_extraction():
    assert _extract_response_text({"content": "hello"}) == "hello"
    assert _extract_response_text({"content": "", "reasoning_content": "thoughts"}) == "thoughts"
    assert _extract_response_text({"content": "  ", "reasoning_content": " R "}) == " R "


def test_ollama_no_server_fail_safe():
    """Transport death on ollama must not rubber-stamp findings as confirmed."""
    evidences = [make_evidence()]
    cfg = AiConfig(provider="ollama", model="llama3.2",
                   api_base="http://localhost:11434/v1")
    with mock.patch("urllib.request.urlopen", side_effect=Exception("no server")), \
         mock.patch("time.sleep"):
        results = _llm_verify(evidences, cfg)
    assert len(results) == 1
    assert results[0]["ai_status"] == "unverified"


def test_verify_findings_mock_provider_unverified():
    results = verify_findings([make_evidence()])
    assert results[0]["ai_status"] == "unverified"
    assert "no AI provider" in results[0]["ai_reason"]


def test_verify_findings_no_key_unverified(monkeypatch):
    monkeypatch.setenv("AICAUDIT_AI_PROVIDER", "openai")
    monkeypatch.delenv("AICAUDIT_AI_KEY", raising=False)
    results = verify_findings([make_evidence()])
    assert results[0]["ai_status"] == "unverified"


def test_openai_compat_endpoint_and_headers():
    cfg = AiConfig(provider="relay", model="gpt-x", api_key="sk-k",
                   api_base="https://relay.test/v1")
    captured = {}

    def fake_urlopen(req, timeout=60):
        captured["url"] = req.full_url
        captured["auth"] = req.headers.get("Authorization")
        captured["body"] = json.loads(req.data.decode())
        return make_ok_resp([0])

    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        _llm_verify([make_evidence()], cfg)
    assert captured["url"] == "https://relay.test/v1/chat/completions"
    assert captured["auth"] == "Bearer sk-k"
    assert captured["body"]["model"] == "gpt-x"
