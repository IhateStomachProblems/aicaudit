"""Tests for AI-static engine collaboration."""
import json
from unittest import mock

from codeaudit.graph import EvidenceChain
from codeaudit.llm.client import (
    AiConfig,
    _build_deep_prompt,
    _llm_verify,
    _parse_deep_response,
)
from codeaudit.rules.base import Finding, Severity


def make_finding(rule_id="S001", line=5, file="app.py"):
    return Finding(rule_id=rule_id, message="sql risk", message_zh="sql", file=file,
                   line=line, severity=Severity.CRITICAL, snippet="conn.execute(q)")


def test_deep_prompt_has_evidence_chain():
    ec = EvidenceChain(entry="route: /api", path=[("app.py", 10, "handle")], sink="conn.execute", risk="high")
    prompt = _build_deep_prompt([make_finding()], {5: "conn.execute(q)"}, {"S001:app.py:5": [ec]})
    assert "Evidence chain" in prompt
    assert "/api" in prompt


def test_deep_prompt_without_chains():
    prompt = _build_deep_prompt([make_finding()], {5: "conn.execute(q)"}, None)
    assert "Finding [0]" in prompt
    assert "Evidence chain" not in prompt


def test_parse_deep_response_severity_override():
    findings = [make_finding()]
    resp = json.dumps([{"index": 0, "is_real": True, "severity": "error", "vuln_type": "SQL-injection",
                        "suggested_fix": "use params", "reason": "confirmed"}])
    result = _parse_deep_response(resp, findings, {})
    assert result[0]["ai_verified"] == True
    assert result[0]["ai_severity"] == "error"
    assert result[0]["ai_vuln_type"] == "SQL-injection"
    assert result[0]["ai_suggested_fix"] == "use params"


def test_parse_deep_response_with_evidence():
    findings = [make_finding()]
    ec = EvidenceChain(entry="main", path=[("a.py", 1, "f")], sink="eval")
    resp = json.dumps([{"index": 0, "is_real": True, "reason": "yes"}])
    result = _parse_deep_response(resp, findings, {"S001:app.py:5": [ec]})
    assert len(result[0]["evidence_used"]) == 1


def test_llm_verify_ollama_no_key_fallback():
    findings = [make_finding()]
    cfg = AiConfig(provider="ollama", model="llama3.2", api_base="http://localhost:11434/v1")
    with mock.patch("urllib.request.urlopen", side_effect=Exception("no server")):
        result = _llm_verify(findings, {5: "x"}, {}, cfg)
    assert len(result) == 1
    assert result[0]["ai_verified"] == True
