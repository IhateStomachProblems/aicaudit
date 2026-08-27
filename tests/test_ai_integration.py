"""Integration test: real AI harness against an OpenAI-compatible relay API.

Set the environment variables below to run the live tests; they are skipped
automatically when no key is configured:

    AICAUDIT_AI_KEY=sk-...
    AICAUDIT_AI_BASE=https://api.aixforge.com/v1
    AICAUDIT_AI_MODEL=glm-5.2
"""
import os

import pytest

from aicaudit.llm.client import (
    AiConfig,
    _build_deep_prompt,
    _call_openai_compat,
    _extract_response_text,
    _llm_verify,
    _parse_deep_response,
)
from aicaudit.rules.base import Finding, Severity

TEST_API_KEY = os.environ.get("AICAUDIT_AI_KEY", "")
TEST_API_BASE = os.environ.get("AICAUDIT_AI_BASE", "https://api.aixforge.com/v1")
TEST_MODEL = os.environ.get("AICAUDIT_AI_MODEL", "glm-5.2")

requires_live_ai = pytest.mark.skipif(
    not TEST_API_KEY, reason="AICAUDIT_AI_KEY not set; live AI tests skipped"
)


def _cfg():
    return AiConfig(
        provider="relay",
        model=TEST_MODEL,
        api_key=TEST_API_KEY,
        api_base=TEST_API_BASE,
        temperature=0.1,
        max_tokens=2048,
    )


def make_finding(rule_id, line, file="app.py", msg="test", sev=Severity.WARNING, snippet=""):
    return Finding(rule_id=rule_id, message=msg, message_zh=msg,
                   file=file, line=line, severity=sev, snippet=snippet)


class TestAIIntegration:

    def test_extract_response_text(self):
        """Test _extract_response_text handles content and reasoning_content."""
        msg1 = {"content": "Hello"}
        assert _extract_response_text(msg1) == "Hello"
        msg2 = {"content": "", "reasoning_content": "Thinking..."}
        assert _extract_response_text(msg2) == "Thinking..."
        msg3 = {"content": "Direct answer"}
        assert _extract_response_text(msg3) == "Direct answer"

    @requires_live_ai
    def test_single_finding_verification(self):
        """AI analyzes a single SQL injection finding."""
        finding = make_finding(
            "S001", 15, msg="SQL injection risk: f-string in query",
            sev=Severity.CRITICAL,
            snippet='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        )
        cfg = _cfg()
        prompt = _build_deep_prompt(
            [finding],
            {15: 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'},
            {},
        )
        response = _call_openai_compat(prompt, cfg)
        results = _parse_deep_response(response, [finding], {})
        assert len(results) == 1
        r = results[0]
        assert r["ai_verified"] is True
        assert r["ai_severity"] in ("error", "critical")
        assert len(r["ai_reason"]) > 10

    @requires_live_ai
    def test_false_positive_detection(self):
        """AI correctly identifies a parameterized query as safe."""
        finding = make_finding(
            "S001", 20, file="db.py",
            msg="SQL injection risk: variable in query",
            sev=Severity.ERROR,
            snippet='cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,))',
        )
        cfg = _cfg()
        prompt = _build_deep_prompt(
            [finding],
            {20: 'cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,))'},
            {},
        )
        response = _call_openai_compat(prompt, cfg)
        results = _parse_deep_response(response, [finding], {})
        assert len(results) == 1
        r = results[0]
        assert r["ai_verified"] is False

    @requires_live_ai
    def test_multi_finding_batch(self):
        """AI analyzes a batch of mixed findings."""
        findings = [
            make_finding("S001", 10, msg="eval(user_input)", sev=Severity.CRITICAL,
                         snippet="eval(user_input)"),
            make_finding("S002", 20, msg="Hardcoded API key",
                         sev=Severity.CRITICAL, snippet='API_KEY = "sk-test12345678"'),
            make_finding("Q001", 30, msg="Bare except clause",
                         sev=Severity.WARNING, snippet="except:"),
        ]
        cfg = _cfg()
        prompt = _build_deep_prompt(findings, {
            10: "eval(user_input)",
            20: 'API_KEY = "sk-test12345678"',
            30: "except:",
        }, {})
        response = _call_openai_compat(prompt, cfg)
        results = _parse_deep_response(response, findings, {})
        assert len(results) == 3
        for r in results:
            assert "ai_verified" in r
            assert len(r.get("ai_reason", "")) > 5

    @requires_live_ai
    def test_full_pipeline_with_retry(self):
        """Full _llm_verify pipeline: batching + retry + parse."""
        findings = [
            make_finding("S001", 5, msg="exec(cmd)", sev=Severity.CRITICAL,
                         snippet="exec(cmd)"),
            make_finding("S003", 12, msg="subprocess shell=True",
                         sev=Severity.ERROR,
                         snippet="subprocess.run(cmd, shell=True)"),
        ]
        cfg = _cfg()
        results = _llm_verify(findings, {
            5: "exec(cmd)",
            12: "subprocess.run(cmd, shell=True)",
        }, {}, cfg)
        assert len(results) == 2
        for r in results:
            assert r["ai_verified"] is True
            assert len(r.get("ai_reason", "")) > 5
