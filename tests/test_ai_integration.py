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
    _call_openai_compat,
    _extract_response_text,
    verify_findings,
)
from aicaudit.llm.prompts import FindingEvidence, build_evidence_prompt
from aicaudit.taint.model import TaintHop, TaintOrigin, TaintPath

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


def make_evidence(rule_id, snippet, taint=True):
    paths = [TaintPath(
        origin=TaintOrigin(kind="source", desc="request.args (Flask user input)",
                           file="app.py", line=15),
        hops=[TaintHop(file="app.py", line=16, desc="assigned to 'uid'")],
        sink=TaintHop(file="app.py", line=17, desc=".execute()"))] if taint else []
    return FindingEvidence(
        rule_id=rule_id, severity="critical", file="app.py", line=17,
        message="SQL injection risk", snippet=snippet, taint_paths=paths,
        function_source="def view(conn):\n"
                        "    uid = request.args.get('id')\n"
                        "    conn.execute(f\"SELECT * FROM t WHERE id={uid}\")",
        imports="from flask import request")


class TestAIIntegration:

    def test_extract_response_text(self):
        """Test _extract_response_text handles content and reasoning_content."""
        assert _extract_response_text({"content": "Hello"}) == "Hello"
        assert _extract_response_text({"content": "", "reasoning_content": "Thinking..."}) == "Thinking..."

    @requires_live_ai
    def test_single_finding_verdict(self):
        """AI judges a SQL injection backed by a complete taint path."""
        ev = make_evidence("S001", 'conn.execute(f"SELECT * FROM users WHERE id={user_id}")')
        results = verify_findings([ev], config=_cfg())
        assert len(results) == 1
        r = results[0]
        assert r["ai_status"] in ("confirmed", "false_positive", "unverified")
        if r["ai_status"] == "confirmed":
            assert r["ai_confidence"] > 0.5
            assert len(r["ai_reason"]) > 10

    @requires_live_ai
    def test_false_positive_detection(self):
        """Parameterized query must never be a high-confidence confirm."""
        ev = FindingEvidence(
            rule_id="S001", severity="error", file="db.py", line=20,
            message="SQL injection risk",
            snippet='conn.execute("SELECT * FROM t WHERE id = ?", (user_id,))',
            function_source='def get(db, user_id):\n'
                            '    return db.execute("SELECT * FROM t WHERE id = ?", (user_id,))',
            imports="import sqlite3", taint_paths=[])
        results = verify_findings([ev], config=_cfg())
        r = results[0]
        assert not (r["ai_status"] == "confirmed" and r["ai_confidence"] > 0.8)

    @requires_live_ai
    def test_multi_finding_batch(self):
        """AI handles a batch of mixed findings."""
        evidences = [
            make_evidence("S001", "conn.execute(f'... {uid}')"),
            make_evidence("S002", 'API_KEY = "sk-test12345678"', taint=False),
            FindingEvidence(rule_id="Q001", severity="warning", file="app.py", line=30,
                            message="Bare except", snippet="except:",
                            function_source="try:\n    x = 1\nexcept:\n    pass",
                            imports="", taint_paths=[]),
        ]
        results = verify_findings(evidences, config=_cfg())
        assert len(results) == 3
        for r in results:
            assert r["ai_status"] in ("confirmed", "false_positive", "unverified")

    @requires_live_ai
    def test_transport_alive(self):
        resp = _call_openai_compat("Reply with exactly: ok", _cfg())
        assert resp.strip()

    def test_prompt_shape_local(self):
        ev = make_evidence("S001", "conn.execute(q)")
        prompt = build_evidence_prompt([ev])
        assert "Taint path" in prompt
        assert "Enclosing function:" in prompt
