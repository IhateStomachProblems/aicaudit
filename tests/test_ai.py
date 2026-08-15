"""Tests for AI verification module."""

import json

from codeaudit.llm.client import (
    _mock_verify,
    _parse_deep_response,
    filter_verified,
    verify_findings,
)
from codeaudit.rules.base import Finding, Severity


def make_finding(rule_id="S001", line=1, snippet="x = 1", msg="test"):
    return Finding(
        rule_id=rule_id, message=msg, message_zh=msg + "zh",
        file="test.py", line=line, severity=Severity.WARNING,
        snippet=snippet,
    )


def test_mock_verify_returns_all():
    findings = [make_finding()]
    result = _mock_verify(findings)
    assert len(result) == 1
    assert result[0]["ai_verified"] == True


def test_mock_verify_preserves_fields():
    findings = [make_finding(rule_id="S001", line=5, snippet="exec('x')")]
    result = _mock_verify(findings)
    assert result[0]["rule_id"] == "S001"
    assert result[0]["line"] == 5
    assert result[0]["snippet"] == "exec('x')"


def test_filter_verified_keeps_real():
    items = [
        {"rule_id": "S001", "ai_verified": True},
        {"rule_id": "S002", "ai_verified": False},
    ]
    result = filter_verified(items)
    assert len(result) == 1
    assert result[0]["rule_id"] == "S001"


def test_parse_deep_response_valid_json():
    findings = [make_finding()]
    response = json.dumps([{"index": 0, "is_real": True, "reason": "Looks valid"}])
    result = _parse_deep_response(response, findings, {})
    assert result[0]["ai_verified"] == True
    assert result[0]["ai_reason"] == "Looks valid"


def test_parse_deep_response_false_positive():
    findings = [make_finding()]
    response = json.dumps([{"index": 0, "is_real": False, "reason": "Safe input"}])
    result = _parse_deep_response(response, findings, {})
    assert result[0]["ai_verified"] == False


def test_parse_deep_response_fallback_on_bad_json():
    findings = [make_finding()]
    response = "not json at all"
    result = _parse_deep_response(response, findings, {})
    assert result[0]["ai_verified"] == True
    assert "Fallback" in result[0]["ai_reason"]


def test_verify_findings_with_mock_default():
    findings = [make_finding()]
    result = verify_findings(findings, {1: 'x = 1'})
    assert len(result) == 1


def test_ai_flag_works_on_cli():
    import os
    import tempfile

    from click.testing import CliRunner

    from codeaudit.cli import main
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write("exec('x')\n")
        fname = f.name
    try:
        r = CliRunner().invoke(main, ["scan", fname, "--ai"])
        assert r.exit_code == 0
    finally:
        os.unlink(fname)
