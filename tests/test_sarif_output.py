"""Tests for SARIF output format."""

import json

from aicaudit.output.sarif_output import SARIF_SCHEMA, SARIF_VERSION, dump_sarif
from aicaudit.rules.base import Finding, Severity


def _make_finding(rule_id, msg, sev, line=1):
    return Finding(rule_id=rule_id, message=msg, message_zh=msg + "_zh",
                   file="test.py", line=line, severity=sev)


def test_sarif_valid_schema():
    findings = [_make_finding("S001", "SQL injection", Severity.CRITICAL)]
    result = dump_sarif(findings)
    doc = json.loads(result)
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == SARIF_VERSION


def test_sarif_has_runs():
    findings = [_make_finding("S001", "test", Severity.ERROR)]
    doc = json.loads(dump_sarif(findings))
    assert len(doc["runs"]) == 1


def test_sarif_tool_info():
    doc = json.loads(dump_sarif([]))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AICAudit"
    assert len(driver["rules"]) >= 15


def test_sarif_results():
    findings = [
        _make_finding("S001", "SQL injection", Severity.CRITICAL, 10),
        _make_finding("Q001", "bare except", Severity.WARNING, 20),
    ]
    doc = json.loads(dump_sarif(findings))
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "S001"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


def test_sarif_with_fix():
    f = Finding(rule_id="S001", message="SQL injection", message_zh="SQL注入",
                file="test.py", line=1, severity=Severity.CRITICAL,
                fix="Use parameterized queries")
    doc = json.loads(dump_sarif([f]))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "parameterized" in msg


def test_sarif_level_mapping():
    sev_map = {
        Severity.CRITICAL: "error",
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.INFO: "note",
    }
    for sev, expected in sev_map.items():
        f = _make_finding("TEST", "msg", sev)
        doc = json.loads(dump_sarif([f]))
        assert doc["runs"][0]["results"][0]["level"] == expected, f"Failed for {sev}"


def test_sarif_empty_findings():
    doc = json.loads(dump_sarif([]))
    assert doc["runs"][0]["results"] == []
