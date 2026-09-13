"""Extended audit tests: evidence assembly + three-state AI verdicts."""
import json
import tempfile
from pathlib import Path
from unittest import mock

from aicaudit.audit import _entry_in_file, run_audit
from aicaudit.graph import EntryPoint


def _make_project():
    d = Path(tempfile.mkdtemp())
    (d / "app.py").write_text(
        "from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n"
        "@app.route('/user')\ndef get_user():\n"
        "    uid = request.args.get('id')\n"
        "    query = f\"SELECT * FROM users WHERE id = {uid}\"\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    conn.execute(query)\n    return 'ok'\n"
        "API_TOKEN = 'sk-abcdefghijklmnop1234567890'\n"
        "import hashlib\n"
        "def hash_pw(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n", encoding="utf-8")
    return d


def _verdict(status, **extra):
    v = {"ai_status": status, "ai_confidence": 0.9, "ai_reason": "taint confirms",
         "ai_severity": "critical", "ai_cwe": "CWE-89", "ai_vuln_type": "sql-injection",
         "ai_suggested_fix": "parameterize", "evidence_used": []}
    v.update(extra)
    return v


def _run_with_verdicts(verdict_by_rule):
    """Run audit with verify_findings mocked: rule -> verdict mapping."""
    d = _make_project()

    def fake_verify(evidences, config=None):
        out = []
        for ev in evidences:
            status = verdict_by_rule.get(ev.rule_id, "unverified")
            v = _verdict(status)
            v.update({"rule_id": ev.rule_id, "message": ev.message, "file": ev.file,
                      "line": ev.line, "severity": ev.severity, "snippet": ev.snippet,
                      "fix": ev.fix})
            out.append(v)
        return out

    with mock.patch.dict("os.environ", {
        "AICAUDIT_AI_PROVIDER": "openai", "AICAUDIT_AI_KEY": "sk-test",
    }), mock.patch("aicaudit.audit.verify_findings", side_effect=fake_verify):
        return run_audit([str(d)], lang="en", use_ai=True)


def test_audit_report_carries_taint_paths():
    report = _run_with_verdicts({"S001": "confirmed"})
    issues = report["issues"]
    s001 = [i for i in issues if i["rule_id"] == "S001"]
    assert s001, "SQLi finding must be present"
    assert s001[0]["taint_paths"], "taint path must be in the report"
    assert "Flask request" in s001[0]["taint_paths"][0]
    assert report["scan"]["taint_paths_traced"] >= 1


def test_audit_ai_confirmed():
    report = _run_with_verdicts({"S001": "confirmed"})
    assert report["ai"]["provider"] == "openai"
    assert report["ai"]["confirmed"] >= 1
    confirmed = [i for i in report["issues"] if i["ai"]["status"] == "confirmed"]
    assert confirmed
    assert confirmed[0]["ai"]["cwe"] == "CWE-89"


def test_audit_ai_three_state_summary():
    report = _run_with_verdicts({"S001": "confirmed", "S002": "false_positive",
                                 "S006": "unverified"})
    ai = report["ai"]
    assert ai["confirmed"] >= 1
    assert ai["false_positive"] >= 1
    assert ai["unverified"] >= 1
    assert ai["total"] >= 3


def test_audit_without_ai():
    d = _make_project()
    report = run_audit([str(d)], lang="en", use_ai=False)
    assert report["ai"]["provider"] == "disabled"
    assert report["issues"]
    assert all(i["ai"]["status"] is None for i in report["issues"])


def test_audit_json_serializable():
    report = _run_with_verdicts({"S001": "confirmed"})
    json.dumps(report)


def test_entry_in_file():
    ep = EntryPoint(kind="route", location="app.py:5", pattern="/user")
    assert _entry_in_file(ep, "app.py")
    assert _entry_in_file(ep, "/abs/path/app.py")
    assert not _entry_in_file(ep, "other.py")
