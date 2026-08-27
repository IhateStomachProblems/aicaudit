"""Extended audit tests: AI deep-audit branch + helper functions."""
import json
import tempfile
from pathlib import Path
from unittest import mock

from aicaudit.audit import _build_file_function_map, _entry_in_file, run_audit
from aicaudit.graph import CodeGraph, EntryPoint


def _make_project():
    d = Path(tempfile.mkdtemp())
    (d / "app.py").write_text(
        "from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n"
        "@app.route('/user')\ndef get_user():\n"
        "    uid = request.args.get('id')\n"
        "    query = f\"SELECT * FROM users WHERE id = {uid}\"\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    conn.execute(query)\n    return 'ok'\n", encoding="utf-8")
    return d


def _run_with_ai(verdict):
    d = _make_project()
    with mock.patch.dict("os.environ", {
        "AICAUDIT_AI_PROVIDER": "openai", "AICAUDIT_AI_KEY": "sk-test",
        "AICAUDIT_AI_BASE": "https://api.openai.com/v1",
    }), mock.patch("aicaudit.audit.verify_findings", side_effect=_fake_verify(verdict)):
        report = run_audit([str(d)], lang="en", use_ai=True)
    return report
def _fake_verify(verdict):
    """Factory returning a function that parses verdict and returns verify-shaped list."""
    verdicts = json.loads(verdict)
    def _v(findings, snippets, ec, cfg):
        out = []
        for i, f in enumerate(findings):
            v = {}
            for item in verdicts:
                if item.get("index") == i:
                    v = item
                    break
            out.append({
                "rule_id": f.rule_id, "message": f.message, "file": f.file,
                "line": f.line, "severity": f.severity.value, "snippet": f.snippet,
                "fix": f.fix,
                "ai_verified": v.get("is_real", True),
                "ai_reason": v.get("reason", ""),
                "ai_severity": v.get("severity", f.severity.value),
                "ai_vuln_type": v.get("vuln_type", ""),
                "ai_suggested_fix": v.get("suggested_fix", ""),
                "evidence_used": [],
            })
        return out
    return _v


def test_audit_with_ai_verified():
    verdict = json.dumps([{"index": 0, "is_real": True, "severity": "critical",
                           "vuln_type": "SQL-injection", "suggested_fix": "use params",
                           "reason": "confirmed"}])
    report = _run_with_ai(verdict)
    assert report["ai"]["provider"] == "openai"
    assert report["ai"]["confirmed"] == 1
    assert report["issues"][0]["ai"]["confirmed"] is True
    assert report["issues"][0]["ai"]["vuln_type"] == "SQL-injection"


def test_audit_with_ai_false_positive():
    verdict = json.dumps([{"index": 0, "is_real": False, "reason": "safe input"}])
    report = _run_with_ai(verdict)
    assert report["ai"]["confirmed"] == 0
    assert report["issues"][0]["ai"]["confirmed"] is False


def test_build_file_function_map():
    d = _make_project()
    g = CodeGraph(d)
    g.build()
    mapping = _build_file_function_map(g)
    assert "app.py" in mapping
    assert mapping["app.py"]


def test_entry_in_file():
    ep = EntryPoint(kind="route", location="app.py:5", pattern="/user")
    assert _entry_in_file(ep, "app.py")
    assert _entry_in_file(ep, "/abs/path/app.py")
    assert not _entry_in_file(ep, "other.py")
