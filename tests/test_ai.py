"""scan --ai integration: verdicts mark findings, never silently delete."""
from click.testing import CliRunner

from aicaudit.cli import main
from aicaudit.output.json_output import dump_json
from aicaudit.scan import scan


def _write_vuln(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(
        "from flask import request\n"
        "def view(conn):\n"
        "    uid = request.args.get('id')\n"
        "    conn.execute(f'SELECT * FROM t WHERE id={uid}')\n", encoding="utf-8")
    return p


def test_ai_marks_without_deleting(tmp_path, monkeypatch):
    """Mock provider (no LLM) -> every finding stays, marked unverified."""
    monkeypatch.delenv("AICAUDIT_AI_PROVIDER", raising=False)
    findings = scan([_write_vuln(tmp_path)], ai_verify=True)
    assert len(findings) >= 1
    for f in findings:
        if f.ai is not None:
            assert f.ai["ai_status"] == "unverified"


def test_ai_attaches_verdict_fields(tmp_path, monkeypatch):
    from unittest import mock

    monkeypatch.setenv("AICAUDIT_AI_PROVIDER", "openai")
    monkeypatch.setenv("AICAUDIT_AI_KEY", "sk-test")

    def fake_verify(evidences, config=None):
        out = []
        for i, ev in enumerate(evidences):
            out.append({
                "rule_id": ev.rule_id, "message": ev.message, "file": ev.file,
                "line": ev.line, "severity": ev.severity, "snippet": ev.snippet,
                "fix": ev.fix,
                "ai_status": "confirmed" if i == 0 else "unverified",
                "ai_confidence": 0.9, "ai_reason": "taint path confirms",
                "ai_severity": ev.severity, "ai_cwe": ev.cwe or "",
                "ai_vuln_type": "sql-injection",
                "ai_suggested_fix": "parameterize", "evidence_used": [],
            })
        return out

    with mock.patch("aicaudit.llm.client.verify_findings", side_effect=fake_verify):
        findings = scan([_write_vuln(tmp_path)], ai_verify=True)
    assert findings, "findings must survive AI verification"
    with_ai = [f for f in findings if f.ai]
    assert with_ai, "verdicts must be attached"
    assert any(f.ai["ai_status"] == "confirmed" for f in with_ai)


def test_ai_strict_cli_filters_everything_unverified(tmp_path, monkeypatch):
    monkeypatch.delenv("AICAUDIT_AI_PROVIDER", raising=False)
    p = _write_vuln(tmp_path)
    result = CliRunner().invoke(main, ["scan", str(p), "--ai", "--ai-strict"])
    out = result.output + getattr(result, "stderr", "")
    assert "--ai-strict" in out          # filter summary printed
    assert "No issues found" in out      # mock -> all unverified -> empty


def test_ai_flag_accepted():
    import os
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write("def f(cmd):\n    exec(cmd)\n")
        fname = f.name
    try:
        r = CliRunner().invoke(main, ["scan", fname, "--ai"])
        assert r.exit_code == 0
    finally:
        os.unlink(fname)


def test_json_output_carries_ai_verdict(tmp_path):
    import json
    findings = scan([_write_vuln(tmp_path)])
    assert findings
    findings[0].ai = {"ai_status": "false_positive", "ai_confidence": 0.8,
                      "ai_reason": "sanitized upstream", "ai_severity": None,
                      "ai_cwe": "", "ai_suggested_fix": ""}
    data = json.loads(dump_json(findings))
    assert data["findings"][0]["ai"]["status"] == "false_positive"
    assert data["findings"][0]["ai"]["confidence"] == 0.8
