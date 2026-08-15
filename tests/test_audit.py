"""Tests for audit command (evidence-chain deep audit)."""
import tempfile
from pathlib import Path

from codeaudit.audit import _find_containing_func, run_audit
from codeaudit.graph import CodeGraph


def test_audit_basic_no_ai():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "app.py").write_text(
            "from flask import Flask, request\n"
            "import sqlite3\n"
            "app = Flask(__name__)\n"
            "@app.route('/user')\n"
            "def get_user():\n"
            "    uid = request.args.get('id')\n"
            "    query = f\"SELECT * FROM users WHERE id = {uid}\"\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    conn.execute(query)\n"
            "    return 'ok'\n"
            "if __name__ == '__main__':\n"
            "    app.run()\n", encoding="utf-8")
        report = run_audit([str(d)], lang="en", use_ai=False)
        assert report["scan"]["findings"] >= 1
        assert report["scan"]["evidence_chains_traced"] >= 1
        assert report["ai"]["provider"] == "disabled"


def test_audit_find_containing_func():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "x.py").write_text("def a():\n    pass\ndef b():\n    eval('1')\n", encoding="utf-8")
        g = CodeGraph(d)
        g.build()
        # line 4 is inside def b
        result = _find_containing_func(g, str(d / "x.py"), 4)
        assert result is not None
        assert result.name == "b"


def test_audit_report_structure():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "x.py").write_text("eval('1')\n", encoding="utf-8")
        report = run_audit([str(d)], lang="en", use_ai=False)
        assert {"tool", "version", "paths", "scan", "ai", "issues"}.issubset(report.keys())
        assert report["tool"] == "codeaudit"
        assert isinstance(report["issues"], list)
