"""MCP server tests: tool implementations + server wiring."""

import pytest

pytest.importorskip("mcp", reason="aicaudit[mcp] extra not installed")

from aicaudit.mcp_server import (
    build_server,
    explain_finding_impl,
    fix_preview_impl,
    rules_impl,
    scan_impl,
    verify_impl,
)

VULN = (
    "from flask import request\n"
    "def view(conn):\n"
    "    uid = request.args.get('id')\n"
    "    conn.execute(f'SELECT * FROM t WHERE id={uid}')\n"
)

CLEAN = "x = eval('1+1')\n"


def _vuln_file(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(VULN, encoding="utf-8")
    return str(p)


class TestScanTool:

    def test_finding_with_taint_path(self, tmp_path):
        result = scan_impl([_vuln_file(tmp_path)])
        assert result["summary"]["total"] >= 1
        s001 = [f for f in result["findings"] if f["rule_id"] == "S001"]
        assert s001, "S001 must fire on flask injection"
        assert s001[0]["cwe"] == "CWE-89"
        assert s001[0]["taint_path"], "taint path must be rendered"
        assert "Flask request" in s001[0]["taint_path"][0]

    def test_constant_eval_stays_quiet(self, tmp_path):
        p = tmp_path / "clean.py"
        p.write_text(CLEAN, encoding="utf-8")
        result = scan_impl([str(p)])
        assert not [f for f in result["findings"] if f["rule_id"] == "S003"]

    def test_min_severity_filters(self, tmp_path):
        p = tmp_path / "warn.py"
        p.write_text("import random\nrandom.random()\n", encoding="utf-8")
        result = scan_impl([str(p)], min_severity="error")
        assert result["summary"]["total"] == 0

    def test_max_results_truncation_note(self, tmp_path):
        p = _vuln_file(tmp_path)
        result = scan_impl([p], max_results=0)
        assert result["findings"] == []
        assert "note" in result


class TestRulesTool:

    def test_catalog_contains_core_rules(self):
        rules = rules_impl()
        ids = {r["id"] for r in rules}
        assert {"S001", "S005", "Q001"} <= ids
        s001 = next(r for r in rules if r["id"] == "S001")
        assert s001["category"] == "taint-aware"
        assert s001["severity"] == "critical"


class TestVerifyTool:

    def test_mock_provider_all_unverified(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AICAUDIT_AI_PROVIDER", raising=False)
        result = verify_impl([_vuln_file(tmp_path)])
        assert result["ai_summary"]["unverified"] >= 1
        assert "advisory" in result["note"].lower()


class TestExplainTool:

    def test_explain_returns_path_and_function(self, tmp_path):
        p = _vuln_file(tmp_path)
        s001 = next(f for f in scan_impl([p])["findings"] if f["rule_id"] == "S001")
        detail = explain_finding_impl(p, s001["line"], "S001")
        assert detail["finding"]["rule_id"] == "S001"
        assert detail["taint_path_detail"]
        assert detail["enclosing_function"] and "def view" in detail["enclosing_function"]

    def test_explain_missing_finding(self, tmp_path):
        p = _vuln_file(tmp_path)
        detail = explain_finding_impl(p, 1, "S001")
        assert "error" in detail


class TestFixPreviewTool:

    def test_fix_preview_diff(self, tmp_path):
        p = tmp_path / "fixable.py"
        p.write_text("eval(user_cmd)\ny = 1\n", encoding="utf-8")
        scan = scan_impl([str(p)])
        s003 = next(f for f in scan["findings"] if f["rule_id"] == "S003")
        result = fix_preview_impl(str(p), "S003", s003["line"])
        assert result["changed"] is True
        assert "+#" in result["diff"]
        assert "nothing written" in result["note"]


class TestServerWiring:

    def test_build_server_registers_five_tools(self):
        import asyncio
        server = build_server()
        if not hasattr(server, "list_tools"):
            pytest.skip("MCP SDK list_tools API not available")
        tools = asyncio.run(server.list_tools())
        names = {t.name for t in tools}
        assert {"scan", "list_rules", "verify", "explain_finding", "fix_preview"} <= names
