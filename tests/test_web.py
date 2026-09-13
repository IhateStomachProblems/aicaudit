"""Web UI server tests: pages, scan API, export, fix, config, SSE, persistence."""
import os

import pytest
from fastapi.testclient import TestClient

from aicaudit.web.server import app, sessions

client = TestClient(app)

BAD_CODE = "x = eval(user_input)\n"


@pytest.fixture
def bad_file(tmp_path):
    p = tmp_path / "bad.py"
    p.write_text(BAD_CODE, encoding="utf-8")
    return p


@pytest.fixture
def taint_file(tmp_path):
    p = tmp_path / "vuln.py"
    p.write_text(
        "from flask import request\n"
        "def view(conn):\n"
        "    uid = request.args.get('id')\n"
        "    conn.execute(f'SELECT * FROM t WHERE id={uid}')\n", encoding="utf-8")
    return p


def _scan(bad_file, lang="en"):
    resp = client.post("/api/scan", json={"paths": [str(bad_file)], "lang": lang})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    return data["session_id"]


class TestNewEndpoints:

    def test_scan_carries_taint_path_and_cwe(self, taint_file):
        sid = _scan(taint_file)
        s = sessions[sid]
        s001 = [f for f in s["findings"] if f["rule_id"] == "S001"]
        assert s001, "S001 must fire on the vulnerable flask app"
        f = s001[0]
        assert f["cwe"] == "CWE-89"
        assert f["taint_path"], "taint path must be serialized into the session"
        assert f["taint_path"][0]["source"]["desc"].startswith("Flask request")

    def test_sessions_listing(self, bad_file):
        _scan(bad_file)
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        items = resp.json()["sessions"]
        assert any(s["total"] >= 1 for s in items)
        first = items[0]
        assert {"session_id", "timestamp", "total", "counts"}.issubset(first)

    def test_file_content_pygments_window(self, taint_file):
        resp = client.get("/api/file-content", params={"path": str(taint_file), "line": 4})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_line"] == 4
        assert "html" in data and 'class="n">conn<' in data["html"]
        assert 'class="hll"' in data["html"]      # target line emphasized

    def test_file_content_missing_file_404(self):
        resp = client.get("/api/file-content", params={"path": "nope.py", "line": 1})
        assert resp.status_code == 404

    def test_fix_preview_diff(self, tmp_path):
        p = tmp_path / "fixable.py"
        p.write_text("eval(user_input)\ny = 1\n", encoding="utf-8")
        resp = client.post("/api/fix-preview", json={
            "file": str(p), "rule_id": "S003", "line": 1, "fix": "# comment out",
            "severity": "error", "message": "eval",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["changed"]
        assert data["diff"] and "+#" in data["diff"]

    def test_fix_rollback_restores(self, tmp_path):
        p = tmp_path / "fixable.py"
        original = "eval(user_input)\ny = 1\n"
        p.write_text(original, encoding="utf-8")
        apply = client.post("/api/apply-fix", json={
            "file": str(p), "rule_id": "S003", "line": 1, "fix": "# x",
            "severity": "error", "message": "eval",
        }).json()
        assert apply["backup"], "backup path must be returned"
        assert "TODO" in p.read_text(encoding="utf-8")
        rb = client.post("/api/fix-rollback", json={"backup": apply["backup"]})
        assert rb.status_code == 200
        assert p.read_text(encoding="utf-8") == original

    def test_fix_rollback_rejects_non_bak(self):
        resp = client.post("/api/fix-rollback", json={"backup": "important.py"})
        assert resp.status_code == 400

    def test_sse_scan_stream(self, bad_file):
        with client.stream("GET", "/api/scan/stream",
                           params={"paths": str(bad_file)}) as resp:
            assert resp.status_code == 200
            body = ""
            for chunk in resp.iter_text():
                body += chunk
        assert '"type": "progress"' in body or '"type":"progress"' in body
        assert '"type": "done"' in body or '"type":"done"' in body

    def test_config_status(self, monkeypatch):
        monkeypatch.delenv("AICAUDIT_AI_PROVIDER", raising=False)
        resp = client.get("/api/config/status")
        assert resp.status_code == 200
        assert resp.json()["provider"] == "mock"


class TestPages:

    def test_index(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_scan_page_lists_rules(self):
        resp = client.get("/scan")
        assert resp.status_code == 200
        assert "S001" in resp.text

    def test_rules_page(self):
        resp = client.get("/rules")
        assert resp.status_code == 200
        assert "SQL" in resp.text

    def test_config_page(self):
        resp = client.get("/config")
        assert resp.status_code == 200

    def test_results_page_known_and_unknown_session(self, bad_file):
        sid = _scan(bad_file)
        assert client.get(f"/results/{sid}").status_code == 200
        assert client.get("/results/nonexistent").status_code == 200


class TestScanApi:

    def test_scan_creates_session(self, bad_file):
        sid = _scan(bad_file)
        assert sid in sessions
        s = sessions[sid]
        assert s["total"] >= 1
        assert any(f["rule_id"] == "S003" for f in s["findings"])

    def test_scan_chinese_lang(self, bad_file):
        sid = _scan(bad_file, lang="zh")
        assert sessions[sid]["lang"] == "zh"

    def test_results_404_for_unknown(self):
        assert client.get("/api/results/does-not-exist").status_code == 404

    def test_results_roundtrip(self, bad_file):
        sid = _scan(bad_file)
        resp = client.get(f"/api/results/{sid}")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1


class TestVerifyApi:

    def test_verify_unknown_session_404(self):
        resp = client.post("/api/verify", json={"session_id": "nope"})
        assert resp.status_code == 404

    def test_verify_without_provider_returns_error(self, bad_file, monkeypatch):
        monkeypatch.delenv("AICAUDIT_AI_PROVIDER", raising=False)
        sid = _scan(bad_file)
        resp = client.post("/api/verify", json={"session_id": sid})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ai_verified"] is False


class TestConfigApi:

    def test_set_and_clear_env(self, monkeypatch):
        monkeypatch.delenv("AICAUDIT_AI_KEY", raising=False)
        resp = client.post("/api/config", json={"ai_key": "sk-test-123"})
        assert resp.status_code == 200 and resp.json()["ok"] is True
        assert os.environ["AICAUDIT_AI_KEY"] == "sk-test-123"
        resp = client.post("/api/config", json={"ai_key": ""})
        assert "AICAUDIT_AI_KEY" not in os.environ


class TestExportApi:

    def test_export_unknown_session_404(self):
        resp = client.post("/api/export", json={"session_id": "nope"})
        assert resp.status_code == 404

    def test_export_json(self, bad_file):
        sid = _scan(bad_file)
        resp = client.post("/api/export", json={"session_id": sid, "format": "json"})
        assert resp.status_code == 200
        assert "findings" in resp.json()

    def test_export_sarif(self, bad_file):
        sid = _scan(bad_file)
        resp = client.post("/api/export", json={"session_id": sid, "format": "sarif"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["version"] == "2.1.0"
        assert body["runs"][0]["tool"]["driver"]["name"]


class TestApplyFixApi:

    def test_missing_params_400(self):
        resp = client.post("/api/apply-fix", json={"file": "", "fix": ""})
        assert resp.status_code == 400

    def test_apply_fix_writes_and_backs_up(self, tmp_path):
        p = tmp_path / "fixable.py"
        p.write_text("eval(user_input)\ny = 1\n", encoding="utf-8")
        resp = client.post("/api/apply-fix", json={
            "file": str(p), "rule_id": "S003", "line": 1,
            "fix": "# TODO: refactor dangerous call",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["backup"] is not None
        assert str(tmp_path / "fixable.py.bak") == data["backup"]
        assert "TODO" in p.read_text(encoding="utf-8")
