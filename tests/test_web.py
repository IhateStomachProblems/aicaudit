"""Web UI server tests: pages, scan API, export, fix, config."""
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


def _scan(bad_file, lang="en"):
    resp = client.post("/api/scan", json={"paths": [str(bad_file)], "lang": lang})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    return data["session_id"]


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
