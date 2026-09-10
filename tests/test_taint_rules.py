"""Taint-aware rule integration tests: full scan() pipeline."""
import json

from aicaudit.scan import scan


def scan_code(tmp_path, code, name="app.py"):
    (tmp_path / name).write_text(code, encoding="utf-8")
    return scan([tmp_path / name])


class TestFalsePositiveKills:

    def test_constant_sql_variable_not_flagged(self, tmp_path):
        findings = scan_code(tmp_path, 'query = "SELECT 1"\nconn.execute(query)\n')
        assert not [f for f in findings if f.rule_id == "S001"]

    def test_join_with_base_dir_not_flagged(self, tmp_path):
        findings = scan_code(tmp_path,
                             'import os\n'
                             'BASE_DIR = os.path.dirname(os.path.abspath(__file__))\n'
                             'open(os.path.join(BASE_DIR, "cfg.json"))\n')
        assert not [f for f in findings if f.rule_id == "S004"]

    def test_literal_eval_not_flagged(self, tmp_path):
        findings = scan_code(tmp_path, 'x = eval("1+1")\n')
        assert not [f for f in findings if f.rule_id == "S003"]

    def test_literal_os_system_not_flagged(self, tmp_path):
        findings = scan_code(tmp_path, 'import os\nos.system("ls")\n')
        assert not [f for f in findings if f.rule_id == "S003"]

    def test_self_scan_has_no_s004_s005_on_constants(self, tmp_path):
        # the classic self-scan false positives from the project history
        findings = scan_code(tmp_path,
                             'import urllib.request\n'
                             'pyproject = "pyproject.toml"\n'
                             'data = open(pyproject, "rb").read()\n'
                             'resp = urllib.request.urlopen("https://example.com/api")\n')
        assert not [f for f in findings if f.rule_id in ("S004", "S005")]


class TestTruePositivesWithPaths:

    def test_s001_carries_taint_path_and_cwe(self, tmp_path):
        findings = scan_code(tmp_path,
                             'from flask import request\n'
                             'def view(conn):\n'
                             '    uid = request.args.get("id")\n'
                             '    conn.execute(f"SELECT * FROM t WHERE id={uid}")\n')
        s001 = [f for f in findings if f.rule_id == "S001"]
        assert len(s001) == 1
        f = s001[0]
        assert f.cwe == "CWE-89"
        assert f.taint_path and "request" in f.taint_path[0].origin.desc

    def test_s003_tainted_eval_keeps_firing(self, tmp_path):
        findings = scan_code(tmp_path, 'cmd = input()\neval(cmd)\n')
        assert [f for f in findings if f.rule_id == "S003"]

    def test_unknown_param_still_fires_s004(self, tmp_path):
        findings = scan_code(tmp_path, 'def load(filename):\n    open(filename)\n')
        assert [f for f in findings if f.rule_id == "S004"]

    def test_sanitized_path_not_flagged(self, tmp_path):
        findings = scan_code(tmp_path,
                             'import os\n'
                             'name = input()\n'
                             'open(os.path.basename(name))\n')
        assert not [f for f in findings if f.rule_id == "S004"]


class TestOutputFields:

    def test_json_includes_cwe_and_taint_path(self, tmp_path):
        from aicaudit.output.json_output import dump_json
        (tmp_path / "app.py").write_text(
            'from flask import request\n'
            'def v(conn):\n'
            '    uid = request.args.get("i")\n'
            '    conn.execute(f"SELECT {uid}")\n', encoding="utf-8")
        findings = scan([tmp_path / "app.py"])
        data = json.loads(dump_json(findings))
        rec = data["findings"][0]
        assert rec["cwe"] == "CWE-89"
        assert rec["taint_path"][0]["source"]["desc"].startswith("Flask request")

    def test_markdown_renders_taint_line(self, tmp_path):
        from aicaudit.output.markdown_output import dump_markdown
        (tmp_path / "app.py").write_text(
            'from flask import request\n'
            'def v(conn):\n'
            '    uid = request.args.get("i")\n'
            '    conn.execute(f"SELECT {uid}")\n', encoding="utf-8")
        findings = scan([tmp_path / "app.py"])
        md = dump_markdown(findings)
        assert "Taint path" in md
        assert "CWE-89" in md
        assert "app.py:3" in md

    def test_sarif_codeflows_present(self, tmp_path):
        from aicaudit.output.sarif_output import dump_sarif
        (tmp_path / "app.py").write_text(
            'from flask import request\n'
            'def v(conn):\n'
            '    uid = request.args.get("i")\n'
            '    conn.execute(f"SELECT {uid}")\n', encoding="utf-8")
        findings = scan([tmp_path / "app.py"])
        doc = json.loads(dump_sarif(findings))
        result = doc["runs"][0]["results"][0]
        assert result["properties"]["cwe"] == "CWE-89"
        assert result["codeFlows"]
        locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 3
