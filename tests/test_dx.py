"""DX features: CI exit codes, init wizard, external rule dirs, hook files."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml not installed")
from click.testing import CliRunner

from aicaudit.cli import main
from aicaudit.scan import scan

REPO = Path(__file__).resolve().parent.parent


class TestExitCodes:

    def _write(self, tmp_path, code):
        p = tmp_path / "app.py"
        p.write_text(code, encoding="utf-8")
        return str(p)

    def test_fail_on_error_exits_1(self, tmp_path):
        # eval(cmd) is CRITICAL -> above error threshold
        path = self._write(tmp_path, "def f(cmd):\n    eval(cmd)\n")
        r = CliRunner().invoke(main, ["scan", path, "--fail-on", "error"])
        assert r.exit_code == 1
        assert "fail-on error" in r.output + getattr(r, "stderr", "")

    def test_fail_on_critical_with_lower_severity_exits_0(self, tmp_path):
        # bare except is WARNING -> below critical threshold
        path = self._write(tmp_path, "try:\n    x = 1\nexcept:\n    pass\n")
        r = CliRunner().invoke(main, ["scan", path, "--fail-on", "critical"])
        assert r.exit_code == 0

    def test_no_fail_on_always_0(self, tmp_path):
        path = self._write(tmp_path, "def f(cmd):\n    eval(cmd)\n")
        r = CliRunner().invoke(main, ["scan", path])
        assert r.exit_code == 0

    def test_clean_scan_fail_on_info_exits_0(self, tmp_path):
        path = self._write(tmp_path, "def add(a, b):\n    return a + b\n")
        r = CliRunner().invoke(main, ["scan", path, "--fail-on", "info"])
        assert r.exit_code == 0


class TestInit:

    def test_init_yes_creates_section(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = CliRunner().invoke(main, ["init", "--yes"])
        assert r.exit_code == 0
        pyproject = tmp_path / "pyproject.toml"
        assert pyproject.exists()
        text = pyproject.read_text(encoding="utf-8")
        assert '[tool.aicaudit]' in text
        assert 'min-severity = "warning"' in text

    def test_init_updates_existing_section(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text(
            "[tool.other]\nkey = 1\n\n[tool.aicaudit]\nmin-severity = \"info\"\n",
            encoding="utf-8")
        r = CliRunner().invoke(main, ["init", "--min-severity", "error", "--yes"])
        assert r.exit_code == 0
        text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
        assert 'min-severity = "error"' in text
        assert 'min-severity = "info"' not in text
        assert "[tool.other]" in text          # other sections preserved

    def test_init_with_ignore(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = CliRunner().invoke(main, ["init", "--yes", "--ignore", "venv/, build/"])
        assert r.exit_code == 0
        text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
        assert '"venv/"' in text and '"build/"' in text

    def test_init_interactive_prompts(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = CliRunner().invoke(main, ["init"], input="error\nmigrations/\n")
        assert r.exit_code == 0
        text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
        assert 'min-severity = "error"' in text
        assert '"migrations/"' in text


CUSTOM_RULE = '''
import ast
from aicaudit.rules.base import Finding, Rule, Severity, register

@register
class NoPrint(Rule):
    id = "Q100"
    name = "no-print"
    severity = Severity.INFO
    description = "no print"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "print":
                findings.append(Finding(
                    rule_id=self.id, message="print() call", message_zh="print()",
                    file=str(context.file_path), line=node.lineno,
                    severity=self.severity))
        return findings
'''


class TestExternalRules:

    def test_autodiscovered_rules_dir(self, tmp_path):
        rules_dir = tmp_path / ".aicaudit" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "no_print.py").write_text(CUSTOM_RULE, encoding="utf-8")
        (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

        findings = scan([tmp_path / "app.py"], base_root=tmp_path)
        q100 = [f for f in findings if f.rule_id == "Q100"]
        assert q100, "external rule must fire"
        assert q100[0].line == 1

    def test_rule_dirs_config(self, tmp_path):
        custom = tmp_path / "custom_rules"
        custom.mkdir()
        (custom / "no_print.py").write_text(CUSTOM_RULE, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.aicaudit]\nrule-dirs = ["custom_rules"]\n', encoding="utf-8")
        (tmp_path / "app.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")

        findings = scan([tmp_path / "app.py"], base_root=tmp_path)
        assert [f for f in findings if f.rule_id == "Q100"]

    def test_broken_rule_file_does_not_crash(self, tmp_path):
        rules_dir = tmp_path / ".aicaudit" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "broken.py").write_text("this is not python(\n", encoding="utf-8")
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        findings = scan([tmp_path / "app.py"], base_root=tmp_path)
        assert isinstance(findings, list)

    def test_external_rule_overrides_builtin(self, tmp_path):
        # same id as a builtin (S008) -> later registration wins
        rule = CUSTOM_RULE.replace('id = "Q100"', 'id = "S008"') \
                          .replace('message="print() call"', 'message="overridden: print() call"')
        rules_dir = tmp_path / ".aicaudit" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "override.py").write_text(rule, encoding="utf-8")
        (tmp_path / "app.py").write_text("print('x')\n", encoding="utf-8")

        findings = scan([tmp_path / "app.py"], base_root=tmp_path)
        s008 = [f for f in findings if f.rule_id == "S008"]
        assert s008 and "overridden" in s008[0].message


class TestHookFiles:

    def test_pre_commit_hooks_yaml_valid(self):
        doc = yaml.safe_load((REPO / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
        assert isinstance(doc, list) and doc[0]["id"] == "aicaudit"

    def test_action_yml_valid(self):
        doc = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))
        assert doc["name"] == "AICAudit"
        assert doc["runs"]["using"] == "composite"
        steps = doc["runs"]["steps"]
        assert any("aicaudit scan" in str(s.get("run", "")) for s in steps)

    def test_example_custom_rule_file_parses(self):
        import ast as _ast
        src = (REPO / "examples" / "custom_rule_example.py").read_text(encoding="utf-8")
        _ast.parse(src)
        assert "Q100" in src
