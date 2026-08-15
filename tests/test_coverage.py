"""Coverage: __main__, config edge cases, fix failure paths, LLM providers."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from click.testing import CliRunner

from codeaudit.cli import main
from codeaudit.config import merge_config
from codeaudit.fix import FixStatus, fix_file
from codeaudit.llm.client import (
    AiConfig,
    _mock_verify,
    _parse_response,
    load_ai_config,
    verify_findings,
)
from codeaudit.rules.base import Finding, Severity


def make_finding(rule_id="S001", line=1, msg="test", snippet="x=1", file="test.py"):
    return Finding(rule_id=rule_id, message=msg, message_zh=msg+"zh", file=file, line=line, severity=Severity.WARNING, snippet=snippet)


# ---------- __main__ ----------

def test_main_module_entry():
    """python -m codeaudit --help should work."""
    r = subprocess.run([sys.executable, "-m", "codeaudit", "--help"], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)), encoding="utf-8", errors="replace")
    assert r.returncode == 0
    assert "CodeAudit" in r.stdout


# ---------- config edge cases ----------

def test_config_no_pyproject():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        cfg = merge_config(None, None, d)
        assert cfg.rules == set()


def test_config_pyproject_with_rules():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "pyproject.toml").write_text("[tool.codeaudit]\nrules = [\"S001\", \"Q001\"]\nmin-severity = \"error\"\n", encoding="utf-8")
        cfg = merge_config(None, None, d)
        assert cfg.rules == {"S001", "Q001"}
        assert cfg.min_severity == "error"


def test_config_pyproject_ignore():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "pyproject.toml").write_text("[tool.codeaudit]\nignore = [\"tests/\"]\n", encoding="utf-8")
        (d / ".codeauditignore").write_text("venv/\n", encoding="utf-8")
        cfg = merge_config(None, None, d)
        assert "tests/" in cfg.ignore_patterns
        assert "venv/" in cfg.ignore_patterns


def test_cli_scan_with_config():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "pyproject.toml").write_text("[tool.codeaudit]\nmin-severity = \"error\"\n", encoding="utf-8")
        (d / "main.py").write_text("eval('1+1')", encoding="utf-8")
        r = CliRunner().invoke(main, ["scan", td])
        assert r.exit_code == 0


# ---------- fix failure paths ----------

def test_fix_syntax_error_original():
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    f.write("def broken(:\n")
    fname = f.name
    f.close()
    try:
        result = fix_file(fname, [], dry_run=True)
        assert result.status == FixStatus.FAILED
    finally:
        os.unlink(fname)


def test_fix_nonexistent_file():
    result = fix_file("/nonexistent/file.py", [], dry_run=True)
    assert result.status == FixStatus.FAILED


def test_fix_skipped_no_fix_needed():
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    f.write("x = 1\n")
    fname = f.name
    f.close()
    try:
        result = fix_file(fname, [], dry_run=True)
        assert result.status == FixStatus.SKIPPED
    finally:
        os.unlink(fname)


def test_fix_dangerous_call_syntax_error_after():
    """If fix introduces syntax error, it should fail."""
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    f.write("exec('x=1')\n")
    fname = f.name
    f.close()
    try:
        findings = [Finding(rule_id="S003", message="test", message_zh="test", file=fname, line=1, severity=Severity.ERROR, fix="dangerous")]
        result = fix_file(fname, findings, dry_run=True)
        assert result.verified == True
    finally:
        os.unlink(fname)


# ---------- LLM providers ----------

def test_load_ai_config_mock_default():
    cfg = AiConfig()
    assert cfg.provider == "mock"


def test_ai_config_openai():
    os.environ["CODEAUDIT_AI_PROVIDER"] = "openai"
    os.environ["CODEAUDIT_AI_KEY"] = "sk-test"
    cfg = load_ai_config()
    assert cfg.provider == "openai"
    assert cfg.model == "gpt-4o-mini"
    del os.environ["CODEAUDIT_AI_PROVIDER"]
    del os.environ["CODEAUDIT_AI_KEY"]


def test_ai_config_ollama():
    os.environ["CODEAUDIT_AI_PROVIDER"] = "ollama"
    cfg = load_ai_config()
    assert cfg.provider == "ollama"
    del os.environ["CODEAUDIT_AI_PROVIDER"]


def test_ai_config_openrouter():
    os.environ["CODEAUDIT_AI_PROVIDER"] = "openrouter"
    cfg = load_ai_config()
    assert cfg.provider == "openrouter"
    del os.environ["CODEAUDIT_AI_PROVIDER"]


def test_mock_verify_empty():
    assert _mock_verify([]) == []


def test_parse_response_multiple():
    findings = [make_finding(), make_finding(rule_id="S002")]
    response = json.dumps([{"index": 0, "is_real": True, "reason": "ok"}, {"index": 1, "is_real": False, "reason": "fp"}])
    result = _parse_response(response, findings)
    assert result[0]["ai_verified"] == True
    assert result[1]["ai_verified"] == False


def test_verify_findings_mock_default():
    result = verify_findings([make_finding()], {1: "x=1"})
    assert len(result) == 1
