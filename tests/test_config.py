"""Tests for config and filtering features."""

import os
import tempfile
from pathlib import Path

from click.testing import CliRunner

from codeaudit.cli import main
from codeaudit.config import find_project_root, load_ignore_file, merge_config


def test_merge_config_cli_rules_override():
    cfg = merge_config("S001,Q001", None)
    assert cfg.rules == {"S001", "Q001"}


def test_merge_config_min_severity():
    cfg = merge_config(None, "warning")
    assert cfg.min_severity == "warning"


def test_load_ignore_file():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".codeauditignore").write_text(
            "build/\n# comment\ndist/\n", encoding="utf-8"
        )
        patterns = load_ignore_file(Path(td))
        assert patterns == ["build/", "dist/"]


def test_find_project_root():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "pyproject.toml").write_text("[tool.codeaudit]\n", encoding="utf-8")
        sub = root / "src" / "pkg"
        sub.mkdir(parents=True)
        assert find_project_root(sub) == root


def test_rules_filter_cli():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("exec('x')\npassword='sk-1234567890abcdefghijklmnop'\n")
        fname = f.name
    try:
        r = CliRunner().invoke(main, ["scan", fname, "--rules", "S002"])
        assert r.exit_code == 0
        assert "S002" in r.output
        assert "S003" not in r.output
    finally:
        os.unlink(fname)


def test_min_severity_filter_cli():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("x = 1729\n")
        fname = f.name
    try:
        r = CliRunner().invoke(main, ["scan", fname, "--min-severity", "warning"])
        assert "No issues found" in r.output
    finally:
        os.unlink(fname)


def test_ignore_patterns_cli():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / ".codeauditignore").write_text("generated/\n", encoding="utf-8")
        sub = d / "generated"
        sub.mkdir()
        (sub / "bad.py").write_text("exec('x')\n", encoding="utf-8")
        (d / "main.py").write_text("eval('1+1')\n", encoding="utf-8")
        r = CliRunner().invoke(main, ["scan", td])
        assert "1 files" in r.output
