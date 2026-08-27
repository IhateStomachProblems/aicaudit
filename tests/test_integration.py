"""Integration tests: exercise the CLI and scan engine end-to-end."""

import json
import os
import tempfile
from pathlib import Path

from click.testing import CliRunner

from aicaudit.cli import main


def write_temp(code, suffix=".py"):
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as f:
        f.write(code)
        fname = f.name
    return fname


def test_scan_default_markdown():
    path = write_temp(
        "def foo():\n    exec('x = 1')\n    return x\n"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", path])
    assert result.exit_code == 0
    assert "AICAudit Report" in result.output
    assert "S003" in result.output
    os.unlink(path)


def test_scan_json_output():
    path = write_temp(
        "password = 'sk-1234567890abcdefghijklmnop'\n"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", path, "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output[result.output.index("{"):])
    assert data["total"] >= 1
    assert data["findings"][0]["severity"] == "critical"
    os.unlink(path)


def test_scan_zh_lang():
    path = write_temp(
        "def foo():\n    import os\n    os.system('ls')\n"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", path, "--lang", "zh"])
    assert result.exit_code == 0
    assert "危险函数" in result.output
    os.unlink(path)


def test_scan_no_findings():
    path = write_temp("def add(a, b):\n    return a + b\n")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", path])
    assert "No issues found" in result.output
    os.unlink(path)


def test_rules_command():
    runner = CliRunner()
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    assert "S001" in result.output
    assert "P002" in result.output


def test_scan_directory_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        (d / "a.py").write_text("exec('x=1')", encoding="utf-8")
        (d / "sub").mkdir()
        (d / "sub" / "b.py").write_text("eval('1+1')", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", tmpdir])
        assert result.exit_code == 0
        assert "2 files" in result.output


def test_scan_nonexistent_path():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "/does/not/exist.py"])
    assert result.exit_code != 0
