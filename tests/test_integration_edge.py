"""Integration tests: edge cases and defensive branches."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from click.testing import CliRunner

from aicaudit.cli import main


def test_scan_default_cwd():
    # No paths arg -> defaults to current dir
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code == 0


def test_scan_syntax_error_file_skipped():
    # Invalid python file should be skipped silently (no crash)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write("def broken(:\n")
        fname = tf.name
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", fname])
        assert result.exit_code == 0
    finally:
        os.unlink(fname)


def test_scan_directory_with_no_python_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "readme.txt").write_text("hello", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", tmpdir])
        assert "No Python files found" in result.output + getattr(result, "stderr", "")


def test_scan_ai_flag_accepted():
    # --ai flag is accepted (currently no-op hook)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write("x = 1\n")
        fname = tf.name
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", fname, "--ai"])
        assert result.exit_code == 0
    finally:
        os.unlink(fname)


def test_main_module_entry():
    # python -m aicaudit should work (exercises __main__.py)
    result = subprocess.run(
        [sys.executable, "-m", "aicaudit", "--help"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    assert result.returncode == 0
    assert "AICAudit" in result.stdout


def test_dangerous_member_access_not_flag():
    # a Call with a non-Name, non-Attribute func (e.g. builtin callable) -> ""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("result = sorted([3,1,2])\n")
        fname = f.name
    try:
        runner = CliRunner()
        r = runner.invoke(main, ["scan", fname])
        assert r.exit_code == 0
    finally:
        os.unlink(fname)

def test_dangerous_lambda_call_safe():
    import ast as _ast

    from aicaudit.rules.base import ScanContext
    from aicaudit.rules.security.dangerous_functions import DangerousFunctions
    code = "(lambda x: x + 1)(5)"
    tree = _ast.parse(code)
    ctx = ScanContext(file_path=Path("fake.py"), source=code, lines=code.splitlines(keepends=False))
    assert DangerousFunctions().check(tree, ctx) == []

