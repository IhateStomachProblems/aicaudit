"""Tests for fix engine with verification loop."""

import os
import tempfile

from aicaudit.fix import (
    FixStatus,
    _fix_bare_except,
    _fix_dangerous_call,
    fix_file,
)
from aicaudit.rules.base import Finding, Severity


def make_finding(rule_id="Q001", line=1, fix_desc="fix this", file="test.py"):
    return Finding(
        rule_id=rule_id, message="test", message_zh="test",
        file=file, line=line, severity=Severity.WARNING,
        fix=fix_desc,
    )


def test_fix_bare_except():
    result = _fix_bare_except("except:\n")
    assert result is not None
    assert "except Exception:" in result


def test_fix_bare_except_with_indent():
    result = _fix_bare_except("    except:\n")
    assert result is not None
    assert result.startswith("    ")
    assert "except Exception:" in result


def test_fix_bare_except_not_bare():
    result = _fix_bare_except("except ValueError:\n")
    assert result is None


def test_fix_dangerous_eval():
    result = _fix_dangerous_call("eval('1+1')\n")
    assert result is not None
    assert "TODO" in result


def test_fix_dangerous_exec():
    result = _fix_dangerous_call("exec('x=1')\n")
    assert result is not None
    assert "TODO" in result


def test_fix_dangerous_safe_call():
    result = _fix_dangerous_call("print('hello')\n")
    assert result is None


def test_fix_file_dry_run():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:\n    pass\n")
        fname = f.name
    try:
        findings = [make_finding(rule_id="Q001", line=3, fix_desc="bare except", file=fname)]
        result = fix_file(fname, findings, dry_run=True)
        assert result.status == FixStatus.APPLIED
        assert "except Exception:" in result.after
    finally:
        os.unlink(fname)


def test_fix_file_actual_write():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:\n    pass\n")
        fname = f.name
    try:
        findings = [make_finding(rule_id="Q001", line=3, fix_desc="bare except", file=fname)]
        fix_file(fname, findings, dry_run=False, backup=False)
        with open(fname, encoding="utf-8") as fh:
            content = fh.read()
        assert "except Exception:" in content
        assert "except:" not in content
    finally:
        os.unlink(fname)


def test_fix_file_backup():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:\n    pass\n")
        fname = f.name
    try:
        findings = [make_finding(rule_id="Q001", line=3, fix_desc="bare except", file=fname)]
        fix_file(fname, findings, dry_run=False, backup=True)
        assert os.path.exists(fname + ".bak")
        os.unlink(fname + ".bak")
    finally:
        os.unlink(fname)


def test_fix_nonexistent_file():
    result = fix_file("/nonexistent/file.py", [], dry_run=True)
    assert result.status == FixStatus.FAILED


def test_fix_already_clean():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("x = 1\n")
        fname = f.name
    try:
        result = fix_file(fname, [], dry_run=True)
        assert result.status == FixStatus.SKIPPED
    finally:
        os.unlink(fname)
