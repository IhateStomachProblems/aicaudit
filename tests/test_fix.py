"""Tests for fix engine."""

import os
import tempfile

from codeaudit.fix import (
    _comment_dangerous,
    _fix_bare_except,
    _is_dangerous_call,
    apply_fixes,
)
from codeaudit.rules.base import Finding, Severity


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


def test_is_dangerous_eval():
    assert _is_dangerous_call("eval('1+1')")


def test_is_dangerous_exec():
    assert _is_dangerous_call("exec('x=1')")


def test_is_dangerous_os_system():
    assert _is_dangerous_call("os.system('ls')")


def test_is_dangerous_safe():
    assert not _is_dangerous_call("print('hello')")


def test_comment_dangerous():
    result = _comment_dangerous("    eval('1+1')\n")
    assert result is not None
    assert "TODO" in result


def test_apply_fixes_dry_run():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:\n    pass\n")
        fname = f.name
    try:
        findings = [make_finding(rule_id="Q001", line=3, fix_desc="bare except", file=fname)]
        result = apply_fixes(findings, {}, dry_run=True)
        assert fname in result
        assert "except Exception:" in result[fname]
    finally:
        os.unlink(fname)


def test_apply_fixes_actual_write():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:\n    pass\n")
        fname = f.name
    try:
        findings = [make_finding(rule_id="Q001", line=3, fix_desc="bare except", file=fname)]
        apply_fixes(findings, {}, dry_run=False, backup=False)
        with open(fname, encoding="utf-8") as fh:
            content = fh.read()
        assert "except Exception:" in content
        assert "except:" not in content
    finally:
        os.unlink(fname)


def test_apply_fixes_backup_created():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("try:\n    x = 1\nexcept:\n    pass\n")
        fname = f.name
    try:
        findings = [make_finding(rule_id="Q001", line=3, fix_desc="bare except", file=fname)]
        apply_fixes(findings, {}, dry_run=False, backup=True)
        assert os.path.exists(fname + ".bak")
        os.unlink(fname + ".bak")
    finally:
        os.unlink(fname)
