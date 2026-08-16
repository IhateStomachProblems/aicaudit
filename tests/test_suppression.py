"""Tests for inline suppression feature."""
import ast
from pathlib import Path

from codeaudit.rules.base import ScanContext, Severity
from codeaudit.rules.security.sql_injection import SqlInjection
from codeaudit.rules.security.insecure_random import InsecureRandom
from codeaudit.scan import _parse_suppressions, _is_suppressed


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


def test_suppress_specific_rule():
    code = 'x = f"SELECT * FROM t WHERE id={a}"  # codeaudit: ignore S001'
    lines = code.splitlines()
    suppress = _parse_suppressions(lines)
    assert 1 in suppress
    assert "S001" in suppress[1]


def test_suppress_all_rules():
    code = 'x = f"SELECT * FROM t WHERE id={a}"  # codeaudit: ignore'
    lines = code.splitlines()
    suppress = _parse_suppressions(lines)
    assert 1 in suppress
    assert suppress[1] is None


def test_no_suppress():
    code = '# normal comment'
    lines = code.splitlines()
    suppress = _parse_suppressions(lines)
    assert len(suppress) == 0


def test_is_suppressed_specific():
    from codeaudit.rules.base import Finding
    f = Finding(rule_id="S001", message="test", message_zh="test", file="f.py", line=1, severity=Severity.CRITICAL)
    suppress_map = {1: {"S001"}}
    assert _is_suppressed(f, suppress_map) is True


def test_is_suppressed_different_rule():
    from codeaudit.rules.base import Finding
    f = Finding(rule_id="S002", message="test", message_zh="test", file="f.py", line=1, severity=Severity.CRITICAL)
    suppress_map = {1: {"S001"}}
    assert _is_suppressed(f, suppress_map) is False


def test_is_suppressed_all():
    from codeaudit.rules.base import Finding
    f = Finding(rule_id="S002", message="test", message_zh="test", file="f.py", line=1, severity=Severity.CRITICAL)
    suppress_map = {1: None}
    assert _is_suppressed(f, suppress_map) is True


def test_integration_suppress_sql():
    code = 'conn.execute(f"SELECT * FROM users WHERE id={a}")  # codeaudit: ignore S001'
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    # The rule still finds it - suppression happens at scan level
    assert len(findings) == 1


def test_suppress_case_insensitive():
    code = 'x = f"SELECT * FROM t WHERE id={a}"  # codeaudit: ignore=s001'
    lines = code.splitlines()
    suppress = _parse_suppressions(lines)
    assert "S001" in suppress[1]
