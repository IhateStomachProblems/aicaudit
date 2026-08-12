"""Tests for security rules."""

import ast
from pathlib import Path

from codeaudit.rules.base import ScanContext, Severity
from codeaudit.rules.security.dangerous_functions import DangerousFunctions
from codeaudit.rules.security.secret_leak import SecretLeak
from codeaudit.rules.security.sql_injection import SqlInjection


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


def test_sql_injection_fstring():
    code = 'conn.execute(f"SELECT * FROM users WHERE id = {uid}")'
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_sql_injection_parametrized_safe():
    code = 'conn.execute("SELECT * FROM users WHERE id = ?", (uid,))'
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 0


def test_secret_leak_api_key():
    code = 'api_key = "sk-1234567890abcdefghijklmnop"'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) >= 1


def test_secret_leak_normal_var_safe():
    code = 'count = 42'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) == 0


def test_dangerous_eval():
    code = "eval('1+1')"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_dangerous_safe_call():
    code = "print('hello')"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert len(findings) == 0

