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
# ---------- Regression: false positive fixes ----------

def test_s003_subprocess_shell_false_safe():
    """subprocess.run without shell=True should NOT be flagged."""
    code = "subprocess.run([\"ls\", \"-la\"])"
    from codeaudit.rules.security.dangerous_functions import DangerousFunctions
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert len(findings) == 0


def test_s003_subprocess_shell_true_flagged():
    """subprocess.run with shell=True should still be flagged."""
    code = "subprocess.run([\"rm\", \"-rf\", \"/\"], shell=True)"
    from codeaudit.rules.security.dangerous_functions import DangerousFunctions
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert len(findings) == 1


def test_s001_plain_sql_literal_safe():
    """Plain SQL literal without external input should NOT be flagged."""
    code = 'conn.execute("SELECT 1")'
    from codeaudit.rules.security.sql_injection import SqlInjection
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 0


def test_s001_fstring_sql_flagged():
    """f-string SQL should still be flagged."""
    code = 'conn.execute(f"SELECT * FROM users WHERE id = {uid}")'
    from codeaudit.rules.security.sql_injection import SqlInjection
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 1


def test_s001_parametrized_safe():
    """Parameterized queries should not be flagged."""
    code = 'conn.execute("SELECT * FROM users WHERE id = ?", (uid,))'
    from codeaudit.rules.security.sql_injection import SqlInjection
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 0


def test_s001_variable_not_parametrized_flagged():
    """Variable passed to execute without parameterization should be flagged."""
    code = "conn.execute(query)"
    from codeaudit.rules.security.sql_injection import SqlInjection
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 1


def test_q002_http_status_allowed():
    """HTTP status codes like 404, 403 should not be flagged."""
    code = "not_found = 404"
    from codeaudit.rules.quality.magic_numbers import MagicNumbers
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0


def test_q002_port_allowed():
    """Common ports like 80, 443, 3306 should not be flagged."""
    code = "port = 443"
    from codeaudit.rules.quality.magic_numbers import MagicNumbers
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0
