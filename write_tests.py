import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

# Unit tests for rules
with open(os.path.join(proj_dir, "tests", "test_security_rules.py"), "w", encoding="utf-8") as f:
    f.write('''"""Tests for security rules."""

import ast
from pathlib import Path
from unittest.mock import Mock

from codeaudit.rules.base import ScanContext, Severity
from codeaudit.rules.security.sql_injection import SqlInjection
from codeaudit.rules.security.secret_leak import SecretLeak
from codeaudit.rules.security.dangerous_functions import DangerousFunctions


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
''')

# Tests for quality rules
with open(os.path.join(proj_dir, "tests", "test_quality_rules.py"), "w", encoding="utf-8") as f:
    f.write('''"""Tests for quality rules."""

import ast
from pathlib import Path

from codeaudit.rules.base import ScanContext
from codeaudit.rules.quality.bare_except import BareExcept
from codeaudit.rules.quality.undefined_name import UndefinedName
from codeaudit.rules.quality.unused_variable import UnusedVariable
from codeaudit.rules.quality.todo_comment import TodoComment
from codeaudit.rules.quality.magic_numbers import MagicNumbers


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


def test_bare_except_detected():
    code = "try:\\n    x = 1\\nexcept:\\n    pass"
    tree, ctx = make_context(code)
    findings = BareExcept().check(tree, ctx)
    assert len(findings) == 1


def test_bare_except_specific_safe():
    code = "try:\\n    x = 1\\nexcept ValueError:\\n    pass"
    tree, ctx = make_context(code)
    findings = BareExcept().check(tree, ctx)
    assert len(findings) == 0


def test_undefined_name_detected():
    code = "print(undefined_var)"
    tree, ctx = make_context(code)
    findings = UndefinedName().check(tree, ctx)
    assert any("undefined_var" in f.message for f in findings)


def test_undefined_name_import_safe():
    code = "import os\\nos.getcwd()"
    tree, ctx = make_context(code)
    findings = UndefinedName().check(tree, ctx)
    assert len(findings) == 0


def test_unused_variable_detected():
    code = "def foo():\\n    x = 1\\n    return 2"
    tree, ctx = make_context(code)
    findings = UnusedVariable().check(tree, ctx)
    assert any("x" in f.message for f in findings)


def test_todo_detected():
    code = "# TODO: fix this"
    tree, ctx = make_context(code)
    findings = TodoComment().check(tree, ctx)
    assert len(findings) == 1


def test_magic_number_detected():
    code = "x = 1729"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) >= 1


def test_magic_number_common_safe():
    code = "x = 1"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0
''')

# Tests for performance rules
with open(os.path.join(proj_dir, "tests", "test_performance_rules.py"), "w", encoding="utf-8") as f:
    f.write('''"""Tests for performance rules."""

import ast
from pathlib import Path

from codeaudit.rules.base import ScanContext
from codeaudit.rules.performance.complexity import Complexity
from codeaudit.rules.performance.nesting_depth import NestingDepth


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


def test_complexity_detected():
    code = (
        "def complex_func(a, b, c):\\n"
        "    if a:\\n        x = 1\\n"
        "    elif b:\\n        x = 2\\n"
        "    else:\\n        x = 3\\n"
        "    for i in range(10):\\n"
        "        if i > 5:\\n            x += i\\n"
        "        while x > 100:\\n            x -= 1\\n"
        "    if a and b and c:\\n        x = 99\\n"
        "    for j in range(20):\\n"
        "        if j > 10:\\n            x += j\\n"
        "        else:\\n            x -= j\\n"
        "    if a:\\n        x = 1\\n"
        "    elif b:\\n        x = 2\\n"
        "    return x"
    )
    tree, ctx = make_context(code)
    findings = Complexity().check(tree, ctx)
    assert len(findings) >= 1


def test_complexity_simple_safe():
    code = "def foo():\\n    return 1"
    tree, ctx = make_context(code)
    findings = Complexity().check(tree, ctx)
    assert len(findings) == 0


def test_nesting_detected():
    code = (
        "def deep(x):\\n"
        "    if x:\\n"
        "        for i in range(10):\\n"
        "            while i > 0:\\n"
        "                if i == 1:\\n"
        "                    return 1"
    )
    tree, ctx = make_context(code)
    findings = NestingDepth().check(tree, ctx)
    assert len(findings) == 1


def test_nesting_flat_safe():
    code = "def flat(x):\\n    return x"
    tree, ctx = make_context(code)
    findings = NestingDepth().check(tree, ctx)
    assert len(findings) == 0
''')

print("Test files written")
