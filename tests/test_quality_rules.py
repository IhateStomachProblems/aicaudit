"""Tests for quality rules."""

import ast
from pathlib import Path

from codeaudit.rules.base import ScanContext
from codeaudit.rules.quality.bare_except import BareExcept
from codeaudit.rules.quality.magic_numbers import MagicNumbers
from codeaudit.rules.quality.todo_comment import TodoComment
from codeaudit.rules.quality.undefined_name import UndefinedName
from codeaudit.rules.quality.unused_variable import UnusedVariable


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


def test_bare_except_detected():
    code = "try:\n    x = 1\nexcept:\n    pass"
    tree, ctx = make_context(code)
    findings = BareExcept().check(tree, ctx)
    assert len(findings) == 1


def test_bare_except_specific_safe():
    code = "try:\n    x = 1\nexcept ValueError:\n    pass"
    tree, ctx = make_context(code)
    findings = BareExcept().check(tree, ctx)
    assert len(findings) == 0


def test_undefined_name_detected():
    code = "print(undefined_var)"
    tree, ctx = make_context(code)
    findings = UndefinedName().check(tree, ctx)
    assert any("undefined_var" in f.message for f in findings)


def test_undefined_name_import_safe():
    code = "import os\nos.getcwd()"
    tree, ctx = make_context(code)
    findings = UndefinedName().check(tree, ctx)
    assert len(findings) == 0


def test_unused_variable_detected():
    code = "def foo():\n    x = 1\n    return 2"
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
# ---------- Regression: Q002 false positive fixes ----------

def test_q002_http_status_allowed():
    code = "not_found = 404"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0


def test_q002_port_allowed():
    code = "port = 443"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0


def test_q002_db_port_allowed():
    code = "db_port = 3306"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0


def test_q002_http_403_safe():
    code = "status = 403"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0


def test_q002_time_constant_allowed():
    code = "timeout = 3600"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) == 0


def test_q002_obscure_number_flagged():
    code = "weird = 1729"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) >= 1


def test_q002_timeout_150_flagged():
    """150 is not in the whitelist - should still be flagged."""
    code = "timeout = 150"
    tree, ctx = make_context(code)
    findings = MagicNumbers().check(tree, ctx)
    assert len(findings) >= 1
