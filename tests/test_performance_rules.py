"""Tests for performance rules."""

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
        "def complex_func(a, b, c):\n"
        "    if a:\n        x = 1\n"
        "    elif b:\n        x = 2\n"
        "    else:\n        x = 3\n"
        "    for i in range(10):\n"
        "        if i > 5:\n            x += i\n"
        "        while x > 100:\n            x -= 1\n"
        "    if a and b and c:\n        x = 99\n"
        "    for j in range(20):\n"
        "        if j > 10:\n            x += j\n"
        "        else:\n            x -= j\n"
        "    if a:\n        x = 1\n"
        "    elif b:\n        x = 2\n"
        "    return x"
    )
    tree, ctx = make_context(code)
    findings = Complexity().check(tree, ctx)
    assert len(findings) >= 1


def test_complexity_simple_safe():
    code = "def foo():\n    return 1"
    tree, ctx = make_context(code)
    findings = Complexity().check(tree, ctx)
    assert len(findings) == 0


def test_nesting_detected():
    code = (
        "def deep(x):\n"
        "    if x:\n"
        "        for i in range(10):\n"
        "            while i > 0:\n"
        "                if i == 1:\n"
        "                    return 1"
    )
    tree, ctx = make_context(code)
    findings = NestingDepth().check(tree, ctx)
    assert len(findings) == 1


def test_nesting_flat_safe():
    code = "def flat(x):\n    return x"
    tree, ctx = make_context(code)
    findings = NestingDepth().check(tree, ctx)
    assert len(findings) == 0
