"""Tests for S008: Insecure Random rule."""
import ast
from pathlib import Path

from aicaudit.rules.base import ScanContext, Severity
from aicaudit.rules.security.insecure_random import InsecureRandom


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


def test_random_random_detected():
    code = "token = random.random()"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert "random.random" in findings[0].message


def test_random_randint_detected():
    code = "pin = random.randint(1000, 9999)"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 1


def test_random_choice_detected():
    code = "c = random.choice(abc)"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 1


def test_secrets_safe():
    code = "token = secrets.token_hex(32)"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 0


def test_random_uniform_detected():
    code = "x = random.uniform(0.0, 1.0)"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 1


def test_random_choices_detected():
    code = "s = random.choices(population, k=5)"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 1


def test_random_sample_detected():
    code = "s = random.sample(range(100), 10)"
    tree, ctx = make_context(code)
    findings = InsecureRandom().check(tree, ctx)
    assert len(findings) == 1
