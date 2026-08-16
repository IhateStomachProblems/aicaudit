"""Extended tests covering edge branches that were previously uncovered."""

import ast
from pathlib import Path

from codeaudit.rules.base import (
    Finding,
    Rule,
    ScanContext,
    Severity,
    active_rules,
    all_rules,
    get_rule,
    register,
)

# Import all rule modules to ensure they are registered
from codeaudit.rules.performance.complexity import Complexity
from codeaudit.rules.performance.nesting_depth import NestingDepth
from codeaudit.rules.quality.bare_except import BareExcept
from codeaudit.rules.quality.magic_numbers import MagicNumbers
from codeaudit.rules.quality.todo_comment import TodoComment
from codeaudit.rules.quality.undefined_name import UndefinedName
from codeaudit.rules.quality.unused_variable import UnusedVariable
from codeaudit.rules.security.dangerous_functions import DangerousFunctions
from codeaudit.rules.security.path_traversal import PathTraversal
from codeaudit.rules.security.secret_leak import SecretLeak
from codeaudit.rules.security.sql_injection import SqlInjection
from codeaudit.rules.security.ssrf import SSRF
from codeaudit.rules.security.weak_crypto import WeakCrypto
from codeaudit.rules.security.xml_xxe import XXE


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


# ---------- base.py ----------

def test_finding_text_lang_switch():
    f = Finding(
        rule_id="T", message="hello", message_zh="你好",
        file="f.py", line=1, severity=Severity.INFO,
    )
    assert f.text("en") == "hello"
    assert f.text("zh") == "你好"
    assert f.text() == "hello"


def test_rule_base_check_raises():
    tree, ctx = make_context("x = 1")
    try:
        Rule().check(tree, ctx)
        assert False, "should have raised"
    except NotImplementedError:
        pass


def test_get_rule_and_active_rules():
    r = get_rule("S001")
    assert r is not None and r.id == "S001"
    assert get_rule("does-not-exist") is None
    rules = active_rules(include={"S001"})
    assert len(rules) == 1 and rules[0].id == "S001"
    assert len(all_rules()) >= 10


def test_register_decorator_returns_class():
    @register
    class TempRule(Rule):
        id = "ZZZ"
    assert TempRule.id == "ZZZ"
    assert get_rule("ZZZ") is TempRule


# ---------- sql_injection.py ----------

def test_sql_non_attribute_call_ignored():
    code = "execute('SELECT 1')"
    tree, ctx = make_context(code)
    assert SqlInjection().check(tree, ctx) == []


def test_sql_non_execute_method_ignored():
    code = "conn.foo('SELECT * FROM users')"
    tree, ctx = make_context(code)
    assert SqlInjection().check(tree, ctx) == []


def test_sql_no_args_ignored():
    code = "conn.execute()"
    tree, ctx = make_context(code)
    assert SqlInjection().check(tree, ctx) == []


def test_sql_non_sql_string_ignored():
    code = "conn.execute('hello world')"
    tree, ctx = make_context(code)
    assert SqlInjection().check(tree, ctx) == []


def test_sql_variable_not_parametrized_flagged():
    code = "conn.execute(query)"
    tree, ctx = make_context(code)
    findings = SqlInjection().check(tree, ctx)
    assert len(findings) == 1


def test_sql_variable_parametrized_safe():
    code = "conn.execute(query, params)"
    tree, ctx = make_context(code)
    assert SqlInjection().check(tree, ctx) == []


# ---------- secret_leak.py ----------

def test_secret_tuple_target_ignored():
    code = "(x, y) = (1, 2)"
    tree, ctx = make_context(code)
    assert SecretLeak().check(tree, ctx) == []


def test_secret_long_password_no_pattern():
    code = 'api_password = "super_secret_password_123"'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) == 1


# ---------- dangerous_functions.py ----------

def test_dangerous_attribute_chain():
    code = "os.path.join(a, b)"
    tree, ctx = make_context(code)
    assert DangerousFunctions().check(tree, ctx) == []


def test_dangerous_pickle_loads():
    code = "pickle.loads(data)"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_dangerous_subprocess_run():
    code = "subprocess.run(cmd, shell=True)"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING


# ---------- complexity.py ----------

def test_complexity_ternary_counts():
    code = "def f(x):\n    return 1 if x else 2"
    tree, ctx = make_context(code)
    assert Complexity().check(tree, ctx) == []


def test_complexity_error_severity():
    code = "def huge(a, b, c, d, e):\n"
    chunks = []
    for i in range(16):
        chunks.append(f"    if {chr(97 + i)}:")
        chunks.append(f"        x = {i}")
    code += "\n".join(chunks) + "\n    return x"
    tree, ctx = make_context(code)
    findings = Complexity().check(tree, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR


# ---------- magic_numbers.py ----------

def test_magic_string_literal_ignored():
    code = 'name = "hello world"'
    tree, ctx = make_context(code)
    assert MagicNumbers().check(tree, ctx) == []


def test_magic_float_ignored():
    code = "ratio = 0.75"
    tree, ctx = make_context(code)
    assert MagicNumbers().check(tree, ctx) == []


def test_magic_module_const_allowed():
    code = "MAX_SIZE = 5000"
    tree, ctx = make_context(code)
    assert MagicNumbers().check(tree, ctx) == []


# ---------- undefined_name.py ----------

def test_undefined_function_param():
    code = "def foo(bar):\n    print(bar)"
    tree, ctx = make_context(code)
    assert UndefinedName().check(tree, ctx) == []


def test_undefined_kwargs_and_vararg():
    code = "def foo(*args, **kwargs):\n    return args, kwargs"
    tree, ctx = make_context(code)
    assert UndefinedName().check(tree, ctx) == []


def test_undefined_class_defined():
    code = "class MyClass:\n    pass\nobj = MyClass()"
    tree, ctx = make_context(code)
    assert UndefinedName().check(tree, ctx) == []


def test_undefined_except_as_var():
    code = "try:\n    x = 1\nexcept ValueError as e:\n    print(e)"
    tree, ctx = make_context(code)
    assert UndefinedName().check(tree, ctx) == []


# ---------- unused_variable.py ----------

def test_unused_nested_function_skipped():
    code = "def outer():\n    def inner():\n        y = 1\n        return y\n    return inner()"
    tree, ctx = make_context(code)
    findings = UnusedVariable().check(tree, ctx)
    assert findings == []


# ---------- remaining defensive branches ----------

def test_active_rules_empty_include_means_all():
    # include as empty set -> behaves like "all"
    rules = active_rules(include=set())
    assert len(rules) == len(all_rules())


def test_magic_small_number_ignored():
    # abs(value) <= 10 -> skipped by the defensive branch
    code = "x = 5"
    tree, ctx = make_context(code)
    assert MagicNumbers().check(tree, ctx) == []


def test_magic_small_negative_ignored():
    code = "x = -7"
    tree, ctx = make_context(code)
    assert MagicNumbers().check(tree, ctx) == []
