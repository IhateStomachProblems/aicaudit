import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

# Refactor undefined_name.py - reduce complexity
content = '''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

BUILTINS = {
    "print", "len", "range", "int", "str", "float", "list", "dict", "set",
    "tuple", "bool", "type", "isinstance", "hasattr", "getattr", "setattr",
    "open", "input", "sum", "min", "max", "abs", "sorted", "reversed", "enumerate",
    "zip", "map", "filter", "any", "all", "eval", "exec", "next", "iter",
    "True", "False", "None", "__name__", "__file__", "__doc__", "__init__",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError", "OSError",
    "RuntimeError", "StopIteration", "FileNotFoundError", "NotImplementedError",
    "ZeroDivisionError", "AttributeError", "NameError", "ImportError", "SyntaxError",
    "super", "classmethod", "staticmethod", "property", "repr", "format",
    "vars", "dir", "id", "hash", "round", "divmod", "pow", "ord", "chr", "bytes",
    "bytearray", "frozenset", "object", "NotImplemented", "Ellipsis",
    "exit", "quit", "help", "callable", "issubclass", "delattr", "globals",
    "locals", "compile", "memoryview", "ascii", "bin", "hex", "oct",
}


def _collect_names(tree):
    defined, used = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                defined.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
            for arg in node.args.args:
                defined.add(arg.arg)
            if node.args.vararg:
                defined.add(node.args.vararg.arg)
            if node.args.kwarg:
                defined.add(node.args.kwarg.arg)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                defined.add(node.name)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Store):
                defined.add(node.id)
            elif isinstance(node.ctx, ast.Load):
                used.add(node.id)
    return defined, used


def _find_line(tree, name):
    return next(
        (n.lineno for n in ast.walk(tree)
         if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)),
        0,
    )


@register
class UndefinedName(Rule):
    id = "Q003"
    name = "undefined-name"
    severity = Severity.ERROR
    description = "Detect use of undefined names (potential NameError)"
    description_zh = "检测使用未定义的变量名（潜在的NameError）"

    def check(self, tree, context):
        defined, used = _collect_names(tree)
        findings = []
        for name in sorted(used - defined - BUILTINS):
            line = _find_line(tree, name)
            findings.append(Finding(
                rule_id=self.id,
                message=f"Undefined name '{name}'",
                message_zh=f"未定义的变量 '{name}'",
                file=str(context.file_path),
                line=line,
                severity=self.severity,
                snippet=context.lines[line - 1].strip() if line else None,
                fix=f"Define '{name}' or import it before use",
            ))
        return findings
'''

with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "undefined_name.py"), "w", encoding="utf-8") as f:
    f.write(content)
print("undefined_name.py refactored")

# Refactor unused_variable.py
content2 = '''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register


def _local_names(func_node):
    """Names assigned and used inside a function (excluding nested funcs)."""
    local, used = set(), set()
    for sub in ast.walk(func_node):
        if sub is func_node:
            continue
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(sub, ast.Name):
            if isinstance(sub.ctx, ast.Store):
                local.add(sub.id)
            elif isinstance(sub.ctx, ast.Load):
                used.add(sub.id)
    return local, used


def _find_store_line(func_node, name):
    return next(
        (n.lineno for n in ast.walk(func_node)
         if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store)),
        0,
    )


@register
class UnusedVariable(Rule):
    id = "Q005"
    name = "unused-variable"
    severity = Severity.WARNING
    description = "Detect local variables assigned but never used"
    description_zh = "检测已赋值但从未使用的局部变量"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            local, used = _local_names(node)
            for name in sorted(local - used - {"self", "cls", "_"}):
                line = _find_store_line(node, name)
                findings.append(Finding(
                    rule_id=self.id,
                    message=f"Unused variable '{name}' in '{node.name}'",
                    message_zh=f"函数 '{node.name}' 中未使用的变量 '{name}'",
                    file=str(context.file_path),
                    line=line,
                    severity=self.severity,
                    snippet=context.lines[line - 1].strip() if line else None,
                ))
        return findings
'''

with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "unused_variable.py"), "w", encoding="utf-8") as f:
    f.write(content2)
print("unused_variable.py refactored")
