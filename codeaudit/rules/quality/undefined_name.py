import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

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
