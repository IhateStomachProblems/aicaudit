import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

# Fix Q003: add more builtins + handle except-as variables
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


@register
class UndefinedName(Rule):
    id = "Q003"
    name = "undefined-name"
    severity = Severity.ERROR
    description = "Detect use of undefined names (potential NameError)"
    description_zh = "检测使用未定义的变量名（潜在的NameError）"

    def check(self, tree, context):
        defined = set()
        used = set()

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

        findings = []
        for name in sorted(used - defined - BUILTINS):
            line = next(
                (n.lineno for n in ast.walk(tree)
                 if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)),
                0,
            )
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
print("Q003 fixed")

# Fix Q002: skip module-level constants (UPPER_CASE)
content2 = '''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

ALLOWED = {0, 1, -1, 100}


def _is_module_const(node, value):
    """Skip named constants like MAX_DEPTH = 3 or ERROR_AT = 15."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id.isupper():
            return True
    return False


@register
class MagicNumbers(Rule):
    id = "Q002"
    name = "magic-numbers"
    severity = Severity.INFO
    description = "Detect unexplained numeric literals (magic numbers)"
    description_zh = "检测未命名的数字字面量（魔法数字）"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            if not isinstance(node.value, (int, float)):
                continue
            if node.value in ALLOWED:
                continue
            if isinstance(node.value, float):
                continue
            if not isinstance(node.value, int) or abs(node.value) <= 10:
                continue
            # Skip if it's part of a constant assignment (named)
            parent = next((p for p in ast.walk(tree) if isinstance(p, ast.Assign)
                           and p.value is node), None)
            if parent and _is_module_const(parent, node.value):
                continue
            findings.append(Finding(
                rule_id=self.id,
                message=f"Magic number {node.value}: consider naming it as a constant",
                message_zh=f"魔法数字 {node.value}：建议定义为常量",
                file=str(context.file_path),
                line=node.lineno or 0,
                severity=self.severity,
                snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
            ))
        return findings
'''

with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "magic_numbers.py"), "w", encoding="utf-8") as f:
    f.write(content2)
print("Q002 fixed")
