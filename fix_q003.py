import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

content = '''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

BUILTINS = {
    "print", "len", "range", "int", "str", "float", "list", "dict", "set",
    "tuple", "bool", "type", "isinstance", "hasattr", "getattr", "setattr",
    "open", "input", "sum", "min", "max", "abs", "sorted", "reversed", "enumerate",
    "zip", "map", "filter", "any", "all", "eval", "exec",
    "True", "False", "None",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError", "OSError",
    "RuntimeError", "StopIteration", "FileNotFoundError",
    "super", "classmethod", "staticmethod", "property", "repr", "format",
    "vars", "dir", "id", "hash", "round", "divmod", "pow", "ord", "chr", "bytes",
    "bytearray", "frozenset", "object", "NotImplemented", "Ellipsis",
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
            elif isinstance(node, ast.ClassDef):
                defined.add(node.name)
            elif isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    defined.add(node.id)
                elif isinstance(node.ctx, ast.Load):
                    used.add(node.id)

        findings = []
        for name in sorted(used - defined - BUILTINS):
            # Find a line for context
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
print("Q003 rewritten")
