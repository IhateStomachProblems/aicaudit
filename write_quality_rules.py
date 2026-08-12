import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

# Q001 - Bare except
with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "bare_except.py"), "w", encoding="utf-8") as f:
    f.write('''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

@register
class BareExcept(Rule):
    id = "Q001"
    name = "bare-except"
    severity = Severity.WARNING
    description = "Detect bare except: clauses that catch all exceptions"
    description_zh = "检测捕获所有异常的裸except语句"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                findings.append(Finding(
                    rule_id=self.id,
                    message="Bare except: catches all exceptions, consider except Exception:",
                    message_zh="裸except会捕获所有异常，建议改为 except Exception:",
                    file=str(context.file_path),
                    line=node.lineno or 0,
                    severity=self.severity,
                    snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
                    fix="except Exception: instead of bare except:",
                ))
        return findings
''')

# Q002 - Magic numbers
with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "magic_numbers.py"), "w", encoding="utf-8") as f:
    f.write('''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

ALLOWED = {0, 1, -1, 100, -1}  # common constants

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
            # Skip if it's a default argument or part of a comparison with 0/1
            if isinstance(node.value, int) and abs(node.value) > 10:
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
''')

# Q003 - Undefined names
with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "undefined_name.py"), "w", encoding="utf-8") as f:
    f.write('''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

BUILTINS = {
    "print", "len", "range", "int", "str", "float", "list", "dict", "set",
    "tuple", "bool", "type", "isinstance", "hasattr", "getattr", "setattr",
    "open", "input", "sum", "min", "max", "abs", "sorted", "reversed", "enumerate",
    "zip", "map", "filter", "any", "all", "True", "False", "None",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError", "OSError",
    "RuntimeError", "StopIteration", "FileNotFoundError",
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
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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
            findings.append(Finding(
                rule_id=self.id,
                message=f"Undefined name '{name}'",
                message_zh=f"未定义的变量 '{name}'",
                file=str(context.file_path),
                line=0,
                severity=self.severity,
            ))
        return findings
''')

# Q004 - TODO markers
with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "todo_comment.py"), "w", encoding="utf-8") as f:
    f.write('''import re
from codeaudit.rules.base import Rule, Severity, Finding, register

TODO_RE = re.compile(r"#\\s*(TODO|FIXME|HACK|XXX)\\b", re.I)

@register
class TodoComment(Rule):
    id = "Q004"
    name = "todo-comment"
    severity = Severity.INFO
    description = "Detect TODO, FIXME, HACK, and XXX comments"
    description_zh = "检测TODO、FIXME、HACK和XXX注释"

    def check(self, tree, context):
        findings = []
        for i, line in enumerate(context.lines, 1):
            m = TODO_RE.search(line)
            if m:
                findings.append(Finding(
                    rule_id=self.id,
                    message=f"{m.group(1)} comment left in code",
                    message_zh=f"代码中遗留了{m.group(1)}注释",
                    file=str(context.file_path),
                    line=i,
                    severity=self.severity,
                    snippet=line.strip(),
                ))
        return findings
''')

# Q005 - Unused variable
with open(os.path.join(proj_dir, "codeaudit", "rules", "quality", "unused_variable.py"), "w", encoding="utf-8") as f:
    f.write('''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

@register
class UnusedVariable(Rule):
    id = "Q005"
    name = "unused-variable"
    severity = Severity.WARNING
    description = "Detect variables that are assigned but never read"
    description_zh = "检测已赋值但从未读取的变量"

    def check(self, tree, context):
        assigned = set()
        read = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assigned.add(node.name)
                for arg in node.args.args:
                    assigned.add(arg.arg)
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    assigned.add(node.id)
                elif isinstance(node.ctx, ast.Load):
                    read.add(node.id)

        unused = sorted(assigned - read - {"self", "cls", "_"})
        findings = []
        for name in unused:
            findings.append(Finding(
                rule_id=self.id,
                message=f"Unused variable '{name}'",
                message_zh=f"未使用的变量 '{name}'",
                file=str(context.file_path),
                line=0,
                severity=self.severity,
            ))
        return findings
''')

print("Quality rules written")
