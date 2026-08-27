import ast

from aicaudit.rules.base import Finding, Rule, Severity, register


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
