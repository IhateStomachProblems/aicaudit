import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

content = '''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register


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
            # Track names defined and used inside this function
            local_names = set()
            used_names = set()
            for sub in ast.walk(node):
                if sub is node:  # skip the function def itself
                    continue
                # Skip nested function defs entirely (handled separately)
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if isinstance(sub, ast.Name):
                    if isinstance(sub.ctx, ast.Store):
                        if not isinstance(sub.ctx, ast.Global) and not isinstance(sub.ctx, ast.Nonlocal):
                            local_names.add(sub.id)
                    elif isinstance(sub.ctx, ast.Load):
                        used_names.add(sub.id)

            for name in sorted(local_names - used_names - {"self", "cls", "_"}):
                line = next(
                    (n.lineno for n in ast.walk(node)
                     if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store)),
                    0,
                )
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
    f.write(content)
print("Q005 rewritten")
