import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

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
