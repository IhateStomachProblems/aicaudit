import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

# Thresholds: a function is getting complex above 10, problematic above 15
WARN_AT = 10
ERROR_AT = 15

DECISION_NODES = (
    ast.If, ast.While, ast.For, ast.AsyncFor,
    ast.Assert, ast.ExceptHandler,
)


def _complexity(func_node):
    count = 1  # every function starts with one path
    for node in ast.walk(func_node):
        if isinstance(node, DECISION_NODES):
            count += 1
        elif isinstance(node, ast.BoolOp):  # and / or add paths
            count += len(node.values) - 1
        elif isinstance(node, ast.IfExp):  # ternary
            count += 1
    return count


@register
class Complexity(Rule):
    id = "P001"
    name = "cyclomatic-complexity"
    severity = Severity.WARNING
    description = "Detect functions with high cyclomatic complexity"
    description_zh = "检测圈复杂度过高的函数"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            score = _complexity(node)
            if score > ERROR_AT:
                sev = Severity.ERROR
            elif score > WARN_AT:
                sev = Severity.WARNING
            else:
                continue
            findings.append(Finding(
                rule_id=self.id,
                message=f"Cyclomatic complexity {score} in '{node.name}' (threshold: {WARN_AT})",
                message_zh=f"函数 '{node.name}' 圈复杂度为 {score}（阈值：{WARN_AT}）",
                file=str(context.file_path),
                line=node.lineno or 0,
                severity=sev,
                snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
                fix=f"Split '{node.name}' into smaller functions to reduce complexity below {WARN_AT}",
            ))
        return findings
