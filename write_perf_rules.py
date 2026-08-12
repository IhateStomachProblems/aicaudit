import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

# P001 - Cyclomatic complexity
with open(os.path.join(proj_dir, "codeaudit", "rules", "performance", "complexity.py"), "w", encoding="utf-8") as f:
    f.write('''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

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
''')

# P002 - Nesting depth
with open(os.path.join(proj_dir, "codeaudit", "rules", "performance", "nesting_depth.py"), "w", encoding="utf-8") as f:
    f.write('''import ast
from codeaudit.rules.base import Rule, Severity, Finding, register

MAX_DEPTH = 3
NESTING_NODES = (ast.If, ast.For, ast.While, ast.Try, ast.With,
                 ast.AsyncFor, ast.AsyncWith)


def _max_depth(func_node):
    best = 0

    def visit(node, depth):
        nonlocal best
        if isinstance(node, NESTING_NODES):
            depth += 1
            best = max(best, depth)
        for child in ast.iter_child_nodes(node):
            visit(child, depth)

    visit(func_node, 0)
    return best


@register
class NestingDepth(Rule):
    id = "P002"
    name = "nesting-depth"
    severity = Severity.WARNING
    description = "Detect functions with deeply nested control flow"
    description_zh = "检测嵌套过深的控制流"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            depth = _max_depth(node)
            if depth > MAX_DEPTH:
                findings.append(Finding(
                    rule_id=self.id,
                    message=f"Nesting depth {depth} in '{node.name}' (max: {MAX_DEPTH})",
                    message_zh=f"函数 '{node.name}' 嵌套深度为 {depth}（上限：{MAX_DEPTH}）",
                    file=str(context.file_path),
                    line=node.lineno or 0,
                    severity=self.severity,
                    snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
                    fix=f"Use early returns or extract helper functions to reduce nesting below {MAX_DEPTH}",
                ))
        return findings
''')

print("Performance rules written")
