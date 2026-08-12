import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

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
