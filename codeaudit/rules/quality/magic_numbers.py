import ast

from codeaudit.rules.base import Finding, Rule, Severity, register

ALLOWED = {0, 1, -1, 100}

# Numbers commonly used in logic (ranges, indexes, counters) - skip these
COMMON_LOGIC_NUMBERS = {2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 64, 128, 256}


def _module_const_targets(tree):
    """Pre-build the set of Constant objects that are module-level named constants."""
    consts = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id.isupper() and isinstance(node.value, ast.Constant):
                    consts.add(id(node.value))
    return consts


@register
class MagicNumbers(Rule):
    id = "Q002"
    name = "magic-numbers"
    severity = Severity.INFO
    description = "Detect unexplained numeric literals (magic numbers)"
    description_zh = "检测未命名的数字字面量（魔法数字）"

    def check(self, tree, context):
        # Precompute named constants once (not per node)
        named_consts = _module_const_targets(tree)
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            if not isinstance(node.value, int):
                continue
            if node.value in ALLOWED or node.value in COMMON_LOGIC_NUMBERS:
                continue
            # Negative numbers handled by value check below
            if abs(node.value) <= 10:
                continue
            # Named constant assignment is acceptable
            if id(node) in named_consts:
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
