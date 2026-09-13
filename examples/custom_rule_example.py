"""Example external rule — copy into .aicaudit/rules/ to activate.

External rules are ordinary Python files using the public rule API.
A later registration with the same id overrides builtin rules.
"""
import ast

from aicaudit.rules.base import Finding, Rule, Severity, register


@register
class NoPrint(Rule):
    id = "Q100"
    name = "no-print"
    severity = Severity.INFO
    description = "Detect print() calls (noise in library code)"
    description_zh = "检测 print() 调用（库代码中的噪音）"

    def check(self, tree, context):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "print":
                findings.append(Finding(
                    rule_id=self.id,
                    message="print() call — prefer logging",
                    message_zh="print() 调用——建议改用 logging",
                    file=str(context.file_path), line=node.lineno or 0,
                    severity=self.severity,
                    snippet=context.lines[node.lineno - 1].strip() if node.lineno else None,
                    fix="Replace print() with logging.getLogger(__name__).info(...)",
                ))
        return findings
